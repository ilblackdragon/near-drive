//! Windows: files on demand with the Cloud Files API (what OneDrive uses).
//!
//! The folder is registered as a sync root. Windows shows every remote file
//! as a placeholder (name, size, date, cloud icon) and calls back:
//! - `fetch_placeholders` when a folder is first opened: list it remotely;
//! - `fetch_data` when a file's bytes are read: download that range;
//! - `delete` / `rename` in Explorer: applied remotely (conditional on the
//!   version the placeholder holds);
//! - `state_changed` for local edits and new files: uploaded, then marked in
//!   sync (new files become placeholders).
//!
//! Remote changes are applied by a refresh loop (on `watch` notifications
//! and periodically): new files get placeholders, changed files are updated
//! and dehydrated (their new content downloads on next open), deleted files
//! are removed if they have no local changes.
use crate::MountOptions;
use anyhow::{Context, Result};
use cloud_filter::{
    error::{CResult, CloudErrorKind},
    filter::{info, ticket, Request, StateWatchEvent, SyncFilter},
    metadata::Metadata,
    placeholder::{ConvertOptions, Placeholder, UpdateOptions},
    placeholder_create_info::PlaceholderCreateInfo,
    root::{Connection, HydrationPolicy, HydrationType, PopulationType, SecurityId, Session, SyncRootId, SyncRootIdBuilder, SyncRootInfo},
    utility::{FileTime, WriteAt},
};
use near_drive_client::{near_drive_core::NearUri, Client, Conflict, GatewayError, PutOptions};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Transfer size per download request while hydrating.
const PIECE: u64 = 4 << 20;
/// Cloud Files transfers must be 4 KiB aligned (except at end of file).
const ALIGN: u64 = 4096;

/// Stored in each placeholder: the remote version it shows.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Blob {
    seq: u64,
    cid: String,
}

impl Blob {
    fn parse(b: &[u8]) -> Option<Blob> {
        serde_json::from_slice(b).ok()
    }
    fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

#[derive(Clone)]
struct RemoteFile {
    size: u64,
    seq: u64,
    cid: String,
    ts_ms: u64,
}

struct Provider {
    client: Arc<Client>,
    remote: NearUri,
    root: PathBuf,
    rt: tokio::runtime::Handle,
    /// Local paths with pending uploads (a burst of events per save).
    pending: Arc<Mutex<HashSet<PathBuf>>>,
}

fn file_time(ms: u64) -> FileTime {
    FileTime::try_from(UNIX_EPOCH + Duration::from_millis(ms)).unwrap_or(FileTime::NT_TIME_EPOCH)
}

/// `rel` ('/'-separated) for a full path under `root`. Callback paths may lack
/// the drive letter (`\Users\x\...`), so compare without it too.
fn rel_of(root: &Path, p: &Path) -> Option<String> {
    let strip = |s: String| -> String { s.trim_start_matches(r"\\?\").to_string() };
    let root_s = strip(root.display().to_string());
    let p_s = strip(p.display().to_string());
    let no_drive = |s: &str| -> String { if s.len() > 2 && s.as_bytes()[1] == b':' { s[2..].to_string() } else { s.to_string() } };
    let (r, q) = (no_drive(&root_s).to_lowercase(), no_drive(&p_s));
    let ql = q.to_lowercase();
    if ql == r {
        return Some(String::new());
    }
    let rest = ql.strip_prefix(&format!("{r}\\"))?;
    let rest = &q[q.len() - rest.len()..];
    Some(rest.replace('\\', "/"))
}

impl Provider {
    fn uri(&self, rel: &str) -> Result<NearUri> {
        Ok(NearUri::object(&self.remote.namespace, &format!("{}{rel}", self.remote.path))?)
    }

    fn local(&self, rel: &str) -> PathBuf {
        let mut p = self.root.clone();
        p.extend(rel.split('/'));
        p
    }

    /// All remote files under the mounted prefix: rel -> file.
    fn list_all(&self) -> Result<BTreeMap<String, RemoteFile>> {
        let entries = self.rt.block_on(self.client.list(&self.remote))?;
        Ok(entries
            .into_iter()
            .filter_map(|e| {
                let rel = e.path.strip_prefix(&self.remote.path)?.to_string();
                if rel.is_empty() || rel.ends_with('/') || near_drive_sync::local::valid_local(&rel, true).is_err() {
                    return None;
                }
                Some((rel, RemoteFile { size: e.size, seq: e.seq, cid: e.manifest_cid.unwrap_or_default(), ts_ms: e.ts_ms }))
            })
            .collect())
    }

    fn file_info(name: &str, f: &RemoteFile) -> PlaceholderCreateInfo {
        let t = file_time(f.ts_ms);
        PlaceholderCreateInfo::new(name)
            .metadata(Metadata::file().size(f.size).written(t).created(t).changed(t).accessed(t))
            .blob(Blob { seq: f.seq, cid: f.cid.clone() }.bytes())
            .has_no_children()
            .mark_in_sync()
    }

    /// Folders are populated eagerly by `refresh` (the whole tree as
    /// placeholders), so they never need an on-demand listing.
    fn dir_info(name: &str) -> PlaceholderCreateInfo {
        PlaceholderCreateInfo::new(name).metadata(Metadata::directory()).has_no_children().mark_in_sync()
    }

    /// Placeholders for the direct children of `dir` (rel, "" = root).
    fn children(&self, dir: &str, all: &BTreeMap<String, RemoteFile>) -> Vec<(String, PlaceholderCreateInfo)> {
        let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
        let mut dirs = HashSet::new();
        let mut out = vec![];
        for (rel, f) in all.range(prefix.clone()..) {
            let Some(rest) = rel.strip_prefix(&prefix) else { break };
            match rest.split_once('/') {
                None => out.push((rest.to_string(), Self::file_info(rest, f))),
                Some((d, _)) => {
                    if dirs.insert(d.to_string()) {
                        out.push((d.to_string(), Self::dir_info(d)));
                    }
                }
            }
        }
        out
    }

    fn delete_remote(&self, rel: &str, seq: u64) -> Result<()> {
        match self.rt.block_on(self.client.delete_if(&self.uri(rel)?, seq)) {
            Ok(()) => Ok(()),
            Err(e) if e.downcast_ref::<GatewayError>().is_some_and(|g| g.status == 404) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Copy a remote object to a new path (download + upload), then delete the old one.
    fn move_remote(&self, from: &str, to: &str, f: &RemoteFile) -> Result<()> {
        let tmp = std::env::temp_dir().join(format!("near-drive-mv-{}", rand_suffix()));
        self.rt.block_on(self.client.get_to_file(&self.uri(from)?, &tmp))?;
        let r = self.rt.block_on(self.client.put_file(&tmp, &self.uri(to)?, &PutOptions { expect_seq: Some(0), ..Default::default() }));
        let _ = std::fs::remove_file(&tmp);
        r?;
        self.delete_remote(from, f.seq)
    }

    /// Upload a new or edited local file, then mark it in sync.
    fn upload(&self, path: &Path) -> Result<()> {
        let Some(rel) = rel_of(&self.root, path) else { return Ok(()) };
        if rel.is_empty() || rel.split('/').any(near_drive_sync::local::ignored) {
            return Ok(());
        }
        let md = match std::fs::metadata(path) {
            Ok(m) if m.is_file() => m,
            _ => return Ok(()),
        };
        // Already in sync (e.g. our own hydration or placeholder update)?
        let ph: Placeholder = std::fs::File::open(path)?.into();
        let info = ph.info().ok().flatten();
        if info.as_ref().is_some_and(|i| i.is_in_sync()) {
            return Ok(());
        }
        // A placeholder that isn't fully on disk cannot have local edits to upload.
        if info.as_ref().is_some_and(|i| i.on_disk_data_size() < md.len() as i64) {
            return Ok(());
        }
        let base = info.as_ref().and_then(|i| Blob::parse(i.blob())).map_or(0, |b| b.seq);
        drop(ph);
        let opts = PutOptions { expect_seq: Some(base), ..Default::default() };
        let rec = match self.rt.block_on(self.client.put_file(path, &self.uri(&rel)?, &opts)) {
            Ok(r) => r,
            Err(e) if e.downcast_ref::<Conflict>().is_some() => {
                // Changed remotely too: keep ours as a conflicted copy, take theirs.
                let copy = near_drive_sync::local::conflicted_name(&rel, &near_drive_sync::local::host_name(), near_drive_sync::local::now());
                std::fs::rename(path, self.local(&copy))?;
                self.pending.lock().unwrap().insert(self.local(&copy));
                tracing::warn!("{rel} changed elsewhere; your version is now {copy}");
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let blob = Blob { seq: rec.seq, cid: rec.manifest_cid }.bytes();
        let mut ph: Placeholder = std::fs::OpenOptions::new().read(true).write(true).open(path)?.into();
        if info.is_some() {
            ph.update(UpdateOptions::default().mark_in_sync().blob(&blob), None)?;
        } else {
            ph.convert_to_placeholder(ConvertOptions::default().mark_in_sync().blob(blob), None)?;
        }
        tracing::info!("uploaded {rel}");
        Ok(())
    }

    /// Make sure every folder on the way to `rel` exists (as a placeholder).
    fn ensure_dirs(&self, rel: &str) -> Result<()> {
        let mut dir = self.root.clone();
        let parts: Vec<&str> = rel.split('/').collect();
        for d in &parts[..parts.len().saturating_sub(1)] {
            let next = dir.join(d);
            if !next.exists() {
                if let Err(e) = Self::dir_info(d).create(&dir) {
                    tracing::warn!("placeholder folder {}: {e}", next.display());
                    std::fs::create_dir_all(&next)?;
                }
            }
            dir = next;
        }
        Ok(())
    }

    /// Bring placeholders in line with the remote: new files and folders get
    /// placeholders (cheap: no data), changed in-sync files are updated and
    /// dehydrated, deleted in-sync files are removed.
    fn refresh(&self) -> Result<()> {
        let all = self.list_all()?;
        // New and changed remote files.
        for (rel, f) in &all {
            let path = self.local(rel);
            let parent = path.parent().unwrap_or(&self.root).to_path_buf();
            if let Err(e) = self.ensure_dirs(rel) {
                tracing::warn!("{rel}: {e:#}");
                continue;
            }
            match std::fs::File::open(&path) {
                Err(_) => {
                    let name = rel.rsplit('/').next().unwrap_or(rel);
                    match Self::file_info(name, f).create(&parent) {
                        Ok(_) => tracing::debug!("placeholder {rel}"),
                        Err(e) => tracing::warn!("placeholder {rel}: {e}"),
                    }
                }
                Ok(file) => {
                    let ph: Placeholder = file.into();
                    let Some(info) = ph.info().ok().flatten() else { continue };
                    let held = Blob::parse(info.blob()).unwrap_or_default();
                    if held.cid != f.cid && info.is_in_sync() {
                        drop(ph);
                        let mut ph: Placeholder = std::fs::OpenOptions::new().read(true).write(true).open(&path)?.into();
                        let t = file_time(f.ts_ms);
                        let blob = Blob { seq: f.seq, cid: f.cid.clone() }.bytes();
                        let opts = UpdateOptions::default().metadata(Metadata::file().size(f.size).written(t).changed(t)).blob(&blob).dehydrate().mark_in_sync();
                        if let Err(e) = ph.update(opts, None) {
                            tracing::warn!("updating {rel}: {e}");
                        }
                    }
                }
            }
        }
        // Remote deletions: remove in-sync placeholders that are gone.
        let mut stack = vec![self.root.clone()];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                let Some(rel) = rel_of(&self.root, &p) else { continue };
                if rel.split('/').any(near_drive_sync::local::ignored) {
                    continue;
                }
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if all.contains_key(&rel) {
                    continue;
                }
                let Ok(file) = std::fs::File::open(&p) else { continue };
                let ph: Placeholder = file.into();
                let in_sync_remote = ph.info().ok().flatten().is_some_and(|i| i.is_in_sync() && Blob::parse(i.blob()).is_some_and(|b| b.seq > 0));
                drop(ph);
                if in_sync_remote {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
        Ok(())
    }
}

fn rand_suffix() -> String {
    format!("{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0))
}

fn cerr(e: anyhow::Error) -> CloudErrorKind {
    tracing::warn!("{e:#}");
    CloudErrorKind::Unsuccessful
}

impl SyncFilter for Provider {
    fn fetch_placeholders(&self, request: Request, ticket: ticket::FetchPlaceholders, _info: info::FetchPlaceholders) -> CResult<()> {
        tracing::debug!("fetch_placeholders {}", request.path().display());
        let dir = rel_of(&self.root, &request.path()).ok_or(CloudErrorKind::NotUnderSyncRoot)?;
        let all = self.list_all().map_err(cerr)?;
        let here = if dir.is_empty() { self.root.clone() } else { self.local(&dir) };
        // Only what isn't there yet (refresh may have created some already).
        let mut items: Vec<PlaceholderCreateInfo> = self
            .children(&dir, &all)
            .into_iter()
            .filter(|(name, _)| !here.join(name).exists())
            .map(|(_, i)| i)
            .collect();
        let r = ticket.pass_with_placeholders(&mut items);
        tracing::debug!("fetch_placeholders {dir:?}: {} new, {r:?}", items.len());
        r.map_err(|e| cerr(e.into()))
    }

    fn fetch_data(&self, request: Request, ticket: ticket::FetchData, info: info::FetchData) -> CResult<()> {
        tracing::debug!("fetch_data {} {:?}", request.path().display(), info.required_file_range());
        let rel = rel_of(&self.root, &request.path()).ok_or(CloudErrorKind::NotUnderSyncRoot)?;
        let size = request.file_size();
        let want = info.required_file_range();
        let start = want.start / ALIGN * ALIGN;
        let end = want.end.div_ceil(ALIGN).saturating_mul(ALIGN).min(size);
        let uri = self.uri(&rel).map_err(cerr)?;
        let mut off = start;
        while off < end {
            let to = (off + PIECE).min(end);
            let data = self.rt.block_on(self.client.get_range(&uri, off..to)).map_err(cerr)?;
            if data.len() as u64 != to - off {
                // The remote file changed size since the placeholder was made.
                let _ = ticket.fail(CloudErrorKind::NotInSync);
                return Err(CloudErrorKind::NotInSync);
            }
            ticket.write_at(&data, off).map_err(|e| cerr(e.into()))?;
            let _ = ticket.report_progress(end - start, to - start);
            off = to;
        }
        Ok(())
    }

    fn delete(&self, request: Request, ticket: ticket::Delete, info: info::Delete) -> CResult<()> {
        let rel = rel_of(&self.root, &request.path()).ok_or(CloudErrorKind::NotUnderSyncRoot)?;
        let r = if info.is_directory() {
            self.list_all().and_then(|all| {
                let prefix = format!("{rel}/");
                all.iter().filter(|(p, _)| p.starts_with(&prefix)).try_for_each(|(p, f)| self.delete_remote(p, f.seq))
            })
        } else {
            match Blob::parse(request.file_blob()) {
                Some(b) if b.seq > 0 => self.delete_remote(&rel, b.seq),
                _ => Ok(()), // never uploaded
            }
        };
        r.map_err(cerr)?;
        ticket.pass().map_err(|e| cerr(e.into()))
    }

    fn rename(&self, request: Request, ticket: ticket::Rename, info: info::Rename) -> CResult<()> {
        let src = rel_of(&self.root, &request.path());
        let dst = info.target_in_scope().then(|| rel_of(&self.root, &info.target_path())).flatten();
        let r = (|| -> Result<()> {
            let Some(src) = src else { return Ok(()) };
            let all = self.list_all()?;
            let moves: Vec<(String, RemoteFile)> = if info.is_directory() {
                let prefix = format!("{src}/");
                all.iter().filter(|(p, _)| p.starts_with(&prefix)).map(|(p, f)| (p.clone(), f.clone())).collect()
            } else {
                all.get(&src).map(|f| vec![(src.clone(), f.clone())]).unwrap_or_default()
            };
            for (from, f) in moves {
                match &dst {
                    Some(d) => self.move_remote(&from, &format!("{d}{}", &from[src.len()..]), &f)?,
                    // Moved out of the drive folder: gone from NEAR Drive.
                    None => self.delete_remote(&from, f.seq)?,
                }
            }
            Ok(())
        })();
        r.map_err(cerr)?;
        ticket.pass().map_err(|e| cerr(e.into()))
    }

    fn state_changed(&self, event: StateWatchEvent) {
        if let StateWatchEvent::Changed(paths) = event {
            self.pending.lock().unwrap().extend(paths);
        }
    }
}

/// A connected sync root; disconnects on drop (placeholders stay).
pub struct Mounted {
    _conn: Connection<Provider>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Mounted {
    pub fn unmount(mut self) -> Result<()> {
        self.stop.take();
        Ok(())
    }
}

fn root_id(remote: &NearUri) -> Result<SyncRootId> {
    let tag = &blake3::hash(remote.to_string().as_bytes()).to_hex()[..12];
    Ok(SyncRootIdBuilder::new(format!("NEARDrive{tag}")).user_security_id(SecurityId::current_user()?).account_name(remote.namespace.clone()).build())
}

/// Stop showing `folder` as a NEAR Drive folder (placeholders whose content
/// is not on disk are removed by Windows).
pub fn unregister(remote: &NearUri) -> Result<()> {
    Ok(root_id(remote)?.unregister()?)
}

/// Make `folder` a files-on-demand view of `remote` and keep it connected.
pub fn mount(client: Arc<Client>, remote: NearUri, folder: &Path, _opts: MountOptions, rt: tokio::runtime::Handle) -> Result<Mounted> {
    anyhow::ensure!(cloud_filter::root::is_supported().unwrap_or(false), "this Windows version has no Cloud Files API (Windows 10 1709+ on NTFS needed)");
    anyhow::ensure!(remote.path.is_empty() || remote.path.ends_with('/'), "mount a folder: end the remote with /");
    std::fs::create_dir_all(folder)?;
    let root = std::fs::canonicalize(folder)?;
    let root = PathBuf::from(root.display().to_string().trim_start_matches(r"\\?\"));
    let id = root_id(&remote)?;
    if !id.is_registered()? {
        id.register(
            SyncRootInfo::default()
                .with_display_name(format!("NEAR Drive ({remote})"))
                .with_icon("%SystemRoot%\\system32\\imageres.dll,-1043")
                .with_version(env!("CARGO_PKG_VERSION"))
                .with_hydration_type(HydrationType::Full)
                .with_hydration_policy(HydrationPolicy::AutoDehydrationAllowed)
                .with_population_type(PopulationType::Full)
                .with_path(&root)?,
        )
        .context("registering the sync root")?;
    }
    let pending = Arc::new(Mutex::new(HashSet::new()));
    let worker = Arc::new(Provider { client: client.clone(), remote: remote.clone(), root: root.clone(), rt: rt.clone(), pending: pending.clone() });
    // The whole tree as placeholders (no file data), before connecting.
    {
        let w = worker.clone();
        tokio::task::block_in_place(|| w.refresh()).context("listing the remote folder")?;
    }
    let provider = Provider { client: client.clone(), remote: remote.clone(), root, rt: rt.clone(), pending };
    let conn = Session::new().connect(&worker.root, provider).context("connecting the sync root")?;
    // Background: uploads of local changes (after they settle) and remote refreshes.
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let changed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let changed2 = changed.clone();
    let (c2, r2) = (client.clone(), remote.clone());
    rt.spawn(async move {
        let mut cursor: Option<String> = None;
        loop {
            match c2.watch(&r2, cursor.as_deref(), Duration::from_secs(25)).await {
                Ok(Some(w)) => {
                    if w.changed {
                        changed2.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    cursor = Some(w.cursor);
                }
                Ok(None) => return,
                Err(_) => tokio::time::sleep(Duration::from_secs(5)).await,
            }
        }
    });
    rt.spawn(async move {
        let mut last_refresh = std::time::Instant::now() - Duration::from_secs(3600);
        loop {
            tokio::select! {
                _ = &mut stop_rx => return,
                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            }
            let paths: Vec<PathBuf> = worker.pending.lock().unwrap().drain().collect();
            let w = worker.clone();
            let refresh = changed.swap(false, std::sync::atomic::Ordering::SeqCst) || last_refresh.elapsed() > Duration::from_secs(30);
            if refresh {
                last_refresh = std::time::Instant::now();
            }
            let _ = tokio::task::spawn_blocking(move || {
                for p in paths {
                    if let Err(e) = w.upload(&p) {
                        tracing::warn!("{}: {e:#}", p.display());
                        w.pending.lock().unwrap().insert(p); // retry (e.g. still open by an editor)
                    }
                }
                if refresh {
                    if let Err(e) = w.refresh() {
                        tracing::warn!("refresh: {e:#}");
                    }
                }
            })
            .await;
        }
    });
    Ok(Mounted { _conn: conn, stop: Some(stop_tx) })
}
