//! One sync pass: compare base (state), local and remote for every path,
//! then apply the resulting actions in parallel.
//!
//! | local \ remote      | unchanged      | changed / new | deleted / absent |
//! |---------------------|----------------|---------------|------------------|
//! | unchanged           | —              | download      | move to trash    |
//! | changed / new       | upload (CAS)   | conflict      | upload (new)     |
//! | deleted / absent    | delete (CAS)   | download      | forget           |
//!
//! Remote writes are conditional on the version this device last saw, so a
//! concurrent change elsewhere becomes a conflict on the next pass instead of
//! being overwritten. A conflict keeps both: the remote version takes the
//! name, the local one becomes "name (conflicted copy from <device> <time>)"
//! and is uploaded next pass. Files deleted remotely are moved to
//! `.near-drive/trash/`, never removed.
use crate::local::{self, LocalFile, Stat};
use crate::state::{Entry, State};
use crate::{Folder, Options, Report};
use anyhow::{Context, Result};
use futures_util::StreamExt;
use near_drive_client::{near_drive_core::NearUri, Client, Conflict, GatewayError, ListEntry, PutOptions};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub(crate) struct Remote {
    seq: u64,
    manifest_cid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Side {
    Unchanged,
    /// Same content, new mtime (touched): nothing to transfer.
    Touched,
    Changed,
    New,
    Deleted,
    Absent,
}

#[derive(Debug)]
enum Action {
    Upload { expect: u64 },
    Download,
    Conflict,
    DeleteLocal,
    DeleteRemote { seq: u64 },
    Forget,
    /// Content unchanged, only the mtime moved: record the new stat.
    Adopt,
}

struct Ctx<'a> {
    client: &'a Client,
    folder: &'a Folder,
    state: Mutex<State>,
    report: Mutex<Report>,
    host: String,
}

fn is_conflict(e: &anyhow::Error) -> bool {
    e.downcast_ref::<Conflict>().is_some()
}

fn is_not_found(e: &anyhow::Error) -> bool {
    e.downcast_ref::<GatewayError>().is_some_and(|g| g.status == 404)
}

impl Ctx<'_> {
    fn uri(&self, rel: &str) -> Result<NearUri> {
        Ok(NearUri::object(&self.folder.remote.namespace, &format!("{}{rel}", self.folder.remote.path))?)
    }

    fn set(&self, rel: &str, e: Option<Entry>) {
        let mut s = self.state.lock().unwrap();
        match e {
            Some(e) => s.files.insert(rel.to_string(), e),
            None => s.files.remove(rel),
        };
    }

    fn note(&self, f: impl FnOnce(&mut Report)) {
        f(&mut self.report.lock().unwrap())
    }

    async fn hash(&self, p: &Path) -> Result<String> {
        let p = p.to_path_buf();
        tokio::task::spawn_blocking(move || local::hash_file(&p)).await?
    }

    async fn upload(&self, rel: &str, l: &LocalFile, expect: u64) -> Result<()> {
        // The file must still be what the scan saw (not mid-write).
        if local::stat(&l.path)? != Some(l.stat) {
            self.note(|r| r.pending = true);
            return Ok(());
        }
        let hash = self.hash(&l.path).await?;
        let opts = PutOptions { expect_seq: Some(expect), resume_dir: Some(self.folder.meta_dir().join("uploads")), ..Default::default() };
        match self.client.put_file(&l.path, &self.uri(rel)?, &opts).await {
            Ok(rec) => {
                self.set(rel, Some(Entry { seq: rec.seq, manifest_cid: rec.manifest_cid, size: l.stat.size, mtime_ns: l.stat.mtime_ns, hash }));
                self.note(|r| r.uploaded.push(rel.into()));
            }
            // Changed remotely since we looked: reconcile on the next pass.
            Err(e) if is_conflict(&e) => self.note(|r| r.pending = true),
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Download into a hidden temp file next to the target (same folder, so
    /// the final move is an atomic rename; resumes if interrupted).
    async fn fetch_temp(&self, rel: &str, target: &Path) -> Result<(PathBuf, near_drive_client::ObjectHead)> {
        local::ensure_parent(target)?;
        let name = target.file_name().and_then(|n| n.to_str()).context("bad file name")?;
        let tmp = target.with_file_name(format!(".{name}.drive-dl"));
        let head = self.client.get_to_file(&self.uri(rel)?, &tmp).await?;
        Ok((tmp, head))
    }

    async fn entry_for(&self, path: &Path, head: &near_drive_client::ObjectHead) -> Result<Entry> {
        let st = local::stat(path)?.context("file vanished")?;
        Ok(Entry { seq: head.record.seq, manifest_cid: head.record.manifest_cid.clone(), size: st.size, mtime_ns: st.mtime_ns, hash: self.hash(path).await? })
    }

    /// Move the local file out of the way as a conflicted copy.
    fn keep_local_copy(&self, rel: &str, path: &Path) -> Result<String> {
        let mut name = local::conflicted_name(rel, &self.host, chrono::Local::now());
        let mut n = 2;
        while local::local_path(&self.folder.local, &name).exists() {
            name = format!("{} {n}", local::conflicted_name(rel, &self.host, chrono::Local::now()));
            n += 1;
        }
        std::fs::rename(path, local::local_path(&self.folder.local, &name))?;
        Ok(name)
    }

    async fn download(&self, rel: &str, l: Option<&LocalFile>) -> Result<()> {
        let target = l.map(|l| l.path.clone()).unwrap_or_else(|| local::local_path(&self.folder.local, rel));
        let (tmp, head) = self.fetch_temp(rel, &target).await?;
        // The local file changed while we downloaded: keep it as a conflicted copy.
        let now = local::stat(&target)?;
        if now != l.map(|l| l.stat) && now.is_some() {
            let copy = self.keep_local_copy(rel, &target)?;
            self.note(|r| {
                r.conflicts.push(copy);
                r.pending = true;
            });
        }
        std::fs::rename(&tmp, &target).with_context(|| format!("replacing {}", target.display()))?;
        let e = self.entry_for(&target, &head).await?;
        self.set(rel, Some(e));
        self.note(|r| r.downloaded.push(rel.into()));
        Ok(())
    }

    async fn conflict(&self, rel: &str, l: &LocalFile) -> Result<()> {
        let (tmp, head) = self.fetch_temp(rel, &l.path).await?;
        let (theirs, mine) = (self.hash(&tmp).await?, self.hash(&l.path).await?);
        if theirs == mine {
            // Same bytes on both sides (e.g. first sync of a copied folder).
            std::fs::remove_file(&tmp)?;
            let e = self.entry_for(&l.path, &head).await?;
            self.set(rel, Some(e));
            return Ok(());
        }
        let copy = self.keep_local_copy(rel, &l.path)?;
        std::fs::rename(&tmp, &l.path)?;
        let e = self.entry_for(&l.path, &head).await?;
        self.set(rel, Some(e));
        self.note(|r| {
            r.conflicts.push(copy);
            r.downloaded.push(rel.into());
            r.pending = true; // upload the conflicted copy next
        });
        Ok(())
    }

    async fn apply(&self, rel: &str, action: Action, l: Option<&LocalFile>) -> Result<()> {
        match action {
            Action::Upload { expect } => self.upload(rel, l.context("no local file")?, expect).await,
            Action::Download => self.download(rel, l).await,
            Action::Conflict => self.conflict(rel, l.context("no local file")?).await,
            Action::DeleteLocal => {
                let l = l.context("no local file")?;
                if local::stat(&l.path)? != Some(l.stat) {
                    self.note(|r| r.pending = true);
                    return Ok(());
                }
                local::trash(&self.folder.local, rel, &l.path)?;
                self.set(rel, None);
                self.note(|r| r.deleted_local.push(rel.into()));
                Ok(())
            }
            Action::DeleteRemote { seq } => {
                match self.client.delete_if(&self.uri(rel)?, seq).await {
                    Ok(()) => {}
                    Err(e) if is_not_found(&e) => {}
                    Err(e) if is_conflict(&e) => {
                        self.note(|r| r.pending = true);
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                }
                self.set(rel, None);
                self.note(|r| r.deleted_remote.push(rel.into()));
                Ok(())
            }
            Action::Forget => {
                self.set(rel, None);
                Ok(())
            }
            Action::Adopt => {
                let l = l.context("no local file")?;
                let mut s = self.state.lock().unwrap();
                if let Some(e) = s.files.get_mut(rel) {
                    e.mtime_ns = l.stat.mtime_ns;
                }
                Ok(())
            }
        }
    }
}

fn remote_side(base: Option<&Entry>, r: Option<&Remote>) -> Side {
    match (base, r) {
        (Some(b), Some(r)) => {
            let same = match &r.manifest_cid {
                Some(c) => *c == b.manifest_cid,
                None => r.seq == b.seq,
            };
            if same {
                Side::Unchanged
            } else {
                Side::Changed
            }
        }
        (None, Some(_)) => Side::New,
        (Some(_), None) => Side::Deleted,
        (None, None) => Side::Absent,
    }
}

fn local_side(base: Option<&Entry>, l: Option<&LocalFile>) -> Result<Side> {
    Ok(match (base, l) {
        (Some(b), Some(l)) => {
            if l.stat == (Stat { size: b.size, mtime_ns: b.mtime_ns }) {
                Side::Unchanged
            } else if l.stat.size == b.size && local::hash_file(&l.path)? == b.hash {
                Side::Touched
            } else {
                Side::Changed
            }
        }
        (None, Some(_)) => Side::New,
        (Some(_), None) => Side::Deleted,
        (None, None) => Side::Absent,
    })
}

fn decide(base: Option<&Entry>, ls: Side, rs: Side) -> Option<Action> {
    use Side::*;
    let unchanged = |s| matches!(s, Unchanged | Touched);
    Some(match (ls, rs) {
        (l, Unchanged) if unchanged(l) => {
            if l == Touched {
                Action::Adopt
            } else {
                return None;
            }
        }
        (l, Changed | New) if unchanged(l) => Action::Download,
        (l, Deleted) if unchanged(l) => Action::DeleteLocal,
        (Changed | New, Unchanged) => Action::Upload { expect: base.map_or(0, |b| b.seq) },
        (Changed | New, Changed | New) => Action::Conflict,
        (Changed | New, Deleted | Absent) => Action::Upload { expect: 0 },
        (Deleted | Absent, Unchanged) => Action::DeleteRemote { seq: base.map_or(0, |b| b.seq) },
        (Deleted | Absent, Changed | New) => Action::Download,
        (Deleted | Absent, Deleted | Absent) => Action::Forget,
        _ => return None,
    })
}

pub(crate) async fn pass(client: &Client, folder: &Folder, opts: &Options) -> Result<Report> {
    let root = folder.local.clone();
    std::fs::create_dir_all(folder.meta_dir())?;
    let state = State::load(&root, &folder.remote.to_string(), client.account())?;

    // Remote first: if the gateway is unreachable, change nothing locally.
    let prefix = folder.remote.path.clone();
    let listing: Vec<ListEntry> = client.list(&folder.remote).await.context("listing the remote folder")?;
    let mut report = Report::default();
    let mut remote: BTreeMap<String, Remote> = BTreeMap::new();
    let mut folded: HashMap<String, String> = HashMap::new();
    for e in listing {
        let Some(rel) = e.path.strip_prefix(&prefix) else { continue };
        if rel.is_empty() || rel.ends_with('/') {
            continue;
        }
        if let Err(why) = local::valid_local(rel, cfg!(windows)) {
            report.skipped.push((rel.to_string(), why));
            continue;
        }
        if local::CASE_INSENSITIVE {
            if let Some(other) = folded.insert(local::fold(rel), rel.to_string()) {
                report.skipped.push((rel.to_string(), format!("differs from {other} only in letter case, which this file system cannot hold")));
                continue;
            }
        }
        remote.insert(rel.to_string(), Remote { seq: e.seq, manifest_cid: e.manifest_cid });
    }
    let skipped_remote: BTreeSet<String> = report.skipped.iter().map(|(r, _)| r.clone()).collect();

    let (root2, mut skipped) = (root.clone(), vec![]);
    let (scan, skipped) = tokio::task::spawn_blocking(move || {
        let s = local::scan(&root2, &mut skipped);
        s.map(|s| (s, skipped))
    })
    .await??;
    // Local paths the scan could not read (and everything under them): their
    // files would look deleted locally, so leave them out of the plan entirely.
    let skipped_local: Vec<String> = skipped.iter().map(|(r, _)| r.clone()).collect();
    report.skipped.extend(skipped);

    // Plan (hashing touched files off the async runtime).
    let now_ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
    let settle_ns = opts.settle.as_nanos() as u64;
    let keys: BTreeSet<String> = state.files.keys().chain(scan.keys()).chain(remote.keys()).filter(|k| !folder.excluded(k)).cloned().collect();
    // Selective sync: forget what we knew about excluded paths, so including
    // them again later reconciles from scratch (identical copies merge).
    let mut state = state;
    state.files.retain(|k, _| !folder.excluded(k));
    let mut plan = vec![];
    for rel in keys {
        if skipped_remote.contains(&rel) || local::under_skipped(&rel, &skipped_local) {
            continue; // never act on a path we cannot represent or read here
        }
        let (base, l, r) = (state.files.get(&rel), scan.get(&rel), remote.get(&rel));
        let ls = {
            let (b, l) = (base.cloned(), l.cloned());
            tokio::task::spawn_blocking(move || local_side(b.as_ref(), l.as_ref())).await??
        };
        let rs = remote_side(base, r);
        // Don't upload a file that is still being written.
        if matches!(ls, Side::Changed | Side::New) && l.is_some_and(|l| now_ns.saturating_sub(l.stat.mtime_ns) < settle_ns) {
            report.pending = true;
            continue;
        }
        if let Some(a) = decide(base, ls, rs) {
            plan.push((rel, a));
        }
    }

    let ctx = Ctx { client, folder, state: Mutex::new(state), report: Mutex::new(report), host: local::host_name() };
    let ctx = &ctx;
    let scan = &scan;
    let results: Vec<(String, Result<()>)> = futures_util::stream::iter(plan)
        .map(|(rel, a)| async move {
            let r = ctx.apply(&rel, a, scan.get(&rel)).await;
            (rel, r)
        })
        .buffer_unordered(opts.parallel.max(1))
        .collect()
        .await;
    for (rel, r) in results {
        if let Err(e) = r {
            ctx.note(|rep| rep.errors.push((rel, format!("{e:#}"))));
        }
    }
    let state = ctx.state.lock().unwrap();
    state.save(&root)?;
    let mut report = std::mem::take(&mut *ctx.report.lock().unwrap());
    report.files = state.files.len();
    Ok(report)
}
