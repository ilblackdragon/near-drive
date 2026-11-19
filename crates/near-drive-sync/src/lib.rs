//! NEAR Drive folder sync (Dropbox-style): a local folder kept in two-way
//! sync with a NEAR Drive prefix, on Linux, macOS and Windows.
//!
//! - Local changes are picked up from file-system events (inotify, FSEvents,
//!   ReadDirectoryChangesW via `notify`) plus a periodic rescan; remote changes
//!   by polling the listing. Each trigger runs one [`sync_once`] pass.
//! - Everything is end-to-end encrypted like any other NEAR Drive write;
//!   transfers are chunked, parallel, retried and resumable.
//! - Per-folder state, trash and temp files live in `<folder>/.near-drive/`,
//!   which is never synced.
//!
//! See `engine.rs` for how each file is reconciled.
mod engine;
pub mod local;
pub mod state;

use anyhow::{bail, Result};
use near_drive_client::{near_drive_core::NearUri, Client};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// A local folder and the remote prefix it mirrors.
#[derive(Debug, Clone)]
pub struct Folder {
    pub local: PathBuf,
    /// `near://<namespace>/` or `near://<namespace>/<prefix>/`.
    pub remote: NearUri,
    /// Selective sync: subfolders (relative, e.g. `Photos/2019`) left out in
    /// both directions. Excluded files are neither downloaded, uploaded nor
    /// deleted; local copies already present stay as they are.
    pub exclude: Vec<String>,
}

impl Folder {
    pub fn new(local: impl Into<PathBuf>, remote: NearUri) -> Result<Self> {
        let local = local.into();
        if !(remote.path.is_empty() || remote.path.ends_with('/')) {
            bail!("the remote of a synced folder is a prefix: end it with / ({remote}/)");
        }
        std::fs::create_dir_all(&local)?;
        let local = std::fs::canonicalize(&local)?;
        Ok(Self { local, remote, exclude: vec![] })
    }

    /// Leave these subfolders out (see [`Folder::exclude`]).
    pub fn with_exclude(mut self, exclude: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.exclude = exclude.into_iter().map(|e| normalize_folder(e.as_ref())).filter(|e| !e.is_empty()).collect();
        self
    }

    /// Is `rel` inside an excluded subfolder?
    pub fn excluded(&self, rel: &str) -> bool {
        self.exclude.iter().any(|e| rel.starts_with(e.as_str()))
    }

    pub fn meta_dir(&self) -> PathBuf {
        self.local.join(local::META_DIR)
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    /// Files transferred at once (each also uses the client's chunk parallelism).
    pub parallel: usize,
    /// Remote poll interval (local changes are noticed immediately).
    pub poll: Duration,
    /// A changed file must be untouched this long before it is uploaded.
    pub settle: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self { parallel: 4, poll: Duration::from_secs(30), settle: Duration::from_secs(2) }
    }
}

/// `Photos\\2019`, `/Photos/2019/` -> `Photos/2019/` (NFC, '/'-separated).
pub fn normalize_folder(s: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let parts: Vec<String> = s.split(['/', '\\']).filter(|p| !p.is_empty() && *p != ".").map(|p| p.nfc().collect()).collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("{}/", parts.join("/"))
    }
}

/// What one pass did.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Report {
    pub uploaded: Vec<String>,
    pub downloaded: Vec<String>,
    pub deleted_local: Vec<String>,
    pub deleted_remote: Vec<String>,
    /// Conflicted copies created (local names).
    pub conflicts: Vec<String>,
    /// Paths left alone, with the reason.
    pub skipped: Vec<(String, String)>,
    pub errors: Vec<(String, String)>,
    /// Something is waiting (a file still being written, a conflict to
    /// upload, a concurrent remote change): run again soon.
    pub pending: bool,
    /// Files in sync after the pass.
    pub files: usize,
}

impl Report {
    pub fn changed(&self) -> bool {
        !(self.uploaded.is_empty() && self.downloaded.is_empty() && self.deleted_local.is_empty() && self.deleted_remote.is_empty() && self.conflicts.is_empty())
    }

    pub fn summary(&self) -> String {
        format!(
            "{} up, {} down, {} deleted here, {} deleted remotely, {} conflicts, {} errors, {} files in sync",
            self.uploaded.len(),
            self.downloaded.len(),
            self.deleted_local.len(),
            self.deleted_remote.len(),
            self.conflicts.len(),
            self.errors.len(),
            self.files
        )
    }
}

/// One full reconcile of `folder`.
pub async fn sync_once(client: &Client, folder: &Folder, opts: &Options) -> Result<Report> {
    engine::pass(client, folder, opts).await
}

/// Last pass, for `near drive sync status` (`<folder>/.near-drive/status.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub remote: String,
    pub last_pass_ms: u64,
    pub ok: bool,
    pub error: Option<String>,
    pub report: Report,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn read_status(local: &std::path::Path) -> Option<Status> {
    serde_json::from_slice(&std::fs::read(local.join(local::META_DIR).join("status.json")).ok()?).ok()
}

fn write_status(folder: &Folder, s: &Status) {
    let p = folder.meta_dir().join("status.json");
    let tmp = p.with_extension("json.tmp");
    if std::fs::write(&tmp, serde_json::to_vec_pretty(s).unwrap_or_default()).is_ok() {
        let _ = std::fs::rename(&tmp, &p);
    }
}

/// Keep `folder` in sync until `stop` resolves: a pass at start, after local
/// changes (debounced), when the gateway reports a remote change (long-poll
/// `watch`), every `poll`, and with backoff after failures (e.g. offline:
/// local edits wait and go up once the gateway is reachable).
pub async fn run(client: &Client, folder: &Folder, opts: &Options, stop: impl std::future::Future<Output = ()>) -> Result<()> {
    use notify::{RecursiveMode, Watcher};
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let meta = folder.meta_dir();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res {
            // Our own state/temp files don't count as changes.
            let ours = |p: &std::path::PathBuf| p.starts_with(&meta) || p.file_name().and_then(|n| n.to_str()).is_some_and(local::ignored);
            if ev.paths.is_empty() || !ev.paths.iter().all(ours) {
                let _ = tx.send(());
            }
        }
    })?;
    watcher.watch(&folder.local, RecursiveMode::Recursive)?;
    tokio::pin!(stop);
    let (rtx, mut rrx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let remote = watch_remote(client, folder, rtx);
    tokio::pin!(remote);
    let mut failures = 0u32;
    loop {
        let (wait, status) = match sync_once(client, folder, opts).await {
            Ok(rep) => {
                failures = 0;
                if rep.changed() || !rep.errors.is_empty() {
                    tracing::info!("{}: {}", folder.local.display(), rep.summary());
                }
                for (p, e) in &rep.errors {
                    tracing::warn!("{p}: {e}");
                }
                let wait = if rep.pending || !rep.errors.is_empty() { opts.settle.max(Duration::from_secs(1)) } else { opts.poll };
                (wait, Status { remote: folder.remote.to_string(), last_pass_ms: now_ms(), ok: rep.errors.is_empty(), error: None, report: rep })
            }
            Err(e) => {
                failures += 1;
                tracing::warn!("{}: sync failed: {e:#}", folder.local.display());
                let wait = (Duration::from_secs(2) * 2u32.saturating_pow(failures.min(6))).min(opts.poll.max(Duration::from_secs(60)));
                (wait, Status { remote: folder.remote.to_string(), last_pass_ms: now_ms(), ok: false, error: Some(format!("{e:#}")), report: Report::default() })
            }
        };
        write_status(folder, &status);
        tokio::select! {
            _ = &mut stop => return Ok(()),
            _ = &mut remote => {}
            _ = tokio::time::sleep(wait) => {}
            Some(()) = rx.recv() => {
                // Debounce bursts (a save is several events; a copy is many).
                while tokio::time::timeout(Duration::from_millis(500), rx.recv()).await.is_ok_and(|v| v.is_some()) {}
            }
            Some(()) = rrx.recv() => {
                // A burst of remote writes (e.g. another device's sync pass): wait for it to settle.
                while tokio::time::timeout(Duration::from_millis(300), rrx.recv()).await.is_ok_and(|v| v.is_some()) {}
            }
        }
    }
}

/// Long-poll the gateway for changes under the folder's prefix and signal
/// each one. Never returns while watching works; on a gateway without watch
/// support it parks (the periodic poll still runs).
async fn watch_remote(client: &Client, folder: &Folder, tx: tokio::sync::mpsc::UnboundedSender<()>) {
    let mut cursor: Option<String> = None;
    let mut failures = 0u32;
    loop {
        match client.watch(&folder.remote, cursor.as_deref(), Duration::from_secs(25)).await {
            Ok(Some(r)) => {
                failures = 0;
                if r.changed && cursor.is_some() {
                    let _ = tx.send(());
                }
                cursor = Some(r.cursor);
            }
            Ok(None) => return std::future::pending().await,
            Err(e) => {
                failures += 1;
                tracing::debug!("watch {}: {e:#}", folder.remote);
                tokio::time::sleep((Duration::from_secs(1) * 2u32.saturating_pow(failures.min(6))).min(Duration::from_secs(60))).await;
            }
        }
    }
}
