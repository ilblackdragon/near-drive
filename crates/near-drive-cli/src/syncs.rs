//! `near drive sync ...`: folders kept in sync with NEAR Drive.
//!
//! Registered folders live in `<home>/sync.json`; `near drive up` runs them in
//! the background (and picks up `sync add` / `sync remove` within seconds).
//! `sync run` syncs one folder in the foreground (once, or `--watch`).
use crate::{resolve_uri, Ctx};
use anyhow::{bail, Context, Result};
use near_drive_client::Client;
use near_drive_sync::{Folder, Options};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncEntry {
    pub local: PathBuf,
    pub remote: String,
    pub account: String,
    pub network: String,
    /// Selective sync: subfolders left out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SyncConfig {
    pub folders: Vec<SyncEntry>,
}

fn config_path(home: &Path) -> PathBuf {
    home.join("sync.json")
}

impl SyncConfig {
    pub fn load(home: &Path) -> Result<Self> {
        match std::fs::read(config_path(home)) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| format!("parsing {}", config_path(home).display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, home: &Path) -> Result<()> {
        std::fs::create_dir_all(home)?;
        let p = config_path(home);
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(tmp, p)?;
        Ok(())
    }
}

/// The remote prefix for a folder: `Drive/` by default; bare paths are in
/// the account's namespace; always ends with `/`.
pub fn remote_prefix(remote: Option<&str>, account: &str) -> Result<near_drive_client::near_drive_core::NearUri> {
    let r = remote.unwrap_or("Drive/");
    let r = if r.is_empty() || r.ends_with('/') { r.to_string() } else { format!("{r}/") };
    resolve_uri(&r, account)
}

fn folder_path(dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(std::fs::canonicalize(dir)?)
}

pub async fn add(ctx: &mut Ctx, dir: PathBuf, remote: Option<String>) -> Result<()> {
    let account = ctx.account()?;
    let remote = remote_prefix(remote.as_deref(), &account)?;
    let local = folder_path(&dir)?;
    let home = ctx.drive_home()?;
    let mut cfg = SyncConfig::load(&home)?;
    for f in &cfg.folders {
        if f.local == local {
            bail!("{} is already synced with {} (remove it first)", local.display(), f.remote);
        }
        if local.starts_with(&f.local) || f.local.starts_with(&local) {
            bail!("{} overlaps the synced folder {}", local.display(), f.local.display());
        }
    }
    cfg.folders.push(SyncEntry { local: local.clone(), remote: remote.to_string(), account, network: ctx.network.clone(), exclude: vec![] });
    cfg.save(&home)?;
    println!("{} <-> {remote}", local.display());
    if crate::daemon::running(&home) {
        println!("the background service picks it up within a few seconds (`near drive sync status`)");
    } else {
        println!("start syncing in the background with `near drive up` (or once now: `near drive sync run {}`)", local.display());
    }
    Ok(())
}

pub fn remove(ctx: &Ctx, dir: PathBuf) -> Result<()> {
    let home = ctx.drive_home()?;
    let mut cfg = SyncConfig::load(&home)?;
    let local = std::fs::canonicalize(&dir).unwrap_or(dir);
    let before = cfg.folders.len();
    cfg.folders.retain(|f| f.local != local);
    if cfg.folders.len() == before {
        bail!("{} is not a synced folder", local.display());
    }
    cfg.save(&home)?;
    println!("stopped syncing {} (its files stay; remove {} to forget its sync state)", local.display(), local.join(near_drive_sync::local::META_DIR).display());
    Ok(())
}

/// Selective sync: leave `sub` out of a registered folder (or put it back).
pub fn set_excluded(ctx: &Ctx, dir: PathBuf, sub: &str, exclude: bool) -> Result<()> {
    let home = ctx.drive_home()?;
    let mut cfg = SyncConfig::load(&home)?;
    let local = std::fs::canonicalize(&dir).unwrap_or(dir);
    let f = cfg.folders.iter_mut().find(|f| f.local == local).with_context(|| format!("{} is not a synced folder", local.display()))?;
    // Accept a path inside the folder as well as a relative one.
    let rel = Path::new(sub).strip_prefix(&local).map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| sub.to_string());
    let rel = near_drive_sync::normalize_folder(&rel);
    if rel.is_empty() {
        bail!("name a subfolder of {}", local.display());
    }
    f.exclude.retain(|e| near_drive_sync::normalize_folder(e) != rel);
    if exclude {
        f.exclude.push(rel.clone());
        println!("{rel} is no longer synced in {} (local files there stay; delete them to free space)", local.display());
    } else {
        println!("{rel} is synced again in {}", local.display());
    }
    cfg.save(&home)
}

pub fn status(ctx: &Ctx) -> Result<()> {
    let home = ctx.drive_home()?;
    let cfg = SyncConfig::load(&home)?;
    if cfg.folders.is_empty() {
        println!("no synced folders; add one with `near drive sync add <folder>`");
        return Ok(());
    }
    println!("background service: {}", if crate::daemon::running(&home) { "running" } else { "stopped (`near drive up`)" });
    for f in &cfg.folders {
        println!("\n{} <-> {} ({} on {})", f.local.display(), f.remote, f.account, f.network);
        if !f.exclude.is_empty() {
            println!("  not synced: {}", f.exclude.join(", "));
        }
        match near_drive_sync::read_status(&f.local) {
            None => println!("  not synced yet"),
            Some(s) => {
                let ago = (now_ms().saturating_sub(s.last_pass_ms)) / 1000;
                match &s.error {
                    Some(e) => println!("  last attempt {ago}s ago failed: {e}"),
                    None => println!("  last sync {ago}s ago: {}", s.report.summary()),
                }
                for c in &s.report.conflicts {
                    println!("  conflict: kept your version as {c}");
                }
                for (p, e) in s.report.errors.iter().take(10) {
                    println!("  error: {p}: {e}");
                }
                for (p, e) in s.report.skipped.iter().take(10) {
                    println!("  skipped: {p}: {e}");
                }
            }
        }
    }
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn print_report(f: &Folder, r: &near_drive_sync::Report) {
    for p in &r.uploaded {
        eprintln!("  up     {p}");
    }
    for p in &r.downloaded {
        eprintln!("  down   {p}");
    }
    for p in &r.deleted_remote {
        eprintln!("  delete {p} (remote)");
    }
    for p in &r.deleted_local {
        eprintln!("  trash  {p} (deleted remotely; kept in {})", f.meta_dir().join("trash").display());
    }
    for p in &r.conflicts {
        eprintln!("  conflict: your version kept as {p}");
    }
    for (p, e) in &r.skipped {
        eprintln!("  skip   {p}: {e}");
    }
    for (p, e) in &r.errors {
        eprintln!("  error  {p}: {e}");
    }
    eprintln!("{}: {}", f.local.display(), r.summary());
}

/// `sync run`: one pass (repeated while something is pending), or `--watch`.
pub async fn run(ctx: &mut Ctx, dir: PathBuf, remote: Option<String>, watch: bool, exclude: Vec<String>) -> Result<()> {
    let c = ctx.client().await?;
    let remote = remote_prefix(remote.as_deref(), c.account())?;
    let folder = Folder::new(&dir, remote)?.with_exclude(exclude);
    let opts = Options { parallel: 4, ..Default::default() };
    if watch {
        init_tracing();
        eprintln!("syncing {} <-> {} (Ctrl-C to stop)", folder.local.display(), folder.remote);
        return near_drive_sync::run(&c, &folder, &opts, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    }
    for _ in 0..5 {
        let r = near_drive_sync::sync_once(&c, &folder, &opts).await?;
        print_report(&folder, &r);
        if !r.pending {
            if !r.errors.is_empty() {
                bail!("{} files failed", r.errors.len());
            }
            return Ok(());
        }
        tokio::time::sleep(opts.settle).await;
    }
    Ok(())
}

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn,near_drive_s3=info,near_drive_sync=info".into()))
        .with_writer(std::io::stderr)
        .try_init();
}

/// Background: keep every registered folder of `account` on `network` in
/// sync, re-reading `sync.json` so `sync add` / `remove` take effect live.
pub async fn supervise(client: Arc<Client>, home: PathBuf, account: String, network: String) -> Result<()> {
    // (stop, what it was started with, task)
    type Running = (tokio::sync::oneshot::Sender<()>, (String, Vec<String>), tokio::task::JoinHandle<()>);
    let mut running: HashMap<PathBuf, Running> = HashMap::new();
    loop {
        let wanted: Vec<SyncEntry> = match SyncConfig::load(&home) {
            Ok(c) => c.folders.into_iter().filter(|f| f.account == account && f.network == network).collect(),
            Err(e) => {
                tracing::warn!("{e:#}");
                vec![]
            }
        };
        // Stop removed (or re-pointed) folders (dropping the sender stops the
        // loop); restart ones whose loop ended with an error.
        running.retain(|local, (_, started, task)| !task.is_finished() && wanted.iter().any(|w| &w.local == local && (&w.remote, &w.exclude) == (&started.0, &started.1)));
        for w in wanted {
            if running.contains_key(&w.local) {
                continue;
            }
            let folder = match near_drive_client::near_drive_core::NearUri::parse(&w.remote).map_err(anyhow::Error::from).and_then(|r| Folder::new(&w.local, r)).map(|f| f.with_exclude(&w.exclude)) {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!("{}: {e:#}", w.local.display());
                    continue;
                }
            };
            let (tx, rx) = tokio::sync::oneshot::channel();
            let c = client.clone();
            tracing::info!("syncing {} <-> {}", folder.local.display(), folder.remote);
            let task = tokio::spawn(async move {
                if let Err(e) = near_drive_sync::run(&c, &folder, &Options::default(), async {
                    let _ = rx.await;
                })
                .await
                {
                    tracing::error!("{}: {e:#}", folder.local.display());
                }
            });
            running.insert(w.local.clone(), (tx, (w.remote.clone(), w.exclude.clone()), task));
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
