//! Chunk garbage collection (mark and sweep).
//!
//! Deleting or overwriting an object only changes the index; its chunks stay
//! in the backends. Chunks can be shared between objects (public data dedups
//! by content, `share` writes a new manifest over the same data chunks), so
//! they cannot be deleted per object. Instead:
//!
//! 1. **Mark**: list every live index entry in every namespace, read its
//!    manifest (itself a chunk) and collect the manifest cid plus all data
//!    chunk cids. A manifest that cannot be read aborts the run: never sweep
//!    on partial knowledge.
//! 2. **Sweep**: on every backend that can list its chunks, delete chunks
//!    that are not marked and were last written before `start - grace`.
//!    Chunks are uploaded before the record that references them is
//!    committed (and resumable uploads can take long); the grace period
//!    keeps those. Re-uploading an existing chunk refreshes its timestamp.
//!
//! Runs are safe while gateways serve traffic (that is what the grace period
//! is for) and concurrent runs do not hurt each other, but one run at a time
//! from one place is enough. Backends without a listing (blob bridges) are
//! skipped and reported.
use crate::{
    placement::Placement,
    store::{ChunkInfo, IndexEntry, IndexStore},
    AppState, Config,
};
use anyhow::{anyhow, bail, Context, Result};
use futures_util::{StreamExt, TryStreamExt};
use near_drive_core::manifest::Manifest;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    sync::Weak,
    time::{Duration, Instant, SystemTime},
};

pub const DEFAULT_GRACE: Duration = Duration::from_secs(24 * 3600);

/// `gc` section of the gateway config: periodic GC inside the server. Off
/// unless `interval_secs` > 0. With several gateways sharing an index and
/// backends, enable it on one of them only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcConfig {
    /// Seconds between runs; 0 = off.
    #[serde(default)]
    pub interval_secs: u64,
    /// Unreferenced chunks younger than this are kept (default 86400).
    #[serde(default = "default_grace_secs")]
    pub grace_secs: u64,
    /// Only report what would be deleted.
    #[serde(default)]
    pub dry_run: bool,
}

fn default_grace_secs() -> u64 {
    DEFAULT_GRACE.as_secs()
}

impl Default for GcConfig {
    fn default() -> Self {
        Self { interval_secs: 0, grace_secs: default_grace_secs(), dry_run: false }
    }
}

#[derive(Debug, Clone)]
pub struct GcOptions {
    /// Unreferenced chunks last written within this long before the run started are kept.
    pub grace: Duration,
    /// Report only; delete nothing.
    pub dry_run: bool,
    /// Sweep even when the index has no live entries at all (normally that
    /// looks like a misconfigured index and the run is refused).
    pub force: bool,
    /// Concurrent manifest reads and chunk deletes.
    pub concurrency: usize,
}

impl Default for GcOptions {
    fn default() -> Self {
        Self { grace: DEFAULT_GRACE, dry_run: false, force: false, concurrency: 32 }
    }
}

/// Per-backend outcome.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackendReport {
    pub name: String,
    /// False: the backend cannot list its chunks (blob bridges); not swept.
    pub swept: bool,
    pub chunks: u64,
    pub bytes: u64,
    /// Referenced by a live object.
    pub live: u64,
    /// Unreferenced but within the grace period (kept).
    pub recent: u64,
    /// Unreferenced and older than the grace period: deleted (or, in a dry
    /// run, would be).
    pub garbage: u64,
    pub garbage_bytes: u64,
    /// Actually deleted (0 in a dry run; may be below `garbage` when a chunk
    /// was refreshed or removed concurrently).
    pub deleted: u64,
    pub deleted_bytes: u64,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GcReport {
    pub dry_run: bool,
    pub grace_secs: u64,
    pub namespaces: u64,
    pub live_entries: u64,
    /// Distinct manifest + data chunk cids referenced by live entries.
    pub live_chunks: u64,
    pub backends: Vec<BackendReport>,
    pub garbage: u64,
    pub garbage_bytes: u64,
    pub deleted: u64,
    pub deleted_bytes: u64,
    pub elapsed_ms: u64,
}

impl GcReport {
    pub fn errors(&self) -> impl Iterator<Item = (&str, &str)> {
        self.backends.iter().flat_map(|b| b.errors.iter().map(move |e| (b.name.as_str(), e.as_str())))
    }
}

/// The live set: every chunk referenced by a live index entry.
pub struct Marked {
    pub chunks: HashSet<String>,
    pub namespaces: u64,
    pub entries: u64,
}

/// Mark phase. Fails if the index cannot be enumerated or any live entry's
/// manifest is missing or unreadable.
pub async fn mark(blobs: &Placement, index: &dyn IndexStore, concurrency: usize) -> Result<Marked> {
    let namespaces = index.namespaces().await.context("listing index namespaces")?;
    let mut m = Marked { chunks: HashSet::new(), namespaces: 0, entries: 0 };
    for ns in &namespaces {
        let entries = index.list(ns, "").await.with_context(|| format!("listing namespace {ns}"))?;
        if entries.is_empty() {
            continue;
        }
        m.namespaces += 1;
        m.entries += entries.len() as u64;
        // A manifest's content is fixed by its cid: read each one once.
        let mut todo: Vec<IndexEntry> = vec![];
        for e in entries {
            if !m.chunks.contains(&e.manifest_cid) && !todo.iter().any(|t| t.manifest_cid == e.manifest_cid) {
                todo.push(e);
            }
        }
        let mut loads = futures_util::stream::iter(todo)
            .map(|e| async move {
                let what = || format!("manifest {} of {}/{}", e.manifest_cid, e.namespace, e.path);
                let bytes = blobs.get(e.class.as_deref(), &e.manifest_cid).await.with_context(what)?.ok_or_else(|| anyhow!("{} is missing from every backend", what()))?;
                let manifest = Manifest::from_bytes(&bytes).with_context(what)?;
                Ok::<_, anyhow::Error>((e.record.manifest_cid, manifest))
            })
            .buffer_unordered(concurrency.max(1));
        while let Some((mcid, manifest)) = loads.try_next().await.context("GC aborted: cannot read a live manifest")? {
            m.chunks.insert(mcid);
            m.chunks.extend(manifest.chunks.into_iter().map(|c| c.cid));
        }
    }
    Ok(m)
}

/// One full mark-and-sweep run over `blobs`' backends.
pub async fn run(blobs: &Placement, index: &dyn IndexStore, opts: &GcOptions) -> Result<GcReport> {
    let t0 = Instant::now();
    // Fixed before marking: anything written after the run starts is younger than this.
    let cutoff = SystemTime::now().checked_sub(opts.grace).unwrap_or(SystemTime::UNIX_EPOCH);
    let marked = mark(blobs, index, opts.concurrency).await?;
    tracing::info!("gc: mark found {} live entries in {} namespaces, {} live chunks", marked.entries, marked.namespaces, marked.chunks.len());

    // Candidates per backend first, so the sanity check sees everything before anything is deleted.
    let mut reports = vec![];
    let mut candidates: Vec<Vec<ChunkInfo>> = vec![];
    for (name, store) in blobs.backends() {
        let mut r = BackendReport { name: name.to_string(), ..Default::default() };
        let mut garbage = vec![];
        match store.list() {
            None => tracing::info!("gc: backend {name} cannot list its chunks; skipped"),
            Some(mut s) => {
                r.swept = true;
                loop {
                    match s.next().await {
                        None => break,
                        Some(Ok(c)) => {
                            r.chunks += 1;
                            r.bytes += c.size;
                            if marked.chunks.contains(&c.cid) {
                                r.live += 1;
                            } else if c.modified >= cutoff {
                                r.recent += 1;
                            } else {
                                r.garbage += 1;
                                r.garbage_bytes += c.size;
                                garbage.push(c);
                            }
                        }
                        Some(Err(e)) => {
                            // A partial listing is still safe to sweep (only listed chunks are judged).
                            tracing::warn!("gc: listing backend {name}: {e:#}");
                            r.errors.push(format!("listing: {e:#}"));
                            break;
                        }
                    }
                }
            }
        }
        reports.push(r);
        candidates.push(garbage);
    }
    let garbage: u64 = reports.iter().map(|r| r.garbage).sum();
    if marked.entries == 0 && garbage > 0 && !opts.force {
        bail!("GC refused: the index has no live entries but the backends hold {garbage} unreferenced chunks (wrong index configured?); pass --force to sweep anyway");
    }

    if !opts.dry_run {
        for ((name, store), (r, garbage)) in blobs.backends().zip(reports.iter_mut().zip(candidates)) {
            let mut dels = futures_util::stream::iter(garbage)
                .map(|c| async move {
                    let res = store.delete_if_older(&c.cid, cutoff).await;
                    if matches!(res, Ok(true)) {
                        blobs.forget_cached(&c.cid).await;
                    }
                    (c, res)
                })
                .buffer_unordered(opts.concurrency.max(1));
            while let Some((c, res)) = dels.next().await {
                match res {
                    Ok(true) => {
                        r.deleted += 1;
                        r.deleted_bytes += c.size;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        if r.errors.len() < 20 {
                            r.errors.push(format!("deleting {}: {e:#}", c.cid));
                        }
                        tracing::warn!("gc: deleting {} from {name}: {e:#}", c.cid);
                    }
                }
            }
        }
    }

    let report = GcReport {
        dry_run: opts.dry_run,
        grace_secs: opts.grace.as_secs(),
        namespaces: marked.namespaces,
        live_entries: marked.entries,
        live_chunks: marked.chunks.len() as u64,
        garbage,
        garbage_bytes: reports.iter().map(|r| r.garbage_bytes).sum(),
        deleted: reports.iter().map(|r| r.deleted).sum(),
        deleted_bytes: reports.iter().map(|r| r.deleted_bytes).sum(),
        backends: reports,
        elapsed_ms: t0.elapsed().as_millis() as u64,
    };
    for b in &report.backends {
        if b.swept {
            tracing::info!(
                "gc: backend {}: {} chunks ({} bytes), {} live, {} recent, {} garbage ({} bytes), {} deleted ({} bytes){}",
                b.name,
                b.chunks,
                b.bytes,
                b.live,
                b.recent,
                b.garbage,
                b.garbage_bytes,
                b.deleted,
                b.deleted_bytes,
                if b.errors.is_empty() { String::new() } else { format!(", {} errors", b.errors.len()) }
            );
        }
    }
    tracing::info!(
        "gc: {}{} garbage chunks ({} bytes), {} deleted ({} bytes) in {} ms",
        if report.dry_run { "dry run: " } else { "" },
        report.garbage,
        report.garbage_bytes,
        report.deleted,
        report.deleted_bytes,
        report.elapsed_ms
    );
    Ok(report)
}

/// A run against the storage in `cfg`, outside a serving gateway (the `gc`
/// subcommand). The on-disk chunk cache of `cfg` is left alone: the serving
/// gateway owns it, and it is size-bounded anyway.
pub async fn run_config(cfg: &Config, opts: &GcOptions) -> Result<GcReport> {
    let mut storage = cfg.storage.clone();
    storage.cache = None;
    let blobs = Placement::from_config(&storage, &cfg.data_dir)?;
    let index = cfg.storage.index.build(&cfg.data_dir)?;
    run(&blobs, index.as_ref(), opts).await
}

/// Periodic GC inside the server; stops when the state is dropped.
pub(crate) fn spawn_periodic(state: Weak<AppState>, cfg: GcConfig) {
    if cfg.interval_secs == 0 {
        return;
    }
    let interval = Duration::from_secs(cfg.interval_secs);
    let opts = GcOptions { grace: Duration::from_secs(cfg.grace_secs), dry_run: cfg.dry_run, ..Default::default() };
    tokio::spawn(async move {
        // First run soon after start (restarts may be more frequent than the interval).
        let mut wait = interval.min(Duration::from_secs(300));
        loop {
            tokio::time::sleep(wait).await;
            wait = interval;
            let Some(st) = state.upgrade() else { return };
            if let Err(e) = run(&st.blobs, st.index.as_ref(), &opts).await {
                tracing::error!("gc: {e:#}");
            }
        }
    });
}

/// `90`, `90s`, `15m`, `24h`, `7d`.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    let (num, mult) = match s.char_indices().last() {
        Some((i, 's')) => (&s[..i], 1),
        Some((i, 'm')) => (&s[..i], 60),
        Some((i, 'h')) => (&s[..i], 3600),
        Some((i, 'd')) => (&s[..i], 86400),
        _ => (s, 1),
    };
    let n: u64 = num.trim().parse().map_err(|_| anyhow!("bad duration {s:?} (use e.g. 3600, 90s, 15m, 24h, 7d)"))?;
    Ok(Duration::from_secs(n.checked_mul(mult).ok_or_else(|| anyhow!("duration {s:?} too large"))?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(7 * 86400));
        assert!(parse_duration("").is_err() && parse_duration("h").is_err() && parse_duration("-1h").is_err() && parse_duration("1w").is_err());
    }

    #[test]
    fn config_defaults() {
        let c: GcConfig = serde_json::from_str("{}").unwrap();
        assert_eq!((c.interval_secs, c.grace_secs, c.dry_run), (0, 86400, false));
    }
}
