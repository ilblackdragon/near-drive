//! Storage configuration, storage classes and replication.
//!
//! A *backend* is one concrete [`BlobStore`] (fs dir, S3 bucket, blob bridge).
//! A *storage class* (`hot`, `bulk`, ...) is an ordered list of backends: a
//! chunk uploaded with that class is written to all of them, and the upload
//! succeeds once `min_successes` writes succeed.
//!
//! Reads are planned from the class, with no per-chunk location state: the
//! index entry records the object's class, and a read tries that class's
//! `backends`, then its `previous` backends (where it lived before a
//! migration), then every other backend as a fallback. Without a class (old
//! entries) the order is: default class first, then the rest. All of this is
//! shared config, so gateways stay stateless.
use crate::{
    bridge::{BridgeBlobStore, BridgeConfig},
    cache::{CacheConfig, ChunkCache},
    s3::{ObjectIndexStore, S3BlobStore, S3Config},
    store::{BlobStore, DirectUrl, FsBlobStore, FsIndexStore, IndexStore},
};
use anyhow::{anyhow, bail, ensure, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ops::Range, path::Path, path::PathBuf, sync::Arc};

pub const DEFAULT_CLASS: &str = "hot";
/// Request header selecting the storage class of an uploaded chunk.
pub const CLASS_HEADER: &str = "x-near-drive-class";

/// `storage` section of the gateway config. Everything is optional: the
/// default is one fs backend at `{data_dir}/chunks`, class `hot` = that
/// backend, fs index at `{data_dir}/index`, no cache.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default)]
    pub backends: BTreeMap<String, BackendConfig>,
    /// class name -> placement. Empty = one class `hot` over all backends.
    #[serde(default)]
    pub classes: BTreeMap<String, ClassConfig>,
    /// Class used when an upload names none (default `hot`).
    #[serde(default)]
    pub default_class: Option<String>,
    #[serde(default)]
    pub index: IndexConfig,
    /// Local read-through chunk cache (useful in front of remote backends).
    #[serde(default)]
    pub cache: Option<CacheConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BackendConfig {
    /// Local directory (default `{data_dir}/chunks`).
    Fs {
        #[serde(default)]
        path: Option<PathBuf>,
    },
    S3(S3Config),
    Bridge(BridgeConfig),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassConfig {
    /// Backend names, in read-preference order.
    pub backends: Vec<String>,
    /// Writes needed for an upload to succeed (default: all backends).
    #[serde(default)]
    pub min_successes: Option<usize>,
    /// Backends this class used before a migration: read after `backends`,
    /// never written. Remove an entry once its data has been copied over.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum IndexConfig {
    /// Single gateway only (process-local lock). Default `{data_dir}/index`.
    Fs {
        #[serde(default)]
        path: Option<PathBuf>,
    },
    /// S3/R2/MinIO with conditional writes; safe for many gateways.
    S3(S3Config),
}

impl Default for IndexConfig {
    fn default() -> Self {
        IndexConfig::Fs { path: None }
    }
}

impl IndexConfig {
    pub fn build(&self, data_dir: &Path) -> Result<Arc<dyn IndexStore>> {
        Ok(match self {
            IndexConfig::Fs { path } => Arc::new(FsIndexStore::new(path.clone().unwrap_or_else(|| data_dir.join("index")))),
            IndexConfig::S3(c) => Arc::new(ObjectIndexStore::new(c)?),
        })
    }
}

impl BackendConfig {
    pub fn build(&self, data_dir: &Path) -> Result<Arc<dyn BlobStore>> {
        Ok(match self {
            BackendConfig::Fs { path } => Arc::new(FsBlobStore::new(path.clone().unwrap_or_else(|| data_dir.join("chunks")))),
            BackendConfig::S3(c) => Arc::new(S3BlobStore::new(c)?),
            BackendConfig::Bridge(c) => Arc::new(BridgeBlobStore::new(c)?),
        })
    }
}

/// A class's write side: writes to every backend; succeeds with at least `min_successes`.
pub struct Replicated {
    backends: Vec<(String, Arc<dyn BlobStore>)>,
    min_successes: usize,
}

impl Replicated {
    pub fn new(backends: Vec<(String, Arc<dyn BlobStore>)>, min_successes: usize) -> Result<Self> {
        ensure!(!backends.is_empty(), "storage class needs at least one backend");
        ensure!((1..=backends.len()).contains(&min_successes), "min_successes must be in 1..={}", backends.len());
        Ok(Self { backends, min_successes })
    }
}

impl Replicated {
    pub async fn put(&self, cid: &str, bytes: Bytes) -> Result<()> {
        let results = futures_util::future::join_all(self.backends.iter().map(|(_, b)| b.put(cid, bytes.clone()))).await;
        let mut errors = vec![];
        for ((name, _), r) in self.backends.iter().zip(results) {
            if let Err(e) = r {
                tracing::warn!("put {cid} to backend {name} failed: {e:#}");
                errors.push(format!("{name}: {e:#}"));
            }
        }
        let ok = self.backends.len() - errors.len();
        if ok < self.min_successes {
            bail!("chunk stored on {ok} of {} backends (need {}): {}", self.backends.len(), self.min_successes, errors.join("; "));
        }
        Ok(())
    }
}

/// Backends to read from, in order. Finding a chunk past the first `primary`
/// backends is logged: the chunk is not where its class says it should be.
pub struct ReadOrder {
    label: String,
    backends: Vec<(String, Arc<dyn BlobStore>)>,
    primary: usize,
}

impl ReadOrder {
    /// Try backends in order; a failing backend is skipped (logged) unless all fail.
    async fn first_some<T, F, Fut>(&self, cid: &str, f: F) -> Result<Option<T>>
    where
        F: Fn(Arc<dyn BlobStore>) -> Fut,
        Fut: std::future::Future<Output = Result<Option<T>>>,
    {
        let mut last_err = None;
        for (i, (name, b)) in self.backends.iter().enumerate() {
            match f(b.clone()).await {
                Ok(Some(v)) => {
                    if i >= self.primary {
                        tracing::info!("chunk {cid} found on backend {name}, outside {}", self.label);
                    }
                    return Ok(Some(v));
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("backend {name}: {e:#}");
                    last_err = Some(e);
                }
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(None),
        }
    }

    async fn get(&self, cid: &str) -> Result<Option<Bytes>> {
        self.first_some(cid, |b| async move { b.get(cid).await }).await
    }

    async fn get_range(&self, cid: &str, range: Range<u64>) -> Result<Option<Bytes>> {
        self.first_some(cid, |b| {
            let r = range.clone();
            async move { b.get_range(cid, r).await }
        })
        .await
    }

    async fn has(&self, cid: &str) -> Result<bool> {
        Ok(self.first_some(cid, |b| async move { Ok(b.has(cid).await?.then_some(())) }).await?.is_some())
    }

    /// From the first backend holding the chunk, if it offers one.
    async fn direct_url(&self, cid: &str) -> Result<Option<DirectUrl>> {
        let found = self.first_some(cid, |b| async move { Ok(b.has(cid).await?.then_some(b)) }).await?;
        match found {
            Some(b) => b.direct_url(cid).await,
            None => Ok(None),
        }
    }
}

/// All storage classes of a gateway plus the read path (with optional cache).
pub struct Placement {
    classes: BTreeMap<String, Replicated>,
    default_class: String,
    /// Per class: its backends, its previous backends, then all others.
    class_reads: BTreeMap<String, ReadOrder>,
    /// No (or an unknown) class: default class first, then all others.
    any_reads: ReadOrder,
    cache: Option<ChunkCache>,
}

#[derive(Debug)]
pub struct UnknownClass(pub String);

impl Placement {
    pub fn from_config(cfg: &StorageConfig, data_dir: &Path) -> Result<Self> {
        let mut backend_cfgs = cfg.backends.clone();
        if backend_cfgs.is_empty() {
            backend_cfgs.insert("local".into(), BackendConfig::Fs { path: None });
        }
        let backends: BTreeMap<String, Arc<dyn BlobStore>> =
            backend_cfgs.iter().map(|(n, c)| Ok((n.clone(), c.build(data_dir)?))).collect::<Result<_>>()?;
        let mut class_cfgs = cfg.classes.clone();
        if class_cfgs.is_empty() {
            class_cfgs.insert(DEFAULT_CLASS.into(), ClassConfig { backends: backends.keys().cloned().collect(), ..Default::default() });
        }
        let default_class = cfg.default_class.clone().unwrap_or_else(|| DEFAULT_CLASS.into());
        ensure!(class_cfgs.contains_key(&default_class), "default storage class {default_class:?} is not configured");

        let pick = |names: &[String]| -> Result<Vec<(String, Arc<dyn BlobStore>)>> {
            names.iter().map(|n| Ok((n.clone(), backends.get(n).ok_or_else(|| anyhow!("unknown backend {n:?}"))?.clone()))).collect()
        };
        // Fallback tail shared by every read order: default class, then all classes, then backends in no class.
        let mut everything: Vec<String> = class_cfgs[&default_class].backends.clone();
        everything.extend(class_cfgs.values().flat_map(|c| c.backends.iter().chain(&c.previous).cloned()));
        everything.extend(backends.keys().cloned());
        let order = |label: String, first: Vec<String>| -> Result<ReadOrder> {
            let mut names = first;
            let primary = dedup(&mut names);
            names.extend(everything.iter().cloned());
            dedup(&mut names);
            Ok(ReadOrder { label, backends: pick(&names)?, primary })
        };

        let mut classes = BTreeMap::new();
        let mut class_reads = BTreeMap::new();
        for (name, c) in &class_cfgs {
            let bs = pick(&c.backends).map_err(|e| anyhow!("class {name}: {e}"))?;
            pick(&c.previous).map_err(|e| anyhow!("class {name} previous: {e}"))?;
            let n = bs.len();
            classes.insert(name.clone(), Replicated::new(bs, c.min_successes.unwrap_or(n)).map_err(|e| anyhow!("class {name}: {e}"))?);
            let first = c.backends.iter().chain(&c.previous).cloned().collect();
            class_reads.insert(name.clone(), order(format!("class {name}"), first)?);
        }
        let any_reads = order(format!("default class {default_class}"), class_cfgs[&default_class].backends.clone())?;
        let cache = cfg.cache.as_ref().map(|c| ChunkCache::open(c, data_dir)).transpose()?;
        Ok(Self { classes, default_class, class_reads, any_reads, cache })
    }

    pub fn default_class(&self) -> &str {
        &self.default_class
    }

    pub fn class_names(&self) -> impl Iterator<Item = &str> {
        self.classes.keys().map(String::as_str)
    }

    pub fn has_class(&self, class: &str) -> bool {
        self.classes.contains_key(class)
    }

    fn reads(&self, class: Option<&str>) -> &ReadOrder {
        class.and_then(|c| self.class_reads.get(c)).unwrap_or(&self.any_reads)
    }

    /// Store a chunk in `class` (None = default class).
    pub async fn put_class(&self, class: Option<&str>, cid: &str, bytes: Bytes) -> Result<Result<(), UnknownClass>> {
        let name = class.unwrap_or(&self.default_class);
        let Some(c) = self.classes.get(name) else { return Ok(Err(UnknownClass(name.to_string()))) };
        c.put(cid, bytes).await?;
        Ok(Ok(()))
    }

    /// Store in the default class.
    pub async fn put(&self, cid: &str, bytes: Bytes) -> Result<()> {
        self.classes[&self.default_class].put(cid, bytes).await
    }

    /// Read a chunk of an object stored with `class` (None: unknown).
    pub async fn get(&self, class: Option<&str>, cid: &str) -> Result<Option<Bytes>> {
        if let Some(c) = &self.cache {
            if let Some(b) = c.get(cid).await {
                return Ok(Some(b));
            }
        }
        let b = self.reads(class).get(cid).await?;
        if let (Some(c), Some(b)) = (&self.cache, &b) {
            c.insert(cid, b).await;
        }
        Ok(b)
    }

    pub async fn get_range(&self, class: Option<&str>, cid: &str, range: Range<u64>) -> Result<Option<Bytes>> {
        if let Some(c) = &self.cache {
            if let Some(b) = c.get_range(cid, range.clone()).await {
                return Ok(Some(b));
            }
            // fill the cache with the whole chunk, then slice
            return Ok(self.get(class, cid).await?.map(|b| crate::store::slice_range(&b, &range)));
        }
        self.reads(class).get_range(cid, range).await
    }

    pub async fn has(&self, class: Option<&str>, cid: &str) -> Result<bool> {
        if let Some(c) = &self.cache {
            if c.contains(cid).await {
                return Ok(true);
            }
        }
        self.reads(class).has(cid).await
    }

    /// Direct-fetch URL from the first backend holding the chunk, if it offers one.
    pub async fn direct_url(&self, class: Option<&str>, cid: &str) -> Result<Option<DirectUrl>> {
        self.reads(class).direct_url(cid).await
    }
}

/// Drop repeated names, keeping the first; returns the new length.
fn dedup(names: &mut Vec<String>) -> usize {
    let mut seen = std::collections::HashSet::new();
    names.retain(|n| seen.insert(n.clone()));
    names.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::{reference_router, ReferenceBridge};

    #[tokio::test]
    async fn classes_replication_and_reads() {
        let dir = tempfile::tempdir().unwrap();
        // a bridge whose backing store we can inspect
        let bridge_dir = dir.path().join("bridge");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let rb = ReferenceBridge { store: Arc::new(FsBlobStore::new(bridge_dir.clone())), token: None, public_base: Some(base.clone()) };
        tokio::spawn(async move { axum::serve(listener, reference_router(rb)).await.unwrap() });

        let cfg: StorageConfig = serde_json::from_value(serde_json::json!({
            "backends": {
                "a": {"type": "fs", "path": dir.path().join("a")},
                "b": {"type": "fs", "path": dir.path().join("b")},
                "fil": {"type": "bridge", "url": base},
                "dead": {"type": "bridge", "url": "http://127.0.0.1:9"}
            },
            "classes": {
                "hot": {"backends": ["a", "b"]},
                "bulk": {"backends": ["fil", "dead"], "min_successes": 1},
                "strict": {"backends": ["fil", "dead"]}
            }
        }))
        .unwrap();
        let p = Placement::from_config(&cfg, dir.path()).unwrap();
        assert_eq!(p.default_class(), "hot");
        let hot = Bytes::from_static(b"hot chunk");
        let hcid = near_drive_core::cid(&hot);
        p.put_class(None, &hcid, hot.clone()).await.unwrap().unwrap();
        let a = FsBlobStore::new(dir.path().join("a"));
        let b = FsBlobStore::new(dir.path().join("b"));
        assert!(a.has(&hcid).await.unwrap() && b.has(&hcid).await.unwrap(), "hot replicates to a and b");
        assert!(p.direct_url(None, &hcid).await.unwrap().is_none(), "fs has no direct url");

        let bulk = Bytes::from_static(b"bulk chunk");
        let bcid = near_drive_core::cid(&bulk);
        p.put_class(Some("bulk"), &bcid, bulk.clone()).await.unwrap().unwrap(); // dead backend tolerated
        assert!(!a.has(&bcid).await.unwrap());
        assert!(FsBlobStore::new(bridge_dir).has(&bcid).await.unwrap());
        assert!(p.put_class(Some("strict"), &bcid, bulk.clone()).await.is_err(), "strict needs both");
        assert!(p.put_class(Some("nope"), &bcid, bulk.clone()).await.unwrap().is_err());

        // reads find chunks regardless of class
        assert_eq!(p.get(None, &bcid).await.unwrap().unwrap(), bulk);
        assert_eq!(p.get_range(None, &bcid, 5..10).await.unwrap().unwrap(), &b"chunk"[..]);
        assert!(p.has(None, &bcid).await.unwrap());
        let u = p.direct_url(Some("bulk"), &bcid).await.unwrap().unwrap();
        assert!(u.url.starts_with(&base));
        // a backend that fails is skipped on read when another has the data
        std::fs::remove_dir_all(dir.path().join("a")).unwrap();
        assert_eq!(p.get(Some("hot"), &hcid).await.unwrap().unwrap(), hot);
        assert!(p.get(None, &near_drive_core::cid(b"missing")).await.is_err(), "dead bridge error surfaces when nobody has it");
    }

    /// Records which backend each read asked, then delegates.
    struct Probe(&'static str, Arc<std::sync::Mutex<Vec<&'static str>>>, FsBlobStore);

    #[async_trait::async_trait]
    impl BlobStore for Probe {
        async fn put(&self, cid: &str, bytes: Bytes) -> Result<()> {
            self.2.put(cid, bytes).await
        }
        async fn get(&self, cid: &str) -> Result<Option<Bytes>> {
            self.1.lock().unwrap().push(self.0);
            self.2.get(cid).await
        }
        async fn has(&self, cid: &str) -> Result<bool> {
            self.1.lock().unwrap().push(self.0);
            self.2.has(cid).await
        }
    }

    #[tokio::test]
    async fn reads_follow_class_then_previous_then_rest() {
        let dir = tempfile::tempdir().unwrap();
        let cfg: StorageConfig = serde_json::from_value(serde_json::json!({
            "backends": {
                "old": {"type": "fs", "path": dir.path().join("old")},
                "new": {"type": "fs", "path": dir.path().join("new")},
                "cold": {"type": "fs", "path": dir.path().join("cold")},
                "spare": {"type": "fs", "path": dir.path().join("spare")}
            },
            "classes": {
                "hot": {"backends": ["new"], "previous": ["old"]},
                "bulk": {"backends": ["cold"]}
            }
        }))
        .unwrap();
        let mut p = Placement::from_config(&cfg, dir.path()).unwrap();
        // Swap in probes so the read order is observable.
        let log = Arc::new(std::sync::Mutex::new(vec![]));
        let probe = |n: &'static str| -> Arc<dyn BlobStore> { Arc::new(Probe(n, log.clone(), FsBlobStore::new(dir.path().join(n)))) };
        for r in p.class_reads.values_mut().chain(std::iter::once(&mut p.any_reads)) {
            for (name, b) in r.backends.iter_mut() {
                *b = probe(Box::leak(name.clone().into_boxed_str()));
            }
        }
        fn names(r: &ReadOrder) -> Vec<&str> {
            r.backends.iter().map(|(n, _)| n.as_str()).collect()
        }
        assert_eq!(names(&p.class_reads["hot"]), ["new", "old", "cold", "spare"]);
        assert_eq!(p.class_reads["hot"].primary, 2);
        assert_eq!(names(&p.class_reads["bulk"]), ["cold", "new", "old", "spare"]);
        assert_eq!(names(&p.any_reads), ["new", "cold", "old", "spare"], "no class: default class first");

        // A chunk still only on the previous backend: found after one miss, no writes go there.
        let data = Bytes::from_static(b"migrating");
        let cid = near_drive_core::cid(&data);
        FsBlobStore::new(dir.path().join("old")).put(&cid, data.clone()).await.unwrap();
        assert_eq!(p.get(Some("hot"), &cid).await.unwrap().unwrap(), data);
        assert_eq!(*log.lock().unwrap(), ["new", "old"]);
        log.lock().unwrap().clear();
        // A bulk object's chunk is looked up on its class's backend first.
        let b = Bytes::from_static(b"weights");
        let bcid = near_drive_core::cid(&b);
        p.put_class(Some("bulk"), &bcid, b.clone()).await.unwrap().unwrap();
        assert!(p.has(Some("bulk"), &bcid).await.unwrap());
        assert_eq!(*log.lock().unwrap(), ["cold"]);
        log.lock().unwrap().clear();
        // Unknown / removed class: same order as no class; misplaced chunks are still found.
        assert_eq!(p.get(Some("gone"), &bcid).await.unwrap().unwrap(), b);
        assert_eq!(*log.lock().unwrap(), ["new", "cold"]);
        assert!(!FsBlobStore::new(dir.path().join("old")).has(&bcid).await.unwrap(), "previous backends are never written");
    }

    #[test]
    fn config_validation() {
        let d = Path::new("/tmp/x");
        let bad: StorageConfig = serde_json::from_str(r#"{"backends":{"a":{"type":"fs"}},"classes":{"bulk":{"backends":["a"]}}}"#).unwrap();
        assert!(Placement::from_config(&bad, d).is_err(), "no hot class");
        let bad: StorageConfig = serde_json::from_str(r#"{"classes":{"hot":{"backends":["zzz"]}}}"#).unwrap();
        assert!(Placement::from_config(&bad, d).is_err(), "unknown backend");
        let bad: StorageConfig = serde_json::from_str(r#"{"classes":{"hot":{"backends":["local"],"min_successes":2}}}"#).unwrap();
        assert!(Placement::from_config(&bad, d).is_err(), "min_successes too large");
        let bad: StorageConfig = serde_json::from_str(r#"{"classes":{"hot":{"backends":["local"],"previous":["zzz"]}}}"#).unwrap();
        assert!(Placement::from_config(&bad, d).is_err(), "unknown previous backend");
        let ok: StorageConfig = serde_json::from_str("{}").unwrap();
        let p = Placement::from_config(&ok, d).unwrap();
        assert_eq!(p.class_names().collect::<Vec<_>>(), vec!["hot"]);
    }
}
