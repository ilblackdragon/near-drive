//! Storage configuration, storage classes and replication.
//!
//! A *backend* is one concrete [`BlobStore`] (fs dir, S3 bucket, blob bridge).
//! A *storage class* (`hot`, `bulk`, ...) is an ordered list of backends: a
//! chunk uploaded with that class is written to all of them, and the upload
//! succeeds once `min_successes` writes succeed. Reads do not need to know the
//! class: [`Placement`] tries every backend (default class first) until one
//! has the chunk.
use crate::{
    bridge::{BridgeBlobStore, BridgeConfig},
    cache::{CacheConfig, ChunkCache},
    s3::{ObjectIndexStore, S3BlobStore, S3Config},
    store::{BlobStore, DirectUrl, FsBlobStore, FsIndexStore, IndexStore},
};
use anyhow::{anyhow, bail, ensure, Result};
use async_trait::async_trait;
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

/// Writes to every backend; succeeds with at least `min_successes`.
/// Reads from the first backend that has the chunk.
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

#[async_trait]
impl BlobStore for Replicated {
    async fn put(&self, cid: &str, bytes: Bytes) -> Result<()> {
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
    async fn get(&self, cid: &str) -> Result<Option<Bytes>> {
        first_some(&self.backends, |b| async move { b.get(cid).await }).await
    }
    async fn get_range(&self, cid: &str, range: Range<u64>) -> Result<Option<Bytes>> {
        first_some(&self.backends, |b| {
            let r = range.clone();
            async move { b.get_range(cid, r).await }
        })
        .await
    }
    async fn has(&self, cid: &str) -> Result<bool> {
        Ok(first_some(&self.backends, |b| async move { Ok(b.has(cid).await?.then_some(())) }).await?.is_some())
    }
    async fn direct_url(&self, cid: &str) -> Result<Option<DirectUrl>> {
        for (_, b) in &self.backends {
            if b.has(cid).await.unwrap_or(false) {
                return b.direct_url(cid).await;
            }
        }
        Ok(None)
    }
}

/// Try backends in order; a failing backend is skipped (logged) unless all fail.
async fn first_some<T, F, Fut>(backends: &[(String, Arc<dyn BlobStore>)], f: F) -> Result<Option<T>>
where
    F: Fn(Arc<dyn BlobStore>) -> Fut,
    Fut: std::future::Future<Output = Result<Option<T>>>,
{
    let mut last_err = None;
    for (name, b) in backends {
        match f(b.clone()).await {
            Ok(Some(v)) => return Ok(Some(v)),
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

/// All storage classes of a gateway plus the read path (with optional cache).
pub struct Placement {
    classes: BTreeMap<String, Replicated>,
    default_class: String,
    /// Every distinct backend, default class first; used for reads.
    readers: Replicated,
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
            class_cfgs.insert(DEFAULT_CLASS.into(), ClassConfig { backends: backends.keys().cloned().collect(), min_successes: None });
        }
        let default_class = cfg.default_class.clone().unwrap_or_else(|| DEFAULT_CLASS.into());
        ensure!(class_cfgs.contains_key(&default_class), "default storage class {default_class:?} is not configured");

        let pick = |names: &[String]| -> Result<Vec<(String, Arc<dyn BlobStore>)>> {
            names.iter().map(|n| Ok((n.clone(), backends.get(n).ok_or_else(|| anyhow!("unknown backend {n:?}"))?.clone()))).collect()
        };
        let mut classes = BTreeMap::new();
        let mut read_order: Vec<String> = class_cfgs[&default_class].backends.clone();
        for (name, c) in &class_cfgs {
            let bs = pick(&c.backends).map_err(|e| anyhow!("class {name}: {e}"))?;
            let n = bs.len();
            classes.insert(name.clone(), Replicated::new(bs, c.min_successes.unwrap_or(n)).map_err(|e| anyhow!("class {name}: {e}"))?);
            read_order.extend(c.backends.iter().cloned());
        }
        // backends in no class are still read (e.g. during a migration)
        read_order.extend(backends.keys().cloned());
        let mut seen = std::collections::HashSet::new();
        read_order.retain(|n| seen.insert(n.clone()));
        let readers = Replicated::new(pick(&read_order)?, 1)?;
        let cache = cfg.cache.as_ref().map(|c| ChunkCache::open(c, data_dir)).transpose()?;
        Ok(Self { classes, default_class, readers, cache })
    }

    pub fn default_class(&self) -> &str {
        &self.default_class
    }

    pub fn class_names(&self) -> impl Iterator<Item = &str> {
        self.classes.keys().map(String::as_str)
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

    pub async fn get(&self, cid: &str) -> Result<Option<Bytes>> {
        if let Some(c) = &self.cache {
            if let Some(b) = c.get(cid).await {
                return Ok(Some(b));
            }
        }
        let b = self.readers.get(cid).await?;
        if let (Some(c), Some(b)) = (&self.cache, &b) {
            c.insert(cid, b).await;
        }
        Ok(b)
    }

    pub async fn get_range(&self, cid: &str, range: Range<u64>) -> Result<Option<Bytes>> {
        if let Some(c) = &self.cache {
            if let Some(b) = c.get_range(cid, range.clone()).await {
                return Ok(Some(b));
            }
            // fill the cache with the whole chunk, then slice
            return Ok(self.get(cid).await?.map(|b| crate::store::slice_range(&b, &range)));
        }
        self.readers.get_range(cid, range).await
    }

    pub async fn has(&self, cid: &str) -> Result<bool> {
        if let Some(c) = &self.cache {
            if c.contains(cid).await {
                return Ok(true);
            }
        }
        self.readers.has(cid).await
    }

    /// Direct-fetch URL from the first backend holding the chunk, if it offers one.
    pub async fn direct_url(&self, cid: &str) -> Result<Option<DirectUrl>> {
        self.readers.direct_url(cid).await
    }
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
        assert!(p.direct_url(&hcid).await.unwrap().is_none(), "fs has no direct url");

        let bulk = Bytes::from_static(b"bulk chunk");
        let bcid = near_drive_core::cid(&bulk);
        p.put_class(Some("bulk"), &bcid, bulk.clone()).await.unwrap().unwrap(); // dead backend tolerated
        assert!(!a.has(&bcid).await.unwrap());
        assert!(FsBlobStore::new(bridge_dir).has(&bcid).await.unwrap());
        assert!(p.put_class(Some("strict"), &bcid, bulk.clone()).await.is_err(), "strict needs both");
        assert!(p.put_class(Some("nope"), &bcid, bulk.clone()).await.unwrap().is_err());

        // reads find chunks regardless of class
        assert_eq!(p.get(&bcid).await.unwrap().unwrap(), bulk);
        assert_eq!(p.get_range(&bcid, 5..10).await.unwrap().unwrap(), &b"chunk"[..]);
        assert!(p.has(&bcid).await.unwrap());
        let u = p.direct_url(&bcid).await.unwrap().unwrap();
        assert!(u.url.starts_with(&base));
        // a backend that fails is skipped on read when another has the data
        std::fs::remove_dir_all(dir.path().join("a")).unwrap();
        assert_eq!(p.get(&hcid).await.unwrap().unwrap(), hot);
        assert!(p.get(&near_drive_core::cid(b"missing")).await.is_err(), "dead bridge error surfaces when nobody has it");
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
        let ok: StorageConfig = serde_json::from_str("{}").unwrap();
        let p = Placement::from_config(&ok, d).unwrap();
        assert_eq!(p.class_names().collect::<Vec<_>>(), vec!["hot"]);
    }
}
