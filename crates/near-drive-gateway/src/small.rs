//! Small-object cache: makes small files cheap to write and read.
//!
//! A small file is three blobs (data chunk, manifest, index entry). Without a
//! cache, a read is an index lookup plus two backend round trips, and a write
//! re-reads the manifest and checks every chunk on the backends. This module:
//!
//! - keeps small content-addressed blobs (manifests and small chunks) in
//!   memory, LRU-bounded. Blobs are immutable, so there is nothing to
//!   invalidate. Uploads write through, so the commit right after an upload
//!   finds its manifest and chunks in memory;
//! - optionally caches index entries for `index_ttl_ms`. Writes and deletes
//!   through this gateway update the cache; with several gateways sharing an
//!   index, a read can be up to the TTL stale, so it is off by default;
//! - lets `?mode=locate` inline the chunks of objects up to
//!   `inline_max_bytes`, so a small read is a single request.
use crate::store::{CasError, IndexEntry, IndexStore};
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SmallCacheConfig {
    /// Memory for small blobs; 0 turns the blob cache off.
    pub max_bytes: u64,
    /// Largest blob kept in memory.
    pub max_item_bytes: u64,
    /// `?mode=locate` inlines the chunks of objects whose stored size is at
    /// most this; 0 turns inlining off.
    pub inline_max_bytes: u64,
    /// Cache index entries this long; 0 (default) = off. Safe to raise when
    /// this is the only gateway writing the index.
    pub index_ttl_ms: u64,
    /// Most index entries kept.
    pub index_max_entries: usize,
}

impl Default for SmallCacheConfig {
    fn default() -> Self {
        Self { max_bytes: 64 << 20, max_item_bytes: 256 << 10, inline_max_bytes: 64 << 10, index_ttl_ms: 0, index_max_entries: 100_000 }
    }
}

#[derive(Default)]
struct Lru {
    total: u64,
    tick: u64,
    entries: HashMap<String, (Bytes, u64)>,
    order: BTreeMap<u64, String>,
}

/// In-memory LRU of small content-addressed blobs.
pub struct MemCache {
    max_bytes: u64,
    max_item: u64,
    lru: Mutex<Lru>,
}

impl MemCache {
    pub fn new(cfg: &SmallCacheConfig) -> Option<Self> {
        (cfg.max_bytes > 0 && cfg.max_item_bytes > 0).then(|| Self { max_bytes: cfg.max_bytes, max_item: cfg.max_item_bytes.min(cfg.max_bytes), lru: Mutex::default() })
    }

    pub fn get(&self, cid: &str) -> Option<Bytes> {
        let mut l = self.lru.lock().unwrap();
        let l = &mut *l;
        let (b, t) = l.entries.get_mut(cid)?;
        l.order.remove(t);
        l.tick += 1;
        *t = l.tick;
        l.order.insert(l.tick, cid.to_string());
        Some(b.clone())
    }

    pub fn contains(&self, cid: &str) -> bool {
        self.lru.lock().unwrap().entries.contains_key(cid)
    }

    /// Keep `bytes` if small enough. Callers pass bytes already verified
    /// against `cid` (uploads are checked; backend reads are re-checked here).
    pub fn insert(&self, cid: &str, bytes: &Bytes, verified: bool) {
        let size = bytes.len() as u64;
        if size > self.max_item || (!verified && near_drive_core::cid(bytes) != cid) {
            return;
        }
        let mut l = self.lru.lock().unwrap();
        if l.entries.contains_key(cid) {
            return;
        }
        l.tick += 1;
        let t = l.tick;
        l.entries.insert(cid.to_string(), (bytes.clone(), t));
        l.order.insert(t, cid.to_string());
        l.total += size;
        while l.total > self.max_bytes {
            let Some((_, victim)) = l.order.pop_first() else { break };
            let (b, _) = l.entries.remove(&victim).expect("lru consistent");
            l.total -= b.len() as u64;
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.lru.lock().unwrap().total
    }

    /// Drop a blob (garbage collection deleted it from the backends).
    pub fn remove(&self, cid: &str) {
        let mut l = self.lru.lock().unwrap();
        if let Some((b, t)) = l.entries.remove(cid) {
            l.order.remove(&t);
            l.total -= b.len() as u64;
        }
    }
}

/// When it was fetched, and the entry (None = known absent).
type Cached = (Instant, Option<IndexEntry>);

/// Index store wrapper caching `get` for a TTL (positive and negative hits).
pub struct CachedIndex {
    inner: Arc<dyn IndexStore>,
    ttl: Duration,
    max_entries: usize,
    map: Mutex<HashMap<(String, String), Cached>>,
}

impl CachedIndex {
    /// `inner` unchanged when the TTL is 0.
    pub fn wrap(inner: Arc<dyn IndexStore>, cfg: &SmallCacheConfig) -> Arc<dyn IndexStore> {
        if cfg.index_ttl_ms == 0 {
            return inner;
        }
        Arc::new(Self { inner, ttl: Duration::from_millis(cfg.index_ttl_ms), max_entries: cfg.index_max_entries.max(1), map: Mutex::default() })
    }

    fn put(&self, ns: &str, path: &str, v: Option<IndexEntry>) {
        let mut m = self.map.lock().unwrap();
        if m.len() >= self.max_entries {
            let ttl = self.ttl;
            m.retain(|_, (t, _)| t.elapsed() < ttl);
            if m.len() >= self.max_entries {
                m.clear();
            }
        }
        m.insert((ns.to_string(), path.to_string()), (Instant::now(), v));
    }

    fn forget(&self, ns: &str, path: &str) {
        self.map.lock().unwrap().remove(&(ns.to_string(), path.to_string()));
    }
}

#[async_trait]
impl IndexStore for CachedIndex {
    async fn get(&self, ns: &str, path: &str) -> Result<Option<IndexEntry>> {
        if let Some((t, v)) = self.map.lock().unwrap().get(&(ns.to_string(), path.to_string())) {
            if t.elapsed() < self.ttl {
                return Ok(v.clone());
            }
        }
        let v = self.inner.get(ns, path).await?;
        self.put(ns, path, v.clone());
        Ok(v)
    }

    async fn cas_put(&self, rec: &IndexEntry) -> Result<(), CasError> {
        let r = self.inner.cas_put(rec).await;
        match &r {
            Ok(()) => self.put(&rec.namespace, &rec.path, Some(rec.clone())),
            Err(_) => self.forget(&rec.namespace, &rec.path),
        }
        r
    }

    async fn delete(&self, ns: &str, path: &str, expected_seq: u64) -> Result<(), CasError> {
        let r = self.inner.delete(ns, path, expected_seq).await;
        match &r {
            Ok(()) => self.put(ns, path, None),
            Err(_) => self.forget(ns, path),
        }
        r
    }

    async fn list(&self, ns: &str, prefix: &str) -> Result<Vec<IndexEntry>> {
        self.inner.list(ns, prefix).await
    }

    async fn namespaces(&self) -> Result<Vec<String>> {
        self.inner.namespaces().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::FsIndexStore;
    use ed25519_dalek::SigningKey;
    use near_drive_core::record::PointerRecord;

    #[test]
    fn mem_lru() {
        let c = MemCache::new(&SmallCacheConfig { max_bytes: 250, max_item_bytes: 120, ..Default::default() }).unwrap();
        let b = |i: u8| Bytes::from(vec![i; 100]);
        let cid = |i: u8| near_drive_core::cid(&b(i));
        c.insert(&cid(1), &b(1), false);
        c.insert(&cid(2), &b(2), false);
        assert_eq!(c.get(&cid(1)).unwrap(), b(1));
        c.insert(&cid(3), &b(3), false); // evicts 2 (least recent)
        assert!(c.get(&cid(2)).is_none() && c.contains(&cid(1)) && c.contains(&cid(3)));
        assert_eq!(c.total_bytes(), 200);
        c.insert(&cid(4), &b(5), false);
        assert!(!c.contains(&cid(4)), "wrong content never cached");
        let big = Bytes::from(vec![7; 121]);
        c.insert(&near_drive_core::cid(&big), &big, true);
        assert!(!c.contains(&near_drive_core::cid(&big)), "over max_item_bytes");
        assert!(MemCache::new(&SmallCacheConfig { max_bytes: 0, ..Default::default() }).is_none());
    }

    #[tokio::test]
    async fn index_ttl() {
        let dir = tempfile::tempdir().unwrap();
        let fs: Arc<dyn IndexStore> = Arc::new(FsIndexStore::new(dir.path().to_path_buf()));
        let cached = CachedIndex::wrap(fs.clone(), &SmallCacheConfig { index_ttl_ms: 60_000, ..Default::default() });
        let sk = SigningKey::from_bytes(&[3; 32]);
        let e = |seq| IndexEntry { record: PointerRecord::new_signed("a.near", "p", &near_drive_core::cid(b"m"), 1, 2, seq, "a.near", &sk, 1), class: None };
        assert!(cached.get("a.near", "p").await.unwrap().is_none());
        fs.cas_put(&e(1)).await.unwrap(); // behind the cache's back (another gateway)
        assert!(cached.get("a.near", "p").await.unwrap().is_none(), "negative hit within TTL");
        // a write through this gateway conflicts, invalidates, and the next read sees the truth
        assert!(cached.cas_put(&e(1)).await.is_err());
        assert_eq!(cached.get("a.near", "p").await.unwrap().unwrap().seq, 1);
        cached.cas_put(&e(2)).await.unwrap();
        assert_eq!(cached.get("a.near", "p").await.unwrap().unwrap().seq, 2);
        cached.delete("a.near", "p", 2).await.unwrap();
        assert!(cached.get("a.near", "p").await.unwrap().is_none());
        let off = CachedIndex::wrap(fs.clone(), &SmallCacheConfig::default());
        assert!(Arc::ptr_eq(&off, &fs), "TTL 0 = no wrapper");
    }
}
