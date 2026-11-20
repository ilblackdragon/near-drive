//! Bounded read-through chunk cache on local disk. Chunks are immutable and
//! content-addressed, so caching needs no invalidation; entries are verified
//! (blake3) before insertion and evicted least-recently-used.
use crate::store::{read_file_range, write_atomic};
use anyhow::Result;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    ops::Range,
    path::{Path, PathBuf},
};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Default `{data_dir}/cache`.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// Total bytes kept on disk.
    pub max_bytes: u64,
}

#[derive(Default)]
struct Lru {
    total: u64,
    tick: u64,
    /// cid -> (size, last-use tick)
    entries: HashMap<String, (u64, u64)>,
    /// last-use tick -> cid
    order: BTreeMap<u64, String>,
}

impl Lru {
    fn touch(&mut self, cid: &str) -> bool {
        let Some((_, t)) = self.entries.get_mut(cid) else { return false };
        self.order.remove(t);
        self.tick += 1;
        *t = self.tick;
        self.order.insert(self.tick, cid.to_string());
        true
    }
    fn remove(&mut self, cid: &str) {
        if let Some((size, t)) = self.entries.remove(cid) {
            self.order.remove(&t);
            self.total -= size;
        }
    }
}

pub struct ChunkCache {
    dir: PathBuf,
    max_bytes: u64,
    lru: Mutex<Lru>,
}

impl ChunkCache {
    /// Opens (and indexes) an existing cache directory.
    pub fn open(cfg: &CacheConfig, data_dir: &Path) -> Result<Self> {
        let dir = cfg.path.clone().unwrap_or_else(|| data_dir.join("cache"));
        std::fs::create_dir_all(&dir)?;
        let mut files = vec![];
        for e in std::fs::read_dir(&dir)?.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Ok(md) = e.metadata() else { continue };
            if name.starts_with(".tmp-") {
                let _ = std::fs::remove_file(e.path());
                continue;
            }
            let cid = format!("b3:{name}");
            if md.is_file() && near_drive_core::is_valid_cid(&cid) {
                files.push((md.modified().ok(), cid, md.len()));
            }
        }
        files.sort();
        let mut lru = Lru::default();
        for (_, cid, size) in files {
            lru.tick += 1;
            lru.total += size;
            lru.order.insert(lru.tick, cid.clone());
            lru.entries.insert(cid, (size, lru.tick));
        }
        let c = Self { dir, max_bytes: cfg.max_bytes, lru: Mutex::new(lru) };
        Ok(c)
    }

    fn file(&self, cid: &str) -> PathBuf {
        self.dir.join(&cid[3..])
    }

    pub async fn contains(&self, cid: &str) -> bool {
        self.lru.lock().await.entries.contains_key(cid)
    }

    pub async fn get(&self, cid: &str) -> Option<Bytes> {
        if !self.lru.lock().await.touch(cid) {
            return None;
        }
        match tokio::fs::read(self.file(cid)).await {
            Ok(b) => Some(b.into()),
            Err(_) => {
                self.lru.lock().await.remove(cid);
                None
            }
        }
    }

    pub async fn get_range(&self, cid: &str, range: Range<u64>) -> Option<Bytes> {
        if !self.lru.lock().await.touch(cid) {
            return None;
        }
        match read_file_range(&self.file(cid), range).await {
            Ok(Some(b)) => Some(b),
            _ => {
                self.lru.lock().await.remove(cid);
                None
            }
        }
    }

    /// Insert a chunk fetched from a backend (verified against its cid).
    pub async fn insert(&self, cid: &str, bytes: &Bytes) {
        let size = bytes.len() as u64;
        if size > self.max_bytes / 2 || !near_drive_core::is_valid_cid(cid) || near_drive_core::cid(bytes) != cid {
            return;
        }
        if self.contains(cid).await {
            return;
        }
        if let Err(e) = write_atomic(&self.file(cid), bytes).await {
            tracing::warn!("chunk cache write failed: {e:#}");
            return;
        }
        let mut evict = vec![];
        {
            let mut lru = self.lru.lock().await;
            if lru.entries.contains_key(cid) {
                return;
            }
            lru.tick += 1;
            let t = lru.tick;
            lru.entries.insert(cid.to_string(), (size, t));
            lru.order.insert(t, cid.to_string());
            lru.total += size;
            while lru.total > self.max_bytes {
                let Some((_, victim)) = lru.order.pop_first() else { break };
                let (vsize, _) = lru.entries.remove(&victim).expect("lru consistent");
                lru.total -= vsize;
                evict.push(victim);
            }
        }
        for v in evict {
            let _ = tokio::fs::remove_file(self.file(&v)).await;
        }
    }

    /// Drop a chunk (garbage collection deleted it from the backends).
    pub async fn remove(&self, cid: &str) {
        let had = {
            let mut lru = self.lru.lock().await;
            let had = lru.entries.contains_key(cid);
            lru.remove(cid);
            had
        };
        if had {
            let _ = tokio::fs::remove_file(self.file(cid)).await;
        }
    }

    pub async fn total_bytes(&self) -> u64 {
        self.lru.lock().await.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lru_eviction_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = CacheConfig { path: Some(dir.path().to_path_buf()), max_bytes: 250 };
        let c = ChunkCache::open(&cfg, dir.path()).unwrap();
        let chunk = |i: u8| Bytes::from(vec![i; 100]);
        let cid = |i: u8| near_drive_core::cid(&chunk(i));
        c.insert(&cid(1), &chunk(1)).await;
        c.insert(&cid(2), &chunk(2)).await;
        assert_eq!(c.get(&cid(1)).await.unwrap(), chunk(1)); // 1 is now most recent
        c.insert(&cid(3), &chunk(3)).await; // evicts 2
        assert!(c.get(&cid(2)).await.is_none());
        assert_eq!(c.get_range(&cid(3), 10..20).await.unwrap(), chunk(3).slice(10..20));
        assert_eq!(c.total_bytes().await, 200);
        // wrong content is never cached
        c.insert(&cid(4), &chunk(5)).await;
        assert!(!c.contains(&cid(4)).await);
        // too large for this cache
        let big = Bytes::from(vec![9u8; 200]);
        c.insert(&near_drive_core::cid(&big), &big).await;
        assert!(!c.contains(&near_drive_core::cid(&big)).await);
        drop(c);
        let c = ChunkCache::open(&cfg, dir.path()).unwrap();
        assert_eq!(c.total_bytes().await, 200);
        assert!(c.contains(&cid(1)).await && c.contains(&cid(3)).await);
    }
}
