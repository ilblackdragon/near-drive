//! Storage traits and filesystem implementations (dev / single node).
//! Other backends: `s3` (S3/R2/MinIO), `bridge` (HTTP blob bridge), `placement`, `cache`.
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use nstorage_core::record::PointerRecord;
use serde::{Deserialize, Serialize};
use std::{ops::Range, path::PathBuf};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::Mutex,
};

#[derive(Debug)]
pub enum CasError {
    /// Stored seq differs from the expected previous seq.
    Conflict { current: u64 },
    Other(anyhow::Error),
}

impl From<anyhow::Error> for CasError {
    fn from(e: anyhow::Error) -> Self {
        CasError::Other(e)
    }
}

/// A direct-fetch URL for a chunk (presigned S3 URL, bridge CDN URL, ...).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirectUrl {
    pub url: String,
    /// Unix ms after which the URL stops working; None = does not expire.
    pub expires_ms: Option<u64>,
}

/// Content-addressed chunk storage (DESIGN.md §3.1 L0). Implementations:
/// fs ([`FsBlobStore`]), S3/R2/MinIO ([`crate::s3::S3BlobStore`]), HTTP blob
/// bridge ([`crate::bridge::BridgeBlobStore`]), and the combinators
/// [`crate::placement::Replicated`] / [`crate::cache::CachedBlobStore`].
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Idempotent: storing an existing cid is a no-op success.
    async fn put(&self, cid: &str, bytes: Bytes) -> Result<()>;
    async fn get(&self, cid: &str) -> Result<Option<Bytes>>;
    /// Bytes `[range.start, min(range.end, len))`; None if the chunk is absent.
    async fn get_range(&self, cid: &str, range: Range<u64>) -> Result<Option<Bytes>> {
        Ok(self.get(cid).await?.map(|b| slice_range(&b, &range)))
    }
    async fn has(&self, cid: &str) -> Result<bool>;
    /// A URL a client can fetch the chunk from without going through the gateway.
    async fn direct_url(&self, _cid: &str) -> Result<Option<DirectUrl>> {
        Ok(None)
    }
}

/// Clamp `range` to `b` and slice.
pub fn slice_range(b: &Bytes, range: &Range<u64>) -> Bytes {
    let len = b.len() as u64;
    let s = range.start.min(len) as usize;
    let e = range.end.clamp(range.start.min(len), len) as usize;
    b.slice(s..e)
}

/// Mutable pointer-record index (DESIGN.md §3.2). Implementations: fs
/// ([`FsIndexStore`], single gateway) and object-store / S3 with conditional
/// writes ([`crate::s3::ObjectIndexStore`], safe with many gateways).
#[async_trait]
pub trait IndexStore: Send + Sync {
    async fn get(&self, ns: &str, path: &str) -> Result<Option<PointerRecord>>;
    /// Store `rec` iff the current seq equals `rec.seq - 1` (0 = absent).
    async fn cas_put(&self, rec: &PointerRecord) -> Result<(), CasError>;
    /// Delete iff current seq == `expected_seq`.
    async fn delete(&self, ns: &str, path: &str, expected_seq: u64) -> Result<(), CasError>;
    /// All live records in `ns` whose path starts with `prefix`, sorted by path.
    async fn list(&self, ns: &str, prefix: &str) -> Result<Vec<PointerRecord>>;
}

pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
    fn path(&self, cid: &str) -> Result<PathBuf> {
        if !nstorage_core::is_valid_cid(cid) {
            return Err(anyhow!("bad cid"));
        }
        let h = &cid[3..];
        Ok(self.root.join(&h[..2]).join(&h[2..4]).join(h))
    }
}

pub(crate) async fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap();
    tokio::fs::create_dir_all(dir).await?;
    let tmp = dir.join(format!(".tmp-{}", rand_suffix()));
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

fn rand_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    format!("{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed))
}

#[async_trait]
impl BlobStore for FsBlobStore {
    async fn put(&self, cid: &str, bytes: Bytes) -> Result<()> {
        let p = self.path(cid)?;
        if tokio::fs::try_exists(&p).await? {
            return Ok(()); // content-addressed: already there
        }
        write_atomic(&p, &bytes).await
    }
    async fn get(&self, cid: &str) -> Result<Option<Bytes>> {
        match tokio::fs::read(self.path(cid)?).await {
            Ok(b) => Ok(Some(b.into())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    async fn get_range(&self, cid: &str, range: Range<u64>) -> Result<Option<Bytes>> {
        read_file_range(&self.path(cid)?, range).await
    }
    async fn has(&self, cid: &str) -> Result<bool> {
        Ok(tokio::fs::try_exists(self.path(cid)?).await?)
    }
}

/// Read `[start, min(end, len))` of a file; None if it does not exist.
pub(crate) async fn read_file_range(path: &std::path::Path, range: Range<u64>) -> Result<Option<Bytes>> {
    let mut f = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let len = f.metadata().await?.len();
    let start = range.start.min(len);
    let end = range.end.clamp(start, len);
    f.seek(std::io::SeekFrom::Start(start)).await?;
    let mut buf = vec![0u8; (end - start) as usize];
    f.read_exact(&mut buf).await?;
    Ok(Some(buf.into()))
}

/// One file per record, named hex(path), under `<root>/<namespace>/`.
/// A process-wide lock provides CAS; fine for a single dev gateway only.
pub struct FsIndexStore {
    root: PathBuf,
    lock: Mutex<()>,
}

impl FsIndexStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root, lock: Mutex::new(()) }
    }
    fn file(&self, ns: &str, path: &str) -> PathBuf {
        self.root.join(ns).join(hex::encode(path))
    }
    async fn read(&self, ns: &str, path: &str) -> Result<Option<PointerRecord>> {
        match tokio::fs::read(self.file(ns, path)).await {
            Ok(b) => Ok(Some(serde_json::from_slice(&b)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

#[async_trait]
impl IndexStore for FsIndexStore {
    async fn get(&self, ns: &str, path: &str) -> Result<Option<PointerRecord>> {
        self.read(ns, path).await
    }
    async fn cas_put(&self, rec: &PointerRecord) -> Result<(), CasError> {
        let _g = self.lock.lock().await;
        let current = self.read(&rec.namespace, &rec.path).await?.map(|r| r.seq).unwrap_or(0);
        if current + 1 != rec.seq {
            return Err(CasError::Conflict { current });
        }
        write_atomic(&self.file(&rec.namespace, &rec.path), &serde_json::to_vec(rec).map_err(anyhow::Error::from)?).await?;
        Ok(())
    }
    async fn delete(&self, ns: &str, path: &str, expected_seq: u64) -> Result<(), CasError> {
        let _g = self.lock.lock().await;
        let current = self.read(ns, path).await?.map(|r| r.seq).unwrap_or(0);
        if current != expected_seq {
            return Err(CasError::Conflict { current });
        }
        tokio::fs::remove_file(self.file(ns, path)).await.map_err(anyhow::Error::from)?;
        Ok(())
    }
    async fn list(&self, ns: &str, prefix: &str) -> Result<Vec<PointerRecord>> {
        let dir = self.root.join(ns);
        let mut rd = match tokio::fs::read_dir(&dir).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let mut out = vec![];
        while let Some(e) = rd.next_entry().await? {
            let name = e.file_name().to_string_lossy().to_string();
            let Ok(p) = hex::decode(&name).map(|b| String::from_utf8_lossy(&b).to_string()) else { continue };
            if p.starts_with(prefix) {
                if let Some(r) = self.read(ns, &p).await? {
                    out.push(r);
                }
            }
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }
}
