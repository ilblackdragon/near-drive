//! Storage traits and filesystem implementations (dev / single node).
//! Production: S3/R2 index store with conditional writes; FOC/Shelby/R2 blobs.
use anyhow::{anyhow, Result};
use nstorage_core::record::PointerRecord;
use std::path::PathBuf;
use tokio::sync::Mutex;

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

pub trait BlobStore: Send + Sync {
    fn put(&self, cid: &str, bytes: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send;
    fn get(&self, cid: &str) -> impl std::future::Future<Output = Result<Option<Vec<u8>>>> + Send;
    fn has(&self, cid: &str) -> impl std::future::Future<Output = Result<bool>> + Send;
}

pub trait IndexStore: Send + Sync {
    fn get(&self, ns: &str, path: &str) -> impl std::future::Future<Output = Result<Option<PointerRecord>>> + Send;
    /// Store `rec` iff the current seq equals `rec.seq - 1` (0 = absent).
    fn cas_put(&self, rec: &PointerRecord) -> impl std::future::Future<Output = Result<(), CasError>> + Send;
    /// Delete iff current seq == `expected_seq`.
    fn delete(&self, ns: &str, path: &str, expected_seq: u64) -> impl std::future::Future<Output = Result<(), CasError>> + Send;
    fn list(&self, ns: &str, prefix: &str) -> impl std::future::Future<Output = Result<Vec<PointerRecord>>> + Send;
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

async fn write_atomic(path: &PathBuf, bytes: &[u8]) -> Result<()> {
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

impl BlobStore for FsBlobStore {
    async fn put(&self, cid: &str, bytes: &[u8]) -> Result<()> {
        let p = self.path(cid)?;
        if tokio::fs::try_exists(&p).await? {
            return Ok(()); // content-addressed: already there
        }
        write_atomic(&p, bytes).await
    }
    async fn get(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        match tokio::fs::read(self.path(cid)?).await {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    async fn has(&self, cid: &str) -> Result<bool> {
        Ok(tokio::fs::try_exists(self.path(cid)?).await?)
    }
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
