//! Storage traits and filesystem implementations (dev / single node).
//! Other backends: `s3` (S3/R2/MinIO), `bridge` (HTTP blob bridge), `placement`, `cache`.
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::TryStreamExt;
use near_drive_core::record::PointerRecord;
use serde::{Deserialize, Serialize};
use futures_util::stream::BoxStream;
use std::{
    ops::Range,
    path::PathBuf,
    time::SystemTime,
};
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
    /// Every chunk this backend holds (for garbage collection), in no
    /// particular order. None: the backend cannot enumerate its chunks.
    fn list(&self) -> Option<BoxStream<'_, Result<ChunkInfo>>> {
        None
    }
    /// Garbage collection: delete the chunk iff it was last written before
    /// `cutoff` (re-checked right before deleting, so a concurrent re-upload
    /// that refreshed it keeps it). Returns whether it was deleted; a missing
    /// chunk is `Ok(false)`. Only backends that implement `list` need this.
    async fn delete_if_older(&self, _cid: &str, _cutoff: SystemTime) -> Result<bool> {
        Err(anyhow!("backend does not support deleting chunks"))
    }
}

/// One stored chunk, as listed by [`BlobStore::list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkInfo {
    pub cid: String,
    pub size: u64,
    /// Last write (fs mtime, S3 `Last-Modified`). Re-uploading an existing
    /// chunk refreshes it, which is what the GC grace period relies on.
    pub modified: SystemTime,
}

/// Clamp `range` to `b` and slice.
pub fn slice_range(b: &Bytes, range: &Range<u64>) -> Bytes {
    let len = b.len() as u64;
    let s = range.start.min(len) as usize;
    let e = range.end.clamp(range.start.min(len), len) as usize;
    b.slice(s..e)
}

/// What the index holds per object: the writer-signed record plus fields the
/// gateway adds (not covered by the record signature). Serialized flat, so
/// entries written before a field existed still parse.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IndexEntry {
    #[serde(flatten)]
    pub record: PointerRecord,
    /// Storage class the object's chunks were written with; reads go to that
    /// class's backends first. None for entries from before classes were recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
}

impl std::ops::Deref for IndexEntry {
    type Target = PointerRecord;
    fn deref(&self) -> &PointerRecord {
        &self.record
    }
}

/// Mutable pointer-record index (DESIGN.md §3.2). Implementations: fs
/// ([`FsIndexStore`], single gateway) and object-store / S3 with conditional
/// writes ([`crate::s3::ObjectIndexStore`], safe with many gateways).
#[async_trait]
pub trait IndexStore: Send + Sync {
    async fn get(&self, ns: &str, path: &str) -> Result<Option<IndexEntry>>;
    /// Store `rec` iff the current seq equals `rec.seq - 1` (0 = absent).
    async fn cas_put(&self, rec: &IndexEntry) -> Result<(), CasError>;
    /// Delete iff current seq == `expected_seq`.
    async fn delete(&self, ns: &str, path: &str, expected_seq: u64) -> Result<(), CasError>;
    /// All live records in `ns` whose path starts with `prefix`, sorted by path.
    async fn list(&self, ns: &str, prefix: &str) -> Result<Vec<IndexEntry>>;
    /// Every namespace that may hold records (it may also name namespaces
    /// whose records were all deleted). Used by garbage collection with
    /// `list(ns, "")` to enumerate the whole index.
    async fn namespaces(&self) -> Result<Vec<String>> {
        Err(anyhow!("index store cannot enumerate namespaces"))
    }
}

pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }
    fn path(&self, cid: &str) -> Result<PathBuf> {
        if !near_drive_core::is_valid_cid(cid) {
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
            // Content-addressed: already there. Refresh its mtime so that GC
            // treats it as freshly uploaded (it may be about to be referenced).
            if touch(p.clone()).await.is_ok() {
                return Ok(());
            }
            // e.g. deleted by GC in between: fall through and write it
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
    fn list(&self) -> Option<BoxStream<'_, Result<ChunkInfo>>> {
        Some(Box::pin(list_fs_chunks(self.root.clone())))
    }
    async fn delete_if_older(&self, cid: &str, cutoff: SystemTime) -> Result<bool> {
        let p = self.path(cid)?;
        let md = match tokio::fs::metadata(&p).await {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        if md.modified()? >= cutoff {
            return Ok(false);
        }
        match tokio::fs::remove_file(&p).await {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

/// Set a file's mtime to now.
async fn touch(p: PathBuf) -> std::io::Result<()> {
    tokio::task::spawn_blocking(move || std::fs::File::options().write(true).open(&p)?.set_modified(SystemTime::now()))
        .await
        .map_err(std::io::Error::other)?
}

/// Walk the `{root}/xx/yy/{hex}` layout of [`FsBlobStore`]. Anything else
/// (temp files, stray names) is skipped.
fn list_fs_chunks(root: PathBuf) -> impl futures_util::Stream<Item = Result<ChunkInfo>> {
    let is_hex = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    // One batch per leaf directory, read on the blocking pool.
    let leaves = futures_util::stream::once(async move {
        let r = tokio::task::spawn_blocking(move || -> Result<Vec<(PathBuf, String)>> {
            let mut out = vec![];
            let subdirs = |d: &std::path::Path| -> Result<Vec<(PathBuf, String)>> {
                match std::fs::read_dir(d) {
                    Ok(rd) => rd
                        .map(|e| {
                            let e = e?;
                            Ok((e.path(), e.file_name().to_string_lossy().into_owned(), e.file_type()?.is_dir()))
                        })
                        .filter_map(|r: Result<_>| match r {
                            Ok((p, n, true)) if is_hex(&n, 2) => Some(Ok((p, n))),
                            Ok(_) => None,
                            Err(e) => Some(Err(e)),
                        })
                        .collect(),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
                    Err(e) => Err(e.into()),
                }
            };
            for (p1, n1) in subdirs(&root)? {
                for (p2, n2) in subdirs(&p1)? {
                    out.push((p2, format!("{n1}{n2}")));
                }
            }
            Ok(out)
        })
        .await;
        r.map_err(anyhow::Error::from).and_then(|r| r)
    });
    leaves
        .map_ok(|v| futures_util::stream::iter(v.into_iter().map(Ok::<_, anyhow::Error>)))
        .try_flatten()
        .and_then(move |(dir, pfx)| async move {
            tokio::task::spawn_blocking(move || -> Result<Vec<ChunkInfo>> {
                let mut out = vec![];
                for e in std::fs::read_dir(&dir)? {
                    let e = e?;
                    let name = e.file_name().to_string_lossy().into_owned();
                    if !is_hex(&name, 64) || !name.starts_with(&pfx) {
                        continue;
                    }
                    let md = match e.metadata() {
                        Ok(md) => md,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue, // deleted meanwhile
                        Err(e) => return Err(e.into()),
                    };
                    if md.is_file() {
                        out.push(ChunkInfo { cid: format!("b3:{name}"), size: md.len(), modified: md.modified()? });
                    }
                }
                Ok(out)
            })
            .await?
        })
        .map_ok(|v| futures_util::stream::iter(v.into_iter().map(Ok::<_, anyhow::Error>)))
        .try_flatten()
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
    async fn read(&self, ns: &str, path: &str) -> Result<Option<IndexEntry>> {
        match tokio::fs::read(self.file(ns, path)).await {
            Ok(b) => Ok(Some(serde_json::from_slice(&b)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

#[async_trait]
impl IndexStore for FsIndexStore {
    async fn get(&self, ns: &str, path: &str) -> Result<Option<IndexEntry>> {
        self.read(ns, path).await
    }
    async fn cas_put(&self, rec: &IndexEntry) -> Result<(), CasError> {
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
    async fn list(&self, ns: &str, prefix: &str) -> Result<Vec<IndexEntry>> {
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
    async fn namespaces(&self) -> Result<Vec<String>> {
        let mut rd = match tokio::fs::read_dir(&self.root).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let mut out = vec![];
        while let Some(e) = rd.next_entry().await? {
            if e.file_type().await?.is_dir() {
                out.push(e.file_name().to_string_lossy().into_owned());
            }
        }
        out.sort();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn fs_listing_delete_and_touch() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsBlobStore::new(dir.path().join("chunks"));
        assert!(s.list().unwrap().try_collect::<Vec<_>>().await.unwrap().is_empty(), "missing root lists nothing");
        let mut cids = vec![];
        for i in 0..4u8 {
            let b = Bytes::from(vec![i; 5 + i as usize]);
            cids.push(near_drive_core::cid(&b));
            s.put(&cids[i as usize], b).await.unwrap();
        }
        // junk: temp files, wrong names, misplaced chunk
        let p0 = s.path(&cids[0]).unwrap();
        std::fs::write(p0.parent().unwrap().join(".tmp-1-2"), b"x").unwrap();
        std::fs::write(dir.path().join("chunks").join("README"), b"x").unwrap();
        std::fs::create_dir_all(dir.path().join("chunks/zz/yy")).unwrap();
        std::fs::write(dir.path().join("chunks/zz/yy").join(&cids[1][3..]), b"x").unwrap();
        std::fs::create_dir_all(dir.path().join("chunks/00/00")).unwrap();
        std::fs::write(dir.path().join("chunks/00/00").join(&cids[1][3..]), b"x").unwrap();
        let mut ls: Vec<ChunkInfo> = s.list().unwrap().try_collect().await.unwrap();
        ls.sort_by(|a, b| a.cid.cmp(&b.cid));
        let mut want = cids.clone();
        want.sort();
        assert_eq!(ls.iter().map(|c| c.cid.clone()).collect::<Vec<_>>(), want);
        assert_eq!(ls.iter().map(|c| c.size).sum::<u64>(), 5 + 6 + 7 + 8);

        // age the first chunk; a re-put refreshes it
        let old = SystemTime::now() - Duration::from_secs(7200);
        std::fs::File::options().write(true).open(&p0).unwrap().set_modified(old).unwrap();
        let cutoff = SystemTime::now() - Duration::from_secs(3600);
        assert!(!s.delete_if_older(&cids[1], cutoff).await.unwrap(), "fresh chunk kept");
        s.put(&cids[0], Bytes::from(vec![0u8; 5])).await.unwrap();
        assert!(std::fs::metadata(&p0).unwrap().modified().unwrap() > cutoff, "re-put touched the chunk");
        assert!(!s.delete_if_older(&cids[0], cutoff).await.unwrap());
        std::fs::File::options().write(true).open(&p0).unwrap().set_modified(old).unwrap();
        assert!(s.delete_if_older(&cids[0], cutoff).await.unwrap());
        assert!(!s.has(&cids[0]).await.unwrap());
        assert!(!s.delete_if_older(&cids[0], cutoff).await.unwrap(), "already gone");
        assert_eq!(s.list().unwrap().try_collect::<Vec<_>>().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn fs_index_namespaces() {
        let dir = tempfile::tempdir().unwrap();
        let idx = FsIndexStore::new(dir.path().join("index"));
        assert!(idx.namespaces().await.unwrap().is_empty());
        let sk = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        for ns in ["b.near", "a.near"] {
            let record = PointerRecord::new_signed(ns, "p", &near_drive_core::cid(b"m"), 1, 2, 1, ns, &sk, 1);
            idx.cas_put(&IndexEntry { record, class: None }).await.unwrap();
        }
        assert_eq!(idx.namespaces().await.unwrap(), vec!["a.near", "b.near"]);
    }
}
