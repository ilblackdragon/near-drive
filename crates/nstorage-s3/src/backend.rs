//! Object I/O adapter between the S3 front end and nstorage.
//!
//! All object reads/writes of the proxy go through [`ObjectBackend`]. The
//! current implementation, [`ClientBackend`], uses the in-memory
//! `Client::put` / `fetch_chunks` + `decrypt`; whole objects are buffered.
//! When the client gains streaming `put_file` / `get_to_file` / `get_range`,
//! only this file needs to change: `PutSource::File` already hands over a
//! path on disk (multipart assembly, large PUTs), and `get` already receives
//! the requested byte range.
use nstorage_client::{
    nstorage_core::NearUri,
    Client, GatewayError, ObjectHead, PutOptions,
};
use std::{future::Future, path::PathBuf};

#[derive(Debug, Clone)]
pub struct ObjectInfo {
    /// Plaintext size.
    pub size: u64,
    pub manifest_cid: String,
    pub ts_ms: u64,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ListItem {
    pub key: String,
    pub size: u64,
    pub ts_ms: u64,
    pub manifest_cid: Option<String>,
}

pub enum PutSource {
    Mem(Vec<u8>),
    /// A local file to upload; the backend may delete it afterwards.
    File(PathBuf),
}

#[derive(Debug, Clone, Default)]
pub struct PutParams {
    pub public: bool,
    pub content_type: Option<String>,
}

/// Inclusive byte range, already resolved against the object size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

/// A `Range:` request before the object size is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeSpec {
    /// `bytes=a-` / `bytes=a-b`
    From(u64, Option<u64>),
    /// `bytes=-n`
    Suffix(u64),
}

impl RangeSpec {
    /// `None` for anything we do not handle (multiple ranges, other units):
    /// S3 then serves the whole object.
    pub fn parse(h: &str) -> Option<Self> {
        let r = h.trim().strip_prefix("bytes=")?;
        if r.contains(',') {
            return None;
        }
        let (a, b) = r.split_once('-')?;
        let (a, b) = (a.trim(), b.trim());
        if a.is_empty() {
            return Some(Self::Suffix(b.parse().ok()?));
        }
        let a = a.parse().ok()?;
        let b = if b.is_empty() { None } else { Some(b.parse().ok()?) };
        if let Some(b) = b {
            if b < a {
                return None;
            }
        }
        Some(Self::From(a, b))
    }

    /// `Err(())` = not satisfiable (416).
    #[allow(clippy::result_unit_err)]
    pub fn resolve(self, size: u64) -> Result<ByteRange, ()> {
        match self {
            Self::From(a, b) => {
                if a >= size {
                    return Err(());
                }
                Ok(ByteRange { start: a, end: b.unwrap_or(u64::MAX).min(size - 1) })
            }
            Self::Suffix(n) => {
                if n == 0 || size == 0 {
                    return Err(());
                }
                Ok(ByteRange { start: size.saturating_sub(n), end: size - 1 })
            }
        }
    }
}

#[derive(Debug)]
pub enum BackendError {
    NotFound,
    RangeNotSatisfiable { size: u64 },
    /// Gateway answered with a non-2xx status.
    Gateway { status: u16, body: String },
    /// Object exists but this proxy cannot decrypt it.
    Decrypt(String),
    /// Request rejected locally (invalid path, missing root key, …).
    Invalid(String),
    Other(anyhow::Error),
}

impl From<anyhow::Error> for BackendError {
    fn from(e: anyhow::Error) -> Self {
        match e.downcast_ref::<GatewayError>() {
            Some(g) if g.status == 404 => BackendError::NotFound,
            Some(g) => BackendError::Gateway { status: g.status, body: g.body.clone() },
            None => BackendError::Other(e),
        }
    }
}

pub type BResult<T> = Result<T, BackendError>;

pub struct GetResult {
    pub info: ObjectInfo,
    pub data: Vec<u8>,
    /// The range served, when one was requested.
    pub range: Option<ByteRange>,
}

pub trait ObjectBackend: Send + Sync + 'static {
    /// The NEAR account the proxy acts as (its own bucket).
    fn account(&self) -> &str;
    fn head(&self, ns: &str, path: &str) -> impl Future<Output = BResult<Option<ObjectInfo>>> + Send;
    fn get(&self, ns: &str, path: &str, range: Option<RangeSpec>) -> impl Future<Output = BResult<GetResult>> + Send;
    fn put(&self, ns: &str, path: &str, src: PutSource, p: &PutParams) -> impl Future<Output = BResult<ObjectInfo>> + Send;
    /// `Ok(false)` if the object did not exist.
    fn delete(&self, ns: &str, path: &str) -> impl Future<Output = BResult<bool>> + Send;
    /// All readable objects whose path starts with `prefix`, any order.
    fn list(&self, ns: &str, prefix: &str) -> impl Future<Output = BResult<Vec<ListItem>>> + Send;
}

/// [`ObjectBackend`] over the in-memory `nstorage_client::Client` API.
pub struct ClientBackend {
    pub client: Client,
}

impl ClientBackend {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

fn uri(ns: &str, path: &str) -> BResult<NearUri> {
    NearUri::object(ns, path).map_err(|e| BackendError::Invalid(e.to_string()))
}

fn info(h: &ObjectHead) -> ObjectInfo {
    ObjectInfo { size: h.record.size, manifest_cid: h.record.manifest_cid.clone(), ts_ms: h.record.ts_ms, content_type: h.manifest.content_type.clone() }
}

impl ObjectBackend for ClientBackend {
    fn account(&self) -> &str {
        self.client.account()
    }

    async fn head(&self, ns: &str, path: &str) -> BResult<Option<ObjectInfo>> {
        Ok(self.client.head(&uri(ns, path)?).await?.as_ref().map(info))
    }

    async fn get(&self, ns: &str, path: &str, range: Option<RangeSpec>) -> BResult<GetResult> {
        let u = uri(ns, path)?;
        // The object can be replaced between HEAD and the chunk fetches
        // (gateway then 404s the old chunks); retry once with the new head.
        for attempt in 0..2 {
            let head = self.client.head(&u).await?.ok_or(BackendError::NotFound)?;
            let range = match range {
                None => None,
                Some(r) => Some(r.resolve(head.record.size).map_err(|_| BackendError::RangeNotSatisfiable { size: head.record.size })?),
            };
            // TODO(streaming): fetch only the chunks covering `range` once the client has get_range.
            let chunks = match self.client.fetch_chunks(&u, &head).await.map_err(BackendError::from) {
                Ok(c) => c,
                Err(BackendError::NotFound) if attempt == 0 => continue,
                Err(e) => return Err(e),
            };
            let mut data = self.client.decrypt(&head, &chunks).map_err(|e| BackendError::Decrypt(format!("{e:#}")))?;
            if let Some(r) = range {
                data = data[r.start as usize..=r.end as usize].to_vec();
            }
            return Ok(GetResult { info: info(&head), data, range });
        }
        Err(BackendError::NotFound)
    }

    async fn put(&self, ns: &str, path: &str, src: PutSource, p: &PutParams) -> BResult<ObjectInfo> {
        let u = uri(ns, path)?;
        // TODO(streaming): use Client::put_file for PutSource::File.
        let data = match src {
            PutSource::Mem(d) => d,
            PutSource::File(f) => {
                let d = tokio::fs::read(&f).await.map_err(|e| BackendError::Other(e.into()))?;
                let _ = tokio::fs::remove_file(&f).await;
                d
            }
        };
        let opts = PutOptions { public: p.public, content_type: p.content_type.clone(), share_with: vec![] };
        let rec = self.client.put(&u, &data, &opts).await.map_err(|e| {
            let msg = format!("{e:#}");
            match BackendError::from(e) {
                BackendError::Other(_) if msg.contains("no root key") => BackendError::Invalid(msg),
                other => other,
            }
        })?;
        Ok(ObjectInfo { size: rec.size, manifest_cid: rec.manifest_cid, ts_ms: rec.ts_ms, content_type: p.content_type.clone() })
    }

    async fn delete(&self, ns: &str, path: &str) -> BResult<bool> {
        match self.client.delete(&uri(ns, path)?).await.map_err(BackendError::from) {
            Ok(()) => Ok(true),
            Err(BackendError::NotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn list(&self, ns: &str, prefix: &str) -> BResult<Vec<ListItem>> {
        // Not validated as an object path: S3 prefixes are arbitrary strings.
        let p = NearUri { namespace: ns.to_string(), path: prefix.to_string() };
        let entries = self.client.list(&p).await?;
        Ok(entries.into_iter().map(|e| ListItem { key: e.path, size: e.size, ts_ms: e.ts_ms, manifest_cid: e.manifest_cid }).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ranges() {
        assert_eq!(RangeSpec::parse("bytes=0-9"), Some(RangeSpec::From(0, Some(9))));
        assert_eq!(RangeSpec::parse("bytes=5-"), Some(RangeSpec::From(5, None)));
        assert_eq!(RangeSpec::parse("bytes=-3"), Some(RangeSpec::Suffix(3)));
        assert_eq!(RangeSpec::parse("bytes=0-1,4-5"), None);
        assert_eq!(RangeSpec::parse("bytes=9-1"), None);
        assert_eq!(RangeSpec::From(0, Some(99)).resolve(10), Ok(ByteRange { start: 0, end: 9 }));
        assert_eq!(RangeSpec::Suffix(30).resolve(10), Ok(ByteRange { start: 0, end: 9 }));
        assert_eq!(RangeSpec::From(10, None).resolve(10), Err(()));
    }
}
