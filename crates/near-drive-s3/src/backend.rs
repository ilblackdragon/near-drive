//! Object I/O adapter between the S3 front end and NEAR Drive.
//!
//! All object reads/writes of the proxy go through [`ObjectBackend`].
//! [`ClientBackend`] uses the streaming client APIs:
//! - GET / ranged GET: `locate` once, then `write_range` for exactly the
//!   requested bytes (only overlapping chunks are fetched, in parallel,
//!   direct URLs preferred). Responses above [`STREAM_THRESHOLD`] are
//!   streamed to the HTTP client with bounded memory.
//! - PUT: `put_file` for staged files (multipart assembly, large copies),
//!   `put_reader` for large in-memory bodies, `put` for small ones.
use bytes::Bytes;
use futures_util::Stream;
use near_drive_client::{
    near_drive_core::NearUri,
    Client, GatewayError, Located, PutOptions,
};
use std::{future::Future, path::PathBuf, pin::Pin, sync::Arc};
use tokio::io::AsyncReadExt;

/// Reads larger than this are streamed to the HTTP response.
pub const STREAM_THRESHOLD: u64 = 8 * 1024 * 1024;

pub type ByteStream = Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send>>;

pub enum ObjectData {
    Mem(Vec<u8>),
    Stream(ByteStream),
}

impl ObjectData {
    pub async fn into_vec(self) -> std::io::Result<Vec<u8>> {
        use futures_util::TryStreamExt;
        match self {
            ObjectData::Mem(v) => Ok(v),
            ObjectData::Stream(s) => s.try_fold(Vec::new(), |mut acc, b| async move {
                acc.extend_from_slice(&b);
                Ok(acc)
            })
            .await,
        }
    }
}

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
    pub data: ObjectData,
    /// The range served, when one was requested.
    pub range: Option<ByteRange>,
}

/// An object being written piece by piece (multipart uploads): bytes are
/// encrypted and uploaded as they arrive; `finish` commits the object.
pub trait ObjectSink: Send + 'static {
    fn write(&mut self, data: Vec<u8>) -> impl Future<Output = BResult<()>> + Send;
    fn finish(self) -> impl Future<Output = BResult<ObjectInfo>> + Send;
}

pub trait ObjectBackend: Send + Sync + 'static {
    type Sink: ObjectSink;
    /// Start a streamed upload of `ns`/`path`.
    fn begin(&self, ns: &str, path: &str, p: &PutParams) -> BResult<Self::Sink>;
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

/// [`ObjectBackend`] over `near_drive_client::Client`.
pub struct ClientBackend {
    pub client: Arc<Client>,
}

impl ClientBackend {
    pub fn new(client: Client) -> Self {
        Self { client: Arc::new(client) }
    }
}

fn uri(ns: &str, path: &str) -> BResult<NearUri> {
    NearUri::object(ns, path).map_err(|e| BackendError::Invalid(e.to_string()))
}

/// Client errors: gateway status, decryption problems, everything else.
fn classify(e: anyhow::Error) -> BackendError {
    if e.downcast_ref::<GatewayError>().is_some() {
        return e.into();
    }
    let msg = format!("{e:#}");
    if ["not encrypted to this account", "cannot unwrap object key", "no root key is loaded", "failed authentication", "open failed"]
        .iter()
        .any(|m| msg.contains(m))
    {
        return BackendError::Decrypt(msg);
    }
    if msg.contains("no root key loaded") {
        return BackendError::Invalid(msg);
    }
    BackendError::Other(e)
}

fn info_of(loc: &Located) -> ObjectInfo {
    ObjectInfo {
        size: loc.record.size,
        manifest_cid: loc.record.manifest_cid.clone(),
        ts_ms: loc.record.ts_ms,
        content_type: loc.manifest.content_type.clone(),
    }
}

impl ClientBackend {
    async fn read(&self, u: &NearUri, loc: &Located, start: u64, end: u64) -> BResult<Vec<u8>> {
        let mut v = Vec::with_capacity((end - start) as usize);
        self.client.write_range(u, loc, start..end, &mut v).await.map_err(classify)?;
        Ok(v)
    }
}

/// [`ObjectSink`] over the client's incremental [`near_drive_client::ObjectWriter`].
pub struct ClientSink {
    w: near_drive_client::ObjectWriter,
    content_type: Option<String>,
}

impl ObjectSink for ClientSink {
    async fn write(&mut self, data: Vec<u8>) -> BResult<()> {
        self.w.write(&data).await.map_err(classify)
    }

    async fn finish(self) -> BResult<ObjectInfo> {
        let size = self.w.size();
        let rec = self.w.finish().await.map_err(classify)?;
        Ok(ObjectInfo { size, manifest_cid: rec.manifest_cid, ts_ms: rec.ts_ms, content_type: self.content_type })
    }
}

impl ObjectBackend for ClientBackend {
    type Sink = ClientSink;

    fn begin(&self, ns: &str, path: &str, p: &PutParams) -> BResult<ClientSink> {
        let opts = PutOptions { public: p.public, content_type: p.content_type.clone(), ..Default::default() };
        let w = self.client.writer(&uri(ns, path)?, &opts).map_err(classify)?;
        Ok(ClientSink { w, content_type: p.content_type.clone() })
    }

    fn account(&self) -> &str {
        self.client.account()
    }

    async fn head(&self, ns: &str, path: &str) -> BResult<Option<ObjectInfo>> {
        let h = self.client.head(&uri(ns, path)?).await.map_err(classify)?;
        Ok(h.map(|h| ObjectInfo {
            size: h.record.size,
            manifest_cid: h.record.manifest_cid.clone(),
            ts_ms: h.record.ts_ms,
            content_type: h.manifest.content_type.clone(),
        }))
    }

    async fn get(&self, ns: &str, path: &str, range: Option<RangeSpec>) -> BResult<GetResult> {
        let u = uri(ns, path)?;
        // The object can be replaced between locate and the chunk fetches
        // (the gateway then 404s the old chunks); retry once.
        for attempt in 0..2 {
            let loc = self.client.locate(&u).await.map_err(classify)?.ok_or(BackendError::NotFound)?;
            let size = loc.record.size;
            let served = match range {
                None => None,
                Some(r) => Some(r.resolve(size).map_err(|_| BackendError::RangeNotSatisfiable { size })?),
            };
            let (start, end) = served.map(|r| (r.start, r.end + 1)).unwrap_or((0, size));
            let info = info_of(&loc);
            if end - start <= STREAM_THRESHOLD {
                match self.read(&u, &loc, start, end).await {
                    Ok(v) => return Ok(GetResult { info, data: ObjectData::Mem(v), range: served }),
                    Err(BackendError::NotFound) if attempt == 0 => continue,
                    Err(e) => return Err(e),
                }
            }
            // Large: read the first chunk-aligned piece up front so key and
            // gateway errors surface as a proper S3 error, then stream the rest.
            let cs = loc.manifest.chunk_size;
            let first_end = ((start / cs + 1) * cs).min(end);
            let head = match self.read(&u, &loc, start, first_end).await {
                Ok(v) => v,
                Err(BackendError::NotFound) if attempt == 0 => continue,
                Err(e) => return Err(e),
            };
            let (w, r) = tokio::io::duplex(1 << 20);
            let client = self.client.clone();
            let (u2, loc2) = (u.clone(), loc.clone());
            tokio::spawn(async move {
                if let Err(e) = client.write_range(&u2, &loc2, first_end..end, w).await {
                    tracing::warn!("streaming {u2} failed: {e:#}");
                }
            });
            let remaining = end - first_end;
            let rest = futures_util::stream::unfold((r, 0u64), move |(mut r, got)| async move {
                let mut buf = vec![0u8; 256 * 1024];
                match r.read(&mut buf).await {
                    Ok(0) if got < remaining => Some((
                        Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "NEAR Drive stream ended early")),
                        (r, u64::MAX),
                    )),
                    Ok(0) => None,
                    Ok(_) if got == u64::MAX => None,
                    Ok(n) => {
                        buf.truncate(n);
                        Some((Ok(Bytes::from(buf)), (r, got + n as u64)))
                    }
                    Err(e) if got != u64::MAX => Some((Err(e), (r, u64::MAX))),
                    Err(_) => None,
                }
            });
            let first = futures_util::stream::once(async move { Ok(Bytes::from(head)) });
            use futures_util::StreamExt;
            return Ok(GetResult { info, data: ObjectData::Stream(Box::pin(first.chain(rest))), range: served });
        }
        Err(BackendError::NotFound)
    }

    async fn put(&self, ns: &str, path: &str, src: PutSource, p: &PutParams) -> BResult<ObjectInfo> {
        let u = uri(ns, path)?;
        let opts = PutOptions { public: p.public, content_type: p.content_type.clone(), ..Default::default() };
        let rec = match src {
            PutSource::File(f) => {
                let r = self.client.put_file(&f, &u, &opts).await;
                let _ = tokio::fs::remove_file(&f).await;
                r
            }
            PutSource::Mem(d) if d.len() > self.client.chunk_size => self.client.put_reader(std::io::Cursor::new(d), &u, &opts).await,
            PutSource::Mem(d) => self.client.put(&u, &d, &opts).await,
        }
        .map_err(classify)?;
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

/// A bucket name mapped onto a NEAR Drive folder, so existing S3 code keeps
/// its bucket names: `delta-artifacts` -> `near://deltaleague.near/artifacts/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alias {
    pub namespace: String,
    /// Key prefix inside the namespace (empty, or ends with `/`).
    pub prefix: String,
}

impl Alias {
    /// `near://<account>/[<prefix>/]`
    pub fn parse(target: &str) -> Result<Self, String> {
        let u = NearUri::parse(target).map_err(|e| e.to_string())?;
        if !(u.path.is_empty() || u.path.ends_with('/')) {
            return Err(format!("alias target must be a folder ending with /: {target}"));
        }
        Ok(Alias { namespace: u.namespace, prefix: u.path })
    }
}

/// [`ObjectBackend`] that resolves bucket aliases before calling `inner`.
pub struct Aliased<B> {
    pub inner: B,
    pub aliases: std::collections::BTreeMap<String, Alias>,
}

impl<B> Aliased<B> {
    /// (namespace, path) for an S3 (bucket, key).
    pub fn resolve(&self, bucket: &str, key: &str) -> (String, String) {
        match self.aliases.get(bucket) {
            Some(a) => (a.namespace.clone(), format!("{}{key}", a.prefix)),
            None => (bucket.to_string(), key.to_string()),
        }
    }
}

impl<B: ObjectBackend> ObjectBackend for Aliased<B> {
    type Sink = B::Sink;

    fn begin(&self, ns: &str, path: &str, p: &PutParams) -> BResult<B::Sink> {
        let (ns, path) = self.resolve(ns, path);
        self.inner.begin(&ns, &path, p)
    }

    fn account(&self) -> &str {
        self.inner.account()
    }

    async fn head(&self, ns: &str, path: &str) -> BResult<Option<ObjectInfo>> {
        let (ns, path) = self.resolve(ns, path);
        self.inner.head(&ns, &path).await
    }

    async fn get(&self, ns: &str, path: &str, range: Option<RangeSpec>) -> BResult<GetResult> {
        let (ns, path) = self.resolve(ns, path);
        self.inner.get(&ns, &path, range).await
    }

    async fn put(&self, ns: &str, path: &str, src: PutSource, p: &PutParams) -> BResult<ObjectInfo> {
        let (ns, path) = self.resolve(ns, path);
        self.inner.put(&ns, &path, src, p).await
    }

    async fn delete(&self, ns: &str, path: &str) -> BResult<bool> {
        let (ns, path) = self.resolve(ns, path);
        self.inner.delete(&ns, &path).await
    }

    async fn list(&self, ns: &str, prefix: &str) -> BResult<Vec<ListItem>> {
        match self.aliases.get(ns) {
            None => self.inner.list(ns, prefix).await,
            Some(a) => {
                let items = self.inner.list(&a.namespace, &format!("{}{prefix}", a.prefix)).await?;
                Ok(items
                    .into_iter()
                    .filter_map(|mut it| {
                        it.key = it.key.strip_prefix(&a.prefix)?.to_string();
                        Some(it)
                    })
                    .collect())
            }
        }
    }
}
