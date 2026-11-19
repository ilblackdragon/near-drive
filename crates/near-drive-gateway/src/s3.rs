//! S3-compatible (AWS S3, Cloudflare R2, MinIO) blob and index stores, via
//! the `object_store` crate.
//!
//! Key layout (all under a configurable `prefix`):
//! - chunks: `{prefix}b3/{hex[0..2]}/{hex}` for cid `b3:{hex}`
//! - index:  `{prefix}{namespace}/{path}`, where each `/`-separated path
//!   segment is escaped with `object_store`'s `PathPart` rules: the bytes
//!   `\ { ^ } % ` ] " > [ ~ < # | * ?`, CR, LF and other ASCII controls are
//!   percent-encoded (`%XX`), and segments equal to `.`/`..` become
//!   `%2E`/`%2E%2E` (NEAR Drive paths never contain those). Non-ASCII bytes are
//!   percent-encoded too (`ü` -> `%C3%BC`); everything else is stored as-is.
//!   Escaping is per byte, so keys group like the paths and
//!   group like the paths; LIST of a path prefix lists the S3 "directory" up to
//!   the prefix's last `/` and filters the remainder.
//!
//! Index writes use conditional PUTs, so any number of gateways can share
//! one bucket: a new record is `PutMode::Create` (`If-None-Match: *`), an
//! update is `PutMode::Update` (`If-Match: <etag>`). A delete overwrites the
//! record (CAS) with a tombstone `{"tombstone":true,"seq":n}` because plain S3
//! DELETE is not conditional; tombstones are invisible to get/list and the
//! next write of that path starts again at seq 1.
use crate::store::{BlobStore, CasError, DirectUrl, IndexEntry, IndexStore};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt};
use object_store::{
    aws::{AmazonS3, AmazonS3Builder},
    path::{Path as OPath, PathPart},
    GetOptions, GetRange, ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion,
};
use serde::{Deserialize, Serialize};
use std::{ops::Range, sync::Arc, time::Duration};

/// `{"type":"s3", ...}` in gateway config. Unset credentials / region /
/// endpoint fall back to the standard `AWS_*` environment variables.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct S3Config {
    pub bucket: String,
    /// e.g. `https://<account>.r2.cloudflarestorage.com` or `http://127.0.0.1:9000`.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// `auto` for R2; defaults to `us-east-1` when an endpoint is set.
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub access_key_id: Option<String>,
    #[serde(default)]
    pub secret_access_key: Option<String>,
    /// Key prefix inside the bucket (default `chunks/` for blobs, `index/` for the index).
    #[serde(default)]
    pub prefix: Option<String>,
    /// Allow `http://` endpoints (MinIO in dev).
    #[serde(default)]
    pub allow_http: bool,
    /// Use `https://bucket.endpoint/` instead of path-style `https://endpoint/bucket/`.
    #[serde(default)]
    pub virtual_hosted_style: bool,
    /// Blobs only: lifetime of presigned GET URLs returned by `?mode=locate`.
    /// 0 disables presigning. Default 3600.
    #[serde(default)]
    pub presign_ttl_secs: Option<u64>,
    /// Blobs only: if the bucket (or a CDN in front of it) is publicly
    /// readable, direct URLs are `{public_url_base}/{key}` and never expire.
    #[serde(default)]
    pub public_url_base: Option<String>,
}

impl S3Config {
    pub fn build(&self) -> Result<AmazonS3> {
        let mut b = AmazonS3Builder::from_env().with_bucket_name(&self.bucket).with_allow_http(self.allow_http);
        if let Some(e) = &self.endpoint {
            b = b.with_endpoint(e).with_virtual_hosted_style_request(self.virtual_hosted_style);
            if self.region.is_none() {
                b = b.with_region("us-east-1");
            }
        }
        if let Some(r) = &self.region {
            b = b.with_region(r);
        }
        if let Some(k) = &self.access_key_id {
            b = b.with_access_key_id(k);
        }
        if let Some(k) = &self.secret_access_key {
            b = b.with_secret_access_key(k);
        }
        b.build().with_context(|| format!("configuring S3 bucket {}", self.bucket))
    }

    fn prefix_or(&self, default: &str) -> String {
        self.prefix.clone().unwrap_or_else(|| default.to_string())
    }
}

fn prefix_parts(prefix: &str) -> Vec<PathPart<'static>> {
    prefix.split('/').filter(|s| !s.is_empty()).map(|s| PathPart::from(s.to_string())).collect()
}

fn not_found(e: &object_store::Error) -> bool {
    matches!(e, object_store::Error::NotFound { .. })
}

pub struct S3BlobStore {
    store: Arc<dyn ObjectStore>,
    signer: Option<Arc<AmazonS3>>,
    prefix: Vec<PathPart<'static>>,
    presign_ttl: Duration,
    public_url_base: Option<String>,
}

impl S3BlobStore {
    pub fn new(cfg: &S3Config) -> Result<Self> {
        let s3 = Arc::new(cfg.build()?);
        let mut s = Self::with_store(s3.clone(), &cfg.prefix_or("chunks/"));
        let ttl = cfg.presign_ttl_secs.unwrap_or(3600);
        if ttl > 0 {
            s.signer = Some(s3);
            s.presign_ttl = Duration::from_secs(ttl);
        }
        s.public_url_base = cfg.public_url_base.as_ref().map(|u| u.trim_end_matches('/').to_string());
        Ok(s)
    }

    /// Any `object_store` backend (tests use `InMemory`). No direct URLs.
    pub fn with_store(store: Arc<dyn ObjectStore>, prefix: &str) -> Self {
        Self {
            store,
            signer: None,
            prefix: prefix_parts(prefix),
            presign_ttl: Duration::from_secs(3600),
            public_url_base: None,
        }
    }

    fn key(&self, cid: &str) -> Result<OPath> {
        if !near_drive_core::is_valid_cid(cid) {
            return Err(anyhow!("bad cid"));
        }
        let h = &cid[3..];
        let mut parts = self.prefix.clone();
        parts.extend(["b3", &h[..2], h].map(|s| PathPart::from(s.to_string())));
        Ok(OPath::from_iter(parts))
    }
}

#[async_trait]
impl BlobStore for S3BlobStore {
    async fn put(&self, cid: &str, bytes: Bytes) -> Result<()> {
        // Content-addressed, so overwriting is harmless and needs no conditional support.
        self.store.put(&self.key(cid)?, PutPayload::from_bytes(bytes)).await?;
        Ok(())
    }
    async fn get(&self, cid: &str) -> Result<Option<Bytes>> {
        match self.store.get(&self.key(cid)?).await {
            Ok(r) => Ok(Some(r.bytes().await?)),
            Err(e) if not_found(&e) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    async fn get_range(&self, cid: &str, range: Range<u64>) -> Result<Option<Bytes>> {
        if range.start >= range.end {
            return Ok(if self.has(cid).await? { Some(Bytes::new()) } else { None });
        }
        let range_copy = range.clone();
        let opts = GetOptions { range: Some(GetRange::Bounded(range)), ..Default::default() };
        match self.store.get_opts(&self.key(cid)?, opts).await {
            Ok(r) => Ok(Some(r.bytes().await?)),
            Err(e) if not_found(&e) => Ok(None),
            // e.g. 416 when the range starts past the end: fall back to a full read
            Err(_) => Ok(self.get(cid).await?.map(|b| crate::store::slice_range(&b, &range_copy))),
        }
    }
    async fn has(&self, cid: &str) -> Result<bool> {
        match self.store.head(&self.key(cid)?).await {
            Ok(_) => Ok(true),
            Err(e) if not_found(&e) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    async fn direct_url(&self, cid: &str) -> Result<Option<DirectUrl>> {
        let key = self.key(cid)?;
        if let Some(base) = &self.public_url_base {
            return Ok(Some(DirectUrl { url: format!("{base}/{key}"), expires_ms: None }));
        }
        let Some(signer) = &self.signer else { return Ok(None) };
        let url = object_store::signer::Signer::signed_url(signer.as_ref(), reqwest::Method::GET, &key, self.presign_ttl).await?;
        let expires_ms = crate::now_ms() + self.presign_ttl.as_millis() as u64;
        Ok(Some(DirectUrl { url: url.to_string(), expires_ms: Some(expires_ms) }))
    }
}

#[derive(Serialize, Deserialize)]
struct Tombstone {
    tombstone: bool,
    seq: u64,
}

enum Stored {
    Live(IndexEntry),
    Deleted,
}

/// Pointer-record index on any `object_store` backend with conditional
/// writes (S3/R2/MinIO, or `InMemory` in tests). Safe for many gateways.
pub struct ObjectIndexStore {
    store: Arc<dyn ObjectStore>,
    prefix: Vec<PathPart<'static>>,
    /// Concurrent record GETs during LIST.
    list_concurrency: usize,
}

impl ObjectIndexStore {
    pub fn new(cfg: &S3Config) -> Result<Self> {
        Ok(Self::with_store(Arc::new(cfg.build()?), &cfg.prefix_or("index/")))
    }

    pub fn with_store(store: Arc<dyn ObjectStore>, prefix: &str) -> Self {
        Self { store, prefix: prefix_parts(prefix), list_concurrency: 32 }
    }

    /// `{prefix}/{ns}/{escaped path segments}`.
    pub fn key(&self, ns: &str, path: &str) -> OPath {
        let mut parts = self.prefix.clone();
        parts.push(PathPart::from(ns.to_string()));
        parts.extend(path.split('/').map(|s| PathPart::from(s.to_string())));
        OPath::from_iter(parts)
    }

    async fn read(&self, key: &OPath) -> Result<Option<(Stored, UpdateVersion)>> {
        let r = match self.store.get(key).await {
            Ok(r) => r,
            Err(e) if not_found(&e) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let v = UpdateVersion { e_tag: r.meta.e_tag.clone(), version: r.meta.version.clone() };
        let b = r.bytes().await?;
        let val: serde_json::Value = serde_json::from_slice(&b).context("corrupt index record")?;
        let stored = if val.get("tombstone").is_some() { Stored::Deleted } else { Stored::Live(serde_json::from_value(val)?) };
        Ok(Some((stored, v)))
    }

    async fn current_seq(&self, key: &OPath) -> Result<u64> {
        Ok(match self.read(key).await? {
            Some((Stored::Live(r), _)) => r.seq,
            _ => 0,
        })
    }

    /// Conditional write; a lost race maps to `Conflict` with the winner's seq.
    async fn put_cond(&self, key: &OPath, body: Vec<u8>, mode: PutMode) -> Result<(), CasError> {
        match self.store.put_opts(key, PutPayload::from(body), PutOptions::from(mode)).await {
            Ok(_) => Ok(()),
            Err(object_store::Error::AlreadyExists { .. } | object_store::Error::Precondition { .. }) => {
                Err(CasError::Conflict { current: self.current_seq(key).await? })
            }
            Err(e) => Err(CasError::Other(e.into())),
        }
    }
}

fn decode_part(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[async_trait]
impl IndexStore for ObjectIndexStore {
    async fn get(&self, ns: &str, path: &str) -> Result<Option<IndexEntry>> {
        Ok(match self.read(&self.key(ns, path)).await? {
            Some((Stored::Live(r), _)) => Some(r),
            _ => None,
        })
    }

    async fn cas_put(&self, rec: &IndexEntry) -> Result<(), CasError> {
        let key = self.key(&rec.namespace, &rec.path);
        let body = serde_json::to_vec(rec).map_err(anyhow::Error::from)?;
        match self.read(&key).await? {
            None if rec.seq == 1 => self.put_cond(&key, body, PutMode::Create).await,
            Some((Stored::Deleted, v)) if rec.seq == 1 => self.put_cond(&key, body, PutMode::Update(v)).await,
            Some((Stored::Live(cur), v)) if cur.seq + 1 == rec.seq => self.put_cond(&key, body, PutMode::Update(v)).await,
            Some((Stored::Live(cur), _)) => Err(CasError::Conflict { current: cur.seq }),
            None | Some((Stored::Deleted, _)) => Err(CasError::Conflict { current: 0 }),
        }
    }

    async fn delete(&self, ns: &str, path: &str, expected_seq: u64) -> Result<(), CasError> {
        let key = self.key(ns, path);
        match self.read(&key).await? {
            Some((Stored::Live(cur), v)) if cur.seq == expected_seq => {
                let body = serde_json::to_vec(&Tombstone { tombstone: true, seq: cur.seq }).map_err(anyhow::Error::from)?;
                self.put_cond(&key, body, PutMode::Update(v)).await
            }
            Some((Stored::Live(cur), _)) => Err(CasError::Conflict { current: cur.seq }),
            _ => Err(CasError::Conflict { current: 0 }),
        }
    }

    async fn list(&self, ns: &str, prefix: &str) -> Result<Vec<IndexEntry>> {
        // List the deepest complete "directory" of the prefix, filter the rest.
        let dir = match prefix.rfind('/') {
            Some(i) => &prefix[..i],
            None => "",
        };
        let mut base = self.prefix.clone();
        base.push(PathPart::from(ns.to_string()));
        base.extend(dir.split('/').filter(|s| !s.is_empty()).map(|s| PathPart::from(s.to_string())));
        let base_path = OPath::from_iter(base);
        let skip = self.prefix.len() + 1;
        let metas: Vec<_> = self.store.list(Some(&base_path)).try_collect().await?;
        let keys: Vec<OPath> = metas
            .into_iter()
            .map(|m| m.location)
            .filter(|loc| {
                let p: Vec<String> = loc.parts().skip(skip).map(|p| decode_part(p.as_ref())).collect();
                p.join("/").starts_with(prefix)
            })
            .collect();
        let mut out: Vec<IndexEntry> = futures_util::stream::iter(keys)
            .map(|k| async move { self.read(&k).await })
            .buffer_unordered(self.list_concurrency)
            .try_filter_map(|r| async move {
                Ok(match r {
                    Some((Stored::Live(rec), _)) => Some(rec),
                    _ => None,
                })
            })
            .try_collect()
            .await?;
        out.retain(|r| r.namespace == ns && r.path.starts_with(prefix));
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use object_store::memory::InMemory;

    use near_drive_core::record::PointerRecord;

    fn rec(path: &str, seq: u64, sk: &SigningKey) -> IndexEntry {
        let record = PointerRecord::new_signed("alice.near", path, &near_drive_core::cid(path.as_bytes()), 1, 2, seq, "alice.near", sk, 1);
        IndexEntry { record, class: Some("bulk".into()) }
    }

    #[tokio::test]
    async fn index_cas_tombstone_list() {
        let idx = ObjectIndexStore::with_store(Arc::new(InMemory::new()), "index/");
        let sk = SigningKey::from_bytes(&[1; 32]);
        idx.cas_put(&rec("a/b", 1, &sk)).await.unwrap();
        assert!(matches!(idx.cas_put(&rec("a/b", 1, &sk)).await, Err(CasError::Conflict { current: 1 })));
        assert!(matches!(idx.cas_put(&rec("a/b", 3, &sk)).await, Err(CasError::Conflict { current: 1 })));
        idx.cas_put(&rec("a/b", 2, &sk)).await.unwrap();
        let got = idx.get("alice.near", "a/b").await.unwrap().unwrap();
        assert_eq!((got.seq, got.class.as_deref()), (2, Some("bulk")), "class round-trips");
        // weird characters round-trip and list by partial segment
        for p in ["a/bc%20d", "a/b[1]#?", "a/b c/ü*x", "ab", "a/b~"] {
            idx.cas_put(&rec(p, 1, &sk)).await.unwrap();
        }
        let ls: Vec<_> = idx.list("alice.near", "a/b").await.unwrap().into_iter().map(|r| r.record.path).collect();
        assert_eq!(ls, vec!["a/b", "a/b c/ü*x", "a/b[1]#?", "a/bc%20d", "a/b~"]);
        assert_eq!(idx.list("alice.near", "a").await.unwrap().len(), 6);
        assert_eq!(idx.list("alice.near", "a/b c/").await.unwrap().len(), 1);
        assert!(idx.list("bob.near", "").await.unwrap().is_empty());
        // delete is CAS; tombstone hides the record; recreate restarts at seq 1
        assert!(matches!(idx.delete("alice.near", "a/b", 1).await, Err(CasError::Conflict { current: 2 })));
        idx.delete("alice.near", "a/b", 2).await.unwrap();
        assert!(idx.get("alice.near", "a/b").await.unwrap().is_none());
        assert_eq!(idx.list("alice.near", "a/b").await.unwrap().len(), 4);
        assert!(matches!(idx.cas_put(&rec("a/b", 3, &sk)).await, Err(CasError::Conflict { current: 0 })));
        idx.cas_put(&rec("a/b", 1, &sk)).await.unwrap();
        assert_eq!(idx.get("alice.near", "a/b").await.unwrap().unwrap().seq, 1);
    }

    #[tokio::test]
    async fn blob_store_on_memory() {
        let s = S3BlobStore::with_store(Arc::new(InMemory::new()), "chunks/");
        let data = Bytes::from_static(b"hello world");
        let cid = near_drive_core::cid(&data);
        assert!(!s.has(&cid).await.unwrap());
        assert!(s.get(&cid).await.unwrap().is_none());
        s.put(&cid, data.clone()).await.unwrap();
        s.put(&cid, data.clone()).await.unwrap();
        assert!(s.has(&cid).await.unwrap());
        assert_eq!(s.get(&cid).await.unwrap().unwrap(), data);
        assert_eq!(s.get_range(&cid, 6..11).await.unwrap().unwrap(), &b"world"[..]);
        assert_eq!(s.get_range(&cid, 6..100).await.unwrap().unwrap(), &b"world"[..]);
        assert!(s.direct_url(&cid).await.unwrap().is_none());
        assert_eq!(s.key(&cid).unwrap().to_string(), format!("chunks/b3/{}/{}", &cid[3..5], &cid[3..]));
    }

    #[test]
    fn decode() {
        assert_eq!(decode_part("a%20b%25"), "a b%");
        assert_eq!(decode_part("%2E%2E"), "..");
        assert_eq!(decode_part("x%2"), "x%2");
    }
}
