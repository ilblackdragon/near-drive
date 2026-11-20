//! S3-compatible (AWS S3, Cloudflare R2, MinIO) blob and index stores, via
//! the `object_store` crate.
//!
//! Key layout (all under a configurable `prefix`):
//! - chunks: `{prefix}b3/{hex[0..2]}/{hex}` for cid `b3:{hex}`
//! - index:  `{prefix}{namespace}/{path}`, the path stored verbatim. Valid
//!   NEAR Drive paths (non-empty segments, no `.`/`..`, no control characters)
//!   are valid object keys, so key order is path order and an index LIST is
//!   one native S3 ListObjectsV2 request with `prefix`, `delimiter`,
//!   `start-after` and `max-keys` mapped straight through.
//!
//! Index writes use conditional PUTs, so any number of gateways can share
//! one bucket: a new record is `PutMode::Create` (`If-None-Match: *`), an
//! update is `PutMode::Update` (`If-Match: <etag>`). A delete overwrites the
//! record (CAS) with a tombstone `{"tombstone":true,"seq":n}` because plain S3
//! DELETE is not conditional; tombstones are invisible to get/list and the
//! next write of that path starts again at seq 1. Tombstones are never
//! removed: an unconditional DELETE could race a re-create of the same path
//! and erase the new live record. LIST recognises them by size from the
//! listing alone (no GET).
//!
//! LIST cost per page: one LIST request plus one GET per live record on the
//! page whose (key, etag) is not in the bounded in-memory entry cache.
use crate::store::{before_cursor, paginate, BlobStore, CasError, ChunkInfo, DirectUrl, IndexEntry, IndexStore, ListPage, Listed};
use std::collections::HashMap;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt};
use object_store::{
    aws::{AmazonS3, AmazonS3Builder},
    path::{Path as OPath, PathPart},
    list::{PaginatedListOptions, PaginatedListStore},
    GetOptions, GetRange, ObjectMeta, ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion,
};
use serde::{Deserialize, Serialize};
use futures_util::stream::BoxStream;
use std::{
    ops::Range,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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

/// `object_store` timestamp as `SystemTime`.
fn system_time(t: &object_store::ObjectMeta) -> SystemTime {
    let ms = t.last_modified.timestamp_millis();
    if ms >= 0 {
        UNIX_EPOCH + Duration::from_millis(ms as u64)
    } else {
        UNIX_EPOCH
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
    /// Lists `{prefix}b3/`; keys that are not `b3/{hex[0..2]}/{hex}` are skipped.
    fn list(&self) -> Option<BoxStream<'_, Result<ChunkInfo>>> {
        let mut parts = self.prefix.clone();
        parts.push(PathPart::from("b3"));
        let base = OPath::from_iter(parts);
        let depth = self.prefix.len() + 3;
        let s = self.store.list(Some(&base)).map_err(anyhow::Error::from).try_filter_map(move |m| async move {
            let parts: Vec<String> = m.location.parts().map(|p| p.as_ref().to_string()).collect();
            if parts.len() != depth {
                return Ok(None);
            }
            let (dir, hex) = (&parts[depth - 2], &parts[depth - 1]);
            let cid = format!("b3:{hex}");
            if !near_drive_core::is_valid_cid(&cid) || !hex.starts_with(dir.as_str()) || dir.len() != 2 {
                return Ok(None);
            }
            Ok(Some(ChunkInfo { cid, size: m.size, modified: system_time(&m) }))
        });
        Some(Box::pin(s))
    }
    /// HEAD (age re-check), then DELETE. S3 has no conditional delete, so a
    /// re-upload landing between the two is lost; the window is one round trip.
    async fn delete_if_older(&self, cid: &str, cutoff: SystemTime) -> Result<bool> {
        let key = self.key(cid)?;
        match self.store.head(&key).await {
            Ok(m) if system_time(&m) < cutoff => {}
            Ok(_) => return Ok(false),
            Err(e) if not_found(&e) => return Ok(false),
            Err(e) => return Err(e.into()),
        }
        match self.store.delete(&key).await {
            Ok(()) => Ok(true),
            Err(e) if not_found(&e) => Ok(false),
            Err(e) => Err(e.into()),
        }
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

/// A record object this small is a tombstone (at most
/// `{"tombstone":true,"seq":18446744073709551615}`, 46 bytes); a live record
/// carries a signature, cid and paths and is always far larger. Lets LIST skip
/// tombstones from the listing metadata alone.
const TOMBSTONE_MAX_SIZE: u64 = 64;

/// Decoded records kept by (key, etag) so repeated listings do not re-GET
/// unchanged entries.
const ENTRY_CACHE_MAX: usize = 100_000;

/// Bounded map key -> (etag, decoded record or None for a tombstone); oldest
/// insertions are evicted first.
#[derive(Default)]
struct EntryCache {
    map: HashMap<String, (String, Option<IndexEntry>)>,
    order: std::collections::VecDeque<String>,
}

impl EntryCache {
    fn get(&self, key: &str, etag: &str) -> Option<Option<IndexEntry>> {
        self.map.get(key).filter(|(t, _)| t == etag).map(|(_, e)| e.clone())
    }
    fn put(&mut self, key: String, etag: String, e: Option<IndexEntry>) {
        if self.map.insert(key.clone(), (etag, e)).is_none() {
            self.order.push_back(key);
            while self.order.len() > ENTRY_CACHE_MAX {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }
}

/// Pointer-record index on any `object_store` backend with conditional
/// writes (S3/R2/MinIO, or `InMemory` in tests). Safe for many gateways.
pub struct ObjectIndexStore {
    store: Arc<dyn ObjectStore>,
    /// Native paginated LIST (S3: ListObjectsV2 with prefix / delimiter /
    /// start-after / max-keys). Without it (e.g. `InMemory`) a page is cut
    /// from a listing of the prefix's directory.
    pager: Option<Arc<dyn PaginatedListStore>>,
    /// Key prefix: empty or ends with `/`.
    prefix: String,
    /// Concurrent record GETs during LIST.
    list_concurrency: usize,
    cache: std::sync::Mutex<EntryCache>,
}

impl ObjectIndexStore {
    pub fn new(cfg: &S3Config) -> Result<Self> {
        let s3 = Arc::new(cfg.build()?);
        Ok(Self::with_paginated(s3.clone(), Some(s3), &cfg.prefix_or("index/")))
    }

    pub fn with_store(store: Arc<dyn ObjectStore>, prefix: &str) -> Self {
        Self::with_paginated(store, None, prefix)
    }

    pub fn with_paginated(store: Arc<dyn ObjectStore>, pager: Option<Arc<dyn PaginatedListStore>>, prefix: &str) -> Self {
        let p = OPath::from_iter(prefix_parts(prefix)).to_string();
        let prefix = if p.is_empty() { p } else { format!("{p}/") };
        Self { store, pager, prefix, list_concurrency: 32, cache: Default::default() }
    }

    /// `{prefix}{ns}/` — every key of the namespace starts with this.
    fn ns_base(&self, ns: &str) -> String {
        format!("{}{ns}/", self.prefix)
    }

    /// `{prefix}{ns}/{path}`, the path verbatim (valid NEAR Drive paths are
    /// valid object keys), so key order is path order and S3 prefix /
    /// delimiter listing works on paths directly.
    pub fn key(&self, ns: &str, path: &str) -> Result<OPath> {
        OPath::parse(format!("{}{path}", self.ns_base(ns))).with_context(|| format!("invalid index key for {ns}/{path}"))
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
        if let Some(t) = &v.e_tag {
            let e = match &stored {
                Stored::Live(r) => Some(r.clone()),
                Stored::Deleted => None,
            };
            self.cache.lock().unwrap().put(key.to_string(), t.clone(), e);
        }
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

    /// One raw LIST page of keys (relative to the namespace) with their
    /// metadata, plus common prefixes and the next cursor.
    async fn raw_page(&self, ns: &str, prefix: &str, delimiter: Option<&str>, start_after: Option<&str>, limit: usize) -> Result<(Vec<Listed>, HashMap<String, ObjectMeta>, Option<String>)> {
        let base = self.ns_base(ns);
        let rel = |p: &OPath| p.as_ref().strip_prefix(base.as_str()).map(str::to_string);
        let mut metas = HashMap::new();
        let Some(pager) = &self.pager else {
            // Emulated: list the prefix's deepest complete directory (from the
            // cursor on) and cut one page out of it. O(directory) per page;
            // only for stores without native paginated listing (tests).
            let dir = match prefix.rfind('/') {
                Some(i) => &prefix[..i],
                None => "",
            };
            // A prefix that is no valid key prefix (e.g. `a//`) matches nothing.
            let Ok(dir) = OPath::parse(format!("{base}{dir}")) else { return Ok((vec![], metas, None)) };
            let offset = start_after.and_then(|sa| OPath::parse(format!("{base}{sa}")).ok());
            let listing: Vec<ObjectMeta> = match &offset {
                Some(o) => self.store.list_with_offset(Some(&dir), o).try_collect().await?,
                None => self.store.list(Some(&dir)).try_collect().await?,
            };
            let mut keys = vec![];
            for m in listing {
                if let Some(k) = rel(&m.location) {
                    keys.push(k.clone());
                    metas.insert(k, m);
                }
            }
            keys.sort();
            let (items, next) = paginate(keys, prefix, delimiter, start_after, limit);
            return Ok((items, metas, next));
        };
        let opts = PaginatedListOptions {
            delimiter: delimiter.map(|d| d.to_string().into()),
            max_keys: Some(limit),
            // A common-prefix cursor must skip everything under it; S3's
            // start-after is a plain key bound, so append the largest char.
            offset: start_after.map(|sa| {
                let mut o = format!("{base}{sa}");
                if delimiter.is_some_and(|d| sa.ends_with(d)) {
                    o.push(char::MAX);
                }
                o
            }),
            ..Default::default()
        };
        let r = pager.list_paginated(Some(&format!("{base}{prefix}")), opts).await?;
        let mut items = vec![];
        // The raw page's last item, before any filtering: the next cursor.
        let mut raw_last: Option<String> = None;
        let mut seen = |k: &str| {
            if raw_last.as_deref().is_none_or(|l| l < k) {
                raw_last = Some(k.to_string());
            }
        };
        for m in r.result.objects {
            if let Some(k) = rel(&m.location) {
                seen(&k);
                if k.starts_with(prefix) && !before_cursor(&k, start_after, delimiter) {
                    items.push(Listed::Key(k.clone()));
                    metas.insert(k, m);
                }
            }
        }
        for p in r.result.common_prefixes {
            // `Path` drops a trailing `/`; S3 common prefixes end with the delimiter.
            let Some(mut cp) = rel(&p) else { continue };
            if let Some(d) = delimiter {
                if !cp.ends_with(d) {
                    cp.push_str(d);
                }
            }
            seen(&cp);
            if !before_cursor(&cp, start_after, delimiter) {
                items.push(Listed::Prefix(cp));
            }
        }
        let name = |l: &Listed| match l {
            Listed::Key(k) | Listed::Prefix(k) => k.clone(),
        };
        items.sort_by_key(name);
        let next = if r.page_token.is_some() { raw_last } else { None };
        Ok((items, metas, next))
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
        Ok(match self.read(&self.key(ns, path)?).await? {
            Some((Stored::Live(r), _)) => Some(r),
            _ => None,
        })
    }

    async fn cas_put(&self, rec: &IndexEntry) -> Result<(), CasError> {
        let key = self.key(&rec.namespace, &rec.path)?;
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
        let key = self.key(ns, path)?;
        match self.read(&key).await? {
            Some((Stored::Live(cur), v)) if cur.seq == expected_seq => {
                let body = serde_json::to_vec(&Tombstone { tombstone: true, seq: cur.seq }).map_err(anyhow::Error::from)?;
                self.put_cond(&key, body, PutMode::Update(v)).await
            }
            Some((Stored::Live(cur), _)) => Err(CasError::Conflict { current: cur.seq }),
            _ => Err(CasError::Conflict { current: 0 }),
        }
    }

    /// One native LIST request (S3), then GETs only for this page's records
    /// that are neither tombstones (recognised by size) nor already cached
    /// under their current etag.
    async fn list_page(&self, ns: &str, prefix: &str, delimiter: Option<&str>, start_after: Option<&str>, limit: usize) -> Result<ListPage> {
        let delimiter = delimiter.filter(|d| !d.is_empty());
        let (items, metas, next_cursor) = self.raw_page(ns, prefix, delimiter, start_after, limit.clamp(1, crate::store::MAX_LIST_LIMIT)).await?;
        let mut page = ListPage { next_cursor, ..Default::default() };
        let mut keys = vec![];
        for it in items {
            match it {
                Listed::Prefix(p) => page.common_prefixes.push(p),
                Listed::Key(k) => {
                    let m = &metas[&k];
                    if m.size >= TOMBSTONE_MAX_SIZE {
                        keys.push((m.location.clone(), m.e_tag.clone()));
                    }
                }
            }
        }
        let fetched: Vec<Option<IndexEntry>> = futures_util::stream::iter(keys)
            .map(|(k, tag)| {
                async move {
                    if let Some(hit) = tag.and_then(|t| self.cache.lock().unwrap().get(k.as_ref(), &t)) {
                        return Ok(hit);
                    }
                    Ok::<_, anyhow::Error>(match self.read(&k).await? {
                        Some((Stored::Live(r), _)) => Some(r),
                        _ => None,
                    })
                }
            })
            .buffered(self.list_concurrency)
            .try_collect()
            .await?;
        page.entries = fetched.into_iter().flatten().filter(|r| r.namespace == ns && r.path.starts_with(prefix)).collect();
        Ok(page)
    }

    /// The first-level "directories" under the index prefix.
    async fn namespaces(&self) -> Result<Vec<String>> {
        let base = OPath::parse(&self.prefix)?;
        let r = self.store.list_with_delimiter(Some(&base)).await?;
        let mut out: Vec<String> = r.common_prefixes.iter().filter_map(|p| p.parts().next_back().map(|p| decode_part(p.as_ref()))).collect();
        out.sort();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::list_all;
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
        let ls: Vec<_> = list_all(&idx, "alice.near", "a/b").await.unwrap().into_iter().map(|r| r.record.path).collect();
        assert_eq!(ls, vec!["a/b", "a/b c/ü*x", "a/b[1]#?", "a/bc%20d", "a/b~"]);
        assert_eq!(list_all(&idx, "alice.near", "a").await.unwrap().len(), 6);
        assert_eq!(list_all(&idx, "alice.near", "a/b c/").await.unwrap().len(), 1);
        assert!(list_all(&idx, "bob.near", "").await.unwrap().is_empty());
        // delete is CAS; tombstone hides the record; recreate restarts at seq 1
        assert!(matches!(idx.delete("alice.near", "a/b", 1).await, Err(CasError::Conflict { current: 2 })));
        idx.delete("alice.near", "a/b", 2).await.unwrap();
        assert!(idx.get("alice.near", "a/b").await.unwrap().is_none());
        assert_eq!(list_all(&idx, "alice.near", "a/b").await.unwrap().len(), 4);
        assert!(matches!(idx.cas_put(&rec("a/b", 3, &sk)).await, Err(CasError::Conflict { current: 0 })));
        idx.cas_put(&rec("a/b", 1, &sk)).await.unwrap();
        assert_eq!(idx.get("alice.near", "a/b").await.unwrap().unwrap().seq, 1);
    }

    /// S3 ListObjectsV2 semantics over `InMemory`, to exercise the native
    /// paginated path without a real bucket.
    struct MemPager(Arc<InMemory>);

    #[async_trait]
    impl PaginatedListStore for MemPager {
        async fn list_paginated(&self, prefix: Option<&str>, opts: PaginatedListOptions) -> object_store::Result<object_store::list::PaginatedListResult> {
            let prefix = prefix.unwrap_or("");
            let mut keys: Vec<ObjectMeta> = self.0.list(None).try_collect().await?;
            keys.sort_by(|a, b| a.location.as_ref().cmp(b.location.as_ref()));
            let mut res = object_store::ListResult { common_prefixes: vec![], objects: vec![] };
            let (mut n, mut last_cp, mut truncated) = (0, None::<String>, false);
            for m in keys {
                let k = m.location.as_ref().to_string();
                if !k.starts_with(prefix) || opts.offset.as_deref().is_some_and(|o| k.as_str() <= o) {
                    continue;
                }
                let cp = opts.delimiter.as_deref().and_then(|d| k[prefix.len()..].find(d).map(|i| k[..prefix.len() + i + d.len()].to_string()));
                if cp.is_some() && cp == last_cp {
                    continue;
                }
                if n == opts.max_keys.unwrap_or(1000) {
                    truncated = true;
                    break;
                }
                n += 1;
                match cp {
                    Some(cp) => {
                        res.common_prefixes.push(OPath::parse(&cp).unwrap());
                        last_cp = Some(cp);
                    }
                    None => res.objects.push(m),
                }
            }
            Ok(object_store::list::PaginatedListResult { result: res, page_token: truncated.then(|| "t".to_string()) })
        }
    }

    async fn pages(idx: &ObjectIndexStore, prefix: &str, delimiter: Option<&str>, limit: usize) -> (Vec<String>, Vec<String>, usize) {
        let (mut paths, mut cps, mut n, mut cursor) = (vec![], vec![], 0, None::<String>);
        loop {
            let p = idx.list_page("alice.near", prefix, delimiter, cursor.as_deref(), limit).await.unwrap();
            assert!(p.entries.len() + p.common_prefixes.len() <= limit);
            n += 1;
            paths.extend(p.entries.into_iter().map(|e| e.record.path));
            cps.extend(p.common_prefixes);
            match p.next_cursor {
                None => return (paths, cps, n),
                c => cursor = c,
            }
        }
    }

    #[tokio::test]
    async fn index_pagination_native_and_emulated() {
        let mem = Arc::new(InMemory::new());
        let sk = SigningKey::from_bytes(&[1; 32]);
        let native = ObjectIndexStore::with_paginated(mem.clone(), Some(Arc::new(MemPager(mem.clone()))), "index/");
        let emulated = ObjectIndexStore::with_store(mem.clone(), "index/");
        let mut all = vec![];
        for d in 0..5 {
            for f in 0..7 {
                all.push(format!("d{d}/f{f}"));
            }
        }
        all.extend(["d1x", "d1/sub/a", "d1/sub/b", "top", "t[1]", "t~ü"].map(String::from));
        for p in &all {
            native.cas_put(&rec(p, 1, &sk)).await.unwrap();
        }
        // deleted entries are skipped without a GET, pages still advance
        for p in ["d0/f0", "d0/f1", "d0/f2", "d3/f6"] {
            native.delete("alice.near", p, 1).await.unwrap();
            all.retain(|x| x != p);
        }
        all.sort();
        for idx in [&native, &emulated] {
            let (paths, cps, n) = pages(idx, "", None, 4).await;
            assert_eq!(paths, all);
            assert!(n >= all.len() / 4, "paged");
            let (paths, cps2, _) = pages(idx, "d1", None, 3).await;
            assert_eq!(paths, all.iter().filter(|p| p.starts_with("d1")).cloned().collect::<Vec<_>>(), "raw string prefix");
            assert!(cps.is_empty() && cps2.is_empty());
            let (paths, cps, _) = pages(idx, "", Some("/"), 2).await;
            assert_eq!(paths, vec!["d1x", "t[1]", "top", "t~ü"]);
            assert_eq!(cps, vec!["d0/", "d1/", "d2/", "d3/", "d4/"]);
            let (paths, cps, _) = pages(idx, "d1/", Some("/"), 1).await;
            assert_eq!(paths.len(), 7);
            assert_eq!(cps, vec!["d1/sub/"]);
            let p = idx.list_page("alice.near", "", Some("/"), Some("d1/"), 2).await.unwrap();
            assert_eq!(p.entries.iter().map(|e| e.record.path.as_str()).collect::<Vec<_>>(), vec!["d1x"], "a common-prefix cursor skips its subtree");
            assert_eq!(p.common_prefixes, vec!["d2/"]);
        }
        // repeated listings are served from the (key, etag) cache
        let n = native.cache.lock().unwrap().map.len();
        assert!(n >= all.len(), "{n}");
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

    #[tokio::test]
    async fn blob_listing_and_gc_delete() {
        let mem: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let s = S3BlobStore::with_store(mem.clone(), "chunks/");
        let other = S3BlobStore::with_store(mem.clone(), "other/");
        let mut cids = vec![];
        for i in 0..5u8 {
            let b = Bytes::from(vec![i; 10 + i as usize]);
            cids.push(near_drive_core::cid(&b));
            s.put(&cids[i as usize], b).await.unwrap();
        }
        let x = Bytes::from_static(b"elsewhere");
        other.put(&near_drive_core::cid(&x), x).await.unwrap();
        // junk under the chunk prefix is ignored
        for k in ["chunks/b3/zz/notahash", "chunks/b3/ab", "chunks/readme", &format!("chunks/b3/00/{}", &cids[0][3..])] {
            mem.put(&OPath::from(k), PutPayload::from_static(b"x")).await.unwrap();
        }
        let mut ls: Vec<ChunkInfo> = s.list().unwrap().try_collect().await.unwrap();
        ls.sort_by(|a, b| a.cid.cmp(&b.cid));
        let mut want = cids.clone();
        want.sort();
        assert_eq!(ls.iter().map(|c| c.cid.clone()).collect::<Vec<_>>(), want, "only this prefix's well-formed chunks");
        let i = cids.iter().position(|c| *c == ls[0].cid).unwrap();
        assert_eq!(ls[0].size, 10 + i as u64);
        let now = SystemTime::now();
        assert!(ls.iter().all(|c| c.modified <= now && now.duration_since(c.modified).unwrap() < Duration::from_secs(60)));
        // delete only if older than the cutoff (re-checked against the store)
        assert!(!s.delete_if_older(&cids[0], now - Duration::from_secs(3600)).await.unwrap(), "fresh chunk kept");
        assert!(s.has(&cids[0]).await.unwrap());
        let later = now + Duration::from_secs(3600);
        assert!(s.delete_if_older(&cids[0], later).await.unwrap());
        assert!(!s.has(&cids[0]).await.unwrap());
        assert!(!s.delete_if_older(&cids[0], later).await.unwrap(), "already gone");
        assert_eq!(s.list().unwrap().try_collect::<Vec<_>>().await.unwrap().len(), 4);
        assert_eq!(other.list().unwrap().try_collect::<Vec<_>>().await.unwrap().len(), 1);
        // empty prefix lists `b3/` only
        let root = S3BlobStore::with_store(mem.clone(), "");
        assert!(root.list().unwrap().try_collect::<Vec<_>>().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn index_namespaces() {
        let mem: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let idx = ObjectIndexStore::with_store(mem.clone(), "index/");
        assert!(idx.namespaces().await.unwrap().is_empty());
        let sk = SigningKey::from_bytes(&[1; 32]);
        idx.cas_put(&rec("a/b", 1, &sk)).await.unwrap();
        let mut bob = rec("x", 1, &sk);
        bob.record.namespace = "bob.near".into();
        idx.cas_put(&bob).await.unwrap();
        mem.put(&OPath::from("elsewhere/c.near/x"), PutPayload::from_static(b"{}")).await.unwrap();
        assert_eq!(idx.namespaces().await.unwrap(), vec!["alice.near", "bob.near"]);
        // a namespace whose records are all tombstones is listed but empty
        idx.delete("alice.near", "a/b", 1).await.unwrap();
        assert_eq!(idx.namespaces().await.unwrap().len(), 2);
        assert!(list_all(&idx, "alice.near", "").await.unwrap().is_empty());
    }

    #[test]
    fn decode() {
        assert_eq!(decode_part("a%20b%25"), "a b%");
        assert_eq!(decode_part("%2E%2E"), "..");
        assert_eq!(decode_part("x%2"), "x%2");
    }
}
