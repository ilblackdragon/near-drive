//! Rust SDK for NEAR Drive. Does chunking, client-side encryption and request
//! signing; verifies everything it reads (record signature, manifest and
//! chunk content ids, AEAD).
use anyhow::{anyhow, bail, ensure, Context, Result};
use ed25519_dalek::SigningKey;
use near_drive_core::{
    auth,
    crypto::{self, RootKey},
    manifest::{ChunkRef, Manifest},
    record::PointerRecord,
    NearUri,
};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use bytes::Bytes;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub use near_drive_core;

mod chain;
mod large;
mod net;
mod resume;
pub use chain::discover_gateway;
pub use large::{Located, LocatedChunk};
pub use net::NetConfig;
use net::{ok_or_attempt, reject, transport, with_retries, Attempt};

pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;
pub const DEFAULT_PARALLELISM: usize = 8;
/// Request header choosing the storage class of an uploaded chunk.
pub const CLASS_HEADER: &str = "x-near-drive-class";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectHead {
    pub record: PointerRecord,
    pub manifest: Manifest,
    /// Exact stored manifest bytes (base64), when the gateway provides them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_raw: Option<String>,
    /// Storage class the gateway recorded for the object (None: not recorded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
}

/// Answer of [`Client::watch`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchResult {
    pub cursor: String,
    pub changed: bool,
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListEntry {
    pub path: String,
    pub size: u64,
    pub seq: u64,
    pub writer: String,
    pub ts_ms: u64,
    /// Present on gateways that report it; lets callers derive an ETag without a HEAD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_cid: Option<String>,
}

/// Non-2xx answer from the gateway. `Display` keeps the historical
/// "gateway returned {status}: {body}" text; callers can downcast
/// (`err.downcast_ref::<GatewayError>()`) to get the status code.
#[derive(Debug, Clone)]
pub struct GatewayError {
    pub status: u16,
    pub body: String,
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = StatusCode::from_u16(self.status).map(|s| s.to_string()).unwrap_or_else(|_| self.status.to_string());
        write!(f, "gateway returned {st}: {}", self.body)
    }
}

impl std::error::Error for GatewayError {}

#[derive(Debug, Clone, Default)]
pub struct PutOptions {
    /// Store plaintext (for public data such as open model weights).
    pub public: bool,
    pub content_type: Option<String>,
    /// Extra recipients (`x25519:<base58>` keys) who can decrypt. Lets an app
    /// write data only the user can read: no owner root key + `share_with`.
    pub share_with: Vec<String>,
    /// Storage class for the chunks (`hot`, `bulk`, ...); None = gateway default.
    pub class: Option<String>,
    /// [`Client::put_file`] keeps a journal here so an interrupted upload of the
    /// same file to the same URI resumes instead of starting over. None = off.
    pub resume_dir: Option<std::path::PathBuf>,
    /// Write only if the object is currently at this seq (0 = must not exist);
    /// otherwise fail with [`Conflict`] instead of overwriting a newer version.
    pub expect_seq: Option<u64>,
}

/// A conditional write or delete found a different current version.
#[derive(Debug, Clone)]
pub struct Conflict {
    pub uri: String,
    /// Current seq (0 = the object does not exist).
    pub current: u64,
}

impl std::fmt::Display for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} changed concurrently (current seq {})", self.uri, self.current)
    }
}

impl std::error::Error for Conflict {}

pub struct Client {
    http: reqwest::Client,
    gateway: String,
    account: String,
    sk: SigningKey,
    root: Option<RootKey>,
    pub chunk_size: usize,
    /// Concurrent chunk transfers for put_file / put_reader / get_to_file / get_range.
    pub parallelism: usize,
    /// `drive.near` access for sharing-by-account and policy grants.
    chain: Option<near_drive_chain::StorageContract>,
    net: NetConfig,
}

pub(crate) fn debug(msg: &str) {
    if std::env::var_os("NEAR_DRIVE_DEBUG").is_some() {
        eprintln!("near-drive: {msg}");
    }
}

/// Last request timestamp, process-wide: timestamps strictly increase across
/// every client in the process, so two identical concurrent requests (even
/// from two clients with the same key) never produce the same signature,
/// which the gateway's replay cache would reject.
static LAST_TS: AtomicU64 = AtomicU64::new(0);

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// Percent-encode everything except RFC 3986 unreserved characters and `/`.
pub fn encode_path(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    for b in p.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl Client {
    pub fn new(gateway: impl Into<String>, account: impl Into<String>, sk: SigningKey, root: Option<RootKey>) -> Self {
        let net = NetConfig::default();
        Self {
            http: net.http_client(),
            net,
            gateway: gateway.into().trim_end_matches('/').to_string(),
            account: account.into(),
            sk,
            root,
            chunk_size: DEFAULT_CHUNK_SIZE,
            parallelism: DEFAULT_PARALLELISM,
            chain: None,
        }
    }

    fn next_ts(&self) -> u64 {
        let now = now_ms();
        let prev = LAST_TS.fetch_max(now, Ordering::SeqCst);
        if prev < now {
            return now;
        }
        LAST_TS.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    /// Timeouts and retry policy (see [`NetConfig`]).
    pub fn net(&self) -> &NetConfig {
        &self.net
    }

    pub fn set_net(&mut self, net: NetConfig) {
        self.http = net.http_client();
        self.net = net;
    }

    /// One signed request (no retries). `xfer`: payload bytes expected to move
    /// in either direction, for the request deadline.
    async fn send(&self, method: Method, path: &str, query: &str, body: impl Into<bytes::Bytes>) -> Result<reqwest::Response> {
        self.send_with(method, path, query, body.into(), None, 0).await
    }

    async fn send_with(&self, method: Method, path: &str, query: &str, body: bytes::Bytes, class: Option<&str>, xfer: u64) -> Result<reqwest::Response> {
        let ts = self.next_ts();
        let h = auth::sign_request(&self.account, &self.sk, method.as_str(), path, query, ts, &body);
        let url = if query.is_empty() { format!("{}{}", self.gateway, path) } else { format!("{}{}?{}", self.gateway, path, query) };
        let timeout = self.net.timeout_for(xfer.max(body.len() as u64));
        let mut req = self.http.request(method, url).timeout(timeout);
        if let Some(c) = class {
            req = req.header(CLASS_HEADER, c);
        }
        req
            .header(auth::H_ACCOUNT, h.account)
            .header(auth::H_PUBKEY, h.public_key)
            .header(auth::H_TS, h.ts_ms.to_string())
            .header(auth::H_SIG, h.signature)
            .body(body)
            .send()
            .await
            .context("gateway request failed")
    }

    fn obj_path(uri: &NearUri) -> String {
        format!("/v1/o/{}/{}", uri.namespace, encode_path(&uri.path))
    }

    async fn put_chunk(&self, namespace: &str, bytes: Vec<u8>, class: Option<&str>) -> Result<ChunkRef> {
        let cid = near_drive_core::cid(&bytes);
        self.upload_chunk(namespace, cid, bytes.into(), class).await
    }

    /// GET returning JSON, retried; `None` on 404.
    async fn get_json<T: serde::de::DeserializeOwned>(&self, what: &str, path: &str, query: &str) -> Result<Option<T>> {
        with_retries(&self.net, what, |_| async {
            let resp = match self.send(Method::GET, path, query, Bytes::new()).await {
                Ok(r) => r,
                Err(e) => return transport(e),
            };
            if resp.status() == StatusCode::NOT_FOUND {
                return Attempt::Done(None);
            }
            if !resp.status().is_success() {
                return reject(resp).await;
            }
            match resp.bytes().await {
                Ok(b) => match serde_json::from_slice(&b) {
                    Ok(v) => Attempt::Done(Some(v)),
                    Err(e) => Attempt::Fatal(anyhow!("bad response to {what}: {e}")),
                },
                Err(e) => transport(e.into()),
            }
        })
        .await
    }

    pub async fn head(&self, uri: &NearUri) -> Result<Option<ObjectHead>> {
        let Some(head): Option<ObjectHead> = self.get_json("head", &Self::obj_path(uri), "").await? else { return Ok(None) };
        verify_head(uri, &head)?;
        Ok(Some(head))
    }

    /// Upload `data` to `uri`. Retries once on a concurrent-write conflict.
    pub async fn put(&self, uri: &NearUri, data: &[u8], opts: &PutOptions) -> Result<PointerRecord> {
        NearUri::object(&uri.namespace, &uri.path)?;
        let (chunks, enc) = if opts.public {
            (crypto::plaintext_chunks(data, self.chunk_size)?, None)
        } else {
            let mut rs = Vec::new();
            if let Some(root) = &self.root {
                rs.push(crypto::Recipient::Owner(root));
            }
            for k in &opts.share_with {
                rs.push(crypto::Recipient::X25519(crypto::parse_x25519(k)?));
            }
            ensure!(!rs.is_empty(), "no root key loaded and no share_with recipients; run `near drive keygen` or use --public");
            let (c, e) = crypto::encrypt_for(&rs, data, self.chunk_size)?;
            (c, Some(e))
        };
        use futures_util::{StreamExt, TryStreamExt};
        let class = opts.class.as_deref();
        let refs: Vec<ChunkRef> = futures_util::stream::iter(chunks)
            .map(|c| self.put_chunk(&uri.namespace, c, class))
            .buffered(self.parallelism.max(1))
            .try_collect()
            .await?;
        let manifest = Manifest {
            version: 1,
            size: data.len() as u64,
            chunk_size: self.chunk_size as u64,
            chunks: refs,
            enc,
            content_type: opts.content_type.clone(),
        };
        self.commit_manifest(uri, &manifest, opts.class.as_deref(), opts.expect_seq).await
    }

    /// Publish `manifest` (chunks already uploaded) as the new version of `uri`.
    ///
    /// The record PUT is a compare-and-swap on `seq`, so it is the one write
    /// that is not idempotent. After a transient failure the earlier attempt
    /// may have landed; a following 409 is then checked against the current
    /// head, and if that head is this manifest by this key, the write succeeded.
    /// A conflict with someone else's write is retried once with the new seq.
    async fn commit_manifest(&self, uri: &NearUri, manifest: &Manifest, class: Option<&str>, expect_seq: Option<u64>) -> Result<PointerRecord> {
        let mbytes = manifest.to_bytes();
        let stored = manifest.stored_size() + mbytes.len() as u64;
        let (mref, mut prev) = match expect_seq {
            Some(s) => (self.put_chunk(&uri.namespace, mbytes, class).await?, s),
            None => {
                // Independent: upload the manifest chunk while reading the current seq.
                let (mref, head) = tokio::join!(self.put_chunk(&uri.namespace, mbytes, class), self.head(uri));
                (mref?, head?.map(|h| h.record.seq).unwrap_or(0))
            }
        };
        let my_pk = near_drive_core::keys::format_public_key(&self.sk.verifying_key());
        let mut maybe_landed = false;
        let mut conflicts = 0;
        let mut attempt = 0;
        loop {
            let rec = PointerRecord::new_signed(&uri.namespace, &uri.path, &mref.cid, manifest.size, stored, prev + 1, &self.account, &self.sk, now_ms());
            // Same class header as the chunks: the gateway records it in the index.
            let r = self.send_with(Method::PUT, &Self::obj_path(uri), "", serde_json::to_vec(&rec)?.into(), class, 0).await;
            let wait = match r {
                Ok(resp) if resp.status().is_success() => return Ok(rec),
                Ok(resp) if resp.status() == StatusCode::CONFLICT => {
                    let cur = self.head(uri).await?;
                    if let Some(h) = &cur {
                        if maybe_landed && h.record.manifest_cid == mref.cid && h.record.writer_pk == my_pk && h.record.seq == prev + 1 {
                            return Ok(h.record.clone());
                        }
                    }
                    if expect_seq.is_some() {
                        return Err(Conflict { uri: uri.to_string(), current: cur.map(|h| h.record.seq).unwrap_or(0) }.into());
                    }
                    conflicts += 1;
                    if conflicts >= 2 {
                        bail!("concurrent write conflict on {uri}");
                    }
                    prev = cur.map(|h| h.record.seq).unwrap_or(0);
                    continue;
                }
                Ok(resp) => match reject::<()>(resp).await {
                    Attempt::Retry(e, w) => (e, w),
                    Attempt::Fatal(e) => return Err(e),
                    Attempt::Done(()) => unreachable!("reject never succeeds"),
                },
                Err(e) => (e, None),
            };
            maybe_landed = true;
            attempt += 1;
            if attempt >= self.net.attempts.max(1) {
                debug(&format!("committing {uri}: giving up after {attempt} attempts"));
                return Err(wait.0);
            }
            tokio::time::sleep(self.net.delay(attempt - 1, wait.1)).await;
        }
    }

    /// This account's public key for receiving shared objects.
    pub fn x25519_public(&self) -> Option<String> {
        self.root.as_ref().map(RootKey::x25519_public)
    }

    /// Re-wrap the object key of `uri` to `recipient` (`x25519:<base58>`).
    /// Chunks are reused; only a new manifest and record are written. The
    /// recipient also needs read access via namespace policy.
    pub async fn share(&self, uri: &NearUri, recipient: &str) -> Result<PointerRecord> {
        let root = self.root.as_ref().ok_or_else(|| anyhow!("sharing requires the root key"))?;
        let head = self.head(uri).await?.ok_or_else(|| anyhow!("{uri} not found"))?;
        let enc = head.manifest.enc.as_ref().ok_or_else(|| anyhow!("{uri} is public; nothing to share"))?;
        let enc = crypto::add_recipient(root, enc, &crypto::Recipient::X25519(crypto::parse_x25519(recipient)?))?;
        let manifest = Manifest { enc: Some(enc), ..head.manifest };
        // Chunks are reused, so the object keeps its class.
        self.commit_manifest(uri, &manifest, head.class.as_deref(), None).await
    }

    pub async fn get(&self, uri: &NearUri) -> Result<(ObjectHead, Vec<u8>)> {
        let head = self.head(uri).await?.ok_or_else(|| anyhow!("{uri} not found"))?;
        let chunks = self.fetch_chunks(uri, &head).await?;
        let data = self.decrypt(&head, &chunks)?;
        Ok((head, data))
    }

    /// Fetch and cid-check the stored (possibly encrypted) chunks of a verified head.
    pub async fn fetch_chunks(&self, uri: &NearUri, head: &ObjectHead) -> Result<Vec<Vec<u8>>> {
        use futures_util::{StreamExt, TryStreamExt};
        futures_util::stream::iter(head.manifest.chunks.iter().enumerate())
            .map(|(i, c)| async move { Ok::<_, anyhow::Error>(self.fetch_via_gateway(uri, &c.cid, i, c.len).await?.to_vec()) })
            .buffered(self.parallelism.max(1))
            .try_collect()
            .await
    }

    /// Turn the chunks returned by [`Client::fetch_chunks`] into plaintext.
    pub fn decrypt(&self, head: &ObjectHead, chunks: &[Vec<u8>]) -> Result<Vec<u8>> {
        let data = match &head.manifest.enc {
            None => chunks.concat(),
            Some(enc) => {
                let root = self.root.as_ref().ok_or_else(|| anyhow!("object is encrypted and no root key is loaded"))?;
                crypto::decrypt_object(root, enc, chunks)?
            }
        };
        ensure!(data.len() as u64 == head.manifest.size, "size mismatch");
        Ok(data)
    }

    /// Long poll: returns when something under `prefix` changes (through
    /// this gateway) or after `timeout`. Pass `None` first to get a cursor,
    /// then the returned cursor each time. `changed` with no `paths` means
    /// "re-list". `Ok(None)`: the gateway has no watch support.
    pub async fn watch(&self, prefix: &NearUri, cursor: Option<&str>, timeout: std::time::Duration) -> Result<Option<WatchResult>> {
        let mut q = format!("prefix={}&timeout_ms={}", encode_path(&prefix.path), timeout.as_millis());
        if let Some(c) = cursor {
            q.push_str(&format!("&cursor={}", encode_path(c)));
        }
        let path = format!("/v1/watch/{}", prefix.namespace);
        let resp = self
            // request deadline = base + the long-poll wait
            .send_with(Method::GET, &path, &q, Bytes::new(), None, timeout.as_secs().saturating_mul(self.net.min_throughput))
            .await
            .map_err(|e| e.context("watch"))?;
        if resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::METHOD_NOT_ALLOWED {
            return Ok(None);
        }
        match ok_or_attempt(Ok(resp)).await {
            Attempt::Done(r) => Ok(Some(r.json().await?)),
            Attempt::Retry(e, _) | Attempt::Fatal(e) => Err(e),
        }
    }

    pub async fn list(&self, prefix: &NearUri) -> Result<Vec<ListEntry>> {
        let q = format!("prefix={}", encode_path(&prefix.path));
        Ok(self.get_json("list", &format!("/v1/list/{}", prefix.namespace), &q).await?.unwrap_or_default())
    }

    /// Delete `uri`. Retried; a 404 after a failed attempt means that attempt
    /// already deleted it.
    pub async fn delete(&self, uri: &NearUri) -> Result<()> {
        self.delete_inner(uri, None).await
    }

    /// Delete `uri` only if its current version is `seq`; otherwise [`Conflict`].
    pub async fn delete_if(&self, uri: &NearUri, seq: u64) -> Result<()> {
        self.delete_inner(uri, Some(seq)).await
    }

    async fn delete_inner(&self, uri: &NearUri, seq: Option<u64>) -> Result<()> {
        let path = Self::obj_path(uri);
        let q = seq.map(|s| format!("seq={s}")).unwrap_or_default();
        with_retries(&self.net, "delete", |attempt| {
            let (path, q) = (path.clone(), q.clone());
            async move {
                match self.send(Method::DELETE, &path, &q, Bytes::new()).await {
                    Ok(r) if r.status() == StatusCode::NOT_FOUND && attempt > 0 => Attempt::Done(()),
                    Ok(r) if r.status() == StatusCode::CONFLICT && seq.is_some() => {
                        let body = r.text().await.unwrap_or_default();
                        let current = body.rsplit("current seq is ").next().and_then(|t| t.trim_matches(|c: char| !c.is_ascii_digit()).parse().ok()).unwrap_or(0);
                        Attempt::Fatal(Conflict { uri: uri.to_string(), current }.into())
                    }
                    r => match ok_or_attempt(r).await {
                        Attempt::Done(_) => Attempt::Done(()),
                        Attempt::Retry(e, w) => Attempt::Retry(e, w),
                        Attempt::Fatal(e) => Attempt::Fatal(e),
                    },
                }
            }
        })
        .await
    }
}

/// Client-side checks on what a (possibly untrusted) gateway returned.
pub fn verify_head(uri: &NearUri, head: &ObjectHead) -> Result<()> {
    let r = &head.record;
    ensure!(r.namespace == uri.namespace && r.path == uri.path, "gateway returned a record for a different object");
    r.verify_signature()?;
    match &head.manifest_raw {
        Some(raw) => {
            use base64::Engine;
            let raw = base64::engine::general_purpose::STANDARD.decode(raw).context("bad manifest_raw")?;
            ensure!(near_drive_core::cid(&raw) == r.manifest_cid, "manifest does not match record");
            ensure!(Manifest::from_bytes(&raw)? == head.manifest, "manifest_raw does not match manifest");
        }
        None => ensure!(near_drive_core::cid(&head.manifest.to_bytes()) == r.manifest_cid, "manifest does not match record"),
    }
    head.manifest.validate()?;
    ensure!(head.manifest.size == r.size, "record size does not match manifest");
    Ok(())
}
