//! Rust SDK for nstorage. Does chunking, client-side encryption and request
//! signing; verifies everything it reads (record signature, manifest and
//! chunk content ids, AEAD).
use anyhow::{anyhow, bail, ensure, Context, Result};
use ed25519_dalek::SigningKey;
use nstorage_core::{
    auth,
    crypto::{self, RootKey},
    manifest::{ChunkRef, Manifest},
    record::PointerRecord,
    NearUri,
};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub use nstorage_core;

mod chain;
mod large;
pub use chain::discover_gateway;
pub use large::{Located, LocatedChunk};

pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;
pub const DEFAULT_PARALLELISM: usize = 8;
/// Request header choosing the storage class of an uploaded chunk.
pub const CLASS_HEADER: &str = "x-nst-class";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectHead {
    pub record: PointerRecord,
    pub manifest: Manifest,
    /// Exact stored manifest bytes (base64), when the gateway provides them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_raw: Option<String>,
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
}

pub struct Client {
    http: reqwest::Client,
    gateway: String,
    account: String,
    sk: SigningKey,
    root: Option<RootKey>,
    pub chunk_size: usize,
    /// Concurrent chunk transfers for put_file / put_reader / get_to_file / get_range.
    pub parallelism: usize,
    /// Last request timestamp; keeps timestamps strictly increasing so two
    /// identical concurrent requests never produce the same signature (the
    /// gateway's replay cache would reject the second one).
    last_ts: AtomicU64,
    /// `storage.near` access for sharing-by-account and policy grants.
    chain: Option<nstorage_near::StorageContract>,
}

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
        Self {
            http: reqwest::Client::new(),
            gateway: gateway.into().trim_end_matches('/').to_string(),
            account: account.into(),
            sk,
            root,
            chunk_size: DEFAULT_CHUNK_SIZE,
            parallelism: DEFAULT_PARALLELISM,
            last_ts: AtomicU64::new(0),
            chain: None,
        }
    }

    fn next_ts(&self) -> u64 {
        let now = now_ms();
        let prev = self.last_ts.fetch_max(now, Ordering::SeqCst);
        if prev < now {
            return now;
        }
        self.last_ts.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    async fn send(&self, method: Method, path: &str, query: &str, body: impl Into<bytes::Bytes>) -> Result<reqwest::Response> {
        self.send_with(method, path, query, body.into(), None).await
    }

    async fn send_with(&self, method: Method, path: &str, query: &str, body: bytes::Bytes, class: Option<&str>) -> Result<reqwest::Response> {
        let ts = self.next_ts();
        let h = auth::sign_request(&self.account, &self.sk, method.as_str(), path, query, ts, &body);
        let url = if query.is_empty() { format!("{}{}", self.gateway, path) } else { format!("{}{}?{}", self.gateway, path, query) };
        let mut req = self.http.request(method, url);
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

    async fn check(resp: reqwest::Response) -> Result<reqwest::Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let body = resp.text().await.unwrap_or_default();
        Err(GatewayError { status: status.as_u16(), body }.into())
    }

    fn obj_path(uri: &NearUri) -> String {
        format!("/v1/o/{}/{}", uri.namespace, encode_path(&uri.path))
    }

    async fn put_chunk(&self, namespace: &str, bytes: Vec<u8>, class: Option<&str>) -> Result<ChunkRef> {
        let cid = nstorage_core::cid(&bytes);
        self.upload_chunk(namespace, cid, bytes.into(), class).await
    }

    pub async fn head(&self, uri: &NearUri) -> Result<Option<ObjectHead>> {
        let resp = self.send(Method::GET, &Self::obj_path(uri), "", vec![]).await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let head: ObjectHead = Self::check(resp).await?.json().await?;
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
            ensure!(!rs.is_empty(), "no root key loaded and no share_with recipients; run `nst keygen` or use --public");
            let (c, e) = crypto::encrypt_for(&rs, data, self.chunk_size)?;
            (c, Some(e))
        };
        let mut refs = Vec::with_capacity(chunks.len());
        for c in chunks {
            refs.push(self.put_chunk(&uri.namespace, c, opts.class.as_deref()).await?);
        }
        let manifest = Manifest {
            version: 1,
            size: data.len() as u64,
            chunk_size: self.chunk_size as u64,
            chunks: refs,
            enc,
            content_type: opts.content_type.clone(),
        };
        self.commit_manifest(uri, &manifest, opts.class.as_deref()).await
    }

    /// Publish `manifest` (chunks already uploaded) as the new version of `uri`.
    async fn commit_manifest(&self, uri: &NearUri, manifest: &Manifest, class: Option<&str>) -> Result<PointerRecord> {
        let mbytes = manifest.to_bytes();
        let stored = manifest.stored_size() + mbytes.len() as u64;
        let mref = self.put_chunk(&uri.namespace, mbytes, class).await?;

        for attempt in 0..2 {
            let prev = self.head(uri).await?.map(|h| h.record.seq).unwrap_or(0);
            let rec = PointerRecord::new_signed(&uri.namespace, &uri.path, &mref.cid, manifest.size, stored, prev + 1, &self.account, &self.sk, now_ms());
            let resp = self.send(Method::PUT, &Self::obj_path(uri), "", serde_json::to_vec(&rec)?).await?;
            if resp.status() == StatusCode::CONFLICT && attempt == 0 {
                continue;
            }
            Self::check(resp).await?;
            return Ok(rec);
        }
        bail!("concurrent write conflict on {uri}")
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
        self.commit_manifest(uri, &manifest, None).await
    }

    pub async fn get(&self, uri: &NearUri) -> Result<(ObjectHead, Vec<u8>)> {
        let head = self.head(uri).await?.ok_or_else(|| anyhow!("{uri} not found"))?;
        let chunks = self.fetch_chunks(uri, &head).await?;
        let data = self.decrypt(&head, &chunks)?;
        Ok((head, data))
    }

    /// Fetch and cid-check the stored (possibly encrypted) chunks of a verified head.
    pub async fn fetch_chunks(&self, uri: &NearUri, head: &ObjectHead) -> Result<Vec<Vec<u8>>> {
        let mut chunks = Vec::with_capacity(head.manifest.chunks.len());
        for c in &head.manifest.chunks {
            let resp = self.send(Method::GET, &Self::obj_path(uri), &format!("chunk={}", c.cid), vec![]).await?;
            let bytes = Self::check(resp).await?.bytes().await?.to_vec();
            ensure!(nstorage_core::cid(&bytes) == c.cid, "chunk {} content does not match its id", c.cid);
            chunks.push(bytes);
        }
        Ok(chunks)
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

    pub async fn list(&self, prefix: &NearUri) -> Result<Vec<ListEntry>> {
        let q = format!("prefix={}", encode_path(&prefix.path));
        let resp = self.send(Method::GET, &format!("/v1/list/{}", prefix.namespace), &q, vec![]).await?;
        Ok(Self::check(resp).await?.json().await?)
    }

    pub async fn delete(&self, uri: &NearUri) -> Result<()> {
        Self::check(self.send(Method::DELETE, &Self::obj_path(uri), "", vec![]).await?).await?;
        Ok(())
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
            ensure!(nstorage_core::cid(&raw) == r.manifest_cid, "manifest does not match record");
            ensure!(Manifest::from_bytes(&raw)? == head.manifest, "manifest_raw does not match manifest");
        }
        None => ensure!(nstorage_core::cid(&head.manifest.to_bytes()) == r.manifest_cid, "manifest does not match record"),
    }
    head.manifest.validate()?;
    ensure!(head.manifest.size == r.size, "record size does not match manifest");
    Ok(())
}
