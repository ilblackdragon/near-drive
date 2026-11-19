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
use std::time::{SystemTime, UNIX_EPOCH};

pub use nstorage_core;

pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectHead {
    pub record: PointerRecord,
    pub manifest: Manifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListEntry {
    pub path: String,
    pub size: u64,
    pub seq: u64,
    pub writer: String,
    pub ts_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct PutOptions {
    /// Store plaintext (for public data such as open model weights).
    pub public: bool,
    pub content_type: Option<String>,
}

pub struct Client {
    http: reqwest::Client,
    gateway: String,
    account: String,
    sk: SigningKey,
    root: Option<RootKey>,
    pub chunk_size: usize,
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
        }
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    async fn send(&self, method: Method, path: &str, query: &str, body: Vec<u8>) -> Result<reqwest::Response> {
        let ts = now_ms();
        let h = auth::sign_request(&self.account, &self.sk, method.as_str(), path, query, ts, &body);
        let url = if query.is_empty() { format!("{}{}", self.gateway, path) } else { format!("{}{}?{}", self.gateway, path, query) };
        self.http
            .request(method, url)
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
        let text = resp.text().await.unwrap_or_default();
        bail!("gateway returned {status}: {text}")
    }

    fn obj_path(uri: &NearUri) -> String {
        format!("/v1/o/{}/{}", uri.namespace, encode_path(&uri.path))
    }

    async fn put_chunk(&self, namespace: &str, bytes: Vec<u8>) -> Result<ChunkRef> {
        let cid = nstorage_core::cid(&bytes);
        let len = bytes.len() as u64;
        let path = format!("/v1/chunk/{namespace}/{cid}");
        Self::check(self.send(Method::PUT, &path, "", bytes).await?).await?;
        Ok(ChunkRef { cid, len })
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
            let root = self.root.as_ref().ok_or_else(|| anyhow!("no root key loaded; run `nst keygen` or use --public"))?;
            let (c, e) = crypto::encrypt_object(root, data, self.chunk_size)?;
            (c, Some(e))
        };
        let mut refs = Vec::with_capacity(chunks.len());
        for c in chunks {
            refs.push(self.put_chunk(&uri.namespace, c).await?);
        }
        let manifest = Manifest {
            version: 1,
            size: data.len() as u64,
            chunk_size: self.chunk_size as u64,
            chunks: refs,
            enc,
            content_type: opts.content_type.clone(),
        };
        let mbytes = manifest.to_bytes();
        let stored = manifest.stored_size() + mbytes.len() as u64;
        let mref = self.put_chunk(&uri.namespace, mbytes).await?;

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

    pub async fn get(&self, uri: &NearUri) -> Result<(ObjectHead, Vec<u8>)> {
        let head = self.head(uri).await?.ok_or_else(|| anyhow!("{uri} not found"))?;
        let mut chunks = Vec::with_capacity(head.manifest.chunks.len());
        for c in &head.manifest.chunks {
            let resp = self.send(Method::GET, &Self::obj_path(uri), &format!("chunk={}", c.cid), vec![]).await?;
            let bytes = Self::check(resp).await?.bytes().await?.to_vec();
            ensure!(nstorage_core::cid(&bytes) == c.cid, "chunk {} content does not match its id", c.cid);
            chunks.push(bytes);
        }
        let data = match &head.manifest.enc {
            None => chunks.concat(),
            Some(enc) => {
                let root = self.root.as_ref().ok_or_else(|| anyhow!("object is encrypted and no root key is loaded"))?;
                crypto::decrypt_object(root, enc, &chunks)?
            }
        };
        ensure!(data.len() as u64 == head.manifest.size, "size mismatch");
        Ok((head, data))
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
    ensure!(nstorage_core::cid(&head.manifest.to_bytes()) == r.manifest_cid, "manifest does not match record");
    head.manifest.validate()?;
    ensure!(head.manifest.size == r.size, "record size does not match manifest");
    Ok(())
}
