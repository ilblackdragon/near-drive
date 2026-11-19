//! HTTP "blob bridge" backend: a [`BlobStore`] that talks to an external
//! service (e.g. the Filecoin / Shelby bridges). The protocol is specified in
//! `docs/blob-bridge.md`; [`reference_router`] is a reference server
//! implementation of it (used by tests, and handy for checking a bridge).
use crate::store::{slice_range, BlobStore, DirectUrl};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use axum::{
    body::Bytes as AxBytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use bytes::Bytes;
use reqwest::header::{AUTHORIZATION, RANGE};
use serde::{Deserialize, Serialize};
use std::{ops::Range, sync::Arc, time::Duration};

/// `{"type":"bridge", ...}` in gateway config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Base URL; requests go to `{url}/blobs/{cid}`.
    pub url: String,
    /// Sent as `Authorization: Bearer <token>`.
    #[serde(default)]
    pub token: Option<String>,
    /// Per-request timeout (default 300 s; chunks can be 64 MiB).
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

pub struct BridgeBlobStore {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
}

impl BridgeBlobStore {
    pub fn new(cfg: &BridgeConfig) -> Result<Self> {
        let http = reqwest::Client::builder().timeout(Duration::from_secs(cfg.timeout_secs.unwrap_or(300))).build()?;
        Ok(Self { http, base: cfg.url.trim_end_matches('/').to_string(), token: cfg.token.clone() })
    }

    fn req(&self, method: reqwest::Method, cid: &str, suffix: &str) -> Result<reqwest::RequestBuilder> {
        if !nstorage_core::is_valid_cid(cid) {
            bail!("bad cid");
        }
        let mut r = self.http.request(method, format!("{}/blobs/{cid}{suffix}", self.base));
        if let Some(t) = &self.token {
            r = r.header(AUTHORIZATION, format!("Bearer {t}"));
        }
        Ok(r)
    }
}

async fn fail(what: &str, resp: reqwest::Response) -> anyhow::Error {
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    anyhow!("blob bridge {what} returned {status}: {}", body.chars().take(200).collect::<String>())
}

#[async_trait]
impl BlobStore for BridgeBlobStore {
    async fn put(&self, cid: &str, bytes: Bytes) -> Result<()> {
        let resp = self.req(reqwest::Method::PUT, cid, "")?.body(bytes).send().await.context("blob bridge PUT")?;
        if resp.status().is_success() {
            return Ok(());
        }
        Err(fail("PUT", resp).await)
    }

    async fn get(&self, cid: &str) -> Result<Option<Bytes>> {
        let resp = self.req(reqwest::Method::GET, cid, "")?.send().await.context("blob bridge GET")?;
        match resp.status() {
            StatusCode::OK => Ok(Some(resp.bytes().await?)),
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(fail("GET", resp).await),
        }
    }

    async fn get_range(&self, cid: &str, range: Range<u64>) -> Result<Option<Bytes>> {
        if range.start >= range.end {
            return Ok(if self.has(cid).await? { Some(Bytes::new()) } else { None });
        }
        let resp = self
            .req(reqwest::Method::GET, cid, "")?
            .header(RANGE, format!("bytes={}-{}", range.start, range.end - 1))
            .send()
            .await
            .context("blob bridge ranged GET")?;
        match resp.status() {
            StatusCode::PARTIAL_CONTENT => Ok(Some(resp.bytes().await?)),
            // bridge ignored Range: slice locally
            StatusCode::OK => Ok(Some(slice_range(&resp.bytes().await?, &range))),
            StatusCode::RANGE_NOT_SATISFIABLE => Ok(Some(Bytes::new())),
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(fail("GET", resp).await),
        }
    }

    async fn has(&self, cid: &str) -> Result<bool> {
        let resp = self.req(reqwest::Method::HEAD, cid, "")?.send().await.context("blob bridge HEAD")?;
        match resp.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            s => bail!("blob bridge HEAD returned {s}"),
        }
    }

    async fn direct_url(&self, cid: &str) -> Result<Option<DirectUrl>> {
        let resp = self.req(reqwest::Method::GET, cid, "/url")?.send().await.context("blob bridge GET url")?;
        match resp.status() {
            StatusCode::OK => Ok(Some(resp.json().await.context("blob bridge /url: bad JSON")?)),
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(fail("GET url", resp).await),
        }
    }
}

/// Parse a single-range `Range` header (`bytes=a-b`, `bytes=a-`, `bytes=-n`)
/// against an object of `len` bytes into a half-open range. `Err(())` means
/// unsatisfiable (416); `Ok(None)` means no usable Range header (serve all).
pub fn parse_range(h: Option<&str>, len: u64) -> Result<Option<Range<u64>>, ()> {
    let Some(spec) = h.and_then(|h| h.trim().strip_prefix("bytes=")) else { return Ok(None) };
    if spec.contains(',') {
        return Ok(None); // multi-range: serve the whole thing
    }
    let Some((a, b)) = spec.split_once('-') else { return Ok(None) };
    let (a, b) = (a.trim(), b.trim());
    let r = if a.is_empty() {
        let n: u64 = b.parse().map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        len.saturating_sub(n)..len
    } else {
        let s: u64 = a.parse().map_err(|_| ())?;
        let e = if b.is_empty() { len } else { b.parse::<u64>().map_err(|_| ())?.saturating_add(1).min(len) };
        if s >= len || e <= s {
            return Err(());
        }
        s..e
    };
    Ok(Some(r))
}

/// Serve `bytes` honoring an optional Range header: 200, 206 or 416.
pub fn ranged_response(headers: &HeaderMap, bytes: Bytes) -> Response {
    let len = bytes.len() as u64;
    match parse_range(headers.get(header::RANGE).and_then(|v| v.to_str().ok()), len) {
        Ok(None) => ([(header::CONTENT_TYPE, "application/octet-stream".to_string()), (header::ACCEPT_RANGES, "bytes".into())], bytes).into_response(),
        Ok(Some(r)) => (
            StatusCode::PARTIAL_CONTENT,
            [
                (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                (header::CONTENT_RANGE, format!("bytes {}-{}/{len}", r.start, r.end - 1)),
            ],
            bytes.slice(r.start as usize..r.end as usize),
        )
            .into_response(),
        Err(()) => (StatusCode::RANGE_NOT_SATISFIABLE, [(header::CONTENT_RANGE, format!("bytes */{len}"))]).into_response(),
    }
}

/// Reference blob-bridge server over any [`BlobStore`].
#[derive(Clone)]
pub struct ReferenceBridge {
    pub store: Arc<dyn BlobStore>,
    /// Required bearer token, if any.
    pub token: Option<String>,
    /// If set, `GET /blobs/{cid}/url` returns `{public_base}/public/{cid}`
    /// (served without auth, no expiry); otherwise it returns 404.
    pub public_base: Option<String>,
}

pub fn reference_router(b: ReferenceBridge) -> Router {
    Router::new()
        .route("/blobs/{cid}", get(ref_get).head(ref_head).put(ref_put))
        .route("/blobs/{cid}/url", get(ref_url))
        .route("/public/{cid}", get(ref_public))
        .layer(DefaultBodyLimit::max(nstorage_core::manifest::MAX_CHUNK_BYTES as usize + 1024 * 1024))
        .with_state(b)
}

fn ref_auth(b: &ReferenceBridge, h: &HeaderMap) -> Result<(), StatusCode> {
    match &b.token {
        None => Ok(()),
        Some(t) if h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {t}")) => Ok(()),
        Some(_) => Err(StatusCode::UNAUTHORIZED),
    }
}

fn ise(e: anyhow::Error) -> StatusCode {
    tracing::error!("reference bridge: {e:#}");
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn ref_put(State(b): State<ReferenceBridge>, Path(cid): Path<String>, h: HeaderMap, body: AxBytes) -> Result<StatusCode, StatusCode> {
    ref_auth(&b, &h)?;
    if !nstorage_core::is_valid_cid(&cid) || nstorage_core::cid(&body) != cid {
        return Err(StatusCode::BAD_REQUEST);
    }
    let existed = b.store.has(&cid).await.map_err(ise)?;
    b.store.put(&cid, body).await.map_err(ise)?;
    Ok(if existed { StatusCode::OK } else { StatusCode::CREATED })
}

async fn ref_get(State(b): State<ReferenceBridge>, Path(cid): Path<String>, h: HeaderMap) -> Result<Response, StatusCode> {
    ref_auth(&b, &h)?;
    serve(&b, &cid, &h).await
}

async fn ref_public(State(b): State<ReferenceBridge>, Path(cid): Path<String>, h: HeaderMap) -> Result<Response, StatusCode> {
    if b.public_base.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    serve(&b, &cid, &h).await
}

async fn serve(b: &ReferenceBridge, cid: &str, h: &HeaderMap) -> Result<Response, StatusCode> {
    if !nstorage_core::is_valid_cid(cid) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let bytes = b.store.get(cid).await.map_err(ise)?.ok_or(StatusCode::NOT_FOUND)?;
    Ok(ranged_response(h, bytes))
}

async fn ref_head(State(b): State<ReferenceBridge>, Path(cid): Path<String>, h: HeaderMap) -> Result<StatusCode, StatusCode> {
    ref_auth(&b, &h)?;
    if !nstorage_core::is_valid_cid(&cid) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(if b.store.has(&cid).await.map_err(ise)? { StatusCode::OK } else { StatusCode::NOT_FOUND })
}

async fn ref_url(State(b): State<ReferenceBridge>, Path(cid): Path<String>, h: HeaderMap) -> Result<Json<DirectUrl>, StatusCode> {
    ref_auth(&b, &h)?;
    let base = b.public_base.as_ref().ok_or(StatusCode::NOT_FOUND)?;
    if !nstorage_core::is_valid_cid(&cid) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !b.store.has(&cid).await.map_err(ise)? {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(Json(DirectUrl { url: format!("{}/public/{cid}", base.trim_end_matches('/')), expires_ms: None }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::FsBlobStore;

    #[test]
    fn ranges() {
        assert_eq!(parse_range(None, 10), Ok(None));
        assert_eq!(parse_range(Some("bytes=2-4"), 10), Ok(Some(2..5)));
        assert_eq!(parse_range(Some("bytes=2-"), 10), Ok(Some(2..10)));
        assert_eq!(parse_range(Some("bytes=2-100"), 10), Ok(Some(2..10)));
        assert_eq!(parse_range(Some("bytes=-3"), 10), Ok(Some(7..10)));
        assert_eq!(parse_range(Some("bytes=10-"), 10), Err(()));
        assert_eq!(parse_range(Some("bytes=5-4"), 10), Err(()));
        assert_eq!(parse_range(Some("bytes=0-1,4-5"), 10), Ok(None));
    }

    #[tokio::test]
    async fn client_against_reference_server() {
        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let r = ReferenceBridge {
            store: Arc::new(FsBlobStore::new(dir.path().to_path_buf())),
            token: Some("s3cret".into()),
            public_base: Some(base.clone()),
        };
        tokio::spawn(async move { axum::serve(listener, reference_router(r)).await.unwrap() });

        let c = BridgeBlobStore::new(&BridgeConfig { url: format!("{base}/"), token: Some("s3cret".into()), timeout_secs: None }).unwrap();
        let data = Bytes::from((0..1000u32).map(|i| i as u8).collect::<Vec<_>>());
        let cid = nstorage_core::cid(&data);
        assert!(!c.has(&cid).await.unwrap());
        assert!(c.get(&cid).await.unwrap().is_none());
        assert!(c.direct_url(&cid).await.unwrap().is_none());
        c.put(&cid, data.clone()).await.unwrap();
        c.put(&cid, data.clone()).await.unwrap(); // idempotent
        assert!(c.has(&cid).await.unwrap());
        assert_eq!(c.get(&cid).await.unwrap().unwrap(), data);
        assert_eq!(c.get_range(&cid, 10..20).await.unwrap().unwrap(), data.slice(10..20));
        assert_eq!(c.get_range(&cid, 990..2000).await.unwrap().unwrap(), data.slice(990..));
        let u = c.direct_url(&cid).await.unwrap().unwrap();
        assert_eq!(reqwest::get(&u.url).await.unwrap().bytes().await.unwrap(), data);

        // wrong token / wrong cid are rejected
        let bad = BridgeBlobStore::new(&BridgeConfig { url: base.clone(), token: Some("nope".into()), timeout_secs: None }).unwrap();
        assert!(bad.get(&cid).await.is_err());
        let other = nstorage_core::cid(b"other");
        assert!(c.put(&other, data.clone()).await.unwrap_err().to_string().contains("400"));
    }
}
