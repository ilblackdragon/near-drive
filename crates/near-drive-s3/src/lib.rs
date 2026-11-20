//! `near drive s3-proxy`: an S3-compatible sidecar for NEAR Drive.
//!
//! Listens on loopback only, authenticates S3 clients with SigV4 against
//! local credentials and translates requests to the NEAR Drive native API via
//! [`backend::ObjectBackend`] (client-side encryption with the user's root
//! key, requests signed with the user's NEAR key).
//!
//! Mapping: bucket = NEAR namespace (account id), key = object path.
//! Path-style (`http://127.0.0.1:9000/alice.near/key`) and virtual-host
//! style for `<bucket>.localhost` are accepted.
//!
//! User metadata (`x-amz-meta-*`) is kept in an encrypted sidecar object
//! `<key>.drive-s3meta` (JSON `{"for": manifest_cid, "meta": {...}}`), which
//! is hidden from listings. The main object's stored content type carries a
//! `;drive-s3-meta=1` marker so reads only fetch the sidecar when it exists,
//! and the sidecar only applies while `for` matches the object's manifest.
pub mod backend;
pub mod credentials;
pub mod error;
pub mod multipart;
pub mod stream;
pub mod sigv4;
pub mod xml;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::Response,
    Router,
};
use backend::{BackendError, GetResult, ListItem, ObjectBackend, ObjectData, ObjectInfo, ObjectSink, PutParams, PutSource, RangeSpec};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use error::{S3Error, S3Result};
use multipart::{Staging, UploadMeta};
use near_drive_client::near_drive_core::{uri::validate_account_id, NearUri};
use serde::{Deserialize, Serialize};
use sigv4::Credentials;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use xml::{escape, iso8601};

pub const META_SUFFIX: &str = ".drive-s3meta";
const META_MARK: &str = ";drive-s3-meta=1";
const NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";
const XML_DECL: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub credentials: Credentials,
    /// Namespaces besides the proxy's own account shown in ListBuckets.
    pub extra_buckets: Vec<String>,
    /// Keys starting with any of these are stored unencrypted (public data).
    pub public_prefixes: Vec<String>,
    /// Multipart staging directory.
    pub staging_dir: PathBuf,
    /// Max request body (single PUT / part) held in memory.
    pub max_body_bytes: usize,
    /// Region reported by GetBucketLocation. Any region is accepted in signatures.
    pub region: String,
    /// Bucket names mapped onto NEAR Drive folders (existing bucket names keep working).
    pub aliases: BTreeMap<String, backend::Alias>,
    /// Browser origins allowed to call the endpoint (CORS), e.g. for presigned
    /// uploads from a web page. `*` = any. Empty = no CORS headers.
    pub cors_origins: Vec<String>,
    /// Domains for virtual-host addressing: `<bucket>.<domain>`.
    pub vhost_domains: Vec<String>,
}

impl ProxyConfig {
    pub fn new(credentials: Credentials, staging_dir: PathBuf) -> Self {
        Self {
            credentials,
            extra_buckets: vec![],
            public_prefixes: vec![],
            staging_dir,
            max_body_bytes: 5 * 1024 * 1024 * 1024,
            region: "us-east-1".into(),
            aliases: BTreeMap::new(),
            cors_origins: vec![],
            vhost_domains: vec!["localhost".into()],
        }
    }
}

pub struct Proxy<B: ObjectBackend> {
    cfg: ProxyConfig,
    backend: backend::Aliased<B>,
    staging: Staging,
    sessions: stream::Sessions<B::Sink>,
    started_ms: u64,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// Refuse anything that is not a loopback address.
pub fn check_loopback(addr: &SocketAddr) -> anyhow::Result<()> {
    anyhow::ensure!(addr.ip().is_loopback(), "s3-proxy only listens on loopback (127.0.0.1 / ::1), not {addr}");
    Ok(())
}

/// Non-loopback listening is for deployments behind a TLS-terminating proxy
/// (so presigned URLs work for remote machines); it must be asked for.
pub fn check_listen(addr: &SocketAddr, public: bool) -> anyhow::Result<()> {
    if public {
        return Ok(());
    }
    check_loopback(addr).map_err(|e| e.context("pass --public-listen to serve other machines (behind TLS)"))
}

pub fn router<B: ObjectBackend>(p: Arc<Proxy<B>>) -> Router {
    Router::new().fallback(handle::<B>).with_state(p)
}

/// Bind `addr` and serve until the task is dropped. Loopback only, unless
/// `public` (see [`check_listen`]).
pub async fn run<B: ObjectBackend>(addr: SocketAddr, p: Arc<Proxy<B>>, public: bool) -> anyhow::Result<()> {
    check_listen(&addr, public)?;
    let l = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(l, router(p)).await?;
    Ok(())
}

impl<B: ObjectBackend> Proxy<B> {
    pub fn new(cfg: ProxyConfig, backend: B) -> Arc<Self> {
        // Multipart uploads stream into the object from an in-memory session,
        // so none survives a restart: drop whatever an earlier run left.
        Staging::cleanup(&cfg.staging_dir, Duration::ZERO);
        let backend = backend::Aliased { inner: backend, aliases: cfg.aliases.clone() };
        Arc::new(Self { staging: Staging::new(cfg.staging_dir.clone()), sessions: Default::default(), cfg, backend, started_ms: now_ms() })
    }

    pub fn config(&self) -> &ProxyConfig {
        &self.cfg
    }
}

/// The request's Origin if CORS allows it.
fn cors_origin(cfg: &ProxyConfig, h: &HeaderMap) -> Option<HeaderValue> {
    let origin = h.get(header::ORIGIN)?;
    let o = origin.to_str().ok()?;
    cfg.cors_origins.iter().any(|a| a == "*" || a == o).then(|| origin.clone())
}

fn cors_headers(h: &mut HeaderMap, origin: HeaderValue) {
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    h.insert(header::VARY, HeaderValue::from_static("Origin"));
    // Browser multipart uploads read the part ETag.
    h.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, HeaderValue::from_static("ETag, x-amz-request-id, x-amz-version-id, Content-Range, Content-Length"));
}

async fn handle<B: ObjectBackend>(State(p): State<Arc<Proxy<B>>>, req: Request) -> Response {
    let origin = cors_origin(&p.cfg, req.headers());
    // CORS preflight: answered without authentication (browsers send no credentials).
    if req.method() == Method::OPTIONS {
        let Some(origin) = origin else { return S3Error::new(StatusCode::FORBIDDEN, "AccessForbidden", "CORSResponse: This CORS request is not allowed.").into_response(req.uri().path(), "0", false) };
        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = StatusCode::OK;
        let h = resp.headers_mut();
        cors_headers(h, origin);
        h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, PUT, POST, DELETE, HEAD"));
        let asked = req.headers().get(header::ACCESS_CONTROL_REQUEST_HEADERS).cloned().unwrap_or(HeaderValue::from_static("*"));
        h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, asked);
        h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("3600"));
        return resp;
    }
    let rid = hex::encode_upper(rand::random::<[u8; 8]>());
    let is_head = req.method() == Method::HEAD;
    let resource = req.uri().path().to_string();
    let method = req.method().clone();
    let mut resp = match p.dispatch(req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::info!("{method} {resource} -> {} {}: {}", e.status.as_u16(), e.code, e.message);
            e.into_response(&resource, &rid, is_head)
        }
    };
    let h = resp.headers_mut();
    h.insert("x-amz-request-id", HeaderValue::from_str(&rid).expect("hex"));
    h.insert(header::SERVER, HeaderValue::from_static("near-drive-s3"));
    if let Some(o) = origin {
        cors_headers(h, o);
    }
    resp
}

/// Decoded query parameters.
struct Q(Vec<(String, String)>);

impl Q {
    fn get(&self, k: &str) -> Option<&str> {
        self.0.iter().find(|(qk, _)| qk == k).map(|(_, v)| v.as_str())
    }
    fn has(&self, k: &str) -> bool {
        self.0.iter().any(|(qk, _)| qk == k)
    }
}

fn hstr<'a>(h: &'a HeaderMap, n: &str) -> Option<&'a str> {
    h.get(n).and_then(|v| v.to_str().ok())
}

fn etag(cid: &str) -> String {
    format!("\"{}\"", cid.strip_prefix("b3:").unwrap_or(cid).get(..32).unwrap_or(cid))
}

fn list_etag(it: &ListItem) -> String {
    match &it.manifest_cid {
        Some(c) => etag(c),
        None => etag(&fallback_hex(format!("{}|{}|{}", it.key, it.ts_ms, it.size).as_bytes())),
    }
}

fn fallback_hex(b: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(b))
}

fn user_meta(h: &HeaderMap) -> BTreeMap<String, String> {
    h.iter()
        .filter_map(|(n, v)| Some((n.as_str().strip_prefix("x-amz-meta-")?.to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())))
        .collect()
}

fn split_ct(stored: Option<&str>) -> (Option<String>, bool) {
    match stored {
        None => (None, false),
        Some(s) => match s.strip_suffix(META_MARK) {
            Some(rest) => ((!rest.is_empty()).then(|| rest.to_string()), true),
            None => (Some(s.to_string()), false),
        },
    }
}

fn xml_response(status: StatusCode, body: String) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/xml")
        .body(Body::from(format!("{XML_DECL}{body}")))
        .expect("valid response")
}

fn empty(status: StatusCode) -> Response {
    Response::builder().status(status).body(Body::empty()).expect("valid response")
}

pub(crate) fn map_backend(e: BackendError) -> S3Error {
    match e {
        BackendError::NotFound => S3Error::no_such_key(),
        BackendError::RangeNotSatisfiable { .. } => {
            S3Error::new(StatusCode::RANGE_NOT_SATISFIABLE, "InvalidRange", "The requested range is not satisfiable")
        }
        BackendError::Gateway { status, body } => match status {
            401 => S3Error::access_denied(format!("NEAR Drive gateway rejected this proxy's NEAR key: {body}")),
            403 => S3Error::access_denied(format!("NEAR Drive gateway denied access: {body}")),
            409 => S3Error::new(StatusCode::CONFLICT, "OperationAborted", "A conflicting operation is currently in progress against this object. Please try again."),
            413 => S3Error::new(StatusCode::BAD_REQUEST, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed object size."),
            429 | 503 => S3Error::new(StatusCode::SERVICE_UNAVAILABLE, "SlowDown", format!("gateway is busy: {body}")),
            400..=499 => S3Error::invalid_request(format!("gateway rejected the request ({status}): {body}")),
            _ => S3Error::new(StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable", format!("gateway error {status}: {body}")),
        },
        BackendError::Decrypt(m) => S3Error::access_denied(format!("object cannot be decrypted with this account's root key: {m}")),
        BackendError::Invalid(m) => S3Error::invalid_argument(m),
        BackendError::Other(e) => {
            tracing::error!("backend error: {e:#}");
            S3Error::new(StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable", format!("NEAR Drive request failed: {e:#}"))
        }
    }
}

#[derive(Serialize, Deserialize)]
struct MetaSidecar {
    #[serde(rename = "for")]
    for_cid: String,
    meta: BTreeMap<String, String>,
}

/// Object listing page.
struct Page {
    contents: Vec<ListItem>,
    prefixes: Vec<String>,
    truncated: bool,
    last: Option<String>,
}

fn http_date_secs(s: &str) -> Option<u64> {
    httpdate::parse_http_date(s).ok()?.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

/// Evaluate If-Match / If-None-Match / If-(Un)Modified-Since.
/// Returns `Some(status)` (304 or 412) when the request must not proceed.
fn conditional(h: &HeaderMap, info: &ObjectInfo, read: bool) -> Option<StatusCode> {
    let et = etag(&info.manifest_cid);
    let lm = info.ts_ms / 1000;
    let matches = |v: &str| v.split(',').map(str::trim).any(|t| t == "*" || t.trim_start_matches("W/") == et);
    if let Some(v) = hstr(h, "if-match") {
        if !matches(v) {
            return Some(StatusCode::PRECONDITION_FAILED);
        }
    } else if let Some(t) = hstr(h, "if-unmodified-since").and_then(http_date_secs) {
        if lm > t {
            return Some(StatusCode::PRECONDITION_FAILED);
        }
    }
    if let Some(v) = hstr(h, "if-none-match") {
        if matches(v) {
            return Some(if read { StatusCode::NOT_MODIFIED } else { StatusCode::PRECONDITION_FAILED });
        }
    } else if let Some(t) = hstr(h, "if-modified-since").and_then(http_date_secs) {
        if read && lm <= t {
            return Some(StatusCode::NOT_MODIFIED);
        }
    }
    None
}

fn precondition_failed() -> S3Error {
    S3Error::new(StatusCode::PRECONDITION_FAILED, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold")
}

/// Bucket subresources we do not implement.
const UNSUPPORTED_SUBRESOURCES: &[&str] = &[
    "acl", "policy", "policyStatus", "cors", "lifecycle", "tagging", "encryption", "website", "logging", "notification",
    "replication", "object-lock", "ownershipControls", "publicAccessBlock", "accelerate", "requestPayment",
    "intelligent-tiering", "inventory", "metrics", "analytics", "versions", "retention", "legal-hold", "torrent",
    "restore", "select", "attributes",
];

impl<B: ObjectBackend> Proxy<B> {
    async fn dispatch(&self, req: Request) -> S3Result<Response> {
        let (parts, body) = req.into_parts();
        let method = parts.method.clone();
        let h = &parts.headers;
        let raw_path = parts.uri.path();
        let raw_query = parts.uri.query().unwrap_or("");
        let auth = sigv4::authenticate(
            &sigv4::Request { method: method.as_str(), raw_path, raw_query, headers: h, vhost_domains: &self.cfg.vhost_domains },
            &self.cfg.credentials,
            (now_ms() / 1000) as i64,
        )?;
        let q = Q(sigv4::parse_query(raw_query));
        tracing::debug!("{method} {raw_path} payload={:?}", auth.payload);

        let too_large = || S3Error::new(StatusCode::BAD_REQUEST, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed size");
        if hstr(h, "content-length").and_then(|v| v.parse::<usize>().ok()).is_some_and(|n| n > self.cfg.max_body_bytes) {
            return Err(too_large());
        }
        let raw = axum::body::to_bytes(body, self.cfg.max_body_bytes).await.map_err(|_| too_large())?;
        let is_complete = method == Method::POST && q.has("uploadId");
        let payload = auth.decode_body(h, &raw, !is_complete)?;
        drop(raw);

        let path = xml::percent_decode_str(raw_path).ok_or_else(|| S3Error::new(StatusCode::BAD_REQUEST, "InvalidURI", "path is not valid UTF-8"))?;
        let host = hstr(h, "host").unwrap_or("");
        let host_name = host.rsplit_once(':').map(|(n, _)| n).unwrap_or(host);
        let vhost = self.cfg.vhost_domains.iter().find_map(|d| host_name.strip_suffix(&format!(".{d}")).filter(|b| !b.is_empty()));
        let (bucket, key) = match vhost {
            Some(b) => (Some(b.to_string()), path.trim_start_matches('/').to_string()),
            None => {
                let p = path.trim_start_matches('/');
                match p.split_once('/') {
                    Some((b, k)) => (Some(b.to_string()), k.to_string()),
                    None if p.is_empty() => (None, String::new()),
                    None => (Some(p.to_string()), String::new()),
                }
            }
        };
        let Some(bucket) = bucket else {
            return match method {
                Method::GET => Ok(self.list_buckets()),
                _ => Err(S3Error::new(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", "The specified method is not allowed against this resource.")),
            };
        };
        if key.is_empty() {
            return self.bucket_op(&method, &bucket, &q, payload).await;
        }
        if validate_account_id(&bucket).is_err() && !self.cfg.aliases.contains_key(&bucket) {
            return Err(S3Error::no_such_bucket());
        }
        self.object_op(&method, &bucket, &key, &q, h, payload, host).await
    }

    fn is_public(&self, key: &str) -> bool {
        self.cfg.public_prefixes.iter().any(|p| key.starts_with(p.as_str()))
    }

    /// Bucket names this endpoint serves: its account, extra namespaces, aliases.
    fn known_bucket(&self, bucket: &str) -> bool {
        bucket == self.backend.account() || self.cfg.extra_buckets.iter().any(|b| b == bucket) || self.cfg.aliases.contains_key(bucket)
    }

    fn check_key(&self, bucket: &str, key: &str) -> S3Result<()> {
        if key.ends_with(META_SUFFIX) {
            return Err(S3Error::invalid_argument(format!("keys ending in {META_SUFFIX} are reserved by the NEAR Drive S3 proxy")));
        }
        let (ns, path) = self.backend.resolve(bucket, key);
        NearUri::object(&ns, &path).map_err(|e| S3Error::invalid_argument(format!("key is not a valid NEAR Drive path: {e}")))?;
        Ok(())
    }

    fn buckets(&self) -> Vec<String> {
        let mut b = vec![self.backend.account().to_string()];
        for x in self.cfg.extra_buckets.iter().chain(self.cfg.aliases.keys()) {
            if !b.contains(x) {
                b.push(x.clone());
            }
        }
        b
    }

    fn list_buckets(&self) -> Response {
        let acct = escape(self.backend.account());
        let date = iso8601(self.started_ms);
        let buckets: String =
            self.buckets().iter().map(|b| format!("<Bucket><Name>{}</Name><CreationDate>{date}</CreationDate></Bucket>", escape(b))).collect();
        xml_response(
            StatusCode::OK,
            format!("<ListAllMyBucketsResult xmlns=\"{NS}\"><Owner><ID>{acct}</ID><DisplayName>{acct}</DisplayName></Owner><Buckets>{buckets}</Buckets></ListAllMyBucketsResult>"),
        )
    }

    async fn bucket_op(&self, method: &Method, bucket: &str, q: &Q, payload: sigv4::Decoded) -> S3Result<Response> {
        let valid = validate_account_id(bucket).is_ok();
        if *method == Method::PUT && q.0.is_empty() {
            if !valid {
                return Err(S3Error::new(StatusCode::BAD_REQUEST, "InvalidBucketName", "Bucket names must be NEAR account ids (namespaces)."));
            }
            if self.buckets().iter().any(|b| b == bucket) {
                return Ok(Response::builder().status(StatusCode::OK).header(header::LOCATION, format!("/{bucket}")).body(Body::empty()).unwrap());
            }
            return Err(S3Error::new(
                StatusCode::CONFLICT,
                "BucketAlreadyExists",
                "Buckets are NEAR namespaces; only this proxy's own account (or configured --bucket namespaces) can be used.",
            ));
        }
        if !valid {
            return Err(S3Error::no_such_bucket());
        }
        if let Some(sub) = UNSUPPORTED_SUBRESOURCES.iter().find(|s| q.has(s)) {
            return Err(S3Error::not_implemented(format!("bucket subresource ?{sub} is not supported")));
        }
        match *method {
            Method::HEAD => Ok(Response::builder().status(StatusCode::OK).header("x-amz-bucket-region", &self.cfg.region).body(Body::empty()).unwrap()),
            Method::GET if q.has("location") => {
                let loc = if self.cfg.region == "us-east-1" { String::new() } else { escape(&self.cfg.region) };
                Ok(xml_response(StatusCode::OK, format!("<LocationConstraint xmlns=\"{NS}\">{loc}</LocationConstraint>")))
            }
            Method::GET if q.has("versioning") => Ok(xml_response(StatusCode::OK, format!("<VersioningConfiguration xmlns=\"{NS}\"/>"))),
            Method::GET if q.has("uploads") => self.list_uploads(bucket, q).await,
            Method::GET if q.get("list-type") == Some("2") => self.list_v2(bucket, q).await,
            Method::GET => self.list_v1(bucket, q).await,
            Method::POST if q.has("delete") => self.delete_objects(bucket, &payload.data).await,
            Method::DELETE => {
                if !self.known_bucket(bucket) {
                    return Err(S3Error::access_denied("not your bucket"));
                }
                let p = self.page(bucket, "", "", "", 1).await?;
                if !p.contents.is_empty() {
                    return Err(S3Error::new(StatusCode::CONFLICT, "BucketNotEmpty", "The bucket you tried to delete is not empty"));
                }
                // Namespaces cannot be deleted; an empty one behaves as deleted.
                Ok(empty(StatusCode::NO_CONTENT))
            }
            _ => Err(S3Error::new(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", "The specified method is not allowed against this resource.")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn object_op(&self, method: &Method, bucket: &str, key: &str, q: &Q, h: &HeaderMap, payload: sigv4::Decoded, host: &str) -> S3Result<Response> {
        self.check_key(bucket, key)?;
        if let Some(sub) = UNSUPPORTED_SUBRESOURCES.iter().find(|s| q.has(s)) {
            return Err(S3Error::not_implemented(format!("object subresource ?{sub} is not supported")));
        }
        match *method {
            Method::GET if q.has("uploadId") => self.list_parts(bucket, key, q).await,
            Method::GET => self.get_object(bucket, key, q, h, false).await,
            Method::HEAD => self.get_object(bucket, key, q, h, true).await,
            Method::PUT if q.has("uploadId") || q.has("partNumber") => self.upload_part(bucket, key, q, h, payload).await,
            Method::PUT if h.contains_key("x-amz-copy-source") => self.copy_object(bucket, key, h).await,
            Method::PUT => self.put_object(bucket, key, h, payload).await,
            Method::POST if q.has("uploads") => self.create_upload(bucket, key, h).await,
            Method::POST if q.has("uploadId") => self.complete_upload(bucket, key, q, &payload.data, host).await,
            Method::DELETE if q.has("uploadId") => {
                let id = q.get("uploadId").unwrap_or("");
                self.staging.load(id, bucket, key).await?;
                self.sessions.remove(id);
                self.staging.abort(id).await?;
                Ok(empty(StatusCode::NO_CONTENT))
            }
            Method::DELETE => {
                self.delete_one(bucket, key).await?;
                Ok(empty(StatusCode::NO_CONTENT))
            }
            _ => Err(S3Error::new(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", "The specified method is not allowed against this resource.")),
        }
    }

    // ---- storage helpers -------------------------------------------------

    /// Write an object (and its metadata sidecar, if any).
    async fn store(&self, bucket: &str, key: &str, src: PutSource, content_type: Option<String>, meta: BTreeMap<String, String>) -> S3Result<ObjectInfo> {
        let public = self.is_public(key);
        let stored_ct = if meta.is_empty() { content_type.clone() } else { Some(format!("{}{META_MARK}", content_type.as_deref().unwrap_or(""))) };
        let mut info = self.backend.put(bucket, key, src, &PutParams { public, content_type: stored_ct }).await.map_err(map_backend)?;
        if !meta.is_empty() {
            let side = serde_json::to_vec(&MetaSidecar { for_cid: info.manifest_cid.clone(), meta }).expect("serializable");
            self.backend
                .put(bucket, &format!("{key}{META_SUFFIX}"), PutSource::Mem(side), &PutParams { public, content_type: Some("application/json".into()) })
                .await
                .map_err(map_backend)?;
        }
        info.content_type = content_type;
        Ok(info)
    }

    /// Turn object data into an upload source: small data stays in memory,
    /// streams are spooled to a temp file in the staging dir (bounded memory).
    async fn spool(&self, data: ObjectData) -> S3Result<PutSource> {
        use futures_util::TryStreamExt;
        use tokio::io::AsyncWriteExt;
        match data {
            ObjectData::Mem(v) => Ok(PutSource::Mem(v)),
            ObjectData::Stream(mut s) => {
                tokio::fs::create_dir_all(&self.cfg.staging_dir).await?;
                let path = self.cfg.staging_dir.join(format!("copy-{}.tmp", hex::encode(rand::random::<[u8; 8]>())));
                let mut f = tokio::fs::File::create(&path).await?;
                let res: std::io::Result<()> = async {
                    while let Some(b) = s.try_next().await? {
                        f.write_all(&b).await?;
                    }
                    f.flush().await
                }
                .await;
                if let Err(e) = res {
                    let _ = tokio::fs::remove_file(&path).await;
                    return Err(e.into());
                }
                Ok(PutSource::File(path))
            }
        }
    }

    async fn load_meta(&self, bucket: &str, key: &str, info: &ObjectInfo) -> BTreeMap<String, String> {
        if !split_ct(info.content_type.as_deref()).1 {
            return BTreeMap::new();
        }
        match self.backend.get(bucket, &format!("{key}{META_SUFFIX}"), None).await {
            Ok(GetResult { data, .. }) => match serde_json::from_slice::<MetaSidecar>(&data.into_vec().await.unwrap_or_default()) {
                Ok(s) if s.for_cid == info.manifest_cid => s.meta,
                _ => BTreeMap::new(),
            },
            Err(e) => {
                tracing::debug!("metadata sidecar for {bucket}/{key} unavailable: {e:?}");
                BTreeMap::new()
            }
        }
    }

    async fn delete_one(&self, bucket: &str, key: &str) -> S3Result<()> {
        let side = format!("{key}{META_SUFFIX}");
        let (main, _) = tokio::join!(self.backend.delete(bucket, key), self.backend.delete(bucket, &side));
        main.map_err(map_backend)?;
        Ok(())
    }

    /// One S3 page of up to `max` keys + common prefixes, sidecars hidden.
    /// Built from as few native backend pages as needed (each continues from
    /// the previous cursor; nothing is re-listed). Backend pages can come
    /// back short (sidecars, objects the proxy cannot read), so this may take
    /// several; a page is cut after its `max`-th item and the next S3 page
    /// starts after that item.
    async fn page(&self, bucket: &str, prefix: &str, delimiter: &str, marker: &str, max: usize) -> S3Result<Page> {
        let delim = (!delimiter.is_empty()).then_some(delimiter);
        let mut page = Page { contents: vec![], prefixes: vec![], truncated: false, last: None };
        let mut cursor = (!marker.is_empty()).then(|| marker.to_string());
        let mut count = 0;
        while count < max {
            // Ask for some slack: sidecars take up to half of a backend page.
            let want = ((max - count) * 2).min(1000);
            let bp = self.backend.list_page(bucket, prefix, delim, cursor.as_deref(), want).await.map_err(map_backend)?;
            let mut merged: Vec<(String, Option<ListItem>)> = bp.items.into_iter().map(|i| (i.key.clone(), Some(i))).chain(bp.prefixes.into_iter().map(|p| (p, None))).collect();
            merged.sort_by(|a, b| a.0.cmp(&b.0));
            for (key, item) in merged {
                if count == max {
                    page.truncated = true;
                    return Ok(page);
                }
                match item {
                    Some(_) if key.ends_with(META_SUFFIX) => continue,
                    Some(it) => page.contents.push(it),
                    None => page.prefixes.push(key.clone()),
                }
                page.last = Some(key);
                count += 1;
            }
            match bp.next {
                Some(n) if Some(&n) != cursor.as_ref() => cursor = Some(n),
                _ => return Ok(page),
            }
        }
        // Full page and the backend has more.
        page.truncated = page.last.is_some();
        Ok(page)
    }

    // ---- bucket operations -------------------------------------------------

    fn max_keys(q: &Q) -> S3Result<usize> {
        match q.get("max-keys") {
            None => Ok(1000),
            Some(v) => v.parse::<i64>().ok().filter(|n| *n >= 0).map(|n| n.min(1000) as usize).ok_or_else(|| S3Error::invalid_argument("max-keys must be a non-negative integer")),
        }
    }

    fn contents_xml(&self, page: &Page, enc: &dyn Fn(&str) -> String, owner: bool) -> String {
        let acct = escape(self.backend.account());
        let mut s = String::new();
        for c in &page.contents {
            s.push_str(&format!(
                "<Contents><Key>{}</Key><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass>{}</Contents>",
                enc(&c.key),
                iso8601(c.ts_ms),
                escape(&list_etag(c)),
                c.size,
                if owner { format!("<Owner><ID>{acct}</ID><DisplayName>{acct}</DisplayName></Owner>") } else { String::new() }
            ));
        }
        for p in &page.prefixes {
            s.push_str(&format!("<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>", enc(p)));
        }
        s
    }

    async fn list_v2(&self, bucket: &str, q: &Q) -> S3Result<Response> {
        let prefix = q.get("prefix").unwrap_or("");
        let delimiter = q.get("delimiter").unwrap_or("");
        let max = Self::max_keys(q)?;
        let url = match q.get("encoding-type") {
            None => false,
            Some("url") => true,
            Some(_) => return Err(S3Error::invalid_argument("Invalid Encoding Method specified in Request")),
        };
        let token = q.get("continuation-token");
        let start_after = q.get("start-after").unwrap_or("");
        let marker = match token {
            Some(t) => String::from_utf8(B64URL.decode(t).map_err(|_| S3Error::invalid_argument("The continuation token provided is incorrect"))?)
                .map_err(|_| S3Error::invalid_argument("The continuation token provided is incorrect"))?,
            None => start_after.to_string(),
        };
        let page = self.page(bucket, prefix, delimiter, &marker, max).await?;
        let enc = |s: &str| if url { xml::uri_encode(s, true) } else { escape(s) };
        let mut x = format!("<ListBucketResult xmlns=\"{NS}\"><Name>{}</Name><Prefix>{}</Prefix>", escape(bucket), enc(prefix));
        if !delimiter.is_empty() {
            x.push_str(&format!("<Delimiter>{}</Delimiter>", enc(delimiter)));
        }
        x.push_str(&format!("<MaxKeys>{max}</MaxKeys><KeyCount>{}</KeyCount><IsTruncated>{}</IsTruncated>", page.contents.len() + page.prefixes.len(), page.truncated));
        if let Some(t) = token {
            x.push_str(&format!("<ContinuationToken>{}</ContinuationToken>", escape(t)));
        }
        if page.truncated {
            if let Some(l) = &page.last {
                x.push_str(&format!("<NextContinuationToken>{}</NextContinuationToken>", B64URL.encode(l)));
            }
        }
        if !start_after.is_empty() {
            x.push_str(&format!("<StartAfter>{}</StartAfter>", enc(start_after)));
        }
        if url {
            x.push_str("<EncodingType>url</EncodingType>");
        }
        x.push_str(&self.contents_xml(&page, &enc, q.get("fetch-owner") == Some("true")));
        x.push_str("</ListBucketResult>");
        Ok(xml_response(StatusCode::OK, x))
    }

    async fn list_v1(&self, bucket: &str, q: &Q) -> S3Result<Response> {
        let prefix = q.get("prefix").unwrap_or("");
        let delimiter = q.get("delimiter").unwrap_or("");
        let marker = q.get("marker").unwrap_or("");
        let max = Self::max_keys(q)?;
        let url = q.get("encoding-type") == Some("url");
        let page = self.page(bucket, prefix, delimiter, marker, max).await?;
        let enc = |s: &str| if url { xml::uri_encode(s, true) } else { escape(s) };
        let mut x = format!(
            "<ListBucketResult xmlns=\"{NS}\"><Name>{}</Name><Prefix>{}</Prefix><Marker>{}</Marker><MaxKeys>{max}</MaxKeys>",
            escape(bucket),
            enc(prefix),
            enc(marker)
        );
        if !delimiter.is_empty() {
            x.push_str(&format!("<Delimiter>{}</Delimiter>", enc(delimiter)));
        }
        x.push_str(&format!("<IsTruncated>{}</IsTruncated>", page.truncated));
        if page.truncated {
            if let Some(l) = &page.last {
                x.push_str(&format!("<NextMarker>{}</NextMarker>", enc(l)));
            }
        }
        if url {
            x.push_str("<EncodingType>url</EncodingType>");
        }
        x.push_str(&self.contents_xml(&page, &enc, true));
        x.push_str("</ListBucketResult>");
        Ok(xml_response(StatusCode::OK, x))
    }

    async fn delete_objects(&self, bucket: &str, body: &[u8]) -> S3Result<Response> {
        let body = std::str::from_utf8(body).map_err(|_| S3Error::malformed_xml())?;
        let quiet = xml::text(body, "Quiet").is_some_and(|v| v.eq_ignore_ascii_case("true"));
        let objs = xml::elements(body, "Object");
        if objs.is_empty() || objs.len() > 1000 {
            return Err(S3Error::malformed_xml());
        }
        let mut out = format!("<DeleteResult xmlns=\"{NS}\">");
        for o in objs {
            let key = xml::text(o, "Key").ok_or_else(S3Error::malformed_xml)?;
            let res = match self.check_key(bucket, &key) {
                Ok(()) => self.delete_one(bucket, &key).await,
                Err(e) => Err(e),
            };
            match res {
                Ok(()) => {
                    if !quiet {
                        out.push_str(&format!("<Deleted><Key>{}</Key></Deleted>", escape(&key)));
                    }
                }
                Err(e) => out.push_str(&format!("<Error><Key>{}</Key><Code>{}</Code><Message>{}</Message></Error>", escape(&key), e.code, escape(&e.message))),
            }
        }
        out.push_str("</DeleteResult>");
        Ok(xml_response(StatusCode::OK, out))
    }

    async fn list_uploads(&self, bucket: &str, q: &Q) -> S3Result<Response> {
        let prefix = q.get("prefix").unwrap_or("");
        let mut x = format!(
            "<ListMultipartUploadsResult xmlns=\"{NS}\"><Bucket>{}</Bucket><KeyMarker></KeyMarker><UploadIdMarker></UploadIdMarker><Prefix>{}</Prefix><MaxUploads>1000</MaxUploads><IsTruncated>false</IsTruncated>",
            escape(bucket),
            escape(prefix)
        );
        for (id, m) in self.staging.list(bucket).await? {
            if m.key.starts_with(prefix) {
                x.push_str(&format!(
                    "<Upload><Key>{}</Key><UploadId>{id}</UploadId><StorageClass>STANDARD</StorageClass><Initiated>{}</Initiated></Upload>",
                    escape(&m.key),
                    iso8601(m.initiated_ms)
                ));
            }
        }
        x.push_str("</ListMultipartUploadsResult>");
        Ok(xml_response(StatusCode::OK, x))
    }

    // ---- object operations -------------------------------------------------

    async fn get_object(&self, bucket: &str, key: &str, q: &Q, h: &HeaderMap, head_only: bool) -> S3Result<Response> {
        let range = hstr(h, "range").and_then(RangeSpec::parse);
        let has_cond = ["if-match", "if-none-match", "if-modified-since", "if-unmodified-since"].iter().any(|n| h.contains_key(*n));
        let (info, data, served) = if head_only || has_cond {
            let info = self.backend.head(bucket, key).await.map_err(map_backend)?.ok_or_else(S3Error::no_such_key)?;
            if let Some(st) = conditional(h, &info, true) {
                if st == StatusCode::PRECONDITION_FAILED {
                    return Err(precondition_failed());
                }
                return Ok(Response::builder()
                    .status(st)
                    .header(header::ETAG, etag(&info.manifest_cid))
                    .header(header::LAST_MODIFIED, xml::http_date(info.ts_ms))
                    .body(Body::empty())
                    .unwrap());
            }
            if head_only {
                let served = match range {
                    None => None,
                    Some(r) => Some(r.resolve(info.size).map_err(|_| map_backend(BackendError::RangeNotSatisfiable { size: info.size }))?),
                };
                (info, None, served)
            } else {
                let g = self.backend.get(bucket, key, range).await.map_err(map_backend)?;
                (g.info, Some(g.data), g.range)
            }
        } else {
            let g = self.backend.get(bucket, key, range).await.map_err(map_backend)?;
            (g.info, Some(g.data), g.range)
        };
        let meta = self.load_meta(bucket, key, &info).await;
        let (ct, _) = split_ct(info.content_type.as_deref());
        let len = match served {
            Some(r) => r.end - r.start + 1,
            None => info.size,
        };
        let mut b = Response::builder()
            .status(if served.is_some() { StatusCode::PARTIAL_CONTENT } else { StatusCode::OK })
            .header(header::CONTENT_LENGTH, len)
            .header(header::ETAG, etag(&info.manifest_cid))
            .header(header::LAST_MODIFIED, xml::http_date(info.ts_ms))
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::CONTENT_TYPE, q.get("response-content-type").map(str::to_string).or(ct).unwrap_or_else(|| "binary/octet-stream".into()));
        if let Some(r) = served {
            b = b.header(header::CONTENT_RANGE, format!("bytes {}-{}/{}", r.start, r.end, info.size));
        }
        for (qn, hn) in [
            ("response-content-disposition", "content-disposition"),
            ("response-content-encoding", "content-encoding"),
            ("response-content-language", "content-language"),
            ("response-cache-control", "cache-control"),
            ("response-expires", "expires"),
        ] {
            if let Some(v) = q.get(qn) {
                b = b.header(hn, v);
            }
        }
        for (k, v) in &meta {
            if let (Ok(n), Ok(v)) = (header::HeaderName::from_bytes(format!("x-amz-meta-{k}").as_bytes()), HeaderValue::from_str(v)) {
                b = b.header(n, v);
            }
        }
        let body = match data {
            Some(ObjectData::Mem(d)) if !head_only => Body::from(d),
            Some(ObjectData::Stream(s)) if !head_only => Body::from_stream(s),
            _ => Body::empty(),
        };
        Ok(b.body(body).unwrap())
    }

    async fn put_object(&self, bucket: &str, key: &str, h: &HeaderMap, payload: sigv4::Decoded) -> S3Result<Response> {
        if h.contains_key("if-none-match") || h.contains_key("if-match") {
            match self.backend.head(bucket, key).await.map_err(map_backend)? {
                Some(info) => {
                    if conditional(h, &info, false).is_some() {
                        return Err(precondition_failed());
                    }
                }
                None if h.contains_key("if-match") => return Err(S3Error::no_such_key()),
                None => {}
            }
        }
        let ct = hstr(h, "content-type").map(str::to_string);
        let info = self.store(bucket, key, PutSource::Mem(payload.data), ct, user_meta(h)).await?;
        let mut b = Response::builder().status(StatusCode::OK).header(header::ETAG, etag(&info.manifest_cid));
        for (n, v) in &payload.checksums {
            b = b.header(n.as_str(), v.as_str());
        }
        Ok(b.body(Body::empty()).unwrap())
    }

    /// Parse `x-amz-copy-source` (`[/]bucket/key[?versionId=…]`, URL-encoded).
    fn copy_source(&self, h: &HeaderMap) -> S3Result<(String, String)> {
        let raw = hstr(h, "x-amz-copy-source").ok_or_else(|| S3Error::invalid_argument("missing x-amz-copy-source"))?;
        let raw = raw.split_once('?').map(|(p, _)| p).unwrap_or(raw);
        let dec = xml::percent_decode_str(raw).ok_or_else(|| S3Error::invalid_argument("bad x-amz-copy-source"))?;
        let (b, k) = dec.trim_start_matches('/').split_once('/').ok_or_else(|| S3Error::invalid_argument("x-amz-copy-source must be bucket/key"))?;
        if validate_account_id(b).is_err() {
            return Err(S3Error::no_such_bucket());
        }
        self.check_key(b, k)?;
        Ok((b.to_string(), k.to_string()))
    }

    async fn copy_object(&self, bucket: &str, key: &str, h: &HeaderMap) -> S3Result<Response> {
        let (sb, sk) = self.copy_source(h)?;
        let replace = match hstr(h, "x-amz-metadata-directive").unwrap_or("COPY") {
            "COPY" => false,
            "REPLACE" => true,
            _ => return Err(S3Error::invalid_argument("Unknown metadata directive.")),
        };
        if sb == bucket && sk == key && !replace {
            return Err(S3Error::invalid_request(
                "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes.",
            ));
        }
        let src = self.backend.get(&sb, &sk, None).await.map_err(map_backend)?;
        let cond = [
            ("x-amz-copy-source-if-match", "if-match"),
            ("x-amz-copy-source-if-none-match", "if-none-match"),
            ("x-amz-copy-source-if-modified-since", "if-modified-since"),
            ("x-amz-copy-source-if-unmodified-since", "if-unmodified-since"),
        ];
        let mut ch = HeaderMap::new();
        for (from, to) in cond {
            if let Some(v) = h.get(from) {
                ch.insert(to, v.clone());
            }
        }
        if conditional(&ch, &src.info, true).is_some() {
            return Err(precondition_failed());
        }
        let (ct, meta) = if replace {
            (hstr(h, "content-type").map(str::to_string), user_meta(h))
        } else {
            (split_ct(src.info.content_type.as_deref()).0, self.load_meta(&sb, &sk, &src.info).await)
        };
        let data = self.spool(src.data).await?;
        let info = self.store(bucket, key, data, ct, meta).await?;
        Ok(xml_response(
            StatusCode::OK,
            format!(
                "<CopyObjectResult xmlns=\"{NS}\"><LastModified>{}</LastModified><ETag>{}</ETag></CopyObjectResult>",
                iso8601(info.ts_ms),
                escape(&etag(&info.manifest_cid))
            ),
        ))
    }

    async fn create_upload(&self, bucket: &str, key: &str, h: &HeaderMap) -> S3Result<Response> {
        let meta = UploadMeta {
            bucket: bucket.into(),
            key: key.into(),
            content_type: hstr(h, "content-type").map(str::to_string),
            user_meta: user_meta(h),
            initiated_ms: now_ms(),
        };
        for gone in self.sessions.prune(Duration::from_secs(7 * 24 * 3600)) {
            let _ = self.staging.abort(&gone).await;
        }
        let id = self.staging.create(&meta).await?;
        // Stream parts into the object as they arrive (see stream.rs).
        let public = self.is_public(key);
        let stored_ct = if meta.user_meta.is_empty() { meta.content_type.clone() } else { Some(format!("{}{META_MARK}", meta.content_type.as_deref().unwrap_or(""))) };
        let sink = match self.backend.begin(bucket, key, &PutParams { public, content_type: stored_ct }) {
            Ok(s) => s,
            Err(e) => {
                let _ = self.staging.abort(&id).await;
                return Err(map_backend(e));
            }
        };
        self.sessions.start(&id, sink, self.cfg.staging_dir.join(&id));
        let mut b = Response::builder().status(StatusCode::OK).header(header::CONTENT_TYPE, "application/xml");
        if let Some(a) = h.get("x-amz-checksum-algorithm") {
            b = b.header("x-amz-checksum-algorithm", a.clone());
        }
        Ok(b.body(Body::from(format!(
            "{XML_DECL}<InitiateMultipartUploadResult xmlns=\"{NS}\"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{id}</UploadId></InitiateMultipartUploadResult>",
            escape(bucket),
            escape(key)
        )))
        .unwrap())
    }

    async fn upload_part(&self, bucket: &str, key: &str, q: &Q, h: &HeaderMap, payload: sigv4::Decoded) -> S3Result<Response> {
        let id = q.get("uploadId").ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?;
        let n: u32 = q
            .get("partNumber")
            .and_then(|v| v.parse().ok())
            .filter(|n| (1..=10_000).contains(n))
            .ok_or_else(|| S3Error::invalid_argument("Part number must be an integer between 1 and 10000, inclusive"))?;
        self.staging.load(id, bucket, key).await?;
        if h.contains_key("x-amz-copy-source") {
            // UploadPartCopy
            let (sb, sk) = self.copy_source(h)?;
            let range = match hstr(h, "x-amz-copy-source-range") {
                None => None,
                Some(r) => Some(RangeSpec::parse(r).ok_or_else(|| S3Error::invalid_argument("bad x-amz-copy-source-range"))?),
            };
            let src = self.backend.get(&sb, &sk, range).await.map_err(map_backend)?;
            let et = self.sessions.put_part(id, n, src.data.into_vec().await?).await?;
            return Ok(xml_response(
                StatusCode::OK,
                format!("<CopyPartResult xmlns=\"{NS}\"><LastModified>{}</LastModified><ETag>\"{et}\"</ETag></CopyPartResult>", iso8601(now_ms())),
            ));
        }
        let et = self.sessions.put_part(id, n, payload.data).await?;
        let mut b = Response::builder().status(StatusCode::OK).header(header::ETAG, format!("\"{et}\""));
        for (n, v) in &payload.checksums {
            b = b.header(n.as_str(), v.as_str());
        }
        Ok(b.body(Body::empty()).unwrap())
    }

    async fn complete_upload(&self, bucket: &str, key: &str, q: &Q, body: &[u8], host: &str) -> S3Result<Response> {
        let id = q.get("uploadId").unwrap_or("");
        let meta = self.staging.load(id, bucket, key).await?;
        let body = std::str::from_utf8(body).map_err(|_| S3Error::malformed_xml())?;
        let mut parts = vec![];
        for p in xml::elements(body, "Part") {
            let n = xml::text(p, "PartNumber").and_then(|v| v.parse::<u32>().ok()).ok_or_else(S3Error::malformed_xml)?;
            let et = xml::text(p, "ETag").ok_or_else(S3Error::malformed_xml)?;
            parts.push((n, et.trim_matches('"').to_string()));
        }
        let sink = self.sessions.complete(id, &parts).await?;
        let info = sink.finish().await.map_err(map_backend);
        let _ = self.staging.abort(id).await;
        let mut info = info?;
        if !meta.user_meta.is_empty() {
            let public = self.is_public(key);
            let side = serde_json::to_vec(&MetaSidecar { for_cid: info.manifest_cid.clone(), meta: meta.user_meta }).expect("serializable");
            self.backend
                .put(bucket, &format!("{key}{META_SUFFIX}"), PutSource::Mem(side), &PutParams { public, content_type: Some("application/json".into()) })
                .await
                .map_err(map_backend)?;
        }
        info.content_type = meta.content_type;
        Ok(xml_response(
            StatusCode::OK,
            format!(
                "<CompleteMultipartUploadResult xmlns=\"{NS}\"><Location>http://{}/{}/{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag></CompleteMultipartUploadResult>",
                escape(host),
                escape(bucket),
                escape(&xml::uri_encode(key, true)),
                escape(bucket),
                escape(key),
                escape(&etag(&info.manifest_cid))
            ),
        ))
    }

    async fn list_parts(&self, bucket: &str, key: &str, q: &Q) -> S3Result<Response> {
        let id = q.get("uploadId").unwrap_or("");
        self.staging.load(id, bucket, key).await?;
        let marker: u32 = q.get("part-number-marker").and_then(|v| v.parse().ok()).unwrap_or(0);
        let max: usize = q.get("max-parts").and_then(|v| v.parse().ok()).unwrap_or(1000).min(1000);
        let all: Vec<_> = self.sessions.parts(id)?.into_iter().filter(|p| p.number > marker).collect();
        let truncated = all.len() > max;
        let shown = &all[..all.len().min(max)];
        let acct = escape(self.backend.account());
        let mut x = format!(
            "<ListPartsResult xmlns=\"{NS}\"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{id}</UploadId><Initiator><ID>{acct}</ID><DisplayName>{acct}</DisplayName></Initiator><Owner><ID>{acct}</ID><DisplayName>{acct}</DisplayName></Owner><StorageClass>STANDARD</StorageClass><PartNumberMarker>{marker}</PartNumberMarker><NextPartNumberMarker>{}</NextPartNumberMarker><MaxParts>{max}</MaxParts><IsTruncated>{truncated}</IsTruncated>",
            escape(bucket),
            escape(key),
            shown.last().map(|p| p.number).unwrap_or(marker)
        );
        for p in shown {
            x.push_str(&format!(
                "<Part><PartNumber>{}</PartNumber><LastModified>{}</LastModified><ETag>\"{}\"</ETag><Size>{}</Size></Part>",
                p.number,
                iso8601(p.modified_ms),
                p.etag,
                p.size
            ));
        }
        x.push_str("</ListPartsResult>");
        Ok(xml_response(StatusCode::OK, x))
    }
}
