//! NEAR Drive gateway: stateless HTTP front for the index store and blob backends.
pub mod billing;
pub mod bridge;
pub mod cache;
pub mod keys;
pub mod locate;
pub mod placement;
pub mod policies;
pub mod s3;
pub mod small;
pub mod store;
pub mod usage;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, put},
    Json, Router,
};
use near_drive_core::{
    auth,
    manifest::{Manifest, MAX_CHUNK_BYTES},
    policy::{self, Rule},
    record::PointerRecord,
    NearUri,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use placement::{Placement, StorageConfig};
use store::{CasError, IndexEntry, IndexStore};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub listen: String,
    pub data_dir: PathBuf,
    /// NEAR RPC used to resolve access keys; None = dev keys only.
    #[serde(default)]
    pub rpc_url: Option<String>,
    #[serde(default = "default_contract")]
    pub storage_contract: String,
    /// account -> allowed public keys (dev / tests).
    #[serde(default)]
    pub dev_keys: HashMap<String, Vec<String>>,
    /// namespace -> ordered rules. Overrides `drive.near` for these
    /// namespaces; the only policy source when `rpc_url` is None.
    #[serde(default)]
    pub policies: HashMap<String, Vec<Rule>>,
    /// Read namespace rules from `storage_contract` via `rpc_url` (cached 30 s).
    #[serde(default = "default_true")]
    pub contract_policies: bool,
    /// Blob backends, storage classes, index store, chunk cache (see README).
    #[serde(default)]
    pub storage: StorageConfig,
    /// NEAR AI Cloud credits billing (metering, reporting, credit gate). Off when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing: Option<billing::BillingConfig>,
    /// Browser origins allowed via CORS (e.g. `["https://app.example"]`, or
    /// `["*"]`). Empty = no CORS headers. Requests are authenticated by NEAR
    /// signatures, not cookies, so credentials are never allowed.
    #[serde(default)]
    pub cors_origins: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8787".into(),
            data_dir: "./drive-data".into(),
            rpc_url: None,
            storage_contract: default_contract(),
            dev_keys: HashMap::new(),
            policies: HashMap::new(),
            contract_policies: true,
            storage: StorageConfig::default(),
            billing: None,
            cors_origins: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_contract() -> String {
    "drive.near".into()
}

pub struct AppState {
    pub cfg: Config,
    pub blobs: Placement,
    pub index: Arc<dyn IndexStore>,
    pub keys: keys::KeyResolver,
    pub policies: policies::PolicySource,
    pub usage: usage::UsageSink,
    pub billing: Option<Arc<billing::Billing>>,
    replay: Mutex<HashMap<String, Instant>>,
}

impl AppState {
    pub async fn new(cfg: Config) -> anyhow::Result<Arc<Self>> {
        tokio::fs::create_dir_all(&cfg.data_dir).await?;
        let billing = match &cfg.billing {
            Some(b) => {
                let b = Arc::new(billing::Billing::open(b, &cfg.data_dir)?);
                b.spawn();
                Some(b)
            }
            None => None,
        };
        Ok(Arc::new(Self {
            billing,
            blobs: Placement::from_config(&cfg.storage, &cfg.data_dir)?,
            index: small::CachedIndex::wrap(cfg.storage.index.build(&cfg.data_dir)?, &cfg.storage.small_cache),
            keys: keys::KeyResolver::new(cfg.rpc_url.clone(), cfg.storage_contract.clone(), cfg.dev_keys.clone()),
            policies: policies::PolicySource::new(
                &cfg.policies,
                match (&cfg.rpc_url, cfg.contract_policies) {
                    (Some(rpc), true) => Some(near_drive_chain::StorageContract::new(rpc.clone(), cfg.storage_contract.clone())),
                    _ => None,
                },
            ),
            usage: usage::UsageSink::open(cfg.data_dir.join("usage.jsonl")).await?,
            replay: Mutex::new(HashMap::new()),
            cfg,
        }))
    }

    async fn rules(&self, ns: &str) -> Result<Arc<Vec<Rule>>, ApiError> {
        self.policies.rules(ns).await.map_err(|e| {
            tracing::error!("{e:#}");
            err(StatusCode::SERVICE_UNAVAILABLE, "namespace policy unavailable")
        })
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    let cors = cors_layer(&state.cfg.cors_origins);
    let r = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/chunk/{ns}/{cid}", put(put_chunk))
        .route("/v1/o/{ns}/{*path}", put(put_object).get(get_object).delete(delete_object))
        .route("/v1/list/{ns}", get(list_objects))
        .layer(DefaultBodyLimit::max(MAX_CHUNK_BYTES as usize + 1024 * 1024))
        .with_state(state);
    match cors {
        Some(c) => r.layer(c),
        None => r,
    }
}

fn cors_layer(origins: &[String]) -> Option<tower_http::cors::CorsLayer> {
    use axum::http::{header, HeaderName, HeaderValue};
    use tower_http::cors::{AllowOrigin, CorsLayer};
    if origins.is_empty() {
        return None;
    }
    let allow = if origins.iter().any(|o| o == "*") {
        AllowOrigin::any()
    } else {
        AllowOrigin::list(origins.iter().filter_map(|o| HeaderValue::from_str(o).ok()))
    };
    let h = |s: &'static str| HeaderName::from_static(s);
    Some(
        CorsLayer::new()
            .allow_origin(allow)
            .allow_methods([Method::GET, Method::PUT, Method::DELETE, Method::HEAD])
            .allow_headers([
                h(auth::H_ACCOUNT),
                h(auth::H_PUBKEY),
                h(auth::H_TS),
                h(auth::H_SIG),
                h("x-near-drive-class"),
                header::CONTENT_TYPE,
                header::RANGE,
            ])
            .expose_headers([header::CONTENT_RANGE, header::CONTENT_LENGTH])
            .max_age(std::time::Duration::from_secs(600)),
    )
}

pub struct ApiError(StatusCode, String, Option<serde_json::Value>);

impl ApiError {
    /// Error with extra top-level JSON fields (an object) besides `error`.
    pub fn with(code: StatusCode, msg: impl Into<String>, extra: serde_json::Value) -> Self {
        ApiError(code, msg.into(), Some(extra))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({"error": self.1});
        if let Some(serde_json::Value::Object(extra)) = self.2 {
            body.as_object_mut().unwrap().extend(extra);
        }
        (self.0, Json(body)).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("internal error: {e:#}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into(), None)
    }
}

fn err(code: StatusCode, msg: impl Into<String>) -> ApiError {
    ApiError(code, msg.into(), None)
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

struct Signer {
    account: String,
    public_key: String,
}

async fn authenticate(st: &AppState, method: &Method, uri: &Uri, headers: &HeaderMap, body: &[u8]) -> Result<Signer, ApiError> {
    let h = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| err(StatusCode::UNAUTHORIZED, format!("missing {name}")))
    };
    let (account, public_key, ts, sig) = (h(auth::H_ACCOUNT)?, h(auth::H_PUBKEY)?, h(auth::H_TS)?, h(auth::H_SIG)?);
    let ts: u64 = ts.parse().map_err(|_| err(StatusCode::UNAUTHORIZED, "bad timestamp"))?;
    if now_ms().abs_diff(ts) > auth::MAX_SKEW_MS {
        return Err(err(StatusCode::UNAUTHORIZED, "timestamp outside allowed window"));
    }
    near_drive_core::uri::validate_account_id(&account).map_err(|e| err(StatusCode::UNAUTHORIZED, e.to_string()))?;
    let pk = near_drive_core::keys::parse_public_key(&public_key).map_err(|e| err(StatusCode::UNAUTHORIZED, e.to_string()))?;
    let msg = auth::canonical_request(method.as_str(), uri.path(), uri.query().unwrap_or(""), &account, &public_key, ts, body);
    near_drive_core::keys::verify(&pk, &msg, &sig).map_err(|_| err(StatusCode::UNAUTHORIZED, "bad signature"))?;

    {
        let mut seen = st.replay.lock().await;
        let window = Duration::from_millis(2 * auth::MAX_SKEW_MS);
        seen.retain(|_, t| t.elapsed() < window);
        if seen.insert(sig, Instant::now()).is_some() {
            return Err(err(StatusCode::UNAUTHORIZED, "replayed request"));
        }
    }

    if !st.keys.is_authorized(&account, &public_key).await? {
        return Err(err(StatusCode::UNAUTHORIZED, "public key is not authorized for account"));
    }
    Ok(Signer { account, public_key })
}

fn check_ns(ns: &str) -> Result<(), ApiError> {
    near_drive_core::uri::validate_account_id(ns).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))
}

fn check_obj(ns: &str, path: &str) -> Result<(), ApiError> {
    NearUri::object(ns, path).map(|_| ()).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))
}

async fn put_chunk(
    State(st): State<Arc<AppState>>,
    Path((ns, cid)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    check_ns(&ns)?;
    let signer = authenticate(&st, &method, &uri, &headers, &body).await?;
    let rules = st.rules(&ns).await?;
    if !policy::can_write_somewhere(&ns, &rules, &signer.account) {
        return Err(err(StatusCode::FORBIDDEN, "no write access to namespace"));
    }
    billing::check_chunk(st.billing.as_deref(), &ns, &rules, &signer.account).await?;
    if !near_drive_core::is_valid_cid(&cid) || near_drive_core::cid(&body) != cid {
        return Err(err(StatusCode::BAD_REQUEST, "cid does not match content"));
    }
    if body.len() as u64 > MAX_CHUNK_BYTES + 64 {
        return Err(err(StatusCode::PAYLOAD_TOO_LARGE, "chunk too large"));
    }
    let class = headers.get(placement::CLASS_HEADER).and_then(|v| v.to_str().ok());
    if let Err(placement::UnknownClass(c)) = st.blobs.put_class(class, &cid, body).await? {
        return Err(err(StatusCode::BAD_REQUEST, format!("unknown storage class {c:?}")));
    }
    Ok(StatusCode::CREATED)
}

async fn load_manifest(st: &AppState, class: Option<&str>, cid: &str) -> Result<(Manifest, u64), ApiError> {
    let (m, raw) = load_manifest_raw(st, class, cid).await?;
    Ok((m, raw.len() as u64))
}

/// Parsed manifest plus the exact stored bytes. Responses carry the bytes as
/// `manifest_raw` (base64) so clients hash what was signed rather than a
/// re-serialization (robust to manifest fields a client does not know yet).
async fn load_manifest_raw(st: &AppState, class: Option<&str>, cid: &str) -> Result<(Manifest, Vec<u8>), ApiError> {
    let b = st.blobs.get(class, cid).await?.ok_or_else(|| err(StatusCode::BAD_REQUEST, "manifest chunk not uploaded"))?;
    let m = Manifest::from_bytes(&b).map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid manifest: {e}")))?;
    Ok((m, b.to_vec()))
}

async fn put_object(
    State(st): State<Arc<AppState>>,
    Path((ns, path)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    check_obj(&ns, &path)?;
    let signer = authenticate(&st, &method, &uri, &headers, &body).await?;
    let access = policy::resolve(&ns, &st.rules(&ns).await?, &path, &signer.account);
    if !access.write {
        return Err(err(StatusCode::FORBIDDEN, "no write access"));
    }
    let rec: PointerRecord = serde_json::from_slice(&body).map_err(|e| err(StatusCode::BAD_REQUEST, format!("bad record: {e}")))?;
    let bad = |m: &str| Err(err(StatusCode::BAD_REQUEST, m));
    if rec.namespace != ns || rec.path != path {
        return bad("record does not match url");
    }
    if rec.writer != signer.account || rec.writer_pk != signer.public_key {
        return bad("record must be signed by the request signer");
    }
    if rec.verify_signature().is_err() {
        return bad("bad record signature");
    }
    if now_ms().abs_diff(rec.ts_ms) > auth::MAX_SKEW_MS {
        return bad("record timestamp outside allowed window");
    }
    // The class the client uploaded the chunks with (same header as on the
    // chunk PUTs); recorded so reads go to that class's backends first.
    let class = match headers.get(placement::CLASS_HEADER).map(|v| v.to_str()) {
        None => st.blobs.default_class().to_string(),
        Some(Ok(c)) if st.blobs.has_class(c) => c.to_string(),
        Some(c) => return Err(err(StatusCode::BAD_REQUEST, format!("unknown storage class {:?}", c.unwrap_or("")))),
    };
    let (m, mlen) = load_manifest(&st, Some(&class), &rec.manifest_cid).await?;
    if m.size != rec.size || m.stored_size() + mlen != rec.stored_size {
        return bad("record sizes do not match manifest");
    }
    if let Some(missing) = missing_chunk(&st, &class, &m).await? {
        return Err(err(StatusCode::BAD_REQUEST, format!("chunk {missing} not uploaded")));
    }
    let prev = st.index.get(&ns, &path).await?;
    // Writes that grow the payer's storage need credit; shrinking or replacing in place does not.
    if rec.stored_size > prev.as_ref().map(|p| p.stored_size).unwrap_or(0) {
        billing::check(st.billing.as_deref(), &access.payer).await?;
    }
    let entry = IndexEntry { record: rec, class: Some(class) };
    match st.index.cas_put(&entry).await {
        Ok(()) => {}
        Err(CasError::Conflict { current }) => {
            return Err(err(StatusCode::CONFLICT, format!("seq conflict: current seq is {current}")));
        }
        Err(CasError::Other(e)) => return Err(e.into()),
    }
    st.usage
        .record(usage::Event::put(&ns, &path, &signer.account, &access.payer, entry.stored_size, prev.map(|p| p.stored_size).unwrap_or(0)))
        .await;
    Ok((StatusCode::CREATED, Json(json!({"seq": entry.seq}))).into_response())
}

/// First chunk of `m` that no backend has (checked concurrently).
async fn missing_chunk(st: &AppState, class: &str, m: &Manifest) -> anyhow::Result<Option<String>> {
    use futures_util::{StreamExt, TryStreamExt};
    let cids: Vec<String> = m.chunks.iter().map(|c| c.cid.clone()).collect();
    let mut s = futures_util::stream::iter(cids)
        .map(move |cid: String| async move {
            let has = st.blobs.has(Some(class), &cid).await?;
            Ok::<_, anyhow::Error>((cid, has))
        })
        .buffer_unordered(32);
    while let Some((cid, has)) = s.try_next().await? {
        if !has {
            return Ok(Some(cid));
        }
    }
    Ok(None)
}

#[derive(Deserialize)]
struct GetQuery {
    chunk: Option<String>,
    /// `locate`: also return per-chunk direct-fetch URLs.
    mode: Option<String>,
}

async fn get_object(
    State(st): State<Arc<AppState>>,
    Path((ns, path)): Path<(String, String)>,
    Query(q): Query<GetQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    check_obj(&ns, &path)?;
    let signer = authenticate(&st, &method, &uri, &headers, &[]).await?;
    let access = policy::resolve(&ns, &st.rules(&ns).await?, &path, &signer.account);
    if !access.read {
        return Err(err(StatusCode::FORBIDDEN, "no read access"));
    }
    let entry = st.index.get(&ns, &path).await?.ok_or_else(|| err(StatusCode::NOT_FOUND, "not found"))?;
    let class = entry.class.as_deref();
    let (manifest, manifest_raw) = load_manifest_raw(&st, class, &entry.manifest_cid).await?;
    let manifest_raw = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &manifest_raw);
    match q.chunk {
        None if q.mode.as_deref() == Some("locate") => {
            billing::check(st.billing.as_deref(), &access.payer).await?;
            let located = locate::locate(&st, entry, manifest, manifest_raw).await?;
            // Chunks handed out as direct URLs bypass the gateway, and inlined
            // chunks ride in this response; meter both as egress here (for
            // URLs an upper bound: the client may fetch fewer bytes).
            let direct: u64 = located.chunks.iter().filter(|c| c.url.is_some() || c.data.is_some()).map(|c| c.len).sum();
            if direct > 0 {
                st.usage.record(usage::Event::egress(&ns, &path, &signer.account, &access.payer, direct)).await;
            }
            Ok(Json(located).into_response())
        }
        None => Ok(Json(json!({"record": entry.record, "manifest": manifest, "manifest_raw": manifest_raw, "class": entry.class})).into_response()),
        Some(cid) => {
            billing::check(st.billing.as_deref(), &access.payer).await?;
            let len = if cid == entry.manifest_cid {
                None
            } else {
                Some(manifest.chunks.iter().find(|c| c.cid == cid).ok_or_else(|| err(StatusCode::NOT_FOUND, "chunk is not part of this object"))?.len)
            };
            let missing = || err(StatusCode::NOT_FOUND, "chunk missing from backend");
            let range_h = headers.get(axum::http::header::RANGE).and_then(|v| v.to_str().ok());
            let resp = match (len, range_h) {
                // ranged read of a data chunk: fetch only the range from the backend
                (Some(len), Some(h)) => match bridge::parse_range(Some(h), len) {
                    Ok(Some(r)) => {
                        let bytes = st.blobs.get_range(class, &cid, r.clone()).await?.ok_or_else(missing)?;
                        let cr = format!("bytes {}-{}/{len}", r.start, r.end - 1);
                        (StatusCode::PARTIAL_CONTENT, [("content-type", "application/octet-stream".to_string()), ("content-range", cr)], bytes).into_response()
                    }
                    Ok(None) => bridge::ranged_response(&headers, st.blobs.get(class, &cid).await?.ok_or_else(missing)?),
                    Err(bridge::Unsatisfiable) => return Err(err(StatusCode::RANGE_NOT_SATISFIABLE, "range not satisfiable")),
                },
                _ => bridge::ranged_response(&headers, st.blobs.get(class, &cid).await?.ok_or_else(missing)?),
            };
            let served = axum::body::HttpBody::size_hint(resp.body()).exact().unwrap_or(0);
            st.usage.record(usage::Event::egress(&ns, &path, &signer.account, &access.payer, served)).await;
            Ok(resp)
        }
    }
}

#[derive(Deserialize)]
struct DeleteQuery {
    /// Delete only if the current version is this seq (409 otherwise).
    seq: Option<u64>,
}

async fn delete_object(
    State(st): State<Arc<AppState>>,
    Path((ns, path)): Path<(String, String)>,
    Query(q): Query<DeleteQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    check_obj(&ns, &path)?;
    let signer = authenticate(&st, &method, &uri, &headers, &[]).await?;
    let access = policy::resolve(&ns, &st.rules(&ns).await?, &path, &signer.account);
    if !access.write {
        return Err(err(StatusCode::FORBIDDEN, "no write access"));
    }
    let rec = st.index.get(&ns, &path).await?.ok_or_else(|| err(StatusCode::NOT_FOUND, "not found"))?;
    if q.seq.is_some_and(|s| s != rec.seq) {
        return Err(err(StatusCode::CONFLICT, format!("seq conflict: current seq is {}", rec.seq)));
    }
    match st.index.delete(&ns, &path, rec.seq).await {
        Ok(()) => {}
        Err(CasError::Conflict { .. }) => return Err(err(StatusCode::CONFLICT, "object changed concurrently")),
        Err(CasError::Other(e)) => return Err(e.into()),
    }
    st.usage.record(usage::Event::delete(&ns, &path, &signer.account, &access.payer, rec.stored_size)).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default)]
    prefix: String,
}

async fn list_objects(
    State(st): State<Arc<AppState>>,
    Path(ns): Path<String>,
    Query(q): Query<ListQuery>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    check_ns(&ns)?;
    let signer = authenticate(&st, &method, &uri, &headers, &[]).await?;
    let rules = st.rules(&ns).await?;
    let entries: Vec<_> = st
        .index
        .list(&ns, &q.prefix)
        .await?
        .into_iter()
        .filter(|r| policy::resolve(&ns, &rules, &r.path, &signer.account).read)
        .map(|r| json!({"path": r.path, "size": r.size, "seq": r.seq, "writer": r.writer, "ts_ms": r.ts_ms, "manifest_cid": r.manifest_cid, "class": r.class}))
        .collect();
    Ok(Json(entries).into_response())
}
