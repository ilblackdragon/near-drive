//! nstorage gateway: stateless HTTP front for the index store and blob backends.
pub mod bridge;
pub mod cache;
pub mod keys;
pub mod locate;
pub mod placement;
pub mod policies;
pub mod s3;
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
use nstorage_core::{
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
use store::{CasError, IndexStore};
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
    /// namespace -> ordered rules. Overrides `storage.near` for these
    /// namespaces; the only policy source when `rpc_url` is None.
    #[serde(default)]
    pub policies: HashMap<String, Vec<Rule>>,
    /// Read namespace rules from `storage_contract` via `rpc_url` (cached 30 s).
    #[serde(default = "default_true")]
    pub contract_policies: bool,
    /// Blob backends, storage classes, index store, chunk cache (see README).
    #[serde(default)]
    pub storage: StorageConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8787".into(),
            data_dir: "./nst-data".into(),
            rpc_url: None,
            storage_contract: default_contract(),
            dev_keys: HashMap::new(),
            policies: HashMap::new(),
            contract_policies: true,
            storage: StorageConfig::default(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_contract() -> String {
    "storage.near".into()
}

pub struct AppState {
    pub cfg: Config,
    pub blobs: Placement,
    pub index: Arc<dyn IndexStore>,
    pub keys: keys::KeyResolver,
    pub policies: policies::PolicySource,
    pub usage: usage::UsageSink,
    replay: Mutex<HashMap<String, Instant>>,
}

impl AppState {
    pub async fn new(cfg: Config) -> anyhow::Result<Arc<Self>> {
        tokio::fs::create_dir_all(&cfg.data_dir).await?;
        Ok(Arc::new(Self {
            blobs: Placement::from_config(&cfg.storage, &cfg.data_dir)?,
            index: cfg.storage.index.build(&cfg.data_dir)?,
            keys: keys::KeyResolver::new(cfg.rpc_url.clone(), cfg.storage_contract.clone(), cfg.dev_keys.clone()),
            policies: policies::PolicySource::new(
                &cfg.policies,
                match (&cfg.rpc_url, cfg.contract_policies) {
                    (Some(rpc), true) => Some(nstorage_near::StorageContract::new(rpc.clone(), cfg.storage_contract.clone())),
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
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/chunk/{ns}/{cid}", put(put_chunk))
        .route("/v1/o/{ns}/{*path}", put(put_object).get(get_object).delete(delete_object))
        .route("/v1/list/{ns}", get(list_objects))
        .layer(DefaultBodyLimit::max(MAX_CHUNK_BYTES as usize + 1024 * 1024))
        .with_state(state)
}

pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("internal error: {e:#}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}

fn err(code: StatusCode, msg: impl Into<String>) -> ApiError {
    ApiError(code, msg.into())
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
    nstorage_core::uri::validate_account_id(&account).map_err(|e| err(StatusCode::UNAUTHORIZED, e.to_string()))?;
    let pk = nstorage_core::keys::parse_public_key(&public_key).map_err(|e| err(StatusCode::UNAUTHORIZED, e.to_string()))?;
    let msg = auth::canonical_request(method.as_str(), uri.path(), uri.query().unwrap_or(""), &account, &public_key, ts, body);
    nstorage_core::keys::verify(&pk, &msg, &sig).map_err(|_| err(StatusCode::UNAUTHORIZED, "bad signature"))?;

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
    nstorage_core::uri::validate_account_id(ns).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))
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
    if !policy::can_write_somewhere(&ns, &st.rules(&ns).await?, &signer.account) {
        return Err(err(StatusCode::FORBIDDEN, "no write access to namespace"));
    }
    if !nstorage_core::is_valid_cid(&cid) || nstorage_core::cid(&body) != cid {
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

async fn load_manifest(st: &AppState, cid: &str) -> Result<(Manifest, u64), ApiError> {
    let b = st.blobs.get(cid).await?.ok_or_else(|| err(StatusCode::BAD_REQUEST, "manifest chunk not uploaded"))?;
    let m = Manifest::from_bytes(&b).map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid manifest: {e}")))?;
    Ok((m, b.len() as u64))
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
    let (m, mlen) = load_manifest(&st, &rec.manifest_cid).await?;
    if m.size != rec.size || m.stored_size() + mlen != rec.stored_size {
        return bad("record sizes do not match manifest");
    }
    if let Some(missing) = missing_chunk(&st, &m).await? {
        return Err(err(StatusCode::BAD_REQUEST, format!("chunk {missing} not uploaded")));
    }
    let prev = st.index.get(&ns, &path).await?;
    match st.index.cas_put(&rec).await {
        Ok(()) => {}
        Err(CasError::Conflict { current }) => {
            return Err(err(StatusCode::CONFLICT, format!("seq conflict: current seq is {current}")));
        }
        Err(CasError::Other(e)) => return Err(e.into()),
    }
    st.usage
        .record(usage::Event::put(&ns, &path, &signer.account, &access.payer, rec.stored_size, prev.map(|p| p.stored_size).unwrap_or(0)))
        .await;
    Ok((StatusCode::CREATED, Json(json!({"seq": rec.seq}))).into_response())
}

/// First chunk of `m` that no backend has (checked concurrently).
async fn missing_chunk(st: &AppState, m: &Manifest) -> anyhow::Result<Option<String>> {
    use futures_util::{StreamExt, TryStreamExt};
    let cids: Vec<String> = m.chunks.iter().map(|c| c.cid.clone()).collect();
    let mut s = futures_util::stream::iter(cids)
        .map(move |cid: String| async move {
            let has = st.blobs.has(&cid).await?;
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
    let rec = st.index.get(&ns, &path).await?.ok_or_else(|| err(StatusCode::NOT_FOUND, "not found"))?;
    let (manifest, _) = load_manifest(&st, &rec.manifest_cid).await?;
    match q.chunk {
        None if q.mode.as_deref() == Some("locate") => Ok(Json(locate::locate(&st, rec, manifest).await?).into_response()),
        None => Ok(Json(json!({"record": rec, "manifest": manifest})).into_response()),
        Some(cid) => {
            let len = if cid == rec.manifest_cid {
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
                        let bytes = st.blobs.get_range(&cid, r.clone()).await?.ok_or_else(missing)?;
                        let cr = format!("bytes {}-{}/{len}", r.start, r.end - 1);
                        (StatusCode::PARTIAL_CONTENT, [("content-type", "application/octet-stream".to_string()), ("content-range", cr)], bytes).into_response()
                    }
                    Ok(None) => bridge::ranged_response(&headers, st.blobs.get(&cid).await?.ok_or_else(missing)?),
                    Err(bridge::Unsatisfiable) => return Err(err(StatusCode::RANGE_NOT_SATISFIABLE, "range not satisfiable")),
                },
                _ => bridge::ranged_response(&headers, st.blobs.get(&cid).await?.ok_or_else(missing)?),
            };
            let served = axum::body::HttpBody::size_hint(resp.body()).exact().unwrap_or(0);
            st.usage.record(usage::Event::egress(&ns, &path, &signer.account, &access.payer, served)).await;
            Ok(resp)
        }
    }
}

async fn delete_object(
    State(st): State<Arc<AppState>>,
    Path((ns, path)): Path<(String, String)>,
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
        .map(|r| json!({"path": r.path, "size": r.size, "seq": r.seq, "writer": r.writer, "ts_ms": r.ts_ms}))
        .collect();
    Ok(Json(entries).into_response())
}
