//! Local provider API for OS file-provider extensions (the macOS File
//! Provider extension in `macos/`), served by the background service.
//!
//! The extension is sandboxed Swift code that holds no keys: it calls this
//! loopback HTTP API (bearer token), and the Rust side does the signing,
//! encryption, verification, retries and resumable transfers.
//!
//! Items are identified by path relative to the mounted prefix: files as
//! `a/b.txt`, folders as `a/` (trailing slash), the root as `""`. Folders
//! exist implicitly (any file below them) or were created here (kept until a
//! file is put in them or they are removed).
//!
//! | method & path | |
//! |---|---|
//! | `GET /v1/item?id=` | one item |
//! | `GET /v1/items?parent=` | children of a folder |
//! | `GET /v1/all` | every item + a sync anchor (working-set enumeration) |
//! | `GET /v1/changes?anchor=` | `{anchor, updated, deleted}` since an anchor; 410 if it expired |
//! | `GET /v1/watch?timeout_ms=` | long poll: returns when the remote changes (for `signalEnumerator`) |
//! | `GET /v1/content?id=` | file bytes (decrypted); `x-near-drive-item` header = the item |
//! | `PUT /v1/content?id=&base_seq=` | upload a file (`base_seq` 0 = new); 409 `{current}` on conflict |
//! | `POST /v1/folder?id=a/b/` | create a folder |
//! | `POST /v1/rename?from=&to=` | move a file or folder |
//! | `DELETE /v1/item?id=&seq=` | delete a file (if still at `seq`) or a folder and everything in it |
use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use near_drive_client::{near_drive_core::NearUri, Client, Conflict, GatewayError, PutOptions};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Snapshots kept for `changes`; an older anchor answers 410 (re-enumerate).
const ANCHORS: usize = 64;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub parent: String,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    /// Remote version (0 for folders).
    pub seq: u64,
    /// Content version (manifest id; empty for folders).
    pub cid: String,
    pub mtime_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Changes {
    pub anchor: u64,
    pub updated: Vec<Item>,
    pub deleted: Vec<String>,
}

/// Where the extension finds the API: written to `<home>/provider.json` and,
/// on macOS, into the App Group container shared with the extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub url: String,
    pub token: String,
    pub remote: String,
}

struct Api {
    client: Arc<Client>,
    remote: NearUri,
    token: String,
    tmp: PathBuf,
    /// Folders created here that hold no files yet.
    dirs: Mutex<BTreeSet<String>>,
    snapshots: Mutex<VecDeque<(u64, HashMap<String, Item>)>>,
    next_anchor: AtomicU64,
    next_tmp: AtomicU64,
}

type Shared = Arc<Api>;

struct ApiError(StatusCode, String, Option<serde_json::Value>);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = serde_json::json!({ "error": self.1 });
        if let (Some(serde_json::Value::Object(extra)), Some(o)) = (self.2, body.as_object_mut()) {
            o.extend(extra);
        }
        (self.0, Json(body)).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        if let Some(c) = e.downcast_ref::<Conflict>() {
            return ApiError(StatusCode::CONFLICT, c.to_string(), Some(serde_json::json!({ "current": c.current })));
        }
        if e.downcast_ref::<GatewayError>().is_some_and(|g| g.status == 404) {
            return ApiError(StatusCode::NOT_FOUND, "not found".into(), None);
        }
        tracing::warn!("provider api: {e:#}");
        ApiError(StatusCode::BAD_GATEWAY, format!("{e:#}"), None)
    }
}

fn bad(msg: &str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into(), None)
}

fn parent_of(id: &str) -> String {
    let t = id.trim_end_matches('/');
    match t.rfind('/') {
        Some(i) => t[..=i].to_string(),
        None => String::new(),
    }
}

fn name_of(id: &str) -> String {
    id.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string()
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && !id.starts_with('/') && id.trim_end_matches('/').split('/').all(|s| !s.is_empty() && s != "." && s != "..")
}

fn dir_item(id: &str) -> Item {
    Item { id: id.to_string(), parent: parent_of(id), name: name_of(id), is_dir: true, size: 0, seq: 0, cid: String::new(), mtime_ms: 0 }
}

impl Api {
    fn uri(&self, path: &str) -> Result<NearUri> {
        Ok(NearUri::object(&self.remote.namespace, &format!("{}{path}", self.remote.path))?)
    }

    /// Every item: remote files, their folders, and folders created here.
    async fn snapshot(&self) -> Result<HashMap<String, Item>> {
        let entries = self.client.list(&self.remote).await.context("listing")?;
        let mut items = HashMap::new();
        let mut files = BTreeSet::new();
        for e in entries {
            let Some(rel) = e.path.strip_prefix(&self.remote.path) else { continue };
            if !valid_id(rel) || rel.ends_with('/') {
                continue;
            }
            files.insert(rel.to_string());
            let mut p = parent_of(rel);
            while !p.is_empty() {
                items.entry(p.clone()).or_insert_with(|| dir_item(&p));
                p = parent_of(&p);
            }
            items.insert(
                rel.to_string(),
                Item {
                    id: rel.to_string(),
                    parent: parent_of(rel),
                    name: name_of(rel),
                    is_dir: false,
                    size: e.size,
                    seq: e.seq,
                    cid: e.manifest_cid.unwrap_or_default(),
                    mtime_ms: e.ts_ms,
                },
            );
        }
        let mut dirs = self.dirs.lock().unwrap();
        // A created folder that now holds files is an ordinary folder.
        dirs.retain(|d| !files.iter().any(|f| f.starts_with(d.as_str())));
        for d in dirs.iter() {
            let mut p = d.clone();
            while !p.is_empty() {
                items.entry(p.clone()).or_insert_with(|| dir_item(&p));
                p = parent_of(&p);
            }
        }
        Ok(items)
    }

    /// Take a snapshot and remember it under a new anchor.
    async fn anchored(&self) -> Result<(u64, HashMap<String, Item>)> {
        let snap = self.snapshot().await?;
        let anchor = self.next_anchor.fetch_add(1, Ordering::SeqCst);
        let mut s = self.snapshots.lock().unwrap();
        s.push_back((anchor, snap.clone()));
        while s.len() > ANCHORS {
            s.pop_front();
        }
        Ok((anchor, snap))
    }

    async fn item(&self, id: &str) -> Result<Option<Item>, ApiError> {
        if id.is_empty() {
            return Ok(Some(dir_item("")));
        }
        Ok(self.snapshot().await?.remove(id))
    }

    fn tmp_file(&self) -> PathBuf {
        self.tmp.join(format!("p-{}", self.next_tmp.fetch_add(1, Ordering::SeqCst)))
    }

    async fn move_file(&self, from: &str, to: &str, it: &Item) -> Result<()> {
        let tmp = self.tmp_file();
        self.client.get_to_file(&self.uri(from)?, &tmp).await?;
        let r = self.client.put_file(&tmp, &self.uri(to)?, &PutOptions { expect_seq: Some(0), ..Default::default() }).await;
        let _ = tokio::fs::remove_file(&tmp).await;
        r?;
        self.client.delete_if(&self.uri(from)?, it.seq).await
    }
}

#[derive(Deserialize)]
struct IdQ {
    #[serde(default)]
    id: String,
}

#[derive(Deserialize)]
struct ParentQ {
    #[serde(default)]
    parent: String,
}

#[derive(Deserialize)]
struct AnchorQ {
    anchor: u64,
}

#[derive(Deserialize)]
struct WatchQ {
    #[serde(default)]
    timeout_ms: u64,
}

#[derive(Deserialize)]
struct PutQ {
    id: String,
    #[serde(default)]
    base_seq: u64,
}

#[derive(Deserialize)]
struct RenameQ {
    from: String,
    to: String,
}

#[derive(Deserialize)]
struct DeleteQ {
    id: String,
    #[serde(default)]
    seq: u64,
}

async fn get_item(State(a): State<Shared>, Query(q): Query<IdQ>) -> Result<Json<Item>, ApiError> {
    a.item(&q.id).await?.map(Json).ok_or(ApiError(StatusCode::NOT_FOUND, "no such item".into(), None))
}

async fn get_items(State(a): State<Shared>, Query(q): Query<ParentQ>) -> Result<Json<Vec<Item>>, ApiError> {
    let mut v: Vec<Item> = a.snapshot().await?.into_values().filter(|i| i.parent == q.parent).collect();
    v.sort_by(|x, y| x.name.cmp(&y.name));
    Ok(Json(v))
}

async fn get_all(State(a): State<Shared>) -> Result<Json<Changes>, ApiError> {
    let (anchor, snap) = a.anchored().await?;
    let mut updated: Vec<Item> = snap.into_values().collect();
    updated.sort_by(|x, y| x.id.cmp(&y.id));
    Ok(Json(Changes { anchor, updated, deleted: vec![] }))
}

async fn get_changes(State(a): State<Shared>, Query(q): Query<AnchorQ>) -> Result<Json<Changes>, ApiError> {
    let Some(old) = a.snapshots.lock().unwrap().iter().find(|(n, _)| *n == q.anchor).map(|(_, s)| s.clone()) else {
        return Err(ApiError(StatusCode::GONE, "sync anchor expired; enumerate again".into(), None));
    };
    let (anchor, now) = a.anchored().await?;
    let mut updated: Vec<Item> = now.values().filter(|i| old.get(&i.id) != Some(*i)).cloned().collect();
    updated.sort_by(|x, y| x.id.cmp(&y.id));
    let mut deleted: Vec<String> = old.keys().filter(|k| !now.contains_key(*k)).cloned().collect();
    deleted.sort();
    Ok(Json(Changes { anchor, updated, deleted }))
}

async fn watch(State(a): State<Shared>, Query(q): Query<WatchQ>) -> Result<Json<serde_json::Value>, ApiError> {
    let timeout = Duration::from_millis(q.timeout_ms.clamp(1, 55_000));
    let first = a.client.watch(&a.remote, None, Duration::ZERO).await?;
    let Some(first) = first else {
        // Gateway without change notifications: the caller polls on its own.
        tokio::time::sleep(timeout).await;
        return Ok(Json(serde_json::json!({ "changed": true })));
    };
    let r = a.client.watch(&a.remote, Some(&first.cursor), timeout).await?;
    Ok(Json(serde_json::json!({ "changed": r.is_some_and(|r| r.changed) })))
}

async fn get_content(State(a): State<Shared>, Query(q): Query<IdQ>) -> Result<Response, ApiError> {
    if !valid_id(&q.id) || q.id.ends_with('/') {
        return Err(bad("not a file id"));
    }
    let tmp = a.tmp_file();
    let head = a.client.get_to_file(&a.uri(&q.id)?, &tmp).await?;
    let item = Item {
        id: q.id.clone(),
        parent: parent_of(&q.id),
        name: name_of(&q.id),
        is_dir: false,
        size: head.manifest.size,
        seq: head.record.seq,
        cid: head.record.manifest_cid.clone(),
        mtime_ms: head.record.ts_ms,
    };
    let f = tokio::fs::File::open(&tmp).await.map_err(anyhow::Error::from)?;
    // Unlinked while open (Unix): the bytes go away when the response ends.
    #[cfg(unix)]
    let _ = std::fs::remove_file(&tmp);
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(f));
    let mut resp = Response::new(body);
    resp.headers_mut().insert(header::CONTENT_LENGTH, item.size.into());
    resp.headers_mut().insert("x-near-drive-item", serde_json::to_string(&item).unwrap_or_default().parse().map_err(|_| bad("item header"))?);
    Ok(resp)
}

async fn put_content(State(a): State<Shared>, Query(q): Query<PutQ>, body: Body) -> Result<Json<Item>, ApiError> {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;
    if !valid_id(&q.id) || q.id.ends_with('/') {
        return Err(bad("not a file id"));
    }
    let tmp = a.tmp_file();
    let mut f = tokio::fs::File::create(&tmp).await.map_err(anyhow::Error::from)?;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| bad(&e.to_string()))?;
        f.write_all(&chunk).await.map_err(anyhow::Error::from)?;
    }
    f.flush().await.map_err(anyhow::Error::from)?;
    drop(f);
    let size = tokio::fs::metadata(&tmp).await.map_err(anyhow::Error::from)?.len();
    let r = a.client.put_file(&tmp, &a.uri(&q.id)?, &PutOptions { expect_seq: Some(q.base_seq), ..Default::default() }).await;
    let _ = tokio::fs::remove_file(&tmp).await;
    let rec = r?;
    a.dirs.lock().unwrap().retain(|d| !q.id.starts_with(d.as_str()));
    Ok(Json(Item { id: q.id.clone(), parent: parent_of(&q.id), name: name_of(&q.id), is_dir: false, size, seq: rec.seq, cid: rec.manifest_cid, mtime_ms: rec.ts_ms }))
}

async fn post_folder(State(a): State<Shared>, Query(q): Query<IdQ>) -> Result<Json<Item>, ApiError> {
    if !valid_id(&q.id) || !q.id.ends_with('/') {
        return Err(bad("folder ids end with /"));
    }
    a.dirs.lock().unwrap().insert(q.id.clone());
    Ok(Json(dir_item(&q.id)))
}

async fn post_rename(State(a): State<Shared>, Query(q): Query<RenameQ>) -> Result<Json<Item>, ApiError> {
    if !valid_id(&q.from) || !valid_id(&q.to) || q.from.ends_with('/') != q.to.ends_with('/') {
        return Err(bad("bad ids"));
    }
    let snap = a.snapshot().await?;
    if q.from.ends_with('/') {
        let files: Vec<Item> = snap.values().filter(|i| !i.is_dir && i.id.starts_with(&q.from)).cloned().collect();
        for it in files {
            let to = format!("{}{}", q.to, &it.id[q.from.len()..]);
            a.move_file(&it.id, &to, &it).await?;
        }
        let mut dirs = a.dirs.lock().unwrap();
        let moved: Vec<String> = dirs.iter().filter(|d| d.starts_with(&q.from)).cloned().collect();
        for d in moved {
            dirs.remove(&d);
            dirs.insert(format!("{}{}", q.to, &d[q.from.len()..]));
        }
        dirs.insert(q.to.clone());
        return Ok(Json(dir_item(&q.to)));
    }
    let it = snap.get(&q.from).cloned().ok_or(ApiError(StatusCode::NOT_FOUND, "no such item".into(), None))?;
    a.move_file(&q.from, &q.to, &it).await?;
    a.item(&q.to).await?.map(Json).ok_or(ApiError(StatusCode::BAD_GATEWAY, "moved item not visible".into(), None))
}

async fn delete_item(State(a): State<Shared>, Query(q): Query<DeleteQ>) -> Result<StatusCode, ApiError> {
    if !valid_id(&q.id) {
        return Err(bad("bad id"));
    }
    if q.id.ends_with('/') {
        let snap = a.snapshot().await?;
        for it in snap.values().filter(|i| !i.is_dir && i.id.starts_with(&q.id)) {
            match a.client.delete_if(&a.uri(&it.id)?, it.seq).await {
                Ok(()) => {}
                Err(e) if e.downcast_ref::<GatewayError>().is_some_and(|g| g.status == 404) => {}
                Err(e) => return Err(e.into()),
            }
        }
        a.dirs.lock().unwrap().retain(|d| !d.starts_with(&q.id));
        return Ok(StatusCode::NO_CONTENT);
    }
    match a.client.delete_if(&a.uri(&q.id)?, q.seq).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) if e.downcast_ref::<GatewayError>().is_some_and(|g| g.status == 404) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err(e.into()),
    }
}

async fn auth(State(a): State<Shared>, headers: HeaderMap, req: Request, next: Next) -> Response {
    let ok = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).is_some_and(|t| constant_eq(t.as_bytes(), a.token.as_bytes()));
    if !ok {
        return ApiError(StatusCode::UNAUTHORIZED, "bad token".into(), None).into_response();
    }
    next.run(req).await
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A running provider API.
pub struct ProviderApi {
    pub endpoint: Endpoint,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ProviderApi {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Serve the provider API for `remote` on a random loopback port.
pub async fn serve(client: Arc<Client>, remote: NearUri, tmp: PathBuf) -> Result<ProviderApi> {
    anyhow::ensure!(remote.path.is_empty() || remote.path.ends_with('/'), "the provider remote is a folder: end it with /");
    tokio::fs::create_dir_all(&tmp).await?;
    let token: String = (0..32).map(|_| format!("{:02x}", rand::random::<u8>())).collect();
    let api = Arc::new(Api {
        client,
        remote: remote.clone(),
        token: token.clone(),
        tmp,
        dirs: Mutex::default(),
        snapshots: Mutex::default(),
        next_anchor: AtomicU64::new(1),
        next_tmp: AtomicU64::new(1),
    });
    let app = Router::new()
        .route("/v1/item", get(get_item).delete(delete_item))
        .route("/v1/items", get(get_items))
        .route("/v1/all", get(get_all))
        .route("/v1/changes", get(get_changes))
        .route("/v1/watch", get(watch))
        .route("/v1/content", get(get_content).put(put_content))
        .route("/v1/folder", post(post_folder))
        .route("/v1/rename", post(post_rename))
        .layer(axum::middleware::from_fn_with_state(api.clone(), auth))
        .layer(axum::extract::DefaultBodyLimit::disable())
        .with_state(api);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("provider api: {e}");
        }
    });
    Ok(ProviderApi { endpoint: Endpoint { url, token, remote: remote.to_string() }, task })
}

/// Write the endpoint where the extension reads it (owner-only).
pub fn publish(endpoint: &Endpoint, path: &std::path::Path) -> Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("json.tmp");
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    std::io::Write::write_all(&mut o.open(&tmp)?, &serde_json::to_vec_pretty(endpoint)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// The macOS App Group container shared with the File Provider extension.
pub fn app_group_dir(group: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join("Library").join("Group Containers").join(group))
}
