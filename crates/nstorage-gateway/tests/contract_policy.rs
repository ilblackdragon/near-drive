//! Gateway reading namespace policy from `storage.near` through a mock NEAR RPC.
mod common;

use axum::{extract::State, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use common::{client, dev_keys};
use nstorage_client::{nstorage_core::NearUri, PutOptions};
use nstorage_gateway::{policies::PolicySource, router, AppState, Config};
use nstorage_near::StorageContract;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

const CONTRACT: &str = "storage.test";

#[derive(Default)]
struct Mock {
    hits: AtomicUsize,
    flaky_calls: AtomicUsize,
}

async fn rpc(State(m): State<Arc<Mock>>, Json(req): Json<Value>) -> Json<Value> {
    let p = &req["params"];
    assert_eq!(req["method"], "query");
    assert_eq!(p["request_type"], "call_function");
    assert_eq!(p["method_name"], "get_rules");
    m.hits.fetch_add(1, Ordering::SeqCst);
    if p["account_id"] != CONTRACT {
        return Json(json!({"jsonrpc":"2.0","id":req["id"],"error":{"name":"HANDLER_ERROR","cause":{"name":"UNKNOWN_ACCOUNT"},"message":"account does not exist"}}));
    }
    let args: Value = serde_json::from_slice(&B64.decode(p["args_base64"].as_str().unwrap()).unwrap()).unwrap();
    let ns = args["namespace"].as_str().unwrap();
    let rules = match ns {
        "app.near" => json!([
            {"prefix":"users/{account}/","read":["{account}"],"write":["{account}","app.near"],"payer":"app.near"},
            {"prefix":"public/","read":["*"],"write":[]}
        ]),
        "down.near" => return Json(json!({"jsonrpc":"2.0","id":req["id"],"error":{"name":"HANDLER_ERROR","cause":{"name":"TIMEOUT_ERROR"}}})),
        "flaky.near" if m.flaky_calls.fetch_add(1, Ordering::SeqCst) > 0 => {
            return Json(json!({"jsonrpc":"2.0","id":req["id"],"error":{"name":"HANDLER_ERROR","cause":{"name":"TIMEOUT_ERROR"}}}))
        }
        "flaky.near" => json!([{"prefix":"p/","read":["*"]}]),
        _ => json!([]),
    };
    let bytes: Vec<u8> = serde_json::to_vec(&rules).unwrap();
    Json(json!({"jsonrpc":"2.0","id":req["id"],"result":{"result": bytes, "logs": [], "block_height": 1, "block_hash": "11111111111111111111111111111111"}}))
}

async fn start_rpc() -> (String, Arc<Mock>) {
    let m = Arc::new(Mock::default());
    let app = Router::new().route("/", post(rpc)).with_state(m.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, m)
}

fn u(s: &str) -> NearUri {
    NearUri::parse(s).unwrap()
}

#[tokio::test]
async fn gateway_enforces_contract_rules() {
    let (rpc_url, mock) = start_rpc().await;
    let dir = tempfile::tempdir().unwrap();
    let (keys, dev) = dev_keys(&["app.near", "bob.near", "eve.near", "ovr.near", "down.near"]);
    let cfg = Config {
        listen: "127.0.0.1:0".into(),
        data_dir: dir.path().to_path_buf(),
        rpc_url: Some(rpc_url),
        storage_contract: CONTRACT.into(),
        dev_keys: dev,
        // Config override: everyone may write ovr.near/open/.
        policies: serde_json::from_str(r#"{"ovr.near":[{"prefix":"open/","read":["*"],"write":["*"]}]}"#).unwrap(),
        ..Default::default()
    };
    let state = AppState::new(cfg).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });

    let bob = client(&url, "bob.near", &keys["bob.near"], None);
    let eve = client(&url, "eve.near", &keys["eve.near"], None);
    let public = PutOptions { public: true, ..Default::default() };

    // Rules from the contract: bob writes his own prefix, eve cannot.
    bob.put(&u("near://app.near/users/bob.near/a"), b"hi", &public).await.unwrap();
    assert_eq!(bob.get(&u("near://app.near/users/bob.near/a")).await.unwrap().1, b"hi");
    let e = eve.put(&u("near://app.near/users/bob.near/b"), b"x", &public).await.unwrap_err().to_string();
    assert!(e.contains("403"), "{e}");
    assert!(eve.get(&u("near://app.near/users/bob.near/a")).await.unwrap_err().to_string().contains("403"));
    let hits = mock.hits.load(Ordering::SeqCst);
    assert_eq!(hits, 1, "app.near rules cached across requests");

    // Config override wins and never touches the RPC.
    eve.put(&u("near://ovr.near/open/x"), b"o", &public).await.unwrap();
    assert_eq!(mock.hits.load(Ordering::SeqCst), hits);

    // RPC failure with nothing cached: 503 (not a silent policy change).
    let e = eve.put(&u("near://down.near/x"), b"x", &public).await.unwrap_err().to_string();
    assert!(e.contains("503"), "{e}");
}

#[tokio::test]
async fn policy_source_fallbacks() {
    let (rpc_url, _mock) = start_rpc().await;
    // Contract account missing: no rules (owner-only default).
    let src = PolicySource::new(&HashMap::new(), Some(StorageContract::new(&rpc_url, "missing.test")));
    assert!(src.rules("app.near").await.unwrap().is_empty());
    // RPC errors after expiry: the stale copy is served.
    let src = PolicySource::new(&HashMap::new(), Some(StorageContract::new(&rpc_url, CONTRACT))).with_ttl(Duration::ZERO);
    assert_eq!(src.rules("flaky.near").await.unwrap().len(), 1);
    assert_eq!(src.rules("flaky.near").await.unwrap()[0].prefix, "p/");
    assert!(src.rules("down.near").await.is_err());
    // No contract configured: config only.
    let src = PolicySource::new(&HashMap::new(), None);
    assert!(src.rules("app.near").await.unwrap().is_empty());
}
