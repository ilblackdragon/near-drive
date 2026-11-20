//! Gateway reading namespace policy from `drive.near` through a mock NEAR RPC.
mod common;

use axum::{extract::State, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use common::dev_keys;
use near_drive_client::{
    near_drive_core::{crypto::RootKey, NearUri},
    Client, PutOptions,
};
use near_drive_gateway::{policies::PolicySource, router, AppState, Config};
use near_drive_chain::StorageContract;
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
    /// `get_rules` calls (gateway and clients).
    hits: AtomicUsize,
    flaky_calls: AtomicUsize,
    sponsor_hits: AtomicUsize,
    /// account -> `get_sign_keys` answer.
    sign_keys: std::sync::Mutex<HashMap<String, Value>>,
}

fn answer(id: &Value, v: &Value) -> Json<Value> {
    let bytes: Vec<u8> = serde_json::to_vec(v).unwrap();
    Json(json!({"jsonrpc":"2.0","id":id,"result":{"result": bytes, "logs": [], "block_height": 1, "block_hash": "11111111111111111111111111111111"}}))
}

async fn rpc(State(m): State<Arc<Mock>>, Json(req): Json<Value>) -> Json<Value> {
    let p = &req["params"];
    assert_eq!(req["method"], "query");
    assert_eq!(p["request_type"], "call_function");
    if p["account_id"] != CONTRACT {
        return Json(json!({"jsonrpc":"2.0","id":req["id"],"error":{"name":"HANDLER_ERROR","cause":{"name":"UNKNOWN_ACCOUNT"},"message":"account does not exist"}}));
    }
    let args: Value = serde_json::from_slice(&B64.decode(p["args_base64"].as_str().unwrap()).unwrap()).unwrap();
    if p["method_name"] == "is_sponsor" {
        m.sponsor_hits.fetch_add(1, Ordering::SeqCst);
        let pair = (args["payer"].as_str().unwrap(), args["namespace"].as_str().unwrap());
        return answer(&req["id"], &json!(matches!(pair, ("rich.near", "spons.near") | ("bob.near", "spons.near"))));
    }
    if p["method_name"] == "get_sign_keys" {
        let keys = m.sign_keys.lock().unwrap().get(args["account_id"].as_str().unwrap()).cloned().unwrap_or(json!([]));
        return answer(&req["id"], &keys);
    }
    assert_eq!(p["method_name"], "get_rules");
    m.hits.fetch_add(1, Ordering::SeqCst);
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
        "spons.near" => json!([
            {"prefix":"a/","write":["*"],"payer":"rich.near"},
            {"prefix":"b/","write":["*"],"payer":"poor.near"},
            {"prefix":"u/{account}/","write":["*"],"payer":"{account}"}
        ]),
        _ => json!([]),
    };
    answer(&req["id"], &rules)
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
        rpc_url: Some(rpc_url.clone()),
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

    // Clients check writers against the same (mock) chain.
    let chain_client = |a: &str, root: RootKey| Client::new(&url, a, keys[a].clone(), Some(root)).with_chain(&rpc_url, CONTRACT);
    let (bob_root, eve_root) = (RootKey::from_bytes([1; 32]), RootKey::from_bytes([2; 32]));
    mock.sign_keys.lock().unwrap().insert("bob.near".into(), json!([{"key": bob_root.sign_public_key(), "since_ms": "1"}]));
    let bob = chain_client("bob.near", bob_root);
    let eve = chain_client("eve.near", eve_root);
    let public = PutOptions { public: true, ..Default::default() };

    // Rules from the contract: bob writes his own prefix, eve cannot.
    bob.put(&u("near://app.near/users/bob.near/a"), b"hi", &public).await.unwrap();
    assert_eq!(bob.get(&u("near://app.near/users/bob.near/a")).await.unwrap().1, b"hi");
    let e = eve.put(&u("near://app.near/users/bob.near/b"), b"x", &public).await.unwrap_err().to_string();
    assert!(e.contains("403"), "{e}");
    assert!(eve.get(&u("near://app.near/users/bob.near/a")).await.unwrap_err().to_string().contains("403"));
    let hits = mock.hits.load(Ordering::SeqCst);
    assert_eq!(hits, 2, "app.near rules cached across requests (once by the gateway, once by bob's client)");

    // Config override wins and never touches the RPC.
    bob.put(&u("near://ovr.near/open/x"), b"o", &public).await.unwrap();
    assert_eq!(mock.hits.load(Ordering::SeqCst), hits);

    // eve never published a signing key: the gateway refuses her records.
    let e = eve.put(&u("near://app.near/users/eve.near/x"), b"x", &public).await.unwrap_err().to_string();
    assert!(e.contains("400") && e.contains("signing key"), "{e}");

    // bob rotates his key onchain: what he signed before still reads (it
    // was in force then), records with the new key are accepted too.
    let new_root = RootKey::from_bytes([3; 32]);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    let old_pk = RootKey::from_bytes([1; 32]).sign_public_key();
    mock.sign_keys.lock().unwrap().insert(
        "bob.near".into(),
        json!([{"key": old_pk, "since_ms": "1"}, {"key": new_root.sign_public_key(), "since_ms": now.to_string()}]),
    );
    let bob2 = chain_client("bob.near", new_root);
    assert_eq!(bob2.get(&u("near://app.near/users/bob.near/a")).await.unwrap().1, b"hi");
    tokio::time::sleep(Duration::from_millis(2100)).await; // past the gateway's re-check interval
    bob2.put(&u("near://app.near/users/bob.near/a"), b"v2", &public).await.unwrap();
    assert_eq!(bob2.get(&u("near://app.near/users/bob.near/a")).await.unwrap().1, b"v2");
    // A writer whose key is not in bob's history is rejected by the gateway.
    let e = chain_client("bob.near", RootKey::from_bytes([9; 32])).put(&u("near://app.near/users/bob.near/a"), b"x", &public).await.unwrap_err().to_string();
    assert!(e.contains("400") && e.contains("signing key"), "{e}");

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

#[tokio::test]
async fn payer_must_opt_in() {
    let (rpc_url, mock) = start_rpc().await;
    let src = PolicySource::new(&HashMap::new(), Some(StorageContract::new(&rpc_url, CONTRACT)));
    let rules = src.rules("spons.near").await.unwrap();
    // rich.near sponsors spons.near; poor.near never agreed, so the owner pays.
    assert_eq!(rules[0].payer.as_deref(), Some("rich.near"));
    assert_eq!(rules[1].payer, None);
    let a = src.access("spons.near", &rules, "b/x", "eve.near").await.unwrap();
    assert_eq!(a.payer, "spons.near");
    // `{account}` payers are checked per request.
    let a = src.access("spons.near", &rules, "u/bob.near/x", "eve.near").await.unwrap();
    assert_eq!(a.payer, "bob.near");
    let a = src.access("spons.near", &rules, "u/eve.near/x", "eve.near").await.unwrap();
    assert_eq!(a.payer, "spons.near");
    // Answers are cached.
    let n = mock.sponsor_hits.load(Ordering::SeqCst);
    src.access("spons.near", &rules, "u/eve.near/y", "eve.near").await.unwrap();
    src.access("spons.near", &rules, "u/bob.near/y", "eve.near").await.unwrap();
    assert_eq!(mock.sponsor_hits.load(Ordering::SeqCst), n);
    // Config overrides are trusted as written.
    let ovr: HashMap<String, Vec<near_drive_client::near_drive_core::policy::Rule>> =
        serde_json::from_str(r#"{"spons.near":[{"prefix":"","write":["*"],"payer":"poor.near"}]}"#).unwrap();
    let src = PolicySource::new(&ovr, Some(StorageContract::new(&rpc_url, CONTRACT)));
    let rules = src.rules("spons.near").await.unwrap();
    assert_eq!(src.access("spons.near", &rules, "x", "eve.near").await.unwrap().payer, "poor.near");
}
