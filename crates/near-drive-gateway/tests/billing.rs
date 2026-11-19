//! Billing integration: real gateway + client against a mock cloud-api on a
//! random 127.0.0.1 port. Covers metering of real traffic, reporting with
//! retries and an at-least-once resend after a simulated crash (deduped by
//! idempotency key), and the 402 credit gate.
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::SigningKey;
use near_drive_client::{near_drive_core::{crypto::RootKey, keys, NearUri}, Client, PutOptions};
use near_drive_gateway::{
    billing::{settle::Service, Billing, BillingConfig},
    router, AppState, Config,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex},
};

const TOKEN: &str = "mock-storage-token";
const H: u64 = 3_600_000;
const GIB: u128 = 1 << 30;

#[derive(Default)]
struct Mock {
    /// idempotency key -> first accepted body.
    recorded: Mutex<HashMap<String, Value>>,
    posts: AtomicUsize,
    duplicates: AtomicUsize,
    /// Fail this many upcoming POSTs with 500.
    fail_posts: AtomicUsize,
    /// payer -> (can_charge, reason); unknown payers are `unknown_account`.
    status: Mutex<HashMap<String, (bool, &'static str)>>,
    status_calls: AtomicUsize,
    status_down: std::sync::atomic::AtomicBool,
}

fn authorized(h: &HeaderMap) -> bool {
    h.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {TOKEN}"))
}

async fn mock_usage(State(m): State<Arc<Mock>>, h: HeaderMap, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    if !authorized(&h) {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    m.posts.fetch_add(1, Ordering::SeqCst);
    if m.fail_posts.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": {"type": "internal_server_error"}})));
    }
    let key = body["idempotency_key"].as_str().unwrap().to_string();
    let mut rec = m.recorded.lock().unwrap();
    match rec.get(&key) {
        Some(prev) if *prev != body => (StatusCode::CONFLICT, Json(json!({"error": {"type": "conflict"}}))),
        Some(_) => {
            m.duplicates.fetch_add(1, Ordering::SeqCst);
            (StatusCode::OK, Json(json!({"id": key})))
        }
        None => {
            rec.insert(key.clone(), body);
            (StatusCode::OK, Json(json!({"id": key})))
        }
    }
}

async fn mock_status(State(m): State<Arc<Mock>>, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> (StatusCode, Json<Value>) {
    if !authorized(&h) {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    m.status_calls.fetch_add(1, Ordering::SeqCst);
    if m.status_down.load(Ordering::SeqCst) {
        return (StatusCode::BAD_GATEWAY, Json(json!({})));
    }
    let payer = &q["near_account_id"];
    let (can, reason) = m.status.lock().unwrap().get(payer).copied().unwrap_or((false, "unknown_account"));
    (StatusCode::OK, Json(json!({"near_account_id": payer, "can_charge": can, "reason": reason, "remaining": if can { 1_000_000 } else { 0 }})))
}

async fn start_mock() -> (String, Arc<Mock>) {
    let m = Arc::new(Mock::default());
    let app = Router::new()
        .route("/v1/internal/service-usage", post(mock_usage))
        .route("/v1/internal/billing-status", get(mock_status))
        .with_state(m.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, m)
}

struct Env {
    url: String,
    state: Arc<AppState>,
    keys: HashMap<&'static str, SigningKey>,
    _dir: tempfile::TempDir,
}

impl Env {
    fn client(&self, account: &str) -> Client {
        // 503 billing_unavailable is retried; keep these tests fast.
        let mut c = Client::new(&self.url, account, self.keys[account].clone(), Some(RootKey::generate()));
        c.set_net(near_drive_client::NetConfig { attempts: 2, base_delay: std::time::Duration::from_millis(10), ..Default::default() });
        c
    }
    fn billing(&self) -> &Billing {
        self.state.billing.as_deref().unwrap()
    }
}

fn billing_cfg(mock: &str, extra: Value) -> BillingConfig {
    // SAFETY-free on edition 2021; every test uses the same value.
    std::env::set_var("NEAR_DRIVE_TEST_BILLING_TOKEN", TOKEN);
    let mut v = json!({
        "cloud_api_url": mock,
        "token_env": "NEAR_DRIVE_TEST_BILLING_TOKEN",
        "gateway_id": "gw-test",
        // Background loops stay out of the way; tests drive the meter and reporter.
        "meter_interval_secs": 3600,
        "report_interval_secs": 3600,
    });
    v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    serde_json::from_value(v).unwrap()
}

async fn start(mock: &str, extra: Value) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let mut keys = HashMap::new();
    let mut dev_keys = HashMap::new();
    for a in ["alice.near", "bob.near", "app.near", "broke.near"] {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        dev_keys.insert(a.to_string(), vec![keys::format_public_key(&sk.verifying_key())]);
        keys.insert(a, sk);
    }
    let policies = serde_json::from_str(
        r#"{"app.near": [{"prefix":"users/{account}/","read":["{account}"],"write":["{account}","app.near"],"payer":"app.near"}]}"#,
    )
    .unwrap();
    let cfg = Config {
        listen: "127.0.0.1:0".into(),
        data_dir: dir.path().to_path_buf(),
        dev_keys,
        policies,
        billing: Some(billing_cfg(mock, extra)),
        ..Default::default()
    };
    let state = AppState::new(cfg).await.unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let s = state.clone();
    tokio::spawn(async move { axum::serve(l, router(s)).await.unwrap() });
    Env { url, state, keys, _dir: dir }
}

fn u(s: &str) -> NearUri {
    NearUri::parse(s).unwrap()
}

fn now_ms() -> u64 {
    near_drive_gateway::billing::now_ms()
}

fn usage_events(env: &Env) -> Vec<Value> {
    std::fs::read_to_string(env.state.cfg.data_dir.join("usage.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[tokio::test]
async fn meters_traffic_and_reports_exactly_once_across_retries_and_restart() {
    let (mock, m) = start_mock().await;
    for p in ["alice.near", "app.near", "bob.near"] {
        m.status.lock().unwrap().insert(p.into(), (true, "ok"));
    }
    let env = start(&mock, json!({})).await;
    let mut alice = env.client("alice.near");
    alice.chunk_size = 1 << 20;
    let big: Vec<u8> = (0..(8u32 << 20)).map(|i| (i % 251) as u8).collect();
    alice.put(&u("near://alice.near/w/big.bin"), &big, &PutOptions::default()).await.unwrap();
    alice.put(&u("near://alice.near/w/small"), b"v1", &PutOptions::default()).await.unwrap();
    alice.put(&u("near://alice.near/w/small"), b"version two", &PutOptions::default()).await.unwrap();
    assert_eq!(alice.get(&u("near://alice.near/w/big.bin")).await.unwrap().1, big);
    alice.delete(&u("near://alice.near/w/small")).await.unwrap();
    // app pays for bob's prefix
    env.client("bob.near").put(&u("near://app.near/users/bob.near/x"), b"hi", &PutOptions::default()).await.unwrap();

    // Expected totals straight from the usage log.
    let events = usage_events(&env);
    let alice_events: Vec<_> = events.iter().filter(|e| e["payer"] == "alice.near").collect();
    let egress: u128 = alice_events.iter().filter(|e| e["kind"] == "egress").map(|e| e["bytes"].as_u64().unwrap() as u128).sum();
    let big_put = alice_events.iter().find(|e| e["path"] == "w/big.bin").unwrap();
    let (big_bytes, big_ts) = (big_put["bytes"].as_u64().unwrap() as u128, big_put["ts_ms"].as_u64().unwrap());
    assert!(egress >= 8 << 20, "{egress}");

    // Close 100 hourly windows.
    let now = now_ms();
    let horizon = now + 100 * H + 60_000;
    env.billing().meter_tick(horizon).await.unwrap();
    let pending = env.billing().pending().await;
    let sum = |payer: &str, svc: Service| -> u64 {
        pending.iter().filter(|p| p.line.payer == payer && p.line.service == svc).map(|p| p.line.quantity_milli).sum()
    };
    // Requests: every put/delete/egress event.
    assert_eq!(sum("alice.near", Service::Requests), alice_events.len() as u64 * 1000);
    assert_eq!(sum("app.near", Service::Requests), 1000);
    assert_eq!(sum("bob.near", Service::Requests), 0, "bob is not the payer");
    // Egress: bytes served, floor to milli-GiB (remainder carried).
    assert_eq!(sum("alice.near", Service::EgressGib) as u128, egress * 1000 / GIB);
    // Storage: big.bin's bytes from its put until the end of the last closed window
    // (the small object lived < 1 s and only adds a sub-unit remainder).
    let last_end = pending.iter().map(|p| p.line.period_end_ms).max().unwrap();
    let expected = big_bytes * (last_end - big_ts) as u128 * 1000 / (GIB * H as u128);
    let got = sum("alice.near", Service::StorageGibHour) as u128;
    assert!(got.abs_diff(expected) <= 1, "storage milli {got} vs {expected}");
    assert!((770..=782).contains(&got), "8 MiB for ~100 h is ~0.78 GiB-h = ~781 milli, got {got}");
    let lines = pending.len();

    // Report: the first two POSTs fail transiently and are retried later.
    let state_file = env.state.cfg.data_dir.join("billing/state.json");
    let snapshot = std::fs::read(&state_file).unwrap();
    m.fail_posts.store(2, Ordering::SeqCst);
    let settled = env.billing().report_once(now).await.unwrap();
    assert_eq!(settled, lines - 2);
    let left = env.billing().pending().await;
    assert_eq!(left.len(), 2);
    assert!(left.iter().all(|p| p.attempts == 1 && p.next_attempt_ms > now && p.last_error.as_deref().unwrap().contains("500")));
    assert_eq!(env.billing().report_once(now).await.unwrap(), 0, "backoff: not due yet");
    assert_eq!(env.billing().report_once(now + 10 * 60_000).await.unwrap(), 2);
    assert!(env.billing().pending().await.is_empty());
    let unique = m.recorded.lock().unwrap().len();
    assert_eq!(unique, lines);

    // Crash simulation: restore the state saved before reporting (as if the
    // process died after cloud-api accepted the lines but before saving) and
    // restart. Every line is re-sent with the same key; cloud-api dedupes.
    std::fs::write(&state_file, &snapshot).unwrap();
    let restarted = Billing::open(env.state.cfg.billing.as_ref().unwrap(), &env.state.cfg.data_dir).unwrap();
    assert_eq!(restarted.pending().await.len(), lines);
    restarted.meter_tick(horizon).await.unwrap();
    assert_eq!(restarted.pending().await.len(), lines, "no events are re-metered after restart");
    assert_eq!(restarted.report_once(now).await.unwrap(), lines);
    assert_eq!(m.recorded.lock().unwrap().len(), unique, "no new charges");
    assert_eq!(m.duplicates.load(Ordering::SeqCst), lines);

    // Recorded bodies carry the cloud-api contract.
    let rec = m.recorded.lock().unwrap();
    let (key, body) = rec.iter().find(|(_, b)| b["service_name"] == "storage_gib_hour").unwrap();
    assert!(key.starts_with("near-drive:gw-test:alice.near:"), "{key}");
    assert_eq!(body["near_account_id"], "alice.near");
    assert!(body["quantity"].as_str().unwrap().parse::<f64>().unwrap() > 0.0);
    assert!(body["period_start"].as_str().unwrap().ends_with(":00:00Z"));
}

#[tokio::test]
async fn permanent_rejections_go_to_the_dead_letter_log() {
    let (mock, m) = start_mock().await;
    m.status.lock().unwrap().insert("alice.near".into(), (true, "ok"));
    let env = start(&mock, json!({})).await;
    env.client("alice.near").put(&u("near://alice.near/a"), b"x", &PutOptions::default()).await.unwrap();
    // Past the window end plus the close grace, whatever the time of day.
    env.billing().meter_tick(now_ms() + 2 * H).await.unwrap();
    // Pre-record the same key with different data: cloud-api answers 409.
    let line = env.billing().pending().await[0].line.clone();
    m.recorded.lock().unwrap().insert(line.idempotency_key.clone(), json!({"other": true}));
    env.billing().report_once(now_ms()).await.unwrap();
    assert!(env.billing().pending().await.is_empty());
    let dead = std::fs::read_to_string(env.state.cfg.data_dir.join("billing/dead_letter.jsonl")).unwrap();
    assert!(dead.contains(&line.idempotency_key) && dead.contains("409"), "{dead}");
}

#[tokio::test]
async fn credit_gate_refuses_writes_and_egress_with_402() {
    let (mock, m) = start_mock().await;
    {
        let mut s = m.status.lock().unwrap();
        s.insert("alice.near".into(), (true, "ok"));
        s.insert("app.near".into(), (true, "ok"));
        s.insert("broke.near".into(), (false, "limit_exceeded"));
    }
    // Cache answers for 60 s (default).
    let env = start(&mock, json!({})).await;
    let alice = env.client("alice.near");
    alice.put(&u("near://alice.near/a"), b"one", &PutOptions::default()).await.unwrap();
    alice.put(&u("near://alice.near/b"), b"two", &PutOptions::default()).await.unwrap();
    assert_eq!(m.status_calls.load(Ordering::SeqCst), 1, "one cached lookup for chunk uploads, puts");

    let err = env.client("broke.near").put(&u("near://broke.near/a"), b"x", &PutOptions::default()).await.unwrap_err().to_string();
    assert!(err.contains("402") && err.contains("payment_required") && err.contains("limit_exceeded"), "{err}");
    // bob has no account at all, but app.near pays for his prefix: allowed.
    env.client("bob.near").put(&u("near://app.near/users/bob.near/x"), b"hi", &PutOptions::default()).await.unwrap();
    // ...while bob's own namespace is refused (unknown account).
    let err = env.client("bob.near").put(&u("near://bob.near/x"), b"hi", &PutOptions::default()).await.unwrap_err().to_string();
    assert!(err.contains("402") && err.contains("no NEAR AI Cloud account"), "{err}");
}

#[tokio::test]
async fn gate_uses_stale_answers_then_fail_mode_when_cloud_api_is_down() {
    let (mock, m) = start_mock().await;
    {
        let mut s = m.status.lock().unwrap();
        s.insert("alice.near".into(), (true, "ok"));
        s.insert("broke.near".into(), (false, "no_credits"));
    }
    // No caching, so every request asks cloud-api; stale answers are kept 1 h.
    let closed = start(&mock, json!({"status_cache_secs": 0, "negative_cache_secs": 0, "fail_open": false})).await;
    let alice = closed.client("alice.near");
    alice.put(&u("near://alice.near/a"), b"one", &PutOptions::default()).await.unwrap();
    assert!(closed.client("broke.near").put(&u("near://broke.near/a"), b"x", &PutOptions::default()).await.unwrap_err().to_string().contains("402"));

    // Egress is gated too: alice runs out, reads of her objects stop.
    m.status.lock().unwrap().insert("alice.near".into(), (false, "limit_exceeded"));
    let err = alice.get(&u("near://alice.near/a")).await.unwrap_err().to_string();
    assert!(err.contains("402"), "{err}");
    // Deletes are never gated.
    alice.delete(&u("near://alice.near/a")).await.unwrap();
    m.status.lock().unwrap().insert("alice.near".into(), (true, "ok"));
    alice.put(&u("near://alice.near/b"), b"two", &PutOptions::default()).await.unwrap();

    m.status_down.store(true, Ordering::SeqCst);
    // Known payers: last answer reused.
    alice.put(&u("near://alice.near/c"), b"three", &PutOptions::default()).await.unwrap();
    assert!(closed.client("broke.near").put(&u("near://broke.near/a"), b"x", &PutOptions::default()).await.unwrap_err().to_string().contains("402"));
    // Payer never seen: fail closed -> 503.
    let err = closed.client("app.near").put(&u("near://app.near/x"), b"x", &PutOptions::default()).await.unwrap_err().to_string();
    assert!(err.contains("503") && err.contains("billing_unavailable"), "{err}");

    // Same outage with fail_open (the default): the unknown payer is let through.
    let open = start(&mock, json!({"status_cache_secs": 0})).await;
    open.client("app.near").put(&u("near://app.near/x"), b"x", &PutOptions::default()).await.unwrap();
}
