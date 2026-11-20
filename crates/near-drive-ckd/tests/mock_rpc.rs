//! End-to-end `request_root_key` against a mock NEAR RPC that plays the MPC
//! contract + network (yield/resume simulated by a send_tx timeout error and a
//! later `tx` poll). Checks tx signature, args and deposit as the chain would.
use axum::{extract::State, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use blstrs::{G1Projective, G2Projective, Scalar};
use ed25519_dalek::{Signature, SigningKey, Verifier};
use ff::Field;
use group::Group;
use near_drive_ckd::{near, *};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

struct Mock {
    msk: Scalar,
    account: String,
    signer_pk: [u8; 32],
    result: Mutex<Option<Value>>,
    send_calls: Mutex<u32>,
}

fn read_str(b: &[u8], i: &mut usize) -> Vec<u8> {
    let n = u32::from_le_bytes(b[*i..*i + 4].try_into().unwrap()) as usize;
    *i += 4;
    let s = b[*i..*i + n].to_vec();
    *i += n;
    s
}

/// Decodes the one tx shape we send; panics on anything else.
fn decode(signed: &[u8], signer_pk: &[u8; 32]) -> (String, String, String, Vec<u8>, u64, u128) {
    let mut i = 0;
    let signer = String::from_utf8(read_str(signed, &mut i)).unwrap();
    assert_eq!(signed[i], 0);
    assert_eq!(&signed[i + 1..i + 33], signer_pk);
    i += 33 + 8;
    let receiver = String::from_utf8(read_str(signed, &mut i)).unwrap();
    i += 32;
    assert_eq!(u32::from_le_bytes(signed[i..i + 4].try_into().unwrap()), 1);
    i += 4;
    assert_eq!(signed[i], 2);
    i += 1;
    let method = String::from_utf8(read_str(signed, &mut i)).unwrap();
    let args = read_str(signed, &mut i);
    let gas = u64::from_le_bytes(signed[i..i + 8].try_into().unwrap());
    i += 8;
    let deposit = u128::from_le_bytes(signed[i..i + 16].try_into().unwrap());
    i += 16;
    let body = &signed[..i];
    assert_eq!(signed[i], 0);
    let sig = Signature::from_slice(&signed[i + 1..i + 65]).unwrap();
    assert_eq!(signed.len(), i + 65);
    let hash: [u8; 32] = Sha256::digest(body).into();
    ed25519_dalek::VerifyingKey::from_bytes(signer_pk)
        .unwrap()
        .verify(&hash, &sig)
        .expect("tx signature");
    (signer, receiver, method, args, gas, deposit)
}

async fn rpc(State(m): State<Arc<Mock>>, Json(req): Json<Value>) -> Json<Value> {
    let p = &req["params"];
    let result = match req["method"].as_str().unwrap() {
        "query" if p["request_type"] == "call_function" => {
            assert_eq!(p["method_name"], "public_key");
            let pk = format_g2(&(G2Projective::generator() * m.msk));
            json!({"result": serde_json::to_vec(&json!(pk)).unwrap()})
        }
        "query" => json!({"nonce": 41, "permission": "FullAccess"}),
        "block" => json!({"header": {"hash": bs58::encode([9u8; 32]).into_string()}}),
        "send_tx" => {
            *m.send_calls.lock().unwrap() += 1;
            let signed = B64.decode(p["signed_tx_base64"].as_str().unwrap()).unwrap();
            let (signer, receiver, method, args, gas, deposit) = decode(&signed, &m.signer_pk);
            assert_eq!(signer, m.account);
            assert_eq!(receiver, "v1.signer-prod.testnet");
            assert_eq!(method, "request_app_private_key");
            assert!(gas >= 15_000_000_000_000);
            assert!(deposit >= 1);
            let args: Value = serde_json::from_slice(&args).unwrap();
            let r = &args["request"];
            let pk1 = parse_g1(
                r["app_public_key"]["AppPublicKeyPV"]["pk1"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            let pk2 = parse_g2(
                r["app_public_key"]["AppPublicKeyPV"]["pk2"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            // contract's app_public_key_check: e(A1, G2) == e(G1, A2)
            assert_eq!(
                blstrs::pairing(&pk1.into(), &G2Projective::generator().into()),
                blstrs::pairing(&G1Projective::generator().into(), &pk2.into())
            );
            let app_id = derive_app_id(&signer, r["derivation_path"].as_str().unwrap());
            let pk = G2Projective::generator() * m.msk;
            let y = Scalar::random(rand::rngs::OsRng);
            let resp = json!({
                "big_y": format_g1(&(G1Projective::generator() * y)),
                "big_c": format_g1(&(hash_to_g1(&pk, &app_id) * m.msk + pk1 * y)),
            });
            *m.result.lock().unwrap() =
                Some(json!({"status": {"SuccessValue": B64.encode(resp.to_string())}}));
            // Like a real RPC while the yield is pending.
            return Json(
                json!({"jsonrpc": "2.0", "id": req["id"], "error": {"name": "HANDLER_ERROR", "cause": {"name": "TIMEOUT_ERROR"}}}),
            );
        }
        "tx" => m
            .result
            .lock()
            .unwrap()
            .clone()
            .expect("tx polled before send"),
        other => panic!("unexpected rpc {other}"),
    };
    Json(json!({"jsonrpc": "2.0", "id": req["id"], "result": result}))
}

#[tokio::test]
async fn request_root_key_end_to_end_with_mock_rpc() {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mock = Arc::new(Mock {
        msk: Scalar::random(rand::rngs::OsRng),
        account: "alice.testnet".into(),
        signer_pk: key.verifying_key().to_bytes(),
        result: Mutex::new(None),
        send_calls: Mutex::new(0),
    });
    let app = Router::new().route("/", post(rpc)).with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mut net = CkdNetwork::for_network("testnet").unwrap();
    net.rpc_url = format!("http://{addr}/");
    let signer = near::Signer {
        account_id: "alice.testnet".into(),
        key,
    };
    let k1 = near::request_root_key(&net, &signer, DERIVATION_PATH)
        .await
        .unwrap();
    let k2 = near::request_root_key(&net, &signer, DERIVATION_PATH)
        .await
        .unwrap();
    assert_eq!(
        k1.as_bytes(),
        k2.as_bytes(),
        "same account+path → same root key"
    );
    assert_eq!(*mock.send_calls.lock().unwrap(), 2);

    // Expected value computed independently from msk.
    let pk = G2Projective::generator() * mock.msk;
    let sig = hash_to_g1(&pk, &derive_app_id("alice.testnet", DERIVATION_PATH)) * mock.msk;
    assert_eq!(
        root_key_from_ckd_secret(&sig.to_compressed()).as_bytes(),
        k1.as_bytes()
    );
}

/// Scripted RPC for `send_and_wait`: answers come from per-method queues
/// (the last answer repeats); every call is recorded.
#[derive(Default)]
struct Script {
    send_tx: Mutex<Vec<Value>>,
    tx: Mutex<Vec<Value>>,
    calls: Mutex<Vec<(String, Value)>>,
}

fn rpc_err(cause: &str) -> Value {
    json!({"error": {"name": "HANDLER_ERROR", "cause": {"name": cause, "info": {}}}})
}

async fn scripted(State(s): State<Arc<Script>>, Json(req): Json<Value>) -> Json<Value> {
    let method = req["method"].as_str().unwrap().to_string();
    s.calls.lock().unwrap().push((method.clone(), req["params"].clone()));
    let q = match method.as_str() {
        "send_tx" => &s.send_tx,
        "tx" => &s.tx,
        m => panic!("unexpected {m}"),
    };
    let mut q = q.lock().unwrap();
    let a = if q.len() > 1 { q.remove(0) } else { q[0].clone() };
    let mut out = json!({"jsonrpc": "2.0", "id": req["id"]});
    match a.get("error") {
        Some(e) => out["error"] = e.clone(),
        None => out["result"] = a,
    }
    Json(out)
}

async fn serve_script(s: Arc<Script>) -> near::Rpc {
    let app = Router::new().route("/", post(scripted)).with_state(s);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    near::Rpc::new(&format!("http://{addr}/"))
}

const POLL: std::time::Duration = std::time::Duration::from_millis(20);

#[tokio::test]
async fn unknown_transaction_is_resent_with_the_same_bytes() {
    let ok = json!({"status": {"SuccessValue": ""}});
    let s = Arc::new(Script {
        send_tx: Mutex::new(vec![rpc_err("TIMEOUT_ERROR"), json!({"final_execution_status": "NONE"})]),
        tx: Mutex::new(vec![rpc_err("UNKNOWN_TRANSACTION"), ok.clone()]),
        ..Default::default()
    });
    let rpc = serve_script(s.clone()).await;
    let v = rpc
        .send_and_wait(b"signed-bytes", &[5; 32], "alice.testnet", std::time::Duration::from_secs(5), POLL)
        .await
        .unwrap();
    assert_eq!(v, ok);
    let calls = s.calls.lock().unwrap();
    let names: Vec<&str> = calls.iter().map(|(m, _)| m.as_str()).collect();
    assert_eq!(names, ["send_tx", "tx", "send_tx", "tx"]);
    assert_eq!(calls[0].1["signed_tx_base64"], calls[2].1["signed_tx_base64"], "re-sent the identical tx");
    assert_eq!(calls[1].1["tx_hash"], bs58::encode([5u8; 32]).into_string());
}

#[tokio::test]
async fn invalid_transaction_stops_at_once() {
    let s = Arc::new(Script {
        send_tx: Mutex::new(vec![rpc_err("INVALID_TRANSACTION")]),
        tx: Mutex::new(vec![json!({"status": {"SuccessValue": ""}})]),
        ..Default::default()
    });
    let rpc = serve_script(s.clone()).await;
    let e = rpc
        .send_and_wait(b"x", &[6; 32], "alice.testnet", std::time::Duration::from_secs(5), POLL)
        .await
        .unwrap_err();
    let msg = format!("{e:#}");
    assert!(msg.contains("INVALID_TRANSACTION") && msg.contains(&bs58::encode([6u8; 32]).into_string()), "{msg}");
    assert_eq!(s.calls.lock().unwrap().len(), 1, "no polling after a rejection");
}

#[tokio::test]
async fn timeout_reports_hash_and_first_send_error() {
    let s = Arc::new(Script {
        send_tx: Mutex::new(vec![rpc_err("TIMEOUT_ERROR")]),
        tx: Mutex::new(vec![json!({"final_execution_status": "INCLUDED"})]),
        ..Default::default()
    });
    let rpc = serve_script(s).await;
    let e = rpc
        .send_and_wait(b"x", &[7; 32], "alice.testnet", std::time::Duration::from_millis(200), POLL)
        .await
        .unwrap_err();
    let msg = format!("{e:#}");
    assert!(msg.contains(&bs58::encode([7u8; 32]).into_string()), "{msg}");
    assert!(msg.contains("first send_tx error") && msg.contains("TIMEOUT_ERROR"), "{msg}");
}
