//! End-to-end `request_root_key` against a mock NEAR RPC that plays the MPC
//! contract + network (yield/resume simulated by a send_tx timeout error and a
//! later `tx` poll). Checks tx signature, args and deposit as the chain would.
use axum::{extract::State, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use blstrs::{G1Projective, G2Projective, Scalar};
use ed25519_dalek::{Signature, SigningKey, Verifier};
use ff::Field;
use group::Group;
use nstorage_ckd::{near, *};
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
