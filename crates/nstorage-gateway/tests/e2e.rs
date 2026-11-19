//! End-to-end: real gateway on a random port, real client.
use ed25519_dalek::SigningKey;
use nstorage_client::{nstorage_core::{crypto::RootKey, keys, record::PointerRecord, NearUri}, Client, PutOptions};
use nstorage_gateway::{router, AppState, Config};
use std::collections::HashMap;

struct Env {
    url: String,
    dir: tempfile::TempDir,
    keys: HashMap<&'static str, SigningKey>,
}

async fn start() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let mut keys = HashMap::new();
    let mut dev_keys = HashMap::new();
    for a in ["alice.near", "bob.near", "app.near", "eve.near"] {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        dev_keys.insert(a.to_string(), vec![keys::format_public_key(&sk.verifying_key())]);
        keys.insert(a, sk);
    }
    let policies = serde_json::from_str(
        r#"{"app.near": [
            {"prefix":"users/{account}/","read":["{account}"],"write":["{account}","app.near"],"payer":"app.near"},
            {"prefix":"public/","read":["*"],"write":[]}
        ]}"#,
    )
    .unwrap();
    let cfg = Config {
        listen: "127.0.0.1:0".into(),
        data_dir: dir.path().to_path_buf(),
        rpc_url: None,
        storage_contract: "storage.near".into(),
        dev_keys,
        policies,
        ..Default::default()
    };
    let state = AppState::new(cfg).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    Env { url, dir, keys }
}

impl Env {
    fn client(&self, account: &str, root: Option<RootKey>) -> Client {
        Client::new(&self.url, account, self.keys[account].clone(), root)
    }
}

fn u(s: &str) -> NearUri {
    NearUri::parse(s).unwrap()
}

#[tokio::test]
async fn encrypted_roundtrip_overwrite_list_delete() {
    let env = start().await;
    let mut alice = env.client("alice.near", Some(RootKey::from_bytes([7; 32])));
    alice.chunk_size = 1000; // force multiple chunks
    let data: Vec<u8> = (0..5000u32).map(|i| (i * 31) as u8).collect();
    let uri = u("near://alice.near/memory/notes 1.json");

    let r1 = alice.put(&uri, &data, &PutOptions::default()).await.unwrap();
    assert_eq!(r1.seq, 1);
    let (head, got) = alice.get(&uri).await.unwrap();
    assert_eq!(got, data);
    assert_eq!(head.manifest.chunks.len(), 5);

    // ciphertext on disk: plaintext must not appear in any stored chunk
    let mut found_plain = false;
    for e in walk(env.dir.path().join("chunks")) {
        let b = std::fs::read(e).unwrap();
        if b.windows(64).any(|w| w == &data[..64]) {
            found_plain = true;
        }
    }
    assert!(!found_plain, "plaintext leaked to backend");

    let r2 = alice.put(&uri, b"v2", &PutOptions::default()).await.unwrap();
    assert_eq!(r2.seq, 2);
    assert_eq!(alice.get(&uri).await.unwrap().1, b"v2");

    alice.put(&u("near://alice.near/memory/b"), b"b", &PutOptions::default()).await.unwrap();
    alice.put(&u("near://alice.near/other/c"), b"c", &PutOptions::default()).await.unwrap();
    let ls = alice.list(&u("near://alice.near/memory/")).await.unwrap();
    assert_eq!(ls.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), vec!["memory/b", "memory/notes 1.json"]);

    alice.delete(&uri).await.unwrap();
    assert!(alice.head(&uri).await.unwrap().is_none());

    // a different root key cannot decrypt
    let other = env.client("alice.near", Some(RootKey::generate()));
    assert!(other.get(&u("near://alice.near/memory/b")).await.is_err());

    // usage events were metered
    let usage = std::fs::read_to_string(env.dir.path().join("usage.jsonl")).unwrap();
    assert!(usage.lines().any(|l| l.contains("\"kind\":\"put\"")));
    assert!(usage.lines().any(|l| l.contains("\"kind\":\"egress\"")));
    assert!(usage.lines().any(|l| l.contains("\"kind\":\"delete\"")));
}

#[tokio::test]
async fn namespace_isolation() {
    let env = start().await;
    let alice = env.client("alice.near", Some(RootKey::generate()));
    let eve = env.client("eve.near", Some(RootKey::generate()));
    let uri = u("near://alice.near/secret");
    alice.put(&uri, b"s", &PutOptions::default()).await.unwrap();

    let e = eve.put(&uri, b"x", &PutOptions::default()).await.unwrap_err().to_string();
    assert!(e.contains("403"), "{e}");
    let e = eve.get(&uri).await.unwrap_err().to_string();
    assert!(e.contains("403"), "{e}");
    assert!(eve.list(&u("near://alice.near/")).await.unwrap().is_empty());
    assert!(eve.delete(&uri).await.unwrap_err().to_string().contains("403"));
}

#[tokio::test]
async fn app_pays_per_user_prefix() {
    let env = start().await;
    let bob = env.client("bob.near", Some(RootKey::generate()));
    let eve = env.client("eve.near", Some(RootKey::generate()));
    let app = env.client("app.near", None);

    let uri = u("near://app.near/users/bob.near/chat/1");
    bob.put(&uri, b"hello", &PutOptions::default()).await.unwrap();
    assert_eq!(bob.get(&uri).await.unwrap().1, b"hello");
    assert!(eve.get(&uri).await.unwrap_err().to_string().contains("403"));
    // eve cannot write into bob's prefix, but can into her own
    assert!(eve.put(&uri, b"x", &PutOptions::default()).await.unwrap_err().to_string().contains("403"));
    eve.put(&u("near://app.near/users/eve.near/x"), b"e", &PutOptions::default()).await.unwrap();
    // eve's listing only shows her own objects
    let ls = eve.list(&u("near://app.near/users/")).await.unwrap();
    assert_eq!(ls.len(), 1);
    // app publishes public data; anyone reads it
    app.put(&u("near://app.near/public/model.bin"), b"weights", &PutOptions { public: true, ..Default::default() }).await.unwrap();
    assert_eq!(eve.get(&u("near://app.near/public/model.bin")).await.unwrap().1, b"weights");

    let usage = std::fs::read_to_string(env.dir.path().join("usage.jsonl")).unwrap();
    let bob_put = usage.lines().find(|l| l.contains("users/bob.near/chat/1") && l.contains("\"kind\":\"put\"")).unwrap();
    assert!(bob_put.contains("\"payer\":\"app.near\""), "{bob_put}");
}

#[tokio::test]
async fn rejects_forged_and_stale_records() {
    let env = start().await;
    let alice = env.client("alice.near", None);
    let uri = u("near://alice.near/pub");
    alice.put(&uri, b"one", &PutOptions { public: true, ..Default::default() }).await.unwrap();
    let head = alice.head(&uri).await.unwrap().unwrap();
    let http = reqwest::Client::new();
    let sk = &env.keys["alice.near"];

    let send = |rec: PointerRecord| {
        let body = serde_json::to_vec(&rec).unwrap();
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let h = nstorage_client::nstorage_core::auth::sign_request("alice.near", sk, "PUT", "/v1/o/alice.near/pub", "", ts, &body);
        http.put(format!("{}/v1/o/alice.near/pub", env.url))
            .header("x-near-account", h.account)
            .header("x-near-publickey", h.public_key)
            .header("x-near-timestamp", h.ts_ms.to_string())
            .header("x-near-signature", h.signature)
            .body(body)
            .send()
    };
    let now = head.record.ts_ms;
    // stale seq -> conflict
    let stale = PointerRecord::new_signed("alice.near", "pub", &head.record.manifest_cid, 3, head.record.stored_size, 1, "alice.near", sk, now);
    assert_eq!(send(stale).await.unwrap().status(), 409);
    // tampered size -> bad signature
    let mut forged = PointerRecord::new_signed("alice.near", "pub", &head.record.manifest_cid, 3, head.record.stored_size, 2, "alice.near", sk, now);
    forged.size = 4;
    assert_eq!(send(forged).await.unwrap().status(), 400);
    // record pointing at a manifest that was never uploaded
    let missing = PointerRecord::new_signed("alice.near", "pub", &nstorage_client::nstorage_core::cid(b"nope"), 3, 10, 2, "alice.near", sk, now);
    assert_eq!(send(missing).await.unwrap().status(), 400);
    // unknown key for the account
    let rogue = env.keys["eve.near"].clone();
    let c = Client::new(&env.url, "alice.near", rogue, None);
    assert!(c.head(&uri).await.unwrap_err().to_string().contains("401"));
}

fn walk(p: std::path::PathBuf) -> Vec<std::path::PathBuf> {
    let mut out = vec![];
    if let Ok(rd) = std::fs::read_dir(&p) {
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() { out.extend(walk(path)) } else { out.push(path) }
        }
    }
    out
}

#[tokio::test]
async fn sharing_and_app_writes_for_user() {
    let env = start().await;
    let bob_root = RootKey::generate();
    let bob_pk = bob_root.x25519_public();
    let bob = env.client("bob.near", Some(bob_root));
    // app writes into bob's prefix, encrypted only to bob; app can't read it back
    let app = env.client("app.near", None);
    let uri = u("near://app.near/users/bob.near/inbox/1");
    app.put(&uri, b"secret for bob", &PutOptions { share_with: vec![bob_pk.clone()], ..Default::default() }).await.unwrap();
    assert_eq!(bob.get(&uri).await.unwrap().1, b"secret for bob");
    assert!(app.get(&uri).await.is_err());

    // alice shares one of her objects with bob after the fact
    let alice = env.client("alice.near", Some(RootKey::generate()));
    let a_uri = u("near://alice.near/doc");
    alice.put(&a_uri, b"shared doc", &PutOptions::default()).await.unwrap();
    let rec = alice.share(&a_uri, &bob_pk).await.unwrap();
    assert_eq!(rec.seq, 2);
    // gateway policy still blocks bob (no grant) -> 403; decryption alone is not access
    assert!(bob.get(&a_uri).await.unwrap_err().to_string().contains("403"));
}
