//! End-to-end: real gateway on a random port, real client.
use ed25519_dalek::SigningKey;
use near_drive_client::{
    near_drive_core::{crypto::RootKey, keys, policy::Rule, record::PointerRecord, NearUri},
    Client, PutOptions, TrustedWriters, WriterCheck,
};
use near_drive_gateway::{router, AppState, Config};
use std::collections::HashMap;

struct Env {
    url: String,
    dir: tempfile::TempDir,
    keys: HashMap<&'static str, SigningKey>,
    policies: HashMap<String, Vec<Rule>>,
}

const ACCOUNTS: [&str; 4] = ["alice.near", "bob.near", "app.near", "eve.near"];

/// Each account's root key (its record-signing key is derived from it).
fn root(account: &str) -> RootKey {
    RootKey::from_bytes(*blake3::hash(account.as_bytes()).as_bytes())
}

async fn start() -> Env {
    start_cfg(|_| {}).await
}

async fn start_cfg(tweak: impl FnOnce(&mut Config)) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let mut keys = HashMap::new();
    let mut dev_keys = HashMap::new();
    for a in ACCOUNTS {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        dev_keys.insert(a.to_string(), vec![keys::format_public_key(&sk.verifying_key())]);
        keys.insert(a, sk);
    }
    let policies: HashMap<String, Vec<Rule>> = serde_json::from_str(
        r#"{"app.near": [
            {"prefix":"users/{account}/","read":["{account}"],"write":["{account}","app.near"],"payer":"app.near"},
            {"prefix":"public/","read":["*"],"write":[]}
        ]}"#,
    )
    .unwrap();
    let mut cfg = Config {
        listen: "127.0.0.1:0".into(),
        data_dir: dir.path().to_path_buf(),
        rpc_url: None,
        storage_contract: "drive.near".into(),
        dev_keys,
        policies: policies.clone(),
        ..Default::default()
    };
    tweak(&mut cfg);
    let state = AppState::new(cfg).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    Env { url, dir, keys, policies }
}

impl Env {
    /// What every reader trusts: each account's derived signing key and the
    /// gateway's policies (the stand-in for `drive.near` here).
    fn trusted(&self) -> TrustedWriters {
        let mut t = TrustedWriters::new();
        for a in ACCOUNTS {
            t = t.key(a, root(a).sign_public_key());
        }
        for (ns, r) in &self.policies {
            t = t.rules(ns.clone(), r.clone());
        }
        t
    }

    fn client(&self, account: &str, root: Option<RootKey>) -> Client {
        Client::new(&self.url, account, self.keys[account].clone(), root).with_writer_check(WriterCheck::Trusted(self.trusted()))
    }
}

fn u(s: &str) -> NearUri {
    NearUri::parse(s).unwrap()
}

#[tokio::test]
async fn encrypted_roundtrip_overwrite_list_delete() {
    let env = start().await;
    let mut alice = env.client("alice.near", Some(root("alice.near")));
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
    let alice = env.client("alice.near", Some(root("alice.near")));
    let eve = env.client("eve.near", Some(root("eve.near")));
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
async fn list_pages_and_common_prefixes_follow_policy() {
    let env = start().await;
    let bob = env.client("bob.near", Some(RootKey::generate()));
    let eve = env.client("eve.near", Some(RootKey::generate()));
    let app = env.client("app.near", Some(RootKey::generate()));
    for p in ["users/bob.near/a", "users/bob.near/b", "users/bob.near/c"] {
        bob.put(&u(&format!("near://app.near/{p}")), b"b", &PutOptions::default()).await.unwrap();
    }
    for p in ["users/eve.near/x", "users/eve.near/y"] {
        eve.put(&u(&format!("near://app.near/{p}")), b"e", &PutOptions::default()).await.unwrap();
    }
    for p in ["public/p1", "secret/s", "top"] {
        app.put(&u(&format!("near://app.near/{p}")), b"a", &PutOptions { public: p != "secret/s", ..Default::default() }).await.unwrap();
    }
    let root = u("near://app.near/");
    let pg = eve.list_page(&u("near://app.near/users/"), Some("/"), None, None).await.unwrap();
    assert_eq!(pg.common_prefixes, vec!["users/eve.near/"], "other users' folders are hidden");
    assert!(pg.entries.is_empty() && pg.next_cursor.is_none());
    let pg = eve.list_page(&root, Some("/"), None, None).await.unwrap();
    assert_eq!(pg.common_prefixes, vec!["public/", "users/"]);
    assert!(pg.entries.is_empty(), "top is readable only by the owner");
    let pg = app.list_page(&root, Some("/"), None, None).await.unwrap();
    assert_eq!(pg.common_prefixes, vec!["public/", "secret/", "users/"]);
    assert_eq!(pg.entries.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), ["top"]);

    // limit 1: pages of bob's entries come back empty for eve, but the cursor advances
    let (mut cursor, mut pages, mut seen) = (None::<String>, 0, vec![]);
    loop {
        let pg = eve.list_page(&u("near://app.near/users/"), None, cursor.as_deref(), Some(1)).await.unwrap();
        pages += 1;
        assert!(pg.entries.len() <= 1);
        seen.extend(pg.entries.into_iter().map(|e| e.path));
        match pg.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(seen, ["users/eve.near/x", "users/eve.near/y"]);
    assert_eq!(pages, 5);
    // a raw (not /-aligned) prefix, and the iterate-all list
    assert_eq!(app.list(&u("near://app.near/users/bob.near/")).await.unwrap().len(), 3);
    let all = app.list_page(&u("near://app.near/t"), None, None, Some(5000)).await.unwrap();
    assert_eq!(all.entries.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), ["top"]);
}

#[tokio::test]
async fn app_pays_per_user_prefix() {
    let env = start().await;
    let bob = env.client("bob.near", Some(root("bob.near")));
    let eve = env.client("eve.near", Some(root("eve.near")));
    let app = env.client("app.near", Some(root("app.near")));

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
    let alice = env.client("alice.near", Some(root("alice.near")));
    let uri = u("near://alice.near/pub");
    alice.put(&uri, b"one", &PutOptions { public: true, ..Default::default() }).await.unwrap();
    let head = alice.head(&uri).await.unwrap().unwrap();
    let http = reqwest::Client::new();
    let req_sk = &env.keys["alice.near"];
    let sk = &root("alice.near").signing_key();

    let send = |rec: PointerRecord| {
        let body = serde_json::to_vec(&rec).unwrap();
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let h = near_drive_client::near_drive_core::auth::sign_request("alice.near", req_sk, "PUT", "/v1/o/alice.near/pub", "", ts, &body);
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
    let missing = PointerRecord::new_signed("alice.near", "pub", &near_drive_client::near_drive_core::cid(b"nope"), 3, 10, 2, "alice.near", sk, now);
    assert_eq!(send(missing).await.unwrap().status(), 400);
    // record claiming another writer than the request signer
    let other = PointerRecord::new_signed("alice.near", "pub", &head.record.manifest_cid, 3, head.record.stored_size, 2, "bob.near", sk, now_ms());
    assert_eq!(send(other).await.unwrap().status(), 400);
    // unknown key for the account
    let rogue = env.keys["eve.near"].clone();
    let c = Client::new(&env.url, "alice.near", rogue, None).insecure_skip_writer_check();
    assert!(c.head(&uri).await.unwrap_err().to_string().contains("401"));
}

/// The attack the writer check exists for: a gateway (or anyone it lets
/// write) signs a record with its own key and names alice as the writer. The
/// signature is valid, but the key is not one alice published, so readers
/// reject it. (This dev gateway checks no signing keys, like a malicious one.)
#[tokio::test]
async fn readers_reject_records_signed_with_unpublished_keys() {
    let env = start().await;
    let uri = u("near://alice.near/doc");
    let alice = env.client("alice.near", Some(root("alice.near")));
    alice.put(&uri, b"real", &PutOptions::default()).await.unwrap();

    // "forger": alice's request key but a root alice never published, and the
    // DEK wrapped to alice's real X25519 key so she could decrypt it.
    let forger = Client::new(&env.url, "alice.near", env.keys["alice.near"].clone(), Some(RootKey::from_bytes([66; 32]))).insecure_skip_writer_check();
    let opts = PutOptions { share_with: vec![root("alice.near").x25519_public()], skip_owner_key: true, ..Default::default() };
    let forged = forger.put(&uri, b"forged", &opts).await.unwrap();
    assert_eq!(forged.writer, "alice.near");

    let e = format!("{:#}", alice.get(&uri).await.unwrap_err());
    assert!(e.contains("not a trusted signing key"), "{e}");
    assert!(alice.head(&uri).await.is_err());
    assert!(alice.locate(&uri).await.is_err());
    assert!(alice.get_range(&uri, 0..2).await.is_err());
    let out = env.dir.path().join("out");
    assert!(alice.get_to_file(&uri, &out).await.is_err());
    assert!(!out.exists());

    // Without any writer check configured, reads fail and say how to fix it.
    let bare = Client::new(&env.url, "alice.near", env.keys["alice.near"].clone(), Some(root("alice.near")));
    let e = format!("{:#}", bare.get(&uri).await.unwrap_err());
    assert!(e.contains("with_chain") && e.contains("WriterCheck"), "{e}");
}

/// A writer with a published key, but writing a path the namespace policy
/// does not give it, is rejected by readers (whatever the gateway allowed).
#[tokio::test]
async fn readers_check_the_path_against_the_namespace_policy() {
    let env = start().await;
    let uri = u("near://app.near/users/bob.near/chat/1");
    let bob = env.client("bob.near", Some(root("bob.near")));
    bob.put(&uri, b"hi", &PutOptions::default()).await.unwrap();
    assert_eq!(bob.get(&uri).await.unwrap().1, b"hi");
    // A reader whose view of app.near's policy has no rule for bob.
    let strict = TrustedWriters::new().key("bob.near", root("bob.near").sign_public_key());
    let reader = Client::new(&env.url, "bob.near", env.keys["bob.near"].clone(), Some(root("bob.near"))).with_writer_check(WriterCheck::Trusted(strict));
    let e = format!("{:#}", reader.get(&uri).await.unwrap_err());
    assert!(e.contains("not allowed to write"), "{e}");
}

/// With `dev_sign_keys`, the gateway itself refuses records signed with a
/// key not listed for the writer.
#[tokio::test]
async fn gateway_checks_dev_sign_keys() {
    let env = start_cfg(|c| {
        c.dev_sign_keys = HashMap::from([("alice.near".to_string(), vec![root("alice.near").sign_public_key()])]);
    })
    .await;
    let uri = u("near://alice.near/x");
    env.client("alice.near", Some(root("alice.near"))).put(&uri, b"ok", &PutOptions::default()).await.unwrap();
    let wrong = env.client("alice.near", Some(RootKey::from_bytes([5; 32])));
    let e = wrong.put(&uri, b"no", &PutOptions::default()).await.unwrap_err().to_string();
    assert!(e.contains("400") && e.contains("signing key"), "{e}");
    // bob is not listed: any key (dev mode)
    env.client("bob.near", Some(RootKey::from_bytes([6; 32]))).put(&u("near://bob.near/y"), b"ok", &PutOptions::default()).await.unwrap();
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
    let bob_pk = root("bob.near").x25519_public();
    let bob = env.client("bob.near", Some(root("bob.near")));
    // app writes into bob's prefix, encrypted only to bob; app can't read it back
    let app = env.client("app.near", Some(root("app.near")));
    let uri = u("near://app.near/users/bob.near/inbox/1");
    app.put(&uri, b"secret for bob", &PutOptions { share_with: vec![bob_pk.clone()], skip_owner_key: true, ..Default::default() }).await.unwrap();
    assert_eq!(bob.get(&uri).await.unwrap().1, b"secret for bob");
    assert!(app.get(&uri).await.is_err());

    // alice shares one of her objects with bob after the fact
    let alice = env.client("alice.near", Some(root("alice.near")));
    let a_uri = u("near://alice.near/doc");
    alice.put(&a_uri, b"shared doc", &PutOptions::default()).await.unwrap();
    let rec = alice.share(&a_uri, &bob_pk).await.unwrap();
    assert_eq!(rec.seq, 2);
    // gateway policy still blocks bob (no grant) -> 403; decryption alone is not access
    assert!(bob.get(&a_uri).await.unwrap_err().to_string().contains("403"));
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

async fn signed(env: &Env, account: &str, method: reqwest::Method, path: &str, body: Vec<u8>) -> reqwest::Response {
    let h = near_drive_client::near_drive_core::auth::sign_request(account, &env.keys[account], method.as_str(), path, "", now_ms(), &body);
    reqwest::Client::new()
        .request(method, format!("{}{}", env.url, path))
        .header("x-near-account", h.account)
        .header("x-near-publickey", h.public_key)
        .header("x-near-timestamp", h.ts_ms.to_string())
        .header("x-near-signature", h.signature)
        .body(body)
        .send()
        .await
        .unwrap()
}

/// A manifest written by a future client with a field today's `Manifest`
/// does not know must still verify (clients hash `manifest_raw`, not a
/// re-serialization).
#[tokio::test]
async fn forward_compatible_manifest() {
    let env = start().await;
    let cid = near_drive_client::near_drive_core::cid;
    let data = b"abc".to_vec();
    let dcid = cid(&data);
    let manifest = format!(
        r#"{{"version":1,"size":3,"chunk_size":1024,"chunks":[{{"cid":"{dcid}","len":3}}],"future_field":{{"x":1}}}}"#
    )
    .into_bytes();
    let mcid = cid(&manifest);
    assert_eq!(signed(&env, "alice.near", reqwest::Method::PUT, &format!("/v1/chunk/alice.near/{dcid}"), data).await.status(), 201);
    assert_eq!(signed(&env, "alice.near", reqwest::Method::PUT, &format!("/v1/chunk/alice.near/{mcid}"), manifest.clone()).await.status(), 201);
    let rec = PointerRecord::new_signed("alice.near", "future", &mcid, 3, 3 + manifest.len() as u64, 1, "alice.near", &root("alice.near").signing_key(), now_ms());
    let resp = signed(&env, "alice.near", reqwest::Method::PUT, "/v1/o/alice.near/future", serde_json::to_vec(&rec).unwrap()).await;
    assert_eq!(resp.status(), 201);

    let alice = env.client("alice.near", None);
    let (head, got) = alice.get(&u("near://alice.near/future")).await.unwrap();
    assert_eq!(got, b"abc");
    assert!(head.manifest_raw.is_some());
    // a gateway that tampers with manifest_raw is caught
    let mut bad = head.clone();
    bad.manifest_raw = Some(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"{}"));
    assert!(near_drive_client::verify_head(&u("near://alice.near/future"), &bad).is_err());
}

#[tokio::test]
async fn cors_preflight() {
    let env = start_cfg(|c| c.cors_origins = vec!["https://app.example".into()]).await;
    let http = reqwest::Client::new();
    let pre = http
        .request(reqwest::Method::OPTIONS, format!("{}/v1/o/alice.near/x", env.url))
        .header("origin", "https://app.example")
        .header("access-control-request-method", "PUT")
        .header("access-control-request-headers", "x-near-account,x-near-signature,x-near-publickey,x-near-timestamp")
        .send()
        .await
        .unwrap();
    assert!(pre.status().is_success());
    assert_eq!(pre.headers()["access-control-allow-origin"], "https://app.example");
    let other = http
        .request(reqwest::Method::OPTIONS, format!("{}/v1/o/alice.near/x", env.url))
        .header("origin", "https://evil.example")
        .header("access-control-request-method", "PUT")
        .send()
        .await
        .unwrap();
    assert!(other.headers().get("access-control-allow-origin").is_none());
    // off by default
    let plain = start().await;
    let r = http
        .request(reqwest::Method::OPTIONS, format!("{}/v1/o/alice.near/x", plain.url))
        .header("origin", "https://app.example")
        .header("access-control-request-method", "PUT")
        .send()
        .await
        .unwrap();
    assert!(r.headers().get("access-control-allow-origin").is_none());
}
