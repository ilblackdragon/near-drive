//! The provider API (what the macOS File Provider extension calls), driven
//! over HTTP against an in-process gateway.
use ed25519_dalek::SigningKey;
use near_drive_client::{
    near_drive_core::{crypto::RootKey, keys, NearUri},
    Client, PutOptions,
};
use near_drive_gateway::{router, AppState, Config};
use near_drive_mount::provider::{serve, Changes, Item};
use reqwest::StatusCode;
use std::collections::HashMap;
use std::sync::Arc;

fn u(s: &str) -> NearUri {
    NearUri::parse(s).unwrap()
}

#[tokio::test]
async fn provider_api() {
    let tmp = tempfile::tempdir().unwrap();
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let dev = HashMap::from([("alice.near".to_string(), vec![keys::format_public_key(&sk.verifying_key())])]);
    let cfg = Config { listen: "127.0.0.1:0".into(), data_dir: tmp.path().join("gw"), dev_keys: dev, ..Default::default() };
    let state = AppState::new(cfg).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    let root = *RootKey::generate().as_bytes();
    let c = Client::new(&url, "alice.near", sk.clone(), Some(RootKey::from_bytes(root)));
    c.put(&u("near://alice.near/Drive/docs/a.txt"), b"hello", &PutOptions::default()).await.unwrap();
    c.put(&u("near://alice.near/Drive/b.bin"), &vec![7u8; 100_000], &PutOptions::default()).await.unwrap();

    let api = serve(Arc::new(Client::new(&url, "alice.near", sk.clone(), Some(RootKey::from_bytes(root)))), u("near://alice.near/Drive/"), tmp.path().join("ptmp")).await.unwrap();
    let ep = api.endpoint.clone();
    let http = reqwest::Client::new();
    let req = |m: reqwest::Method, path: &str| http.request(m, format!("{}{path}", ep.url)).bearer_auth(&ep.token);

    // Auth.
    assert_eq!(http.get(format!("{}/v1/all", ep.url)).send().await.unwrap().status(), StatusCode::UNAUTHORIZED);
    assert_eq!(http.get(format!("{}/v1/all", ep.url)).bearer_auth("nope").send().await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // Enumeration.
    let all: Changes = req(reqwest::Method::GET, "/v1/all").send().await.unwrap().json().await.unwrap();
    let ids: Vec<&str> = all.updated.iter().map(|i| i.id.as_str()).collect();
    assert_eq!(ids, vec!["b.bin", "docs/", "docs/a.txt"]);
    let root_items: Vec<Item> = req(reqwest::Method::GET, "/v1/items?parent=").send().await.unwrap().json().await.unwrap();
    assert_eq!(root_items.iter().map(|i| (i.id.as_str(), i.is_dir)).collect::<Vec<_>>(), vec![("b.bin", false), ("docs/", true)]);
    let a: Item = req(reqwest::Method::GET, "/v1/item?id=docs/a.txt").send().await.unwrap().json().await.unwrap();
    assert_eq!((a.size, a.seq, a.parent.as_str(), a.name.as_str()), (5, 1, "docs/", "a.txt"));
    assert_eq!(req(reqwest::Method::GET, "/v1/item?id=nope").send().await.unwrap().status(), StatusCode::NOT_FOUND);

    // Contents (decrypted), with the item in a header.
    let r = req(reqwest::Method::GET, "/v1/content?id=b.bin").send().await.unwrap();
    let hdr: Item = serde_json::from_str(r.headers()["x-near-drive-item"].to_str().unwrap()).unwrap();
    assert_eq!(hdr.size, 100_000);
    assert_eq!(r.bytes().await.unwrap().to_vec(), vec![7u8; 100_000]);

    // Create, modify (conditional), conflict.
    let n: Item = req(reqwest::Method::PUT, "/v1/content?id=new/x.txt&base_seq=0").body("made on a mac").send().await.unwrap().json().await.unwrap();
    assert_eq!((n.seq, n.size), (1, 13));
    assert_eq!(c.get(&u("near://alice.near/Drive/new/x.txt")).await.unwrap().1, b"made on a mac");
    let m: Item = req(reqwest::Method::PUT, "/v1/content?id=docs/a.txt&base_seq=1").body("edited").send().await.unwrap().json().await.unwrap();
    assert_eq!(m.seq, 2);
    let r = req(reqwest::Method::PUT, "/v1/content?id=docs/a.txt&base_seq=1").body("stale edit").send().await.unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(r.json::<serde_json::Value>().await.unwrap()["current"], 2);

    // Changes since the first anchor.
    let ch: Changes = req(reqwest::Method::GET, &format!("/v1/changes?anchor={}", all.anchor)).send().await.unwrap().json().await.unwrap();
    let up: Vec<&str> = ch.updated.iter().map(|i| i.id.as_str()).collect();
    assert_eq!(up, vec!["docs/a.txt", "new/", "new/x.txt"]);
    assert!(ch.deleted.is_empty());
    assert_eq!(req(reqwest::Method::GET, "/v1/changes?anchor=999999").send().await.unwrap().status(), StatusCode::GONE);

    // Folders, rename, delete.
    let f: Item = req(reqwest::Method::POST, "/v1/folder?id=empty/").send().await.unwrap().json().await.unwrap();
    assert!(f.is_dir);
    req(reqwest::Method::POST, "/v1/rename?from=new/&to=moved/").send().await.unwrap().error_for_status().unwrap();
    assert!(c.head(&u("near://alice.near/Drive/new/x.txt")).await.unwrap().is_none());
    assert_eq!(c.get(&u("near://alice.near/Drive/moved/x.txt")).await.unwrap().1, b"made on a mac");
    let r: Item = req(reqwest::Method::POST, "/v1/rename?from=b.bin&to=docs/b2.bin").send().await.unwrap().json().await.unwrap();
    assert_eq!(r.parent, "docs/");
    assert_eq!(req(reqwest::Method::DELETE, "/v1/item?id=docs/a.txt&seq=1").send().await.unwrap().status(), StatusCode::CONFLICT);
    assert_eq!(req(reqwest::Method::DELETE, "/v1/item?id=docs/a.txt&seq=2").send().await.unwrap().status(), StatusCode::NO_CONTENT);
    req(reqwest::Method::DELETE, "/v1/item?id=moved/").send().await.unwrap().error_for_status().unwrap();
    let ch2: Changes = req(reqwest::Method::GET, &format!("/v1/changes?anchor={}", ch.anchor)).send().await.unwrap().json().await.unwrap();
    let mut gone = ch2.deleted.clone();
    gone.sort();
    // new/ was renamed to moved/ and then deleted: from that anchor's view, new/ is gone.
    assert_eq!(gone, vec!["b.bin", "docs/a.txt", "new/", "new/x.txt"]);
    let all2: Changes = req(reqwest::Method::GET, "/v1/all").send().await.unwrap().json().await.unwrap();
    assert_eq!(all2.updated.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), vec!["docs/", "docs/b2.bin", "empty/"]);

    // Watch: returns when the remote changes.
    let (http2, ep2) = (http.clone(), ep.clone());
    let w = tokio::spawn(async move {
        http2.get(format!("{}/v1/watch?timeout_ms=10000", ep2.url)).bearer_auth(&ep2.token).send().await.unwrap().json::<serde_json::Value>().await.unwrap()
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    c.put(&u("near://alice.near/Drive/ping.txt"), b"x", &PutOptions::default()).await.unwrap();
    let t0 = std::time::Instant::now();
    let v = w.await.unwrap();
    assert_eq!(v["changed"], true);
    assert!(t0.elapsed() < std::time::Duration::from_secs(5));
}
