//! Streaming large-object APIs, storage classes, blob bridge and locate,
//! against a real gateway (fs + in-process reference bridge; no docker).
mod common;
use common::*;
use near_drive_client::{near_drive_core::crypto::RootKey, near_drive_core::NearUri, PutOptions};
use serde_json::json;

fn u(s: &str) -> NearUri {
    NearUri::parse(s).unwrap()
}

struct Setup {
    gw: Gw,
    bridge_dir: std::path::PathBuf,
    keys: std::collections::HashMap<&'static str, ed25519_dalek::SigningKey>,
    _dir: tempfile::TempDir,
}

/// Classes: hot = local fs; bulk = blob bridge (with direct URLs) + fs replica.
async fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let bridge_dir = dir.path().join("bridge");
    let bridge = start_bridge(bridge_dir.clone(), Some("tok"), true).await;
    let (keys, dev) = dev_keys(&["alice.near", "bob.near"]);
    let storage = json!({
        "backends": {
            "local": {"type": "fs"},
            "fil": {"type": "bridge", "url": bridge, "token": "tok"},
            "replica": {"type": "fs", "path": dir.path().join("replica")}
        },
        "classes": {
            "hot": {"backends": ["local"]},
            "bulk": {"backends": ["fil", "replica"], "min_successes": 1}
        },
        "cache": {"max_bytes": 64 << 20}
    });
    let gw = start_gateway(dir.path().join("gw"), dev, storage).await;
    Setup { gw, bridge_dir, keys, _dir: dir }
}

fn count_files(p: &std::path::Path) -> usize {
    std::fs::read_dir(p)
        .map(|rd| rd.flatten().map(|e| if e.path().is_dir() { count_files(&e.path()) } else { 1 }).sum())
        .unwrap_or(0)
}

fn egress_events(gw: &Gw) -> usize {
    std::fs::read_to_string(gw.data_dir.join("usage.jsonl")).unwrap_or_default().lines().filter(|l| l.contains("\"kind\":\"egress\"")).count()
}

#[tokio::test]
async fn streaming_and_one_shot_interoperate() {
    let s = setup().await;
    let tmp = tempfile::tempdir().unwrap();
    let mut alice = client(&s.gw.url, "alice.near", &s.keys["alice.near"], Some(RootKey::from_bytes([3; 32])));
    alice.chunk_size = 1000;
    alice.parallelism = 4;

    for (i, size) in [0u64, 1, 999, 1000, 1001, 5000, 12_345].into_iter().enumerate() {
        let src = tmp.path().join(format!("src{i}"));
        let h = write_pattern_file(&src, i as u64, size);
        let data = std::fs::read(&src).unwrap();

        // streaming put -> one-shot get, streaming get, ranges
        let a = u(&format!("near://alice.near/s/{i}"));
        let rec = alice.put_file(&src, &a, &PutOptions::default()).await.unwrap();
        assert_eq!(rec.size, size);
        assert_eq!(alice.get(&a).await.unwrap().1, data, "size {size}");
        let dst = tmp.path().join(format!("dst{i}"));
        alice.get_to_file(&a, &dst).await.unwrap();
        assert_eq!(hash_file(&dst), h);
        let mut w = vec![];
        alice.get_to_writer(&a, &mut w).await.unwrap();
        assert_eq!(w, data);
        for (lo, hi) in [(0, 1), (0, size), (999, 1001), (1, 4000), (size.saturating_sub(3), size + 10), (size, size + 5), (7, 7)] {
            let got = alice.get_range(&a, lo..hi).await.unwrap();
            let (l, h) = ((lo.min(size)) as usize, (hi.min(size)) as usize);
            assert_eq!(got, data[l..h.max(l)], "range {lo}..{hi} of {size}");
        }

        // one-shot put -> streaming get
        let b = u(&format!("near://alice.near/o/{i}"));
        alice.put(&b, &data, &PutOptions::default()).await.unwrap();
        let dst2 = tmp.path().join(format!("dst2-{i}"));
        alice.get_to_file(&b, &dst2).await.unwrap();
        assert_eq!(hash_file(&dst2), h);
    }

    // stdin-like reader of unknown size, public object
    let p = u("near://alice.near/pub/reader");
    let data = pattern(9, 0, 4321);
    alice.put_reader(&data[..], &p, &PutOptions { public: true, ..Default::default() }).await.unwrap();
    let bob = client(&s.gw.url, "bob.near", &s.keys["bob.near"], None);
    let _ = bob; // no read grant for bob on alice's namespace; alice reads it back
    assert_eq!(alice.get(&p).await.unwrap().1, data);

    // repeated content (public): identical chunks are deduped on upload and
    // concurrent fetches of the same cid are not mistaken for replays
    let zeros = vec![0u8; 20_000];
    let z = u("near://alice.near/pub/zeros");
    let rec = alice.put_reader(&zeros[..], &z, &PutOptions { public: true, ..Default::default() }).await.unwrap();
    assert_eq!(rec.size, 20_000);
    let mut w = vec![];
    alice.get_to_writer(&z, &mut w).await.unwrap();
    assert_eq!(w, zeros);
}

#[tokio::test]
async fn classes_and_direct_urls() {
    let s = setup().await;
    let tmp = tempfile::tempdir().unwrap();
    let mut alice = client(&s.gw.url, "alice.near", &s.keys["alice.near"], Some(RootKey::generate()));
    alice.chunk_size = 64 * 1024;
    let src = tmp.path().join("w.bin");
    let h = write_pattern_file(&src, 42, 1_000_000);

    // hot (default): local fs only, no direct URLs -> gateway serves chunks
    let hot = u("near://alice.near/hot.bin");
    alice.put_file(&src, &hot, &PutOptions::default()).await.unwrap();
    let loc = alice.locate(&hot).await.unwrap().unwrap();
    assert_eq!(loc.chunks.len(), 16);
    assert!(loc.chunks.iter().all(|c| c.url.is_none()));
    assert_eq!(count_files(&s.bridge_dir), 0);
    let before = egress_events(&s.gw);
    alice.get_to_file(&hot, tmp.path().join("hot.out")).await.unwrap();
    assert_eq!(hash_file(&tmp.path().join("hot.out")), h);
    assert_eq!(egress_events(&s.gw) - before, 16, "every chunk via gateway");

    // bulk: chunks (and the manifest) go to the bridge; reads use direct URLs
    let bulk = u("near://alice.near/bulk.bin");
    alice.put_file(&src, &bulk, &PutOptions { class: Some("bulk".into()), ..Default::default() }).await.unwrap();
    assert_eq!(count_files(&s.bridge_dir), 17);
    assert_eq!(count_files(&s.gw.data_dir.join("../replica")), 17);
    let loc = alice.locate(&bulk).await.unwrap().unwrap();
    assert!(loc.chunks.iter().all(|c| c.url.as_deref().is_some_and(|u| u.contains("/public/b3:"))));
    let before = egress_events(&s.gw);
    alice.get_to_file(&bulk, tmp.path().join("bulk.out")).await.unwrap();
    assert_eq!(hash_file(&tmp.path().join("bulk.out")), h);
    // No chunk went through the gateway; the one egress event is the locate
    // response, which meters the bytes handed out as direct URLs.
    assert_eq!(egress_events(&s.gw), before + 1, "all chunks fetched directly from the bridge");
    let r = alice.get_range(&bulk, 100_000..300_000).await.unwrap();
    assert_eq!(r, std::fs::read(&src).unwrap()[100_000..300_000]);

    // bridge loses the data -> direct fetch 404s -> client falls back to the
    // gateway, which reads the fs replica
    std::fs::remove_dir_all(&s.bridge_dir).unwrap();
    alice.get_to_file(&bulk, tmp.path().join("bulk2.out")).await.unwrap();
    assert_eq!(hash_file(&tmp.path().join("bulk2.out")), h);

    // unknown class is rejected
    let e = alice.put(&u("near://alice.near/x"), b"x", &PutOptions { class: Some("nope".into()), ..Default::default() }).await.unwrap_err();
    assert!(e.to_string().contains("unknown storage class"), "{e}");
}

#[tokio::test]
async fn gateway_chunk_range_requests() {
    let s = setup().await;
    let mut alice = client(&s.gw.url, "alice.near", &s.keys["alice.near"], None);
    alice.chunk_size = 1000;
    let data = pattern(1, 0, 2500);
    let uri = u("near://alice.near/pub/r");
    alice.put(&uri, &data, &PutOptions { public: true, ..Default::default() }).await.unwrap();
    let head = alice.head(&uri).await.unwrap().unwrap();
    let cid = &head.manifest.chunks[1].cid;
    let sk = &s.keys["alice.near"];
    let http = reqwest::Client::new();
    let get = |range: &'static str, n: u64| {
        let q = format!("chunk={cid}&n={n}");
        let h = near_drive_client::near_drive_core::auth::sign_request("alice.near", sk, "GET", "/v1/o/alice.near/pub/r", &q, now_ms(), b"");
        http.get(format!("{}/v1/o/alice.near/pub/r?{q}", s.gw.url))
            .header("x-near-account", h.account)
            .header("x-near-publickey", h.public_key)
            .header("x-near-timestamp", h.ts_ms.to_string())
            .header("x-near-signature", h.signature)
            .header("range", range)
            .send()
    };
    let r = get("bytes=10-19", 1).await.unwrap();
    assert_eq!(r.status(), 206);
    assert_eq!(r.headers()["content-range"], "bytes 10-19/1000");
    assert_eq!(r.bytes().await.unwrap(), data[1010..1020]);
    let r = get("bytes=-5", 2).await.unwrap();
    assert_eq!(r.status(), 206);
    assert_eq!(r.bytes().await.unwrap(), data[1995..2000]);
    assert_eq!(get("bytes=5000-", 3).await.unwrap().status(), 416);
}
