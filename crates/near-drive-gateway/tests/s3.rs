//! Integration tests against a real S3-compatible store (MinIO). Skipped
//! unless NEAR_DRIVE_TEST_S3_ENDPOINT is set; see `common::s3_env`.
//!
//! ```sh
//! docker run -d --name drive-minio -p 127.0.0.1:19000:9000 \
//!   -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
//!   -e MINIO_DEFAULT_BUCKETS=near-drive-test bitnamilegacy/minio:latest
//! NEAR_DRIVE_TEST_S3_ENDPOINT=http://127.0.0.1:19000 cargo test -p near-drive-gateway --test s3
//! ```
mod common;
use common::*;
use ed25519_dalek::SigningKey;
use near_drive_client::{
    near_drive_core::{auth, crypto::RootKey, record::PointerRecord, NearUri},
    PutOptions,
};
use near_drive_gateway::{
    s3::{ObjectIndexStore, S3Config},
    store::{CasError, IndexStore},
};
use serde_json::json;

macro_rules! s3_or_skip {
    () => {
        match s3_env() {
            Some(v) => v,
            None => {
                eprintln!("skipping: NEAR_DRIVE_TEST_S3_ENDPOINT not set");
                return;
            }
        }
    };
}

fn u(s: &str) -> NearUri {
    NearUri::parse(s).unwrap()
}

async fn put_record(http: &reqwest::Client, gw: &str, sk: &SigningKey, rec: &PointerRecord) -> u16 {
    let body = serde_json::to_vec(rec).unwrap();
    let path = format!("/v1/o/{}/{}", rec.namespace, rec.path);
    let h = auth::sign_request(&rec.writer, sk, "PUT", &path, "", now_ms(), &body);
    http.put(format!("{gw}{path}"))
        .header(auth::H_ACCOUNT, h.account)
        .header(auth::H_PUBKEY, h.public_key)
        .header(auth::H_TS, h.ts_ms.to_string())
        .header(auth::H_SIG, h.signature)
        .body(body)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn s3_index_store_cas_on_real_s3() {
    let base = s3_or_skip!();
    let cfg: S3Config = serde_json::from_value(s3_with_prefix(&base, &format!("{}/index/", run_id()))).unwrap();
    let idx = ObjectIndexStore::new(&cfg).unwrap();
    let sk = SigningKey::from_bytes(&[5; 32]);
    let rec = |p: &str, seq| PointerRecord::new_signed("alice.near", p, &near_drive_client::near_drive_core::cid(b"m"), 1, 2, seq, "alice.near", &sk, 1);
    idx.cas_put(&rec("m/a", 1)).await.unwrap();
    assert!(matches!(idx.cas_put(&rec("m/a", 1)).await, Err(CasError::Conflict { current: 1 })));
    idx.cas_put(&rec("m/a", 2)).await.unwrap();
    for p in ["m/a b", "m/a%2F", "m/ü/[x]#?*", "m/ab", "n/a"] {
        idx.cas_put(&rec(p, 1)).await.unwrap();
        assert_eq!(idx.get("alice.near", p).await.unwrap().unwrap().path, p);
    }
    let ls: Vec<_> = idx.list("alice.near", "m/a").await.unwrap().into_iter().map(|r| r.path).collect();
    assert_eq!(ls, vec!["m/a", "m/a b", "m/a%2F", "m/ab"]);
    assert_eq!(idx.list("alice.near", "").await.unwrap().len(), 6);
    assert_eq!(idx.list("alice.near", "m/ü/").await.unwrap().len(), 1);
    idx.delete("alice.near", "m/a", 2).await.unwrap();
    assert!(idx.get("alice.near", "m/a").await.unwrap().is_none());
    assert_eq!(idx.list("alice.near", "m/a").await.unwrap().len(), 3);
    idx.cas_put(&rec("m/a", 1)).await.unwrap();

    // raw concurrent CAS on one key: exactly one winner per seq
    for seq in 2..=6 {
        let (r1, r2) = (rec("m/a", seq), rec("m/a", seq));
        let (a, b) = tokio::join!(idx.cas_put(&r1), idx.cas_put(&r2));
        assert!(a.is_ok() != b.is_ok(), "seq {seq}: exactly one CAS must win ({a:?} / {b:?})");
    }
}

#[tokio::test]
async fn two_gateways_share_s3_index() {
    let base = s3_or_skip!();
    let run = run_id();
    let dir = tempfile::tempdir().unwrap();
    let (keys, dev) = dev_keys(&["alice.near", "bob.near"]);
    let storage = json!({
        "backends": {"s3": s3_with_prefix(&base, &format!("{run}/chunks/"))},
        "index": s3_with_prefix(&base, &format!("{run}/index/")),
    });
    let g1 = start_gateway(dir.path().join("g1"), dev.clone(), storage.clone()).await;
    let g2 = start_gateway(dir.path().join("g2"), dev, storage).await;
    let sk = &keys["alice.near"];
    let a1 = client(&g1.url, "alice.near", sk, Some(RootKey::from_bytes([1; 32])));
    let a2 = client(&g2.url, "alice.near", sk, Some(RootKey::from_bytes([1; 32])));

    // written through one gateway, visible through the other
    let uri = u("near://alice.near/shared/doc.txt");
    a1.put(&uri, b"v1", &PutOptions::default()).await.unwrap();
    assert_eq!(a2.get(&uri).await.unwrap().1, b"v1");
    assert_eq!(a2.list(&u("near://alice.near/shared/")).await.unwrap().len(), 1);

    // concurrent writers of the same seq through different gateways:
    // exactly one 201, the other 409; the loser's retry at seq+1 wins.
    let http = reqwest::Client::new();
    let head = a1.head(&uri).await.unwrap().unwrap();
    let mut seq = head.record.seq;
    for round in 0..10 {
        let mk = |ts: u64| PointerRecord::new_signed("alice.near", &uri.path, &head.record.manifest_cid, head.record.size, head.record.stored_size, seq + 1, "alice.near", sk, ts);
        let (r1, r2) = (mk(now_ms()), mk(now_ms() + 1));
        let (s1, s2) = tokio::join!(put_record(&http, &g1.url, sk, &r1), put_record(&http, &g2.url, sk, &r2));
        let mut st = [s1, s2];
        st.sort();
        assert_eq!(st, [201, 409], "round {round}: statuses {s1} {s2}");
        seq += 1;
        let retry = PointerRecord::new_signed("alice.near", &uri.path, &head.record.manifest_cid, head.record.size, head.record.stored_size, seq + 1, "alice.near", sk, now_ms());
        let loser = if s1 == 409 { &g1.url } else { &g2.url };
        assert_eq!(put_record(&http, loser, sk, &retry).await, 201, "round {round}: retry");
        seq += 1;
    }
    assert_eq!(a2.head(&uri).await.unwrap().unwrap().record.seq, seq);

    // SDK-level: two concurrent puts via different gateways both land (one retries)
    let opts = PutOptions::default();
    let (p1, p2) = tokio::join!(a1.put(&uri, b"from g1", &opts), a2.put(&uri, b"from g2", &opts));
    let (p1, p2) = (p1.unwrap(), p2.unwrap());
    let mut seqs = [p1.seq, p2.seq];
    seqs.sort();
    assert_eq!(seqs, [seq + 1, seq + 2]);
    let winner: &[u8] = if p1.seq > p2.seq { b"from g1" } else { b"from g2" };
    assert_eq!(a1.get(&uri).await.unwrap().1, winner);

    // delete through g2, gone through g1, recreate starts at seq 1
    a2.delete(&uri).await.unwrap();
    assert!(a1.head(&uri).await.unwrap().is_none());
    assert!(a1.list(&u("near://alice.near/shared/")).await.unwrap().is_empty());
    assert_eq!(a1.put(&uri, b"again", &PutOptions::default()).await.unwrap().seq, 1);
    assert_eq!(a2.get(&uri).await.unwrap().1, b"again");
}

#[tokio::test]
async fn s3_blobs_presigned_locate_and_cache() {
    let base = s3_or_skip!();
    let run = run_id();
    let dir = tempfile::tempdir().unwrap();
    let (keys, dev) = dev_keys(&["alice.near"]);
    let storage = json!({
        "backends": {"s3": s3_with_prefix(&base, &format!("{run}/chunks/"))},
        "index": s3_with_prefix(&base, &format!("{run}/index/")),
        "cache": {"max_bytes": 32 << 20}
    });
    let gw = start_gateway(dir.path().join("gw"), dev, storage).await;
    let mut alice = client(&gw.url, "alice.near", &keys["alice.near"], Some(RootKey::generate()));
    alice.chunk_size = 1 << 20;
    let src = dir.path().join("w.bin");
    let h = write_pattern_file(&src, 7, 8 * (1 << 20) + 12345);
    let uri = u("near://alice.near/weights/w.bin");
    alice.put_file(&src, &uri, &PutOptions::default()).await.unwrap();

    let loc = alice.locate(&uri).await.unwrap().unwrap();
    assert_eq!(loc.chunks.len(), 9);
    for c in &loc.chunks {
        let url = c.url.as_deref().expect("presigned url");
        assert!(url.starts_with("http://127.0.0.1") && url.contains("X-Amz-Signature"), "{url}");
        assert!(c.expires_ms.unwrap() > now_ms());
    }
    // presigned URL works without NEAR Drive auth and returns the exact chunk
    let b = reqwest::get(loc.chunks[3].url.as_deref().unwrap()).await.unwrap().bytes().await.unwrap();
    assert_eq!(near_drive_client::near_drive_core::cid(&b), loc.chunks[3].cid);

    let usage = || std::fs::read_to_string(gw.data_dir.join("usage.jsonl")).unwrap().lines().filter(|l| l.contains("egress")).count();
    let before = usage();
    alice.get_to_file(&uri, dir.path().join("out")).await.unwrap();
    assert_eq!(hash_file(&dir.path().join("out")), h);
    assert_eq!(usage(), before, "chunks came from S3 directly");
    let data = std::fs::read(&src).unwrap();
    assert_eq!(alice.get_range(&uri, 1_000_000..3_500_000).await.unwrap(), data[1_000_000..3_500_000]);

    // gateway path (one-shot get) fills the read-through cache
    assert_eq!(alice.get(&uri).await.unwrap().1, data);
    let cached = std::fs::read_dir(gw.data_dir.join("cache")).unwrap().count();
    assert!(cached >= 9, "cache has {cached} entries");
}
