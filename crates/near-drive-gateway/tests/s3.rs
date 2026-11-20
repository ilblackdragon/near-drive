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
    store::{list_all, CasError, IndexEntry, IndexStore},
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
    let rec = |p: &str, seq| IndexEntry { record: PointerRecord::new_signed("alice.near", p, &near_drive_client::near_drive_core::cid(b"m"), 1, 2, seq, "alice.near", &sk, 1), class: None };
    idx.cas_put(&rec("m/a", 1)).await.unwrap();
    assert!(matches!(idx.cas_put(&rec("m/a", 1)).await, Err(CasError::Conflict { current: 1 })));
    idx.cas_put(&rec("m/a", 2)).await.unwrap();
    for p in ["m/a b", "m/a%2F", "m/ü/[x]#?*", "m/ab", "n/a"] {
        idx.cas_put(&rec(p, 1)).await.unwrap();
        assert_eq!(idx.get("alice.near", p).await.unwrap().unwrap().path, p);
    }
    let ls: Vec<_> = list_all(&idx, "alice.near", "m/a").await.unwrap().into_iter().map(|r| r.record.path).collect();
    assert_eq!(ls, vec!["m/a", "m/a b", "m/a%2F", "m/ab"]);
    assert_eq!(list_all(&idx, "alice.near", "").await.unwrap().len(), 6);
    assert_eq!(list_all(&idx, "alice.near", "m/ü/").await.unwrap().len(), 1);
    idx.delete("alice.near", "m/a", 2).await.unwrap();
    assert!(idx.get("alice.near", "m/a").await.unwrap().is_none());
    assert_eq!(list_all(&idx, "alice.near", "m/a").await.unwrap().len(), 3);
    idx.cas_put(&rec("m/a", 1)).await.unwrap();

    // native pages: prefix / delimiter / start-after / max-keys; tombstones skipped
    for i in 0..30 {
        idx.cas_put(&rec(&format!("p/d{}/f{i:02}", i % 3), 1)).await.unwrap();
    }
    for i in [0, 4, 8] {
        idx.delete("alice.near", &format!("p/d{}/f{i:02}", i % 3), 1).await.unwrap();
    }
    let (mut cursor, mut seen, mut pages) = (None::<String>, vec![], 0);
    loop {
        let pg = idx.list_page("alice.near", "p/", None, cursor.as_deref(), 7).await.unwrap();
        pages += 1;
        seen.extend(pg.entries.into_iter().map(|e| e.record.path));
        match pg.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    assert_eq!((seen.len(), pages), (27, 5));
    assert!(seen.windows(2).all(|w| w[0] < w[1]), "sorted by path");
    let pg = idx.list_page("alice.near", "p/", Some("/"), None, 2).await.unwrap();
    assert_eq!(pg.common_prefixes, vec!["p/d0/", "p/d1/"]);
    let pg = idx.list_page("alice.near", "p/", Some("/"), pg.next_cursor.as_deref(), 2).await.unwrap();
    assert_eq!((pg.common_prefixes, pg.next_cursor), (vec!["p/d2/".to_string()], None));
    let pg = idx.list_page("alice.near", "", Some("/"), None, 1000).await.unwrap();
    assert_eq!(pg.common_prefixes, vec!["m/", "n/", "p/"]);

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
        "cache": {"max_bytes": 32 << 20},
        // off: its write-through would serve small chunks from memory, and
        // this test checks the disk cache
        "small_cache": {"max_bytes": 0}
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

    // Egress is metered once per locate (all URL chunks, up front); chunks
    // served through the gateway would add an event each.
    let egress = || -> Vec<u64> {
        std::fs::read_to_string(gw.data_dir.join("usage.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|e| e["kind"] == "egress")
            .map(|e| e["bytes"].as_u64().unwrap())
            .collect()
    };
    let located: u64 = loc.chunks.iter().map(|c| c.len).sum();
    assert_eq!(egress(), vec![located], "locate meters the direct chunks");
    alice.get_to_file(&uri, dir.path().join("out")).await.unwrap();
    assert_eq!(hash_file(&dir.path().join("out")), h);
    assert_eq!(egress(), vec![located, located], "only the download's locate: chunks came from S3 directly");
    let data = std::fs::read(&src).unwrap();
    assert_eq!(alice.get_range(&uri, 1_000_000..3_500_000).await.unwrap(), data[1_000_000..3_500_000]);

    // gateway path (one-shot get) fills the read-through cache
    assert_eq!(alice.get(&uri).await.unwrap().1, data);
    for c in &loc.chunks {
        let f = gw.data_dir.join("cache").join(c.cid.strip_prefix("b3:").unwrap());
        assert!(f.is_file(), "{} not in the disk cache", c.cid);
    }
}

#[tokio::test]
async fn gc_on_real_s3() {
    use near_drive_gateway::{
        gc::{self, GcOptions},
        s3::S3BlobStore,
        store::BlobStore,
    };
    let base = s3_or_skip!();
    let run = run_id();
    let dir = tempfile::tempdir().unwrap();
    let (keys, dev) = dev_keys(&["alice.near"]);
    let chunks_cfg = s3_with_prefix(&base, &format!("{run}/chunks/"));
    let storage = json!({"backends": {"s3": chunks_cfg}, "index": s3_with_prefix(&base, &format!("{run}/index/"))});
    let cfg = gateway_config(dir.path().join("gw"), dev, storage);
    let gw = start_gateway_with(cfg.clone()).await;
    let mut alice = client(&gw.url, "alice.near", &keys["alice.near"], Some(RootKey::generate()));
    alice.chunk_size = 4096;
    let opts = PutOptions::default();
    alice.put(&u("near://alice.near/a"), &pattern(1, 0, 9000), &opts).await.unwrap();
    alice.put(&u("near://alice.near/b"), &pattern(2, 0, 9000), &opts).await.unwrap();
    let b1 = alice.head(&u("near://alice.near/b")).await.unwrap().unwrap();
    alice.put(&u("near://alice.near/b"), &pattern(3, 0, 9000), &opts).await.unwrap();
    alice.put(&u("near://alice.near/c"), &pattern(4, 0, 9000), &opts).await.unwrap();
    let c1 = alice.head(&u("near://alice.near/c")).await.unwrap().unwrap();
    alice.delete(&u("near://alice.near/c")).await.unwrap(); // tombstone in the S3 index
    let blobs = S3BlobStore::new(&serde_json::from_value(chunks_cfg).unwrap()).unwrap();

    let gc_opts = |grace, dry_run| GcOptions { grace, dry_run, ..Default::default() };
    let r = gc::run_config(&cfg, &gc_opts(std::time::Duration::from_secs(3600), false)).await.unwrap();
    assert_eq!((r.live_entries, r.backends[0].chunks, r.garbage), (2, 16, 0));
    let r = gc::run_config(&cfg, &gc_opts(std::time::Duration::ZERO, true)).await.unwrap();
    assert_eq!((r.garbage, r.deleted), (8, 0));
    let r = gc::run_config(&cfg, &gc_opts(std::time::Duration::ZERO, false)).await.unwrap();
    assert_eq!(r.deleted, 8);
    for h in [&b1, &c1] {
        assert!(!blobs.has(&h.record.manifest_cid).await.unwrap());
        for c in &h.manifest.chunks {
            assert!(!blobs.has(&c.cid).await.unwrap());
        }
    }
    assert_eq!(alice.get(&u("near://alice.near/a")).await.unwrap().1, pattern(1, 0, 9000));
    assert_eq!(alice.get(&u("near://alice.near/b")).await.unwrap().1, pattern(3, 0, 9000));
}
