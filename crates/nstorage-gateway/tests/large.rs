//! Large-object streaming with bounded memory. A single test in its own
//! binary so peak-RSS measurement is not disturbed by other tests.
//!
//! Size: NSTORAGE_TEST_LARGE_MB (default 24). Backend: S3/MinIO if
//! NSTORAGE_TEST_S3_ENDPOINT is set, else local fs. E.g.
//! `NSTORAGE_TEST_LARGE_MB=200 NSTORAGE_TEST_S3_ENDPOINT=http://127.0.0.1:19000 cargo test --release -p nstorage-gateway --test large -- --nocapture`
mod common;
use common::*;
use nstorage_client::{nstorage_core::crypto::RootKey, nstorage_core::NearUri, PutOptions};
use serde_json::json;
use std::io::{Read, Seek, SeekFrom};

const MIB: u64 = 1 << 20;

fn read_at(path: &std::path::Path, off: u64, len: u64) -> Vec<u8> {
    let mut f = std::fs::File::open(path).unwrap();
    f.seek(SeekFrom::Start(off)).unwrap();
    let mut b = vec![0u8; len as usize];
    f.read_exact(&mut b).unwrap();
    b
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_object_bounded_memory_and_ranges() {
    let mb: u64 = std::env::var("NSTORAGE_TEST_LARGE_MB").ok().and_then(|v| v.parse().ok()).unwrap_or(24);
    let size = mb * MIB + 4321; // not a chunk multiple
    let dir = tempfile::tempdir().unwrap();
    let (keys, dev) = dev_keys(&["alice.near"]);
    let storage = match s3_env() {
        Some(base) => {
            let run = run_id();
            json!({
                "backends": {"s3": s3_with_prefix(&base, &format!("{run}/chunks/"))},
                "index": s3_with_prefix(&base, &format!("{run}/index/")),
            })
        }
        None => json!({}),
    };
    let backend = if s3_env().is_some() { "s3" } else { "fs" };
    let gw = start_gateway(dir.path().join("gw"), dev, storage).await;
    let mut alice = client(&gw.url, "alice.near", &keys["alice.near"], Some(RootKey::generate()));
    alice.chunk_size = MIB as usize;
    alice.parallelism = 4;

    let src = dir.path().join("weights.bin");
    let h = write_pattern_file(&src, 0xfeed, size);
    let uri = NearUri::parse("near://alice.near/models/weights.bin").unwrap();

    reset_peak_rss();
    let base_rss = peak_rss();
    let t = std::time::Instant::now();
    let rec = alice.put_file(&src, &uri, &PutOptions::default()).await.unwrap();
    let up = t.elapsed();
    assert_eq!(rec.size, size);
    let t = std::time::Instant::now();
    let out = dir.path().join("out.bin");
    alice.get_to_file(&uri, &out).await.unwrap();
    let down = t.elapsed();
    let peak = peak_rss();
    assert_eq!(hash_file(&out), h, "downloaded content differs");

    if let (Some(b), Some(p)) = (base_rss, peak) {
        let delta = p.saturating_sub(b);
        eprintln!(
            "[{backend}] {mb} MiB: upload {:.1}s, download {:.1}s, peak RSS {} MiB (+{} MiB over baseline)",
            up.as_secs_f64(),
            down.as_secs_f64(),
            p / MIB,
            delta / MIB
        );
        // client + in-process gateway, 1 MiB chunks, 4-way parallel
        assert!(delta < 128 * MIB, "peak RSS grew by {} MiB for a {mb} MiB object", delta / MIB);
    }

    // byte-range reads: chunk-aligned, straddling, tail, single byte
    let ranges = [(0, 10), (MIB - 3, MIB + 3), (5 * MIB, 7 * MIB + 17), (size - 100, size + 100), (size / 2, size / 2 + 1), (123_457, 123_457 + 3 * MIB)];
    for (a, b) in ranges {
        let got = alice.get_range(&uri, a..b).await.unwrap();
        let end = b.min(size);
        assert_eq!(got.len() as u64, end - a, "range {a}..{b}");
        assert!(got == read_at(&src, a, end - a), "range {a}..{b} content");
    }
}
