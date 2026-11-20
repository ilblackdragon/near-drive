//! Chunk garbage collection: mark live chunks from the index, sweep the rest
//! from listable backends after a grace period.
mod common;
use common::*;
use near_drive_client::{
    near_drive_core::{crypto::RootKey, NearUri},
    Client, ObjectHead, PutOptions,
};
use near_drive_gateway::{
    gc::{self, GcConfig, GcOptions},
    store::{BlobStore, FsBlobStore},
    Config,
};
use serde_json::json;
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, SystemTime},
};

fn u(s: &str) -> NearUri {
    NearUri::parse(s).unwrap()
}

/// Manifest cid + data chunk cids of a version.
fn cids(h: &ObjectHead) -> BTreeSet<String> {
    let mut s: BTreeSet<String> = h.manifest.chunks.iter().map(|c| c.cid.clone()).collect();
    s.insert(h.record.manifest_cid.clone());
    s
}

async fn head(c: &Client, uri: &str) -> ObjectHead {
    c.head(&u(uri)).await.unwrap().unwrap()
}

/// Every chunk file under an fs backend dir.
fn files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = vec![];
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            if e.file_type().unwrap().is_dir() {
                stack.push(e.path());
            } else {
                out.push(e.path());
            }
        }
    }
    out
}

/// Pretend every chunk on these backends was written two hours ago.
fn age_all(dirs: &[&Path]) {
    let old = SystemTime::now() - Duration::from_secs(7200);
    for d in dirs {
        for f in files(d) {
            std::fs::File::options().write(true).open(&f).unwrap().set_modified(old).unwrap();
        }
    }
}

async fn on(dir: &Path, cid: &str) -> bool {
    FsBlobStore::new(dir.to_path_buf()).has(cid).await.unwrap()
}

fn opts(grace: Duration, dry_run: bool) -> GcOptions {
    GcOptions { grace, dry_run, ..Default::default() }
}

#[tokio::test]
async fn gc_sweeps_unreferenced_chunks_and_keeps_live_ones() {
    let dir = tempfile::tempdir().unwrap();
    let bridge_dir = dir.path().join("bridge");
    let bridge = start_bridge(bridge_dir.clone(), None, false).await;
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let storage = json!({
        "backends": {
            "a": {"type": "fs", "path": a},
            "b": {"type": "fs", "path": b},
            "br": {"type": "bridge", "url": bridge}
        },
        "classes": {"hot": {"backends": ["a", "b"]}, "bulk": {"backends": ["br"]}}
    });
    let (keys, dev) = dev_keys(&["alice.near", "bob.near"]);
    let cfg: Config = gateway_config(dir.path().join("gw"), dev, storage);
    let gw = start_gateway_with(cfg.clone()).await;
    let mut alice = client(&gw.url, "alice.near", &keys["alice.near"], Some(RootKey::generate()));
    alice.chunk_size = 4096;
    let bob = client(&gw.url, "bob.near", &keys["bob.near"], Some(RootKey::generate()));
    let enc = PutOptions::default();
    let public = PutOptions { public: true, ..Default::default() };

    // live: encrypted, multi-chunk
    let data_a = pattern(1, 0, 10_000);
    alice.put(&u("near://alice.near/enc/a.bin"), &data_a, &enc).await.unwrap();
    // overwritten: v1 is garbage
    alice.put(&u("near://alice.near/enc/b.bin"), &pattern(2, 0, 9000), &enc).await.unwrap();
    let b_v1 = head(&alice, "near://alice.near/enc/b.bin").await;
    let data_b = pattern(3, 0, 9000);
    alice.put(&u("near://alice.near/enc/b.bin"), &data_b, &enc).await.unwrap();
    // deleted: garbage
    alice.put(&u("near://alice.near/enc/c.bin"), &pattern(4, 0, 9000), &enc).await.unwrap();
    let c_v1 = head(&alice, "near://alice.near/enc/c.bin").await;
    alice.delete(&u("near://alice.near/enc/c.bin")).await.unwrap();
    // public: x and y are identical (same chunks, same manifest); z shares x's first chunk
    let data_x = pattern(5, 0, 8192 + 100);
    alice.put(&u("near://alice.near/pub/x.bin"), &data_x, &public).await.unwrap();
    alice.put(&u("near://alice.near/pub/y.bin"), &data_x, &public).await.unwrap();
    let mut data_z = data_x[..4096].to_vec();
    data_z.extend(pattern(6, 0, 3000));
    alice.put(&u("near://alice.near/pub/z.bin"), &data_z, &public).await.unwrap();
    let (x, y, z) = (head(&alice, "near://alice.near/pub/x.bin").await, head(&alice, "near://alice.near/pub/y.bin").await, head(&alice, "near://alice.near/pub/z.bin").await);
    assert_eq!(x.record.manifest_cid, y.record.manifest_cid, "identical public objects dedup");
    assert_eq!(x.manifest.chunks[0].cid, z.manifest.chunks[0].cid, "chunk shared between x and z");
    alice.delete(&u("near://alice.near/pub/y.bin")).await.unwrap();
    alice.delete(&u("near://alice.near/pub/z.bin")).await.unwrap();
    // shared: new manifest over the same data chunks; the old manifest is garbage
    let data_s = pattern(7, 0, 9000);
    alice.put(&u("near://alice.near/enc/s.bin"), &data_s, &enc).await.unwrap();
    let s_v1 = head(&alice, "near://alice.near/enc/s.bin").await;
    alice.share(&u("near://alice.near/enc/s.bin"), &bob.x25519_public().unwrap()).await.unwrap();
    let s_v2 = head(&alice, "near://alice.near/enc/s.bin").await;
    assert_ne!(s_v1.record.manifest_cid, s_v2.record.manifest_cid);
    assert_eq!(s_v1.manifest.chunks, s_v2.manifest.chunks, "share reuses data chunks");
    // a namespace of its own
    let data_bob = pattern(8, 0, 500);
    bob.put(&u("near://bob.near/notes.txt"), &data_bob, &enc).await.unwrap();
    // on the bridge (class bulk): written then deleted; bridges cannot be swept
    alice.put(&u("near://alice.near/bulk/w.bin"), &pattern(9, 0, 5000), &PutOptions { class: Some("bulk".into()), ..Default::default() }).await.unwrap();
    let w = head(&alice, "near://alice.near/bulk/w.bin").await;
    alice.delete(&u("near://alice.near/bulk/w.bin")).await.unwrap();

    let live_heads = [
        head(&alice, "near://alice.near/enc/a.bin").await,
        head(&alice, "near://alice.near/enc/b.bin").await,
        x.clone(),
        s_v2.clone(),
        head(&bob, "near://bob.near/notes.txt").await,
    ];
    let live: BTreeSet<String> = live_heads.iter().flat_map(cids).collect();
    let garbage: BTreeSet<String> = [&b_v1, &c_v1, &z, &s_v1].into_iter().flat_map(cids).filter(|c| !live.contains(c)).collect();
    assert!(garbage.contains(&s_v1.record.manifest_cid) && !garbage.contains(&s_v1.manifest.chunks[0].cid));
    assert!(!garbage.contains(&z.manifest.chunks[0].cid) && garbage.contains(&z.manifest.chunks[1].cid));
    assert_eq!(garbage.len(), 3 + 1 + 3 + 1 + 2 + 1, "b v1 (3 data + manifest), c (3 + 1), z's own chunk + manifest, s v1 manifest");
    for c in live.iter().chain(&garbage) {
        assert!(on(&a, c).await && on(&b, c).await, "hot class writes both backends");
    }
    let total_files = files(&a).len();
    assert_eq!(total_files, live.len() + garbage.len());

    // dry run: reports, deletes nothing
    let r = gc::run_config(&cfg, &opts(Duration::ZERO, true)).await.unwrap();
    assert!(r.dry_run);
    assert_eq!((r.namespaces, r.live_entries, r.live_chunks as usize), (2, 5, live.len()));
    assert_eq!(r.garbage as usize, 2 * garbage.len(), "garbage on both backends");
    assert!(r.garbage_bytes > 0);
    assert_eq!((r.deleted, r.deleted_bytes), (0, 0));
    assert_eq!(files(&a).len(), total_files);
    assert_eq!(files(&b).len(), total_files);
    let br = r.backends.iter().find(|x| x.name == "br").unwrap();
    assert!(!br.swept && br.chunks == 0, "bridge skipped");

    // grace period: nothing is old enough yet
    let r = gc::run_config(&cfg, &opts(Duration::from_secs(3600), false)).await.unwrap();
    assert_eq!((r.garbage, r.deleted), (0, 0));
    assert_eq!(r.backends.iter().filter(|x| x.swept).map(|x| x.recent as usize).sum::<usize>(), 2 * garbage.len());
    assert_eq!(files(&a).len(), total_files);

    // Everything is now 2 h old except an unreferenced chunk uploaded just now
    // (an upload whose record is not committed yet).
    age_all(&[&a, &b]);
    let fresh = bytes::Bytes::from_static(b"upload in progress");
    let fresh_cid = near_drive_client::near_drive_core::cid(&fresh);
    FsBlobStore::new(a.clone()).put(&fresh_cid, fresh.clone()).await.unwrap();
    // Re-uploading an old garbage chunk refreshes it: it is about to be referenced again.
    let reused = c_v1.manifest.chunks[0].cid.clone();
    let reused_bytes = FsBlobStore::new(b.clone()).get(&reused).await.unwrap().unwrap();
    FsBlobStore::new(b.clone()).put(&reused, reused_bytes).await.unwrap();

    let r = gc::run_config(&cfg, &opts(Duration::from_secs(3600), false)).await.unwrap();
    assert_eq!(r.deleted as usize, 2 * garbage.len() - 1);
    assert_eq!(r.deleted, r.garbage);
    assert!(r.deleted_bytes > 0 && r.deleted_bytes == r.garbage_bytes);
    assert_eq!(r.errors().count(), 0);
    for c in &garbage {
        assert!(!on(&a, c).await, "garbage {c} gone from a");
        assert_eq!(on(&b, c).await, *c == reused, "garbage {c} gone from b unless re-uploaded");
    }
    for c in &live {
        assert!(on(&a, c).await && on(&b, c).await, "live {c} kept on both backends");
    }
    assert!(on(&a, &fresh_cid).await, "grace period protects the fresh upload");
    assert!(on(&bridge_dir, &w.record.manifest_cid).await, "bridge untouched");

    // every live object still downloads and verifies
    assert_eq!(alice.get(&u("near://alice.near/enc/a.bin")).await.unwrap().1, data_a);
    assert_eq!(alice.get(&u("near://alice.near/enc/b.bin")).await.unwrap().1, data_b);
    assert_eq!(alice.get(&u("near://alice.near/pub/x.bin")).await.unwrap().1, data_x);
    assert_eq!(alice.get(&u("near://alice.near/enc/s.bin")).await.unwrap().1, data_s);
    assert_eq!(bob.get(&u("near://bob.near/notes.txt")).await.unwrap().1, data_bob);
    assert!(alice.get(&u("near://alice.near/pub/y.bin")).await.is_err());

    // grace 0: the uncommitted upload and the refreshed chunk go too
    let r = gc::run_config(&cfg, &opts(Duration::ZERO, false)).await.unwrap();
    assert_eq!(r.deleted, 2);
    assert!(!on(&a, &fresh_cid).await && !on(&b, &reused).await);
    assert_eq!(files(&a).len(), live.len());
    assert_eq!(files(&b).len(), live.len());
    // idempotent
    let r = gc::run_config(&cfg, &opts(Duration::ZERO, false)).await.unwrap();
    assert_eq!((r.garbage, r.deleted), (0, 0));
    assert_eq!(alice.get(&u("near://alice.near/enc/s.bin")).await.unwrap().1, data_s);

    // a new upload still works after GC (chunks re-written, not assumed present)
    alice.put(&u("near://alice.near/enc/c.bin"), &pattern(4, 0, 9000), &enc).await.unwrap();
    assert_eq!(alice.get(&u("near://alice.near/enc/c.bin")).await.unwrap().1, pattern(4, 0, 9000));
}

#[tokio::test]
async fn gc_aborts_on_unreadable_manifest_and_refuses_empty_index() {
    let dir = tempfile::tempdir().unwrap();
    let chunks = dir.path().join("chunks");
    let storage = json!({"backends": {"local": {"type": "fs", "path": chunks}}});
    let (keys, dev) = dev_keys(&["alice.near"]);
    let cfg = gateway_config(dir.path().join("gw"), dev, storage);
    let gw = start_gateway_with(cfg.clone()).await;
    let alice = client(&gw.url, "alice.near", &keys["alice.near"], Some(RootKey::generate()));
    alice.put(&u("near://alice.near/a"), b"live", &PutOptions::default()).await.unwrap();
    alice.put(&u("near://alice.near/b"), b"also live", &PutOptions::default()).await.unwrap();
    alice.put(&u("near://alice.near/gone"), b"deleted", &PutOptions::default()).await.unwrap();
    alice.delete(&u("near://alice.near/gone")).await.unwrap();
    let n = files(&chunks).len();
    assert_eq!(n, 6);

    // A live manifest that cannot be read aborts before anything is swept.
    let hb = head(&alice, "near://alice.near/b").await;
    let mpath = files(&chunks).into_iter().find(|p| p.file_name().unwrap().to_string_lossy() == hb.record.manifest_cid[3..]).unwrap();
    let saved = std::fs::read(&mpath).unwrap();
    std::fs::remove_file(&mpath).unwrap();
    let e = gc::run_config(&cfg, &opts(Duration::ZERO, false)).await.unwrap_err();
    assert!(format!("{e:#}").contains("missing"), "{e:#}");
    std::fs::write(&mpath, b"not a manifest").unwrap();
    assert!(gc::run_config(&cfg, &opts(Duration::ZERO, false)).await.is_err(), "corrupt manifest aborts too");
    assert_eq!(files(&chunks).len(), n);
    std::fs::write(&mpath, saved).unwrap();

    // An index with no live entries next to backends full of chunks looks
    // like a misconfiguration: refused unless forced.
    let mut wrong = cfg.clone();
    wrong.storage.index = serde_json::from_value(json!({"type": "fs", "path": dir.path().join("empty-index")})).unwrap();
    let e = gc::run_config(&wrong, &opts(Duration::ZERO, false)).await.unwrap_err();
    assert!(format!("{e:#}").contains("--force"), "{e:#}");
    assert_eq!(files(&chunks).len(), n);
    let dry = gc::run_config(&wrong, &GcOptions { grace: Duration::ZERO, dry_run: true, force: true, ..Default::default() }).await.unwrap();
    assert_eq!((dry.garbage as usize, dry.deleted), (n, 0));

    // the real index: only the deleted object's two chunks go
    let r = gc::run_config(&cfg, &opts(Duration::ZERO, false)).await.unwrap();
    assert_eq!((r.live_entries, r.deleted), (2, 2));
    assert_eq!(alice.get(&u("near://alice.near/a")).await.unwrap().1, b"live");
    assert_eq!(alice.get(&u("near://alice.near/b")).await.unwrap().1, b"also live");

    let r = gc::run_config(&wrong, &GcOptions { grace: Duration::ZERO, force: true, ..Default::default() }).await.unwrap();
    assert_eq!(r.deleted, 4, "forced");
    assert!(files(&chunks).is_empty());
}

#[tokio::test]
async fn periodic_gc_in_the_server() {
    let dir = tempfile::tempdir().unwrap();
    let chunks = dir.path().join("chunks");
    let (keys, dev) = dev_keys(&["alice.near"]);
    let mut cfg = gateway_config(dir.path().join("gw"), dev, json!({"backends": {"local": {"type": "fs", "path": chunks}}}));
    // grace well above an upload-to-commit round trip
    cfg.gc = Some(GcConfig { interval_secs: 1, grace_secs: 2, dry_run: false });
    let gw = start_gateway_with(cfg).await;
    let alice = client(&gw.url, "alice.near", &keys["alice.near"], Some(RootKey::generate()));
    alice.put(&u("near://alice.near/keep"), b"keep me", &PutOptions::default()).await.unwrap();
    alice.put(&u("near://alice.near/drop"), b"drop me", &PutOptions::default()).await.unwrap();
    let dropped = cids(&head(&alice, "near://alice.near/drop").await);
    alice.delete(&u("near://alice.near/drop")).await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let mut gone = true;
        for c in &dropped {
            gone &= !on(&chunks, c).await;
        }
        if gone {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "periodic GC did not sweep");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(files(&chunks).len(), 2);
    assert_eq!(alice.get(&u("near://alice.near/keep")).await.unwrap().1, b"keep me");
}

/// The `gc` subcommand of the binary, with the config inline in NEAR_DRIVE_CONFIG_JSON or as a file.
#[tokio::test]
async fn gc_subcommand() {
    let dir = tempfile::tempdir().unwrap();
    let chunks = dir.path().join("chunks");
    let (keys, dev) = dev_keys(&["alice.near"]);
    let cfg = gateway_config(dir.path().join("gw"), dev, json!({"backends": {"local": {"type": "fs", "path": chunks}}}));
    let gw = start_gateway_with(cfg.clone()).await;
    let alice = client(&gw.url, "alice.near", &keys["alice.near"], Some(RootKey::generate()));
    alice.put(&u("near://alice.near/keep"), b"keep", &PutOptions::default()).await.unwrap();
    alice.put(&u("near://alice.near/drop"), b"drop", &PutOptions::default()).await.unwrap();
    alice.delete(&u("near://alice.near/drop")).await.unwrap();
    let json_cfg = serde_json::to_string(&cfg).unwrap();
    let cfg_file = dir.path().join("gateway.json");
    std::fs::write(&cfg_file, &json_cfg).unwrap();

    let run = |args: &[&str], env_json: Option<&str>| {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_near-drive-gateway"));
        c.args(args).env_remove("NEAR_DRIVE_CONFIG").env_remove("NEAR_DRIVE_CONFIG_JSON").env("RUST_LOG", "warn");
        if let Some(j) = env_json {
            c.env("NEAR_DRIVE_CONFIG_JSON", j);
        }
        c.output().unwrap()
    };
    let report = |o: &std::process::Output| -> gc::GcReport {
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        serde_json::from_slice(&o.stdout).unwrap()
    };

    // default grace (24h) keeps everything
    let r = report(&run(&["gc"], Some(&json_cfg)));
    assert_eq!((r.grace_secs, r.live_entries, r.garbage, r.deleted), (86400, 1, 0, 0));
    let r = report(&run(&["gc", "--dry-run", "--grace", "0"], Some(&json_cfg)));
    assert_eq!((r.dry_run, r.garbage, r.deleted), (true, 2, 0));
    assert_eq!(files(&chunks).len(), 4);
    // --config before or after the subcommand
    let f = cfg_file.to_str().unwrap();
    let r = report(&run(&["--config", f, "gc", "--grace", "0s"], None));
    assert_eq!((r.dry_run, r.deleted), (false, 2));
    assert_eq!(files(&chunks).len(), 2);
    let r = report(&run(&["gc", "--config", f, "--grace=0"], None));
    assert_eq!(r.deleted, 0);
    assert_eq!(alice.get(&u("near://alice.near/keep")).await.unwrap().1, b"keep");

    // config errors
    let o = run(&["gc"], None);
    assert!(!o.status.success() && String::from_utf8_lossy(&o.stderr).contains("NEAR_DRIVE_CONFIG_JSON"));
    let o = run(&["--config", f, "gc"], Some(&json_cfg));
    assert!(!o.status.success() && String::from_utf8_lossy(&o.stderr).contains("both"));
    let o = run(&["gc", "--grace", "soon"], Some(&json_cfg));
    assert!(!o.status.success());
}
