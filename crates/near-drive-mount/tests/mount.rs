//! A real FUSE mount over an in-process gateway (Linux; skipped when FUSE is
//! unavailable, e.g. in a container without /dev/fuse).
#![cfg(target_os = "linux")]
use ed25519_dalek::SigningKey;
use near_drive_client::{
    near_drive_core::{crypto::RootKey, keys, NearUri},
    Client, PutOptions,
};
use near_drive_gateway::{router, AppState, Config};
use near_drive_mount::{mount, MountOptions};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

fn u(s: &str) -> NearUri {
    NearUri::parse(s).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn files_on_demand() {
    let tmp = tempfile::tempdir().unwrap();
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let dev = HashMap::from([("alice.near".to_string(), vec![keys::format_public_key(&sk.verifying_key())])]);
    let cfg = Config { listen: "127.0.0.1:0".into(), data_dir: tmp.path().join("gw"), dev_keys: dev, ..Default::default() };
    let state = AppState::new(cfg).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    let root = *RootKey::generate().as_bytes();
    let mk = || {
        let mut c = Client::new(&url, "alice.near", sk.clone(), Some(RootKey::from_bytes(root)));
        c.chunk_size = 64 * 1024;
        c
    };
    let c = mk();
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
    c.put(&u("near://alice.near/Drive/docs/a.txt"), b"hello", &PutOptions::default()).await.unwrap();
    c.put(&u("near://alice.near/Drive/b.bin"), &big, &PutOptions::default()).await.unwrap();

    let mnt = tmp.path().join("mnt");
    let cache = tmp.path().join("cache");
    std::fs::create_dir_all(&mnt).unwrap();
    let opts = MountOptions { refresh: Duration::from_millis(200), ..MountOptions::new(&cache) };
    let m = match mount(Arc::new(mk()), u("near://alice.near/Drive/"), &mnt, opts, tokio::runtime::Handle::current()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("skipping: cannot mount FUSE here: {e:#}");
            return;
        }
    };

    let (mnt2, cache2, big2) = (mnt.clone(), cache.clone(), big.clone());
    let cached_files = move || std::fs::read_dir(&cache2).unwrap().flatten().filter(|e| e.path().is_file()).count();
    let r = tokio::task::spawn_blocking(move || {
        let mnt = mnt2;
        let mut names: Vec<String> = std::fs::read_dir(&mnt).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        assert_eq!(names, vec!["b.bin", "docs"]);
        assert_eq!(std::fs::metadata(mnt.join("b.bin")).unwrap().len(), 300_000, "size known before download");
        assert_eq!(cached_files(), 0, "listing downloads nothing");
        assert_eq!(std::fs::read(mnt.join("b.bin")).unwrap(), big2, "downloaded on open");
        assert_eq!(cached_files(), 1);
        assert_eq!(std::fs::read_to_string(mnt.join("docs/a.txt")).unwrap(), "hello");

        // New file, edit, rename, folders, delete.
        std::fs::write(mnt.join("c.txt"), "created in the mount").unwrap();
        std::fs::write(mnt.join("docs/a.txt"), "hello, edited").unwrap();
        std::fs::create_dir(mnt.join("new")).unwrap();
        std::fs::rename(mnt.join("c.txt"), mnt.join("new/c2.txt")).unwrap();
        std::fs::create_dir(mnt.join("empty")).unwrap();
        std::fs::remove_dir(mnt.join("empty")).unwrap();
        std::fs::remove_file(mnt.join("b.bin")).unwrap();
        assert!(!mnt.join("b.bin").exists());
        let mut names: Vec<String> = std::fs::read_dir(&mnt).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        assert_eq!(names, vec!["docs", "new"]);
    })
    .await;
    if let Err(e) = r {
        drop(m);
        std::panic::resume_unwind(e.into_panic());
    }
    assert_eq!(c.get(&u("near://alice.near/Drive/new/c2.txt")).await.unwrap().1, b"created in the mount");
    assert!(c.head(&u("near://alice.near/Drive/c.txt")).await.unwrap().is_none());
    assert_eq!(c.get(&u("near://alice.near/Drive/docs/a.txt")).await.unwrap().1, b"hello, edited");
    assert!(c.head(&u("near://alice.near/Drive/b.bin")).await.unwrap().is_none());

    // Changes made elsewhere show up.
    c.put(&u("near://alice.near/Drive/docs/a.txt"), b"changed remotely", &PutOptions::default()).await.unwrap();
    c.put(&u("near://alice.near/Drive/remote.txt"), b"new remotely", &PutOptions::default()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    let mnt2 = mnt.clone();
    let (a, rem) = tokio::task::spawn_blocking(move || (std::fs::read_to_string(mnt2.join("docs/a.txt")).unwrap(), std::fs::read_to_string(mnt2.join("remote.txt")).unwrap())).await.unwrap();
    assert_eq!((a.as_str(), rem.as_str()), ("changed remotely", "new remotely"));

    // Edited here while changed elsewhere: both versions kept.
    let mnt2 = mnt.clone();
    let c2 = mk();
    let writer = tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).truncate(true).open(mnt2.join("docs/a.txt")).unwrap();
        f.write_all(b"my edit").unwrap();
        f
    })
    .await
    .unwrap();
    c2.put(&u("near://alice.near/Drive/docs/a.txt"), b"their edit", &PutOptions::default()).await.unwrap();
    tokio::task::spawn_blocking(move || drop(writer)).await.unwrap(); // close -> upload -> conflict
    assert_eq!(c.get(&u("near://alice.near/Drive/docs/a.txt")).await.unwrap().1, b"their edit");
    let listing = c.list(&u("near://alice.near/Drive/docs/")).await.unwrap();
    let copy = listing.iter().find(|e| e.path.contains("conflicted copy")).expect("conflicted copy uploaded");
    assert_eq!(c.get(&u(&format!("near://alice.near/{}", copy.path))).await.unwrap().1, b"my edit");

    tokio::task::spawn_blocking(move || m.unmount().unwrap()).await.unwrap();
}
