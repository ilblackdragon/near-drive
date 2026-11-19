//! Two devices (same account and root key, separate folders) syncing through
//! one gateway.
use ed25519_dalek::SigningKey;
use near_drive_client::{
    near_drive_core::{crypto::RootKey, keys, NearUri},
    Client, Conflict, NetConfig, PutOptions,
};
use near_drive_gateway::{router, AppState, Config};
use near_drive_sync::{local::META_DIR, sync_once, Folder, Options};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

struct Env {
    url: String,
    sk: SigningKey,
    root: [u8; 32],
    tmp: tempfile::TempDir,
}

async fn setup() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let dev = HashMap::from([("alice.near".to_string(), vec![keys::format_public_key(&sk.verifying_key())])]);
    let cfg = Config { listen: "127.0.0.1:0".into(), data_dir: tmp.path().join("gw"), dev_keys: dev, ..Default::default() };
    let state = AppState::new(cfg).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    Env { url, sk, root: *RootKey::generate().as_bytes(), tmp }
}

impl Env {
    fn client(&self) -> Client {
        let mut c = Client::new(&self.url, "alice.near", self.sk.clone(), Some(RootKey::from_bytes(self.root)));
        c.chunk_size = 64 * 1024;
        c
    }
    fn device(&self, name: &str) -> Folder {
        Folder::new(self.tmp.path().join(name), NearUri::parse("near://alice.near/Drive/").unwrap()).unwrap()
    }
}

fn opts() -> Options {
    Options { settle: Duration::ZERO, ..Default::default() }
}

fn write(f: &Folder, rel: &str, data: &[u8]) {
    let p = f.local.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

fn read(f: &Folder, rel: &str) -> Option<Vec<u8>> {
    std::fs::read(f.local.join(rel)).ok()
}

/// Every syncable file in the folder (not the metadata dir).
fn files(f: &Folder) -> Vec<String> {
    near_drive_sync::local::scan(&f.local, &mut vec![]).unwrap().into_keys().collect()
}

fn trash_has(f: &Folder, name: &str) -> bool {
    fn walk(d: &Path, name: &str) -> bool {
        std::fs::read_dir(d).map(|rd| rd.flatten().any(|e| if e.path().is_dir() { walk(&e.path(), name) } else { e.file_name() == name })).unwrap_or(false)
    }
    walk(&f.local.join(META_DIR).join("trash"), name)
}

#[tokio::test]
async fn two_devices_stay_in_sync() {
    let env = setup().await;
    let (c, a, b) = (env.client(), env.device("laptop"), env.device("desktop"));
    let o = opts();

    // First sync: laptop's files go up, desktop pulls them.
    let big: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    write(&a, "notes.txt", b"hello");
    write(&a, "docs/report.pdf", &big); // 5 chunks
    write(&a, "docs/deep/empty", b"");
    write(&a, "Caf\u{e9}/menu.txt", b"unicode folder");
    write(&a, ".DS_Store", b"ignored");
    let r = sync_once(&c, &a, &o).await.unwrap();
    assert_eq!(r.uploaded.len(), 4, "{r:?}");
    assert!(r.errors.is_empty(), "{r:?}");
    let r = sync_once(&c, &b, &o).await.unwrap();
    assert_eq!(r.downloaded.len(), 4, "{r:?}");
    assert_eq!(files(&a), files(&b));
    assert_eq!(read(&b, "docs/report.pdf").unwrap(), big);
    assert!(read(&b, ".DS_Store").is_none());
    // Nothing to do on either side now.
    assert!(!sync_once(&c, &a, &o).await.unwrap().changed());
    assert!(!sync_once(&c, &b, &o).await.unwrap().changed());

    // Edit on desktop -> laptop gets it.
    write(&b, "notes.txt", b"hello from desktop");
    assert_eq!(sync_once(&c, &b, &o).await.unwrap().uploaded, vec!["notes.txt"]);
    assert_eq!(sync_once(&c, &a, &o).await.unwrap().downloaded, vec!["notes.txt"]);
    assert_eq!(read(&a, "notes.txt").unwrap(), b"hello from desktop");

    // Touch without changing content: no transfer.
    let f = std::fs::File::options().write(true).open(a.local.join("notes.txt")).unwrap();
    f.set_modified(std::time::SystemTime::now() - Duration::from_secs(3600)).unwrap();
    let r = sync_once(&c, &a, &o).await.unwrap();
    assert!(!r.changed(), "{r:?}");

    // Delete on laptop -> deleted remotely -> moved to desktop's trash.
    std::fs::remove_file(a.local.join("docs/deep/empty")).unwrap();
    assert_eq!(sync_once(&c, &a, &o).await.unwrap().deleted_remote, vec!["docs/deep/empty"]);
    assert_eq!(sync_once(&c, &b, &o).await.unwrap().deleted_local, vec!["docs/deep/empty"]);
    assert!(read(&b, "docs/deep/empty").is_none() && trash_has(&b, "empty"));
    assert!(!b.local.join("docs/deep").exists(), "emptied folder removed");

    // Both edit the same file: one wins the name, the other becomes a conflicted copy; nothing is lost.
    write(&a, "notes.txt", b"laptop version");
    write(&b, "notes.txt", b"desktop version!");
    sync_once(&c, &a, &o).await.unwrap();
    let r = sync_once(&c, &b, &o).await.unwrap();
    assert_eq!(r.conflicts.len(), 1, "{r:?}");
    assert!(r.pending);
    let copy = r.conflicts[0].clone();
    assert!(copy.starts_with("notes (conflicted copy from ") && copy.ends_with(".txt"), "{copy}");
    assert_eq!(read(&b, "notes.txt").unwrap(), b"laptop version");
    assert_eq!(read(&b, &copy).unwrap(), b"desktop version!");
    assert_eq!(sync_once(&c, &b, &o).await.unwrap().uploaded, vec![copy.clone()]);
    sync_once(&c, &a, &o).await.unwrap();
    assert_eq!(read(&a, &copy).unwrap(), b"desktop version!");
    assert_eq!(files(&a), files(&b));

    // Remote deleted while edited locally: the edit is kept and re-uploaded.
    write(&a, "Caf\u{e9}/menu.txt", b"new menu");
    std::fs::remove_file(b.local.join("Caf\u{e9}/menu.txt")).unwrap();
    sync_once(&c, &b, &o).await.unwrap(); // deletes remotely
    let r = sync_once(&c, &a, &o).await.unwrap();
    assert_eq!(r.uploaded, vec!["Caf\u{e9}/menu.txt"], "{r:?}");
    sync_once(&c, &b, &o).await.unwrap();
    assert_eq!(read(&b, "Caf\u{e9}/menu.txt").unwrap(), b"new menu");

    // Files are end-to-end encrypted like any other upload.
    let gw_files: Vec<_> = walk_bytes(&env.tmp.path().join("gw"));
    assert!(!gw_files.iter().any(|b| b.windows(14).any(|w| w == b"laptop version")), "plaintext on the gateway");
}

fn walk_bytes(d: &Path) -> Vec<Vec<u8>> {
    let mut out = vec![];
    for e in std::fs::read_dir(d).unwrap().flatten() {
        if e.path().is_dir() {
            out.extend(walk_bytes(&e.path()));
        } else {
            out.push(std::fs::read(e.path()).unwrap());
        }
    }
    out
}

#[tokio::test]
async fn existing_folders_merge_and_writes_are_conditional() {
    let env = setup().await;
    let (c, a, b) = (env.client(), env.device("a"), env.device("b"));
    let o = opts();
    // Both devices start with the same file (e.g. a copied folder) plus their own.
    write(&a, "same.txt", b"identical");
    write(&b, "same.txt", b"identical");
    write(&a, "only-a.txt", b"a");
    write(&b, "only-b.txt", b"b");
    sync_once(&c, &a, &o).await.unwrap();
    let r = sync_once(&c, &b, &o).await.unwrap();
    assert!(r.conflicts.is_empty(), "identical content is not a conflict: {r:?}");
    sync_once(&c, &a, &o).await.unwrap();
    assert_eq!(files(&a), vec!["only-a.txt", "only-b.txt", "same.txt"]);
    assert_eq!(files(&a), files(&b));

    // The client refuses to overwrite a version it has not seen.
    let uri = NearUri::parse("near://alice.near/Drive/same.txt").unwrap();
    let e = c.put(&uri, b"blind", &PutOptions { expect_seq: Some(0), ..Default::default() }).await.unwrap_err();
    assert!(e.downcast_ref::<Conflict>().is_some_and(|c| c.current == 1), "{e:#}");
    let e = c.delete_if(&uri, 7).await.unwrap_err();
    assert!(e.downcast_ref::<Conflict>().is_some(), "{e:#}");
    assert!(c.head(&uri).await.unwrap().is_some());

    // A folder already bound to another remote is refused.
    let other = Folder::new(a.local.clone(), NearUri::parse("near://alice.near/Other/").unwrap()).unwrap();
    assert!(sync_once(&c, &other, &o).await.unwrap_err().to_string().contains("already synced"));
}

#[tokio::test]
async fn offline_changes_wait_and_unfinished_writes_are_not_uploaded() {
    let env = setup().await;
    let a = env.device("a");
    write(&a, "x.txt", b"written offline");
    // Gateway unreachable: the pass fails, nothing local is touched.
    let mut dead = Client::new("http://127.0.0.1:9", "alice.near", env.sk.clone(), Some(RootKey::from_bytes(env.root)));
    dead.set_net(NetConfig { attempts: 1, ..Default::default() });
    assert!(sync_once(&dead, &a, &opts()).await.is_err());
    assert_eq!(read(&a, "x.txt").unwrap(), b"written offline");
    // A file modified just now waits for `settle` before it goes up.
    let c = env.client();
    let r = sync_once(&c, &a, &Options { settle: Duration::from_secs(60), ..Default::default() }).await.unwrap();
    assert!(r.uploaded.is_empty() && r.pending, "{r:?}");
    let r = sync_once(&c, &a, &opts()).await.unwrap();
    assert_eq!(r.uploaded, vec!["x.txt"]);
}

#[tokio::test]
async fn run_loop_picks_up_local_changes() {
    let env = setup().await;
    let (a, b) = (env.device("a"), env.device("b"));
    let o = Options { settle: Duration::from_millis(200), poll: Duration::from_millis(300), ..Default::default() };
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let (ca, fa, oa) = (env.client(), a.clone(), o.clone());
    let task = tokio::spawn(async move { near_drive_sync::run(&ca, &fa, &oa, async { let _ = stop_rx.await; }).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    write(&a, "live.txt", b"saved in an editor");
    let c = env.client();
    let mut got = None;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        sync_once(&c, &b, &opts()).await.unwrap();
        if let Some(d) = read(&b, "live.txt") {
            got = Some(d);
            break;
        }
    }
    assert_eq!(got.as_deref(), Some(&b"saved in an editor"[..]));
    let st = near_drive_sync::read_status(&a.local).unwrap();
    assert!(st.ok, "{st:?}");
    stop_tx.send(()).unwrap();
    task.await.unwrap().unwrap();
}
