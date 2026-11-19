//! Bad networks: a fault-injecting proxy between the client and the gateway.
//!
//! - flaky: 503s, response bodies cut off mid-transfer, and writes that land
//!   on the gateway but whose response is lost; every operation still succeeds;
//! - interrupted uploads and downloads resume and transfer only what is missing;
//! - a file changed under an interrupted upload starts over with a fresh key
//!   (never re-encrypts different bytes under an old nonce);
//! - small objects are read in one request (chunks inlined by `locate`).
mod common;
use axum::{body::Body, extract::State, http::Request, response::Response};
use common::*;
use near_drive_client::{near_drive_core::crypto::RootKey, Client, NetConfig, PutOptions};
use near_drive_client::near_drive_core::NearUri;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Pass,
    /// Request k: k%4==1 -> 503; k%4==2 -> forwarded, but the response is
    /// lost (PUT/DELETE: 502) or cut off halfway (GET).
    Flaky,
    /// Chunk transfers after the first `n` fail with 503 (a dead link).
    CutAfter(usize),
}

struct Proxy {
    upstream: String,
    http: reqwest::Client,
    mode: Mutex<Mode>,
    k: AtomicUsize,
    requests: AtomicUsize,
    chunk_ops: AtomicUsize,
    chunk_puts: AtomicUsize,
    chunk_gets: AtomicUsize,
}

impl Proxy {
    fn set(&self, m: Mode) {
        *self.mode.lock().unwrap() = m;
        for c in [&self.k, &self.requests, &self.chunk_ops, &self.chunk_puts, &self.chunk_gets] {
            c.store(0, SeqCst);
        }
    }
}

fn status(code: u16) -> Response {
    Response::builder().status(code).header("retry-after", "0").body(Body::from("injected")).unwrap()
}

async fn handle(State(p): State<Arc<Proxy>>, req: Request<Body>) -> Response {
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let pq = parts.uri.path_and_query().map(|x| x.as_str()).unwrap_or("/").to_string();
    let is_chunk_put = parts.method == "PUT" && pq.starts_with("/v1/chunk/");
    let is_chunk_get = parts.method == "GET" && pq.contains("chunk=");
    p.requests.fetch_add(1, SeqCst);
    let mode = *p.mode.lock().unwrap();
    let k = p.k.fetch_add(1, SeqCst);
    if mode == Mode::Flaky && k % 4 == 1 {
        return status(503);
    }
    if let Mode::CutAfter(n) = mode {
        if (is_chunk_put || is_chunk_get) && p.chunk_ops.fetch_add(1, SeqCst) >= n {
            return status(503);
        }
    }
    let mut fwd = p.http.request(parts.method.clone(), format!("{}{pq}", p.upstream)).body(body);
    for (name, v) in &parts.headers {
        if name != "host" && name != "content-length" {
            fwd = fwd.header(name, v);
        }
    }
    let resp = fwd.send().await.unwrap();
    let st = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.bytes().await.unwrap();
    if st.is_success() {
        if is_chunk_put {
            p.chunk_puts.fetch_add(1, SeqCst);
        }
        if is_chunk_get {
            p.chunk_gets.fetch_add(1, SeqCst);
        }
    }
    if mode == Mode::Flaky && k % 4 == 2 {
        if parts.method != "GET" {
            return status(502); // it happened upstream; the client doesn't know
        }
        let half = bytes.slice(..bytes.len() / 2);
        let s = futures_util::stream::iter(vec![Ok(half), Err(std::io::Error::other("connection reset"))]);
        return Response::builder().status(st).body(Body::from_stream(s)).unwrap();
    }
    let mut out = Response::builder().status(st);
    for (name, v) in &headers {
        if name != "content-length" && name != "transfer-encoding" {
            out = out.header(name, v);
        }
    }
    out.body(Body::from(bytes)).unwrap()
}

struct Env {
    proxy: Arc<Proxy>,
    url: String,
    key: ed25519_dalek::SigningKey,
    root: RootKey,
    tmp: tempfile::TempDir,
}

async fn setup() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let (keys, dev) = dev_keys(&["alice.near"]);
    let gw = start_gateway(tmp.path().join("gw"), dev, json!({})).await;
    let proxy = Arc::new(Proxy {
        upstream: gw.url,
        http: reqwest::Client::new(),
        mode: Mutex::new(Mode::Pass),
        k: AtomicUsize::new(0),
        requests: AtomicUsize::new(0),
        chunk_ops: AtomicUsize::new(0),
        chunk_puts: AtomicUsize::new(0),
        chunk_gets: AtomicUsize::new(0),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = axum::Router::new().fallback(handle).with_state(proxy.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Env { proxy, url, key: keys["alice.near"].clone(), root: RootKey::generate(), tmp }
}

impl Env {
    fn client(&self, attempts: u32, parallelism: usize) -> Client {
        let mut c = client(&self.url, "alice.near", &self.key, Some(RootKey::from_bytes(*self.root.as_bytes())));
        c.chunk_size = 64 * 1024;
        c.parallelism = parallelism;
        c.set_net(NetConfig { attempts, base_delay: Duration::from_millis(1), max_delay: Duration::from_millis(5), ..Default::default() });
        c
    }
    fn path(&self, p: &str) -> std::path::PathBuf {
        self.tmp.path().join(p)
    }
}

fn u(s: &str) -> NearUri {
    NearUri::parse(s).unwrap()
}

#[tokio::test]
async fn every_operation_survives_a_flaky_network() {
    let env = setup().await;
    let c = env.client(8, 4);
    env.proxy.set(Mode::Flaky);
    let h = write_pattern_file(&env.path("big"), 7, 1_000_000);
    let big = u("near://alice.near/big.bin");
    c.put_file(env.path("big"), &big, &PutOptions::default()).await.unwrap();
    c.get_to_file(&big, env.path("big.out")).await.unwrap();
    assert_eq!(hash_file(&env.path("big.out")), h);
    let r = c.get_range(&big, 100_000..400_000).await.unwrap();
    assert_eq!(r, std::fs::read(env.path("big")).unwrap()[100_000..400_000]);

    let small = u("near://alice.near/small.txt");
    c.put(&small, b"hello", &PutOptions::default()).await.unwrap();
    c.put(&small, b"hello again", &PutOptions::default()).await.unwrap(); // seq 2 through lost responses
    assert_eq!(c.get(&small).await.unwrap().1, b"hello again");
    assert_eq!(c.head(&small).await.unwrap().unwrap().record.seq, 2);
    assert_eq!(c.list(&u("near://alice.near/")).await.unwrap().len(), 2);
    c.delete(&small).await.unwrap();
    assert!(c.head(&small).await.unwrap().is_none());
    assert!(env.proxy.k.load(SeqCst) > 40, "faults were actually injected");
}

#[tokio::test]
async fn interrupted_upload_resumes_without_resending_chunks() {
    let env = setup().await;
    let h = write_pattern_file(&env.path("f"), 1, 1_000_000); // 16 chunks of 64 KiB
    let uri = u("near://alice.near/f.bin");
    let jdir = env.path("journal");
    let opts = PutOptions { resume_dir: Some(jdir.clone()), ..Default::default() };

    env.proxy.set(Mode::CutAfter(5));
    let e = env.client(1, 1).put_file(env.path("f"), &uri, &opts).await.unwrap_err();
    assert!(format!("{e:#}").contains("run it again to resume"), "{e:#}");
    assert_eq!(std::fs::read_dir(&jdir).unwrap().count(), 1, "journal kept");

    env.proxy.set(Mode::Pass);
    env.client(1, 1).put_file(env.path("f"), &uri, &opts).await.unwrap();
    assert_eq!(env.proxy.chunk_puts.load(SeqCst), 16 - 5 + 1, "only the missing chunks + the manifest");
    assert_eq!(std::fs::read_dir(&jdir).unwrap().count(), 0, "journal removed after success");
    env.client(1, 1).get_to_file(&uri, env.path("f.out")).await.unwrap();
    assert_eq!(hash_file(&env.path("f.out")), h);
}

#[tokio::test]
async fn changed_file_restarts_the_upload_with_a_fresh_key() {
    let env = setup().await;
    write_pattern_file(&env.path("f"), 1, 1_000_000);
    let uri = u("near://alice.near/f.bin");
    let opts = PutOptions { resume_dir: Some(env.path("journal")), ..Default::default() };
    env.proxy.set(Mode::CutAfter(5));
    env.client(1, 1).put_file(env.path("f"), &uri, &opts).await.unwrap_err();

    // Same size and mtime, different bytes in an already-sent chunk.
    let mtime = std::fs::metadata(env.path("f")).unwrap().modified().unwrap();
    let mut data = std::fs::read(env.path("f")).unwrap();
    data[10] ^= 0xff;
    std::fs::write(env.path("f"), &data).unwrap();
    std::fs::File::options().write(true).open(env.path("f")).unwrap().set_modified(mtime).unwrap();

    env.proxy.set(Mode::Pass);
    env.client(1, 1).put_file(env.path("f"), &uri, &opts).await.unwrap();
    assert_eq!(env.proxy.chunk_puts.load(SeqCst), 16 + 1, "everything re-encrypted and re-sent");
    env.client(1, 1).get_to_file(&uri, env.path("f.out")).await.unwrap();
    assert_eq!(std::fs::read(env.path("f.out")).unwrap(), data);
}

#[tokio::test]
async fn interrupted_download_resumes_from_the_part_file() {
    let env = setup().await;
    let h = write_pattern_file(&env.path("f"), 3, 1_000_000);
    let uri = u("near://alice.near/f.bin");
    env.client(1, 4).put_file(env.path("f"), &uri, &PutOptions::default()).await.unwrap();

    env.proxy.set(Mode::CutAfter(6));
    let e = env.client(1, 1).get_to_file(&uri, env.path("out")).await.unwrap_err();
    assert!(format!("{e:#}").contains("run it again to resume"), "{e:#}");
    assert!(env.path("out.drive-part").exists() && env.path("out.drive-part.json").exists());

    env.proxy.set(Mode::Pass);
    env.client(1, 1).get_to_file(&uri, env.path("out")).await.unwrap();
    assert_eq!(env.proxy.chunk_gets.load(SeqCst), 16 - 6, "chunks on disk were verified, not refetched");
    assert_eq!(hash_file(&env.path("out")), h);
    assert!(!env.path("out.drive-part").exists() && !env.path("out.drive-part.json").exists());

    // A new version invalidates the part file: start from scratch.
    env.client(1, 4).put_file(env.path("f"), &uri, &PutOptions::default()).await.unwrap();
    env.proxy.set(Mode::CutAfter(6));
    env.client(1, 1).get_to_file(&uri, env.path("out2")).await.unwrap_err();
    write_pattern_file(&env.path("f"), 4, 1_000_000);
    env.proxy.set(Mode::Pass);
    env.client(1, 4).put_file(env.path("f"), &uri, &PutOptions::default()).await.unwrap();
    env.proxy.set(Mode::Pass);
    env.client(1, 1).get_to_file(&uri, env.path("out2")).await.unwrap();
    assert_eq!(env.proxy.chunk_gets.load(SeqCst), 16, "stale part file not reused");
    assert_eq!(hash_file(&env.path("out2")), hash_file(&env.path("f")));
}

#[tokio::test]
async fn small_objects_are_read_in_one_request() {
    let env = setup().await;
    let c = env.client(1, 4);
    let uri = u("near://alice.near/note.txt");
    c.put(&uri, b"tiny file", &PutOptions::default()).await.unwrap();
    env.proxy.set(Mode::Pass);
    let mut out = vec![];
    c.get_to_writer(&uri, &mut out).await.unwrap();
    assert_eq!(out, b"tiny file");
    assert_eq!(env.proxy.requests.load(SeqCst), 1, "locate inlines the chunk");
    let loc = c.locate(&uri).await.unwrap().unwrap();
    assert!(loc.chunks.iter().all(|ch| ch.data.is_some() && ch.url.is_none()));
}
