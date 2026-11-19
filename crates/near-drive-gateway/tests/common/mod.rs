//! Shared helpers for integration tests (gateway on a random local port).
#![allow(dead_code)]
use ed25519_dalek::SigningKey;
use near_drive_client::{near_drive_core::keys, Client};
use near_drive_gateway::{
    bridge::{reference_router, ReferenceBridge},
    placement::StorageConfig,
    router,
    store::FsBlobStore,
    AppState, Config,
};
use std::{collections::HashMap, path::PathBuf, sync::Arc};

pub struct Gw {
    pub url: String,
    pub data_dir: PathBuf,
}

pub fn dev_keys(accounts: &[&'static str]) -> (HashMap<&'static str, SigningKey>, HashMap<String, Vec<String>>) {
    let mut keys = HashMap::new();
    let mut dev = HashMap::new();
    for a in accounts {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        dev.insert(a.to_string(), vec![keys::format_public_key(&sk.verifying_key())]);
        keys.insert(*a, sk);
    }
    (keys, dev)
}

pub async fn start_gateway(data_dir: PathBuf, dev: HashMap<String, Vec<String>>, storage: serde_json::Value) -> Gw {
    let storage: StorageConfig = serde_json::from_value(storage).unwrap();
    let cfg = Config { listen: "127.0.0.1:0".into(), data_dir: data_dir.clone(), dev_keys: dev, storage, ..Default::default() };
    let state = AppState::new(cfg).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    Gw { url, data_dir }
}

/// Reference blob bridge on fs `dir`; returns its base URL.
pub async fn start_bridge(dir: PathBuf, token: Option<&str>, direct_urls: bool) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let rb = ReferenceBridge { store: Arc::new(FsBlobStore::new(dir)), token: token.map(str::to_string), public_base: direct_urls.then(|| base.clone()) };
    tokio::spawn(async move { axum::serve(listener, reference_router(rb)).await.unwrap() });
    base
}

pub fn client(url: &str, account: &str, sk: &SigningKey, root: Option<near_drive_client::near_drive_core::crypto::RootKey>) -> Client {
    Client::new(url, account, sk.clone(), root)
}

/// Deterministic pseudo-random bytes; `off` must be a multiple of 8.
pub fn pattern(seed: u64, off: u64, len: usize) -> Vec<u8> {
    assert_eq!(off % 8, 0);
    let mut out = Vec::with_capacity(len + 8);
    let mut i = off / 8;
    while out.len() < len {
        let mut x = seed ^ i.wrapping_mul(0x9E3779B97F4A7C15);
        x ^= x >> 29;
        x = x.wrapping_mul(0xBF58476D1CE4E5B9);
        x ^= x >> 32;
        out.extend_from_slice(&x.to_le_bytes());
        i += 1;
    }
    out.truncate(len);
    out
}

/// Write `size` pattern bytes to `path` in 1 MiB pieces; returns blake3 of the content.
pub fn write_pattern_file(path: &std::path::Path, seed: u64, size: u64) -> blake3::Hash {
    use std::io::Write;
    let mut f = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    let mut h = blake3::Hasher::new();
    let mut off = 0u64;
    while off < size {
        let n = (size - off).min(1 << 20) as usize;
        let b = pattern(seed, off, n);
        h.update(&b);
        f.write_all(&b).unwrap();
        off += n as u64;
    }
    f.flush().unwrap();
    h.finalize()
}

pub fn hash_file(path: &std::path::Path) -> blake3::Hash {
    let mut h = blake3::Hasher::new();
    h.update_reader(std::fs::File::open(path).unwrap()).unwrap();
    h.finalize()
}

/// Peak resident set size of this process (Linux), in bytes.
pub fn peak_rss() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = s.lines().find(|l| l.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse::<u64>().ok().map(|kb| kb * 1024)
}

/// Reset the peak RSS counter (Linux: write 5 to clear_refs).
pub fn reset_peak_rss() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

/// S3 test settings from env; None (test skipped) unless NEAR_DRIVE_TEST_S3_ENDPOINT is set.
/// Also: NEAR_DRIVE_TEST_S3_BUCKET (default `near-drive-test`, must exist),
/// NEAR_DRIVE_TEST_S3_ACCESS_KEY / NEAR_DRIVE_TEST_S3_SECRET_KEY (default minioadmin/minioadmin).
pub fn s3_env() -> Option<serde_json::Value> {
    let endpoint = std::env::var("NEAR_DRIVE_TEST_S3_ENDPOINT").ok()?;
    let var = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    Some(serde_json::json!({
        "type": "s3",
        "endpoint": endpoint,
        "bucket": var("NEAR_DRIVE_TEST_S3_BUCKET", "near-drive-test"),
        "access_key_id": var("NEAR_DRIVE_TEST_S3_ACCESS_KEY", "minioadmin"),
        "secret_access_key": var("NEAR_DRIVE_TEST_S3_SECRET_KEY", "minioadmin"),
        "allow_http": true,
        "region": "us-east-1"
    }))
}

/// `s3_env()` with a key prefix (unique per test run).
pub fn s3_with_prefix(base: &serde_json::Value, prefix: &str) -> serde_json::Value {
    let mut v = base.clone();
    v["prefix"] = serde_json::Value::String(prefix.to_string());
    v
}

pub fn run_id() -> String {
    format!("t{}-{}", now_ms(), rand::random::<u32>())
}
