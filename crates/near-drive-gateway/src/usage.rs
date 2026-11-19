//! Usage events for billing. v0 appends JSONL; a metering job aggregates
//! into storage GiB-hours / egress GiB / requests and reports to NEAR AI
//! Cloud (see DESIGN.md §6).
use serde::Serialize;
use std::path::PathBuf;
use tokio::{io::AsyncWriteExt, sync::Mutex};

#[derive(Debug, Serialize)]
pub struct Event {
    pub ts_ms: u64,
    pub kind: &'static str,
    pub namespace: String,
    pub path: String,
    pub signer: String,
    pub payer: String,
    /// put: new stored bytes; delete: released bytes; egress: bytes served.
    pub bytes: u64,
    /// put only: stored bytes of the replaced version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaced_bytes: Option<u64>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

impl Event {
    fn new(kind: &'static str, ns: &str, path: &str, signer: &str, payer: &str, bytes: u64) -> Self {
        Self { ts_ms: now_ms(), kind, namespace: ns.into(), path: path.into(), signer: signer.into(), payer: payer.into(), bytes, replaced_bytes: None }
    }
    pub fn put(ns: &str, path: &str, signer: &str, payer: &str, bytes: u64, replaced: u64) -> Self {
        Self { replaced_bytes: Some(replaced), ..Self::new("put", ns, path, signer, payer, bytes) }
    }
    pub fn egress(ns: &str, path: &str, signer: &str, payer: &str, bytes: u64) -> Self {
        Self::new("egress", ns, path, signer, payer, bytes)
    }
    pub fn delete(ns: &str, path: &str, signer: &str, payer: &str, bytes: u64) -> Self {
        Self::new("delete", ns, path, signer, payer, bytes)
    }
}

pub struct UsageSink {
    file: Mutex<tokio::fs::File>,
}

impl UsageSink {
    pub async fn open(path: PathBuf) -> anyhow::Result<Self> {
        let file = tokio::fs::OpenOptions::new().create(true).append(true).open(path).await?;
        Ok(Self { file: Mutex::new(file) })
    }
    pub async fn record(&self, e: Event) {
        let mut line = serde_json::to_vec(&e).expect("event serializes");
        line.push(b'\n');
        if let Err(err) = self.file.lock().await.write_all(&line).await {
            tracing::error!("failed to write usage event: {err}");
        }
    }
}
