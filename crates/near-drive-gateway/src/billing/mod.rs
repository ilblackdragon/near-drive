//! Billing (DESIGN.md §6, phase 1: NEAR AI Cloud credits).
//!
//! - [`meter`]: tails `usage.jsonl` into per-payer stored bytes and closed
//!   hourly windows (storage GiB-hours, egress GiB, requests), persisted durably.
//! - reporter: every `report_interval_secs`, sends due outbox lines to the
//!   [`settle::Settlement`] backend, with exponential backoff per line and a
//!   dead-letter log for lines that can never be accepted.
//! - [`gate`]: refuses chunk uploads, record puts that grow storage, and egress
//!   with 402 when the payer cannot pay.
//!
//! Disabled unless the gateway config has a `billing` section.
pub mod cloud;
pub mod gate;
pub mod meter;
pub mod settle;

use crate::ApiError;
use axum::http::StatusCode;
use gate::{CreditGate, Decision, GateTimings};
use meter::Meter;
use near_drive_core::policy::Rule;
use serde::{Deserialize, Serialize};
use serde_json::json;
use settle::{Outcome, Settlement};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementKind {
    /// Report to cloud-api `POST /v1/internal/service-usage`.
    CloudCredits,
    /// Log lines and drop them (dev); the credit gate is off.
    Log,
}

/// `billing` section of the gateway config.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingConfig {
    /// cloud-api base URL, e.g. `https://cloud-api.near.ai`.
    #[serde(default)]
    pub cloud_api_url: String,
    /// Env var holding cloud-api's `CLOUD_API_STORAGE_BILLING_TOKEN`.
    #[serde(default = "d_token_env")]
    pub token_env: String,
    /// Stable, unique id of this gateway; part of every idempotency key.
    #[serde(default = "d_gateway_id")]
    pub gateway_id: String,
    #[serde(default = "d_settlement")]
    pub settlement: SettlementKind,
    #[serde(default = "d_report_interval")]
    pub report_interval_secs: u64,
    /// How often the usage log is read and due windows are closed.
    #[serde(default = "d_meter_interval")]
    pub meter_interval_secs: u64,
    /// Billing window; must divide a day. Default one hour.
    #[serde(default = "d_window")]
    pub window_secs: u64,
    /// A window closes this long after it ends, so in-flight requests land in it.
    #[serde(default = "d_grace")]
    pub close_grace_secs: u64,
    /// Refuse writes/egress for payers that cannot pay (402).
    #[serde(default = "d_true")]
    pub credit_gate: bool,
    #[serde(default = "d_status_cache")]
    pub status_cache_secs: u64,
    #[serde(default = "d_negative_cache")]
    pub negative_cache_secs: u64,
    /// Reuse the last billing-status answer this long while cloud-api is down.
    #[serde(default = "d_stale")]
    pub stale_status_max_secs: u64,
    /// With no usable answer: allow (true, default) or refuse with 503 (false).
    #[serde(default = "d_true")]
    pub fail_open: bool,
    #[serde(default = "d_timeout")]
    pub request_timeout_secs: u64,
    #[serde(default = "d_max_backoff")]
    pub max_backoff_secs: u64,
    /// A line still failing transiently after this long is dead-lettered.
    #[serde(default = "d_dead_letter")]
    pub dead_letter_after_secs: u64,
}

fn d_token_env() -> String {
    "NEAR_DRIVE_CLOUD_API_TOKEN".into()
}
fn d_gateway_id() -> String {
    "gateway".into()
}
fn d_settlement() -> SettlementKind {
    SettlementKind::CloudCredits
}
fn d_report_interval() -> u64 {
    300
}
fn d_meter_interval() -> u64 {
    10
}
fn d_window() -> u64 {
    3600
}
fn d_grace() -> u64 {
    60
}
fn d_true() -> bool {
    true
}
fn d_status_cache() -> u64 {
    60
}
fn d_negative_cache() -> u64 {
    15
}
fn d_stale() -> u64 {
    3600
}
fn d_timeout() -> u64 {
    10
}
fn d_max_backoff() -> u64 {
    3600
}
fn d_dead_letter() -> u64 {
    7 * 86_400
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

pub struct Billing {
    cfg: BillingConfig,
    meter: Mutex<Meter>,
    settlement: Box<dyn Settlement>,
    gate: Option<CreditGate>,
    usage_log: PathBuf,
    state_path: PathBuf,
    dead_letter_path: PathBuf,
    /// Serializes report rounds.
    reporting: Mutex<()>,
}

impl Billing {
    /// Load state and build backends; does not start background tasks.
    pub fn open(cfg: &BillingConfig, data_dir: &Path) -> anyhow::Result<Self> {
        anyhow::ensure!(cfg.window_secs > 0 && 86_400 % cfg.window_secs == 0, "billing.window_secs must divide 86400");
        anyhow::ensure!(!cfg.gateway_id.is_empty() && !cfg.gateway_id.contains(':'), "billing.gateway_id must be non-empty without ':'");
        let (settlement, gate): (Box<dyn Settlement>, _) = match cfg.settlement {
            SettlementKind::Log => (Box::new(settle::LogSettlement), None),
            SettlementKind::CloudCredits => {
                anyhow::ensure!(!cfg.cloud_api_url.is_empty(), "billing.cloud_api_url is required for cloud_credits settlement");
                let token = std::env::var(&cfg.token_env)
                    .ok()
                    .filter(|t| !t.is_empty())
                    .ok_or_else(|| anyhow::anyhow!("billing: env var {} (cloud-api storage billing token) is not set", cfg.token_env))?;
                let api = cloud::CloudApi::new(&cfg.cloud_api_url, token, Duration::from_secs(cfg.request_timeout_secs))?;
                let gate = cfg.credit_gate.then(|| {
                    CreditGate::new(
                        api.clone(),
                        GateTimings {
                            ttl: Duration::from_secs(cfg.status_cache_secs),
                            negative_ttl: Duration::from_secs(cfg.negative_cache_secs),
                            stale_max: Duration::from_secs(cfg.stale_status_max_secs),
                            fail_open: cfg.fail_open,
                        },
                    )
                });
                (Box::new(settle::CloudCreditsSettlement { api }), gate)
            }
        };
        Self::with_settlement(cfg, data_dir, settlement, gate)
    }

    /// Like [`Billing::open`] with an explicit backend (e.g. the NEAR escrow settler).
    pub fn with_settlement(
        cfg: &BillingConfig,
        data_dir: &Path,
        settlement: Box<dyn Settlement>,
        gate: Option<CreditGate>,
    ) -> anyhow::Result<Self> {
        let dir = data_dir.join("billing");
        std::fs::create_dir_all(&dir)?;
        let state_path = dir.join("state.json");
        let meter = Meter::load_or_new(&state_path, &cfg.gateway_id, cfg.window_secs * 1000, now_ms())?;
        meter.save(&state_path)?;
        tracing::info!(settlement = settlement.name(), gateway_id = %cfg.gateway_id, gate = gate.is_some(), "billing enabled");
        Ok(Self {
            cfg: cfg.clone(),
            meter: Mutex::new(meter),
            settlement,
            gate,
            usage_log: data_dir.join("usage.jsonl"),
            state_path,
            dead_letter_path: dir.join("dead_letter.jsonl"),
            reporting: Mutex::new(()),
        })
    }

    /// Start the meter and reporter loops. They stop when the last `Arc` drops.
    pub fn spawn(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let every = Duration::from_secs(self.cfg.meter_interval_secs.max(1));
        spawn_loop(weak.clone(), every, |b| Box::pin(async move { b.meter_tick(now_ms()).await }));
        let every = Duration::from_secs(self.cfg.report_interval_secs.max(1));
        spawn_loop(weak, every, |b| Box::pin(async move { b.report_once(now_ms()).await.map(|_| ()) }));
    }

    /// Ingest new usage events and close due windows; persists on change.
    pub async fn meter_tick(&self, now: u64) -> anyhow::Result<()> {
        let mut m = self.meter.lock().await;
        let read = m.ingest_file(&self.usage_log)?;
        let closed = m.close_due(now, self.cfg.close_grace_secs * 1000);
        if read || closed {
            m.save(&self.state_path)?;
        }
        Ok(())
    }

    /// One report round: settle every due outbox line. Returns how many settled.
    pub async fn report_once(&self, now: u64) -> anyhow::Result<usize> {
        let _round = self.reporting.lock().await;
        let due: Vec<_> = {
            let m = self.meter.lock().await;
            m.state.outbox.iter().filter(|p| p.next_attempt_ms <= now).map(|p| p.line.clone()).collect()
        };
        if due.is_empty() {
            return Ok(0);
        }
        let mut settled = 0;
        for batch in due.chunks(100) {
            let outcomes = self.settlement.settle(batch).await;
            anyhow::ensure!(outcomes.len() == batch.len(), "settlement returned {} outcomes for {} lines", outcomes.len(), batch.len());
            let mut dead = vec![];
            {
                let mut m = self.meter.lock().await;
                for (line, outcome) in batch.iter().zip(outcomes) {
                    let Some(i) = m.state.outbox.iter().position(|p| p.line.idempotency_key == line.idempotency_key) else { continue };
                    match outcome {
                        Outcome::Settled => {
                            m.state.outbox.remove(i);
                            settled += 1;
                        }
                        Outcome::Rejected(why) => {
                            tracing::error!(key = %line.idempotency_key, "usage line rejected: {why}");
                            dead.push(json!({"line": m.state.outbox.remove(i).line, "error": why, "at_ms": now}));
                        }
                        Outcome::Retry(why) => {
                            let p = &mut m.state.outbox[i];
                            p.attempts += 1;
                            let first = *p.first_failure_ms.get_or_insert(now);
                            if now.saturating_sub(first) >= self.cfg.dead_letter_after_secs * 1000 {
                                tracing::error!(key = %line.idempotency_key, "usage line expired after retries: {why}");
                                dead.push(json!({"line": m.state.outbox.remove(i).line, "error": format!("expired: {why}"), "at_ms": now}));
                                continue;
                            }
                            let backoff = (5_000u64 << p.attempts.min(20)).min(self.cfg.max_backoff_secs * 1000);
                            p.next_attempt_ms = now + backoff;
                            p.last_error = Some(why);
                        }
                    }
                }
                // Dead letters first: a crash in between re-sends, never loses a line.
                if !dead.is_empty() {
                    append_jsonl(&self.dead_letter_path, &dead)?;
                }
                m.save(&self.state_path)?;
            }
        }
        Ok(settled)
    }

    /// Lines not yet settled (for tests and ops).
    pub async fn pending(&self) -> Vec<meter::PendingLine> {
        self.meter.lock().await.state.outbox.clone()
    }

    async fn gate(&self, payers: &[String]) -> Result<(), ApiError> {
        let Some(gate) = &self.gate else { return Ok(()) };
        let mut denied = None;
        for payer in payers {
            match gate.check(payer).await {
                Decision::Allow => return Ok(()),
                Decision::Deny { reason } => denied = Some((payer, reason)),
                Decision::Unavailable => {
                    return Err(ApiError::with(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "billing status is unavailable; retry later",
                        json!({"code": "billing_unavailable", "payer": payer}),
                    ))
                }
            }
        }
        let Some((payer, reason)) = denied else { return Ok(()) };
        let message = if reason == "unknown_account" {
            format!("payment required: payer {payer} has no NEAR AI Cloud account; sign in at NEAR AI Cloud with this account and add credits")
        } else {
            format!("payment required: payer {payer} has no remaining NEAR AI Cloud credits ({reason})")
        };
        Err(ApiError::with(StatusCode::PAYMENT_REQUIRED, message, json!({"code": "payment_required", "payer": payer, "reason": reason})))
    }
}

fn spawn_loop<F>(weak: Weak<Billing>, every: Duration, f: F)
where
    F: Fn(Arc<Billing>) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>> + Send + 'static,
{
    tokio::spawn(async move {
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Some(b) = weak.upgrade() else { break };
            if let Err(e) = f(b).await {
                tracing::error!("billing task failed: {e:#}");
            }
        }
    });
}

fn append_jsonl(path: &Path, rows: &[serde_json::Value]) -> anyhow::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    for r in rows {
        let mut line = serde_json::to_vec(r)?;
        line.push(b'\n');
        f.write_all(&line)?;
    }
    f.sync_all()?;
    Ok(())
}

/// Payers a chunk upload could be billed to: the namespace owner, or the payer
/// of each rule the signer may write under (`{account}` bound to the signer).
/// Chunks carry no path, so the gate passes if any of them can pay.
pub fn chunk_payers(namespace: &str, rules: &[Rule], signer: &str) -> Vec<String> {
    if signer == namespace {
        return vec![namespace.to_string()];
    }
    let mut out: Vec<String> = rules
        .iter()
        .filter(|r| r.write.iter().any(|e| e == "*" || e == signer || (e == "{account}" && r.prefix.contains("{account}"))))
        .map(|r| r.payer.as_deref().map(|p| p.replace("{account}", signer)).unwrap_or_else(|| namespace.to_string()))
        .collect();
    out.dedup();
    if out.is_empty() {
        out.push(namespace.to_string());
    }
    out
}

/// Gate one payer (record put, egress). No-op when billing is off.
pub async fn check(billing: Option<&Billing>, payer: &str) -> Result<(), ApiError> {
    match billing {
        Some(b) => b.gate(&[payer.to_string()]).await,
        None => Ok(()),
    }
}

/// Gate a chunk upload.
pub async fn check_chunk(billing: Option<&Billing>, namespace: &str, rules: &[Rule], signer: &str) -> Result<(), ApiError> {
    match billing {
        Some(b) => b.gate(&chunk_payers(namespace, rules, signer)).await,
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_payers_follow_writable_rules() {
        let rules: Vec<Rule> = serde_json::from_str(
            r#"[{"prefix":"users/{account}/","read":["{account}"],"write":["{account}","app.near"],"payer":"app.near"},
                {"prefix":"inbox/","write":["bob.near"]},
                {"prefix":"public/","read":["*"],"write":[]}]"#,
        )
        .unwrap();
        assert_eq!(chunk_payers("app.near", &rules, "app.near"), vec!["app.near"]);
        assert_eq!(chunk_payers("app.near", &rules, "bob.near"), vec!["app.near".to_string()]);
        assert_eq!(chunk_payers("app.near", &rules, "eve.near"), vec!["app.near".to_string()]);
        let user_pays: Vec<Rule> =
            serde_json::from_str(r#"[{"prefix":"users/{account}/","write":["{account}"],"payer":"{account}"}]"#).unwrap();
        assert_eq!(chunk_payers("app.near", &user_pays, "bob.near"), vec!["bob.near".to_string()]);
    }

    #[test]
    fn config_defaults_and_unknown_fields() {
        let c: BillingConfig = serde_json::from_str(r#"{"cloud_api_url":"http://x"}"#).unwrap();
        assert_eq!((c.report_interval_secs, c.window_secs, c.status_cache_secs, c.fail_open), (300, 3600, 60, true));
        assert_eq!(c.settlement, SettlementKind::CloudCredits);
        assert!(serde_json::from_str::<BillingConfig>(r#"{"cloud_api_url":"http://x","typo":1}"#).is_err());
    }
}
