//! Credit gate: refuse writes and egress for payers that cannot pay.
//!
//! Answers come from cloud-api `billing-status` and are cached per payer:
//! `status_cache_secs` (default 60) while the payer can pay, and
//! `negative_cache_secs` (default 15) once it cannot, so a top-up unlocks writes
//! quickly. If cloud-api is unreachable, the last answer is reused for up to
//! `stale_status_max_secs`; after that `fail_open` decides.
use super::cloud::{BillingStatus, CloudApi};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// The payer cannot pay (`reason` from cloud-api, e.g. `limit_exceeded`).
    Deny { reason: String },
    /// No usable answer and the gate fails closed.
    Unavailable,
}

pub struct GateTimings {
    pub ttl: Duration,
    pub negative_ttl: Duration,
    pub stale_max: Duration,
    pub fail_open: bool,
}

pub struct CreditGate {
    api: CloudApi,
    t: GateTimings,
    cache: Mutex<HashMap<String, (BillingStatus, Instant)>>,
}

fn decide(s: &BillingStatus) -> Decision {
    if s.can_charge {
        Decision::Allow
    } else {
        Decision::Deny { reason: s.reason.clone() }
    }
}

impl CreditGate {
    pub fn new(api: CloudApi, t: GateTimings) -> Self {
        Self { api, t, cache: Mutex::new(HashMap::new()) }
    }

    pub async fn check(&self, payer: &str) -> Decision {
        let cached = self.cache.lock().await.get(payer).cloned();
        if let Some((s, at)) = &cached {
            let ttl = if s.can_charge { self.t.ttl } else { self.t.negative_ttl };
            if at.elapsed() < ttl {
                return decide(s);
            }
        }
        match self.api.billing_status(payer).await {
            Ok(s) => {
                let d = decide(&s);
                let mut cache = self.cache.lock().await;
                if cache.len() > 100_000 {
                    let max = self.t.ttl.max(self.t.negative_ttl);
                    cache.retain(|_, (_, at)| at.elapsed() < max);
                }
                cache.insert(payer.to_string(), (s, Instant::now()));
                d
            }
            Err(e) => {
                tracing::warn!(payer, "billing-status unavailable: {e:#}");
                match cached {
                    Some((s, at)) if at.elapsed() < self.t.stale_max => decide(&s),
                    _ if self.t.fail_open => Decision::Allow,
                    _ => Decision::Unavailable,
                }
            }
        }
    }
}
