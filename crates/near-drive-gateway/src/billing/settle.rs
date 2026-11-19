//! Settlement backends: where closed metering windows are sent.
//!
//! Phase 1 settles in NEAR AI Cloud credits ([`CloudCreditsSettlement`]). The
//! phase-2 NEAR escrow settler (`drive.near` `settle([{payer, amount, gateway,
//! period_id}])`) implements [`Settlement`] too: it prices each [`UsageLine`],
//! groups by `(payer, period_id)` and submits one call per batch, returning one
//! outcome per line.
use super::cloud::{CloudApi, PostError};
use std::{future::Future, pin::Pin};

/// A metered service (DESIGN.md §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    /// Stored bytes over time; quantity in milli-GiB-hours.
    StorageGibHour,
    /// Bytes served; quantity in milli-GiB.
    EgressGib,
    /// Billable requests (object puts, deletes, chunk reads); quantity in milli-requests (count × 1000).
    Requests,
}

impl Service {
    pub const ALL: [Service; 3] = [Service::StorageGibHour, Service::EgressGib, Service::Requests];

    /// cloud-api catalog name.
    pub fn catalog_name(self) -> &'static str {
        match self {
            Service::StorageGibHour => "storage_gib_hour",
            Service::EgressGib => "storage_egress_gib",
            Service::Requests => "storage_requests",
        }
    }
}

/// One closed window of one service for one payer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UsageLine {
    /// Deterministic: `near-drive:{gateway}:{payer}:{period_start}:{service}`.
    pub idempotency_key: String,
    pub gateway_id: String,
    pub payer: String,
    pub service: Service,
    /// Milli-units of the service's unit (requests: count × 1000).
    pub quantity_milli: u64,
    pub period_start_ms: u64,
    pub period_end_ms: u64,
}

impl UsageLine {
    /// Escrow period id: index of the window since the epoch.
    pub fn period_id(&self) -> u64 {
        self.period_start_ms / (self.period_end_ms - self.period_start_ms).max(1)
    }

    /// Decimal quantity in whole units, e.g. `"1.5"`.
    pub fn quantity_decimal(&self) -> String {
        let (int, frac) = (self.quantity_milli / 1000, self.quantity_milli % 1000);
        if frac == 0 {
            int.to_string()
        } else {
            format!("{int}.{}", format!("{frac:03}").trim_end_matches('0'))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Recorded (or already recorded under the same idempotency key).
    Settled,
    /// Transient: keep the line and retry later.
    Retry(String),
    /// Permanent: the line can never be accepted; it goes to the dead-letter log.
    Rejected(String),
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Settlement: Send + Sync {
    fn name(&self) -> &'static str;
    /// Settle `lines`; returns exactly one outcome per line, in order. Must be
    /// idempotent per `idempotency_key`: lines are resent after a crash.
    fn settle<'a>(&'a self, lines: &'a [UsageLine]) -> BoxFuture<'a, Vec<Outcome>>;
}

/// Logs lines and drops them. For dev gateways and dry runs.
pub struct LogSettlement;

impl Settlement for LogSettlement {
    fn name(&self) -> &'static str {
        "log"
    }
    fn settle<'a>(&'a self, lines: &'a [UsageLine]) -> BoxFuture<'a, Vec<Outcome>> {
        Box::pin(async move {
            for l in lines {
                tracing::info!(payer = %l.payer, service = l.service.catalog_name(), quantity = %l.quantity_decimal(), key = %l.idempotency_key, "usage line (log settlement)");
            }
            vec![Outcome::Settled; lines.len()]
        })
    }
}

/// NEAR AI Cloud credits via `POST /v1/internal/service-usage`.
pub struct CloudCreditsSettlement {
    pub api: CloudApi,
}

impl Settlement for CloudCreditsSettlement {
    fn name(&self) -> &'static str {
        "cloud_credits"
    }
    fn settle<'a>(&'a self, lines: &'a [UsageLine]) -> BoxFuture<'a, Vec<Outcome>> {
        Box::pin(async move {
            let mut out = Vec::with_capacity(lines.len());
            for l in lines {
                out.push(match self.api.post_service_usage(l).await {
                    Ok(()) => Outcome::Settled,
                    Err(PostError::Permanent(m)) => Outcome::Rejected(m),
                    Err(PostError::Transient(m)) => Outcome::Retry(m),
                });
            }
            out
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_and_period() {
        let l = |q| UsageLine {
            idempotency_key: "k".into(),
            gateway_id: "g".into(),
            payer: "p".into(),
            service: Service::StorageGibHour,
            quantity_milli: q,
            period_start_ms: 7_200_000,
            period_end_ms: 10_800_000,
        };
        assert_eq!(l(1500).quantity_decimal(), "1.5");
        assert_eq!(l(1).quantity_decimal(), "0.001");
        assert_eq!(l(2000).quantity_decimal(), "2");
        assert_eq!(l(1010).quantity_decimal(), "1.01");
        assert_eq!(l(1).period_id(), 2);
    }
}
