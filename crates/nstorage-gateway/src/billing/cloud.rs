//! NEAR AI Cloud (cloud-api) client: `POST /v1/internal/service-usage` and
//! `GET /v1/internal/billing-status`, authenticated by the storage billing token.
use super::settle::UsageLine;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

#[derive(Clone)]
pub struct CloudApi {
    http: reqwest::Client,
    base: String,
    token: String,
}

#[derive(Debug)]
pub enum PostError {
    /// Retry later (network, 5xx, 401/429, 404 unknown account, ...).
    Transient(String),
    /// The request can never succeed (400 validation, 409 key conflict).
    Permanent(String),
}

/// `GET /v1/internal/billing-status` answer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BillingStatus {
    pub can_charge: bool,
    pub reason: String,
    #[serde(default)]
    pub remaining: Option<i64>,
}

impl CloudApi {
    pub fn new(base: &str, token: String, timeout: Duration) -> anyhow::Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder().timeout(timeout).build()?,
            base: base.trim_end_matches('/').to_string(),
            token,
        })
    }

    pub async fn post_service_usage(&self, line: &UsageLine) -> Result<(), PostError> {
        let body = json!({
            "near_account_id": line.payer,
            "service_name": line.service.catalog_name(),
            "quantity": line.quantity_decimal(),
            "idempotency_key": line.idempotency_key,
            "period_start": rfc3339(line.period_start_ms),
            "period_end": rfc3339(line.period_end_ms),
        });
        let resp = self
            .http
            .post(format!("{}/v1/internal/service-usage", self.base))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| PostError::Transient(format!("request failed: {e}")))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let text = resp.text().await.unwrap_or_default();
        let msg = format!("{status}: {}", text.chars().take(300).collect::<String>());
        match status.as_u16() {
            400 | 409 | 422 => Err(PostError::Permanent(msg)),
            _ => Err(PostError::Transient(msg)),
        }
    }

    pub async fn billing_status(&self, near_account_id: &str) -> anyhow::Result<BillingStatus> {
        let resp = self
            .http
            .get(format!("{}/v1/internal/billing-status", self.base))
            .bearer_auth(&self.token)
            .query(&[("near_account_id", near_account_id)])
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("billing-status returned {status}");
        }
        Ok(resp.json().await?)
    }
}

/// UTC RFC 3339 with second precision, e.g. `2026-11-19T01:00:00Z`.
pub fn rfc3339(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Howard Hinnant's days-to-civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    #[test]
    fn rfc3339_formats_utc() {
        assert_eq!(super::rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::rfc3339(1_763_514_000_000), "2025-11-19T01:00:00Z");
        assert_eq!(super::rfc3339(951_782_400_000), "2000-02-29T00:00:00Z");
    }
}
