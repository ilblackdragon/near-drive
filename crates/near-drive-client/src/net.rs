//! Network behaviour: timeouts and retries for every gateway request.
//!
//! - Connections: connect timeout, TCP keepalive, pooled keep-alive reuse.
//! - Each request gets a deadline that grows with its size
//!   (`base_timeout + bytes / min_throughput`), plus an idle (no bytes read)
//!   timeout, so a stalled connection fails fast and a slow but moving one is
//!   not cut off.
//! - Transient failures (connection errors, timeouts, truncated bodies, 5xx,
//!   408, 429) are retried with full-jitter exponential backoff, honouring
//!   `Retry-After`. Each attempt is signed afresh.
//!
//! Chunk transfers are idempotent (content-addressed), so they retry freely.
//! The record commit is the only non-idempotent write; see `commit_manifest`.
use crate::GatewayError;
use anyhow::Result;
use reqwest::{Response, StatusCode};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct NetConfig {
    /// Attempts per request (1 = no retries).
    pub attempts: u32,
    /// First backoff; doubles per attempt (full jitter), capped at `max_delay`.
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub connect_timeout: Duration,
    /// Fail a request when no bytes arrive for this long.
    pub idle_timeout: Duration,
    /// Deadline for a request moving no payload.
    pub base_timeout: Duration,
    /// Slowest acceptable transfer rate (bytes/s); sets the deadline of large requests.
    pub min_throughput: u64,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            attempts: 8,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
            base_timeout: Duration::from_secs(30),
            min_throughput: 64 * 1024,
        }
    }
}

impl NetConfig {
    pub(crate) fn http_client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .connect_timeout(self.connect_timeout)
            .read_timeout(self.idle_timeout)
            .tcp_keepalive(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .expect("http client")
    }

    /// Deadline for a request that moves `bytes` of payload (either direction).
    pub(crate) fn timeout_for(&self, bytes: u64) -> Duration {
        self.base_timeout + Duration::from_secs_f64(bytes as f64 / self.min_throughput.max(1) as f64)
    }

    /// Full-jitter backoff before retry number `attempt` (0-based), at least `floor`.
    pub(crate) fn delay(&self, attempt: u32, floor: Option<Duration>) -> Duration {
        let cap = self.base_delay.saturating_mul(1u32 << attempt.min(16)).min(self.max_delay);
        let jitter = cap.mul_f64(rand::random::<f64>());
        floor.map_or(jitter, |f| jitter.max(f.min(self.max_delay * 4)))
    }
}

/// Outcome of one attempt.
pub(crate) enum Attempt<T> {
    Done(T),
    /// Transient; `Some(d)`: the server asked to wait at least `d`.
    Retry(anyhow::Error, Option<Duration>),
    Fatal(anyhow::Error),
}

pub(crate) fn retryable_status(s: StatusCode) -> bool {
    s.is_server_error() || s == StatusCode::TOO_MANY_REQUESTS || s == StatusCode::REQUEST_TIMEOUT
}

fn retry_after(resp: &Response) -> Option<Duration> {
    let v = resp.headers().get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    v.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// Turn a non-success response into a retry or a fatal [`GatewayError`].
pub(crate) async fn reject<T>(resp: Response) -> Attempt<T> {
    let status = resp.status();
    let wait = retry_after(&resp);
    let body = resp.text().await.unwrap_or_default();
    let e: anyhow::Error = GatewayError { status: status.as_u16(), body }.into();
    if retryable_status(status) {
        Attempt::Retry(e, wait)
    } else {
        Attempt::Fatal(e)
    }
}

/// Transport errors (connect, timeout, reset, truncated body) are transient.
pub(crate) fn transport<T>(e: anyhow::Error) -> Attempt<T> {
    Attempt::Retry(e, None)
}

/// Run `f(attempt)` until it is done, fatal, or out of attempts.
pub(crate) async fn with_retries<T, F, Fut>(cfg: &NetConfig, what: &str, mut f: F) -> Result<T>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Attempt<T>>,
{
    let attempts = cfg.attempts.max(1);
    let mut attempt = 0;
    loop {
        match f(attempt).await {
            Attempt::Done(v) => return Ok(v),
            Attempt::Fatal(e) => return Err(e),
            Attempt::Retry(e, wait) => {
                if attempt + 1 >= attempts {
                    crate::debug(&format!("{what}: giving up after {attempts} attempts"));
                    return Err(e);
                }
                let d = cfg.delay(attempt, wait);
                crate::debug(&format!("{what}: {e:#}; retry {} in {d:?}", attempt + 1));
                tokio::time::sleep(d).await;
                attempt += 1;
            }
        }
    }
}

/// Shorthand for "this response must be a success".
pub(crate) async fn ok_or_attempt(r: Result<Response>) -> Attempt<Response> {
    match r {
        Ok(resp) if resp.status().is_success() => Attempt::Done(resp),
        Ok(resp) => reject(resp).await,
        Err(e) => transport(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delays_are_capped_and_jittered() {
        let c = NetConfig { base_delay: Duration::from_millis(100), max_delay: Duration::from_secs(1), ..Default::default() };
        for a in 0..30 {
            assert!(c.delay(a, None) <= Duration::from_secs(1));
        }
        assert!(c.delay(0, Some(Duration::from_secs(2))) >= Duration::from_secs(2), "Retry-After is a floor");
        assert_eq!(c.timeout_for(0), c.base_timeout);
        assert_eq!(c.timeout_for(64 * 1024 * 10), c.base_timeout + Duration::from_secs(10));
    }
}
