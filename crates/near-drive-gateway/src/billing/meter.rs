//! Metering aggregator: turns the gateway's JSONL usage log into closed,
//! per-payer billing windows.
//!
//! The usage log (`usage.jsonl`) is the source of truth. The meter tails it by
//! byte offset and keeps, per payer, the live stored bytes (put adds `bytes` and
//! releases `replaced_bytes`; delete releases `bytes`) and the current window's
//! accumulators: stored byte-milliseconds, egress bytes and request count. When a
//! window closes, each payer's totals become [`UsageLine`]s in the outbox.
//!
//! Exactly-once: the log offset, the accumulators and the outbox are saved
//! together, atomically (write-then-rename), so after a crash the meter resumes
//! from the last saved offset with matching accumulators, and every window is
//! closed exactly once with a deterministic idempotency key. Sub-unit remainders
//! (below 0.001 GiB-hour or 0.001 GiB) carry over to the next window instead of
//! being rounded away.
//!
//! Limits: a meter must see every event that touches a payer's bytes, so one
//! meter consumes one gateway's log and gateways sharing payers need distinct
//! `gateway_id`s and a common index (a put through gateway A deleted through
//! gateway B releases bytes A never saw: B saturates at zero, A keeps billing).
//! Merging logs across gateways is future work.
use super::settle::{Service, UsageLine};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

const GIB: u128 = 1 << 30;
const HOUR_MS: u128 = 3_600_000;
/// Largest quantity per line: cloud-api stores milli-units in an `INTEGER`.
pub const MAX_LINE_MILLI: u64 = i32::MAX as u64;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PayerState {
    pub live_bytes: u64,
    /// Storage is integrated up to here.
    pub last_ms: u64,
    /// Current window: stored bytes × ms.
    pub byte_ms: u128,
    pub egress_bytes: u64,
    pub requests: u64,
    /// Carried remainders, in (byte-ms × 1000) and (bytes × 1000).
    pub rem_storage: u128,
    pub rem_egress: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PendingLine {
    pub line: UsageLine,
    pub attempts: u32,
    pub next_attempt_ms: u64,
    #[serde(default)]
    pub first_failure_ms: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MeterState {
    pub version: u32,
    /// Bytes of `usage.jsonl` consumed.
    pub log_offset: u64,
    /// Usage before this instant only sets live bytes; nothing earlier is billed.
    pub billing_start_ms: u64,
    pub window_start_ms: u64,
    pub payers: BTreeMap<String, PayerState>,
    pub outbox: Vec<PendingLine>,
}

/// The subset of a usage event the meter reads (see `usage::Event`).
#[derive(Debug, Deserialize)]
pub struct LogEvent {
    pub ts_ms: u64,
    pub kind: String,
    pub payer: String,
    pub bytes: u64,
    #[serde(default)]
    pub replaced_bytes: Option<u64>,
}

pub struct Meter {
    pub state: MeterState,
    pub gateway_id: String,
    pub window_ms: u64,
}

impl Meter {
    pub fn new(gateway_id: &str, window_ms: u64, now_ms: u64) -> Self {
        Self {
            state: MeterState {
                version: 1,
                log_offset: 0,
                billing_start_ms: now_ms,
                window_start_ms: now_ms / window_ms * window_ms,
                payers: BTreeMap::new(),
                outbox: vec![],
            },
            gateway_id: gateway_id.to_string(),
            window_ms,
        }
    }

    pub fn load_or_new(path: &Path, gateway_id: &str, window_ms: u64, now_ms: u64) -> anyhow::Result<Self> {
        match std::fs::read(path) {
            Ok(b) => {
                let state: MeterState = serde_json::from_slice(&b)?;
                anyhow::ensure!(
                    state.window_start_ms.is_multiple_of(window_ms),
                    "billing window_secs changed while windows are open; restore it or move the state file aside"
                );
                Ok(Self { state, gateway_id: gateway_id.to_string(), window_ms })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::new(gateway_id, window_ms, now_ms)),
            Err(e) => Err(e.into()),
        }
    }

    /// Atomic, durable save: write a temp file, fsync, rename, fsync the dir.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let dir = path.parent().expect("state path has a parent");
        std::fs::create_dir_all(dir)?;
        let tmp = path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            std::io::Write::write_all(&mut f, &serde_json::to_vec(&self.state)?)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    fn window_end(&self) -> u64 {
        self.state.window_start_ms + self.window_ms
    }

    /// Read complete new lines from the usage log. Returns whether anything was consumed.
    pub fn ingest_file(&mut self, log: &Path) -> anyhow::Result<bool> {
        let mut f = match std::fs::File::open(log) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        let len = f.metadata()?.len();
        if len < self.state.log_offset {
            tracing::error!(offset = self.state.log_offset, len, "usage log shrank (rotated?); restarting from its beginning");
            self.state.log_offset = 0;
        }
        if len == self.state.log_offset {
            return Ok(false);
        }
        f.seek(SeekFrom::Start(self.state.log_offset))?;
        let mut buf = Vec::with_capacity((len - self.state.log_offset) as usize);
        f.take(len - self.state.log_offset).read_to_end(&mut buf)?;
        // Only complete lines: a partially written last line is read next time.
        let Some(end) = buf.iter().rposition(|&b| b == b'\n') else { return Ok(false) };
        for line in buf[..end].split(|&b| b == b'\n') {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            match serde_json::from_slice::<LogEvent>(line) {
                Ok(ev) => self.apply(&ev),
                Err(e) => tracing::error!("skipping malformed usage event: {e}"),
            }
        }
        self.state.log_offset += end as u64 + 1;
        Ok(true)
    }

    /// Apply one event. Events past the open window close it first; events from
    /// an already closed window count in the open one.
    pub fn apply(&mut self, ev: &LogEvent) {
        while ev.ts_ms >= self.window_end() && ev.ts_ms >= self.state.billing_start_ms {
            self.close_window();
        }
        let billable = ev.ts_ms >= self.state.billing_start_ms;
        let t = ev.ts_ms.max(self.state.window_start_ms).max(self.state.billing_start_ms);
        let p = self.state.payers.entry(ev.payer.clone()).or_insert_with(|| PayerState { last_ms: t, ..Default::default() });
        integrate(p, t);
        match ev.kind.as_str() {
            "put" => {
                p.live_bytes = p.live_bytes.saturating_add(ev.bytes).saturating_sub(ev.replaced_bytes.unwrap_or(0));
            }
            "delete" => p.live_bytes = p.live_bytes.saturating_sub(ev.bytes),
            "egress" if billable => p.egress_bytes = p.egress_bytes.saturating_add(ev.bytes),
            "egress" => {}
            other => {
                tracing::warn!("ignoring unknown usage event kind {other:?}");
                return;
            }
        }
        if billable {
            p.requests += 1;
        }
    }

    /// Close every window that ended at least `grace_ms` before `now_ms`.
    pub fn close_due(&mut self, now_ms: u64, grace_ms: u64) -> bool {
        let mut closed = false;
        while now_ms >= self.window_end() + grace_ms {
            self.close_window();
            closed = true;
        }
        closed
    }

    fn close_window(&mut self) {
        let (start, end) = (self.state.window_start_ms, self.window_end());
        let mut lines = vec![];
        self.state.payers.retain(|payer, p| {
            integrate(p, end);
            let storage = std::mem::take(&mut p.byte_ms) * 1000 + p.rem_storage;
            let storage_unit = GIB * HOUR_MS;
            p.rem_storage = storage % storage_unit;
            let egress = u128::from(std::mem::take(&mut p.egress_bytes)) * 1000 + p.rem_egress;
            p.rem_egress = egress % GIB;
            let requests = u128::from(std::mem::take(&mut p.requests)) * 1000;
            for (service, q) in [
                (Service::StorageGibHour, storage / storage_unit),
                (Service::EgressGib, egress / GIB),
                (Service::Requests, requests),
            ] {
                lines.push((payer.clone(), service, u64::try_from(q).unwrap_or(u64::MAX)));
            }
            p.live_bytes > 0 || p.rem_storage > 0 || p.rem_egress > 0
        });
        for (payer, service, mut q) in lines {
            let base = format!("near-drive:{}:{}:{}:{}", self.gateway_id, payer, super::cloud::rfc3339(start), service.catalog_name());
            let mut part = 0;
            while q > 0 {
                let take = q.min(MAX_LINE_MILLI);
                q -= take;
                let idempotency_key = if part == 0 { base.clone() } else { format!("{base}#{part}") };
                part += 1;
                self.state.outbox.push(PendingLine {
                    line: UsageLine {
                        idempotency_key,
                        gateway_id: self.gateway_id.clone(),
                        payer: payer.clone(),
                        service,
                        quantity_milli: take,
                        period_start_ms: start,
                        period_end_ms: end,
                    },
                    attempts: 0,
                    next_attempt_ms: 0,
                    first_failure_ms: None,
                    last_error: None,
                });
            }
        }
        self.state.window_start_ms = end;
    }
}

fn integrate(p: &mut PayerState, to_ms: u64) {
    if to_ms > p.last_ms {
        p.byte_ms += u128::from(p.live_bytes) * u128::from(to_ms - p.last_ms);
        p.last_ms = to_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: u64 = 3_600_000;
    const G: u64 = 1 << 30;

    fn ev(ts_ms: u64, kind: &str, payer: &str, bytes: u64, replaced: Option<u64>) -> LogEvent {
        LogEvent { ts_ms, kind: kind.into(), payer: payer.into(), bytes, replaced_bytes: replaced }
    }

    fn lines(m: &Meter) -> Vec<(String, Service, u64, u64)> {
        m.state.outbox.iter().map(|p| (p.line.payer.clone(), p.line.service, p.line.quantity_milli, p.line.period_start_ms)).collect()
    }

    #[test]
    fn storage_is_integrated_per_window_and_replacements_release_bytes() {
        let t0 = 100 * H;
        let mut m = Meter::new("gw", H, t0);
        // 1 GiB stored at t0, replaced by 2 GiB at t0+30min, deleted at t0+1h+15min.
        m.apply(&ev(t0, "put", "a.near", G, Some(0)));
        m.apply(&ev(t0 + H / 2, "put", "a.near", 2 * G, Some(G)));
        m.apply(&ev(t0 + H + H / 4, "delete", "a.near", 2 * G, None));
        // First window: 0.5 GiB-h + 1 GiB-h = 1.5; 2 requests.
        assert_eq!(
            lines(&m),
            vec![("a.near".into(), Service::StorageGibHour, 1500, t0), ("a.near".into(), Service::Requests, 2000, t0)]
        );
        assert!(m.close_due(t0 + 2 * H + 60_000, 60_000));
        // Second window: 2 GiB for 15 min = 0.5 GiB-h; 1 request. Payer then dropped (no bytes, no remainder).
        assert_eq!(lines(&m)[2..], [("a.near".into(), Service::StorageGibHour, 500, t0 + H), ("a.near".into(), Service::Requests, 1000, t0 + H)]);
        assert!(m.state.payers.is_empty());
    }

    #[test]
    fn egress_and_requests_are_attributed_to_the_payer() {
        let t0 = 5 * H;
        let mut m = Meter::new("gw", H, t0);
        m.apply(&ev(t0 + 1, "egress", "app.near", G / 4, None));
        m.apply(&ev(t0 + 2, "egress", "app.near", G / 4, None));
        m.apply(&ev(t0 + 3, "egress", "bob.near", 10, None));
        m.close_due(t0 + H, 0);
        let l = lines(&m);
        assert!(l.contains(&("app.near".into(), Service::EgressGib, 500, t0)), "{l:?}");
        assert!(l.contains(&("app.near".into(), Service::Requests, 2000, t0)));
        // 10 bytes is below 0.001 GiB: carried, not billed yet.
        assert!(!l.iter().any(|x| x.0 == "bob.near" && x.1 == Service::EgressGib));
        assert_eq!(m.state.payers["bob.near"].rem_egress, 10_000);
    }

    #[test]
    fn sub_unit_remainders_carry_over_windows() {
        let t0 = 10 * H;
        let mut m = Meter::new("gw", H, t0);
        // 1 MiB stored: 1/1024 GiB-h per hour, i.e. 0.98 milli-units per window.
        m.apply(&ev(t0, "put", "s.near", 1 << 20, Some(0)));
        m.close_due(t0 + 1024 * H, 0);
        let total: u64 = m.state.outbox.iter().filter(|p| p.line.service == Service::StorageGibHour).map(|p| p.line.quantity_milli).sum();
        // 1024 hours of 1 MiB = 1 GiB-h exactly, despite every window being < 1 milli-unit.
        assert_eq!(total, 1000);
        assert_eq!(m.state.payers["s.near"].rem_storage, 0);
    }

    #[test]
    fn events_before_billing_start_set_bytes_but_bill_nothing() {
        let start = 50 * H + H / 2;
        let mut m = Meter::new("gw", H, start);
        m.apply(&ev(start - 10 * H, "put", "old.near", G, Some(0)));
        m.apply(&ev(start - 5 * H, "egress", "old.near", G, None));
        m.close_due(start + H / 2, 0);
        // Billing covers only [start, window end): 0.5 GiB-h, no egress, no requests.
        assert_eq!(lines(&m), vec![("old.near".into(), Service::StorageGibHour, 500, 50 * H)]);
    }

    #[test]
    fn late_events_count_in_the_open_window_and_keys_are_deterministic() {
        let t0 = 7 * H;
        let mut m = Meter::new("gw1", H, t0);
        m.close_due(t0 + H, 0);
        m.apply(&ev(t0 + 5, "egress", "late.near", G, None));
        m.close_due(t0 + 2 * H, 0);
        let l = &m.state.outbox[0].line;
        assert_eq!(l.period_start_ms, t0 + H);
        assert_eq!(l.idempotency_key, "near-drive:gw1:late.near:1970-01-01T08:00:00Z:storage_egress_gib");
    }

    #[test]
    fn oversized_quantities_split_into_lines_with_distinct_keys() {
        let t0 = 3 * H;
        let mut m = Meter::new("gw", H, t0);
        // 3 PiB for one hour = 3,145,728 GiB-h > the 2,147,483 GiB-h line cap.
        m.apply(&ev(t0, "put", "big.near", 3 << 50, Some(0)));
        m.close_due(t0 + H, 0);
        let parts: Vec<_> = m.state.outbox.iter().filter(|p| p.line.service == Service::StorageGibHour).collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts.iter().map(|p| p.line.quantity_milli).sum::<u64>(), 3_145_728_000);
        assert!(parts[1].line.idempotency_key.ends_with("#1"));
    }

    #[test]
    fn ingest_reads_complete_lines_and_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("usage.jsonl");
        let state = dir.path().join("billing/state.json");
        let t0 = 20 * H;
        let line = |ts: u64, kind: &str, bytes: u64| format!(r#"{{"ts_ms":{ts},"kind":"{kind}","namespace":"n","path":"p","signer":"s","payer":"p.near","bytes":{bytes},"replaced_bytes":0}}"#);
        std::fs::write(&log, format!("{}\n{}", line(t0, "put", G), &line(t0 + 1, "put", G)[..20])).unwrap();
        let mut m = Meter::new("gw", H, t0);
        assert!(m.ingest_file(&log).unwrap());
        assert_eq!(m.state.payers["p.near"].live_bytes, G, "partial line must not be applied");
        m.save(&state).unwrap();

        // Finish the partial line, restart from the saved state, ingest again.
        std::fs::write(&log, format!("{}\n{}\n", line(t0, "put", G), line(t0 + 1, "put", G))).unwrap();
        let mut m2 = Meter::load_or_new(&state, "gw", H, t0 + 999).unwrap();
        assert_eq!(m2.state.billing_start_ms, t0, "restart keeps the original billing start");
        assert!(m2.ingest_file(&log).unwrap());
        assert!(!m2.ingest_file(&log).unwrap(), "nothing new");
        assert_eq!(m2.state.payers["p.near"].live_bytes, 2 * G);
        assert_eq!(m2.state.payers["p.near"].requests, 2);
    }
}
