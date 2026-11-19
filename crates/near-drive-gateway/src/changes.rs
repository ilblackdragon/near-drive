//! Change notifications: `GET /v1/watch/{ns}?prefix=&cursor=&timeout_ms=`.
//!
//! A long poll that returns as soon as an object under `prefix` is written
//! or deleted through this gateway, or after `timeout_ms` (max 60 s). Clients
//! (folder sync) use it instead of polling the listing.
//!
//! The gateway stays stateless: the change feed is in memory, per process,
//! and only covers writes through this gateway. A cursor names the process
//! (`<instance>:<n>`), so after a restart, or against another gateway, a
//! stale cursor answers "changed" and the client re-lists. Writes made through
//! other gateways are seen at the client's next timeout / periodic re-list.
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::Notify;

/// Changes remembered per namespace; an older cursor reads as "changed".
const RING: usize = 1024;
pub const MAX_WAIT: Duration = Duration::from_secs(60);

#[derive(Default)]
struct Ns {
    seq: u64,
    recent: VecDeque<(u64, String)>,
}

pub struct Hub {
    instance: String,
    inner: Mutex<HashMap<String, Ns>>,
    notify: Notify,
}

impl Default for Hub {
    fn default() -> Self {
        Self { instance: hex::encode(rand::random::<[u8; 8]>()), inner: Mutex::default(), notify: Notify::new() }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct WatchResult {
    pub cursor: String,
    pub changed: bool,
    /// Paths that changed (when known), so a client can skip a full re-list.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
}

impl Hub {
    pub fn record(&self, ns: &str, path: &str) {
        {
            let mut m = self.inner.lock().unwrap();
            let n = m.entry(ns.to_string()).or_default();
            n.seq += 1;
            let s = n.seq;
            n.recent.push_back((s, path.to_string()));
            if n.recent.len() > RING {
                n.recent.pop_front();
            }
        }
        self.notify.notify_waiters();
    }

    fn cursor(&self, ns: &str) -> String {
        format!("{}:{}", self.instance, self.inner.lock().unwrap().get(ns).map_or(0, |n| n.seq))
    }

    /// Changes under `prefix` after `cursor`: Some(paths) if any (empty paths
    /// = unknown, re-list), None if nothing yet.
    fn since(&self, ns: &str, prefix: &str, cursor: &str) -> Option<Vec<String>> {
        let Some((inst, n)) = cursor.split_once(':') else { return Some(vec![]) };
        let Ok(after) = n.parse::<u64>() else { return Some(vec![]) };
        if inst != self.instance {
            return Some(vec![]);
        }
        let m = self.inner.lock().unwrap();
        let Some(st) = m.get(ns) else {
            // No changes yet: only a cursor from the future (another process) is stale.
            return (after > 0).then(Vec::new);
        };
        if after > st.seq {
            return Some(vec![]);
        }
        if st.recent.front().is_some_and(|(s, _)| *s > after + 1) {
            return Some(vec![]); // fell out of the ring
        }
        let paths: Vec<String> = st.recent.iter().filter(|(s, p)| *s > after && p.starts_with(prefix)).map(|(_, p)| p.clone()).collect();
        (!paths.is_empty()).then_some(paths)
    }

    /// Wait for a change under `prefix` after `cursor` (or return the current
    /// cursor at once when none is given).
    pub async fn wait(&self, ns: &str, prefix: &str, cursor: Option<&str>, timeout: Duration) -> WatchResult {
        let Some(cursor) = cursor else { return WatchResult { cursor: self.cursor(ns), changed: false, paths: vec![] } };
        let deadline = tokio::time::Instant::now() + timeout.min(MAX_WAIT);
        loop {
            // Register before checking, so a change between check and wait is not missed.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(paths) = self.since(ns, prefix, cursor) {
                return WatchResult { cursor: self.cursor(ns), changed: true, paths };
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                // Nothing for us: keep the client's cursor (other namespaces' or prefixes' changes don't matter).
                return WatchResult { cursor: cursor.to_string(), changed: false, paths: vec![] };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn long_poll() {
        let h = Arc::new(Hub::default());
        let c0 = h.wait("a.near", "", None, Duration::ZERO).await.cursor;
        assert!(!h.wait("a.near", "docs/", Some(&c0), Duration::from_millis(20)).await.changed);
        let h2 = h.clone();
        let c = c0.clone();
        let w = tokio::spawn(async move { h2.wait("a.near", "docs/", Some(&c), Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        h.record("b.near", "docs/x"); // other namespace: ignored
        h.record("a.near", "other/y"); // other prefix: ignored
        h.record("a.near", "docs/z");
        let r = w.await.unwrap();
        assert!(r.changed);
        assert_eq!(r.paths, vec!["docs/z"]);
        // Caught up: nothing new.
        assert!(!h.wait("a.near", "docs/", Some(&r.cursor), Duration::from_millis(20)).await.changed);
        // A cursor from another gateway / before a restart: changed (re-list).
        assert!(h.wait("a.near", "docs/", Some("deadbeef:3"), Duration::ZERO).await.changed);
        // Missed changes that fell out of the ring: changed with unknown paths.
        for i in 0..RING + 5 {
            h.record("a.near", &format!("docs/{i}"));
        }
        let r = h.wait("a.near", "docs/", Some(&c0), Duration::ZERO).await;
        assert!(r.changed && r.paths.is_empty());
    }
}
