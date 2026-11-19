//! Namespace policy source: `drive.near` `get_rules`, cached per namespace.
//!
//! Config `policies` entries override the contract for their namespace (and
//! are the only source when no RPC / contract is configured). A namespace
//! without rules gets the owner-only default. If the RPC fails, the last
//! cached rules are served; with nothing cached the request fails (503)
//! rather than silently falling back to a different policy.
use near_drive_core::policy::Rule;
use near_drive_chain::{NoContract, StorageContract};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

pub const CACHE_TTL: Duration = Duration::from_secs(30);

type Cached = (Arc<Vec<Rule>>, Instant);

pub struct PolicySource {
    overrides: HashMap<String, Arc<Vec<Rule>>>,
    contract: Option<StorageContract>,
    ttl: Duration,
    cache: Mutex<HashMap<String, Cached>>,
}

impl PolicySource {
    pub fn new(overrides: &HashMap<String, Vec<Rule>>, contract: Option<StorageContract>) -> Self {
        Self {
            overrides: overrides.iter().map(|(k, v)| (k.clone(), Arc::new(v.clone()))).collect(),
            contract,
            ttl: CACHE_TTL,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub async fn rules(&self, ns: &str) -> anyhow::Result<Arc<Vec<Rule>>> {
        if let Some(r) = self.overrides.get(ns) {
            return Ok(r.clone());
        }
        let Some(contract) = &self.contract else { return Ok(Arc::default()) };
        let stale = match self.cache.lock().await.get(ns) {
            Some((r, at)) if at.elapsed() < self.ttl => return Ok(r.clone()),
            Some((r, _)) => Some(r.clone()),
            None => None,
        };
        let fetched = match contract.get_rules(ns).await {
            Ok(r) => Arc::new(r),
            // No contract deployed yet: nobody has published rules.
            Err(e) if e.downcast_ref::<NoContract>().is_some() => Arc::default(),
            Err(e) => {
                return match stale {
                    Some(r) => {
                        tracing::warn!("get_rules({ns}) failed, serving cached rules: {e:#}");
                        Ok(r)
                    }
                    None => Err(e.context(format!("reading policy for {ns}"))),
                };
            }
        };
        self.cache.lock().await.insert(ns.to_string(), (fetched.clone(), Instant::now()));
        Ok(fetched)
    }
}
