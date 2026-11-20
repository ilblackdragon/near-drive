//! Namespace policy source: `drive.near` `get_rules`, cached per namespace.
//!
//! Config `policies` entries override the contract for their namespace (and
//! are the only source when no RPC / contract is configured). A namespace
//! without rules gets the owner-only default. If the RPC fails, the last
//! cached rules are served; with nothing cached the request fails (503)
//! rather than silently falling back to a different policy.
//!
//! Payer opt-in: a rule's `payer` other than the namespace owner only counts
//! if that account agreed with `drive.near` `set_sponsorship(namespace)`
//! (`is_sponsor`, cached for [`SPONSOR_TTL`]); otherwise the namespace owner
//! pays. Concrete payers are checked when rules are loaded; `{account}`
//! payers are checked per request in [`PolicySource::effective_payer`].
//! Config overrides are trusted as written.
use near_drive_core::policy::{Access, Rule};
use near_drive_chain::{NoContract, StorageContract};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

pub const CACHE_TTL: Duration = Duration::from_secs(30);
pub const SPONSOR_TTL: Duration = Duration::from_secs(60);
const MAX_SPONSOR_CACHE: usize = 100_000;

type Cached = (Arc<Vec<Rule>>, Instant);

pub struct PolicySource {
    overrides: HashMap<String, Arc<Vec<Rule>>>,
    contract: Option<StorageContract>,
    ttl: Duration,
    cache: Mutex<HashMap<String, Cached>>,
    /// (payer, namespace) -> is_sponsor
    sponsors: Mutex<HashMap<(String, String), (bool, Instant)>>,
}

impl PolicySource {
    pub fn new(overrides: &HashMap<String, Vec<Rule>>, contract: Option<StorageContract>) -> Self {
        Self {
            overrides: overrides.iter().map(|(k, v)| (k.clone(), Arc::new(v.clone()))).collect(),
            contract,
            ttl: CACHE_TTL,
            cache: Mutex::new(HashMap::new()),
            sponsors: Mutex::new(HashMap::new()),
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
            Ok(r) => match self.drop_unsponsored(ns, r).await {
                Ok(r) => Arc::new(r),
                Err(e) => return stale.ok_or_else(|| e.context(format!("checking payers of {ns}"))),
            },
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

    /// `policy::resolve` with the payer opt-in applied.
    pub async fn access(&self, ns: &str, rules: &[Rule], path: &str, signer: &str) -> anyhow::Result<Access> {
        let mut access = near_drive_core::policy::resolve(ns, rules, path, signer);
        access.payer = self.effective_payer(ns, &access.payer).await?;
        Ok(access)
    }

    /// `payer` if it may be billed for `ns` (it is `ns`, or sponsors it),
    /// otherwise `ns`.
    pub async fn effective_payer(&self, ns: &str, payer: &str) -> anyhow::Result<String> {
        if payer == ns || self.overrides.contains_key(ns) || self.is_sponsor(payer, ns).await? {
            Ok(payer.to_string())
        } else {
            Ok(ns.to_string())
        }
    }

    /// Clear concrete payers that did not opt in, so the owner pays.
    async fn drop_unsponsored(&self, ns: &str, mut rules: Vec<Rule>) -> anyhow::Result<Vec<Rule>> {
        for r in &mut rules {
            let Some(p) = r.payer.as_deref() else { continue };
            if p == ns || p.contains("{account}") {
                continue;
            }
            if !self.is_sponsor(p, ns).await? {
                tracing::debug!("{ns}: payer {p} has not opted in; billing the owner");
                r.payer = None;
            }
        }
        Ok(rules)
    }

    async fn is_sponsor(&self, payer: &str, ns: &str) -> anyhow::Result<bool> {
        let Some(contract) = &self.contract else { return Ok(true) };
        let key = (payer.to_string(), ns.to_string());
        let stale = match self.sponsors.lock().await.get(&key) {
            Some((v, at)) if at.elapsed() < SPONSOR_TTL => return Ok(*v),
            Some((v, _)) => Some(*v),
            None => None,
        };
        let v = match contract.is_sponsor(payer, ns).await {
            Ok(v) => v,
            Err(e) if e.downcast_ref::<NoContract>().is_some() => false,
            Err(e) => {
                return match stale {
                    Some(v) => {
                        tracing::warn!("is_sponsor({payer}, {ns}) failed, using the cached answer: {e:#}");
                        Ok(v)
                    }
                    None => Err(e.context(format!("is_sponsor({payer}, {ns})"))),
                };
            }
        };
        let mut cache = self.sponsors.lock().await;
        if cache.len() >= MAX_SPONSOR_CACHE {
            cache.retain(|_, (_, at)| at.elapsed() < SPONSOR_TTL);
            if cache.len() >= MAX_SPONSOR_CACHE {
                cache.clear();
            }
        }
        cache.insert(key, (v, Instant::now()));
        Ok(v)
    }
}
