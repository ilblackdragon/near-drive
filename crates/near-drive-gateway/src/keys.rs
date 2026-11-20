//! Resolves whether a public key may act for a NEAR account.
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const CACHE_TTL: Duration = Duration::from_secs(30);

pub struct KeyResolver {
    http: reqwest::Client,
    rpc_url: Option<String>,
    /// Function-call keys are accepted only if scoped to this contract.
    storage_contract: String,
    dev_keys: HashMap<String, Vec<String>>,
    cache: Mutex<HashMap<(String, String), (bool, Instant)>>,
}

impl KeyResolver {
    pub fn new(rpc_url: Option<String>, storage_contract: String, dev_keys: HashMap<String, Vec<String>>) -> Self {
        Self { http: reqwest::Client::new(), rpc_url, storage_contract, dev_keys, cache: Mutex::new(HashMap::new()) }
    }

    pub async fn is_authorized(&self, account: &str, public_key: &str) -> Result<bool> {
        if self.dev_keys.get(account).is_some_and(|ks| ks.iter().any(|k| k == public_key)) {
            return Ok(true);
        }
        let Some(rpc) = &self.rpc_url else { return Ok(false) };
        let key = (account.to_string(), public_key.to_string());
        if let Some((ok, at)) = self.cache.lock().await.get(&key) {
            if at.elapsed() < CACHE_TTL {
                return Ok(*ok);
            }
        }
        let resp: Value = self
            .http
            .post(rpc)
            .json(&json!({
                "jsonrpc": "2.0", "id": "near-drive", "method": "query",
                "params": {"request_type": "view_access_key", "finality": "final",
                           "account_id": account, "public_key": public_key}
            }))
            .timeout(Duration::from_secs(10))
            .send()
            .await?
            .json()
            .await?;
        let ok = if let Some(perm) = resp.pointer("/result/permission") {
            match perm {
                Value::String(s) if s == "FullAccess" => true,
                Value::Object(o) => o
                    .get("FunctionCall")
                    .and_then(|fc| fc.get("receiver_id"))
                    .and_then(Value::as_str)
                    .is_some_and(|r| r == self.storage_contract),
                _ => false,
            }
        } else if resp.get("error").is_some() || resp.pointer("/result/error").is_some() {
            // Unknown key / account: a definitive "no".
            let s = resp.to_string();
            if !(s.contains("UNKNOWN_ACCESS_KEY") || s.contains("UNKNOWN_ACCOUNT") || s.contains("does not exist")) {
                bail!("rpc error: {s}");
            }
            false
        } else {
            bail!("unexpected rpc response: {resp}");
        };
        self.cache.lock().await.insert(key, (ok, Instant::now()));
        Ok(ok)
    }
}

/// Whether a record's `writer_pk` is its writer's current signing key.
///
/// With an RPC: the latest entry of `get_sign_keys(writer)` in `drive.near`
/// (cached [`SIGN_KEY_TTL`]; a mismatch against an older cache entry re-reads
/// once, so a just-published key works). `dev_sign_keys` entries are accepted
/// as well. Without an RPC (dev): an account listed in `dev_sign_keys` must
/// use one of those keys; any key is accepted for an unlisted account.
pub struct SignKeys {
    dev: HashMap<String, Vec<String>>,
    contract: Option<near_drive_chain::StorageContract>,
    cache: Mutex<HashMap<String, (Option<String>, Instant)>>,
}

pub const SIGN_KEY_TTL: Duration = Duration::from_secs(60);
const SIGN_KEY_RECHECK: Duration = Duration::from_secs(2);
const SIGN_KEY_CACHE_MAX: usize = 4096;

impl SignKeys {
    pub fn new(dev: HashMap<String, Vec<String>>, contract: Option<near_drive_chain::StorageContract>) -> Self {
        Self { dev, contract, cache: Mutex::new(HashMap::new()) }
    }

    async fn latest(&self, c: &near_drive_chain::StorageContract, account: &str, force: bool) -> Result<(Option<String>, Duration)> {
        if !force {
            if let Some((k, at)) = self.cache.lock().await.get(account) {
                if at.elapsed() < SIGN_KEY_TTL {
                    return Ok((k.clone(), at.elapsed()));
                }
            }
        }
        let latest = match c.get_sign_keys(account).await {
            Ok(h) => h.last().map(|e| e.key.clone()),
            Err(e) if e.downcast_ref::<near_drive_chain::NoContract>().is_some() => None,
            Err(e) => return Err(e.context(format!("reading the signing keys of {account}"))),
        };
        let mut cache = self.cache.lock().await;
        if cache.len() >= SIGN_KEY_CACHE_MAX {
            cache.retain(|_, (_, at)| at.elapsed() < SIGN_KEY_TTL);
            if cache.len() >= SIGN_KEY_CACHE_MAX {
                cache.clear();
            }
        }
        cache.insert(account.to_string(), (latest.clone(), Instant::now()));
        Ok((latest, Duration::ZERO))
    }

    pub async fn is_current(&self, account: &str, key: &str) -> Result<bool> {
        let listed = self.dev.get(account);
        if listed.is_some_and(|ks| ks.iter().any(|k| k == key)) {
            return Ok(true);
        }
        let Some(c) = &self.contract else { return Ok(listed.is_none()) };
        let (latest, age) = self.latest(c, account, false).await?;
        if latest.as_deref() == Some(key) {
            return Ok(true);
        }
        if age < SIGN_KEY_RECHECK {
            return Ok(false);
        }
        Ok(self.latest(c, account, true).await?.0.as_deref() == Some(key))
    }
}
