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
