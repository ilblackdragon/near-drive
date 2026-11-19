//! Chain client for near-drive: typed views and transactions against the
//! `drive.near` contract (`contracts/drive`).
//!
//! Dependency choice: NEAR's own client crates (`near-api`,
//! `near-jsonrpc-client`) pull in `near-primitives` and a few hundred
//! transitive crates. NEAR Drive needs exactly one action type (FunctionCall,
//! plus Transfer) on a v0 transaction with an ed25519 key, so [`tx`] encodes
//! that borsh layout by hand (~60 lines, unit-tested against the layout and
//! exercised against a real sandbox node in `contracts/drive/tests`).
pub mod rpc;
pub mod tx;

use anyhow::Result;
use near_drive_core::policy::Rule;
pub use rpc::{default_rpc_url, CallOutcome, KeyPermission, NearRpc, NoContract, Signer, ONE_NEAR, STORAGE_BYTE_COST, TGAS};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// U128 as a JSON string (NEAR convention).
pub mod u128_str {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        String::deserialize(d)?.parse().map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct GatewayInfo {
    pub url: String,
    #[serde(default)]
    pub regions: Vec<String>,
    #[serde(default)]
    pub backends: Vec<String>,
    #[serde(default)]
    pub price_hint: String,
    #[serde(default)]
    pub attestation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayView {
    pub operator: String,
    pub url: String,
    #[serde(default)]
    pub regions: Vec<String>,
    #[serde(default)]
    pub backends: Vec<String>,
    #[serde(default)]
    pub price_hint: String,
    #[serde(default)]
    pub attestation: Option<String>,
    #[serde(with = "u128_str")]
    pub stake: u128,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Anchor {
    pub root: String,
    pub seq: u64,
    pub by: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SettleEntry {
    pub payer: String,
    /// micro-USD
    #[serde(with = "u128_str")]
    pub amount: u128,
    pub gateway: String,
    pub period_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SettleResult {
    pub payer: String,
    pub period_id: String,
    /// `Settled`, `AlreadySettled`, `InvalidEntry`, `GatewayNotAllowed`,
    /// `UnknownGateway`, `NoSpendCap`, `CapExceeded`, `InsufficientBalance`.
    pub status: String,
    #[serde(with = "u128_str")]
    pub charged: u128,
}

/// Deposit to attach for a call that may store about `json_len` bytes:
/// generous, since the contract refunds whatever it does not use.
pub fn storage_deposit_for(json_len: usize) -> u128 {
    (json_len as u128 + 512) * STORAGE_BYTE_COST
}

/// Replace the rule with the same prefix, or append.
pub fn upsert_rule(rules: &mut Vec<Rule>, rule: Rule) {
    match rules.iter_mut().find(|r| r.prefix == rule.prefix) {
        Some(r) => *r = rule,
        None => rules.push(rule),
    }
}

const CALL_GAS: u64 = 50 * TGAS;

/// Typed access to one deployed `drive.near` contract.
#[derive(Clone)]
pub struct StorageContract {
    pub rpc: NearRpc,
    pub contract_id: String,
}

impl StorageContract {
    pub fn new(rpc_url: impl Into<String>, contract_id: impl Into<String>) -> Self {
        Self { rpc: NearRpc::new(rpc_url), contract_id: contract_id.into() }
    }

    async fn view<T: serde::de::DeserializeOwned>(&self, method: &str, args: serde_json::Value) -> Result<T> {
        self.rpc.view(&self.contract_id, method, &args).await
    }

    pub async fn get_rules(&self, namespace: &str) -> Result<Vec<Rule>> {
        self.view("get_rules", json!({"namespace": namespace})).await
    }

    pub async fn get_enc_key(&self, account: &str) -> Result<Option<String>> {
        self.view("get_enc_key", json!({"account_id": account})).await
    }

    pub async fn get_cred_epoch(&self, account: &str) -> Result<u64> {
        self.view("get_cred_epoch", json!({"account_id": account})).await
    }

    pub async fn get_anchor(&self, namespace: &str) -> Result<Option<Anchor>> {
        self.view("get_anchor", json!({"namespace": namespace})).await
    }

    pub async fn list_gateways(&self, from_index: u32, limit: u32) -> Result<Vec<GatewayView>> {
        self.view("list_gateways", json!({"from_index": from_index, "limit": limit})).await
    }

    /// Every registered gateway (pages of 100).
    pub async fn all_gateways(&self) -> Result<Vec<GatewayView>> {
        let mut out = Vec::new();
        loop {
            let page = self.list_gateways(out.len() as u32, 100).await?;
            let n = page.len();
            out.extend(page);
            if n < 100 {
                return Ok(out);
            }
        }
    }

    pub async fn set_rules(&self, signer: &Signer, rules: &[Rule]) -> Result<CallOutcome> {
        let args = json!({"rules": rules});
        let deposit = storage_deposit_for(args.to_string().len());
        self.rpc.call(signer, &self.contract_id, "set_rules", &args, CALL_GAS, deposit).await
    }

    /// Read the signer's rules, upsert `rule` by prefix, write them back.
    pub async fn grant(&self, signer: &Signer, rule: Rule) -> Result<Vec<Rule>> {
        let mut rules = self.get_rules(&signer.account_id).await?;
        upsert_rule(&mut rules, rule);
        self.set_rules(signer, &rules).await?;
        Ok(rules)
    }

    pub async fn set_enc_key(&self, signer: &Signer, key: &str) -> Result<CallOutcome> {
        let args = json!({"key": key});
        self.rpc.call(signer, &self.contract_id, "set_enc_key", &args, CALL_GAS, storage_deposit_for(key.len())).await
    }

    pub async fn bump_cred_epoch(&self, signer: &Signer) -> Result<u64> {
        self.rpc.call(signer, &self.contract_id, "bump_cred_epoch", &json!({}), CALL_GAS, storage_deposit_for(0)).await?.json()
    }

    pub async fn anchor(&self, signer: &Signer, namespace: &str, root: &str, seq: u64) -> Result<CallOutcome> {
        let args = json!({"namespace": namespace, "root": root, "seq": seq});
        self.rpc.call(signer, &self.contract_id, "anchor", &args, CALL_GAS, storage_deposit_for(root.len())).await
    }

    /// `stake` is in yoctoNEAR; the storage cost is added on top.
    pub async fn register_gateway(&self, signer: &Signer, info: &GatewayInfo, stake: u128) -> Result<CallOutcome> {
        let args = json!({"info": info});
        let deposit = stake + storage_deposit_for(args.to_string().len());
        self.rpc.call(signer, &self.contract_id, "register_gateway", &args, CALL_GAS, deposit).await
    }

    pub async fn update_gateway(&self, signer: &Signer, info: &GatewayInfo) -> Result<CallOutcome> {
        let args = json!({"info": info});
        let deposit = storage_deposit_for(args.to_string().len());
        self.rpc.call(signer, &self.contract_id, "update_gateway", &args, CALL_GAS, deposit).await
    }

    pub async fn deregister_gateway(&self, signer: &Signer) -> Result<CallOutcome> {
        self.rpc.call(signer, &self.contract_id, "deregister_gateway", &json!({}), CALL_GAS, 1).await
    }

    /// Billing settlement (approved settlers only). ~0.001 NEAR of storage is
    /// attached per entry; unused deposit is refunded.
    pub async fn settle(&self, signer: &Signer, entries: &[SettleEntry]) -> Result<Vec<SettleResult>> {
        let args = json!({"entries": entries});
        let deposit = storage_deposit_for(entries.len() * 200);
        self.rpc.call(signer, &self.contract_id, "settle", &args, 300 * TGAS, deposit).await?.json()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert() {
        let r = |p: &str, w: &str| Rule { prefix: p.into(), read: vec![], write: vec![w.into()], payer: None };
        let mut rules = vec![r("a/", "x.near"), r("b/", "y.near")];
        upsert_rule(&mut rules, r("a/", "z.near"));
        upsert_rule(&mut rules, r("c/", "w.near"));
        assert_eq!(rules, vec![r("a/", "z.near"), r("b/", "y.near"), r("c/", "w.near")]);
    }

    #[test]
    fn gateway_view_parses_contract_json() {
        let v: Vec<GatewayView> = serde_json::from_str(
            r#"[{"operator":"gw.near","url":"https://gw","regions":["eu"],"backends":["fs"],"price_hint":"",
                "attestation":null,"stake":"5000000000000000000000000","registered_at_ns":"1","active":true,
                "stake_unlock_at_ns":null}]"#,
        )
        .unwrap();
        assert_eq!(v[0].stake, 5 * ONE_NEAR);
    }
}
