//! NEAR JSON-RPC: view calls, access-key lookups and signed function calls.
use crate::tx::{Action, Transaction};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::SigningKey;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::time::Duration;

/// 1 NEAR in yoctoNEAR.
pub const ONE_NEAR: u128 = 1_000_000_000_000_000_000_000_000;
/// Protocol storage price: 10^19 yoctoNEAR per byte.
pub const STORAGE_BYTE_COST: u128 = 10_000_000_000_000_000_000;
pub const TGAS: u64 = 1_000_000_000_000;

pub fn default_rpc_url(network: &str) -> Option<&'static str> {
    match network {
        "mainnet" => Some("https://rpc.mainnet.near.org"),
        "testnet" => Some("https://rpc.testnet.near.org"),
        _ => None,
    }
}

/// Permission of an access key, as far as NEAR Drive cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyPermission {
    FullAccess,
    FunctionCall {
        receiver_id: String,
    },
    /// Gas keys and future kinds.
    Other,
}

/// The target account has no contract deployed (or does not exist).
#[derive(Debug)]
pub struct NoContract(pub String);

impl std::fmt::Display for NoContract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no contract at {}", self.0)
    }
}

impl std::error::Error for NoContract {}

/// An account that signs transactions (`~/.near-credentials` key).
#[derive(Clone)]
pub struct Signer {
    pub account_id: String,
    pub sk: SigningKey,
}

impl Signer {
    pub fn new(account_id: impl Into<String>, sk: SigningKey) -> Self {
        Self {
            account_id: account_id.into(),
            sk,
        }
    }

    pub fn public_key(&self) -> String {
        near_drive_core::keys::format_public_key(&self.sk.verifying_key())
    }

    /// Load `~/.near-credentials/<network>/<account>.json`-format files.
    pub fn from_credentials_file(path: &std::path::Path) -> Result<Self> {
        let (account_id, sk) = near_drive_core::keys::NearCredentials::load(path)?;
        Ok(Self { account_id, sk })
    }
}

/// Outcome of a successful transaction.
#[derive(Debug, Clone)]
pub struct CallOutcome {
    pub tx_hash: String,
    /// Decoded `SuccessValue` of the transaction (empty for no return value).
    pub value: Vec<u8>,
    /// Logs from all receipts.
    pub logs: Vec<String>,
}

impl CallOutcome {
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.value).context("decoding call result")
    }
}

#[derive(Clone)]
pub struct NearRpc {
    http: reqwest::Client,
    url: String,
    finality: String,
}

impl NearRpc {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            url: url.into(),
            finality: "optimistic".into(),
        }
    }

    /// View-call finality: `optimistic` (default; reads your own writes) or `final`.
    pub fn with_finality(mut self, finality: &str) -> Self {
        self.finality = finality.into();
        self
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Raw JSON-RPC: `Ok(result)` or an error carrying the RPC error JSON.
    pub async fn request(&self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        let resp: Value = self
            .http
            .post(&self.url)
            .json(
                &json!({"jsonrpc": "2.0", "id": "near-drive", "method": method, "params": params}),
            )
            .timeout(timeout)
            .send()
            .await
            .with_context(|| format!("rpc {method} to {}", self.url))?
            .json()
            .await
            .with_context(|| format!("rpc {method}: decoding response"))?;
        if let Some(e) = resp.get("error") {
            bail!("rpc {method} error: {e}");
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| anyhow!("rpc {method}: response without result: {resp}"))
    }

    /// `query call_function` at the configured finality. Returns the raw result bytes.
    /// Errors with [`NoContract`] when the account or its code is missing.
    pub async fn view_raw(&self, contract: &str, method: &str, args: &Value) -> Result<Vec<u8>> {
        let params = json!({
            "request_type": "call_function", "finality": self.finality,
            "account_id": contract, "method_name": method,
            "args_base64": B64.encode(serde_json::to_vec(args)?),
        });
        let r = match self.request("query", params, Duration::from_secs(10)).await {
            Ok(r) => r,
            Err(e) => {
                let s = e.to_string();
                if [
                    "UNKNOWN_ACCOUNT",
                    "NO_CONTRACT_CODE",
                    "CodeDoesNotExist",
                    "does not exist",
                ]
                .iter()
                .any(|m| s.contains(m))
                {
                    return Err(NoContract(contract.to_string()).into());
                }
                return Err(e);
            }
        };
        // Older nodes report contract errors inside `result.error`.
        if let Some(e) = r.get("error").and_then(Value::as_str) {
            if e.contains("CodeDoesNotExist") || e.contains("does not exist") {
                return Err(NoContract(contract.to_string()).into());
            }
            bail!("view {contract}.{method} failed: {e}");
        }
        let bytes = r
            .get("result")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("view {method}: missing result bytes"))?;
        bytes
            .iter()
            .map(|b| {
                b.as_u64()
                    .and_then(|b| u8::try_from(b).ok())
                    .ok_or_else(|| anyhow!("bad result byte"))
            })
            .collect()
    }

    pub async fn view<T: DeserializeOwned>(
        &self,
        contract: &str,
        method: &str,
        args: &Value,
    ) -> Result<T> {
        let raw = self.view_raw(contract, method, args).await?;
        serde_json::from_slice(&raw).with_context(|| format!("decoding {contract}.{method} result"))
    }

    /// `(nonce, block_hash)` for the signer's access key.
    pub async fn access_key(&self, account: &str, public_key: &str) -> Result<(u64, [u8; 32])> {
        let r = self
            .request(
                "query",
                json!({"request_type": "view_access_key", "finality": "final", "account_id": account, "public_key": public_key}),
                Duration::from_secs(10),
            )
            .await?;
        if let Some(e) = r.get("error") {
            bail!("access key {public_key} for {account}: {e}");
        }
        let nonce = r
            .get("nonce")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("access key: no nonce in {r}"))?;
        let hash = r
            .get("block_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("access key: no block_hash"))?;
        let hash: [u8; 32] = bs58::decode(hash)
            .into_vec()?
            .try_into()
            .map_err(|_| anyhow!("bad block hash"))?;
        Ok((nonce, hash))
    }

    /// All access keys of `account`: `(public_key, permission)`, where a
    /// function-call key carries its `receiver_id`.
    pub async fn access_key_list(&self, account: &str) -> Result<Vec<(String, KeyPermission)>> {
        let r = self
            .request(
                "query",
                json!({"request_type": "view_access_key_list", "finality": "final", "account_id": account}),
                Duration::from_secs(10),
            )
            .await?;
        let keys = r
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("access key list: no keys in {r}"))?;
        Ok(keys
            .iter()
            .filter_map(|k| {
                let pk = k.get("public_key")?.as_str()?.to_string();
                let perm = k.get("access_key")?.get("permission")?;
                let perm = if perm.as_str() == Some("FullAccess") {
                    KeyPermission::FullAccess
                } else if let Some(fc) = perm.get("FunctionCall") {
                    KeyPermission::FunctionCall {
                        receiver_id: fc.get("receiver_id")?.as_str()?.to_string(),
                    }
                } else {
                    KeyPermission::Other
                };
                Some((pk, perm))
            })
            .collect())
    }

    /// Sign and send a transaction with the given actions; waits until all
    /// its receipts executed. Retries once on a stale nonce.
    pub async fn send(
        &self,
        signer: &Signer,
        receiver_id: &str,
        actions: Vec<Action>,
    ) -> Result<CallOutcome> {
        let mut last_err = None;
        for _ in 0..3 {
            let (nonce, block_hash) = self
                .access_key(&signer.account_id, &signer.public_key())
                .await?;
            let tx = Transaction {
                signer_id: signer.account_id.clone(),
                public_key: signer.sk.verifying_key().to_bytes(),
                nonce: nonce + 1,
                receiver_id: receiver_id.to_string(),
                block_hash,
                actions: actions.clone(),
            };
            let params = json!({"signed_tx_base64": B64.encode(tx.sign(&signer.sk)), "wait_until": "EXECUTED_OPTIMISTIC"});
            match self
                .request("send_tx", params, Duration::from_secs(60))
                .await
            {
                Ok(r) => return parse_outcome(&r, &bs58::encode(tx.hash()).into_string()),
                Err(e) if e.to_string().contains("InvalidNonce") => last_err = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("send_tx failed")))
    }

    /// One `FunctionCall` with JSON args.
    pub async fn call(
        &self,
        signer: &Signer,
        contract: &str,
        method: &str,
        args: &Value,
        gas: u64,
        deposit: u128,
    ) -> Result<CallOutcome> {
        let action = Action::FunctionCall {
            method_name: method.into(),
            args: serde_json::to_vec(args)?,
            gas,
            deposit,
        };
        self.send(signer, contract, vec![action]).await
    }
}

fn parse_outcome(r: &Value, tx_hash: &str) -> Result<CallOutcome> {
    let mut logs = Vec::new();
    for o in r
        .pointer("/transaction_outcome/outcome/logs")
        .into_iter()
        .chain(
            r.get("receipts_outcome")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|ro| ro.pointer("/outcome/logs")),
        )
    {
        logs.extend(
            o.as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(String::from),
        );
    }
    let status = r
        .get("status")
        .ok_or_else(|| anyhow!("tx {tx_hash}: no status in {r}"))?;
    if let Some(f) = status.get("Failure") {
        bail!("tx {tx_hash} failed: {f}");
    }
    let value = match status.get("SuccessValue").and_then(Value::as_str) {
        Some(v) => B64.decode(v)?,
        None => Vec::new(),
    };
    Ok(CallOutcome {
        tx_hash: tx_hash.to_string(),
        value,
        logs,
    })
}
