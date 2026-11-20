//! Minimal NEAR JSON-RPC + transaction path for `request_app_private_key`.
//!
//! Hand-rolled borsh for exactly one transaction shape (one FunctionCall,
//! ed25519 signer) to avoid pulling near-primitives into the workspace. The
//! byte layout is cross-checked against @near-js/transactions in tests.
use crate::{
    parse_g2, root_key_from_response, CkdNetwork, CkdRequestArgs, CkdResponse, EphemeralKey,
};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use blstrs::G2Projective;
use ed25519_dalek::{Signer as _, SigningKey};
use near_drive_core::crypto::RootKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

pub const METHOD: &str = "request_app_private_key";
/// Contract requires `ckd_call_gas_attachment_requirement_tera_gas` (15 on
/// mainnet/testnet as of contract 3.19.0). Unused gas is refunded.
pub const DEFAULT_GAS: u64 = 50_000_000_000_000;
/// The contract requires ≥ 1 yoctoNEAR (excess is refunded). The deposit also
/// forces a full-access key (function-call keys can't attach deposits).
pub const DEPOSIT_YOCTO: u128 = 1;

/// NEAR account + full-access ed25519 key.
pub struct Signer {
    pub account_id: String,
    pub key: SigningKey,
}

/// One FunctionCall transaction (borsh: Transaction V0).
pub struct FunctionCallTx<'a> {
    pub signer_id: &'a str,
    pub public_key: [u8; 32],
    pub nonce: u64,
    pub receiver_id: &'a str,
    pub block_hash: [u8; 32],
    pub method_name: &'a str,
    pub args: &'a [u8],
    pub gas: u64,
    pub deposit: u128,
}

fn put_str(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s);
}

impl FunctionCallTx<'_> {
    pub fn borsh(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(256 + self.args.len());
        put_str(&mut o, self.signer_id.as_bytes());
        o.push(0); // KeyType::ED25519
        o.extend_from_slice(&self.public_key);
        o.extend_from_slice(&self.nonce.to_le_bytes());
        put_str(&mut o, self.receiver_id.as_bytes());
        o.extend_from_slice(&self.block_hash);
        o.extend_from_slice(&1u32.to_le_bytes()); // actions.len()
        o.push(2); // Action::FunctionCall
        put_str(&mut o, self.method_name.as_bytes());
        put_str(&mut o, self.args);
        o.extend_from_slice(&self.gas.to_le_bytes());
        o.extend_from_slice(&self.deposit.to_le_bytes());
        o
    }

    /// Returns (tx hash, borsh(SignedTransaction)).
    pub fn sign(&self, key: &SigningKey) -> ([u8; 32], Vec<u8>) {
        let mut body = self.borsh();
        let hash: [u8; 32] = Sha256::digest(&body).into();
        let sig = key.sign(&hash);
        body.push(0); // Signature::ED25519
        body.extend_from_slice(&sig.to_bytes());
        (hash, body)
    }
}

/// Per-call timeout for view calls and `tx` polls.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// The first `send_tx` waits for execution; the RPC itself gives up after
/// ~10 s with TIMEOUT_ERROR while the MPC network works (then we poll).
const SEND_TIMEOUT: Duration = Duration::from_secs(20);
/// How long to wait for the CKD response (usually 5-10 s).
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(120);
pub const DEFAULT_POLL: Duration = Duration::from_secs(2);

/// A JSON-RPC error answer (as opposed to a transport failure).
#[derive(Debug)]
pub struct RpcError {
    pub method: String,
    /// `error.cause.name` (e.g. `UNKNOWN_TRANSACTION`, `INVALID_TRANSACTION`,
    /// `TIMEOUT_ERROR`), else `error.name`.
    pub cause: Option<String>,
    pub error: Value,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rpc {}: {}", self.method, self.error)
    }
}

impl std::error::Error for RpcError {}

/// The RPC error cause of `e`, if it is an [`RpcError`].
pub fn rpc_cause(e: &anyhow::Error) -> Option<&str> {
    e.downcast_ref::<RpcError>().and_then(|r| r.cause.as_deref())
}

pub struct Rpc {
    url: String,
    http: reqwest::Client,
}

impl Rpc {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.into(),
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        self.call_within(method, params, CALL_TIMEOUT).await
    }

    async fn call_within(&self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        let v: Value = self
            .http
            .post(&self.url)
            .timeout(timeout)
            .json(&json!({"jsonrpc": "2.0", "id": "near-drive-ckd", "method": method, "params": params}))
            .send()
            .await
            .with_context(|| format!("rpc {method} to {} (no answer within {timeout:?})", self.url))?
            .json()
            .await
            .with_context(|| format!("rpc {method}: decoding response"))?;
        if let Some(e) = v.get("error") {
            let cause = e
                .pointer("/cause/name")
                .or_else(|| e.get("name"))
                .and_then(Value::as_str)
                .map(str::to_string);
            return Err(RpcError { method: method.into(), cause, error: e.clone() }.into());
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| anyhow!("rpc {method}: no result"))
    }

    pub async fn view_call(&self, contract: &str, method: &str, args: &Value) -> Result<Value> {
        let r = self
            .call(
                "query",
                json!({"request_type": "call_function", "finality": "final", "account_id": contract,
                       "method_name": method, "args_base64": B64.encode(args.to_string())}),
            )
            .await?;
        if let Some(e) = r.get("error") {
            bail!("view {method}: {e}");
        }
        let bytes: Vec<u8> =
            serde_json::from_value(r.get("result").cloned().context("no result bytes")?)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// The CKD domain's master public key (G2).
    pub async fn mpc_public_key(&self, contract: &str, domain_id: u64) -> Result<G2Projective> {
        let v = self
            .view_call(contract, "public_key", &json!({"domain_id": domain_id}))
            .await?;
        parse_g2(v.as_str().context("public_key: expected string")?)
    }

    async fn access_key_nonce(&self, account: &str, pk: &str) -> Result<u64> {
        let r = self
            .call("query", json!({"request_type": "view_access_key", "finality": "final", "account_id": account, "public_key": pk}))
            .await?;
        if let Some(e) = r.get("error") {
            bail!("view_access_key: {e}");
        }
        if r.pointer("/permission/FunctionCall").is_some() {
            bail!("{pk} is a function-call key; CKD needs a 1 yocto deposit, so use a full-access key");
        }
        r.get("nonce")
            .and_then(Value::as_u64)
            .context("view_access_key: no nonce")
    }

    async fn final_block_hash(&self) -> Result<[u8; 32]> {
        let r = self.call("block", json!({"finality": "final"})).await?;
        let h = r
            .pointer("/header/hash")
            .and_then(Value::as_str)
            .context("block: no hash")?;
        bs58::decode(h)
            .into_vec()?
            .try_into()
            .map_err(|_| anyhow!("bad block hash"))
    }

    /// Sends a signed tx and waits for its final outcome. CKD is
    /// yield/resume: the value arrives a few blocks after inclusion, so the
    /// first `send_tx` often times out and we poll `tx`.
    ///
    /// Prints the tx hash first. Stops at once on INVALID_TRANSACTION. If the
    /// node forgot the tx (UNKNOWN_TRANSACTION: dropped before inclusion), the
    /// same signed bytes are sent again (same hash, so it cannot run twice).
    /// On timeout the error names the hash and the first `send_tx` error.
    pub async fn send_and_wait(
        &self,
        signed: &[u8],
        hash: &[u8; 32],
        sender: &str,
        deadline: Duration,
        poll: Duration,
    ) -> Result<Value> {
        let hash58 = bs58::encode(hash).into_string();
        eprintln!("CKD transaction {hash58}: sent, waiting for the MPC network (usually 5-10 s)");
        let started = std::time::Instant::now();
        let signed_b64 = B64.encode(signed);
        let first_err = match self
            .call_within("send_tx", json!({"signed_tx_base64": signed_b64, "wait_until": "EXECUTED_OPTIMISTIC"}), SEND_TIMEOUT)
            .await
        {
            Ok(v) if v.get("status").is_some() => return Ok(v),
            Ok(v) => anyhow!("send_tx: unexpected result {v}"),
            Err(e) if rpc_cause(&e) == Some("INVALID_TRANSACTION") => {
                return Err(e.context(format!("transaction {hash58} rejected")))
            }
            Err(e) => e, // usually TIMEOUT_ERROR while the MPC network works
        };
        let mut last_err: Option<anyhow::Error> = None;
        let mut resent = 0u32;
        while started.elapsed() < deadline {
            tokio::time::sleep(poll).await;
            match self
                .call("tx", json!({"tx_hash": hash58, "sender_account_id": sender, "wait_until": "EXECUTED_OPTIMISTIC"}))
                .await
            {
                Ok(v) if v.get("status").is_some() => return Ok(v),
                Ok(v) => last_err = Some(anyhow!("no status yet: {v}")),
                Err(e) if rpc_cause(&e) == Some("INVALID_TRANSACTION") => {
                    return Err(e.context(format!("transaction {hash58} rejected")))
                }
                Err(e) if rpc_cause(&e) == Some("UNKNOWN_TRANSACTION") => {
                    resent += 1;
                    // Not seen by the node: re-broadcast the identical bytes.
                    if let Err(se) = self
                        .call("send_tx", json!({"signed_tx_base64": signed_b64, "wait_until": "NONE"}))
                        .await
                    {
                        last_err = Some(se.context("re-sending"));
                    } else {
                        last_err = Some(e);
                    }
                }
                Err(e) => last_err = Some(e),
            }
        }
        let mut msg = format!(
            "CKD transaction {hash58} did not finish within {deadline:?}; first send_tx error: {first_err:#}"
        );
        if let Some(l) = last_err {
            msg.push_str(&format!("; last status check: {l:#}"));
        }
        if resent > 0 {
            msg.push_str(&format!(" (the node did not know the tx; re-sent {resent}x)"));
        }
        msg.push_str(". Look the hash up in an explorer before retrying: if it succeeded, a retry just costs another request");
        bail!(msg)
    }
}

fn success_value(outcome: &Value) -> Result<Vec<u8>> {
    let status = outcome.get("status").context("outcome: no status")?;
    if let Some(v) = status.get("SuccessValue").and_then(Value::as_str) {
        return Ok(B64.decode(v)?);
    }
    bail!("request_app_private_key failed: {status}")
}

/// Sends `request_app_private_key` as `signer` and returns the resulting
/// verified root key. Burns ~16.6 TGas (~0.0017 NEAR) plus 1 yoctoNEAR.
pub async fn request_root_key(
    net: &CkdNetwork,
    signer: &Signer,
    derivation_path: &str,
) -> Result<RootKey> {
    let rpc = Rpc::new(&net.rpc_url);
    let mpc_pk = rpc.mpc_public_key(&net.contract, net.domain_id).await?;
    let eph = EphemeralKey::generate();
    let args = CkdRequestArgs::new(&eph, derivation_path, net.domain_id).to_call_args();
    let pk_bytes = signer.key.verifying_key().to_bytes();
    let pk_str = near_drive_core::keys::format_public_key(&signer.key.verifying_key());
    let nonce = rpc.access_key_nonce(&signer.account_id, &pk_str).await? + 1;
    let block_hash = rpc.final_block_hash().await?;
    let tx = FunctionCallTx {
        signer_id: &signer.account_id,
        public_key: pk_bytes,
        nonce,
        receiver_id: &net.contract,
        block_hash,
        method_name: METHOD,
        args: &args,
        gas: DEFAULT_GAS,
        deposit: DEPOSIT_YOCTO,
    };
    let (hash, signed) = tx.sign(&signer.key);
    let outcome = rpc
        .send_and_wait(&signed, &hash, &signer.account_id, DEFAULT_DEADLINE, DEFAULT_POLL)
        .await?;
    let resp: CkdResponse =
        serde_json::from_slice(&success_value(&outcome)?).context("parsing CKDResponse")?;
    root_key_from_response(&resp, &eph, &signer.account_id, derivation_path, &mpc_pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borsh_layout() {
        let tx = FunctionCallTx {
            signer_id: "a.testnet",
            public_key: [1; 32],
            nonce: 7,
            receiver_id: "v1.signer-prod.testnet",
            block_hash: [2; 32],
            method_name: "m",
            args: b"{}",
            gas: 30_000_000_000_000,
            deposit: 1,
        };
        let b = tx.borsh();
        let expected_len = 4 + 9 + 1 + 32 + 8 + 4 + 22 + 32 + 4 + 1 + 4 + 1 + 4 + 2 + 8 + 16;
        assert_eq!(b.len(), expected_len);
        assert_eq!(&b[..4], &9u32.to_le_bytes());
        assert_eq!(&b[b.len() - 16..], &1u128.to_le_bytes());
        // Produced by @near-js/transactions createTransaction + encodeTransaction
        // with the same fields.
        assert_eq!(
            hex::encode(&b),
            "09000000612e746573746e657400010101010101010101010101010101010101010101010101010101010101010107000000000000001600000076312e7369676e65722d70726f642e746573746e657402020202020202020202020202020202020202020202020202020202020202020100000002010000006d020000007b7d00e057eb481b000001000000000000000000000000000000"
        );
    }
}
