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
use nstorage_core::crypto::RootKey;
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

pub struct Rpc {
    url: String,
    http: reqwest::Client,
}

impl Rpc {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.into(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let v: Value = self
            .http
            .post(&self.url)
            .json(&json!({"jsonrpc": "2.0", "id": "nstorage-ckd", "method": method, "params": params}))
            .send()
            .await
            .with_context(|| format!("rpc {method}"))?
            .json()
            .await?;
        if let Some(e) = v.get("error") {
            bail!("rpc {method}: {e}");
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

    /// Sends a signed tx and waits for the final outcome (CKD is yield/resume:
    /// the value arrives a few blocks later, so poll `tx` after a timeout).
    async fn send_and_wait(
        &self,
        signed: &[u8],
        hash: &[u8; 32],
        sender: &str,
        deadline: Duration,
    ) -> Result<Value> {
        let hash58 = bs58::encode(hash).into_string();
        let started = std::time::Instant::now();
        let first = self
            .call("send_tx", json!({"signed_tx_base64": B64.encode(signed), "wait_until": "EXECUTED_OPTIMISTIC"}))
            .await;
        let mut last_err = match first {
            Ok(v) if v.get("status").is_some() => return Ok(v),
            Ok(v) => anyhow!("send_tx: unexpected result {v}"),
            Err(e) => e, // usually a timeout while the MPC network works
        };
        while started.elapsed() < deadline {
            tokio::time::sleep(Duration::from_secs(2)).await;
            match self
                .call("tx", json!({"tx_hash": hash58, "sender_account_id": sender, "wait_until": "EXECUTED_OPTIMISTIC"}))
                .await
            {
                Ok(v) if v.get("status").is_some() => return Ok(v),
                Ok(v) => last_err = anyhow!("tx {hash58}: no status yet: {v}"),
                Err(e) => last_err = e,
            }
        }
        Err(last_err.context(format!("tx {hash58} did not finish within {deadline:?}")))
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
/// verified root key. Costs gas (~a few TGas burnt) plus 1 yoctoNEAR.
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
    let pk_str = nstorage_core::keys::format_public_key(&signer.key.verifying_key());
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
        .send_and_wait(&signed, &hash, &signer.account_id, Duration::from_secs(120))
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
