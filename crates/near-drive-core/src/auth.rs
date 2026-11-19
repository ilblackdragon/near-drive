//! Request authentication for the native API.
//!
//! Headers: X-Near-Account, X-Near-PublicKey, X-Near-Timestamp (unix ms),
//! X-Near-Signature (base58 ed25519 over `canonical_request`).
use crate::keys;
use ed25519_dalek::SigningKey;

pub const H_ACCOUNT: &str = "x-near-account";
pub const H_PUBKEY: &str = "x-near-publickey";
pub const H_TS: &str = "x-near-timestamp";
pub const H_SIG: &str = "x-near-signature";
pub const MAX_SKEW_MS: u64 = 5 * 60 * 1000;

pub fn canonical_request(method: &str, path: &str, query: &str, account: &str, public_key: &str, ts_ms: u64, body: &[u8]) -> Vec<u8> {
    format!(
        "near-drive-req-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path,
        query,
        account,
        public_key,
        ts_ms,
        blake3::hash(body).to_hex()
    )
    .into_bytes()
}

pub struct SignedHeaders {
    pub account: String,
    pub public_key: String,
    pub ts_ms: u64,
    pub signature: String,
}

pub fn sign_request(account: &str, sk: &SigningKey, method: &str, path: &str, query: &str, ts_ms: u64, body: &[u8]) -> SignedHeaders {
    let public_key = keys::format_public_key(&sk.verifying_key());
    let msg = canonical_request(method, path, query, account, &public_key, ts_ms, body);
    SignedHeaders { account: account.into(), public_key, ts_ms, signature: keys::sign(sk, &msg) }
}
