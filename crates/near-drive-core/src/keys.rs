//! NEAR-format ed25519 keys: `ed25519:<base58>`.
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Deserialize;

pub fn parse_public_key(s: &str) -> Result<VerifyingKey> {
    let b58 = s.strip_prefix("ed25519:").ok_or_else(|| anyhow!("only ed25519 keys are supported"))?;
    let bytes: [u8; 32] = bs58::decode(b58)
        .into_vec()?
        .try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes"))?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

pub fn format_public_key(k: &VerifyingKey) -> String {
    format!("ed25519:{}", bs58::encode(k.as_bytes()).into_string())
}

/// NEAR secret keys are base58 of 64 bytes (seed || public key).
pub fn parse_secret_key(s: &str) -> Result<SigningKey> {
    let b58 = s.strip_prefix("ed25519:").ok_or_else(|| anyhow!("only ed25519 keys are supported"))?;
    let bytes = bs58::decode(b58).into_vec()?;
    let seed: [u8; 32] = match bytes.len() {
        64 | 32 => bytes[..32].try_into().unwrap(),
        n => bail!("secret key must be 32 or 64 bytes, got {n}"),
    };
    let sk = SigningKey::from_bytes(&seed);
    if bytes.len() == 64 && sk.verifying_key().as_bytes() != &bytes[32..] {
        bail!("secret key does not match its embedded public key");
    }
    Ok(sk)
}

pub fn format_secret_key(k: &SigningKey) -> String {
    let mut b = k.to_bytes().to_vec();
    b.extend_from_slice(k.verifying_key().as_bytes());
    format!("ed25519:{}", bs58::encode(b).into_string())
}

pub fn sign(k: &SigningKey, msg: &[u8]) -> String {
    bs58::encode(k.sign(msg).to_bytes()).into_string()
}

pub fn verify(pk: &VerifyingKey, msg: &[u8], sig_b58: &str) -> Result<()> {
    let bytes: [u8; 64] = bs58::decode(sig_b58)
        .into_vec()?
        .try_into()
        .map_err(|_| anyhow!("signature must be 64 bytes"))?;
    pk.verify(msg, &Signature::from_bytes(&bytes)).map_err(|_| anyhow!("bad signature"))
}

/// `~/.near-credentials/<network>/<account>.json`
#[derive(Debug, Deserialize)]
pub struct NearCredentials {
    pub account_id: String,
    pub public_key: String,
    pub private_key: String,
}

impl NearCredentials {
    pub fn load(path: &std::path::Path) -> Result<(String, SigningKey)> {
        let c: NearCredentials = serde_json::from_slice(
            &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        )?;
        let sk = parse_secret_key(&c.private_key)?;
        if format_public_key(&sk.verifying_key()) != c.public_key {
            bail!("credentials file public_key does not match private_key");
        }
        Ok((c.account_id, sk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let s = format_secret_key(&sk);
        assert_eq!(parse_secret_key(&s).unwrap().to_bytes(), sk.to_bytes());
        let p = format_public_key(&sk.verifying_key());
        let pk = parse_public_key(&p).unwrap();
        let sig = sign(&sk, b"hi");
        verify(&pk, b"hi", &sig).unwrap();
        assert!(verify(&pk, b"ho", &sig).is_err());
    }
}
