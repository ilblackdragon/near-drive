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

/// A NEAR credentials file: `~/.near-credentials/<network>/<account>.json`
/// (legacy near-cli), or near-cli-rs's per-key
/// `<network>/<account>/ed25519_<pk>.json`, which has no `account_id` (only
/// `implicit_account_id`, `public_key`, `private_key`).
#[derive(Debug, Deserialize)]
pub struct NearCredentials {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(alias = "secret_key")]
    pub private_key: String,
}

/// The account a credentials file at `path` belongs to when the file does
/// not say: `<account>.json`, or `<account>/ed25519_<pk>.json`.
fn account_from_path(path: &std::path::Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    let name = if stem.starts_with("ed25519_") || stem.starts_with("ed25519:") {
        path.parent()?.file_name()?.to_str()?
    } else {
        stem
    };
    crate::uri::validate_account_id(name).ok()?;
    Some(name.to_string())
}

impl NearCredentials {
    /// Loads and checks a credentials file. The account is the file's
    /// `account_id`, else `account` (e.g. `--account`), else taken from the
    /// file name. A file's `account_id` that differs from `account` is an error.
    pub fn load_for(path: &std::path::Path, account: Option<&str>) -> Result<(String, SigningKey)> {
        let c: NearCredentials = serde_json::from_slice(
            &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        )
        .with_context(|| format!("parsing {}", path.display()))?;
        let sk = parse_secret_key(&c.private_key)?;
        if let Some(pk) = &c.public_key {
            if format_public_key(&sk.verifying_key()) != *pk {
                bail!("credentials file public_key does not match private_key");
            }
        }
        let account_id = match (c.account_id, account) {
            (Some(f), Some(a)) if f != a => bail!("credentials {} are for {f}, not {a}", path.display()),
            (Some(f), _) => f,
            (None, Some(a)) => a.to_string(),
            (None, None) => account_from_path(path).with_context(|| {
                format!("{} has no account_id; pass the account (--account)", path.display())
            })?,
        };
        Ok((account_id, sk))
    }

    /// [`load_for`](Self::load_for) without an account hint.
    pub fn load(path: &std::path::Path) -> Result<(String, SigningKey)> {
        Self::load_for(path, None)
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

    #[test]
    fn credentials_without_account_id() {
        let dir = std::env::temp_dir().join(format!("nd-creds-{}", std::process::id()));
        let sk = SigningKey::from_bytes(&[3; 32]);
        let pk = format_public_key(&sk.verifying_key());
        // near-cli-rs 0.29 per-key file: no account_id.
        let keydir = dir.join("testnet").join("alice.testnet");
        std::fs::create_dir_all(&keydir).unwrap();
        let file = keydir.join(format!("{}.json", pk.replace(':', "_")));
        let body = serde_json::json!({
            "implicit_account_id": hex::encode(sk.verifying_key().as_bytes()),
            "public_key": pk,
            "private_key": format_secret_key(&sk),
        });
        std::fs::write(&file, body.to_string()).unwrap();
        let (a, k) = NearCredentials::load_for(&file, Some("bob.testnet")).unwrap();
        assert_eq!((a.as_str(), k.to_bytes()), ("bob.testnet", sk.to_bytes()));
        // No hint: the account directory the key file sits in.
        assert_eq!(NearCredentials::load(&file).unwrap().0, "alice.testnet");
        // Legacy `<account>.json` without account_id: the file name.
        let legacy = dir.join("carol.testnet.json");
        std::fs::write(&legacy, body.to_string()).unwrap();
        assert_eq!(NearCredentials::load(&legacy).unwrap().0, "carol.testnet");
        // account_id present and different from the hint: refused.
        let named = dir.join("named.json");
        let mut b = body.clone();
        b["account_id"] = "dave.testnet".into();
        std::fs::write(&named, b.to_string()).unwrap();
        assert_eq!(NearCredentials::load_for(&named, Some("dave.testnet")).unwrap().0, "dave.testnet");
        assert!(NearCredentials::load_for(&named, Some("eve.testnet")).is_err());
        // Public key that does not match: refused.
        b["public_key"] = format_public_key(&SigningKey::from_bytes(&[4; 32]).verifying_key()).into();
        std::fs::write(&named, b.to_string()).unwrap();
        assert!(NearCredentials::load(&named).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
