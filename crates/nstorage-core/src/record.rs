//! Signed pointer records: the only mutable state. `(namespace, path) -> manifest`.
use crate::keys;
use anyhow::{ensure, Result};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PointerRecord {
    pub namespace: String,
    pub path: String,
    pub manifest_cid: String,
    /// Plaintext size.
    pub size: u64,
    /// Stored size (manifest + chunks), used for metering.
    pub stored_size: u64,
    /// Monotonic per (namespace, path); 1 for a new object. CAS on prev = seq-1.
    pub seq: u64,
    pub writer: String,
    pub writer_pk: String,
    pub ts_ms: u64,
    pub sig: String,
}

impl PointerRecord {
    fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "nstorage-record-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.namespace,
            self.path,
            self.manifest_cid,
            self.size,
            self.stored_size,
            self.seq,
            self.writer,
            self.writer_pk,
            self.ts_ms
        )
        .into_bytes()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_signed(
        namespace: &str,
        path: &str,
        manifest_cid: &str,
        size: u64,
        stored_size: u64,
        seq: u64,
        writer: &str,
        sk: &SigningKey,
        ts_ms: u64,
    ) -> Self {
        let mut r = Self {
            namespace: namespace.into(),
            path: path.into(),
            manifest_cid: manifest_cid.into(),
            size,
            stored_size,
            seq,
            writer: writer.into(),
            writer_pk: keys::format_public_key(&sk.verifying_key()),
            ts_ms,
            sig: String::new(),
        };
        r.sig = keys::sign(sk, &r.signing_bytes());
        r
    }

    /// Checks the signature only. Whether `writer_pk` belongs to `writer`
    /// and whether `writer` may write `path` is checked against NEAR state.
    pub fn verify_signature(&self) -> Result<()> {
        ensure!(self.seq >= 1, "seq must be >= 1");
        ensure!(crate::is_valid_cid(&self.manifest_cid), "bad manifest cid");
        let pk = keys::parse_public_key(&self.writer_pk)?;
        keys::verify(&pk, &self.signing_bytes(), &self.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sign_verify_tamper() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let cid = crate::cid(b"m");
        let r = PointerRecord::new_signed("a.near", "x/y", &cid, 5, 21, 1, "a.near", &sk, 1);
        r.verify_signature().unwrap();
        let mut t = r.clone();
        t.path = "x/z".into();
        assert!(t.verify_signature().is_err());
        let mut t = r.clone();
        t.seq = 2;
        assert!(t.verify_signature().is_err());
    }
}
