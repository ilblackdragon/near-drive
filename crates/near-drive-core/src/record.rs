//! Signed pointer records: the only mutable state. `(namespace, path) -> manifest`.
use crate::{keys, policy};
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
    /// The writer's record-signing key (`RootKey::signing_key`), published
    /// onchain with `set_sign_key`. Not the NEAR access key used for requests.
    pub writer_pk: String,
    pub ts_ms: u64,
    pub sig: String,
}

impl PointerRecord {
    fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "near-drive-record-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
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
    /// and whether `writer` may write `path` is [`PointerRecord::verify_writer`].
    pub fn verify_signature(&self) -> Result<()> {
        ensure!(self.seq >= 1, "seq must be >= 1");
        ensure!(crate::is_valid_cid(&self.manifest_cid), "bad manifest cid");
        let pk = keys::parse_public_key(&self.writer_pk)?;
        keys::verify(&pk, &self.signing_bytes(), &self.sig)
    }

    /// Reader rule, given NEAR state: `writer_pk` was `writer`'s published
    /// signing key at `ts_ms` (`sign_keys` = `get_sign_keys(writer)`), and the
    /// namespace policy (`rules` = `get_rules(namespace)`) lets `writer` write
    /// `path`. Call after [`PointerRecord::verify_signature`].
    pub fn verify_writer(&self, sign_keys: &[SignKeyEntry], rules: &[policy::Rule]) -> Result<()> {
        ensure!(
            key_in_force(sign_keys, &self.writer_pk, self.ts_ms),
            "{}/{} is signed with {}, which is not a signing key {} had published at {} ms",
            self.namespace,
            self.path,
            self.writer_pk,
            self.writer,
            self.ts_ms
        );
        ensure!(
            policy::resolve(&self.namespace, rules, &self.path, &self.writer).write,
            "{} is not allowed to write {}/{}",
            self.writer,
            self.namespace,
            self.path
        );
        Ok(())
    }
}

/// One entry of an account's signing-key history in `drive.near`
/// (`get_sign_keys`, oldest first). JSON: `{"key": "ed25519:...", "since_ms": "123"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignKeyEntry {
    pub key: String,
    /// Block time (ms) when the key was published; a JSON string (U64).
    #[serde(with = "u64_str")]
    pub since_ms: u64,
}

mod u64_str {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        String::deserialize(d)?.parse().map_err(D::Error::custom)
    }
}

/// Clock slack around key changes (same as the request timestamp window).
pub const SIGN_KEY_SKEW_MS: u64 = crate::auth::MAX_SKEW_MS;

/// Whether `pk` was in force at `ts_ms`: entry `i` covers
/// `[since_i - skew, since_{i+1} + skew)`, the latest entry is open-ended.
pub fn key_in_force(history: &[SignKeyEntry], pk: &str, ts_ms: u64) -> bool {
    history.iter().enumerate().any(|(i, e)| {
        e.key == pk
            && ts_ms >= e.since_ms.saturating_sub(SIGN_KEY_SKEW_MS)
            && history.get(i + 1).is_none_or(|next| ts_ms < next.since_ms.saturating_add(SIGN_KEY_SKEW_MS))
    })
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

    fn e(key: &str, since_ms: u64) -> SignKeyEntry {
        SignKeyEntry { key: key.into(), since_ms }
    }

    #[test]
    fn key_windows() {
        const M: u64 = 60_000;
        let h = [e("A", 100 * M), e("B", 200 * M), e("A", 300 * M)];
        assert!(!key_in_force(&h, "A", 94 * M));
        assert!(key_in_force(&h, "A", 95 * M));
        assert!(key_in_force(&h, "A", 204 * M));
        assert!(!key_in_force(&h, "A", 205 * M));
        assert!(key_in_force(&h, "B", 195 * M));
        assert!(!key_in_force(&h, "B", 194 * M));
        assert!(!key_in_force(&h, "B", 305 * M));
        assert!(key_in_force(&h, "A", 295 * M) && key_in_force(&h, "A", u64::MAX));
        assert!(!key_in_force(&[], "A", 1));
        assert!(!key_in_force(&h, "C", 200 * M));
        let j = serde_json::to_string(&h[0]).unwrap();
        assert_eq!(j, r#"{"key":"A","since_ms":"6000000"}"#);
        assert_eq!(serde_json::from_str::<SignKeyEntry>(&j).unwrap(), h[0]);
    }

    #[test]
    fn verify_writer_checks_key_and_rules() {
        let root = crate::crypto::RootKey::from_bytes([3; 32]);
        let cid = crate::cid(b"m");
        let r = PointerRecord::new_signed("app.near", "users/bob.near/x", &cid, 1, 2, 1, "bob.near", &root.signing_key(), 1_000_000);
        let keys = [e(&root.sign_public_key(), 1_000_000)];
        let rules: Vec<policy::Rule> = serde_json::from_str(r#"[{"prefix":"users/{account}/","write":["{account}"]}]"#).unwrap();
        r.verify_writer(&keys, &rules).unwrap();
        assert!(r.verify_writer(&keys, &[]).is_err(), "owner-only by default");
        assert!(r.verify_writer(&[], &rules).is_err());
        let other = crate::crypto::RootKey::from_bytes([4; 32]);
        assert!(r.verify_writer(&[e(&other.sign_public_key(), 0)], &rules).is_err());
    }
}
