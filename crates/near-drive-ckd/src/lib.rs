//! NEAR Drive root keys from NEAR MPC Confidential Key Derivation (CKD).
//!
//! Protocol (near/mpc `request_app_private_key`, see docs/ckd.md):
//!
//! 1. The client picks a fresh ephemeral scalar `a` and sends
//!    `A = (a·G1, a·G2)` (publicly verifiable variant) with a derivation path
//!    and a CKD `domain_id` to the MPC contract (1 yoctoNEAR deposit, ≥15 TGas).
//! 2. The contract binds `app_id = sha3_256("near-mpc v0.1.0 app_id derivation:"
//!    || predecessor || "," || path)`. Only the predecessor account can obtain
//!    this `app_id`.
//! 3. The MPC network returns an ElGamal encryption of the BLS signature
//!    `sig = msk · H(pk || app_id)` on G1: `(Y, C) = (y·G1, sig + y·A1)`.
//! 4. The client decrypts `sig = C − a·Y` and verifies it as a BLS signature
//!    under the domain public key `pk` (G2): `e(H(pk||app_id), pk) == e(sig, G2)`.
//! 5. NEAR Drive maps the 48-byte compressed `sig` to a [`RootKey`] with
//!    HKDF-SHA256(salt = [`HKDF_SALT`], info = [`HKDF_INFO_ROOT`]).
//!
//! The result is deterministic in (MPC master key of the domain, predecessor
//! account, derivation path) and independent of the ephemeral key.
use anyhow::{anyhow, bail, ensure, Context, Result};
use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use group::{prime::PrimeCurveAffine, Curve, Group};
use hkdf::Hkdf;
use near_drive_core::crypto::RootKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

pub mod near;

/// Hash-to-curve DST used by near/mpc (`NEAR_CKD_DOMAIN` in threshold-signatures).
pub const NEAR_CKD_DST: &[u8] = b"NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_";
/// `APP_ID_DERIVATION_PREFIX` in near-mpc-crypto-types/src/kdf.rs.
pub const APP_ID_DERIVATION_PREFIX: &str = "near-mpc v0.1.0 app_id derivation:";
/// Derivation path NEAR Drive asks the MPC contract for. Changing it changes
/// every user's root key: treat it as a wire constant.
pub const DERIVATION_PATH: &str = "near-drive/v1/root";
/// NEAR Drive's HKDF instantiation over the CKD output (application-chosen; the
/// CKD protocol leaves salt/info to the app).
pub const HKDF_SALT: &[u8] = b"near-drive";
pub const HKDF_INFO_ROOT: &[u8] = b"near-drive/v1/root-from-ckd";

pub const G1_LEN: usize = 48;
pub const G2_LEN: usize = 96;

/// MPC contract deployment for one NEAR network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkdNetwork {
    pub network: String,
    pub rpc_url: String,
    pub contract: String,
    /// Domain with `purpose: CKD` (protocol `ConfidentialKeyDerivation`).
    pub domain_id: u64,
}

/// CKD domain NEAR Drive derives root keys in. Another domain (e.g. 6, also
/// CKD) yields a *different* key for the same account, so this is pinned.
pub const PINNED_DOMAIN: u64 = 2;

/// The MPC contract NEAR Drive derives root keys from on `network_name`
/// (near-cli's `network_name`: `mainnet`, `testnet`). `None` for custom
/// networks (sandbox, localnet), which have no pin.
pub fn pinned_contract(network_name: &str) -> Option<&'static str> {
    match network_name {
        "mainnet" => Some("v1.signer"),
        "testnet" => Some("v1.signer-prod.testnet"),
        _ => None,
    }
}

/// Where a CKD request goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkdTarget {
    pub contract: String,
    pub domain_id: u64,
    /// The pinned contract and domain of a known network.
    pub pinned: bool,
}

/// Picks the MPC contract and domain for `network_name`.
///
/// The root key depends on both, so a typo or an edited near-cli connection
/// (`connection_contract` = its `mpc_contract_account_id`) must not silently
/// produce a different key. On mainnet/testnet the pinned contract and
/// [`PINNED_DOMAIN`] are used; anything else (a different `--ckd-contract` or
/// `--ckd-domain`, or a connection pointing elsewhere) is refused unless
/// `unpinned`. Custom networks have no pin: both flags must be given.
pub fn resolve_target(
    network_name: &str,
    connection_contract: Option<&str>,
    flag_contract: Option<&str>,
    flag_domain: Option<u64>,
    unpinned: bool,
) -> Result<CkdTarget> {
    let Some(pin) = pinned_contract(network_name) else {
        let (Some(c), Some(d)) = (flag_contract, flag_domain) else {
            bail!(
                "network {network_name:?} has no pinned MPC contract (only mainnet and testnet do); \
                 pass --ckd-contract and --ckd-domain explicitly{}",
                connection_contract.map(|c| format!(" (the near-cli connection names {c})")).unwrap_or_default()
            );
        };
        return Ok(CkdTarget { contract: c.into(), domain_id: d, pinned: false });
    };
    let why = "a different MPC contract or domain derives a different root key, \
               so data and records made with your usual key would not match";
    if !unpinned {
        if let Some(c) = flag_contract.filter(|c| *c != pin) {
            bail!("--ckd-contract {c} is not NEAR Drive's MPC contract on {network_name} ({pin}): {why}. Pass --ckd-unpinned if you really mean it");
        }
        if let Some(d) = flag_domain.filter(|d| *d != PINNED_DOMAIN) {
            bail!("--ckd-domain {d} is not NEAR Drive's CKD domain ({PINNED_DOMAIN}): {why}. Pass --ckd-unpinned if you really mean it");
        }
        if flag_contract.is_none() {
            if let Some(cc) = connection_contract.filter(|cc| *cc != pin) {
                bail!(
                    "the near-cli connection's mpc_contract_account_id is {cc}, not NEAR Drive's MPC contract on {network_name} ({pin}): {why}. \
                     Fix the connection (`near config edit-connection`), pass --ckd-contract {pin}, or --ckd-unpinned to use {cc}"
                );
            }
        }
        return Ok(CkdTarget { contract: pin.into(), domain_id: PINNED_DOMAIN, pinned: true });
    }
    let contract = flag_contract.or(connection_contract).unwrap_or(pin).to_string();
    let domain_id = flag_domain.unwrap_or(PINNED_DOMAIN);
    let pinned = contract == pin && domain_id == PINNED_DOMAIN;
    Ok(CkdTarget { contract, domain_id, pinned })
}

impl CkdNetwork {
    /// Known deployments (checked 2026-11-19 via the `state` view: domains 2
    /// and 6 are CKD on both networks; 2 is the one the near/mpc docs use and
    /// the one NEAR Drive pins).
    pub fn for_network(network: &str) -> Result<Self> {
        let contract = pinned_contract(network).ok_or_else(|| {
            anyhow!("unknown network {network:?}; pass --ckd-contract and --ckd-rpc explicitly")
        })?;
        let rpc = match network {
            "mainnet" => "https://rpc.mainnet.near.org",
            _ => "https://rpc.testnet.near.org",
        };
        Ok(Self {
            network: network.into(),
            rpc_url: rpc.into(),
            contract: contract.into(),
            domain_id: PINNED_DOMAIN,
        })
    }

    /// Known deployment for `network` with optional overrides; unknown
    /// networks need both `contract` and `rpc_url`.
    pub fn resolve(
        network: &str,
        contract: Option<String>,
        rpc_url: Option<String>,
        domain_id: Option<u64>,
    ) -> Result<Self> {
        let mut n = match Self::for_network(network) {
            Ok(n) => n,
            Err(e) => Self {
                network: network.into(),
                rpc_url: rpc_url.clone().ok_or(e)?,
                contract: contract
                    .clone()
                    .context("--ckd-contract is required for this network")?,
                domain_id: 2,
            },
        };
        if let Some(c) = contract {
            n.contract = c;
        }
        if let Some(r) = rpc_url {
            n.rpc_url = r;
        }
        if let Some(d) = domain_id {
            n.domain_id = d;
        }
        Ok(n)
    }
}

/// `app_id` exactly as the MPC contract computes it from the predecessor.
pub fn derive_app_id(account_id: &str, derivation_path: &str) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(format!(
        "{APP_ID_DERIVATION_PREFIX}{account_id},{derivation_path}"
    ));
    h.finalize().into()
}

// ---------- encodings: "bls12381g1:<base58 compressed>" ----------

fn decode_prefixed<const N: usize>(s: &str, prefix: &str) -> Result<[u8; N]> {
    let b58 = s
        .strip_prefix(prefix)
        .and_then(|r| r.strip_prefix(':'))
        .ok_or_else(|| anyhow!("expected {prefix}:<base58>, got {s:?}"))?;
    bs58::decode(b58)
        .into_vec()?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("{prefix} must be {N} bytes, got {}", v.len()))
}

pub fn parse_g1(s: &str) -> Result<G1Projective> {
    let b = decode_prefixed::<G1_LEN>(s, "bls12381g1")?;
    let p: Option<G1Affine> = G1Affine::from_compressed(&b).into();
    Ok(
        p.context("invalid G1 point (not on curve / not in subgroup)")?
            .into(),
    )
}

pub fn parse_g2(s: &str) -> Result<G2Projective> {
    let b = decode_prefixed::<G2_LEN>(s, "bls12381g2")?;
    let p: Option<G2Affine> = G2Affine::from_compressed(&b).into();
    Ok(
        p.context("invalid G2 point (not on curve / not in subgroup)")?
            .into(),
    )
}

pub fn format_g1(p: &G1Projective) -> String {
    format!(
        "bls12381g1:{}",
        bs58::encode(p.to_compressed()).into_string()
    )
}

pub fn format_g2(p: &G2Projective) -> String {
    format!(
        "bls12381g2:{}",
        bs58::encode(p.to_compressed()).into_string()
    )
}

// ---------- request / response ----------

/// Ephemeral ElGamal key for one CKD request. Never persisted.
pub struct EphemeralKey {
    a: Scalar,
}

impl EphemeralKey {
    pub fn generate() -> Self {
        Self {
            a: Scalar::random(rand::rngs::OsRng),
        }
    }
    /// For tests / vectors only.
    pub fn from_scalar(a: Scalar) -> Self {
        Self { a }
    }
    pub fn pk1(&self) -> G1Projective {
        G1Projective::generator() * self.a
    }
    pub fn pk2(&self) -> G2Projective {
        G2Projective::generator() * self.a
    }
}

impl Drop for EphemeralKey {
    fn drop(&mut self) {
        self.a = Scalar::ZERO;
    }
}

/// JSON args of `request_app_private_key` (wrapped as `{"request": ...}`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CkdRequestArgs {
    pub derivation_path: String,
    pub app_public_key: AppPublicKey,
    pub domain_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AppPublicKey {
    /// Privately verifiable (legacy): only the app can check the output.
    AppPublicKey(String),
    /// Publicly verifiable: the contract checks `e(A1,G2) == e(G1,A2)` on the
    /// request and the encrypted output on `respond_ckd`.
    AppPublicKeyPV { pk1: String, pk2: String },
}

impl CkdRequestArgs {
    pub fn new(eph: &EphemeralKey, derivation_path: &str, domain_id: u64) -> Self {
        Self {
            derivation_path: derivation_path.into(),
            app_public_key: AppPublicKey::AppPublicKeyPV {
                pk1: format_g1(&eph.pk1()),
                pk2: format_g2(&eph.pk2()),
            },
            domain_id,
        }
    }
    /// Function-call args bytes.
    pub fn to_call_args(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "request": self })).expect("serializable")
    }
}

/// `CKDResponse` returned by the contract (the receipt's SuccessValue).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CkdResponse {
    pub big_y: String,
    pub big_c: String,
}

/// BLS verification of the decrypted CKD output (as in ckd-example-cli `verify`).
pub fn verify_sig(mpc_pk: &G2Projective, app_id: &[u8], sig: &G1Projective) -> bool {
    let s: G1Affine = sig.to_affine();
    let pk: G2Affine = mpc_pk.to_affine();
    if bool::from(s.is_identity()) || bool::from(pk.is_identity()) {
        return false;
    }
    // from_compressed / projective arithmetic already guarantee on-curve and
    // subgroup membership for parsed points; check anyway for direct callers.
    if !bool::from(s.is_on_curve() & s.is_torsion_free() & pk.is_on_curve() & pk.is_torsion_free())
    {
        return false;
    }
    let h = hash_to_g1(mpc_pk, app_id).to_affine();
    blstrs::pairing(&h, &pk) == blstrs::pairing(&s, &G2Affine::generator())
}

/// `H(pk, app_id)` = hash_to_curve_G1(pk_compressed(96) || app_id).
pub fn hash_to_g1(mpc_pk: &G2Projective, app_id: &[u8]) -> G1Projective {
    let input = [mpc_pk.to_compressed().as_slice(), app_id].concat();
    G1Projective::hash_to_curve(&input, NEAR_CKD_DST, &[])
}

/// Decrypts `(Y, C)` with the ephemeral key and verifies the result against
/// the domain public key. Returns the 48-byte compressed BLS signature (the
/// raw CKD secret).
pub fn decrypt_and_verify(
    resp: &CkdResponse,
    eph: &EphemeralKey,
    app_id: &[u8; 32],
    mpc_pk: &G2Projective,
) -> Result<[u8; G1_LEN]> {
    let big_y = parse_g1(&resp.big_y).context("big_y")?;
    let big_c = parse_g1(&resp.big_c).context("big_c")?;
    let sig = big_c - big_y * eph.a;
    ensure!(
        verify_sig(mpc_pk, app_id, &sig),
        "CKD output failed BLS verification against the MPC public key"
    );
    Ok(sig.to_compressed())
}

/// Maps the raw CKD secret to an NEAR Drive root key.
pub fn root_key_from_ckd_secret(sig: &[u8; G1_LEN]) -> RootKey {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(HKDF_SALT), sig)
        .expand(HKDF_INFO_ROOT, &mut out)
        .expect("32 bytes is a valid HKDF length");
    let k = RootKey::from_bytes(out);
    out.zeroize();
    k
}

/// Full client-side processing of a CKD response for `account_id`.
pub fn root_key_from_response(
    resp: &CkdResponse,
    eph: &EphemeralKey,
    account_id: &str,
    derivation_path: &str,
    mpc_pk: &G2Projective,
) -> Result<RootKey> {
    let app_id = derive_app_id(account_id, derivation_path);
    let mut sig = decrypt_and_verify(resp, eph, &app_id, mpc_pk)?;
    let k = root_key_from_ckd_secret(&sig);
    sig.zeroize();
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plays the MPC side: (Y, C) = (y·G1, msk·H(pk||app_id) + y·A1).
    pub(crate) fn simulate(
        msk: Scalar,
        eph: &EphemeralKey,
        app_id: &[u8],
    ) -> (G2Projective, CkdResponse) {
        let pk = G2Projective::generator() * msk;
        let sig = hash_to_g1(&pk, app_id) * msk;
        let y = Scalar::random(rand::rngs::OsRng);
        let resp = CkdResponse {
            big_y: format_g1(&(G1Projective::generator() * y)),
            big_c: format_g1(&(sig + eph.pk1() * y)),
        };
        (pk, resp)
    }

    #[test]
    fn app_id_matches_near_mpc_snapshot() {
        // near-mpc-crypto-types kdf.rs snapshot `derive_app_id__has_not_changed`,
        // entries [0] ("dwefqwg","frwewegwegweg") and [1] ("dwefqwg","fwei2.3f230").
        assert_eq!(
            hex::encode(derive_app_id("dwefqwg", "frwewegwegweg")),
            "b8177b00468f97c337b3f921fbef7aaa959e9a49005aaa59768b795152f4c989"
        );
        let v1: [u8; 32] = [
            22, 172, 125, 184, 183, 195, 173, 44, 94, 143, 231, 209, 169, 233, 28, 166, 99, 76,
            249, 186, 248, 73, 82, 248, 87, 149, 245, 21, 226, 156, 210, 117,
        ];
        assert_eq!(derive_app_id("dwefqwg", "fwei2.3f230"), v1);
    }

    #[test]
    fn deterministic_across_ephemeral_keys_and_bound_to_account() {
        let msk = Scalar::random(rand::rngs::OsRng);
        let id = derive_app_id("alice.testnet", DERIVATION_PATH);
        let e1 = EphemeralKey::generate();
        let e2 = EphemeralKey::generate();
        let (pk, r1) = simulate(msk, &e1, &id);
        let (_, r2) = simulate(msk, &e2, &id);
        assert_ne!(r1, r2);
        let k1 = root_key_from_response(&r1, &e1, "alice.testnet", DERIVATION_PATH, &pk).unwrap();
        let k2 = root_key_from_response(&r2, &e2, "alice.testnet", DERIVATION_PATH, &pk).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
        // Response for alice cannot be passed off as bob's.
        assert!(root_key_from_response(&r1, &e1, "bob.testnet", DERIVATION_PATH, &pk).is_err());
        // Different path → verification fails (different app_id).
        assert!(root_key_from_response(&r1, &e1, "alice.testnet", "other", &pk).is_err());
    }

    #[test]
    fn rejects_wrong_ephemeral_key_tampering_and_wrong_pk() {
        let msk = Scalar::random(rand::rngs::OsRng);
        let id = derive_app_id("alice.testnet", DERIVATION_PATH);
        let e = EphemeralKey::generate();
        let (pk, r) = simulate(msk, &e, &id);
        assert!(decrypt_and_verify(&r, &EphemeralKey::generate(), &id, &pk).is_err());
        let mut t = r.clone();
        t.big_c = format_g1(&(parse_g1(&r.big_c).unwrap() + G1Projective::generator()));
        assert!(decrypt_and_verify(&t, &e, &id, &pk).is_err());
        let other_pk = G2Projective::generator() * Scalar::random(rand::rngs::OsRng);
        assert!(decrypt_and_verify(&r, &e, &id, &other_pk).is_err());
        // Identity "signature" (C = a·Y) must be rejected.
        let y = parse_g1(&r.big_y).unwrap();
        let id_resp = CkdResponse {
            big_y: r.big_y.clone(),
            big_c: format_g1(&(y * e.a)),
        };
        assert!(decrypt_and_verify(&id_resp, &e, &id, &pk).is_err());
    }

    #[test]
    fn request_json_shape() {
        let e = EphemeralKey::generate();
        let args = CkdRequestArgs::new(&e, DERIVATION_PATH, 2);
        let v: serde_json::Value = serde_json::from_slice(&args.to_call_args()).unwrap();
        assert_eq!(v["request"]["domain_id"], 2);
        assert_eq!(v["request"]["derivation_path"], DERIVATION_PATH);
        let pv = &v["request"]["app_public_key"]["AppPublicKeyPV"];
        assert!(pv["pk1"].as_str().unwrap().starts_with("bls12381g1:"));
        assert!(pv["pk2"].as_str().unwrap().starts_with("bls12381g2:"));
        assert_eq!(parse_g1(pv["pk1"].as_str().unwrap()).unwrap(), e.pk1());
        assert_eq!(parse_g2(pv["pk2"].as_str().unwrap()).unwrap(), e.pk2());
    }

    #[test]
    fn parses_contract_readme_example_keys() {
        // From near/mpc crates/contract/README.md (CKD request examples).
        parse_g1("bls12381g1:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6")
            .unwrap();
        assert!(parse_g1(
            "bls12381g2:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6"
        )
        .is_err());
        assert!(parse_g1("bls12381g1:111").is_err());
    }

    #[test]
    fn ckd_target_is_pinned() {
        let t = resolve_target("mainnet", Some("v1.signer"), None, None, false).unwrap();
        assert_eq!(t, CkdTarget { contract: "v1.signer".into(), domain_id: 2, pinned: true });
        let t = resolve_target("testnet", None, Some("v1.signer-prod.testnet"), Some(2), false).unwrap();
        assert!(t.pinned && t.contract == "v1.signer-prod.testnet");
        // Other domain / contract / an edited connection: refused without --ckd-unpinned.
        let e = resolve_target("testnet", None, None, Some(6), false).unwrap_err().to_string();
        assert!(e.contains("--ckd-unpinned") && e.contains("domain 6"), "{e}");
        assert!(resolve_target("testnet", None, Some("evil.testnet"), None, false).is_err());
        let e = resolve_target("mainnet", Some("evil.near"), None, None, false).unwrap_err().to_string();
        assert!(e.contains("evil.near") && e.contains("v1.signer"), "{e}");
        // An explicit pinned --ckd-contract overrides the odd connection.
        assert!(resolve_target("mainnet", Some("evil.near"), Some("v1.signer"), None, false).unwrap().pinned);
        // --ckd-unpinned: the flag, else the connection; reported as unpinned.
        let t = resolve_target("testnet", None, None, Some(6), true).unwrap();
        assert_eq!((t.contract.as_str(), t.domain_id, t.pinned), ("v1.signer-prod.testnet", 6, false));
        let t = resolve_target("mainnet", Some("evil.near"), None, None, true).unwrap();
        assert_eq!((t.contract.as_str(), t.pinned), ("evil.near", false));
        assert!(resolve_target("mainnet", None, None, None, true).unwrap().pinned);
        // Custom networks: both flags required; the connection alone is not enough.
        assert!(resolve_target("localnet", Some("v1.signer.test.near"), None, None, false).is_err());
        assert!(resolve_target("localnet", None, Some("v1.signer.test.near"), None, false).is_err());
        let t = resolve_target("localnet", None, Some("v1.signer.test.near"), Some(1), false).unwrap();
        assert_eq!((t.contract.as_str(), t.domain_id, t.pinned), ("v1.signer.test.near", 1, false));
    }

    #[test]
    fn root_key_domain_separated() {
        let sig = [7u8; G1_LEN];
        let k = root_key_from_ckd_secret(&sig);
        let mut plain = [0u8; 32];
        Hkdf::<Sha256>::new(None, &sig)
            .expand(b"", &mut plain)
            .unwrap();
        assert_ne!(k.as_bytes(), &plain);
        let mut expect = [0u8; 32];
        Hkdf::<Sha256>::new(Some(b"near-drive"), &sig)
            .expand(b"near-drive/v1/root-from-ckd", &mut expect)
            .unwrap();
        assert_eq!(k.as_bytes(), &expect);
    }
}
