//! Checks our CKD client math against the reference test vectors from
//! near/mpc `crates/threshold-signatures/tests/vectors/ckd_test_vectors.json`
//! (MIT, copied verbatim; commit 483e9ff, 2026-11-18).
use blstrs::{G1Affine, G1Projective, G2Projective, Scalar};
use group::Group;
use hkdf::Hkdf;
use near_drive_ckd::*;
use serde::Deserialize;
use sha2::Sha256;

#[derive(Deserialize)]
struct Vectors {
    vectors: Vec<V>,
}

#[derive(Deserialize)]
struct V {
    msk: String,
    a: String,
    app_id: String,
    pk: String,
    app_pk1: String,
    app_pk2: String,
    hash_point: String,
    big_y: String,
    big_c: String,
    sig: String,
    s: String,
}

fn scalar(be_hex: &str) -> Scalar {
    let b: [u8; 32] = hex::decode(be_hex).unwrap().try_into().unwrap();
    Option::from(Scalar::from_bytes_be(&b)).expect("canonical scalar")
}

fn g1_hex(h: &str) -> G1Projective {
    let b: [u8; 48] = hex::decode(h).unwrap().try_into().unwrap();
    let p: Option<G1Affine> = G1Affine::from_compressed(&b).into();
    p.unwrap().into()
}

fn b58_g1(h: &str) -> String {
    format!(
        "bls12381g1:{}",
        bs58::encode(hex::decode(h).unwrap()).into_string()
    )
}

fn load() -> Vec<V> {
    let s = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/ckd_test_vectors.json"
    ))
    .unwrap();
    serde_json::from_str::<Vectors>(&s).unwrap().vectors
}

#[test]
fn reference_vectors() {
    let vs = load();
    assert!(vs.len() >= 4);
    for v in vs {
        let msk = scalar(&v.msk);
        let a = scalar(&v.a);
        let app_id = hex::decode(&v.app_id).unwrap();
        let pk = G2Projective::generator() * msk;
        assert_eq!(hex::encode(pk.to_compressed()), v.pk, "pk");
        let eph = EphemeralKey::from_scalar(a);
        assert_eq!(hex::encode(eph.pk1().to_compressed()), v.app_pk1, "app_pk1");
        assert_eq!(hex::encode(eph.pk2().to_compressed()), v.app_pk2, "app_pk2");
        assert_eq!(
            hex::encode(hash_to_g1(&pk, &app_id).to_compressed()),
            v.hash_point,
            "H(pk||app_id)"
        );

        // Decrypt the recorded (Y, C) and verify.
        let resp = CkdResponse {
            big_y: b58_g1(&v.big_y),
            big_c: b58_g1(&v.big_c),
        };
        let id: [u8; 32] = app_id.clone().try_into().unwrap();
        let pk_s = format_g2(&pk);
        let sig = decrypt_and_verify(&resp, &eph, &id, &parse_g2(&pk_s).unwrap()).unwrap();
        assert_eq!(hex::encode(sig), v.sig, "sig");
        assert!(verify_sig(&pk, &app_id, &g1_hex(&v.sig)));

        // Reference HKDF instantiation (salt none, info "") reproduces `s`.
        let mut s = [0u8; 32];
        Hkdf::<Sha256>::new(None, &sig).expand(b"", &mut s).unwrap();
        assert_eq!(hex::encode(s), v.s, "s");

        // NEAR Drive's root is a distinct, domain-separated HKDF of the same sig.
        let root = root_key_from_ckd_secret(&sig);
        assert_ne!(hex::encode(root.as_bytes()), v.s);
    }
}
