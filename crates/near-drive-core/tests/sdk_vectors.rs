//! Consumes `testvectors/`: re-checks the deterministic vectors against this
//! crate, and decrypts objects that the TypeScript and Python SDKs encrypted
//! (`sdk_objects_{ts,py}.json`), requiring byte-identical manifest JSON.
use near_drive_core::{
    cid, crypto,
    crypto::RootKey,
    manifest::Manifest,
    policy::Rule,
    record::{PointerRecord, SignKeyEntry},
};
use serde_json::Value;
use std::path::PathBuf;

fn load(name: &str) -> Option<Value> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors").join(name);
    let s = std::fs::read_to_string(&p).ok()?;
    Some(serde_json::from_str(&s).unwrap())
}

fn roots(v: &Value) -> Vec<(String, RootKey)> {
    v["roots"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, r)| (k.clone(), RootKey::from_bytes(hex::decode(r["root_key"].as_str().unwrap()).unwrap().try_into().unwrap())))
        .collect()
}

fn check_objects(file: &str, objects: &Value, roots: &[(String, RootKey)]) {
    for o in objects.as_array().unwrap() {
        let name = format!("{file}:{}", o["name"]);
        let mjson = o["manifest_json"].as_str().unwrap();
        let m = Manifest::from_bytes(mjson.as_bytes()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(String::from_utf8(m.to_bytes()).unwrap(), mjson, "{name}: manifest bytes differ from serde_json");
        assert_eq!(cid(mjson.as_bytes()), o["manifest_cid"].as_str().unwrap(), "{name}");
        let chunks: Vec<Vec<u8>> = o["chunks_hex"].as_array().unwrap().iter().map(|h| hex::decode(h.as_str().unwrap()).unwrap()).collect();
        assert_eq!(chunks.len(), m.chunks.len(), "{name}");
        for (c, r) in chunks.iter().zip(&m.chunks) {
            assert_eq!(cid(c), r.cid, "{name}");
            assert_eq!(c.len() as u64, r.len, "{name}");
        }
        let pt = o["plaintext_hex"].as_str().unwrap();
        let who = |label: &str| &roots.iter().find(|(k, _)| k == label).unwrap().1;
        for w in o["readable_by"].as_array().unwrap() {
            let w = w.as_str().unwrap();
            let got = match &m.enc {
                None => chunks.concat(),
                Some(e) => crypto::decrypt_object(who(w), e, &chunks).unwrap_or_else(|e| panic!("{name} by {w}: {e}")),
            };
            assert_eq!(hex::encode(got), pt, "{name} by {w}");
        }
        for w in o["not_readable_by"].as_array().unwrap() {
            let w = w.as_str().unwrap();
            assert!(crypto::decrypt_object(who(w), m.enc.as_ref().unwrap(), &chunks).is_err(), "{name}: {w} should not decrypt");
        }
    }
}

#[test]
fn rust_vectors_still_hold() {
    let Some(v) = load("vectors.json") else { return };
    for (_, r) in roots(&v) {
        let j = &v["roots"].as_object().unwrap().values().find(|x| x["root_key"] == hex::encode(r.as_bytes())).unwrap();
        assert_eq!(j["kek_id"], r.kek_id());
        assert_eq!(j["x25519_public"], r.x25519_public());
        assert_eq!(j["sign_seed"], hex::encode(r.signing_key().to_bytes()));
        assert_eq!(j["sign_public_key"], r.sign_public_key());
    }
    let rs = roots(&v);
    for r in v["signed_records"].as_array().unwrap() {
        let rec: PointerRecord = serde_json::from_value(r["record"].clone()).unwrap();
        rec.verify_signature().unwrap();
        let root = &rs.iter().find(|(k, _)| k == r["root"].as_str().unwrap()).unwrap().1;
        let again = PointerRecord::new_signed(&rec.namespace, &rec.path, &rec.manifest_cid, rec.size, rec.stored_size, rec.seq, &rec.writer, &root.signing_key(), rec.ts_ms);
        assert_eq!(again, rec, "ed25519 is deterministic");
    }
    for c in v["writer_checks"].as_array().unwrap() {
        let keys: Vec<SignKeyEntry> = serde_json::from_value(c["sign_keys"].clone()).unwrap();
        let rules: Vec<Rule> = serde_json::from_value(c["rules"].clone()).unwrap();
        let s = |k: &str| c[k].as_str().unwrap().to_string();
        let rec = PointerRecord { namespace: s("namespace"), path: s("path"), manifest_cid: cid(b"m"), size: 0, stored_size: 0, seq: 1, writer: s("writer"), writer_pk: s("writer_pk"), ts_ms: c["ts_ms"].as_u64().unwrap(), sig: String::new() };
        assert_eq!(rec.verify_writer(&keys, &rules).is_ok(), c["accept"].as_bool().unwrap(), "{}", c["name"]);
    }
    for m in v["manifests"].as_array().unwrap() {
        let man: Manifest = serde_json::from_value(m["manifest"].clone()).unwrap();
        assert_eq!(String::from_utf8(man.to_bytes()).unwrap(), m["json"].as_str().unwrap());
    }
    for r in v["records"].as_array().unwrap() {
        let rec: PointerRecord = serde_json::from_value(r["record"].clone()).unwrap();
        rec.verify_signature().unwrap();
    }
    check_objects("vectors.json", &v["objects"], &roots(&v));
}

#[test]
fn sdk_objects_decrypt_in_rust() {
    let Some(v) = load("vectors.json") else { return };
    let roots = roots(&v);
    let mut n = 0;
    for f in ["sdk_objects_ts.json", "sdk_objects_py.json"] {
        if let Some(o) = load(f) {
            check_objects(f, &o["objects"], &roots);
            n += 1;
        }
    }
    assert!(n > 0, "no SDK object vectors found in testvectors/");
}

/// The SDK track's independently generated signing vectors (Python
/// `cryptography`, not SDK code) must hold in Rust too.
#[test]
fn sdk_sign_vectors_hold_in_rust() {
    let Some(v) = load("sdk_sign_vectors.json") else { return };
    let root = |name: &str| {
        let hex = v["roots"][name]["root_key"].as_str().unwrap();
        RootKey::from_bytes(hex::decode(hex).unwrap().try_into().unwrap())
    };
    for (name, r) in v["roots"].as_object().unwrap() {
        let k = root(name);
        assert_eq!(r["sign_seed"], hex::encode(k.signing_key().to_bytes()));
        assert_eq!(r["sign_public_key"], k.sign_public_key());
    }
    for r in v["records"].as_array().unwrap() {
        let rec: PointerRecord = serde_json::from_value(r["record"].clone()).unwrap();
        rec.verify_signature().unwrap();
        let k = root(r["signed_by"].as_str().unwrap());
        let again = PointerRecord::new_signed(&rec.namespace, &rec.path, &rec.manifest_cid, rec.size, rec.stored_size, rec.seq, &rec.writer, &k.signing_key(), rec.ts_ms);
        assert_eq!(again, rec);
    }
    for c in v["sign_key_in_force"].as_array().unwrap() {
        let entries: Vec<SignKeyEntry> = serde_json::from_value(c["entries"].clone()).unwrap();
        let ok = near_drive_core::record::key_in_force(&entries, c["key"].as_str().unwrap(), c["ts_ms"].as_u64().unwrap());
        assert_eq!(ok, c["ok"].as_bool().unwrap(), "{c}");
    }
    for c in v["policy"].as_array().unwrap() {
        let rules: Vec<Rule> = serde_json::from_value(c["rules"].clone()).unwrap();
        let s = |k: &str| c[k].as_str().unwrap();
        let a = near_drive_core::policy::resolve(s("namespace"), &rules, s("path"), s("signer"));
        assert_eq!((a.read, a.write, a.payer.as_str()), (c["read"].as_bool().unwrap(), c["write"].as_bool().unwrap(), s("payer")), "{c}");
    }
}
