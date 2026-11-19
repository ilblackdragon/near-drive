//! Consumes `testvectors/`: re-checks the deterministic vectors against this
//! crate, and decrypts objects that the TypeScript and Python SDKs encrypted
//! (`sdk_objects_{ts,py}.json`), requiring byte-identical manifest JSON.
use near_drive_core::{cid, crypto, crypto::RootKey, manifest::Manifest, record::PointerRecord};
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
