//! Emit cross-language test vectors for the nstorage wire format.
//!
//! ```sh
//! cargo run -p nstorage-core --example gen_vectors -- testvectors/vectors.json
//! ```
//!
//! Everything is deterministic except the `objects` section: encryption draws
//! a random DEK, object id, nonces and ephemeral keys, so those entries are
//! "encrypt once, record the outputs" vectors that other implementations must
//! be able to *decrypt* (and re-derive manifest/chunk cids for).
use ed25519_dalek::SigningKey;
use nstorage_core::{
    auth, cid,
    crypto::{self, EncInfo, Recipient, RootKey},
    keys,
    manifest::{ChunkRef, Manifest},
    record::PointerRecord,
    uri::{validate_path, NearUri},
};
use serde_json::{json, Value};

fn seq_bytes(n: usize, mul: u8, add: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(mul).wrapping_add(add)).collect()
}

fn root(seed: u8) -> RootKey {
    let b: [u8; 32] = std::array::from_fn(|i| seed.wrapping_add(i as u8));
    RootKey::from_bytes(b)
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&std::array::from_fn(|i| seed.wrapping_add(i as u8)))
}

fn root_json(r: &RootKey) -> Value {
    json!({
        "root_key": hex::encode(r.as_bytes()),
        "kek": hex::encode(r.kek()),
        "kek_id": r.kek_id(),
        "x25519_secret": hex::encode(r.x25519_secret().to_bytes()),
        "x25519_public": r.x25519_public(),
    })
}

/// Mirrors `nstorage_client::encode_path` (kept here so core has no client dep).
fn encode_path(p: &str) -> String {
    let mut out = String::new();
    for b in p.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn manifest_for(size: usize, chunk_size: usize, chunks: &[Vec<u8>], enc: Option<EncInfo>, ct: Option<&str>) -> Manifest {
    Manifest {
        version: 1,
        size: size as u64,
        chunk_size: chunk_size as u64,
        chunks: chunks.iter().map(|c| ChunkRef { cid: cid(c), len: c.len() as u64 }).collect(),
        enc,
        content_type: ct.map(str::to_string),
    }
}

fn main() -> anyhow::Result<()> {
    let out = std::env::args().nth(1);

    // --- cid ---
    let cids: Vec<Value> = [vec![], b"abc".to_vec(), seq_bytes(1000, 7, 3)]
        .iter()
        .map(|b| json!({"input_hex": hex::encode(b), "cid": cid(b)}))
        .collect();

    // --- ed25519 keys (NEAR format) + signatures ---
    let sk = signing_key(1);
    let ed = json!({
        "seed_hex": hex::encode(sk.to_bytes()),
        "secret_key": keys::format_secret_key(&sk),
        "secret_key_32": format!("ed25519:{}", bs58::encode(sk.to_bytes()).into_string()),
        "public_key": keys::format_public_key(&sk.verifying_key()),
        "signatures": [
            {"msg_hex": hex::encode(b"hello"), "sig": keys::sign(&sk, b"hello")},
            {"msg_hex": "", "sig": keys::sign(&sk, b"")},
        ],
    });

    // --- root key derivations ---
    let roots = [root_json(&root(0)), root_json(&root(100)), root_json(&root(200))];

    // --- uri / path encoding ---
    let uri_valid: Vec<Value> = [
        "near://alice.near/objects/etc/mystuff",
        "near://alice.near",
        "near://alice.near/",
        "near://alice.near/dir/",
        "near://a-b_c.near/x y/ü/emoji🙂.txt",
        "near://0x.near/a/b.c/...d",
    ]
    .iter()
    .map(|s| {
        let u = NearUri::parse(s).unwrap();
        json!({"uri": s, "namespace": u.namespace, "path": u.path, "display": u.to_string()})
    })
    .collect();
    let uri_invalid = [
        "s3://a.near/x",
        "near://A.near/x",
        "near://a..near/x",
        "near://.a.near/x",
        "near://a.near./x",
        "near://a/x",
        "near://alice.near/../x",
        "near://alice.near/./x",
        "near://alice.near/a//b",
        "near://alice.near/a\nb",
        "near://alice.near/a\\b",
        "near://alice.near/a\u{7f}b",
        "near://alice.near/a\u{85}b",
    ];
    for s in uri_invalid {
        assert!(NearUri::parse(s).is_err(), "{s}");
    }
    let long_ok = "a".repeat(1024);
    let long_bad = "a".repeat(1025);
    assert!(validate_path(&long_ok, false).is_ok() && validate_path(&long_bad, false).is_err());
    let object_invalid = ["dir/", "", "a//b"];
    for p in object_invalid {
        assert!(NearUri::object("alice.near", p).is_err());
    }
    let paths = ["memory/today.txt", "x y/ü+?#&=%.txt", "a~b-c_d.e/f", "emoji🙂/日本"];
    let encode: Vec<Value> = paths.iter().map(|p| json!({"path": p, "encoded": encode_path(p)})).collect();

    // --- canonical requests ---
    let account = "alice.near";
    let pk = keys::format_public_key(&sk.verifying_key());
    let cid_abc = cid(b"abc");
    let reqs: Vec<(&str, String, String, Vec<u8>)> = vec![
        ("PUT", format!("/v1/chunk/alice.near/{cid_abc}"), String::new(), b"abc".to_vec()),
        ("GET", format!("/v1/o/alice.near/{}", encode_path("x y/ü.txt")), String::new(), vec![]),
        ("GET", "/v1/o/alice.near/memory/today.txt".into(), format!("chunk={cid_abc}"), vec![]),
        ("GET", "/v1/list/alice.near".into(), format!("prefix={}", encode_path("memory/a b")), vec![]),
        ("DELETE", "/v1/o/alice.near/memory/today.txt".into(), String::new(), vec![]),
        ("put", "/v1/o/alice.near/memory/today.txt".into(), String::new(), b"{\"k\":1}".to_vec()),
    ];
    let canon: Vec<Value> = reqs
        .iter()
        .map(|(m, p, q, body)| {
            let ts = 1_763_456_789_012u64;
            let c = auth::canonical_request(m, p, q, account, &pk, ts, body);
            let h = auth::sign_request(account, &sk, m, p, q, ts, body);
            assert_eq!(keys::sign(&sk, &c), h.signature);
            json!({"method": m, "path": p, "query": q, "account": account, "public_key": pk, "ts_ms": ts,
                   "body_hex": hex::encode(body), "canonical": String::from_utf8(c).unwrap(), "signature": h.signature})
        })
        .collect();

    // --- pointer records ---
    let records: Vec<Value> = [("alice.near", "memory/today.txt", 6u64, 120u64, 1u64), ("app.near", "users/bob.near/ü x", 0, 300, 7)]
        .iter()
        .map(|(ns, path, size, stored, seq)| {
            let mcid = cid(path.as_bytes());
            let ts = 1_763_456_789_999u64;
            let r = PointerRecord::new_signed(ns, path, &mcid, *size, *stored, *seq, account, &sk, ts);
            r.verify_signature().unwrap();
            let signing = format!(
                "nstorage-record-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
                r.namespace, r.path, r.manifest_cid, r.size, r.stored_size, r.seq, r.writer, r.writer_pk, r.ts_ms
            );
            // ed25519 is deterministic: equal signatures prove the signing string matches.
            assert_eq!(keys::sign(&sk, signing.as_bytes()), r.sig);
            json!({"record": r, "signing_string": signing, "json": serde_json::to_string(&r).unwrap()})
        })
        .collect();

    // --- manifest serialization (fixed values) ---
    let fixed_enc = EncInfo {
        alg: crypto::ALG.into(),
        object_id: "00112233445566778899aabbccddeeff".into(),
        nonce_prefix: "ffeeddccbbaa99887766554433221100".into(),
        wrapped_keys: vec![
            crypto::WrappedKey { recipient: "kek:0123456789abcdef".into(), epk: None, nonce: "AAAA".into(), ct: "BBBB".into() },
            crypto::WrappedKey {
                recipient: "x25519:11111111111111111111111111111111".into(),
                epk: Some("2222".into()),
                nonce: "CC==".into(),
                ct: "DD/+".into(),
            },
        ],
    };
    let m1 = Manifest { version: 1, size: 3, chunk_size: 4194304, chunks: vec![ChunkRef { cid: cid_abc.clone(), len: 3 }], enc: None, content_type: None };
    let m2 = Manifest {
        version: 1,
        size: 10,
        chunk_size: 8,
        chunks: vec![ChunkRef { cid: cid(b"1"), len: 24 }, ChunkRef { cid: cid(b"2"), len: 18 }],
        enc: Some(fixed_enc),
        content_type: Some("text/plain; charset=\"utf-8\" \\ \n\t\u{1}\u{7f} ü🙂 </x>".into()),
    };
    let manifests: Vec<Value> = [m1, m2]
        .iter()
        .map(|m| {
            let b = m.to_bytes();
            json!({"manifest": m, "json": String::from_utf8(b.clone()).unwrap(), "cid": cid(&b)})
        })
        .collect();

    // --- encrypted objects (decrypt-side vectors) ---
    let owner = root(0);
    let friend = root(100);
    let stranger = root(200);
    let fpk = crypto::parse_x25519(&friend.x25519_public())?;
    struct Case {
        name: &'static str,
        plaintext: Vec<u8>,
        chunk_size: usize,
        owner: bool,
        friend: bool,
        public: bool,
        content_type: Option<&'static str>,
    }
    let cases = [
        Case { name: "single_chunk_owner", plaintext: b"hello nstorage".to_vec(), chunk_size: 4194304, owner: true, friend: false, public: false, content_type: Some("text/plain") },
        Case { name: "multi_chunk_owner", plaintext: seq_bytes(1000, 13, 5), chunk_size: 256, owner: true, friend: false, public: false, content_type: None },
        Case { name: "exact_multiple_owner", plaintext: seq_bytes(512, 3, 1), chunk_size: 256, owner: true, friend: false, public: false, content_type: None },
        Case { name: "empty_owner", plaintext: vec![], chunk_size: 1024, owner: true, friend: false, public: false, content_type: None },
        Case { name: "owner_and_x25519", plaintext: seq_bytes(300, 1, 0), chunk_size: 100, owner: true, friend: true, public: false, content_type: Some("application/octet-stream") },
        Case { name: "x25519_only", plaintext: b"for your eyes only".to_vec(), chunk_size: 7, owner: false, friend: true, public: false, content_type: None },
        Case { name: "public", plaintext: seq_bytes(20, 1, 65), chunk_size: 8, owner: false, friend: false, public: true, content_type: None },
        Case { name: "public_empty", plaintext: vec![], chunk_size: 8, owner: false, friend: false, public: true, content_type: None },
    ];
    let mut objects = vec![];
    for c in cases {
        let (chunks, enc) = if c.public {
            (crypto::plaintext_chunks(&c.plaintext, c.chunk_size)?, None)
        } else {
            let mut rs = vec![];
            if c.owner {
                rs.push(Recipient::Owner(&owner));
            }
            if c.friend {
                rs.push(Recipient::X25519(fpk));
            }
            let (ch, e) = crypto::encrypt_for(&rs, &c.plaintext, c.chunk_size)?;
            (ch, Some(e))
        };
        let m = manifest_for(c.plaintext.len(), c.chunk_size, &chunks, enc.clone(), c.content_type);
        m.validate()?;
        let mb = m.to_bytes();
        let mut readable_by = vec![];
        let mut not_readable_by = vec![];
        for (label, r) in [("owner", &owner), ("friend", &friend), ("stranger", &stranger)] {
            match &enc {
                None => readable_by.push(label),
                Some(e) => match crypto::decrypt_object(r, e, &chunks) {
                    Ok(p) => {
                        assert_eq!(p, c.plaintext);
                        readable_by.push(label)
                    }
                    Err(_) => not_readable_by.push(label),
                },
            }
        }
        objects.push(json!({
            "name": c.name,
            "plaintext_hex": hex::encode(&c.plaintext),
            "chunk_size": c.chunk_size,
            "chunks_hex": chunks.iter().map(hex::encode).collect::<Vec<_>>(),
            "manifest": m,
            "manifest_json": String::from_utf8(mb.clone()).unwrap(),
            "manifest_cid": cid(&mb),
            "readable_by": readable_by,
            "not_readable_by": not_readable_by,
        }));
    }

    let v = json!({
        "comment": "Generated by `cargo run -p nstorage-core --example gen_vectors`. `objects` use random DEKs/nonces: decrypt-side vectors.",
        "cid": cids,
        "ed25519": ed,
        "roots": {"owner": roots[0], "friend": roots[1], "stranger": roots[2]},
        "uri": {"valid": uri_valid, "invalid": uri_invalid, "object_invalid_paths": object_invalid, "encode_path": encode},
        "canonical_requests": canon,
        "records": records,
        "manifests": manifests,
        "objects": objects,
    });
    let s = serde_json::to_string_pretty(&v)? + "\n";
    match out {
        Some(p) => std::fs::write(p, s)?,
        None => print!("{s}"),
    }
    Ok(())
}
