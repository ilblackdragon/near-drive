# Test vectors

| file | produced by | consumed by |
|---|---|---|
| `vectors.json` | `cargo run -p nstorage-core --example gen_vectors -- testvectors/vectors.json` | TS (`sdk/ts/test`), Python (`sdk/python/tests`), `crates/nstorage-core/tests/sdk_vectors.rs` |
| `sdk_objects_ts.json` | `node sdk/ts/scripts/emit-objects.mjs testvectors/sdk_objects_ts.json` | Rust `sdk_vectors.rs`, Python tests |
| `sdk_objects_py.json` | `sdk/python/.venv/bin/python sdk/python/scripts/emit_objects.py testvectors/sdk_objects_py.json` | Rust `sdk_vectors.rs`, TS tests |
| `interop.sh` | — | end-to-end: Rust `nst`, TS and Python against one local gateway |

`vectors.json` is deterministic (cids, NEAR key formats, signatures, HKDF-derived KEK/kek_id/X25519
keys from fixed root keys, URI rules, path encoding, canonical request strings, record signing
strings, manifest serialization) except `objects`: encryption draws random DEKs/nonces/ephemeral
keys, so those are encrypt-once, decrypt-everywhere vectors. Manifest JSON must be byte-identical
to `serde_json` output because the manifest cid is `blake3` of those bytes; the `manifest` objects in the
file are key-sorted (as the gateway returns them), `manifest_json`/`json` hold the exact bytes.

Regenerating any file changes the random parts; rerun all test suites afterwards.
