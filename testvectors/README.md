# Test vectors

| file | produced by | consumed by |
|---|---|---|
| `vectors.json` | `cargo run -p near-drive-core --example gen_vectors -- testvectors/vectors.json` | TS (`sdk/ts/test`), Python (`sdk/python/tests`), `crates/near-drive-core/tests/sdk_vectors.rs` |
| `sdk_objects_ts.json` | `node sdk/ts/scripts/emit-objects.mjs testvectors/sdk_objects_ts.json` | Rust `sdk_vectors.rs`, Python tests |
| `sdk_objects_py.json` | `sdk/python/.venv/bin/python sdk/python/scripts/emit_objects.py testvectors/sdk_objects_py.json` | Rust `sdk_vectors.rs`, TS tests |
| `sdk_sign_vectors.json` | `python3 testvectors/gen_sdk_sign_vectors.py` (system Python + `cryptography`, independent of the SDKs) | TS, Python: record-signing-key derivation, records signed with it, sign-key-in-force windows, namespace policy. Interim until `gen_vectors` emits these |
| `interop.sh` | — | end-to-end: Rust `near-drive`, TS and Python against one local gateway |

`vectors.json` is deterministic (cids, NEAR key formats, signatures, HKDF-derived KEK/kek_id/X25519
keys from fixed root keys, URI rules, path encoding, canonical request strings, record signing
strings, manifest serialization) except `objects`: encryption draws random DEKs/nonces/ephemeral
keys, so those are encrypt-once, decrypt-everywhere vectors. Manifest JSON must be byte-identical
to `serde_json` output because the manifest cid is `blake3` of those bytes; the `manifest` objects in the
file are key-sorted (as the gateway returns them), `manifest_json`/`json` hold the exact bytes.

Record signing (`roots.*.sign_seed` / `sign_public_key`, `signed_records`, `writer_checks`): records
are signed with an ed25519 key whose seed is `HKDF-SHA256(salt="near-drive", ikm=root,
info="near-drive/v1/sign")` (same construction as the KEK / X25519 derivations). `signed_records` are
records signed with the `owner` root's derived key (deterministic: re-signing must give the same
`sig`). `writer_checks` exercise the reader rule: `accept` is whether a record with that
`namespace`/`path`/`writer`/`writer_pk`/`ts_ms` passes given `sign_keys` (= `get_sign_keys(writer)`,
`since_ms` as a JSON string) and `rules` (= `get_rules(namespace)`); entry *i* is in force for
`ts_ms` in `[since_i - 5 min, since_{i+1} + 5 min)`, and `policy.resolve(...).write` must hold.
The older `records` section is still signed with the plain `ed25519` test key (signature format only).

Regenerating any file changes the random parts; rerun all test suites afterwards.
