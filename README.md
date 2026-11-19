# nstorage

NEAR-account-addressed, end-to-end-encrypted object storage: `near://alice.near/path/to/object`.
See [DESIGN.md](DESIGN.md) for the architecture and roadmap.

## Phase 0 (this code)

| crate | what |
|---|---|
| `nstorage-core` | URIs, chunked XChaCha20-Poly1305 envelope encryption, manifests, signed pointer records, request signing, namespace policy |
| `nstorage-client` | Rust SDK: chunk + encrypt + sign, verifies everything it reads |
| `nstorage-gateway` | stateless HTTP gateway; NEAR access-key auth (RPC `view_access_key` or dev keys); fs blob + index stores; JSONL usage metering |
| `nst` | CLI: `keygen`, `dev-key`, `put`, `get`, `ls`, `rm` |

## Quickstart (dev)

```sh
cargo build
PK=$(target/debug/nst --account alice.near dev-key --out /tmp/alice.json)
cat > /tmp/gw.json <<JSON
{"listen":"127.0.0.1:8787","data_dir":"/tmp/nst-data","dev_keys":{"alice.near":["$PK"]}}
JSON
target/debug/nstorage-gateway --config /tmp/gw.json &

export NSTORAGE_ACCOUNT=alice.near NSTORAGE_CREDENTIALS=/tmp/alice.json
target/debug/nst keygen
echo hello | target/debug/nst put - near://alice.near/memory/today.txt
target/debug/nst ls near://alice.near/
target/debug/nst get near://alice.near/memory/today.txt
```

With real NEAR accounts, set `"rpc_url": "https://rpc.mainnet.near.org"` in the gateway config. Then use
`~/.near-credentials/mainnet/<account>.json`, which needs a full-access key or a function-call key for `storage_contract`.

Gateway config `policies` stands in for the `storage.near` contract until it exists. For example, an app pays for its users' data:

```json
"policies": {"app.near": [
  {"prefix": "users/{account}/", "read": ["{account}"], "write": ["{account}", "app.near"], "payer": "app.near"}
]}
```

## Tests

`cargo test`: unit tests plus a gateway+client e2e covering encryption at rest, overwrite/CAS, listing, namespace isolation, app-pays prefixes, and forged or stale record rejection.
