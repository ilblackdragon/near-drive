# nstorage

NEAR-account-addressed, end-to-end-encrypted object storage: `near://alice.near/path/to/object`.
See [DESIGN.md](DESIGN.md) for the architecture and roadmap.

## Phase 0 (this code)

| crate | what |
|---|---|
| `nstorage-core` | URIs, chunked XChaCha20-Poly1305 envelope encryption, manifests, signed pointer records, request signing, namespace policy |
| `nstorage-client` | Rust SDK: chunk + encrypt + sign, verifies everything it reads; streaming `put_file`/`get_to_file`/`get_range` for large objects |
| `nstorage-gateway` | stateless HTTP gateway; NEAR access-key auth (RPC `view_access_key` or dev keys); blob backends fs / S3 / R2 / MinIO / HTTP blob bridge with storage classes and replication; fs or S3 (multi-gateway CAS) index; chunk cache; `?mode=locate` direct URLs; JSONL usage metering |
| `nst` | CLI: `keygen`, `dev-key`, `put`, `get` (streaming, `--range`, `--class`), `ls`, `rm`, `share`; chain: `grant`, `rules`, `publish-key`, `gateways` |
| `nstorage-near` | NEAR JSON-RPC views + signed function calls (small hand-rolled borsh tx builder) for `storage.near` |
| `contracts/storage` | the `storage.near` contract: namespace rules, X25519 keys, gateway registry, credential epochs, anchors, stablecoin / NEAR Intents escrow ([docs/payments.md](docs/payments.md)) |

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

With `rpc_url` set, the gateway reads namespace rules from the `storage_contract` (`get_rules`, cached 30 s; set
`"contract_policies": false` to disable). Config `policies` entries override the contract for their namespaces, and are
the only policy source without `rpc_url`. For example, an app pays for its users' data:

```json
"policies": {"app.near": [
  {"prefix": "users/{account}/", "read": ["{account}"], "write": ["{account}", "app.near"], "payer": "app.near"}
]}
```

The same rule onchain, plus sharing by account name (`--rpc-url` defaults per `--network`; `--contract` defaults to
`storage.near`; `NSTORAGE_GATEWAY=auto` picks the fastest healthy gateway from the onchain registry):

```sh
nst --account app.near grant 'near://app.near/users/{account}/' --read '{account}' --write '{account},app.near' --payer app.near
nst rules app.near
nst --account bob.near publish-key            # set_enc_key with bob's x25519 key
nst --account alice.near share near://alice.near/doc/x bob.near   # looks up bob's key onchain
nst gateways
```

Onchain writes attach a NEAR deposit for storage staking (excess refunded), so they need a full-access key.

## storage.near contract

`contracts/` is a separate cargo workspace (wasm). Build and test:

```sh
contracts/build.sh                                   # cargo near build → contracts/target/near/*/
cd contracts && cargo test -p nstorage-contract      # unit tests + local sandbox (near-workspaces) tests
```

Methods (JSON args; `U128` = decimal string):

| area | methods |
|---|---|
| policy | `set_rules(rules)` (payable; caller's namespace; ≤32 rules, one `{account}` per prefix), `get_rules(namespace)` |
| keys | `set_enc_key(key)` / `remove_enc_key()` (payable), `get_enc_key(account_id)` |
| revocation | `bump_cred_epoch() -> u64` (payable), `get_cred_epoch(account_id) -> u64` |
| anchors | `anchor(namespace, root, seq)` (owner or active gateway; seq strictly increasing), `get_anchor(namespace)` |
| registry | `register_gateway(info)` (stake ≥ `gateway_min_stake` + storage), `update_gateway(info)`, `deregister_gateway()`, `withdraw_gateway_stake()` (after delay), `get_gateway(operator)`, `list_gateways(from_index, limit)`, `gateways_count()` |
| escrow | `ft_on_transfer`, `mt_on_transfer`, `set_spend_cap(per_day)`, `settle(entries)`, `request_withdraw_balance(asset, amount)`, `cancel_withdraw_balance()`, `withdraw_balance()`, `withdraw_earnings()`, `get_payer`, `get_earnings`, `is_settled`, `get_assets`, `get_settlers` |
| owner | `new(owner_id, assets?, config?)`, `set_config(patch)`, `set_asset(asset)`, `add_settler(account_id, any_gateway)`, `remove_settler`, `set_owner`, `get_config`, `get_owner` |

`info = {url, regions, backends, price_hint, attestation?}`. See [docs/payments.md](docs/payments.md) for funding
(USDC `ft_transfer_call`, NEAR Intents `mt_transfer_call` / signed `transfer` intent) and settlement.

## Storage backends, classes and index

By default the gateway keeps chunks in `{data_dir}/chunks` and the index in `{data_dir}/index`. Those defaults suit a single
dev gateway. The optional `storage` section of the gateway config sets up the following.

**Backends** are named and can be:
- `fs`: a local directory;
- `s3`: AWS S3, Cloudflare R2 or MinIO;
- `bridge`: an HTTP blob bridge, such as the Filecoin or Shelby bridges. The protocol is in [docs/blob-bridge.md](docs/blob-bridge.md).

**Storage classes** are lists of backends:
- An upload writes each chunk to every backend in its class. It succeeds once `min_successes` writes succeed (default: all backends).
- Reads try every backend, default class first, so readers never need to know the class.
- Clients pick a class per upload with the `x-nst-class` chunk header (`PutOptions::class`, `nst put --class bulk`). The default class is `hot`.

**The index** can live on S3/R2/MinIO and use conditional writes. With that setup, any number of gateways can share it safely.

```json
"storage": {
  "backends": {
    "r2":    {"type": "s3", "bucket": "nst", "endpoint": "https://<acct>.r2.cloudflarestorage.com", "region": "auto",
              "access_key_id": "...", "secret_access_key": "...", "prefix": "chunks/", "presign_ttl_secs": 3600},
    "fil":   {"type": "bridge", "url": "http://127.0.0.1:7070", "token": "..."},
    "local": {"type": "fs", "path": "/var/lib/nst/chunks"}
  },
  "classes": {
    "hot":  {"backends": ["r2", "fil"], "min_successes": 1},
    "bulk": {"backends": ["fil"]}
  },
  "default_class": "hot",
  "index": {"type": "s3", "bucket": "nst", "endpoint": "https://<acct>.r2.cloudflarestorage.com", "region": "auto", "prefix": "index/"},
  "cache": {"path": "/var/cache/nst", "max_bytes": 10737418240}
}
```

### Option reference

- **Omitted fields.**
  - `storage` omitted: `{"local": fs at data_dir/chunks}`.
  - `classes` omitted: `hot` = every backend.
  - `index` omitted: fs.
- **`s3` fields.**
  - Credentials, region and endpoint fall back to the standard `AWS_*` env vars.
  - `allow_http: true` is required for `http://` MinIO.
  - `virtual_hosted_style: true` switches to bucket-subdomain URLs.
  - `prefix` defaults to `chunks/` for blobs and `index/` for the index.
- **Direct URLs for S3 blobs.**
  - Presigned GET URLs are returned by `?mode=locate`. Set `presign_ttl_secs: 0` to turn them off.
  - With `public_url_base` (a public bucket or CDN), the gateway returns `{public_url_base}/{key}` instead.
- **S3 key layout.**
  - Chunks: `{prefix}b3/{hex[0..2]}/{hex}`.
  - Index records: `{prefix}{namespace}/{path}`. Each path segment is percent-escaped per `object_store` rules (see `crates/nstorage-gateway/src/s3.rs`).
  - Updates are `If-Match` CAS writes.
  - A delete writes a CAS tombstone, because plain S3 DELETE is not conditional.
- **`cache`.** A bounded, LRU, read-through chunk cache on local disk for remote backends. Chunks are checked against their cid before they are cached.

## Large objects

The SDK streams data, so memory stays around `(parallelism + 2) × chunk_size` whatever the object size.

| SDK call | What it does |
|---|---|
| `Client::put_file` / `put_reader` | Reads, encrypts and uploads chunk by chunk, with `client.parallelism` uploads in flight. Encryption is per chunk, in the same format as `put`. |
| `Client::get_to_file` | Calls `GET ...?mode=locate` to get the record, the manifest and a direct URL per chunk (a presigned S3 URL or a bridge CDN URL). Fetches chunks in parallel and verifies every cid. Falls back to the gateway (`?chunk=`, which supports `Range`) when a direct URL is missing or fails. Decrypts each chunk and writes it at its offset. |
| `get_to_writer` | Like `get_to_file`, but streams in order to any writer. |
| `get_range(uri, a..b)` | Fetches and decrypts only the chunks that cover the range. |

The CLI uses these calls:

```sh
nst --chunk-mib 16 --parallel 16 put --class bulk model.safetensors near://alice.near/models/m.safetensors
nst get near://alice.near/models/m.safetensors ./m.safetensors
nst get --range 0-1048575 near://alice.near/models/m.safetensors > header.bin
```

## Tests

`cargo test` runs the following:
- unit tests;
- a gateway+client e2e covering encryption at rest, overwrite/CAS, listing, namespace isolation, app-pays prefixes, and forged or stale record rejection;
- `tests/streaming.rs`: streaming vs one-shot interop, ranges, storage classes, a blob bridge with direct URLs and fallback;
- `tests/large.rs`: a large object with bounded memory;
- `tests/contract_policy.rs`: gateway policy from `storage.near` through a mock RPC (cache, override, failure → 503).

Contract tests (`cd contracts && cargo test`, after `contracts/build.sh`; the sandbox node binary is downloaded on first
run) include `tests/sandbox.rs` (contract flows with mock FT/MT tokens, plus the `nstorage-near` tx builder) and
`tests/gateway_chain.rs` (a real gateway resolving keys and rules from the sandbox chain, sharing by account, discovery).

To run the S3 tests against a local MinIO (bind it to localhost only):

```sh
docker run -d --name nst-minio -p 127.0.0.1:19000:9000 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  -e MINIO_DEFAULT_BUCKETS=nstorage-test bitnamilegacy/minio:latest
export NSTORAGE_TEST_S3_ENDPOINT=http://127.0.0.1:19000   # also _BUCKET, _ACCESS_KEY, _SECRET_KEY
cargo test -p nstorage-gateway --test s3          # index CAS on S3, two gateways sharing one index, presigned locate, cache
NSTORAGE_TEST_LARGE_MB=200 cargo test -p nstorage-gateway --test large -- --nocapture
```
