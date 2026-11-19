# nstorage

NEAR-account-addressed, end-to-end-encrypted object storage: `near://alice.near/path/to/object`.
See [DESIGN.md](DESIGN.md) for the architecture and roadmap.

## Phase 0 (this code)

| crate | what |
|---|---|
| `nstorage-core` | URIs, chunked XChaCha20-Poly1305 envelope encryption, manifests, signed pointer records, request signing, namespace policy |
| `nstorage-client` | Rust SDK: chunk + encrypt + sign, verifies everything it reads; streaming `put_file`/`get_to_file`/`get_range` for large objects |
| `nstorage-gateway` | stateless HTTP gateway; NEAR access-key auth (RPC `view_access_key` or dev keys); blob backends fs / S3 / R2 / MinIO / HTTP blob bridge with storage classes and replication; fs or S3 (multi-gateway CAS) index; chunk cache; `?mode=locate` direct URLs; JSONL usage metering |
| `nst` | CLI: `keygen`, `dev-key`, `put`, `get` (streaming, `--range`, `--class`), `ls`, `rm` |

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

## Billing (NEAR AI Cloud credits)

Add a `billing` section to the gateway config to bill each prefix's `payer` in NEAR AI Cloud credits. Without the section, nothing changes.

```json
"billing": {"cloud_api_url": "https://cloud-api.near.ai", "token_env": "NSTORAGE_CLOUD_API_TOKEN", "gateway_id": "gw-eu-1"}
```

- **Metering.** The gateway tails `usage.jsonl` and keeps live stored bytes per payer: a put adds `bytes` and releases `replaced_bytes`, and a delete releases `bytes`. It closes hourly windows into three meters: storage GiB-hours, egress GiB, and requests (puts, deletes and chunk reads). Bytes handed out as direct URLs by `?mode=locate` count as egress when the locate is served; this is an upper bound. State (log offset, accumulators, outbox) is saved atomically in `data_dir/billing/state.json`, so a restart neither loses nor double-counts usage. Remainders smaller than 0.001 units carry over to the next window.
- **Reporting.** Every `report_interval_secs` (default 300), the gateway posts closed windows to cloud-api `POST /v1/internal/service-usage` with idempotency key `nstorage:{gateway_id}:{payer}:{window_start}:{service}`. Failed posts retry with exponential backoff (capped at `max_backoff_secs`). cloud-api deduplicates resends after a crash. Lines rejected permanently (400/409), or still failing after `dead_letter_after_secs` (default 7 days), go to `billing/dead_letter.jsonl`. The token comes from the env var named by `token_env` (cloud-api's `CLOUD_API_STORAGE_BILLING_TOKEN`). `gateway_id` must be unique per gateway.
- **Credit gate.** Before a chunk upload, a put that grows storage, or egress (chunk read or locate), the gateway checks cloud-api `billing-status` for the payer. Answers are cached for 60 s while the payer can pay and 15 s once it cannot. When the payer cannot pay, the request gets `402 {"error": "...", "code": "payment_required", "payer": "...", "reason": "limit_exceeded" | "no_credits" | "unknown_account" | ...}`. Deletes are never gated. If cloud-api is unreachable, the last answer is reused for up to `stale_status_max_secs` (1 h). After that, `fail_open` decides. It defaults to `true`: usage is still metered and reported later, so an outage costs at most unpaid usage by payers with no credit, while failing closed would make cloud-api a hard dependency of every write. Set `fail_open` to `false` to answer `503 billing_unavailable` instead.
- **Settlement.** `billing::settle::Settlement` is the plug-in point for the NEAR escrow settler (`settle([{payer, amount, gateway, period_id}])`). It ships with `cloud_credits` (default) and `log` (dev: logs lines, gate off) backends.
- **Limits.** One meter reads one gateway's log, so a payer's bytes must be written and deleted through the same gateway for storage to integrate correctly. A NEAR account is billed to its personal NEAR AI Cloud organization and must have signed in to NEAR AI Cloud once; until then, writes get 402 `unknown_account`.

## Tests

`cargo test` runs the following:
- unit tests;
- a gateway+client e2e covering encryption at rest, overwrite/CAS, listing, namespace isolation, app-pays prefixes, and forged or stale record rejection;
- `tests/streaming.rs`: streaming vs one-shot interop, ranges, storage classes, a blob bridge with direct URLs and fallback;
- `tests/large.rs`: a large object with bounded memory.

To run the S3 tests against a local MinIO (bind it to localhost only):

```sh
docker run -d --name nst-minio -p 127.0.0.1:19000:9000 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  -e MINIO_DEFAULT_BUCKETS=nstorage-test bitnamilegacy/minio:latest
export NSTORAGE_TEST_S3_ENDPOINT=http://127.0.0.1:19000   # also _BUCKET, _ACCESS_KEY, _SECRET_KEY
cargo test -p nstorage-gateway --test s3          # index CAS on S3, two gateways sharing one index, presigned locate, cache
NSTORAGE_TEST_LARGE_MB=200 cargo test -p nstorage-gateway --test large -- --nocapture
```
