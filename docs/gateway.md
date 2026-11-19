# Running a gateway

A gateway is a stateless HTTP service: it checks NEAR signatures and access rules, stores encrypted chunks in one or
more storage backends, and keeps the index (path → current version). Anyone can run one and register it in the
`drive.near` contract.

```sh
cargo install --git https://github.com/ilblackdragon/near-drive near-drive-gateway
near-drive-gateway --config gateway.json
```

```json
{
  "listen": "127.0.0.1:8787",
  "data_dir": "/var/lib/near-drive",
  "rpc_url": "https://rpc.mainnet.near.org",
  "storage_contract": "drive.near"
}
```

| field | meaning |
|---|---|
| `listen` | address to serve on (put it behind TLS) |
| `data_dir` | local state: default chunk store and index, usage log, billing state |
| `rpc_url` | NEAR RPC used to check that a request's public key belongs to the account (full-access, or a function-call key for `storage_contract`); without it only `dev_keys` work |
| `storage_contract` | the NEAR Drive contract (`drive.near`) |
| `contract_policies` | read access rules from the contract (`get_rules`, cached 30 s); default `true` |
| `policies` | `account -> [rules]`, overriding the contract for those accounts (the only source without `rpc_url`) |
| `dev_keys` | `account -> [public keys]` accepted without RPC (development and tests) |
| `storage` | backends, storage classes, index, caches ([below](#storage-backends-classes-and-index)) |
| `billing` | NEAR AI Cloud credits billing ([below](#billing-near-ai-cloud-credits)) |
| `cors_origins` | browser origins allowed to call the gateway ([below](#browser-access-cors)) |

A rule looks like this (an app pays for its users' data):

```json
"policies": {"app.near": [
  {"prefix": "users/{account}/", "read": ["{account}"], "write": ["{account}", "app.near"], "payer": "app.near"}
]}
```

## Storage backends, classes and index

By default chunks are kept in `{data_dir}/chunks` and the index in `{data_dir}/index`, which suits a single gateway.
The optional `storage` section sets up the following.

**Backends** are named and can be:
- `fs`: a local directory;
- `s3`: AWS S3, Cloudflare R2 or MinIO;
- `bridge`: an HTTP blob bridge, such as the Filecoin or Shelby bridges in `bridges/`
  ([blob-bridge.md](blob-bridge.md), [backends.md](backends.md) for costs and guarantees).

**Storage classes** are lists of backends:
- An upload writes each chunk to every backend in its class and succeeds once `min_successes` writes succeed
  (default: all of them).
- Clients pick a class per upload (`near drive put --class bulk`); the default class is `hot`.
- The class is recorded in the file's index entry. Reads try that class's backends first, then its `previous`
  backends, then all others, so a misplaced chunk is still found (and logged).
- **Migrating a class:** list the old backends in `previous` and the new ones in `backends`. New writes go to the new
  backends while reads still find old chunks; drop `previous` once the old chunks are copied. No per-chunk state is
  kept, so any number of gateways can share the configuration.

**The index** can live on S3 / R2 / MinIO with conditional writes; then any number of gateways can share it.

```json
"storage": {
  "backends": {
    "r2":    {"type": "s3", "bucket": "near-drive", "endpoint": "https://<acct>.r2.cloudflarestorage.com", "region": "auto",
              "access_key_id": "...", "secret_access_key": "...", "prefix": "chunks/", "presign_ttl_secs": 3600},
    "fil":   {"type": "bridge", "url": "http://127.0.0.1:7070", "token": "..."},
    "local": {"type": "fs", "path": "/var/lib/near-drive/chunks"}
  },
  "classes": {
    "hot":  {"backends": ["r2", "fil"], "min_successes": 1, "previous": ["local"]},
    "bulk": {"backends": ["fil"]}
  },
  "default_class": "hot",
  "index": {"type": "s3", "bucket": "near-drive", "endpoint": "https://<acct>.r2.cloudflarestorage.com", "region": "auto", "prefix": "index/"},
  "cache": {"path": "/var/cache/near-drive", "max_bytes": 10737418240},
  "small_cache": {"max_bytes": 67108864, "inline_max_bytes": 65536}
}
```

### Option reference

- **Omitted fields.** `storage` omitted: one `fs` backend at `data_dir/chunks`. `classes` omitted: `hot` = every
  backend. `index` omitted: fs.
- **`s3` fields.**
  - Credentials, region and endpoint fall back to the standard `AWS_*` env vars.
  - `allow_http: true` is required for `http://` MinIO; `virtual_hosted_style: true` switches to bucket-subdomain URLs.
  - `prefix` defaults to `chunks/` for blobs and `index/` for the index.
- **Direct downloads.** For S3 backends, `?mode=locate` hands clients presigned GET URLs so large downloads skip the
  gateway (`presign_ttl_secs: 0` turns this off). With `public_url_base` (a public bucket or CDN) it returns
  `{public_url_base}/{key}` instead.
- **S3 layout.** Chunks: `{prefix}b3/{hex[0..2]}/{hex}`. Index entries: `{prefix}{account}/{path}` (each segment
  percent-escaped per `object_store` rules), updated with `If-Match` writes; a delete writes a tombstone, because a
  plain S3 DELETE is not conditional.
- **`cache`.** A bounded, LRU, read-through chunk cache on local disk in front of remote backends. Chunks are checked
  against their id before they are cached.
- **`small_cache`** (on by default) makes small files cheap:
  - `max_bytes` (64 MiB; 0 = off) of memory for blobs up to `max_item_bytes` (256 KiB): manifests and small chunks.
    Uploads write through, so the commit right after an upload finds them in memory.
  - `inline_max_bytes` (64 KiB; 0 = off): `?mode=locate` returns the chunks of files up to this stored size inline,
    so a small read is one request. Inlined bytes are metered as egress.
  - `index_ttl_ms` (0 = off): caches index entries. Writes and deletes through this gateway update it, but with several
    gateways sharing one index a read can be up to the TTL stale, so only raise it for a single writing gateway.
  - `index_max_entries` (100 000).

## Browser access (CORS)

Off by default. To let web apps call the gateway directly, list their origins:

```json
"cors_origins": ["https://app.example"]
```

`["*"]` allows any origin. Requests are authenticated by NEAR signatures, not cookies, so credentials are never
allowed.

## Billing (NEAR AI Cloud credits)

Add a `billing` section to bill each folder's `payer` in NEAR AI Cloud credits. Without it, nothing is billed.

```json
"billing": {"cloud_api_url": "https://cloud-api.near.ai", "token_env": "NEAR_DRIVE_CLOUD_API_TOKEN", "gateway_id": "gw-eu-1"}
```

- **Metering.** The gateway follows its `usage.jsonl` and keeps live stored bytes per payer: a put adds its bytes and
  releases the replaced version's, a delete releases them. It closes hourly windows into three meters: storage
  GiB-hours, egress GiB, and requests (puts, deletes and chunk reads). Bytes handed out as direct URLs count as egress
  when the locate is served (an upper bound). State is saved atomically in `data_dir/billing/state.json`, so a restart
  neither loses nor double-counts usage; remainders below 0.001 units carry over.
- **Reporting.** Every `report_interval_secs` (default 300) closed windows are posted to cloud-api
  `POST /v1/internal/service-usage` with the idempotency key
  `near-drive:{gateway_id}:{payer}:{window_start}:{service}`, retried with backoff (capped at `max_backoff_secs`).
  Lines rejected permanently (400/409), or still failing after `dead_letter_after_secs` (7 days), go to
  `billing/dead_letter.jsonl`. The token comes from the env var named by `token_env`; `gateway_id` must be unique per
  gateway.
- **Credit gate.** Before a chunk upload, a put that grows storage, or a download, the gateway checks the payer's
  `billing-status` (cached 60 s while it can pay, 15 s once it cannot). A payer that cannot pay gets
  `402 {"code": "payment_required", "payer": "...", "reason": "limit_exceeded" | "no_credits" | "unknown_account" | ...}`.
  Deletes are never gated. If cloud-api is unreachable the last answer is reused for up to `stale_status_max_secs`
  (1 h); after that `fail_open` (default `true`) lets requests through and bills later, while `false` answers
  `503 billing_unavailable`.
- **Limits.** One meter reads one gateway's log, so a payer's bytes must be written and deleted through the same
  gateway. A NEAR account is billed to its personal NEAR AI Cloud organization and must have signed in to NEAR AI
  Cloud once; until then, writes get 402 `unknown_account`.
- Payment in stablecoins / NEAR Intents through the contract: [payments.md](payments.md).

## Registering

Register the gateway in `drive.near` so clients with `--gateway auto` can find it: `register_gateway({url, regions,
backends, price_hint, attestation?})` with a stake of at least `gateway_min_stake` ([contract.md](contract.md)).
