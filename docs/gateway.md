# Running a gateway

A gateway is a stateless HTTP service: it checks NEAR signatures and access rules, stores encrypted chunks in one or
more storage backends, and keeps the index (path → current version). Anyone can run one and register it in the
`drive.near` contract.

```sh
cargo install --git https://github.com/ilblackdragon/near-drive near-drive-gateway
near-drive-gateway --config gateway.json
```

The config file can also be given as `NEAR_DRIVE_CONFIG=gateway.json`, or the whole config as inline JSON in
`NEAR_DRIVE_CONFIG_JSON` (handy for containers); setting both a file and the inline JSON is an error.
`near-drive-gateway [--config X] [serve]` serves (the default); `near-drive-gateway gc` collects garbage
([below](#garbage-collection)).

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
| `rpc_url` | NEAR RPC used to check that a request's public key belongs to the account (full-access, or a function-call key for `storage_contract`), and that a written record is signed with the writer's latest published signing key (`get_sign_keys`, cached 60 s); without it only `dev_keys` work |
| `storage_contract` | the NEAR Drive contract (`drive.near`) |
| `contract_policies` | read access rules from the contract (`get_rules`, cached 30 s); default `true` |
| `policies` | `account -> [rules]`, overriding the contract for those accounts (the only source without `rpc_url`) |
| `dev_keys` | `account -> [public keys]` accepted without RPC (development and tests) |
| `dev_sign_keys` | `account -> [record-signing keys]` accepted on writes besides the key published onchain (`set_sign_key`). Without `rpc_url`, a listed account must sign records with one of these and unlisted accounts are not checked (development and tests) |
| `storage` | backends, storage classes, index, caches ([below](#storage-backends-classes-and-index)) |
| `billing` | NEAR AI Cloud credits billing ([below](#billing-near-ai-cloud-credits)) |
| `cors_origins` | browser origins allowed to call the gateway ([below](#browser-access-cors)) |
| `gc` | periodic chunk garbage collection, off by default ([below](#garbage-collection)) |

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
Each record is one object, `{prefix}{namespace}/{path}` with the path verbatim, so key order is path order. Listing a
page (`GET /v1/list`) is one S3 ListObjectsV2 request (prefix, delimiter, start-after and max-keys passed through)
plus a GET for each live record on that page that the gateway has not already cached under its current ETag (bounded
in-memory cache, 100k records). Deleted paths leave a small tombstone object (S3 DELETE cannot be made conditional,
so removing it could race a re-create); listings recognise tombstones by size and skip them without a GET. The `fs`
index (default) scans the namespace directory's file names for each page but reads only that page's records.

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

## Garbage collection

Deleting or overwriting a file only changes the index; the old version's chunks stay in the backends. Chunks can be
shared (identical public files dedup; `share` writes a new manifest over the same data chunks), so they are reclaimed
by mark and sweep rather than per file:

- **Mark.** Every live index entry in every namespace is listed and its manifest read; the manifest and its data chunks
  are live. If any live manifest cannot be read, GC stops before deleting anything.
- **Sweep.** On each backend that can list its chunks (`fs`, `s3`, within its `prefix`), chunks that are not live
  *and* were last written more than the **grace period** before the run started are deleted. Chunks are uploaded
  before the record that references them is committed, and resumable uploads can take long; the grace period
  (default 24 h) keeps them. Re-uploading a chunk that already exists refreshes its timestamp. Keep the grace period
  longer than any upload takes from first chunk to commit.
- **Blob bridges are not swept** (the bridge protocol has no listing); they are reported as skipped. The local
  `cache` is size-bounded and evicts on its own; a periodic run also drops deleted chunks from its gateway's caches.
- **Safety.** A run whose index has no live entries at all while the backends hold old chunks is refused (a wrong
  index config would otherwise delete everything); `--force` overrides. Each deletion re-checks the chunk's age first.
  Never point two deployments with different indexes at the same backend (bucket + prefix or directory): each would
  collect the other's chunks.

The mark phase walks each namespace one listing page (1000 records) at a time.

Run it once (prints a JSON report with per-backend counts and bytes; exit code 1 if a backend had errors):

```sh
near-drive-gateway --config gateway.json gc --dry-run        # what would be deleted, and how many bytes
near-drive-gateway --config gateway.json gc --grace 48h      # delete; grace as seconds or 90s / 15m / 24h / 7d
```

or periodically inside the server:

```json
"gc": {"interval_secs": 86400, "grace_secs": 86400, "dry_run": false}
```

GC is safe while gateways serve traffic. With several gateways sharing one index and backends, run it from one place
(a cron job, or `gc` on a single gateway): concurrent runs do not corrupt anything but duplicate the work.

## Listing API

`GET /v1/list/{namespace}?prefix=&delimiter=&cursor=&limit=` (signed like every request) returns one page:

```json
{"entries": [{"path": "docs/a.txt", "size": 12, "seq": 1, "writer": "alice.near", "ts_ms": 1763000000000,
              "manifest_cid": "b3:...", "class": "hot"}],
 "common_prefixes": ["docs/sub/"],
 "next_cursor": "docs/sub/"}
```

- `prefix` is a raw string prefix (`docs/a` matches `docs/a.txt` and `docs/ab/c`), not cut at `/`.
- `delimiter` (normally `/`) rolls paths that contain it after the prefix up into `common_prefixes`, as in S3.
- `limit` is 1..=1000, default 1000; it bounds entries plus common prefixes.
- Entries the caller may not read are dropped after the page is fetched, and deleted paths are skipped, so a page can
  hold fewer items than `limit` (even none) while `next_cursor` is still set. Keep requesting with
  `cursor=<next_cursor>` until it is `null`.
- A common prefix is shown when the namespace rules let the caller read something under it (the rules are checked,
  not the objects under it).
- The cursor is opaque to SDK users. Today it is the last path or common prefix the page examined, and any path works
  as a start-after bound (a cursor ending in the delimiter skips everything under it); the S3 endpoint relies on
  that to map S3 markers onto it.

The SDKs expose `list_page` / `listPage` for one page and `list` for everything under a prefix; `near drive ls`
lists recursively, `near drive ls --dir` one level (`delimiter=/`).

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

## Change notifications

`GET /v1/watch/{account}?prefix=&cursor=&timeout_ms=` is a long poll (up to 60 s) that returns as soon as a file under
the prefix is written or deleted through this gateway; folder sync uses it instead of polling. The feed is in memory
per gateway process, so the gateway stays stateless: a cursor from another process (after a restart, or another
gateway) simply answers "changed" and the client re-lists, and writes made through other gateways reach clients at
their periodic re-list.

## Registering

Register the gateway in `drive.near` so clients with `--gateway auto` can find it: `register_gateway({url, regions,
backends, price_hint, attestation?})` with a stake of at least `gateway_min_stake` ([contract.md](contract.md)).
