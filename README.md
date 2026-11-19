# NEAR Drive

NEAR-account-addressed, end-to-end-encrypted object storage: `near://alice.near/path/to/object`.
See [DESIGN.md](DESIGN.md) for the architecture and roadmap.

## Components

| crate | what |
|---|---|
| `near-drive-core` | URIs, chunked XChaCha20-Poly1305 envelope encryption, manifests, signed pointer records, request signing, namespace policy |
| `near-drive-client` | Rust SDK: chunk + encrypt + sign, verifies everything it reads; streaming `put_file`/`get_to_file`/`get_range` for large objects |
| `near-drive-gateway` | stateless HTTP gateway; NEAR access-key auth (RPC `view_access_key` or dev keys); blob backends fs / S3 / R2 / MinIO / HTTP blob bridge with storage classes and replication; fs or S3 (multi-gateway CAS) index; chunk cache; `?mode=locate` direct URLs; JSONL usage metering |
| `near-drive-s3` | S3-compatible local sidecar: SigV4/SigV2 verification, aws-chunked + checksum trailers, S3 ops → native API |
| `near-drive-cli` | the `near-drive` binary, also `near drive` (near-cli-rs extension): `login`/`logout`, `keygen [--ckd]`, `put`, `get` (streaming, `--range`, `--class`), `ls`, `rm`, `share`, `grant`, `rules`, `publish-key`, `whoami`, `gateways`, `up`/`down` (S3 endpoint; `s3-proxy` in the foreground); interactive when run in a terminal. NEAR keys come from near-cli ([below](#cli-near-drive--near-drive)) |
| `near-drive-chain` | NEAR JSON-RPC views + signed function calls (small hand-rolled borsh tx builder) for `drive.near` |
| `contracts/drive` | the `drive.near` contract: namespace rules, X25519 keys, gateway registry, credential epochs, anchors, stablecoin / NEAR Intents escrow ([docs/payments.md](docs/payments.md)) |

## CLI: `near drive` / `near-drive`

One binary, two ways to run it:

- `near drive <command>` once `near-drive` is on `PATH`. near-cli-rs runs `near-<name>` for subcommands it
  does not know (like `cargo`). (`near storage` is taken: near-cli keeps it as a legacy alias of `view-state`.)
- `near-drive <command>` standalone.

```sh
cargo install --path crates/near-drive-cli        # installs near-drive
near drive login                                  # pick an account; adds a NEAR Drive session key via near-cli
near drive keygen --ckd                           # encryption key derived from the account (MPC CKD)
near drive put ./notes.txt docs/                  # -> near://<you>/docs/notes.txt (bare paths = your namespace)
near drive get docs/notes.txt ./notes.txt          # other namespaces: near://bob.near/...
near drive up                                     # local S3 endpoint in the background; prints AWS_* exports
near drive down
near drive                                        # no arguments: menu
```

**NEAR keys are near-cli's.** NEAR Drive never stores or creates NEAR keys itself:

- Requests to the gateway are signed with a key from near-cli's keychain: the OS keychain entries `near` writes
  (`near-<network>-<account>` / `<account>:<public key>`) or the legacy files under `~/.near-credentials/<network>/`.
  The CLI lists the account's keys onchain and picks a function-call key for the drive contract first, then a
  full-access key. `near drive whoami` shows which one and where it came from.
- `near drive login` runs `near account add-key <account> grant-function-call-access --contract-account-id drive.near
  ... autogenerate-new-keypair save-to-keychain`: near-cli generates the session key, stores it, and signs the
  `AddKey` with whatever signer you choose (keychain, Ledger, seed phrase, ...). `near drive logout` deletes it.
- Transactions (`grant`, `publish-key`, `keygen --ckd`, `login`, `logout`) are run by `near contract call-function
  as-transaction ...`, so near-cli asks for the signer. Without a terminal it uses `sign-with-keychain send`; override
  with `--near-sign "sign-with-ledger send"` (or `NEAR_DRIVE_NEAR_SIGN`).
- `--network` is a near-cli connection name (`mainnet`, `testnet`, or your own from `near config add-connection`);
  the RPC URL and the CKD MPC contract come from that connection.
- `--credentials <file>` bypasses near-cli for everything (dev gateways, CI): requests and transactions are signed
  with that key file.

The encryption root key is not a NEAR key and stays in `~/.near-drive/keys/<account>.root` (the TS and Python SDKs
read it there). With `keygen --ckd` it can be re-derived from the account on any device.

**Interactive mode.** In a terminal, anything missing is asked for with the same prompt library near-cli uses:
`near drive` alone opens a menu; `near drive get` lists your files to pick from; `put` suggests a destination;
`grant` asks who can read, write and pay; `keygen` asks CKD or random. Afterwards it prints the equivalent
non-interactive command. Without a terminal (or with `--no-interactive`) missing arguments are errors.

## Quickstart (dev)

```sh
cargo build
PK=$(target/debug/near-drive --account alice.near dev-key --out /tmp/alice.json)
cat > /tmp/gw.json <<JSON
{"listen":"127.0.0.1:8787","data_dir":"/tmp/drive-data","dev_keys":{"alice.near":["$PK"]}}
JSON
target/debug/near-drive-gateway --config /tmp/gw.json &

export NEAR_DRIVE_ACCOUNT=alice.near NEAR_DRIVE_CREDENTIALS=/tmp/alice.json
target/debug/near-drive keygen
echo hello | target/debug/near-drive put - near://alice.near/memory/today.txt
target/debug/near-drive ls near://alice.near/
target/debug/near-drive get near://alice.near/memory/today.txt
```

With real NEAR accounts, set `"rpc_url": "https://rpc.mainnet.near.org"` in the gateway config and drop
`NEAR_DRIVE_CREDENTIALS`: the CLI then uses near-cli's keys (`near drive login`). The gateway accepts a full-access key
or a function-call key for `storage_contract`.

With `rpc_url` set, the gateway reads namespace rules from the `storage_contract` (`get_rules`, cached 30 s; set
`"contract_policies": false` to disable). Config `policies` entries override the contract for their namespaces, and are
the only policy source without `rpc_url`. For example, an app pays for its users' data:

```json
"policies": {"app.near": [
  {"prefix": "users/{account}/", "read": ["{account}"], "write": ["{account}", "app.near"], "payer": "app.near"}
]}
```

The same rule onchain, plus sharing by account name (`--rpc-url` defaults to the near-cli connection's; `--contract`
defaults to `drive.near`; `NEAR_DRIVE_GATEWAY=auto` picks the fastest healthy gateway from the onchain registry):

```sh
near drive --account app.near grant 'near://app.near/users/{account}/' --read '{account}' --write '{account},app.near' --payer app.near
near drive rules app.near
near drive --account bob.near publish-key            # set_enc_key with bob's x25519 key
near drive --account alice.near share near://alice.near/doc/x bob.near   # looks up bob's key onchain
near drive gateways
```

Onchain writes attach a NEAR deposit for storage staking (excess refunded), so near-cli must sign them with a
full-access key (or Ledger); the session key cannot.

## drive.near contract

`contracts/` is a separate cargo workspace (wasm). Build and test:

```sh
contracts/build.sh                                   # cargo near build → contracts/target/near/*/
cd contracts && cargo test -p near-drive-contract      # unit tests + local sandbox (near-workspaces) tests
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
- Clients pick a class per upload with the `x-near-drive-class` chunk header (`PutOptions::class`, `near drive put --class bulk`). The default class is `hot`.

**The index** can live on S3/R2/MinIO and use conditional writes. With that setup, any number of gateways can share it safely.

```json
"storage": {
  "backends": {
    "r2":    {"type": "s3", "bucket": "near-drive", "endpoint": "https://<acct>.r2.cloudflarestorage.com", "region": "auto",
              "access_key_id": "...", "secret_access_key": "...", "prefix": "chunks/", "presign_ttl_secs": 3600},
    "fil":   {"type": "bridge", "url": "http://127.0.0.1:7070", "token": "..."},
    "local": {"type": "fs", "path": "/var/lib/near-drive/chunks"}
  },
  "classes": {
    "hot":  {"backends": ["r2", "fil"], "min_successes": 1},
    "bulk": {"backends": ["fil"]}
  },
  "default_class": "hot",
  "index": {"type": "s3", "bucket": "near-drive", "endpoint": "https://<acct>.r2.cloudflarestorage.com", "region": "auto", "prefix": "index/"},
  "cache": {"path": "/var/cache/near-drive", "max_bytes": 10737418240}
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
  - Index records: `{prefix}{namespace}/{path}`. Each path segment is percent-escaped per `object_store` rules (see `crates/near-drive-gateway/src/s3.rs`).
  - Updates are `If-Match` CAS writes.
  - A delete writes a CAS tombstone, because plain S3 DELETE is not conditional.
- **`cache`.** A bounded, LRU, read-through chunk cache on local disk for remote backends. Chunks are checked against their cid before they are cached.

## Browser access (CORS)

Off by default. To let web apps call a gateway directly, list their origins in the gateway config:

```json
"cors_origins": ["https://app.example"]
```

`["*"]` allows any origin. Requests are authenticated by NEAR signatures, not cookies, so credentials are never allowed.

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
near drive --chunk-mib 16 --parallel 16 put --class bulk model.safetensors near://alice.near/models/m.safetensors
near drive get near://alice.near/models/m.safetensors ./m.safetensors
near drive get --range 0-1048575 near://alice.near/models/m.safetensors > header.bin
```

## Billing (NEAR AI Cloud credits)

Add a `billing` section to the gateway config to bill each prefix's `payer` in NEAR AI Cloud credits. Without the section, nothing changes.

```json
"billing": {"cloud_api_url": "https://cloud-api.near.ai", "token_env": "NEAR_DRIVE_CLOUD_API_TOKEN", "gateway_id": "gw-eu-1"}
```

- **Metering.** The gateway tails `usage.jsonl` and keeps live stored bytes per payer: a put adds `bytes` and releases `replaced_bytes`, and a delete releases `bytes`. It closes hourly windows into three meters: storage GiB-hours, egress GiB, and requests (puts, deletes and chunk reads). Bytes handed out as direct URLs by `?mode=locate` count as egress when the locate is served; this is an upper bound. State (log offset, accumulators, outbox) is saved atomically in `data_dir/billing/state.json`, so a restart neither loses nor double-counts usage. Remainders smaller than 0.001 units carry over to the next window.
- **Reporting.** Every `report_interval_secs` (default 300), the gateway posts closed windows to cloud-api `POST /v1/internal/service-usage` with idempotency key `near-drive:{gateway_id}:{payer}:{window_start}:{service}`. Failed posts retry with exponential backoff (capped at `max_backoff_secs`). cloud-api deduplicates resends after a crash. Lines rejected permanently (400/409), or still failing after `dead_letter_after_secs` (default 7 days), go to `billing/dead_letter.jsonl`. The token comes from the env var named by `token_env` (cloud-api's `CLOUD_API_STORAGE_BILLING_TOKEN`). `gateway_id` must be unique per gateway.
- **Credit gate.** Before a chunk upload, a put that grows storage, or egress (chunk read or locate), the gateway checks cloud-api `billing-status` for the payer. Answers are cached for 60 s while the payer can pay and 15 s once it cannot. When the payer cannot pay, the request gets `402 {"error": "...", "code": "payment_required", "payer": "...", "reason": "limit_exceeded" | "no_credits" | "unknown_account" | ...}`. Deletes are never gated. If cloud-api is unreachable, the last answer is reused for up to `stale_status_max_secs` (1 h). After that, `fail_open` decides. It defaults to `true`: usage is still metered and reported later, so an outage costs at most unpaid usage by payers with no credit, while failing closed would make cloud-api a hard dependency of every write. Set `fail_open` to `false` to answer `503 billing_unavailable` instead.
- **Settlement.** `billing::settle::Settlement` is the plug-in point for the NEAR escrow settler (`settle([{payer, amount, gateway, period_id}])`). It ships with `cloud_credits` (default) and `log` (dev: logs lines, gate off) backends.
- **Limits.** One meter reads one gateway's log, so a payer's bytes must be written and deleted through the same gateway for storage to integrate correctly. A NEAR account is billed to its personal NEAR AI Cloud organization and must have signed in to NEAR AI Cloud once; until then, writes get 402 `unknown_account`.

## S3 sidecar (`near drive up` / `down`)

Existing S3 code (boto3, aws-cli, aws-sdk-*) can talk to NEAR Drive by changing only `endpoint_url` and the keys:

```sh
near drive up                             # background, 127.0.0.1:9000, loopback only; prints AWS_* exports
#  keys generated once, stored 0600 in ~/.near-drive/s3-proxy.json; pid/log in ~/.near-drive/s3-proxy.{pid,log}
near drive down                           # stop it
near drive s3-proxy                       # same, in the foreground (containers, systemd); takes the same flags
#  or: --access-key/--secret-key (env NEAR_DRIVE_S3_ACCESS_KEY / NEAR_DRIVE_S3_SECRET_KEY)
#  --public-prefix weights/public/   store keys under that prefix unencrypted
#  --bucket other.near               also list this namespace in ListBuckets
```

```python
s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:9000",
                  aws_access_key_id=AK, aws_secret_access_key=SK, region_name="us-east-1")
s3.upload_file("ckpt.bin", "alice.near", "ckpts/step-100.bin")
```

The proxy encrypts client-side with the account's root key and signs requests with its NEAR key.
- **Addressing.** Bucket = NEAR namespace and key = object path. Path-style URLs (`http://127.0.0.1:9000/alice.near/key`) work, and so does virtual-host style when the host is `alice.near.localhost`.
- **Auth.** Accepted: SigV4 header and presigned auth, including signed `aws-chunked` with every chunk signature verified, `UNSIGNED-PAYLOAD` and `STREAMING-UNSIGNED-PAYLOAD-TRAILER`. `x-amz-checksum-{crc32,crc32c,crc64nvme,sha1,sha256}` and `Content-MD5` are checked. SigV2 is also accepted, because botocore < 1.36 presigns with it. Requests fail on a bad signature, a wrong key or more than 15 minutes of clock skew.
- **Operations.**
  - Buckets: ListBuckets, Head/Create/DeleteBucket (own namespace only, as no-ops) and GetBucketLocation.
  - Objects: Put/Get/Head/Delete Object, with Range and the If-* conditions, plus DeleteObjects and CopyObject.
  - Listing: ListObjects v1/v2 with prefix, delimiter, pagination and `encoding-type=url`.
  - Multipart: Create/UploadPart/UploadPartCopy/Complete/Abort/ListParts/ListMultipartUploads. Parts are staged in `~/.near-drive/s3-staging` and uploaded with `put_file` on completion.
  - Not supported (`NotImplemented`): ACLs, policies, tagging, versioning, lifecycle, CORS, SSE-C headers and SigV4a.
- **Metadata.** Content-Type is kept in the manifest. `x-amz-meta-*` goes into an encrypted sidecar object `<key>.drive-s3meta`, which listings hide; keys ending in that suffix are reserved. ETag is the first 32 hex characters of the manifest cid, quoted (multipart objects have no `-N` suffix). Last-Modified comes from the record timestamp.
- **Keys.** They must be valid NEAR Drive paths: no empty, `.` or `..` segments and no trailing `/`. Other keys get `InvalidArgument`.

`tests/boto3_smoke.sh` starts a dev gateway and the proxy and runs `tests/boto3_smoke.py`. Set `PYTHON=` to choose the boto3 install and `AWS_CLI=` to also test `aws s3 cp`.

## Tests

`cargo test` runs the following:
- unit tests;
- a gateway+client e2e covering encryption at rest, overwrite/CAS, listing, namespace isolation, app-pays prefixes, and forged or stale record rejection;
- `tests/streaming.rs`: streaming vs one-shot interop, ranges, storage classes, a blob bridge with direct URLs and fallback;
- `tests/large.rs`: a large object with bounded memory;
- `crates/near-drive-s3/tests/s3_e2e.rs`: gateway + S3 proxy driven by the AWS Rust SDK (and raw signed requests for chunk signatures, trailers, skew and presigned URLs).
- `tests/contract_policy.rs`: gateway policy from `drive.near` through a mock RPC (cache, override, failure → 503).

Contract tests (`cd contracts && cargo test`, after `contracts/build.sh`; the sandbox node binary is downloaded on first
run) include `tests/sandbox.rs` (contract flows with mock FT/MT tokens, plus the `near-drive-chain` tx builder) and
`tests/gateway_chain.rs` (a real gateway resolving keys and rules from the sandbox chain, sharing by account, discovery).

CLI scripts (after `cargo build`):
- `tests/near_cli_e2e.sh`: sandbox node + contract + gateway; the CLI with near-cli-rs: key from near-cli's
  keychain, `login` (session key added by near-cli), put/get/ls signed by it, `grant` and `publish-key` sent by
  near-cli (also interactively, through near-cli's signer menu), `near drive ...` as an extension, `logout`.
  Needs `near` and `contracts/build.sh`.
- `tests/interactive_smoke.py` (pexpect): menu, account/network pickers, put, get from a listing, rm with
  confirmation, and no prompts without a terminal.

To run the S3 tests against a local MinIO (bind it to localhost only):

```sh
docker run -d --name drive-minio -p 127.0.0.1:19000:9000 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  -e MINIO_DEFAULT_BUCKETS=near-drive-test bitnamilegacy/minio:latest
export NEAR_DRIVE_TEST_S3_ENDPOINT=http://127.0.0.1:19000   # also _BUCKET, _ACCESS_KEY, _SECRET_KEY
cargo test -p near-drive-gateway --test s3          # index CAS on S3, two gateways sharing one index, presigned locate, cache
NEAR_DRIVE_TEST_LARGE_MB=200 cargo test -p near-drive-gateway --test large -- --nocapture
```
