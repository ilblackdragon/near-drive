# Development

## Layout

| path | what |
|---|---|
| `crates/near-drive-core` | URIs, chunked XChaCha20-Poly1305 envelope encryption, manifests, signed records, request signing, access rules |
| `crates/near-drive-client` | Rust SDK: chunk + encrypt + sign, verifies everything it reads; streaming, retries, resumable transfers |
| `crates/near-drive-gateway` | the gateway: NEAR key auth, backends (fs / S3 / R2 / MinIO / blob bridge), storage classes, index, caches, metering, billing |
| `crates/near-drive-s3` | the local S3-compatible endpoint (SigV4/SigV2, aws-chunked, multipart) on top of the client |
| `crates/near-drive-sync` | folder sync engine (Linux / macOS / Windows) |
| `crates/near-drive-mount` | files on demand: FUSE (Linux, macOS with macFUSE) and the Windows Cloud Files API |
| `crates/near-drive-tray` | tray / menu-bar app (`near-drive-tray`) |
| `crates/near-drive-cli` | the `near-drive` binary / `near drive` near-cli extension |
| `crates/near-drive-chain` | NEAR JSON-RPC views and signed function calls for `drive.near` |
| `crates/near-drive-ckd` | MPC confidential key derivation for root keys ([ckd.md](ckd.md)) |
| `contracts/drive` | the `drive.near` contract (separate cargo workspace, wasm) |
| `sdk/ts`, `sdk/python` | TypeScript and Python SDKs (wire-compatible; checked by `testvectors/`) |
| `bridges/` | Filecoin Onchain Cloud and Shelby blob bridges ([blob-bridge.md](blob-bridge.md), [backends.md](backends.md)) |
| `DESIGN.md` | architecture, protocol, roadmap and what is verified |

## Local gateway with a dev key

```sh
cargo build
PK=$(target/debug/near-drive --account alice.near dev-key --out /tmp/alice.json)
cat > /tmp/gw.json <<JSON
{"listen":"127.0.0.1:8787","data_dir":"/tmp/drive-data","dev_keys":{"alice.near":["$PK"]}}
JSON
target/debug/near-drive-gateway --config /tmp/gw.json &

export NEAR_DRIVE_ACCOUNT=alice.near NEAR_DRIVE_CREDENTIALS=/tmp/alice.json
# alice.near has no signing key onchain to check records against (dev only; see docs/cli.md)
export NEAR_DRIVE_INSECURE_SKIP_WRITER_CHECK=1
target/debug/near-drive keygen --random
echo hello | target/debug/near-drive put - memory/today.txt
target/debug/near-drive ls
target/debug/near-drive get memory/today.txt
```

With real NEAR accounts, set `"rpc_url"` in the gateway config and drop `NEAR_DRIVE_CREDENTIALS` and
`NEAR_DRIVE_INSECURE_SKIP_WRITER_CHECK`: the CLI then uses near-cli's keys (`near drive login`), and
`near drive publish-key` publishes the record-signing key that readers and the gateway check.

## Client internals

Large objects stream with memory around `(parallelism + 2) × chunk_size` whatever the size.

| SDK call | what it does |
|---|---|
| `Client::put_file` / `put_reader` | reads, encrypts and uploads chunk by chunk, `client.parallelism` uploads in flight |
| `Client::get_to_file` | `GET ...?mode=locate` returns the record, manifest and a direct URL per chunk (presigned S3 or bridge CDN), or the chunk bytes inline for small objects; chunks are fetched in parallel, every id verified, with fallback to the gateway (`?chunk=`, supports `Range`) |
| `get_to_writer` | like `get_to_file`, streamed in order to any writer |
| `get_range(uri, a..b)` | fetches and decrypts only the chunks that cover the range |

Network behaviour (`NetConfig`):
- Deadlines: 10 s connect, 60 s idle, and `30 s + size / 64 KiB/s` per request.
- Retries: connection errors, timeouts, truncated bodies, chunks whose bytes don't match their id, 5xx, 408 and 429,
  with full-jitter exponential backoff (250 ms doubling, capped at 30 s), honouring `Retry-After`; 8 attempts. Each
  attempt is signed afresh.
- The record commit is a compare-and-swap. If its response is lost, the client checks whether the current version is
  its own write before retrying. Deletes likewise.
- `PutOptions::expect_seq` / `Client::delete_if` make writes conditional on a version (used by sync); a mismatch is a
  `Conflict` error.

Resuming:
- Downloads keep `{file}.drive-part` + `{file}.drive-part.json`; a rerun re-derives each chunk's id from the bytes on
  disk and fetches only what is missing. A newer version starts over.
- Uploads (`PutOptions::resume_dir`) journal each stored chunk. A rerun reuses the object key, so unchanged chunks
  re-encrypt to the same ids and are skipped. Before a chunk is sent, the journal durably records a hash of its
  plaintext; if the file changed (even with the same size and mtime), the upload restarts with a fresh key, so a
  nonce is never reused for different bytes.

## Tests

```sh
cargo test --workspace
```

covers:
- unit tests;
- `crates/near-drive-gateway/tests/e2e.rs`: encryption at rest, overwrite/CAS, listing, namespace isolation, app-pays
  prefixes, forged or stale record rejection;
- `tests/streaming.rs`: streaming vs one-shot, ranges, storage classes, a blob bridge with direct URLs and fallback;
- `tests/resilience.rs`: a fault-injecting proxy (503s, truncated bodies, lost write responses, dead links); resumed
  transfers move only what is missing; a changed file restarts with a fresh key; small reads take one request;
- `tests/large.rs`: a large object with bounded memory;
- `tests/contract_policy.rs`: rules from `drive.near` through a mock RPC;
- `crates/near-drive-sync/tests/sync.rs`: two devices syncing through a gateway (first sync, edits both ways, deletes
  to trash, conflicted copies, touch without transfer, conditional writes, offline, settle, the watch loop);
- `crates/near-drive-mount/tests/mount.rs`: a real FUSE mount (skipped without `/dev/fuse`): on-demand download,
  create / edit / rename / delete, remote changes, conflicted copies; `tests/windows.rs` does the same against the
  Cloud Files API on Windows (CI);
- `crates/near-drive-s3/tests/s3_e2e.rs`: the S3 endpoint driven by the AWS Rust SDK and raw signed requests.

Windows builds can be checked from Linux: `cargo check --workspace --tests --target x86_64-pc-windows-gnu`. CI
(`.github/workflows/ci.yml`) builds and tests on Linux, macOS and Windows.

Scripts (after `cargo build`):
- `tests/near_cli_e2e.sh`: local NEAR sandbox + contract + gateway with near-cli-rs: keys from near-cli's keychain,
  `login`, put/get/ls with the session key, `grant` and `publish-key` sent by near-cli (also interactively), `near
  drive ...` as an extension, `logout`. Needs `near` and `contracts/build.sh`.
- `tests/interactive_smoke.py` (pexpect): menus and pickers, put/get/rm, bare paths, `up`/`down` with boto3, folder
  sync through the background service, no prompts without a terminal.
- `tests/deltaleague_compat.sh`: deltaleague's storage patterns (boto3 upload_file / upload_fileobj from a pipe,
  presigned GET via httpx without redirects, presigned PUT, CORS, ranges) against the S3 endpoint configured like a
  service (env keys, bucket aliases);
- `tests/boto3_smoke.sh`: dev gateway + S3 endpoint driven by boto3 (`PYTHON=` picks the install, `AWS_CLI=` also
  tests `aws s3 cp`).
- `testvectors/interop.sh`: Rust, TypeScript and Python read each other's objects.
- SDKs: `cd sdk/ts && npx vitest run`; `cd sdk/python && .venv/bin/pytest -q`.

S3 / R2 backends against a local MinIO (bind it to localhost only):

```sh
docker run -d --name drive-minio -p 127.0.0.1:19000:9000 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  -e MINIO_DEFAULT_BUCKETS=near-drive-test bitnamilegacy/minio:latest
export NEAR_DRIVE_TEST_S3_ENDPOINT=http://127.0.0.1:19000   # also _BUCKET, _ACCESS_KEY, _SECRET_KEY
cargo test -p near-drive-gateway --test s3          # index CAS on S3, two gateways sharing one index, presigned locate, cache
NEAR_DRIVE_TEST_LARGE_MB=200 cargo test -p near-drive-gateway --test large -- --nocapture
```

## Contract

```sh
contracts/build.sh                                     # cargo near build -> contracts/target/near/*/
cd contracts && cargo test -p near-drive-contract      # unit tests + local sandbox (near-workspaces) tests
```

For deployment, build reproducibly instead (Docker, pinned image, NEP-330 build info):
`contracts/build-reproducible.sh` — see [contract.md](contract.md#reproducible-build-and-verification).

`tests/sandbox.rs` covers contract flows with mock FT/MT tokens and the `near-drive-chain` transaction builder;
`tests/gateway_chain.rs` runs a real gateway resolving keys and rules from the sandbox chain, sharing by account and
discovery. The sandbox node binary is downloaded on first run.
