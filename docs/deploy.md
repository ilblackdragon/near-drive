# Deploying NEAR Drive for a service

How a service that uses S3 / R2 today (example: deltaleague) moves its storage to NEAR Drive without changing its
code: run a **gateway** (storage, backed by your existing R2 / S3 bucket) and an **S3 endpoint** (what your code talks
to; it holds your keys and encrypts). Both ship in one container image.

```
 your services (boto3) ──┐                                  ┌─> R2 / S3 (ciphertext only)
 GPU workers / browsers ─┼─ presigned URLs ─> S3 endpoint ──┼─> gateway ─┤
                         │                  (your keys,      │            └─> index (R2 / S3)
                         └─────────────────  encrypts) ──────┘
```

- The **S3 endpoint** runs in your trust domain, next to the services that today hold your R2 keys. It verifies the
  same SigV4 requests and **presigned URLs** your code already makes (boto3 signs them locally), so remote machines
  that receive a presigned URL (GPU workers, a browser upload) use it unchanged. It encrypts on the way in and
  decrypts on the way out; the gateway and storage only ever see ciphertext.
- The **gateway** stores chunks in your bucket and keeps the index; it never sees plaintext or your keys.

## Image

```sh
docker pull ghcr.io/ilblackdragon/near-drive:latest      # or build: docker build -t near-drive .
```

Contains `near-drive-gateway` (the default command) and `near-drive` (for the S3 endpoint), runs as an unprivileged
user with data under `/data`. Configure everything with environment variables; nothing has to be mounted.

## 1. Gateway

```sh
docker run -d --name drive-gateway -p 127.0.0.1:8787:8787 -v drive-gw:/data \
  -e NEAR_DRIVE_CONFIG_JSON='{
    "listen": "0.0.0.0:8787",
    "data_dir": "/data/gw",
    "rpc_url": "https://rpc.mainnet.near.org",
    "storage": {
      "backends": {"r2": {"type": "s3", "bucket": "delta-artifacts", "endpoint": "https://<acct>.r2.cloudflarestorage.com",
                          "region": "auto", "prefix": "near-drive/chunks/"}},
      "index": {"type": "s3", "bucket": "delta-artifacts", "endpoint": "https://<acct>.r2.cloudflarestorage.com",
                "region": "auto", "prefix": "near-drive/index/"}
    },
    "gc": {"interval_secs": 86400, "grace_secs": 86400}
  }' \
  -e AWS_ACCESS_KEY_ID=<r2 key> -e AWS_SECRET_ACCESS_KEY=<r2 secret> \
  ghcr.io/ilblackdragon/near-drive
```

- `NEAR_DRIVE_CONFIG_JSON` is the whole [gateway config](gateway.md) (or mount a file and pass `--config`).
- With `rpc_url`, requests are authenticated against the account's NEAR keys, and records must be signed with the
  writer's published signing key (`near drive publish-key`). For a private gateway serving one service you can instead
  list its key in `"dev_keys": {"app.near": ["ed25519:..."]}` (and its record-signing key, `near drive whoami`, in
  `"dev_sign_keys"`) and leave out `rpc_url`. Clients still check records against the chain, so publish the signing
  key anyway.
- Keep the index and chunks on R2 so the container is stateless; `gc` frees chunks of deleted and replaced files
  ([gateway.md](gateway.md#garbage-collection)).
- Inside the container it listens on `0.0.0.0`; publish the port only on a private address (as above) or a private
  network.

## 2. S3 endpoint

```sh
docker run -d --name drive-s3 -p 127.0.0.1:9000:9000 \
  -e NEAR_DRIVE_ACCOUNT=app.near \
  -e NEAR_DRIVE_GATEWAY=http://drive-gateway:8787 \
  -e NEAR_DRIVE_SECRET_KEY=ed25519:...          `# the NEAR key that signs requests (a function-call key is enough)` \
  -e NEAR_DRIVE_ROOT_KEY=<64 hex>               `# the encryption root key; back it up` \
  -e NEAR_DRIVE_S3_ACCESS_KEY=... -e NEAR_DRIVE_S3_SECRET_KEY=... \
  ghcr.io/ilblackdragon/near-drive \
  near-drive --no-interactive s3-proxy --listen 0.0.0.0:9000 --public-listen \
    --bucket-alias delta-artifacts=near://app.near/artifacts/ \
    --bucket-alias delta-private=near://app.near/private/ \
    --cors-origin https://portal.example
```

| setting | |
|---|---|
| `NEAR_DRIVE_SECRET_KEY` | NEAR key for `NEAR_DRIVE_ACCOUNT` that signs gateway requests (instead of near-cli / files) |
| `NEAR_DRIVE_ROOT_KEY` | encryption root key, hex (instead of `~/.near-drive/keys`); use the account's key (`near drive key export` prints it). Writes are refused if it does not match the keys the account published |
| `NEAR_DRIVE_S3_ACCESS_KEY` / `_SECRET_KEY` | the S3 credentials your code uses (replace the R2 ones) |
| `--bucket-alias NAME=near://ACCOUNT/PREFIX/` | keep existing bucket names; repeatable |
| `--cors-origin` | browser origins allowed to use presigned URLs (uploads from a web page) |
| `--public-listen` | allow a non-loopback address. Put the endpoint behind TLS (the platform's HTTPS, or a reverse proxy) |
| `--virtual-host-domain` | if clients address buckets as `<bucket>.<domain>` |

Then point the service at it: for deltaleague, `R2_ENDPOINT=https://s3.your-domain`, `R2_ACCESS_KEY_ID` /
`R2_SECRET_ACCESS_KEY` = the endpoint's S3 credentials. Bucket names, presigned URLs (GET with ranges, PUT), multipart
uploads and streaming downloads keep working.

**Multipart uploads stream:** parts are encrypted and uploaded as they arrive; only parts that arrive ahead of their
turn are held on disk briefly. A 56 GB checkpoint uploaded with 128 MiB parts × 4 needs a few hundred MB of temporary
disk, not 56 GB. An upload in progress does not survive a restart of the endpoint (the client gets `NoSuchUpload` and
starts over).

## Separating access

Two buckets with different credentials (e.g. a web app that must not read private data) map to two S3 endpoints with
different keys:

- the controller's endpoint holds the account key and root key, with aliases for both buckets;
- the web app's endpoint serves only `delta-artifacts`, with a **different NEAR account** (e.g. `app-web.near`) that
  the account's [access rules](cli.md#sharing-and-access-rules) allow to read/write `artifacts/`, and its own root
  key. Files it must read are written for it (`share_with`), or stored under a `--public-prefix` if they are public.

## Moving existing data

With both running, copy each bucket through the endpoint (it encrypts on the way in), e.g. with
[rclone](https://rclone.org) and two S3 remotes, `r2` (your R2 account) and `neardrive` (the endpoint and its keys):

```sh
rclone copy r2:delta-artifacts neardrive:delta-artifacts --checksum --transfers 8
rclone copy r2:delta-private   neardrive:delta-private   --checksum --transfers 8
```

Keep R2 as the fallback until downloads (hashes and speed) are confirmed through NEAR Drive.

## Checked

- `tests/deltaleague_compat.sh` runs deltaleague's own patterns against the endpoint configured as above (env keys,
  aliases, CORS): `upload_file` with 10 concurrent parts, streamed `get_object`, presigned GET through `httpx.stream`
  without redirects, presigned PUT, `upload_fileobj` from a non-seekable pipe (8 MiB × 4) with staging staying near
  zero, ranged reads, list / delete, and no plaintext in the gateway's storage. The same script passes against the
  two containers on a private Docker network.
- Not yet: real R2 underneath (only MinIO / local disk), throughput numbers for 56 GB downloads, a TLS front end.
