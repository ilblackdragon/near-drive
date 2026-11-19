# nstorage

NEAR-account-addressed, end-to-end-encrypted object storage: `near://alice.near/path/to/object`.
See [DESIGN.md](DESIGN.md) for the architecture and roadmap.

## Phase 0 (this code)

| crate | what |
|---|---|
| `nstorage-core` | URIs, chunked XChaCha20-Poly1305 envelope encryption, manifests, signed pointer records, request signing, namespace policy |
| `nstorage-client` | Rust SDK: chunk + encrypt + sign, verifies everything it reads; streaming `put_file`/`get_to_file`/`get_range` for large objects |
| `nstorage-gateway` | stateless HTTP gateway; NEAR access-key auth (RPC `view_access_key` or dev keys); blob backends fs / S3 / R2 / MinIO / HTTP blob bridge with storage classes and replication; fs or S3 (multi-gateway CAS) index; chunk cache; `?mode=locate` direct URLs; JSONL usage metering |
| `nstorage-s3` | S3-compatible local sidecar: SigV4/SigV2 verification, aws-chunked + checksum trailers, S3 ops → native API |
| `nst` | CLI: `keygen`, `dev-key`, `put`, `get` (streaming, `--range`, `--class`), `ls`, `rm`, `s3-proxy` |

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

## S3 sidecar (`nst s3-proxy`)

Existing S3 code (boto3, aws-cli, aws-sdk-*) can talk to nstorage by changing only `endpoint_url` and the keys:

```sh
nst s3-proxy                       # 127.0.0.1:9000; loopback only
#  first start prints the generated keys (stored 0600 in ~/.nstorage/s3-proxy.json)
#  or: --access-key/--secret-key (env NSTORAGE_S3_ACCESS_KEY / NSTORAGE_S3_SECRET_KEY)
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
  - Multipart: Create/UploadPart/UploadPartCopy/Complete/Abort/ListParts/ListMultipartUploads. Parts are staged in `~/.nstorage/s3-staging` and uploaded with `put_file` on completion.
  - Not supported (`NotImplemented`): ACLs, policies, tagging, versioning, lifecycle, CORS, SSE-C headers and SigV4a.
- **Metadata.** Content-Type is kept in the manifest. `x-amz-meta-*` goes into an encrypted sidecar object `<key>.nst-s3meta`, which listings hide; keys ending in that suffix are reserved. ETag is the first 32 hex characters of the manifest cid, quoted (multipart objects have no `-N` suffix). Last-Modified comes from the record timestamp.
- **Keys.** They must be valid nstorage paths: no empty, `.` or `..` segments and no trailing `/`. Other keys get `InvalidArgument`.

`tests/boto3_smoke.sh` starts a dev gateway and the proxy and runs `tests/boto3_smoke.py`. Set `PYTHON=` to choose the boto3 install and `AWS_CLI=` to also test `aws s3 cp`.

## Tests

`cargo test` runs the following:
- unit tests;
- a gateway+client e2e covering encryption at rest, overwrite/CAS, listing, namespace isolation, app-pays prefixes, and forged or stale record rejection;
- `tests/streaming.rs`: streaming vs one-shot interop, ranges, storage classes, a blob bridge with direct URLs and fallback;
- `tests/large.rs`: a large object with bounded memory;
- `crates/nstorage-s3/tests/s3_e2e.rs`: gateway + S3 proxy driven by the AWS Rust SDK (and raw signed requests for chunk signatures, trailers, skew and presigned URLs).

To run the S3 tests against a local MinIO (bind it to localhost only):

```sh
docker run -d --name nst-minio -p 127.0.0.1:19000:9000 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  -e MINIO_DEFAULT_BUCKETS=nstorage-test bitnamilegacy/minio:latest
export NSTORAGE_TEST_S3_ENDPOINT=http://127.0.0.1:19000   # also _BUCKET, _ACCESS_KEY, _SECRET_KEY
cargo test -p nstorage-gateway --test s3          # index CAS on S3, two gateways sharing one index, presigned locate, cache
NSTORAGE_TEST_LARGE_MB=200 cargo test -p nstorage-gateway --test large -- --nocapture
```
