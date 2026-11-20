# NEAR Drive (Python)

Python SDK for [NEAR Drive](../../DESIGN.md): NEAR-account-addressed, end-to-end-encrypted
object storage (`near://alice.near/path/to/object`). Wire-compatible with the Rust
`near-drive-client` and the TypeScript `@near-drive/sdk` (checked by `testvectors/`).

- Python >= 3.10; dependencies: PyNaCl (libsodium: XChaCha20-Poly1305, ed25519, X25519),
  `blake3`, `base58`, `httpx`.
- Synchronous `Client`. Everything read is verified: record signature, the writer's authorization
  (onchain signing key and namespace rules, see [Writer check](#writer-check)), manifest cid,
  chunk cids, AEAD tags.

## Usage

```python
from near_drive import Client, RootKey

client = Client(
    gateway="http://127.0.0.1:8787",
    account_id="alice.near",
    signer="ed25519:...",        # NEAR secret key (full-access or fn-call key for the storage contract)
    root_key="<64 hex chars>",   # root key; `near drive keygen` writes ~/.near-drive/keys/<account>.root
    rpc_url="https://rpc.mainnet.near.org",   # reads verify record writers against drive.near
)

client.put("near://alice.near/memory/today.json", b'{"hello": "world"}', content_type="application/json")
data = client.get("near://alice.near/memory/today.json")
head, data = client.get_object("near://alice.near/memory/today.json")   # verified record + manifest
for e in client.list("near://alice.near/memory/"):          # every page
    print(e.path, e.size, e.seq)
page = client.list_page("near://alice.near/", delimiter="/", limit=100)   # one level, one page
print(page.common_prefixes, page.next_cursor)               # pass next_cursor as cursor= for more
client.delete("near://alice.near/memory/today.json")

# public (unencrypted) data
client.put("near://alice.near/weights/v1.bin", blob, public=True)
```

Reuse the `near-drive` CLI's files:

```python
from near_drive import Client, load_credentials, load_root_key, default_root_key_path

account, sk = load_credentials("/path/alice.json")       # NEAR credentials JSON
client = Client("http://127.0.0.1:8787", account, sk, load_root_key(default_root_key_path(account)), rpc_url=RPC_URL)
```

### Writer check

A pointer record is signed with a key derived from the writer's root key
(`HKDF-SHA256(salt="near-drive", ikm=root, info="near-drive/v1/sign")` as an ed25519 seed;
`client.sign_public_key()` / `root.sign_public_key()`). The writer publishes it once in the drive
contract with **`near drive publish-key`** (`set_sign_key`; this SDK does not send transactions). So:

- **Writing requires the root key**, also for public objects and app-writes-for-user.
- **Every read** (`get`, `get_object`, `head`, `locate`, `get_range`, `get_to_file`, `get_to_writer`)
  accepts a record only if its `writer_pk` is one of `get_sign_keys(writer)` in force at the record's
  `ts_ms` (±5 min around key changes) and the namespace rules (`get_rules`) let `writer` write the path
  (the owner always may). A malicious gateway can withhold or serve stale data, but cannot forge a writer.

How a client checks (`writer_check=`; there is no silent default):

```python
from near_drive import Client, WriterCheck

# Production: NEAR RPC view calls (finality "final"), cached 60 s per account / namespace (1024 entries max).
Client(gateway, account, sk, root, rpc_url="https://rpc.mainnet.near.org")        # contract_id="drive.near"
Client(gateway, account, sk, root, writer_check=WriterCheck.chain(rpc_url, "drive.near", ttl=60, max_entries=1024))

# Dev gateways / tests without a chain: fixed signing keys (+ optional rules per namespace).
Client(..., writer_check=WriterCheck.trusted({"alice.near": [alice_root.sign_public_key()]}, {"app.near": rules}))

# Tests only: no writer check at all.
Client(..., writer_check=WriterCheck.insecure_skip_writer_check())
```

A client with neither `writer_check` nor `rpc_url` can write, but every read raises an error naming
these options. `verify_head(uri, head, writer_check)` runs the same checks on a head you fetched
yourself; `resolve_policy` is the namespace-rule evaluation (`near_drive_core::policy::resolve`).

### Sharing

```python
bob_key = bob.x25519_public()          # "x25519:<base58>"; `near drive whoami` prints the same thing

alice.put("near://alice.near/shared/report.pdf", pdf, share_with=[bob_key])   # at write time
alice.share("near://alice.near/shared/old.pdf", bob_key)                     # later; chunks reused

data = bob.get("near://alice.near/shared/report.pdf")   # policy must also let bob read the prefix
```

### App writes for user

Encrypt to the user's X25519 key with `skip_owner_key=True`, so the object key is not also wrapped to
the app's own root key (the app still needs a root key: it signs the record). With a policy like `{"prefix": "users/{account}/", "read": ["{account}"], "write": ["{account}", "app.near"], "payer": "app.near"}`
on `app.near`, the app pays for storage but cannot decrypt what it wrote.

```python
app = Client(gateway, "app.near", APP_SECRET_KEY, APP_ROOT_KEY, rpc_url=RPC_URL)
app.put("near://app.near/users/bob.near/chat/0001.json", message,
        share_with=[bob_x25519], skip_owner_key=True, content_type="application/json")

# bob, with his own root key:
msg = bob.get("near://app.near/users/bob.near/chat/0001.json")
```

### Large files, bad networks and resuming

```python
from near_drive import Client, NetConfig, Conflict, TransferInterrupted

client = Client(gateway, account, sk, root,
                net=NetConfig(attempts=8, base_delay=0.25, max_delay=30.0),   # the defaults
                parallelism=8)                                                 # chunk transfers in flight

# Stream a file up / down with bounded memory (about (parallelism + 2) x chunk_size).
client.put_file("model.bin", "near://alice.near/models/v1.bin", resume_dir="~/.cache/drive-journal")
client.get_to_file("near://alice.near/models/v1.bin", "model.bin")
part = client.get_range("near://alice.near/models/v1.bin", 0, 1 << 20)   # only the chunks covering the range
```

- Every request has a deadline of `30 s + size / 64 KiB/s` (plus 10 s connect and 60 s idle timeouts) and is
  retried on connection errors, timeouts, truncated bodies, chunks whose bytes don't match their id, 5xx, 408
  and 429, with full-jitter exponential backoff (250 ms doubling, capped at 30 s), honouring `Retry-After`;
  8 attempts. Each attempt is signed afresh. Tune with `NetConfig` (`Client(net=...)` or `client.set_net(...)`).
- The record write is a compare-and-swap: if its response is lost, the client checks whether the current
  version is its own write before retrying, so a retry never produces a spurious extra version. Deletes are
  retried the same way.
- Conditional writes: `put(..., expect_seq=n)` / `put_file(..., expect_seq=n)` (0 = must not exist) and
  `delete_if(uri, seq)` raise `Conflict` (with `.current`, the seq now) instead of overwriting a newer version.
- `get_to_file` writes `{file}.drive-part` + `{file}.drive-part.json`. If it raises `TransferInterrupted`,
  run it again: chunks already on disk are verified (their id re-derived from the bytes) and only the missing
  ones are fetched. A newer version of the object starts over.
- `put_file(..., resume_dir=...)` keeps a journal (same format as the Rust client). Rerunning after
  `TransferInterrupted` reuses the object key so stored chunks are skipped; if the file changed meanwhile, the
  upload restarts with a fresh key (a nonce is never reused for different bytes). Encrypted uploads with
  `skip_owner_key=True` do not resume.
- Small objects are read in one request (the gateway inlines their chunks in `?mode=locate`; still verified).
- `storage_class="bulk"` (or another class the gateway defines) applies to the chunks and is recorded with the
  object; `share` keeps it.

### Custom signers

`signer` may be any object with a `public_key` attribute (`ed25519:<base58>`) and a
`sign(message: bytes)` method returning the raw 64-byte signature (or base58 string).

### CLI

`python -m near_drive` (or the `near-drive-py` script) mirrors `near-drive`: `keygen`, `whoami`, `put`, `get`,
`ls`, `rm`, `share`, with the same `NEAR_DRIVE_*` environment variables and key files. Reads check writers via
`--rpc-url` / `NEAR_DRIVE_RPC_URL` (+ `--contract` / `NEAR_DRIVE_CONTRACT`); `--insecure-skip-writer-check`
(`NEAR_DRIVE_INSECURE_SKIP_WRITER_CHECK=1`) turns that off for local dev gateways.

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q                 # test vectors, unit + writer-check tests, resilience tests (fake gateway, and the
                                    # real ../../target/debug/near-drive-gateway on 127.0.0.1 when built)
../../testvectors/interop.sh        # Rust <-> TS <-> Python against a live local gateway
```

`put` / `get` buffer the object in memory; `put_file` / `get_to_file` / `get_to_writer` stream it
(chunked at 4 MiB by default; `chunk_size` argument).
