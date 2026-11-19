# NEAR Drive (Python)

Python SDK for [NEAR Drive](../../DESIGN.md): NEAR-account-addressed, end-to-end-encrypted
object storage (`near://alice.near/path/to/object`). Wire-compatible with the Rust
`near-drive-client` and the TypeScript `@near-drive/sdk` (checked by `testvectors/`).

- Python >= 3.10; dependencies: PyNaCl (libsodium: XChaCha20-Poly1305, ed25519, X25519),
  `blake3`, `base58`, `httpx`.
- Synchronous `Client`. Everything read is verified: record signature, manifest cid,
  chunk cids, AEAD tags.

## Usage

```python
from near_drive import Client, RootKey

client = Client(
    gateway="http://127.0.0.1:8787",
    account_id="alice.near",
    signer="ed25519:...",        # NEAR secret key (full-access or fn-call key for the storage contract)
    root_key="<64 hex chars>",   # encryption root key; `near drive keygen` writes ~/.near-drive/keys/<account>.root
)

client.put("near://alice.near/memory/today.json", b'{"hello": "world"}', content_type="application/json")
data = client.get("near://alice.near/memory/today.json")
head, data = client.get_object("near://alice.near/memory/today.json")   # verified record + manifest
for e in client.list("near://alice.near/memory/"):
    print(e.path, e.size, e.seq)
client.delete("near://alice.near/memory/today.json")

# public (unencrypted) data
client.put("near://alice.near/weights/v1.bin", blob, public=True)
```

Reuse the `near-drive` CLI's files:

```python
from near_drive import Client, load_credentials, load_root_key, default_root_key_path

account, sk = load_credentials("/path/alice.json")       # NEAR credentials JSON
client = Client("http://127.0.0.1:8787", account, sk, load_root_key(default_root_key_path(account)))
```

### Sharing

```python
bob_key = bob.x25519_public()          # "x25519:<base58>"; `near drive whoami` prints the same thing

alice.put("near://alice.near/shared/report.pdf", pdf, share_with=[bob_key])   # at write time
alice.share("near://alice.near/shared/old.pdf", bob_key)                     # later; chunks reused

data = bob.get("near://alice.near/shared/report.pdf")   # policy must also let bob read the prefix
```

### App writes for user

Create the app's client **without a root key** and encrypt to the user's X25519 key. With a
policy like `{"prefix": "users/{account}/", "read": ["{account}"], "write": ["{account}", "app.near"], "payer": "app.near"}`
on `app.near`, the app pays for storage but cannot decrypt what it wrote.

```python
app = Client(gateway, "app.near", APP_SECRET_KEY)   # no root_key
app.put("near://app.near/users/bob.near/chat/0001.json", message,
        share_with=[bob_x25519], content_type="application/json")

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
  upload restarts with a fresh key (a nonce is never reused for different bytes). Resuming an encrypted upload
  needs the owner's root key.
- Small objects are read in one request (the gateway inlines their chunks in `?mode=locate`; still verified).
- `storage_class="bulk"` (or another class the gateway defines) applies to the chunks and is recorded with the
  object; `share` keeps it.

### Custom signers

`signer` may be any object with a `public_key` attribute (`ed25519:<base58>`) and a
`sign(message: bytes)` method returning the raw 64-byte signature (or base58 string).

### CLI

`python -m near_drive` (or the `near-drive-py` script) mirrors `near-drive`: `keygen`, `whoami`, `put`, `get`,
`ls`, `rm`, `share`, with the same `NEAR_DRIVE_*` environment variables and key files.

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q                 # test vectors, unit tests, resilience tests (fake gateway, and the
                                    # real ../../target/debug/near-drive-gateway on 127.0.0.1 when built)
../../testvectors/interop.sh        # Rust <-> TS <-> Python against a live local gateway
```

`put` / `get` buffer the object in memory; `put_file` / `get_to_file` / `get_to_writer` stream it
(chunked at 4 MiB by default; `chunk_size` argument).
