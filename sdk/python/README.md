# nstorage (Python)

Python SDK for [nstorage](../../DESIGN.md): NEAR-account-addressed, end-to-end-encrypted
object storage (`near://alice.near/path/to/object`). Wire-compatible with the Rust
`nstorage-client` and the TypeScript `@nstorage/sdk` (checked by `testvectors/`).

- Python >= 3.10; dependencies: PyNaCl (libsodium: XChaCha20-Poly1305, ed25519, X25519),
  `blake3`, `base58`, `httpx`.
- Synchronous `Client`. Everything read is verified: record signature, manifest cid,
  chunk cids, AEAD tags.

## Usage

```python
from nstorage import Client, RootKey

client = Client(
    gateway="http://127.0.0.1:8787",
    account_id="alice.near",
    signer="ed25519:...",        # NEAR secret key (full-access or fn-call key for the storage contract)
    root_key="<64 hex chars>",   # encryption root key; `nst keygen` writes ~/.nstorage/keys/<account>.root
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

Reuse the `nst` CLI's files:

```python
from nstorage import Client, load_credentials, load_root_key, default_root_key_path

account, sk = load_credentials("/path/alice.json")       # NEAR credentials JSON
client = Client("http://127.0.0.1:8787", account, sk, load_root_key(default_root_key_path(account)))
```

### Sharing

```python
bob_key = bob.x25519_public()          # "x25519:<base58>"; `nst whoami` prints the same thing

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

### Custom signers

`signer` may be any object with a `public_key` attribute (`ed25519:<base58>`) and a
`sign(message: bytes)` method returning the raw 64-byte signature (or base58 string).

### CLI

`python -m nstorage` (or the `nst-py` script) mirrors `nst`: `keygen`, `whoami`, `put`, `get`,
`ls`, `rm`, `share`, with the same `NSTORAGE_*` environment variables and key files.

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q                 # Rust test vectors (../../testvectors) + unit tests
../../testvectors/interop.sh        # Rust <-> TS <-> Python against a live local gateway
```

Objects are buffered in memory (chunked at 4 MiB by default; `chunk_size` argument).
