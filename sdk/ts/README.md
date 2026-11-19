# @nstorage/sdk (TypeScript)

TypeScript SDK for [nstorage](../../DESIGN.md): NEAR-account-addressed, end-to-end-encrypted
object storage (`near://alice.near/path/to/object`). Wire-compatible with the Rust
`nstorage-client` and the Python `nstorage` package (checked by `testvectors/`).

- ESM, Node >= 20 and browsers. The core uses only `fetch` and Web APIs; Node-only helpers
  (credential files, root key files, file upload) live in `@nstorage/sdk/node`.
- Crypto from audited libraries: `@noble/ciphers` (XChaCha20-Poly1305), `@noble/curves`
  (ed25519, X25519), `@noble/hashes` (BLAKE3, HKDF-SHA256), `@scure/base` (base58/base64).
- Everything read is verified: record signature, manifest cid, chunk cids, AEAD tags.

## Usage

```ts
import { Client, RootKey } from "@nstorage/sdk";

const client = new Client({
  gateway: "http://127.0.0.1:8787",
  accountId: "alice.near",
  signer: "ed25519:...",          // NEAR secret key (full-access or fn-call key for the storage contract)
  rootKey: "<64 hex chars>",      // encryption root key (`nst keygen` writes ~/.nstorage/keys/<account>.root)
});

await client.put("near://alice.near/memory/today.json", JSON.stringify({ hello: "world" }), {
  contentType: "application/json",
});
const text = await client.getText("near://alice.near/memory/today.json");
const head = await client.head("near://alice.near/memory/today.json");   // { record, manifest } | null
const entries = await client.list("near://alice.near/memory/");
await client.delete("near://alice.near/memory/today.json");

// Public (unencrypted) data, e.g. open model weights:
await client.put("near://alice.near/weights/v1.bin", bytes, { public: true });
```

### Sharing

Every account with a root key has an X25519 key for receiving objects:

```ts
const bobKey = bob.x25519Public();          // "x25519:<base58>"; `nst whoami` prints the same thing

// encrypt to bob at write time ...
await alice.put("near://alice.near/shared/report.pdf", pdf, { shareWith: [bobKey] });
// ... or later: re-wraps the object key, chunks are not re-uploaded
await alice.share("near://alice.near/shared/old.pdf", bobKey);

// bob reads (the namespace policy must also let bob read that prefix)
const data = await bob.get("near://alice.near/shared/report.pdf");
```

### App writes for user

An app can store data that only the user can decrypt: create the client **without a
root key** and encrypt to the user's published X25519 key. With a policy such as
`{"prefix": "users/{account}/", "read": ["{account}"], "write": ["{account}", "app.near"], "payer": "app.near"}`
on `app.near`, the app pays for storage but can neither decrypt nor (via policy) serve it to anyone else.

```ts
const app = new Client({ gateway, accountId: "app.near", signer: APP_SECRET_KEY /* no rootKey */ });
await app.put("near://app.near/users/bob.near/chat/0001.json", message, {
  shareWith: [bobX25519],            // bob's key, e.g. from storage.near or `nst whoami`
  contentType: "application/json",
});

// bob, with his own root key:
const msg = await bob.getText("near://app.near/users/bob.near/chat/0001.json");
```

### Wallet / custom signers

`signer` can be any object with the account's public key and a `sign` function returning the
raw 64-byte ed25519 signature (or base58), e.g. a wallet-held function-call key:

```ts
const client = new Client({
  gateway, accountId: "alice.near", rootKey,
  signer: { publicKey: "ed25519:...", sign: async (msg) => wallet.signRaw(msg) },
});
```

### Node helpers

```ts
import { clientFromFiles, putFile, getFile, generateRootKeyFile, defaultRootKeyPath } from "@nstorage/sdk/node";

const c = await clientFromFiles({ gateway: "http://127.0.0.1:8787", credentials: "/path/alice.json" });
await putFile(c, "./model.bin", "near://alice.near/weights/model.bin");
await getFile(c, "near://alice.near/weights/model.bin", "./copy.bin");
```

`scripts/nst-ts.mjs` is a small `nst`-compatible CLI (`whoami`, `put`, `get`, `ls`, `rm`, `share`)
used by the interop test.

## Notes

- Objects are buffered in memory (chunked at 4 MiB by default; `chunkSize` option).
- Browsers: the gateway must send CORS headers allowing the `x-near-*` request headers.
- Request timestamps are made strictly increasing per client, because the gateway's replay
  cache is keyed by signature and ed25519 signatures are deterministic.

## Development

```sh
npm install
npm test            # vitest: Rust test vectors (../../testvectors) + unit tests
npm run build       # tsc -> dist/
../../testvectors/interop.sh   # Rust <-> TS <-> Python against a live local gateway
```
