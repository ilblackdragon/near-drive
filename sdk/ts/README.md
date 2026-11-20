# @near-drive/sdk (TypeScript)

TypeScript SDK for [NEAR Drive](../../DESIGN.md): NEAR-account-addressed, end-to-end-encrypted
object storage (`near://alice.near/path/to/object`). Wire-compatible with the Rust
`near-drive-client` and the Python `near_drive` package (checked by `testvectors/`).

- ESM, Node >= 20 and browsers. The core uses only `fetch` and Web APIs; Node-only helpers
  (credential files, root key files, file upload) live in `@near-drive/sdk/node`.
- Crypto from audited libraries: `@noble/ciphers` (XChaCha20-Poly1305), `@noble/curves`
  (ed25519, X25519), `@noble/hashes` (BLAKE3, HKDF-SHA256), `@scure/base` (base58/base64).
- Everything read is verified: record signature, the writer's authorization (onchain signing key and
  namespace rules, see [Writer check](#writer-check)), manifest cid, chunk cids, AEAD tags.

## Usage

```ts
import { Client, RootKey } from "@near-drive/sdk";

const client = new Client({
  gateway: "http://127.0.0.1:8787",
  accountId: "alice.near",
  signer: "ed25519:...",          // NEAR secret key (full-access or fn-call key for the storage contract)
  rootKey: "<64 hex chars>",      // root key (`near drive keygen` writes ~/.near-drive/keys/<account>.root)
  rpcUrl: "https://rpc.mainnet.near.org",  // reads verify record writers against drive.near
});

await client.put("near://alice.near/memory/today.json", JSON.stringify({ hello: "world" }), {
  contentType: "application/json",
});
const text = await client.getText("near://alice.near/memory/today.json");
const head = await client.head("near://alice.near/memory/today.json");   // { record, manifest } | null
const entries = await client.list("near://alice.near/memory/");   // every page
const page = await client.listPage("near://alice.near/", { delimiter: "/", limit: 100 });
// page.entries, page.common_prefixes; pass page.next_cursor as { cursor } for the next page (null = done)
await client.delete("near://alice.near/memory/today.json");

// Public (unencrypted) data, e.g. open model weights:
await client.put("near://alice.near/weights/v1.bin", bytes, { public: true });
```

### Writer check

A pointer record is signed with a key derived from the writer's root key
(`HKDF-SHA256(salt="near-drive", ikm=root, info="near-drive/v1/sign")` as an ed25519 seed;
`client.signPublicKey()` / `rootKey.signPublicKey()`). The writer publishes it once in the drive contract
with **`near drive publish-key`** (`set_sign_key`; this SDK does not send transactions). So:

- **Writing requires the root key**, also for public objects and app-writes-for-user.
- **Every read** (`get`, `head`, `locate`, `getFile`, chunk reads of a located object) accepts a record
  only if its `writer_pk` is one of `get_sign_keys(writer)` in force at the record's `ts_ms` (±5 min
  around key changes) and the namespace rules (`get_rules`) let `writer` write the path (the owner always
  may). A malicious gateway can withhold or serve stale data, but cannot forge a writer.

How a client checks (`writerCheck` option, there is no silent default):

```ts
import { WriterCheck, StorageContract } from "@near-drive/sdk";

// Production: NEAR RPC view calls (finality "final"), cached 60 s per account / namespace (1024 entries max).
new Client({ ..., rpcUrl: "https://rpc.mainnet.near.org" /* contractId: "drive.near" */ });
new Client({ ..., writerCheck: WriterCheck.chain({ rpcUrl, contractId: "drive.near" }, { ttlMs: 60_000, maxEntries: 1024 }) });

// Dev gateways / tests without a chain: fixed signing keys (+ optional rules per namespace).
new Client({ ..., writerCheck: WriterCheck.trusted({ "alice.near": [aliceRoot.signPublicKey()] }, { "app.near": rules }) });

// Tests only: no writer check at all.
new Client({ ..., writerCheck: WriterCheck.insecureSkipWriterCheck() });
```

A client with neither `writerCheck` nor `rpcUrl` can write, but every read fails with an error naming
these options. `verifyHead(uri, head, writerCheck)` runs the same checks on a head you fetched yourself;
`resolvePolicy` is the namespace-rule evaluation (`near_drive_core::policy::resolve`).

### Sharing

Every account with a root key has an X25519 key for receiving objects:

```ts
const bobKey = bob.x25519Public();          // "x25519:<base58>"; `near drive whoami` prints the same thing

// encrypt to bob at write time ...
await alice.put("near://alice.near/shared/report.pdf", pdf, { shareWith: [bobKey] });
// ... or later: re-wraps the object key, chunks are not re-uploaded
await alice.share("near://alice.near/shared/old.pdf", bobKey);

// bob reads (the namespace policy must also let bob read that prefix)
const data = await bob.get("near://alice.near/shared/report.pdf");
```

### App writes for user

An app can store data that only the user can decrypt: encrypt to the user's published X25519 key
with `skipOwnerKey: true`, so the object key is not also wrapped to the app's own root key (the
app still needs a root key: it signs the record). With a policy such as
`{"prefix": "users/{account}/", "read": ["{account}"], "write": ["{account}", "app.near"], "payer": "app.near"}`
on `app.near`, the app pays for storage but can neither decrypt nor (via policy) serve it to anyone else.

```ts
const app = new Client({ gateway, accountId: "app.near", signer: APP_SECRET_KEY, rootKey: APP_ROOT_KEY, rpcUrl });
await app.put("near://app.near/users/bob.near/chat/0001.json", message, {
  shareWith: [bobX25519],            // bob's key, e.g. from drive.near or `near drive whoami`
  skipOwnerKey: true,               // the app cannot decrypt it
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
import { clientFromFiles, putFile, getFile, generateRootKeyFile, defaultRootKeyPath } from "@near-drive/sdk/node";

const c = await clientFromFiles({ gateway: "http://127.0.0.1:8787", credentials: "/path/alice.json" });
await putFile(c, "./model.bin", "near://alice.near/weights/model.bin");
await getFile(c, "near://alice.near/weights/model.bin", "./copy.bin");
```

## Bad networks and resuming

Every request has a deadline (`30 s + size / 64 KiB/s`) and an idle timeout (60 s without response
bytes). Transient failures (network errors, timeouts, truncated bodies, chunks whose bytes don't match
their id, 5xx, 408, 429) are retried with full-jitter exponential backoff (250 ms doubling, capped at
30 s, `Retry-After` honoured), 8 attempts, each signed afresh. Tune it per client:

```ts
const client = new Client({ gateway, accountId, signer, rootKey, net: { attempts: 4, baseTimeoutMs: 10_000 } });
client.setNet({ attempts: 1 });   // fail fast
```

- The record commit is a compare-and-swap. If its response is lost, the client checks whether the
  current version is its own write before retrying, so a write lands exactly once. Deletes likewise
  (a 404 after a failed attempt means it was already deleted).
- Conditional writes: `put(uri, data, { expectSeq: n })` (0 = must not exist) and `deleteIf(uri, seq)`
  throw `ConflictError` (`err.current` = current seq) instead of overwriting or deleting a newer version.
- `{ class: "bulk" }` picks the storage class (also sent with the record); `share` keeps the object's class.
- Small objects are read in one request: `?mode=locate` inlines their chunks (verified like any fetch).

Resuming large transfers (`@near-drive/sdk/node`, memory about `(parallelism + 2) * chunkSize`):

```ts
// Upload: journals each stored chunk under resumeDir; rerun the same call to resume.
await putFile(c, "./model.bin", "near://alice.near/weights/model.bin", { resumeDir: "./.drive-journal" });
// Download: keeps ./model.bin.drive-part (+ .drive-part.json); rerun to fetch only what is missing.
await getFile(c, "near://alice.near/weights/model.bin", "./model.bin");
```

- Downloads: on a rerun each chunk already on disk is checked by re-deriving its id (hash, or re-encrypt
  with the object key); a newer version of the object starts over.
- Uploads reuse the object key, so unchanged chunks re-encrypt to the same ids and are skipped. Before a
  chunk is sent its plaintext hash is durably journaled; if the file changed (even with the same size and
  mtime) the upload restarts with a fresh key, so a nonce is never reused for different bytes. Encrypted
  uploads resume only with the owner's root key. The journal uses the same JSONL layout as the Rust client's.

`scripts/drive-ts.mjs` is a small `near-drive`-compatible CLI (`whoami`, `put`, `get`, `ls`, `rm`, `share`)
used by the interop test. It checks writers via `NEAR_DRIVE_RPC_URL` (+ `NEAR_DRIVE_CONTRACT`);
`NEAR_DRIVE_INSECURE_SKIP_WRITER_CHECK=1` turns that off for local dev gateways.

## Notes

- `put`/`get` buffer the object in memory (chunked at 4 MiB by default; `chunkSize` option); `putFile`/`getFile`
  stream with bounded memory. `parallelism` (default 8) sets concurrent chunk transfers.
- Browsers: the gateway must send CORS headers allowing the `x-near-*` request headers.
- Request timestamps are made strictly increasing per client, because the gateway's replay
  cache is keyed by signature and ed25519 signatures are deterministic.

## Development

```sh
npm install
npm test            # vitest: test vectors (../../testvectors), unit + writer-check tests, bad-network tests
                    # (in-memory gateway, plus ../../target/debug/near-drive-gateway on 127.0.0.1 if built)
npm run build       # tsc -> dist/
../../testvectors/interop.sh   # Rust <-> TS <-> Python against a live local gateway
```
