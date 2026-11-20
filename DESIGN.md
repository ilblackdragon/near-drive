# NEAR Drive — NEAR storage layer

Status: v0.2 (2026-11-19). Phases 0–3 are implemented in this repo; see §9 for what is verified and what is not.

## 1. What it is

An object store addressed by NEAR accounts:

```
near://alice.near/objects/etc/mystuff
       └ namespace ┘└──── path ──────┘
```

- **Identity and access** come from NEAR accounts (access keys, plus grants stored in a contract).
- **Encryption is client-side by default.** Gateways and storage backends see only ciphertext.
- **Payment** starts as NEAR AI Cloud credits. NEAR Intents deposits come later.
- **Backends** (S3/R2, Filecoin Onchain Cloud, Shelby, local disk) are hidden behind one content-addressed blob interface. Users never pick or see them.
- **Gateways are stateless.** Anyone can run one and register it onchain, like a public RPC.
- **Interfaces**: a native HTTP API with Rust/TS/Python SDKs, and an S3-compatible API so existing `boto3`/`aws-sdk` code works unchanged. deltaleague's `league/storage.py` and holonear's `--durable-store-s3-endpoint` are both already S3 clients.

## 2. Use cases → requirements

| Use case | Requirements |
|---|---|
| Private user data (messages, assistant memory) | E2E encryption; key recoverable from any device that controls the account; many small writes; low latency; LIST by prefix |
| Apps storing data for users | App pays, user owns or reads; per-user path patterns (`users/{account}/**`); app may write without being able to read |
| Model weights and diffs (deltaleague, holonear) | Multi-GB objects; multipart; range reads; dedup between checkpoints; parallel fetch close to the reader; optional group encryption or public objects |

## 3. Architecture

```
  SDK (rs/ts/py)  ── native API ──┐
  boto3 / aws-cli ── S3 API ──────┤
        │                         ▼
        │                 ┌────────────────┐   view_access_key / grants / gateway registry
        │                 │ Gateway (N×,   │◄──────────────── NEAR: drive.near contract
        │                 │  stateless)    │
        │                 └──┬──────────┬──┘
        │       pointer recs │          │ chunks (content-addressed)
        │                    ▼          ▼
        │            ┌───────────┐  ┌───────────────────────────────┐
        │            │ Index     │  │ Blob backends (placement pol.)│
        │            │ store     │  │ R2/S3 · FOC(PDP) · Shelby · fs│
        │            └───────────┘  └───────────────────────────────┘
        └── direct ranged chunk fetch (presigned / public CDN URLs) ──┘
```

### 3.1 Data model (three layers)

**L0 — Chunks.** Immutable, content-addressed (`blake3` of the ciphertext), up to 4 MiB by default (configurable up to 64 MiB for weights). A chunk is identical across backends, so placement, replication and migration are invisible above this layer. The interface is `put(cid, bytes, class)`, `get(cid, range)`, `has(cid)`, and `delete(cid)`.

**L1 — Object manifest.** Immutable and content-addressed, stored as a chunk. It holds:
`{version, size, chunk_size, chunks:[cid], enc:{alg, wrapped_deks:[{recipient, wrapped}], nonce_prefix}, content_type, user_meta(enc), plaintext_hash(enc)}`.
Dedup comes for free: two checkpoints that share a base layer share chunks. This works when the content is public or group-encrypted with convergent per-chunk keys (§5.3).

**L2 — Pointer records** are the only mutable state:
```
key:   (namespace, path)
value: {manifest_cid, size, seq, writer, writer_pk, ts, sig}
```
`writer_pk` is the writer's **record-signing key**, an ed25519 key derived from its root key (§5.1) and published in `drive.near` with `set_sign_key`. It is not the NEAR access key that signs requests (§4.1). `sig` is the signature with that key over
`"near-drive-record-v1\n{namespace}\n{path}\n{manifest_cid}\n{size}\n{stored_size}\n{seq}\n{writer}\n{writer_pk}\n{ts_ms}"`.
Gateways return the manifest's exact stored bytes as `manifest_raw` (base64), and clients hash those bytes rather than a re-serialization, so adding manifest fields later does not break older clients.

Readers accept a record only if (§4.3):
1. the signature verifies with `writer_pk`, and the manifest matches `manifest_cid`;
2. `writer_pk` is in `get_sign_keys(writer)` and was the key in force at `ts_ms`;
3. the namespace policy lets `writer` write `path`.

A gateway can sign records with a key of its own, but it cannot publish keys for other accounts, so it cannot pass check 2. A malicious gateway or index store can therefore *withhold* data or serve *stale* data, but it cannot forge it. Rollback protection comes from periodic onchain anchoring (phase 3).

Why per-path records and not a Merkle tree per account: S3 semantics are per-object last-writer-wins. Per-path records map 1:1 onto that, avoid a write hot-spot on a single root (bad for chat and memory workloads), and keep LIST a plain prefix scan.

### 3.2 Index store

A strongly consistent KV with compare-and-swap and prefix listing. v0 runs it on S3/R2 with conditional writes (`If-Match`/`If-None-Match`), or on the local filesystem in dev. It is replicated across ≥2 providers once there is more than one operator. It is the one piece that is not yet decentralized. The interface stays narrow (`get`, `cas_put`, `delete`, and a paginated `list_page(prefix, delimiter, start_after, limit)` with S3 ListObjects semantics; on S3 one page is one native LIST request plus GETs of the page's uncached records) so it can later move to a gateway-operator quorum or a DA layer without touching clients.

### 3.3 Gateway

A stateless HTTP service. Per request it:
1. authenticates the signer (§4.1), with access keys cached by account for ~30 s;
2. authorizes against the namespace policy (§4.2);
3. streams chunks to and from backends (on writes it checks that the cid matches the bytes);
4. CAS-updates the pointer record;
5. emits a usage event to the billing sink (§6).

Large reads can skip the gateway: `GET ...?mode=locate` returns the manifest plus per-chunk URLs (presigned R2, FilBeam, Shelby), and the SDK fetches them in parallel with ranges. This matters for weights. Gateways in different regions also act as read-through chunk caches. Chunks are immutable, so caching them is trivially safe.

Gateways register in `drive.near` with `{url, operator, regions, backends, price_hint, attestation?}`. SDKs read the registry, probe latency, and pick a gateway, the same way wallets pick an RPC.

### 3.4 Backends and placement

A placement policy per storage class decides where chunks go:

| class | default placement | notes |
|---|---|---|
| `hot` (default) | R2/S3 ×1 + FOC warm ×1 | read from R2, durability from FOC (PDP proofs, 2 copies) |
| `bulk` (weights) | FOC warm + FilBeam CDN | ~$2.5/TiB/mo published early pricing; per-GiB egress |
| `shelby` | Shelby hot storage | public testnet ended 2026-10-01; now an invite-only private beta with an S3-compatible API, which the bridge uses. No mainnet yet |
| `local` | gateway filesystem | dev / tests |

Users never choose a backend directly. At most they choose a class. Locations are not stored per chunk, so gateways stay stateless:

- The manifest (signed by the writer) records no locations.
- The index entry records the object's **class**. The gateway writes it next to the signed record (it is not covered by the signature); clients send it as `x-near-drive-class` on the chunk PUTs and on the record PUT.
- A read works out the backends from the class and the shared config: the class's `backends`, then its `previous` backends, then every other backend as a fallback. Entries without a class (written before this existed) read the default class first.
- **Migration is a config change plus a copy:** move the old backends to `previous`, put the new ones in `backends`, and new writes go to the new backends while reads still find old chunks. A copier (not built) moves old chunks; `previous` is then removed. Chunks found outside their class are logged.

## 4. Identity, auth, access control

### 4.1 Request auth

**Native API.** Each request carries
`X-Near-Account`, `X-Near-PublicKey`, `X-Near-Timestamp`, `X-Near-Signature`.
The signature is ed25519 (base58) over
`"near-drive-req-v1\n{METHOD}\n{url path as sent, percent-encoded}\n{raw query}\n{account}\n{public_key}\n{ts_ms}\n{hex blake3(body)}"`.
Clients keep timestamps strictly increasing so two identical requests never share a signature (the gateway keeps a replay cache keyed by signature).
The gateway accepts the key if it is one of:
- a **full-access key** of the account (`view_access_key`); or
- a **function-call key scoped to `drive.near`**. This is the recommended "storage session key". Wallets can add it without touching funds, and revoking it is a normal NEAR key deletion (`near drive login` / `logout` do both through near-cli, which also stores the key); or
- (dev mode) a key listed in the gateway config.

A timestamp window of ±5 min plus a short replay cache per gateway is enough. Requests are idempotent PUT/GET/DELETE, and content-addressed chunk uploads are harmless to replay.

**S3 API (SigV4)** needs a shared secret, so it runs in two modes:
- **Local sidecar (recommended, E2E).** `near drive up` (background; `s3-proxy` in the foreground) listens on `127.0.0.1:9000`. Credentials are local config. It encrypts client-side and speaks the native API upstream with the user's NEAR key. boto3 code changes only `endpoint_url`. This is how deltaleague and holonear workers would use it.
- **Hosted S3 endpoint (convenience, not E2E).** The user signs a NEP-413 "issue S3 credential" message, and the gateway returns `AKID = base32(account|scope|expiry|gw_id|nonce)`, `secret = HMAC(gateway_secret, AKID)`. This is stateless (any replica of that operator can re-derive the secret) and scoped to a path prefix. Revocation bumps a per-account `cred_epoch` in `drive.near`. Data uses gateway-side encryption, so this should only be offered by TEE-attested gateways (NEAR AI Cloud already runs CVMs). The attestation is published in the registry.

### 4.2 Namespace policy (onchain in `drive.near`)

Each namespace (account) has an ordered rule list:

```jsonc
// set by app.near for its own namespace
{ "prefix": "users/{account}/", "read": ["{account}"], "write": ["{account}", "app.near"], "payer": "app.near" }
// set by alice.near: let an app write into her space, alice pays
{ "prefix": "apps/chat.app.near/", "read": ["alice.near","chat.app.near"], "write": ["chat.app.near"], "payer": "alice.near" }
// public weights
{ "prefix": "weights/", "read": ["*"], "write": ["holonear.near"], "payer": "holonear.near" }
```

- The namespace owner always has full access.
- `{account}` in a prefix captures one path segment, which must be a valid account id. In `read`/`write`/`payer` it refers to that captured account. For example, only bob can read `users/bob.near/...`, while app.near can write there and pays.
- The first matching rule wins.
- `payer` decides who is billed for bytes stored under the prefix and for egress.
- Gateways cache policy per namespace for 30 s. Changes are ordinary transactions.

Gateway-side read ACLs only stop ciphertext from being *served*. Confidentiality comes from encryption (§5). Integrity comes from the pointer signatures (§3.1), checked against the writer's published signing key (§4.3).

### 4.3 Record writers (reader-side checks)

Gateways are not trusted to say who wrote a record, so every client checks it on each read that serves content (head, get, ranged and `?mode=locate` reads, streamed downloads):
- `writer_pk` must be in the writer's signing-key history from `get_sign_keys(writer)` (`[{key, since_ms}]`, oldest first, at most 16 entries). Entry *i* is in force for `ts_ms` in `[since_i − 5 min, since_{i+1} + 5 min)`; the latest entry has no end. Records written before a key rotation therefore stay readable, and a key that was replaced cannot sign new records.
- `policy::resolve(namespace, get_rules(namespace), path, writer).write` must hold. The namespace owner always may write. Rules are read at read time, so revoking someone's write access also hides what they wrote earlier.
- Sign keys and rules are cached per account / namespace for 60 s (bounded size). A rejection based on a cache entry older than a couple of seconds re-reads the chain once, so a just-published key works.

The SDK takes the check as an explicit setting (`WriterCheck` in Rust): `Chain` (the default once an RPC is configured), `Trusted` (fixed keys and rules, for tests and dev setups without a chain), or an explicitly named insecure skip for tests (`--insecure-skip-writer-check` in the CLI). A client with none fails reads instead of silently trusting the gateway.

Gateways check writes the same way: the record's `writer` must be the request signer, and `writer_pk` must be the writer's latest published signing key (or a `dev_sign_keys` entry in dev). This only keeps bad records out of the index; readers do not rely on it.

Writing therefore needs the root key (also for public objects), and an account must run `near drive publish-key` (which publishes both the X25519 and the signing key) before others accept what it writes. An app writing data only a user can read uses its own root key to sign and leaves itself out of the recipients (`skip_owner_key`).

Listings (`/v1/list`) are not signed as a whole, so a gateway can hide entries or report stale ones there. Mount and sync use listings only to decide what to fetch; content is always served from a verified head (the mount reuses its local cache only for a version it verified for that path).

## 5. Encryption

### 5.1 Root key from the NEAR account

`root_key(account)` is derived with **NEAR MPC Confidential Key Derivation (CKD)**: `request_app_private_key` on the MPC contract. The key is deterministic per predecessor account and comes back encrypted to an ephemeral key the client controls. Properties:
- any device that can sign for the account recovers the same root key;
- it survives access-key rotation (unlike "derive from the signature of a fixed message", which breaks when keys change and does not work for multisig or MPC-controlled accounts);
- it is never seen by gateways.

The CLI caches the root key in `~/.near-drive/keys/<account>.root` (hex, mode 0600; services pass `NEAR_DRIVE_ROOT_KEY`). Wrapping the cache with an OS keychain or a passphrase is not built yet. **Fallback:** a random root key (`keygen --random`), moved between devices with `near drive key export` / `key import`. CKD replaces only the key-acquisition step; nothing downstream changes. The CKD target is pinned (`v1.signer` / `v1.signer-prod.testnet`, domain 2), since another contract or domain derives a different key.

Because the record-signing key is derived from the root key, a lost or mismatched root key means both unreadable data and records readers reject. So the CLI compares a root key with the published keys (`get_enc_key` and the latest `get_sign_keys` entry): `keygen` and `key import` refuse a key from a different root key unless forced (then `publish-key` rotates), and writing commands stop on a mismatch and warn when nothing is published yet.

Derived keys:
- `kek = HKDF(root, "kek")` wraps per-object DEKs.
- `enc_sk = X25519(HKDF(root, "x25519"))`. Its public key is published in `drive.near` so others can share to the account.
- `sign_sk = Ed25519(HKDF(root, "near-drive/v1/sign"))` signs pointer records. Its public key (`ed25519:<base58>`) is published in `drive.near` (`set_sign_key`) so readers can check who wrote a record (§4.3). All derivations use HKDF-SHA256 with salt `"near-drive"` and info `"near-drive/v1/<name>"`.
- `path_key = HKDF(root, "paths")` is for optional hidden-path mode.

### 5.2 Objects

- Each object gets a random 256-bit DEK.
- Chunks are encrypted with XChaCha20-Poly1305. The nonce is `nonce_prefix‖chunk_index`, and AAD = `(namespace, path-independent object id, chunk_index, is_last)`. That blocks chunk reordering and truncation.
- The DEK is wrapped once per recipient:
  - for the owner, with `kek`;
  - for a grantee (app, friend, group), with that account's published X25519 key (HPKE).
- Sharing an existing object means appending a wrapped DEK and rewriting the manifest. The chunks are untouched.

### 5.3 Weights and dedup

- `enc: none` for public weights.
- For private weights shared across a team or cluster, use a group key: a DEK wrapped to each member. Optional convergent mode (`chunk_key = HKDF(group_key, plaintext_hash)`) keeps cross-checkpoint dedup inside the group, at the known cost of revealing equality of chunks to anyone who has the group key.

### 5.4 Path privacy

v0 stores paths in plaintext, because LIST and the S3 API need them. An opt-in `hidden` mode HMACs each segment with `path_key`. That keeps delimiter listing but drops arbitrary-prefix listing.

## 6. Billing

Metered units:
- `storage_gib_hour`: integrated over pointer-record lifetime, attributed to `payer`;
- `egress_gib`: bytes served, attributed to the `payer` of the prefix;
- `requests`: per 1k.

**Phase 1 — NEAR AI Cloud credits.**
- The gateway emits usage events. A metering job aggregates them and posts them to cloud-api.
- cloud-api already has the pieces: a service catalog (`GET /v1/services`, priced per unit), a service-usage ledger (`service_usage`, nano-USD, credit allocations), NEAR (NEP-413) login that maps an account to a user and org, and the `POST /v1/internal/usage` service-token pattern.
- **Needed in cloud-api:**
  - new `ServiceUnit` variants (`GibHour`, `Gib`);
  - a `POST /v1/internal/service-usage` endpoint keyed by NEAR account (or `organization_id`);
  - `GET /v1/internal/billing-status?near_account=` so gateways can reject writes when credit is exhausted (cached for ~60 s).
- Because the usage token is a trusted secret, **phase-1 gateways are NEAR AI-operated** (the registry can still list them).

**Phase 2 — NEAR Intents.**
- A payer deposits any intents-supported asset. It settles to USDC in an `intents.near` balance, which is then transferred into `drive.near` escrow.
- Storage is prepaid as reservations (`bytes × duration`).
- Egress is paid by usage receipts that a gateway submits and the contract verifies against per-payer caps. Disputes go through signed request logs.
- Third-party gateway operators get paid from escrow, so permissionless gateways become viable. Cloud credits remain as one funding source: the cloud-api balance can be bridged to escrow.

## 7. `drive.near` contract (phase 2)

Implemented in `contracts/drive` (method list in docs/contract.md; payments in docs/payments.md):

- `register_gateway(info)` / `update_gateway` / `deregister_gateway` / `force_deregister_gateway` / `withdraw_gateway_stake` (NEAR stake, snapshotted unstake delay), `list_gateways`
- `set_rules(rules)`, `get_rules(namespace)`
- `set_enc_key(x25519_pk)`, `get_enc_key(account)`
- `set_sign_key(ed25519_pk)`, `get_sign_keys(account)`: record-signing key history, `[{key, since_ms}]` oldest first, at most 16 (§4.3)
- `bump_cred_epoch()`, `get_cred_epoch(account)`
- `anchor(namespace, root, seq)` / `clear_anchor` / `set_anchor_authority`: periodic Merkle root of pointer records for rollback detection (phase 3); the owner or an owner-authorized active gateway may anchor
- escrow: deposits via `ft_on_transfer` / `mt_on_transfer` (after `register_payer`), `set_spend_cap`, `settle`, notice-period `withdraw_balance`, `withdraw_earnings`, `close_payer`. Lowering a spend cap and revoking a self-settler wait out the same notice period as withdrawals. Settlement idempotency is a bounded sliding window per (payer, gateway) over numeric periods. Prepaid reservations (`reserve`) are not implemented yet.
- payer opt-in: `set_sponsorship(namespace, allowed)` / `is_sponsor(payer, namespace)`; a rule's payer other than the namespace owner only counts if it sponsors that namespace (enforced where gateways resolve the payer; `settle` cannot see namespaces)
- versioned state (`STATE_VERSION`) and a private `migrate()` run in the same transaction as each code upgrade (docs/contract.md)

## 8. APIs

**Native HTTP**

| Request | Meaning |
|---|---|
| `PUT /v1/o/{namespace}/{path}` | body = encrypted object stream; headers carry manifest fields. Large objects: `POST ...?uploads` → `PUT ...?part=n` → `POST ...?complete` |
| `GET /v1/o/{namespace}/{path}` | ciphertext stream; supports `Range` |
| `GET /v1/o/{namespace}/{path}?mode=locate` | manifest plus chunk URLs |
| `HEAD`, `DELETE` | as usual |
| `GET /v1/list/{namespace}?prefix=&delimiter=&cursor=&limit=` | one page of a prefix listing: `{"entries", "common_prefixes", "next_cursor"}`; raw string prefix, ≤ 1000 per page, repeat with `cursor` until `next_cursor` is null (docs/gateway.md) |

**SDK surface** (same shape in Rust, TS and Python):
```
client = Storage(account="alice.near", signer=..., gateway=auto)
client.put("near://alice.near/memory/2026-11-18.json", bytes, share_with=[...], cls="hot")
client.get(uri) -> bytes / stream ; client.list(prefix) ; client.list_page(prefix, delimiter, cursor, limit) ; client.delete(uri)
client.share(uri, account) ; client.grant(prefix, rule)   # onchain policy tx
```

**S3 mapping:** bucket = namespace (path-style: `http://gw/alice.near/key`), key = path. v0 supports Put/Get/Head/Delete/ListObjectsV2 and multipart.

## 9. Phases and status

| Phase | Scope | Status |
|---|---|---|
| **0** | Core (paths, chunking, encryption, manifests, signed records, policy), gateway native API, NEAR-key auth, fs stores, usage log, `near-drive` CLI | Done |
| **1** | S3/R2 stores with conditional writes; storage classes and replication; blob-bridge protocol (`docs/blob-bridge.md`); streaming large objects + `?mode=locate` + chunk cache; `near drive s3-proxy`; cloud-credits billing (metering, reporting, 402 gate) + cloud-api endpoints; TS and Python SDKs; sharing (X25519 recipients); CORS | Done. Verified against MinIO, boto3 1.34 and 1.44, aws-cli, and a local cloud-api build. Not verified against real AWS S3/R2 or a deployed cloud-api. The cloud-api change needs a schema change in `nearai/cloud-platform` first (see its `docs/storage-billing.md`) |
| **2** | `drive.near` contract (rules, enc keys, gateway registry, cred epochs, anchors); gateway reads rules from chain; `near drive grant/rules/publish-key/gateways`, gateway discovery; CKD root keys (`near drive keygen --ckd`); FOC bridge (Synapse) | Done in code. Contract verified in a local sandbox only. CKD verified against the official vectors and with real testnet requests (deterministic per account, different per account; docs/ckd.md). FOC bridge type-checked and mock-tested; no funded upload completed |
| **3** | NEAR Intents / stablecoin escrow (`ft_on_transfer`, `mt_on_transfer`, capped `settle`, delayed withdrawals; `docs/payments.md`); Shelby bridge (S3 mode + experimental SDK mode) | Done in code; sandbox and mock tests only |
| **CLI** | One `near-drive` binary, also `near drive` as a near-cli-rs extension; NEAR keys and transactions delegated to near-cli (`login` adds a function-call session key via `near account add-key`; `grant`/`publish-key`/`keygen --ckd`/`logout` are near-cli transactions); interactive prompts in a terminal; root-key backup (`key export` / `key import`) and a check of the root key against the published keys before saving or writing | Done. Verified on a local sandbox with near-cli-rs 0.29 (`tests/near_cli_e2e.sh`, including near-cli's interactive signer menu) and in a pty (`tests/interactive_smoke.py`). OS-keychain lookup is the same entry format near-cli writes but was only exercised through the legacy-file fallback (headless Linux) |
| **Sync** | `near-drive-sync`: Dropbox-style two-way folder sync (three-way reconcile, conditional writes, conflicted copies, local trash, NFC / Windows-name handling, FS events + polling); `near drive sync add/remove/status/run`, run by `near drive up`; resumable transfers and retries in the client; small-object cache + one-request small reads in the gateway | Done. Tested on Linux (two devices through a real gateway, CLI background service); builds for Windows (cross-checked); CI matrix covers Linux, macOS and Windows |
| **On demand** | `near drive mount`: FUSE (Linux; macOS via macFUSE / FUSE-T) and Windows Cloud Files placeholders; gateway change push (`/v1/watch` long-poll, in-memory per process); selective sync; `near-drive-tray`; TS / Python SDK retries and resumable transfers | Linux mount tested end to end; Windows provider tested in CI only; macOS: File Provider extension (`macos/`, over the tested provider API) builds in CI, not run (needs signing), FUSE path needs macFUSE and is untested; tray logic unit-tested, not run on a desktop |
| **Release** | Prebuilt binaries for Linux / macOS / Windows with installers, Homebrew formula, winget manifests; reproducible `drive.near` wasm (pinned cargo-near image, NEP-330 build info) attached to releases, `contracts/verify.sh` to check a deployment | v0.1.0 released; reproducible contract build verified locally (identical hashes across builds, verify.sh on a sandbox chain) |
| **Service deployment** | Container image (gateway + S3 endpoint, env-only config, GHCR on release); S3 endpoint for remote clients (`--public-listen`, bucket aliases, CORS, virtual-host domains); streaming multipart; chunk garbage collection (mark and sweep, grace period, dry run, periodic) | deltaleague's patterns tested against the endpoint locally and in containers; not yet against real R2 or behind TLS |
| Not built | hosted TEE S3 endpoint; storage reservations, disputes, stake slashing; migration copier and repair for under-replicated chunks; hidden-path mode; keychain-wrapped root key cache; NEAR-escrow settler wired into billing (interface exists); prepaid storage so session keys can set rules; cross-gateway change feed | |

## 10. Open questions

1. **Index store decentralization.** Is an operator quorum enough, or do we want the pointer records on a DA layer? This determines how "trustless" the claim can be.
2. **CKD.** Resolved (docs/ckd.md): `v1.signer` / `v1.signer-prod.testnet`, domain 2, 1 yoctoNEAR deposit and ≥15 TGas attached; a request burns ~16.6 TGas (≈0.0017 NEAR) and answers ~6 blocks (~3 s) after inclusion, 5–8 s end to end. Plain accounts can call it; function-call (session) keys cannot, because they can't attach the deposit. Verified with real testnet transactions (signer contract 3.19.0).
3. **Retention for unpaid data.** Grace period, then delete? Applies when credits run out.
4. **Dedup vs privacy for weights.** Is convergent encryption acceptable inside a group?
5. **Hosted S3 endpoint.** Is the TEE requirement acceptable, or do we offer only the sidecar?
