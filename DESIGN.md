# nstorage — NEAR storage layer

Status: draft v0.1 (2026-11-18)

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
        │                 │ Gateway (N×,   │◄──────────────── NEAR: storage.near contract
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
`sig` is the writer's ed25519 signature over `(namespace, path, manifest_cid, size, seq, ts)`. Readers check it and reject a record whose writer was not authorized for that path (§4). A malicious gateway or index store can therefore *withhold* data or serve *stale* data, but it cannot forge it. Rollback protection comes from periodic onchain anchoring (phase 3).

Why per-path records and not a Merkle tree per account: S3 semantics are per-object last-writer-wins. Per-path records map 1:1 onto that, avoid a write hot-spot on a single root (bad for chat and memory workloads), and keep LIST a plain prefix scan.

### 3.2 Index store

A strongly consistent KV with compare-and-swap and prefix listing. v0 runs it on S3/R2 with conditional writes (`If-Match`/`If-None-Match`), or on the local filesystem in dev. It is replicated across ≥2 providers once there is more than one operator. It is the one piece that is not yet decentralized. The interface stays narrow (`get`, `cas_put`, `list(prefix)`) so it can later move to a gateway-operator quorum or a DA layer without touching clients.

### 3.3 Gateway

A stateless HTTP service. Per request it:
1. authenticates the signer (§4.1), with access keys cached by account for ~30 s;
2. authorizes against the namespace policy (§4.2);
3. streams chunks to and from backends (on writes it checks that the cid matches the bytes);
4. CAS-updates the pointer record;
5. emits a usage event to the billing sink (§6).

Large reads can skip the gateway: `GET ...?mode=locate` returns the manifest plus per-chunk URLs (presigned R2, FilBeam, Shelby), and the SDK fetches them in parallel with ranges. This matters for weights. Gateways in different regions also act as read-through chunk caches. Chunks are immutable, so caching them is trivially safe.

Gateways register in `storage.near` with `{url, operator, regions, backends, price_hint, attestation?}`. SDKs read the registry, probe latency, and pick a gateway, the same way wallets pick an RPC.

### 3.4 Backends and placement

A placement policy per storage class decides where chunks go:

| class | default placement | notes |
|---|---|---|
| `hot` (default) | R2/S3 ×1 + FOC warm ×1 | read from R2, durability from FOC (PDP proofs, 2 copies) |
| `bulk` (weights) | FOC warm + FilBeam CDN | ~$2.5/TiB/mo published early pricing; per-GiB egress |
| `shelby` | Shelby hot storage | once mainnet is live (testnet as of 2026); NEAR Intents already partners with Shelby |
| `local` | gateway filesystem | dev / tests |

Users never choose a backend directly. At most they choose a class. The manifest does not record locations; locations are resolved by cid through a placement log the gateways write. Migration is therefore copy-then-update-log.

## 4. Identity, auth, access control

### 4.1 Request auth

**Native API.** Each request carries
`X-Near-Account`, `X-Near-PublicKey`, `X-Near-Timestamp`, `X-Near-Signature`.
The signature is ed25519 over
`"nstorage-v1\n{method}\n{namespace}\n{path}\n{query}\n{ts}\n{blake3(body) or UNSIGNED}"`.
The gateway accepts the key if it is one of:
- a **full-access key** of the account (`view_access_key`); or
- a **function-call key scoped to `storage.near`**. This is the recommended "storage session key". Wallets can add it without touching funds, and revoking it is a normal NEAR key deletion; or
- (dev mode) a key listed in the gateway config.

A timestamp window of ±5 min plus a short replay cache per gateway is enough. Requests are idempotent PUT/GET/DELETE, and content-addressed chunk uploads are harmless to replay.

**S3 API (SigV4)** needs a shared secret, so it runs in two modes:
- **Local sidecar (recommended, E2E).** `nst s3-proxy` listens on `127.0.0.1:9000`. Credentials are local config. It encrypts client-side and speaks the native API upstream with the user's NEAR key. boto3 code changes only `endpoint_url`. This is how deltaleague and holonear workers would use it.
- **Hosted S3 endpoint (convenience, not E2E).** The user signs a NEP-413 "issue S3 credential" message, and the gateway returns `AKID = base32(account|scope|expiry|gw_id|nonce)`, `secret = HMAC(gateway_secret, AKID)`. This is stateless (any replica of that operator can re-derive the secret) and scoped to a path prefix. Revocation bumps a per-account `cred_epoch` in `storage.near`. Data uses gateway-side encryption, so this should only be offered by TEE-attested gateways (NEAR AI Cloud already runs CVMs). The attestation is published in the registry.

### 4.2 Namespace policy (onchain in `storage.near`)

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

Gateway-side read ACLs only stop ciphertext from being *served*. Confidentiality comes from encryption (§5). Integrity comes from the pointer signatures (§3.1).

## 5. Encryption

### 5.1 Root key from the NEAR account

`root_key(account)` is derived with **NEAR MPC Confidential Key Derivation (CKD)**: `request_app_private_key` on the MPC contract. The key is deterministic per predecessor account and comes back encrypted to an ephemeral key the client controls. Properties:
- any device that can sign for the account recovers the same root key;
- it survives access-key rotation (unlike "derive from the signature of a fixed message", which breaks when keys change and does not work for multisig or MPC-controlled accounts);
- it is never seen by gateways.

The SDK caches the root key locally, encrypted with an OS keychain or a passphrase. **v0 fallback:** a locally generated root key file (`~/.nstorage/<account>.key`) with export/import. CKD replaces only the key-acquisition step; nothing downstream changes.

Derived keys:
- `kek = HKDF(root, "kek")` wraps per-object DEKs.
- `enc_sk = X25519(HKDF(root, "x25519"))`. Its public key is published in `storage.near` so others can share to the account.
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
- A payer deposits any intents-supported asset. It settles to USDC in an `intents.near` balance, which is then transferred into `storage.near` escrow.
- Storage is prepaid as reservations (`bytes × duration`).
- Egress is paid by usage receipts that a gateway submits and the contract verifies against per-payer caps. Disputes go through signed request logs.
- Third-party gateway operators get paid from escrow, so permissionless gateways become viable. Cloud credits remain as one funding source: the cloud-api balance can be bridged to escrow.

## 7. `storage.near` contract (phase 2)

Implemented in `contracts/storage` (method list in README.md; payments in docs/payments.md):

- `register_gateway(info)` / `update_gateway` / `deregister_gateway` / `withdraw_gateway_stake` (NEAR stake, unstake delay), `list_gateways`
- `set_rules(rules)`, `get_rules(namespace)`
- `set_enc_key(x25519_pk)`, `get_enc_key(account)`
- `bump_cred_epoch()`, `get_cred_epoch(account)`
- `anchor(namespace, root, seq)`: periodic Merkle root of pointer records for rollback detection (phase 3)
- escrow: deposits via `ft_on_transfer` / `mt_on_transfer` (NEAR Intents), `set_spend_cap`, `settle`, notice-period `withdraw_balance`, `withdraw_earnings`. Prepaid reservations (`reserve`) are not implemented yet.

## 8. APIs

**Native HTTP**

| Request | Meaning |
|---|---|
| `PUT /v1/o/{namespace}/{path}` | body = encrypted object stream; headers carry manifest fields. Large objects: `POST ...?uploads` → `PUT ...?part=n` → `POST ...?complete` |
| `GET /v1/o/{namespace}/{path}` | ciphertext stream; supports `Range` |
| `GET /v1/o/{namespace}/{path}?mode=locate` | manifest plus chunk URLs |
| `HEAD`, `DELETE` | as usual |
| `GET /v1/list/{namespace}?prefix=&delimiter=&cursor=` | prefix listing |

**SDK surface** (same shape in Rust, TS and Python):
```
client = Storage(account="alice.near", signer=..., gateway=auto)
client.put("near://alice.near/memory/2026-11-18.json", bytes, share_with=[...], cls="hot")
client.get(uri) -> bytes / stream ; client.list(prefix) ; client.delete(uri)
client.share(uri, account) ; client.grant(prefix, rule)   # onchain policy tx
```

**S3 mapping:** bucket = namespace (path-style: `http://gw/alice.near/key`), key = path. v0 supports Put/Get/Head/Delete/ListObjectsV2 and multipart.

## 9. Phases

| Phase | Scope |
|---|---|
| **0 — this repo now** | Rust core (paths, chunking, encryption, manifests, signed records); gateway with native API; NEAR-key auth (RPC + dev keys); fs backend + fs index store; usage log; `nst` CLI (put/get/ls/rm) with local root key |
| **1** | S3/R2 backend and index store (conditional writes); `nst s3-proxy` sidecar; cloud-credits billing (plus the cloud-api endpoints above); TS and Python SDKs (thin: auth, crypto, chunking); multipart + locate for weights; pilot holonear/deltaleague checkpoints through the sidecar |
| **2** | `storage.near` contract (policy, enc pubkeys, gateway registry); FOC backend through Synapse; CKD root keys; sharing; app-pays flows |
| **3** | NEAR Intents escrow; third-party gateways; Shelby backend; onchain anchoring; hosted TEE S3 endpoint |

## 10. Open questions

1. **Index store decentralization.** Is an operator quorum enough, or do we want the pointer records on a DA layer? This determines how "trustless" the claim can be.
2. **CKD availability and cost.** `request_app_private_key` costs ~300 TGas per call (unverified third-party figure). That is fine once per device, but check mainnet availability and the exact interface.
3. **Retention for unpaid data.** Grace period, then delete? Applies when credits run out.
4. **Dedup vs privacy for weights.** Is convergent encryption acceptable inside a group?
5. **Hosted S3 endpoint.** Is the TEE requirement acceptable, or do we offer only the sidecar?
