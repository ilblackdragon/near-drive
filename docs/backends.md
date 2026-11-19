# Blob backends: guarantees, cost, placement

Research snapshot: 2026-11-19. All prices are **early-pricing snapshots** and will change; re-check them before relying on them. Sources are listed per section.

The gateway sees every backend through the same content-addressed chunk interface (DESIGN §3.1 L0). R2/S3 and the local fs are native gateway backends. FOC and Shelby run as **blob bridges**: small Node services in `bridges/` that implement the HTTP spec below and keep their own `cid → backend id` index.

## Summary

| | R2 (Standard) | FOC warm (PDP) + FilBeam | Shelby | local fs |
|---|---|---|---|---|
| Durability model | Cloudflare-managed; "designed for 99.999999999% annual durability" | 2 copies by default, each with a different curated storage provider. PDP proofs every proving period (mainnet 24 h, Calibration 2 h); faults cut payment and end the deal | Clay erasure code 16 = 10 data + 6 parity (1.6× overhead), tolerates losing 6 nodes; Aptos for coordination | one disk |
| Write acknowledged when | persisted to disk | ≥1 copy committed on-chain (`complete` = all copies) | all storage nodes acked the commit | fsync |
| Retrieval latency | ms (no published SLO, 99.9 % availability SLA) | FilBeam cache hit "milliseconds"; direct from provider "seconds" | not published ("writes take longer than on Amazon S3") | local |
| Storage $/TiB-month | $15.36 ($0.015/GB) | **$2.50 per copy** (so $5.00 at the default 2 copies) | $20 (paid plan) | — |
| Egress | free | CDN ≤ $14/TiB (7 CDN + 7 cache-miss, ≈ half on hits); direct provider retrieval: no egress charge | free up to 3× average stored, then $10/TiB | — |
| Per-object / per-op | Class A $4.50/M, Class B $0.36/M | **$0.008 per add-pieces tx + $0.003 per piece, per copy**; $0.025 per data set created; $0.12/month per non-empty data set | free plan: each object counts as ≥ 10 MiB against the 10 GiB cap; paid plan bills actual bytes | — |
| Min / max object | — / 5 TiB | 127 B / ≈ 63.5 GiB per piece (SDK 3.0) | — / 5 GiB single PUT (S3 API); names ≤ 190 chars (SDK) | — |
| Range reads | yes | SDK: whole piece only (CommP-verified). FilBeam/provider HTTP Range is likely but **unverified** | yes (S3 `Range`; SDK `range` with inclusive end) | yes |
| Direct URLs | presigned | FilBeam `https://{payer}.calibration.filbeam.io/{pieceCid}` (mainnet `{payer}.filbeam.io`), public, no expiry | S3 presigned GET (1 s – 7 d). No anonymous reads | — |
| Status (Nov 2026) | GA | mainnet live; same price list on Calibration | **Private Beta** (managed, invite-only, S3 API). Public testnet ended Oct 2026; no mainnet | dev |

## Recommended placement per storage class

DESIGN §3.4 gives the default placements. This refines them with the numbers above.

| class | placement | why |
|---|---|---|
| `hot` (default) | **R2 ×1 (serve) + FOC ×2 via packing bridge (durability)** | R2 gives low-latency reads and free egress. FOC adds independent, provable durability for ~1/3 of R2's per-TiB storage price. FOC's per-piece fees make one piece per 4 MiB chunk uneconomic ($0.0065–0.022 per chunk across 2 copies depending on add-pieces batching, which equals 8–30 years of R2 storage for a 4 MiB chunk), so the FOC bridge **packs** chunks. Reads normally come from R2, so FOC's whole-piece reads rarely matter. |
| `bulk` (weights, multi-GB) | **FOC ×2 + FilBeam CDN, direct pieces** (chunks ≥ 16 MiB go unpacked; use 64 MiB weight chunks) | Cheapest storage. FilBeam gives public CDN URLs for `?mode=locate`, and the CDN fee is only on egress. Keep R2 as a read-through cache only for hot checkpoints. |
| `shelby` | **Shelby (S3 API) ×1**, plus FOC for durability until Shelby reaches GA | Hot reads, egress free up to 3× stored. It is an invite-only beta with no decentralised mainnet, so don't make it the only copy. Revisit when Shelby has a mainnet. |
| `local` | gateway fs | dev / tests |

Rules of thumb:
- **Never rely on a single bridge-staged copy.** A 201 from a packing bridge means the bytes are fsynced on the bridge host and will be on FOC within `PACK_MAX_DELAY_MS`. The gateway should write `hot` data to R2 too, which the `hot` placement already does.
- Placement-log entries for packed chunks should point at the bridge, not at a backend URL. `/url` returns 404 for packed chunks, because their only direct URL would be the whole pack.

## Bridge HTTP spec (implemented by `bridges/common`)

- `PUT /blobs/{cid}`, body = bytes:
  - returns **201** with `{"cid","size","created"}`;
  - idempotent: the index dedups, and concurrent identical PUTs upload once;
  - the server checks `cid == "b3:" + hex(blake3(body))` and returns **400** on mismatch;
  - **413** above `BRIDGE_MAX_BODY_BYTES` (64 MiB).
- `GET /blobs/{cid}`:
  - returns **200** bytes, or **206** for `Range: bytes=a-b | a- | -n` (single range);
  - **416** when the range is unsatisfiable; multi-range requests are served as a full 200;
  - **404** if absent;
  - full reads are blake3-verified before they are served, so a corrupt backend gives **502**.
- `HEAD /blobs/{cid}`: **200** with `content-length`, or **404**.
- `GET /blobs/{cid}/url`: **200** `{"url", "expires_ms"}` (unix ms or `null`), or **404** if the blob is absent or has no direct URL (packed or staged).
- `GET /healthz`: `{"ok":true,"backend",...stats}`. It needs no auth.
- `Authorization: Bearer <BRIDGE_TOKEN>`, if a token is configured. Without it, `/blobs/*` returns **401**.
- Bridges listen on `BRIDGE_HOST` (default `127.0.0.1`). They refuse to start on `0.0.0.0` or `::`.

**Index.** `$BRIDGE_DATA_DIR/index.jsonl` is append-only and fsynced before the 201. A torn final line left by a crash is dropped on restart.

**Packing.** This is common code, used by FOC and opt-in for Shelby. It works as follows:
1. Blobs below `PACK_THRESHOLD_BYTES` are fsynced to `staging/` and served from there.
2. The bridge flushes them into one backend object once `PACK_TARGET_BYTES` accumulate, or once the oldest blob is older than `PACK_MAX_DELAY_MS`. Failed flushes retry with exponential backoff, and staged blobs survive restarts.
3. Packs are self-describing (`blobs ‖ JSON trailer [[cid, offset, size]…] ‖ u32 len ‖ "NSPK"`), so the index can be rebuilt from the backend.

### Running

```sh
cd bridges && npm install && npm run build && npm test

# FOC (Calibration by default). One-time: get tFIL + tUSDFC from the faucets, then
FOC_PRIVATE_KEY=0x... node foc/dist/main.js setup          # quote deposit/approval
FOC_PRIVATE_KEY=0x... node foc/dist/main.js setup --yes    # execute (testnet funds)
FOC_PRIVATE_KEY=0x... node foc/dist/main.js selftest       # real upload+download
FOC_PRIVATE_KEY=0x... BRIDGE_TOKEN=... node foc/dist/main.js   # serve on 127.0.0.1:7701
#   FOC_NETWORK=mainnet additionally requires FOC_ALLOW_MAINNET=1.
#   Defaults: PACK_THRESHOLD_BYTES=16MiB, PACK_TARGET_BYTES=64MiB, PACK_MAX_DELAY_MS=600000,
#   FOC_WITH_CDN=1, FOC_CACHE_BYTES=256MiB.

# Shelby (S3 API, Private Beta)
SHELBY_S3_BUCKET=... SHELBY_ACCESS_KEY_ID=SHLB... SHELBY_SECRET_ACCESS_KEY=... node shelby/dist/main.js  # 127.0.0.1:7702
# Shelby native SDK on shelbynet (dev network): SHELBY_MODE=sdk SHELBY_PRIVATE_KEY=... SHELBY_API_KEY=AG-...
```

## Backend notes

### Filecoin Onchain Cloud (FOC) via Synapse SDK

- **SDK.** `@filoz/synapse-sdk` 3.0.1 (2026-11-18), with `@filoz/synapse-core` 0.11 and `viem` ^2.58.
  - Create the client with `Synapse.create({ account: privateKeyToAccount(pk), chain: calibration, transport?: http(url), withCDN, source })`.
  - `storage.upload(bytes)` returns `{ pieceCid, complete, copies[] }`. Batching of `addPieces` across concurrent uploads is on by default.
  - `storage.download({ pieceCid })` returns the whole piece, CommP-verified.
  - `storage.prepare({ pieceSizes })` quotes, and can execute, the USDFC deposit plus operator approval.
- **Bridge behaviour.**
  - Backend id is the PieceCID.
  - Payloads under 127 B are zero-padded, and the index keeps the true size.
  - Range reads try `Range:` on the FilBeam URL first, then fall back to a whole-piece download with a 256 MiB LRU cache.
- **Funding.** You prepay ~30 days. If the balance runs below that, providers may remove data, so the bridge operator must monitor the balance. Lockups are refundable: ~0.5 USDFC per data set, plus 0.7 + 0.3 USDFC for CDN.
- **Verification status.**
  - HTTP layer, packing and padding: tested with a mock Synapse client.
  - SDK integration: type-checked against 3.0.1.
  - Real network: a local smoke run by accident used a public dev key, which happens to hold Calibration USDFC. Synapse reached a Calibration provider (`calib.ezpdpz.net`) and the provider accepted the bytes. Data-set creation then failed with `InsufficientLockupFunds`, so no piece was committed and no funds were spent.
  - Not yet done: a full funded round-trip. It needs a dedicated `FOC_PRIVATE_KEY` with tFIL + tUSDFC, then `setup --yes` and `selftest`.
- **Open question.** The FilBeam docs (Apr 2026) still say the max piece size is 254 MiB, while SDK 3.0 says ~63.5 GiB. Our 64 MiB packs are below both limits.
- **Sources:**
  - `npm view @filoz/synapse-sdk` and the package `.d.ts`/CHANGELOG
  - https://github.com/FilOzone/synapse-sdk
  - https://docs.filecoin.cloud/developer-guides/storage/storage-costs/
  - https://docs.filecoin.cloud/core-concepts/retrieval/
  - https://docs.filecoin.cloud/core-concepts/pdp-overview/
  - https://docs.filecoin.cloud/core-concepts/fwss-overview/
  - https://docs.filbeam.com/
  - On-chain `getPriceList` / `getPDPConfig`, read 2026-11-19; the price list is identical on Calibration and mainnet.

### Shelby

- **Status.** On 2026-10-01 Shelby ended its public testnet and moved to a **Private Beta**: a managed service whose documented interface is an **S3-compatible API**.
  - Endpoint `https://s3.beta.shelby.xyz`, region `default`, path-style addressing.
  - Access keys start with `SHLB…` and come from console.shelby.xyz, scoped to one bucket.
  - `If-None-Match: *` is enforced and `If-Match` is not. There are no anonymous reads; use presigned GETs (1 s – 7 d).
- **Default bridge mode** (`SHELBY_MODE=s3`) uses `@aws-sdk/client-s3`:
  - create-only PUTs, where a 412 means "already exists" and counts as success;
  - ranged GETs;
  - presigned `/url`, with expiry `SHELBY_URL_TTL_S` (default 3600 s).
- **Native SDK.** `@shelby-protocol/sdk` 0.11.0 exists on npm, but:
  - its license is **"Proprietary"**, it is pre-1.0, and its exports are `./node` and `./browser` only;
  - the only named network is `shelbynet` (a dev network);
  - per-blob expiry was removed in 0.8, so the examples repo is stale;
  - its RPC host was unreachable from our host on 2026-11-19.

  `SHELBY_MODE=sdk` (`ShelbySdkBackend`) uses `ShelbyNodeClient.upload/download` and is type-checked against 0.11.0. Treat it as experimental; it is loaded lazily, so S3 mode never imports it.
- **Pricing** (early snapshot, docs `/protocol/pricing`): free plan 10 GiB storage + 10 GiB/month egress, where each object counts as ≥ 10 MiB; paid plan $20/TiB-month, egress free up to 3× average storage, then $10/TiB.
- **Sources:**
  - https://docs.shelby.xyz (llms-full.txt: `/protocol/pricing`, `/protocol/architecture/overview`, `/tools/s3-gateway`, `/tools/s3-gateway/limits`)
  - https://shelby.xyz/news/from-testnet-to-private-beta
  - https://shelby.xyz/news/shelby-private-beta-the-first-customer-workloads-are-live
  - `npm view @shelby-protocol/sdk` and the package `.d.ts`
  - https://github.com/shelby/examples

### Cloudflare R2 (native gateway backend, not a bridge)

- Durability: 99.999999999% (eleven 9s) annual durability by design. Availability SLA is 99.9%. Durability does not protect against deletion.
- A write is acknowledged once the data is persisted to disk.
- Pricing:
  - Standard: $0.015/GB-month, Class A $4.50/M, Class B $0.36/M, free egress. Free tier 10 GB-month, 1M A, 10M B.
  - Infrequent Access: $0.01/GB-month, $0.01/GB retrieval, 30-day minimum.
- Sources: https://developers.cloudflare.com/r2/pricing/ and https://developers.cloudflare.com/r2/reference/durability/
