# Blob bridge protocol (v1)

A blob bridge is an HTTP service that stores NEAR Drive chunks in some other
system, such as Filecoin Onchain Cloud or Shelby. The gateway uses it as one
more blob backend (`{"type": "bridge"}`, see [gateway.md](gateway.md)). Bridges never see
plaintext: chunks are opaque, content-addressed ciphertext (or public data).

Reference implementations:
- client: `crates/near-drive-gateway/src/bridge.rs` (`BridgeBlobStore`)
- server: `reference_router` in the same file (fs-backed; used by the tests)

## Identifiers

`{cid}` is `b3:` followed by 64 lowercase hex characters: the BLAKE3 hash of
the chunk bytes. Example: `b3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262`.

The `:` appears literally in the URL path. Clients send it unescaped, and
servers should also accept `%3A`.

A bridge must reject (400) any request whose cid does not match that format.

## Authentication

If the bridge is configured with a token, every request carries
`Authorization: Bearer <token>`. Without a valid token the bridge returns 401.
Direct URLs returned by `/url` (below) must not need this header.

## Endpoints

`{base}` is the configured `url`, with any trailing `/` removed.

### `PUT {base}/blobs/{cid}`

The body is the chunk bytes, up to 64 MiB + 64 bytes.

| Response | Meaning |
|---|---|
| `201 Created` | stored |
| `200 OK` | already stored |
| `400` | `blake3(body)` does not equal `{cid}`. A bridge MUST check this. |
| `401` | bad or missing token |
| `413` | body too large |
| `5xx` | transient failure; the gateway may retry or count the write as failed |

Rules:
- The request is idempotent: storing the same cid twice must succeed.
- When the bridge answers 200 or 201, the chunk must be durable, or durable
  enough for the bridge's class (for example, staged and queued for a PDP deal).
- A GET that follows must return the chunk, even if the long-term copy
  is still being made.

The response body is ignored.

### `GET {base}/blobs/{cid}`

| Response | Meaning |
|---|---|
| `200 OK` | body = the exact chunk bytes, `Content-Type: application/octet-stream` |
| `206 Partial Content` | answer to a `Range` request (see below) |
| `404 Not Found` | the bridge does not have the chunk |
| `416 Range Not Satisfiable` | the range starts at or past the end of the chunk |

#### Range requests

`Range: bytes=a-b` uses inclusive offsets, as in RFC 9110.

- Servers MUST support the forms `bytes=a-b` and `bytes=a-`.
- They SHOULD also support `bytes=-n` (the last n bytes).
- The gateway only sends `bytes=a-b`.

A ranged reply is `206` with `Content-Range: bytes a-b/total`. It covers
`[a, min(b, total-1)]`.

A bridge that cannot serve ranges may ignore the header and reply `200` with
the whole chunk; the gateway then slices the bytes itself.

Multi-range requests are not used.

### `HEAD {base}/blobs/{cid}`

Returns `200` if the bridge has the chunk, `404` if not. The response has no
body.

### `GET {base}/blobs/{cid}/url`

Returns a URL that a client can fetch the chunk from directly, without the
gateway, for example a FilBeam/CDN URL or a presigned URL.

| Response | Meaning |
|---|---|
| `200 OK` | `{"url": "https://...", "expires_ms": 1763600000000}`. `expires_ms` is in unix milliseconds, or `null` if the URL does not expire. |
| `404 Not Found` | no direct URL for this chunk, or the bridge does not offer direct URLs at all |

Requirements for the URL:
- A plain `GET` with no auth headers must return the exact chunk bytes.
- It SHOULD honor `Range`.
- It MAY live on another host, such as a CDN.

Clients always check the fetched bytes against the cid. When a direct fetch
fails, or the URL is due to expire within 30 s, they fetch the chunk through
the gateway instead.

## What a bridge does not need

- No listing and no delete endpoints in v1. Garbage collection is a future
  extension.
- No knowledge of objects, namespaces or encryption.

## Gateway behaviour

The gateway uses the bridge as a storage-class member (see [gateway.md](gateway.md#storage-backends-classes-and-index)).
- **Writes:** a storage class writes each chunk to all of its backends
  concurrently. The upload succeeds once `min_successes` of those writes
  succeed.
- **Reads:** the gateway tries backends in order. A `404` means "try the next
  backend". Any other error is logged, then the next backend is tried.
- **`?mode=locate`:** the gateway calls `HEAD` and then `/url` on the first
  backend that has each chunk.

The gateway's request timeout is `timeout_secs`, 300 s by default.
