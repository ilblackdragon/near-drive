/** Object manifests, serialized byte-identically to Rust's serde_json output. */
import { ALG, TAG_LEN, type EncInfo, type WrappedKey } from "./crypto.js";
import { cid, isValidCid, utf8ToBytes } from "./bytes.js";

export interface ChunkRef {
  cid: string;
  /** Stored (ciphertext) length in bytes. */
  len: number;
}

export interface Manifest {
  version: number;
  /** Plaintext size in bytes. */
  size: number;
  chunk_size: number;
  chunks: ChunkRef[];
  enc?: EncInfo;
  content_type?: string;
}

export const MAX_CHUNK_BYTES = 64 * 1024 * 1024;

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const u64 = (v: unknown, what: string): number => {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw new Error(`manifest: ${what} must be an unsigned integer`);
  return v;
};
const str = (v: unknown, what: string): string => {
  if (typeof v !== "string") throw new Error(`manifest: ${what} must be a string`);
  return v;
};
// serde: `Option` fields with `#[serde(default)]` accept a missing key or `null`.
const optStr = (v: unknown, what: string): string | undefined => (v === undefined || v === null ? undefined : str(v, what));

function normWrapped(v: unknown): WrappedKey {
  if (!isObj(v)) throw new Error("manifest: wrapped key must be an object");
  // Key insertion order is serialization order: recipient, epk?, nonce, ct.
  const recipient = str(v.recipient, "recipient");
  const epk = optStr(v.epk, "epk");
  const nonce = str(v.nonce, "nonce");
  const ct = str(v.ct, "ct");
  return epk === undefined ? { recipient, nonce, ct } : { recipient, epk, nonce, ct };
}

function normEnc(v: unknown): EncInfo {
  if (!isObj(v)) throw new Error("manifest: enc must be an object");
  if (!Array.isArray(v.wrapped_keys)) throw new Error("manifest: wrapped_keys must be an array");
  return {
    alg: str(v.alg, "alg"),
    object_id: str(v.object_id, "object_id"),
    nonce_prefix: str(v.nonce_prefix, "nonce_prefix"),
    wrapped_keys: v.wrapped_keys.map(normWrapped),
  };
}

/**
 * Rebuild a manifest from parsed JSON keeping only the fields Rust knows, in
 * Rust's declaration order (the gateway returns keys alphabetically sorted).
 */
export function normalizeManifest(v: unknown): Manifest {
  if (!isObj(v)) throw new Error("manifest must be an object");
  if (!Array.isArray(v.chunks)) throw new Error("manifest: chunks must be an array");
  const m: Manifest = {
    version: u64(v.version, "version"),
    size: u64(v.size, "size"),
    chunk_size: u64(v.chunk_size, "chunk_size"),
    chunks: v.chunks.map((c) => {
      if (!isObj(c)) throw new Error("manifest: chunk must be an object");
      return { cid: str(c.cid, "cid"), len: u64(c.len, "len") };
    }),
  };
  if (v.enc !== undefined && v.enc !== null) m.enc = normEnc(v.enc);
  const ct = optStr(v.content_type, "content_type");
  if (ct !== undefined) m.content_type = ct;
  return m;
}

/** Compact JSON identical to `serde_json::to_vec(&Manifest)`. */
export function manifestToJson(m: Manifest): string {
  // JSON.stringify escapes strings exactly like serde_json (", \, \b \f \n \r \t, other
  // C0 controls as \u00xx; everything else verbatim). Key order is fixed by normalizeManifest.
  return JSON.stringify(normalizeManifest(m));
}

export function manifestToBytes(m: Manifest): Uint8Array {
  return utf8ToBytes(manifestToJson(m));
}

export function manifestCid(m: Manifest): string {
  return cid(manifestToBytes(m));
}

export function storedSize(m: Manifest): number {
  return m.chunks.reduce((a, c) => a + c.len, 0);
}

export function validateManifest(m: Manifest): void {
  if (m.version !== 1) throw new Error("unsupported manifest version");
  if (m.chunks.length === 0) throw new Error("manifest has no chunks");
  if (m.chunk_size <= 0 || m.chunk_size > MAX_CHUNK_BYTES) throw new Error("bad chunk_size");
  for (const c of m.chunks) {
    if (!isValidCid(c.cid)) throw new Error(`bad cid ${c.cid}`);
    if (c.len > MAX_CHUNK_BYTES + 64) throw new Error("chunk too large");
  }
  const overhead = m.enc ? TAG_LEN : 0;
  if (storedSize(m) !== m.size + overhead * m.chunks.length) throw new Error("chunk lengths do not add up to size");
  if (m.enc && m.enc.alg !== ALG) throw new Error(`unsupported alg ${m.enc.alg}`);
}

export function parseManifest(bytes: Uint8Array): Manifest {
  const m = normalizeManifest(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
  validateManifest(m);
  return m;
}
