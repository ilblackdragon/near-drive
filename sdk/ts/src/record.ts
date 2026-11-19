/** Signed pointer records `(namespace, path) -> manifest`. */
import { utf8ToBytes } from "./bytes.js";
import { isValidCid } from "./bytes.js";
import { verify } from "./keys.js";

export interface PointerRecord {
  namespace: string;
  path: string;
  manifest_cid: string;
  /** Plaintext size. */
  size: number;
  /** Stored size (manifest + chunks), used for metering. */
  stored_size: number;
  /** Monotonic per (namespace, path); 1 for a new object. */
  seq: number;
  writer: string;
  writer_pk: string;
  ts_ms: number;
  sig: string;
}

export function recordSigningBytes(r: Omit<PointerRecord, "sig">): Uint8Array {
  return utf8ToBytes(
    `near-drive-record-v1\n${r.namespace}\n${r.path}\n${r.manifest_cid}\n${r.size}\n${r.stored_size}\n${r.seq}\n${r.writer}\n${r.writer_pk}\n${r.ts_ms}`,
  );
}

/** Type-check a record received as JSON (throws on wrong field types). */
export function normalizeRecord(v: unknown): PointerRecord {
  if (typeof v !== "object" || v === null) throw new Error("record must be an object");
  const o = v as Record<string, unknown>;
  const s = (k: string) => {
    if (typeof o[k] !== "string") throw new Error(`record: ${k} must be a string`);
    return o[k] as string;
  };
  const n = (k: string) => {
    const x = o[k];
    if (typeof x !== "number" || !Number.isSafeInteger(x) || x < 0) throw new Error(`record: ${k} must be an unsigned integer`);
    return x;
  };
  return {
    namespace: s("namespace"),
    path: s("path"),
    manifest_cid: s("manifest_cid"),
    size: n("size"),
    stored_size: n("stored_size"),
    seq: n("seq"),
    writer: s("writer"),
    writer_pk: s("writer_pk"),
    ts_ms: n("ts_ms"),
    sig: s("sig"),
  };
}

/** Signature check only (writer authorization is NEAR state, checked by the gateway). */
export function verifyRecordSignature(r: PointerRecord): void {
  if (!Number.isSafeInteger(r.seq) || r.seq < 1) throw new Error("seq must be >= 1");
  if (!isValidCid(r.manifest_cid)) throw new Error("bad manifest cid");
  if (!verify(r.writer_pk, recordSigningBytes(r), r.sig)) throw new Error("bad record signature");
}

/** Field order matches Rust's struct (not required by the gateway, but tidy). */
export function recordToJson(r: PointerRecord): string {
  const { namespace, path, manifest_cid, size, stored_size, seq, writer, writer_pk, ts_ms, sig } = r;
  return JSON.stringify({ namespace, path, manifest_cid, size, stored_size, seq, writer, writer_pk, ts_ms, sig });
}
