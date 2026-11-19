import { base58, base64 } from "@scure/base";
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes, randomBytes } from "@noble/hashes/utils.js";
import { blake3 } from "@noble/hashes/blake3.js";

export { base58, base64, bytesToHex, hexToBytes, utf8ToBytes, concatBytes, randomBytes };

const td = new TextDecoder("utf-8", { fatal: true });
export const bytesToUtf8 = (b: Uint8Array): string => td.decode(b);

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/** Big-endian u64 (`n` must be a safe integer). */
export function u64be(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`not a u64: ${n}`);
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n));
  return out;
}

/** Strict lowercase/uppercase hex decode of exactly `len` bytes. */
export function hexN(s: string, len: number, what: string): Uint8Array {
  if (typeof s !== "string" || s.length !== len * 2 || !/^[0-9a-fA-F]*$/.test(s)) throw new Error(`bad ${what}: expected ${len} hex bytes`);
  return hexToBytes(s);
}

export function b58N(s: string, len: number, what: string): Uint8Array {
  let b: Uint8Array;
  try {
    b = base58.decode(s);
  } catch {
    throw new Error(`bad ${what}: invalid base58`);
  }
  if (b.length !== len) throw new Error(`bad ${what}: expected ${len} bytes, got ${b.length}`);
  return b;
}

export function b64N(s: string, len: number | undefined, what: string): Uint8Array {
  let b: Uint8Array;
  try {
    b = base64.decode(s);
  } catch {
    throw new Error(`bad ${what}: invalid base64`);
  }
  if (len !== undefined && b.length !== len) throw new Error(`bad ${what}: expected ${len} bytes`);
  return b;
}

/** Content id of a chunk: `b3:` + hex(blake3(bytes)). */
export function cid(bytes: Uint8Array): string {
  return "b3:" + bytesToHex(blake3(bytes));
}

export function isValidCid(s: unknown): s is string {
  return typeof s === "string" && /^b3:[0-9a-f]{64}$/.test(s);
}

export function toBytes(data: Uint8Array | ArrayBuffer | string): Uint8Array {
  if (typeof data === "string") return utf8ToBytes(data);
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  throw new TypeError("data must be Uint8Array, ArrayBuffer or string");
}
