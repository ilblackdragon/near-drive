import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex } from "@noble/hashes/utils.js";

/** NEAR Drive chunk id: "b3:" + lowercase hex(blake3(bytes)). */
export const CID_RE = /^b3:[0-9a-f]{64}$/;

export function computeCid(data: Uint8Array): string {
  return "b3:" + bytesToHex(blake3(data));
}

export function isValidCid(cid: string): boolean {
  return CID_RE.test(cid);
}
