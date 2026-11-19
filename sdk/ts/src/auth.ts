/** Request authentication for the native API. */
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex, utf8ToBytes } from "./bytes.js";

export const H_ACCOUNT = "x-near-account";
export const H_PUBKEY = "x-near-publickey";
export const H_TS = "x-near-timestamp";
export const H_SIG = "x-near-signature";

/** `path` is the percent-encoded request path as sent; `query` the raw query string without `?`. */
export function canonicalRequest(method: string, path: string, query: string, account: string, publicKey: string, tsMs: number, body: Uint8Array): Uint8Array {
  return utf8ToBytes(`nstorage-req-v1\n${method.toUpperCase()}\n${path}\n${query}\n${account}\n${publicKey}\n${tsMs}\n${bytesToHex(blake3(body))}`);
}
