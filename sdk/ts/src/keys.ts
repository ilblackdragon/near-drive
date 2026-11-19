/** NEAR-format ed25519 keys (`ed25519:<base58>`) and X25519 recipient keys (`x25519:<base58>`). */
import { ed25519 } from "@noble/curves/ed25519.js";
import { base58, b58N, equalBytes } from "./bytes.js";

export function parsePublicKey(s: string): Uint8Array {
  if (typeof s !== "string" || !s.startsWith("ed25519:")) throw new Error("only ed25519 keys are supported");
  const pk = b58N(s.slice(8), 32, "public key");
  // Same check as ed25519-dalek's VerifyingKey::from_bytes: must decompress.
  try {
    ed25519.Point.fromBytes(pk);
  } catch {
    throw new Error("invalid ed25519 public key");
  }
  return pk;
}

export function formatPublicKey(pk: Uint8Array): string {
  return "ed25519:" + base58.encode(pk);
}

/** NEAR secret keys are base58 of 64 bytes (seed || public key); 32-byte seeds are accepted too. Returns the 32-byte seed. */
export function parseSecretKey(s: string): Uint8Array {
  if (typeof s !== "string" || !s.startsWith("ed25519:")) throw new Error("only ed25519 keys are supported");
  let b: Uint8Array;
  try {
    b = base58.decode(s.slice(8));
  } catch {
    throw new Error("invalid base58 in secret key");
  }
  if (b.length !== 64 && b.length !== 32) throw new Error(`secret key must be 32 or 64 bytes, got ${b.length}`);
  const seed = b.slice(0, 32);
  if (b.length === 64 && !equalBytes(ed25519.getPublicKey(seed), b.slice(32))) {
    throw new Error("secret key does not match its embedded public key");
  }
  return seed;
}

export function formatSecretKey(seed: Uint8Array): string {
  const out = new Uint8Array(64);
  out.set(seed, 0);
  out.set(ed25519.getPublicKey(seed), 32);
  return "ed25519:" + base58.encode(out);
}

export function publicKeyOf(seed: Uint8Array): string {
  return formatPublicKey(ed25519.getPublicKey(seed));
}

/** base58 ed25519 signature. */
export function sign(seed: Uint8Array, msg: Uint8Array): string {
  return base58.encode(ed25519.sign(msg, seed));
}

export function verify(publicKey: string, msg: Uint8Array, sigB58: string): boolean {
  let pk: Uint8Array, sig: Uint8Array;
  try {
    pk = parsePublicKey(publicKey);
    sig = b58N(sigB58, 64, "signature");
  } catch {
    return false;
  }
  try {
    // zip215: false = strict RFC 8032 verification, like ed25519-dalek's `verify`.
    return ed25519.verify(sig, msg, pk, { zip215: false });
  } catch {
    return false;
  }
}

export function formatX25519(pk: Uint8Array): string {
  return "x25519:" + base58.encode(pk);
}

export function parseX25519(s: string): Uint8Array {
  if (typeof s !== "string" || !s.startsWith("x25519:")) throw new Error("expected x25519:<base58>");
  return b58N(s.slice(7), 32, "x25519 key");
}

/** Generate a fresh ed25519 key in NEAR secret-key format. */
export function generateSecretKey(): string {
  return formatSecretKey(ed25519.utils.randomSecretKey());
}
