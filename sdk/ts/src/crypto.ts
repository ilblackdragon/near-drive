/**
 * Chunked envelope encryption, byte-compatible with `near_drive_core::crypto`.
 *
 * - per-object random 256-bit DEK; chunks sealed with XChaCha20-Poly1305,
 *   nonce = nonce_prefix(16) || chunk_index(u64 BE),
 *   AAD = "near-drive-chunk-v1" || object_id(16) || chunk_index(u64 BE) || is_last(u8).
 * - DEK wrapped per recipient:
 *   `kek:<kek_id>` (owner; XChaCha20-Poly1305 under HKDF(root, kek), AAD = object_id) or
 *   `x25519:<base58>` (ephemeral-static X25519, key = HKDF-SHA256(salt="near-drive", ikm=shared,
 *   info="near-drive/v1/wrap-x25519"||epk||pk), AAD = object_id).
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { base58, base64, b58N, b64N, bytesToHex, concatBytes, hexN, hexToBytes, randomBytes, u64be, utf8ToBytes } from "./bytes.js";
import { formatX25519, parseX25519, publicKeyOf } from "./keys.js";

export const ALG = "xchacha20poly1305-chunked-v1";
export const TAG_LEN = 16;

export interface WrappedKey {
  /** `kek:<kek_id>` for the owner or `x25519:<base58 pk>` for others. */
  recipient: string;
  /** Ephemeral X25519 public key (base58), x25519 recipients only. */
  epk?: string;
  nonce: string;
  ct: string;
}

export interface EncInfo {
  alg: string;
  object_id: string;
  nonce_prefix: string;
  wrapped_keys: WrappedKey[];
}

const SALT = utf8ToBytes("near-drive");

function derive(ikm: Uint8Array, info: Uint8Array): Uint8Array {
  return hkdf(sha256, ikm, SALT, info, 32);
}

/** Account root key. v0: a local 32-byte secret; later obtained via NEAR MPC CKD. */
export class RootKey {
  readonly #k: Uint8Array;

  constructor(bytes: Uint8Array) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error("root key must be 32 bytes");
    this.#k = bytes.slice();
  }

  static generate(): RootKey {
    return new RootKey(randomBytes(32));
  }

  static fromHex(h: string): RootKey {
    return new RootKey(hexN(h.trim(), 32, "root key"));
  }

  static from(k: RootKey | Uint8Array | string): RootKey {
    if (k instanceof RootKey) return k;
    return typeof k === "string" ? RootKey.fromHex(k) : new RootKey(k);
  }

  bytes(): Uint8Array {
    return this.#k.slice();
  }

  toHex(): string {
    return bytesToHex(this.#k);
  }

  #derive(info: string): Uint8Array {
    return derive(this.#k, utf8ToBytes(info));
  }

  /** X25519 secret (unclamped bytes, as x25519-dalek StaticSecret stores them). */
  x25519Secret(): Uint8Array {
    return this.#derive("near-drive/v1/x25519");
  }

  /** `x25519:<base58>`: publish this so others can share objects with the account. */
  x25519Public(): string {
    return formatX25519(x25519.getPublicKey(this.x25519Secret()));
  }

  kek(): Uint8Array {
    return this.#derive("near-drive/v1/kek");
  }

  /**
   * Ed25519 seed that signs pointer records: HKDF-SHA256(salt="near-drive", ikm=root,
   * info="near-drive/v1/sign"), used as an RFC 8032 secret key (ed25519-dalek `SigningKey::from_bytes`).
   */
  signSeed(): Uint8Array {
    return this.#derive("near-drive/v1/sign");
  }

  /** `ed25519:<base58>` record-signing key; publish it with `set_sign_key` (`near drive publish-key`). */
  signPublicKey(): string {
    return publicKeyOf(this.signSeed());
  }

  /** Short public fingerprint of the KEK so readers can pick the right wrapped key. */
  kekId(): string {
    return bytesToHex(blake3(this.#derive("near-drive/v1/kek-id")).slice(0, 8));
  }
}

/** Who an object key is wrapped to: the owner's root key, or an `x25519:<base58>` public key. */
export type Recipient = RootKey | string;

function seal(key: Uint8Array, nonce: Uint8Array, msg: Uint8Array, aad: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, nonce, aad).encrypt(msg);
}

function open(key: Uint8Array, nonce: Uint8Array, ct: Uint8Array, aad: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, nonce, aad).decrypt(ct);
}

function dh(sk: Uint8Array, pk: Uint8Array): Uint8Array {
  let s: Uint8Array;
  try {
    s = x25519.getSharedSecret(sk, pk);
  } catch {
    throw new Error("invalid recipient key");
  }
  if (s.every((b) => b === 0)) throw new Error("invalid recipient key");
  return s;
}

function x25519WrapKey(shared: Uint8Array, epk: Uint8Array, pk: Uint8Array): Uint8Array {
  return derive(shared, concatBytes(utf8ToBytes("near-drive/v1/wrap-x25519"), epk, pk));
}

function wrapDek(dek: Uint8Array, objectId: Uint8Array, r: Recipient): WrappedKey {
  const nonce = randomBytes(24);
  if (r instanceof RootKey) {
    return { recipient: `kek:${r.kekId()}`, nonce: base64.encode(nonce), ct: base64.encode(seal(r.kek(), nonce, dek, objectId)) };
  }
  const pk = parseX25519(r);
  const esk = randomBytes(32);
  const epk = x25519.getPublicKey(esk);
  const k = x25519WrapKey(dh(esk, pk), epk, pk);
  return {
    recipient: formatX25519(pk),
    epk: base58.encode(epk),
    nonce: base64.encode(nonce),
    ct: base64.encode(seal(k, nonce, dek, objectId)),
  };
}

function unwrapDek(root: RootKey, enc: EncInfo, objectId: Uint8Array): Uint8Array {
  const kekName = `kek:${root.kekId()}`;
  const xName = root.x25519Public();
  const wk = enc.wrapped_keys.find((w) => w.recipient === kekName || w.recipient === xName);
  if (!wk) throw new Error(`object is not encrypted to this account's keys (${kekName}, ${xName})`);
  const nonce = b64N(wk.nonce, 24, "wrap nonce");
  const ct = b64N(wk.ct, undefined, "wrapped key");
  let dek: Uint8Array;
  try {
    if (wk.recipient === kekName) {
      dek = open(root.kek(), nonce, ct, objectId);
    } else {
      if (wk.epk === undefined) throw new Error("missing epk");
      const epk = b58N(wk.epk, 32, "epk");
      const sk = root.x25519Secret();
      const pk = x25519.getPublicKey(sk);
      dek = open(x25519WrapKey(x25519.getSharedSecret(sk, epk), epk, pk), nonce, ct, objectId);
    }
  } catch {
    throw new Error("cannot unwrap object key (wrong root key?)");
  }
  if (dek.length !== 32) throw new Error("bad DEK length");
  return dek;
}

function chunkNonce(prefix: Uint8Array, idx: number): Uint8Array {
  return concatBytes(prefix, u64be(idx));
}

function chunkAad(objectId: Uint8Array, idx: number, last: boolean): Uint8Array {
  return concatBytes(utf8ToBytes("near-drive-chunk-v1"), objectId, u64be(idx), new Uint8Array([last ? 1 : 0]));
}

/** Split plaintext into chunks; an empty object is one empty chunk. */
export function plaintextChunks(plaintext: Uint8Array, chunkSize: number): Uint8Array[] {
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) throw new Error("chunk_size must be > 0");
  if (plaintext.length === 0) return [new Uint8Array(0)];
  const out: Uint8Array[] = [];
  for (let i = 0; i < plaintext.length; i += chunkSize) out.push(plaintext.subarray(i, i + chunkSize));
  return out;
}

/** Encrypt `plaintext` for an explicit recipient set (at least one). */
export function encryptFor(recipients: Recipient[], plaintext: Uint8Array, chunkSize: number): { chunks: Uint8Array[]; enc: EncInfo } {
  if (recipients.length === 0) throw new Error("need at least one recipient");
  const pieces = plaintextChunks(plaintext, chunkSize);
  const dek = randomBytes(32);
  const objectId = randomBytes(16);
  const noncePrefix = randomBytes(16);
  const n = pieces.length;
  const chunks = pieces.map((p, i) => seal(dek, chunkNonce(noncePrefix, i), p, chunkAad(objectId, i, i + 1 === n)));
  const wrapped_keys = recipients.map((r) => wrapDek(dek, objectId, r));
  return { chunks, enc: { alg: ALG, object_id: bytesToHex(objectId), nonce_prefix: bytesToHex(noncePrefix), wrapped_keys } };
}

export function encryptObject(root: RootKey, plaintext: Uint8Array, chunkSize: number) {
  return encryptFor([root], plaintext, chunkSize);
}

export function decryptObject(root: RootKey, enc: EncInfo, chunks: Uint8Array[]): Uint8Array {
  if (enc.alg !== ALG) throw new Error(`unsupported alg ${enc.alg}`);
  if (chunks.length === 0) throw new Error("object has no chunks");
  const objectId = hexN(enc.object_id, 16, "object_id");
  const noncePrefix = hexN(enc.nonce_prefix, 16, "nonce_prefix");
  const dek = unwrapDek(root, enc, objectId);
  const n = chunks.length;
  const parts = chunks.map((c, i) => {
    try {
      return open(dek, chunkNonce(noncePrefix, i), c, chunkAad(objectId, i, i + 1 === n));
    } catch {
      throw new Error(`chunk ${i} failed authentication`);
    }
  });
  return concatBytes(...parts);
}

/** Give another recipient access to an existing object: same chunks, one more wrapped key. */
export function addRecipient(root: RootKey, enc: EncInfo, r: Recipient): EncInfo {
  const objectId = hexN(enc.object_id, 16, "object_id");
  const dek = unwrapDek(root, enc, objectId);
  const w = wrapDek(dek, objectId, r);
  return { ...enc, wrapped_keys: [...enc.wrapped_keys.filter((x) => x.recipient !== w.recipient), w] };
}

export { hexToBytes };

/** Number of chunks an object of `size` plaintext bytes is split into (an empty object has one). */
export function chunkCount(size: number, chunkSize: number): number {
  return size === 0 ? 1 : Math.ceil(size / chunkSize);
}

/** Plaintext length of chunk `idx` of an object. */
export function chunkPlainLen(size: number, chunkSize: number, idx: number): number {
  return Math.max(0, Math.min(chunkSize, size - idx * chunkSize));
}

/**
 * Seals the chunks of one object one at a time (same format as {@link encryptFor}).
 * Chunks are independent: the caller passes the index and whether it is the last one.
 */
export class ChunkSealer {
  readonly #dek: Uint8Array;
  readonly #objectId: Uint8Array;
  readonly #prefix: Uint8Array;
  /** Goes into `Manifest.enc`. */
  readonly encInfo: EncInfo;

  private constructor(dek: Uint8Array, objectId: Uint8Array, prefix: Uint8Array, enc: EncInfo) {
    this.#dek = dek;
    this.#objectId = objectId;
    this.#prefix = prefix;
    this.encInfo = enc;
  }

  /** Fresh DEK / object id / nonce prefix, the DEK wrapped to every recipient. */
  static create(recipients: Recipient[]): ChunkSealer {
    if (recipients.length === 0) throw new Error("need at least one recipient");
    const dek = randomBytes(32);
    const objectId = randomBytes(16);
    const prefix = randomBytes(16);
    const wrapped_keys = recipients.map((r) => wrapDek(dek, objectId, r));
    return new ChunkSealer(dek, objectId, prefix, { alg: ALG, object_id: bytesToHex(objectId), nonce_prefix: bytesToHex(prefix), wrapped_keys });
  }

  /**
   * The sealer of an object started earlier, rebuilt from its `enc` (DEK
   * unwrapped with `root`). Identical plaintext re-seals to identical chunks.
   * Never seal *different* plaintext under an index used before: that reuses a nonce.
   */
  static reopen(root: RootKey, enc: EncInfo): ChunkSealer {
    const o = new ChunkOpener(root, enc);
    return new ChunkSealer(o.dek, o.objectId, o.prefix, enc);
  }

  seal(idx: number, last: boolean, plaintext: Uint8Array): Uint8Array {
    return seal(this.#dek, chunkNonce(this.#prefix, idx), plaintext, chunkAad(this.#objectId, idx, last));
  }
}

/** Opens (and deterministically re-seals) chunks of an existing object. */
export class ChunkOpener {
  /** @internal */ readonly dek: Uint8Array;
  /** @internal */ readonly objectId: Uint8Array;
  /** @internal */ readonly prefix: Uint8Array;

  constructor(root: RootKey, enc: EncInfo) {
    if (enc.alg !== ALG) throw new Error(`unsupported alg ${enc.alg}`);
    this.objectId = hexN(enc.object_id, 16, "object_id");
    this.prefix = hexN(enc.nonce_prefix, 16, "nonce_prefix");
    this.dek = unwrapDek(root, enc, this.objectId);
  }

  open(idx: number, last: boolean, ct: Uint8Array): Uint8Array {
    try {
      return open(this.dek, chunkNonce(this.prefix, idx), ct, chunkAad(this.objectId, idx, last));
    } catch {
      throw new Error(`chunk ${idx} failed authentication`);
    }
  }

  /** Re-encrypt plaintext as chunk `idx`, e.g. to check bytes on disk against a cid. */
  reseal(idx: number, last: boolean, plaintext: Uint8Array): Uint8Array {
    return seal(this.dek, chunkNonce(this.prefix, idx), plaintext, chunkAad(this.objectId, idx, last));
  }
}
