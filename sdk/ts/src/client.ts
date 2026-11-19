/**
 * nstorage client: chunking, client-side encryption, request signing. Verifies
 * everything it reads (record signature, manifest cid, chunk cids, AEAD).
 * Uses only `fetch` + Web APIs, so it runs in Node >= 20 and browsers.
 */
import { base58, cid as cidOf, toBytes } from "./bytes.js";
import { canonicalRequest, H_ACCOUNT, H_PUBKEY, H_SIG, H_TS } from "./auth.js";
import { addRecipient, decryptObject, encryptFor, plaintextChunks, RootKey, type EncInfo, type Recipient } from "./crypto.js";
import { parsePublicKey, parseSecretKey, parseX25519, publicKeyOf, sign } from "./keys.js";
import { manifestCid, manifestToBytes, normalizeManifest, storedSize, validateManifest, type ChunkRef, type Manifest } from "./manifest.js";
import { normalizeRecord, recordSigningBytes, recordToJson, verifyRecordSignature, type PointerRecord } from "./record.js";
import { encodePath, NearUri, validateAccountId } from "./uri.js";

export const DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024;

/**
 * Signs with an ed25519 key authorized for the account (full-access key, a
 * function-call key scoped to the storage contract, or a gateway dev key).
 * Implement this to plug in a wallet / HSM; `sign` returns the raw 64-byte
 * signature (or its base58 string).
 */
export interface Signer {
  /** `ed25519:<base58>` */
  publicKey: string;
  sign(message: Uint8Array): Promise<Uint8Array | string> | Uint8Array | string;
}

/** A signer from a NEAR secret key string (`ed25519:<base58>`, 64- or 32-byte form). */
export function keySigner(secretKey: string): Signer {
  const seed = parseSecretKey(secretKey);
  return { publicKey: publicKeyOf(seed), sign: (m) => sign(seed, m) };
}

export interface ClientOptions {
  /** Gateway base URL, e.g. `http://127.0.0.1:8787`. */
  gateway: string;
  /** NEAR account to act as. */
  accountId: string;
  /** NEAR secret key string or a custom {@link Signer}. */
  signer: string | Signer;
  /** Encryption root key (32 bytes / hex). Without it you can only write public objects or for `shareWith` recipients. */
  rootKey?: RootKey | Uint8Array | string;
  chunkSize?: number;
  /** Custom fetch (defaults to globalThis.fetch). */
  fetch?: typeof fetch;
}

export interface PutOptions {
  /** Store plaintext (for public data such as open model weights). */
  public?: boolean;
  contentType?: string;
  /** Extra recipients (`x25519:<base58>`). With no root key this lets an app write data only the user can read. */
  shareWith?: string[];
}

export interface ObjectHead {
  record: PointerRecord;
  manifest: Manifest;
}

export interface ListEntry {
  path: string;
  size: number;
  seq: number;
  writer: string;
  ts_ms: number;
}

export class GatewayError extends Error {
  constructor(
    readonly status: number,
    readonly body: string,
  ) {
    super(`gateway returned ${status}: ${body}`);
  }
}

const objPath = (u: NearUri) => `/v1/o/${u.namespace}/${encodePath(u.path)}`;

export class Client {
  readonly gateway: string;
  readonly accountId: string;
  readonly chunkSize: number;
  readonly #signer: Signer;
  readonly #root?: RootKey;
  readonly #fetch: typeof fetch;
  #lastTs = 0;

  constructor(o: ClientOptions) {
    validateAccountId(o.accountId);
    this.gateway = o.gateway.replace(/\/+$/, "");
    this.accountId = o.accountId;
    this.#signer = typeof o.signer === "string" ? keySigner(o.signer) : o.signer;
    parsePublicKey(this.#signer.publicKey);
    if (o.rootKey !== undefined) this.#root = RootKey.from(o.rootKey);
    this.chunkSize = o.chunkSize ?? DEFAULT_CHUNK_SIZE;
    if (!Number.isSafeInteger(this.chunkSize) || this.chunkSize <= 0) throw new Error("chunkSize must be > 0");
    this.#fetch = o.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** This account's `x25519:<base58>` key for receiving shared objects (needs the root key). */
  x25519Public(): string | undefined {
    return this.#root?.x25519Public();
  }

  get publicKey(): string {
    return this.#signer.publicKey;
  }

  async #sign(msg: Uint8Array): Promise<string> {
    const s = await this.#signer.sign(msg);
    return typeof s === "string" ? s : base58.encode(s);
  }

  /**
   * Strictly increasing per client: the gateway's replay cache is keyed by
   * signature and ed25519 is deterministic, so two identical requests in the
   * same millisecond would otherwise be rejected as replays.
   */
  #nowMs(): number {
    const t = Math.max(Date.now(), this.#lastTs + 1);
    this.#lastTs = t;
    return t;
  }

  async #send(method: string, path: string, query: string, body?: Uint8Array): Promise<Response> {
    const b = body ?? new Uint8Array(0);
    const ts = this.#nowMs();
    const sig = await this.#sign(canonicalRequest(method, path, query, this.accountId, this.#signer.publicKey, ts, b));
    const url = this.gateway + path + (query ? `?${query}` : "");
    return this.#fetch(url, {
      method,
      headers: { [H_ACCOUNT]: this.accountId, [H_PUBKEY]: this.#signer.publicKey, [H_TS]: String(ts), [H_SIG]: sig },
      body: method === "GET" || method === "HEAD" ? undefined : (b as BodyInit),
    });
  }

  static async #check(r: Response): Promise<Response> {
    if (r.ok) return r;
    throw new GatewayError(r.status, await r.text().catch(() => ""));
  }

  async #putChunk(namespace: string, bytes: Uint8Array): Promise<ChunkRef> {
    const cid = cidOf(bytes);
    await Client.#check(await this.#send("PUT", `/v1/chunk/${namespace}/${cid}`, "", bytes));
    return { cid, len: bytes.length };
  }

  /** Record + manifest of `uri`, verified; `null` if absent. */
  async head(uri: string | NearUri): Promise<ObjectHead | null> {
    const u = NearUri.from(uri);
    const r = await this.#send("GET", objPath(u), "");
    if (r.status === 404) return null;
    const raw = (await (await Client.#check(r)).json()) as { record: unknown; manifest: unknown };
    const head = { record: normalizeRecord(raw.record), manifest: normalizeManifest(raw.manifest) };
    verifyHead(u, head);
    return head;
  }

  /** Upload `data` to `uri`. Retries once on a concurrent-write conflict. */
  async put(uri: string | NearUri, data: Uint8Array | ArrayBuffer | string, opts: PutOptions = {}): Promise<PointerRecord> {
    const u = NearUri.from(uri);
    NearUri.object(u.namespace, u.path);
    const bytes = toBytes(data);
    let chunks: Uint8Array[];
    let enc: EncInfo | undefined;
    if (opts.public) {
      chunks = plaintextChunks(bytes, this.chunkSize);
    } else {
      const rs: Recipient[] = [];
      if (this.#root) rs.push(this.#root);
      for (const k of opts.shareWith ?? []) {
        parseX25519(k);
        rs.push(k);
      }
      if (rs.length === 0) throw new Error("no root key and no shareWith recipients; pass rootKey or use {public: true}");
      ({ chunks, enc } = encryptFor(rs, bytes, this.chunkSize));
    }
    const refs: ChunkRef[] = [];
    const uploaded = new Set<string>();
    for (const c of chunks) {
      const id = cidOf(c);
      if (uploaded.has(id)) refs.push({ cid: id, len: c.length });
      else refs.push(await this.#putChunk(u.namespace, c));
      uploaded.add(id);
    }
    const manifest: Manifest = { version: 1, size: bytes.length, chunk_size: this.chunkSize, chunks: refs };
    if (enc) manifest.enc = enc;
    if (opts.contentType !== undefined) manifest.content_type = opts.contentType;
    return this.#commit(u, manifest);
  }

  async #commit(u: NearUri, manifest: Manifest): Promise<PointerRecord> {
    const mbytes = manifestToBytes(manifest);
    const stored = storedSize(manifest) + mbytes.length;
    const mref = await this.#putChunk(u.namespace, mbytes);
    for (let attempt = 0; attempt < 2; attempt++) {
      const prev = (await this.head(u))?.record.seq ?? 0;
      const unsigned = {
        namespace: u.namespace,
        path: u.path,
        manifest_cid: mref.cid,
        size: manifest.size,
        stored_size: stored,
        seq: prev + 1,
        writer: this.accountId,
        writer_pk: this.#signer.publicKey,
        ts_ms: this.#nowMs(),
      };
      const rec: PointerRecord = { ...unsigned, sig: await this.#sign(recordSigningBytes(unsigned)) };
      const r = await this.#send("PUT", objPath(u), "", new TextEncoder().encode(recordToJson(rec)));
      if (r.status === 409 && attempt === 0) continue;
      await Client.#check(r);
      return rec;
    }
    throw new Error(`concurrent write conflict on ${u}`);
  }

  /** Download, verify and decrypt. */
  async getObject(uri: string | NearUri): Promise<{ head: ObjectHead; data: Uint8Array }> {
    const u = NearUri.from(uri);
    const head = await this.head(u);
    if (!head) throw new GatewayError(404, `${u} not found`);
    const chunks: Uint8Array[] = [];
    for (const c of head.manifest.chunks) {
      const r = await Client.#check(await this.#send("GET", objPath(u), `chunk=${c.cid}`));
      const b = new Uint8Array(await r.arrayBuffer());
      if (cidOf(b) !== c.cid) throw new Error(`chunk ${c.cid} content does not match its id`);
      chunks.push(b);
    }
    let data: Uint8Array;
    if (!head.manifest.enc) {
      data = new Uint8Array(chunks.reduce((a, c) => a + c.length, 0));
      let off = 0;
      for (const c of chunks) {
        data.set(c, off);
        off += c.length;
      }
    } else {
      if (!this.#root) throw new Error("object is encrypted and no root key is loaded");
      data = decryptObject(this.#root, head.manifest.enc, chunks);
    }
    if (data.length !== head.manifest.size) throw new Error("size mismatch");
    return { head, data };
  }

  async get(uri: string | NearUri): Promise<Uint8Array> {
    return (await this.getObject(uri)).data;
  }

  async getText(uri: string | NearUri): Promise<string> {
    return new TextDecoder().decode(await this.get(uri));
  }

  /** List objects under a prefix URI (e.g. `near://alice.near/memory/`). */
  async list(prefix: string | NearUri): Promise<ListEntry[]> {
    const u = NearUri.from(prefix);
    const r = await this.#send("GET", `/v1/list/${u.namespace}`, `prefix=${encodePath(u.path)}`);
    return (await (await Client.#check(r)).json()) as ListEntry[];
  }

  async delete(uri: string | NearUri): Promise<void> {
    const u = NearUri.from(uri);
    await Client.#check(await this.#send("DELETE", objPath(u), ""));
  }

  /**
   * Re-wrap the object key of `uri` to `recipient` (`x25519:<base58>`). Chunks
   * are reused; only a new manifest and record are written. The recipient also
   * needs read access via namespace policy.
   */
  async share(uri: string | NearUri, recipient: string): Promise<PointerRecord> {
    if (!this.#root) throw new Error("sharing requires the root key");
    const u = NearUri.from(uri);
    const head = await this.head(u);
    if (!head) throw new GatewayError(404, `${u} not found`);
    if (!head.manifest.enc) throw new Error(`${u} is public; nothing to share`);
    parseX25519(recipient);
    const enc = addRecipient(this.#root, head.manifest.enc, recipient);
    return this.#commit(u, { ...head.manifest, enc });
  }
}

/** Client-side checks on what a (possibly untrusted) gateway returned. */
export function verifyHead(uri: NearUri, head: ObjectHead): void {
  const r = head.record;
  if (!r || r.namespace !== uri.namespace || r.path !== uri.path) throw new Error("gateway returned a record for a different object");
  verifyRecordSignature(r);
  if (manifestCid(head.manifest) !== r.manifest_cid) throw new Error("manifest does not match record");
  validateManifest(head.manifest);
  if (head.manifest.size !== r.size) throw new Error("record size does not match manifest");
}
