/**
 * NEAR Drive client: chunking, client-side encryption, request signing. Verifies
 * everything it reads (record signature, writer authorization against `drive.near`,
 * manifest cid, chunk cids, AEAD).
 * Uses only `fetch` + Web APIs, so it runs in Node >= 20 and browsers.
 */
import { b64N, base58, bytesToHex, cid as cidOf, toBytes } from "./bytes.js";
import { canonicalRequest, H_ACCOUNT, H_PUBKEY, H_SIG, H_TS } from "./auth.js";
import { addRecipient, chunkCount, chunkPlainLen, ChunkOpener, ChunkSealer, decryptObject, encryptFor, plaintextChunks, RootKey, type EncInfo, type Recipient } from "./crypto.js";
import { parsePublicKey, parseSecretKey, parseX25519, publicKeyOf, sign } from "./keys.js";
import { manifestCid, manifestToBytes, MAX_CHUNK_BYTES, normalizeManifest, storedSize, validateManifest, type ChunkRef, type Manifest } from "./manifest.js";
import {
  ConflictError,
  DEFAULT_NET,
  debug,
  done,
  fetchFully,
  GatewayError,
  okOrAttempt,
  reject,
  retryDelay,
  sleep,
  timeoutFor,
  transport,
  withRetries,
  type Attempt,
  type NetConfig,
  type Resp,
} from "./net.js";
import { normalizeRecord, recordSigningBytes, recordToJson, verifyRecordSignature, type PointerRecord } from "./record.js";
import { NO_WRITER_CHECK, StorageContract, WriterCheck } from "./chain.js";
import { encodePath, NearUri, validateAccountId } from "./uri.js";

export { ConflictError, GatewayError };

export const DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024;
export const DEFAULT_PARALLELISM = 8;
/** Request header choosing the storage class of uploaded chunks (also sent on the record PUT). */
export const CLASS_HEADER = "x-near-drive-class";
/** Don't use a direct URL that expires sooner than this. */
const URL_MIN_REMAINING_MS = 30_000;

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
  /**
   * Root key (32 bytes / hex). Required for writing: records are signed with a key derived
   * from it (publish that key with `near drive publish-key`). Also decrypts objects for this account.
   */
  rootKey?: RootKey | Uint8Array | string;
  /**
   * How reads check that a record's writer was allowed to write it (see {@link WriterCheck}).
   * Default: `WriterCheck.chain({ rpcUrl, contractId })` when `rpcUrl` is set; otherwise none,
   * and every read fails until one is configured.
   */
  writerCheck?: WriterCheck;
  /** NEAR RPC endpoint for the default chain writer check, e.g. `https://rpc.mainnet.near.org`. */
  rpcUrl?: string;
  /** The NEAR Drive contract (default `drive.near`). */
  contractId?: string;
  chunkSize?: number;
  /** Concurrent chunk transfers (default 8). */
  parallelism?: number;
  /** Timeouts and retry policy; unset fields keep the defaults ({@link DEFAULT_NET}). */
  net?: Partial<NetConfig>;
  /** Custom fetch (defaults to globalThis.fetch). */
  fetch?: typeof fetch;
}

export interface PutOptions {
  /** Store plaintext (for public data such as open model weights). */
  public?: boolean;
  contentType?: string;
  /** Extra recipients (`x25519:<base58>`). With `skipOwnerKey: true` this lets an app write data only the user can read. */
  shareWith?: string[];
  /** Also wrap the object key to this account's own root key (default true; false needs `shareWith`). */
  skipOwnerKey?: boolean;
  /** Storage class for the chunks (`hot`, `bulk`, ...); unset = gateway default. */
  class?: string;
  /**
   * Write only if the object is currently at this seq (0 = must not exist);
   * otherwise throw {@link ConflictError} instead of overwriting a newer version.
   */
  expectSeq?: number;
}

export interface ObjectHead {
  record: PointerRecord;
  manifest: Manifest;
  /** Exact stored manifest bytes (base64) when the gateway provides them. */
  manifest_raw?: string;
  /** Storage class the gateway recorded for the object (absent: not recorded). */
  class?: string;
}

/** One chunk as returned by `?mode=locate`. */
export interface LocatedChunk {
  cid: string;
  len: number;
  /** Direct-fetch URL (presigned S3, bridge/CDN). Absent = fetch via the gateway. */
  url?: string;
  expires_ms?: number;
  /** The chunk itself (base64), inlined for small objects. Verified against `cid`. */
  data?: string;
}

/** `GET ...?mode=locate`: a head plus per-chunk locations (empty `chunks` on gateways without locate). */
export interface Located extends ObjectHead {
  chunks: LocatedChunk[];
}

export interface ListEntry {
  path: string;
  size: number;
  seq: number;
  writer: string;
  ts_ms: number;
  /** Present on gateways that report it. */
  manifest_cid?: string;
}

/** One page of `GET /v1/list` ({@link Client.listPage}). */
export interface ListPage {
  entries: ListEntry[];
  /** Rolled-up prefixes (with a delimiter), each ending with it. */
  common_prefixes: string[];
  /** Pass back as `cursor` for the next page; null at the end. */
  next_cursor: string | null;
}

export interface ListPageOptions {
  delimiter?: string;
  cursor?: string;
  limit?: number;
}

const objPath = (u: NearUri) => `/v1/o/${u.namespace}/${encodePath(u.path)}`;

/** `f` over `items` with at most `limit` in flight; results in order. Stops starting new work after a failure. */
export async function mapLimit<T, R>(items: Iterable<T>, limit: number, f: (item: T, i: number) => Promise<R>): Promise<R[]> {
  const it = Array.from(items);
  const out = new Array<R>(it.length);
  let next = 0;
  let failed = false;
  const worker = async () => {
    while (!failed && next < it.length) {
      const i = next++;
      try {
        out[i] = await f(it[i]!, i);
      } catch (e) {
        failed = true;
        throw e;
      }
    }
  };
  const ws = Array.from({ length: Math.max(1, Math.min(limit, it.length)) }, worker);
  const rs = await Promise.allSettled(ws);
  const bad = rs.find((r): r is PromiseRejectedResult => r.status === "rejected");
  if (bad) throw bad.reason;
  return out;
}

function parseHead(raw: unknown): ObjectHead {
  const o = raw as { record: unknown; manifest: unknown; manifest_raw?: unknown; class?: unknown };
  const head: ObjectHead = { record: normalizeRecord(o.record), manifest: normalizeManifest(o.manifest) };
  if (typeof o.manifest_raw === "string") head.manifest_raw = o.manifest_raw;
  if (typeof o.class === "string") head.class = o.class;
  return head;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((a, c) => a + c.length, 0));
  let off = 0;
  for (const c of parts) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Default NEAR Drive contract account. */
export const DEFAULT_CONTRACT = "drive.near";

export class Client {
  readonly gateway: string;
  readonly accountId: string;
  readonly chunkSize: number;
  parallelism: number;
  readonly #signer: Signer;
  readonly #root?: RootKey;
  readonly #fetch: typeof fetch;
  readonly #writerCheck?: WriterCheck;
  #net: NetConfig;
  #lastTs = 0;

  constructor(o: ClientOptions) {
    validateAccountId(o.accountId);
    this.gateway = o.gateway.replace(/\/+$/, "");
    this.accountId = o.accountId;
    this.#signer = typeof o.signer === "string" ? keySigner(o.signer) : o.signer;
    parsePublicKey(this.#signer.publicKey);
    if (o.rootKey !== undefined) this.#root = RootKey.from(o.rootKey);
    this.chunkSize = o.chunkSize ?? DEFAULT_CHUNK_SIZE;
    if (!Number.isSafeInteger(this.chunkSize) || this.chunkSize <= 0 || this.chunkSize > MAX_CHUNK_BYTES) throw new Error("bad chunkSize");
    this.parallelism = o.parallelism ?? DEFAULT_PARALLELISM;
    this.#net = { ...DEFAULT_NET, ...o.net };
    this.#fetch = o.fetch ?? globalThis.fetch.bind(globalThis);
    this.#writerCheck = o.writerCheck ?? (o.rpcUrl !== undefined ? WriterCheck.chain(new StorageContract(o.rpcUrl, o.contractId ?? DEFAULT_CONTRACT, { fetch: o.fetch })) : undefined);
  }

  /** The configured writer check (undefined: reads fail). */
  get writerCheck(): WriterCheck | undefined {
    return this.#writerCheck;
  }

  /** `ed25519:<base58>` key this client signs records with (derived from the root key). Publish it with `near drive publish-key`. */
  signPublicKey(): string | undefined {
    return this.#root?.signPublicKey();
  }

  /** The record-signing seed; writing requires the root key. */
  #recordSeed(): Uint8Array {
    if (!this.#root) throw new Error("writing requires the root key: records are signed with a key derived from it (pass rootKey)");
    return this.#root.signSeed();
  }

  /** Wrap-key recipients for a new encrypted object. */
  #recipients(opts: PutOptions): Recipient[] {
    const rs: Recipient[] = [];
    if (this.#root && !opts.skipOwnerKey) rs.push(this.#root);
    for (const k of opts.shareWith ?? []) {
      parseX25519(k);
      rs.push(k);
    }
    if (rs.length === 0) throw new Error("no recipients: pass rootKey, shareWith recipients, or use {public: true}");
    return rs;
  }

  /** Timeouts and retry policy. */
  get net(): Readonly<NetConfig> {
    return this.#net;
  }

  setNet(net: Partial<NetConfig>): void {
    this.#net = { ...this.#net, ...net };
  }

  /** This account's `x25519:<base58>` key for receiving shared objects (needs the root key). */
  x25519Public(): string | undefined {
    return this.#root?.x25519Public();
  }

  get publicKey(): string {
    return this.#signer.publicKey;
  }

  get hasRootKey(): boolean {
    return this.#root !== undefined;
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

  /** One signed request (no retries); the body is read fully. `xfer`: payload bytes expected to move, for the deadline. */
  async #send(method: string, path: string, query: string, body?: Uint8Array, o: { class?: string; xfer?: number } = {}): Promise<Resp> {
    const b = body ?? new Uint8Array(0);
    const ts = this.#nowMs();
    const sig = await this.#sign(canonicalRequest(method, path, query, this.accountId, this.#signer.publicKey, ts, b));
    const url = this.gateway + path + (query ? `?${query}` : "");
    const headers: Record<string, string> = { [H_ACCOUNT]: this.accountId, [H_PUBKEY]: this.#signer.publicKey, [H_TS]: String(ts), [H_SIG]: sig };
    if (o.class !== undefined) headers[CLASS_HEADER] = o.class;
    const init: RequestInit = { method, headers, body: method === "GET" || method === "HEAD" ? undefined : (b as BodyInit) };
    return fetchFully(this.#fetch, url, init, timeoutFor(this.#net, Math.max(o.xfer ?? 0, b.length)), this.#net.idleTimeoutMs);
  }

  /** Signed, retried request that must succeed. */
  async #sendOk(what: string, method: string, path: string, query: string, body?: Uint8Array, o: { class?: string; xfer?: number } = {}): Promise<Resp> {
    return withRetries(this.#net, what, async () => {
      try {
        return okOrAttempt(await this.#send(method, path, query, body, o));
      } catch (e) {
        return transport(e);
      }
    });
  }

  /** GET returning JSON, retried; `null` on 404. */
  async #getJson(what: string, path: string, query: string): Promise<unknown | null> {
    return withRetries(this.#net, what, async () => {
      let r: Resp;
      try {
        r = await this.#send("GET", path, query);
      } catch (e) {
        return transport(e);
      }
      if (r.status === 404) return done(null);
      if (!r.ok) return reject(r);
      try {
        return done(JSON.parse(new TextDecoder().decode(r.body)) as unknown);
      } catch (e) {
        return { fatal: new Error(`bad response to ${what}: ${errMsg(e)}`) };
      }
    });
  }

  /** Upload one already-encoded chunk (content-addressed, so retried freely). */
  async uploadChunk(namespace: string, bytes: Uint8Array, cls?: string): Promise<ChunkRef> {
    const cid = cidOf(bytes);
    await this.#sendOk(`upload chunk ${cid}`, "PUT", `/v1/chunk/${namespace}/${cid}`, "", bytes, { class: cls });
    return { cid, len: bytes.length };
  }

  /** Record + manifest of `uri`, verified (including the writer, see {@link WriterCheck}); `null` if absent. */
  async head(uri: string | NearUri): Promise<ObjectHead | null> {
    const u = NearUri.from(uri);
    const head = await this.#headUnchecked(u);
    if (head) await this.#checkWriter(head.record);
    return head;
  }

  /** Head with signature/manifest checks but no writer check: only for the current seq when writing (the gateway enforces CAS). */
  async #headUnchecked(u: NearUri): Promise<ObjectHead | null> {
    const raw = await this.#getJson("head", objPath(u), "");
    if (raw === null) return null;
    const head = parseHead(raw);
    checkHead(u, head);
    return head;
  }

  async #checkWriter(r: PointerRecord): Promise<void> {
    if (!this.#writerCheck) throw new Error(NO_WRITER_CHECK);
    await this.#writerCheck.verify(r);
  }

  /** Record + manifest + per-chunk locations (inlined bytes or direct URLs), verified; `null` if absent. */
  async locate(uri: string | NearUri): Promise<Located | null> {
    const u = NearUri.from(uri);
    const raw = await this.#getJson("locate", objPath(u), "mode=locate");
    if (raw === null) return null;
    const loc: Located = { ...parseHead(raw), chunks: [] };
    const cs = (raw as { chunks?: unknown }).chunks;
    if (Array.isArray(cs)) {
      loc.chunks = cs.map((c) => {
        const o = c as Record<string, unknown>;
        if (typeof o.cid !== "string" || typeof o.len !== "number") throw new Error("bad locate response");
        const lc: LocatedChunk = { cid: o.cid, len: o.len };
        if (typeof o.url === "string") lc.url = o.url;
        if (typeof o.expires_ms === "number") lc.expires_ms = o.expires_ms;
        if (typeof o.data === "string") lc.data = o.data;
        return lc;
      });
    }
    checkHead(u, loc);
    const m = loc.manifest;
    if (loc.chunks.length > 0 && (loc.chunks.length !== m.chunks.length || loc.chunks.some((c, i) => c.cid !== m.chunks[i]!.cid))) {
      throw new Error("gateway locate chunks do not match the manifest");
    }
    if (m.chunks.length !== chunkCount(m.size, m.chunk_size)) throw new Error("manifest chunk count does not match size / chunk_size");
    await this.#checkWriter(loc.record);
    return loc;
  }

  /** A sealer for a new object per `opts` (null for public objects). */
  newSealer(opts: PutOptions = {}): ChunkSealer | null {
    this.#recordSeed();
    if (opts.public) return null;
    return ChunkSealer.create(this.#recipients(opts));
  }

  /** The sealer of an object started earlier (resumed upload); needs the owner's root key. */
  reopenSealer(enc: EncInfo): ChunkSealer {
    if (!this.#root) throw new Error("resuming an encrypted upload requires the root key");
    return ChunkSealer.reopen(this.#root, enc);
  }

  /** Opener for an object's chunks (null for public objects). */
  opener(m: Manifest): ChunkOpener | null {
    if (!m.enc) return null;
    if (!this.#root) throw new Error("object is encrypted and no root key is loaded");
    return new ChunkOpener(this.#root, m.enc);
  }

  /** Upload `data` to `uri`. Retries transient failures; retries once on a concurrent-write conflict (unless `expectSeq`). */
  async put(uri: string | NearUri, data: Uint8Array | ArrayBuffer | string, opts: PutOptions = {}): Promise<PointerRecord> {
    const u = NearUri.from(uri);
    NearUri.object(u.namespace, u.path);
    const bytes = toBytes(data);
    this.#recordSeed();
    let chunks: Uint8Array[];
    let enc: EncInfo | undefined;
    if (opts.public) {
      chunks = plaintextChunks(bytes, this.chunkSize);
    } else {
      ({ chunks, enc } = encryptFor(this.#recipients(opts), bytes, this.chunkSize));
    }
    // Repeated content (public data) yields repeated cids: upload each once.
    const seen = new Set<string>();
    const refs = await mapLimit(chunks, this.parallelism, async (c) => {
      const id = cidOf(c);
      if (seen.has(id)) return { cid: id, len: c.length };
      seen.add(id);
      return this.uploadChunk(u.namespace, c, opts.class);
    });
    const manifest: Manifest = { version: 1, size: bytes.length, chunk_size: this.chunkSize, chunks: refs };
    if (enc) manifest.enc = enc;
    if (opts.contentType !== undefined) manifest.content_type = opts.contentType;
    return this.commitManifest(u, manifest, { class: opts.class, expectSeq: opts.expectSeq });
  }

  /**
   * Publish `manifest` (chunks already uploaded) as the new version of `uri`.
   *
   * The record PUT is a compare-and-swap on `seq`, so it is the one write that
   * is not idempotent. After a transient failure the earlier attempt may have
   * landed; a following 409 is then checked against the current head, and if
   * that head is this manifest by this key at the seq we wrote, the write
   * succeeded. A conflict with someone else's write is retried once with the
   * new seq, or with `expectSeq` reported as {@link ConflictError}.
   */
  async commitManifest(uri: string | NearUri, manifest: Manifest, o: { class?: string; expectSeq?: number } = {}): Promise<PointerRecord> {
    const u = NearUri.from(uri);
    const seed = this.#recordSeed();
    const myPk = publicKeyOf(seed);
    const mbytes = manifestToBytes(manifest);
    const stored = storedSize(manifest) + mbytes.length;
    let mref: ChunkRef;
    let prev: number;
    if (o.expectSeq !== undefined) {
      if (!Number.isSafeInteger(o.expectSeq) || o.expectSeq < 0) throw new Error("expectSeq must be a non-negative integer");
      mref = await this.uploadChunk(u.namespace, mbytes, o.class);
      prev = o.expectSeq;
    } else {
      // Independent: upload the manifest chunk while reading the current seq.
      const [m, h] = await Promise.all([this.uploadChunk(u.namespace, mbytes, o.class), this.#headUnchecked(u)]);
      mref = m;
      prev = h?.record.seq ?? 0;
    }
    let maybeLanded = false;
    let conflicts = 0;
    let attempt = 0;
    for (;;) {
      const unsigned = {
        namespace: u.namespace,
        path: u.path,
        manifest_cid: mref.cid,
        size: manifest.size,
        stored_size: stored,
        seq: prev + 1,
        writer: this.accountId,
        writer_pk: myPk,
        ts_ms: this.#nowMs(),
      };
      const rec: PointerRecord = { ...unsigned, sig: sign(seed, recordSigningBytes(unsigned)) };
      // Same class header as the chunks: the gateway records it in the index.
      let r: Resp | undefined;
      let a: Attempt<never> | undefined;
      try {
        r = await this.#send("PUT", objPath(u), "", new TextEncoder().encode(recordToJson(rec)), { class: o.class });
      } catch (e) {
        a = transport(e);
      }
      if (r) {
        if (r.ok) return rec;
        if (r.status === 409) {
          const cur = await this.#headUnchecked(u);
          if (cur && maybeLanded && cur.record.manifest_cid === mref.cid && cur.record.writer_pk === myPk && cur.record.seq === prev + 1) {
            return cur.record;
          }
          if (o.expectSeq !== undefined) throw new ConflictError(u.toString(), cur?.record.seq ?? 0);
          if (++conflicts >= 2) throw new Error(`concurrent write conflict on ${u}`);
          prev = cur?.record.seq ?? 0;
          continue;
        }
        a = reject(r);
      }
      if (!a || "done" in a) throw new Error("unreachable");
      if ("fatal" in a) throw a.fatal;
      maybeLanded = true;
      attempt++;
      if (attempt >= Math.max(1, this.#net.attempts)) {
        debug(`committing ${u}: giving up after ${attempt} attempts`);
        throw a.retry;
      }
      await sleep(retryDelay(this.#net, attempt - 1, a.waitMs));
    }
  }

  /** Fetch a chunk through the gateway (signed, retried), verifying its cid. */
  async fetchViaGateway(uri: string | NearUri, cid: string, idx: number, len: number): Promise<Uint8Array> {
    const u = NearUri.from(uri);
    // `i` goes into the signed query so concurrent fetches of a repeated chunk never share a signature.
    const q = `chunk=${cid}&i=${idx}`;
    return withRetries(this.#net, `fetch chunk ${idx}`, async () => {
      let r: Resp;
      try {
        r = await this.#send("GET", objPath(u), q, undefined, { xfer: len });
      } catch (e) {
        return transport(e);
      }
      if (!r.ok) return reject(r);
      // corrupted or truncated in transit: fetch again
      if (cidOf(r.body) !== cid) return { retry: new Error(`chunk ${cid} content does not match its id`) };
      return done(r.body);
    });
  }

  /** Stored (possibly encrypted) chunk `idx` of a located object: inlined bytes, else direct URL, else the gateway. */
  async fetchChunk(uri: string | NearUri, loc: Located, idx: number): Promise<Uint8Array> {
    const c = loc.manifest.chunks[idx];
    if (!c) throw new Error(`no chunk ${idx}`);
    const lc = loc.chunks[idx];
    if (lc?.data !== undefined) {
      try {
        const b = b64N(lc.data, undefined, "inlined chunk");
        if (cidOf(b) === c.cid) return b;
      } catch {
        /* fall through */
      }
      debug(`inlined chunk ${c.cid} is invalid; fetching it`);
    }
    if (lc?.url !== undefined && !(lc.expires_ms !== undefined && lc.expires_ms < Date.now() + URL_MIN_REMAINING_MS)) {
      try {
        const r = await fetchFully(this.#fetch, lc.url, { method: "GET" }, timeoutFor(this.#net, c.len), this.#net.idleTimeoutMs);
        if (r.status === 200 && cidOf(r.body) === c.cid) return r.body;
        debug(`direct fetch of ${c.cid}: HTTP ${r.status} or wrong content; using gateway`);
      } catch (e) {
        debug(`direct fetch of ${c.cid}: ${errMsg(e)}; using gateway`);
      }
    }
    return this.fetchViaGateway(uri, c.cid, idx, c.len);
  }

  /** Fetch, verify and decrypt chunk `idx` of a located object. */
  async readChunk(uri: string | NearUri, loc: Located, idx: number, opener: ChunkOpener | null = this.opener(loc.manifest)): Promise<Uint8Array> {
    const ct = await this.fetchChunk(uri, loc, idx);
    const m = loc.manifest;
    const pt = opener ? opener.open(idx, idx + 1 === m.chunks.length, ct) : ct;
    const expect = chunkPlainLen(m.size, m.chunk_size, idx);
    if (pt.length !== expect) throw new Error(`chunk ${idx} has ${pt.length} plaintext bytes, expected ${expect}`);
    return pt;
  }

  /** Download, verify and decrypt. Small objects come inlined in one request. */
  async getObject(uri: string | NearUri): Promise<{ head: ObjectHead; data: Uint8Array }> {
    const u = NearUri.from(uri);
    const loc = await this.locate(u);
    if (!loc) throw new GatewayError(404, `${u} not found`);
    const chunks = await mapLimit(loc.manifest.chunks, this.parallelism, (_, i) => this.fetchChunk(u, loc, i));
    let data: Uint8Array;
    if (!loc.manifest.enc) {
      data = concat(chunks);
    } else {
      if (!this.#root) throw new Error("object is encrypted and no root key is loaded");
      data = decryptObject(this.#root, loc.manifest.enc, chunks);
    }
    if (data.length !== loc.manifest.size) throw new Error("size mismatch");
    const { chunks: _, ...head } = loc;
    return { head, data };
  }

  async get(uri: string | NearUri): Promise<Uint8Array> {
    return (await this.getObject(uri)).data;
  }

  async getText(uri: string | NearUri): Promise<string> {
    return new TextDecoder().decode(await this.get(uri));
  }

  /**
   * Every readable object whose path starts with the prefix URI's path (a raw
   * string prefix, e.g. `near://alice.near/memory/`), sorted by path:
   * {@link listPage} until the end.
   */
  async list(prefix: string | NearUri): Promise<ListEntry[]> {
    const out: ListEntry[] = [];
    let cursor: string | undefined;
    for (;;) {
      const page = await this.listPage(prefix, { cursor });
      out.push(...page.entries);
      if (page.next_cursor == null) return out;
      if (page.next_cursor === cursor) throw new Error(`gateway listing of ${String(prefix)} did not advance`);
      cursor = page.next_cursor;
    }
  }

  /**
   * One page of the listing. With `delimiter` (normally `/`) deeper paths are
   * rolled up into `common_prefixes`. Pass the previous page's `next_cursor` as
   * `cursor`; `limit` defaults to (and is capped at) 1000 by the gateway. Pages
   * may hold fewer items than the limit; continue while `next_cursor` is set.
   */
  async listPage(prefix: string | NearUri, opts: ListPageOptions = {}): Promise<ListPage> {
    const u = NearUri.from(prefix);
    let q = `prefix=${encodePath(u.path)}`;
    if (opts.delimiter) q += `&delimiter=${encodePath(opts.delimiter)}`;
    if (opts.cursor) q += `&cursor=${encodePath(opts.cursor)}`;
    if (opts.limit !== undefined) q += `&limit=${opts.limit}`;
    const raw = (await this.#getJson("list", `/v1/list/${u.namespace}`, q)) as Partial<ListPage> | null;
    return { entries: raw?.entries ?? [], common_prefixes: raw?.common_prefixes ?? [], next_cursor: raw?.next_cursor ?? null };
  }

  /** Delete `uri`. Retried; a 404 after a failed attempt means that attempt already deleted it. */
  async delete(uri: string | NearUri): Promise<void> {
    await this.#delete(NearUri.from(uri));
  }

  /** Delete `uri` only if its current version is `seq`; otherwise {@link ConflictError}. */
  async deleteIf(uri: string | NearUri, seq: number): Promise<void> {
    if (!Number.isSafeInteger(seq) || seq < 0) throw new Error("seq must be a non-negative integer");
    await this.#delete(NearUri.from(uri), seq);
  }

  async #delete(u: NearUri, seq?: number): Promise<void> {
    const q = seq === undefined ? "" : `seq=${seq}`;
    await withRetries(this.#net, "delete", async (attempt) => {
      let r: Resp;
      try {
        r = await this.#send("DELETE", objPath(u), q);
      } catch (e) {
        return transport(e);
      }
      if (r.status === 404 && attempt > 0) return done(undefined);
      if (r.status === 409 && seq !== undefined) {
        const m = /current seq is (\d+)/.exec(new TextDecoder().decode(r.body));
        return { fatal: new ConflictError(u.toString(), m ? Number(m[1]) : 0) };
      }
      return r.ok ? done(undefined) : reject(r);
    });
  }

  /**
   * Re-wrap the object key of `uri` to `recipient` (`x25519:<base58>`). Chunks
   * are reused (so the object keeps its storage class); only a new manifest and
   * record are written. The recipient also needs read access via namespace policy.
   */
  async share(uri: string | NearUri, recipient: string): Promise<PointerRecord> {
    if (!this.#root) throw new Error("sharing requires the root key");
    const u = NearUri.from(uri);
    const head = await this.head(u);
    if (!head) throw new GatewayError(404, `${u} not found`);
    if (!head.manifest.enc) throw new Error(`${u} is public; nothing to share`);
    parseX25519(recipient);
    const enc = addRecipient(this.#root, head.manifest.enc, recipient);
    return this.commitManifest(u, { ...head.manifest, enc }, { class: head.class });
  }
}

/**
 * Client-side checks on what a (possibly untrusted) gateway returned: record signature,
 * manifest, and (via `check`) that the writer was allowed to write it with that key.
 */
export async function verifyHead(uri: NearUri, head: ObjectHead, check: WriterCheck | undefined): Promise<void> {
  checkHead(uri, head);
  if (!check) throw new Error(NO_WRITER_CHECK);
  await check.verify(head.record);
}

/** Everything but the writer check. */
function checkHead(uri: NearUri, head: ObjectHead): void {
  const r = head.record;
  if (!r || r.namespace !== uri.namespace || r.path !== uri.path) throw new Error("gateway returned a record for a different object");
  verifyRecordSignature(r);
  if (head.manifest_raw !== undefined) {
    // Hash the stored bytes, not a re-serialization: robust to manifest fields
    // this SDK does not know yet.
    const bytes = b64N(head.manifest_raw, undefined, "manifest_raw");
    if (cidOf(bytes) !== r.manifest_cid) throw new Error("manifest does not match record");
    const parsed = normalizeManifest(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
    if (bytesToHex(manifestToBytes(parsed)) !== bytesToHex(manifestToBytes(head.manifest))) throw new Error("manifest_raw does not match manifest");
  } else if (manifestCid(head.manifest) !== r.manifest_cid) {
    throw new Error("manifest does not match record");
  }
  validateManifest(head.manifest);
  if (head.manifest.size !== r.size) throw new Error("record size does not match manifest");
}
