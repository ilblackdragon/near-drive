/** Node-only helpers: NEAR credential files, local root keys, file upload/download. */
import { readFile, writeFile, mkdir, open, realpath, rename, rm, stat, type FileHandle } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex, cid as cidOf } from "./bytes.js";
import { Client, ConflictError, mapLimit, type ClientOptions, type ObjectHead, type PutOptions } from "./client.js";
import { chunkPlainLen, RootKey, type ChunkOpener, type ChunkSealer, type EncInfo } from "./crypto.js";
import { parseSecretKey, publicKeyOf } from "./keys.js";
import type { ChunkRef, Manifest } from "./manifest.js";
import { debug } from "./net.js";
import type { PointerRecord } from "./record.js";
import { NearUri } from "./uri.js";

export interface NearCredentials {
  account_id: string;
  public_key: string;
  private_key: string;
}

/** Load `~/.near-credentials/<network>/<account>.json` (or any file in that format). */
export async function loadCredentials(path: string): Promise<NearCredentials> {
  const c = JSON.parse(await readFile(path, "utf8")) as NearCredentials;
  if (publicKeyOf(parseSecretKey(c.private_key)) !== c.public_key) throw new Error("credentials file public_key does not match private_key");
  return c;
}

export function defaultCredentialsPath(account: string, network = "mainnet"): string {
  return join(homedir(), ".near-credentials", network, `${account}.json`);
}

/** Where `near drive keygen` keeps root keys: `$NEAR_DRIVE_HOME/keys/<account>.root` (default `~/.near-drive`). */
export function defaultRootKeyPath(account: string, home = process.env.NEAR_DRIVE_HOME ?? join(homedir(), ".near-drive")): string {
  return join(home, "keys", `${account}.root`);
}

export async function loadRootKey(path: string): Promise<RootKey | undefined> {
  try {
    return RootKey.fromHex(await readFile(path, "utf8"));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw e;
  }
}

/** Create a new root key file (mode 0600); refuses to overwrite. */
export async function generateRootKeyFile(path: string): Promise<RootKey> {
  const k = RootKey.generate();
  await mkdir(dirname(path), { recursive: true });
  const f = await open(path, "wx", 0o600);
  try {
    await f.writeFile(k.toHex());
  } finally {
    await f.close();
  }
  return k;
}

/** Client from a credentials file plus the account's local root key (if any), like `near-drive`. */
export async function clientFromFiles(
  o: { gateway: string; credentials: string; rootKey?: string } & Pick<ClientOptions, "chunkSize" | "parallelism" | "net" | "fetch" | "writerCheck" | "rpcUrl" | "contractId">,
): Promise<Client> {
  const c = await loadCredentials(o.credentials);
  const root = await loadRootKey(o.rootKey ?? defaultRootKeyPath(c.account_id));
  const opts: ClientOptions = {
    gateway: o.gateway,
    accountId: c.account_id,
    signer: c.private_key,
    rootKey: root,
    chunkSize: o.chunkSize,
    parallelism: o.parallelism,
    net: o.net,
    fetch: o.fetch,
    writerCheck: o.writerCheck,
    rpcUrl: o.rpcUrl,
    contractId: o.contractId,
  };
  return new Client(opts);
}


export interface PutFileOptions extends PutOptions {
  /**
   * Keep an upload journal in this directory so an interrupted upload of the
   * same file to the same URI resumes instead of starting over (unset = off).
   * Encrypted uploads resume only when encrypted to the client's own root key (not with `skipOwnerKey: true`).
   */
  resumeDir?: string;
}

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Wrap a failure with a hint, keeping {@link ConflictError} as is. */
function interrupted(e: unknown, msg: string): Error {
  if (e instanceof ConflictError) return e;
  return new Error(`${msg}: ${errMsg(e)}`, { cause: e });
}

/** Read up to `n` bytes at `pos` (fewer only at EOF). */
async function readAt(fh: FileHandle, n: number, pos: number): Promise<Uint8Array> {
  const buf = new Uint8Array(n);
  let filled = 0;
  while (filled < n) {
    const { bytesRead } = await fh.read(buf, filled, n - filled, pos + filled);
    if (bytesRead === 0) break;
    filled += bytesRead;
  }
  return filled === n ? buf : buf.subarray(0, filled);
}

async function writeAt(fh: FileHandle, b: Uint8Array, pos: number): Promise<void> {
  let off = 0;
  while (off < b.length) off += (await fh.write(b, off, b.length - off, pos + off)).bytesWritten;
}

// ---- upload journal (same layout as the Rust client's resume.rs) ----
//
// {"header": {account, uri, src, size, mtime_ns, chunk_size, public, class, share_with, content_type, enc}}
// {"i": 7, "ph": "<blake3 hex of chunk 7's plaintext>"}   before chunk 7 is sent (fsynced)
// {"i": 7, "cid": "b3:...", "len": 65552}                 after the gateway stored it

interface JournalKey {
  account: string;
  uri: string;
  src: string;
  size: number;
  /** Nanoseconds; serialized as an exact integer. */
  mtime_ns: bigint;
  chunk_size: number;
  public: boolean;
  class: string | null;
  share_with: string[];
  content_type: string | null;
}

const KEY_FIELDS = ["account", "uri", "src", "size", "mtime_ns", "chunk_size", "public", "class", "share_with", "content_type"] as const;

/** JSON with bigints written as plain integers (like serde's u64). */
function toJson(v: unknown): string {
  const marks: string[] = [];
  const s = JSON.stringify(v, (_, x) => (typeof x === "bigint" ? `\u0000${marks.push(x.toString()) - 1}\u0000` : x));
  return s.replace(/"\\u0000(\d+)\\u0000"/g, (_, i: string) => marks[Number(i)]!);
}

function plainHash(pt: Uint8Array): string {
  return bytesToHex(blake3(pt));
}

interface Resumed {
  enc: EncInfo | null;
  dispatched: Map<number, string>;
  done: Map<number, ChunkRef>;
}

async function journalKey(account: string, uri: string, src: string, chunkSize: number, o: PutFileOptions): Promise<JournalKey> {
  const real = await realpath(src);
  const st = await stat(real, { bigint: true });
  return {
    account,
    uri,
    src: real,
    size: Number(st.size),
    mtime_ns: st.mtimeNs,
    chunk_size: chunkSize,
    public: !!o.public,
    class: o.class ?? null,
    share_with: o.shareWith ?? [],
    content_type: o.contentType ?? null,
  };
}

function journalPath(dir: string, k: JournalKey): string {
  const id = bytesToHex(blake3(new TextEncoder().encode(`${k.account}\n${k.uri}\n${k.src}`)));
  return join(dir, `${id.slice(0, 32)}.jsonl`);
}

/** Load a journal for exactly this upload; null if absent or for something else. */
async function loadJournal(path: string, key: JournalKey): Promise<Resumed | null> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch {
    return null;
  }
  const lines = text.split("\n");
  let header: Record<string, unknown>;
  try {
    header = (JSON.parse(lines[0]!) as { header: Record<string, unknown> }).header;
  } catch {
    return null;
  }
  // Compare through the same JSON round trip (mtime_ns may exceed 2^53 either way).
  const mine = JSON.parse(toJson(key)) as Record<string, unknown>;
  for (const f of KEY_FIELDS) if (JSON.stringify(header[f] ?? null) !== JSON.stringify(mine[f] ?? null)) return null;
  const r: Resumed = { enc: (header.enc as EncInfo | null) ?? null, dispatched: new Map(), done: new Map() };
  // A torn final line (crash mid-write) fails to parse and is ignored.
  for (const l of lines.slice(1)) {
    let o: { i?: unknown; ph?: unknown; cid?: unknown; len?: unknown };
    try {
      o = JSON.parse(l);
    } catch {
      continue;
    }
    if (typeof o.i !== "number") continue;
    if (typeof o.cid === "string" && typeof o.len === "number") r.done.set(o.i, { cid: o.cid, len: o.len });
    else if (typeof o.ph === "string") r.dispatched.set(o.i, o.ph);
  }
  // Only trust "done" for chunks whose plaintext hash was journaled first.
  for (const i of [...r.done.keys()]) if (!r.dispatched.has(i)) r.done.delete(i);
  return r;
}

/** Every journaled chunk's plaintext hash still matches the file. */
async function fileUnchanged(src: string, chunkSize: number, r: Resumed): Promise<boolean> {
  const fh = await open(src, "r");
  try {
    const len = (await fh.stat()).size;
    for (const [i, ph] of r.dispatched) {
      const n = chunkPlainLen(len, chunkSize, i);
      const b = await readAt(fh, n, i * chunkSize);
      if (b.length !== n || plainHash(b) !== ph) return false;
    }
    return true;
  } finally {
    await fh.close();
  }
}

class Journal {
  #chain: Promise<void> = Promise.resolve();
  private constructor(
    readonly path: string,
    readonly fh: FileHandle,
  ) {}

  static async create(path: string, key: JournalKey, enc: EncInfo | null): Promise<Journal> {
    await mkdir(dirname(path), { recursive: true });
    const fh = await open(path, "w");
    await fh.write(toJson({ header: { ...key, enc } }) + "\n");
    await fh.datasync();
    return new Journal(path, fh);
  }

  static async append(path: string): Promise<Journal> {
    return new Journal(path, await open(path, "a"));
  }

  #write(line: unknown, sync: boolean): Promise<void> {
    const p = this.#chain.then(async () => {
      await this.fh.write(JSON.stringify(line) + "\n");
      if (sync) await this.fh.datasync();
    });
    this.#chain = p.catch(() => {});
    return p;
  }

  /** Before chunk `i` is sealed and sent: durable, so a resume can never seal different plaintext under this index. */
  dispatched(i: number, ph: string): Promise<void> {
    return this.#write({ i, ph }, true);
  }

  done(i: number, r: ChunkRef): Promise<void> {
    return this.#write({ i, cid: r.cid, len: r.len }, false);
  }

  async close(): Promise<void> {
    await this.#chain;
    await this.fh.close();
  }

  async finish(): Promise<void> {
    await this.close();
    await rm(this.path, { force: true });
  }
}

/**
 * Upload a file with bounded memory (about `(parallelism + 2) * chunkSize`)
 * and `client.parallelism` concurrent chunk uploads. Same wire format as
 * `client.put`. With `opts.resumeDir`, an interrupted upload of the same file
 * to the same URI resumes where it stopped: the object key is reused so
 * unchanged chunks re-encrypt to the same ids and are skipped; if the file
 * changed (even with the same size and mtime) the upload starts over with a
 * fresh key, so a nonce is never reused for different bytes.
 */
export async function putFile(client: Client, src: string, uri: string | NearUri, opts: PutFileOptions = {}): Promise<PointerRecord> {
  const u = NearUri.from(uri);
  NearUri.object(u.namespace, u.path);
  const fh = await open(src, "r");
  try {
    // Resuming an encrypted upload needs the owner's key to recover the object key.
    if (!opts.resumeDir || (!opts.public && opts.skipOwnerKey)) {
      return await putStream(client, fh, u, opts, client.newSealer(opts), null, new Map());
    }
    const key = await journalKey(client.accountId, u.toString(), src, client.chunkSize, opts);
    const jpath = journalPath(opts.resumeDir, key);
    let resumed = await loadJournal(jpath, key);
    if (resumed && !(await fileUnchanged(key.src, key.chunk_size, resumed))) {
      debug("file changed since the interrupted upload; starting over");
      resumed = null;
    }
    let sealer: ChunkSealer | null;
    let journal: Journal;
    let done: Map<number, ChunkRef>;
    if (resumed) {
      sealer = resumed.enc ? client.reopenSealer(resumed.enc) : null;
      if (resumed.done.size > 0) debug(`resuming upload of ${u}: ${resumed.done.size} chunks already stored`);
      journal = await Journal.append(jpath);
      done = resumed.done;
    } else {
      sealer = client.newSealer(opts);
      journal = await Journal.create(jpath, key, sealer?.encInfo ?? null);
      done = new Map();
    }
    let rec: PointerRecord;
    try {
      rec = await putStream(client, fh, u, opts, sealer, journal, done);
    } catch (e) {
      await journal.close().catch(() => {});
      throw interrupted(e, `upload of ${u} interrupted; run it again to resume`);
    }
    await journal.finish();
    return rec;
  } finally {
    await fh.close();
  }
}

async function putStream(
  client: Client,
  fh: FileHandle,
  u: NearUri,
  opts: PutOptions,
  sealer: ChunkSealer | null,
  journal: Journal | null,
  done: Map<number, ChunkRef>,
): Promise<PointerRecord> {
  const cs = client.chunkSize;
  const seen = new Set<string>();
  const refs: ChunkRef[] = [];
  let size = 0;

  const one = async (idx: number, last: boolean, pt: Uint8Array): Promise<void> => {
    const prev = done.get(idx);
    if (prev) {
      seen.add(prev.cid);
      refs[idx] = prev;
      return;
    }
    if (journal) await journal.dispatched(idx, plainHash(pt));
    const ct = sealer ? sealer.seal(idx, last, pt) : pt;
    const cid = cidOf(ct);
    if (seen.has(cid)) {
      refs[idx] = { cid, len: ct.length };
      return;
    }
    seen.add(cid);
    const r = await client.uploadChunk(u.namespace, ct, opts.class);
    if (journal) await journal.done(idx, r);
    refs[idx] = r;
  };

  const inflight = new Set<Promise<void>>();
  let failure: { e: unknown } | null = null;
  const launch = (p: Promise<void>) => {
    const t = p.catch((e) => {
      failure ??= { e };
    });
    const tracked = t.finally(() => inflight.delete(tracked));
    inflight.add(tracked);
  };
  // One chunk of read-ahead to know which chunk is the last.
  let pos = 0;
  let cur = await readAt(fh, cs, pos);
  pos += cur.length;
  for (let idx = 0; ; idx++) {
    const next = cur.length < cs ? new Uint8Array(0) : await readAt(fh, cs, pos);
    pos += next.length;
    const last = next.length === 0;
    size += cur.length;
    launch(one(idx, last, cur));
    while (inflight.size >= Math.max(1, client.parallelism) && !failure) await Promise.race(inflight);
    if (failure || last) break;
    cur = next;
  }
  await Promise.all(inflight);
  if (failure) throw (failure as { e: unknown }).e;

  const manifest: Manifest = { version: 1, size, chunk_size: cs, chunks: refs };
  if (sealer) manifest.enc = sealer.encInfo;
  if (opts.contentType !== undefined) manifest.content_type = opts.contentType;
  return client.commitManifest(u, manifest, { class: opts.class, expectSeq: opts.expectSeq });
}

/** For each chunk: are the bytes at its offset in the file exactly that chunk? (Re-derive its cid.) */
async function chunksOnDisk(fh: FileHandle, m: Manifest, opener: ChunkOpener | null): Promise<boolean[]> {
  const n = m.chunks.length;
  const have: boolean[] = [];
  for (let i = 0; i < n; i++) {
    const len = chunkPlainLen(m.size, m.chunk_size, i);
    const b = await readAt(fh, len, i * m.chunk_size);
    if (b.length !== len) {
      have.push(false);
      continue;
    }
    const ct = opener ? opener.reseal(i, i + 1 === n, b) : b;
    have.push(cidOf(ct) === m.chunks[i]!.cid);
  }
  return have;
}

/**
 * Download to `dst` with `client.parallelism` concurrent chunk fetches
 * (inlined data and direct URLs preferred). Writes `{dst}.drive-part` and
 * renames it into place when complete.
 *
 * Resumable: if a download fails, the part file and `{dst}.drive-part.json`
 * stay. The next call for the same version of the object checks every chunk
 * already on disk (by re-deriving its cid from the bytes) and fetches only
 * the missing or damaged ones. A newer version starts over.
 */
export async function getFile(client: Client, uri: string | NearUri, dst: string): Promise<ObjectHead> {
  const u = NearUri.from(uri);
  const loc = await client.locate(u);
  if (!loc) throw new Error(`${u} not found`);
  const opener = client.opener(loc.manifest);
  const part = `${dst}.drive-part`;
  const metaPath = `${dst}.drive-part.json`;
  const meta = { uri: u.toString(), manifest_cid: loc.record.manifest_cid, size: loc.manifest.size };
  let resumable = false;
  try {
    await stat(part);
    const m = JSON.parse(await readFile(metaPath, "utf8")) as Record<string, unknown>;
    resumable = m.uri === meta.uri && m.manifest_cid === meta.manifest_cid && m.size === meta.size;
  } catch {
    resumable = false;
  }
  let fh: FileHandle;
  if (resumable) {
    fh = await open(part, "r+");
  } else {
    fh = await open(part, "w+");
    await writeFile(metaPath, JSON.stringify(meta));
  }
  try {
    await fh.truncate(loc.manifest.size);
    const n = loc.manifest.chunks.length;
    const have = resumable ? await chunksOnDisk(fh, loc.manifest, opener) : new Array<boolean>(n).fill(false);
    if (resumable) debug(`resuming download of ${u}: ${have.filter(Boolean).length}/${n} chunks already on disk`);
    const cs = loc.manifest.chunk_size;
    const todo = have.flatMap((h, i) => (h ? [] : [i]));
    try {
      await mapLimit(todo, client.parallelism, async (i) => {
        const pt = await client.readChunk(u, loc, i, opener);
        await writeAt(fh, pt, i * cs);
      });
    } catch (e) {
      await fh.datasync().catch(() => {});
      throw interrupted(e, `download of ${u} interrupted; partial data kept in ${part}, run it again to resume`);
    }
    await fh.sync();
  } finally {
    await fh.close();
  }
  await rename(part, dst);
  await rm(metaPath, { force: true });
  const { chunks: _, ...head } = loc;
  return head;
}

/** Same as {@link getFile}. */
export const getToFile = getFile;
