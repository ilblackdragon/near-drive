import { mkdirSync, openSync, writeSync, fsyncSync, closeSync, renameSync, readFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { BackendNotFound, type BlobBackend, type BlobUrl } from "./backend.js";
import { computeCid } from "./cid.js";
import { JsonlIndex, type Location } from "./index-store.js";
import { sliceRange, type ByteRange } from "./range.js";

export interface PackingOptions {
  /** Blobs smaller than this are staged locally and packed (0 disables packing). */
  thresholdBytes: number;
  /** Flush a pack once this many staged bytes are pending. */
  targetBytes: number;
  /** …or once the oldest staged blob is this old. */
  maxDelayMs: number;
}

export interface BridgeStoreOptions {
  backend: BlobBackend;
  /** Directory for index.jsonl and staging/. */
  dataDir: string;
  packing?: PackingOptions;
  /** Verify blake3 of full-object reads before serving them (default true). */
  verifyReads?: boolean;
  log?: (msg: string) => void;
}

const PACK_MAGIC = new TextEncoder().encode("NSPK");

/**
 * Pack layout: blob_0 ‖ … ‖ blob_n ‖ trailer(JSON) ‖ u32le(trailer len) ‖ "NSPK".
 * The trailer `{"v":1,"entries":[[cid, offset, size], …]}` makes packs
 * self-describing, so the index can be rebuilt from the backend alone.
 */
export function buildPack(blobs: { cid: string; data: Uint8Array }[]): {
  pack: Uint8Array;
  entries: [string, number, number][];
} {
  const entries: [string, number, number][] = [];
  let off = 0;
  for (const b of blobs) {
    entries.push([b.cid, off, b.data.length]);
    off += b.data.length;
  }
  const trailer = new TextEncoder().encode(JSON.stringify({ v: 1, entries }));
  const pack = new Uint8Array(off + trailer.length + 8);
  off = 0;
  for (const b of blobs) {
    pack.set(b.data, off);
    off += b.data.length;
  }
  pack.set(trailer, off);
  new DataView(pack.buffer).setUint32(off + trailer.length, trailer.length, true);
  pack.set(PACK_MAGIC, off + trailer.length + 4);
  return { pack, entries };
}

export function parsePackTrailer(pack: Uint8Array): [string, number, number][] {
  const n = pack.length;
  if (n < 8 || !PACK_MAGIC.every((c, i) => pack[n - 4 + i] === c)) throw new Error("not an NEAR Drive pack");
  const len = new DataView(pack.buffer, pack.byteOffset).getUint32(n - 8, true);
  const t = JSON.parse(new TextDecoder().decode(pack.subarray(n - 8 - len, n - 8))) as { v: number; entries: [string, number, number][] };
  if (t.v !== 1) throw new Error(`unknown pack version ${t.v}`);
  return t.entries;
}

export class NotFound extends Error {}
export class IntegrityError extends Error {}

/**
 * cid-addressed store on top of a backend: maintains the cid → backend-id
 * index, dedups PUTs, and optionally packs small blobs (needed for FOC, where
 * every piece costs a fixed on-chain fee).
 *
 * Durability of a 201: direct blobs are on the backend; staged blobs are
 * fsynced on local disk and reach the backend within `maxDelayMs` (or on
 * `flush()`), with retries.
 */
export class BridgeStore {
  readonly index: JsonlIndex;
  private readonly stagingDir: string;
  private readonly inflight = new Map<string, Promise<boolean>>();
  private pending: string[] = [];
  private pendingBytes = 0;
  private oldestPendingTs = 0;
  private flushing: Promise<void> | null = null;
  private timer: NodeJS.Timeout | null = null;
  private failures = 0;
  private closed = false;
  private readonly log: (m: string) => void;

  constructor(private readonly opts: BridgeStoreOptions) {
    mkdirSync(opts.dataDir, { recursive: true });
    this.index = new JsonlIndex(join(opts.dataDir, "index.jsonl"));
    this.stagingDir = join(opts.dataDir, "staging");
    mkdirSync(this.stagingDir, { recursive: true });
    this.log = opts.log ?? (() => {});
    // Resume staged blobs left over from a previous run.
    for (const [cid, loc] of this.index.entries()) {
      if (loc.kind === "staged") {
        if (existsSync(this.stagedPath(cid))) this.enqueue(cid, loc.size);
        else this.log(`index says ${cid} is staged but the file is gone`);
      }
    }
    this.schedule();
  }

  get backendName(): string {
    return this.opts.backend.name;
  }

  stats() {
    return { objects: this.index.size, pending: this.pending.length, pendingBytes: this.pendingBytes, flushFailures: this.failures };
  }

  locate(cid: string): Location | undefined {
    return this.index.get(cid);
  }

  /** Stores `data` under `cid` (caller has verified the cid). Returns true if newly stored. */
  async put(cid: string, data: Uint8Array): Promise<boolean> {
    if (this.index.get(cid)) return false;
    const existing = this.inflight.get(cid);
    if (existing) return existing.then(() => false);
    const p = this.doPut(cid, data).finally(() => this.inflight.delete(cid));
    this.inflight.set(cid, p);
    return p;
  }

  private async doPut(cid: string, data: Uint8Array): Promise<boolean> {
    const pk = this.opts.packing;
    if (pk && pk.thresholdBytes > 0 && data.length < pk.thresholdBytes) {
      this.writeStaged(cid, data);
      this.index.append([{ cid, loc: { kind: "staged", size: data.length } }]);
      this.enqueue(cid, data.length);
      if (this.pendingBytes >= pk.targetBytes) void this.flush().catch(() => {});
      return true;
    }
    const id = await this.opts.backend.put(cid, data);
    this.index.append([{ cid, loc: { kind: "direct", size: data.length, backend_id: id } }]);
    return true;
  }

  async get(cid: string, range?: ByteRange): Promise<Uint8Array> {
    const loc = this.index.get(cid);
    if (!loc) throw new NotFound(cid);
    let out: Uint8Array;
    try {
      switch (loc.kind) {
        case "staged":
          out = sliceRange(readFileSync(this.stagedPath(cid)), range);
          break;
        case "direct":
          out = await this.opts.backend.get(loc.backend_id, range);
          // Backends may pad tiny objects (FOC's 127-byte minimum piece).
          if (!range && out.length > loc.size) out = out.subarray(0, loc.size);
          break;
        case "packed": {
          const r = range ?? { start: 0, end: loc.size - 1 };
          out = loc.size === 0 ? new Uint8Array() : await this.opts.backend.get(loc.backend_id, { start: loc.offset + r.start, end: loc.offset + r.end });
          break;
        }
      }
    } catch (e) {
      // Staged file may have been packed and removed between lookup and read.
      if (loc.kind === "staged" && (e as NodeJS.ErrnoException).code === "ENOENT") return this.get(cid, range);
      if (e instanceof BackendNotFound) throw new IntegrityError(`${cid}: indexed but missing on ${this.backendName}`);
      throw e;
    }
    const want = range ? range.end - range.start + 1 : loc.size;
    if (out.length !== want) throw new IntegrityError(`${cid}: backend returned ${out.length} bytes, expected ${want}`);
    if (!range && this.opts.verifyReads !== false && computeCid(out) !== cid) {
      throw new IntegrityError(`${cid}: content hash mismatch from ${this.backendName}`);
    }
    return out;
  }

  async url(cid: string): Promise<BlobUrl | null> {
    const loc = this.index.get(cid);
    if (!loc || loc.kind !== "direct" || !this.opts.backend.url) return null;
    return this.opts.backend.url(loc.backend_id);
  }

  /** Packs and uploads everything currently staged. */
  flush(): Promise<void> {
    if (this.flushing) return this.flushing.then(() => (this.pending.length ? this.flush() : undefined));
    this.flushing = this.doFlush().finally(() => {
      this.flushing = null;
      this.schedule();
    });
    return this.flushing;
  }

  private async doFlush(): Promise<void> {
    const target = this.opts.packing?.targetBytes ?? Infinity;
    while (this.pending.length > 0) {
      const batch: string[] = [];
      let bytes = 0;
      for (const cid of this.pending) {
        const size = (this.index.get(cid) as { size: number }).size;
        if (batch.length > 0 && bytes + size > target) break;
        batch.push(cid);
        bytes += size;
      }
      const blobs = batch.map((cid) => ({ cid, data: readFileSync(this.stagedPath(cid)) as Uint8Array }));
      const { pack, entries } = buildPack(blobs);
      const packCid = computeCid(pack);
      let id: string;
      try {
        id = await this.opts.backend.put(`pack-${packCid.slice(3)}`, pack);
      } catch (e) {
        this.failures++;
        this.log(`pack upload of ${batch.length} blobs failed (attempt ${this.failures}): ${(e as Error).message}`);
        throw e;
      }
      this.failures = 0;
      this.index.append(entries.map(([cid, offset, size]) => ({ cid, loc: { kind: "packed", size, backend_id: id, offset } })));
      const done = new Set(batch);
      this.pending = this.pending.filter((c) => !done.has(c));
      this.pendingBytes -= bytes;
      this.oldestPendingTs = this.pending.length ? Date.now() : 0;
      for (const cid of batch) rmSync(this.stagedPath(cid), { force: true });
      this.log(`packed ${batch.length} blobs (${bytes} B) into ${id}`);
    }
  }

  private schedule(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const pk = this.opts.packing;
    if (this.closed || !pk || this.pending.length === 0) return;
    const backoff = this.failures ? Math.min(1000 * 2 ** this.failures, 5 * 60_000) : 0;
    const due = Math.max(0, this.oldestPendingTs + pk.maxDelayMs - Date.now()) + backoff;
    this.timer = setTimeout(() => void this.flush().catch(() => {}), due);
    this.timer.unref();
  }

  private enqueue(cid: string, size: number): void {
    if (this.pending.length === 0) this.oldestPendingTs = Date.now();
    this.pending.push(cid);
    this.pendingBytes += size;
    if (!this.flushing) this.schedule();
  }

  private stagedPath(cid: string): string {
    return join(this.stagingDir, cid.replace(":", "_"));
  }

  private writeStaged(cid: string, data: Uint8Array): void {
    const final = this.stagedPath(cid);
    const tmp = final + ".tmp";
    const fd = openSync(tmp, "w");
    try {
      writeSync(fd, data);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, final);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    if (this.timer) clearTimeout(this.timer);
    if (this.flushing) await this.flushing.catch(() => {});
    this.index.close();
    await this.opts.backend.close?.();
  }
}
