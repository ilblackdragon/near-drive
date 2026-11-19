import { mkdirSync, readFileSync, existsSync, openSync, writeSync, fsyncSync, closeSync, truncateSync } from "node:fs";
import { dirname } from "node:path";

/** Where a cid lives. */
export type Location =
  /** Stored as its own backend object. */
  | { kind: "direct"; size: number; backend_id: string }
  /** Stored inside a pack object at [offset, offset+size). */
  | { kind: "packed"; size: number; backend_id: string; offset: number }
  /** Durably staged on local disk, waiting to be packed. */
  | { kind: "staged"; size: number };

export interface IndexRecord {
  cid: string;
  loc: Location;
  ts: number;
}

/**
 * Append-only JSON-lines index cid → location. The last record for a cid
 * wins. Every append is fsynced before the PUT is acknowledged. Small and
 * dependency-free; at ~150 B/record, 10M chunks ≈ 1.5 GB of log, at which
 * point swap in SQLite behind the same interface.
 */
export class JsonlIndex {
  private readonly map = new Map<string, Location>();
  private fd = -1;

  constructor(readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
    if (existsSync(path)) {
      const buf = readFileSync(path);
      let pos = 0;
      let good = 0; // byte length of the valid prefix
      let lineNo = 0;
      while (pos < buf.length) {
        const nl = buf.indexOf(0x0a, pos);
        const end = nl === -1 ? buf.length : nl;
        const line = buf.subarray(pos, end).toString("utf8");
        lineNo++;
        if (line.trim()) {
          try {
            if (nl === -1) throw new Error("unterminated line");
            const r = JSON.parse(line) as IndexRecord;
            this.map.set(r.cid, r.loc);
          } catch (e) {
            // Only a torn final record (crash mid-append) is tolerated; drop it.
            if (buf.subarray(end).toString("utf8").trim()) {
              throw new Error(`corrupt index ${path} line ${lineNo}: ${(e as Error).message}`);
            }
            truncateSync(path, good);
            break;
          }
        }
        pos = end + 1;
        good = Math.min(pos, buf.length);
      }
    }
    this.fd = openSync(path, "a");
  }

  get(cid: string): Location | undefined {
    return this.map.get(cid);
  }

  entries(): IterableIterator<[string, Location]> {
    return this.map.entries();
  }

  get size(): number {
    return this.map.size;
  }

  append(records: { cid: string; loc: Location }[]): void {
    if (records.length === 0) return;
    const ts = Date.now();
    const text = records.map((r) => JSON.stringify({ cid: r.cid, loc: r.loc, ts }) + "\n").join("");
    writeSync(this.fd, text);
    fsyncSync(this.fd);
    for (const r of records) this.map.set(r.cid, r.loc);
  }

  close(): void {
    if (this.fd < 0) return;
    closeSync(this.fd);
    this.fd = -1;
  }
}
