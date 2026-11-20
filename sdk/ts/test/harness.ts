/**
 * Test harness for bad networks:
 * - `fakeGateway()`: an in-memory gateway (fetch implementation) with the
 *   same CAS / locate / delete-if semantics as the real one (no auth checks);
 * - `realGateway()`: the `near-drive-gateway` binary on 127.0.0.1 (if built);
 * - `faulty(fetch)`: injects faults like the Rust `tests/resilience.rs` proxy.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { base64 } from "@scure/base";
import { cid, generateSecretKey, publicKeyOf, parseSecretKey } from "../src/index.js";

export type Mode =
  | { kind: "pass" }
  /** request k: k%4==1 -> 503; k%4==2 -> forwarded, but the response is lost (non-GET: 502) or cut off halfway (GET). */
  | { kind: "flaky" }
  /** chunk transfers after the first `n` fail with 503 (a dead link). */
  | { kind: "cutAfter"; n: number };

export interface Faulty {
  fetch: typeof fetch;
  set(m: Mode): void;
  /** Requests seen since the last `set`. */
  requests: number;
  chunkPuts: number;
  chunkGets: number;
  k: number;
  log: { method: string; url: string; headers: Record<string, string>; status: number }[];
}

const injected = (status: number) => new Response("injected", { status, headers: { "retry-after": "0" } });

/** A body that delivers the first half, then fails like a reset connection. */
function cutOff(bytes: Uint8Array): ReadableStream<Uint8Array> {
  let sent = false;
  return new ReadableStream({
    pull(c) {
      if (!sent) {
        sent = true;
        c.enqueue(bytes.slice(0, bytes.length >> 1));
      } else c.error(new TypeError("terminated: connection reset"));
    },
  });
}

export function faulty(inner: typeof fetch): Faulty {
  const st: Faulty = {
    fetch: null as unknown as typeof fetch,
    set(m) {
      mode = m;
      st.requests = st.chunkPuts = st.chunkGets = st.k = 0;
      chunkOps = 0;
      st.log = [];
    },
    requests: 0,
    chunkPuts: 0,
    chunkGets: 0,
    k: 0,
    log: [],
  };
  let mode: Mode = { kind: "pass" };
  let chunkOps = 0;
  st.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const u = new URL(url);
    const isChunkPut = method === "PUT" && u.pathname.startsWith("/v1/chunk/");
    const isChunkGet = method === "GET" && u.search.includes("chunk=");
    st.requests++;
    const k = st.k++;
    const headers = Object.fromEntries(new Headers(init?.headers).entries());
    const rec = { method, url, headers, status: 0 };
    st.log.push(rec);
    if (mode.kind === "flaky" && k % 4 === 1) return (rec.status = 503), injected(503);
    if (mode.kind === "cutAfter" && (isChunkPut || isChunkGet) && chunkOps++ >= mode.n) return (rec.status = 503), injected(503);
    const r = await inner(url, init);
    const bytes = new Uint8Array(await r.arrayBuffer());
    rec.status = r.status;
    if (r.ok) {
      if (isChunkPut) st.chunkPuts++;
      if (isChunkGet) st.chunkGets++;
    }
    if (mode.kind === "flaky" && k % 4 === 2) {
      if (method !== "GET") return (rec.status = 502), injected(502); // it happened upstream; the client doesn't know
      return new Response(cutOff(bytes), { status: r.status });
    }
    const h = new Headers(r.headers);
    h.delete("content-length");
    h.delete("content-encoding");
    h.delete("transfer-encoding");
    return new Response(r.status === 204 ? null : bytes, { status: r.status, headers: h });
  }) as typeof fetch;
  return st;
}

// ---------------------------------------------------------------------------
// In-memory gateway

interface Entry {
  record: Record<string, unknown> & { seq: number; manifest_cid: string; size: number };
  class: string | null;
}

export interface FakeGateway {
  url: string;
  fetch: typeof fetch;
  chunks: Map<string, Uint8Array>;
  index: Map<string, Entry>;
  /** Objects with at most this many stored bytes get their chunks inlined by `locate`. */
  inlineMax: number;
}

const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });
const text = (s: string, status: number) => new Response(s, { status });

export function fakeGateway(): FakeGateway {
  const g: FakeGateway = { url: "http://fake.gateway", fetch: null as unknown as typeof fetch, chunks: new Map(), index: new Map(), inlineMax: 64 * 1024 };
  const manifestOf = (e: Entry) => {
    const raw = g.chunks.get(e.record.manifest_cid);
    if (!raw) throw new Error("manifest missing");
    return { raw, m: JSON.parse(new TextDecoder().decode(raw)) as { chunks: { cid: string; len: number }[] } };
  };
  g.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    // A little latency jitter, like a real network (an instant server lets
    // parallel workers fall into lockstep with the proxy's k%4 fault pattern).
    await new Promise((r) => setTimeout(r, Math.random() * 3));
    if (init?.signal?.aborted) throw init.signal.reason;
    const u = new URL(String(input));
    const method = init?.method ?? "GET";
    const body = init?.body ? new Uint8Array(init.body as Uint8Array) : new Uint8Array(0);
    const headers = new Headers(init?.headers);
    const q = u.searchParams;
    let m: RegExpExecArray | null;
    if ((m = /^\/v1\/chunk\/([^/]+)\/(b3:[0-9a-f]{64})$/.exec(u.pathname)) && method === "PUT") {
      if (cid(body) !== m[2]) return text("cid mismatch", 400);
      g.chunks.set(m[2]!, body);
      return text("", 200);
    }
    if ((m = /^\/v1\/list\/([^/]+)$/.exec(u.pathname)) && method === "GET") {
      const ns = m[1]!;
      const prefix = q.get("prefix") ?? "";
      const delim = q.get("delimiter") || null;
      const cursor = q.get("cursor") || null;
      const limit = Math.min(Math.max(Number(q.get("limit") ?? 1000) || 1000, 1), 1000);
      const paths = [...g.index.keys()]
        .filter((k) => k.startsWith(`${ns}/${prefix}`))
        .map((k) => k.slice(ns.length + 1))
        .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
      const entries: unknown[] = [];
      const common_prefixes: string[] = [];
      let last: string | null = null;
      let next: string | null = null;
      for (const p of paths) {
        if (cursor !== null && (p <= cursor || (delim !== null && cursor.endsWith(delim) && p.startsWith(cursor)))) continue;
        const i = delim === null ? -1 : p.indexOf(delim, prefix.length);
        const cp = i < 0 ? null : p.slice(0, i + delim!.length);
        if (cp !== null && cp === last) continue;
        if (entries.length + common_prefixes.length === limit) {
          next = last;
          break;
        }
        if (cp !== null) {
          common_prefixes.push(cp);
          last = cp;
        } else {
          const e = g.index.get(`${ns}/${p}`)!;
          entries.push({ path: p, size: e.record.size, seq: e.record.seq, writer: e.record.writer, ts_ms: e.record.ts_ms, manifest_cid: e.record.manifest_cid });
          last = p;
        }
      }
      return json({ entries, common_prefixes, next_cursor: next });
    }
    if (!(m = /^\/v1\/o\/([^/]+)\/(.+)$/.exec(u.pathname))) return text("no route", 404);
    const key = `${m[1]}/${decodeURIComponent(m[2]!)}`;
    const cur = g.index.get(key);
    if (method === "PUT") {
      const rec = JSON.parse(new TextDecoder().decode(body)) as Entry["record"];
      if (!g.chunks.has(rec.manifest_cid)) return text("manifest not uploaded", 400);
      const now = cur?.record.seq ?? 0;
      if (rec.seq !== now + 1) return text(`seq conflict: current seq is ${now}`, 409);
      g.index.set(key, { record: rec, class: headers.get("x-near-drive-class") ?? "default" });
      return json({ seq: rec.seq }, 201);
    }
    if (method === "DELETE") {
      if (!cur) return text("not found", 404);
      const s = q.get("seq");
      if (s !== null && Number(s) !== cur.record.seq) return text(`seq conflict: current seq is ${cur.record.seq}`, 409);
      g.index.delete(key);
      return new Response(null, { status: 204 });
    }
    if (method !== "GET") return text("method", 405);
    if (!cur) return text("not found", 404);
    const { raw, m: manifest } = manifestOf(cur);
    const c = q.get("chunk");
    if (c !== null) {
      const b = g.chunks.get(c);
      if (!b) return text("missing", 404);
      return new Response(b, { status: 200, headers: { "content-length": String(b.length) } });
    }
    const head = { record: cur.record, manifest, manifest_raw: base64.encode(raw), class: cur.class };
    if (q.get("mode") !== "locate") return json(head);
    const stored = manifest.chunks.reduce((a, x) => a + x.len, 0);
    const inline = g.inlineMax > 0 && stored <= g.inlineMax;
    const chunks = manifest.chunks.map((x) => ({ cid: x.cid, len: x.len, url: null, expires_ms: null, ...(inline ? { data: base64.encode(g.chunks.get(x.cid)!) } : {}) }));
    return json({ ...head, chunks });
  }) as typeof fetch;
  return g;
}

// ---------------------------------------------------------------------------
// Real gateway

export const GATEWAY_BIN = fileURLToPath(new URL("../../../target/debug/near-drive-gateway", import.meta.url));
export const haveGatewayBin = existsSync(GATEWAY_BIN);

async function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = createServer();
    s.once("error", rej);
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => res(p));
    });
  });
}

export interface RealGateway {
  url: string;
  secretKey: string;
  stop(): void;
}

/** Start the gateway binary on 127.0.0.1 with a dev key for `alice.near`. */
export async function realGateway(): Promise<RealGateway> {
  const dir = mkdtempSync(join(tmpdir(), "drive-ts-gw-"));
  const secretKey = generateSecretKey();
  const pk = publicKeyOf(parseSecretKey(secretKey));
  const port = await freePort();
  const cfg = join(dir, "gw.json");
  writeFileSync(cfg, JSON.stringify({ listen: `127.0.0.1:${port}`, data_dir: join(dir, "data"), dev_keys: { "alice.near": [pk] } }));
  const child: ChildProcess = spawn(GATEWAY_BIN, ["--config", cfg], { stdio: "ignore", env: { ...process.env, RUST_LOG: "warn" } });
  const url = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 200; i++) {
    try {
      await fetch(`${url}/v1/list/alice.near`);
      break;
    } catch {
      if (child.exitCode !== null) throw new Error("gateway exited");
      await new Promise((r) => setTimeout(r, 50));
    }
  }
  return { url, secretKey, stop: () => child.kill() };
}

/** Deterministic pseudo-random bytes. */
export function pattern(seed: number, n: number): Uint8Array {
  const out = new Uint8Array(n);
  let x = (seed * 2654435761) >>> 0 || 1;
  for (let i = 0; i < n; i++) {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    out[i] = x & 0xff;
  }
  return out;
}

export const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
