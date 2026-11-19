import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, appendFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  BridgeStore,
  MemoryBackend,
  computeCid,
  parseRange,
  startBridgeServer,
  assertSafeHost,
  buildPack,
  parsePackTrailer,
  JsonlIndex,
  type PackingOptions,
} from "@nstorage/bridge-common";

const bytes = (n: number, seed = 1) => {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 31 + seed * 7) & 0xff;
  return b;
};

let dir: string;
let backend: MemoryBackend;
let store: BridgeStore;
let base: string;
let close: () => Promise<void>;

async function boot(opts: { token?: string; packing?: PackingOptions; maxBodyBytes?: number } = {}) {
  backend = new MemoryBackend();
  store = new BridgeStore({ backend, dataDir: dir, packing: opts.packing });
  const s = await startBridgeServer({ store, token: opts.token, maxBodyBytes: opts.maxBodyBytes });
  base = s.url;
  close = async () => {
    await s.close();
    await store.close();
  };
}

const put = (cid: string, body: Uint8Array, headers: Record<string, string> = {}) =>
  fetch(`${base}/blobs/${cid}`, { method: "PUT", body: body as Uint8Array<ArrayBuffer>, headers });

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "bridge-test-"));
});
afterEach(async () => {
  await close?.();
  close = async () => {};
  rmSync(dir, { recursive: true, force: true });
});

describe("cid", () => {
  it("matches the Rust blake3 hex format", () => {
    // blake3("") from the BLAKE3 reference test vectors.
    expect(computeCid(new Uint8Array())).toBe("b3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    expect(computeCid(new TextEncoder().encode("abc"))).toBe(
      "b3:6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
    );
  });
});

describe("parseRange", () => {
  it.each([
    ["bytes=0-9", 100, { kind: "ok", range: { start: 0, end: 9 } }],
    ["bytes=90-", 100, { kind: "ok", range: { start: 90, end: 99 } }],
    ["bytes=-10", 100, { kind: "ok", range: { start: 90, end: 99 } }],
    ["bytes=-1000", 100, { kind: "ok", range: { start: 0, end: 99 } }],
    ["bytes=50-1000", 100, { kind: "ok", range: { start: 50, end: 99 } }],
    ["bytes=100-", 100, { kind: "unsatisfiable" }],
    ["bytes=-0", 100, { kind: "unsatisfiable" }],
    ["bytes=0-0", 0, { kind: "unsatisfiable" }],
    ["bytes=9-1", 100, { kind: "none" }],
    ["bytes=0-1,5-6", 100, { kind: "none" }],
    ["items=0-1", 100, { kind: "none" }],
    [undefined, 100, { kind: "none" }],
  ] as const)("%s of %d", (h, size, want) => {
    expect(parseRange(h, size)).toEqual(want);
  });
});

describe("host safety", () => {
  it("refuses wildcard binds", () => {
    for (const h of ["0.0.0.0", "::", "[::]", ""]) expect(() => assertSafeHost(h)).toThrow();
    expect(() => assertSafeHost("127.0.0.1")).not.toThrow();
  });
  it("binds loopback by default", async () => {
    await boot();
    expect(base).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
  });
});

describe("HTTP spec (direct)", () => {
  beforeEach(() => boot());

  it("PUT → 201, GET → 200 bytes, HEAD → 200", async () => {
    const data = bytes(1000);
    const cid = computeCid(data);
    const r = await put(cid, data);
    expect(r.status).toBe(201);
    expect(await r.json()).toMatchObject({ cid, size: 1000, created: true });

    const g = await fetch(`${base}/blobs/${cid}`);
    expect(g.status).toBe(200);
    expect(g.headers.get("accept-ranges")).toBe("bytes");
    expect(new Uint8Array(await g.arrayBuffer())).toEqual(data);

    const h = await fetch(`${base}/blobs/${cid}`, { method: "HEAD" });
    expect(h.status).toBe(200);
    expect(h.headers.get("content-length")).toBe("1000");
  });

  it("PUT is idempotent and does not re-upload", async () => {
    const data = bytes(10);
    const cid = computeCid(data);
    expect((await put(cid, data)).status).toBe(201);
    const again = await put(cid, data);
    expect(again.status).toBe(201);
    expect((await again.json()).created).toBe(false);
    expect(backend.puts).toBe(1);
  });

  it("concurrent identical PUTs upload once", async () => {
    const data = bytes(5000);
    const cid = computeCid(data);
    const rs = await Promise.all(Array.from({ length: 8 }, () => put(cid, data)));
    expect(rs.every((r) => r.status === 201)).toBe(true);
    expect(backend.puts).toBe(1);
  });

  it("rejects cid mismatch with 400 and stores nothing", async () => {
    const data = bytes(10);
    const wrong = computeCid(bytes(10, 2));
    const r = await put(wrong, data);
    expect(r.status).toBe(400);
    expect((await r.json()).error).toContain(computeCid(data));
    expect(backend.puts).toBe(0);
    expect((await fetch(`${base}/blobs/${wrong}`)).status).toBe(404);
  });

  it("rejects malformed cids with 400", async () => {
    for (const c of ["b3:XYZ", "b3:" + "A".repeat(64), "sha256:" + "0".repeat(64), "b3:" + "0".repeat(63)]) {
      expect((await fetch(`${base}/blobs/${encodeURIComponent(c)}`)).status).toBe(400);
    }
  });

  it("404 for absent blobs on GET, HEAD and /url", async () => {
    const cid = computeCid(bytes(3));
    expect((await fetch(`${base}/blobs/${cid}`)).status).toBe(404);
    expect((await fetch(`${base}/blobs/${cid}`, { method: "HEAD" })).status).toBe(404);
    expect((await fetch(`${base}/blobs/${cid}/url`)).status).toBe(404);
  });

  it("Range → 206 with Content-Range; suffix and open ranges; 416", async () => {
    const data = bytes(100);
    const cid = computeCid(data);
    await put(cid, data);
    const r = await fetch(`${base}/blobs/${cid}`, { headers: { range: "bytes=10-19" } });
    expect(r.status).toBe(206);
    expect(r.headers.get("content-range")).toBe("bytes 10-19/100");
    expect(new Uint8Array(await r.arrayBuffer())).toEqual(data.subarray(10, 20));

    const s = await fetch(`${base}/blobs/${cid}`, { headers: { range: "bytes=-5" } });
    expect(new Uint8Array(await s.arrayBuffer())).toEqual(data.subarray(95));
    const o = await fetch(`${base}/blobs/${cid}`, { headers: { range: "bytes=98-" } });
    expect(o.headers.get("content-range")).toBe("bytes 98-99/100");

    const bad = await fetch(`${base}/blobs/${cid}`, { headers: { range: "bytes=100-200" } });
    expect(bad.status).toBe(416);
    expect(bad.headers.get("content-range")).toBe("bytes */100");
  });

  it("empty blob round-trips", async () => {
    const cid = computeCid(new Uint8Array());
    expect((await put(cid, new Uint8Array())).status).toBe(201);
    const g = await fetch(`${base}/blobs/${cid}`);
    expect(g.status).toBe(200);
    expect((await g.arrayBuffer()).byteLength).toBe(0);
  });

  it("GET /url returns the backend URL", async () => {
    const data = bytes(10);
    const cid = computeCid(data);
    await put(cid, data);
    const r = await fetch(`${base}/blobs/${cid}/url`);
    expect(r.status).toBe(200);
    const j = await r.json();
    expect(j.url).toMatch(/^https:\/\/mem\.invalid\//);
    expect(j.expires_ms).toBeNull();
  });

  it("detects backend corruption on full reads (502)", async () => {
    const data = bytes(64);
    const cid = computeCid(data);
    await put(cid, data);
    const [id, stored] = [...backend.objects.entries()][0]!;
    stored[0]! ^= 0xff;
    backend.objects.set(id, stored);
    expect((await fetch(`${base}/blobs/${cid}`)).status).toBe(502);
  });

  it("backend failure on PUT → 502 and nothing indexed", async () => {
    backend.failNextPuts = 1;
    const data = bytes(10);
    const cid = computeCid(data);
    expect((await put(cid, data)).status).toBe(502);
    expect((await fetch(`${base}/blobs/${cid}`, { method: "HEAD" })).status).toBe(404);
    expect((await put(cid, data)).status).toBe(201);
  });

  it("405 for other methods, 404 for unknown paths, healthz", async () => {
    const cid = computeCid(bytes(1));
    expect((await fetch(`${base}/blobs/${cid}`, { method: "DELETE" })).status).toBe(405);
    expect((await fetch(`${base}/nope`)).status).toBe(404);
    const h = await fetch(`${base}/healthz`);
    expect(h.status).toBe(200);
    expect(await h.json()).toMatchObject({ ok: true, backend: "memory" });
  });
});

describe("limits and auth", () => {
  it("413 for oversized bodies", async () => {
    await boot({ maxBodyBytes: 100 });
    const data = bytes(101);
    expect((await put(computeCid(data), data)).status).toBe(413);
  });

  it("bearer token required when configured", async () => {
    await boot({ token: "s3cret" });
    const data = bytes(10);
    const cid = computeCid(data);
    expect((await put(cid, data)).status).toBe(401);
    expect((await put(cid, data, { authorization: "Bearer nope" })).status).toBe(401);
    expect((await fetch(`${base}/blobs/${cid}`)).status).toBe(401);
    expect((await put(cid, data, { authorization: "Bearer s3cret" })).status).toBe(201);
    expect((await fetch(`${base}/blobs/${cid}`, { headers: { authorization: "Bearer s3cret" } })).status).toBe(200);
    expect((await fetch(`${base}/healthz`)).status).toBe(200);
  });
});

describe("index persistence", () => {
  it("survives restart and a torn last line", async () => {
    await boot();
    const data = bytes(10);
    const cid = computeCid(data);
    await put(cid, data);
    const objects = backend.objects;
    await close();
    appendFileSync(join(dir, "index.jsonl"), '{"cid":"b3:tor');
    backend = new MemoryBackend();
    for (const [k, v] of objects) backend.objects.set(k, v);
    store = new BridgeStore({ backend, dataDir: dir });
    const s = await startBridgeServer({ store });
    base = s.url;
    close = async () => {
      await s.close();
      await store.close();
    };
    expect(new Uint8Array(await (await fetch(`${base}/blobs/${cid}`)).arrayBuffer())).toEqual(data);
    // The torn record was dropped; later appends parse.
    const d2 = bytes(11);
    await put(computeCid(d2), d2);
    const idx = new JsonlIndex(join(dir, "index.jsonl"));
    expect(idx.get(computeCid(d2))).toBeDefined();
    idx.close();
    expect(readFileSync(join(dir, "index.jsonl"), "utf8").split("\n").filter(Boolean).length).toBe(2);
  });
});

describe("packing", () => {
  const packing = { thresholdBytes: 1024, targetBytes: 4096, maxDelayMs: 60_000 };

  it("stages small blobs, serves them immediately, packs on flush", async () => {
    await boot({ packing });
    const blobs = Array.from({ length: 5 }, (_, i) => bytes(500 + i, i + 1));
    for (const b of blobs) expect((await put(computeCid(b), b)).status).toBe(201);
    expect(backend.puts).toBe(0);
    const first = blobs[0]!;
    expect(new Uint8Array(await (await fetch(`${base}/blobs/${computeCid(first)}`)).arrayBuffer())).toEqual(first);
    // staged/packed blobs have no direct URL
    expect((await fetch(`${base}/blobs/${computeCid(first)}/url`)).status).toBe(404);

    await store.flush();
    expect(backend.puts).toBe(1);
    expect(store.locate(computeCid(first))?.kind).toBe("packed");
    for (const b of blobs) {
      const cid = computeCid(b);
      expect(new Uint8Array(await (await fetch(`${base}/blobs/${cid}`)).arrayBuffer())).toEqual(b);
      const r = await fetch(`${base}/blobs/${cid}`, { headers: { range: "bytes=100-199" } });
      expect(r.status).toBe(206);
      expect(new Uint8Array(await r.arrayBuffer())).toEqual(b.subarray(100, 200));
    }
    // Pack is self-describing.
    const pack = [...backend.objects.values()][0]!;
    expect(parsePackTrailer(pack).map((e) => e[0])).toEqual(blobs.map(computeCid));
  });

  it("large blobs bypass packing", async () => {
    await boot({ packing });
    const big = bytes(2048);
    await put(computeCid(big), big);
    expect(backend.puts).toBe(1);
    expect(store.locate(computeCid(big))?.kind).toBe("direct");
    expect((await fetch(`${base}/blobs/${computeCid(big)}/url`)).status).toBe(200);
  });

  it("auto-flushes at target size into multiple packs", async () => {
    await boot({ packing: { thresholdBytes: 1024, targetBytes: 2000, maxDelayMs: 60_000 } });
    const blobs = Array.from({ length: 10 }, (_, i) => bytes(900, i + 10));
    for (const b of blobs) await put(computeCid(b), b);
    await store.flush();
    expect(backend.puts).toBeGreaterThanOrEqual(5);
    for (const b of blobs) expect(store.locate(computeCid(b))?.kind).toBe("packed");
  });

  it("flushes after maxDelayMs", async () => {
    await boot({ packing: { thresholdBytes: 1024, targetBytes: 1 << 20, maxDelayMs: 50 } });
    const b = bytes(10);
    await put(computeCid(b), b);
    await new Promise((r) => setTimeout(r, 300));
    expect(store.locate(computeCid(b))?.kind).toBe("packed");
  });

  it("retries failed pack uploads; staged data survives a restart", async () => {
    await boot({ packing });
    backend.failNextPuts = 1;
    const b = bytes(100);
    const cid = computeCid(b);
    await put(cid, b);
    await expect(store.flush()).rejects.toThrow("injected");
    expect(store.locate(cid)?.kind).toBe("staged");
    await close();
    // restart: staged blob is re-queued and packed
    backend = new MemoryBackend();
    store = new BridgeStore({ backend, dataDir: dir, packing });
    close = () => store.close();
    expect(store.stats().pending).toBe(1);
    await store.flush();
    expect(store.locate(cid)?.kind).toBe("packed");
    expect(await store.get(cid)).toEqual(b);
  });

  it("buildPack / parsePackTrailer round trip", () => {
    const blobs = [bytes(3), bytes(0), bytes(7, 3)].map((data) => ({ cid: computeCid(data), data }));
    const { pack, entries } = buildPack(blobs);
    expect(parsePackTrailer(pack)).toEqual(entries);
    for (const [i, [, off, size]] of entries.entries()) expect(pack.subarray(off, off + size)).toEqual(blobs[i]!.data);
  });
});
