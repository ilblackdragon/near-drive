import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BridgeStore, computeCid, startBridgeServer } from "@nstorage/bridge-common";
import { FocBackend, FOC_MIN_UPLOAD, type FocClient } from "../src/backend.js";
import { SynapseFocClient } from "../src/synapse.js";

/** Fake Synapse: pieces keyed by a fake PieceCID, optional CDN URLs. */
class FakeFoc implements FocClient {
  readonly network = "calibration";
  pieces = new Map<string, Uint8Array>();
  uploads: number[] = [];
  downloads = 0;
  cdn = true;
  async upload(data: Uint8Array) {
    if (data.length < FOC_MIN_UPLOAD) throw new Error("piece too small");
    this.uploads.push(data.length);
    const id = "bafkzcibfake" + computeCid(data).slice(3, 40);
    this.pieces.set(id, new Uint8Array(data));
    return { pieceCid: id, complete: true, copies: 2 };
  }
  async download(id: string) {
    this.downloads++;
    const p = this.pieces.get(id);
    if (!p) throw new Error(`piece ${id} not found`);
    return new Uint8Array(p);
  }
  cdnUrl(id: string) {
    return this.cdn ? `https://0xpayer.calibration.filbeam.io/${id}` : null;
  }
}

const bytes = (n: number, seed = 1) => Uint8Array.from({ length: n }, (_, i) => (i * 13 + seed) & 0xff);

describe("FocBackend", () => {
  it("pads payloads below the 127-byte minimum; store truncates on read", async () => {
    const dir = mkdtempSync(join(tmpdir(), "foc-"));
    const fake = new FakeFoc();
    const store = new BridgeStore({ backend: new FocBackend(fake, { rangeViaCdn: false }), dataDir: dir });
    const d = bytes(5);
    await store.put(computeCid(d), d);
    expect(fake.uploads).toEqual([127]);
    expect(await store.get(computeCid(d))).toEqual(d);
    await store.close();
    rmSync(dir, { recursive: true });
  });

  it("serves ranges from the CDN when it answers 206", async () => {
    const fake = new FakeFoc();
    const calls: string[] = [];
    const fetchFn = (async (url: string, init?: RequestInit) => {
      calls.push(`${url} ${(init?.headers as Record<string, string>).range}`);
      const id = url.split("/").pop()!;
      const m = /bytes=(\d+)-(\d+)/.exec((init?.headers as Record<string, string>).range!)!;
      return new Response(fake.pieces.get(id)!.slice(Number(m[1]), Number(m[2]) + 1), { status: 206 });
    }) as unknown as typeof fetch;
    const b = new FocBackend(fake, { fetch: fetchFn });
    const id = await b.put("k", bytes(1000));
    expect(await b.get(id, { start: 10, end: 19 })).toEqual(bytes(1000).subarray(10, 20));
    expect(fake.downloads).toBe(0);
    expect(calls).toEqual([`https://0xpayer.calibration.filbeam.io/${id} bytes=10-19`]);
  });

  it("falls back to full download (and caches) when the CDN ignores Range or fails", async () => {
    const fake = new FakeFoc();
    const fetchFn = (async () => new Response("whole", { status: 200 })) as unknown as typeof fetch;
    const b = new FocBackend(fake, { fetch: fetchFn });
    const id = await b.put("k", bytes(1000));
    expect(await b.get(id, { start: 0, end: 9 })).toEqual(bytes(1000).subarray(0, 10));
    expect(await b.get(id, { start: 500, end: 509 })).toEqual(bytes(1000).subarray(500, 510));
    expect(fake.downloads).toBe(1);

    const failing = new FocBackend(fake, { fetch: (async () => { throw new Error("dns"); }) as unknown as typeof fetch });
    expect(await failing.get(id, { start: 1, end: 2 })).toEqual(bytes(1000).subarray(1, 3));
  });

  it("url() is the FilBeam URL, or null without CDN", async () => {
    const fake = new FakeFoc();
    const b = new FocBackend(fake);
    expect(await b.url("bafk")).toEqual({ url: "https://0xpayer.calibration.filbeam.io/bafk", expires_ms: null });
    fake.cdn = false;
    expect(await b.url("bafk")).toBeNull();
  });
});

describe("FOC bridge over HTTP (mock Synapse)", () => {
  let dir: string;
  let fake: FakeFoc;
  let store: BridgeStore;
  let base: string;
  let close: () => Promise<void>;
  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), "foc-http-"));
    fake = new FakeFoc();
    store = new BridgeStore({
      backend: new FocBackend(fake, { rangeViaCdn: false }),
      dataDir: dir,
      packing: { thresholdBytes: 16 * 1024, targetBytes: 64 * 1024, maxDelayMs: 60_000 },
    });
    const s = await startBridgeServer({ store, token: "t" });
    base = s.url;
    close = async () => {
      await s.close();
      await store.close();
    };
  });
  afterEach(async () => {
    await close();
    rmSync(dir, { recursive: true, force: true });
  });

  const auth = { authorization: "Bearer t" };

  it("many small chunks → few pieces; reads, ranges, url semantics", async () => {
    const chunks = Array.from({ length: 40 }, (_, i) => bytes(3000 + i, i));
    await Promise.all(chunks.map((c) => fetch(`${base}/blobs/${computeCid(c)}`, { method: "PUT", body: c, headers: auth })));
    await store.flush();
    expect(fake.uploads.length).toBeLessThanOrEqual(3); // 40 × ~3 KB into 64 KiB packs
    for (const c of chunks) {
      const cid = computeCid(c);
      const g = await fetch(`${base}/blobs/${cid}`, { headers: auth });
      expect(new Uint8Array(await g.arrayBuffer())).toEqual(c);
      const r = await fetch(`${base}/blobs/${cid}`, { headers: { ...auth, range: "bytes=2990-" } });
      expect(r.status).toBe(206);
      expect(new Uint8Array(await r.arrayBuffer())).toEqual(c.subarray(2990));
      expect((await fetch(`${base}/blobs/${cid}/url`, { headers: auth })).status).toBe(404);
    }
    // a big chunk is its own piece with a FilBeam URL
    const big = bytes(20_000, 99);
    expect((await fetch(`${base}/blobs/${computeCid(big)}`, { method: "PUT", body: big, headers: auth })).status).toBe(201);
    const u = await (await fetch(`${base}/blobs/${computeCid(big)}/url`, { headers: auth })).json();
    expect(u.url).toMatch(/^https:\/\/0xpayer\.calibration\.filbeam\.io\/bafkzcib/);
  });
});

describe("SynapseFocClient (real SDK, offline)", () => {
  // Offline: Synapse.create does no I/O. The key is the public Anvil dev key #1, so never use it on a network.
  it("constructs for calibration and builds FilBeam URLs", () => {
    const c = new SynapseFocClient({
      network: "calibration",
      privateKey: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
      withCDN: true,
    });
    expect(c.chain.id).toBe(314159);
    const url = c.cdnUrl("bafkzcibexample")!;
    expect(url.toLowerCase()).toBe(`https://${c.address.toLowerCase()}.calibration.filbeam.io/bafkzcibexample`);
  });
});
