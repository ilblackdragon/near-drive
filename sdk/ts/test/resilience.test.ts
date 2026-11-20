/**
 * Bad networks: the same scenarios as crates/near-drive-gateway/tests/resilience.rs,
 * run against an in-memory gateway and (if built) the real gateway binary,
 * through a fetch that injects 503s, lost responses and cut-off bodies.
 */
import { mkdtempSync, readdirSync, readFileSync, existsSync, writeFileSync, utimesSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, ConflictError, GatewayError, generateSecretKey, RootKey, WriterCheck, type NetConfig } from "../src/index.js";
import { getFile, putFile } from "../src/node.js";
import { fakeGateway, faulty, haveGatewayBin, pattern, realGateway, sha, type Faulty, type RealGateway } from "./harness.js";

const FAST: Partial<NetConfig> = { baseDelayMs: 1, maxDelayMs: 5 };
const EMPTY_LIST = JSON.stringify({ entries: [], common_prefixes: [], next_cursor: null });

interface Env {
  proxy: Faulty;
  client(attempts: number, parallelism: number): Client;
  tmp: string;
}

type Backend = { name: string; skip: boolean; setup(): Promise<Env>; teardown(): void };

function envFor(url: string, inner: typeof fetch, secretKey: string): Env {
  const proxy = faulty(inner);
  const root = RootKey.generate();
  const tmp = mkdtempSync(join(tmpdir(), "drive-ts-res-"));
  return {
    proxy,
    tmp,
    client: (attempts, parallelism) =>
      new Client({
        gateway: url,
        accountId: "alice.near",
        signer: secretKey,
        rootKey: root,
        writerCheck: WriterCheck.trusted({ "alice.near": [root.signPublicKey()] }),
        chunkSize: 64 * 1024,
        parallelism,
        net: { ...FAST, attempts },
        fetch: proxy.fetch,
      }),
  };
}

let gw: RealGateway | undefined;
const backends: Backend[] = [
  {
    name: "fake gateway",
    skip: false,
    setup: async () => {
      const g = fakeGateway();
      return envFor(g.url, g.fetch, generateSecretKey());
    },
    teardown: () => {},
  },
  {
    name: "real gateway",
    skip: !haveGatewayBin,
    setup: async () => {
      gw ??= await realGateway();
      return envFor(gw.url, globalThis.fetch.bind(globalThis), gw.secretKey);
    },
    teardown: () => gw?.stop(),
  },
];

const writePattern = (path: string, seed: number, n: number) => {
  const b = pattern(seed, n);
  writeFileSync(path, b);
  return sha(b);
};
const hashFile = (p: string) => sha(readFileSync(p));
let uniq = 0;
const fresh = (name: string) => `near://alice.near/t${Date.now()}-${uniq++}/${name}`;

for (const b of backends) {
  describe.skipIf(b.skip)(`resilience (${b.name})`, () => {
    let env: Env;
    beforeAll(async () => {
      env = await b.setup();
    });
    afterAll(() => b.teardown());
    const p = (n: string) => join(env.tmp, n);

    it("every operation survives a flaky network", async () => {
      // Half of all requests fail; with near-zero latency the in-memory backend can keep a
      // worker in lockstep with the k%4 fault slots, so allow more attempts than the default 8.
      const c = env.client(16, 4);
      env.proxy.set({ kind: "flaky" });
      const h = writePattern(p("big"), 7, 1_000_000);
      const big = fresh("big.bin");
      await putFile(c, p("big"), big);
      await getFile(c, big, p("big.out"));
      expect(hashFile(p("big.out"))).toBe(h);

      const small = fresh("small.txt");
      await c.put(small, "hello");
      await c.put(small, "hello again"); // seq 2 through lost responses
      expect(await c.getText(small)).toBe("hello again");
      expect((await c.head(small))!.record.seq).toBe(2);
      const bob = RootKey.generate().x25519Public();
      expect((await c.share(small, bob)).seq).toBe(3);
      expect((await c.list(small.slice(0, small.lastIndexOf("/") + 1))).length).toBe(1);
      await c.delete(small);
      expect(await c.head(small)).toBeNull();
      expect(env.proxy.k).toBeGreaterThan(40);
    });

    it("lists page by page, with and without a delimiter", async () => {
      const c = env.client(8, 4);
      env.proxy.set({ kind: "pass" });
      const dir = fresh("");
      const names = ["a", "b", "c", "d/1", "d/2", "e/1", "f"];
      for (const n of names) await c.put(dir + n, n);
      expect((await c.list(dir)).map((e) => e.path.slice(dir.length - "near://alice.near/".length))).toEqual(names);
      let cursor: string | undefined;
      const seen: string[] = [];
      let pages = 0;
      for (;;) {
        const pg = await c.listPage(dir, { delimiter: "/", cursor, limit: 2 });
        pages++;
        expect(pg.entries.length + pg.common_prefixes.length).toBeLessThanOrEqual(2);
        seen.push(...pg.entries.map((e) => e.path), ...pg.common_prefixes);
        if (pg.next_cursor === null) break;
        cursor = pg.next_cursor;
      }
      const base = dir.slice("near://alice.near/".length);
      expect(seen.sort()).toEqual(["a", "b", "c", "d/", "e/", "f"].map((n) => base + n));
      expect(pages).toBe(3);
    });

    it("interrupted upload resumes without resending chunks", async () => {
      const h = writePattern(p("f"), 1, 1_000_000); // 16 chunks of 64 KiB
      const uri = fresh("f.bin");
      const resumeDir = p("journal-a");
      env.proxy.set({ kind: "cutAfter", n: 5 });
      const e = await putFile(env.client(1, 1), p("f"), uri, { resumeDir }).catch((x: Error) => x);
      expect(String((e as Error).message)).toMatch(/run it again to resume/);
      expect(readdirSync(resumeDir).length).toBe(1);

      env.proxy.set({ kind: "pass" });
      await putFile(env.client(1, 1), p("f"), uri, { resumeDir });
      expect(env.proxy.chunkPuts).toBe(16 - 5 + 1); // only the missing chunks + the manifest
      expect(readdirSync(resumeDir).length).toBe(0);
      await getFile(env.client(1, 1), uri, p("f.out"));
      expect(hashFile(p("f.out"))).toBe(h);
    });

    it("interrupted public upload resumes too", async () => {
      const h = writePattern(p("pub"), 9, 600_000); // 10 chunks
      const uri = fresh("pub.bin");
      const resumeDir = p("journal-pub");
      env.proxy.set({ kind: "cutAfter", n: 3 });
      await expect(putFile(env.client(1, 1), p("pub"), uri, { resumeDir, public: true })).rejects.toThrow(/resume/);
      env.proxy.set({ kind: "pass" });
      await putFile(env.client(1, 1), p("pub"), uri, { resumeDir, public: true });
      expect(env.proxy.chunkPuts).toBe(10 - 3 + 1);
      await getFile(env.client(1, 1), uri, p("pub.out"));
      expect(hashFile(p("pub.out"))).toBe(h);
    });

    it("changed file restarts the upload with a fresh key", async () => {
      writePattern(p("g"), 1, 1_000_000);
      const uri = fresh("g.bin");
      const resumeDir = p("journal-b");
      env.proxy.set({ kind: "cutAfter", n: 5 });
      await expect(putFile(env.client(1, 1), p("g"), uri, { resumeDir })).rejects.toThrow();

      // Same size and mtime, different bytes in an already-sent chunk.
      const st = statSync(p("g"));
      const data = readFileSync(p("g"));
      data[10]! ^= 0xff;
      writeFileSync(p("g"), data);
      utimesSync(p("g"), st.atime, st.mtime);

      env.proxy.set({ kind: "pass" });
      await putFile(env.client(1, 1), p("g"), uri, { resumeDir });
      expect(env.proxy.chunkPuts).toBe(16 + 1); // everything re-encrypted and re-sent
      await getFile(env.client(1, 1), uri, p("g.out"));
      expect(readFileSync(p("g.out")).equals(data)).toBe(true);
    });

    it("interrupted download resumes from the part file", async () => {
      const h = writePattern(p("d"), 3, 1_000_000);
      const uri = fresh("d.bin");
      await putFile(env.client(1, 4), p("d"), uri);

      env.proxy.set({ kind: "cutAfter", n: 6 });
      await expect(getFile(env.client(1, 1), uri, p("out"))).rejects.toThrow(/run it again to resume/);
      expect(existsSync(p("out.drive-part")) && existsSync(p("out.drive-part.json"))).toBe(true);

      env.proxy.set({ kind: "pass" });
      await getFile(env.client(1, 1), uri, p("out"));
      expect(env.proxy.chunkGets).toBe(16 - 6); // chunks on disk were verified, not refetched
      expect(hashFile(p("out"))).toBe(h);
      expect(existsSync(p("out.drive-part")) || existsSync(p("out.drive-part.json"))).toBe(false);

      // A new version invalidates the part file.
      env.proxy.set({ kind: "cutAfter", n: 6 });
      await expect(getFile(env.client(1, 1), uri, p("out2"))).rejects.toThrow();
      writePattern(p("d"), 4, 1_000_000);
      env.proxy.set({ kind: "pass" });
      await putFile(env.client(1, 4), p("d"), uri);
      env.proxy.set({ kind: "pass" });
      await getFile(env.client(1, 1), uri, p("out2"));
      expect(env.proxy.chunkGets).toBe(16);
      expect(hashFile(p("out2"))).toBe(hashFile(p("d")));
    });

    it("small objects are read in one request", async () => {
      const c = env.client(1, 4);
      const uri = fresh("note.txt");
      await c.put(uri, "tiny file");
      env.proxy.set({ kind: "pass" });
      expect(await c.getText(uri)).toBe("tiny file");
      expect(env.proxy.requests).toBe(1);
      const loc = (await c.locate(uri))!;
      expect(loc.chunks.every((ch) => ch.data !== undefined && ch.url === undefined)).toBe(true);
    });

    it("conditional writes and deletes", async () => {
      const c = env.client(3, 2);
      const uri = fresh("cas.txt");
      env.proxy.set({ kind: "flaky" });
      expect((await c.put(uri, "v1", { expectSeq: 0 })).seq).toBe(1);
      const e = await c.put(uri, "again", { expectSeq: 0 }).catch((x) => x);
      expect(e).toBeInstanceOf(ConflictError);
      expect((e as ConflictError).current).toBe(1);
      expect((await c.put(uri, "v2", { expectSeq: 1 })).seq).toBe(2);
      const d = await c.deleteIf(uri, 1).catch((x) => x);
      expect(d).toBeInstanceOf(ConflictError);
      expect((d as ConflictError).current).toBe(2);
      await c.deleteIf(uri, 2);
      expect(await c.head(uri)).toBeNull();
    });

    it("sends the class on the record PUT and share keeps it", async () => {
      const c = env.client(1, 1);
      const uri = fresh("classy.txt");
      env.proxy.set({ kind: "pass" });
      // the real gateway only knows its default class; an unknown one is a 400
      const cls = b.name === "fake gateway" ? "bulk" : undefined;
      await c.put(uri, "x", cls ? { class: cls } : {});
      const recPut = env.proxy.log.find((r) => r.method === "PUT" && r.url.includes("/v1/o/"))!;
      expect(recPut.headers["x-near-drive-class"]).toBe(cls);
      const head = (await c.head(uri))!;
      if (cls) expect(head.class).toBe(cls);
      env.proxy.set({ kind: "pass" });
      await c.share(uri, RootKey.generate().x25519Public());
      const puts = env.proxy.log.filter((r) => r.method === "PUT");
      expect(puts.length).toBe(2); // manifest chunk + record
      for (const r of puts) expect(r.headers["x-near-drive-class"]).toBe(head.class);
    });
  });
}

describe("retry policy (mocked fetch)", () => {
  const sk = generateSecretKey();
  const mk = (f: typeof fetch, net: Partial<NetConfig> = {}) => new Client({ gateway: "http://x", accountId: "alice.near", signer: sk, fetch: f, net: { ...FAST, ...net } });

  it("gives up after `attempts` on persistent 503, signing each attempt afresh", async () => {
    const seen: string[] = [];
    const f = (async (_u: unknown, init?: RequestInit) => {
      seen.push(new Headers(init?.headers).get("x-near-timestamp")!);
      return new Response("busy", { status: 503 });
    }) as typeof fetch;
    const e = await mk(f, { attempts: 3 }).head("near://alice.near/a").catch((x) => x);
    expect(e).toBeInstanceOf(GatewayError);
    expect((e as GatewayError).status).toBe(503);
    expect(seen.length).toBe(3);
    expect(new Set(seen).size).toBe(3);
  });

  it("does not retry 4xx (other than 408/429)", async () => {
    let n = 0;
    const f = (async () => (n++, new Response("no", { status: 403 }))) as typeof fetch;
    await expect(mk(f).list("near://alice.near/")).rejects.toThrow(/403/);
    expect(n).toBe(1);
  });

  it("honours Retry-After", async () => {
    let n = 0;
    const t0 = Date.now();
    const f = (async () => (n++ === 0 ? new Response("slow down", { status: 429, headers: { "retry-after": "1" } }) : new Response(EMPTY_LIST, { status: 200 }))) as typeof fetch;
    expect(await mk(f, { maxDelayMs: 1000 }).list("near://alice.near/")).toEqual([]); // floor capped at 4 * maxDelayMs
    expect(Date.now() - t0).toBeGreaterThanOrEqual(950);
  });

  it("times out a stalled request and retries", async () => {
    let n = 0;
    const f = ((_u: unknown, init?: RequestInit) => {
      n++;
      if (n === 1) return new Promise((_, rej) => init!.signal!.addEventListener("abort", () => rej(init!.signal!.reason)));
      return Promise.resolve(new Response(EMPTY_LIST, { status: 200 }));
    }) as typeof fetch;
    expect(await mk(f, { baseTimeoutMs: 50 }).list("near://alice.near/")).toEqual([]);
    expect(n).toBe(2);
  });

  it("idle timeout cuts a body that stops flowing", async () => {
    let n = 0;
    const f = (async () => {
      n++;
      if (n === 1) return new Response(new ReadableStream({ start: (c) => c.enqueue(new TextEncoder().encode("[")) }), { status: 200 });
      return new Response(EMPTY_LIST, { status: 200 });
    }) as typeof fetch;
    expect(await mk(f, { idleTimeoutMs: 50 }).list("near://alice.near/")).toEqual([]);
    expect(n).toBe(2);
  });

  it("retries a body shorter than its content-length", async () => {
    let n = 0;
    const f = (async () => (n++ === 0 ? new Response("[", { status: 200, headers: { "content-length": "2" } }) : new Response(EMPTY_LIST, { status: 200 }))) as typeof fetch;
    expect(await mk(f).list("near://alice.near/")).toEqual([]);
    expect(n).toBe(2);
  });

  it("refetches a chunk whose bytes do not match its id; rejects a bad inlined chunk", async () => {
    const g = fakeGateway();
    const root = RootKey.generate();
    const writerCheck = WriterCheck.trusted({ "alice.near": [root.signPublicKey()] });
    const c = new Client({ gateway: g.url, accountId: "alice.near", signer: sk, rootKey: root, writerCheck, net: FAST, fetch: g.fetch });
    // corrupt the inlined copy: client must fall back to a verified fetch
    let corruptOnce = true;
    const f = (async (u: RequestInfo | URL, init?: RequestInit) => {
      const r = await g.fetch(u, init);
      const s = String(u);
      if (s.includes("mode=locate")) {
        const j = await r.json();
        j.chunks[0].data = "AAAA";
        return new Response(JSON.stringify(j), { status: 200 });
      }
      if (s.includes("chunk=") && corruptOnce) {
        corruptOnce = false;
        return new Response("garbage", { status: 200 });
      }
      return r;
    }) as typeof fetch;
    const reader = new Client({ gateway: g.url, accountId: "alice.near", signer: sk, writerCheck, net: FAST, fetch: f });
    await c.put("near://alice.near/pub", "public bytes", { public: true });
    expect(new TextDecoder().decode(await reader.get("near://alice.near/pub"))).toBe("public bytes");
    expect(corruptOnce).toBe(false);
  });
});
