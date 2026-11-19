import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { BridgeStore, computeCid, startBridgeServer } from "@nstorage/bridge-common";
import { ShelbyS3Backend } from "../src/s3.js";
import { ShelbySdkBackend } from "../src/sdk.js";
import { backendFromEnv } from "../src/config.js";

/** Minimal path-style S3: PUT (If-None-Match: * → 412), GET (+Range), HEAD. */
function mockS3() {
  const objects = new Map<string, Buffer>();
  const seen: { method: string; path: string; headers: Record<string, unknown> }[] = [];
  const server = createServer((req, res) => {
    const path = decodeURIComponent(new URL(req.url!, "http://x").pathname);
    seen.push({ method: req.method!, path, headers: req.headers });
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const obj = objects.get(path);
      if (req.method === "PUT") {
        if (req.headers["if-none-match"] === "*" && obj) {
          res.writeHead(412, { "content-type": "application/xml" });
          return res.end("<Error><Code>PreconditionFailed</Code><Message>exists</Message></Error>");
        }
        objects.set(path, Buffer.concat(chunks));
        res.writeHead(200, { etag: '"x"' });
        return res.end();
      }
      if (!obj) {
        res.writeHead(404, { "content-type": "application/xml" });
        return res.end(req.method === "HEAD" ? undefined : "<Error><Code>NoSuchKey</Code><Message>nope</Message></Error>");
      }
      const m = /bytes=(\d+)-(\d+)/.exec(String(req.headers.range ?? ""));
      if (m) {
        const [a, b] = [Number(m[1]), Math.min(Number(m[2]), obj.length - 1)];
        res.writeHead(206, { "content-length": b - a + 1, "content-range": `bytes ${a}-${b}/${obj.length}` });
        return res.end(obj.subarray(a, b + 1));
      }
      res.writeHead(200, { "content-length": obj.length });
      res.end(req.method === "HEAD" ? undefined : obj);
    });
  });
  return { server, objects, seen };
}

const bytes = (n: number, seed = 1) => Uint8Array.from({ length: n }, (_, i) => (i * 7 + seed) & 0xff);

describe("ShelbyS3Backend against a mock S3", () => {
  const s3 = mockS3();
  let endpoint: string;
  let backend: ShelbyS3Backend;
  beforeAll(async () => {
    await new Promise<void>((r) => s3.server.listen(0, "127.0.0.1", r));
    endpoint = `http://127.0.0.1:${(s3.server.address() as AddressInfo).port}`;
    backend = new ShelbyS3Backend({ endpoint, bucket: "bkt", accessKeyId: "SHLBTEST", secretAccessKey: "secret", urlTtlSeconds: 600 });
  });
  afterAll(async () => {
    await backend.close();
    await new Promise((r) => (s3.server as Server).close(r));
  });

  it("put is create-only and idempotent; get, ranged get, has", async () => {
    const d = bytes(1000);
    const id = await backend.put("abc", d);
    expect(id).toBe("nstorage/abc");
    expect(s3.objects.get("/bkt/nstorage/abc")).toEqual(Buffer.from(d));
    expect(await backend.put("abc", d)).toBe(id); // 412 swallowed
    const puts = s3.seen.filter((x) => x.method === "PUT");
    expect(puts.every((p) => p.headers["if-none-match"] === "*")).toBe(true);
    expect(puts[0]!.headers.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=SHLBTEST\//);
    expect(await backend.get(id)).toEqual(d);
    expect(await backend.get(id, { start: 5, end: 9 })).toEqual(d.subarray(5, 10));
    expect(await backend.has(id)).toBe(true);
    expect(await backend.has("nstorage/missing")).toBe(false);
    await expect(backend.get("nstorage/missing")).rejects.toThrow();
  });

  it("url is a presigned GET with expiry", async () => {
    const before = Date.now();
    const u = (await backend.url("nstorage/abc"))!;
    expect(u.url).toContain(`${endpoint}/bkt/nstorage/abc?`);
    expect(u.url).toContain("X-Amz-Expires=600");
    expect(u.expires_ms).toBeGreaterThanOrEqual(before + 600_000);
    const r = await fetch(u.url);
    expect(r.status).toBe(200);
  });

  it("full bridge over HTTP", async () => {
    const dir = mkdtempSync(join(tmpdir(), "shelby-"));
    const store = new BridgeStore({ backend, dataDir: dir });
    const srv = await startBridgeServer({ store });
    const d = bytes(4096, 5);
    const cid = computeCid(d);
    expect((await fetch(`${srv.url}/blobs/${cid}`, { method: "PUT", body: d })).status).toBe(201);
    expect(s3.objects.has(`/bkt/nstorage/${cid}`)).toBe(true);
    const r = await fetch(`${srv.url}/blobs/${cid}`, { headers: { range: "bytes=0-99" } });
    expect(r.status).toBe(206);
    expect(new Uint8Array(await r.arrayBuffer())).toEqual(d.subarray(0, 100));
    const u = await (await fetch(`${srv.url}/blobs/${cid}/url`)).json();
    expect(u.url).toContain("X-Amz-Signature=");
    await srv.close();
    await store.close().catch(() => {}); // closes the shared backend's client: last test
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("ShelbySdkBackend (real SDK, offline)", () => {
  it("constructs a shelbynet client and builds RPC blob URLs", async () => {
    const b = new ShelbySdkBackend({ privateKey: "0x" + "11".repeat(32) });
    const u = (await b.url("nstorage/b3:ab"))!;
    expect(u.url).toBe(`https://shelby.shelbynet.shelby.xyz/shelby/v1/blobs/${b.signer.accountAddress.toString()}/nstorage/b3%3Aab`);
  });
});

describe("config", () => {
  it("requires credentials and validates mode", async () => {
    await expect(backendFromEnv({})).rejects.toThrow("SHELBY_S3_BUCKET");
    await expect(backendFromEnv({ SHELBY_MODE: "x" })).rejects.toThrow("SHELBY_MODE");
    const b = await backendFromEnv({ SHELBY_S3_BUCKET: "b", SHELBY_ACCESS_KEY_ID: "k", SHELBY_SECRET_ACCESS_KEY: "s" });
    expect(b.name).toBe("shelby-s3");
  });
});
