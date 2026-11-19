import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { timingSafeEqual, createHash } from "node:crypto";
import type { AddressInfo } from "node:net";
import { computeCid, isValidCid } from "./cid.js";
import { parseRange } from "./range.js";
import { IntegrityError, NotFound, type BridgeStore } from "./store.js";

export interface BridgeServerOptions {
  store: BridgeStore;
  /** If set, every /blobs request needs `Authorization: Bearer <token>`. */
  token?: string;
  /** Max PUT body (default 64 MiB, the max nstorage chunk size). */
  maxBodyBytes?: number;
  log?: (msg: string) => void;
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    msg: string,
  ) {
    super(msg);
  }
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const b = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { "content-type": "application/json", "content-length": b.length });
  res.end(b);
}

function readBody(req: IncomingMessage, max: number): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers["content-length"] ?? NaN);
    if (declared > max) return reject(new HttpError(413, `body exceeds ${max} bytes`));
    const chunks: Buffer[] = [];
    let n = 0;
    req.on("data", (c: Buffer) => {
      n += c.length;
      if (n > max) {
        req.removeAllListeners("data");
        req.resume();
        reject(new HttpError(413, `body exceeds ${max} bytes`));
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(new Uint8Array(Buffer.concat(chunks))));
    req.on("error", reject);
  });
}

const digest = (s: string) => createHash("sha256").update(s).digest();

function authorized(req: IncomingMessage, token: string | undefined): boolean {
  if (!token) return true;
  const h = req.headers.authorization ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return !!m && timingSafeEqual(digest(m[1]!.trim()), digest(token));
}

/** Request handler implementing the nstorage blob-bridge HTTP spec. */
export function bridgeHandler(opts: BridgeServerOptions) {
  const { store } = opts;
  const max = opts.maxBodyBytes ?? 64 * 1024 * 1024;
  const log = opts.log ?? (() => {});

  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      const path = new URL(req.url ?? "/", "http://bridge").pathname;
      if (path === "/healthz") {
        if (req.method !== "GET" && req.method !== "HEAD") throw new HttpError(405, "method not allowed");
        return sendJson(res, 200, { ok: true, backend: store.backendName, ...store.stats() });
      }
      const m = /^\/blobs\/([^/]+)(\/url)?$/.exec(path);
      if (!m) throw new HttpError(404, "not found");
      if (!authorized(req, opts.token)) {
        res.setHeader("www-authenticate", "Bearer");
        throw new HttpError(401, "unauthorized");
      }
      const cid = decodeURIComponent(m[1]!);
      if (!isValidCid(cid)) throw new HttpError(400, "cid must be b3:<64 lowercase hex>");

      if (m[2]) {
        if (req.method !== "GET") throw new HttpError(405, "method not allowed");
        const u = await store.url(cid);
        if (!u) throw new HttpError(404, store.locate(cid) ? "no direct URL for this blob (packed or staged)" : "not found");
        return sendJson(res, 200, u);
      }

      switch (req.method) {
        case "PUT": {
          const body = await readBody(req, max);
          const actual = computeCid(body);
          if (actual !== cid) throw new HttpError(400, `cid mismatch: body hashes to ${actual}`);
          const created = await store.put(cid, body);
          return sendJson(res, 201, { cid, size: body.length, created });
        }
        case "HEAD":
        case "GET": {
          const loc = store.locate(cid);
          if (!loc) throw new HttpError(404, "not found");
          const headers: Record<string, string | number> = {
            "content-type": "application/octet-stream",
            "accept-ranges": "bytes",
            etag: `"${cid}"`,
            "cache-control": "public, max-age=31536000, immutable",
          };
          if (req.method === "HEAD") {
            res.writeHead(200, { ...headers, "content-length": loc.size });
            return void res.end();
          }
          const r = parseRange(req.headers.range, loc.size);
          if (r.kind === "unsatisfiable") {
            res.writeHead(416, { "content-range": `bytes */${loc.size}` });
            return void res.end();
          }
          const range = r.kind === "ok" ? r.range : undefined;
          const data = await store.get(cid, range);
          if (range) {
            headers["content-range"] = `bytes ${range.start}-${range.end}/${loc.size}`;
          }
          res.writeHead(range ? 206 : 200, { ...headers, "content-length": data.length });
          return void res.end(data);
        }
        default:
          throw new HttpError(405, "method not allowed");
      }
    } catch (e) {
      let status = 502;
      if (e instanceof HttpError) status = e.status;
      else if (e instanceof NotFound) status = 404;
      else if (e instanceof IntegrityError) status = 502;
      if (status >= 500) log(`${req.method} ${req.url}: ${(e as Error).stack ?? e}`);
      if (res.headersSent) return void res.destroy();
      if (req.method === "HEAD") {
        res.writeHead(status);
        return void res.end();
      }
      sendJson(res, status, { error: (e as Error).message });
    }
  };
}

const FORBIDDEN_HOSTS = new Set(["0.0.0.0", "::", "[::]", "", "*"]);

/** Refuses wildcard binds: bridges must listen on loopback (or a specific private IP). */
export function assertSafeHost(host: string): void {
  if (FORBIDDEN_HOSTS.has(host.trim())) {
    throw new Error(`refusing to listen on ${JSON.stringify(host)}: bind 127.0.0.1 (default) or a specific interface IP`);
  }
}

export async function startBridgeServer(
  opts: BridgeServerOptions & { host?: string; port?: number },
): Promise<{ server: Server; url: string; close: () => Promise<void> }> {
  const host = opts.host ?? "127.0.0.1";
  assertSafeHost(host);
  const handler = bridgeHandler(opts);
  const server = createServer((req, res) => void handler(req, res));
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port ?? 0, host, () => resolve());
  });
  const a = server.address() as AddressInfo;
  const h = a.family === "IPv6" ? `[${a.address}]` : a.address;
  return {
    server,
    url: `http://${h}:${a.port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
