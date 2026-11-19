/**
 * Network behaviour: deadlines and retries for every gateway request (same
 * policy as the Rust client's `NetConfig`).
 *
 * - Each request gets a deadline that grows with its size
 *   (`baseTimeoutMs + bytes / minThroughput`), plus an idle timeout while the
 *   response body streams in, so a stalled connection fails fast and a slow
 *   but moving one is not cut off.
 * - Transient failures (network errors, timeouts, truncated bodies, 5xx, 408,
 *   429) are retried with full-jitter exponential backoff, honouring
 *   `Retry-After`. Each attempt is signed afresh.
 */

export interface NetConfig {
  /** Attempts per request (1 = no retries). Default 8. */
  attempts: number;
  /** First backoff; doubles per attempt (full jitter), capped at `maxDelayMs`. Default 250. */
  baseDelayMs: number;
  /** Default 30 000. */
  maxDelayMs: number;
  /** Fail when no response bytes arrive for this long. Default 60 000. */
  idleTimeoutMs: number;
  /** Deadline for a request moving no payload. Default 30 000. */
  baseTimeoutMs: number;
  /** Slowest acceptable transfer rate (bytes/s); sets the deadline of large requests. Default 64 KiB/s. */
  minThroughput: number;
}

export const DEFAULT_NET: Readonly<NetConfig> = Object.freeze({
  attempts: 8,
  baseDelayMs: 250,
  maxDelayMs: 30_000,
  idleTimeoutMs: 60_000,
  baseTimeoutMs: 30_000,
  minThroughput: 64 * 1024,
});

/** Deadline (ms) for a request that moves `bytes` of payload in either direction. */
export function timeoutFor(cfg: NetConfig, bytes: number): number {
  return cfg.baseTimeoutMs + (bytes / Math.max(1, cfg.minThroughput)) * 1000;
}

/** Full-jitter backoff before retry number `attempt` (0-based), at least `floorMs`. */
export function retryDelay(cfg: NetConfig, attempt: number, floorMs?: number): number {
  const cap = Math.min(cfg.baseDelayMs * 2 ** Math.min(attempt, 16), cfg.maxDelayMs);
  const jitter = cap * Math.random();
  return floorMs === undefined ? jitter : Math.max(jitter, Math.min(floorMs, cfg.maxDelayMs * 4));
}

export function retryableStatus(s: number): boolean {
  return s >= 500 || s === 429 || s === 408;
}

/** A fully read response. */
export interface Resp {
  status: number;
  ok: boolean;
  headers: Headers;
  body: Uint8Array;
}

/** Non-2xx answer from the gateway. */
export class GatewayError extends Error {
  constructor(
    readonly status: number,
    readonly body: string,
  ) {
    super(`gateway returned ${status}: ${body}`);
    this.name = "GatewayError";
  }
}

/** A conditional write or delete found a different current version. */
export class ConflictError extends Error {
  constructor(
    readonly uri: string,
    /** Current seq (0 = the object does not exist). */
    readonly current: number,
  ) {
    super(`${uri} changed concurrently (current seq ${current})`);
    this.name = "ConflictError";
  }
}

/** Outcome of one attempt. */
export type Attempt<T> = { done: T } | { retry: Error; waitMs?: number } | { fatal: Error };

export const done = <T>(v: T): Attempt<T> => ({ done: v });
export const transport = <T>(e: unknown): Attempt<T> => ({ retry: e instanceof Error ? e : new Error(String(e)) });

function retryAfterMs(h: Headers): number | undefined {
  const v = h.get("retry-after")?.trim();
  return v && /^\d+$/.test(v) ? Number(v) * 1000 : undefined;
}

/** Turn a non-success response into a retry or a fatal {@link GatewayError}. */
export function reject<T>(r: Resp): Attempt<T> {
  const e = new GatewayError(r.status, new TextDecoder().decode(r.body));
  return retryableStatus(r.status) ? { retry: e, waitMs: retryAfterMs(r.headers) } : { fatal: e };
}

export function okOrAttempt(r: Resp): Attempt<Resp> {
  return r.ok ? done(r) : reject(r);
}

export const sleep = (ms: number) => new Promise<void>((res) => setTimeout(res, ms));

export function debug(msg: string): void {
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
  if (env?.NEAR_DRIVE_DEBUG) console.error(`near-drive: ${msg}`);
}

/** Run `f(attempt)` until it is done, fatal, or out of attempts. */
export async function withRetries<T>(cfg: NetConfig, what: string, f: (attempt: number) => Promise<Attempt<T>>): Promise<T> {
  const attempts = Math.max(1, cfg.attempts);
  for (let attempt = 0; ; attempt++) {
    let a: Attempt<T>;
    try {
      a = await f(attempt);
    } catch (e) {
      a = { fatal: e instanceof Error ? e : new Error(String(e)) };
    }
    if ("done" in a) return a.done;
    if ("fatal" in a) throw a.fatal;
    if (attempt + 1 >= attempts) {
      debug(`${what}: giving up after ${attempts} attempts`);
      throw a.retry;
    }
    const d = retryDelay(cfg, attempt, a.waitMs);
    debug(`${what}: ${a.retry.message}; retry ${attempt + 1} in ${Math.round(d)}ms`);
    await sleep(d);
  }
}

/**
 * One HTTP exchange with a deadline of `timeoutMs` and an idle timeout while
 * the body streams in; the body is read completely (a cut-off body throws).
 */
export async function fetchFully(f: typeof fetch, url: string, init: RequestInit, timeoutMs: number, idleMs: number): Promise<Resp> {
  const ac = new AbortController();
  const deadline = setTimeout(() => ac.abort(new Error(`request timed out after ${Math.round(timeoutMs)}ms`)), timeoutMs);
  let idle: ReturnType<typeof setTimeout> | undefined;
  const kick = () => {
    if (idle !== undefined) clearTimeout(idle);
    idle = setTimeout(() => ac.abort(new Error(`no data for ${idleMs}ms`)), idleMs);
  };
  try {
    const r = await f(url, { ...init, signal: ac.signal });
    kick();
    const parts: Uint8Array[] = [];
    let n = 0;
    if (r.body) {
      const reader = r.body.getReader();
      const aborted = new Promise<never>((_, rej) => {
        if (ac.signal.aborted) rej(ac.signal.reason);
        ac.signal.addEventListener("abort", () => rej(ac.signal.reason), { once: true });
      });
      aborted.catch(() => {});
      try {
        for (;;) {
          const { value, done: end } = await Promise.race([reader.read(), aborted]);
          if (end) break;
          parts.push(value);
          n += value.length;
          kick();
        }
      } catch (e) {
        reader.cancel().catch(() => {});
        throw e;
      }
    }
    const declared = r.headers.get("content-length");
    // (only meaningful for an identity-encoded body)
    if (declared !== null && /^\d+$/.test(declared) && Number(declared) !== n && init.method !== "HEAD" && !r.headers.get("content-encoding")) {
      throw new Error(`response truncated: ${n} of ${declared} bytes`);
    }
    const body = new Uint8Array(n);
    let off = 0;
    for (const p of parts) {
      body.set(p, off);
      off += p.length;
    }
    return { status: r.status, ok: r.ok, headers: r.headers, body };
  } finally {
    clearTimeout(deadline);
    if (idle !== undefined) clearTimeout(idle);
  }
}
