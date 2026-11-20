/**
 * Read-only access to the `drive.near` contract (NEAR JSON-RPC view calls over `fetch`, so it
 * runs in browsers too) and the reader-side writer check: a record is accepted only if
 * `writer_pk` is a signing key `writer` published with `set_sign_key` (in force at `ts_ms`) and
 * the namespace rules let `writer` write `path`.
 */
import { base64, utf8ToBytes } from "./bytes.js";
import { normalizeRules, resolve, type Rule } from "./policy.js";
import type { PointerRecord } from "./record.js";
import { isValidAccountId } from "./uri.js";

/** One entry of `get_sign_keys(account_id)`, oldest first. */
export interface SignKeyEntry {
  /** `ed25519:<base58>` */
  key: string;
  /** Block time (ms) at which the key was published. */
  since_ms: number;
}

/** Clock skew tolerated around a key change (5 min, like the request-timestamp window). */
export const SIGN_KEY_SKEW_MS = 5 * 60 * 1000;
export const DEFAULT_CACHE_TTL_MS = 60_000;
export const DEFAULT_CACHE_MAX_ENTRIES = 1024;
/** A failed check re-reads chain state once if the cached copy is older than this. */
const REFRESH_AFTER_MS = 5_000;

/**
 * Whether `key` is the key in force at `tsMs`: entry i covers
 * `[since_i - 5 min, since_{i+1} + 5 min)`, the latest entry is open-ended.
 */
export function signKeyInForce(entries: readonly SignKeyEntry[], key: string, tsMs: number): boolean {
  return entries.some((e, i) => {
    if (e.key !== key || tsMs < e.since_ms - SIGN_KEY_SKEW_MS) return false;
    const next = entries[i + 1];
    return next === undefined || tsMs < next.since_ms + SIGN_KEY_SKEW_MS;
  });
}

function normalizeSignKeys(v: unknown): SignKeyEntry[] {
  if (!Array.isArray(v)) throw new Error("get_sign_keys: expected an array");
  return v.map((e) => {
    const o = e as Record<string, unknown>;
    const since = typeof o?.since_ms === "string" ? Number(o.since_ms) : o?.since_ms;
    if (typeof o?.key !== "string" || typeof since !== "number" || !Number.isSafeInteger(since) || since < 0) throw new Error("get_sign_keys: bad entry");
    return { key: o.key, since_ms: since };
  });
}

export interface StorageContractOptions {
  /** Custom fetch (defaults to globalThis.fetch). */
  fetch?: typeof fetch;
  /** Per-call timeout (default 10 s). */
  timeoutMs?: number;
}

/** View calls on a deployed `drive.near` contract (`query` / `call_function`, finality `final`). */
export class StorageContract {
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;

  constructor(
    readonly rpcUrl: string,
    readonly contractId: string,
    o: StorageContractOptions = {},
  ) {
    this.#fetch = o.fetch ?? globalThis.fetch.bind(globalThis);
    this.#timeoutMs = o.timeoutMs ?? 10_000;
  }

  /** `method(args)` as a view call; returns the decoded JSON result. */
  async view(method: string, args: unknown): Promise<unknown> {
    const params = {
      request_type: "call_function",
      finality: "final",
      account_id: this.contractId,
      method_name: method,
      args_base64: base64.encode(utf8ToBytes(JSON.stringify(args))),
    };
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(new Error(`rpc ${method}: timed out`)), this.#timeoutMs);
    let resp: { error?: unknown; result?: { result?: unknown; error?: unknown } };
    try {
      const r = await this.#fetch(this.rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: "near-drive", method: "query", params }),
        signal: ctl.signal,
      });
      if (!r.ok) throw new Error(`rpc ${method}: HTTP ${r.status}`);
      resp = (await r.json()) as typeof resp;
    } finally {
      clearTimeout(t);
    }
    if (resp.error !== undefined) throw new Error(`rpc ${this.contractId}.${method} error: ${JSON.stringify(resp.error)}`);
    const res = resp.result;
    if (res?.error !== undefined) throw new Error(`view ${this.contractId}.${method} failed: ${String(res.error)}`);
    const bytes = res?.result;
    if (!Array.isArray(bytes) || bytes.some((b) => typeof b !== "number" || !Number.isInteger(b) || b < 0 || b > 255)) {
      throw new Error(`view ${method}: missing result bytes`);
    }
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(bytes as number[])));
  }

  /** Signing keys `accountId` published with `set_sign_key`, oldest first. */
  async getSignKeys(accountId: string): Promise<SignKeyEntry[]> {
    return normalizeSignKeys(await this.view("get_sign_keys", { account_id: accountId }));
  }

  /** The namespace's policy rules (empty: only the owner may read/write). */
  async getRules(namespace: string): Promise<Rule[]> {
    return normalizeRules(await this.view("get_rules", { namespace }));
  }
}

/** TTL + size-bounded cache of in-flight/settled lookups. */
class TtlCache<V> {
  readonly #m = new Map<string, { at: number; p: Promise<V> }>();
  constructor(
    readonly ttlMs: number,
    readonly max: number,
  ) {}

  get(k: string, load: () => Promise<V>, fresherThanMs?: number): Promise<V> {
    const now = Date.now();
    const e = this.#m.get(k);
    const maxAge = Math.min(this.ttlMs, fresherThanMs ?? Infinity);
    if (e && now - e.at < maxAge) return e.p;
    this.#m.delete(k);
    while (this.#m.size >= this.max) this.#m.delete(this.#m.keys().next().value!);
    const p = load();
    const ent = { at: now, p };
    this.#m.set(k, ent);
    p.catch(() => {
      if (this.#m.get(k) === ent) this.#m.delete(k);
    });
    return p;
  }

  age(k: string): number {
    const e = this.#m.get(k);
    return e ? Date.now() - e.at : Infinity;
  }

  get size(): number {
    return this.#m.size;
  }
}

export interface ChainCheckOptions extends StorageContractOptions {
  /** Cache lifetime of sign keys / rules (default 60 s). */
  ttlMs?: number;
  /** Max cached accounts and namespaces, each (default 1024). */
  maxEntries?: number;
}

type Mode =
  | { kind: "chain"; contract: StorageContract; keys: TtlCache<SignKeyEntry[]>; rules: TtlCache<Rule[]> }
  | { kind: "trusted"; keys: ReadonlyMap<string, readonly string[]>; rules: ReadonlyMap<string, readonly Rule[]> }
  | { kind: "insecure-skip" };

/**
 * How a client decides that a record's writer was allowed to write it. There is no default
 * that skips the check: a client without one fails reads.
 *
 * - {@link WriterCheck.chain}: `drive.near` state over NEAR RPC (production);
 * - {@link WriterCheck.trusted}: a fixed map of accounts to signing keys (+ optional rules),
 *   for tests and dev gateways without a chain;
 * - {@link WriterCheck.insecureSkipWriterCheck}: no writer check at all (tests only).
 */
export class WriterCheck {
  readonly #mode: Mode;

  private constructor(mode: Mode) {
    this.#mode = mode;
  }

  /** Check against the drive contract (`get_sign_keys`, `get_rules`), cached `ttlMs` (60 s). */
  static chain(contract: StorageContract | { rpcUrl: string; contractId: string }, o: ChainCheckOptions = {}): WriterCheck {
    const c = contract instanceof StorageContract ? contract : new StorageContract(contract.rpcUrl, contract.contractId, o);
    const ttl = o.ttlMs ?? DEFAULT_CACHE_TTL_MS;
    const max = Math.max(1, o.maxEntries ?? DEFAULT_CACHE_MAX_ENTRIES);
    return new WriterCheck({ kind: "chain", contract: c, keys: new TtlCache(ttl, max), rules: new TtlCache(ttl, max) });
  }

  /**
   * Fixed trust (tests, dev gateways): `signKeys` maps an account to its signing keys
   * (`RootKey.signPublicKey()`), all always in force; `rules` maps a namespace to its rules
   * (absent: only the namespace owner may write).
   */
  static trusted(signKeys: Record<string, readonly string[]>, rules: Record<string, readonly Rule[]> = {}): WriterCheck {
    return new WriterCheck({ kind: "trusted", keys: new Map(Object.entries(signKeys)), rules: new Map(Object.entries(rules)) });
  }

  /** INSECURE: accept any correctly self-signed record (a malicious gateway can forge writers). Tests only. */
  static insecureSkipWriterCheck(): WriterCheck {
    return new WriterCheck({ kind: "insecure-skip" });
  }

  get kind(): Mode["kind"] {
    return this.#mode.kind;
  }

  /** Throws unless `r.writer_pk` is `r.writer`'s signing key in force at `r.ts_ms` and `r.writer` may write `r.path`. */
  async verify(r: PointerRecord): Promise<void> {
    const m = this.#mode;
    if (m.kind === "insecure-skip") return;
    const where = `near://${r.namespace}/${r.path}`;
    if (!isValidAccountId(r.writer)) throw new Error(`record for ${where}: invalid writer account ${JSON.stringify(r.writer)}`);
    const keyErr = () => new Error(`record for ${where} is signed with ${r.writer_pk}, which is not a signing key of ${r.writer} in force at ts ${r.ts_ms}`);
    const ruleErr = () => new Error(`record for ${where} was written by ${r.writer}, who may not write there under the namespace rules`);
    if (m.kind === "trusted") {
      if (!(m.keys.get(r.writer) ?? []).includes(r.writer_pk)) throw keyErr();
      if (!resolve(r.namespace, m.rules.get(r.namespace) ?? [], r.path, r.writer).write) throw ruleErr();
      return;
    }
    const keysOk = (fresh?: number) => m.keys.get(r.writer, () => m.contract.getSignKeys(r.writer), fresh).then((ks) => signKeyInForce(ks, r.writer_pk, r.ts_ms));
    const rulesOk = (fresh?: number) => m.rules.get(r.namespace, () => m.contract.getRules(r.namespace), fresh).then((rs) => resolve(r.namespace, rs, r.path, r.writer).write);
    // Owners need no rules lookup.
    const [k, w] = await Promise.all([keysOk(), r.writer === r.namespace ? true : rulesOk()]);
    // A key or rule may have changed within the cache TTL: re-read once before rejecting.
    if (!k && !(m.keys.age(r.writer) < REFRESH_AFTER_MS ? false : await keysOk(REFRESH_AFTER_MS))) throw keyErr();
    if (!w && !(m.rules.age(r.namespace) < REFRESH_AFTER_MS ? false : await rulesOk(REFRESH_AFTER_MS))) throw ruleErr();
  }
}

/** Error for reads on a client with no writer check configured. */
export const NO_WRITER_CHECK =
  "no writer check configured: records cannot be verified against their writer. Pass `writerCheck` " +
  "(WriterCheck.chain({ rpcUrl, contractId }) or WriterCheck.trusted({...}) for dev/tests) or `rpcUrl` in ClientOptions";
