/**
 * Reader-side writer authorization: records must be signed with a key the writer published
 * (`get_sign_keys`) and the namespace rules (`get_rules`) must let the writer write the path.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { base64 } from "@scure/base";
import {
  cid as cidOf,
  Client,
  generateSecretKey,
  manifestCid,
  manifestToBytes,
  recordSigningBytes,
  recordToJson,
  RootKey,
  sign,
  StorageContract,
  WriterCheck,
  publicKeyOf,
  type Manifest,
  type PointerRecord,
  type Rule,
} from "../src/index.js";
import { getFile } from "../src/node.js";
import { fakeGateway } from "./harness.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const FAST = { baseDelayMs: 1, maxDelayMs: 5, attempts: 2 };

/** A NEAR RPC endpoint serving `get_sign_keys` / `get_rules` of a fake drive contract. */
function fakeRpc(contractId = "drive.test") {
  const st = {
    signKeys: new Map<string, { key: string; since_ms: string }[]>(),
    rules: new Map<string, Rule[]>(),
    calls: [] as { method: string; args: Record<string, unknown> }[],
    requests: [] as Record<string, unknown>[],
    fetch: null as unknown as typeof fetch,
  };
  st.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
    const req = JSON.parse(String(init?.body)) as { method: string; params: Record<string, string> };
    st.requests.push(req as unknown as Record<string, unknown>);
    const p = req.params;
    if (req.method !== "query" || p.request_type !== "call_function" || p.account_id !== contractId) {
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: "x", error: { name: "HANDLER_ERROR", cause: { name: "UNKNOWN_ACCOUNT" } } }));
    }
    const args = JSON.parse(new TextDecoder().decode(base64.decode(p.args_base64!))) as Record<string, string>;
    st.calls.push({ method: p.method_name!, args });
    let out: unknown;
    if (p.method_name === "get_sign_keys") out = st.signKeys.get(args.account_id!) ?? [];
    else if (p.method_name === "get_rules") out = st.rules.get(args.namespace!) ?? [];
    else return new Response(JSON.stringify({ jsonrpc: "2.0", id: "x", result: { error: "MethodNotFound" } }));
    const bytes = Array.from(new TextEncoder().encode(JSON.stringify(out)));
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: "x", result: { result: bytes, logs: [], block_height: 1, block_hash: "h" } }));
  }) as typeof fetch;
  return st;
}

const manifest: Manifest = { version: 1, size: 0, chunk_size: 8, chunks: [] };
function rec(seed: Uint8Array, over: Partial<PointerRecord> = {}): PointerRecord {
  const u = { namespace: "alice.near", path: "a", manifest_cid: manifestCid(manifest), size: 0, stored_size: 1, seq: 1, writer: "alice.near", writer_pk: publicKeyOf(seed), ts_ms: 2_000_000_000_000, ...over };
  return { ...u, sig: sign(seed, recordSigningBytes(u)) };
}

describe("StorageContract (JSON-RPC view calls)", () => {
  it("sends query/call_function at final finality with base64 JSON args", async () => {
    const rpc = fakeRpc();
    rpc.signKeys.set("alice.near", [{ key: "ed25519:x", since_ms: "123" }]);
    const c = new StorageContract("http://rpc.test", "drive.test", { fetch: rpc.fetch });
    expect(await c.getSignKeys("alice.near")).toEqual([{ key: "ed25519:x", since_ms: 123 }]);
    expect(rpc.requests[0]).toMatchObject({ jsonrpc: "2.0", method: "query", params: { request_type: "call_function", finality: "final", account_id: "drive.test", method_name: "get_sign_keys" } });
    expect(rpc.calls[0]).toEqual({ method: "get_sign_keys", args: { account_id: "alice.near" } });
    rpc.rules.set("app.near", [{ prefix: "u/", write: ["*"] }]);
    expect(await c.getRules("app.near")).toEqual([{ prefix: "u/", read: [], write: ["*"], payer: null }]);
    expect(rpc.calls[1]).toEqual({ method: "get_rules", args: { namespace: "app.near" } });
  });

  it("surfaces RPC errors", async () => {
    const rpc = fakeRpc();
    await expect(new StorageContract("http://rpc.test", "nope.test", { fetch: rpc.fetch }).getRules("a.near")).rejects.toThrow(/UNKNOWN_ACCOUNT/);
    await expect(new StorageContract("http://rpc.test", "drive.test", { fetch: rpc.fetch }).view("other", {})).rejects.toThrow(/MethodNotFound/);
  });
});

describe("WriterCheck.chain", () => {
  afterEach(() => vi.useRealTimers());
  const alice = new Uint8Array(32).fill(1);
  const app = new Uint8Array(32).fill(2);
  const evil = new Uint8Array(32).fill(3);
  const setup = (o: { ttlMs?: number; maxEntries?: number } = {}) => {
    const rpc = fakeRpc();
    rpc.signKeys.set("alice.near", [{ key: publicKeyOf(alice), since_ms: "1000000000000" }]);
    rpc.signKeys.set("app.near", [{ key: publicKeyOf(app), since_ms: "1000000000000" }]);
    const check = WriterCheck.chain({ rpcUrl: "http://rpc.test", contractId: "drive.test" }, { fetch: rpc.fetch, ...o });
    return { rpc, check };
  };

  it("accepts the owner's published key without a rules lookup, rejects others", async () => {
    const { rpc, check } = setup();
    await check.verify(rec(alice));
    expect(rpc.calls.map((c) => c.method)).toEqual(["get_sign_keys"]);
    await expect(check.verify(rec(evil))).rejects.toThrow(/not a signing key of alice.near/);
    // a key used before it was published (beyond the 5 min skew)
    await expect(check.verify(rec(alice, { ts_ms: 1_000_000_000_000 - 300_001 }))).rejects.toThrow(/not a signing key/);
  });

  it("checks the namespace rules for non-owner writers", async () => {
    const { rpc, check } = setup();
    const r = rec(app, { writer: "app.near", path: "inbox/1" });
    await expect(check.verify(r)).rejects.toThrow(/may not write there/);
    rpc.rules.set("alice.near", [{ prefix: "inbox/", write: ["app.near"] }]);
    vi.useFakeTimers({ now: Date.now() + 6_000, toFake: ["Date"] });
    await check.verify(r); // a failed check re-reads state older than 5 s
    await expect(check.verify(rec(app, { writer: "app.near", path: "other/1" }))).rejects.toThrow(/may not write there/);
  });

  it("caches per account / namespace for the TTL, bounded", async () => {
    const { rpc, check } = setup({ maxEntries: 2 });
    for (let i = 0; i < 5; i++) await check.verify(rec(alice));
    expect(rpc.calls.length).toBe(1);
    vi.useFakeTimers({ now: Date.now() + 61_000, toFake: ["Date"] });
    await check.verify(rec(alice));
    expect(rpc.calls.length).toBe(2);
    // bounded: two more accounts through a 2-entry cache evict alice's keys
    for (const w of ["w1.near", "w2.near"]) await expect(check.verify(rec(alice, { namespace: w, writer: w }))).rejects.toThrow(/not a signing key/);
    const n = rpc.calls.length;
    await check.verify(rec(alice));
    expect(rpc.calls.length).toBe(n + 1);
  });

  it("does not cache failures", async () => {
    let fail = true;
    const rpc = fakeRpc();
    rpc.signKeys.set("alice.near", [{ key: publicKeyOf(alice), since_ms: "1" }]);
    const f = ((u: RequestInfo | URL, init?: RequestInit) => (fail ? Promise.reject(new TypeError("network down")) : rpc.fetch(u, init))) as typeof fetch;
    const check = WriterCheck.chain(new StorageContract("http://rpc.test", "drive.test", { fetch: f }));
    await expect(check.verify(rec(alice))).rejects.toThrow(/network down/);
    fail = false;
    await check.verify(rec(alice));
  });
});

describe("client reads check the writer", () => {
  const sk = generateSecretKey();
  const aliceRoot = RootKey.generate();
  const uri = "near://alice.near/doc.txt";

  /** Put a record that claims `writer` but is signed by `seed`, as a malicious gateway would. */
  function forge(g: ReturnType<typeof fakeGateway>, path: string, seed: Uint8Array, data: string) {
    const c = new TextEncoder().encode(data);
    const ccid = cidOf(c);
    const m: Manifest = { version: 1, size: c.length, chunk_size: 1024, chunks: [{ cid: ccid, len: c.length }] };
    const mbytes = manifestToBytes(m);
    g.chunks.set(ccid, c);
    g.chunks.set(manifestCid(m), mbytes);
    const u = { namespace: "alice.near", path, manifest_cid: manifestCid(m), size: c.length, stored_size: c.length + mbytes.length, seq: 1, writer: "alice.near", writer_pk: publicKeyOf(seed), ts_ms: Date.now() };
    const r = { ...u, sig: sign(seed, recordSigningBytes(u)) };
    g.index.set(`alice.near/${path}`, { record: JSON.parse(recordToJson(r)), class: null });
  }

  it("rejects a forged writer on get, head, locate and getFile", async () => {
    const g = fakeGateway();
    forge(g, "forged.txt", new Uint8Array(32).fill(66), "evil");
    const c = new Client({ gateway: g.url, accountId: "alice.near", signer: sk, rootKey: aliceRoot, writerCheck: WriterCheck.trusted({ "alice.near": [aliceRoot.signPublicKey()] }), net: FAST, fetch: g.fetch });
    const f = "near://alice.near/forged.txt";
    await expect(c.get(f)).rejects.toThrow(/not a signing key of alice.near/);
    await expect(c.head(f)).rejects.toThrow(/not a signing key/);
    await expect(c.locate(f)).rejects.toThrow(/not a signing key/);
    await expect(getFile(c, f, join(mkdtempSync(join(tmpdir(), "drive-ts-w-")), "out"))).rejects.toThrow(/not a signing key/);
    // ... while insecure skip (tests only) would have served it
    const skip = new Client({ gateway: g.url, accountId: "alice.near", signer: sk, writerCheck: WriterCheck.insecureSkipWriterCheck(), net: FAST, fetch: g.fetch });
    expect(new TextDecoder().decode(await skip.get(f))).toBe("evil");
  });

  it("signs records with the derived key; reads verify it over RPC", async () => {
    const g = fakeGateway();
    const rpc = fakeRpc();
    rpc.signKeys.set("alice.near", [{ key: aliceRoot.signPublicKey(), since_ms: "1" }]);
    const c = new Client({ gateway: g.url, accountId: "alice.near", signer: sk, rootKey: aliceRoot, rpcUrl: "http://rpc.test", contractId: "drive.test", net: FAST, fetch: routeFetch(g.fetch, rpc.fetch) });
    const r = await c.put(uri, "hello");
    expect(r.writer_pk).toBe(aliceRoot.signPublicKey());
    expect(r.writer_pk).not.toBe(c.publicKey); // not the request-signing access key
    expect(c.signPublicKey()).toBe(aliceRoot.signPublicKey());
    expect(await c.getText(uri)).toBe("hello");
    expect(rpc.calls.map((x) => x.method)).toEqual(["get_sign_keys"]);
    // key rotated away (the old key's window closed long ago): new reads reject the record
    rpc.signKeys.set("alice.near", [
      { key: aliceRoot.signPublicKey(), since_ms: "1" },
      { key: RootKey.generate().signPublicKey(), since_ms: "2" },
    ]);
    const c2 = new Client({ gateway: g.url, accountId: "alice.near", signer: sk, rootKey: aliceRoot, rpcUrl: "http://rpc.test", contractId: "drive.test", net: FAST, fetch: routeFetch(g.fetch, rpc.fetch) });
    await expect(c2.get(uri)).rejects.toThrow(/not a signing key/);
  });

  it("app writes for a user under the namespace rules, without being able to read", async () => {
    const g = fakeGateway();
    const appRoot = RootKey.generate();
    const bobRoot = RootKey.generate();
    const rules = { "app.near": [{ prefix: "users/{account}/", read: ["{account}"], write: ["{account}", "app.near"], payer: "app.near" }] };
    const writerCheck = WriterCheck.trusted({ "app.near": [appRoot.signPublicKey()], "bob.near": [bobRoot.signPublicKey()] }, rules);
    const app = new Client({ gateway: g.url, accountId: "app.near", signer: generateSecretKey(), rootKey: appRoot, writerCheck, net: FAST, fetch: g.fetch });
    const bob = new Client({ gateway: g.url, accountId: "bob.near", signer: generateSecretKey(), rootKey: bobRoot, writerCheck, net: FAST, fetch: g.fetch });
    const u = "near://app.near/users/bob.near/chat/1";
    await expect(app.put(u, "hi bob", { skipOwnerKey: true })).rejects.toThrow(/no recipients/);
    await app.put(u, "hi bob", { shareWith: [bobRoot.x25519Public()], skipOwnerKey: true });
    expect(await bob.getText(u)).toBe("hi bob");
    await expect(app.get(u)).rejects.toThrow(/not encrypted to this account/);
    // bob may not write into another user's space; a record he signed there is rejected
    await bob.put("near://app.near/users/carol.near/x", "nope");
    await expect(app.head("near://app.near/users/carol.near/x")).rejects.toThrow(/may not write there/);
  });

  it("writing requires the root key; reading requires a writer check", async () => {
    const g = fakeGateway();
    const noRoot = new Client({ gateway: g.url, accountId: "alice.near", signer: sk, writerCheck: WriterCheck.insecureSkipWriterCheck(), net: FAST, fetch: g.fetch });
    await expect(noRoot.put(uri, "x", { public: true })).rejects.toThrow(/writing requires the root key/);
    await expect(noRoot.put(uri, "x", { shareWith: [RootKey.generate().x25519Public()] })).rejects.toThrow(/writing requires the root key/);
    expect(g.chunks.size).toBe(0); // failed before uploading anything
    const noCheck = new Client({ gateway: g.url, accountId: "alice.near", signer: sk, rootKey: aliceRoot, net: FAST, fetch: g.fetch });
    await noCheck.put(uri, "x"); // writes work (the seq lookup needs no writer check)
    await noCheck.put(uri, "y");
    await expect(noCheck.get(uri)).rejects.toThrow(/no writer check configured.*writerCheck.*rpcUrl/);
    await expect(noCheck.head(uri)).rejects.toThrow(/writerCheck/);
  });
});

/** Send RPC posts to `rpc`, everything else to the gateway. */
function routeFetch(gw: typeof fetch, rpc: typeof fetch): typeof fetch {
  return ((u: RequestInfo | URL, init?: RequestInit) => (String(u).startsWith("http://rpc.test") ? rpc(u, init) : gw(u, init))) as typeof fetch;
}
