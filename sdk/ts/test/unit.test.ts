import { describe, expect, it } from "vitest";
import { addRecipient, decryptObject, encryptFor, encryptObject, manifestToJson, normalizeManifest, RootKey } from "../src/index.js";

describe("crypto", () => {
  it("roundtrip and tamper", () => {
    const root = RootKey.generate();
    const data = Uint8Array.from({ length: 10_000 }, (_, i) => i & 0xff);
    const { chunks, enc } = encryptObject(root, data, 4096);
    expect(chunks.length).toBe(3);
    expect(decryptObject(root, enc, chunks)).toEqual(data);
    expect(() => decryptObject(root, enc, chunks.slice(0, 2))).toThrow(); // truncation
    expect(() => decryptObject(root, enc, [chunks[1]!, chunks[0]!, chunks[2]!])).toThrow(); // reorder
    const f = chunks.map((c) => c.slice());
    f[1]![5]! ^= 1;
    expect(() => decryptObject(root, enc, f)).toThrow(); // bit flip
    expect(() => decryptObject(RootKey.generate(), enc, chunks)).toThrow(); // wrong key
  });

  it("sharing and app-writes-for-user", () => {
    const owner = RootKey.generate(), friend = RootKey.generate(), stranger = RootKey.generate();
    const msg = new TextEncoder().encode("hello");
    const { chunks, enc } = encryptFor([owner, friend.x25519Public()], msg, 4);
    expect(decryptObject(owner, enc, chunks)).toEqual(msg);
    expect(decryptObject(friend, enc, chunks)).toEqual(msg);
    expect(() => decryptObject(stranger, enc, chunks)).toThrow();
    const enc2 = addRecipient(owner, enc, stranger.x25519Public());
    expect(decryptObject(stranger, enc2, chunks)).toEqual(msg);
    // re-adding replaces rather than duplicates
    expect(addRecipient(owner, enc2, stranger.x25519Public()).wrapped_keys.length).toBe(3);
    const app = encryptFor([friend.x25519Public()], msg, 1024);
    expect(decryptObject(friend, app.enc, app.chunks)).toEqual(msg);
    expect(() => decryptObject(owner, app.enc, app.chunks)).toThrow();
  });

  it("empty object is one tag-only chunk", () => {
    const root = RootKey.generate();
    const { chunks, enc } = encryptObject(root, new Uint8Array(0), 1024);
    expect(chunks.length).toBe(1);
    expect(chunks[0]!.length).toBe(16);
    expect(decryptObject(root, enc, chunks).length).toBe(0);
  });

  it("manifest normalization drops unknown fields and nulls", () => {
    const m = normalizeManifest({ chunks: [{ len: 3, cid: "b3:x", extra: 1 }], size: 3, version: 1, chunk_size: 4, enc: null, content_type: null, junk: true });
    expect(manifestToJson(m)).toBe('{"version":1,"size":3,"chunk_size":4,"chunks":[{"cid":"b3:x","len":3}]}');
    expect(() => normalizeManifest({ version: "1", size: 3, chunk_size: 4, chunks: [] })).toThrow();
  });
});

import { cid, manifestCid, NearUri, recordSigningBytes, sign, verifyHead, publicKeyOf, WriterCheck, type Manifest, type PointerRecord } from "../src/index.js";

describe("verifyHead (untrusted gateway responses)", () => {
  const seed = new Uint8Array(32).fill(7);
  const uri = NearUri.parse("near://alice.near/a/b");
  const manifest: Manifest = { version: 1, size: 3, chunk_size: 8, chunks: [{ cid: cid(new TextEncoder().encode("abc")), len: 3 }] };
  const trusted = WriterCheck.trusted({ "alice.near": [publicKeyOf(seed)] });
  const mk = (m: Manifest, over: Partial<PointerRecord> = {}): PointerRecord => {
    const u = { namespace: "alice.near", path: "a/b", manifest_cid: manifestCid(m), size: m.size, stored_size: 100, seq: 1, writer: "alice.near", writer_pk: publicKeyOf(seed), ts_ms: 1, ...over };
    return { ...u, sig: sign(seed, recordSigningBytes(u)) };
  };
  it("accepts a consistent head", () => verifyHead(uri, { record: mk(manifest), manifest }, trusted));
  it("rejects a record for another path", () => expect(verifyHead(uri, { record: mk(manifest, { path: "a/c" }), manifest }, trusted)).rejects.toThrow(/different object/));
  it("rejects a forged signature", () => expect(verifyHead(uri, { record: { ...mk(manifest), seq: 2 }, manifest }, trusted)).rejects.toThrow(/signature/));
  it("rejects a swapped manifest", () => {
    const other = { ...manifest, content_type: "x" };
    return expect(verifyHead(uri, { record: mk(manifest), manifest: other }, trusted)).rejects.toThrow(/manifest does not match/);
  });
  it("rejects inconsistent sizes", () => {
    const m = { ...manifest, size: 4 };
    return expect(verifyHead(uri, { record: mk(m), manifest: m }, trusted)).rejects.toThrow(/do not add up/);
  });
  it("rejects a self-signed record by a key the writer never published", () => {
    const evil = new Uint8Array(32).fill(9);
    const u = { namespace: "alice.near", path: "a/b", manifest_cid: manifestCid(manifest), size: 3, stored_size: 100, seq: 1, writer: "alice.near", writer_pk: publicKeyOf(evil), ts_ms: 1 };
    const record = { ...u, sig: sign(evil, recordSigningBytes(u)) };
    return expect(verifyHead(uri, { record, manifest }, trusted)).rejects.toThrow(/not a signing key of alice.near/);
  });
  it("requires a writer check", () => expect(verifyHead(uri, { record: mk(manifest), manifest }, undefined)).rejects.toThrow(/writerCheck/));
  it("insecure skip accepts any self-signed writer", () => verifyHead(uri, { record: mk(manifest), manifest }, WriterCheck.insecureSkipWriterCheck()));
});
