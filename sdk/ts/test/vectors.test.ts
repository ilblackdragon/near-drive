import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  canonicalRequest,
  cid,
  decryptObject,
  encodePath,
  formatSecretKey,
  manifestCid,
  manifestToJson,
  NearUri,
  normalizeManifest,
  parseManifest,
  parsePublicKey,
  parseSecretKey,
  publicKeyOf,
  recordSigningBytes,
  RootKey,
  resolvePolicy,
  sign,
  signKeyInForce,
  verify,
  verifyRecordSignature,
  WriterCheck,
  type PointerRecord,
  type SignKeyEntry,
} from "../src/index.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "../src/bytes.js";

const V = JSON.parse(readFileSync(fileURLToPath(new URL("../../../testvectors/vectors.json", import.meta.url)), "utf8"));
/**
 * Record-signing-key vectors. Interim file generated independently of the SDKs by
 * testvectors/gen_sdk_sign_vectors.py; switch to the Rust-generated vectors here once they exist.
 */
const SIGN_VECTORS = JSON.parse(readFileSync(fileURLToPath(new URL("../../../testvectors/sdk_sign_vectors.json", import.meta.url)), "utf8"));
const roots: Record<string, RootKey> = Object.fromEntries(Object.entries(V.roots).map(([k, r]: [string, any]) => [k, RootKey.fromHex(r.root_key)]));

describe("vectors", () => {
  it("cid", () => {
    for (const c of V.cid) expect(cid(hexToBytes(c.input_hex))).toBe(c.cid);
  });

  it("ed25519 NEAR keys and signatures", () => {
    const e = V.ed25519;
    const seed = hexToBytes(e.seed_hex);
    expect(formatSecretKey(seed)).toBe(e.secret_key);
    expect(bytesToHex(parseSecretKey(e.secret_key))).toBe(e.seed_hex);
    expect(bytesToHex(parseSecretKey(e.secret_key_32))).toBe(e.seed_hex);
    expect(publicKeyOf(seed)).toBe(e.public_key);
    parsePublicKey(e.public_key);
    for (const s of e.signatures) {
      expect(sign(seed, hexToBytes(s.msg_hex))).toBe(s.sig);
      expect(verify(e.public_key, hexToBytes(s.msg_hex), s.sig)).toBe(true);
      expect(verify(e.public_key, utf8ToBytes("other"), s.sig)).toBe(false);
    }
  });

  it("root key derivations", () => {
    for (const r of Object.values(V.roots) as any[]) {
      const k = RootKey.fromHex(r.root_key);
      expect(bytesToHex(k.kek())).toBe(r.kek);
      expect(k.kekId()).toBe(r.kek_id);
      expect(bytesToHex(k.x25519Secret())).toBe(r.x25519_secret);
      expect(k.x25519Public()).toBe(r.x25519_public);
    }
  });

  it("uris and path encoding", () => {
    for (const u of V.uri.valid) {
      const p = NearUri.parse(u.uri);
      expect([p.namespace, p.path, p.toString()]).toEqual([u.namespace, u.path, u.display]);
    }
    for (const u of V.uri.invalid) expect(() => NearUri.parse(u), u).toThrow();
    for (const p of V.uri.object_invalid_paths) expect(() => NearUri.object("alice.near", p)).toThrow();
    expect(() => NearUri.object("alice.near", "a".repeat(1024))).not.toThrow();
    expect(() => NearUri.object("alice.near", "a".repeat(1025))).toThrow();
    for (const e of V.uri.encode_path) expect(encodePath(e.path)).toBe(e.encoded);
  });

  it("canonical requests", () => {
    const seed = hexToBytes(V.ed25519.seed_hex);
    for (const c of V.canonical_requests) {
      const msg = canonicalRequest(c.method, c.path, c.query, c.account, c.public_key, c.ts_ms, hexToBytes(c.body_hex));
      expect(new TextDecoder().decode(msg)).toBe(c.canonical);
      expect(sign(seed, msg)).toBe(c.signature);
    }
  });

  it("records", () => {
    const seed = hexToBytes(V.ed25519.seed_hex);
    for (const r of V.records) {
      const rec = r.record as PointerRecord;
      expect(new TextDecoder().decode(recordSigningBytes(rec))).toBe(r.signing_string);
      expect(sign(seed, recordSigningBytes(rec))).toBe(rec.sig);
      verifyRecordSignature(rec);
      expect(() => verifyRecordSignature({ ...rec, seq: rec.seq + 1 })).toThrow();
    }
  });

  it("manifest serialization", () => {
    for (const m of V.manifests) {
      // `manifest` in the vector file is key-sorted (serde_json::Value), like gateway responses.
      expect(manifestToJson(normalizeManifest(m.manifest))).toBe(m.json);
      expect(manifestCid(normalizeManifest(m.manifest))).toBe(m.cid);
      expect(cid(utf8ToBytes(m.json))).toBe(m.cid);
    }
  });

  const load = (f: string) => JSON.parse(readFileSync(fileURLToPath(new URL(`../../../testvectors/${f}`, import.meta.url)), "utf8")).objects;
  it.each([
    ["vectors.json (Rust)", () => V.objects],
    ["sdk_objects_py.json (Python)", () => load("sdk_objects_py.json")],
    ["sdk_objects_ts.json (TS)", () => load("sdk_objects_ts.json")],
  ])("encrypted objects decrypt: %s", (_label, objs) => {
    for (const o of objs()) {
      const chunks = o.chunks_hex.map((h: string) => hexToBytes(h));
      const m = parseManifest(utf8ToBytes(o.manifest_json));
      expect(manifestToJson(m)).toBe(o.manifest_json);
      if (o.manifest) expect(manifestToJson(normalizeManifest(o.manifest))).toBe(o.manifest_json);
      expect(manifestCid(m)).toBe(o.manifest_cid);
      m.chunks.forEach((c, i) => expect(cid(chunks[i])).toBe(c.cid));
      for (const who of o.readable_by) {
        const pt = m.enc ? decryptObject(roots[who]!, m.enc, chunks) : Buffer.concat(chunks);
        expect(bytesToHex(pt), `${o.name} by ${who}`).toBe(o.plaintext_hex);
      }
      for (const who of o.not_readable_by) expect(() => decryptObject(roots[who]!, m.enc!, chunks)).toThrow();
    }
  });

  it("record signing key derivation", () => {
    for (const r of Object.values(SIGN_VECTORS.roots) as any[]) {
      const k = RootKey.fromHex(r.root_key);
      expect(bytesToHex(k.signSeed())).toBe(r.sign_seed);
      expect(k.signPublicKey()).toBe(r.sign_public_key);
    }
  });

  it("records signed with the derived key", async () => {
    for (const v of SIGN_VECTORS.records) {
      const rec = v.record as PointerRecord;
      const k = RootKey.fromHex(SIGN_VECTORS.roots[v.signed_by].root_key);
      expect(new TextDecoder().decode(recordSigningBytes(rec))).toBe(v.signing_string);
      expect(sign(k.signSeed(), recordSigningBytes(rec))).toBe(rec.sig);
      expect(rec.writer_pk).toBe(k.signPublicKey());
      verifyRecordSignature(rec);
      await WriterCheck.trusted({ [rec.writer]: [k.signPublicKey()] }, { "app.near": [{ prefix: "users/", write: ["alice.near"] }] }).verify(rec);
    }
  });

  it("sign key in force", () => {
    for (const c of SIGN_VECTORS.sign_key_in_force) {
      const entries: SignKeyEntry[] = c.entries.map((e: any) => ({ key: e.key, since_ms: Number(e.since_ms) }));
      expect(signKeyInForce(entries, c.key, c.ts_ms), JSON.stringify(c)).toBe(c.ok);
    }
  });

  it("namespace policy", () => {
    for (const c of SIGN_VECTORS.policy) {
      expect(resolvePolicy(c.namespace, c.rules, c.path, c.signer), JSON.stringify(c)).toEqual({ read: c.read, write: c.write, payer: c.payer });
    }
  });
  it("Rust-generated signing vectors", () => {
    for (const r of Object.values(V.roots) as any[]) {
      const k = RootKey.fromHex(r.root_key);
      expect(bytesToHex(k.signSeed())).toBe(r.sign_seed);
      expect(k.signPublicKey()).toBe(r.sign_public_key);
    }
    for (const v of V.signed_records) {
      const rec = v.record as PointerRecord;
      verifyRecordSignature(rec);
      expect(sign(roots[v.root]!.signSeed(), recordSigningBytes(rec))).toBe(rec.sig);
    }
    for (const c of V.writer_checks) {
      const entries: SignKeyEntry[] = c.sign_keys.map((e: any) => ({ key: e.key, since_ms: Number(e.since_ms) }));
      const ok = signKeyInForce(entries, c.writer_pk, c.ts_ms) && (c.writer === c.namespace || resolvePolicy(c.namespace, c.rules, c.path, c.writer).write);
      expect(ok, c.name).toBe(c.accept);
    }
  });
});
