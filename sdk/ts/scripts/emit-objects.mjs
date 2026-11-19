// Encrypt a fixed set of objects with the TS SDK and write them as decrypt-side
// vectors for the Rust test `crates/nstorage-core/tests/sdk_vectors.rs`.
// Usage: node scripts/emit-objects.mjs ../../testvectors/sdk_objects_ts.json   (after `npm run build`)
import { readFileSync, writeFileSync } from "node:fs";
import { addRecipient, cid, encryptFor, manifestCid, manifestToJson, plaintextChunks, RootKey } from "../dist/index.js";

const V = JSON.parse(readFileSync(new URL("../../../testvectors/vectors.json", import.meta.url), "utf8"));
const R = Object.fromEntries(Object.entries(V.roots).map(([k, r]) => [k, RootKey.fromHex(r.root_key)]));
const hex = (b) => Buffer.from(b).toString("hex");
const seq = (n, mul, add) => Uint8Array.from({ length: n }, (_, i) => (i * mul + add) & 0xff);

const cases = [
  { name: "single_chunk_owner", pt: new TextEncoder().encode("hello from typescript"), cs: 4194304, rs: ["owner"], ct: 'text/plain; q="ü🙂" \\ \n\t\u0001\u007f' },
  { name: "multi_chunk_owner", pt: seq(1000, 13, 5), cs: 256, rs: ["owner"] },
  { name: "empty_owner", pt: new Uint8Array(0), cs: 1024, rs: ["owner"] },
  { name: "owner_and_x25519", pt: seq(300, 1, 0), cs: 100, rs: ["owner", "friend"], ct: "application/octet-stream" },
  { name: "x25519_only", pt: new TextEncoder().encode("app wrote this for friend"), cs: 7, rs: ["friend"] },
  { name: "shared_after", pt: seq(50, 3, 1), cs: 16, rs: ["owner"], shareAfter: "stranger" },
  { name: "public", pt: seq(20, 1, 65), cs: 8, rs: [] },
];
const objects = cases.map((c) => {
  let chunks, enc;
  if (c.rs.length === 0) chunks = plaintextChunks(c.pt, c.cs);
  else ({ chunks, enc } = encryptFor(c.rs.map((r) => (r === "owner" ? R.owner : R[r].x25519Public())), c.pt, c.cs));
  if (c.shareAfter) enc = addRecipient(R.owner, enc, R[c.shareAfter].x25519Public());
  const m = { version: 1, size: c.pt.length, chunk_size: c.cs, chunks: chunks.map((x) => ({ cid: cid(x), len: x.length })) };
  if (enc) m.enc = enc;
  if (c.ct !== undefined) m.content_type = c.ct;
  const readable = enc ? [...c.rs, ...(c.shareAfter ? [c.shareAfter] : [])] : ["owner", "friend", "stranger"];
  return {
    name: c.name,
    plaintext_hex: hex(c.pt),
    chunk_size: c.cs,
    chunks_hex: chunks.map(hex),
    manifest_json: manifestToJson(m),
    manifest_cid: manifestCid(m),
    readable_by: readable,
    not_readable_by: ["owner", "friend", "stranger"].filter((w) => !readable.includes(w)),
  };
});
const out = JSON.stringify({ comment: "Produced by sdk/ts/scripts/emit-objects.mjs; roots from vectors.json", objects }, null, 2) + "\n";
if (process.argv[2]) writeFileSync(process.argv[2], out);
else process.stdout.write(out);
