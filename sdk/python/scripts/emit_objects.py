"""Encrypt a fixed set of objects with the Python SDK and write them as decrypt-side
vectors for the Rust test ``crates/nstorage-core/tests/sdk_vectors.rs``.

Usage: python scripts/emit_objects.py ../../testvectors/sdk_objects_py.json
"""
import json
import sys
from pathlib import Path

from nstorage import ChunkRef, Manifest, RootKey, add_recipient, cid, encrypt_for, plaintext_chunks

V = json.loads((Path(__file__).resolve().parents[3] / "testvectors" / "vectors.json").read_text())
R = {k: RootKey.from_hex(r["root_key"]) for k, r in V["roots"].items()}
ALL = ["owner", "friend", "stranger"]


def seq(n, mul, add):
    return bytes((i * mul + add) & 0xFF for i in range(n))


cases = [
    dict(name="single_chunk_owner", pt="hello from python".encode(), cs=4194304, rs=["owner"], ct='text/plain; q="ü🙂" \\ \n\t\x01\x7f'),
    dict(name="multi_chunk_owner", pt=seq(1000, 13, 5), cs=256, rs=["owner"]),
    dict(name="empty_owner", pt=b"", cs=1024, rs=["owner"]),
    dict(name="owner_and_x25519", pt=seq(300, 1, 0), cs=100, rs=["owner", "friend"], ct="application/octet-stream"),
    dict(name="x25519_only", pt=b"app wrote this for friend", cs=7, rs=["friend"]),
    dict(name="shared_after", pt=seq(50, 3, 1), cs=16, rs=["owner"], share_after="stranger"),
    dict(name="public", pt=seq(20, 1, 65), cs=8, rs=[]),
]
objects = []
for c in cases:
    enc = None
    if not c["rs"]:
        chunks = plaintext_chunks(c["pt"], c["cs"])
    else:
        chunks, enc = encrypt_for([R["owner"] if r == "owner" else R[r].x25519_public() for r in c["rs"]], c["pt"], c["cs"])
    if c.get("share_after"):
        enc = add_recipient(R["owner"], enc, R[c["share_after"]].x25519_public())
    m = Manifest(1, len(c["pt"]), c["cs"], [ChunkRef(cid(x), len(x)) for x in chunks], enc, c.get("ct"))
    readable = (c["rs"] + ([c["share_after"]] if c.get("share_after") else [])) if enc else ALL
    objects.append(
        dict(
            name=c["name"],
            plaintext_hex=c["pt"].hex(),
            chunk_size=c["cs"],
            chunks_hex=[x.hex() for x in chunks],
            manifest_json=m.to_json(),
            manifest_cid=m.cid(),
            readable_by=readable,
            not_readable_by=[w for w in ALL if w not in readable],
        )
    )
out = json.dumps({"comment": "Produced by sdk/python/scripts/emit_objects.py; roots from vectors.json", "objects": objects}, indent=2, ensure_ascii=False) + "\n"
if len(sys.argv) > 1:
    Path(sys.argv[1]).write_text(out)
else:
    sys.stdout.write(out)
