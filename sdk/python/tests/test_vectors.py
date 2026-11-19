import json
from pathlib import Path

import pytest

from nstorage import (
    Manifest,
    NearUri,
    PointerRecord,
    RootKey,
    canonical_request,
    cid,
    decrypt_object,
    encode_path,
    format_secret_key,
    parse_secret_key,
    public_key_of,
    sign,
    verify,
)

V = json.loads((Path(__file__).resolve().parents[3] / "testvectors" / "vectors.json").read_text())
ROOTS = {k: RootKey.from_hex(r["root_key"]) for k, r in V["roots"].items()}
SEED = bytes.fromhex(V["ed25519"]["seed_hex"])


def test_cid():
    for c in V["cid"]:
        assert cid(bytes.fromhex(c["input_hex"])) == c["cid"]


def test_ed25519():
    e = V["ed25519"]
    assert format_secret_key(SEED) == e["secret_key"]
    assert parse_secret_key(e["secret_key"]) == SEED
    assert parse_secret_key(e["secret_key_32"]) == SEED
    assert public_key_of(SEED) == e["public_key"]
    for s in e["signatures"]:
        msg = bytes.fromhex(s["msg_hex"])
        assert sign(SEED, msg) == s["sig"]
        assert verify(e["public_key"], msg, s["sig"])
        assert not verify(e["public_key"], b"other", s["sig"])


def test_root_derivations():
    for r in V["roots"].values():
        k = RootKey.from_hex(r["root_key"])
        assert k.kek().hex() == r["kek"]
        assert k.kek_id() == r["kek_id"]
        assert k.x25519_secret().hex() == r["x25519_secret"]
        assert k.x25519_public() == r["x25519_public"]


def test_uris():
    for u in V["uri"]["valid"]:
        p = NearUri.parse(u["uri"])
        assert (p.namespace, p.path, str(p)) == (u["namespace"], u["path"], u["display"])
    for u in V["uri"]["invalid"]:
        with pytest.raises(ValueError):
            NearUri.parse(u)
    for p in V["uri"]["object_invalid_paths"]:
        with pytest.raises(ValueError):
            NearUri.object("alice.near", p)
    NearUri.object("alice.near", "a" * 1024)
    with pytest.raises(ValueError):
        NearUri.object("alice.near", "a" * 1025)
    for e in V["uri"]["encode_path"]:
        assert encode_path(e["path"]) == e["encoded"]


def test_canonical_requests():
    for c in V["canonical_requests"]:
        msg = canonical_request(c["method"], c["path"], c["query"], c["account"], c["public_key"], c["ts_ms"], bytes.fromhex(c["body_hex"]))
        assert msg.decode() == c["canonical"]
        assert sign(SEED, msg) == c["signature"]


def test_records():
    for r in V["records"]:
        rec = PointerRecord.from_dict(r["record"])
        assert rec.signing_bytes().decode() == r["signing_string"]
        assert sign(SEED, rec.signing_bytes()) == rec.sig
        rec.verify_signature()
        rec.seq += 1
        with pytest.raises(ValueError):
            rec.verify_signature()


def test_manifests():
    for m in V["manifests"]:
        man = Manifest.from_dict(m["manifest"])  # key-sorted, like gateway responses
        assert man.to_json() == m["json"]
        assert man.cid() == m["cid"]


def _objects():
    d = Path(__file__).resolve().parents[3] / "testvectors"
    for f in ["vectors.json", "sdk_objects_ts.json", "sdk_objects_py.json"]:
        for o in json.loads((d / f).read_text())["objects"]:
            yield pytest.param(o, id=f"{f}:{o['name']}")


@pytest.mark.parametrize("o", list(_objects()))
def test_objects(o):
    chunks = [bytes.fromhex(h) for h in o["chunks_hex"]]
    m = Manifest.from_bytes(o["manifest_json"].encode())
    assert m.to_json() == o["manifest_json"]
    if "manifest" in o:
        assert Manifest.from_dict(o["manifest"]).to_json() == o["manifest_json"]
    assert m.cid() == o["manifest_cid"]
    for c, ch in zip(m.chunks, chunks):
        assert cid(ch) == c.cid
    for who in o["readable_by"]:
        pt = decrypt_object(ROOTS[who], m.enc, chunks) if m.enc else b"".join(chunks)
        assert pt.hex() == o["plaintext_hex"]
    for who in o["not_readable_by"]:
        with pytest.raises(ValueError):
            decrypt_object(ROOTS[who], m.enc, chunks)
