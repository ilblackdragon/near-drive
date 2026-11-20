import json
from pathlib import Path

import pytest

from near_drive import (
    Manifest,
    NearUri,
    PointerRecord,
    RootKey,
    Rule,
    SignKeyEntry,
    WriterCheck,
    canonical_request,
    cid,
    decrypt_object,
    encode_path,
    format_secret_key,
    parse_secret_key,
    public_key_of,
    resolve_policy,
    sign,
    sign_key_in_force,
    verify,
)

V = json.loads((Path(__file__).resolve().parents[3] / "testvectors" / "vectors.json").read_text())
ROOTS = {k: RootKey.from_hex(r["root_key"]) for k, r in V["roots"].items()}
SEED = bytes.fromhex(V["ed25519"]["seed_hex"])
#: Record-signing-key vectors. Interim file generated independently of the SDKs by
#: testvectors/gen_sdk_sign_vectors.py; switch to the Rust-generated vectors here once they exist.
SIGN_VECTORS = json.loads((Path(__file__).resolve().parents[3] / "testvectors" / "sdk_sign_vectors.json").read_text())


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


def test_sign_key_derivation():
    for r in SIGN_VECTORS["roots"].values():
        k = RootKey.from_hex(r["root_key"])
        assert k.sign_seed().hex() == r["sign_seed"]
        assert k.sign_public_key() == r["sign_public_key"]


def test_records_signed_with_derived_key():
    for v in SIGN_VECTORS["records"]:
        rec = PointerRecord.from_dict(v["record"])
        k = RootKey.from_hex(SIGN_VECTORS["roots"][v["signed_by"]]["root_key"])
        assert rec.signing_bytes().decode() == v["signing_string"]
        assert sign(k.sign_seed(), rec.signing_bytes()) == rec.sig
        assert rec.writer_pk == k.sign_public_key()
        rec.verify_signature()
        WriterCheck.trusted({rec.writer: [k.sign_public_key()]}, {"app.near": [{"prefix": "users/", "write": ["alice.near"]}]}).verify(rec)


def test_sign_key_in_force():
    for c in SIGN_VECTORS["sign_key_in_force"]:
        entries = [SignKeyEntry.from_dict(e) for e in c["entries"]]
        assert sign_key_in_force(entries, c["key"], c["ts_ms"]) == c["ok"], c


def test_policy():
    for c in SIGN_VECTORS["policy"]:
        a = resolve_policy(c["namespace"], [Rule.from_dict(r) for r in c["rules"]], c["path"], c["signer"])
        assert (a.read, a.write, a.payer) == (c["read"], c["write"], c["payer"]), c


def test_rust_sign_vectors():
    """Rust-generated (gen_vectors.rs) signing keys, signed records and writer checks."""
    for r in V["roots"].values():
        k = RootKey.from_hex(r["root_key"])
        assert k.sign_seed().hex() == r["sign_seed"]
        assert k.sign_public_key() == r["sign_public_key"]
    for v in V["signed_records"]:
        rec = PointerRecord.from_dict(v["record"])
        rec.verify_signature()
        assert sign(ROOTS[v["root"]].sign_seed(), rec.signing_bytes()) == rec.sig
    for c in V["writer_checks"]:
        entries = [SignKeyEntry.from_dict(e) for e in c["sign_keys"]]
        rules = [Rule.from_dict(r) for r in c["rules"]]
        ok = sign_key_in_force(entries, c["writer_pk"], c["ts_ms"]) and (
            c["writer"] == c["namespace"] or resolve_policy(c["namespace"], rules, c["path"], c["writer"]).write
        )
        assert ok == c["accept"], c["name"]
