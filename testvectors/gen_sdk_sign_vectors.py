#!/usr/bin/env python3
"""Generate testvectors/sdk_sign_vectors.json: record-signing-key derivation, a record signed
with the derived key, sign-key-in-force cases and namespace-policy cases.

Independent of the SDKs (uses the `cryptography` package, not near_drive / @near-drive/sdk), and
mirrors the Rust reference exactly:
  sign_seed = HKDF-SHA256(salt=b"near-drive", ikm=root, info=b"near-drive/v1/sign", L=32)
  sign_sk   = ed25519_dalek::SigningKey::from_bytes(&sign_seed)   (RFC 8032 seed)
  sign_pk   = "ed25519:" + base58(public key)                       (keys::format_public_key)
Records keep the "near-drive-record-v1\\n..." signing string; writer_pk is sign_pk.

Superseded once the Rust generator (gen_vectors) emits the same data into vectors.json; the SDK
tests read this file through one `SIGN_VECTORS` constant so switching is a one-line change.

    python3 testvectors/gen_sdk_sign_vectors.py testvectors/sdk_sign_vectors.json
"""
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def derive(root: bytes, info: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"near-drive", info=info.encode()).derive(root)


def pub(seed: bytes) -> str:
    pk = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + b58(pk)


def sign(seed: bytes, msg: bytes) -> str:
    return b58(Ed25519PrivateKey.from_private_bytes(seed).sign(msg))


def signing_string(r: dict) -> str:
    f = ["namespace", "path", "manifest_cid", "size", "stored_size", "seq", "writer", "writer_pk", "ts_ms"]
    return "near-drive-record-v1\n" + "\n".join(str(r[k]) for k in f)


def main(out: str) -> None:
    here = Path(__file__).resolve().parent
    V = json.loads((here / "vectors.json").read_text())
    roots = {}
    seeds = {}
    for name, r in V["roots"].items():
        root = bytes.fromhex(r["root_key"])
        seed = derive(root, "near-drive/v1/sign")
        seeds[name] = seed
        roots[name] = {"root_key": r["root_key"], "sign_seed": seed.hex(), "sign_public_key": pub(seed)}

    base = V["records"][0]["record"]
    records = []
    for who, over in [("owner", {}), ("owner", {"path": "users/bob.near/x", "namespace": "app.near", "writer": "alice.near", "seq": 3})]:
        r = {k: base[k] for k in ["namespace", "path", "manifest_cid", "size", "stored_size", "seq", "writer"]}
        r.update(over)
        r["writer_pk"] = roots[who]["sign_public_key"]
        r["ts_ms"] = base["ts_ms"]
        s = signing_string(r)
        r["sig"] = sign(seeds[who], s.encode())
        records.append({"signed_by": who, "record": r, "signing_string": s})

    A, B = roots["owner"]["sign_public_key"], roots["friend"]["sign_public_key"]
    M = 5 * 60 * 1000
    hist = [{"key": A, "since_ms": "1000000000"}, {"key": B, "since_ms": "2000000000"}]
    in_force = [
        {"entries": [], "key": A, "ts_ms": 1, "ok": False},
        {"entries": hist[:1], "key": A, "ts_ms": 1000000000, "ok": True},
        {"entries": hist[:1], "key": A, "ts_ms": 1000000000 - M, "ok": True},
        {"entries": hist[:1], "key": A, "ts_ms": 1000000000 - M - 1, "ok": False},
        {"entries": hist[:1], "key": A, "ts_ms": 9000000000000, "ok": True},
        {"entries": hist[:1], "key": B, "ts_ms": 1500000000, "ok": False},
        {"entries": hist, "key": A, "ts_ms": 1500000000, "ok": True},
        {"entries": hist, "key": A, "ts_ms": 2000000000 + M - 1, "ok": True},
        {"entries": hist, "key": A, "ts_ms": 2000000000 + M, "ok": False},
        {"entries": hist, "key": B, "ts_ms": 2000000000 - M, "ok": True},
        {"entries": hist, "key": B, "ts_ms": 2000000000 - M - 1, "ok": False},
        {"entries": hist, "key": B, "ts_ms": 9000000000000, "ok": True},
        # A key that comes back later is in force in both of its windows.
        {"entries": hist + [{"key": A, "since_ms": "3000000000"}], "key": A, "ts_ms": 3500000000, "ok": True},
        {"entries": hist + [{"key": A, "since_ms": "3000000000"}], "key": A, "ts_ms": 2500000000, "ok": False},
    ]

    rules = [
        {"prefix": "users/{account}/", "read": ["{account}"], "write": ["{account}", "app.near"], "payer": "app.near"},
        {"prefix": "public/", "read": ["*"], "write": []},
    ]
    P = lambda ns, rs, path, signer, read, write, payer: {"namespace": ns, "rules": rs, "path": path, "signer": signer, "read": read, "write": write, "payer": payer}  # noqa: E731
    policy = [
        # crates/near-drive-core/src/policy.rs tests
        P("app.near", rules, "users/bob.near/chat/1", "bob.near", True, True, "app.near"),
        P("app.near", rules, "users/bob.near/chat/1", "app.near", True, True, "app.near"),
        P("app.near", rules, "users/bob.near/chat/1", "eve.near", False, False, "app.near"),
        P("app.near", rules, "users/bob.near.evil/x", "bob.near", False, False, "app.near"),
        P("app.near", rules, "users/bob.near", "bob.near", False, False, "app.near"),
        P("app.near", rules, "public/x", "anyone.near", True, False, "app.near"),
        P("app.near", rules, "private/x", "anyone.near", False, False, "app.near"),
        P("alice.near", [{"prefix": "inbox/", "read": [], "write": ["app.near"], "payer": "app.near"}], "inbox/1", "app.near", False, True, "app.near"),
        # first match wins; '*'; {account} capture must be a valid account id; payer substitution
        P("ns.near", [{"prefix": "a/", "write": []}, {"prefix": "a/b/", "write": ["*"]}], "a/b/c", "x.near", False, False, "ns.near"),
        P("ns.near", [{"prefix": "a/b/", "write": ["*"]}, {"prefix": "a/", "write": []}], "a/b/c", "x.near", False, True, "ns.near"),
        P("ns.near", [{"prefix": "u/{account}/", "write": ["{account}"], "payer": "{account}"}], "u/x.near/f", "x.near", False, True, "x.near"),
        P("ns.near", [{"prefix": "u/{account}/", "write": ["{account}"]}], "u/X.near/f", "X.near", False, False, "ns.near"),
        P("ns.near", [{"prefix": "u/{account}", "write": ["{account}"]}], "u/x.near", "x.near", False, True, "ns.near"),
        P("ns.near", [], "anything", "ns.near", True, True, "ns.near"),
        P("ns.near", [], "anything", "other.near", False, False, "ns.near"),
    ]

    doc = {
        "comment": "Generated by testvectors/gen_sdk_sign_vectors.py (independent of the SDKs). Interim until gen_vectors emits sign-key vectors.",
        "roots": roots,
        "records": records,
        "sign_key_in_force": in_force,
        "policy": policy,
    }
    Path(out).write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parent / "sdk_sign_vectors.json"))
