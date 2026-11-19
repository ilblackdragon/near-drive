"""``python -m nstorage``: a small CLI mirroring ``nst`` (same env vars and key files)."""
from __future__ import annotations

import argparse
import os
import sys

from .client import Client
from .files import default_credentials_path, default_root_key_path, generate_root_key_file, load_credentials, load_root_key
from .uri import NearUri


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="nst-py", description="nstorage client (Python)")
    p.add_argument("--gateway", default=os.environ.get("NSTORAGE_GATEWAY", "http://127.0.0.1:8787"))
    p.add_argument("--account", default=os.environ.get("NSTORAGE_ACCOUNT"))
    p.add_argument("--credentials", default=os.environ.get("NSTORAGE_CREDENTIALS"))
    p.add_argument("--network", default=os.environ.get("NEAR_NETWORK", "mainnet"))
    p.add_argument("--home", default=os.environ.get("NSTORAGE_HOME"))
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    sub.add_parser("whoami")
    s = sub.add_parser("put")
    s.add_argument("src")
    s.add_argument("uri")
    s.add_argument("--public", action="store_true")
    s.add_argument("--content-type")
    s.add_argument("--share", action="append", default=[])
    s = sub.add_parser("get")
    s.add_argument("uri")
    s.add_argument("dst", nargs="?")
    s = sub.add_parser("ls")
    s.add_argument("uri")
    s = sub.add_parser("rm")
    s.add_argument("uri")
    s = sub.add_parser("share")
    s.add_argument("uri")
    s.add_argument("recipient")
    a = p.parse_args(argv)
    if not a.account:
        p.error("--account (or NSTORAGE_ACCOUNT) is required")
    root_path = default_root_key_path(a.account, a.home)

    if a.cmd == "keygen":
        generate_root_key_file(root_path)
        print(f"root key written to {root_path} — back it up; losing it loses your encrypted data", file=sys.stderr)
        return 0

    account, sk = load_credentials(a.credentials or default_credentials_path(a.account, a.network))
    if account != a.account:
        p.error(f"credentials are for {account}, not {a.account}")
    with Client(a.gateway, account, sk, load_root_key(root_path)) as c:
        if a.cmd == "whoami":
            print(f"account: {account}")
            print(f"x25519:  {c.x25519_public() or '(no root key; run keygen)'}")
        elif a.cmd == "put":
            data = sys.stdin.buffer.read() if a.src == "-" else open(a.src, "rb").read()
            r = c.put(a.uri, data, public=a.public, content_type=a.content_type, share_with=a.share)
            print(f"{NearUri.parse(a.uri)} seq={r.seq} size={r.size} stored={r.stored_size}", file=sys.stderr)
        elif a.cmd == "get":
            data = c.get(a.uri)
            if a.dst:
                open(a.dst, "wb").write(data)
            else:
                sys.stdout.buffer.write(data)
        elif a.cmd == "ls":
            for e in c.list(a.uri):
                print(f"{e.size:>12}  seq={e.seq:<4} {e.writer:<24} {e.path}")
        elif a.cmd == "rm":
            c.delete(a.uri)
        elif a.cmd == "share":
            r = c.share(a.uri, a.recipient)
            print(f"shared; seq={r.seq}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
