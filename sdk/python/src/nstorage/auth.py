"""Request authentication for the native API."""
from __future__ import annotations

import blake3

H_ACCOUNT = "x-near-account"
H_PUBKEY = "x-near-publickey"
H_TS = "x-near-timestamp"
H_SIG = "x-near-signature"


def canonical_request(method: str, path: str, query: str, account: str, public_key: str, ts_ms: int, body: bytes) -> bytes:
    """``path`` is the percent-encoded request path as sent; ``query`` the raw query string without ``?``."""
    return f"nstorage-req-v1\n{method.upper()}\n{path}\n{query}\n{account}\n{public_key}\n{ts_ms}\n{blake3.blake3(body).hexdigest()}".encode("utf-8")
