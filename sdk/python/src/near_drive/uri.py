"""``near://<namespace>/<path>`` addressing (namespace = NEAR account id)."""
from __future__ import annotations

import re
from dataclasses import dataclass

_ACCOUNT_RE = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*")
# Rust `char::is_control` == Unicode general category Cc.
_CONTROL_OR_BACKSLASH = re.compile("[\x00-\x1f\x7f-\x9f\\\\]")
_UNRESERVED = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/")


class UriError(ValueError):
    pass


def validate_account_id(id: str) -> None:
    """NEAR account id: 2..=64 chars of [a-z0-9] separated by single ``.``, ``-`` or ``_``."""
    if not isinstance(id, str) or not 2 <= len(id) <= 64 or _ACCOUNT_RE.fullmatch(id) is None:
        raise UriError(f"invalid NEAR account id: {id}")


def is_valid_account_id(id: str) -> bool:
    try:
        validate_account_id(id)
        return True
    except UriError:
        return False


def validate_path(p: str, allow_trailing_slash: bool) -> None:
    """1..=1024 UTF-8 bytes, ``/``-separated non-empty segments, no ``.``/``..``, no control chars or ``\\``."""

    def err(m: str) -> UriError:
        return UriError(f"invalid object path {p!r}: {m}")

    if not isinstance(p, str):
        raise err("not a string")
    if not 1 <= len(p.encode("utf-8")) <= 1024:
        raise err("length must be 1..=1024")
    if _CONTROL_OR_BACKSLASH.search(p):
        raise err("control characters or backslash")
    body = p[:-1] if allow_trailing_slash and p.endswith("/") else p
    if not body:
        raise err("empty")
    for seg in body.split("/"):
        if seg in ("", ".", ".."):
            raise err("empty, '.' or '..' segment")


@dataclass(frozen=True)
class NearUri:
    namespace: str
    path: str

    @classmethod
    def parse(cls, s: str) -> "NearUri":
        """Parse ``near://ns/path``; ``path`` may be empty or end in ``/`` (a prefix)."""
        if not isinstance(s, str) or not s.startswith("near://"):
            raise UriError("uri must start with near://")
        ns, _, path = s[7:].partition("/")
        validate_account_id(ns)
        if path:
            validate_path(path, True)
        return cls(ns, path)

    @classmethod
    def object(cls, namespace: str, path: str) -> "NearUri":
        """A concrete object (non-empty path, no trailing slash)."""
        validate_account_id(namespace)
        validate_path(path, False)
        return cls(namespace, path)

    @classmethod
    def coerce(cls, u: "str | NearUri") -> "NearUri":
        return u if isinstance(u, NearUri) else cls.parse(u)

    def __str__(self) -> str:
        return f"near://{self.namespace}/{self.path}"


def encode_path(p: str) -> str:
    """Percent-encode everything except RFC 3986 unreserved characters and ``/`` (byte-wise, uppercase hex)."""
    return "".join(chr(b) if b in _UNRESERVED else f"%{b:02X}" for b in p.encode("utf-8"))
