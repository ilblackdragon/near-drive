"""Object manifests (serialized byte-identically to Rust's serde_json) and signed pointer records."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

import blake3

from .crypto import ALG, TAG_LEN, EncInfo, WrappedKey
from .keys import verify

MAX_CHUNK_BYTES = 64 * 1024 * 1024
_CID_RE = re.compile(r"b3:[0-9a-f]{64}")


def cid(data: bytes) -> str:
    """Content id of a chunk: ``b3:`` + hex(blake3(bytes))."""
    return "b3:" + blake3.blake3(data).hexdigest()


def is_valid_cid(s: Any) -> bool:
    return isinstance(s, str) and _CID_RE.fullmatch(s) is not None


def _u64(v: Any, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v < 2**64:
        raise ValueError(f"{what} must be an unsigned 64-bit integer")
    return v


def _str(v: Any, what: str) -> str:
    if not isinstance(v, str):
        raise ValueError(f"{what} must be a string")
    return v


def _opt_str(v: Any, what: str) -> Optional[str]:
    # serde `Option` + `#[serde(default)]`: missing key or null both mean None.
    return None if v is None else _str(v, what)


@dataclass
class ChunkRef:
    cid: str
    #: Stored (ciphertext) length in bytes.
    len: int


@dataclass
class Manifest:
    version: int
    #: Plaintext size in bytes.
    size: int
    chunk_size: int
    chunks: list = field(default_factory=list)
    enc: Optional[EncInfo] = None
    content_type: Optional[str] = None

    def to_dict(self) -> dict:
        d: dict = {
            "version": self.version,
            "size": self.size,
            "chunk_size": self.chunk_size,
            "chunks": [{"cid": c.cid, "len": c.len} for c in self.chunks],
        }
        if self.enc is not None:
            d["enc"] = self.enc.to_dict()
        if self.content_type is not None:
            d["content_type"] = self.content_type
        return d

    def to_json(self) -> str:
        # Same bytes as serde_json::to_vec: compact, struct field order, and only
        # `"`, `\` and C0 controls escaped (\b \f \n \r \t short forms, else \u00xx).
        return json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False)

    def to_bytes(self) -> bytes:
        return self.to_json().encode("utf-8")

    def cid(self) -> str:
        return cid(self.to_bytes())

    def stored_size(self) -> int:
        return sum(c.len for c in self.chunks)

    @classmethod
    def from_dict(cls, v: Any) -> "Manifest":
        """Parse JSON-decoded data, keeping only the fields Rust knows (unknown keys ignored)."""
        if not isinstance(v, dict):
            raise ValueError("manifest must be an object")
        chunks = v.get("chunks")
        if not isinstance(chunks, list):
            raise ValueError("manifest: chunks must be an array")
        refs = []
        for c in chunks:
            if not isinstance(c, dict):
                raise ValueError("manifest: chunk must be an object")
            refs.append(ChunkRef(_str(c.get("cid"), "cid"), _u64(c.get("len"), "len")))
        enc = None
        e = v.get("enc")
        if e is not None:
            if not isinstance(e, dict) or not isinstance(e.get("wrapped_keys"), list):
                raise ValueError("manifest: bad enc")
            wks = []
            for w in e["wrapped_keys"]:
                if not isinstance(w, dict):
                    raise ValueError("manifest: wrapped key must be an object")
                wks.append(WrappedKey(_str(w.get("recipient"), "recipient"), _str(w.get("nonce"), "nonce"), _str(w.get("ct"), "ct"), _opt_str(w.get("epk"), "epk")))
            enc = EncInfo(_str(e.get("alg"), "alg"), _str(e.get("object_id"), "object_id"), _str(e.get("nonce_prefix"), "nonce_prefix"), wks)
        return cls(
            _u64(v.get("version"), "version"),
            _u64(v.get("size"), "size"),
            _u64(v.get("chunk_size"), "chunk_size"),
            refs,
            enc,
            _opt_str(v.get("content_type"), "content_type"),
        )

    @classmethod
    def from_bytes(cls, b: bytes) -> "Manifest":
        m = cls.from_dict(json.loads(b.decode("utf-8")))
        m.validate()
        return m

    def validate(self) -> None:
        if self.version != 1:
            raise ValueError("unsupported manifest version")
        if not self.chunks:
            raise ValueError("manifest has no chunks")
        if not 0 < self.chunk_size <= MAX_CHUNK_BYTES:
            raise ValueError("bad chunk_size")
        for c in self.chunks:
            if not is_valid_cid(c.cid):
                raise ValueError(f"bad cid {c.cid}")
            if c.len > MAX_CHUNK_BYTES + 64:
                raise ValueError("chunk too large")
        overhead = TAG_LEN if self.enc is not None else 0
        if self.stored_size() != self.size + overhead * len(self.chunks):
            raise ValueError("chunk lengths do not add up to size")
        if self.enc is not None and self.enc.alg != ALG:
            raise ValueError(f"unsupported alg {self.enc.alg}")


@dataclass
class PointerRecord:
    namespace: str
    path: str
    manifest_cid: str
    #: Plaintext size.
    size: int
    #: Stored size (manifest + chunks), used for metering.
    stored_size: int
    #: Monotonic per (namespace, path); 1 for a new object.
    seq: int
    writer: str
    writer_pk: str
    ts_ms: int
    sig: str = ""

    def signing_bytes(self) -> bytes:
        return (
            f"nstorage-record-v1\n{self.namespace}\n{self.path}\n{self.manifest_cid}\n{self.size}\n"
            f"{self.stored_size}\n{self.seq}\n{self.writer}\n{self.writer_pk}\n{self.ts_ms}"
        ).encode("utf-8")

    def verify_signature(self) -> None:
        """Signature check only (writer authorization is NEAR state, checked by the gateway)."""
        if self.seq < 1:
            raise ValueError("seq must be >= 1")
        if not is_valid_cid(self.manifest_cid):
            raise ValueError("bad manifest cid")
        if not verify(self.writer_pk, self.signing_bytes(), self.sig):
            raise ValueError("bad record signature")

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in ("namespace", "path", "manifest_cid", "size", "stored_size", "seq", "writer", "writer_pk", "ts_ms", "sig")}

    @classmethod
    def from_dict(cls, v: Any) -> "PointerRecord":
        if not isinstance(v, dict):
            raise ValueError("record must be an object")
        s = lambda k: _str(v.get(k), f"record.{k}")  # noqa: E731
        n = lambda k: _u64(v.get(k), f"record.{k}")  # noqa: E731
        return cls(s("namespace"), s("path"), s("manifest_cid"), n("size"), n("stored_size"), n("seq"), s("writer"), s("writer_pk"), n("ts_ms"), s("sig"))
