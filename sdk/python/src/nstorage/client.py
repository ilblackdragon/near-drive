"""Synchronous nstorage client: chunking, client-side encryption, request signing.

Verifies everything it reads: record signature, manifest cid, chunk cids, AEAD.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from typing import Iterable, Optional, Protocol, Sequence, Union

import httpx

from .auth import H_ACCOUNT, H_PUBKEY, H_SIG, H_TS, canonical_request
from .crypto import Recipient, RootKey, add_recipient, decrypt_object, encrypt_for, plaintext_chunks
from .keys import b58encode, parse_public_key, parse_secret_key, parse_x25519, public_key_of, sign
from .manifest import ChunkRef, Manifest, PointerRecord, cid
from .uri import NearUri, encode_path, validate_account_id

DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024


class Signer(Protocol):
    """Signs with an ed25519 key authorized for the account (full-access key, a function-call
    key scoped to the storage contract, or a gateway dev key). ``sign`` returns the raw
    64-byte signature or its base58 string."""

    public_key: str

    def sign(self, message: bytes) -> Union[bytes, str]: ...


class KeySigner:
    """Signer from a NEAR secret key string (``ed25519:<base58>``)."""

    def __init__(self, secret_key: str):
        self._seed = parse_secret_key(secret_key)
        self.public_key = public_key_of(self._seed)

    def sign(self, message: bytes) -> str:
        return sign(self._seed, message)


class GatewayError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"gateway returned {status}: {body}")
        self.status = status
        self.body = body


@dataclass
class ObjectHead:
    record: PointerRecord
    manifest: Manifest


@dataclass
class ListEntry:
    path: str
    size: int
    seq: int
    writer: str
    ts_ms: int


def _obj_path(u: NearUri) -> str:
    return f"/v1/o/{u.namespace}/{encode_path(u.path)}"


def verify_head(uri: NearUri, head: ObjectHead) -> None:
    """Client-side checks on what a (possibly untrusted) gateway returned."""
    r = head.record
    if r.namespace != uri.namespace or r.path != uri.path:
        raise ValueError("gateway returned a record for a different object")
    r.verify_signature()
    if head.manifest.cid() != r.manifest_cid:
        raise ValueError("manifest does not match record")
    head.manifest.validate()
    if head.manifest.size != r.size:
        raise ValueError("record size does not match manifest")


class Client:
    def __init__(
        self,
        gateway: str,
        account_id: str,
        signer: Union[str, Signer],
        root_key: Union[RootKey, bytes, str, None] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        http: Optional[httpx.Client] = None,
        timeout: float = 60.0,
    ):
        validate_account_id(account_id)
        self.gateway = gateway.rstrip("/")
        self.account_id = account_id
        self._signer: Signer = KeySigner(signer) if isinstance(signer, str) else signer
        parse_public_key(self._signer.public_key)
        self._root = RootKey.coerce(root_key) if root_key is not None else None
        if chunk_size <= 0:
            raise ValueError("chunk_size must be > 0")
        self.chunk_size = chunk_size
        self._http = http or httpx.Client(timeout=timeout)
        self._last_ts = 0
        self._ts_lock = threading.Lock()

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def public_key(self) -> str:
        return self._signer.public_key

    def x25519_public(self) -> Optional[str]:
        """This account's ``x25519:<base58>`` key for receiving shared objects (needs the root key)."""
        return self._root.x25519_public() if self._root else None

    def _sign(self, msg: bytes) -> str:
        s = self._signer.sign(msg)
        return s if isinstance(s, str) else b58encode(bytes(s))

    def _now_ms(self) -> int:
        # Strictly increasing per client: the gateway's replay cache is keyed by signature
        # and ed25519 is deterministic, so identical requests in the same ms would collide.
        with self._ts_lock:
            t = max(int(time.time() * 1000), self._last_ts + 1)
            self._last_ts = t
            return t

    def _send(self, method: str, path: str, query: str = "", body: bytes = b"") -> httpx.Response:
        ts = self._now_ms()
        sig = self._sign(canonical_request(method, path, query, self.account_id, self._signer.public_key, ts, body))
        url = self.gateway + path + (f"?{query}" if query else "")
        headers = {H_ACCOUNT: self.account_id, H_PUBKEY: self._signer.public_key, H_TS: str(ts), H_SIG: sig}
        return self._http.request(method, url, headers=headers, content=body if body else None)

    @staticmethod
    def _check(r: httpx.Response) -> httpx.Response:
        if r.is_success:
            return r
        raise GatewayError(r.status_code, r.text)

    def _put_chunk(self, namespace: str, data: bytes) -> ChunkRef:
        c = cid(data)
        self._check(self._send("PUT", f"/v1/chunk/{namespace}/{c}", "", data))
        return ChunkRef(c, len(data))

    def head(self, uri: Union[str, NearUri]) -> Optional[ObjectHead]:
        """Record + manifest of ``uri``, verified; ``None`` if absent."""
        u = NearUri.coerce(uri)
        r = self._send("GET", _obj_path(u))
        if r.status_code == 404:
            return None
        raw = self._check(r).json()
        head = ObjectHead(PointerRecord.from_dict(raw.get("record")), Manifest.from_dict(raw.get("manifest")))
        verify_head(u, head)
        return head

    def put(
        self,
        uri: Union[str, NearUri],
        data: Union[bytes, bytearray, memoryview, str],
        *,
        public: bool = False,
        content_type: Optional[str] = None,
        share_with: Iterable[str] = (),
    ) -> PointerRecord:
        """Upload ``data`` to ``uri``. Retries once on a concurrent-write conflict."""
        u = NearUri.coerce(uri)
        NearUri.object(u.namespace, u.path)
        b = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        enc = None
        if public:
            chunks = plaintext_chunks(b, self.chunk_size)
        else:
            rs: list[Recipient] = [self._root] if self._root else []
            for k in share_with:
                parse_x25519(k)
                rs.append(k)
            if not rs:
                raise ValueError("no root key and no share_with recipients; pass root_key or use public=True")
            chunks, enc = encrypt_for(rs, b, self.chunk_size)
        refs: list[ChunkRef] = []
        uploaded: set[str] = set()
        for c in chunks:
            ref = ChunkRef(cid(c), len(c)) if cid(c) in uploaded else self._put_chunk(u.namespace, c)
            uploaded.add(ref.cid)
            refs.append(ref)
        return self._commit(u, Manifest(1, len(b), self.chunk_size, refs, enc, content_type))

    def _commit(self, u: NearUri, manifest: Manifest) -> PointerRecord:
        mbytes = manifest.to_bytes()
        stored = manifest.stored_size() + len(mbytes)
        mref = self._put_chunk(u.namespace, mbytes)
        for attempt in range(2):
            h = self.head(u)
            prev = h.record.seq if h else 0
            rec = PointerRecord(u.namespace, u.path, mref.cid, manifest.size, stored, prev + 1, self.account_id, self._signer.public_key, self._now_ms())
            rec.sig = self._sign(rec.signing_bytes())
            body = json.dumps(rec.to_dict(), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            r = self._send("PUT", _obj_path(u), "", body)
            if r.status_code == 409 and attempt == 0:
                continue
            self._check(r)
            return rec
        raise RuntimeError(f"concurrent write conflict on {u}")

    def get_object(self, uri: Union[str, NearUri]) -> tuple[ObjectHead, bytes]:
        """Download, verify and decrypt."""
        u = NearUri.coerce(uri)
        head = self.head(u)
        if head is None:
            raise GatewayError(404, f"{u} not found")
        chunks = []
        for c in head.manifest.chunks:
            b = self._check(self._send("GET", _obj_path(u), f"chunk={c.cid}")).content
            if cid(b) != c.cid:
                raise ValueError(f"chunk {c.cid} content does not match its id")
            chunks.append(b)
        if head.manifest.enc is None:
            data = b"".join(chunks)
        else:
            if self._root is None:
                raise ValueError("object is encrypted and no root key is loaded")
            data = decrypt_object(self._root, head.manifest.enc, chunks)
        if len(data) != head.manifest.size:
            raise ValueError("size mismatch")
        return head, data

    def get(self, uri: Union[str, NearUri]) -> bytes:
        return self.get_object(uri)[1]

    def list(self, prefix: Union[str, NearUri]) -> list[ListEntry]:
        """List objects under a prefix URI (e.g. ``near://alice.near/memory/``)."""
        u = NearUri.coerce(prefix)
        r = self._check(self._send("GET", f"/v1/list/{u.namespace}", f"prefix={encode_path(u.path)}"))
        return [ListEntry(e["path"], e["size"], e["seq"], e["writer"], e["ts_ms"]) for e in r.json()]

    def delete(self, uri: Union[str, NearUri]) -> None:
        u = NearUri.coerce(uri)
        self._check(self._send("DELETE", _obj_path(u)))

    def share(self, uri: Union[str, NearUri], recipient: str) -> PointerRecord:
        """Re-wrap the object key of ``uri`` to ``recipient`` (``x25519:<base58>``). Chunks are
        reused; only a new manifest and record are written. The recipient also needs read
        access via namespace policy."""
        if self._root is None:
            raise ValueError("sharing requires the root key")
        u = NearUri.coerce(uri)
        head = self.head(u)
        if head is None:
            raise GatewayError(404, f"{u} not found")
        if head.manifest.enc is None:
            raise ValueError(f"{u} is public; nothing to share")
        parse_x25519(recipient)
        m = head.manifest
        return self._commit(u, Manifest(m.version, m.size, m.chunk_size, m.chunks, add_recipient(self._root, m.enc, recipient), m.content_type))
