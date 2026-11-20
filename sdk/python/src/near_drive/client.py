"""Synchronous NEAR Drive client: chunking, client-side encryption, request signing.

Verifies everything it reads: record signature, the writer's authorization against ``drive.near``
(signing key + namespace rules, see :class:`~near_drive.chain.WriterCheck`), manifest cid, chunk
cids, AEAD.
Every request is retried on transient failures (see :mod:`near_drive.net`); large files
stream with bounded memory and resume after interruptions (``put_file``, ``get_to_file``).
"""
from __future__ import annotations

import base64
import binascii
import io
import json
import os
import re
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterable, Iterator, Optional, Protocol, TypeVar, Union

import httpx

from . import resume
from .auth import H_ACCOUNT, H_PUBKEY, H_SIG, H_TS, canonical_request
from .chain import NO_WRITER_CHECK, StorageContract, WriterCheck
from .crypto import ChunkOpener, ChunkSealer, Recipient, RootKey, add_recipient, chunk_count, chunk_plain_len
from .keys import b58encode, parse_public_key, parse_secret_key, parse_x25519, public_key_of, sign
from .manifest import MAX_CHUNK_BYTES, ChunkRef, Manifest, PointerRecord, cid
from .net import DeadlineExceeded, NetConfig, Retry, Truncated, debug, retry_after, retryable_status, with_retries
from .uri import NearUri, encode_path, validate_account_id

DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
DEFAULT_PARALLELISM = 8
#: Default NEAR Drive contract account.
DEFAULT_CONTRACT = "drive.near"
#: Request header choosing the storage class of uploaded chunks (and recorded with the object).
CLASS_HEADER = "x-near-drive-class"
#: Don't use a direct URL that expires sooner than this.
_URL_MIN_REMAINING_MS = 30_000
_UPLOAD_SLICE = 256 * 1024

T = TypeVar("T")
U = TypeVar("U")


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


class Conflict(Exception):
    """A conditional write (``expect_seq``) or delete (``delete_if``) found a different
    current version. Not retried."""

    def __init__(self, uri: str, current: int):
        super().__init__(f"{uri} changed concurrently (current seq {current})")
        self.uri = uri
        #: Current seq (0 = the object does not exist).
        self.current = current


class TransferInterrupted(Exception):
    """``put_file`` (with ``resume_dir``) or ``get_to_file`` failed part-way; the progress is
    kept and calling it again resumes. The underlying error is ``__cause__``."""


@dataclass
class ObjectHead:
    record: PointerRecord
    manifest: Manifest
    #: Exact stored manifest bytes (base64) when the gateway provides them.
    manifest_raw: Optional[str] = None
    #: Storage class the gateway recorded for the object (None: not recorded).
    storage_class: Optional[str] = None


@dataclass
class ListEntry:
    path: str
    size: int
    seq: int
    writer: str
    ts_ms: int
    #: Present on gateways that report it.
    manifest_cid: Optional[str] = None


@dataclass
class ListPage:
    """One page of ``GET /v1/list`` (:meth:`Client.list_page`)."""
    entries: list[ListEntry]
    #: Rolled-up prefixes (with a delimiter), each ending with it.
    common_prefixes: list[str]
    #: Pass back as ``cursor`` for the next page; None at the end.
    next_cursor: Optional[str] = None


@dataclass
class LocatedChunk:
    cid: str
    len: int
    #: Direct-fetch URL (presigned S3, bridge/CDN). None = fetch via gateway.
    url: Optional[str] = None
    expires_ms: Optional[int] = None
    #: The chunk itself (base64), inlined by the gateway for small objects; verified like any fetch.
    data: Optional[str] = None


@dataclass
class Located:
    """``GET ...?mode=locate`` response. Gateways without locate support answer with a plain
    head (no ``chunks``), which degrades to gateway fetches."""

    record: PointerRecord
    manifest: Manifest
    manifest_raw: Optional[str] = None
    storage_class: Optional[str] = None
    chunks: list = field(default_factory=list)

    def head(self) -> ObjectHead:
        return ObjectHead(self.record, self.manifest, self.manifest_raw, self.storage_class)

    def direct_url(self, idx: int) -> Optional[str]:
        if idx >= len(self.chunks):
            return None
        c = self.chunks[idx]
        if c.expires_ms is not None and c.expires_ms < int(time.time() * 1000) + _URL_MIN_REMAINING_MS:
            return None
        return c.url


class _Resp:
    """A fully read response."""

    __slots__ = ("status_code", "headers", "content")

    def __init__(self, status_code: int, headers: httpx.Headers, content: bytes):
        self.status_code, self.headers, self.content = status_code, headers, content

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")

    def json(self) -> Any:
        return json.loads(self.content)


def _obj_path(u: NearUri) -> str:
    return f"/v1/o/{u.namespace}/{encode_path(u.path)}"


def _opt(v: Any, t: type) -> Any:
    return v if isinstance(v, t) and not isinstance(v, bool) else None


def verify_head(uri: NearUri, head: ObjectHead, writer_check: Optional[WriterCheck]) -> None:
    """Client-side checks on what a (possibly untrusted) gateway returned: record signature,
    manifest, and (via ``writer_check``) that the writer was allowed to write it with that key."""
    _check_head(uri, head)
    if writer_check is None:
        raise ValueError(NO_WRITER_CHECK)
    writer_check.verify(head.record)


def _check_head(uri: NearUri, head: ObjectHead) -> None:
    """Everything but the writer check."""
    r = head.record
    if r.namespace != uri.namespace or r.path != uri.path:
        raise ValueError("gateway returned a record for a different object")
    r.verify_signature()
    if head.manifest_raw is not None:
        # Hash the stored bytes, not a re-serialization: robust to manifest
        # fields this SDK does not know yet.
        raw = base64.b64decode(head.manifest_raw, validate=True)
        if cid(raw) != r.manifest_cid:
            raise ValueError("manifest does not match record")
        if Manifest.from_dict(json.loads(raw)).to_bytes() != head.manifest.to_bytes():
            raise ValueError("manifest_raw does not match manifest")
    elif head.manifest.cid() != r.manifest_cid:
        raise ValueError("manifest does not match record")
    head.manifest.validate()
    if head.manifest.size != r.size:
        raise ValueError("record size does not match manifest")


def _read_full(r: BinaryIO, n: int) -> bytes:
    """Read until ``n`` bytes or EOF."""
    buf = bytearray()
    while len(buf) < n:
        b = r.read(n - len(buf))
        if not b:
            break
        buf += b
    return bytes(buf)


def _chunks_on_disk(f: BinaryIO, m: Manifest, opener: Optional[ChunkOpener]) -> list:
    """For each chunk: are the bytes at its offset in ``f`` exactly that chunk?
    (Re-encrypt / hash them and compare with the manifest's cid.)"""
    n = len(m.chunks)
    out = []
    for i in range(n):
        f.seek(i * m.chunk_size)
        b = f.read(chunk_plain_len(m.size, m.chunk_size, i))
        c = cid(b) if opener is None else cid(opener.reseal(i, i + 1 == n, b))
        out.append(c == m.chunks[i].cid)
    return out


class Client:
    _last_ts = 0
    _ts_lock = threading.Lock()

    def __init__(
        self,
        gateway: str,
        account_id: str,
        signer: Union[str, Signer],
        root_key: Union[RootKey, bytes, str, None] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        http: Optional[httpx.Client] = None,
        timeout: Optional[float] = None,
        *,
        net: Optional[NetConfig] = None,
        parallelism: int = DEFAULT_PARALLELISM,
        writer_check: Optional[WriterCheck] = None,
        rpc_url: Optional[str] = None,
        contract_id: str = DEFAULT_CONTRACT,
    ):
        """``root_key``: required for writing (records are signed with a key derived from it;
        publish that key with ``near drive publish-key``); also decrypts this account's objects.

        ``writer_check``: how reads check that a record's writer was allowed to write it (see
        :class:`WriterCheck`). Default: ``WriterCheck.chain(rpc_url, contract_id)`` when ``rpc_url``
        is set; otherwise none, and every read fails until one is configured.

        ``net``: timeouts and retry policy (see :class:`NetConfig`); ``timeout`` (legacy)
        sets its idle timeout. ``parallelism``: concurrent chunk transfers."""
        validate_account_id(account_id)
        self.gateway = gateway.rstrip("/")
        self.account_id = account_id
        self._signer: Signer = KeySigner(signer) if isinstance(signer, str) else signer
        parse_public_key(self._signer.public_key)
        self._root = RootKey.coerce(root_key) if root_key is not None else None
        if chunk_size <= 0:
            raise ValueError("chunk_size must be > 0")
        self.chunk_size = chunk_size
        self.parallelism = parallelism
        self.net = net or NetConfig()
        if timeout is not None:
            self.net.idle_timeout = timeout
        self._own_http = http is None
        self._http = http or self.net.http_client()
        self._sleep: Callable[[float], None] = time.sleep
        self._own_contract: Optional[StorageContract] = None
        if writer_check is None and rpc_url is not None:
            self._own_contract = StorageContract(rpc_url, contract_id)
            writer_check = WriterCheck.chain(self._own_contract)
        self.writer_check: Optional[WriterCheck] = writer_check

    def set_net(self, net: NetConfig) -> None:
        """Replace the timeout/retry policy (rebuilds the HTTP client if this client owns it)."""
        self.net = net
        if self._own_http:
            self._http.close()
            self._http = net.http_client()

    def close(self) -> None:
        self._http.close()
        if self._own_contract is not None:
            self._own_contract.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def public_key(self) -> str:
        return self._signer.public_key

    def sign_public_key(self) -> Optional[str]:
        """``ed25519:<base58>`` key this client signs records with (derived from the root key).
        Publish it with ``near drive publish-key``."""
        return self._root.sign_public_key() if self._root else None

    def _record_seed(self) -> bytes:
        if self._root is None:
            raise ValueError("writing requires the root key: records are signed with a key derived from it (pass root_key)")
        return self._root.sign_seed()

    def _check_writer(self, r: PointerRecord) -> None:
        if self.writer_check is None:
            raise ValueError(NO_WRITER_CHECK)
        self.writer_check.verify(r)

    def x25519_public(self) -> Optional[str]:
        """This account's ``x25519:<base58>`` key for receiving shared objects (needs the root key)."""
        return self._root.x25519_public() if self._root else None

    # ---------------------------------------------------------------- transport

    def _sign(self, msg: bytes) -> str:
        s = self._signer.sign(msg)
        return s if isinstance(s, str) else b58encode(bytes(s))

    def _now_ms(self) -> int:
        # Strictly increasing across all clients in this process: the gateway's replay cache
        # is keyed by signature and ed25519 is deterministic, so identical requests (e.g. the
        # retry of a chunk fetch by a second client with the same key) in the same ms would
        # collide.
        with Client._ts_lock:
            t = max(int(time.time() * 1000), Client._last_ts + 1)
            Client._last_ts = t
            return t

    def _read(self, req: httpx.Request, deadline_at: float) -> _Resp:
        r = self._http.send(req, stream=True)
        try:
            buf = bytearray()
            for b in r.iter_bytes():
                buf += b
                if time.monotonic() > deadline_at:
                    raise DeadlineExceeded("request deadline exceeded", request=req)
            cl = r.headers.get("content-length")
            if cl is not None and "content-encoding" not in r.headers and cl.isdigit() and int(cl) != len(buf):
                raise Truncated(f"response body truncated ({len(buf)} of {cl} bytes)", request=req)
        finally:
            r.close()
        return _Resp(r.status_code, r.headers, bytes(buf))

    def _send(self, method: str, path: str, query: str = "", body: bytes = b"", storage_class: Optional[str] = None, xfer: int = 0) -> _Resp:
        """One signed request (no retries). ``xfer``: payload bytes expected to move in
        either direction, for the request deadline."""
        ts = self._now_ms()
        sig = self._sign(canonical_request(method, path, query, self.account_id, self._signer.public_key, ts, body))
        url = self.gateway + path + (f"?{query}" if query else "")
        headers = {H_ACCOUNT: self.account_id, H_PUBKEY: self._signer.public_key, H_TS: str(ts), H_SIG: sig}
        if storage_class is not None:
            headers[CLASS_HEADER] = storage_class
        deadline = self.net.timeout_for(max(xfer, len(body)))
        deadline_at = time.monotonic() + deadline
        content = None
        if body:
            headers["content-length"] = str(len(body))

            def gen(b: bytes = body) -> Iterator[bytes]:
                mv = memoryview(b)
                for off in range(0, len(b), _UPLOAD_SLICE):
                    if time.monotonic() > deadline_at:
                        raise DeadlineExceeded("request deadline exceeded")
                    yield bytes(mv[off : off + _UPLOAD_SLICE])

            content = gen()
        req = self._http.build_request(method, url, headers=headers, content=content, timeout=self.net.httpx_timeout(deadline))
        return self._read(req, deadline_at)

    @staticmethod
    def _ok(r: _Resp) -> _Resp:
        """Success, or a :class:`Retry` (transient status) / :class:`GatewayError`."""
        if r.is_success:
            return r
        e = GatewayError(r.status_code, r.text)
        if retryable_status(r.status_code):
            raise Retry(e, retry_after(r.headers))
        raise e

    def _retry(self, what: str, f: Callable[[int], T]) -> T:
        return with_retries(self.net, what, f, self._sleep)

    def _get_json(self, what: str, path: str, query: str = "") -> Any:
        """GET returning JSON, retried; ``None`` on 404."""

        def once(_: int) -> Any:
            r = self._send("GET", path, query)
            if r.status_code == 404:
                return None
            self._ok(r)
            try:
                return r.json()
            except ValueError as e:
                raise ValueError(f"bad response to {what}: {e}") from e

        return self._retry(what, once)

    def _upload_chunk(self, namespace: str, c: str, data: bytes, storage_class: Optional[str]) -> ChunkRef:
        """Upload one already-encoded chunk (retries transient failures)."""
        path = f"/v1/chunk/{namespace}/{c}"
        self._retry(f"upload chunk {c}", lambda _: self._ok(self._send("PUT", path, "", data, storage_class)))
        return ChunkRef(c, len(data))

    def _pmap(self, fn: Callable[[T], U], items: Iterable[T]) -> Iterator[U]:
        """``map`` with up to ``parallelism`` calls in flight, results in order. Consumes
        ``items`` lazily, so memory stays bounded."""
        p = max(1, self.parallelism)
        if p == 1:
            for x in items:
                yield fn(x)
            return
        with ThreadPoolExecutor(p) as ex:
            pending: deque = deque()
            try:
                for x in items:
                    pending.append(ex.submit(fn, x))
                    if len(pending) >= p:
                        yield pending.popleft().result()
                while pending:
                    yield pending.popleft().result()
            finally:
                for fut in pending:
                    fut.cancel()

    # ---------------------------------------------------------------- metadata

    def head(self, uri: Union[str, NearUri]) -> Optional[ObjectHead]:
        """Record + manifest of ``uri``, verified (including the writer, see :class:`WriterCheck`);
        ``None`` if absent."""
        head = self._head_unchecked(NearUri.coerce(uri))
        if head is not None:
            self._check_writer(head.record)
        return head

    def _head_unchecked(self, u: NearUri) -> Optional[ObjectHead]:
        """Head with signature/manifest checks but no writer check: only for the current seq
        when writing (the gateway enforces the CAS)."""
        raw = self._get_json("head", _obj_path(u))
        if raw is None:
            return None
        head = self._parse_head(raw)
        _check_head(u, head)
        return head

    @staticmethod
    def _parse_head(raw: Any) -> ObjectHead:
        if not isinstance(raw, dict):
            raise ValueError("bad head response")
        return ObjectHead(
            PointerRecord.from_dict(raw.get("record")),
            Manifest.from_dict(raw.get("manifest")),
            _opt(raw.get("manifest_raw"), str),
            _opt(raw.get("class"), str),
        )

    def locate(self, uri: Union[str, NearUri]) -> Optional[Located]:
        """Record + manifest + per-chunk direct URLs or inlined bytes. None if absent."""
        u = NearUri.coerce(uri)
        raw = self._get_json("locate", _obj_path(u), "mode=locate")
        if raw is None:
            return None
        h = self._parse_head(raw)
        chunks = []
        for c in raw.get("chunks") or []:
            if not isinstance(c, dict) or not isinstance(c.get("cid"), str) or _opt(c.get("len"), int) is None:
                raise ValueError("bad locate chunk")
            chunks.append(LocatedChunk(c["cid"], c["len"], _opt(c.get("url"), str), _opt(c.get("expires_ms"), int), _opt(c.get("data"), str)))
        loc = Located(h.record, h.manifest, h.manifest_raw, h.storage_class, chunks)
        _check_head(u, h)
        m = loc.manifest
        if chunks and (len(chunks) != len(m.chunks) or any(a.cid != b.cid for a, b in zip(chunks, m.chunks))):
            raise ValueError("gateway locate chunks do not match the manifest")
        if len(m.chunks) != chunk_count(m.size, m.chunk_size):
            raise ValueError("manifest chunk count does not match size / chunk_size")
        self._check_writer(loc.record)
        return loc

    def _locate_or_404(self, u: NearUri) -> Located:
        loc = self.locate(u)
        if loc is None:
            raise GatewayError(404, f"{u} not found")
        return loc

    def list(self, prefix: Union[str, NearUri]) -> list[ListEntry]:
        """Every readable object whose path starts with the prefix URI's path (a raw
        string prefix, e.g. ``near://alice.near/memory/``), sorted by path:
        :meth:`list_page` until the end."""
        out: list[ListEntry] = []
        cursor: Optional[str] = None
        while True:
            page = self.list_page(prefix, cursor=cursor)
            out.extend(page.entries)
            if page.next_cursor is None:
                return out
            if page.next_cursor == cursor:
                raise RuntimeError(f"gateway listing of {prefix} did not advance")
            cursor = page.next_cursor

    def list_page(self, prefix: Union[str, NearUri], delimiter: Optional[str] = None, cursor: Optional[str] = None,
                  limit: Optional[int] = None) -> ListPage:
        """One page of the listing. With ``delimiter`` (normally ``/``) deeper paths are
        rolled up into ``common_prefixes``. Pass the previous page's ``next_cursor`` as
        ``cursor``; ``limit`` defaults to (and is capped at) 1000 by the gateway. Pages may
        hold fewer items than the limit; continue while ``next_cursor`` is set."""
        u = NearUri.coerce(prefix)
        q = f"prefix={encode_path(u.path)}"
        if delimiter:
            q += f"&delimiter={encode_path(delimiter)}"
        if cursor:
            q += f"&cursor={encode_path(cursor)}"
        if limit is not None:
            q += f"&limit={int(limit)}"
        raw = self._get_json("list", f"/v1/list/{u.namespace}", q) or {}
        return ListPage(
            [ListEntry(e["path"], e["size"], e["seq"], e["writer"], e["ts_ms"], _opt(e.get("manifest_cid"), str)) for e in raw.get("entries", [])],
            list(raw.get("common_prefixes") or []),
            _opt(raw.get("next_cursor"), str),
        )

    # ---------------------------------------------------------------- writes

    def _new_sealer(self, public: bool, share_with: Iterable[str], skip_owner_key: bool = False) -> Optional[ChunkSealer]:
        self._record_seed()
        if public:
            return None
        rs: list[Recipient] = [self._root] if self._root and not skip_owner_key else []
        for k in share_with:
            parse_x25519(k)
            rs.append(k)
        if not rs:
            raise ValueError("no recipients: pass root_key, share_with recipients, or use public=True")
        return ChunkSealer.new(rs)

    def put(
        self,
        uri: Union[str, NearUri],
        data: Union[bytes, bytearray, memoryview, str],
        *,
        public: bool = False,
        content_type: Optional[str] = None,
        share_with: Iterable[str] = (),
        storage_class: Optional[str] = None,
        expect_seq: Optional[int] = None,
        skip_owner_key: bool = False,
    ) -> PointerRecord:
        """Upload ``data`` to ``uri``. Requires the root key (it signs the record).

        ``share_with``: extra ``x25519:<base58>`` recipients. ``skip_owner_key=True``: do not
        also wrap the object key to this account's root key (an app writing data only the user
        can read).
        ``storage_class``: e.g. ``hot`` / ``bulk`` (None = gateway default).
        ``expect_seq``: write only if the object is currently at this seq (0 = must not
        exist), else raise :class:`Conflict`. Without it, a concurrent write is retried once.
        """
        u = NearUri.coerce(uri)
        NearUri.object(u.namespace, u.path)
        b = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        sealer = self._new_sealer(public, list(share_with), skip_owner_key)
        return self._put_stream(io.BytesIO(b), u, sealer, content_type, storage_class, expect_seq)

    def put_file(
        self,
        path: Union[str, os.PathLike],
        uri: Union[str, NearUri],
        *,
        public: bool = False,
        content_type: Optional[str] = None,
        share_with: Iterable[str] = (),
        storage_class: Optional[str] = None,
        expect_seq: Optional[int] = None,
        resume_dir: Union[str, os.PathLike, None] = None,
        skip_owner_key: bool = False,
    ) -> PointerRecord:
        """Upload a file with bounded memory (about ``(parallelism + 2) * chunk_size``) and
        ``parallelism`` concurrent chunk uploads.

        With ``resume_dir``, a journal is kept there so that an interrupted upload of the same
        file to the same URI resumes where it stopped (raises :class:`TransferInterrupted`;
        call again). Encrypted uploads resume only with the owner's root key loaded; if the
        file changed, the upload starts over with a fresh key.
        """
        u = NearUri.coerce(uri)
        NearUri.object(u.namespace, u.path)
        share_with = list(share_with)
        self._record_seed()
        with open(path, "rb") as f:
            if resume_dir is None or (not public and skip_owner_key):
                return self._put_stream(f, u, self._new_sealer(public, share_with, skip_owner_key), content_type, storage_class, expect_seq)
            key = resume.journal_key(self.account_id, str(u), os.fspath(path), self.chunk_size, public, storage_class, share_with, content_type)
            jpath = resume.journal_path(Path(resume_dir).expanduser(), key)
            r = resume.load(jpath, key)
            if r is not None and not resume.file_unchanged(key["src"], self.chunk_size, r):
                debug("file changed since the interrupted upload; starting over")
                r = None
            if r is not None:
                sealer = None if r.enc is None else ChunkSealer.reopen(self._root, r.enc)  # type: ignore[arg-type]
                if r.done:
                    debug(f"resuming upload of {u}: {len(r.done)} chunks already stored")
                journal, done = resume.Journal.append(jpath), r.done
            else:
                sealer = self._new_sealer(public, share_with, skip_owner_key)
                journal, done = resume.Journal.create(jpath, key, sealer.enc_info if sealer else None), {}
            try:
                rec = self._put_stream(f, u, sealer, content_type, storage_class, expect_seq, journal, done)
            except Conflict:
                journal.close()
                raise
            except Exception as e:
                journal.close()
                raise TransferInterrupted(f"upload of {u} interrupted; run it again to resume: {e}") from e
            journal.finish()
            return rec

    def _put_stream(
        self,
        reader: BinaryIO,
        u: NearUri,
        sealer: Optional[ChunkSealer],
        content_type: Optional[str],
        storage_class: Optional[str],
        expect_seq: Optional[int],
        journal: Optional[resume.Journal] = None,
        done: Optional[dict] = None,
    ) -> PointerRecord:
        cs = self.chunk_size
        if not 0 < cs <= MAX_CHUNK_BYTES:
            raise ValueError("bad chunk_size")
        ns = u.namespace
        # Repeated content (public data) yields repeated cids: upload each once.
        seen: set[str] = set()
        lock = threading.Lock()

        def pieces() -> Iterator[tuple[int, bool, bytes]]:
            # One chunk of read-ahead to know which chunk is the last.
            cur, idx = _read_full(reader, cs), 0
            while True:
                nxt = _read_full(reader, cs) if len(cur) == cs else b""
                last = not nxt
                yield idx, last, cur
                if last:
                    return
                cur, idx = nxt, idx + 1

        def work(p: tuple[int, bool, bytes]) -> tuple[ChunkRef, int]:
            idx, last, pt = p
            if done and idx in done:
                with lock:
                    seen.add(done[idx].cid)
                return done[idx], len(pt)
            if journal is not None:
                journal.dispatched(idx, resume.plain_hash(pt))
            ct = pt if sealer is None else sealer.seal(idx, last, pt)
            c = cid(ct)
            with lock:
                dup = c in seen
                seen.add(c)
            if dup:
                return ChunkRef(c, len(ct)), len(pt)
            ref = self._upload_chunk(ns, c, ct, storage_class)
            if journal is not None:
                journal.done(idx, ref)
            return ref, len(pt)

        refs = list(self._pmap(work, pieces()))
        manifest = Manifest(1, sum(n for _, n in refs), cs, [r for r, _ in refs], sealer.enc_info if sealer else None, content_type)
        return self._commit(u, manifest, storage_class, expect_seq)

    def _commit(self, u: NearUri, manifest: Manifest, storage_class: Optional[str] = None, expect_seq: Optional[int] = None) -> PointerRecord:
        """Publish ``manifest`` (chunks already uploaded) as the new version of ``u``.

        The record PUT is a compare-and-swap on ``seq``, so it is the one write that is not
        idempotent. After a transient failure the earlier attempt may have landed; a following
        409 is then checked against the current head, and if that head is this manifest by
        this key, the write succeeded. A conflict with someone else's write is retried once
        with the new seq (unless ``expect_seq`` is set: then it is a :class:`Conflict`).
        """
        seed = self._record_seed()
        my_pk = public_key_of(seed)
        mbytes = manifest.to_bytes()
        stored = manifest.stored_size() + len(mbytes)
        mref = self._upload_chunk(u.namespace, cid(mbytes), mbytes, storage_class)
        if expect_seq is not None:
            prev = expect_seq
        else:
            h = self._head_unchecked(u)
            prev = h.record.seq if h else 0
        maybe_landed = False
        conflicts = 0
        attempt = 0
        while True:
            rec = PointerRecord(u.namespace, u.path, mref.cid, manifest.size, stored, prev + 1, self.account_id, my_pk, int(time.time() * 1000))
            rec.sig = sign(seed, rec.signing_bytes())
            body = json.dumps(rec.to_dict(), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            wait: Optional[float] = None
            try:
                # Same class header as the chunks: the gateway records it in the index.
                r = self._send("PUT", _obj_path(u), "", body, storage_class)
            except httpx.TransportError as e:
                err: BaseException = e
            else:
                if r.is_success:
                    return rec
                if r.status_code == 409:
                    cur = self._head_unchecked(u)
                    if cur is not None and maybe_landed and cur.record.manifest_cid == mref.cid and cur.record.writer_pk == my_pk and cur.record.seq == prev + 1:
                        return cur.record
                    current = cur.record.seq if cur else 0
                    if expect_seq is not None:
                        raise Conflict(str(u), current)
                    conflicts += 1
                    if conflicts >= 2:
                        raise RuntimeError(f"concurrent write conflict on {u}")
                    prev = current
                    continue
                err = GatewayError(r.status_code, r.text)
                if not retryable_status(r.status_code):
                    raise err
                wait = retry_after(r.headers)
            maybe_landed = True
            attempt += 1
            if attempt >= max(1, self.net.attempts):
                debug(f"committing {u}: giving up after {attempt} attempts")
                raise err
            self._sleep(self.net.delay(attempt - 1, wait))

    def share(self, uri: Union[str, NearUri], recipient: str) -> PointerRecord:
        """Re-wrap the object key of ``uri`` to ``recipient`` (``x25519:<base58>``). Chunks are
        reused (and keep their storage class); only a new manifest and record are written. The
        recipient also needs read access via namespace policy."""
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
        nm = Manifest(m.version, m.size, m.chunk_size, m.chunks, add_recipient(self._root, m.enc, recipient), m.content_type)
        return self._commit(u, nm, head.storage_class)

    def delete(self, uri: Union[str, NearUri]) -> None:
        """Delete ``uri``. Retried; a 404 after a failed attempt means that attempt already deleted it."""
        self._delete(NearUri.coerce(uri), None)

    def delete_if(self, uri: Union[str, NearUri], seq: int) -> None:
        """Delete ``uri`` only if its current version is ``seq``; otherwise :class:`Conflict`."""
        self._delete(NearUri.coerce(uri), seq)

    def _delete(self, u: NearUri, seq: Optional[int]) -> None:
        q = f"seq={seq}" if seq is not None else ""

        def once(attempt: int) -> None:
            r = self._send("DELETE", _obj_path(u), q)
            if r.status_code == 404 and attempt > 0:
                return
            if r.status_code == 409 and seq is not None:
                m = re.search(r"current seq is (\d+)", r.text)
                raise Conflict(str(u), int(m.group(1)) if m else 0)
            self._ok(r)

        self._retry("delete", once)

    # ---------------------------------------------------------------- reads

    def _fetch_via_gateway(self, u: NearUri, c: str, idx: int, length: int) -> bytes:
        """Fetch a chunk via the gateway (signed, retried), verifying its cid. ``idx`` goes
        into the signed query so concurrent fetches of a repeated chunk never produce
        identical signatures (gateway replay cache)."""
        q = f"chunk={c}&i={idx}"

        def once(_: int) -> bytes:
            b = self._ok(self._send("GET", _obj_path(u), q, xfer=length)).content
            if cid(b) != c:
                # corrupted or truncated in transit: fetch again
                raise Retry(ValueError(f"chunk {c} content does not match its id"))
            return b

        return self._retry(f"fetch chunk {idx}", once)

    def _fetch_chunk(self, u: NearUri, loc: Located, idx: int) -> bytes:
        """Chunk ``idx``: inlined bytes, else the direct URL, else (or on any direct-fetch
        problem) the gateway."""
        c = loc.manifest.chunks[idx]
        lc = loc.chunks[idx] if idx < len(loc.chunks) else None
        if lc is not None and lc.data is not None:
            try:
                b = base64.b64decode(lc.data, validate=True)
                if cid(b) == c.cid:
                    return b
            except (binascii.Error, ValueError):
                pass
            debug(f"inlined chunk {c.cid} is invalid; fetching it")
        url = loc.direct_url(idx)
        if url is not None:
            try:
                deadline = self.net.timeout_for(c.len)
                r = self._read(self._http.build_request("GET", url, timeout=self.net.httpx_timeout(deadline)), time.monotonic() + deadline)
                if r.status_code == 200 and cid(r.content) == c.cid:
                    return r.content
                debug(f"direct fetch of {c.cid}: HTTP {r.status_code} or wrong content; using gateway")
            except httpx.HTTPError as e:
                debug(f"direct fetch of {c.cid}: {e!r}; using gateway")
        return self._fetch_via_gateway(u, c.cid, idx, c.len)

    def _opener(self, m: Manifest) -> Optional[ChunkOpener]:
        if m.enc is None:
            return None
        if self._root is None:
            raise ValueError("object is encrypted and no root key is loaded")
        return ChunkOpener(self._root, m.enc)

    def _plain_chunk(self, u: NearUri, loc: Located, opener: Optional[ChunkOpener], idx: int) -> bytes:
        """Fetch + verify + decrypt chunk ``idx``."""
        ct = self._fetch_chunk(u, loc, idx)
        m = loc.manifest
        n = len(m.chunks)
        pt = ct if opener is None else opener.open(idx, idx + 1 == n, ct)
        expect = chunk_plain_len(m.size, m.chunk_size, idx)
        if len(pt) != expect:
            raise ValueError(f"chunk {idx} has {len(pt)} plaintext bytes, expected {expect}")
        return pt

    def get_object(self, uri: Union[str, NearUri]) -> tuple[ObjectHead, bytes]:
        """Download, verify and decrypt (in memory; see ``get_to_file`` for large objects)."""
        u = NearUri.coerce(uri)
        loc = self._locate_or_404(u)
        opener = self._opener(loc.manifest)
        data = b"".join(self._pmap(lambda i: self._plain_chunk(u, loc, opener, i), range(len(loc.manifest.chunks))))
        if len(data) != loc.manifest.size:
            raise ValueError("size mismatch")
        return loc.head(), data

    def get(self, uri: Union[str, NearUri]) -> bytes:
        return self.get_object(uri)[1]

    def get_to_file(self, uri: Union[str, NearUri], path: Union[str, os.PathLike]) -> ObjectHead:
        """Download to ``path`` with bounded memory and parallel chunk fetches. Writes
        ``{path}.drive-part`` and renames it into place when complete.

        Resumable: if a download fails (:class:`TransferInterrupted`), the part file and
        ``{path}.drive-part.json`` stay. The next call for the same version of the object
        checks every chunk already on disk (by re-deriving its cid from the bytes) and fetches
        only the missing or damaged ones. A newer version starts over.
        """
        u = NearUri.coerce(uri)
        path = os.fspath(path)
        loc = self._locate_or_404(u)
        m = loc.manifest
        opener = self._opener(m)
        part, meta_path = path + ".drive-part", path + ".drive-part.json"
        meta = {"uri": str(u), "manifest_cid": loc.record.manifest_cid, "size": m.size}
        resumable = False
        if os.path.exists(part):
            try:
                with open(meta_path, "rb") as mf:
                    resumable = json.load(mf) == meta
            except (OSError, ValueError):
                pass
        if resumable:
            f = open(part, "r+b")
        else:
            f = open(part, "w+b")
            with open(meta_path, "w", encoding="utf-8") as mf:
                json.dump(meta, mf, separators=(",", ":"), ensure_ascii=False)
        try:
            f.truncate(m.size)
            n = len(m.chunks)
            have = _chunks_on_disk(f, m, opener) if resumable else [False] * n
            if resumable:
                debug(f"resuming download of {u}: {sum(have)}/{n} chunks already on disk")
            lock = threading.Lock()

            def work(i: int) -> None:
                pt = self._plain_chunk(u, loc, opener, i)
                with lock:
                    f.seek(i * m.chunk_size)
                    f.write(pt)

            try:
                for _ in self._pmap(work, [i for i in range(n) if not have[i]]):
                    pass
            except Exception as e:
                f.flush()
                os.fsync(f.fileno())
                raise TransferInterrupted(f"download of {u} interrupted; partial data kept in {part}, run it again to resume: {e}") from e
            f.flush()
            os.fsync(f.fileno())
        finally:
            f.close()
        os.replace(part, path)
        try:
            os.remove(meta_path)
        except FileNotFoundError:
            pass
        return loc.head()

    def get_to_writer(self, uri: Union[str, NearUri], w: BinaryIO) -> ObjectHead:
        """Stream the object, in order, into the binary writer ``w`` with bounded memory."""
        u = NearUri.coerce(uri)
        loc = self._locate_or_404(u)
        self.write_range(u, loc, 0, loc.manifest.size, w)
        return loc.head()

    def get_range(self, uri: Union[str, NearUri], start: int, end: int) -> bytes:
        """Plaintext bytes ``[start, min(end, size))``; fetches only the chunks covering them."""
        u = NearUri.coerce(uri)
        out = io.BytesIO()
        self.write_range(u, self._locate_or_404(u), start, end, out)
        return out.getvalue()

    def write_range(self, uri: Union[str, NearUri], loc: Located, start: int, end: int, w: BinaryIO) -> None:
        """Stream plaintext bytes ``[start, min(end, size))`` of an already-located object into ``w``."""
        u = NearUri.coerce(uri)
        m = loc.manifest
        start, end = min(start, m.size), min(end, m.size)
        if start >= end:
            return
        opener = self._opener(m)
        cs = m.chunk_size
        first, last = start // cs, (end - 1) // cs
        for idx, pt in zip(range(first, last + 1), self._pmap(lambda i: self._plain_chunk(u, loc, opener, i), range(first, last + 1))):
            base = idx * cs
            w.write(pt[max(0, start - base) : min(end - base, len(pt))])
