"""Test gateways (an in-memory fake, and the real binary when built) behind a fault-injecting
httpx transport, mirroring ``crates/near-drive-gateway/tests/resilience.rs``."""
from __future__ import annotations

import base64
import json
import os
import random
import re
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, unquote

import httpx
import pytest

from near_drive import Client, NetConfig, RootKey, WriterCheck, canonical_request, cid, generate_secret_key, parse_secret_key, public_key_of, verify

REPO = Path(__file__).resolve().parents[3]
GATEWAY_BIN = REPO / "target" / "debug" / "near-drive-gateway"
INLINE_MAX = 64 * 1024


class FakeGateway:
    """Just enough of the gateway API: signed requests (with a replay cache), chunks, CAS
    records with storage class, head / locate (inlining small objects) / chunk reads,
    conditional deletes, list."""

    def __init__(self, keys: dict[str, str]):
        self.keys = keys
        self.chunks: dict[str, bytes] = {}
        self.index: dict[tuple[str, str], tuple[dict, Optional[str]]] = {}
        self.seen_sigs: set[str] = set()
        self.record_put_classes: list[Optional[str]] = []
        self.lock = threading.Lock()

    @staticmethod
    def _err(status: int, msg: str) -> httpx.Response:
        return httpx.Response(status, text=msg)

    def handle(self, req: httpx.Request) -> httpx.Response:
        body = req.read()
        raw = req.url.raw_path.decode()
        path, _, query = raw.partition("?")
        h = req.headers
        acct, pk, ts, sig = h.get("x-near-account"), h.get("x-near-publickey"), h.get("x-near-timestamp"), h.get("x-near-signature")
        if pk not in self.keys.get(acct, ()) or not verify(pk, canonical_request(req.method, path, query, acct, pk, int(ts), body), sig):
            return self._err(401, "bad signature")
        with self.lock:
            if sig in self.seen_sigs:
                return self._err(401, "replayed request")
            self.seen_sigs.add(sig)
            return self._route(req.method, path, parse_qs(query), body, h)

    def _route(self, method: str, path: str, q: dict, body: bytes, h: httpx.Headers) -> httpx.Response:
        if m := re.fullmatch(r"/v1/chunk/([^/]+)/(b3:[0-9a-f]{64})", path):
            if method != "PUT" or cid(body) != m.group(2):
                return self._err(400, "bad chunk")
            self.chunks[m.group(2)] = body
            return httpx.Response(201)
        if m := re.fullmatch(r"/v1/list/([^/]+)", path):
            prefix = q.get("prefix", [""])[0]
            delim = q.get("delimiter", [""])[0] or None
            cursor = q.get("cursor", [""])[0] or None
            limit = min(max(int(q.get("limit", ["1000"])[0]), 1), 1000)
            entries, prefixes, last, nxt = [], [], None, None
            for (ns, p), (r, _) in sorted(self.index.items(), key=lambda kv: (kv[0][0], kv[0][1].encode())):
                if ns != m.group(1) or not p.startswith(prefix):
                    continue
                if cursor is not None and (p.encode() <= cursor.encode() or (delim and cursor.endswith(delim) and p.startswith(cursor))):
                    continue
                i = p.find(delim, len(prefix)) if delim else -1
                cp = p[: i + len(delim)] if i >= 0 else None
                if cp is not None and cp == last:
                    continue
                if len(entries) + len(prefixes) == limit:
                    nxt = last
                    break
                if cp is not None:
                    prefixes.append(cp)
                    last = cp
                else:
                    entries.append({"path": p, "size": r["size"], "seq": r["seq"], "writer": r["writer"], "ts_ms": r["ts_ms"], "manifest_cid": r["manifest_cid"]})
                    last = p
            return httpx.Response(200, json={"entries": entries, "common_prefixes": prefixes, "next_cursor": nxt})
        m = re.fullmatch(r"/v1/o/([^/]+)/(.+)", path)
        if not m:
            return self._err(404, "no route")
        key = (m.group(1), unquote(m.group(2)))
        cur = self.index.get(key)
        if method == "PUT":
            rec = json.loads(body)
            cls = h.get("x-near-drive-class")
            self.record_put_classes.append(cls)
            mbytes = self.chunks.get(rec["manifest_cid"])
            if mbytes is None or any(c["cid"] not in self.chunks for c in json.loads(mbytes)["chunks"]):
                return self._err(400, "chunk not uploaded")
            cur_seq = cur[0]["seq"] if cur else 0
            if rec["seq"] != cur_seq + 1:
                return self._err(409, f"seq conflict: current seq is {cur_seq}")
            self.index[key] = (rec, cls or "hot")
            return httpx.Response(201, json={"seq": rec["seq"]})
        if method == "DELETE":
            if cur is None:
                return self._err(404, "not found")
            if "seq" in q and int(q["seq"][0]) != cur[0]["seq"]:
                return self._err(409, f"seq conflict: current seq is {cur[0]['seq']}")
            del self.index[key]
            return httpx.Response(204)
        if cur is None:
            return self._err(404, "not found")
        rec, cls = cur
        mbytes = self.chunks[rec["manifest_cid"]]
        manifest = json.loads(mbytes)
        if "chunk" in q:
            c = q["chunk"][0]
            if c != rec["manifest_cid"] and all(x["cid"] != c for x in manifest["chunks"]):
                return self._err(404, "chunk is not part of this object")
            return httpx.Response(200, content=self.chunks[c])
        out = {"record": rec, "manifest": manifest, "manifest_raw": base64.b64encode(mbytes).decode(), "class": cls}
        if q.get("mode") == ["locate"]:
            inline = sum(c["len"] for c in manifest["chunks"]) <= INLINE_MAX
            out["chunks"] = [
                {"cid": c["cid"], "len": c["len"], "url": None, "expires_ms": None, **({"data": base64.b64encode(self.chunks[c["cid"]]).decode()} if inline else {})}
                for c in manifest["chunks"]
            ]
        return httpx.Response(200, json=out)


class _Halfway(httpx.SyncByteStream):
    """Yields half the body, then fails (connection reset) or just ends (short body)."""

    def __init__(self, body: bytes, fail: bool):
        self.body, self.fail = body, fail

    def __iter__(self):
        yield self.body[: len(self.body) // 2]
        if self.fail:
            raise httpx.RemoteProtocolError("peer closed connection without sending complete message body")


class FaultTransport(httpx.BaseTransport):
    """Modes (like the Rust test proxy):
    - ``pass``;
    - ``flaky``: request k: k%4==1 -> 503; k%4==2 -> forwarded, but the response is lost
      (writes: 502 or a connection error) or cut off halfway (GET);
    - ``("cut", n)``: chunk transfers after the first n fail with 503 (a dead link);
    - ``("lose", pred)``: forward requests matching ``pred(method, path)`` once, then lose the response.
    """

    def __init__(self, inner: httpx.BaseTransport):
        self.inner = inner
        self.lock = threading.Lock()
        self.set("pass")

    def set(self, mode) -> None:
        self.mode = mode
        self.k = self.requests = self.chunk_ops = self.chunk_puts = self.chunk_gets = 0
        self.log: list[tuple[str, str]] = []

    def handle_request(self, req: httpx.Request) -> httpx.Response:
        req.read()
        pq = req.url.raw_path.decode()
        is_chunk_put = req.method == "PUT" and pq.startswith("/v1/chunk/")
        is_chunk_get = req.method == "GET" and "chunk=" in pq
        with self.lock:
            self.requests += 1
            self.log.append((req.method, pq))
            k = self.k
            self.k += 1
            mode = self.mode
            if mode == "flaky" and k % 4 == 1:
                return httpx.Response(503, headers={"retry-after": "0"}, text="injected")
            if isinstance(mode, tuple) and mode[0] == "cut" and (is_chunk_put or is_chunk_get):
                self.chunk_ops += 1
                if self.chunk_ops > mode[1]:
                    return httpx.Response(503, headers={"retry-after": "0"}, text="injected")
        resp = self.inner.handle_request(req)
        body = resp.read()
        resp.close()
        with self.lock:
            if 200 <= resp.status_code < 300:
                self.chunk_puts += is_chunk_put
                self.chunk_gets += is_chunk_get
            lose = isinstance(mode, tuple) and mode[0] == "lose" and mode[1](req.method, pq)
            if lose:
                self.mode = "pass"
        headers = [(n, v) for n, v in resp.headers.items() if n.lower() not in ("content-length", "transfer-encoding", "content-encoding")]
        if (mode == "flaky" and k % 4 == 2) or lose:
            if req.method != "GET":
                # it happened upstream; the client doesn't know
                if k % 8 == 6 or lose:
                    raise httpx.ReadError("connection reset", request=req)
                return httpx.Response(502, text="injected")
            return httpx.Response(resp.status_code, headers=headers + [("content-length", str(len(body)))], stream=_Halfway(body, k % 8 == 2))
        return httpx.Response(resp.status_code, headers=headers, content=body)


def write_pattern_file(path: Path, seed: int, n: int) -> bytes:
    data = random.Random(seed).randbytes(n)
    path.write_bytes(data)
    return data


class Env:
    def __init__(self, url: str, inner: httpx.BaseTransport, sk: str, tmp: Path, fake: Optional[FakeGateway]):
        self.url, self.sk, self.tmp, self.fake = url, sk, tmp, fake
        self.proxy = FaultTransport(inner)
        self.root = RootKey.generate()
        # Every client of this env writes as alice.near with this root's derived signing key.
        self.writer_check = WriterCheck.trusted({"alice.near": [self.root.sign_public_key()]})
        self._clients: list[Client] = []

    def client(self, attempts: int = 8, parallelism: int = 4, root: bool = True) -> Client:
        net = NetConfig(attempts=attempts, base_delay=0.001, max_delay=0.005)
        c = Client(self.url, "alice.near", self.sk, self.root if root else None, chunk_size=64 * 1024,
                   http=httpx.Client(transport=self.proxy), net=net, parallelism=parallelism, writer_check=self.writer_check)
        self._clients.append(c)
        return c

    def path(self, p: str) -> Path:
        return self.tmp / p

    def close(self) -> None:
        for c in self._clients:
            c.close()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(params=["fake", "real"])
def env(request, tmp_path):
    sk = generate_secret_key()
    pk = public_key_of(parse_secret_key(sk))
    if request.param == "fake":
        fake = FakeGateway({"alice.near": {pk}})
        e = Env("http://gateway.test", httpx.MockTransport(fake.handle), sk, tmp_path, fake)
        yield e
        e.close()
        return
    if not GATEWAY_BIN.exists() or os.environ.get("NEAR_DRIVE_SKIP_REAL_GATEWAY"):
        pytest.skip(f"{GATEWAY_BIN} not built")
    port = _free_port()
    cfg = tmp_path / "gw.json"
    # Loopback only.
    cfg.write_text(json.dumps({"listen": f"127.0.0.1:{port}", "data_dir": str(tmp_path / "gw-data"), "dev_keys": {"alice.near": [pk]}}))
    log = open(tmp_path / "gw.log", "wb")
    proc = subprocess.Popen([str(GATEWAY_BIN), "--config", str(cfg)], stdout=log, stderr=subprocess.STDOUT, env={**os.environ, "RUST_LOG": "warn"})
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                if httpx.get(url + "/healthz", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        else:
            pytest.fail("gateway did not start: " + (tmp_path / "gw.log").read_text())
        if proc.poll() is not None:
            pytest.fail("gateway exited: " + (tmp_path / "gw.log").read_text())
        e = Env(url, httpx.HTTPTransport(), sk, tmp_path, None)
        yield e
        e.close()
    finally:
        proc.terminate()
        proc.wait(5)
        log.close()


@pytest.fixture
def fake_env(tmp_path):
    sk = generate_secret_key()
    fake = FakeGateway({"alice.near": {public_key_of(parse_secret_key(sk))}})
    e = Env("http://gateway.test", httpx.MockTransport(fake.handle), sk, tmp_path, fake)
    yield e
    e.close()
