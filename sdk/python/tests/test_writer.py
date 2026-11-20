"""Reader-side writer authorization: records must be signed with a key the writer published
(``get_sign_keys``) and the namespace rules (``get_rules``) must let the writer write the path."""
from __future__ import annotations

import base64
import json
import time

import httpx
import pytest

from conftest import FakeGateway
from near_drive import (
    ChunkRef,
    Client,
    Manifest,
    NetConfig,
    PointerRecord,
    RootKey,
    StorageContract,
    WriterCheck,
    cid,
    generate_secret_key,
    parse_secret_key,
    public_key_of,
    sign,
)
from near_drive import chain as chain_mod


class FakeRpc:
    """A NEAR RPC endpoint serving ``get_sign_keys`` / ``get_rules`` of a fake drive contract."""

    def __init__(self, contract_id: str = "drive.test"):
        self.contract_id = contract_id
        self.sign_keys: dict[str, list] = {}
        self.rules: dict[str, list] = {}
        self.calls: list[tuple[str, dict]] = []
        self.requests: list[dict] = []
        self.fail = False

    def handle(self, req: httpx.Request) -> httpx.Response:
        if self.fail:
            raise httpx.ConnectError("network down", request=req)
        body = json.loads(req.read())
        self.requests.append(body)
        p = body["params"]
        if body["method"] != "query" or p["request_type"] != "call_function" or p["account_id"] != self.contract_id:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": "x", "error": {"name": "HANDLER_ERROR", "cause": {"name": "UNKNOWN_ACCOUNT"}}})
        args = json.loads(base64.b64decode(p["args_base64"]))
        self.calls.append((p["method_name"], args))
        if p["method_name"] == "get_sign_keys":
            out = self.sign_keys.get(args["account_id"], [])
        elif p["method_name"] == "get_rules":
            out = self.rules.get(args["namespace"], [])
        else:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": "x", "result": {"error": "MethodNotFound"}})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "x", "result": {"result": list(json.dumps(out).encode()), "logs": []}})

    def contract(self, contract_id: str = "drive.test") -> StorageContract:
        return StorageContract("http://rpc.test", contract_id, http=httpx.Client(transport=httpx.MockTransport(self.handle)))


EMPTY = Manifest(1, 0, 8, [])


def _rec(seed: bytes, **over) -> PointerRecord:
    kw = dict(namespace="alice.near", path="a", manifest_cid=EMPTY.cid(), size=0, stored_size=1, seq=1, writer="alice.near", writer_pk=public_key_of(seed), ts_ms=2_000_000_000_000)
    kw.update(over)
    r = PointerRecord(**kw)
    r.sig = sign(seed, r.signing_bytes())
    return r


ALICE, APP, EVIL = bytes([1]) * 32, bytes([2]) * 32, bytes([3]) * 32


def test_storage_contract_view_calls():
    rpc = FakeRpc()
    rpc.sign_keys["alice.near"] = [{"key": "ed25519:x", "since_ms": "123"}]
    c = rpc.contract()
    assert [(e.key, e.since_ms) for e in c.get_sign_keys("alice.near")] == [("ed25519:x", 123)]
    assert rpc.requests[0]["method"] == "query"
    assert {k: rpc.requests[0]["params"][k] for k in ("request_type", "finality", "account_id", "method_name")} == {
        "request_type": "call_function", "finality": "final", "account_id": "drive.test", "method_name": "get_sign_keys"}
    assert rpc.calls[0] == ("get_sign_keys", {"account_id": "alice.near"})
    rpc.rules["app.near"] = [{"prefix": "u/", "write": ["*"]}]
    rules = c.get_rules("app.near")
    assert [(r.prefix, r.read, r.write, r.payer) for r in rules] == [("u/", [], ["*"], None)]
    assert rpc.calls[1] == ("get_rules", {"namespace": "app.near"})
    with pytest.raises(RuntimeError, match="UNKNOWN_ACCOUNT"):
        rpc.contract("nope.test").get_rules("a.near")
    with pytest.raises(RuntimeError, match="MethodNotFound"):
        c.view("other", {})


def _chain(**kw):
    rpc = FakeRpc()
    rpc.sign_keys["alice.near"] = [{"key": public_key_of(ALICE), "since_ms": "1000000000000"}]
    rpc.sign_keys["app.near"] = [{"key": public_key_of(APP), "since_ms": "1000000000000"}]
    return rpc, WriterCheck.chain(rpc.contract(), **kw)


class _Clock:
    def __init__(self, monkeypatch):
        self.t = time.monotonic()
        monkeypatch.setattr(chain_mod.time, "monotonic", lambda: self.t)


def test_chain_owner_key(monkeypatch):
    rpc, wc = _chain()
    wc.verify(_rec(ALICE))
    assert [m for m, _ in rpc.calls] == ["get_sign_keys"]  # owners need no rules lookup
    with pytest.raises(ValueError, match="not a signing key of alice.near"):
        wc.verify(_rec(EVIL))
    with pytest.raises(ValueError, match="not a signing key"):
        wc.verify(_rec(ALICE, ts_ms=1_000_000_000_000 - 300_001))  # used before it was published


def test_chain_rules_for_non_owner_and_refresh(monkeypatch):
    clock = _Clock(monkeypatch)
    rpc, wc = _chain()
    r = _rec(APP, writer="app.near", path="inbox/1")
    with pytest.raises(ValueError, match="may not write there"):
        wc.verify(r)
    rpc.rules["alice.near"] = [{"prefix": "inbox/", "write": ["app.near"]}]
    clock.t += 6  # a failed check re-reads state older than 5 s
    wc.verify(r)
    with pytest.raises(ValueError, match="may not write there"):
        wc.verify(_rec(APP, writer="app.near", path="other/1"))


def test_chain_cache_ttl_and_bound(monkeypatch):
    clock = _Clock(monkeypatch)
    rpc, wc = _chain(max_entries=2)
    for _ in range(5):
        wc.verify(_rec(ALICE))
    assert len(rpc.calls) == 1
    clock.t += 61
    wc.verify(_rec(ALICE))
    assert len(rpc.calls) == 2
    for w in ("w1.near", "w2.near"):
        with pytest.raises(ValueError, match="not a signing key"):
            wc.verify(_rec(ALICE, namespace=w, writer=w))
    n = len(rpc.calls)
    wc.verify(_rec(ALICE))  # evicted by the 2-entry bound
    assert len(rpc.calls) == n + 1


def test_chain_failures_not_cached():
    rpc, wc = _chain()
    rpc.fail = True
    with pytest.raises(httpx.ConnectError):
        wc.verify(_rec(ALICE))
    rpc.fail = False
    wc.verify(_rec(ALICE))


# ---------------------------------------------------------------- client end to end

NET = NetConfig(attempts=2, base_delay=0.001, max_delay=0.005)


class World:
    def __init__(self, rpc: FakeRpc | None = None):
        self.keys: dict[str, set] = {}
        self.fake = FakeGateway(self.keys)
        self.rpc = rpc

    def transport(self) -> httpx.BaseTransport:
        def route(req: httpx.Request) -> httpx.Response:
            if self.rpc is not None and req.url.host == "rpc.test":
                return self.rpc.handle(req)
            return self.fake.handle(req)

        return httpx.MockTransport(route)

    def client(self, account: str, root: RootKey | None, **kw) -> Client:
        sk = generate_secret_key()
        self.keys.setdefault(account, set()).add(public_key_of(parse_secret_key(sk)))
        if "rpc_url" in kw:
            # the client's own StorageContract must go through the mock transport too
            kw["writer_check"] = WriterCheck.chain(StorageContract(kw.pop("rpc_url"), kw.pop("contract_id"), http=httpx.Client(transport=self.transport())))
        return Client("http://gateway.test", account, sk, root, http=httpx.Client(transport=self.transport()), net=NET, **kw)

    def forge(self, path: str, seed: bytes, data: bytes) -> None:
        """A record claiming alice.near but self-signed with ``seed``, as a malicious gateway would serve."""
        c = cid(data)
        m = Manifest(1, len(data), 1024, [ChunkRef(c, len(data))])
        mb = m.to_bytes()
        self.fake.chunks[c] = data
        self.fake.chunks[m.cid()] = mb
        r = PointerRecord("alice.near", path, m.cid(), len(data), len(data) + len(mb), 1, "alice.near", public_key_of(seed), int(time.time() * 1000))
        r.sig = sign(seed, r.signing_bytes())
        self.fake.index[("alice.near", path)] = (r.to_dict(), "hot")


def test_forged_writer_rejected_on_every_read_path(tmp_path):
    w = World()
    w.forge("forged.txt", bytes([66]) * 32, b"evil")
    root = RootKey.generate()
    c = w.client("alice.near", root, writer_check=WriterCheck.trusted({"alice.near": [root.sign_public_key()]}))
    u = "near://alice.near/forged.txt"
    for f in (lambda: c.get(u), lambda: c.head(u), lambda: c.locate(u), lambda: c.get_range(u, 0, 2),
              lambda: c.get_to_file(u, tmp_path / "out"), lambda: c.get_to_writer(u, open(tmp_path / "w", "wb"))):
        with pytest.raises(ValueError, match="not a signing key of alice.near"):
            f()
    skip = w.client("alice.near", None, writer_check=WriterCheck.insecure_skip_writer_check())
    assert skip.get(u) == b"evil"


def test_records_signed_with_derived_key_and_checked_over_rpc():
    rpc = FakeRpc()
    w = World(rpc)
    root = RootKey.generate()
    rpc.sign_keys["alice.near"] = [{"key": root.sign_public_key(), "since_ms": "1"}]
    c = w.client("alice.near", root, rpc_url="http://rpc.test", contract_id="drive.test")
    u = "near://alice.near/doc.txt"
    r = c.put(u, b"hello")
    assert r.writer_pk == root.sign_public_key() == c.sign_public_key()
    assert r.writer_pk != c.public_key  # not the request-signing access key
    assert c.get(u) == b"hello"
    assert [m for m, _ in rpc.calls] == ["get_sign_keys"]
    # rotated away long ago: a fresh client rejects the old record
    rpc.sign_keys["alice.near"].append({"key": RootKey.generate().sign_public_key(), "since_ms": "2"})
    c2 = w.client("alice.near", root, rpc_url="http://rpc.test", contract_id="drive.test")
    with pytest.raises(ValueError, match="not a signing key"):
        c2.get(u)


def test_rpc_url_makes_a_chain_check():
    c = Client("http://gateway.test", "alice.near", generate_secret_key(), rpc_url="http://rpc.test")
    assert c.writer_check is not None and c.writer_check.kind == "chain"
    assert c.writer_check.contract.contract_id == "drive.near"


def test_app_writes_for_user_under_rules():
    w = World()
    app_root, bob_root = RootKey.generate(), RootKey.generate()
    rules = {"app.near": [{"prefix": "users/{account}/", "read": ["{account}"], "write": ["{account}", "app.near"], "payer": "app.near"}]}
    wc = WriterCheck.trusted({"app.near": [app_root.sign_public_key()], "bob.near": [bob_root.sign_public_key()]}, rules)
    app = w.client("app.near", app_root, writer_check=wc)
    bob = w.client("bob.near", bob_root, writer_check=wc)
    u = "near://app.near/users/bob.near/chat/1"
    with pytest.raises(ValueError, match="no recipients"):
        app.put(u, b"hi bob", skip_owner_key=True)
    app.put(u, b"hi bob", share_with=[bob_root.x25519_public()], skip_owner_key=True)
    assert bob.get(u) == b"hi bob"
    with pytest.raises(ValueError, match="not encrypted to this account"):
        app.get(u)
    # bob may not write into another user's space; his record there is rejected by readers
    bob.put("near://app.near/users/carol.near/x", b"nope")
    with pytest.raises(ValueError, match="may not write there"):
        app.head("near://app.near/users/carol.near/x")


def test_write_needs_root_and_read_needs_writer_check(tmp_path):
    w = World()
    no_root = w.client("alice.near", None, writer_check=WriterCheck.insecure_skip_writer_check())
    u = "near://alice.near/doc.txt"
    with pytest.raises(ValueError, match="writing requires the root key"):
        no_root.put(u, b"x", public=True)
    with pytest.raises(ValueError, match="writing requires the root key"):
        no_root.put(u, b"x", share_with=[RootKey.generate().x25519_public()])
    (tmp_path / "f").write_bytes(b"x")
    with pytest.raises(ValueError, match="writing requires the root key"):
        no_root.put_file(tmp_path / "f", u, public=True)
    assert not w.fake.chunks  # failed before uploading anything
    c = w.client("alice.near", RootKey.generate())
    c.put(u, b"x")  # writes work: the seq lookup needs no writer check
    c.put(u, b"y")
    with pytest.raises(ValueError, match="no writer check configured.*writer_check.*rpc_url"):
        c.get(u)
    with pytest.raises(ValueError, match="writer_check"):
        c.head(u)
