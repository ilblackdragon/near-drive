"""Bad networks: retries, safe commits, conditional writes, resumable transfers.

Each ``env`` test runs against the in-memory fake gateway and, when
``target/debug/near-drive-gateway`` is built, the real one (on 127.0.0.1)."""
from __future__ import annotations

import os

import httpx
import pytest

from conftest import write_pattern_file
from near_drive import Conflict, GatewayError, NetConfig, RootKey, TransferInterrupted

BIG = 1_000_000  # 16 chunks of 64 KiB


def test_netconfig_delays_and_deadlines():
    c = NetConfig(base_delay=0.1, max_delay=1.0)
    assert all(c.delay(a) <= 1.0 for a in range(30))
    assert c.delay(0, 2.0) >= 2.0, "Retry-After is a floor"
    assert c.delay(0, 1000.0) <= 4.0, "but capped"
    assert c.timeout_for(0) == c.base_timeout
    assert c.timeout_for(64 * 1024 * 10) == c.base_timeout + 10


def test_every_operation_survives_a_flaky_network(env):
    c = env.client(attempts=8, parallelism=4)
    env.proxy.set("flaky")
    data = write_pattern_file(env.path("big"), 7, BIG)
    big = "near://alice.near/big.bin"
    c.put_file(env.path("big"), big)
    c.get_to_file(big, env.path("big.out"))
    assert env.path("big.out").read_bytes() == data
    assert c.get_range(big, 100_000, 400_000) == data[100_000:400_000]
    assert c.get(big) == data

    small = "near://alice.near/small.txt"
    c.put(small, b"hello")
    c.put(small, b"hello again")  # seq 2 through lost responses
    assert c.get(small) == b"hello again"
    assert c.head(small).record.seq == 2
    assert len(c.list("near://alice.near/")) == 2
    c.delete(small)
    assert c.head(small) is None
    assert env.proxy.k > 40, "faults were actually injected"


def test_lost_commit_response_is_not_a_conflict(env):
    c = env.client(attempts=4, parallelism=1)
    u = "near://alice.near/lost.txt"
    is_record_put = lambda m, p: m == "PUT" and p.startswith("/v1/o/")  # noqa: E731
    env.proxy.set(("lose", is_record_put))
    assert c.put(u, b"one").seq == 1
    env.proxy.set(("lose", is_record_put))
    rec = c.put(u, b"two")
    assert rec.seq == 2
    h = c.head(u)
    assert h.record.seq == 2 and h.record.manifest_cid == rec.manifest_cid
    # the 409 after the lost response was resolved by looking at the head, not by writing seq 3
    assert sum(1 for m, p in env.proxy.log if m == "PUT" and p.startswith("/v1/o/")) == 2


def test_lost_delete_response(env):
    c = env.client(attempts=4, parallelism=1)
    u = "near://alice.near/d.txt"
    c.put(u, b"x")
    env.proxy.set(("lose", lambda m, p: m == "DELETE"))
    c.delete(u)  # second attempt sees 404: already deleted
    assert c.head(u) is None
    with pytest.raises(GatewayError) as e:
        c.delete(u)  # a first-attempt 404 is an error
    assert e.value.status == 404


def test_expect_seq_and_delete_if(env):
    c = env.client()
    u = "near://alice.near/cas.txt"
    assert c.put(u, b"a", expect_seq=0).seq == 1
    with pytest.raises(Conflict) as e:
        c.put(u, b"b", expect_seq=0)
    assert e.value.current == 1
    assert c.put(u, b"b", expect_seq=1).seq == 2
    with pytest.raises(Conflict) as e:
        c.delete_if(u, 1)
    assert e.value.current == 2
    c.delete_if(u, 2)
    assert c.head(u) is None
    with pytest.raises(Conflict) as e:
        c.put(u, b"c", expect_seq=5)
    assert e.value.current == 0


def test_interrupted_upload_resumes_without_resending_chunks(env):
    data = write_pattern_file(env.path("f"), 1, BIG)
    u = "near://alice.near/f.bin"
    jdir = env.path("journal")
    env.proxy.set(("cut", 5))
    with pytest.raises(TransferInterrupted, match="run it again to resume"):
        env.client(1, 1).put_file(env.path("f"), u, resume_dir=jdir)
    assert len(os.listdir(jdir)) == 1, "journal kept"

    env.proxy.set("pass")
    env.client(1, 1).put_file(env.path("f"), u, resume_dir=jdir)
    assert env.proxy.chunk_puts == 16 - 5 + 1, "only the missing chunks + the manifest"
    assert os.listdir(jdir) == [], "journal removed after success"
    env.client(1, 1).get_to_file(u, env.path("f.out"))
    assert env.path("f.out").read_bytes() == data


def test_interrupted_public_upload_resumes(env):
    data = write_pattern_file(env.path("f"), 2, BIG)
    u = "near://alice.near/pub.bin"
    jdir = env.path("journal")
    env.proxy.set(("cut", 3))
    with pytest.raises(TransferInterrupted):
        env.client(1, 1).put_file(env.path("f"), u, public=True, resume_dir=jdir)
    env.proxy.set("pass")
    env.client(1, 1, root=False).put_file(env.path("f"), u, public=True, resume_dir=jdir)
    assert env.proxy.chunk_puts == 16 - 3 + 1
    assert env.client(root=False).get(u) == data


def test_changed_file_restarts_the_upload_with_a_fresh_key(env):
    write_pattern_file(env.path("f"), 1, BIG)
    u = "near://alice.near/f.bin"
    jdir = env.path("journal")
    env.proxy.set(("cut", 5))
    with pytest.raises(TransferInterrupted):
        env.client(1, 1).put_file(env.path("f"), u, resume_dir=jdir)

    # Same size and mtime, different bytes in an already-sent chunk.
    st = os.stat(env.path("f"))
    data = bytearray(env.path("f").read_bytes())
    data[10] ^= 0xFF
    env.path("f").write_bytes(data)
    os.utime(env.path("f"), ns=(st.st_atime_ns, st.st_mtime_ns))

    env.proxy.set("pass")
    env.client(1, 1).put_file(env.path("f"), u, resume_dir=jdir)
    assert env.proxy.chunk_puts == 16 + 1, "everything re-encrypted and re-sent"
    env.client(1, 1).get_to_file(u, env.path("f.out"))
    assert env.path("f.out").read_bytes() == bytes(data)


def test_interrupted_download_resumes_from_the_part_file(env):
    data = write_pattern_file(env.path("f"), 3, BIG)
    u = "near://alice.near/f.bin"
    env.client(1, 4).put_file(env.path("f"), u)

    env.proxy.set(("cut", 6))
    with pytest.raises(TransferInterrupted, match="run it again to resume"):
        env.client(1, 1).get_to_file(u, env.path("out"))
    assert env.path("out.drive-part").exists() and env.path("out.drive-part.json").exists()

    env.proxy.set("pass")
    env.client(1, 1).get_to_file(u, env.path("out"))
    assert env.proxy.chunk_gets == 16 - 6, "chunks on disk were verified, not refetched"
    assert env.path("out").read_bytes() == data
    assert not env.path("out.drive-part").exists() and not env.path("out.drive-part.json").exists()

    # A new version invalidates the part file: start from scratch.
    env.proxy.set(("cut", 6))
    with pytest.raises(TransferInterrupted):
        env.client(1, 1).get_to_file(u, env.path("out2"))
    data2 = write_pattern_file(env.path("f"), 4, BIG)
    env.proxy.set("pass")
    env.client(1, 4).put_file(env.path("f"), u)
    env.proxy.set("pass")
    env.client(1, 1).get_to_file(u, env.path("out2"))
    assert env.proxy.chunk_gets == 16, "stale part file not reused"
    assert env.path("out2").read_bytes() == data2


def test_damaged_part_file_chunks_are_refetched(env):
    data = write_pattern_file(env.path("f"), 5, BIG)
    u = "near://alice.near/f.bin"
    env.client().put_file(env.path("f"), u, public=True)
    env.proxy.set(("cut", 10))
    with pytest.raises(TransferInterrupted):
        env.client(1, 1).get_to_file(u, env.path("out"))
    with open(env.path("out.drive-part"), "r+b") as f:
        f.seek(3 * 64 * 1024 + 5)
        f.write(b"\x00garbage")
    env.proxy.set("pass")
    env.client(1, 1).get_to_file(u, env.path("out"))
    assert env.proxy.chunk_gets == 16 - 10 + 1
    assert env.path("out").read_bytes() == data


def test_small_objects_are_read_in_one_request(env):
    c = env.client(1, 4)
    u = "near://alice.near/note.txt"
    c.put(u, b"tiny file")
    env.proxy.set("pass")
    assert c.get(u) == b"tiny file"
    assert env.proxy.requests == 1, "locate inlines the chunk"
    loc = c.locate(u)
    assert all(ch.data is not None and ch.url is None for ch in loc.chunks)


def test_empty_and_exact_multiple_files(env):
    c = env.client()
    env.path("empty").write_bytes(b"")
    c.put_file(env.path("empty"), "near://alice.near/empty")
    assert c.get("near://alice.near/empty") == b""
    data = write_pattern_file(env.path("two"), 9, 2 * 64 * 1024)
    rec = c.put_file(env.path("two"), "near://alice.near/two", public=True)
    assert rec.size == len(data)
    assert len(c.head("near://alice.near/two").manifest.chunks) == 2
    c.get_to_file("near://alice.near/empty", env.path("empty.out"))
    assert env.path("empty.out").read_bytes() == b""


# ---- fake-gateway-only checks (precise fault shapes, headers)


def test_storage_class_on_record_put_and_share_keeps_it(fake_env):
    c = fake_env.client()
    u = "near://alice.near/cold.bin"
    c.put(u, b"archive", storage_class="bulk")
    assert fake_env.fake.record_put_classes[-1] == "bulk"
    assert c.head(u).storage_class == "bulk"
    c.share(u, RootKey.generate().x25519_public())
    assert fake_env.fake.record_put_classes[-1] == "bulk", "share keeps the object's class"


def test_retry_after_is_honoured_and_attempts_are_bounded(fake_env):
    c = fake_env.client(attempts=3)
    c.net.max_delay = 1.0  # Retry-After floors are capped at 4 * max_delay
    slept = []
    c._sleep = slept.append
    calls = []

    class Always503(httpx.BaseTransport):
        def handle_request(self, req):
            calls.append(req.headers["x-near-signature"])
            return httpx.Response(503, headers={"retry-after": "2"}, text="busy")

    c._http = httpx.Client(transport=Always503())
    with pytest.raises(GatewayError) as e:
        c.head("near://alice.near/x")
    assert e.value.status == 503
    assert len(calls) == 3 and len(set(calls)) == 3, "each attempt is signed afresh"
    assert len(slept) == 2 and all(s >= 2 for s in slept)


def test_non_retryable_errors_fail_fast(fake_env):
    c = fake_env.client(attempts=5)
    n = []

    class Forbidden(httpx.BaseTransport):
        def handle_request(self, req):
            n.append(1)
            return httpx.Response(403, text="no")

    c._http = httpx.Client(transport=Forbidden())
    with pytest.raises(GatewayError):
        c.get("near://alice.near/x")
    assert len(n) == 1


def test_bad_inline_data_falls_back_to_the_gateway(fake_env):
    c = fake_env.client()
    u = "near://alice.near/n.txt"
    c.put(u, b"hello")
    inner = fake_env.proxy.inner

    class Corrupt(httpx.BaseTransport):
        def handle_request(self, req):
            r = inner.handle_request(req)
            if "mode=locate" in str(req.url):
                v = r.json()
                for ch in v["chunks"]:
                    ch["data"] = "AAAA"
                return httpx.Response(200, json=v)
            return r

    c._http = httpx.Client(transport=Corrupt())
    assert c.get(u) == b"hello"


def test_truncated_and_corrupt_chunk_bodies_are_refetched(fake_env):
    c = fake_env.client(attempts=4, parallelism=1)
    data = write_pattern_file(fake_env.path("f"), 6, 200_000)
    c.put_file(fake_env.path("f"), "near://alice.near/f", public=True)
    inner = fake_env.proxy.inner
    bad = {"n": 0}

    class Mangle(httpx.BaseTransport):
        def handle_request(self, req):
            r = inner.handle_request(req)
            if "chunk=" in str(req.url):
                bad["n"] += 1
                if bad["n"] % 3 == 1:
                    return httpx.Response(200, content=r.content[:-1] + bytes([r.content[-1] ^ 1]))  # flipped bit
                if bad["n"] % 3 == 2:
                    return httpx.Response(200, headers={"content-length": str(len(r.content))}, stream=_short(r.content))
            return r

    c._http = httpx.Client(transport=Mangle())
    assert c.get("near://alice.near/f") == data
    assert bad["n"] > 4


def _short(body):
    class S(httpx.SyncByteStream):
        def __iter__(self):
            yield body[:10]

    return S()
