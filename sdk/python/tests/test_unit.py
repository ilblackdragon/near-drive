import pytest

from near_drive import Manifest, RootKey, add_recipient, decrypt_object, encrypt_for, encrypt_object


def test_roundtrip_and_tamper():
    root = RootKey.generate()
    data = bytes(i & 0xFF for i in range(10_000))
    chunks, enc = encrypt_object(root, data, 4096)
    assert len(chunks) == 3
    assert decrypt_object(root, enc, chunks) == data
    with pytest.raises(ValueError):
        decrypt_object(root, enc, chunks[:2])  # truncation
    with pytest.raises(ValueError):
        decrypt_object(root, enc, [chunks[1], chunks[0], chunks[2]])  # reorder
    f = [bytearray(c) for c in chunks]
    f[1][5] ^= 1
    with pytest.raises(ValueError):
        decrypt_object(root, enc, [bytes(c) for c in f])
    with pytest.raises(ValueError):
        decrypt_object(RootKey.generate(), enc, chunks)


def test_sharing_and_app_writes_for_user():
    owner, friend, stranger = RootKey.generate(), RootKey.generate(), RootKey.generate()
    chunks, enc = encrypt_for([owner, friend.x25519_public()], b"hello", 4)
    assert decrypt_object(owner, enc, chunks) == b"hello"
    assert decrypt_object(friend, enc, chunks) == b"hello"
    with pytest.raises(ValueError):
        decrypt_object(stranger, enc, chunks)
    enc2 = add_recipient(owner, enc, stranger.x25519_public())
    assert decrypt_object(stranger, enc2, chunks) == b"hello"
    assert len(add_recipient(owner, enc2, stranger.x25519_public()).wrapped_keys) == 3
    c, e = encrypt_for([friend.x25519_public()], b"for you", 1024)
    assert decrypt_object(friend, e, c) == b"for you"
    with pytest.raises(ValueError):
        decrypt_object(owner, e, c)


def test_empty_object():
    root = RootKey.generate()
    chunks, enc = encrypt_object(root, b"", 1024)
    assert len(chunks) == 1 and len(chunks[0]) == 16
    assert decrypt_object(root, enc, chunks) == b""


def test_manifest_normalization():
    m = Manifest.from_dict({"chunks": [{"len": 3, "cid": "b3:x", "extra": 1}], "size": 3, "version": 1, "chunk_size": 4, "enc": None, "content_type": None, "junk": True})
    assert m.to_json() == '{"version":1,"size":3,"chunk_size":4,"chunks":[{"cid":"b3:x","len":3}]}'
    with pytest.raises(ValueError):
        Manifest.from_dict({"version": 1.0, "size": 3, "chunk_size": 4, "chunks": []})
    with pytest.raises(ValueError):
        Manifest.from_dict({"version": True, "size": 3, "chunk_size": 4, "chunks": []})


from near_drive import ChunkRef, NearUri, ObjectHead, PointerRecord, WriterCheck, cid, public_key_of, sign, verify_head  # noqa: E402

SEED = bytes([7]) * 32
URI = NearUri.parse("near://alice.near/a/b")
MAN = Manifest(1, 3, 8, [ChunkRef(cid(b"abc"), 3)])


def _rec(m, **over):
    kw = dict(namespace="alice.near", path="a/b", manifest_cid=m.cid(), size=m.size, stored_size=100, seq=1, writer="alice.near", writer_pk=public_key_of(SEED), ts_ms=1)
    kw.update(over)
    r = PointerRecord(**kw)
    r.sig = sign(SEED, r.signing_bytes())
    return r


def test_verify_head():
    wc = WriterCheck.trusted({"alice.near": [public_key_of(SEED)]})
    verify_head(URI, ObjectHead(_rec(MAN), MAN), wc)
    with pytest.raises(ValueError, match="different object"):
        verify_head(URI, ObjectHead(_rec(MAN, path="a/c"), MAN), wc)
    r = _rec(MAN)
    r.seq = 2
    with pytest.raises(ValueError, match="signature"):
        verify_head(URI, ObjectHead(r, MAN), wc)
    other = Manifest(1, 3, 8, MAN.chunks, None, "x")
    with pytest.raises(ValueError, match="manifest does not match"):
        verify_head(URI, ObjectHead(_rec(MAN), other), wc)
    m4 = Manifest(1, 4, 8, MAN.chunks)
    with pytest.raises(ValueError, match="do not add up"):
        verify_head(URI, ObjectHead(_rec(m4), m4), wc)
    # a record self-signed by a key alice never published (a forging gateway)
    evil = bytes([9]) * 32
    f = PointerRecord("alice.near", "a/b", MAN.cid(), 3, 100, 1, "alice.near", public_key_of(evil), 1)
    f.sig = sign(evil, f.signing_bytes())
    with pytest.raises(ValueError, match="not a signing key of alice.near"):
        verify_head(URI, ObjectHead(f, MAN), wc)
    verify_head(URI, ObjectHead(f, MAN), WriterCheck.insecure_skip_writer_check())
    with pytest.raises(ValueError, match="writer_check"):
        verify_head(URI, ObjectHead(_rec(MAN), MAN), None)
