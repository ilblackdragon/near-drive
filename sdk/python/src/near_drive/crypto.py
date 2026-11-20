"""Chunked envelope encryption, byte-compatible with ``near_drive_core::crypto``.

- per-object random 256-bit DEK; chunks sealed with XChaCha20-Poly1305,
  nonce = nonce_prefix(16) || chunk_index(u64 BE),
  AAD = b"near-drive-chunk-v1" || object_id(16) || chunk_index(u64 BE) || is_last(u8).
- DEK wrapped per recipient: ``kek:<kek_id>`` (owner; XChaCha20-Poly1305 under
  HKDF(root, kek), AAD = object_id) or ``x25519:<base58>`` (ephemeral-static
  X25519; key = HKDF-SHA256(salt="near-drive", ikm=shared,
  info="near-drive/v1/wrap-x25519"||epk||pk), AAD = object_id).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field, replace
from typing import Optional, Sequence, Union

import blake3
import nacl.bindings as nb
import nacl.exceptions

from .keys import _b58, b58encode, format_x25519, parse_x25519, public_key_of

ALG = "xchacha20poly1305-chunked-v1"
TAG_LEN = 16


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def _derive(ikm: bytes, info: bytes) -> bytes:
    return hkdf_sha256(ikm, b"near-drive", info)


class RootKey:
    """Account root key. v0: a local 32-byte secret; later obtained via NEAR MPC CKD."""

    __slots__ = ("_k",)

    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise ValueError("root key must be 32 bytes")
        self._k = bytes(key)

    @classmethod
    def generate(cls) -> "RootKey":
        return cls(os.urandom(32))

    @classmethod
    def from_hex(cls, s: str) -> "RootKey":
        try:
            b = bytes.fromhex(s.strip())
        except ValueError as e:
            raise ValueError("root key must be 32 hex bytes") from e
        return cls(b)

    @classmethod
    def coerce(cls, k: Union["RootKey", bytes, str]) -> "RootKey":
        if isinstance(k, RootKey):
            return k
        return cls.from_hex(k) if isinstance(k, str) else cls(k)

    def __repr__(self) -> str:
        return f"RootKey(kek_id={self.kek_id()})"

    def to_bytes(self) -> bytes:
        return self._k

    def hex(self) -> str:
        return self._k.hex()

    def x25519_secret(self) -> bytes:
        return _derive(self._k, b"near-drive/v1/x25519")

    def x25519_public(self) -> str:
        """``x25519:<base58>``: publish this so others can share objects with the account."""
        return format_x25519(nb.crypto_scalarmult_base(self.x25519_secret()))

    def kek(self) -> bytes:
        return _derive(self._k, b"near-drive/v1/kek")

    def sign_seed(self) -> bytes:
        """Ed25519 seed that signs pointer records: HKDF-SHA256(salt="near-drive", ikm=root,
        info="near-drive/v1/sign"), an RFC 8032 secret key (ed25519-dalek ``SigningKey::from_bytes``)."""
        return _derive(self._k, b"near-drive/v1/sign")

    def sign_public_key(self) -> str:
        """``ed25519:<base58>`` record-signing key; publish it with ``set_sign_key`` (``near drive publish-key``)."""
        return public_key_of(self.sign_seed())

    def kek_id(self) -> str:
        return blake3.blake3(_derive(self._k, b"near-drive/v1/kek-id")).digest()[:8].hex()


#: Who an object key is wrapped to: the owner's RootKey or an ``x25519:<base58>`` key.
Recipient = Union[RootKey, str]


@dataclass
class WrappedKey:
    recipient: str
    nonce: str
    ct: str
    epk: Optional[str] = None

    def to_dict(self) -> dict:
        # Field order of the Rust struct: recipient, epk (if any), nonce, ct.
        d: dict = {"recipient": self.recipient}
        if self.epk is not None:
            d["epk"] = self.epk
        d["nonce"] = self.nonce
        d["ct"] = self.ct
        return d


@dataclass
class EncInfo:
    alg: str
    object_id: str
    nonce_prefix: str
    wrapped_keys: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "alg": self.alg,
            "object_id": self.object_id,
            "nonce_prefix": self.nonce_prefix,
            "wrapped_keys": [w.to_dict() for w in self.wrapped_keys],
        }


def _seal(key: bytes, nonce: bytes, msg: bytes, aad: bytes) -> bytes:
    return nb.crypto_aead_xchacha20poly1305_ietf_encrypt(msg, aad, nonce, key)


def _open(key: bytes, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    return nb.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, aad, nonce, key)


def _dh(sk: bytes, pk: bytes) -> bytes:
    try:
        s = nb.crypto_scalarmult(sk, pk)
    except Exception as e:  # libsodium rejects all-zero (non-contributory) results
        raise ValueError("invalid recipient key") from e
    if s == bytes(32):
        raise ValueError("invalid recipient key")
    return s


def _x25519_wrap_key(shared: bytes, epk: bytes, pk: bytes) -> bytes:
    return _derive(shared, b"near-drive/v1/wrap-x25519" + epk + pk)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str, what: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError, TypeError) as e:
        raise ValueError(f"bad {what}: invalid base64") from e


def _hex16(s: str, what: str) -> bytes:
    try:
        b = bytes.fromhex(s)
    except (ValueError, TypeError) as e:
        raise ValueError(f"bad {what}") from e
    if len(b) != 16 or len(s) != 32:
        raise ValueError(f"bad {what}: expected 16 bytes")
    return b


def _wrap_dek(dek: bytes, object_id: bytes, r: Recipient) -> WrappedKey:
    nonce = os.urandom(24)
    if isinstance(r, RootKey):
        return WrappedKey(f"kek:{r.kek_id()}", _b64(nonce), _b64(_seal(r.kek(), nonce, dek, object_id)))
    pk = parse_x25519(r)
    esk = os.urandom(32)
    epk = nb.crypto_scalarmult_base(esk)
    k = _x25519_wrap_key(_dh(esk, pk), epk, pk)
    return WrappedKey(format_x25519(pk), _b64(nonce), _b64(_seal(k, nonce, dek, object_id)), epk=b58encode(epk))


def _unwrap_dek(root: RootKey, enc: EncInfo, object_id: bytes) -> bytes:
    kek_name = f"kek:{root.kek_id()}"
    x_name = root.x25519_public()
    wk = next((w for w in enc.wrapped_keys if w.recipient in (kek_name, x_name)), None)
    if wk is None:
        raise ValueError(f"object is not encrypted to this account's keys ({kek_name}, {x_name})")
    nonce = _unb64(wk.nonce, "wrap nonce")
    if len(nonce) != 24:
        raise ValueError("bad wrap nonce")
    ct = _unb64(wk.ct, "wrapped key")
    try:
        if wk.recipient == kek_name:
            dek = _open(root.kek(), nonce, ct, object_id)
        else:
            if wk.epk is None:
                raise ValueError("missing epk")
            epk = _b58(wk.epk, 32, "epk")
            sk = root.x25519_secret()
            pk = nb.crypto_scalarmult_base(sk)
            dek = _open(_x25519_wrap_key(nb.crypto_scalarmult(sk, epk), epk, pk), nonce, ct, object_id)
    except (nacl.exceptions.CryptoError, ValueError, RuntimeError) as e:
        raise ValueError("cannot unwrap object key (wrong root key?)") from e
    if len(dek) != 32:
        raise ValueError("bad DEK length")
    return dek


def _chunk_nonce(prefix: bytes, idx: int) -> bytes:
    return prefix + struct.pack(">Q", idx)


def _chunk_aad(object_id: bytes, idx: int, last: bool) -> bytes:
    return b"near-drive-chunk-v1" + object_id + struct.pack(">Q", idx) + (b"\x01" if last else b"\x00")


def plaintext_chunks(plaintext: bytes, chunk_size: int) -> list[bytes]:
    """Split into chunks; an empty object is one empty chunk."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")
    if not plaintext:
        return [b""]
    return [plaintext[i : i + chunk_size] for i in range(0, len(plaintext), chunk_size)]


def encrypt_for(recipients: Sequence[Recipient], plaintext: bytes, chunk_size: int) -> tuple[list[bytes], EncInfo]:
    """Encrypt ``plaintext`` for an explicit recipient set (at least one)."""
    if not recipients:
        raise ValueError("need at least one recipient")
    pieces = plaintext_chunks(plaintext, chunk_size)
    dek, object_id, nonce_prefix = os.urandom(32), os.urandom(16), os.urandom(16)
    n = len(pieces)
    chunks = [_seal(dek, _chunk_nonce(nonce_prefix, i), p, _chunk_aad(object_id, i, i + 1 == n)) for i, p in enumerate(pieces)]
    wrapped = [_wrap_dek(dek, object_id, r) for r in recipients]
    return chunks, EncInfo(ALG, object_id.hex(), nonce_prefix.hex(), wrapped)


def encrypt_object(root: RootKey, plaintext: bytes, chunk_size: int) -> tuple[list[bytes], EncInfo]:
    return encrypt_for([root], plaintext, chunk_size)


def decrypt_object(root: RootKey, enc: EncInfo, chunks: Sequence[bytes]) -> bytes:
    if enc.alg != ALG:
        raise ValueError(f"unsupported alg {enc.alg}")
    if not chunks:
        raise ValueError("object has no chunks")
    object_id = _hex16(enc.object_id, "object_id")
    nonce_prefix = _hex16(enc.nonce_prefix, "nonce_prefix")
    dek = _unwrap_dek(root, enc, object_id)
    n = len(chunks)
    out = []
    for i, c in enumerate(chunks):
        try:
            out.append(_open(dek, _chunk_nonce(nonce_prefix, i), bytes(c), _chunk_aad(object_id, i, i + 1 == n)))
        except nacl.exceptions.CryptoError as e:
            raise ValueError(f"chunk {i} failed authentication") from e
    return b"".join(out)


def add_recipient(root: RootKey, enc: EncInfo, r: Recipient) -> EncInfo:
    """Give another recipient access to an existing object: same chunks, one more wrapped key."""
    object_id = _hex16(enc.object_id, "object_id")
    dek = _unwrap_dek(root, enc, object_id)
    w = _wrap_dek(dek, object_id, r)
    return replace(enc, wrapped_keys=[x for x in enc.wrapped_keys if x.recipient != w.recipient] + [w])


# --- streaming (one chunk at a time), same format as the one-shot functions above ---


def chunk_count(size: int, chunk_size: int) -> int:
    """Number of chunks of an object of ``size`` plaintext bytes (an empty object is one chunk)."""
    return 1 if size == 0 else -(-size // chunk_size)


def chunk_plain_len(size: int, chunk_size: int, idx: int) -> int:
    """Plaintext length of chunk ``idx``."""
    return max(0, min(chunk_size, size - idx * chunk_size))


class ChunkOpener:
    """Opens (and deterministically re-seals) chunks of an existing object."""

    def __init__(self, root: RootKey, enc: EncInfo):
        if enc.alg != ALG:
            raise ValueError(f"unsupported alg {enc.alg}")
        self._object_id = _hex16(enc.object_id, "object_id")
        self._prefix = _hex16(enc.nonce_prefix, "nonce_prefix")
        self._dek = _unwrap_dek(root, enc, self._object_id)

    def open(self, idx: int, last: bool, ciphertext: bytes) -> bytes:
        try:
            return _open(self._dek, _chunk_nonce(self._prefix, idx), bytes(ciphertext), _chunk_aad(self._object_id, idx, last))
        except nacl.exceptions.CryptoError as e:
            raise ValueError(f"chunk {idx} failed authentication") from e

    def reseal(self, idx: int, last: bool, plaintext: bytes) -> bytes:
        """Re-encrypt ``plaintext`` as chunk ``idx`` (deterministic), e.g. to check that bytes
        already on disk are exactly chunk ``idx`` by comparing cids."""
        return _seal(self._dek, _chunk_nonce(self._prefix, idx), bytes(plaintext), _chunk_aad(self._object_id, idx, last))


class ChunkSealer:
    """Seals the chunks of one new object, one at a time."""

    def __init__(self, dek: bytes, object_id: bytes, nonce_prefix: bytes, enc: EncInfo):
        self._dek, self._object_id, self._prefix, self.enc_info = dek, object_id, nonce_prefix, enc

    @classmethod
    def new(cls, recipients: Sequence[Recipient]) -> "ChunkSealer":
        if not recipients:
            raise ValueError("need at least one recipient")
        dek, object_id, nonce_prefix = os.urandom(32), os.urandom(16), os.urandom(16)
        wrapped = [_wrap_dek(dek, object_id, r) for r in recipients]
        return cls(dek, object_id, nonce_prefix, EncInfo(ALG, object_id.hex(), nonce_prefix.hex(), wrapped))

    @classmethod
    def reopen(cls, root: RootKey, enc: EncInfo) -> "ChunkSealer":
        """Continue sealing an object started earlier (resumed upload); needs the owner's key.
        Sealing the same plaintext at the same index reproduces the same ciphertext."""
        o = ChunkOpener(root, enc)
        return cls(o._dek, o._object_id, o._prefix, enc)

    def seal(self, idx: int, last: bool, plaintext: bytes) -> bytes:
        return _seal(self._dek, _chunk_nonce(self._prefix, idx), bytes(plaintext), _chunk_aad(self._object_id, idx, last))
