"""NEAR-format ed25519 keys (``ed25519:<base58>``) and X25519 recipient keys (``x25519:<base58>``)."""
from __future__ import annotations

import base58
import nacl.exceptions
import nacl.signing


def _b58(s: str, n: int, what: str) -> bytes:
    try:
        b = base58.b58decode(s.encode("ascii"))
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"bad {what}: invalid base58") from e
    if len(b) != n:
        raise ValueError(f"bad {what}: expected {n} bytes, got {len(b)}")
    return b


def b58encode(b: bytes) -> str:
    return base58.b58encode(b).decode("ascii")


def parse_public_key(s: str) -> bytes:
    if not isinstance(s, str) or not s.startswith("ed25519:"):
        raise ValueError("only ed25519 keys are supported")
    return _b58(s[8:], 32, "public key")


def format_public_key(pk: bytes) -> str:
    return "ed25519:" + b58encode(pk)


def parse_secret_key(s: str) -> bytes:
    """NEAR secret keys are base58 of 64 bytes (seed || public key); 32-byte seeds are accepted. Returns the seed."""
    if not isinstance(s, str) or not s.startswith("ed25519:"):
        raise ValueError("only ed25519 keys are supported")
    try:
        b = base58.b58decode(s[8:].encode("ascii"))
    except Exception as e:  # noqa: BLE001
        raise ValueError("invalid base58 in secret key") from e
    if len(b) not in (32, 64):
        raise ValueError(f"secret key must be 32 or 64 bytes, got {len(b)}")
    seed = b[:32]
    if len(b) == 64 and bytes(nacl.signing.SigningKey(seed).verify_key) != b[32:]:
        raise ValueError("secret key does not match its embedded public key")
    return seed


def format_secret_key(seed: bytes) -> str:
    return "ed25519:" + b58encode(seed + bytes(nacl.signing.SigningKey(seed).verify_key))


def public_key_of(seed: bytes) -> str:
    return format_public_key(bytes(nacl.signing.SigningKey(seed).verify_key))


def generate_secret_key() -> str:
    return format_secret_key(bytes(nacl.signing.SigningKey.generate()))


def sign(seed: bytes, msg: bytes) -> str:
    """base58 ed25519 signature."""
    return b58encode(nacl.signing.SigningKey(seed).sign(msg).signature)


def verify(public_key: str, msg: bytes, sig_b58: str) -> bool:
    try:
        pk = parse_public_key(public_key)
        sig = _b58(sig_b58, 64, "signature")
        nacl.signing.VerifyKey(pk).verify(msg, sig)
        return True
    except (ValueError, TypeError, nacl.exceptions.BadSignatureError, nacl.exceptions.CryptoError):
        return False


def format_x25519(pk: bytes) -> str:
    return "x25519:" + b58encode(pk)


def parse_x25519(s: str) -> bytes:
    if not isinstance(s, str) or not s.startswith("x25519:"):
        raise ValueError("expected x25519:<base58>")
    return _b58(s[7:], 32, "x25519 key")
