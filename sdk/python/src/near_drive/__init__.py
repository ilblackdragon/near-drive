"""near-drive: NEAR-account-addressed, end-to-end-encrypted object storage."""
from .auth import canonical_request
from .chain import SIGN_KEY_SKEW_MS, SignKeyEntry, StorageContract, WriterCheck, sign_key_in_force
from .policy import Access, Rule, resolve as resolve_policy
from .client import CLASS_HEADER, DEFAULT_CHUNK_SIZE, DEFAULT_CONTRACT, DEFAULT_PARALLELISM, Client, Conflict, GatewayError, KeySigner, ListEntry, ListPage, Located, LocatedChunk, ObjectHead, Signer, TransferInterrupted, verify_head
from .net import NetConfig
from .crypto import ALG, TAG_LEN, ChunkOpener, ChunkSealer, EncInfo, chunk_count, chunk_plain_len, RootKey, WrappedKey, add_recipient, decrypt_object, encrypt_for, encrypt_object, plaintext_chunks
from .keys import format_public_key, format_secret_key, format_x25519, generate_secret_key, parse_public_key, parse_secret_key, parse_x25519, public_key_of, sign, verify
from .manifest import MAX_CHUNK_BYTES, ChunkRef, Manifest, PointerRecord, cid, is_valid_cid
from .uri import NearUri, UriError, encode_path, is_valid_account_id, validate_account_id, validate_path
from .files import default_credentials_path, default_root_key_path, generate_root_key_file, load_credentials, load_root_key

__version__ = "0.1.0"

__all__ = [
    "ALG", "TAG_LEN", "CLASS_HEADER", "DEFAULT_CHUNK_SIZE", "DEFAULT_PARALLELISM", "MAX_CHUNK_BYTES",
    "Client", "Conflict", "GatewayError", "KeySigner", "ListEntry", "ListPage", "Located", "LocatedChunk", "NetConfig", "ObjectHead", "Signer",
    "TransferInterrupted", "verify_head", "DEFAULT_CONTRACT",
    "SIGN_KEY_SKEW_MS", "SignKeyEntry", "StorageContract", "WriterCheck", "sign_key_in_force", "Access", "Rule", "resolve_policy",
    "ChunkOpener", "ChunkSealer", "chunk_count", "chunk_plain_len", "EncInfo", "RootKey", "WrappedKey", "add_recipient", "decrypt_object", "encrypt_for", "encrypt_object", "plaintext_chunks",
    "format_public_key", "format_secret_key", "format_x25519", "generate_secret_key", "parse_public_key", "parse_secret_key",
    "parse_x25519", "public_key_of", "sign", "verify",
    "ChunkRef", "Manifest", "PointerRecord", "cid", "is_valid_cid", "canonical_request",
    "NearUri", "UriError", "encode_path", "is_valid_account_id", "validate_account_id", "validate_path",
    "default_credentials_path", "default_root_key_path", "generate_root_key_file", "load_credentials", "load_root_key",
]
