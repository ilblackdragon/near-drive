"""nstorage: NEAR-account-addressed, end-to-end-encrypted object storage."""
from .auth import canonical_request
from .client import DEFAULT_CHUNK_SIZE, Client, GatewayError, KeySigner, ListEntry, ObjectHead, Signer, verify_head
from .crypto import ALG, TAG_LEN, EncInfo, RootKey, WrappedKey, add_recipient, decrypt_object, encrypt_for, encrypt_object, plaintext_chunks
from .keys import format_public_key, format_secret_key, format_x25519, generate_secret_key, parse_public_key, parse_secret_key, parse_x25519, public_key_of, sign, verify
from .manifest import MAX_CHUNK_BYTES, ChunkRef, Manifest, PointerRecord, cid, is_valid_cid
from .uri import NearUri, UriError, encode_path, is_valid_account_id, validate_account_id, validate_path
from .files import default_credentials_path, default_root_key_path, generate_root_key_file, load_credentials, load_root_key

__version__ = "0.1.0"

__all__ = [
    "ALG", "TAG_LEN", "DEFAULT_CHUNK_SIZE", "MAX_CHUNK_BYTES",
    "Client", "GatewayError", "KeySigner", "ListEntry", "ObjectHead", "Signer", "verify_head",
    "EncInfo", "RootKey", "WrappedKey", "add_recipient", "decrypt_object", "encrypt_for", "encrypt_object", "plaintext_chunks",
    "format_public_key", "format_secret_key", "format_x25519", "generate_secret_key", "parse_public_key", "parse_secret_key",
    "parse_x25519", "public_key_of", "sign", "verify",
    "ChunkRef", "Manifest", "PointerRecord", "cid", "is_valid_cid", "canonical_request",
    "NearUri", "UriError", "encode_path", "is_valid_account_id", "validate_account_id", "validate_path",
    "default_credentials_path", "default_root_key_path", "generate_root_key_file", "load_credentials", "load_root_key",
]
