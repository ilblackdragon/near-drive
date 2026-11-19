//! NEAR Drive core: addressing, chunked envelope encryption, manifests,
//! signed pointer records and request authentication. No I/O.

pub mod auth;
pub mod crypto;
pub mod keys;
pub mod manifest;
pub mod policy;
pub mod record;
pub mod uri;

pub use uri::NearUri;

/// Content id of a chunk: `b3:` + hex(blake3(bytes)).
pub fn cid(bytes: &[u8]) -> String {
    format!("b3:{}", blake3::hash(bytes).to_hex())
}

pub fn is_valid_cid(s: &str) -> bool {
    s.len() == 67 && s.starts_with("b3:") && s[3..].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
