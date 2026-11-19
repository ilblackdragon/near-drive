use crate::crypto::EncInfo;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChunkRef {
    pub cid: String,
    /// Stored (ciphertext) length in bytes.
    pub len: u64,
}

/// Immutable object manifest, itself stored as a content-addressed chunk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub version: u32,
    /// Plaintext size in bytes.
    pub size: u64,
    pub chunk_size: u64,
    pub chunks: Vec<ChunkRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc: Option<EncInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

pub const MAX_CHUNK_BYTES: u64 = 64 * 1024 * 1024;

impl Manifest {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("manifest serializes")
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let m: Manifest = serde_json::from_slice(b)?;
        m.validate()?;
        Ok(m)
    }

    pub fn stored_size(&self) -> u64 {
        self.chunks.iter().map(|c| c.len).sum()
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported manifest version");
        ensure!(!self.chunks.is_empty(), "manifest has no chunks");
        ensure!(self.chunk_size > 0 && self.chunk_size <= MAX_CHUNK_BYTES, "bad chunk_size");
        for c in &self.chunks {
            ensure!(crate::is_valid_cid(&c.cid), "bad cid {}", c.cid);
            ensure!(c.len <= MAX_CHUNK_BYTES + 64, "chunk too large");
        }
        let overhead = if self.enc.is_some() { crate::crypto::TAG_LEN as u64 } else { 0 };
        let expected: u64 = self.size + overhead * self.chunks.len() as u64;
        ensure!(self.stored_size() == expected, "chunk lengths do not add up to size");
        Ok(())
    }
}
