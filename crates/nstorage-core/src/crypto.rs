//! Chunked envelope encryption.
//!
//! - per-object random DEK (256-bit), chunks sealed with XChaCha20-Poly1305;
//!   nonce = nonce_prefix(16) || chunk_index(u64 BE); AAD binds object_id,
//!   chunk index and a last-chunk flag (prevents reorder / truncation).
//! - DEK wrapped per recipient. v0 recipient kind: `kek` (owner's key derived
//!   from the account root key). HPKE-to-X25519 recipients land with sharing.
use anyhow::{anyhow, bail, ensure, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub const ALG: &str = "xchacha20poly1305-chunked-v1";
pub const TAG_LEN: usize = 16;

/// Account root key. v0: generated locally; later obtained via NEAR MPC CKD.
pub struct RootKey([u8; 32]);

impl RootKey {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        Self(k)
    }
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    fn derive(&self, info: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(Some(b"nstorage"), &self.0)
            .expand(info.as_bytes(), &mut out)
            .expect("32 bytes is a valid HKDF length");
        out
    }
    pub fn kek(&self) -> [u8; 32] {
        self.derive("nstorage/v1/kek")
    }
    /// Short public fingerprint of the KEK so readers can pick the right key.
    pub fn kek_id(&self) -> String {
        hex::encode(&blake3::hash(&self.derive("nstorage/v1/kek-id")).as_bytes()[..8])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WrappedKey {
    /// `kek:<kek_id>` for the owner.
    pub recipient: String,
    pub nonce: String,
    pub ct: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncInfo {
    pub alg: String,
    pub object_id: String,
    pub nonce_prefix: String,
    pub wrapped_keys: Vec<WrappedKey>,
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

fn chunk_nonce(prefix: &[u8; 16], idx: u64) -> XNonce {
    let mut n = [0u8; 24];
    n[..16].copy_from_slice(prefix);
    n[16..].copy_from_slice(&idx.to_be_bytes());
    XNonce::from(n)
}

fn chunk_aad(object_id: &[u8; 16], idx: u64, last: bool) -> Vec<u8> {
    let mut a = b"nstorage-chunk-v1".to_vec();
    a.extend_from_slice(object_id);
    a.extend_from_slice(&idx.to_be_bytes());
    a.push(last as u8);
    a
}

fn hex16(s: &str) -> Result<[u8; 16]> {
    hex::decode(s)?.try_into().map_err(|_| anyhow!("expected 16 bytes"))
}

/// Encrypt `plaintext` into chunks of at most `chunk_size` plaintext bytes.
/// An empty object yields one empty (tag-only) chunk so truncation is detectable.
pub fn encrypt_object(root: &RootKey, plaintext: &[u8], chunk_size: usize) -> Result<(Vec<Vec<u8>>, EncInfo)> {
    ensure!(chunk_size > 0, "chunk_size must be > 0");
    let dek = rand_bytes::<32>();
    let object_id = rand_bytes::<16>();
    let nonce_prefix = rand_bytes::<16>();
    let cipher = XChaCha20Poly1305::new(&dek.into());

    let pieces: Vec<&[u8]> = if plaintext.is_empty() { vec![&[][..]] } else { plaintext.chunks(chunk_size).collect() };
    let n = pieces.len();
    let mut chunks = Vec::with_capacity(n);
    for (i, p) in pieces.into_iter().enumerate() {
        let aad = chunk_aad(&object_id, i as u64, i + 1 == n);
        let ct = cipher
            .encrypt(&chunk_nonce(&nonce_prefix, i as u64), Payload { msg: p, aad: &aad })
            .map_err(|_| anyhow!("encryption failed"))?;
        chunks.push(ct);
    }

    let wrap_nonce = rand_bytes::<24>();
    let kek_cipher = XChaCha20Poly1305::new(&root.kek().into());
    let wrapped = kek_cipher
        .encrypt(XNonce::from_slice(&wrap_nonce), Payload { msg: &dek, aad: &object_id })
        .map_err(|_| anyhow!("wrap failed"))?;

    Ok((
        chunks,
        EncInfo {
            alg: ALG.into(),
            object_id: hex::encode(object_id),
            nonce_prefix: hex::encode(nonce_prefix),
            wrapped_keys: vec![WrappedKey {
                recipient: format!("kek:{}", root.kek_id()),
                nonce: B64.encode(wrap_nonce),
                ct: B64.encode(wrapped),
            }],
        },
    ))
}

pub fn decrypt_object(root: &RootKey, enc: &EncInfo, chunks: &[Vec<u8>]) -> Result<Vec<u8>> {
    ensure!(enc.alg == ALG, "unsupported alg {}", enc.alg);
    ensure!(!chunks.is_empty(), "object has no chunks");
    let object_id = hex16(&enc.object_id)?;
    let nonce_prefix = hex16(&enc.nonce_prefix)?;
    let me = format!("kek:{}", root.kek_id());
    let wk = enc
        .wrapped_keys
        .iter()
        .find(|w| w.recipient == me)
        .ok_or_else(|| anyhow!("object is not encrypted to this account's key ({me})"))?;
    let wrap_nonce: [u8; 24] = B64.decode(&wk.nonce)?.try_into().map_err(|_| anyhow!("bad wrap nonce"))?;
    let dek: [u8; 32] = XChaCha20Poly1305::new(&root.kek().into())
        .decrypt(XNonce::from_slice(&wrap_nonce), Payload { msg: &B64.decode(&wk.ct)?, aad: &object_id })
        .map_err(|_| anyhow!("cannot unwrap object key (wrong root key?)"))?
        .try_into()
        .map_err(|_| anyhow!("bad DEK length"))?;
    let cipher = XChaCha20Poly1305::new(&dek.into());
    let n = chunks.len();
    let mut out = Vec::new();
    for (i, c) in chunks.iter().enumerate() {
        let aad = chunk_aad(&object_id, i as u64, i + 1 == n);
        let p = cipher
            .decrypt(&chunk_nonce(&nonce_prefix, i as u64), Payload { msg: c, aad: &aad })
            .map_err(|_| anyhow!("chunk {i} failed authentication"))?;
        out.extend_from_slice(&p);
    }
    Ok(out)
}

pub fn plaintext_chunks(plaintext: &[u8], chunk_size: usize) -> Result<Vec<Vec<u8>>> {
    if chunk_size == 0 {
        bail!("chunk_size must be > 0");
    }
    Ok(if plaintext.is_empty() { vec![vec![]] } else { plaintext.chunks(chunk_size).map(<[u8]>::to_vec).collect() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let root = RootKey::generate();
        let data: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        let (chunks, enc) = encrypt_object(&root, &data, 4096).unwrap();
        assert_eq!(chunks.len(), 3);
        assert_eq!(decrypt_object(&root, &enc, &chunks).unwrap(), data);

        // truncation: drop last chunk -> new last chunk fails AAD
        assert!(decrypt_object(&root, &enc, &chunks[..2]).is_err());
        // reorder
        let mut r = chunks.clone();
        r.swap(0, 1);
        assert!(decrypt_object(&root, &enc, &r).is_err());
        // bit flip
        let mut f = chunks.clone();
        f[1][5] ^= 1;
        assert!(decrypt_object(&root, &enc, &f).is_err());
        // wrong key
        assert!(decrypt_object(&RootKey::generate(), &enc, &chunks).is_err());
    }

    #[test]
    fn empty_object() {
        let root = RootKey::generate();
        let (chunks, enc) = encrypt_object(&root, b"", 1024).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(decrypt_object(&root, &enc, &chunks).unwrap(), b"");
    }
}
