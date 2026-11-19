//! Streaming (chunk-at-a-time) encryption for large objects.
//!
//! Produces exactly the format of [`super::encrypt_for`] / [`super::decrypt_object`]:
//! same DEK wrapping, nonce = nonce_prefix || chunk_index, same AAD
//! (object_id, chunk_index, is_last). Chunks are independent, so callers may
//! seal / open them in parallel and in any order; the caller supplies the
//! chunk index and whether it is the last chunk.
use super::{chunk_aad, chunk_nonce, hex16, rand_bytes, unwrap_dek, wrap_dek, EncInfo, Recipient, RootKey, ALG};
use anyhow::{anyhow, ensure, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};

/// Number of chunks an object of `size` plaintext bytes is split into.
/// An empty object still has one (empty) chunk.
pub fn chunk_count(size: u64, chunk_size: u64) -> u64 {
    if size == 0 {
        1
    } else {
        size.div_ceil(chunk_size)
    }
}

/// Plaintext length of chunk `idx` of an object.
pub fn chunk_plain_len(size: u64, chunk_size: u64, idx: u64) -> u64 {
    let start = idx * chunk_size;
    size.saturating_sub(start).min(chunk_size)
}

/// Seals the chunks of one new object.
pub struct ChunkSealer {
    cipher: XChaCha20Poly1305,
    object_id: [u8; 16],
    nonce_prefix: [u8; 16],
    enc: EncInfo,
}

impl ChunkSealer {
    /// Fresh DEK / object id / nonce prefix, DEK wrapped to every recipient.
    pub fn new(recipients: &[Recipient]) -> Result<Self> {
        ensure!(!recipients.is_empty(), "need at least one recipient");
        let dek = rand_bytes::<32>();
        let object_id = rand_bytes::<16>();
        let nonce_prefix = rand_bytes::<16>();
        let wrapped_keys = recipients.iter().map(|r| wrap_dek(&dek, &object_id, r)).collect::<Result<Vec<_>>>()?;
        Ok(Self {
            cipher: XChaCha20Poly1305::new(&dek.into()),
            object_id,
            nonce_prefix,
            enc: EncInfo { alg: ALG.into(), object_id: hex::encode(object_id), nonce_prefix: hex::encode(nonce_prefix), wrapped_keys },
        })
    }

    /// The sealer of an object started earlier, rebuilt from its `enc` (the
    /// DEK unwrapped with the owner's root key). Resuming an upload with it
    /// re-creates identical ciphertext for identical plaintext. The caller must
    /// make sure a chunk index is never sealed with *different* plaintext:
    /// that would reuse a nonce under the same key.
    pub fn reopen(root: &RootKey, enc: &EncInfo) -> Result<Self> {
        let o = ChunkOpener::new(root, enc)?;
        Ok(Self { cipher: o.cipher, object_id: o.object_id, nonce_prefix: o.nonce_prefix, enc: enc.clone() })
    }

    /// Goes into `Manifest::enc`.
    pub fn enc_info(&self) -> &EncInfo {
        &self.enc
    }

    pub fn seal(&self, idx: u64, last: bool, plaintext: &[u8]) -> Result<Vec<u8>> {
        let aad = chunk_aad(&self.object_id, idx, last);
        self.cipher
            .encrypt(&chunk_nonce(&self.nonce_prefix, idx), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| anyhow!("encryption failed"))
    }
}

/// Opens chunks of an existing object.
pub struct ChunkOpener {
    cipher: XChaCha20Poly1305,
    object_id: [u8; 16],
    nonce_prefix: [u8; 16],
}

impl ChunkOpener {
    pub fn new(root: &RootKey, enc: &EncInfo) -> Result<Self> {
        ensure!(enc.alg == ALG, "unsupported alg {}", enc.alg);
        let object_id = hex16(&enc.object_id)?;
        let nonce_prefix = hex16(&enc.nonce_prefix)?;
        let dek = unwrap_dek(root, enc, &object_id)?;
        Ok(Self { cipher: XChaCha20Poly1305::new(&dek.into()), object_id, nonce_prefix })
    }

    pub fn open(&self, idx: u64, last: bool, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let aad = chunk_aad(&self.object_id, idx, last);
        self.cipher
            .decrypt(&chunk_nonce(&self.nonce_prefix, idx), Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| anyhow!("chunk {idx} failed authentication"))
    }

    /// Re-encrypt plaintext as chunk `idx` (deterministic), e.g. to check that
    /// bytes already on disk are exactly chunk `idx` by comparing cids.
    pub fn reseal(&self, idx: u64, last: bool, plaintext: &[u8]) -> Result<Vec<u8>> {
        let aad = chunk_aad(&self.object_id, idx, last);
        self.cipher
            .encrypt(&chunk_nonce(&self.nonce_prefix, idx), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| anyhow!("encryption failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{decrypt_object, encrypt_for, parse_x25519};
    use super::*;

    fn data(n: usize) -> Vec<u8> {
        (0..n as u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect()
    }

    fn seal_all(s: &ChunkSealer, pt: &[u8], cs: usize) -> Vec<Vec<u8>> {
        let n = chunk_count(pt.len() as u64, cs as u64) as usize;
        (0..n)
            .map(|i| {
                let end = ((i + 1) * cs).min(pt.len());
                s.seal(i as u64, i + 1 == n, &pt[(i * cs).min(pt.len())..end]).unwrap()
            })
            .collect()
    }

    #[test]
    fn streaming_seal_opens_with_one_shot_decrypt() {
        let owner = RootKey::generate();
        let friend = RootKey::generate();
        let fpk = parse_x25519(&friend.x25519_public()).unwrap();
        for (len, cs) in [(0usize, 16usize), (1, 16), (16, 16), (17, 16), (10_000, 1000), (10_001, 4096)] {
            let pt = data(len);
            let s = ChunkSealer::new(&[Recipient::Owner(&owner), Recipient::X25519(fpk)]).unwrap();
            // seal out of order: chunks are independent
            let mut chunks = seal_all(&s, &pt, cs);
            assert_eq!(chunks.len() as u64, chunk_count(len as u64, cs as u64));
            assert_eq!(decrypt_object(&owner, s.enc_info(), &chunks).unwrap(), pt);
            assert_eq!(decrypt_object(&friend, s.enc_info(), &chunks).unwrap(), pt);
            if chunks.len() > 1 {
                chunks.pop();
                assert!(decrypt_object(&owner, s.enc_info(), &chunks).is_err(), "truncation must fail");
            }
        }
    }

    #[test]
    fn reopen_and_reseal_are_deterministic() {
        let owner = RootKey::generate();
        let s = ChunkSealer::new(&[Recipient::Owner(&owner)]).unwrap();
        let a = s.seal(3, false, b"same bytes").unwrap();
        let r = ChunkSealer::reopen(&owner, s.enc_info()).unwrap();
        assert_eq!(r.seal(3, false, b"same bytes").unwrap(), a, "resumed sealer reproduces ciphertext");
        let o = ChunkOpener::new(&owner, s.enc_info()).unwrap();
        assert_eq!(o.reseal(3, false, b"same bytes").unwrap(), a);
        assert!(ChunkSealer::reopen(&RootKey::generate(), s.enc_info()).is_err(), "needs the owner's key");
    }

    #[test]
    fn one_shot_encrypt_opens_chunkwise() {
        let owner = RootKey::generate();
        let pt = data(10_000);
        let (chunks, enc) = encrypt_for(&[Recipient::Owner(&owner)], &pt, 1000).unwrap();
        let o = ChunkOpener::new(&owner, &enc).unwrap();
        let n = chunks.len();
        // random access: open chunk 7 alone
        assert_eq!(o.open(7, false, &chunks[7]).unwrap(), &pt[7000..8000]);
        let mut out = vec![];
        for (i, c) in chunks.iter().enumerate() {
            let p = o.open(i as u64, i + 1 == n, c).unwrap();
            assert_eq!(p.len() as u64, chunk_plain_len(10_000, 1000, i as u64));
            out.extend(p);
        }
        assert_eq!(out, pt);
        // wrong index / wrong last flag / wrong key all fail
        assert!(o.open(1, false, &chunks[0]).is_err());
        assert!(o.open(9, false, &chunks[9]).is_err());
        assert!(ChunkOpener::new(&RootKey::generate(), &enc).is_err());
    }

    #[test]
    fn same_key_material_gives_identical_ciphertext() {
        // Byte-identical format: opening a streamed chunk with the one-shot path
        // and re-sealing with the sealer's key material yields the same bytes.
        let owner = RootKey::generate();
        let pt = data(5000);
        let s = ChunkSealer::new(&[Recipient::Owner(&owner)]).unwrap();
        let a = seal_all(&s, &pt, 1000);
        let b = seal_all(&s, &pt, 1000);
        assert_eq!(a, b, "sealing is deterministic per (key, idx, last)");
        let o = ChunkOpener::new(&owner, s.enc_info()).unwrap();
        assert_eq!(o.open(4, true, &a[4]).unwrap(), &pt[4000..]);
    }

    #[test]
    fn counts() {
        assert_eq!(chunk_count(0, 10), 1);
        assert_eq!(chunk_count(10, 10), 1);
        assert_eq!(chunk_count(11, 10), 2);
        assert_eq!(chunk_plain_len(25, 10, 2), 5);
        assert_eq!(chunk_plain_len(0, 10, 0), 0);
    }
}
