//! Chunked envelope encryption.
//!
//! - per-object random DEK (256-bit), chunks sealed with XChaCha20-Poly1305;
//!   nonce = nonce_prefix(16) || chunk_index(u64 BE); AAD binds object_id,
//!   chunk index and a last-chunk flag (prevents reorder / truncation).
//! - DEK wrapped per recipient:
//!   * `kek:<kek_id>`: owner, XChaCha20-Poly1305 under HKDF(root, kek);
//!   * `x25519:<base58 pk>`: anyone with a published X25519 key (sharing,
//!     app-writes-for-user). Ephemeral-static DH, key = HKDF-SHA256(
//!     salt="nstorage", ikm=shared, info="nstorage/v1/wrap-x25519"||epk||pk),
//!     DEK sealed with XChaCha20-Poly1305, AAD = object_id.
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
    /// X25519 secret used to receive shared objects.
    pub fn x25519_secret(&self) -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::from(self.derive("nstorage/v1/x25519"))
    }
    /// Public half, published (e.g. in `storage.near`) as `x25519:<base58>`.
    pub fn x25519_public(&self) -> String {
        format_x25519(&x25519_dalek::PublicKey::from(&self.x25519_secret()))
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
    /// `kek:<kek_id>` for the owner or `x25519:<base58 pk>` for others.
    pub recipient: String,
    /// Ephemeral X25519 public key (base58), x25519 recipients only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epk: Option<String>,
    pub nonce: String,
    pub ct: String,
}

pub fn format_x25519(pk: &x25519_dalek::PublicKey) -> String {
    format!("x25519:{}", bs58::encode(pk.as_bytes()).into_string())
}

pub fn parse_x25519(s: &str) -> Result<x25519_dalek::PublicKey> {
    let b = s.strip_prefix("x25519:").ok_or_else(|| anyhow!("expected x25519:<base58>"))?;
    let bytes: [u8; 32] = bs58::decode(b).into_vec()?.try_into().map_err(|_| anyhow!("x25519 key must be 32 bytes"))?;
    Ok(x25519_dalek::PublicKey::from(bytes))
}

fn x25519_wrap_key(shared: &[u8; 32], epk: &[u8; 32], pk: &[u8; 32]) -> [u8; 32] {
    let mut info = b"nstorage/v1/wrap-x25519".to_vec();
    info.extend_from_slice(epk);
    info.extend_from_slice(pk);
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(b"nstorage"), shared).expand(&info, &mut out).expect("valid length");
    out
}

fn seal(key: &[u8; 32], nonce: &[u8; 24], msg: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(nonce), Payload { msg, aad })
        .map_err(|_| anyhow!("seal failed"))
}

fn open(key: &[u8; 32], nonce: &[u8; 24], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| anyhow!("open failed"))
}

/// Who an object key is wrapped to.
pub enum Recipient<'a> {
    Owner(&'a RootKey),
    X25519(x25519_dalek::PublicKey),
}

fn wrap_dek(dek: &[u8; 32], object_id: &[u8; 16], r: &Recipient) -> Result<WrappedKey> {
    let nonce = rand_bytes::<24>();
    match r {
        Recipient::Owner(root) => Ok(WrappedKey {
            recipient: format!("kek:{}", root.kek_id()),
            epk: None,
            nonce: B64.encode(nonce),
            ct: B64.encode(seal(&root.kek(), &nonce, dek, object_id)?),
        }),
        Recipient::X25519(pk) => {
            let esk = x25519_dalek::StaticSecret::from(rand_bytes::<32>());
            let epk = x25519_dalek::PublicKey::from(&esk);
            let shared = esk.diffie_hellman(pk);
            if !shared.was_contributory() {
                bail!("invalid recipient key");
            }
            let k = x25519_wrap_key(shared.as_bytes(), epk.as_bytes(), pk.as_bytes());
            Ok(WrappedKey {
                recipient: format_x25519(pk),
                epk: Some(bs58::encode(epk.as_bytes()).into_string()),
                nonce: B64.encode(nonce),
                ct: B64.encode(seal(&k, &nonce, dek, object_id)?),
            })
        }
    }
}

/// Recover the object DEK using whichever wrapped key belongs to `root`.
fn unwrap_dek(root: &RootKey, enc: &EncInfo, object_id: &[u8; 16]) -> Result<[u8; 32]> {
    let kek_name = format!("kek:{}", root.kek_id());
    let x_name = root.x25519_public();
    let wk = enc
        .wrapped_keys
        .iter()
        .find(|w| w.recipient == kek_name || w.recipient == x_name)
        .ok_or_else(|| anyhow!("object is not encrypted to this account's keys ({kek_name}, {x_name})"))?;
    let nonce: [u8; 24] = B64.decode(&wk.nonce)?.try_into().map_err(|_| anyhow!("bad wrap nonce"))?;
    let ct = B64.decode(&wk.ct)?;
    let dek = if wk.recipient == kek_name {
        open(&root.kek(), &nonce, &ct, object_id)
    } else {
        let epk: [u8; 32] = bs58::decode(wk.epk.as_deref().ok_or_else(|| anyhow!("missing epk"))?)
            .into_vec()?
            .try_into()
            .map_err(|_| anyhow!("bad epk"))?;
        let sk = root.x25519_secret();
        let pk = x25519_dalek::PublicKey::from(&sk);
        let shared = sk.diffie_hellman(&x25519_dalek::PublicKey::from(epk));
        open(&x25519_wrap_key(shared.as_bytes(), &epk, pk.as_bytes()), &nonce, &ct, object_id)
    }
    .map_err(|_| anyhow!("cannot unwrap object key (wrong root key?)"))?;
    dek.try_into().map_err(|_| anyhow!("bad DEK length"))
}

/// Give another recipient access to an existing object: same chunks, one more
/// wrapped key. Caller must be able to unwrap the DEK.
pub fn add_recipient(root: &RootKey, enc: &EncInfo, r: &Recipient) -> Result<EncInfo> {
    let object_id = hex16(&enc.object_id)?;
    let dek = unwrap_dek(root, enc, &object_id)?;
    let new = wrap_dek(&dek, &object_id, r)?;
    let mut out = enc.clone();
    out.wrapped_keys.retain(|w| w.recipient != new.recipient);
    out.wrapped_keys.push(new);
    Ok(out)
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
/// Encrypt `plaintext` for the owner `root`.
pub fn encrypt_object(root: &RootKey, plaintext: &[u8], chunk_size: usize) -> Result<(Vec<Vec<u8>>, EncInfo)> {
    encrypt_for(&[Recipient::Owner(root)], plaintext, chunk_size)
}

/// Encrypt `plaintext` for an explicit recipient set (at least one).
pub fn encrypt_for(recipients: &[Recipient], plaintext: &[u8], chunk_size: usize) -> Result<(Vec<Vec<u8>>, EncInfo)> {
    ensure!(chunk_size > 0, "chunk_size must be > 0");
    ensure!(!recipients.is_empty(), "need at least one recipient");
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

    let wrapped_keys = recipients.iter().map(|r| wrap_dek(&dek, &object_id, r)).collect::<Result<Vec<_>>>()?;
    Ok((
        chunks,
        EncInfo { alg: ALG.into(), object_id: hex::encode(object_id), nonce_prefix: hex::encode(nonce_prefix), wrapped_keys },
    ))
}

pub fn decrypt_object(root: &RootKey, enc: &EncInfo, chunks: &[Vec<u8>]) -> Result<Vec<u8>> {
    ensure!(enc.alg == ALG, "unsupported alg {}", enc.alg);
    ensure!(!chunks.is_empty(), "object has no chunks");
    let object_id = hex16(&enc.object_id)?;
    let nonce_prefix = hex16(&enc.nonce_prefix)?;
    let dek = unwrap_dek(root, enc, &object_id)?;
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
    fn sharing() {
        let owner = RootKey::generate();
        let friend = RootKey::generate();
        let stranger = RootKey::generate();
        let fpk = parse_x25519(&friend.x25519_public()).unwrap();
        let (chunks, enc) = encrypt_for(&[Recipient::Owner(&owner), Recipient::X25519(fpk)], b"hello", 4).unwrap();
        assert_eq!(decrypt_object(&owner, &enc, &chunks).unwrap(), b"hello");
        assert_eq!(decrypt_object(&friend, &enc, &chunks).unwrap(), b"hello");
        assert!(decrypt_object(&stranger, &enc, &chunks).is_err());
        // share after the fact
        let spk = parse_x25519(&stranger.x25519_public()).unwrap();
        let enc2 = add_recipient(&owner, &enc, &Recipient::X25519(spk)).unwrap();
        assert_eq!(decrypt_object(&stranger, &enc2, &chunks).unwrap(), b"hello");
        // app writes for a user it cannot read
        let upk = parse_x25519(&friend.x25519_public()).unwrap();
        let (c, e) = encrypt_for(&[Recipient::X25519(upk)], b"for you", 1024).unwrap();
        assert_eq!(decrypt_object(&friend, &e, &c).unwrap(), b"for you");
        assert!(decrypt_object(&owner, &e, &c).is_err());
    }

    #[test]
    fn empty_object() {
        let root = RootKey::generate();
        let (chunks, enc) = encrypt_object(&root, b"", 1024).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(decrypt_object(&root, &enc, &chunks).unwrap(), b"");
    }
}
