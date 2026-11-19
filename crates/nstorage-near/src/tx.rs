//! Minimal NEAR transaction builder: borsh encoding of a `Transaction` (v0)
//! with `FunctionCall` / `Transfer` actions, ed25519-signed.
//!
//! Layout (nearcore `core/primitives/src/transaction.rs`):
//! ```text
//! Transaction  = signer_id: string, public_key: PublicKey, nonce: u64,
//!                receiver_id: string, block_hash: [u8; 32], actions: Vec<Action>
//! PublicKey    = 0u8 (ED25519) ++ [u8; 32]
//! Action       = 2u8 FunctionCall{method_name: string, args: Vec<u8>, gas: u64, deposit: u128}
//!              | 3u8 Transfer{deposit: u128}
//! SignedTx     = Transaction ++ Signature(0u8 ++ [u8; 64])
//! signature    = ed25519(sha256(borsh(Transaction)))
//! ```
//! borsh: integers little-endian; strings and vectors are u32 length + bytes.
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    FunctionCall { method_name: String, args: Vec<u8>, gas: u64, deposit: u128 },
    Transfer { deposit: u128 },
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub signer_id: String,
    pub public_key: [u8; 32],
    pub nonce: u64,
    pub receiver_id: String,
    pub block_hash: [u8; 32],
    pub actions: Vec<Action>,
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

impl Transaction {
    pub fn to_borsh(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(256);
        put_bytes(&mut o, self.signer_id.as_bytes());
        o.push(0);
        o.extend_from_slice(&self.public_key);
        o.extend_from_slice(&self.nonce.to_le_bytes());
        put_bytes(&mut o, self.receiver_id.as_bytes());
        o.extend_from_slice(&self.block_hash);
        o.extend_from_slice(&(self.actions.len() as u32).to_le_bytes());
        for a in &self.actions {
            match a {
                Action::FunctionCall { method_name, args, gas, deposit } => {
                    o.push(2);
                    put_bytes(&mut o, method_name.as_bytes());
                    put_bytes(&mut o, args);
                    o.extend_from_slice(&gas.to_le_bytes());
                    o.extend_from_slice(&deposit.to_le_bytes());
                }
                Action::Transfer { deposit } => {
                    o.push(3);
                    o.extend_from_slice(&deposit.to_le_bytes());
                }
            }
        }
        o
    }

    /// sha256 of the borsh encoding: the transaction hash.
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.to_borsh()).into()
    }

    /// Borsh-encoded `SignedTransaction`.
    pub fn sign(&self, sk: &SigningKey) -> Vec<u8> {
        let mut o = self.to_borsh();
        let sig = sk.sign(&Sha256::digest(&o));
        o.push(0);
        o.extend_from_slice(&sig.to_bytes());
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    #[test]
    fn layout() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let tx = Transaction {
            signer_id: "ab".into(),
            public_key: sk.verifying_key().to_bytes(),
            nonce: 5,
            receiver_id: "cd".into(),
            block_hash: [9u8; 32],
            actions: vec![
                Action::FunctionCall { method_name: "m".into(), args: b"{}".to_vec(), gas: 7, deposit: 1 },
                Action::Transfer { deposit: 2 },
            ],
        };
        let b = tx.to_borsh();
        let mut want = vec![2, 0, 0, 0, b'a', b'b', 0];
        want.extend_from_slice(&tx.public_key);
        want.extend_from_slice(&5u64.to_le_bytes());
        want.extend_from_slice(&[2, 0, 0, 0, b'c', b'd']);
        want.extend_from_slice(&[9u8; 32]);
        want.extend_from_slice(&[2, 0, 0, 0]);
        want.extend_from_slice(&[2, 1, 0, 0, 0, b'm', 2, 0, 0, 0, b'{', b'}']);
        want.extend_from_slice(&7u64.to_le_bytes());
        want.extend_from_slice(&1u128.to_le_bytes());
        want.push(3);
        want.extend_from_slice(&2u128.to_le_bytes());
        assert_eq!(b, want);

        let signed = tx.sign(&sk);
        assert_eq!(&signed[..b.len()], &b[..]);
        assert_eq!(signed[b.len()], 0);
        let sig = Signature::from_bytes(signed[b.len() + 1..].try_into().unwrap());
        sk.verifying_key().verify(&tx.hash(), &sig).unwrap();
    }
}
