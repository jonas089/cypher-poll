pub mod gpg;
pub mod identity;

use sha2::{Digest, Sha256};

pub trait CryptoHasher {
    fn hash(&self, data: &[u8]) -> Vec<u8>;
    fn hash_left_right(&self, left: &mut Vec<u8>, right: &mut Vec<u8>) -> Vec<u8>;
}

pub struct CryptoHasherSha256;
impl CryptoHasher for CryptoHasherSha256 {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
    fn hash_left_right(&self, left: &mut Vec<u8>, right: &mut Vec<u8>) -> Vec<u8> {
        left.append(right);
        self.hash(left)
    }
}

pub fn hash<H: CryptoHasher>(hasher: H, data: &[u8]) -> Vec<u8> {
    hasher.hash(data)
}

pub fn hash_left_right<H: CryptoHasher>(
    hasher: H,
    left: &mut Vec<u8>,
    right: &mut Vec<u8>,
) -> Vec<u8> {
    hasher.hash_left_right(left, right)
}
