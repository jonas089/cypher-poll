pub mod gpg;
pub mod identity;

use sha2::{Sha256, Digest};

pub fn default_hash_sha256<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
