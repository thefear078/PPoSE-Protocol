//! BLAKE3 helpers for identity hashing.

use blake3::Hasher;

/// Compute the 32-byte identity hash: `BLAKE3(identity_pubkey)`.
pub fn identity_hash(identity_pubkey: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(identity_pubkey);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_hash_is_32_bytes_and_deterministic() {
        let pk = [7u8; 32];
        let a = identity_hash(&pk);
        let b = identity_hash(&pk);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        assert_ne!(a, [0u8; 32]);
    }
}
