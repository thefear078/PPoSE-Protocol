//! Standalone XChaCha20-Poly1305 helpers (optional; Phase 1 sessions use Noise transport).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use thiserror::Error;

/// AEAD errors.
#[derive(Debug, Error)]
pub enum AeadError {
    /// Encryption failure.
    #[error("encrypt failed")]
    Encrypt,
    /// Decryption / auth failure.
    #[error("decrypt failed")]
    Decrypt,
    /// Nonce must be 24 bytes.
    #[error("invalid nonce length")]
    Nonce,
}

/// Directional session AEAD keyed independently of Noise (for future non-Noise frames).
pub struct SessionAead {
    cipher: XChaCha20Poly1305,
}

impl SessionAead {
    /// Create from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(key.into()),
        }
    }

    /// Seal plaintext with AAD.
    pub fn seal(
        &self,
        nonce24: &[u8; 24],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let nonce = XNonce::from_slice(nonce24);
        self.cipher
            .encrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| AeadError::Encrypt)
    }

    /// Open ciphertext with AAD.
    pub fn open(
        &self,
        nonce24: &[u8; 24],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let nonce = XNonce::from_slice(nonce24);
        self.cipher
            .decrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| AeadError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let aead = SessionAead::new(&[9u8; 32]);
        let nonce = [1u8; 24];
        let aad = b"header";
        let ct = aead.seal(&nonce, aad, b"hello").unwrap();
        let pt = aead.open(&nonce, aad, &ct).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn aad_mismatch_fails() {
        let aead = SessionAead::new(&[9u8; 32]);
        let nonce = [1u8; 24];
        let ct = aead.seal(&nonce, b"a", b"hello").unwrap();
        assert!(aead.open(&nonce, b"b", &ct).is_err());
    }
}
