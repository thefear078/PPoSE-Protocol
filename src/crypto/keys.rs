//! Identity key material placeholders (Ed25519 integration lands in Phase 1).

/// Placeholder identity keypair until Ed25519 wiring is complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityKeyPair {
    /// Public key bytes (32).
    pub public: [u8; 32],
    /// Secret key bytes (32) — never log or serialize in cleartext in production paths.
    pub secret: [u8; 32],
}

impl IdentityKeyPair {
    /// Create a non-cryptographic placeholder pair for scaffolding / tests only.
    pub fn placeholder_from_seed(seed: u8) -> Self {
        Self {
            public: [seed; 32],
            secret: [seed.wrapping_add(1); 32],
        }
    }
}
