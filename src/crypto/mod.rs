//! Cryptographic primitives (Layer 5).
//!
//! Mandatory algorithms: Ed25519, X25519, XChaCha20-Poly1305, BLAKE3, HKDF-SHA256, Noise XX.

pub mod blake3_hash;
pub mod keys;

pub use blake3_hash::identity_hash;
pub use keys::IdentityKeyPair;
