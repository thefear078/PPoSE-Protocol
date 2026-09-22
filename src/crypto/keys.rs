//! Long-term X25519 identity material (Noise static keys).

use blake3::Hasher;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

/// Secret identity (X25519 static).
#[derive(Clone)]
pub struct IdentitySecret {
    secret: StaticSecret,
}

impl IdentitySecret {
    /// Generate a fresh identity.
    pub fn generate() -> Self {
        Self {
            secret: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// Construct from raw 32-byte seed/secret.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    /// Raw secret bytes (handle with care).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Corresponding public identity.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            public: PublicKey::from(&self.secret),
        }
    }
}

/// Public identity (X25519).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    public: PublicKey,
}

impl PublicIdentity {
    /// From raw 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            public: PublicKey::from(bytes),
        }
    }

    /// Raw public key bytes.
    pub fn as_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// BLAKE3 fingerprint for *local* display / logs — never put on the wire in cleartext.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(self.public.as_bytes());
        *hasher.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_fingerprint_stable() {
        let sk = IdentitySecret::from_bytes([7u8; 32]);
        let pk = sk.public();
        assert_eq!(pk.fingerprint(), pk.fingerprint());
        assert_ne!(pk.fingerprint(), [0u8; 32]);
    }
}
