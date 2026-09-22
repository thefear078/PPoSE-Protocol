//! Identity, invitation Web-of-Trust, and reputation (L3).

use crate::crypto::identity_hash;

/// Opaque 32-byte node identity derived from a public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Derive a node id from an identity public key.
    pub fn from_pubkey(pubkey: &[u8]) -> Self {
        Self(identity_hash(pubkey))
    }
}

/// Admission tier in the invitation Web-of-Trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustTier {
    /// Hardcoded bootstrap admins.
    BootstrapAdmin,
    /// Relay operators.
    RelayOperator,
    /// Clients without relay duties.
    Client,
}

impl TrustTier {
    /// Exhaustive helper for future extensions.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BootstrapAdmin => "bootstrap_admin",
            Self::RelayOperator => "relay_operator",
            Self::Client => "client",
        }
    }
}
