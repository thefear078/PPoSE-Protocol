//! PPoSE — Peer-to-Peer Obfuscated Stateless Exchange
//!
//! Research prototype. See `docs/THREAT_MODEL.md` before making security claims.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod admission;
pub mod config;
pub mod cover;
pub mod crypto;
pub mod network;
pub mod onion;
pub mod relay;
pub mod reliability;
pub mod rendezvous;
pub mod session;

/// Wire version byte (`VER` field). v0.3 uses `0x03` (same envelope as 0.2).
pub const PROTOCOL_VERSION: u8 = 0x03;

/// Magic bytes identifying PPoSE datagrams.
pub const MAGIC: [u8; 2] = [0x4A, 0x7F];

/// Cleartext outer header length (bytes).
pub const OUTER_HEADER_LEN: usize = 8;

/// Soft maximum UDP datagram size.
pub const MAX_DATAGRAM: usize = 1200;

/// Crate version string.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Noise protocol string pinned for interop (authoritative).
pub const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_spec() {
        assert_eq!(PROTOCOL_VERSION, 0x03);
        assert_eq!(MAGIC, [0x4A, 0x7F]);
        assert_eq!(OUTER_HEADER_LEN, 8);
        assert!(!NOISE_PARAMS.is_empty());
    }
}
