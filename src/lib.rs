//! PPoSE — Peer-to-Peer Obfuscated Stateless Exchange
//!
//! Reference implementation scaffold for the v1.2 specification.
//! See `docs/SPECIFICATION.md` for normative protocol detail.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod crypto;
pub mod identity;
pub mod network;
pub mod reliability;

/// Protocol version encoded in the packet header (`VER` field).
pub const PROTOCOL_VERSION: u8 = 0x02;

/// Magic bytes identifying PPoSE datagrams.
pub const MAGIC: [u8; 2] = [0x4A, 0x7F];

/// Hard internal MTU (bytes). Non-configurable per spec §5.1.
pub const INTERNAL_MTU: usize = 1200;

/// Default maximum source-routing hops.
pub const DEFAULT_MAX_HOPS: u8 = 3;

/// Absolute maximum source-routing hops.
pub const ABSOLUTE_MAX_HOPS: u8 = 5;

/// Crate version string.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_spec() {
        assert_eq!(PROTOCOL_VERSION, 0x02);
        assert_eq!(MAGIC, [0x4A, 0x7F]);
        assert_eq!(INTERNAL_MTU, 1200);
        const _: () = assert!(DEFAULT_MAX_HOPS <= ABSOLUTE_MAX_HOPS);
    }
}
