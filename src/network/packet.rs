//! Fixed packet header constants (spec §4.1).

use crate::{MAGIC, PROTOCOL_VERSION};

/// Fixed header length in bytes.
pub const HEADER_LEN: usize = 44;

/// Packet type discriminator (header TYP field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// Encrypted data datagram.
    Data = 0x01,
    /// Selective-repeat acknowledgement.
    Ack = 0x02,
    /// Cover / fake traffic.
    Cover = 0x03,
}

impl PacketType {
    /// Parse a raw type byte.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Data),
            0x02 => Some(Self::Ack),
            0x03 => Some(Self::Cover),
            _ => None,
        }
    }
}

/// Minimal header validation helper (magic + version).
pub fn header_magic_ok(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == MAGIC[0] && bytes[1] == MAGIC[1] && bytes[2] == PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAGIC;

    #[test]
    fn packet_type_roundtrip() {
        assert_eq!(PacketType::from_u8(0x02), Some(PacketType::Ack));
        assert_eq!(PacketType::from_u8(0xFF), None);
    }

    #[test]
    fn magic_check() {
        let mut buf = vec![0u8; HEADER_LEN];
        buf[0] = MAGIC[0];
        buf[1] = MAGIC[1];
        buf[2] = crate::PROTOCOL_VERSION;
        assert!(header_magic_ok(&buf));
    }
}
