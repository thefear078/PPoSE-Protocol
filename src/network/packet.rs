//! Cleartext outer header encode/decode (8 bytes).

use crate::{MAGIC, OUTER_HEADER_LEN, PROTOCOL_VERSION};

/// Packet type discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// Noise handshake message.
    Handshake = 1,
    /// Encrypted application data (Noise transport).
    Data = 2,
    /// Acknowledgement (reserved for Phase 2).
    Ack = 3,
}

impl PacketType {
    /// Parse type byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Handshake),
            2 => Some(Self::Data),
            3 => Some(Self::Ack),
            _ => None,
        }
    }
}

/// Encode the 8-byte outer header.
pub fn encode_outer(ty: PacketType, flags: u8) -> [u8; OUTER_HEADER_LEN] {
    let mut out = [0u8; OUTER_HEADER_LEN];
    out[0] = MAGIC[0];
    out[1] = MAGIC[1];
    out[2] = PROTOCOL_VERSION;
    out[3] = ty as u8;
    out[4] = flags;
    // out[5..8] reserved zero
    out
}

/// Decode and validate outer header. Returns `(type, flags, body)`.
pub fn decode_outer(bytes: &[u8]) -> Result<(PacketType, u8, &[u8]), PacketError> {
    if bytes.len() < OUTER_HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    if bytes[0] != MAGIC[0] || bytes[1] != MAGIC[1] {
        return Err(PacketError::BadMagic);
    }
    if bytes[2] != PROTOCOL_VERSION {
        return Err(PacketError::BadVersion);
    }
    let ty = PacketType::from_u8(bytes[3]).ok_or(PacketError::BadType)?;
    let flags = bytes[4];
    Ok((ty, flags, &bytes[OUTER_HEADER_LEN..]))
}

/// Framing errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    /// Datagram shorter than outer header.
    Truncated,
    /// MAGIC mismatch.
    BadMagic,
    /// Unsupported VER.
    BadVersion,
    /// Unknown TYPE.
    BadType,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let hdr = encode_outer(PacketType::Data, 0);
        assert_eq!(hdr.len(), 8);
        let (ty, flags, body) = decode_outer(&hdr).unwrap();
        assert_eq!(ty, PacketType::Data);
        assert_eq!(flags, 0);
        assert!(body.is_empty());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut hdr = encode_outer(PacketType::Handshake, 0);
        hdr[0] ^= 0xff;
        assert_eq!(decode_outer(&hdr), Err(PacketError::BadMagic));
    }
}
