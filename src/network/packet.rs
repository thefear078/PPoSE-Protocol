//! Cleartext outer header encode/decode (8 bytes).

use crate::{MAGIC, MAX_DATAGRAM, OUTER_HEADER_LEN, PROTOCOL_VERSION};

/// Packet type discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// Noise handshake message.
    Handshake = 1,
    /// Encrypted application / ACK (Noise transport).
    Data = 2,
    /// Unused (inner ACK rides in Data). Kept for decode completeness.
    Ack = 3,
    /// Cleartext IPv4 forward wrapper. Relay sees destination. Not onion routing.
    Forward = 4,
    /// Nested AEAD hop (PND). Not Sphinx.
    Onion = 5,
    /// Rendezvous register / lookup.
    Rendezvous = 6,
}

impl PacketType {
    /// Parse type byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Handshake),
            2 => Some(Self::Data),
            3 => Some(Self::Ack),
            4 => Some(Self::Forward),
            5 => Some(Self::Onion),
            6 => Some(Self::Rendezvous),
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
    out
}

/// Full datagram: outer header + body.
pub fn encode_datagram(ty: PacketType, body: &[u8]) -> Result<Vec<u8>, PacketError> {
    if OUTER_HEADER_LEN + body.len() > MAX_DATAGRAM {
        return Err(PacketError::TooLarge);
    }
    let mut pkt = Vec::with_capacity(OUTER_HEADER_LEN + body.len());
    pkt.extend_from_slice(&encode_outer(ty, 0));
    pkt.extend_from_slice(body);
    Ok(pkt)
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
    /// Exceeds MAX_DATAGRAM.
    TooLarge,
    /// Non-IPv4 address in a forward wrapper.
    BadAddress,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated packet"),
            Self::BadMagic => write!(f, "bad magic"),
            Self::BadVersion => write!(f, "bad version"),
            Self::BadType => write!(f, "bad type"),
            Self::TooLarge => write!(f, "datagram too large"),
            Self::BadAddress => write!(f, "non-ipv4 address"),
        }
    }
}

impl std::error::Error for PacketError {}

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

    #[test]
    fn forward_type_roundtrip() {
        assert_eq!(PacketType::from_u8(4), Some(PacketType::Forward));
        assert_eq!(PacketType::from_u8(0), None);
    }
}
