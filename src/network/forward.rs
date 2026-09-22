//! IPv4 forward wrapper (cleartext dest — honest: this is not onion routing).
//!
//! Layout of TYPE=Forward body:
//! ```text
//! dst_ipv4 [4] | dst_port u16 BE | inner datagram (full PPoSE packet)
//! ```
//! Overhead = 6 bytes. The relay sees destination IP:port. That is a
//! documented metadata leak, not an anonymity feature.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use super::packet::PacketError;
use crate::MAX_DATAGRAM;
use crate::OUTER_HEADER_LEN;

/// Bytes added to an inner datagram when wrapping for a relay.
pub const FORWARD_BODY_OVERHEAD: usize = 6;

/// Encode forward body: who the relay should deliver to, plus the inner packet.
pub fn encode_forward_body(dest: SocketAddr, inner: &[u8]) -> Result<Vec<u8>, PacketError> {
    let SocketAddr::V4(v4) = dest else {
        return Err(PacketError::BadAddress);
    };
    if OUTER_HEADER_LEN + FORWARD_BODY_OVERHEAD + inner.len() > MAX_DATAGRAM {
        return Err(PacketError::TooLarge);
    }
    let mut out = Vec::with_capacity(FORWARD_BODY_OVERHEAD + inner.len());
    out.extend_from_slice(&v4.ip().octets());
    out.extend_from_slice(&v4.port().to_be_bytes());
    out.extend_from_slice(inner);
    Ok(out)
}

/// Decode forward body.
pub fn decode_forward_body(body: &[u8]) -> Result<(SocketAddr, &[u8]), PacketError> {
    if body.len() < FORWARD_BODY_OVERHEAD {
        return Err(PacketError::Truncated);
    }
    let ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
    let mut port_b = [0u8; 2];
    port_b.copy_from_slice(&body[4..6]);
    let port = u16::from_be_bytes(port_b);
    let dest = SocketAddr::V4(SocketAddrV4::new(ip, port));
    Ok((dest, &body[FORWARD_BODY_OVERHEAD..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn wrap_unwrap() {
        let dest: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let inner = b"\x4a\x7fhello";
        let body = encode_forward_body(dest, inner).unwrap();
        let (d, rest) = decode_forward_body(&body).unwrap();
        assert_eq!(d, dest);
        assert_eq!(rest, inner);
    }
}
