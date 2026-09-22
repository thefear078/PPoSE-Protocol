//! PPoSE Nested Datagram (PND) — layered X25519 + XChaCha20-Poly1305.
//!
//! **This is not Sphinx** (Danezis–Goldberg). Each hop adds ~79 bytes, the
//! next IPv4:port is in the *encrypted* layer (the hop itself sees the next
//! address after peeling). Intermediate hops do not see the inner payload.
//! Length and timing still leak. No mixing, no SURBs, no GPA claim.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::crypto::aead::SessionAead;
use crate::crypto::keys::{IdentitySecret, PublicIdentity};
use crate::network::packet::{decode_outer, encode_datagram, PacketError, PacketType};
use crate::network::replay::ReplayCache;
use crate::MAX_DATAGRAM;

/// Bytes added per hop: eph(32)+nonce(24)+tag(16)+ipv4(4)+port(2).
pub const LAYER_OVERHEAD: usize = 32 + 24 + 16 + 4 + 2;

/// Domain separation for hop key derivation.
pub const PND_KDF_LABEL: &[u8] = b"ppose-pnd-v1";

/// One onion hop: address + static X25519.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OnionHop {
    /// Hop UDP address (IPv4).
    pub addr: SocketAddr,
    /// Hop long-term public key.
    pub pk: PublicIdentity,
}

/// Build a sendable datagram by wrapping `inner` (full PPoSE packet) in
/// layers from last hop to first. Result includes the outermost header.
pub fn wrap_route(
    hops: &[OnionHop],
    dest: SocketAddr,
    inner: &[u8],
) -> Result<Vec<u8>, PacketError> {
    if hops.is_empty() {
        return Err(PacketError::BadType);
    }
    let mut payload = inner.to_vec();
    let mut next = dest;
    for hop in hops.iter().rev() {
        let body = wrap_layer(&hop.pk, next, &payload)?;
        payload = encode_datagram(PacketType::Onion, &body)?;
        next = hop.addr;
    }
    Ok(payload)
}

fn derive_hop_key(shared: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PND_KDF_LABEL);
    hasher.update(shared);
    *hasher.finalize().as_bytes()
}

fn wrap_layer(
    hop_pk: &PublicIdentity,
    next: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, PacketError> {
    let SocketAddr::V4(v4) = next else {
        return Err(PacketError::BadAddress);
    };
    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&PublicKey::from(hop_pk.as_bytes()));
    let key = derive_hop_key(shared.as_bytes());
    let aead = SessionAead::new(&key);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let mut plain = Vec::with_capacity(6 + payload.len());
    plain.extend_from_slice(&v4.ip().octets());
    plain.extend_from_slice(&v4.port().to_be_bytes());
    plain.extend_from_slice(payload);
    let aad = eph_pub.as_bytes();
    let ct = aead
        .seal(&nonce, aad, &plain)
        .map_err(|_| PacketError::TooLarge)?;
    let mut body = Vec::with_capacity(32 + 24 + ct.len());
    body.extend_from_slice(eph_pub.as_bytes());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ct);
    Ok(body)
}

/// Result of peeling one onion layer.
pub struct Peeled {
    /// Next UDP destination.
    pub next: SocketAddr,
    /// Payload to send there (already a complete datagram).
    pub payload: Vec<u8>,
}

/// Peel one layer using this hop's static key.
pub fn peel_layer(local: &IdentitySecret, body: &[u8]) -> Result<Peeled, PacketError> {
    if body.len() < LAYER_OVERHEAD {
        return Err(PacketError::Truncated);
    }
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&body[..32]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&body[32..56]);
    let ct = &body[56..];
    let shared = local.shared_with(&PublicIdentity::from_bytes(eph));
    let key = derive_hop_key(&shared);
    let aead = SessionAead::new(&key);
    let plain = aead
        .open(&nonce, &eph, ct)
        .map_err(|_| PacketError::BadType)?;
    if plain.len() < 6 {
        return Err(PacketError::Truncated);
    }
    let ip = Ipv4Addr::new(plain[0], plain[1], plain[2], plain[3]);
    let mut port_b = [0u8; 2];
    port_b.copy_from_slice(&plain[4..6]);
    let port = u16::from_be_bytes(port_b);
    let next = SocketAddr::V4(SocketAddrV4::new(ip, port));
    Ok(Peeled {
        next,
        payload: plain[6..].to_vec(),
    })
}

/// Onion hop daemon: peel one layer and forward the payload.
pub struct OnionRelay {
    sock: UdpSocket,
    local: IdentitySecret,
    replay: ReplayCache,
}

impl OnionRelay {
    /// Bind an onion hop.
    pub fn bind(addr: &str, local: IdentitySecret) -> io::Result<Self> {
        let sock = UdpSocket::bind(addr)?;
        sock.set_read_timeout(Some(Duration::from_millis(200)))?;
        Ok(Self {
            sock,
            local,
            replay: ReplayCache::new(),
        })
    }

    /// Local UDP address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    /// Hop public identity.
    pub fn public(&self) -> PublicIdentity {
        self.local.public()
    }

    /// Process one packet.
    pub fn step(&mut self) -> io::Result<bool> {
        let mut buf = [0u8; MAX_DATAGRAM];
        let (n, _from) = match self.sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Ok(false);
            }
            Err(e) => return Err(e),
        };
        let (ty, _flags, body) = match decode_outer(&buf[..n]) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        if ty != PacketType::Onion {
            return Ok(false);
        }
        let peeled = match peel_layer(&self.local, body) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        if !self.replay.accept(&peeled.payload, Instant::now()) {
            return Ok(false);
        }
        if peeled.payload.len() > MAX_DATAGRAM {
            return Ok(false);
        }
        self.sock.send_to(&peeled.payload, peeled.next)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_peel_one_hop() {
        let hop = IdentitySecret::generate();
        let dest: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let inner = encode_datagram(PacketType::Data, b"xyz").unwrap();
        let hops = [OnionHop {
            addr: "127.0.0.1:8".parse().unwrap(),
            pk: hop.public(),
        }];
        let wire = wrap_route(&hops, dest, &inner).unwrap();
        let (ty, _, body) = decode_outer(&wire).unwrap();
        assert_eq!(ty, PacketType::Onion);
        let peeled = peel_layer(&hop, body).unwrap();
        assert_eq!(peeled.next, dest);
        assert_eq!(peeled.payload, inner);
    }
}
