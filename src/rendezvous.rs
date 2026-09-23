//! Token rendezvous (DRAFT).
//!
//! A rendezvous server maps a 32-byte token to the registrar's source
//! address. It does **not** prove operator independence. Two colluding
//! servers plus a passive observer can correlate registrations.
//!
//! Token recommendation: `BLAKE3("ppose-rs" || psk || epoch_hours)`.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use crate::network::packet::{decode_outer, encode_datagram, PacketType};
use crate::MAX_DATAGRAM;

const OP_REGISTER: u8 = 1;
const OP_LOOKUP: u8 = 2;
const OP_REPLY: u8 = 3;

/// In-memory UDP rendezvous service.
pub struct RendezvousService {
    sock: UdpSocket,
    map: HashMap<[u8; 32], (SocketAddr, Instant)>,
    ttl: Duration,
}

impl RendezvousService {
    /// Bind.
    pub fn bind(addr: &str) -> io::Result<Self> {
        let sock = UdpSocket::bind(addr)?;
        sock.set_read_timeout(Some(Duration::from_millis(200)))?;
        Ok(Self {
            sock,
            map: HashMap::new(),
            ttl: Duration::from_secs(60),
        })
    }

    /// Local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    /// Process one datagram.
    pub fn step(&mut self) -> io::Result<bool> {
        let mut buf = [0u8; MAX_DATAGRAM];
        let (n, from) = match self.sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Ok(false);
            }
            Err(e) => return Err(e),
        };
        let Ok((ty, _, body)) = decode_outer(&buf[..n]) else {
            return Ok(false);
        };
        if ty != PacketType::Rendezvous || body.is_empty() {
            return Ok(false);
        }
        self.expire(Instant::now());
        match body[0] {
            OP_REGISTER => {
                if body.len() < 33 {
                    return Ok(false);
                }
                let mut token = [0u8; 32];
                token.copy_from_slice(&body[1..33]);
                self.map.insert(token, (from, Instant::now()));
                Ok(true)
            }
            OP_LOOKUP => {
                if body.len() < 33 {
                    return Ok(false);
                }
                let mut token = [0u8; 32];
                token.copy_from_slice(&body[1..33]);
                let mut reply = vec![OP_REPLY, 0];
                if let Some((SocketAddr::V4(v4), _)) = self.map.get(&token) {
                    reply[1] = 1;
                    reply.extend_from_slice(&v4.ip().octets());
                    reply.extend_from_slice(&v4.port().to_be_bytes());
                }
                let Ok(pkt) = encode_datagram(PacketType::Rendezvous, &reply) else {
                    return Ok(false);
                };
                self.sock.send_to(&pkt, from)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn expire(&mut self, now: Instant) {
        self.map
            .retain(|_, (_, t)| now.saturating_duration_since(*t) < self.ttl);
    }
}

/// Derive a rendezvous token from a pre-shared secret and epoch hours.
pub fn token_from_psk(psk: &[u8], epoch_hours: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ppose-rs");
    hasher.update(psk);
    hasher.update(&epoch_hours.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// Build a register datagram.
pub fn encode_register(token: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(33);
    body.push(OP_REGISTER);
    body.extend_from_slice(token);
    encode_datagram(PacketType::Rendezvous, &body).expect("register fits MTU")
}

/// Build a lookup datagram.
pub fn encode_lookup(token: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(33);
    body.push(OP_LOOKUP);
    body.extend_from_slice(token);
    encode_datagram(PacketType::Rendezvous, &body).expect("lookup fits MTU")
}

/// Parse a lookup reply into an address.
pub fn decode_reply(pkt: &[u8]) -> Option<SocketAddr> {
    let (ty, _, body) = decode_outer(pkt).ok()?;
    if ty != PacketType::Rendezvous || body.len() < 8 || body[0] != OP_REPLY || body[1] != 1 {
        return None;
    }
    let ip = Ipv4Addr::new(body[2], body[3], body[4], body[5]);
    let mut p = [0u8; 2];
    p.copy_from_slice(&body[6..8]);
    Some(SocketAddr::V4(SocketAddrV4::new(ip, u16::from_be_bytes(p))))
}
