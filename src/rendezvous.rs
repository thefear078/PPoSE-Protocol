//! Token rendezvous (DRAFT).
//!
//! A rendezvous server maps a 32-byte token to the registrar's source
//! address. It does **not** prove operator independence. Two colluding
//! servers plus a passive observer can correlate registrations.
//!
//! Token recommendation: `BLAKE3("ppose-rs" || psk || epoch_hours)`.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use crate::network::packet::{decode_outer, encode_datagram, PacketType};
use crate::MAX_DATAGRAM;

const OP_REGISTER: u8 = 1;
const OP_LOOKUP: u8 = 2;
const OP_REPLY: u8 = 3;

/// Maximum distinct tokens retained at once. Registration takes no
/// authentication at all (unlike, say, `Arq`'s fragment reassembly, which
/// at least requires a completed Noise handshake first) — anyone who can
/// send this service a UDP packet can attempt to register a token, so this
/// cap is the only thing standing between that and unbounded memory growth.
const DEFAULT_CAP: usize = 4096;

/// How many `step` calls between full TTL sweeps, when not forced sooner by
/// hitting `DEFAULT_CAP`. Mirrors `network::replay::ReplayCache`: a lookup
/// checks its own entry's freshness directly, so this only delays memory
/// reclamation, not correctness.
const SWEEP_EVERY: u32 = 64;

/// In-memory UDP rendezvous service.
pub struct RendezvousService {
    sock: UdpSocket,
    map: HashMap<[u8; 32], (SocketAddr, Instant)>,
    /// Insertion order of keys in `map`, for bounded FIFO eviction. May
    /// contain stale entries already removed from `map` by TTL expiry —
    /// `register` tolerates that the same way `Arq::on_data` does.
    order: VecDeque<[u8; 32]>,
    ttl: Duration,
    cap: usize,
    calls_since_sweep: u32,
}

impl RendezvousService {
    /// Bind.
    pub fn bind(addr: &str) -> io::Result<Self> {
        let sock = UdpSocket::bind(addr)?;
        sock.set_read_timeout(Some(Duration::from_millis(200)))?;
        Ok(Self {
            sock,
            map: HashMap::new(),
            order: VecDeque::new(),
            ttl: Duration::from_secs(60),
            cap: DEFAULT_CAP,
            calls_since_sweep: 0,
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
        match body[0] {
            OP_REGISTER => {
                if body.len() < 33 {
                    return Ok(false);
                }
                let mut token = [0u8; 32];
                token.copy_from_slice(&body[1..33]);
                self.register(token, from, Instant::now());
                Ok(true)
            }
            OP_LOOKUP => {
                if body.len() < 33 {
                    return Ok(false);
                }
                let mut token = [0u8; 32];
                token.copy_from_slice(&body[1..33]);
                let mut reply = vec![OP_REPLY, 0];
                if let Some(v4) = self.lookup(&token, Instant::now()) {
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

    /// `token`'s registered IPv4 address, if it has one that is still
    /// fresh as of `now`. Checks that entry's own timestamp directly
    /// rather than relying on a prior sweep having removed stale entries
    /// — sweeps are throttled (see `register`), so a stale-but-not-yet-
    /// swept entry must never be returned as live.
    fn lookup(&self, token: &[u8; 32], now: Instant) -> Option<SocketAddrV4> {
        let (addr, seen_at) = self.map.get(token)?;
        if now.saturating_duration_since(*seen_at) >= self.ttl {
            return None;
        }
        match addr {
            SocketAddr::V4(v4) => Some(*v4),
            SocketAddr::V6(_) => None,
        }
    }

    fn register(&mut self, token: [u8; 32], from: SocketAddr, now: Instant) {
        self.calls_since_sweep += 1;
        if self.calls_since_sweep >= SWEEP_EVERY || self.map.len() >= self.cap {
            self.calls_since_sweep = 0;
            self.expire(now);
        }
        if !self.map.contains_key(&token) {
            while self.map.len() >= self.cap {
                let Some(oldest) = self.order.pop_front() else {
                    break;
                };
                // No-op if `oldest` was already swept by TTL expiry above;
                // the loop keeps popping until an eviction actually frees a
                // slot, or the order queue itself runs dry.
                self.map.remove(&oldest);
            }
            self.order.push_back(token);
        }
        self.map.insert(token, (from, now));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Registration takes no authentication at all, so nothing else stops
    /// an unbounded number of distinct tokens from being registered —
    /// confirms the cap actually holds regardless.
    #[test]
    fn registration_table_stays_bounded() {
        let mut svc = RendezvousService::bind("127.0.0.1:0").unwrap();
        svc.cap = 8; // shrink for a fast test; same enforcement, smaller bound
        let now = Instant::now();
        let from: SocketAddr = "127.0.0.1:1".parse().unwrap();
        for i in 0u32..40 {
            let mut token = [0u8; 32];
            token[..4].copy_from_slice(&i.to_be_bytes());
            svc.register(token, from, now);
        }
        assert!(
            svc.map.len() <= svc.cap,
            "registration table must stay bounded, got {}",
            svc.map.len()
        );
    }

    /// A lookup for a token whose entry is past `ttl` must not be treated
    /// as live just because the background sweep hasn't run yet (sweeps
    /// are throttled — see `register`).
    #[test]
    fn expired_registration_not_returned_before_next_sweep() {
        let mut svc = RendezvousService::bind("127.0.0.1:0").unwrap();
        svc.ttl = Duration::from_millis(1);
        let t0 = Instant::now();
        let mut token = [0u8; 32];
        token[0] = 0xAA;
        let from: SocketAddr = "127.0.0.1:2".parse().unwrap();
        svc.register(token, from, t0);
        assert_eq!(
            svc.lookup(&token, t0),
            Some(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 2)),
            "should be found immediately"
        );
        let later = t0 + Duration::from_secs(1);
        assert_eq!(
            svc.lookup(&token, later),
            None,
            "must not be returned once past ttl, even though no sweep has run yet"
        );
        // The entry is still physically present — only the freshness check
        // in `lookup` should be excluding it, not a sweep.
        assert!(svc.map.contains_key(&token));
    }
}
