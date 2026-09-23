//! High-level peer session: Noise XX + ARQ over UDP.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};

use crate::cover::CoverMode;
use crate::crypto::keys::{IdentitySecret, PublicIdentity};
use crate::crypto::noise::{HandshakeRole, NoiseError, NoiseSession};
use crate::network::forward::{decode_forward_body, encode_forward_body};
use crate::network::packet::{decode_outer, encode_datagram, PacketError, PacketType};
use crate::network::udp::recv_raw;
use crate::onion::{wrap_route, OnionHop};
use crate::reliability::{Arq, ArqError, ArqGiveUp};
use crate::MAX_DATAGRAM;

/// How packets reach the other endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Path {
    /// Send UDP directly to the peer.
    Direct {
        /// Peer socket address.
        peer: SocketAddr,
    },
    /// Send Forward wrappers to `relay`; `peer` is the inner destination.
    /// The relay sees `peer`. This is **not** an anonymity hop.
    ViaRelay {
        /// Relay address.
        relay: SocketAddr,
        /// Other endpoint (IPv4).
        peer: SocketAddr,
    },
    /// Nested PND onion. Hops see next address after peel. Not Sphinx.
    ViaOnion {
        /// Outbound hops (first is UDP next-hop).
        hops: Vec<OnionHop>,
        /// Final destination.
        dest: SocketAddr,
    },
}

/// Session-layer errors.
#[derive(Debug)]
pub enum SessionError {
    /// I/O failure.
    Io(io::Error),
    /// Noise failure.
    Noise(NoiseError),
    /// Packet codec.
    Packet(PacketError),
    /// ARQ codec / size.
    Arq(ArqError),
    /// Retransmits exhausted.
    GiveUp(ArqGiveUp),
    /// Unexpected packet type during handshake/data.
    UnexpectedType,
    /// Datagram from an unexpected address.
    UnexpectedAddr,
    /// Handshake did not reach transport mode.
    HandshakeIncomplete,
    /// Timed out waiting for an application message.
    Timeout,
    /// Empty onion hop list.
    EmptyOnion,
}

impl From<io::Error> for SessionError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<NoiseError> for SessionError {
    fn from(value: NoiseError) -> Self {
        Self::Noise(value)
    }
}

impl From<PacketError> for SessionError {
    fn from(value: PacketError) -> Self {
        Self::Packet(value)
    }
}

impl From<ArqError> for SessionError {
    fn from(value: ArqError) -> Self {
        Self::Arq(value)
    }
}

impl From<ArqGiveUp> for SessionError {
    fn from(value: ArqGiveUp) -> Self {
        Self::GiveUp(value)
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Noise(e) => write!(f, "noise: {e}"),
            Self::Packet(e) => write!(f, "packet: {e}"),
            Self::Arq(e) => write!(f, "arq: {e}"),
            Self::GiveUp(e) => write!(f, "{e}"),
            Self::UnexpectedType => write!(f, "unexpected packet type"),
            Self::UnexpectedAddr => write!(f, "unexpected address"),
            Self::HandshakeIncomplete => write!(f, "handshake incomplete"),
            Self::Timeout => write!(f, "timeout"),
            Self::EmptyOnion => write!(f, "onion path has no hops"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Established PPoSE session over UDP.
pub struct UdpSession {
    sock: UdpSocket,
    next_hop: SocketAddr,
    peer: SocketAddr,
    via_relay: bool,
    onion: Option<Vec<OnionHop>>,
    noise: NoiseSession,
    arq: Arq,
    drop_data: u32,
    cover: CoverMode,
    last_cover: Instant,
}

impl UdpSession {
    /// Noise XX initiator.
    pub fn connect_initiator(
        sock: UdpSocket,
        local: &IdentitySecret,
        path: Path,
    ) -> Result<Self, SessionError> {
        Self::connect_initiator_pinned(sock, local, path, None)
    }

    /// Initiator that requires the remote static to match `expected`.
    pub fn connect_initiator_pinned(
        sock: UdpSocket,
        local: &IdentitySecret,
        path: Path,
        expected: Option<PublicIdentity>,
    ) -> Result<Self, SessionError> {
        let (next_hop, peer, via_relay, onion) = match path {
            Path::Direct { peer } => (peer, peer, false, None),
            Path::ViaRelay { relay, peer } => (relay, peer, true, None),
            Path::ViaOnion { hops, dest } => {
                let first = hops.first().ok_or(SessionError::EmptyOnion)?;
                (first.addr, dest, false, Some(hops))
            }
        };
        let noise = NoiseSession::new(HandshakeRole::Initiator, local)?;
        let mut sess = Self {
            sock,
            next_hop,
            peer,
            via_relay,
            onion,
            noise,
            arq: Arq::new(),
            drop_data: 0,
            cover: CoverMode::Off,
            last_cover: Instant::now(),
        };

        let mut buf = [0u8; MAX_DATAGRAM];
        let mut tmp = [0u8; MAX_DATAGRAM];

        let n = sess.noise.write_handshake(&[], &mut buf)?;
        sess.send_inner(PacketType::Handshake, &buf[..n])?;

        let (ty, body) = sess.recv_inner()?;
        if ty != PacketType::Handshake {
            return Err(SessionError::UnexpectedType);
        }
        sess.noise.read_handshake(&body, &mut tmp)?;

        let n = sess.noise.write_handshake(&[], &mut buf)?;
        sess.send_inner(PacketType::Handshake, &buf[..n])?;

        if !sess.noise.is_transport() {
            return Err(SessionError::HandshakeIncomplete);
        }
        if let Some(exp) = expected {
            sess.noise.pin_remote(&exp.as_bytes())?;
        }
        Ok(sess)
    }

    /// Noise XX responder. `expected_relay` is `Some` when the first packet
    /// must arrive wrapped from that relay.
    pub fn accept_responder(
        sock: UdpSocket,
        local: &IdentitySecret,
        expected_relay: Option<SocketAddr>,
    ) -> Result<Self, SessionError> {
        Self::accept_ex(sock, local, expected_relay, None, None)
    }

    /// Responder that pins the remote static key.
    pub fn accept_responder_pinned(
        sock: UdpSocket,
        local: &IdentitySecret,
        expected_relay: Option<SocketAddr>,
        expected: Option<PublicIdentity>,
    ) -> Result<Self, SessionError> {
        Self::accept_ex(sock, local, expected_relay, expected, None)
    }

    /// Responder that onion-wraps all replies (including handshake).
    pub fn accept_responder_onion(
        sock: UdpSocket,
        local: &IdentitySecret,
        hops: Vec<OnionHop>,
        dest: SocketAddr,
    ) -> Result<Self, SessionError> {
        Self::accept_ex(sock, local, None, None, Some((hops, dest)))
    }

    fn accept_ex(
        sock: UdpSocket,
        local: &IdentitySecret,
        expected_relay: Option<SocketAddr>,
        expected: Option<PublicIdentity>,
        outbound_onion: Option<(Vec<OnionHop>, SocketAddr)>,
    ) -> Result<Self, SessionError> {
        let mut noise = NoiseSession::new(HandshakeRole::Responder, local)?;
        let (raw, from) = recv_raw(&sock)?;
        let via_relay = expected_relay.is_some();
        if let Some(relay) = expected_relay {
            if from != relay {
                return Err(SessionError::UnexpectedAddr);
            }
        }
        let (ty, body, other) = decode_incoming(via_relay, &raw)?;
        if ty != PacketType::Handshake {
            return Err(SessionError::UnexpectedType);
        }
        let peer = if via_relay {
            other.ok_or(SessionError::UnexpectedType)?
        } else {
            from
        };
        let mut tmp = [0u8; MAX_DATAGRAM];
        noise.read_handshake(&body, &mut tmp)?;

        let mut sess = Self {
            sock,
            next_hop: from,
            peer,
            via_relay,
            onion: None,
            noise,
            arq: Arq::new(),
            drop_data: 0,
            cover: CoverMode::Off,
            last_cover: Instant::now(),
        };
        if let Some((hops, dest)) = outbound_onion {
            sess.set_outbound_onion(hops, dest)?;
        }

        let mut buf = [0u8; MAX_DATAGRAM];
        let n = sess.noise.write_handshake(&[], &mut buf)?;
        sess.send_inner(PacketType::Handshake, &buf[..n])?;

        let (ty, body) = sess.recv_inner()?;
        if ty != PacketType::Handshake {
            return Err(SessionError::UnexpectedType);
        }
        sess.noise.read_handshake(&body, &mut tmp)?;
        if !sess.noise.is_transport() {
            return Err(SessionError::HandshakeIncomplete);
        }
        if let Some(exp) = expected {
            sess.noise.pin_remote(&exp.as_bytes())?;
        }
        Ok(sess)
    }

    /// Set outbound onion route (return path after accept).
    pub fn set_outbound_onion(
        &mut self,
        hops: Vec<OnionHop>,
        dest: SocketAddr,
    ) -> Result<(), SessionError> {
        let first = hops.first().ok_or(SessionError::EmptyOnion)?;
        self.next_hop = first.addr;
        self.peer = dest;
        self.onion = Some(hops);
        self.via_relay = false;
        Ok(())
    }

    /// Enable cover datagrams on idle.
    pub fn set_cover(&mut self, mode: CoverMode) {
        self.cover = mode;
        self.last_cover = Instant::now();
    }

    /// Queue and send an application message (fragmented + ARQ).
    pub fn send(&mut self, plaintext: &[u8]) -> Result<(), SessionError> {
        self.send_timeout(plaintext, Duration::from_secs(5))
    }

    /// Like [`send`](Self::send) with an explicit ACK wait.
    pub fn send_timeout(
        &mut self,
        plaintext: &[u8],
        timeout: Duration,
    ) -> Result<(), SessionError> {
        self.arq.enqueue(plaintext)?;
        self.wait_acked(timeout)
    }

    /// Wait up to `timeout` for a fully reassembled application message.
    pub fn recv(&mut self, timeout: Duration) -> Result<Vec<u8>, SessionError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(m) = self.arq.pop_delivered() {
                return Ok(m);
            }
            self.flush()?;
            self.maybe_cover()?;
            let now = Instant::now();
            if now >= deadline {
                return Err(SessionError::Timeout);
            }
            let left = deadline.saturating_duration_since(now);
            self.sock.set_read_timeout(Some(left))?;
            match recv_raw(&self.sock) {
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => return Err(e.into()),
                Ok((raw, from)) => {
                    if from != self.next_hop {
                        continue;
                    }
                    self.handle_incoming(&raw)?;
                }
            }
        }
    }

    /// Drop the next `n` outbound encrypted DATA datagrams (loss tests).
    pub fn debug_drop_data(&mut self, n: u32) {
        self.drop_data = n;
    }

    /// Override retransmit timeout (tests / tuning).
    pub fn set_retx_timeout(&mut self, d: Duration) {
        self.arq.set_retx(d);
    }

    /// Peer application address (the other endpoint, not the relay).
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Remote static after handshake.
    pub fn remote_static(&self) -> Result<[u8; 32], SessionError> {
        Ok(self.noise.remote_static()?)
    }

    fn wait_acked(&mut self, timeout: Duration) -> Result<(), SessionError> {
        let deadline = Instant::now() + timeout;
        loop {
            self.flush()?;
            self.maybe_cover()?;
            if self.arq.unacked_len() == 0 {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(SessionError::Timeout);
            }
            let left = deadline.saturating_duration_since(now);
            let slice = left.min(Duration::from_millis(50));
            self.sock.set_read_timeout(Some(slice))?;
            match recv_raw(&self.sock) {
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => return Err(e.into()),
                Ok((raw, from)) => {
                    if from != self.next_hop {
                        continue;
                    }
                    self.handle_incoming(&raw)?;
                }
            }
        }
    }

    fn maybe_cover(&mut self) -> Result<(), SessionError> {
        let Some(interval) = self.cover.interval() else {
            return Ok(());
        };
        let now = Instant::now();
        if now.saturating_duration_since(self.last_cover) < interval {
            return Ok(());
        }
        self.last_cover = now;
        let (min, max) = self.cover.payload_len_range();
        let n = if max > min {
            min + (OsRng.next_u32() as usize % (max - min))
        } else {
            min
        };
        let mut body = vec![0u8; n];
        OsRng.fill_bytes(&mut body);
        self.send_inner(PacketType::Data, &body)
    }

    fn flush(&mut self) -> Result<(), SessionError> {
        let now = Instant::now();
        let news = self.arq.take_new_sends(now);
        for pt in news {
            self.seal_data(&pt)?;
        }
        let retrx = self.arq.take_retransmits(now)?;
        for pt in retrx {
            self.seal_data(&pt)?;
        }
        Ok(())
    }

    fn seal_data(&mut self, inner: &[u8]) -> Result<(), SessionError> {
        if self.drop_data > 0 {
            self.drop_data -= 1;
            return Ok(());
        }
        let mut buf = [0u8; MAX_DATAGRAM];
        let n = self.noise.seal(inner, &mut buf)?;
        self.send_inner(PacketType::Data, &buf[..n])
    }

    fn handle_incoming(&mut self, raw: &[u8]) -> Result<(), SessionError> {
        let (ty, body, other) = decode_incoming(self.via_relay, raw)?;
        if let Some(o) = other {
            self.peer = o;
        }
        match ty {
            PacketType::Data => {
                let mut out = vec![0u8; body.len()];
                let Ok(n) = self.noise.open(&body, &mut out) else {
                    return Ok(());
                };
                out.truncate(n);
                if let Some(ack) = self.arq.ingest(&out)? {
                    let mut buf = [0u8; MAX_DATAGRAM];
                    let n = self.noise.seal(&ack, &mut buf)?;
                    self.send_inner(PacketType::Data, &buf[..n])?;
                }
                Ok(())
            }
            PacketType::Handshake
            | PacketType::Ack
            | PacketType::Forward
            | PacketType::Onion
            | PacketType::Rendezvous => Err(SessionError::UnexpectedType),
        }
    }

    fn send_inner(&self, ty: PacketType, body: &[u8]) -> Result<(), SessionError> {
        let inner_dg = encode_datagram(ty, body)?;
        let wire = if let Some(hops) = &self.onion {
            wrap_route(hops, self.peer, &inner_dg)?
        } else if self.via_relay {
            let fb = encode_forward_body(self.peer, &inner_dg)?;
            encode_datagram(PacketType::Forward, &fb)?
        } else {
            inner_dg
        };
        self.sock.send_to(&wire, self.next_hop)?;
        Ok(())
    }

    fn recv_inner(&mut self) -> Result<(PacketType, Vec<u8>), SessionError> {
        let (raw, from) = recv_raw(&self.sock)?;
        if from != self.next_hop {
            return Err(SessionError::UnexpectedAddr);
        }
        let (ty, body, other) = decode_incoming(self.via_relay, &raw)?;
        if let Some(o) = other {
            self.peer = o;
        }
        Ok((ty, body))
    }
}

fn decode_incoming(
    via_relay: bool,
    bytes: &[u8],
) -> Result<(PacketType, Vec<u8>, Option<SocketAddr>), SessionError> {
    let (ty, _flags, body) = decode_outer(bytes)?;
    if via_relay {
        if ty != PacketType::Forward {
            return Err(SessionError::UnexpectedType);
        }
        let (other, inner) = decode_forward_body(body)?;
        let (ity, _f, ibody) = decode_outer(inner)?;
        Ok((ity, ibody.to_vec(), Some(other)))
    } else {
        Ok((ty, body.to_vec(), None))
    }
}
