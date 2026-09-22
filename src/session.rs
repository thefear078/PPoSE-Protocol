//! High-level peer session: Noise XX + ARQ over UDP (direct or via a relay).

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::crypto::keys::IdentitySecret;
use crate::crypto::noise::{HandshakeRole, NoiseError, NoiseSession};
use crate::network::forward::{decode_forward_body, encode_forward_body};
use crate::network::packet::{decode_outer, encode_datagram, PacketError, PacketType};
use crate::network::udp::recv_raw;
use crate::reliability::{Arq, ArqError, ArqGiveUp};
use crate::MAX_DATAGRAM;

/// How packets reach the other endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    noise: NoiseSession,
    arq: Arq,
    drop_data: u32,
}

impl UdpSession {
    /// Noise XX initiator.
    pub fn connect_initiator(
        sock: UdpSocket,
        local: &IdentitySecret,
        path: Path,
    ) -> Result<Self, SessionError> {
        let (next_hop, peer, via_relay) = match path {
            Path::Direct { peer } => (peer, peer, false),
            Path::ViaRelay { relay, peer } => (relay, peer, true),
        };
        let noise = NoiseSession::new(HandshakeRole::Initiator, local)?;
        let mut sess = Self {
            sock,
            next_hop,
            peer,
            via_relay,
            noise,
            arq: Arq::new(),
            drop_data: 0,
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
        Ok(sess)
    }

    /// Noise XX responder. `expected_relay` is `Some` when the first packet
    /// must arrive wrapped from that relay.
    pub fn accept_responder(
        sock: UdpSocket,
        local: &IdentitySecret,
        expected_relay: Option<SocketAddr>,
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
            noise,
            arq: Arq::new(),
            drop_data: 0,
        };

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
        Ok(sess)
    }

    /// Queue and send an application message (fragmented + ARQ).
    ///
    /// Blocks until the send window for this message is acknowledged or
    /// `timeout` is used via the default 5s wait so retransmits can run.
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
            let now = Instant::now();
            if now >= deadline {
                return Err(SessionError::Timeout);
            }
            let left = deadline.saturating_duration_since(now);
            self.sock.set_read_timeout(Some(left))?;
            match recv_raw(&self.sock) {
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    continue;
                }
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
    /// Handshake packets are never dropped this way. ARQ still marks them sent.
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

    fn wait_acked(&mut self, timeout: Duration) -> Result<(), SessionError> {
        let deadline = Instant::now() + timeout;
        loop {
            self.flush()?;
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
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    continue;
                }
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
                let n = self.noise.open(&body, &mut out)?;
                out.truncate(n);
                if let Some(ack) = self.arq.ingest(&out)? {
                    let mut buf = [0u8; MAX_DATAGRAM];
                    let n = self.noise.seal(&ack, &mut buf)?;
                    self.send_inner(PacketType::Data, &buf[..n])?;
                }
                Ok(())
            }
            PacketType::Handshake | PacketType::Ack | PacketType::Forward => {
                Err(SessionError::UnexpectedType)
            }
        }
    }

    fn send_inner(&self, ty: PacketType, body: &[u8]) -> Result<(), SessionError> {
        let inner_dg = encode_datagram(ty, body)?;
        let wire = if self.via_relay {
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
