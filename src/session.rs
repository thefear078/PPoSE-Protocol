//! High-level peer session: Noise XX over framed UDP (Phase 1).

use std::io;
use std::net::{SocketAddr, UdpSocket};

use crate::crypto::keys::IdentitySecret;
use crate::crypto::noise::{HandshakeRole, NoiseError, NoiseSession};
use crate::network::packet::PacketType;
use crate::network::udp::{recv_framed, send_framed};

/// Session-layer errors.
#[derive(Debug)]
pub enum SessionError {
    /// I/O failure.
    Io(io::Error),
    /// Noise failure.
    Noise(NoiseError),
    /// Unexpected packet type during handshake/data.
    UnexpectedType,
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

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Noise(e) => write!(f, "noise: {e}"),
            Self::UnexpectedType => write!(f, "unexpected packet type"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Established (or in-progress) PPoSE session over UDP.
pub struct UdpSession {
    sock: UdpSocket,
    peer: SocketAddr,
    noise: NoiseSession,
}

impl UdpSession {
    /// Run Noise XX as initiator toward `peer`.
    pub fn connect_initiator(
        sock: UdpSocket,
        peer: SocketAddr,
        local: &IdentitySecret,
    ) -> Result<Self, SessionError> {
        let mut noise = NoiseSession::new(HandshakeRole::Initiator, local)?;
        let mut buf = [0u8; 2048];
        let mut tmp = [0u8; 2048];

        // msg 1 →
        let n = noise.write_handshake(&[], &mut buf)?;
        send_framed(&sock, peer, PacketType::Handshake, &buf[..n])?;

        // msg 2 ←
        let (ty, body, from) = recv_framed(&sock)?;
        if from != peer || ty != PacketType::Handshake {
            return Err(SessionError::UnexpectedType);
        }
        noise.read_handshake(&body, &mut tmp)?;

        // msg 3 →
        let n = noise.write_handshake(&[], &mut buf)?;
        send_framed(&sock, peer, PacketType::Handshake, &buf[..n])?;

        assert!(noise.is_transport());
        Ok(Self { sock, peer, noise })
    }

    /// Accept Noise XX as responder (first datagram must already be available pattern:
    /// this helper reads msg1 itself).
    pub fn accept_responder(sock: UdpSocket, local: &IdentitySecret) -> Result<Self, SessionError> {
        let mut noise = NoiseSession::new(HandshakeRole::Responder, local)?;
        let mut buf = [0u8; 2048];
        let mut tmp = [0u8; 2048];

        // msg 1 ←
        let (ty, body, peer) = recv_framed(&sock)?;
        if ty != PacketType::Handshake {
            return Err(SessionError::UnexpectedType);
        }
        noise.read_handshake(&body, &mut tmp)?;

        // msg 2 →
        let n = noise.write_handshake(&[], &mut buf)?;
        send_framed(&sock, peer, PacketType::Handshake, &buf[..n])?;

        // msg 3 ←
        let (ty, body, from) = recv_framed(&sock)?;
        if from != peer || ty != PacketType::Handshake {
            return Err(SessionError::UnexpectedType);
        }
        noise.read_handshake(&body, &mut tmp)?;

        assert!(noise.is_transport());
        Ok(Self { sock, peer, noise })
    }

    /// Send an encrypted application message.
    pub fn send(&mut self, plaintext: &[u8]) -> Result<(), SessionError> {
        let mut buf = [0u8; 2048];
        let n = self.noise.seal(plaintext, &mut buf)?;
        send_framed(&self.sock, self.peer, PacketType::Data, &buf[..n])?;
        Ok(())
    }

    /// Receive and decrypt one application message.
    pub fn recv(&mut self) -> Result<Vec<u8>, SessionError> {
        let (ty, body, from) = recv_framed(&self.sock)?;
        if from != self.peer || ty != PacketType::Data {
            return Err(SessionError::UnexpectedType);
        }
        let mut out = vec![0u8; body.len()];
        let n = self.noise.open(&body, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// Peer socket address.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }
}
