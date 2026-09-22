//! UDP packet forwarder with a bounded replay window.
//!
//! Does not decrypt. Does not keep circuits. Sees destination addresses
//! (cleartext forward header). Not an anonymity hop.

use std::io;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use crate::network::forward::{decode_forward_body, encode_forward_body};
use crate::network::packet::{decode_outer, encode_outer, PacketType};
use crate::network::replay::ReplayCache;
use crate::MAX_DATAGRAM;

/// One-shot / looped UDP forwarder.
pub struct Relay {
    sock: UdpSocket,
    replay: ReplayCache,
}

impl Relay {
    /// Bind and configure timeouts.
    pub fn bind(addr: &str) -> io::Result<Self> {
        let sock = UdpSocket::bind(addr)?;
        sock.set_read_timeout(Some(Duration::from_millis(200)))?;
        Ok(Self {
            sock,
            replay: ReplayCache::new(),
        })
    }

    /// Local address.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.sock.local_addr()
    }

    /// Process one incoming datagram (timeout is not an error).
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
        let (ty, _flags, body) = match decode_outer(&buf[..n]) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        if ty != PacketType::Forward {
            return Ok(false);
        }
        let (dest, inner) = match decode_forward_body(body) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let now = Instant::now();
        if !self.replay.accept(inner, now) {
            return Ok(false);
        }
        let out_body = match encode_forward_body(from, inner) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let mut pkt = Vec::with_capacity(8 + out_body.len());
        pkt.extend_from_slice(&encode_outer(PacketType::Forward, 0));
        pkt.extend_from_slice(&out_body);
        self.sock.send_to(&pkt, dest)?;
        Ok(true)
    }

    /// Run until `stop` is true (checked after each step).
    pub fn run_until<F: Fn() -> bool>(&mut self, stop: F) -> io::Result<()> {
        while !stop() {
            self.step()?;
        }
        Ok(())
    }
}
