//! Minimal blocking UDP helpers for Phase 1 tests and examples.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::network::packet::{decode_outer, encode_outer, PacketType};
use crate::MAX_DATAGRAM;

/// Bind a UDP socket on loopback with an ephemeral port.
pub fn bind_loopback() -> io::Result<(UdpSocket, SocketAddr)> {
    let sock = UdpSocket::bind("127.0.0.1:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;
    sock.set_write_timeout(Some(Duration::from_secs(2)))?;
    let addr = sock.local_addr()?;
    Ok((sock, addr))
}

/// Send a framed PPoSE datagram.
pub fn send_framed(
    sock: &UdpSocket,
    peer: SocketAddr,
    ty: PacketType,
    body: &[u8],
) -> io::Result<()> {
    if 8 + body.len() > MAX_DATAGRAM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "datagram too large",
        ));
    }
    let mut pkt = Vec::with_capacity(8 + body.len());
    pkt.extend_from_slice(&encode_outer(ty, 0));
    pkt.extend_from_slice(body);
    sock.send_to(&pkt, peer)?;
    Ok(())
}

/// Receive a framed PPoSE datagram.
pub fn recv_framed(sock: &UdpSocket) -> io::Result<(PacketType, Vec<u8>, SocketAddr)> {
    let mut buf = [0u8; MAX_DATAGRAM];
    let (n, from) = sock.recv_from(&mut buf)?;
    let (ty, _flags, body) = decode_outer(&buf[..n])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
    Ok((ty, body.to_vec(), from))
}
