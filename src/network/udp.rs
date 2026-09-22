//! Minimal blocking UDP helpers.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::network::packet::{decode_outer, encode_datagram, PacketType};
use crate::MAX_DATAGRAM;

/// Bind a UDP socket on loopback with an ephemeral port.
pub fn bind_loopback() -> io::Result<(UdpSocket, SocketAddr)> {
    let sock = UdpSocket::bind("127.0.0.1:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;
    sock.set_write_timeout(Some(Duration::from_secs(2)))?;
    let addr = sock.local_addr()?;
    Ok((sock, addr))
}

/// Send a framed PPoSE datagram (not forward-wrapped).
pub fn send_framed(
    sock: &UdpSocket,
    peer: SocketAddr,
    ty: PacketType,
    body: &[u8],
) -> io::Result<()> {
    let pkt =
        encode_datagram(ty, body).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    sock.send_to(&pkt, peer)?;
    Ok(())
}

/// Receive any UDP datagram up to MAX_DATAGRAM.
pub fn recv_raw(sock: &UdpSocket) -> io::Result<(Vec<u8>, SocketAddr)> {
    let mut buf = [0u8; MAX_DATAGRAM];
    let (n, from) = sock.recv_from(&mut buf)?;
    Ok((buf[..n].to_vec(), from))
}

/// Receive a framed PPoSE datagram (direct, not nested in Forward).
pub fn recv_framed(sock: &UdpSocket) -> io::Result<(PacketType, Vec<u8>, SocketAddr)> {
    let (pkt, from) = recv_raw(sock)?;
    let (ty, _flags, body) =
        decode_outer(&pkt).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok((ty, body.to_vec(), from))
}
