//! Direct listen/connect demo (same as `ppose listen` / `ppose connect`).

use std::env;
use std::time::Duration;

use ppose::crypto::keys::IdentitySecret;
use ppose::network::udp::bind_loopback;
use ppose::session::{Path, UdpSession};

fn main() {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("listen") => {
            let bind = args.next().unwrap_or_else(|| "127.0.0.1:0".into());
            let sock = std::net::UdpSocket::bind(bind).expect("bind");
            println!("listen {}", sock.local_addr().unwrap());
            let id = IdentitySecret::generate();
            let mut s = UdpSession::accept_responder(sock, &id, None).expect("hs");
            let msg = s.recv(Duration::from_secs(30)).expect("recv");
            println!("{}", String::from_utf8_lossy(&msg));
            s.send(b"ack").expect("send");
        }
        Some("connect") => {
            let peer: std::net::SocketAddr = args
                .next()
                .expect("peer addr")
                .parse()
                .expect("socket addr");
            let (sock, _) = bind_loopback().expect("bind");
            let id = IdentitySecret::generate();
            let mut s =
                UdpSession::connect_initiator(sock, &id, Path::Direct { peer }).expect("hs");
            s.send(b"hello").expect("send");
            let reply = s.recv(Duration::from_secs(10)).expect("recv");
            println!("{}", String::from_utf8_lossy(&reply));
        }
        _ => {
            eprintln!("usage: cli_client listen [bind] | connect <peer>");
            std::process::exit(2);
        }
    }
}
