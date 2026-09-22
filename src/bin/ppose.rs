//! Command-line entry.

use std::env;
use std::net::UdpSocket;
use std::process;
use std::time::Duration;

use ppose::crypto::keys::IdentitySecret;
use ppose::network::udp::bind_loopback;
use ppose::onion::OnionRelay;
use ppose::relay::Relay;
use ppose::rendezvous::{
    decode_reply, encode_lookup, encode_register, token_from_psk, RendezvousService,
};
use ppose::session::{Path, UdpSession};
use ppose::CRATE_VERSION;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "help".into());
    match cmd.as_str() {
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        "version" | "-V" => {
            println!("ppose {CRATE_VERSION}");
            Ok(())
        }
        "keygen" => {
            let sk = IdentitySecret::generate();
            println!("secret  {}", hex(&sk.to_bytes()));
            println!("public  {}", hex(&sk.public().as_bytes()));
            println!("fp      {}", hex(&sk.public().fingerprint()));
            Ok(())
        }
        "listen" => {
            let bind = args.next().unwrap_or_else(|| "127.0.0.1:0".into());
            let sock = UdpSocket::bind(&bind)?;
            sock.set_read_timeout(Some(Duration::from_secs(30)))?;
            println!("listen {}", sock.local_addr()?);
            let id = IdentitySecret::generate();
            println!("fp {}", hex(&id.public().fingerprint()));
            let mut s = UdpSession::accept_responder(sock, &id, None)?;
            let msg = s.recv(Duration::from_secs(30))?;
            println!("recv {}", String::from_utf8_lossy(&msg));
            s.send(b"ack")?;
            Ok(())
        }
        "connect" => {
            let peer: std::net::SocketAddr =
                args.next().ok_or("usage: ppose connect <peer>")?.parse()?;
            let (sock, addr) = bind_loopback()?;
            println!("local {addr}");
            let id = IdentitySecret::generate();
            let mut s = UdpSession::connect_initiator(sock, &id, Path::Direct { peer })?;
            s.send(b"hello")?;
            let reply = s.recv(Duration::from_secs(10))?;
            println!("recv {}", String::from_utf8_lossy(&reply));
            Ok(())
        }
        "relay" => {
            let bind = args.next().unwrap_or_else(|| "127.0.0.1:0".into());
            let mut r = Relay::bind(&bind)?;
            println!("relay {}", r.local_addr()?);
            loop {
                r.step()?;
            }
        }
        "onion-relay" => {
            let bind = args.next().unwrap_or_else(|| "127.0.0.1:0".into());
            let id = IdentitySecret::generate();
            let mut r = OnionRelay::bind(&bind, id)?;
            println!("onion-relay {}", r.local_addr()?);
            println!("public {}", hex(&r.public().as_bytes()));
            loop {
                r.step()?;
            }
        }
        "rs" => {
            let bind = args.next().unwrap_or_else(|| "127.0.0.1:0".into());
            let mut r = RendezvousService::bind(&bind)?;
            println!("rendezvous {}", r.local_addr()?);
            loop {
                r.step()?;
            }
        }
        "rs-register" => {
            let rs: std::net::SocketAddr = args.next().ok_or("rs-register <rs> <psk>")?.parse()?;
            let psk = args.next().unwrap_or_else(|| "demo".into());
            let token = token_from_psk(psk.as_bytes(), 0);
            let sock = UdpSocket::bind("127.0.0.1:0")?;
            sock.send_to(&encode_register(&token), rs)?;
            println!("registered token {}", hex(&token));
            println!("local {}", sock.local_addr()?);
            Ok(())
        }
        "rs-lookup" => {
            let rs: std::net::SocketAddr = args.next().ok_or("rs-lookup <rs> <psk>")?.parse()?;
            let psk = args.next().unwrap_or_else(|| "demo".into());
            let token = token_from_psk(psk.as_bytes(), 0);
            let sock = UdpSocket::bind("127.0.0.1:0")?;
            sock.set_read_timeout(Some(Duration::from_secs(2)))?;
            sock.send_to(&encode_lookup(&token), rs)?;
            let mut buf = [0u8; 512];
            let (n, _) = sock.recv_from(&mut buf)?;
            match decode_reply(&buf[..n]) {
                Some(addr) => println!("peer {addr}"),
                None => println!("not found"),
            }
            Ok(())
        }
        other => {
            eprintln!("unknown command {other}");
            print_help();
            process::exit(2);
        }
    }
}

fn print_help() {
    eprintln!(
        "ppose {CRATE_VERSION} — research prototype (not an anonymity network)\n\n\
         Commands:\n\
           keygen\n\
           listen [bind]\n\
           connect <peer>\n\
           relay [bind]              cleartext dest forwarder\n\
           onion-relay [bind]        PND hop (not Sphinx)\n\
           rs [bind]                 token rendezvous\n\
           rs-register <rs> [psk]\n\
           rs-lookup <rs> [psk]\n\
           version\n"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
