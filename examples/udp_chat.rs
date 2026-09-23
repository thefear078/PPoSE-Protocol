//! Tiny loopback demo.

use std::thread;
use std::time::Duration;

use ppose::crypto::keys::IdentitySecret;
use ppose::network::udp::bind_loopback;
use ppose::session::{Path, UdpSession};
use ppose::CRATE_VERSION;

fn main() {
    println!("PPoSE udp_chat demo (crate {CRATE_VERSION})");

    let (bob_sock, bob_addr) = bind_loopback().expect("bind bob");
    let (alice_sock, _) = bind_loopback().expect("bind alice");

    let bob_id = IdentitySecret::generate();
    let alice_id = IdentitySecret::generate();

    let bob = thread::spawn(move || {
        let mut s = UdpSession::accept_responder(bob_sock, &bob_id, None).expect("hs");
        let msg = s.recv(Duration::from_secs(2)).expect("recv");
        println!("bob got: {}", String::from_utf8_lossy(&msg));
        s.send(b"ack").expect("send");
    });

    let mut alice =
        UdpSession::connect_initiator(alice_sock, &alice_id, Path::Direct { peer: bob_addr })
            .expect("hs");
    println!("alice fp {}…", hex_prefix(&alice_id.public().fingerprint()));
    alice.send(b"ping").expect("send");
    let reply = alice.recv(Duration::from_secs(2)).expect("recv");
    println!("alice got: {}", String::from_utf8_lossy(&reply));
    bob.join().expect("bob");
}

fn hex_prefix(bytes: &[u8; 32]) -> String {
    bytes[..4].iter().map(|b| format!("{b:02x}")).collect()
}
