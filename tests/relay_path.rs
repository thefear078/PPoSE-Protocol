//! End-to-end encrypted session through an IPv4 forwarder.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ppose::crypto::keys::IdentitySecret;
use ppose::network::udp::bind_loopback;
use ppose::relay::Relay;
use ppose::session::{Path, UdpSession};

#[test]
fn alice_bob_via_relay() {
    let mut relay = Relay::bind("127.0.0.1:0").expect("relay");
    let relay_addr = relay.local_addr().expect("addr");
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let relay_thread = thread::spawn(move || {
        while !flag.load(Ordering::SeqCst) {
            let _ = relay.step();
        }
    });

    let (bob_sock, bob_addr) = bind_loopback().expect("bob bind");
    let (alice_sock, _) = bind_loopback().expect("alice bind");
    let bob_id = IdentitySecret::generate();
    let alice_id = IdentitySecret::generate();

    let bob_thread = thread::spawn(move || {
        let mut bob =
            UdpSession::accept_responder(bob_sock, &bob_id, Some(relay_addr)).expect("bob hs");
        let msg = bob.recv(Duration::from_secs(3)).expect("bob recv");
        assert_eq!(msg, b"via-relay");
        bob.send(b"ok").expect("bob send");
    });

    let mut alice = UdpSession::connect_initiator(
        alice_sock,
        &alice_id,
        Path::ViaRelay {
            relay: relay_addr,
            peer: bob_addr,
        },
    )
    .expect("alice hs");
    alice.send(b"via-relay").expect("alice send");
    let reply = alice.recv(Duration::from_secs(3)).expect("alice recv");
    assert_eq!(reply, b"ok");

    bob_thread.join().expect("bob");
    stop.store(true, Ordering::SeqCst);
    relay_thread.join().expect("relay");
}
