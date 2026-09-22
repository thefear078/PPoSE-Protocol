//! Integration: Noise XX + framed UDP on loopback.

use std::thread;

use ppose::crypto::keys::IdentitySecret;
use ppose::network::udp::bind_loopback;
use ppose::session::UdpSession;

#[test]
fn alice_bob_loopback_chat() {
    let (bob_sock, bob_addr) = bind_loopback().expect("bob bind");
    let (alice_sock, _alice_addr) = bind_loopback().expect("alice bind");

    let bob_id = IdentitySecret::generate();
    let alice_id = IdentitySecret::generate();

    let bob_thread = thread::spawn(move || {
        let mut bob = UdpSession::accept_responder(bob_sock, &bob_id).expect("bob hs");
        let msg = bob.recv().expect("bob recv");
        assert_eq!(msg, b"hello from alice");
        bob.send(b"hello from bob").expect("bob send");
    });

    let mut alice =
        UdpSession::connect_initiator(alice_sock, bob_addr, &alice_id).expect("alice hs");
    alice.send(b"hello from alice").expect("alice send");
    let reply = alice.recv().expect("alice recv");
    assert_eq!(reply, b"hello from bob");

    bob_thread.join().expect("bob thread");
}
