//! Integration: Noise XX + ARQ on loopback (direct path).

use std::thread;
use std::time::Duration;

use ppose::crypto::keys::IdentitySecret;
use ppose::network::udp::bind_loopback;
use ppose::session::{Path, UdpSession};

#[test]
fn alice_bob_loopback_chat() {
    let (bob_sock, bob_addr) = bind_loopback().expect("bob bind");
    let (alice_sock, _alice_addr) = bind_loopback().expect("alice bind");

    let bob_id = IdentitySecret::generate();
    let alice_id = IdentitySecret::generate();

    let bob_thread = thread::spawn(move || {
        let mut bob = UdpSession::accept_responder(bob_sock, &bob_id, None).expect("bob hs");
        let msg = bob.recv(Duration::from_secs(2)).expect("bob recv");
        assert_eq!(msg, b"hello from alice");
        bob.send(b"hello from bob").expect("bob send");
    });

    let mut alice =
        UdpSession::connect_initiator(alice_sock, &alice_id, Path::Direct { peer: bob_addr })
            .expect("alice hs");
    alice.send(b"hello from alice").expect("alice send");
    let reply = alice.recv(Duration::from_secs(2)).expect("alice recv");
    assert_eq!(reply, b"hello from bob");

    bob_thread.join().expect("bob thread");
}

#[test]
fn recovers_dropped_data_datagram() {
    let (bob_sock, bob_addr) = bind_loopback().expect("bob bind");
    let (alice_sock, _) = bind_loopback().expect("alice bind");
    let bob_id = IdentitySecret::generate();
    let alice_id = IdentitySecret::generate();

    let bob_thread = thread::spawn(move || {
        let mut bob = UdpSession::accept_responder(bob_sock, &bob_id, None).expect("bob hs");
        let msg = bob.recv(Duration::from_secs(3)).expect("bob recv");
        assert_eq!(msg, b"lossy-hello");
    });

    let mut alice =
        UdpSession::connect_initiator(alice_sock, &alice_id, Path::Direct { peer: bob_addr })
            .expect("alice hs");
    alice.set_retx_timeout(Duration::from_millis(50));
    alice.debug_drop_data(1);
    alice.send(b"lossy-hello").expect("alice send");
    bob_thread.join().expect("bob thread");
}

#[test]
fn large_message_fragments() {
    let (bob_sock, bob_addr) = bind_loopback().expect("bob bind");
    let (alice_sock, _) = bind_loopback().expect("alice bind");
    let bob_id = IdentitySecret::generate();
    let alice_id = IdentitySecret::generate();
    let payload = vec![0x5a; 2000];
    let expected = payload.clone();

    let bob_thread = thread::spawn(move || {
        let mut bob = UdpSession::accept_responder(bob_sock, &bob_id, None).expect("bob hs");
        let msg = bob.recv(Duration::from_secs(3)).expect("bob recv");
        assert_eq!(msg, expected);
    });

    let mut alice =
        UdpSession::connect_initiator(alice_sock, &alice_id, Path::Direct { peer: bob_addr })
            .expect("alice hs");
    alice.send(&payload).expect("alice send");
    bob_thread.join().expect("bob thread");
}
