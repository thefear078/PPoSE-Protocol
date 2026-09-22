//! Remote static pinning.

use std::thread;
use std::time::Duration;

use ppose::crypto::keys::IdentitySecret;
use ppose::network::udp::bind_loopback;
use ppose::session::{Path, UdpSession};

#[test]
fn pin_accepts_correct_key() {
    let (bob_sock, bob_addr) = bind_loopback().unwrap();
    let (alice_sock, _) = bind_loopback().unwrap();
    let bob_id = IdentitySecret::generate();
    let alice_id = IdentitySecret::generate();
    let bob_pk = bob_id.public();
    let alice_pk = alice_id.public();

    let bob_thread = thread::spawn(move || {
        let mut bob = UdpSession::accept_responder_pinned(bob_sock, &bob_id, None, Some(alice_pk))
            .expect("bob hs");
        let msg = bob.recv(Duration::from_secs(2)).expect("recv");
        assert_eq!(msg, b"pinned");
    });

    let mut alice = UdpSession::connect_initiator_pinned(
        alice_sock,
        &alice_id,
        Path::Direct { peer: bob_addr },
        Some(bob_pk),
    )
    .expect("alice hs");
    alice.send(b"pinned").expect("send");
    bob_thread.join().unwrap();
}

#[test]
fn pin_rejects_wrong_key() {
    let (bob_sock, bob_addr) = bind_loopback().unwrap();
    let (alice_sock, _) = bind_loopback().unwrap();
    let bob_id = IdentitySecret::generate();
    let alice_id = IdentitySecret::generate();
    let wrong = IdentitySecret::generate().public();

    let bob_thread = thread::spawn(move || {
        let _ = UdpSession::accept_responder(bob_sock, &bob_id, None);
    });

    let err = UdpSession::connect_initiator_pinned(
        alice_sock,
        &alice_id,
        Path::Direct { peer: bob_addr },
        Some(wrong),
    );
    assert!(err.is_err());
    let _ = bob_thread.join();
}
