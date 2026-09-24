//! Two-hop PND onion (not Sphinx).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ppose::crypto::keys::IdentitySecret;
use ppose::network::udp::bind_loopback;
use ppose::onion::{OnionHop, OnionRelay};
use ppose::session::{Path, UdpSession};

/// Alice sends `request` to Bob over two PND hops; Bob replies `reply`
/// back over the reverse path. Both sides assert what they receive.
fn two_hop_exchange(request: Vec<u8>, reply: Vec<u8>) {
    let h1_id = IdentitySecret::generate();
    let h2_id = IdentitySecret::generate();
    let mut h1 = OnionRelay::bind("127.0.0.1:0", h1_id).expect("h1");
    let mut h2 = OnionRelay::bind("127.0.0.1:0", h2_id).expect("h2");
    let hop1 = OnionHop {
        addr: h1.local_addr().unwrap(),
        pk: h1.public(),
    };
    let hop2 = OnionHop {
        addr: h2.local_addr().unwrap(),
        pk: h2.public(),
    };

    let stop = Arc::new(AtomicBool::new(false));
    let f1 = stop.clone();
    let t1 = thread::spawn(move || {
        while !f1.load(Ordering::SeqCst) {
            let _ = h1.step();
        }
    });
    let f2 = stop.clone();
    let t2 = thread::spawn(move || {
        while !f2.load(Ordering::SeqCst) {
            let _ = h2.step();
        }
    });

    let (bob_sock, bob_addr) = bind_loopback().unwrap();
    let (alice_sock, alice_addr) = bind_loopback().unwrap();
    let bob_id = IdentitySecret::generate();
    let alice_id = IdentitySecret::generate();

    let expected_request = request.clone();
    let bob_reply = reply.clone();
    let bob_thread = thread::spawn(move || {
        let mut bob =
            UdpSession::accept_responder_onion(bob_sock, &bob_id, vec![hop2, hop1], alice_addr)
                .expect("bob hs");
        let msg = bob.recv(Duration::from_secs(4)).expect("bob recv");
        assert_eq!(msg, expected_request);
        bob.send(&bob_reply).expect("bob send");
    });

    let mut alice = UdpSession::connect_initiator(
        alice_sock,
        &alice_id,
        Path::ViaOnion {
            hops: vec![hop1, hop2],
            dest: bob_addr,
        },
    )
    .expect("alice hs");
    alice.send(&request).expect("alice send");
    let got = alice.recv(Duration::from_secs(4)).expect("alice recv");
    assert_eq!(got, reply);

    bob_thread.join().expect("bob");
    stop.store(true, Ordering::SeqCst);
    t1.join().unwrap();
    t2.join().unwrap();
}

#[test]
fn alice_bob_two_hops() {
    two_hop_exchange(b"onion-hi".to_vec(), b"onion-ok".to_vec());
}

/// A message big enough to need full-size ARQ fragments. Each PND hop adds
/// 86 bytes on the wire (78-byte layer + a fresh 8-byte outer header), so a
/// fragment sized for the direct path must shrink to still fit
/// `MAX_DATAGRAM` once wrapped twice.
#[test]
fn large_message_over_two_hops() {
    let request: Vec<u8> = (0..2500u32).map(|i| (i % 251) as u8).collect();
    let reply: Vec<u8> = (0..1800u32).map(|i| (i % 241) as u8).collect();
    two_hop_exchange(request, reply);
}
