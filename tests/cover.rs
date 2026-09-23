//! Integration: cover traffic (`CoverMode`) must not break real delivery.
//!
//! `set_cover` had no test at all before this — cover packets bypass the
//! Noise seal entirely (see `src/cover.rs`), so this exercises the real
//! risk: that interleaving unsealed TYPE=Data cover packets with real
//! Noise-sealed ones could desync transport state on the receiving end.
//! It doesn't (`snow` only advances its receive nonce on successful
//! decryption — cover packets fail and are silently dropped), but that
//! was previously unverified by any test.

use std::thread;
use std::time::Duration;

use ppose::cover::CoverMode;
use ppose::crypto::keys::IdentitySecret;
use ppose::network::udp::bind_loopback;
use ppose::session::{Path, UdpSession};

#[test]
fn real_message_survives_interleaved_cover_traffic() {
    let (bob_sock, bob_addr) = bind_loopback().expect("bob bind");
    let (alice_sock, _) = bind_loopback().expect("alice bind");
    let bob_id = IdentitySecret::generate();
    let alice_id = IdentitySecret::generate();

    let bob_thread = thread::spawn(move || {
        let mut bob = UdpSession::accept_responder(bob_sock, &bob_id, None).expect("bob hs");
        // Delay consuming so alice's ACK-wait loop actually runs long
        // enough (Stealth cadence is ~50ms) to emit and interleave several
        // cover packets before the real DATA packet gets ACKed and drained
        // — otherwise a fast loopback round-trip could complete before
        // maybe_cover ever fires, and this test would prove nothing.
        thread::sleep(Duration::from_millis(180));
        let msg = bob.recv(Duration::from_secs(3)).expect("bob recv");
        assert_eq!(msg, b"real message despite cover noise");
    });

    let mut alice =
        UdpSession::connect_initiator(alice_sock, &alice_id, Path::Direct { peer: bob_addr })
            .expect("alice hs");
    alice.set_cover(CoverMode::Stealth);
    alice
        .send(b"real message despite cover noise")
        .expect("alice send");

    bob_thread.join().expect("bob thread");
}
