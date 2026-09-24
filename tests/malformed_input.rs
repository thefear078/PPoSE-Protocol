//! Lightweight fuzz-style coverage for every function that parses bytes
//! coming straight off the wire, before any cryptographic authentication
//! has had a chance to reject them.
//!
//! `docs/SECURITY_REVIEW.md` flagged this as the natural next step and
//! noted "none of that was run here" — this is that step, as deterministic
//! (seeded) randomized tests rather than a `cargo-fuzz` corpus, since a
//! `libFuzzer`-based harness doesn't fit this project's plain `cargo test`
//! workflow. It doesn't replace real coverage-guided fuzzing, but it does
//! exercise the length/boundary space no existing unit test covered: every
//! byte length from 0 up to comfortably past each format's fixed overhead,
//! with random content, many times over. A panic here is a real bug —
//! `Err` is the only correct response to malformed/adversarial input.

use ppose::admission::Invitation;
use ppose::admission::InviteVerifyingKey;
use ppose::admission::INVITATION_LEN;
use ppose::crypto::keys::IdentitySecret;
use ppose::network::forward::decode_forward_body;
use ppose::network::packet::decode_outer;
use ppose::onion::peel_layer;
use ppose::reliability::decode_inner;
use ppose::rendezvous::decode_reply;

/// Small deterministic PRNG (xorshift64) — no new dependency, and a fixed
/// seed keeps failures reproducible instead of flaking on CI.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }
}

/// Lengths from 0 up to comfortably past every format's fixed overhead
/// (the largest is `INVITATION_LEN` = 144 bytes), with a few `REPEATS`
/// random fills per length so content, not just length, varies.
fn each_length_and_fill(mut on_input: impl FnMut(&[u8])) {
    const REPEATS: usize = 4;
    let mut rng = Rng(0x9E3779B97F4A7C15);
    for len in 0..=200usize {
        for _ in 0..REPEATS {
            on_input(&rng.bytes(len));
        }
    }
}

#[test]
fn decode_outer_never_panics() {
    each_length_and_fill(|bytes| {
        let _ = decode_outer(bytes);
    });
}

#[test]
fn decode_inner_never_panics() {
    each_length_and_fill(|bytes| {
        let _ = decode_inner(bytes);
    });
}

#[test]
fn decode_forward_body_never_panics() {
    each_length_and_fill(|bytes| {
        let _ = decode_forward_body(bytes);
    });
}

#[test]
fn peel_layer_never_panics() {
    let local = IdentitySecret::from_bytes([0x42; 32]);
    each_length_and_fill(|bytes| {
        let _ = peel_layer(&local, bytes);
    });
}

#[test]
fn invitation_decode_never_panics() {
    each_length_and_fill(|bytes| {
        let _ = Invitation::decode(bytes);
    });
    // The 32-byte issuer prefix of a well-formed invitation must itself be
    // a shape `InviteVerifyingKey::from_bytes` can reject cleanly, not
    // just full 144-byte blobs — exercise exactly that length too.
    let mut rng = Rng(0xD1B54A32D192ED03);
    for _ in 0..64 {
        let bytes = rng.bytes(INVITATION_LEN);
        let _ = Invitation::decode(&bytes);
    }
}

#[test]
fn invite_verifying_key_from_bytes_never_panics() {
    let mut rng = Rng(0x2545F4914F6CDD1D);
    for _ in 0..500 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&rng.bytes(32));
        let _ = InviteVerifyingKey::from_bytes(key);
    }
}

#[test]
fn rendezvous_decode_reply_never_panics() {
    each_length_and_fill(|bytes| {
        let _ = decode_reply(bytes);
    });
}
