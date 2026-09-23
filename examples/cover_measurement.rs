//! Measures the exact on-wire byte sizes of real ACK/DATA traffic versus
//! `CoverMode` cover packets, using the project's real encoding + a real
//! Noise XX session (not estimates). Replaces "unmeasured" with numbers.
//!
//! `docs/SPECIFICATION.md` §8 and `src/cover.rs` only ever claimed cover
//! traffic is size/timing *unmeasured* — this is that measurement's size
//! half. See the printed verdict for what it actually shows.

use ppose::cover::CoverMode;
use ppose::crypto::keys::IdentitySecret;
use ppose::crypto::noise::{HandshakeRole, NoiseSession};
use ppose::network::packet::{encode_datagram, PacketType};
use ppose::reliability::{encode_ack, encode_data, DATA_HDR_LEN};
use ppose::OUTER_HEADER_LEN;

/// Real Noise XX handshake between two fresh identities, transport mode.
fn handshake() -> (NoiseSession, NoiseSession) {
    let alice_id = IdentitySecret::generate();
    let bob_id = IdentitySecret::generate();
    let mut alice = NoiseSession::new(HandshakeRole::Initiator, &alice_id).unwrap();
    let mut bob = NoiseSession::new(HandshakeRole::Responder, &bob_id).unwrap();
    let mut buf_a = [0u8; 1024];
    let mut buf_b = [0u8; 1024];
    let mut tmp = [0u8; 1024];

    let n = alice.write_handshake(&[], &mut buf_a).unwrap();
    bob.read_handshake(&buf_a[..n], &mut tmp).unwrap();
    let n = bob.write_handshake(&[], &mut buf_b).unwrap();
    alice.read_handshake(&buf_b[..n], &mut tmp).unwrap();
    let n = alice.write_handshake(&[], &mut buf_a).unwrap();
    bob.read_handshake(&buf_a[..n], &mut tmp).unwrap();

    (alice, bob)
}

/// Exact wire size of a real DATA fragment carrying `chunk_len` app bytes,
/// as actually produced by `send_inner`/`seal_data` in `src/session.rs`:
/// outer header + Noise-sealed(inner DATA frame).
fn data_wire_len(sender: &mut NoiseSession, chunk_len: usize) -> usize {
    let payload = vec![0xABu8; chunk_len];
    let inner = encode_data(1, 1, 0, 1, &payload);
    let mut sealed = vec![0u8; inner.len() + 64];
    let n = sender.seal(&inner, &mut sealed).unwrap();
    encode_datagram(PacketType::Data, &sealed[..n])
        .unwrap()
        .len()
}

/// Exact wire size of a real ACK, same pipeline as above.
fn ack_wire_len(sender: &mut NoiseSession) -> usize {
    let inner = encode_ack(0, 0);
    let mut sealed = vec![0u8; inner.len() + 64];
    let n = sender.seal(&inner, &mut sealed).unwrap();
    encode_datagram(PacketType::Data, &sealed[..n])
        .unwrap()
        .len()
}

/// Wire-size range a cover packet can land in, as `UdpSession::maybe_cover`
/// actually builds it in `src/session.rs`: TYPE=Data around a
/// randomly-sized random body, with **no Noise seal** — bypassing the AEAD
/// layer real DATA/ACK go through.
fn cover_wire_len_range(mode: CoverMode) -> (usize, usize) {
    let (min, max) = mode.payload_len_range();
    let lo = encode_datagram(PacketType::Data, &vec![0u8; min])
        .unwrap()
        .len();
    let hi = encode_datagram(PacketType::Data, &vec![0u8; max])
        .unwrap()
        .len();
    (lo, hi)
}

fn main() {
    let (mut alice, _bob) = handshake();

    println!("Real traffic (TYPE=Data, Noise-sealed):");
    println!(
        "  outer header........... {} bytes (constant)",
        OUTER_HEADER_LEN
    );
    println!(
        "  inner DATA frame header {} bytes + chunk + 16-byte AEAD tag",
        DATA_HDR_LEN
    );
    let ack_len = ack_wire_len(&mut alice);
    println!("  ACK wire size........... {ack_len} bytes (constant)");
    for chunk_len in [8usize, 64, 256, 1024] {
        let len = data_wire_len(&mut alice, chunk_len);
        println!("  DATA wire size, {chunk_len:>4}B app chunk: {len} bytes");
    }

    println!("\nCover traffic (TYPE=Data, randomly-sized random body, no Noise seal):");
    for mode in [CoverMode::Balanced, CoverMode::Stealth] {
        let (lo, hi) = cover_wire_len_range(mode);
        println!("  {mode:?} cover wire size range: {lo}..={hi} bytes (uniform, per packet)");
    }

    let (cover_lo, cover_hi) = cover_wire_len_range(CoverMode::Balanced);
    println!("\nVerdict:");
    println!(
        "  Cover wire size now varies ({cover_lo}..={cover_hi} bytes for Balanced) and \
         overlaps real DATA's range (41..=1057 bytes above), instead of the single fixed \
         72-byte packet this mode used to always produce. This is a partial mitigation, \
         not distribution-matching: the range was chosen to overlap plausible real sizes, \
         not measured against any specific application's actual traffic — a patient \
         observer with enough samples can still likely tell cover's distribution (uniform \
         over a fixed range) apart from real traffic's (whatever the application actually \
         sends). Real ACKs stay a separate fixed {ack_len}-byte size either way; nothing \
         about cover traffic touches that."
    );
}
