//! Selective-repeat ARQ with pre-encryption fragmentation.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use thiserror::Error;

use super::frame::{decode_inner, encode_ack, encode_data, FrameError, InnerFrame, MAX_PAYLOAD};

/// Sliding window (packets).
pub const WINDOW_SIZE: u32 = 32;

/// Default retransmit timeout.
pub const DEFAULT_RETX: Duration = Duration::from_millis(200);

/// Default give-up after this many sends (1 original + retries).
pub const DEFAULT_MAX_ATTEMPTS: u8 = 5;

/// Maximum number of distinct in-progress fragment reassemblies kept at
/// once. Without a cap, a peer that has already completed the Noise
/// handshake (this is endpoint state, never seen by a relay) could send
/// DATA fragments across many distinct `frag_id`s and never complete any
/// of them, growing `Arq::fragments` without bound — each entry can hold
/// up to 255 payload-sized slots. Oldest-inserted entries are evicted once
/// this cap is reached; see `Arq::on_data`.
const MAX_PENDING_FRAGMENTS: usize = 64;

/// ARQ errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ArqError {
    /// Application message exceeds 255 fragments of `max_fragment` bytes.
    #[error("message too large to fragment")]
    TooLarge,
    /// Inner frame codec.
    #[error("inner frame: {0}")]
    Frame(FrameError),
}

impl From<FrameError> for ArqError {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}

struct Outgoing {
    plaintext: Vec<u8>,
    last_sent: Option<Instant>,
    attempts: u8,
}

struct FragBuf {
    total: u8,
    parts: Vec<Option<Vec<u8>>>,
}

/// Endpoint ARQ state machine.
pub struct Arq {
    next_seq: u32,
    next_frag_id: u16,
    unacked: BTreeMap<u32, Outgoing>,
    recv_base: u32,
    recv_bits: u64,
    fragments: HashMap<u16, FragBuf>,
    /// Insertion order of keys in `fragments`, for bounded FIFO eviction.
    /// May contain stale entries for `frag_id`s already removed from
    /// `fragments` (completed reassembly) — `on_data` tolerates that.
    fragment_order: VecDeque<u16>,
    delivered: VecDeque<Vec<u8>>,
    pending_ack: bool,
    max_attempts: u8,
    retx: Duration,
    max_fragment: usize,
}

impl Default for Arq {
    fn default() -> Self {
        Self::new()
    }
}

impl Arq {
    /// New ARQ state.
    pub fn new() -> Self {
        Self {
            next_seq: 0,
            next_frag_id: 1,
            unacked: BTreeMap::new(),
            recv_base: 0,
            recv_bits: 0,
            fragments: HashMap::new(),
            fragment_order: VecDeque::new(),
            delivered: VecDeque::new(),
            pending_ack: false,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            retx: DEFAULT_RETX,
            max_fragment: MAX_PAYLOAD,
        }
    }

    /// Cap outgoing fragment payloads at `n` bytes (clamped to
    /// `1..=MAX_PAYLOAD`). Paths that add per-packet overhead — onion hops
    /// especially — need smaller fragments so each sealed, wrapped DATA
    /// frame still fits `MAX_DATAGRAM`. Only affects this side's sending;
    /// the receiver reassembles fragments of any size.
    pub fn set_max_fragment(&mut self, n: usize) {
        self.max_fragment = n.clamp(1, MAX_PAYLOAD);
    }

    /// Current outgoing fragment payload cap.
    pub fn max_fragment(&self) -> usize {
        self.max_fragment
    }

    /// Queue an application message (fragmented if needed).
    ///
    /// Returns the inner plaintexts that must be Noise-sealed and sent now
    /// (those that fit in the send window). Remaining fragments stay queued
    /// in `unacked` with `last_sent = None` until the window advances — they
    /// are produced by [`Arq::take_new_sends`].
    pub fn enqueue(&mut self, message: &[u8]) -> Result<(), ArqError> {
        if message.is_empty() {
            self.enqueue_one(message)?;
            return Ok(());
        }
        let chunks: Vec<&[u8]> = message.chunks(self.max_fragment).collect();
        if chunks.len() > 255 {
            return Err(ArqError::TooLarge);
        }
        let total = chunks.len() as u8;
        let frag_id = self.next_frag_id;
        self.next_frag_id = self.next_frag_id.wrapping_add(1);
        if self.next_frag_id == 0 {
            self.next_frag_id = 1;
        }
        for (i, chunk) in chunks.into_iter().enumerate() {
            let seq = self.next_seq;
            self.next_seq = self.next_seq.wrapping_add(1);
            let plaintext = encode_data(seq, frag_id, i as u8, total, chunk);
            self.unacked.insert(
                seq,
                Outgoing {
                    plaintext,
                    last_sent: None,
                    attempts: 0,
                },
            );
        }
        Ok(())
    }

    fn enqueue_one(&mut self, message: &[u8]) -> Result<(), ArqError> {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let plaintext = encode_data(seq, 0, 0, 1, message);
        self.unacked.insert(
            seq,
            Outgoing {
                plaintext,
                last_sent: None,
                attempts: 0,
            },
        );
        Ok(())
    }

    fn in_flight_sent(&self) -> u32 {
        self.unacked
            .values()
            .filter(|o| o.last_sent.is_some())
            .count() as u32
    }

    /// Inner frames that have never been sent and fit in the window.
    pub fn take_new_sends(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut sent = self.in_flight_sent();
        let keys: Vec<u32> = self.unacked.keys().copied().collect();
        for seq in keys {
            if sent >= WINDOW_SIZE {
                break;
            }
            let slot = self.unacked.get_mut(&seq).expect("key");
            if slot.last_sent.is_some() {
                continue;
            }
            slot.last_sent = Some(now);
            slot.attempts = 1;
            out.push(slot.plaintext.clone());
            sent += 1;
        }
        out
    }

    /// Retransmit due packets (same inner plaintext, new Noise seal at caller).
    pub fn take_retransmits(&mut self, now: Instant) -> Result<Vec<Vec<u8>>, ArqGiveUp> {
        let mut out = Vec::new();
        let keys: Vec<u32> = self.unacked.keys().copied().collect();
        for seq in keys {
            let slot = self.unacked.get_mut(&seq).expect("key");
            let Some(last) = slot.last_sent else {
                continue;
            };
            if now.saturating_duration_since(last) < self.retx {
                continue;
            }
            if slot.attempts >= self.max_attempts {
                return Err(ArqGiveUp {
                    seq,
                    attempts: slot.attempts,
                });
            }
            slot.attempts += 1;
            slot.last_sent = Some(now);
            out.push(slot.plaintext.clone());
        }
        Ok(out)
    }

    /// Handle a decrypted inner frame. Returns ACK plaintext if one should be sent.
    pub fn ingest(
        &mut self,
        plaintext: &[u8],
    ) -> Result<Option<[u8; super::frame::ACK_LEN]>, ArqError> {
        match decode_inner(plaintext)? {
            InnerFrame::Ack { base, bitmap } => {
                self.on_ack(base, bitmap);
                Ok(None)
            }
            InnerFrame::Data {
                seq,
                frag_id,
                index,
                total,
                payload,
            } => {
                self.on_data(seq, frag_id, index, total, payload);
                self.pending_ack = true;
                Ok(Some(encode_ack(self.recv_base, self.recv_bits)))
            }
        }
    }

    fn on_ack(&mut self, base: u32, bitmap: u64) {
        let keys: Vec<u32> = self.unacked.keys().copied().collect();
        for seq in keys {
            if acked(base, bitmap, seq) {
                self.unacked.remove(&seq);
            }
        }
    }

    fn on_data(&mut self, seq: u32, frag_id: u16, index: u8, total: u8, payload: Vec<u8>) {
        if !self.mark_received(seq) {
            return;
        }
        if total == 1 {
            self.delivered.push_back(payload);
            return;
        }
        if !self.fragments.contains_key(&frag_id) {
            while self.fragments.len() >= MAX_PENDING_FRAGMENTS {
                let Some(oldest) = self.fragment_order.pop_front() else {
                    break;
                };
                // No-op if `oldest` already completed and was removed below;
                // the loop keeps popping until an eviction actually frees a
                // slot, or the order queue itself runs dry.
                self.fragments.remove(&oldest);
            }
            self.fragment_order.push_back(frag_id);
            self.fragments.insert(
                frag_id,
                FragBuf {
                    total,
                    parts: vec![None; total as usize],
                },
            );
        }
        let buf = self
            .fragments
            .get_mut(&frag_id)
            .expect("just inserted or already present above");
        if buf.total != total || (index as usize) >= buf.parts.len() {
            return;
        }
        buf.parts[index as usize] = Some(payload);
        if buf.parts.iter().all(Option::is_some) {
            let mut full = Vec::new();
            for part in buf.parts.iter().flatten() {
                full.extend_from_slice(part);
            }
            self.fragments.remove(&frag_id);
            if self.fragment_order.front() == Some(&frag_id) {
                self.fragment_order.pop_front();
            }
            self.delivered.push_back(full);
        }
    }

    /// Returns true if this is a newly accepted seq in the receive window.
    fn mark_received(&mut self, seq: u32) -> bool {
        let ahead = seq.wrapping_sub(self.recv_base);
        if ahead >= 64 {
            return false;
        }
        let bit = 1u64 << ahead;
        if self.recv_bits & bit != 0 {
            return false;
        }
        self.recv_bits |= bit;
        while self.recv_bits & 1 == 1 {
            self.recv_base = self.recv_base.wrapping_add(1);
            self.recv_bits >>= 1;
        }
        true
    }

    /// Pop a fully reassembled application message.
    pub fn pop_delivered(&mut self) -> Option<Vec<u8>> {
        self.delivered.pop_front()
    }

    /// True if an ACK should be written.
    pub fn take_ack(&mut self) -> Option<[u8; super::frame::ACK_LEN]> {
        if !self.pending_ack {
            return None;
        }
        self.pending_ack = false;
        Some(encode_ack(self.recv_base, self.recv_bits))
    }

    /// Unacked count (debug / tests).
    pub fn unacked_len(&self) -> usize {
        self.unacked.len()
    }

    /// Shorten retransmit timeout (tests).
    pub fn set_retx(&mut self, d: Duration) {
        self.retx = d;
    }
}

/// Give-up after too many retransmits.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("gave up on seq {seq} after {attempts} attempts")]
pub struct ArqGiveUp {
    /// Sequence that exhausted retries.
    pub seq: u32,
    /// Attempts used.
    pub attempts: u8,
}

fn acked(base: u32, bitmap: u64, seq: u32) -> bool {
    let ahead = seq.wrapping_sub(base);
    if ahead < 64 {
        (bitmap >> ahead) & 1 == 1
    } else {
        let behind = base.wrapping_sub(seq);
        behind > 0 && behind < 1_000_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn in_order_delivery() {
        let mut a = Arq::new();
        let mut b = Arq::new();
        a.enqueue(b"hello").unwrap();
        let now = Instant::now();
        for pt in a.take_new_sends(now) {
            let ack = b.ingest(&pt).unwrap();
            if let Some(ack) = ack {
                a.ingest(&ack).unwrap();
            }
        }
        assert_eq!(b.pop_delivered().unwrap(), b"hello");
        assert_eq!(a.unacked_len(), 0);
    }

    #[test]
    fn recovers_from_loss() {
        let mut a = Arq::new();
        let mut b = Arq::new();
        a.set_retx(Duration::from_millis(1));
        a.enqueue(b"one").unwrap();
        a.enqueue(b"two").unwrap();
        let t0 = Instant::now();
        let sends = a.take_new_sends(t0);
        assert_eq!(sends.len(), 2);
        // drop first, deliver second (independent messages deliver out of order)
        let ack = b.ingest(&sends[1]).unwrap().unwrap();
        a.ingest(&ack).unwrap();
        assert_eq!(b.pop_delivered().as_deref(), Some(&b"two"[..]));
        let t1 = t0 + Duration::from_millis(5);
        let retrx = a.take_retransmits(t1).unwrap();
        assert_eq!(retrx.len(), 1);
        let ack = b.ingest(&retrx[0]).unwrap().unwrap();
        a.ingest(&ack).unwrap();
        assert_eq!(b.pop_delivered().as_deref(), Some(&b"one"[..]));
        assert_eq!(a.unacked_len(), 0);
    }

    #[test]
    fn fragment_reassembly_is_bounded() {
        // A peer that already completed the Noise handshake (this is
        // endpoint state, never seen by an unauthenticated stranger) could
        // otherwise send DATA fragments across unboundedly many distinct
        // frag_ids and never complete any of them. Confirms the fix: the
        // reassembly table stays capped even after well over
        // MAX_PENDING_FRAGMENTS distinct, never-completed fragments.
        let mut b = Arq::new();
        let total_frags: u32 = MAX_PENDING_FRAGMENTS as u32 + 20;
        for frag_id in 0..total_frags {
            let pt = encode_data(frag_id, frag_id as u16, 0, 2, b"never completed");
            assert!(b.ingest(&pt).unwrap().is_some());
        }
        assert!(
            b.fragments.len() <= MAX_PENDING_FRAGMENTS,
            "fragment table must stay bounded, got {}",
            b.fragments.len()
        );
        assert!(b.pop_delivered().is_none());
    }

    #[test]
    fn fragments_reassemble() {
        let mut a = Arq::new();
        let mut b = Arq::new();
        let big = vec![7u8; MAX_PAYLOAD + 50];
        a.enqueue(&big).unwrap();
        let now = Instant::now();
        for pt in a.take_new_sends(now) {
            if let Some(ack) = b.ingest(&pt).unwrap() {
                a.ingest(&ack).unwrap();
            }
        }
        assert_eq!(b.pop_delivered().unwrap(), big);
    }
}
