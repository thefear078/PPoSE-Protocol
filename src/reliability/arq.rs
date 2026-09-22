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

/// ARQ errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ArqError {
    /// Application message exceeds `MAX_PAYLOAD * 255`.
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
    delivered: VecDeque<Vec<u8>>,
    pending_ack: bool,
    max_attempts: u8,
    retx: Duration,
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
            delivered: VecDeque::new(),
            pending_ack: false,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            retx: DEFAULT_RETX,
        }
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
        let chunks: Vec<&[u8]> = message.chunks(MAX_PAYLOAD).collect();
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
        let buf = self.fragments.entry(frag_id).or_insert_with(|| FragBuf {
            total,
            parts: vec![None; total as usize],
        });
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
