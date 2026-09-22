//! Inner plaintext frames carried inside Noise transport messages.

use thiserror::Error;

/// Maximum application bytes per DATA fragment.
///
/// Sized so that `outer(8) + forward(6) + noise_tag(16) + DATA_HDR + payload`
/// stays under [`crate::MAX_DATAGRAM`].
pub const MAX_PAYLOAD: usize = 1024;

/// DATA inner header: kind(1) + seq(4) + frag_id(2) + index(1) + total(1).
pub const DATA_HDR_LEN: usize = 9;

/// ACK inner size: kind(1) + base(4) + bitmap(8).
pub const ACK_LEN: usize = 13;

/// Inner frame after Noise decrypt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InnerFrame {
    /// Application fragment.
    Data {
        /// Per-session sequence number.
        seq: u32,
        /// Groups fragments of one application message.
        frag_id: u16,
        /// Zero-based fragment index.
        index: u8,
        /// Number of fragments in this message (`>= 1`).
        total: u8,
        /// Fragment payload.
        payload: Vec<u8>,
    },
    /// Selective ACK.
    Ack {
        /// Lowest sequence the receiver still considers its window base.
        base: u32,
        /// Bit `i` set ⇒ `base + i` received.
        bitmap: u64,
    },
}

/// Inner codec errors.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    /// Truncated buffer.
    #[error("truncated inner frame")]
    Truncated,
    /// Unknown kind byte.
    #[error("unknown inner kind")]
    BadKind,
    /// Fragment fields inconsistent.
    #[error("invalid fragment header")]
    BadFragment,
}

/// Encode a DATA inner frame.
pub fn encode_data(seq: u32, frag_id: u16, index: u8, total: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATA_HDR_LEN + payload.len());
    out.push(0x01);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&frag_id.to_be_bytes());
    out.push(index);
    out.push(total);
    out.extend_from_slice(payload);
    out
}

/// Encode an ACK inner frame.
pub fn encode_ack(base: u32, bitmap: u64) -> [u8; ACK_LEN] {
    let mut out = [0u8; ACK_LEN];
    out[0] = 0x02;
    out[1..5].copy_from_slice(&base.to_be_bytes());
    out[5..13].copy_from_slice(&bitmap.to_be_bytes());
    out
}

/// Decode an inner frame.
pub fn decode_inner(bytes: &[u8]) -> Result<InnerFrame, FrameError> {
    if bytes.is_empty() {
        return Err(FrameError::Truncated);
    }
    match bytes[0] {
        0x01 => {
            if bytes.len() < DATA_HDR_LEN {
                return Err(FrameError::Truncated);
            }
            let mut seq_b = [0u8; 4];
            seq_b.copy_from_slice(&bytes[1..5]);
            let seq = u32::from_be_bytes(seq_b);
            let mut fid_b = [0u8; 2];
            fid_b.copy_from_slice(&bytes[5..7]);
            let frag_id = u16::from_be_bytes(fid_b);
            let index = bytes[7];
            let total = bytes[8];
            if total == 0 || index >= total {
                return Err(FrameError::BadFragment);
            }
            Ok(InnerFrame::Data {
                seq,
                frag_id,
                index,
                total,
                payload: bytes[DATA_HDR_LEN..].to_vec(),
            })
        }
        0x02 => {
            if bytes.len() < ACK_LEN {
                return Err(FrameError::Truncated);
            }
            let mut base_b = [0u8; 4];
            base_b.copy_from_slice(&bytes[1..5]);
            let base = u32::from_be_bytes(base_b);
            let mut bm_b = [0u8; 8];
            bm_b.copy_from_slice(&bytes[5..13]);
            let bitmap = u64::from_be_bytes(bm_b);
            Ok(InnerFrame::Ack { base, bitmap })
        }
        _ => Err(FrameError::BadKind),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_roundtrip() {
        let enc = encode_data(7, 3, 0, 2, b"ab");
        match decode_inner(&enc).unwrap() {
            InnerFrame::Data {
                seq,
                frag_id,
                index,
                total,
                payload,
            } => {
                assert_eq!(seq, 7);
                assert_eq!(frag_id, 3);
                assert_eq!(index, 0);
                assert_eq!(total, 2);
                assert_eq!(payload, b"ab");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn ack_roundtrip() {
        let enc = encode_ack(10, 0b1011);
        match decode_inner(&enc).unwrap() {
            InnerFrame::Ack { base, bitmap } => {
                assert_eq!(base, 10);
                assert_eq!(bitmap, 0b1011);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
