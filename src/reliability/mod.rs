//! Reliable datagram layer (L6): ACK, reorder, fragmentation.

/// Default sliding window size (packets) per spec §9.1.
pub const DEFAULT_WINDOW_SIZE: u32 = 32;

/// Retransmit timeout in milliseconds per spec §9.1.
pub const DEFAULT_RETX_TIMEOUT_MS: u64 = 200;

/// Maximum retransmit attempts per spec §9.1.
pub const DEFAULT_MAX_RETX: u8 = 5;
