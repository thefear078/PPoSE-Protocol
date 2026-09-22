//! Cover-traffic policy. Cover datagrams use TYPE=Data with random bytes
//! so they are indistinguishable from encrypted payloads to a path observer.
//! Receivers drop them because Noise decryption fails.
//!
//! This does **not** defeat a global passive adversary; it only raises the
//! bar for naive size/timing on a single path. Unmeasured.

use std::time::Duration;

/// Cover-traffic mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CoverMode {
    /// No cover packets.
    #[default]
    Off,
    /// ~200 ms idle cadence, small random payloads.
    Balanced,
    /// ~50 ms idle cadence.
    Stealth,
}

impl CoverMode {
    /// Idle interval between cover packets.
    pub fn interval(self) -> Option<Duration> {
        match self {
            Self::Off => None,
            Self::Balanced => Some(Duration::from_millis(200)),
            Self::Stealth => Some(Duration::from_millis(50)),
        }
    }

    /// Cover payload length (bytes of Noise-looking body).
    pub fn payload_len(self) -> usize {
        match self {
            Self::Off => 0,
            Self::Balanced | Self::Stealth => 64,
        }
    }
}
