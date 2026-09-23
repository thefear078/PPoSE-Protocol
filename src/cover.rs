//! Cover-traffic policy. Cover datagrams use TYPE=Data with random bytes
//! so they are indistinguishable from encrypted payloads to a path observer
//! *by content* (both are uniformly random bytes). They are **not**
//! indistinguishable by timing (fixed cadence) or, until this module
//! randomized the length, by size either: a fixed-length cover packet is a
//! statistical fingerprint next to the variable size of real DATA
//! fragments. See `examples/cover_measurement.rs` for the measured
//! comparison and `docs/SPECIFICATION.md` §8 for the honest scope of what
//! this does and does not achieve. Receivers drop cover packets because
//! Noise decryption fails (they were never Noise-sealed to begin with).
//!
//! This does **not** defeat a global passive adversary; it only raises the
//! bar for naive size/timing correlation on a single path.

use std::time::Duration;

/// Cover-traffic mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CoverMode {
    /// No cover packets.
    #[default]
    Off,
    /// ~200 ms idle cadence, small-to-medium random payloads.
    Balanced,
    /// ~50 ms idle cadence.
    Stealth,
}

impl CoverMode {
    /// Inclusive range the idle interval before the next cover packet is
    /// drawn from (uniformly, per packet — see
    /// `UdpSession::schedule_next_cover`), or `None` if cover is off.
    ///
    /// A single fixed interval (v0.4 used exactly 200 ms / 50 ms) makes
    /// cover cadence a pure periodic signal an observer can pick out with
    /// simple inter-arrival-time analysis, independent of the size
    /// randomization above. Jittering the interval is, like the size
    /// range, a partial mitigation — real traffic's timing isn't uniform
    /// either, it's whatever the application actually does — not a fix
    /// against a patient statistical observer.
    pub fn interval_range(self) -> Option<(Duration, Duration)> {
        match self {
            Self::Off => None,
            Self::Balanced => Some((Duration::from_millis(120), Duration::from_millis(280))),
            Self::Stealth => Some((Duration::from_millis(30), Duration::from_millis(70))),
        }
    }

    /// Inclusive byte-length range a cover payload's length should be drawn
    /// from (uniformly, per packet — see `UdpSession::maybe_cover`).
    ///
    /// A fixed length here would make every cover packet the same
    /// `OUTER_HEADER_LEN + n` bytes on the wire regardless of mode, which
    /// `examples/cover_measurement.rs` shows is trivially distinguishable
    /// from both real ACKs (their own different fixed size) and real DATA
    /// fragments (which vary with the application chunk size). This range
    /// is a partial mitigation, not distribution-matching: it was chosen to
    /// overlap real DATA's plausible size range, not measured against any
    /// specific application's actual traffic.
    pub fn payload_len_range(self) -> (usize, usize) {
        match self {
            Self::Off => (0, 0),
            Self::Balanced => (16, 512),
            Self::Stealth => (16, 256),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_are_well_formed() {
        for mode in [CoverMode::Off, CoverMode::Balanced, CoverMode::Stealth] {
            let (min, max) = mode.payload_len_range();
            assert!(
                min <= max,
                "{mode:?} range must be non-empty: {min}..={max}"
            );
        }
        assert_eq!(CoverMode::Off.payload_len_range(), (0, 0));
        assert_eq!(CoverMode::Off.interval_range(), None);
    }

    #[test]
    fn interval_ranges_are_well_formed() {
        for mode in [CoverMode::Balanced, CoverMode::Stealth] {
            let (min, max) = mode.interval_range().unwrap();
            assert!(min <= max, "{mode:?} interval range must be non-empty");
        }
    }

    #[test]
    fn active_modes_have_an_interval() {
        assert!(CoverMode::Balanced.interval_range().is_some());
        assert!(CoverMode::Stealth.interval_range().is_some());
    }
}
