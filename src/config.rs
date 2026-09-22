//! Runtime knobs (not a security boundary).

use crate::cover::CoverMode;
use crate::MAX_DATAGRAM;

/// Process configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Wire version the process speaks.
    pub wire_version: u8,
    /// Soft datagram cap.
    pub mtu: usize,
    /// Cover policy.
    pub cover: CoverMode,
    /// Max onion hops this process will wrap.
    pub max_onion_hops: u8,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            wire_version: crate::PROTOCOL_VERSION,
            mtu: MAX_DATAGRAM,
            cover: CoverMode::Off,
            max_onion_hops: 3,
        }
    }
}

impl Config {
    /// Balanced cover preset.
    pub fn balanced() -> Self {
        Self {
            cover: CoverMode::Balanced,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let c = Config::default();
        assert_eq!(c.mtu, 1200);
        assert_eq!(c.cover, CoverMode::Off);
    }
}
