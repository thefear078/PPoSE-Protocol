//! Bounded replay cache for forwarders.
//!
//! Stores truncated BLAKE3 of recently forwarded **inner** datagrams with a TTL.
//! This is ephemeral anti-DoS state — not a circuit table.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Default TTL for remembered packet hashes.
pub const DEFAULT_TTL: Duration = Duration::from_secs(30);

/// Default maximum distinct hashes retained.
pub const DEFAULT_CAP: usize = 4096;

/// Hash-and-TTL replay filter.
pub struct ReplayCache {
    seen: HashMap<[u8; 16], Instant>,
    ttl: Duration,
    cap: usize,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayCache {
    /// New cache with default TTL and capacity.
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
            ttl: DEFAULT_TTL,
            cap: DEFAULT_CAP,
        }
    }

    /// Construct with explicit bounds.
    pub fn with_bounds(ttl: Duration, cap: usize) -> Self {
        Self {
            seen: HashMap::new(),
            ttl,
            cap,
        }
    }

    /// Returns `true` if `inner` was not seen recently and is now recorded.
    pub fn accept(&mut self, inner: &[u8], now: Instant) -> bool {
        self.expire(now);
        let mut key = [0u8; 16];
        key.copy_from_slice(&blake3::hash(inner).as_bytes()[..16]);
        if self.seen.contains_key(&key) {
            return false;
        }
        if self.seen.len() >= self.cap {
            if let Some(oldest) = self.seen.iter().min_by_key(|(_, t)| *t).map(|(k, _)| *k) {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(key, now);
        true
    }

    fn expire(&mut self, now: Instant) {
        self.seen
            .retain(|_, t| now.saturating_duration_since(*t) < self.ttl);
    }

    /// Occupancy (tests).
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rejects_duplicate() {
        let mut c = ReplayCache::with_bounds(Duration::from_secs(10), 8);
        let now = Instant::now();
        assert!(c.accept(b"pkt", now));
        assert!(!c.accept(b"pkt", now));
        assert!(c.accept(b"other", now));
    }

    #[test]
    fn ttl_expires() {
        let mut c = ReplayCache::with_bounds(Duration::from_millis(5), 8);
        let t0 = Instant::now();
        assert!(c.accept(b"pkt", t0));
        assert!(!c.accept(b"pkt", t0 + Duration::from_millis(1)));
        assert!(c.accept(b"pkt", t0 + Duration::from_millis(10)));
    }
}
