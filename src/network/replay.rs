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

/// How many `accept` calls between full sweeps of stale entries, when not
/// forced sooner by hitting `cap`. Duplicate detection itself never depends
/// on a sweep having run — see `accept`'s per-key TTL check — so throttling
/// this only delays memory reclamation, not correctness.
const SWEEP_EVERY: u32 = 64;

/// Hash-and-TTL replay filter.
pub struct ReplayCache {
    seen: HashMap<[u8; 16], Instant>,
    ttl: Duration,
    cap: usize,
    calls_since_sweep: u32,
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
            calls_since_sweep: 0,
        }
    }

    /// Construct with explicit bounds.
    pub fn with_bounds(ttl: Duration, cap: usize) -> Self {
        Self {
            seen: HashMap::new(),
            ttl,
            cap,
            calls_since_sweep: 0,
        }
    }

    /// Returns `true` if `inner` was not seen recently and is now recorded.
    pub fn accept(&mut self, inner: &[u8], now: Instant) -> bool {
        let mut key = [0u8; 16];
        key.copy_from_slice(&blake3::hash(inner).as_bytes()[..16]);

        let live_duplicate = self
            .seen
            .get(&key)
            .is_some_and(|seen_at| now.saturating_duration_since(*seen_at) < self.ttl);
        if live_duplicate {
            return false;
        }

        self.calls_since_sweep += 1;
        if self.calls_since_sweep >= SWEEP_EVERY || self.seen.len() >= self.cap {
            self.calls_since_sweep = 0;
            self.expire(now);
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

    #[test]
    fn ttl_correctness_survives_throttled_sweep() {
        // Regression guard: duplicate/TTL correctness must not depend on how
        // often the background sweep runs, only on SWEEP_EVERY's *memory
        // reclamation*, so this pins the latter down too.
        let mut c = ReplayCache::with_bounds(Duration::from_millis(5), 100_000);
        let t0 = Instant::now();
        assert!(c.accept(b"pkt", t0));
        // Exercise well under SWEEP_EVERY calls so no sweep is forced by
        // count; correctness must hold on the very next call regardless.
        assert!(!c.accept(b"pkt", t0 + Duration::from_millis(1)));
        assert!(c.accept(b"pkt", t0 + Duration::from_millis(10)));
    }

    #[test]
    fn sweep_reclaims_stale_entries_over_many_calls() {
        let ttl = Duration::from_millis(1);
        let mut c = ReplayCache::with_bounds(ttl, 100_000);
        let t0 = Instant::now();
        for i in 0..200u32 {
            assert!(c.accept(&i.to_be_bytes(), t0));
        }
        assert_eq!(c.len(), 200);
        // Long past ttl and well past SWEEP_EVERY (64) calls: a sweep must
        // have run and reclaimed the now-stale entries above.
        let t_far = t0 + Duration::from_secs(1);
        for i in 200..264u32 {
            c.accept(&i.to_be_bytes(), t_far);
        }
        assert!(c.len() < 200, "sweep should have reclaimed stale entries");
    }
}
