//! Rate limiting per identity and category (port of `ratelimit.py`, FR-6.8).

use std::collections::{HashMap, VecDeque};

use indexmap::IndexMap;
use parking_lot::Mutex;

use crate::tier1::RateLimit;

/// Sliding window, in memory.
///
/// Sufficient for a handful of agents in a single container; gatekeeper
/// runs as a single instance per §14. Internally locked, so a shared
/// `&RateLimiter` can be used from any task.
#[derive(Debug)]
pub struct RateLimiter {
    limits: IndexMap<String, RateLimit>,
    events: Mutex<HashMap<(String, String), VecDeque<f64>>>,
}

impl RateLimiter {
    pub fn new(limits: IndexMap<String, RateLimit>) -> Self {
        RateLimiter { limits, events: Mutex::new(HashMap::new()) }
    }

    /// Registers a call. `false` = limit reached.
    pub fn check(&self, identity: &str, category: &str) -> bool {
        self.check_at(identity, category, crate::timeutil::monotonic())
    }

    /// [`check`](Self::check) at an explicit monotonic time (for tests).
    pub fn check_at(&self, identity: &str, category: &str, now: f64) -> bool {
        let Some(limit) = self.limits.get(category) else {
            return true;
        };
        let mut events = self.events.lock();
        let window = events.entry((identity.to_string(), category.to_string())).or_default();
        let cutoff = now - limit.window_seconds as f64;
        while window.front().is_some_and(|t| *t < cutoff) {
            window.pop_front();
        }
        if window.len() as i64 >= limit.count {
            return false;
        }
        window.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(count: i64, window: i64) -> RateLimiter {
        let mut limits = IndexMap::new();
        limits.insert("read".to_string(), RateLimit { count, window_seconds: window });
        RateLimiter::new(limits)
    }

    #[test]
    fn sliding_window() {
        let rl = limiter(2, 10);
        assert!(rl.check_at("a", "read", 100.0));
        assert!(rl.check_at("a", "read", 101.0));
        assert!(!rl.check_at("a", "read", 102.0));
        // Another identity has its own window.
        assert!(rl.check_at("b", "read", 102.0));
        // The first event left the window.
        assert!(rl.check_at("a", "read", 110.5));
        // Unknown category: unlimited.
        for _ in 0..10 {
            assert!(rl.check_at("a", "other", 1.0));
        }
    }

    #[test]
    fn real_clock() {
        let rl = limiter(1, 60);
        assert!(rl.check("x", "read"));
        assert!(!rl.check("x", "read"));
    }
}
