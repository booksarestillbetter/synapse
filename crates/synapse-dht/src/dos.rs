//! Abuse limits for the DHT's UDP socket: a per-source-IP message rate limiter and a
//! global cap on how many reply bytes we send per second.
//!
//! A DHT node answers unauthenticated UDP from anyone, so without these it is both a
//! CPU/memory sink (floods of queries) and a traffic amplifier (small spoofed query, large
//! reply). The numbers follow libtorrent's `dos_blocker` and DHT upload limit.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Length of the measurement window.
const WINDOW: Duration = Duration::from_secs(10);
/// Messages allowed per source in one window: an average of 5 per second.
const MAX_MESSAGES_PER_WINDOW: u32 = 50;
/// How long a source that exceeded the rate is ignored.
const BLOCK_DURATION: Duration = Duration::from_secs(5 * 60);
/// Sources tracked at once. Bounded so spoofed-source floods cannot grow the table.
const MAX_TRACKED_SOURCES: usize = 4096;

struct Entry {
    window_start: Instant,
    count: u32,
    blocked_until: Option<Instant>,
}

pub struct DosBlocker {
    entries: HashMap<IpAddr, Entry>,
    pub blocked_count: u64,
}

impl Default for DosBlocker {
    fn default() -> Self {
        Self::new()
    }
}

impl DosBlocker {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            blocked_count: 0,
        }
    }

    /// Records one incoming message from `ip` and returns whether it should be processed.
    /// Loopback is never limited (local tooling, tests).
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        if ip.is_loopback() {
            return true;
        }
        if self.entries.len() >= MAX_TRACKED_SOURCES && !self.entries.contains_key(&ip) {
            self.evict(now);
        }
        let e = self.entries.entry(ip).or_insert(Entry {
            window_start: now,
            count: 0,
            blocked_until: None,
        });
        if let Some(until) = e.blocked_until {
            if now < until {
                self.blocked_count += 1;
                return false;
            }
            e.blocked_until = None;
            e.window_start = now;
            e.count = 0;
        }
        if now.duration_since(e.window_start) >= WINDOW {
            e.window_start = now;
            e.count = 0;
        }
        e.count += 1;
        if e.count > MAX_MESSAGES_PER_WINDOW {
            e.blocked_until = Some(now + BLOCK_DURATION);
            self.blocked_count += 1;
            return false;
        }
        true
    }

    pub fn blocked_count(&self) -> u64 {
        self.blocked_count
    }

    pub fn is_blocked(&self, ip: IpAddr, now: Instant) -> bool {
        self.entries
            .get(&ip)
            .and_then(|e| e.blocked_until)
            .is_some_and(|until| now < until)
    }

    /// Makes room: drops expired windows first, then the stalest non-blocked entry.
    fn evict(&mut self, now: Instant) {
        self.entries.retain(|_, e| {
            e.blocked_until.is_some_and(|u| now < u) || now.duration_since(e.window_start) < WINDOW
        });
        if self.entries.len() >= MAX_TRACKED_SOURCES {
            if let Some(&victim) = self
                .entries
                .iter()
                .filter(|(_, e)| e.blocked_until.is_none())
                .min_by_key(|(_, e)| e.window_start)
                .map(|(ip, _)| ip)
            {
                self.entries.remove(&victim);
            }
        }
    }
}

/// Token bucket over reply bytes: at most `RATE` bytes/second on average with a burst of
/// `BURST`, so a flood of spoofed-source queries cannot turn us into an amplifier.
pub struct ReplyQuota {
    tokens: f64,
    last: Instant,
}

const REPLY_RATE_BYTES_PER_SEC: f64 = 8000.0;
const REPLY_BURST_BYTES: f64 = 16_000.0;

impl ReplyQuota {
    pub fn new(now: Instant) -> Self {
        Self {
            tokens: REPLY_BURST_BYTES,
            last: now,
        }
    }

    /// Returns whether a reply of `len` bytes may be sent now, and charges it if so.
    pub fn try_consume(&mut self, len: usize, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * REPLY_RATE_BYTES_PER_SEC).min(REPLY_BURST_BYTES);
        if self.tokens >= len as f64 {
            self.tokens -= len as f64;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([198, 51, 100, n])
    }

    #[test]
    fn a_source_over_the_rate_is_blocked_for_five_minutes_then_released() {
        let mut d = DosBlocker::new();
        let t0 = Instant::now();
        for i in 0..MAX_MESSAGES_PER_WINDOW {
            assert!(d.allow(ip(1), t0), "message {i} within the budget");
        }
        assert!(
            !d.allow(ip(1), t0),
            "the 51st message in a window trips the block"
        );
        assert!(d.is_blocked(ip(1), t0));
        assert!(
            !d.allow(ip(1), t0 + Duration::from_secs(299)),
            "still blocked"
        );
        assert!(
            d.allow(ip(1), t0 + Duration::from_secs(301)),
            "released after 5 minutes"
        );
        // Other sources are unaffected throughout.
        assert!(d.allow(ip(2), t0));
    }

    #[test]
    fn a_steady_well_behaved_rate_is_never_blocked() {
        let mut d = DosBlocker::new();
        let t0 = Instant::now();
        for s in 0..600u64 {
            // 4 messages a second for ten minutes.
            for _ in 0..4 {
                assert!(d.allow(ip(1), t0 + Duration::from_secs(s)));
            }
        }
    }

    #[test]
    fn loopback_is_exempt() {
        let mut d = DosBlocker::new();
        let t0 = Instant::now();
        for _ in 0..10_000 {
            assert!(d.allow(IpAddr::from([127, 0, 0, 1]), t0));
        }
    }

    #[test]
    fn tracking_table_stays_bounded_under_a_spoofed_source_flood() {
        let mut d = DosBlocker::new();
        let t0 = Instant::now();
        for n in 0..(MAX_TRACKED_SOURCES as u32 * 3) {
            d.allow(
                IpAddr::from([10 + (n >> 16) as u8, (n >> 8) as u8, n as u8, 1]),
                t0,
            );
        }
        assert!(d.entries.len() <= MAX_TRACKED_SOURCES);
    }

    #[test]
    fn reply_quota_limits_bytes_and_refills_over_time() {
        let t0 = Instant::now();
        let mut q = ReplyQuota::new(t0);
        assert!(q.try_consume(16_000, t0), "the burst is available");
        assert!(!q.try_consume(1, t0), "then it is exhausted");
        assert!(
            q.try_consume(8000, t0 + Duration::from_secs(1)),
            "8000 B/s refill"
        );
        assert!(!q.try_consume(100, t0 + Duration::from_secs(1)));
    }
}
