//! Token-Bucket Bandwidth Rate Limiter.
//!
//! Provides lockless and async token-bucket rate limiting for global and per-swarm
//! upload and download bandwidth management.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Debug)]
pub struct TokenBucket {
    rate_bytes_per_sec: AtomicU64,
    capacity_bytes: AtomicU64,
    tokens: AtomicI64,
    last_update: parking_lot::Mutex<Instant>,
}

impl TokenBucket {
    pub fn new(rate_bytes_per_sec: u64, burst_bytes: u64) -> Self {
        Self {
            rate_bytes_per_sec: AtomicU64::new(rate_bytes_per_sec),
            capacity_bytes: AtomicU64::new(burst_bytes.max(rate_bytes_per_sec)),
            tokens: AtomicI64::new(burst_bytes.max(rate_bytes_per_sec) as i64),
            last_update: parking_lot::Mutex::new(Instant::now()),
        }
    }

    pub fn unthrottled() -> Self {
        Self::new(0, 0)
    }

    pub fn is_throttled(&self) -> bool {
        self.rate_bytes_per_sec.load(Ordering::Relaxed) > 0
    }

    pub fn set_rate(&self, rate_bytes_per_sec: u64, burst_bytes: u64) {
        self.rate_bytes_per_sec.store(rate_bytes_per_sec, Ordering::Relaxed);
        let cap = burst_bytes.max(rate_bytes_per_sec);
        self.capacity_bytes.store(cap, Ordering::Relaxed);
    }

    fn refill(&self) {
        let rate = self.rate_bytes_per_sec.load(Ordering::Relaxed);
        if rate == 0 {
            return;
        }

        let mut last = self.last_update.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(*last);

        let added_tokens = (elapsed.as_secs_f64() * rate as f64) as i64;
        if added_tokens > 0 {
            let cap = self.capacity_bytes.load(Ordering::Relaxed) as i64;
            let current = self.tokens.load(Ordering::Relaxed);
            let new_val = (current + added_tokens).min(cap);
            self.tokens.store(new_val, Ordering::Relaxed);

            let time_advanced = Duration::from_secs_f64(added_tokens as f64 / rate as f64);
            *last += time_advanced;
        }
    }

    /// Non-blocking token consumption. Returns true if tokens were consumed or unthrottled,
    /// false if insufficient tokens are currently available.
    pub fn try_consume(&self, bytes: usize) -> bool {
        let rate = self.rate_bytes_per_sec.load(Ordering::Relaxed);
        if rate == 0 || bytes == 0 {
            return true;
        }
        self.refill();
        let needed = bytes as i64;
        let mut current = self.tokens.load(Ordering::Relaxed);
        loop {
            if current < needed {
                return false;
            }
            match self.tokens.compare_exchange_weak(
                current,
                current - needed,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Asynchronously waits until enough tokens are available to consume `bytes`.
    pub async fn consume(&self, bytes: usize) {
        let rate = self.rate_bytes_per_sec.load(Ordering::Relaxed);
        if rate == 0 || bytes == 0 {
            return;
        }

        loop {
            self.refill();
            let current = self.tokens.load(Ordering::Relaxed);
            let needed = bytes as i64;

            if current >= needed {
                self.tokens.fetch_sub(needed, Ordering::Relaxed);
                return;
            } else {
                let deficit = needed - current;
                let wait_secs = (deficit as f64) / (rate as f64);
                let wait_dur = Duration::from_secs_f64(wait_secs.clamp(0.005, 0.5));
                sleep(wait_dur).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_bucket_unthrottled() {
        let tb = TokenBucket::unthrottled();
        assert!(!tb.is_throttled());
        tb.consume(1_000_000).await;
    }

    #[tokio::test]
    async fn test_token_bucket_rate_limiting() {
        let tb = TokenBucket::new(100_000, 100_000); // 100 KB/s
        assert!(tb.is_throttled());

        let start = Instant::now();
        tb.consume(50_000).await;
        // First consume is within initial burst capacity
        assert!(start.elapsed() < Duration::from_millis(50));
    }
}
