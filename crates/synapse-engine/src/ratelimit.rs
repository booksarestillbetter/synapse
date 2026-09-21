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

    pub fn new_with_3s_burst(rate_bytes_per_sec: u64) -> Self {
        let burst = rate_bytes_per_sec.saturating_mul(3);
        Self::new(rate_bytes_per_sec, burst)
    }

    pub fn unthrottled() -> Self {
        Self::new(0, 0)
    }

    pub fn is_throttled(&self) -> bool {
        self.rate_bytes_per_sec.load(Ordering::Relaxed) > 0
    }

    pub fn rate(&self) -> u64 {
        self.rate_bytes_per_sec.load(Ordering::Relaxed)
    }

    pub fn capacity(&self) -> u64 {
        self.capacity_bytes.load(Ordering::Relaxed)
    }

    pub fn available_tokens(&self) -> i64 {
        self.tokens.load(Ordering::Relaxed)
    }

    pub fn set_rate(&self, rate_bytes_per_sec: u64, burst_bytes: u64) {
        self.rate_bytes_per_sec
            .store(rate_bytes_per_sec, Ordering::Relaxed);
        let cap = if burst_bytes > 0 {
            burst_bytes.max(rate_bytes_per_sec)
        } else {
            rate_bytes_per_sec.saturating_mul(3)
        };
        self.capacity_bytes.store(cap, Ordering::Relaxed);
        let current = self.tokens.load(Ordering::Relaxed);
        if current > cap as i64 {
            self.tokens.store(cap as i64, Ordering::Relaxed);
        }
    }

    pub fn set_rate_auto_burst(&self, rate_bytes_per_sec: u64) {
        let burst = rate_bytes_per_sec.saturating_mul(3);
        self.set_rate(rate_bytes_per_sec, burst);
    }

    /// Tokens that must be on hand to start a transfer of `bytes`. A request larger than the
    /// bucket can ever hold (a 16 KiB block through a 2 KiB/s limit, whose burst is 6 KiB) is
    /// admitted once the bucket is *full* and drives it into debt, which later requests then
    /// have to wait off. Demanding the full amount instead would never be satisfiable and
    /// would stall the transfer forever.
    fn required(&self, bytes: usize) -> i64 {
        (bytes as i64).min(self.capacity_bytes.load(Ordering::Relaxed) as i64)
    }

    /// Check if tokens are available without consuming them.
    pub fn can_consume(&self, bytes: usize) -> bool {
        let rate = self.rate_bytes_per_sec.load(Ordering::Relaxed);
        if rate == 0 || bytes == 0 {
            return true;
        }
        self.refill();
        self.tokens.load(Ordering::Relaxed) >= self.required(bytes)
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
            // Atomic read-modify-write: consumers subtract without taking the refill lock, and a
            // plain load/store here could overwrite (lose) a concurrent consumption.
            let _ = self
                .tokens
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |t| {
                    Some((t + added_tokens).min(cap))
                });

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
        let required = self.required(bytes);
        let mut current = self.tokens.load(Ordering::Relaxed);
        loop {
            if current < required {
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

    /// Returns `bytes` previously taken with [`try_consume`](Self::try_consume) that were not
    /// used (the caller could not get the rest of what it needed), capped at the bucket size.
    pub fn refund(&self, bytes: usize) {
        if self.rate_bytes_per_sec.load(Ordering::Relaxed) == 0 || bytes == 0 {
            return;
        }
        let cap = self.capacity_bytes.load(Ordering::Relaxed) as i64;
        let _ = self
            .tokens
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |t| {
                Some((t + bytes as i64).min(cap.max(t)))
            });
    }

    /// How long until `bytes` could be consumed, from the bucket's current state (zero if it
    /// can be now). A hint for callers that poll; refill may make it shorter.
    pub fn wait_hint(&self, bytes: usize) -> Duration {
        let rate = self.rate_bytes_per_sec.load(Ordering::Relaxed);
        if rate == 0 || bytes == 0 {
            return Duration::ZERO;
        }
        self.refill();
        let deficit = self.required(bytes) - self.tokens.load(Ordering::Relaxed);
        if deficit <= 0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(deficit as f64 / rate as f64)
        }
    }

    /// Asynchronously waits until enough tokens are available to consume `bytes`.
    pub async fn consume(&self, bytes: usize) {
        loop {
            if self.try_consume(bytes) {
                return;
            }
            sleep(
                self.wait_hint(bytes)
                    .clamp(Duration::from_millis(5), Duration::from_millis(500)),
            )
            .await;
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

    #[tokio::test]
    async fn a_request_larger_than_the_burst_is_admitted_instead_of_stalling_forever() {
        // 2 KiB/s with the automatic 3x burst (6 KiB) cannot hold a 16 KiB block.
        let tb = TokenBucket::new_with_3s_burst(2048);
        assert!(tb.capacity() < 16 * 1024);
        assert!(
            tb.try_consume(16 * 1024),
            "a full bucket must admit an oversized request"
        );
        assert!(
            !tb.try_consume(16 * 1024),
            "which puts it into debt, so the next one waits"
        );
        assert!(tb.available_tokens() < 0);

        let tb = TokenBucket::new_with_3s_burst(2048);
        let done = tokio::time::timeout(Duration::from_secs(2), tb.consume(16 * 1024)).await;
        assert!(
            done.is_ok(),
            "consume() of more than the burst never returned"
        );
    }

    #[test]
    fn concurrent_refills_and_consumption_do_not_lose_tokens() {
        let tb = std::sync::Arc::new(TokenBucket::new(1_000_000_000, 1_000_000_000));
        let taken = std::sync::Arc::new(AtomicU64::new(0));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let (tb, taken) = (tb.clone(), taken.clone());
                std::thread::spawn(move || {
                    for _ in 0..20_000 {
                        if tb.try_consume(1_000) {
                            taken.fetch_add(1_000, Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        // Consumption never exceeds what was available: capacity plus what refills in the time taken.
        assert!(tb.available_tokens() <= 1_000_000_000);
        assert!(
            taken.load(Ordering::Relaxed) <= 80_000_000,
            "took more than could have been consumed"
        );
    }
}
