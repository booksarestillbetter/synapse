//! Bounded write buffering shared by every disk backend.
//!
//! Writes hold their data in memory until the OS has taken it. A [`WriteBudget`] limits how
//! much may be in flight at once: [`WriteBudget::reserve`] waits (back-pressuring the caller)
//! when the budget is spent, and [`WriteBudget::in_flight`] lets the torrent layer stop
//! requesting more blocks while disk writes are backed up.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub struct WriteBudget {
    semaphore: Arc<Semaphore>,
    /// Permits the semaphore was created with. A single batch never asks for more than this,
    /// so it can always eventually be admitted (a batch larger than the whole budget, e.g. a
    /// big piece with a small budget, runs alone rather than waiting forever).
    capacity: usize,
    in_flight: AtomicUsize,
    /// The level of `in_flight` at which callers should stop issuing new work. Adjustable at
    /// runtime; changing it moves that threshold only, not the semaphore's capacity.
    threshold: AtomicUsize,
}

/// Held while a batch is being written; releases its share of the budget on drop.
pub struct WriteReservation {
    budget: Arc<WriteBudget>,
    bytes: usize,
    _permit: OwnedSemaphorePermit,
}

impl Drop for WriteReservation {
    fn drop(&mut self) {
        self.budget
            .in_flight
            .fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

impl WriteBudget {
    pub fn new(max_bytes: usize) -> Arc<WriteBudget> {
        // Semaphore permits are bounded (and `acquire_many` takes a u32).
        let capacity = max_bytes.clamp(1, u32::MAX as usize);
        Arc::new(WriteBudget {
            semaphore: Arc::new(Semaphore::new(capacity)),
            capacity,
            in_flight: AtomicUsize::new(0),
            threshold: AtomicUsize::new(max_bytes),
        })
    }

    /// Waits until `bytes` fit in the budget, then reserves them.
    pub async fn reserve(
        self: &Arc<Self>,
        bytes: usize,
    ) -> Result<WriteReservation, tokio::sync::AcquireError> {
        let permits = bytes.clamp(1, self.capacity) as u32;
        let permit = self.semaphore.clone().acquire_many_owned(permits).await?;
        self.in_flight.fetch_add(bytes, Ordering::Relaxed);
        Ok(WriteReservation {
            budget: self.clone(),
            bytes,
            _permit: permit,
        })
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    pub fn threshold(&self) -> usize {
        self.threshold.load(Ordering::Relaxed)
    }

    pub fn set_threshold(&self, bytes: usize) {
        self.threshold.store(bytes, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn a_reservation_counts_in_flight_bytes_and_releases_them_on_drop() {
        let b = WriteBudget::new(1000);
        let r = b.reserve(400).await.unwrap();
        assert_eq!(b.in_flight(), 400);
        drop(r);
        assert_eq!(b.in_flight(), 0);
    }

    #[tokio::test]
    async fn a_full_budget_makes_the_next_writer_wait_until_space_frees() {
        let b = WriteBudget::new(1000);
        let first = b.reserve(800).await.unwrap();
        let b2 = b.clone();
        let waiter = tokio::spawn(async move { b2.reserve(500).await.unwrap() });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "must wait while the budget is spent");
        drop(first);
        tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("admitted after release")
            .unwrap();
    }

    #[tokio::test]
    async fn a_batch_larger_than_the_whole_budget_still_runs_and_raising_the_threshold_cannot_deadlock(
    ) {
        let b = WriteBudget::new(1000);
        let big = tokio::time::timeout(Duration::from_secs(2), b.reserve(50_000)).await;
        assert!(big.is_ok(), "an oversized batch must be admitted (alone)");
        drop(big);
        // Raising the threshold above the semaphore's capacity must not make reservations
        // ask for more permits than exist.
        b.set_threshold(10_000_000);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), b.reserve(5_000_000))
                .await
                .is_ok()
        );
        assert_eq!(b.threshold(), 10_000_000);
    }
}
