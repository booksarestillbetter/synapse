//! Temporary IP ban list, fed by smart-ban (peers that poison pieces) and checked on
//! every accept, dial and new peer connection.
//!
//! Bans are per IP address (not per address:port): an abusive peer trivially reconnects
//! from a new source port, so a port-scoped ban would be meaningless.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// How long a smart-banned address stays banned.
pub const DEFAULT_BAN_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// Upper bound on tracked bans, so a flood of distinct poisoning sources (or a spoofed
/// address space) cannot grow the map without limit. When full, expired entries are
/// dropped first, then the oldest entries closest to expiry are evicted in a batch.
const MAX_BANS: usize = 100_000;
const EVICT_BATCH: usize = 1024;

#[derive(Default)]
pub struct BanList {
    entries: RwLock<HashMap<IpAddr, Instant>>,
}

fn evict_batch(
    entries: &mut HashMap<IpAddr, Instant>,
    now: Instant,
    max_bans: usize,
    batch: usize,
) {
    entries.retain(|_, &mut exp| exp > now);
    if entries.len() >= max_bans {
        let target_len = max_bans.saturating_sub(batch);
        let drop_count = entries.len().saturating_sub(target_len).max(1);
        let mut candidates: Vec<(IpAddr, Instant)> =
            entries.iter().map(|(&k, &v)| (k, v)).collect();
        if !candidates.is_empty() {
            let pivot = (drop_count - 1).min(candidates.len() - 1);
            candidates.select_nth_unstable_by_key(pivot, |&(_, exp)| exp);
            for &(victim, _) in &candidates[..=pivot] {
                entries.remove(&victim);
            }
        }
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

impl BanList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bans `ip` until `duration` from now (extending an existing ban, never shortening it).
    pub fn ban(&self, ip: IpAddr, duration: Duration) {
        let ip = canonical_ip(ip);
        let until = Instant::now() + duration;
        let mut entries = self.entries.write();
        if entries.len() >= MAX_BANS && !entries.contains_key(&ip) {
            let now = Instant::now();
            evict_batch(&mut entries, now, MAX_BANS, EVICT_BATCH);
        }
        entries
            .entry(ip)
            .and_modify(|exp| *exp = (*exp).max(until))
            .or_insert(until);
    }

    pub fn is_banned(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        match self.entries.read().get(&ip) {
            Some(&exp) => exp > Instant::now(),
            None => false,
        }
    }

    /// Lifts a ban early; returns whether one was in place.
    pub fn unban(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        self.entries.write().remove(&ip).is_some()
    }

    /// Number of currently active bans.
    pub fn len(&self) -> usize {
        let now = Instant::now();
        self.entries
            .read()
            .values()
            .filter(|&&exp| exp > now)
            .count()
    }

    pub fn is_empty(&self) -> bool {
        let now = Instant::now();
        !self.entries.read().values().any(|&exp| exp > now)
    }

    /// Drops expired entries; call periodically.
    pub fn purge_expired(&self) {
        let now = Instant::now();
        self.entries.write().retain(|_, &mut exp| exp > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([198, 51, 100, n])
    }

    #[test]
    fn ban_applies_until_expiry_and_can_be_lifted() {
        let bans = BanList::new();
        assert!(!bans.is_banned(ip(1)));
        bans.ban(ip(1), Duration::from_secs(60));
        assert!(bans.is_banned(ip(1)));
        assert!(!bans.is_banned(ip(2)));
        assert_eq!(bans.len(), 1);
        assert!(bans.unban(ip(1)));
        assert!(!bans.is_banned(ip(1)));
        assert!(!bans.unban(ip(1)));
    }

    #[test]
    fn expired_bans_stop_applying_and_are_purged() {
        let bans = BanList::new();
        bans.ban(ip(1), Duration::ZERO);
        std::thread::sleep(Duration::from_millis(2));
        assert!(!bans.is_banned(ip(1)));
        assert_eq!(bans.len(), 0);
        bans.purge_expired();
        assert!(bans.is_empty());
    }

    #[test]
    fn a_shorter_ban_never_shortens_an_existing_one() {
        let bans = BanList::new();
        bans.ban(ip(1), Duration::from_secs(3600));
        bans.ban(ip(1), Duration::ZERO);
        assert!(bans.is_banned(ip(1)));
        // IPv4-mapped IPv6 form shares canonical identity with IPv4.
        let mapped: IpAddr = "::ffff:198.51.100.1".parse().unwrap();
        assert!(bans.is_banned(mapped));
        assert!(bans.unban(mapped));
        assert!(!bans.is_banned(ip(1)));
    }

    #[test]
    fn batch_eviction_drops_earliest_expiring_and_preserves_longest_bans() {
        let now = Instant::now();
        let mut entries = HashMap::new();
        for i in 0..100u8 {
            entries.insert(ip(i), now + Duration::from_secs(10 + u64::from(i)));
        }
        evict_batch(&mut entries, now, 100, 20);
        assert_eq!(entries.len(), 80);
        for i in 0..20u8 {
            assert!(!entries.contains_key(&ip(i)), "expected {i} to be evicted");
        }
        for i in 20..100u8 {
            assert!(entries.contains_key(&ip(i)), "expected {i} to survive");
        }
    }
}
