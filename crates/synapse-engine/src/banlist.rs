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
/// dropped first, then the entry closest to expiry.
const MAX_BANS: usize = 100_000;

#[derive(Default)]
pub struct BanList {
    entries: RwLock<HashMap<IpAddr, Instant>>,
}

impl BanList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bans `ip` until `duration` from now (extending an existing ban, never shortening it).
    pub fn ban(&self, ip: IpAddr, duration: Duration) {
        let until = Instant::now() + duration;
        let mut entries = self.entries.write();
        if entries.len() >= MAX_BANS && !entries.contains_key(&ip) {
            let now = Instant::now();
            entries.retain(|_, &mut exp| exp > now);
            if entries.len() >= MAX_BANS {
                if let Some(&oldest) = entries.iter().min_by_key(|(_, &exp)| exp).map(|(ip, _)| ip)
                {
                    entries.remove(&oldest);
                }
            }
        }
        entries
            .entry(ip)
            .and_modify(|exp| *exp = (*exp).max(until))
            .or_insert(until);
    }

    pub fn is_banned(&self, ip: IpAddr) -> bool {
        match self.entries.read().get(&ip) {
            Some(&exp) => exp > Instant::now(),
            None => false,
        }
    }

    /// Lifts a ban early; returns whether one was in place.
    pub fn unban(&self, ip: IpAddr) -> bool {
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
        self.len() == 0
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
    }
}
