//! Hierarchical Bandwidth Management & Traffic Shaping.
//!
//! Provides multi-tier bandwidth allocation (peer -> torrent -> global),
//! peer classification (LAN / WAN, TCP / uTP), LAN bypass toggles,
//! 3-second burst credit allowance, and packet/protocol overhead accounting.

use crate::ratelimit::TokenBucket;
use std::net::IpAddr;
use std::sync::Arc;

/// Classification of a peer connection locality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerClass {
    Lan,
    Wan,
}

/// Transport protocol underlying the peer connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerTransport {
    Tcp,
    Utp,
}

/// Helper to determine if an IP address belongs to a local area network (LAN) or loopback.
pub fn is_lan_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // Unique Local (fc00::/7)
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // Link-Local (fe80::/10)
        }
    }
}

/// Calculates estimated wire and packet overhead for a block transfer.
/// Standard MTU is 1500, TCP MSS is ~1460 bytes.
/// Packet overhead is ~40 bytes per MTU packet, plus BitTorrent framing overhead (13 bytes for Piece).
pub fn calculate_overhead(payload_len: usize, rate_limit_ip_overhead: bool) -> usize {
    if !rate_limit_ip_overhead || payload_len == 0 {
        return payload_len;
    }
    let packets = payload_len.div_ceil(1460);
    let overhead = packets * 40 + 13;
    payload_len + overhead
}

/// Multi-tier hierarchical rate limiter coordinating peer, torrent, and global session budgets.
#[derive(Debug, Clone)]
pub struct HierarchicalRateLimiter {
    pub global: Arc<TokenBucket>,
    pub torrent: Option<Arc<TokenBucket>>,
    pub peer: Option<Arc<TokenBucket>>,
}

impl HierarchicalRateLimiter {
    pub fn new(
        global: Arc<TokenBucket>,
        torrent: Option<Arc<TokenBucket>>,
        peer: Option<Arc<TokenBucket>>,
    ) -> Self {
        Self {
            global,
            torrent,
            peer,
        }
    }

    /// The buckets a transfer of this kind draws from, narrowest first.
    fn tiers(&self, is_lan: bool, limit_lan: bool) -> impl Iterator<Item = &Arc<TokenBucket>> {
        let bypass = is_lan && !limit_lan;
        self.peer
            .iter()
            .chain((!bypass).then_some(&self.torrent).into_iter().flatten())
            .chain((!bypass).then_some(&self.global))
    }

    /// Tries to consume `bytes` from every applicable tier, all or nothing: tokens already
    /// taken from a narrower tier are handed back if a wider one cannot supply them, so a
    /// congested global bucket does not silently drain per-peer and per-torrent budgets.
    /// If `is_lan` is true and `limit_lan` is false, torrent and global limits are bypassed.
    pub fn try_consume(&self, bytes: usize, is_lan: bool, limit_lan: bool) -> bool {
        if bytes == 0 {
            return true;
        }
        let mut taken: Vec<&Arc<TokenBucket>> = Vec::with_capacity(3);
        for bucket in self.tiers(is_lan, limit_lan) {
            if bucket.try_consume(bytes) {
                taken.push(bucket);
            } else {
                for t in taken {
                    t.refund(bytes);
                }
                return false;
            }
        }
        true
    }

    /// Waits until every applicable tier can supply `bytes` at once, then consumes them.
    /// Tokens are only taken when all tiers have them, so a request queued behind the global
    /// limit does not hold (and waste) its peer's or torrent's budget while it waits.
    pub async fn consume(&self, bytes: usize, is_lan: bool, limit_lan: bool) {
        if bytes == 0 {
            return;
        }
        while !self.try_consume(bytes, is_lan, limit_lan) {
            let wait = self
                .tiers(is_lan, limit_lan)
                .map(|b| b.wait_hint(bytes))
                .max()
                .unwrap_or_default();
            tokio::time::sleep(wait.clamp(
                std::time::Duration::from_millis(5),
                std::time::Duration::from_millis(500),
            ))
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_is_lan_address() {
        assert!(is_lan_address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_lan_address(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(is_lan_address(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
        assert!(is_lan_address(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_lan_address(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(!is_lan_address(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_lan_address(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));

        assert!(is_lan_address(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_lan_address(IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(is_lan_address(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_lan_address(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))));
    }

    #[test]
    fn test_calculate_overhead() {
        assert_eq!(calculate_overhead(16384, false), 16384);
        let with_overhead = calculate_overhead(16384, true);
        assert!(with_overhead > 16384);
        // 16384 / 1460 = 12 packets => 12 * 40 + 13 = 493 bytes overhead
        assert_eq!(with_overhead, 16384 + 493);
    }

    #[tokio::test]
    async fn test_hierarchical_rate_limiter_lan_bypass() {
        let global = Arc::new(TokenBucket::new(10_000, 10_000));
        let torrent = Arc::new(TokenBucket::new(5_000, 5_000));
        let peer = None;
        let limiter = HierarchicalRateLimiter::new(global.clone(), Some(torrent.clone()), peer);

        // LAN peer with limit_lan = false bypasses limits even when empty
        assert!(limiter.try_consume(20_000, true, false));

        // A WAN peer's request larger than the torrent bucket's capacity (5,000) is admitted
        // once, from a full bucket, and leaves it in debt...
        assert!(limiter.try_consume(20_000, false, false));
        // ...so the next one is throttled until the debt is worked off.
        assert!(!limiter.try_consume(20_000, false, false));

        // LAN peer with limit_lan = true is throttled by the same buckets
        assert!(!limiter.try_consume(20_000, true, true));
    }

    #[test]
    fn a_full_narrow_bucket_is_not_drained_when_a_wider_one_refuses() {
        let global = Arc::new(TokenBucket::new(1_000, 1_000));
        let torrent = Arc::new(TokenBucket::new(1_000_000, 1_000_000));
        let peer = Arc::new(TokenBucket::new(1_000_000, 1_000_000));
        // Empty the global bucket.
        assert!(global.try_consume(1_000));
        let limiter =
            HierarchicalRateLimiter::new(global.clone(), Some(torrent.clone()), Some(peer.clone()));
        for _ in 0..50 {
            assert!(!limiter.try_consume(500, false, false));
        }
        assert!(
            peer.available_tokens() >= 999_000,
            "peer budget was drained"
        );
        assert!(
            torrent.available_tokens() >= 999_000,
            "torrent budget was drained"
        );
    }

    #[tokio::test]
    async fn consume_waits_for_every_tier_and_takes_from_all() {
        let global = Arc::new(TokenBucket::new(20_000, 20_000));
        let peer = Arc::new(TokenBucket::new(1_000_000, 1_000_000));
        assert!(global.try_consume(20_000));
        let limiter = HierarchicalRateLimiter::new(global, None, Some(peer.clone()));
        let start = std::time::Instant::now();
        limiter.consume(1_000, false, false).await;
        // 1 000 bytes at 20 000 B/s takes at least ~40 ms to refill.
        assert!(start.elapsed() >= std::time::Duration::from_millis(30));
        assert!(peer.available_tokens() <= 999_000);
    }
}
