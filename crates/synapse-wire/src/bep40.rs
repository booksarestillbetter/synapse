//! BEP 40 Canonical Peer Priority.
//!
//! Provides a deterministic tie-breaking algorithm when two BitTorrent peers
//! establish simultaneous cross-connections to each other. Both peers compute
//! identical priority rankings, and the peer with lower priority closes its connection,
//! eliminating connection races, socket leaks, and duplicate swarms.

use std::cmp::Ordering;
use std::net::{IpAddr, SocketAddr};

/// Calculates a canonical 32-bit priority score for an endpoint per BEP 40.
pub fn canonical_peer_score(addr: SocketAddr) -> u32 {
    let mut score = match addr.ip() {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Mask with 0xffffff55 per BEP 40 convention for /24 locality balancing
            let masked = u32::from_be_bytes(octets) & 0xffffff55;
            crc32_fast(masked.to_be_bytes().as_ref())
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            crc32_fast(&octets)
        }
    };

    // Blend high bits of the port into score
    score ^= (u32::from(addr.port()) & 0xff00) << 8;
    score
}

/// Determines which connection should be kept in a simultaneous dual connection race.
/// Returns `Ordering::Greater` if `local` has higher priority (we keep outbound, drop inbound),
/// `Ordering::Less` if `remote` has higher priority, or compares lexicographically if tied.
pub fn canonical_peer_priority(local: SocketAddr, remote: SocketAddr) -> Ordering {
    let score_local = canonical_peer_score(local);
    let score_remote = canonical_peer_score(remote);

    match score_local.cmp(&score_remote) {
        Ordering::Equal => {
            // Tie-break lexicographically by IP and Port
            match (local.ip(), remote.ip()) {
                (IpAddr::V4(l), IpAddr::V4(r)) => l.octets().cmp(&r.octets()).then(local.port().cmp(&remote.port())),
                (IpAddr::V6(l), IpAddr::V6(r)) => l.octets().cmp(&r.octets()).then(local.port().cmp(&remote.port())),
                (IpAddr::V4(_), IpAddr::V6(_)) => Ordering::Less,
                (IpAddr::V6(_), IpAddr::V4(_)) => Ordering::Greater,
            }
        }
        ord => ord,
    }
}

/// Simple standard CRC32 tableless implementation for BEP 40 / BEP 42 calculations.
pub(crate) fn crc32_fast(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_canonical_peer_priority_symmetry() {
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 6881);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 51413);

        let ord1 = canonical_peer_priority(addr1, addr2);
        let ord2 = canonical_peer_priority(addr2, addr1);

        assert_ne!(ord1, Ordering::Equal);
        assert_eq!(ord1, ord2.reverse());
    }

    #[test]
    fn test_canonical_peer_priority_ipv6() {
        let addr1 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 6881);
        let addr2 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 6882);

        let ord1 = canonical_peer_priority(addr1, addr2);
        let ord2 = canonical_peer_priority(addr2, addr1);
        assert_eq!(ord1, ord2.reverse());
    }
}
