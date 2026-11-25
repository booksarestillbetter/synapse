//! BEP 40 Canonical Peer Priority.
//!
//! Provides deterministic pairwise CRC32-C priority calculation for peer dial ordering
//! and tie-breaking when two BitTorrent peers establish simultaneous cross-connections.

use std::cmp::Ordering;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// Castagnoli CRC32-C (polynomial `0x82F63B78`) used by BEP 40 Canonical Peer Priority.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F6_3B78;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 @ IpAddr::V4(_) => v4,
    }
}

fn to_ipv6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

/// Computes the standard BEP 40 pairwise CRC32-C canonical priority for two peer endpoints.
pub fn bep40_peer_priority(a: SocketAddr, b: SocketAddr) -> u32 {
    let ip_a = normalize_ip(a.ip());
    let ip_b = normalize_ip(b.ip());

    if ip_a == ip_b {
        let (p_lo, p_hi) = if a.port() <= b.port() {
            (a.port(), b.port())
        } else {
            (b.port(), a.port())
        };
        let lo_be = p_lo.to_be_bytes();
        let hi_be = p_hi.to_be_bytes();
        return crc32c(&[lo_be[0], lo_be[1], hi_be[0], hi_be[1]]);
    }

    if let (IpAddr::V4(va), IpAddr::V4(vb)) = (ip_a, ip_b) {
        let ao = va.octets();
        let bo = vb.octets();
        let mask = if ao[..2] != bo[..2] {
            [0xFF, 0xFF, 0x55, 0x55]
        } else if ao[..3] != bo[..3] {
            [0xFF, 0xFF, 0xFF, 0x55]
        } else {
            [0xFF, 0xFF, 0xFF, 0xFF]
        };
        let am = [
            ao[0] & mask[0],
            ao[1] & mask[1],
            ao[2] & mask[2],
            ao[3] & mask[3],
        ];
        let bm = [
            bo[0] & mask[0],
            bo[1] & mask[1],
            bo[2] & mask[2],
            bo[3] & mask[3],
        ];
        let (lo, hi) = if am <= bm { (am, bm) } else { (bm, am) };
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&lo);
        buf[4..].copy_from_slice(&hi);
        return crc32c(&buf);
    }

    let ao = to_ipv6(ip_a).octets();
    let bo = to_ipv6(ip_b).octets();
    let mut mask = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55,
    ];
    if ao[..6] == bo[..6] {
        for i in 6..16 {
            mask[i] = 0xFF;
            if ao[i] != bo[i] {
                break;
            }
        }
    }
    let mut am = [0u8; 16];
    let mut bm = [0u8; 16];
    for i in 0..16 {
        am[i] = ao[i] & mask[i];
        bm[i] = bo[i] & mask[i];
    }
    let (lo, hi) = if am <= bm { (am, bm) } else { (bm, am) };
    let mut buf = [0u8; 32];
    buf[..16].copy_from_slice(&lo);
    buf[16..].copy_from_slice(&hi);
    crc32c(&buf)
}

/// Calculates a canonical 32-bit priority score for an endpoint per BEP 40.
pub fn canonical_peer_score(addr: SocketAddr) -> u32 {
    let mut score = match addr.ip() {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Mask with 0xffffff55 per BEP 40 convention for /24 locality balancing
            let masked = u32::from_be_bytes(octets) & 0xffffff55;
            crc32c(masked.to_be_bytes().as_ref())
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            crc32c(&octets)
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
                (IpAddr::V4(l), IpAddr::V4(r)) => l
                    .octets()
                    .cmp(&r.octets())
                    .then(local.port().cmp(&remote.port())),
                (IpAddr::V6(l), IpAddr::V6(r)) => l
                    .octets()
                    .cmp(&r.octets())
                    .then(local.port().cmp(&remote.port())),
                (IpAddr::V4(_), IpAddr::V6(_)) => Ordering::Less,
                (IpAddr::V6(_), IpAddr::V4(_)) => Ordering::Greater,
            }
        }
        ord => ord,
    }
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
        let addr2 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            6882,
        );

        let ord1 = canonical_peer_priority(addr1, addr2);
        let ord2 = canonical_peer_priority(addr2, addr1);
        assert_eq!(ord1, ord2.reverse());
    }

    #[test]
    fn crc32c_standard_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn bep40_official_ipv4_vectors_and_symmetry() {
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(123, 213, 32, 10)), 6881);
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(98, 76, 54, 32)), 51413);
        assert_eq!(bep40_peer_priority(a, b), 0xec2d_7224);
        assert_eq!(bep40_peer_priority(b, a), 0xec2d_7224);

        // Same /24
        let c = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(123, 213, 32, 234)), 51413);
        assert_eq!(bep40_peer_priority(a, c), 0x9956_8189);
        assert_eq!(bep40_peer_priority(c, a), 0x9956_8189);

        // Same /16, different /24
        let d = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(123, 213, 45, 20)), 6881);
        assert_eq!(bep40_peer_priority(a, d), 0xb339_bf01);
        assert_eq!(bep40_peer_priority(d, a), 0xb339_bf01);

        // Same IP, different ports
        let same1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 6881);
        let same2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 51413);
        let same3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 6882);
        assert_eq!(
            bep40_peer_priority(same1, same2),
            bep40_peer_priority(same2, same1)
        );
        assert_ne!(
            bep40_peer_priority(same1, same2),
            bep40_peer_priority(same1, same3)
        );

        // IPv6 symmetry and /48 prefix masking invariance
        let v6_a = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x1111, 0x0001, 0, 0, 0, 1)),
            6881,
        );
        let v6_b1 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x2222, 0x0001, 0, 0, 0, 1)),
            6881,
        );
        let v6_b2 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x2222, 0xFFFF, 0, 0, 0, 2)),
            6881,
        );
        assert_eq!(
            bep40_peer_priority(v6_a, v6_b1),
            bep40_peer_priority(v6_b1, v6_a)
        );
        // Bytes 6..16 are masked with 0x55 when /48 differs, so entries that match after
        // `& 0x55` tail masking yield identical priority
        let v6_b3 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x2222, 0x0003, 0, 0, 0, 3)),
            6881,
        );
        assert_eq!(
            bep40_peer_priority(v6_a, v6_b1),
            bep40_peer_priority(v6_a, v6_b3)
        );
        assert_ne!(
            bep40_peer_priority(v6_a, v6_b1),
            bep40_peer_priority(v6_a, v6_b2)
        );

        // IPv4-mapped IPv6 normalization matches pure IPv4 official vector
        let mapped_a = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(123, 213, 32, 10).to_ipv6_mapped()),
            6881,
        );
        assert_eq!(bep40_peer_priority(mapped_a, b), 0xec2d_7224);
    }
}
