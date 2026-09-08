//! BEP 6 Fast Extension Utilities.
//!
//! Provides deterministic calculation of the `AllowedFast` set per BEP 6, enabling
//! peers to download critical initial pieces even while choked.

use sha1::{Digest, Sha1};
use std::net::IpAddr;

/// Computes the deterministic `AllowedFast` piece index set for a peer per BEP 6.
///
/// `k`: number of allowed fast pieces (BEP 6 default is 10).
pub fn compute_allowed_fast_set(
    peer_ip: IpAddr,
    info_hash: [u8; 20],
    total_pieces: u32,
    k: u32,
) -> Vec<u32> {
    if total_pieces == 0 || k == 0 {
        return Vec::new();
    }

    let mut ip_bytes = Vec::new();
    match peer_ip {
        IpAddr::V4(v4) => {
            // Mask to /24 for IPv4 per BEP 6 to prevent multi-homed farming
            let octets = v4.octets();
            ip_bytes.extend_from_slice(&[octets[0], octets[1], octets[2], 0]);
        }
        IpAddr::V6(v6) => {
            // Mask to /64 for IPv6
            let octets = v6.octets();
            ip_bytes.extend_from_slice(&octets[0..8]);
            ip_bytes.extend_from_slice(&[0u8; 8]);
        }
    }

    let mut x = Vec::new();
    x.extend_from_slice(&ip_bytes);
    x.extend_from_slice(&info_hash);

    let mut result = Vec::new();
    let count = k.min(total_pieces);

    while result.len() < count as usize {
        let digest: [u8; 20] = Sha1::digest(&x).into();
        for chunk in digest.chunks_exact(4) {
            let val = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let index = val % total_pieces;
            if !result.contains(&index) {
                result.push(index);
                if result.len() == count as usize {
                    break;
                }
            }
        }
        x = digest.to_vec();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_allowed_fast_set_generation_and_uniqueness() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 45));
        let hash = [0x55u8; 20];
        let total_pieces = 1000;
        let k = 10;

        let fast_set = compute_allowed_fast_set(ip, hash, total_pieces, k);
        assert_eq!(fast_set.len(), 10);

        // Verify all pieces are within range
        for &idx in &fast_set {
            assert!(idx < total_pieces);
        }

        // Verify uniqueness
        let mut deduped = fast_set.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(deduped.len(), fast_set.len());

        // Verify deterministic reproducibility
        let fast_set_2 = compute_allowed_fast_set(ip, hash, total_pieces, k);
        assert_eq!(fast_set, fast_set_2);
    }
}
