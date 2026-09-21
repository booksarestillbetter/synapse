//! BEP 42 DHT Security Extension (IP-derived Node IDs).
//!
//! Enforces IP-derived Node IDs using CRC32c to mitigate Sybil attacks,
//! eclipse attacks, and routing table poisoning in the Kademlia DHT.

use std::net::IpAddr;

const V4_MASK: u32 = 0x030f3fff;
const V6_MASK: u64 = 0x0103070f1f3f7fff;

/// Generates a secure, BEP 42-compliant 20-byte Node ID for an IP address.
pub fn generate_secure_node_id(ip: IpAddr, seed: u8) -> [u8; 20] {
    let r = seed & 7;
    let crc = compute_ip_crc(ip, r);

    let mut id = [0u8; 20];
    // First 21 bits come from CRC
    id[0] = ((crc >> 24) & 0xff) as u8;
    id[1] = ((crc >> 16) & 0xff) as u8;
    id[2] = (((crc >> 8) & 0xf8) as u8) | (rand::random::<u8>() & 0x07);

    // Random bytes for 3..19
    for byte in &mut id[3..19] {
        *byte = rand::random::<u8>();
    }

    // Byte 19 contains the seed
    id[19] = seed;
    id
}

/// Verifies whether a 20-byte Node ID matches the sender's IP address per BEP 42.
pub fn verify_secure_node_id(node_id: &[u8; 20], ip: IpAddr) -> bool {
    let r = node_id[19] & 7;
    let crc = compute_ip_crc(ip, r);

    let expected_b0 = ((crc >> 24) & 0xff) as u8;
    let expected_b1 = ((crc >> 16) & 0xff) as u8;
    let expected_b2_masked = ((crc >> 8) & 0xf8) as u8;

    node_id[0] == expected_b0
        && node_id[1] == expected_b1
        && (node_id[2] & 0xf8) == expected_b2_masked
}

/// CRC32c of the masked IP with `r` (3 bits) folded into the top bits, exactly as BEP 42
/// specifies: `crc32c((ip & mask) | (r << 29))` for IPv4 (big-endian 4 bytes) and
/// `crc32c((ip[..8] & mask) | (r << 61))` for IPv6 (big-endian 8 bytes).
fn compute_ip_crc(ip: IpAddr, r: u8) -> u32 {
    let r = u32::from(r & 7);
    match ip {
        IpAddr::V4(v4) => {
            let masked = (u32::from_be_bytes(v4.octets()) & V4_MASK) | (r << 29);
            crc32c_hash(&masked.to_be_bytes())
        }
        IpAddr::V6(v6) => {
            let first_8 = u64::from_be_bytes(v6.octets()[0..8].try_into().expect("8 bytes"));
            let masked = (first_8 & V6_MASK) | (u64::from(r) << 61);
            crc32c_hash(&masked.to_be_bytes())
        }
    }
}

/// Whether BEP 42 exempts `ip` from having a derived node id: private, loopback and
/// link-local addresses cannot be forged from the outside, and LAN swarms would otherwise
/// be unusable.
pub fn is_exempt_from_node_id_check(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

fn crc32c_hash(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F63B78; // Castagnoli polynomial (CRC32c)
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

    /// The example table from BEP 42: (ip, rand, node id).
    const BEP42_VECTORS: [([u8; 4], u8, &str); 5] = [
        (
            [124, 31, 75, 21],
            1,
            "5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401",
        ),
        (
            [21, 75, 31, 124],
            86,
            "5a3ce9c14e7a08645677bbd1cfe7d8f956d53256",
        ),
        (
            [65, 23, 51, 170],
            22,
            "a5d43220bc8f112a3d426c84764f8c2a1150e616",
        ),
        (
            [84, 124, 73, 14],
            65,
            "1b0321dd1bb1fe518101ceef99462b947a01ff41",
        ),
        (
            [43, 213, 53, 83],
            90,
            "e56f6cbf5b7c4be0237986d5243b87aa6d51305a",
        ),
    ];

    fn unhex(s: &str) -> [u8; 20] {
        let mut out = [0u8; 20];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn matches_the_published_bep42_test_vectors() {
        for (octets, rand, id_hex) in BEP42_VECTORS {
            let ip = IpAddr::V4(Ipv4Addr::from(octets));
            let id = unhex(id_hex);
            assert_eq!(id[19], rand, "vector sanity");
            assert!(
                verify_secure_node_id(&id, ip),
                "spec vector for {ip} must verify"
            );
            // A generated id for the same ip/rand shares the crc-derived 21-bit prefix.
            let gen = generate_secure_node_id(ip, rand);
            assert_eq!(gen[0], id[0]);
            assert_eq!(gen[1], id[1]);
            assert_eq!(gen[2] & 0xf8, id[2] & 0xf8);
        }
    }

    #[test]
    fn local_addresses_are_exempt_and_public_ones_are_not() {
        for local in [
            "10.1.2.3",
            "192.168.0.9",
            "172.16.5.5",
            "127.0.0.1",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "fe80::2",
        ] {
            assert!(
                is_exempt_from_node_id_check(local.parse().unwrap()),
                "{local}"
            );
        }
        for public in ["8.8.8.8", "124.31.75.21", "2001:4860::1"] {
            assert!(
                !is_exempt_from_node_id_check(public.parse().unwrap()),
                "{public}"
            );
        }
    }

    #[test]
    fn test_bep42_node_id_generation_and_verification_v4() {
        let ip = IpAddr::V4(Ipv4Addr::new(124, 31, 75, 21));
        let seed = 42;
        let id = generate_secure_node_id(ip, seed);

        assert!(verify_secure_node_id(&id, ip));

        // Different IP should fail verification
        let fake_ip = IpAddr::V4(Ipv4Addr::new(124, 31, 75, 22));
        assert!(!verify_secure_node_id(&id, fake_ip));
    }

    #[test]
    fn test_bep42_node_id_generation_and_verification_v6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x5678, 0, 0, 0, 1));
        let seed = 88;
        let id = generate_secure_node_id(ip, seed);

        assert!(verify_secure_node_id(&id, ip));

        let diff_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x9999, 0x5678, 0, 0, 0, 1));
        assert!(!verify_secure_node_id(&id, diff_ip));
    }
}
