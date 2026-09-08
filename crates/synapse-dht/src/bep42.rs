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

fn compute_ip_crc(ip: IpAddr, r: u8) -> u32 {
    let mut data = Vec::with_capacity(8);
    match ip {
        IpAddr::V4(v4) => {
            let ip_int = u32::from_be_bytes(v4.octets()) & V4_MASK;
            let combined = (ip_int & 0xffffff00) | ((ip_int & 0xff) ^ u32::from(r));
            data.extend_from_slice(&combined.to_be_bytes());
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let first_8 = u64::from_be_bytes(octets[0..8].try_into().unwrap()) & V6_MASK;
            let combined = (first_8 & 0xffffffffffffff00) | ((first_8 & 0xff) ^ u64::from(r));
            data.extend_from_slice(&combined.to_be_bytes());
        }
    }

    crc32c_hash(&data)
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
