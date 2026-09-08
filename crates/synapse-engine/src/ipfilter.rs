//! IP Blocklist and Filter Engine.
//!
//! Evaluates incoming and outgoing peer IP addresses against CIDR ranges
//! and `ipfilter.dat` blocklists to drop malicious or unwanted peers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct Ipv4Range {
    pub start: u32,
    pub end: u32,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct Ipv6Range {
    pub start: u128,
    pub end: u128,
    pub description: String,
}

#[derive(Debug, Default)]
pub struct IpFilter {
    v4_ranges: Vec<Ipv4Range>,
    v6_ranges: Vec<Ipv6Range>,
}

impl IpFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an IPv4 range (inclusive) to the blocklist.
    pub fn add_v4_range(&mut self, start: Ipv4Addr, end: Ipv4Addr, description: &str) {
        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);
        self.v4_ranges.push(Ipv4Range {
            start: start_u32.min(end_u32),
            end: start_u32.max(end_u32),
            description: description.to_string(),
        });
    }

    /// Adds an IPv4 CIDR block (e.g. 192.168.1.0/24).
    pub fn add_v4_cidr(&mut self, ip: Ipv4Addr, prefix: u8) {
        if prefix > 32 {
            return;
        }
        let ip_u32 = u32::from(ip);
        let mask = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };
        let start = ip_u32 & mask;
        let end = start | !mask;
        self.v4_ranges.push(Ipv4Range {
            start,
            end,
            description: format!("{}/{}", ip, prefix),
        });
    }

    /// Adds an IPv6 range (inclusive) to the blocklist.
    pub fn add_v6_range(&mut self, start: Ipv6Addr, end: Ipv6Addr, description: &str) {
        let start_u128 = u128::from(start);
        let end_u128 = u128::from(end);
        self.v6_ranges.push(Ipv6Range {
            start: start_u128.min(end_u128),
            end: start_u128.max(end_u128),
            description: description.to_string(),
        });
    }

    /// Checks if a given IP address is blocked.
    pub fn is_blocked(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => {
                let val = u32::from(v4);
                self.v4_ranges.iter().any(|r| val >= r.start && val <= r.end)
            }
            IpAddr::V6(v6) => {
                let val = u128::from(v6);
                self.v6_ranges.iter().any(|r| val >= r.start && val <= r.end)
            }
        }
    }

    pub fn total_rules(&self) -> usize {
        self.v4_ranges.len() + self.v6_ranges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_filter_cidr_and_range_matching() {
        let mut filter = IpFilter::new();

        filter.add_v4_cidr(Ipv4Addr::new(10, 0, 0, 0), 8);
        filter.add_v4_range(
            Ipv4Addr::new(192, 168, 1, 50),
            Ipv4Addr::new(192, 168, 1, 60),
            "Test range",
        );

        assert!(filter.is_blocked(IpAddr::V4(Ipv4Addr::new(10, 254, 1, 1))));
        assert!(filter.is_blocked(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 55))));
        assert!(!filter.is_blocked(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 49))));
        assert!(!filter.is_blocked(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}
