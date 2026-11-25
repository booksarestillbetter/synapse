//! IP Blocklist and Filter Engine.
//!
//! Evaluates incoming and outgoing peer IP addresses against CIDR ranges
//! and `ipfilter.dat` blocklists to drop malicious or unwanted peers.

use std::io::BufRead;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;

/// Parses a dotted-quad address, accepting zero-padded octets (`001.002.003.004`), which
/// `Ipv4Addr::from_str` rejects but eMule-format blocklists use throughout.
fn parse_v4(s: &str) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut parts = s.split('.');
    for slot in &mut octets {
        *slot = parts.next()?.trim().parse().ok()?;
    }
    parts.next().is_none().then(|| Ipv4Addr::from(octets))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Range {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Range {
    pub start: u128,
    pub end: u128,
}

#[derive(Debug, Default)]
pub struct IpFilter {
    v4_ranges: Vec<Ipv4Range>,
    v6_ranges: Vec<Ipv6Range>,
    /// True when both range lists are sorted by start and non-overlapping (see
    /// [`IpFilter::normalize`]), which lets [`IpFilter::is_blocked`] binary-search instead
    /// of scanning every rule. Any `add_*` clears it.
    normalized: bool,
}

impl IpFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an IPv4 range (inclusive) to the blocklist.
    pub fn add_v4_range(&mut self, start: Ipv4Addr, end: Ipv4Addr, _description: &str) {
        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);
        self.normalized = false;
        self.v4_ranges.push(Ipv4Range {
            start: start_u32.min(end_u32),
            end: start_u32.max(end_u32),
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
        self.normalized = false;
        self.v4_ranges.push(Ipv4Range { start, end });
    }

    /// Adds an IPv6 range (inclusive) to the blocklist.
    pub fn add_v6_range(&mut self, start: Ipv6Addr, end: Ipv6Addr, _description: &str) {
        let start_u128 = u128::from(start);
        let end_u128 = u128::from(end);
        self.normalized = false;
        self.v6_ranges.push(Ipv6Range {
            start: start_u128.min(end_u128),
            end: start_u128.max(end_u128),
        });
    }

    /// Adds an IPv6 CIDR block (e.g. `fc00::/7`).
    pub fn add_v6_cidr(&mut self, ip: Ipv6Addr, prefix: u8) {
        if prefix > 128 {
            return;
        }
        let ip_u128 = u128::from(ip);
        let mask = if prefix == 0 {
            0
        } else {
            !0u128 << (128 - prefix)
        };
        let start = ip_u128 & mask;
        let end = start | !mask;
        self.normalized = false;
        self.v6_ranges.push(Ipv6Range { start, end });
    }

    /// Parses and adds a single CIDR string (`"192.168.1.0/24"` or `"fc00::/7"`).
    pub fn add_cidr_str(&mut self, cidr: &str) -> Result<(), String> {
        let (addr_str, prefix_str) = cidr
            .split_once('/')
            .ok_or_else(|| format!("invalid CIDR '{cidr}': missing '/'"))?;
        let prefix: u8 = prefix_str
            .trim()
            .parse()
            .map_err(|_| format!("invalid CIDR '{cidr}': bad prefix"))?;
        match IpAddr::from_str(addr_str.trim()) {
            Ok(IpAddr::V4(ip)) => {
                if prefix > 32 {
                    return Err(format!("invalid IPv4 CIDR prefix '{prefix}' (max 32)"));
                }
                self.add_v4_cidr(ip, prefix);
                Ok(())
            }
            Ok(IpAddr::V6(ip)) => {
                if prefix > 128 {
                    return Err(format!("invalid IPv6 CIDR prefix '{prefix}' (max 128)"));
                }
                self.add_v6_cidr(ip, prefix);
                Ok(())
            }
            Err(_) => Err(format!("invalid CIDR '{cidr}': bad address")),
        }
    }

    /// Loads additional blocklist rules from an `ipfilter.dat`-style file. Two line
    /// formats are auto-detected per line:
    ///   - eMule/PeerGuardian range format: `1.2.3.4 - 1.2.3.10 , level , description`
    ///     (or `1.2.3.4 - 1.2.3.10 , description`; octets may be zero-padded). Per the eMule
    ///     `ipfilter.dat` convention, entries with `level >= 128` are allowlist entries and are
    ///     skipped rather than blocked.
    ///   - Plain CIDR notation: `1.2.3.0/24` or `fc00::/7`
    ///
    /// Blank lines and lines starting with `#` or `;` are ignored. A malformed line is
    /// skipped (logged, not fatal) rather than aborting the whole load -- a single bad
    /// line in a large third-party blocklist should never prevent the daemon starting.
    /// Returns the number of rules successfully loaded.
    pub fn load_file(&mut self, path: &Path) -> std::io::Result<usize> {
        let file = std::fs::File::open(path)?;
        let mut reader = std::io::BufReader::new(file);
        let mut line_buf = String::new();
        let mut loaded = 0usize;
        let mut line_num = 0usize;
        loop {
            line_buf.clear();
            if reader.read_line(&mut line_buf)? == 0 {
                break;
            }
            line_num += 1;
            let line = line_buf.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            if let Some((range_part, rest)) = line.split_once(',') {
                if let Some((start_str, end_str)) = range_part.split_once('-') {
                    let (start_str, end_str) = (start_str.trim(), end_str.trim());
                    // Standard eMule format is `start - end , level , description`: level >= 128
                    // means allow/whitelist rather than block.
                    let level_allowed = if let Some((lvl_str, _desc_part)) = rest.split_once(',') {
                        lvl_str
                            .trim()
                            .parse::<u16>()
                            .map(|level| level < 128)
                            .unwrap_or(true)
                    } else if let Ok(level) = rest.trim().parse::<u16>() {
                        level < 128
                    } else {
                        true
                    };
                    if let (Some(start), Some(end)) = (parse_v4(start_str), parse_v4(end_str)) {
                        if !level_allowed {
                            continue;
                        }
                        self.add_v4_range(start, end, "");
                        loaded += 1;
                        continue;
                    }
                    if let (Ok(start), Ok(end)) =
                        (Ipv6Addr::from_str(start_str), Ipv6Addr::from_str(end_str))
                    {
                        if !level_allowed {
                            continue;
                        }
                        self.add_v6_range(start, end, "");
                        loaded += 1;
                        continue;
                    }
                }
            }

            if line.contains('/') && self.add_cidr_str(line).is_ok() {
                loaded += 1;
                continue;
            }

            tracing::warn!(
                line = line_num,
                path = %path.display(),
                content = %line,
                "Skipping unparseable ipfilter line"
            );
        }
        self.normalize();
        Ok(loaded)
    }

    /// Sorts and merges overlapping/adjacent ranges in-place so lookups are O(log n). Public
    /// blocklists have hundreds of thousands of ranges and every accept, dial and
    /// periodic re-check consults the filter, so a linear scan is not acceptable. Call
    /// after a batch of `add_*`/`load_file`; `is_blocked` stays correct without it, just slower.
    pub fn normalize(&mut self) {
        if self.v4_ranges.len() > 1 {
            self.v4_ranges.sort_unstable_by_key(|r| r.start);
            let mut write = 0usize;
            for read in 1..self.v4_ranges.len() {
                let r = self.v4_ranges[read];
                if r.start <= self.v4_ranges[write].end.saturating_add(1) {
                    self.v4_ranges[write].end = self.v4_ranges[write].end.max(r.end);
                } else {
                    write += 1;
                    self.v4_ranges[write] = r;
                }
            }
            self.v4_ranges.truncate(write + 1);
        }

        if self.v6_ranges.len() > 1 {
            self.v6_ranges.sort_unstable_by_key(|r| r.start);
            let mut write = 0usize;
            for read in 1..self.v6_ranges.len() {
                let r = self.v6_ranges[read];
                if r.start <= self.v6_ranges[write].end.saturating_add(1) {
                    self.v6_ranges[write].end = self.v6_ranges[write].end.max(r.end);
                } else {
                    write += 1;
                    self.v6_ranges[write] = r;
                }
            }
            self.v6_ranges.truncate(write + 1);
        }
        self.normalized = true;
    }

    /// Checks if a given IP address is blocked (canonicalizing IPv4-mapped IPv6 addresses
    /// like `::ffff:1.2.3.4` to their IPv4 form).
    pub fn is_blocked(&self, addr: IpAddr) -> bool {
        let canonical = match addr {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(addr),
            v4 => v4,
        };
        match canonical {
            IpAddr::V4(v4) => {
                let val = u32::from(v4);
                if self.normalized {
                    let i = self.v4_ranges.partition_point(|r| r.start <= val);
                    i > 0 && val <= self.v4_ranges[i - 1].end
                } else {
                    self.v4_ranges
                        .iter()
                        .any(|r| val >= r.start && val <= r.end)
                }
            }
            IpAddr::V6(v6) => {
                let val = u128::from(v6);
                if self.normalized {
                    let i = self.v6_ranges.partition_point(|r| r.start <= val);
                    i > 0 && val <= self.v6_ranges[i - 1].end
                } else {
                    self.v6_ranges
                        .iter()
                        .any(|r| val >= r.start && val <= r.end)
                }
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

    #[test]
    fn test_add_cidr_str_v4_and_v6() {
        let mut filter = IpFilter::new();
        assert!(filter.add_cidr_str("10.0.0.0/8").is_ok());
        assert!(filter.add_cidr_str("fc00::/7").is_ok());
        assert!(filter.add_cidr_str("not-a-cidr").is_err());
        assert!(filter.add_cidr_str("10.0.0.0/33").is_err());
        assert!(filter.add_cidr_str("10.0.0.0/999").is_err());
        assert!(filter.add_cidr_str("fc00::/129").is_err());

        assert!(filter.is_blocked(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(filter.is_blocked("fc00::1".parse().unwrap()));
        assert!(!filter.is_blocked(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    }

    #[test]
    fn emule_files_with_zero_padded_octets_load() {
        let dir = std::env::temp_dir().join(format!("ipf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ipfilter.dat");
        std::fs::write(
            &path,
            "001.002.003.000 - 001.002.003.255 , 000 , Example Range\n\
             010.000.000.001-010.000.000.009 , 100 , Compact\n\
             198.051.100.001 - 198.051.100.050 , 128 , Allowed high level\n\
             203.000.113.001 - 203.000.113.050 , 200 , Allowed level 200\n\
             1.2.3.256 - 1.2.3.300 , 000 , not an address\n",
        )
        .unwrap();
        let mut filter = IpFilter::new();
        assert_eq!(filter.load_file(&path).unwrap(), 2);
        assert!(filter.is_blocked("1.2.3.77".parse().unwrap()));
        assert!(filter.is_blocked("10.0.0.5".parse().unwrap()));
        assert!(!filter.is_blocked("10.0.0.10".parse().unwrap()));
        assert!(!filter.is_blocked("198.51.100.10".parse().unwrap()));
        assert!(!filter.is_blocked("203.0.113.10".parse().unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_file_mixed_formats() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("synapse_ipfilter_test_{}.txt", std::process::id()));
        std::fs::write(
            &path,
            "# comment line\n\
             \n\
             1.2.3.4 - 1.2.3.10 , Example blocklist range\n\
             10.0.0.0/8\n\
             this line is garbage\n",
        )
        .unwrap();

        let mut filter = IpFilter::new();
        let loaded = filter.load_file(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(loaded, 2);
        assert!(filter.is_blocked(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 7))));
        assert!(filter.is_blocked(IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9))));
        assert!(!filter.is_blocked(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 20))));
    }

    #[test]
    fn normalized_lookups_match_linear_scan_and_merge_overlaps() {
        let mut f = IpFilter::new();
        f.add_v4_cidr(Ipv4Addr::new(10, 0, 0, 0), 24);
        f.add_v4_range(
            Ipv4Addr::new(10, 0, 0, 200),
            Ipv4Addr::new(10, 0, 1, 50),
            "overlap",
        );
        f.add_v4_cidr(Ipv4Addr::new(192, 168, 0, 0), 16);
        f.add_v6_range(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::ff".parse().unwrap(),
            "v6",
        );
        let probes: Vec<IpAddr> = [
            "9.255.255.255",
            "10.0.0.0",
            "10.0.0.255",
            "10.0.1.50",
            "10.0.1.51",
            "192.168.44.1",
            "192.169.0.0",
            "2001:db8::1",
            "2001:db8::100",
            "::1",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        let before: Vec<bool> = probes.iter().map(|&p| f.is_blocked(p)).collect();
        f.normalize();
        let after: Vec<bool> = probes.iter().map(|&p| f.is_blocked(p)).collect();
        assert_eq!(before, after);
        assert_eq!(
            after,
            vec![false, true, true, true, false, true, false, true, false, false]
        );
        assert_eq!(f.total_rules(), 3, "overlapping v4 ranges merge into one");
        // Adding after normalizing stays correct (falls back to scanning until re-normalized).
        f.add_v4_cidr(Ipv4Addr::new(172, 16, 0, 0), 12);
        assert!(f.is_blocked("172.20.1.1".parse().unwrap()));
        // IPv4-mapped IPv6 addresses match IPv4 rules too.
        assert!(f.is_blocked("::ffff:172.20.1.1".parse().unwrap()));
        assert!(!f.is_blocked("::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn compact_range_sizes_without_heap_descriptions() {
        assert_eq!(std::mem::size_of::<Ipv4Range>(), 8);
        assert_eq!(std::mem::size_of::<Ipv6Range>(), 32);
    }
}
