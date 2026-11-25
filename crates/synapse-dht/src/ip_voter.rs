//! External-address consensus for BEP 42.
//!
//! A node behind NAT does not know its public address, yet BEP 42 requires its node id to be
//! derived from it. DHT nodes report the address they see a query arriving from in the `ip`
//! field of their replies; no single reporter can be trusted (it may lie, or be behind the
//! same NAT), so [`IpVoter`] only accepts an address once enough *independent* nodes agree.
//! Independence is approximated by keying votes on the reporter's /16 (IPv4) or /32 (IPv6)
//! prefix, so one operator's cluster of nodes counts once (libtorrent's `ip_voter` does the
//! same with `ip_voter::add_vote`).

use std::collections::HashMap;
use std::net::IpAddr;

/// Distinct voter groups that must have voted before any address can win.
const MIN_VOTERS: usize = 8;
/// Fraction (percent) of votes the winner needs.
const MIN_AGREEMENT_PERCENT: usize = 60;
/// Most voter groups remembered; the table is reset when it fills (a fresh, rolling sample).
const MAX_VOTERS: usize = 256;

#[derive(Default)]
pub struct IpVoter {
    /// voter group -> the address it reported.
    votes: HashMap<Vec<u8>, IpAddr>,
    winner: Option<IpAddr>,
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

fn voter_key(voter: IpAddr) -> Vec<u8> {
    match canonical_ip(voter) {
        IpAddr::V4(v4) => v4.octets()[..2].to_vec(),
        IpAddr::V6(v6) => v6.octets()[..4].to_vec(),
    }
}

/// Reported addresses that can never be our public internet address.
fn plausible(reported: IpAddr) -> bool {
    let reported = canonical_ip(reported);
    if reported.is_unspecified() || reported.is_loopback() || reported.is_multicast() {
        return false;
    }
    match reported {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // RFC 6598 CGNAT 100.64.0.0/10
                || o[0] >= 240
            {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return plausible(IpAddr::V4(v4));
            }
            let s = v6.segments();
            // Keep this in sync with `synapse_tracker::safe_http::is_public_ip`'s IPv6 range
            // list: a range accepted as "plausible" here but rejected there would let a peer
            // spoof BEP 42 external-IP consensus with an address the tracker-side SSRF guard
            // would otherwise block.
            !((s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link local fe80::/10
                || (s[0] & 0xffc0) == 0xfec0 // deprecated site-local fec0::/10
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation 2001:db8::/32
                || (s[0] == 0x2001 && s[1] < 0x0200) // IETF protocol assignments 2001::/23 (incl. Teredo)
                || (s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0]) // RFC 6052 NAT64 64:ff9b::/96
                || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001) // RFC 8215 Local-Use NAT64 64:ff9b:1::/48
                || s[0..6] == [0, 0, 0, 0, 0, 0] // Deprecated IPv4-compatible ::/96
                || (s[0] == 0x0100 && s[1..4] == [0, 0, 0])) // RFC 6666 Discard-Only 100::/64
        }
    }
}

impl IpVoter {
    pub fn new() -> Self {
        Self::default()
    }

    /// The agreed external address, once consensus has been reached.
    pub fn consensus(&self) -> Option<IpAddr> {
        self.winner
    }

    /// Records that `voter` reported our address as `reported`. Returns the new consensus
    /// address if this vote *changed* it (first agreement, or a switch after a network change).
    pub fn vote(&mut self, voter: IpAddr, reported: IpAddr) -> Option<IpAddr> {
        let voter = canonical_ip(voter);
        let reported = canonical_ip(reported);
        // Only public reporters and public reported addresses count: a LAN neighbour
        // reports our private address and cannot be used to spoof external consensus.
        if !plausible(reported) || !plausible(voter) {
            return None;
        }
        if self.votes.len() >= MAX_VOTERS && !self.votes.contains_key(&voter_key(voter)) {
            self.votes.clear();
        }
        self.votes.insert(voter_key(voter), reported);
        let mut tally: HashMap<IpAddr, usize> = HashMap::new();
        for ip in self.votes.values() {
            *tally.entry(*ip).or_default() += 1;
        }
        let total = self.votes.len();
        if total < MIN_VOTERS {
            return None;
        }
        let (top, count) = tally.into_iter().max_by_key(|(_, c)| *c)?;
        if count * 100 >= total * MIN_AGREEMENT_PERCENT && self.winner != Some(top) {
            self.winner = Some(top);
            return Some(top);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn voter(n: u8) -> IpAddr {
        IpAddr::from([20 + n, n, 1, 1])
    }

    #[test]
    fn no_address_wins_before_enough_independent_voters() {
        let mut v = IpVoter::new();
        let me: IpAddr = "203.0.113.7".parse().unwrap();
        for n in 0..(MIN_VOTERS as u8 - 1) {
            assert_eq!(v.vote(voter(n), me), None);
        }
        assert_eq!(v.consensus(), None);
        assert_eq!(v.vote(voter(99), me), Some(me));
        assert_eq!(v.consensus(), Some(me));
        // Further agreeing votes do not re-announce the same winner.
        assert_eq!(v.vote(voter(100), me), None);
    }

    #[test]
    fn one_reporter_group_cannot_vote_repeatedly() {
        let mut v = IpVoter::new();
        let liar: IpAddr = "198.51.100.9".parse().unwrap();
        for host in 0..200u8 {
            // Same /16, different hosts: still one voter.
            assert_eq!(v.vote(IpAddr::from([77, 7, 0, host]), liar), None);
        }
        assert_eq!(v.consensus(), None);
    }

    #[test]
    fn a_minority_of_liars_does_not_win_and_a_majority_switch_is_followed() {
        let mut v = IpVoter::new();
        let real: IpAddr = "203.0.113.7".parse().unwrap();
        let fake: IpAddr = "198.51.100.66".parse().unwrap();
        for n in 0..12u8 {
            v.vote(voter(n), if n % 4 == 0 { fake } else { real });
        }
        assert_eq!(
            v.consensus(),
            Some(real),
            "3 liars in 12 must not beat the truth"
        );
        // The network changes: reporters now agree on a new address.
        let new: IpAddr = "203.0.113.200".parse().unwrap();
        let mut switched = None;
        for n in 20..60u8 {
            if let Some(w) = v.vote(voter(n), new) {
                switched = Some(w);
            }
        }
        assert_eq!(switched, Some(new));
    }

    #[test]
    fn implausible_reports_are_ignored() {
        let mut v = IpVoter::new();
        for n in 0..20u8 {
            assert_eq!(v.vote(voter(n), "0.0.0.0".parse().unwrap()), None);
            assert_eq!(v.vote(voter(n), "127.0.0.1".parse().unwrap()), None);
            assert_eq!(v.vote(voter(n), "10.0.0.1".parse().unwrap()), None);
            assert_eq!(v.vote(voter(n), "172.16.5.4".parse().unwrap()), None);
            assert_eq!(v.vote(voter(n), "192.168.1.1".parse().unwrap()), None);
            assert_eq!(v.vote(voter(n), "169.254.1.1".parse().unwrap()), None);
            assert_eq!(v.vote(voter(n), "100.64.0.1".parse().unwrap()), None);
            assert_eq!(v.vote(voter(n), "240.0.0.1".parse().unwrap()), None);
            assert_eq!(v.vote(voter(n), "fc00::1".parse().unwrap()), None);
            assert_eq!(v.vote(voter(n), "fe80::1".parse().unwrap()), None);
        }
        assert_eq!(v.consensus(), None);
        assert_eq!(
            v.vote("127.0.0.1".parse().unwrap(), "203.0.113.7".parse().unwrap()),
            None
        );
        // Non-public voters (RFC1918, ULA, IPv4-mapped private) cannot cast votes either.
        for n in 0..20u8 {
            assert_eq!(
                v.vote(
                    IpAddr::from([192, 168, n, 1]),
                    "203.0.113.7".parse().unwrap()
                ),
                None
            );
            assert_eq!(
                v.vote(
                    "::ffff:10.0.0.1".parse().unwrap(),
                    "203.0.113.7".parse().unwrap()
                ),
                None
            );
        }
        assert_eq!(v.consensus(), None);
    }

    #[test]
    fn ipv4_mapped_votes_share_canonical_v4_bucket_and_identity() {
        let mut v = IpVoter::new();
        let me_v4: IpAddr = "203.0.113.7".parse().unwrap();
        let me_mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        // Same /16 across v4 and ::ffff:v4 counts as only ONE independent voter.
        assert_eq!(v.vote("20.1.0.1".parse().unwrap(), me_v4), None);
        assert_eq!(v.vote("::ffff:20.1.0.2".parse().unwrap(), me_mapped), None);
        for n in 2..9u8 {
            let voted = v.vote(voter(n), me_mapped);
            if n < 8 {
                assert_eq!(voted, None);
            } else {
                assert_eq!(voted, Some(me_v4));
            }
        }
    }
}
