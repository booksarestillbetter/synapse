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

fn voter_key(voter: IpAddr) -> Vec<u8> {
    match voter {
        IpAddr::V4(v4) => v4.octets()[..2].to_vec(),
        IpAddr::V6(v6) => v6.octets()[..4].to_vec(),
    }
}

/// Reported addresses that can never be our public address.
fn plausible(reported: IpAddr) -> bool {
    !(reported.is_unspecified() || reported.is_loopback() || reported.is_multicast())
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
        // Only public reporters count: a LAN neighbour reports our private address.
        if !plausible(reported) || voter.is_loopback() {
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
        }
        assert_eq!(v.consensus(), None);
        assert_eq!(
            v.vote("127.0.0.1".parse().unwrap(), "203.0.113.7".parse().unwrap()),
            None
        );
    }
}
