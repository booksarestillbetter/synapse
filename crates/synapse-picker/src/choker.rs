use std::collections::HashSet;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// A peer's current stats, as input to a rechoke decision. Rate units don't matter as
/// long as they're consistent (bytes/sec is the natural choice) - the choker only ever
/// compares them to each other, never against an absolute threshold.
#[derive(Debug, Clone, Copy)]
pub struct PeerStats<Id> {
    pub id: Id,
    /// Bytes/sec we're downloading from this peer - what matters while leeching.
    pub download_rate: u64,
    /// Bytes/sec we're uploading to this peer - what matters while seeding.
    pub upload_rate: u64,
    /// Whether this peer has told us it's interested in downloading from us. Choking an
    /// uninterested peer has no effect, so they're excluded from the ranked pool.
    pub interested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChokeDecisions<Id> {
    pub unchoke: Vec<Id>,
    pub choke: Vec<Id>,
}

/// Standard BitTorrent tit-for-tat choking: unchoke the `regular_unchokes` interested
/// peers we're getting the best rate from (download rate while leeching, upload rate
/// while seeding - reciprocate with whoever's actually helping us), plus one rotating
/// "optimistic" unchoke to give new/slow peers a chance to prove themselves rather than
pub struct Choker<Id> {
    regular_unchokes: usize,
    optimistic_interval: Duration,
    last_rotation: Instant,
    optimistic_peer: Option<Id>,
    rotation_index: usize,
}

impl<Id: Copy + Eq + Hash> Choker<Id> {
    pub fn new(regular_unchokes: usize, optimistic_interval: Duration) -> Choker<Id> {
        Choker {
            regular_unchokes,
            optimistic_interval,
            last_rotation: Instant::now(),
            optimistic_peer: None,
            rotation_index: 0,
        }
    }

    /// Recomputes who should be choked/unchoked. `we_are_seeding` selects which rate
    /// ranks peers: download rate (reciprocate with who's feeding us fastest) while
    /// leeching, upload rate (spread our upload capacity toward who's downloading
    /// fastest from us) while seeding.
    pub fn rechoke(&mut self, peers: &[PeerStats<Id>], we_are_seeding: bool) -> ChokeDecisions<Id> {
        let now = Instant::now();
        let interval = if we_are_seeding {
            Duration::from_secs(15).min(self.optimistic_interval)
        } else {
            self.optimistic_interval
        };
        let rotate = now.duration_since(self.last_rotation) >= interval;

        let mut interested: Vec<&PeerStats<Id>> = peers.iter().filter(|p| p.interested).collect();
        interested.sort_by(|a, b| {
            let (ra, rb) = if we_are_seeding {
                (a.upload_rate, b.upload_rate)
            } else {
                (a.download_rate, b.download_rate)
            };
            rb.cmp(&ra) // descending: best rate first
        });

        let mut unchoke: HashSet<Id> = interested
            .iter()
            .take(self.regular_unchokes)
            .map(|p| p.id)
            .collect();

        let remaining: Vec<Id> = interested
            .iter()
            .map(|p| p.id)
            .filter(|id| !unchoke.contains(id))
            .collect();

        let still_present = |id: Id| peers.iter().any(|p| p.id == id && p.interested);
        if rotate || self.optimistic_peer.is_none_or(|id| !still_present(id)) {
            let candidate = if remaining.is_empty() {
                None
            } else {
                let idx = self.rotation_index % remaining.len();
                self.rotation_index = self.rotation_index.wrapping_add(1);
                Some(remaining[idx])
            };
            self.optimistic_peer = candidate;
            self.last_rotation = now;
        }
        if let Some(id) = self.optimistic_peer {
            unchoke.insert(id);
        }

        let choke = peers
            .iter()
            .map(|p| p.id)
            .filter(|id| !unchoke.contains(id))
            .collect();

        ChokeDecisions {
            unchoke: unchoke.into_iter().collect(),
            choke,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: u32, download_rate: u64, upload_rate: u64, interested: bool) -> PeerStats<u32> {
        PeerStats {
            id,
            download_rate,
            upload_rate,
            interested,
        }
    }

    #[test]
    fn unchokes_the_fastest_interested_peers_while_leeching() {
        let mut choker: Choker<u32> = Choker::new(2, Duration::from_secs(600));
        let peers = vec![
            peer(1, 100, 0, true),
            peer(2, 300, 0, true),
            peer(3, 200, 0, true),
            peer(4, 50, 0, true),
        ];
        let decisions = choker.rechoke(&peers, false);
        // Top 2 by download rate (2, 3) plus one optimistic unchoke from the rest.
        assert!(decisions.unchoke.contains(&2));
        assert!(decisions.unchoke.contains(&3));
        assert_eq!(decisions.unchoke.len(), 3); // 2 regular + 1 optimistic
    }

    #[test]
    fn uninterested_peers_are_never_unchoked() {
        let mut choker: Choker<u32> = Choker::new(2, Duration::from_secs(600));
        let peers = vec![peer(1, 1000, 0, false), peer(2, 10, 0, true)];
        let decisions = choker.rechoke(&peers, false);
        assert!(!decisions.unchoke.contains(&1));
        assert!(decisions.choke.contains(&1));
    }

    #[test]
    fn seeding_ranks_by_upload_rate_instead_of_download_rate() {
        let mut choker: Choker<u32> = Choker::new(1, Duration::from_secs(600));
        let peers = vec![peer(1, 1000, 10, true), peer(2, 0, 500, true)];
        let decisions = choker.rechoke(&peers, true);
        assert!(decisions.unchoke.contains(&2)); // higher upload rate while seeding
    }

    #[test]
    fn optimistic_unchoke_does_not_rotate_before_its_interval() {
        let mut choker: Choker<u32> = Choker::new(1, Duration::from_secs(600));
        let peers = vec![peer(1, 100, 0, true), peer(2, 10, 0, true), peer(3, 5, 0, true)];
        let first: HashSet<_> = choker.rechoke(&peers, false).unchoke.into_iter().collect();
        let second: HashSet<_> = choker.rechoke(&peers, false).unchoke.into_iter().collect();
        assert_eq!(first, second);
    }

    #[test]
    fn optimistic_unchoke_rotates_immediately_if_its_peer_disconnected() {
        let mut choker: Choker<u32> = Choker::new(1, Duration::from_secs(600));
        let peers = vec![peer(1, 100, 0, true), peer(2, 10, 0, true), peer(3, 5, 0, true)];
        let first = choker.rechoke(&peers, false);
        let optimistic = *first.unchoke.iter().find(|id| **id != 1).unwrap();

        let remaining: Vec<_> = peers.into_iter().filter(|p| p.id != optimistic).collect();
        let second = choker.rechoke(&remaining, false);
        // Must not still be trying to unchoke a peer that's gone.
        assert!(!second.unchoke.contains(&optimistic));
    }

    #[test]
    fn every_peer_ends_up_in_exactly_one_of_choke_or_unchoke() {
        let mut choker: Choker<u32> = Choker::new(2, Duration::from_secs(600));
        let peers = vec![
            peer(1, 100, 0, true),
            peer(2, 300, 0, true),
            peer(3, 200, 0, false),
            peer(4, 50, 0, true),
        ];
        let decisions = choker.rechoke(&peers, false);
        for p in &peers {
            let in_unchoke = decisions.unchoke.contains(&p.id);
            let in_choke = decisions.choke.contains(&p.id);
            assert!(in_unchoke ^ in_choke, "peer {} in both/neither", p.id);
        }
    }
}
