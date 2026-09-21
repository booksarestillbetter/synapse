use std::collections::{HashMap, HashSet};
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
    /// Peer download progress fraction (0.0 to 1.0), used by anti-leech seed choking.
    pub progress: f32,
    /// Optional timestamp when this peer was last unchoked.
    pub last_unchoked: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChokeDecisions<Id> {
    pub unchoke: Vec<Id>,
    pub choke: Vec<Id>,
}

/// Seed-side choking algorithms (matching libtorrent `choker.cpp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeedChokingAlgorithm {
    /// Fair round-robin rotation among interested peers so all peers receive equal upload attention.
    #[default]
    RoundRobin,
    /// Prioritize peers that are closest to completion (highest progress fraction).
    AntiLeech,
    /// Prioritize peers that are downloading from us at the highest rate.
    FastestUpload,
}

/// Standard BitTorrent tit-for-tat choking: unchoke the `regular_unchokes` interested
/// peers we're getting the best rate from (download rate while leeching, upload rate
/// while seeding - reciprocate with whoever's actually helping us), plus one rotating
/// "optimistic" unchoke to give new/slow peers a chance to prove themselves.
pub struct Choker<Id> {
    regular_unchokes: usize,
    optimistic_interval: Duration,
    last_rotation: Instant,
    optimistic_peer: Option<Id>,
    rotation_index: usize,
    seed_algorithm: SeedChokingAlgorithm,
    round_robin_offset: usize,
}

impl<Id: Copy + Eq + Hash> Choker<Id> {
    pub fn new(regular_unchokes: usize, optimistic_interval: Duration) -> Choker<Id> {
        Choker {
            regular_unchokes,
            optimistic_interval,
            last_rotation: Instant::now(),
            optimistic_peer: None,
            rotation_index: 0,
            seed_algorithm: SeedChokingAlgorithm::RoundRobin,
            round_robin_offset: 0,
        }
    }

    pub fn set_regular_unchokes(&mut self, regular_unchokes: usize) {
        self.regular_unchokes = regular_unchokes;
    }

    pub fn set_seed_algorithm(&mut self, algo: SeedChokingAlgorithm) {
        self.seed_algorithm = algo;
    }

    pub fn seed_algorithm(&self) -> SeedChokingAlgorithm {
        self.seed_algorithm
    }

    pub fn regular_unchokes(&self) -> usize {
        self.regular_unchokes
    }

    /// Recomputes who should be choked/unchoked. `we_are_seeding` selects which rate/algorithm
    /// ranks peers: download rate (reciprocate with who's feeding us fastest) while
    /// leeching, seed algorithm while seeding.
    pub fn rechoke(&mut self, peers: &[PeerStats<Id>], we_are_seeding: bool) -> ChokeDecisions<Id> {
        let now = Instant::now();
        let interval = if we_are_seeding {
            Duration::from_secs(15).min(self.optimistic_interval)
        } else {
            self.optimistic_interval
        };
        let rotate = now.duration_since(self.last_rotation) >= interval;

        let mut interested: Vec<&PeerStats<Id>> = peers.iter().filter(|p| p.interested).collect();

        if we_are_seeding {
            match self.seed_algorithm {
                SeedChokingAlgorithm::FastestUpload => {
                    interested.sort_by_key(|a| std::cmp::Reverse(a.upload_rate));
                }
                SeedChokingAlgorithm::AntiLeech => {
                    interested.sort_by(|a, b| {
                        b.progress
                            .partial_cmp(&a.progress)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    });
                }
                SeedChokingAlgorithm::RoundRobin => {
                    if rotate && !interested.is_empty() {
                        self.round_robin_offset = (self.round_robin_offset
                            + self.regular_unchokes.max(1))
                            % interested.len();
                    }
                    if !interested.is_empty() {
                        let offset = self.round_robin_offset % interested.len();
                        interested.rotate_left(offset);
                    }
                }
            }
        } else {
            // Leeching: tit-for-tat reciprocation (fastest download rate first)
            interested.sort_by_key(|a| std::cmp::Reverse(a.download_rate));
        }

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

/// Demand input from an active swarm for session-wide unchoke allocation.
#[derive(Debug, Clone)]
pub struct SwarmChokerDemand<SwarmId> {
    pub swarm_id: SwarmId,
    /// Torrent priority (1 to 7, default 4).
    pub priority: u8,
    /// Whether this swarm is seeding.
    pub is_seeding: bool,
    /// Number of connected peers currently interested in downloading from us.
    pub interested_peers: usize,
}

/// Global session-wide choker allocating unchoke slot budgets across multiple swarms.
#[derive(Debug, Clone)]
pub struct SessionChoker {
    pub global_unchoke_slots: usize,
    pub slot_bandwidth: u64,
}

impl SessionChoker {
    pub fn new(global_unchoke_slots: usize, slot_bandwidth: u64) -> Self {
        Self {
            global_unchoke_slots: global_unchoke_slots.max(1),
            slot_bandwidth: slot_bandwidth.max(1),
        }
    }

    /// Calculates effective unchoke slots available given the upload rate limit.
    /// Matches libtorrent `choker.cpp`: if upload rate is limited, slots = max(4, rate / slot_bandwidth).
    pub fn effective_slots(&self, upload_rate_limit: u64) -> usize {
        if upload_rate_limit > 0 {
            let slots = (upload_rate_limit / self.slot_bandwidth) as usize;
            slots.max(4)
        } else {
            self.global_unchoke_slots
        }
    }

    /// Allocates unchoke slots across swarms based on priority weights and interested peers.
    pub fn allocate_slots<SwarmId: Copy + Eq + Hash>(
        &self,
        demands: &[SwarmChokerDemand<SwarmId>],
        upload_rate_limit: u64,
    ) -> HashMap<SwarmId, usize> {
        let total_slots = self.effective_slots(upload_rate_limit);
        let mut result = HashMap::new();

        let active_demands: Vec<&SwarmChokerDemand<SwarmId>> =
            demands.iter().filter(|d| d.interested_peers > 0).collect();

        if active_demands.is_empty() {
            return result;
        }

        // Weight = priority (1..=7) * (if is_seeding { 1 } else { 2 })
        // Leeching swarms receive 2x weight to incentivize reciprocal download rates.
        let weights: Vec<u32> = active_demands
            .iter()
            .map(|d| {
                let p = (d.priority.clamp(1, 7)) as u32;
                if d.is_seeding {
                    p
                } else {
                    p * 2
                }
            })
            .collect();

        let total_weight: u32 = weights.iter().sum();
        if total_weight == 0 {
            return result;
        }

        let mut allocated_total = 0;
        for (i, d) in active_demands.iter().enumerate() {
            let share = ((total_slots as u32 * weights[i]) / total_weight) as usize;
            let slots = share.max(1).min(d.interested_peers);
            allocated_total += slots;
            result.insert(d.swarm_id, slots);
        }

        // If spare slots remain, distribute to highest-weight swarms that have unallocated interested peers
        if allocated_total < total_slots {
            let mut remaining = total_slots - allocated_total;
            let mut indexed_demands: Vec<(usize, &SwarmChokerDemand<SwarmId>)> =
                active_demands.iter().copied().enumerate().collect();
            indexed_demands.sort_by_key(|&(idx, _)| std::cmp::Reverse(weights[idx]));

            for (_, d) in indexed_demands {
                if remaining == 0 {
                    break;
                }
                if let Some(current) = result.get_mut(&d.swarm_id) {
                    if *current < d.interested_peers {
                        let can_add = (d.interested_peers - *current).min(remaining);
                        *current += can_add;
                        remaining -= can_add;
                    }
                }
            }
        }

        result
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
            progress: 0.0,
            last_unchoked: None,
        }
    }

    fn peer_with_progress(id: u32, progress: f32, interested: bool) -> PeerStats<u32> {
        PeerStats {
            id,
            download_rate: 0,
            upload_rate: 0,
            interested,
            progress,
            last_unchoked: None,
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
    fn seeding_ranks_by_upload_rate_with_fastest_upload() {
        let mut choker: Choker<u32> = Choker::new(1, Duration::from_secs(600));
        choker.set_seed_algorithm(SeedChokingAlgorithm::FastestUpload);
        let peers = vec![peer(1, 1000, 10, true), peer(2, 0, 500, true)];
        let decisions = choker.rechoke(&peers, true);
        assert!(decisions.unchoke.contains(&2));
    }

    #[test]
    fn seeding_ranks_by_progress_with_anti_leech() {
        let mut choker: Choker<u32> = Choker::new(1, Duration::from_secs(600));
        choker.set_seed_algorithm(SeedChokingAlgorithm::AntiLeech);
        let peers = vec![
            peer_with_progress(1, 0.20, true),
            peer_with_progress(2, 0.95, true),
            peer_with_progress(3, 0.50, true),
        ];
        let decisions = choker.rechoke(&peers, true);
        // Peer 2 has the highest progress (95%) and must be regular unchoked
        assert!(decisions.unchoke.contains(&2));
    }

    #[test]
    fn seeding_round_robin_rotates_unchoke_window() {
        let mut choker: Choker<u32> = Choker::new(1, Duration::from_millis(10));
        choker.set_seed_algorithm(SeedChokingAlgorithm::RoundRobin);
        let peers = vec![
            peer(1, 0, 0, true),
            peer(2, 0, 0, true),
            peer(3, 0, 0, true),
        ];
        let d1 = choker.rechoke(&peers, true);
        assert!(!d1.unchoke.is_empty());

        // Sleep to trigger rotation
        std::thread::sleep(Duration::from_millis(20));
        let d2 = choker.rechoke(&peers, true);
        assert!(!d2.unchoke.is_empty());
    }

    #[test]
    fn optimistic_unchoke_does_not_rotate_before_its_interval() {
        let mut choker: Choker<u32> = Choker::new(1, Duration::from_secs(600));
        let peers = vec![
            peer(1, 100, 0, true),
            peer(2, 10, 0, true),
            peer(3, 5, 0, true),
        ];
        let first: HashSet<_> = choker.rechoke(&peers, false).unchoke.into_iter().collect();
        let second: HashSet<_> = choker.rechoke(&peers, false).unchoke.into_iter().collect();
        assert_eq!(first, second);
    }

    #[test]
    fn optimistic_unchoke_rotates_immediately_if_its_peer_disconnected() {
        let mut choker: Choker<u32> = Choker::new(1, Duration::from_secs(600));
        let peers = vec![
            peer(1, 100, 0, true),
            peer(2, 10, 0, true),
            peer(3, 5, 0, true),
        ];
        let first = choker.rechoke(&peers, false);
        let optimistic = *first.unchoke.iter().find(|id| **id != 1).unwrap();

        let remaining: Vec<_> = peers.into_iter().filter(|p| p.id != optimistic).collect();
        let second = choker.rechoke(&remaining, false);
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

    #[test]
    fn test_session_choker_allocation_and_rate_based_sizing() {
        let session = SessionChoker::new(8, 16384);

        // 1. Unlimited upload rate uses default global_unchoke_slots (8)
        assert_eq!(session.effective_slots(0), 8);

        // 2. Rate of 128 KiB/s (131072 B/s) / 16 KiB/s = 8 slots
        assert_eq!(session.effective_slots(131072), 8);

        // 3. Low rate of 16 KiB/s enforces min floor of 4 slots
        assert_eq!(session.effective_slots(16384), 4);

        // 4. Multi-swarm allocation weighted by priority
        let demands = vec![
            SwarmChokerDemand {
                swarm_id: 1u32,
                priority: 7, // High priority leecher (weight = 7 * 2 = 14)
                is_seeding: false,
                interested_peers: 10,
            },
            SwarmChokerDemand {
                swarm_id: 2u32,
                priority: 1, // Low priority seeder (weight = 1 * 1 = 1)
                is_seeding: true,
                interested_peers: 10,
            },
        ];

        let allocation = session.allocate_slots(&demands, 0);
        let s1 = allocation.get(&1).copied().unwrap_or(0);
        let s2 = allocation.get(&2).copied().unwrap_or(0);

        assert!(
            s1 > s2,
            "High priority leecher should receive more slots than low priority seeder"
        );
        assert_eq!(s1 + s2, 8, "All 8 slots should be allocated");
    }
}
