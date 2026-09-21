use std::collections::{BTreeMap, BTreeSet};

use crate::Bitfield;

/// Extent size for piece-extent affinity grouping (libtorrent parity).
pub const EXTENT_SIZE: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Pick the rarest piece (fewest connected peers have it) the requesting peer has
    /// that we're still missing, prioritizing higher priority tiers first (7 down to 1).
    RarestFirst,
    /// Pick the lowest-indexed missing piece the requesting peer has, prioritizing
    /// higher priority tiers first. Used for streaming and sequential access.
    Sequential,
    /// Pick the highest-indexed missing piece the requesting peer has, prioritizing
    /// higher priority tiers first. Used for downloading file trailers and metadata first.
    Reverse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PieceState {
    Missing,
    /// A request for this piece is outstanding. Doesn't block other peers from also
    /// being picked for it near endgame (see `pick`'s `allow_duplicates` parameter).
    Requested,
    Complete,
}

#[derive(Debug, Clone, Default)]
struct PriorityTier {
    /// Maps availability count -> set of missing piece indices in this tier.
    buckets: BTreeMap<u32, BTreeSet<u32>>,
    /// Maps availability count -> set of requested piece indices in this tier.
    requested_buckets: BTreeMap<u32, BTreeSet<u32>>,
    /// Set of all missing piece indices in this tier (for O(1)/fast sequential scans).
    missing_pieces: BTreeSet<u32>,
    /// Set of all requested piece indices in this tier.
    requested_pieces: BTreeSet<u32>,
}

impl PriorityTier {
    fn insert_missing(&mut self, piece: u32, avail: u32) {
        self.buckets.entry(avail).or_default().insert(piece);
        self.missing_pieces.insert(piece);
    }

    fn remove_missing(&mut self, piece: u32, avail: u32) {
        if let Some(set) = self.buckets.get_mut(&avail) {
            set.remove(&piece);
            if set.is_empty() {
                self.buckets.remove(&avail);
            }
        }
        self.missing_pieces.remove(&piece);
    }

    fn insert_requested(&mut self, piece: u32, avail: u32) {
        self.requested_buckets
            .entry(avail)
            .or_default()
            .insert(piece);
        self.requested_pieces.insert(piece);
    }

    fn remove_requested(&mut self, piece: u32, avail: u32) {
        if let Some(set) = self.requested_buckets.get_mut(&avail) {
            set.remove(&piece);
            if set.is_empty() {
                self.requested_buckets.remove(&avail);
            }
        }
        self.requested_pieces.remove(&piece);
    }

    fn update_missing_avail(&mut self, piece: u32, old_avail: u32, new_avail: u32) {
        self.remove_missing(piece, old_avail);
        self.insert_missing(piece, new_avail);
    }

    fn update_requested_avail(&mut self, piece: u32, old_avail: u32, new_avail: u32) {
        self.remove_requested(piece, old_avail);
        self.insert_requested(piece, new_avail);
    }
}

/// Tracks which pieces we have/want and picks what to request next from a given peer.
///
/// Features (libtorrent parity):
/// - Bucketed availability indexing: pieces are partitioned into availability buckets per priority tier,
///   enabling O(1) / O(log n) rarest-first piece discovery rather than linear scans.
/// - 8 priority tiers (0..=7): tier 0 is unselected/DoNotDownload; tiers 1..=7 are weighted where
///   higher tiers are strictly chosen before lower tiers. Default is tier 4 (Normal).
/// - Extent affinity: contiguous piece clustering to maximize sequential disk writes.
/// - Reverse & sequential range selection for media streaming.
pub struct Picker {
    mode: Mode,
    states: Vec<PieceState>,
    availability: Vec<u32>,
    priorities: Vec<u8>,
    tiers: [PriorityTier; 8],
}

impl Picker {
    pub fn new(num_pieces: usize, mode: Mode) -> Picker {
        let mut picker = Picker {
            mode,
            states: vec![PieceState::Missing; num_pieces],
            availability: vec![0; num_pieces],
            priorities: vec![4; num_pieces], // Default priority 4 (Normal)
            tiers: Default::default(),
        };

        for p in 0..num_pieces as u32 {
            picker.tiers[4].insert_missing(p, 0);
        }

        picker
    }

    /// Marks pieces already known-complete at construction (e.g. resuming from bitfield).
    pub fn with_completed(mut self, have: &Bitfield) -> Picker {
        for i in 0..self.states.len() {
            if have.has(i) {
                let piece = i as u32;
                self.states[i] = PieceState::Complete;
                let prio = self.priorities[i] as usize;
                let avail = self.availability[i];
                if prio > 0 {
                    self.tiers[prio].remove_missing(piece, avail);
                }
            }
        }
        self
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// Sets wanted/unwanted flags for all pieces (backwards-compatible API).
    /// `true` maps to priority 4 (Normal); `false` maps to priority 0 (DoNotDownload).
    pub fn set_priorities(&mut self, wanted: Vec<bool>) {
        debug_assert_eq!(wanted.len(), self.states.len());
        for (i, &w) in wanted.iter().enumerate() {
            self.set_piece_priority(i as u32, if w { 4 } else { 0 });
        }
    }

    /// Sets wanted/unwanted priority for a contiguous range of pieces (backwards-compatible API).
    pub fn set_piece_range_priority(&mut self, start: u32, end: u32, wanted: bool) {
        let prio = if wanted { 4 } else { 0 };
        self.set_piece_range_priority_tier(start, end, prio);
    }

    /// Sets granular priority tier (0..=7) for a contiguous range of pieces.
    pub fn set_piece_range_priority_tier(&mut self, start: u32, end: u32, priority: u8) {
        let end = (end as usize).min(self.states.len().saturating_sub(1)) as u32;
        for p in start..=end {
            self.set_piece_priority(p, priority);
        }
    }

    /// Sets priority tier (0..=7) for a single piece.
    pub fn set_piece_priority(&mut self, index: u32, priority: u8) {
        let idx = index as usize;
        if idx >= self.states.len() {
            return;
        }
        let new_prio = priority.min(7);
        let old_prio = self.priorities[idx];
        if old_prio == new_prio {
            return;
        }

        let avail = self.availability[idx];
        let state = self.states[idx];

        // Remove from old tier
        if old_prio > 0 {
            match state {
                PieceState::Missing => self.tiers[old_prio as usize].remove_missing(index, avail),
                PieceState::Requested => {
                    self.tiers[old_prio as usize].remove_requested(index, avail)
                }
                PieceState::Complete => {}
            }
        }

        self.priorities[idx] = new_prio;

        // Add to new tier
        if new_prio > 0 {
            match state {
                PieceState::Missing => self.tiers[new_prio as usize].insert_missing(index, avail),
                PieceState::Requested => {
                    self.tiers[new_prio as usize].insert_requested(index, avail)
                }
                PieceState::Complete => {}
            }
        }
    }

    /// Returns priority tier (0..=7) of a piece.
    pub fn piece_priority(&self, index: u32) -> u8 {
        self.priorities.get(index as usize).copied().unwrap_or(0)
    }

    /// Increments availability count when a peer advertises having piece `index`.
    pub fn peer_has(&mut self, index: u32) {
        let idx = index as usize;
        if idx >= self.states.len() {
            return;
        }
        let old_avail = self.availability[idx];
        let new_avail = old_avail.saturating_add(1);
        self.availability[idx] = new_avail;

        let prio = self.priorities[idx] as usize;
        if prio > 0 {
            match self.states[idx] {
                PieceState::Missing => {
                    self.tiers[prio].update_missing_avail(index, old_avail, new_avail)
                }
                PieceState::Requested => {
                    self.tiers[prio].update_requested_avail(index, old_avail, new_avail)
                }
                PieceState::Complete => {}
            }
        }
    }

    /// Decrements availability count when a peer disconnects or loses piece `index`.
    pub fn peer_lost(&mut self, index: u32) {
        let idx = index as usize;
        if idx >= self.states.len() {
            return;
        }
        let old_avail = self.availability[idx];
        let new_avail = old_avail.saturating_sub(1);
        self.availability[idx] = new_avail;

        let prio = self.priorities[idx] as usize;
        if prio > 0 {
            match self.states[idx] {
                PieceState::Missing => {
                    self.tiers[prio].update_missing_avail(index, old_avail, new_avail)
                }
                PieceState::Requested => {
                    self.tiers[prio].update_requested_avail(index, old_avail, new_avail)
                }
                PieceState::Complete => {}
            }
        }
    }

    /// Exposes slice of swarm availability counts per piece index.
    pub fn availability(&self) -> &[u32] {
        &self.availability
    }

    /// Marks a piece as in-flight requested.
    pub fn mark_requested(&mut self, index: u32) {
        let idx = index as usize;
        if idx >= self.states.len() {
            return;
        }
        if self.states[idx] == PieceState::Missing {
            self.states[idx] = PieceState::Requested;
            let prio = self.priorities[idx] as usize;
            let avail = self.availability[idx];
            if prio > 0 {
                self.tiers[prio].remove_missing(index, avail);
                self.tiers[prio].insert_requested(index, avail);
            }
        }
    }

    /// Returns a piece to `Missing` when request times out or is rejected.
    pub fn mark_missing(&mut self, index: u32) {
        let idx = index as usize;
        if idx >= self.states.len() {
            return;
        }
        if self.states[idx] == PieceState::Requested {
            self.states[idx] = PieceState::Missing;
            let prio = self.priorities[idx] as usize;
            let avail = self.availability[idx];
            if prio > 0 {
                self.tiers[prio].remove_requested(index, avail);
                self.tiers[prio].insert_missing(index, avail);
            }
        }
    }

    /// Forces a piece back to `Missing` regardless of state (used by recheck).
    pub fn force_missing(&mut self, index: u32) {
        let idx = index as usize;
        if idx >= self.states.len() {
            return;
        }
        let old_state = self.states[idx];
        if old_state == PieceState::Missing {
            return;
        }
        self.states[idx] = PieceState::Missing;
        let prio = self.priorities[idx] as usize;
        let avail = self.availability[idx];
        if prio > 0 {
            if old_state == PieceState::Requested {
                self.tiers[prio].remove_requested(index, avail);
            }
            self.tiers[prio].insert_missing(index, avail);
        }
    }

    /// Marks a piece as completely downloaded and verified on disk.
    pub fn mark_complete(&mut self, index: u32) {
        let idx = index as usize;
        if idx >= self.states.len() {
            return;
        }
        let old_state = self.states[idx];
        if old_state == PieceState::Complete {
            return;
        }
        self.states[idx] = PieceState::Complete;
        let prio = self.priorities[idx] as usize;
        let avail = self.availability[idx];
        if prio > 0 {
            if old_state == PieceState::Missing {
                self.tiers[prio].remove_missing(index, avail);
            } else if old_state == PieceState::Requested {
                self.tiers[prio].remove_requested(index, avail);
            }
        }
    }

    /// Whether we locally have piece `index` complete already.
    pub fn have(&self, index: u32) -> bool {
        self.states
            .get(index as usize)
            .is_some_and(|s| *s == PieceState::Complete)
    }

    /// Whether a piece is satisfied: either completed, or deselected (priority 0).
    fn piece_satisfied(&self, idx: usize) -> bool {
        self.states[idx] == PieceState::Complete || self.priorities[idx] == 0
    }

    pub fn is_complete(&self) -> bool {
        (1..=7).all(|t| {
            self.tiers[t].missing_pieces.is_empty() && self.tiers[t].requested_pieces.is_empty()
        })
    }

    pub fn completed_count(&self) -> usize {
        (0..self.states.len())
            .filter(|&i| self.piece_satisfied(i))
            .count()
    }

    /// Picks a piece to request from a peer holding `peer_has`.
    pub fn pick(&self, peer_has: &Bitfield, allow_requested: bool) -> Option<u32> {
        self.pick_internal(peer_has, None, None, allow_requested)
    }

    /// Picks a piece with extent affinity: contiguous pieces within the same extent as `preferred_piece`
    /// are preferred to minimize disk head thrashing and maximize contiguous write coalescing.
    pub fn pick_with_extent_affinity(
        &self,
        peer_has: &Bitfield,
        preferred_piece: Option<u32>,
        allow_requested: bool,
    ) -> Option<u32> {
        if let Some(pref) = preferred_piece {
            let extent_start = (pref / EXTENT_SIZE) * EXTENT_SIZE;
            let extent_end = (extent_start + EXTENT_SIZE).min(self.states.len() as u32);
            for cand in extent_start..extent_end {
                let idx = cand as usize;
                if self.priorities[idx] > 0 && peer_has.has(idx) {
                    match self.states[idx] {
                        PieceState::Missing => return Some(cand),
                        PieceState::Requested if allow_requested => return Some(cand),
                        _ => {}
                    }
                }
            }
        }
        self.pick(peer_has, allow_requested)
    }

    /// Picks a piece restricted to a specific index range `[start, end)`.
    pub fn pick_in_range(
        &self,
        peer_has: &Bitfield,
        start: u32,
        end: u32,
        allow_requested: bool,
    ) -> Option<u32> {
        self.pick_internal(peer_has, Some((start, end)), None, allow_requested)
    }

    /// Internal pick logic supporting RarestFirst (bucketed), Sequential, and Reverse modes across priority tiers 7..=1.
    fn pick_internal(
        &self,
        peer_has: &Bitfield,
        range: Option<(u32, u32)>,
        _affinity: Option<u32>,
        allow_requested: bool,
    ) -> Option<u32> {
        let in_range = |p: u32| -> bool {
            if let Some((start, end)) = range {
                p >= start && p < end
            } else {
                true
            }
        };

        // Scan priority tiers from highest (7) down to lowest (1)
        for prio in (1..=7).rev() {
            let tier = &self.tiers[prio];

            match self.mode {
                Mode::Sequential => {
                    let min_missing = tier
                        .missing_pieces
                        .iter()
                        .find(|&&p| in_range(p) && peer_has.has(p as usize))
                        .copied();
                    if !allow_requested {
                        if let Some(p) = min_missing {
                            return Some(p);
                        }
                    } else {
                        let min_requested = tier
                            .requested_pieces
                            .iter()
                            .find(|&&p| in_range(p) && peer_has.has(p as usize))
                            .copied();
                        match (min_missing, min_requested) {
                            (Some(m), Some(r)) => return Some(m.min(r)),
                            (Some(m), None) => return Some(m),
                            (None, Some(r)) => return Some(r),
                            (None, None) => {}
                        }
                    }
                }
                Mode::Reverse => {
                    let max_missing = tier
                        .missing_pieces
                        .iter()
                        .rev()
                        .find(|&&p| in_range(p) && peer_has.has(p as usize))
                        .copied();
                    if !allow_requested {
                        if let Some(p) = max_missing {
                            return Some(p);
                        }
                    } else {
                        let max_requested = tier
                            .requested_pieces
                            .iter()
                            .rev()
                            .find(|&&p| in_range(p) && peer_has.has(p as usize))
                            .copied();
                        match (max_missing, max_requested) {
                            (Some(m), Some(r)) => return Some(m.max(r)),
                            (Some(m), None) => return Some(m),
                            (None, Some(r)) => return Some(r),
                            (None, None) => {}
                        }
                    }
                }
                Mode::RarestFirst => {
                    if !allow_requested {
                        for piece_set in tier.buckets.values() {
                            for &p in piece_set {
                                if in_range(p) && peer_has.has(p as usize) {
                                    return Some(p);
                                }
                            }
                        }
                    } else {
                        // Gather unique availability levels across missing and requested buckets
                        let mut all_avails: BTreeSet<u32> = tier.buckets.keys().copied().collect();
                        all_avails.extend(tier.requested_buckets.keys().copied());

                        for avail in all_avails {
                            // Missing pieces take precedence over requested pieces at same availability
                            if let Some(piece_set) = tier.buckets.get(&avail) {
                                for &p in piece_set {
                                    if in_range(p) && peer_has.has(p as usize) {
                                        return Some(p);
                                    }
                                }
                            }
                            if let Some(piece_set) = tier.requested_buckets.get(&avail) {
                                for &p in piece_set {
                                    if in_range(p) && peer_has.has(p as usize) {
                                        return Some(p);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_bits(n: usize) -> Bitfield {
        let mut bf = Bitfield::new(n);
        for i in 0..n {
            bf.set(i);
        }
        bf
    }

    #[test]
    fn sequential_picks_lowest_missing_index() {
        let picker = Picker::new(5, Mode::Sequential);
        let peer = all_bits(5);
        assert_eq!(picker.pick(&peer, false), Some(0));
    }

    #[test]
    fn reverse_picks_highest_missing_index() {
        let picker = Picker::new(5, Mode::Reverse);
        let peer = all_bits(5);
        assert_eq!(picker.pick(&peer, false), Some(4));
    }

    #[test]
    fn sequential_survives_out_of_order_completion() {
        let mut picker = Picker::new(4, Mode::Sequential);
        picker.mark_complete(0);
        picker.mark_complete(2); // piece 2 finishes before piece 1
        let peer = all_bits(4);
        assert_eq!(picker.pick(&peer, false), Some(1));
        picker.mark_complete(1);
        assert_eq!(picker.pick(&peer, false), Some(3));
        picker.mark_complete(3);
        assert_eq!(picker.pick(&peer, false), None);
    }

    #[test]
    fn sequential_only_offers_pieces_the_peer_has() {
        let picker = Picker::new(3, Mode::Sequential);
        let mut peer = Bitfield::new(3);
        peer.set(2);
        assert_eq!(picker.pick(&peer, false), Some(2));
    }

    #[test]
    fn rarest_first_prefers_lower_availability() {
        let mut picker = Picker::new(3, Mode::RarestFirst);
        // Piece 0: 3 peers have it. Piece 1: 1 peer. Piece 2: 2 peers.
        for _ in 0..3 {
            picker.peer_has(0);
        }
        picker.peer_has(1);
        for _ in 0..2 {
            picker.peer_has(2);
        }
        let peer = all_bits(3);
        assert_eq!(picker.pick(&peer, false), Some(1));
    }

    #[test]
    fn rarest_first_ties_broken_by_lowest_index() {
        let picker = Picker::new(3, Mode::RarestFirst);
        let peer = all_bits(3);
        assert_eq!(picker.pick(&peer, false), Some(0));
    }

    #[test]
    fn peer_lost_decrements_availability_and_never_underflows() {
        let mut picker = Picker::new(1, Mode::RarestFirst);
        picker.peer_lost(0);
        picker.peer_has(0);
        picker.peer_lost(0);
        picker.peer_lost(0);
        let peer = all_bits(1);
        assert_eq!(picker.pick(&peer, false), Some(0));
    }

    #[test]
    fn requested_pieces_are_skipped_unless_endgame_allows_duplicates() {
        let mut picker = Picker::new(2, Mode::Sequential);
        picker.mark_requested(0);
        let peer = all_bits(2);
        assert_eq!(picker.pick(&peer, false), Some(1));
        assert_eq!(picker.pick(&peer, true), Some(0));
    }

    #[test]
    fn mark_missing_makes_a_requested_piece_pickable_again() {
        let mut picker = Picker::new(1, Mode::Sequential);
        picker.mark_requested(0);
        let peer = all_bits(1);
        assert_eq!(picker.pick(&peer, false), None);
        picker.mark_missing(0);
        assert_eq!(picker.pick(&peer, false), Some(0));
    }

    #[test]
    fn have_reflects_only_complete_pieces() {
        let mut picker = Picker::new(2, Mode::Sequential);
        assert!(!picker.have(0));
        picker.mark_complete(0);
        assert!(picker.have(0));
        assert!(!picker.have(1));
        assert!(!picker.have(99));
    }

    #[test]
    fn priorities_exclude_deselected_pieces() {
        let mut picker = Picker::new(3, Mode::Sequential);
        picker.set_priorities(vec![true, false, true]);
        let peer = all_bits(3);
        assert_eq!(picker.pick(&peer, false), Some(0));
        picker.mark_complete(0);
        assert_eq!(picker.pick(&peer, false), Some(2));
    }

    #[test]
    fn priority_tiers_strictly_prioritize_higher_tiers() {
        let mut picker = Picker::new(3, Mode::RarestFirst);
        // Piece 0 has availability 1, priority 4
        // Piece 1 has availability 5, but priority 7 (High)
        // Piece 2 has availability 1, priority 1 (Low)
        picker.peer_has(0);
        for _ in 0..5 {
            picker.peer_has(1);
        }
        picker.peer_has(2);

        picker.set_piece_priority(0, 4);
        picker.set_piece_priority(1, 7);
        picker.set_piece_priority(2, 1);

        let peer = all_bits(3);
        // Priority 7 (piece 1) must be picked before priority 4 (piece 0), despite being less rare!
        assert_eq!(picker.pick(&peer, false), Some(1));
        picker.mark_complete(1);

        // Priority 4 (piece 0) must be picked before priority 1 (piece 2)
        assert_eq!(picker.pick(&peer, false), Some(0));
        picker.mark_complete(0);

        assert_eq!(picker.pick(&peer, false), Some(2));
    }

    #[test]
    fn extent_affinity_groups_contiguous_pieces() {
        let mut picker = Picker::new(8, Mode::RarestFirst);
        for i in [0, 2, 3, 4, 5, 6] {
            picker.mark_complete(i);
        }
        // Make piece 7 rarest (avail 1), piece 1 common (avail 5)
        for _ in 0..5 {
            picker.peer_has(1);
        }
        picker.peer_has(7);

        let peer = all_bits(8);
        // Without affinity, rarest piece 7 is picked
        assert_eq!(picker.pick(&peer, false), Some(7));

        // With affinity near piece 0 (extent 0..4), contiguous piece 1 is picked instead!
        assert_eq!(
            picker.pick_with_extent_affinity(&peer, Some(0), false),
            Some(1)
        );
    }

    #[test]
    fn pick_in_range_restricts_to_interval() {
        let picker = Picker::new(10, Mode::Sequential);
        let peer = all_bits(10);
        assert_eq!(picker.pick_in_range(&peer, 5, 8, false), Some(5));
    }

    #[test]
    fn with_completed_seeds_state_from_a_resume_bitfield() {
        let mut have = Bitfield::new(3);
        have.set(0);
        have.set(1);
        let picker = Picker::new(3, Mode::Sequential).with_completed(&have);
        assert_eq!(picker.completed_count(), 2);
        let peer = all_bits(3);
        assert_eq!(picker.pick(&peer, false), Some(2));
    }

    #[test]
    fn is_complete_reflects_all_pieces_done() {
        let mut picker = Picker::new(2, Mode::Sequential);
        assert!(!picker.is_complete());
        picker.mark_complete(0);
        assert!(!picker.is_complete());
        picker.mark_complete(1);
        assert!(picker.is_complete());
    }

    #[test]
    fn pick_returns_none_when_peer_has_nothing_we_want() {
        let mut picker = Picker::new(2, Mode::Sequential);
        picker.mark_complete(0);
        picker.mark_complete(1);
        let peer = all_bits(2);
        assert_eq!(picker.pick(&peer, false), None);
    }
}
