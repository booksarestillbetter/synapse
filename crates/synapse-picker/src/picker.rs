use crate::Bitfield;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Pick the rarest piece (fewest connected peers have it) the requesting peer has
    /// that we're still missing. Standard BitTorrent strategy - spreads rare pieces
    /// through the swarm quickly and avoids everyone finishing with the same last few
    /// pieces missing.
    RarestFirst,
    /// Pick the lowest-indexed missing piece the requesting peer has. Used for
    /// streaming/sequential-access use cases where piece order matters more than swarm
    /// health.
    Sequential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PieceState {
    Missing,
    /// A request for this piece is outstanding. Doesn't block other peers from also
    /// being picked for it near endgame (see `pick`'s `allow_duplicates` parameter) -
    /// tracked separately from `Missing` so normal (non-endgame) picking prefers pieces
    /// nobody has asked for yet.
    Requested,
    Complete,
}

/// Tracks which pieces we have/want and picks what to request next from a given peer.
///
/// Deliberately does **not** cache any "already scanned up to here" position the way
/// the pre-rewrite codebase's sequential picker did (`src/torrent/picker/sequential.rs`,
/// before its Phase 4 fix in `CHANGELOG.md`) - that cache could desync from the real
/// piece-state array when pieces completed out of order (endgame, retransmits, disk
/// validation) and permanently hide still-missing pieces from `pick()`. This picker
/// always scans real state fresh, which is O(pieces) per pick rather than O(1) - correct
/// first; if profiling ever shows picking itself (as opposed to the network/disk I/O
/// around it) is a bottleneck, that's a reason to add a proper indexed structure with
/// its own invariant tests, not to reintroduce a hand-maintained cache.
pub struct Picker {
    mode: Mode,
    states: Vec<PieceState>,
    /// How many connected peers have each piece - only consulted in `RarestFirst` mode,
    /// but always kept up to date via `peer_has`/`peer_lost` so switching modes doesn't
    /// require a backfill pass.
    availability: Vec<u32>,
    /// `false` for a piece means "don't download it" (e.g. deselected files) - `pick`
    /// skips these. `None` means every piece is wanted.
    priorities: Option<Vec<bool>>,
}

impl Picker {
    pub fn new(num_pieces: usize, mode: Mode) -> Picker {
        Picker {
            mode,
            states: vec![PieceState::Missing; num_pieces],
            availability: vec![0; num_pieces],
            priorities: None,
        }
    }

    /// Marks pieces already known-complete at construction (e.g. resuming a
    /// partially-downloaded torrent from a saved bitfield).
    pub fn with_completed(mut self, have: &Bitfield) -> Picker {
        for (i, state) in self.states.iter_mut().enumerate() {
            if have.has(i) {
                *state = PieceState::Complete;
            }
        }
        self
    }

    pub fn set_priorities(&mut self, wanted: Vec<bool>) {
        debug_assert_eq!(wanted.len(), self.states.len());
        self.priorities = Some(wanted);
    }

    /// Marks pieces `start..=end` (inclusive) as wanted or not, leaving every other piece's
    /// priority untouched — for applying a single file's priority change without needing the
    /// caller to already have (or reconstruct) the full per-piece vector `set_priorities`
    /// requires. Lazily initializes `priorities` to all-wanted on first use.
    pub fn set_piece_range_priority(&mut self, start: u32, end: u32, wanted: bool) {
        let priorities = self.priorities.get_or_insert_with(|| vec![true; self.states.len()]);
        let end = (end as usize).min(priorities.len().saturating_sub(1));
        for p in priorities.iter_mut().take(end + 1).skip(start as usize) {
            *p = wanted;
        }
    }

    pub fn peer_has(&mut self, index: u32) {
        if let Some(a) = self.availability.get_mut(index as usize) {
            *a += 1;
        }
    }

    /// Call once per piece a disconnecting/errored peer had (its whole bitfield), to
    /// keep availability counts accurate for `RarestFirst`.
    pub fn peer_lost(&mut self, index: u32) {
        if let Some(a) = self.availability.get_mut(index as usize) {
            *a = a.saturating_sub(1);
        }
    }

    /// Exposes slice of swarm availability counts per piece index.
    pub fn availability(&self) -> &[u32] {
        &self.availability
    }

    /// Picks a piece to request from a peer with bitfield `peer_has`. Returns `None` if
    /// the peer has nothing we want. `allow_requested` includes pieces we've already
    /// requested from someone else (for endgame mode, where the same piece is requested
    /// from multiple peers to finish a download's last few pieces faster); normally
    /// `false`.
    pub fn pick(&self, peer_has: &Bitfield, allow_requested: bool) -> Option<u32> {
        let wanted = |i: usize| -> bool {
            match self.states[i] {
                PieceState::Complete => false,
                PieceState::Requested if !allow_requested => false,
                _ => true,
            }
        };
        let candidates = (0..self.states.len()).filter(|&i| {
            peer_has.has(i)
                && wanted(i)
                && self.priorities.as_ref().is_none_or(|p| p[i])
        });

        match self.mode {
            Mode::Sequential => candidates.min(),
            Mode::RarestFirst => candidates.min_by_key(|&i| (self.availability[i], i)),
        }
        .map(|i| i as u32)
    }

    pub fn mark_requested(&mut self, index: u32) {
        if let Some(s) = self.states.get_mut(index as usize) {
            if *s == PieceState::Missing {
                *s = PieceState::Requested;
            }
        }
    }

    /// Call when a request is cancelled, times out, or the peer holding it disconnects
    /// - returns the piece to `Missing` so it can be picked again.
    pub fn mark_missing(&mut self, index: u32) {
        if let Some(s) = self.states.get_mut(index as usize) {
            if *s == PieceState::Requested {
                *s = PieceState::Missing;
            }
        }
    }

    /// Forces a piece back to `Missing` regardless of its current state — unlike
    /// `mark_missing` (which only demotes an in-flight `Requested` piece), this also demotes
    /// an already-`Complete` piece. Used by recheck, where re-verification can find a
    /// previously-good piece corrupted on disk since.
    pub fn force_missing(&mut self, index: u32) {
        if let Some(s) = self.states.get_mut(index as usize) {
            *s = PieceState::Missing;
        }
    }

    pub fn mark_complete(&mut self, index: u32) {
        if let Some(s) = self.states.get_mut(index as usize) {
            *s = PieceState::Complete;
        }
    }

    /// Whether we locally have piece `index` complete already.
    pub fn have(&self, index: u32) -> bool {
        self.states
            .get(index as usize)
            .is_some_and(|s| *s == PieceState::Complete)
    }

    /// Whether a piece counts toward completion — either actually downloaded, or explicitly
    /// deselected (`priorities[i] == false`, e.g. an unwanted file in a multi-file torrent).
    /// Without the deselected case, a torrent with any file marked "don't download" could
    /// never report complete or transition to seeding, since its deselected pieces would stay
    /// `Missing` forever by design.
    fn piece_satisfied(&self, i: usize) -> bool {
        self.states[i] == PieceState::Complete || self.priorities.as_ref().is_some_and(|p| !p[i])
    }

    pub fn is_complete(&self) -> bool {
        (0..self.states.len()).all(|i| self.piece_satisfied(i))
    }

    pub fn completed_count(&self) -> usize {
        (0..self.states.len()).filter(|&i| self.piece_satisfied(i)).count()
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
    fn sequential_survives_out_of_order_completion() {
        // Regression test for the exact bug class fixed in the pre-rewrite codebase
        // (CHANGELOG.md): completing pieces out of order must never hide an earlier
        // still-missing piece from future picks.
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
        // All availability 0 - deterministic tiebreak matters for testability and for
        // not starving high-index pieces.
        let peer = all_bits(3);
        assert_eq!(picker.pick(&peer, false), Some(0));
    }

    #[test]
    fn peer_lost_decrements_availability_and_never_underflows() {
        let mut picker = Picker::new(1, Mode::RarestFirst);
        picker.peer_lost(0); // no prior peer_has call - must saturate, not panic/wrap
        picker.peer_has(0);
        picker.peer_lost(0);
        picker.peer_lost(0);
        // Still shouldn't panic or produce a bogus huge availability count.
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
        assert!(!picker.have(99)); // out of range: false, not a panic
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
