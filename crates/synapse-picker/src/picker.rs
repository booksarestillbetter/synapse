use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::Bitfield;

/// Non-zero fallback seed for SplitMix64/xorshift64* PRNG states.
const PICKER_SEED_FALLBACK: u64 = 0x9E37_79B9_7F4A_7C15;

/// Process-wide seed counter ensuring distinct fresh pickers start at different offsets.
static NEXT_PICKER_SEED: AtomicU64 = AtomicU64::new(1);

fn default_picker_seed(num_pieces: usize) -> u64 {
    let time_bits = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let ctr = NEXT_PICKER_SEED.fetch_add(1, Ordering::Relaxed);
    let mut z = time_bits
        .wrapping_add(ctr.wrapping_mul(PICKER_SEED_FALLBACK))
        .wrapping_add((num_pieces as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9));
    // SplitMix64 finalizer
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    if z == 0 {
        PICKER_SEED_FALLBACK
    } else {
        z
    }
}

/// Extent size for piece-extent affinity grouping (libtorrent parity).
pub const EXTENT_SIZE: u32 = 4;

/// Maximum explicit availability bucket index before clamping.
const MAX_AVAIL_BUCKET: usize = 1024;

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
struct AvailBuckets {
    buckets: Vec<Vec<u32>>,
    min_avail: usize,
    len: usize,
}

impl AvailBuckets {
    #[inline]
    fn bucket_idx(avail: u32) -> usize {
        (avail as usize).min(MAX_AVAIL_BUCKET)
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn insert(&mut self, piece: u32, avail: u32, bucket_pos: &mut [u32]) {
        let b = Self::bucket_idx(avail);
        if self.buckets.len() <= b {
            self.buckets.resize_with(b + 1, Vec::new);
        }
        let slot = &mut self.buckets[b];
        let pos = slot.len();
        slot.push(piece);
        bucket_pos[piece as usize] = pos as u32;
        if self.len == 0 || b < self.min_avail {
            self.min_avail = b;
        }
        self.len += 1;
    }

    fn remove(&mut self, piece: u32, avail: u32, bucket_pos: &mut [u32]) {
        let b = Self::bucket_idx(avail);
        let pos = bucket_pos[piece as usize] as usize;
        let slot = &mut self.buckets[b];
        debug_assert!(pos < slot.len() && slot[pos] == piece);
        let removed = slot.swap_remove(pos);
        debug_assert_eq!(removed, piece);
        if pos < slot.len() {
            let swapped = slot[pos];
            bucket_pos[swapped as usize] = pos as u32;
        }
        self.len -= 1;
        if self.len == 0 {
            self.min_avail = 0;
        } else if b == self.min_avail && self.buckets[b].is_empty() {
            while self.min_avail < self.buckets.len() && self.buckets[self.min_avail].is_empty() {
                self.min_avail += 1;
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
struct PriorityTier {
    /// Slot-indexed availability count -> missing pieces in this tier.
    buckets: AvailBuckets,
    /// Slot-indexed availability count -> requested pieces in this tier.
    requested_buckets: AvailBuckets,
    /// Set of all missing piece indices in this tier (for O(log N) ranged sequential/reverse scans).
    missing_pieces: BTreeSet<u32>,
    /// Set of all requested piece indices in this tier.
    requested_pieces: BTreeSet<u32>,
}

impl PriorityTier {
    fn insert_missing(&mut self, piece: u32, avail: u32, bucket_pos: &mut [u32]) {
        self.buckets.insert(piece, avail, bucket_pos);
        self.missing_pieces.insert(piece);
    }

    fn remove_missing(&mut self, piece: u32, avail: u32, bucket_pos: &mut [u32]) {
        self.buckets.remove(piece, avail, bucket_pos);
        self.missing_pieces.remove(&piece);
    }

    fn insert_requested(&mut self, piece: u32, avail: u32, bucket_pos: &mut [u32]) {
        self.requested_buckets.insert(piece, avail, bucket_pos);
        self.requested_pieces.insert(piece);
    }

    fn remove_requested(&mut self, piece: u32, avail: u32, bucket_pos: &mut [u32]) {
        self.requested_buckets.remove(piece, avail, bucket_pos);
        self.requested_pieces.remove(&piece);
    }

    fn update_missing_avail(
        &mut self,
        piece: u32,
        old_avail: u32,
        new_avail: u32,
        bucket_pos: &mut [u32],
    ) {
        if AvailBuckets::bucket_idx(old_avail) == AvailBuckets::bucket_idx(new_avail) {
            return;
        }
        self.buckets.remove(piece, old_avail, bucket_pos);
        self.buckets.insert(piece, new_avail, bucket_pos);
    }

    fn update_requested_avail(
        &mut self,
        piece: u32,
        old_avail: u32,
        new_avail: u32,
        bucket_pos: &mut [u32],
    ) {
        if AvailBuckets::bucket_idx(old_avail) == AvailBuckets::bucket_idx(new_avail) {
            return;
        }
        self.requested_buckets.remove(piece, old_avail, bucket_pos);
        self.requested_buckets.insert(piece, new_avail, bucket_pos);
    }
}

/// Tracks which pieces we have/want and picks what to request next from a given peer.
///
/// Features (libtorrent parity):
/// - Bucketed availability indexing: pieces are partitioned into availability buckets per priority tier,
///   enabling O(1) availability updates and fast rarest-first discovery.
/// - 8 priority tiers (0..=7): tier 0 is unselected/DoNotDownload; tiers 1..=7 are weighted where
///   higher tiers are strictly chosen before lower tiers. Default is tier 4 (Normal).
/// - Extent affinity: contiguous piece clustering to maximize sequential disk writes.
/// - Reverse & sequential range selection for media streaming.
pub struct Picker {
    mode: Mode,
    first_last_piece_priority: bool,
    states: Vec<PieceState>,
    availability: Vec<u32>,
    priorities: Vec<u8>,
    bucket_pos: Vec<u32>,
    tiers: [PriorityTier; 8],
    verified_count: usize,
    seed_count: u32,
    rng_state: AtomicU64,
}

impl Picker {
    pub fn new(num_pieces: usize, mode: Mode) -> Picker {
        let mut picker = Picker {
            mode,
            first_last_piece_priority: false,
            states: vec![PieceState::Missing; num_pieces],
            availability: vec![0; num_pieces],
            priorities: vec![4; num_pieces], // Default priority 4 (Normal)
            bucket_pos: vec![0; num_pieces],
            tiers: Default::default(),
            verified_count: 0,
            seed_count: 0,
            rng_state: AtomicU64::new(default_picker_seed(num_pieces)),
        };

        for p in 0..num_pieces as u32 {
            picker.tiers[4].insert_missing(p, 0, &mut picker.bucket_pos);
        }

        picker
    }

    /// Sets a deterministic PRNG seed for rarest-first tie-breaking (primarily for tests).
    pub fn with_seed(self, seed: u64) -> Self {
        let normalized = if seed == 0 {
            PICKER_SEED_FALLBACK
        } else {
            seed
        };
        self.rng_state.store(normalized, Ordering::Relaxed);
        self
    }

    /// Marks pieces already known-complete at construction (e.g. resuming from bitfield).
    pub fn with_completed(mut self, have: &Bitfield) -> Picker {
        for i in 0..self.states.len() {
            if have.has(i) && self.states[i] != PieceState::Complete {
                let piece = i as u32;
                self.states[i] = PieceState::Complete;
                self.verified_count += 1;
                let prio = self.priorities[i] as usize;
                let avail = self.availability[i];
                if prio > 0 {
                    self.tiers[prio].remove_missing(piece, avail, &mut self.bucket_pos);
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

    pub fn first_last_piece_priority(&self) -> bool {
        self.first_last_piece_priority
    }

    pub fn set_first_last_piece_priority(&mut self, enabled: bool) {
        self.first_last_piece_priority = enabled;
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
                PieceState::Missing => {
                    self.tiers[old_prio as usize].remove_missing(index, avail, &mut self.bucket_pos)
                }
                PieceState::Requested => self.tiers[old_prio as usize].remove_requested(
                    index,
                    avail,
                    &mut self.bucket_pos,
                ),
                PieceState::Complete => {}
            }
        }

        self.priorities[idx] = new_prio;

        // Add to new tier
        if new_prio > 0 {
            match state {
                PieceState::Missing => {
                    self.tiers[new_prio as usize].insert_missing(index, avail, &mut self.bucket_pos)
                }
                PieceState::Requested => self.tiers[new_prio as usize].insert_requested(
                    index,
                    avail,
                    &mut self.bucket_pos,
                ),
                PieceState::Complete => {}
            }
        }
    }

    /// Returns priority tier (0..=7) of a piece.
    pub fn piece_priority(&self, index: u32) -> u8 {
        self.priorities.get(index as usize).copied().unwrap_or(0)
    }

    /// Increments the full-seeder count in O(1) without touching per-piece buckets.
    pub fn peer_has_all(&mut self) {
        self.seed_count = self.seed_count.saturating_add(1);
    }

    /// Decrements the full-seeder count in O(1) without touching per-piece buckets.
    pub fn peer_lost_all(&mut self) {
        self.seed_count = self.seed_count.saturating_sub(1);
    }

    /// Returns the number of peers currently counted as holding all pieces.
    pub fn seed_count(&self) -> u32 {
        self.seed_count
    }

    /// Writes combined per-piece availability (`availability[i] + seed_count`) into `out`,
    /// reusing its existing buffer capacity.
    pub fn write_availability(&self, out: &mut Vec<u32>) {
        out.clear();
        out.reserve(self.availability.len());
        out.extend(
            self.availability
                .iter()
                .map(|&a| a.saturating_add(self.seed_count)),
        );
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
                PieceState::Missing => self.tiers[prio].update_missing_avail(
                    index,
                    old_avail,
                    new_avail,
                    &mut self.bucket_pos,
                ),
                PieceState::Requested => self.tiers[prio].update_requested_avail(
                    index,
                    old_avail,
                    new_avail,
                    &mut self.bucket_pos,
                ),
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
                PieceState::Missing => self.tiers[prio].update_missing_avail(
                    index,
                    old_avail,
                    new_avail,
                    &mut self.bucket_pos,
                ),
                PieceState::Requested => self.tiers[prio].update_requested_avail(
                    index,
                    old_avail,
                    new_avail,
                    &mut self.bucket_pos,
                ),
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
                self.tiers[prio].remove_missing(index, avail, &mut self.bucket_pos);
                self.tiers[prio].insert_requested(index, avail, &mut self.bucket_pos);
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
                self.tiers[prio].remove_requested(index, avail, &mut self.bucket_pos);
                self.tiers[prio].insert_missing(index, avail, &mut self.bucket_pos);
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
        if old_state == PieceState::Complete {
            self.verified_count = self.verified_count.saturating_sub(1);
        }
        self.states[idx] = PieceState::Missing;
        let prio = self.priorities[idx] as usize;
        let avail = self.availability[idx];
        if prio > 0 {
            if old_state == PieceState::Requested {
                self.tiers[prio].remove_requested(index, avail, &mut self.bucket_pos);
            }
            self.tiers[prio].insert_missing(index, avail, &mut self.bucket_pos);
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
        self.verified_count += 1;
        let prio = self.priorities[idx] as usize;
        let avail = self.availability[idx];
        if prio > 0 {
            if old_state == PieceState::Missing {
                self.tiers[prio].remove_missing(index, avail, &mut self.bucket_pos);
            } else if old_state == PieceState::Requested {
                self.tiers[prio].remove_requested(index, avail, &mut self.bucket_pos);
            }
        }
    }

    /// Whether we locally have piece `index` complete already.
    pub fn have(&self, index: u32) -> bool {
        self.states
            .get(index as usize)
            .is_some_and(|s| *s == PieceState::Complete)
    }

    pub fn is_complete(&self) -> bool {
        !self.states.is_empty()
            && (1..=7).all(|t| {
                self.tiers[t].missing_pieces.is_empty() && self.tiers[t].requested_pieces.is_empty()
            })
    }

    /// Whether every piece in the torrent is physically verified on disk (including
    /// deselected pieces). Distinguishes true full seeders from BEP 21 partial seeds.
    pub fn has_all_pieces(&self) -> bool {
        !self.states.is_empty() && self.verified_count == self.states.len()
    }

    /// Number of physically verified pieces on disk.
    pub fn completed_count(&self) -> usize {
        self.verified_count
    }

    /// Number of pieces satisfied either by verification or explicit `DoNotDownload` priority.
    pub fn satisfied_count(&self) -> usize {
        (0..self.states.len())
            .filter(|&i| self.states[i] == PieceState::Complete || self.priorities[i] == 0)
            .count()
    }

    /// Picks a piece to request from a peer holding `peer_has`.
    pub fn pick(&self, peer_has: &Bitfield, allow_requested: bool) -> Option<u32> {
        self.pick_internal(peer_has, None, None, allow_requested)
    }

    fn tier_has_missing(&self, prio: usize, peer_has: &Bitfield) -> bool {
        self.tiers[prio]
            .missing_pieces
            .iter()
            .any(|&p| peer_has.has(p as usize))
    }

    fn tier_has_requested(&self, prio: usize, peer_has: &Bitfield) -> bool {
        self.tiers[prio]
            .requested_pieces
            .iter()
            .any(|&p| peer_has.has(p as usize))
    }

    fn pick_first_last(
        &self,
        peer_has: &Bitfield,
        range: Option<(u32, u32)>,
        allow_requested: bool,
    ) -> Option<u32> {
        if !self.first_last_piece_priority || self.states.is_empty() {
            return None;
        }
        let in_range = |p: u32| -> bool {
            if let Some((start, end)) = range {
                p >= start && p < end
            } else {
                true
            }
        };
        let last = self.states.len() - 1;
        let check = |target_state: PieceState| -> Option<u32> {
            for idx in [0usize].into_iter().chain((last > 0).then_some(last)) {
                if self.states[idx] == target_state
                    && self.priorities[idx] > 0
                    && in_range(idx as u32)
                    && peer_has.has(idx)
                {
                    return Some(idx as u32);
                }
            }
            None
        };
        check(PieceState::Missing).or_else(|| {
            allow_requested
                .then(|| check(PieceState::Requested))
                .flatten()
        })
    }

    /// Picks a piece with extent affinity: contiguous pieces within the same extent as `preferred_piece`
    /// are preferred to minimize disk head thrashing and maximize contiguous write coalescing.
    pub fn pick_with_extent_affinity(
        &self,
        peer_has: &Bitfield,
        preferred_piece: Option<u32>,
        allow_requested: bool,
    ) -> Option<u32> {
        if self.mode != Mode::RarestFirst {
            return self.pick(peer_has, allow_requested);
        }
        if let Some(pref) = preferred_piece {
            if let Some(fl) = self.pick_first_last(peer_has, None, allow_requested) {
                return Some(fl);
            }
            let top_tier = (1..=7).rev().find(|&prio| {
                self.tier_has_missing(prio, peer_has)
                    || (allow_requested && self.tier_has_requested(prio, peer_has))
            });
            if let Some(max_prio) = top_tier {
                let extent_start = (pref / EXTENT_SIZE) * EXTENT_SIZE;
                let extent_end = (extent_start + EXTENT_SIZE).min(self.states.len() as u32);
                for cand in extent_start..extent_end {
                    let idx = cand as usize;
                    if self.priorities[idx] as usize == max_prio
                        && self.states[idx] == PieceState::Missing
                        && peer_has.has(idx)
                    {
                        return Some(cand);
                    }
                }
                if !self.tier_has_missing(max_prio, peer_has) && allow_requested {
                    for cand in extent_start..extent_end {
                        let idx = cand as usize;
                        if self.priorities[idx] as usize == max_prio
                            && self.states[idx] == PieceState::Requested
                            && peer_has.has(idx)
                        {
                            return Some(cand);
                        }
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

    fn next_rand_usize(&self, bound: usize) -> usize {
        if bound <= 1 {
            return 0;
        }
        let mut cur = self.rng_state.load(Ordering::Relaxed);
        loop {
            let mut x = if cur == 0 { PICKER_SEED_FALLBACK } else { cur };
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            let next = if x == 0 { PICKER_SEED_FALLBACK } else { x };
            match self.rng_state.compare_exchange_weak(
                cur,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let out = next.wrapping_mul(0x2545_F491_4F6C_DD1D);
                    return (out as usize) % bound;
                }
                Err(actual) => cur = actual,
            }
        }
    }

    fn pick_from_bucket(
        &self,
        bucket: &[u32],
        peer_has: &Bitfield,
        range: Option<(u32, u32)>,
    ) -> Option<u32> {
        if bucket.is_empty() {
            return None;
        }
        let in_range = |p: u32| -> bool {
            if let Some((start, end)) = range {
                p >= start && p < end
            } else {
                true
            }
        };
        let start = self.next_rand_usize(bucket.len());
        bucket[start..]
            .iter()
            .chain(&bucket[..start])
            .find(|&&p| in_range(p) && peer_has.has(p as usize))
            .copied()
    }

    /// Internal pick logic supporting RarestFirst (bucketed), Sequential, and Reverse modes across priority tiers 7..=1.
    fn pick_internal(
        &self,
        peer_has: &Bitfield,
        range: Option<(u32, u32)>,
        _affinity: Option<u32>,
        allow_requested: bool,
    ) -> Option<u32> {
        // Prioritize the first and last pieces (headers/footers/moov atoms) before normal picking.
        if let Some(fl) = self.pick_first_last(peer_has, range, allow_requested) {
            return Some(fl);
        }

        // Scan priority tiers from highest (7) down to lowest (1)
        for prio in (1..=7).rev() {
            let tier = &self.tiers[prio];

            match self.mode {
                Mode::Sequential => {
                    let min_missing = if let Some((start, end)) = range {
                        if start < end {
                            tier.missing_pieces
                                .range(start..end)
                                .find(|&&p| peer_has.has(p as usize))
                                .copied()
                        } else {
                            None
                        }
                    } else {
                        tier.missing_pieces
                            .iter()
                            .find(|&&p| peer_has.has(p as usize))
                            .copied()
                    };
                    if !allow_requested {
                        if let Some(p) = min_missing {
                            return Some(p);
                        }
                    } else {
                        let min_requested = if let Some((start, end)) = range {
                            if start < end {
                                tier.requested_pieces
                                    .range(start..end)
                                    .find(|&&p| peer_has.has(p as usize))
                                    .copied()
                            } else {
                                None
                            }
                        } else {
                            tier.requested_pieces
                                .iter()
                                .find(|&&p| peer_has.has(p as usize))
                                .copied()
                        };
                        match (min_missing, min_requested) {
                            (Some(m), Some(r)) => return Some(m.min(r)),
                            (Some(m), None) => return Some(m),
                            (None, Some(r)) => return Some(r),
                            (None, None) => {}
                        }
                    }
                }
                Mode::Reverse => {
                    let max_missing = if let Some((start, end)) = range {
                        if start < end {
                            tier.missing_pieces
                                .range(start..end)
                                .rev()
                                .find(|&&p| peer_has.has(p as usize))
                                .copied()
                        } else {
                            None
                        }
                    } else {
                        tier.missing_pieces
                            .iter()
                            .rev()
                            .find(|&&p| peer_has.has(p as usize))
                            .copied()
                    };
                    if !allow_requested {
                        if let Some(p) = max_missing {
                            return Some(p);
                        }
                    } else {
                        let max_requested = if let Some((start, end)) = range {
                            if start < end {
                                tier.requested_pieces
                                    .range(start..end)
                                    .rev()
                                    .find(|&&p| peer_has.has(p as usize))
                                    .copied()
                            } else {
                                None
                            }
                        } else {
                            tier.requested_pieces
                                .iter()
                                .rev()
                                .find(|&&p| peer_has.has(p as usize))
                                .copied()
                        };
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
                        if !tier.buckets.is_empty() {
                            for bucket in tier.buckets.buckets.iter().skip(tier.buckets.min_avail) {
                                if let Some(p) = self.pick_from_bucket(bucket, peer_has, range) {
                                    return Some(p);
                                }
                            }
                        }
                    } else {
                        let start =
                            match (!tier.buckets.is_empty(), !tier.requested_buckets.is_empty()) {
                                (true, true) => {
                                    tier.buckets.min_avail.min(tier.requested_buckets.min_avail)
                                }
                                (true, false) => tier.buckets.min_avail,
                                (false, true) => tier.requested_buckets.min_avail,
                                (false, false) => continue,
                            };
                        let end = tier
                            .buckets
                            .buckets
                            .len()
                            .max(tier.requested_buckets.buckets.len());

                        for avail in start..end {
                            // Missing pieces take precedence over requested pieces at same availability
                            if let Some(piece_set) = tier.buckets.buckets.get(avail) {
                                if let Some(p) = self.pick_from_bucket(piece_set, peer_has, range) {
                                    return Some(p);
                                }
                            }
                            if let Some(piece_set) = tier.requested_buckets.buckets.get(avail) {
                                if let Some(p) = self.pick_from_bucket(piece_set, peer_has, range) {
                                    return Some(p);
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
    fn rarest_first_ties_broken_randomly_without_piece_zero_stampede() {
        use std::collections::HashSet;

        let picker = Picker::new(64, Mode::RarestFirst).with_seed(0xC0FFEE);
        let peer = all_bits(64);
        let mut distinct = HashSet::new();
        for _ in 0..32 {
            let picked = picker.pick(&peer, false).unwrap();
            distinct.insert(picked);
        }
        assert!(
            distinct.len() >= 8,
            "expected tied rarest-first picks to spread across pieces, got {:?}",
            distinct
        );

        // Fresh pickers with default seeding should not all stampede piece 0.
        let mut first_picks = HashSet::new();
        for _ in 0..20 {
            let p = Picker::new(64, Mode::RarestFirst);
            first_picks.insert(p.pick(&peer, false).unwrap());
        }
        assert!(
            first_picks.len() >= 4,
            "expected fresh pickers not to stampede a single piece, got {:?}",
            first_picks
        );

        // Equal seeds yield reproducible sequences, and strict rarity still wins over tie-breaking.
        let a = Picker::new(16, Mode::RarestFirst).with_seed(42);
        let b = Picker::new(16, Mode::RarestFirst).with_seed(42);
        let peer16 = all_bits(16);
        for _ in 0..8 {
            assert_eq!(a.pick(&peer16, false), b.pick(&peer16, false));
        }

        let mut rare = Picker::new(8, Mode::RarestFirst).with_seed(99);
        for p in 0..8 {
            if p != 5 {
                rare.peer_has(p);
                rare.peer_has(p);
            }
        }
        rare.peer_has(5);
        assert_eq!(rare.pick(&all_bits(8), false), Some(5));
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

    #[test]
    fn first_last_piece_priority_picks_ends_before_middle() {
        let mut picker = Picker::new(5, Mode::RarestFirst);
        picker.set_first_last_piece_priority(true);
        // Make middle piece (2) rarest (availability 1), ends more common (availability 3)
        for p in [0, 1, 3, 4] {
            picker.peer_has(p);
            picker.peer_has(p);
        }
        for p in 0..5 {
            picker.peer_has(p);
        }
        let peer = all_bits(5);

        assert_eq!(picker.pick(&peer, false), Some(0));
        picker.mark_requested(0);
        assert_eq!(picker.pick(&peer, false), Some(4));
        picker.mark_requested(4);
        // After first and last are requested, falls back to rarest-first (piece 2)
        assert_eq!(picker.pick(&peer, false), Some(2));
    }

    #[test]
    fn empty_picker_is_not_complete_and_partial_seed_tracks_all_pieces() {
        let empty = Picker::new(0, Mode::RarestFirst);
        assert!(!empty.is_complete());
        assert!(!empty.has_all_pieces());
        assert_eq!(empty.completed_count(), 0);

        let mut partial = Picker::new(4, Mode::RarestFirst);
        partial.set_piece_priority(2, 0);
        partial.set_piece_priority(3, 0);
        partial.mark_complete(0);
        partial.mark_complete(1);
        assert!(partial.is_complete());
        assert!(!partial.has_all_pieces());
        assert_eq!(partial.completed_count(), 2);
        assert_eq!(partial.satisfied_count(), 4);
    }

    #[test]
    fn extent_affinity_respects_mode_first_last_tiers_and_missing_before_requested() {
        // 1. Sequential mode ignores extent affinity around piece 5.
        let seq = Picker::new(8, Mode::Sequential);
        let peer = all_bits(8);
        assert_eq!(
            seq.pick_with_extent_affinity(&peer, Some(5), false),
            Some(0)
        );

        // 2. first_last_piece_priority wins over extent affinity.
        let mut fl = Picker::new(8, Mode::RarestFirst);
        fl.set_first_last_piece_priority(true);
        assert_eq!(fl.pick_with_extent_affinity(&peer, Some(1), false), Some(0));

        // 3. Higher priority tier outside extent beats lower priority inside extent.
        let mut tiered = Picker::new(8, Mode::RarestFirst);
        tiered.set_piece_priority(6, 7);
        assert_eq!(
            tiered.pick_with_extent_affinity(&peer, Some(0), false),
            Some(6)
        );

        // 4. Within same tier, Missing outside extent beats Requested inside extent.
        let mut mr = Picker::new(8, Mode::RarestFirst);
        mr.mark_requested(1);
        for p in [0u32, 2, 3] {
            mr.mark_complete(p);
        }
        let picked = mr.pick_with_extent_affinity(&peer, Some(0), true);
        assert!(
            matches!(picked, Some(p) if p >= 4),
            "expected a Missing piece outside extent 0..4 rather than Requested piece 1, got {picked:?}"
        );
    }

    #[test]
    fn seed_count_preserves_rarest_ordering_and_write_availability_without_underflow() {
        let mut picker = Picker::new(4, Mode::RarestFirst);
        picker.peer_has_all();
        picker.peer_has_all();
        assert_eq!(picker.seed_count(), 2);

        // Add non-seeder peer counts cleanly on top of seeds.
        picker.peer_has(0);
        picker.peer_has(0);
        picker.peer_has(1);
        picker.peer_has(3);
        let peer = all_bits(4);
        assert_eq!(picker.pick(&peer, false), Some(2));

        let mut pa = Vec::new();
        picker.write_availability(&mut pa);
        assert_eq!(pa, vec![4, 3, 2, 3]);

        picker.peer_lost_all();
        picker.peer_lost_all();
        picker.peer_lost_all(); // Saturates at 0 without underflow.
        assert_eq!(picker.seed_count(), 0);
        picker.write_availability(&mut pa);
        assert_eq!(pa, vec![2, 1, 0, 1]);
    }

    #[test]
    fn avail_buckets_swap_remove_maintains_exact_indices_across_transitions() {
        let mut picker = Picker::new(12, Mode::RarestFirst);
        for p in 0..12u32 {
            for _ in 0..=(p % 4) {
                picker.peer_has(p);
            }
        }
        // Mixed swap-remove transitions: middle removals, availability changes, priority moves,
        // requested <-> missing, force_missing, mark_complete.
        picker.mark_requested(4);
        picker.mark_requested(5);
        picker.set_piece_priority(5, 7);
        picker.peer_lost(5);
        picker.peer_has(1);
        picker.mark_complete(0);
        picker.mark_complete(4);
        picker.force_missing(4);
        picker.mark_missing(5);
        picker.set_piece_priority(5, 4);
        picker.set_piece_priority(2, 0);

        let peer = all_bits(12);
        // Verify internal bucket_pos invariants against every element stored in tiers.
        for prio in 1..=7 {
            for slot in &picker.tiers[prio].buckets.buckets {
                for (pos, &piece) in slot.iter().enumerate() {
                    assert_eq!(picker.bucket_pos[piece as usize], pos as u32);
                }
            }
            for slot in &picker.tiers[prio].requested_buckets.buckets {
                for (pos, &piece) in slot.iter().enumerate() {
                    assert_eq!(picker.bucket_pos[piece as usize], pos as u32);
                }
            }
        }

        // Piece 0 was already completed; remaining 10 wanted pieces (1, 3..11) are all pickable.
        let mut picked = Vec::new();
        while let Some(p) = picker.pick(&peer, false) {
            picker.mark_complete(p);
            picked.push(p);
        }
        assert_eq!(picked.len(), 10);
        assert!(picked.contains(&4));
        assert!(picked.contains(&5));
        assert!(!picked.contains(&2));
    }

    #[test]
    fn pick_in_range_works_in_sequential_reverse_and_rarest_first_modes() {
        let peer = all_bits(8);

        let mut seq = Picker::new(8, Mode::Sequential);
        seq.mark_requested(3);
        assert_eq!(seq.pick_in_range(&peer, 3, 6, false), Some(4));
        assert_eq!(seq.pick_in_range(&peer, 3, 4, true), Some(3));
        assert_eq!(seq.pick_in_range(&peer, 5, 5, false), None);

        let mut rev = Picker::new(8, Mode::Reverse);
        rev.mark_requested(5);
        assert_eq!(rev.pick_in_range(&peer, 2, 6, false), Some(4));
        assert_eq!(rev.pick_in_range(&peer, 5, 6, true), Some(5));

        let mut rare = Picker::new(8, Mode::RarestFirst);
        rare.peer_has(3);
        rare.peer_has(3);
        rare.peer_has(4);
        rare.mark_requested(5); // avail 0 requested inside [3..6)
        assert_eq!(rare.pick_in_range(&peer, 3, 6, false), Some(4));
        assert_eq!(rare.pick_in_range(&peer, 3, 6, true), Some(5));
        assert_eq!(rare.pick_in_range(&peer, 5, 6, false), None);
    }
}
