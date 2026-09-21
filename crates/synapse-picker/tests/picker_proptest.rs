use proptest::prelude::*;
use synapse_picker::{Bitfield, Mode, Picker};

proptest! {
    #[test]
    fn picker_invariants_hold(
        num_pieces in 5usize..100,
        peer_bits in prop::collection::vec(any::<bool>(), 5..100),
        priorities in prop::collection::vec(0u8..=7, 5..100),
        completed_indices in prop::collection::vec(0usize..100, 0..10),
        mode_idx in 0u8..3,
    ) {
        let mode = match mode_idx {
            0 => Mode::RarestFirst,
            1 => Mode::Sequential,
            _ => Mode::Reverse,
        };

        let mut picker = Picker::new(num_pieces, mode);

        // Assign priorities
        for (i, &prio) in priorities.iter().enumerate() {
            if i < num_pieces {
                picker.set_piece_priority(i as u32, prio);
            }
        }

        // Mark some pieces complete
        for &idx in &completed_indices {
            if idx < num_pieces {
                picker.mark_complete(idx as u32);
            }
        }

        // Setup peer bitfield
        let mut peer_has = Bitfield::new(num_pieces);
        for (i, &has) in peer_bits.iter().enumerate() {
            if i < num_pieces && has {
                peer_has.set(i);
                picker.peer_has(i as u32);
            }
        }

        // Try picking
        if let Some(picked) = picker.pick(&peer_has, false) {
            let idx = picked as usize;
            prop_assert!(idx < num_pieces);
            // Invariant 1: peer must have the picked piece
            prop_assert!(peer_has.has(idx), "picked piece {} but peer does not have it", picked);
            // Invariant 2: priority must be > 0
            prop_assert!(picker.piece_priority(picked) > 0, "picked piece {} with priority 0", picked);
            // Invariant 3: must not be already completed locally
            prop_assert!(!picker.have(picked), "picked piece {} which is already completed", picked);
        }
    }

    #[test]
    fn sequential_and_reverse_ordering(
        num_pieces in 10usize..50,
        available_pieces in prop::collection::vec(0usize..50, 2..15),
    ) {
        let mut peer_has = Bitfield::new(num_pieces);
        let mut valid_pieces = Vec::new();
        for &p in &available_pieces {
            if p < num_pieces {
                peer_has.set(p);
                valid_pieces.push(p as u32);
            }
        }

        if valid_pieces.is_empty() {
            return Ok(());
        }
        valid_pieces.sort_unstable();
        valid_pieces.dedup();

        let min_piece = valid_pieces[0];
        let max_piece = *valid_pieces.last().unwrap();

        // Sequential mode picks minimum available piece index
        let seq_picker = Picker::new(num_pieces, Mode::Sequential);
        let picked_seq = seq_picker.pick(&peer_has, false);
        prop_assert_eq!(picked_seq, Some(min_piece));

        // Reverse mode picks maximum available piece index
        let rev_picker = Picker::new(num_pieces, Mode::Reverse);
        let picked_rev = rev_picker.pick(&peer_has, false);
        prop_assert_eq!(picked_rev, Some(max_piece));
    }

    #[test]
    fn priority_tier_dominance(
        num_pieces in 10usize..50,
        high_tier_piece in 0usize..50,
        low_tier_piece in 0usize..50,
    ) {
        if high_tier_piece >= num_pieces || low_tier_piece >= num_pieces || high_tier_piece == low_tier_piece {
            return Ok(());
        }

        let mut picker = Picker::new(num_pieces, Mode::RarestFirst);
        picker.set_piece_priority(high_tier_piece as u32, 7);
        picker.set_piece_priority(low_tier_piece as u32, 2);

        let mut peer_has = Bitfield::new(num_pieces);
        peer_has.set(high_tier_piece);
        peer_has.set(low_tier_piece);

        // Even if low tier is rarer or peer_has has both, priority 7 dominates priority 2
        picker.peer_has(high_tier_piece as u32);
        picker.peer_has(high_tier_piece as u32); // avail 2 for high tier
        picker.peer_has(low_tier_piece as u32);  // avail 1 for low tier (rarer!)

        let picked = picker.pick(&peer_has, false);
        prop_assert_eq!(picked, Some(high_tier_piece as u32));
    }
}
