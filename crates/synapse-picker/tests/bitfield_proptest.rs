use proptest::prelude::*;
use synapse_picker::{Bitfield, RoaringBitfield};

proptest! {
    #[test]
    fn bitfield_set_unset_consistency(
        len in 1usize..500,
        indices in prop::collection::vec(0usize..600, 1..50)
    ) {
        let mut bf = Bitfield::new(len);
        let mut shadow = vec![false; len];

        for &idx in &indices {
            bf.set(idx);
            if idx < len {
                shadow[idx] = true;
            }
        }

        for (i, &expected) in shadow.iter().enumerate() {
            prop_assert_eq!(bf.has(i), expected);
        }
        prop_assert_eq!(bf.count_ones(), shadow.iter().filter(|&&b| b).count());

        // Unset some
        for &idx in &indices[..indices.len() / 2] {
            bf.unset(idx);
            if idx < len {
                shadow[idx] = false;
            }
        }

        for (i, &expected) in shadow.iter().enumerate() {
            prop_assert_eq!(bf.has(i), expected);
        }
        prop_assert_eq!(bf.count_ones(), shadow.iter().filter(|&&b| b).count());
    }

    #[test]
    fn roaring_bitfield_roundtrip(
        len in 1usize..500,
        indices in prop::collection::vec(0usize..500, 0..50)
    ) {
        let mut bf = Bitfield::new(len);
        for &idx in &indices {
            if idx < len {
                bf.set(idx);
            }
        }

        let rbf = RoaringBitfield::from_bitfield(&bf);
        let bf_roundtrip = rbf.to_bitfield();

        prop_assert_eq!(bf.len(), rbf.len());
        prop_assert_eq!(bf.count_ones(), rbf.count_ones());
        prop_assert_eq!(bf.is_complete(), rbf.is_complete());

        for i in 0..len {
            prop_assert_eq!(bf.has(i), rbf.has(i));
            prop_assert_eq!(bf.has(i), bf_roundtrip.has(i));
        }
    }

    #[test]
    fn roaring_bitfield_mutations_track_bitfield(
        len in 1usize..200,
        operations in prop::collection::vec((any::<bool>(), 0usize..250), 1..40)
    ) {
        let mut bf = Bitfield::new(len);
        let mut rbf = RoaringBitfield::from_bitfield(&bf);

        for (set_op, idx) in operations {
            if set_op {
                bf.set(idx);
                rbf.set(idx);
            } else {
                bf.unset(idx);
                rbf.unset(idx);
            }

            prop_assert_eq!(bf.count_ones(), rbf.count_ones());
            prop_assert_eq!(bf.is_complete(), rbf.is_complete());
            if idx < len {
                prop_assert_eq!(bf.has(idx), rbf.has(idx));
            }
        }

        let converted = rbf.to_bitfield();
        for i in 0..len {
            prop_assert_eq!(bf.has(i), converted.has(i));
        }
    }

    #[test]
    fn full_bitfield_is_complete(len in 1usize..300) {
        let full = Bitfield::full(len);
        prop_assert!(full.is_complete());
        prop_assert_eq!(full.count_ones(), len);

        let rbf_full = RoaringBitfield::from_bitfield(&full);
        prop_assert!(rbf_full.is_complete());
        prop_assert_eq!(rbf_full.count_ones(), len);

        // Clearing one bit makes it incomplete
        let mut partial = full;
        partial.unset(len / 2);
        prop_assert!(!partial.is_complete());

        let rbf_partial = RoaringBitfield::from_bitfield(&partial);
        prop_assert!(!rbf_partial.is_complete());
    }
}
