/// A packed bit vector over a fixed number of pieces (`len`), matching BitTorrent's
/// wire-format `bitfield` message layout: MSB-first within each byte, `ceil(len / 8)`
/// bytes, any trailing padding bits in the last byte are ignored/expected to be zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bitfield {
    len: usize,
    data: Vec<u8>,
}

impl Bitfield {
    pub fn new(len: usize) -> Bitfield {
        Bitfield {
            len,
            data: vec![0u8; len.div_ceil(8)],
        }
    }

    /// Builds a `Bitfield` from wire-format bytes. `None` if `data`'s length doesn't
    /// match what `len` bits requires.
    pub fn from_bytes(data: &[u8], len: usize) -> Option<Bitfield> {
        if data.len() != len.div_ceil(8) {
            return None;
        }
        Some(Bitfield {
            len,
            data: data.to_vec(),
        })
    }

    /// Creates a 100% complete `Bitfield` of `len` pieces, setting all bits and correctly
    /// zero-masking any unused trailing bits in the final byte.
    pub fn full(len: usize) -> Bitfield {
        let num_bytes = len.div_ceil(8);
        let mut data = vec![0xFFu8; num_bytes];
        let remainder = len % 8;
        if remainder != 0 {
            if let Some(last) = data.last_mut() {
                *last = !((1u8 << (8 - remainder)) - 1);
            }
        }
        Bitfield { len, data }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn has(&self, idx: usize) -> bool {
        if idx >= self.len {
            return false;
        }
        (self.data[idx / 8] & (0x80 >> (idx % 8))) != 0
    }

    pub fn set(&mut self, idx: usize) {
        if idx < self.len {
            self.data[idx / 8] |= 0x80 >> (idx % 8);
        }
    }

    pub fn unset(&mut self, idx: usize) {
        if idx < self.len {
            self.data[idx / 8] &= !(0x80 >> (idx % 8));
        }
    }

    pub fn count_ones(&self) -> usize {
        self.data.iter().map(|b| b.count_ones() as usize).sum()
    }

    pub fn is_complete(&self) -> bool {
        self.len > 0 && self.count_ones() == self.len
    }

    /// The raw wire-format bytes, for encoding a `Message::Bitfield`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// A memory-efficient compressed piece bitfield representation.
/// For 100% complete seeding swarms, represented as `AllHave { len }` with 0 bytes heap allocation.
#[derive(Debug, Clone, PartialEq)]
pub enum RoaringBitfield {
    AllHave { len: usize },
    Partial { len: usize, bitmap: roaring::RoaringBitmap },
}

impl RoaringBitfield {
    pub fn new(len: usize) -> RoaringBitfield {
        RoaringBitfield::Partial {
            len,
            bitmap: roaring::RoaringBitmap::new(),
        }
    }

    /// Creates a 100% complete bitfield with zero heap allocations.
    pub fn full(len: usize) -> RoaringBitfield {
        RoaringBitfield::AllHave { len }
    }

    /// Converts an uncompressed `Bitfield` to a compressed `RoaringBitfield`.
    pub fn from_bitfield(bf: &Bitfield) -> RoaringBitfield {
        if bf.is_complete() {
            return RoaringBitfield::full(bf.len());
        }
        let mut bitmap = roaring::RoaringBitmap::new();
        let mut start: Option<usize> = None;
        for idx in 0..bf.len() {
            if bf.has(idx) {
                if start.is_none() {
                    start = Some(idx);
                }
            } else if let Some(s) = start {
                bitmap.insert_range((s as u32)..(idx as u32));
                start = None;
            }
        }
        if let Some(s) = start {
            bitmap.insert_range((s as u32)..(bf.len() as u32));
        }
        RoaringBitfield::Partial {
            len: bf.len(),
            bitmap,
        }
    }

    /// Converts a compressed `RoaringBitfield` back to a full wire-ready `Bitfield`.
    pub fn to_bitfield(&self) -> Bitfield {
        match self {
            RoaringBitfield::AllHave { len } => Bitfield::full(*len),
            RoaringBitfield::Partial { len, bitmap } => {
                let mut bf = Bitfield::new(*len);
                for idx in bitmap.iter() {
                    if (idx as usize) < *len {
                        bf.set(idx as usize);
                    }
                }
                bf
            }
        }
    }

    pub fn len(&self) -> usize {
        match self {
            RoaringBitfield::AllHave { len } | RoaringBitfield::Partial { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn has(&self, idx: usize) -> bool {
        match self {
            RoaringBitfield::AllHave { len } => idx < *len,
            RoaringBitfield::Partial { len, bitmap } => {
                if idx >= *len {
                    false
                } else {
                    bitmap.contains(idx as u32)
                }
            }
        }
    }

    pub fn set(&mut self, idx: usize) {
        match self {
            RoaringBitfield::AllHave { .. } => {}
            RoaringBitfield::Partial { len, bitmap } => {
                if idx < *len {
                    bitmap.insert(idx as u32);
                    if bitmap.len() as usize == *len {
                        *self = RoaringBitfield::AllHave { len: *len };
                    }
                }
            }
        }
    }

    pub fn unset(&mut self, idx: usize) {
        match self {
            RoaringBitfield::AllHave { len } => {
                if idx < *len {
                    let mut bitmap = roaring::RoaringBitmap::new();
                    bitmap.insert_range(0..(*len as u32));
                    bitmap.remove(idx as u32);
                    *self = RoaringBitfield::Partial { len: *len, bitmap };
                }
            }
            RoaringBitfield::Partial { len, bitmap } => {
                if idx < *len {
                    bitmap.remove(idx as u32);
                }
            }
        }
    }

    pub fn count_ones(&self) -> usize {
        match self {
            RoaringBitfield::AllHave { len } => *len,
            RoaringBitfield::Partial { bitmap, .. } => bitmap.len() as usize,
        }
    }

    pub fn is_complete(&self) -> bool {
        match self {
            RoaringBitfield::AllHave { len } => *len > 0,
            RoaringBitfield::Partial { len, bitmap } => *len > 0 && bitmap.len() as usize == *len,
        }
    }

    pub fn serialized_size_bytes(&self) -> usize {
        match self {
            RoaringBitfield::AllHave { .. } => 0,
            RoaringBitfield::Partial { bitmap, .. } => bitmap.serialized_size(),
        }
    }

    pub fn as_bitmap(&self) -> Option<&roaring::RoaringBitmap> {
        match self {
            RoaringBitfield::AllHave { .. } => None,
            RoaringBitfield::Partial { bitmap, .. } => Some(bitmap),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_has() {
        let mut bf = Bitfield::new(10);
        assert!(!bf.has(0));
        bf.set(0);
        bf.set(9);
        assert!(bf.has(0));
        assert!(bf.has(9));
        assert!(!bf.has(1));
        assert_eq!(bf.count_ones(), 2);
    }

    #[test]
    fn unset_clears_a_bit() {
        let mut bf = Bitfield::new(10);
        bf.set(3);
        assert!(bf.has(3));
        bf.unset(3);
        assert!(!bf.has(3));
    }

    #[test]
    fn out_of_range_indices_are_ignored_not_panics() {
        let mut bf = Bitfield::new(4);
        bf.set(100);
        assert!(!bf.has(100));
        assert_eq!(bf.count_ones(), 0);
    }

    #[test]
    fn is_complete_requires_every_bit_set() {
        let mut bf = Bitfield::new(3);
        assert!(!bf.is_complete());
        bf.set(0);
        bf.set(1);
        assert!(!bf.is_complete());
        bf.set(2);
        assert!(bf.is_complete());
    }

    #[test]
    fn empty_bitfield_is_not_complete() {
        let bf = Bitfield::new(0);
        assert!(!bf.is_complete());
    }

    #[test]
    fn from_bytes_roundtrips_with_as_bytes() {
        let mut bf = Bitfield::new(12);
        bf.set(0);
        bf.set(11);
        let bytes = bf.as_bytes().to_vec();
        let rebuilt = Bitfield::from_bytes(&bytes, 12).unwrap();
        assert_eq!(bf, rebuilt);
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(Bitfield::from_bytes(&[0u8; 1], 9).is_none());
        assert!(Bitfield::from_bytes(&[0u8; 2], 9).is_some());
    }

    #[test]
    fn msb_first_bit_order_matches_bittorrent_wire_format() {
        let mut bf = Bitfield::new(8);
        bf.set(0);
        assert_eq!(bf.as_bytes(), &[0b1000_0000]);
        bf.set(7);
        assert_eq!(bf.as_bytes(), &[0b1000_0001]);
    }

    #[test]
    fn roaring_bitfield_roundtrip_and_compression() {
        // Create a 10,000 piece torrent bitfield
        let mut bf = Bitfield::new(10_000);
        for i in 0..10_000 {
            bf.set(i);
        }
        assert!(bf.is_complete());

        // Uncompressed byte size is 1250 bytes
        assert_eq!(bf.as_bytes().len(), 1250);

        // Convert to RoaringBitfield
        let rbf = RoaringBitfield::from_bitfield(&bf);
        assert!(rbf.is_complete());
        assert_eq!(rbf.count_ones(), 10_000);
        assert!(rbf.has(0));
        assert!(rbf.has(9999));
        assert!(!rbf.has(10000));

        println!("Serialized size: {} bytes", rbf.serialized_size_bytes());
        assert!(rbf.serialized_size_bytes() < 1000);

        // Roundtrip back to uncompressed Bitfield
        let reconstructed = rbf.to_bitfield();
        assert_eq!(bf, reconstructed);
    }

    #[test]
    fn bitfield_full_masks_remainder_bits_correctly() {
        for len in 1..=25 {
            let full_bf = Bitfield::full(len);
            assert_eq!(full_bf.len(), len);
            assert_eq!(full_bf.count_ones(), len);
            assert!(full_bf.is_complete());
            for i in 0..len {
                assert!(full_bf.has(i));
            }
            assert!(!full_bf.has(len));
            assert!(!full_bf.has(len + 1));

            // Verify trailing padding bits in the last byte are 0
            let remainder = len % 8;
            if remainder != 0 {
                let last_byte = *full_bf.as_bytes().last().unwrap();
                let unused_bits = 8 - remainder;
                let padding_mask = (1u8 << unused_bits) - 1;
                assert_eq!(last_byte & padding_mask, 0, "trailing bits must be 0 for len={len}");
            }
        }
    }

    #[test]
    fn roaring_bitfield_all_have_transitions() {
        let mut rbf = RoaringBitfield::new(3);
        assert!(!rbf.is_complete());
        rbf.set(0);
        rbf.set(1);
        assert!(!rbf.is_complete());
        rbf.set(2);
        // Setting all pieces transitions it to AllHave
        assert!(rbf.is_complete());
        assert!(matches!(rbf, RoaringBitfield::AllHave { len: 3 }));
        assert_eq!(rbf.serialized_size_bytes(), 0);

        // Unsetting a piece transitions back to Partial
        rbf.unset(1);
        assert!(!rbf.is_complete());
        assert!(matches!(rbf, RoaringBitfield::Partial { .. }));
        assert_eq!(rbf.count_ones(), 2);
        assert!(rbf.has(0));
        assert!(!rbf.has(1));
        assert!(rbf.has(2));
    }
}
