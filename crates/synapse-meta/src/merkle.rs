//! BEP 52 BitTorrent v2 SHA-256 Merkle Tree Engine.
//!
//! Computes 16 KiB leaf block Merkle trees, piece layer hashes, and root validation
//! per the BitTorrent v2 specification (BEP 52).

use sha2::{Digest, Sha256};

pub const BLOCK_SIZE: usize = 16 * 1024; // 16 KiB leaf blocks

/// Computes the SHA-256 leaf hash of one block. A short final block is hashed exactly as it
/// is, *not* zero-padded to 16 KiB (BEP 52; libtorrent hashes only the real bytes). The
/// leaf layer is padded with all-zero *hashes* instead, in the tree builders below.
pub fn hash_block(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Computes the parent node hash of two child SHA-256 hashes.
pub fn hash_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Constructs a full Merkle tree for a file's raw payload bytes.
/// Returns the 32-byte Merkle root. For empty (0-byte) files, returns all zeros.
pub fn compute_file_merkle_root(file_bytes: &[u8]) -> [u8; 32] {
    if file_bytes.is_empty() {
        return [0u8; 32];
    }

    let mut current_layer: Vec<[u8; 32]> = file_bytes.chunks(BLOCK_SIZE).map(hash_block).collect();

    // Round up to next power of 2 with zero hashes
    let num_leaves = current_layer.len().next_power_of_two();
    current_layer.resize(num_leaves, [0u8; 32]);

    while current_layer.len() > 1 {
        let mut next_layer = Vec::with_capacity(current_layer.len() / 2);
        for chunk in current_layer.as_chunks::<2>().0.iter() {
            next_layer.push(hash_parent(&chunk[0], &chunk[1]));
        }
        current_layer = next_layer;
    }

    current_layer[0]
}

/// Computes the piece layer hashes for a file given a specific `piece_length`.
/// `piece_length` must be a power of 2 and at least 16 KiB (`BLOCK_SIZE`).
pub fn compute_file_piece_layer(file_bytes: &[u8], piece_length: usize) -> Vec<[u8; 32]> {
    if file_bytes.is_empty() || piece_length < BLOCK_SIZE {
        return Vec::new();
    }

    let blocks_per_piece = (piece_length / BLOCK_SIZE).next_power_of_two();
    let num_pieces = file_bytes.len().div_ceil(piece_length);

    let mut piece_hashes = Vec::with_capacity(num_pieces);

    for piece_chunk in file_bytes.chunks(piece_length) {
        let mut piece_layer: Vec<[u8; 32]> =
            piece_chunk.chunks(BLOCK_SIZE).map(hash_block).collect();

        piece_layer.resize(blocks_per_piece, [0u8; 32]);

        while piece_layer.len() > 1 {
            let mut next = Vec::with_capacity(piece_layer.len() / 2);
            for chunk in piece_layer.as_chunks::<2>().0.iter() {
                next.push(hash_parent(&chunk[0], &chunk[1]));
            }
            piece_layer = next;
        }

        piece_hashes.push(piece_layer[0]);
    }

    piece_hashes
}

/// Root of the subtree of `leaves_per_piece` zero leaf hashes, i.e. the padding hash used
/// above the piece layer when a file's piece count is not a power of two.
fn zero_subtree_root(leaves_per_piece: usize) -> [u8; 32] {
    let mut layer = vec![[0u8; 32]; leaves_per_piece.max(1)];
    while layer.len() > 1 {
        layer = layer
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| hash_parent(&c[0], &c[1]))
            .collect();
    }
    layer[0]
}

/// A file's Merkle root and piece layer from the hashes of its 16 KiB blocks (the leaves),
/// for callers that hash a file as a stream instead of holding it in memory. The piece layer is
/// empty for a file that fits in one piece (its root is then its only hash). Equivalent to
/// [`compute_file_merkle_root`] and [`compute_file_piece_layer`] over the same bytes.
pub fn root_and_piece_layer(leaves: &[[u8; 32]], piece_length: usize) -> ([u8; 32], Vec<[u8; 32]>) {
    if leaves.is_empty() {
        return ([0u8; 32], Vec::new());
    }
    let blocks_per_piece = (piece_length / BLOCK_SIZE).max(1).next_power_of_two();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    level.resize(level.len().next_power_of_two(), [0u8; 32]);
    let mut piece_layer = Vec::new();
    let mut width = 1usize;
    loop {
        if width == blocks_per_piece && leaves.len() > blocks_per_piece {
            let pieces = leaves.len().div_ceil(blocks_per_piece);
            piece_layer = level[..pieces].to_vec();
        }
        if level.len() == 1 {
            break;
        }
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| hash_parent(&c[0], &c[1]))
            .collect();
        width *= 2;
    }
    (level[0], piece_layer)
}

/// Recomputes a file's Merkle root from its piece layer (`piece_layer` is the concatenated
/// 32-byte piece hashes). Used to check a piece layer received from a peer against the
/// `pieces root` in the metainfo before trusting it: the layer is padded to a power of two
/// with the zero-subtree hash for `piece_length`, then hashed up to a single root.
/// Returns `None` for a layer whose length is not a multiple of 32 or that is empty.
#[allow(clippy::manual_is_multiple_of)] // keeps the declared MSRV; `is_multiple_of` is newer
pub fn root_from_piece_layer(piece_layer: &[u8], piece_length: usize) -> Option<[u8; 32]> {
    if piece_layer.is_empty() || piece_layer.len() % 32 != 0 || piece_length < BLOCK_SIZE {
        return None;
    }
    let mut layer: Vec<[u8; 32]> = piece_layer.as_chunks::<32>().0.to_vec();
    let pad = zero_subtree_root((piece_length / BLOCK_SIZE).max(1).next_power_of_two());
    layer.resize(layer.len().next_power_of_two(), pad);
    while layer.len() > 1 {
        layer = layer
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| hash_parent(&c[0], &c[1]))
            .collect();
    }
    Some(layer[0])
}

/// Most hashes a single BEP 52 hash request/response may carry in this implementation.
pub const MAX_HASHES_PER_CHUNK: usize = 512;

/// Number of tree levels above the piece layer of a padded tree with `level_size` nodes on
/// the piece layer (`log2(level_size)`).
fn levels_above(level_size: usize) -> usize {
    level_size.trailing_zeros() as usize
}

/// A file's Merkle tree from the piece layer up, padded to a power of two, kept so that
/// hash requests can be answered *with* uncle-hash proofs (BEP 52) without recomputing the
/// tree per request. `levels[0]` is the padded piece layer, the last level is `[root]`.
pub struct PieceLayerTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl PieceLayerTree {
    /// Builds the tree from concatenated 32-byte piece hashes; `piece_length` is needed for the
    /// padding hash. `None` for an empty or misaligned layer.
    #[allow(clippy::manual_is_multiple_of)]
    pub fn new(piece_layer: &[u8], piece_length: usize) -> Option<PieceLayerTree> {
        if piece_layer.is_empty() || piece_layer.len() % 32 != 0 || piece_length < BLOCK_SIZE {
            return None;
        }
        let mut level: Vec<[u8; 32]> = piece_layer.as_chunks::<32>().0.to_vec();
        let pad = zero_subtree_root((piece_length / BLOCK_SIZE).max(1).next_power_of_two());
        level.resize(level.len().next_power_of_two(), pad);
        let mut levels = vec![level];
        while levels.last().is_some_and(|l| l.len() > 1) {
            let next: Vec<[u8; 32]> = levels
                .last()
                .expect("non-empty")
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| hash_parent(&c[0], &c[1]))
                .collect();
            levels.push(next);
        }
        Some(PieceLayerTree { levels })
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels.last().expect("at least one level")[0]
    }

    /// Nodes on the (padded) piece layer.
    pub fn level_size(&self) -> usize {
        self.levels[0].len()
    }

    /// Answers a hash request for `count` piece-layer hashes starting at `index`, followed by
    /// `proof_layers` uncle hashes (the siblings on the path from that range up towards the
    /// root, lowest first). `count` must be a power of two, `index` a multiple of it, and the
    /// range and proof must lie inside the tree. Positions past the real end of the layer are
    /// padding hashes, as BEP 52 specifies.
    #[allow(clippy::manual_is_multiple_of, clippy::type_complexity)]
    pub fn respond(
        &self,
        index: usize,
        count: usize,
        proof_layers: usize,
    ) -> Option<(Vec<[u8; 32]>, Vec<[u8; 32]>)> {
        let size = self.level_size();
        if count == 0 || !count.is_power_of_two() || index % count != 0 || index + count > size {
            return None;
        }
        let sub = levels_above(count);
        // Uncle layers available: from the range's own layer up to (excluding) the root.
        if proof_layers > levels_above(size) - sub {
            return None;
        }
        let hashes = self.levels[0][index..index + count].to_vec();
        let mut proof = Vec::with_capacity(proof_layers);
        let mut node = index >> sub; // index of the range's subtree root within its level
        for lvl in sub..sub + proof_layers {
            proof.push(self.levels[lvl][node ^ 1]);
            node >>= 1;
        }
        Some((hashes, proof))
    }
}

/// A file's complete Merkle tree, built from its 16 KiB block hashes, so hash requests at any
/// layer (including the block layer, 0) can be answered with uncle proofs. `levels[0]` is the
/// leaf layer padded to a power of two with zero hashes; the last level is `[root]`.
pub struct BlockTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl BlockTree {
    /// Builds the tree from a file's block hashes (see [`hash_block`]). `None` when empty.
    pub fn from_leaves(mut leaves: Vec<[u8; 32]>) -> Option<BlockTree> {
        if leaves.is_empty() {
            return None;
        }
        leaves.resize(leaves.len().next_power_of_two(), [0u8; 32]);
        let mut levels = vec![leaves];
        while levels.last().is_some_and(|l| l.len() > 1) {
            let next: Vec<[u8; 32]> = levels
                .last()
                .expect("non-empty")
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| hash_parent(&c[0], &c[1]))
                .collect();
            levels.push(next);
        }
        Some(BlockTree { levels })
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels.last().expect("at least one level")[0]
    }

    /// Approximate heap size, for cache accounting.
    pub fn heap_bytes(&self) -> usize {
        self.levels.iter().map(|l| l.len() * 32).sum()
    }

    /// Answers a hash request: `count` hashes of layer `base_layer` (0 = blocks) from `index`,
    /// then `proof_layers` uncle hashes, lowest first. Same rules as
    /// [`PieceLayerTree::respond`]: `count` a power of two, `index` a multiple of it, and the
    /// range and proof inside the tree.
    #[allow(clippy::manual_is_multiple_of, clippy::type_complexity)]
    pub fn respond(
        &self,
        base_layer: usize,
        index: usize,
        count: usize,
        proof_layers: usize,
    ) -> Option<(Vec<[u8; 32]>, Vec<[u8; 32]>)> {
        let level = self.levels.get(base_layer)?;
        if count == 0
            || !count.is_power_of_two()
            || index % count != 0
            || index + count > level.len()
        {
            return None;
        }
        let sub = count.trailing_zeros() as usize;
        // Uncle layers available above the range's own layer, excluding the root.
        if base_layer + sub + proof_layers > self.levels.len() - 1 {
            return None;
        }
        let hashes = level[index..index + count].to_vec();
        let mut proof = Vec::with_capacity(proof_layers);
        let mut node = index >> sub;
        for lvl in base_layer + sub..base_layer + sub + proof_layers {
            proof.push(self.levels[lvl][node ^ 1]);
            node >>= 1;
        }
        Some((hashes, proof))
    }
}

/// Verifies a chunk of piece-layer hashes received from a peer against a file's `pieces root`.
///
/// `level_size` is the padded number of nodes on the piece layer, `index` the first hash's
/// position, `hashes` the chunk (a power of two, aligned to its size) and `proof` the uncle
/// hashes the sender supplied. Hashing the chunk up to its subtree root and then folding in the
/// uncles must reproduce `root`, and exactly enough uncles must be present to reach the root,
/// so a peer cannot vouch for hashes it cannot prove.
#[allow(clippy::manual_is_multiple_of)]
pub fn verify_piece_layer_chunk(
    root: &[u8; 32],
    level_size: usize,
    index: usize,
    hashes: &[[u8; 32]],
    proof: &[[u8; 32]],
) -> bool {
    let count = hashes.len();
    if count == 0
        || !count.is_power_of_two()
        || !level_size.is_power_of_two()
        || index % count != 0
        || index + count > level_size
    {
        return false;
    }
    let sub = levels_above(count);
    if proof.len() != levels_above(level_size) - sub {
        return false;
    }
    let mut level: Vec<[u8; 32]> = hashes.to_vec();
    while level.len() > 1 {
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| hash_parent(&c[0], &c[1]))
            .collect();
    }
    let mut node = level[0];
    let mut position = index >> sub;
    for uncle in proof {
        node = if position & 1 == 0 {
            hash_parent(&node, uncle)
        } else {
            hash_parent(uncle, &node)
        };
        position >>= 1;
    }
    &node == root
}

/// Computes the 32-byte piece hash for a single piece's bytes under BEP 52.
///
/// `piece_length` is the width of the Merkle subtree in bytes: the torrent's piece length for a
/// piece of a file that spans several pieces (a short final piece is padded with zero hashes up
/// to that width), or the file's own length for a file that fits in one piece.
pub fn compute_piece_hash(piece_bytes: &[u8], piece_length: usize) -> [u8; 32] {
    if piece_bytes.is_empty() {
        return [0u8; 32];
    }
    let mut piece_layer: Vec<[u8; 32]> = piece_bytes.chunks(BLOCK_SIZE).map(hash_block).collect();
    // `piece_length` is the width of the subtree, not necessarily the number of bytes given; a
    // length that is not a block multiple still needs a leaf for its partial block, and the
    // tree can never be narrower than the leaves we have.
    let blocks_per_piece = piece_length
        .div_ceil(BLOCK_SIZE)
        .max(piece_layer.len())
        .next_power_of_two();

    piece_layer.resize(blocks_per_piece, [0u8; 32]);

    while piece_layer.len() > 1 {
        let mut next = Vec::with_capacity(piece_layer.len() / 2);
        for chunk in piece_layer.as_chunks::<2>().0.iter() {
            next.push(hash_parent(&chunk[0], &chunk[1]));
        }
        piece_layer = next;
    }

    piece_layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root_single_block() {
        let data = vec![0xAB; BLOCK_SIZE];
        let root = compute_file_merkle_root(&data);
        let expected = hash_block(&data);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_two_blocks() {
        let mut data = vec![0x11; BLOCK_SIZE];
        data.extend_from_slice(&vec![0x22; BLOCK_SIZE]);

        let h1 = hash_block(&data[..BLOCK_SIZE]);
        let h2 = hash_block(&data[BLOCK_SIZE..]);
        let expected_root = hash_parent(&h1, &h2);

        let root = compute_file_merkle_root(&data);
        assert_eq!(root, expected_root);
    }

    #[test]
    fn test_piece_layer_calculation() {
        let data = vec![0x77; BLOCK_SIZE * 4]; // 64 KiB
        let piece_len = BLOCK_SIZE * 2; // 32 KiB piece
        let layer = compute_file_piece_layer(&data, piece_len);
        assert_eq!(layer.len(), 2);
        assert_eq!(compute_piece_hash(&data[..piece_len], piece_len), layer[0]);
        assert_eq!(compute_piece_hash(&data[piece_len..], piece_len), layer[1]);
    }

    /// Known-answer vectors computed independently (Python `hashlib`, following BEP 52 /
    /// libtorrent): 40 000 bytes of `i % 251`, so the last block is short (7 232 bytes).
    fn vector_data() -> Vec<u8> {
        (0..40_000usize).map(|i| (i % 251) as u8).collect()
    }

    fn unhex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn short_final_block_is_hashed_unpadded_matching_an_independent_implementation() {
        let data = vector_data();
        assert_eq!(
            compute_file_merkle_root(&data),
            unhex("ab671631a9fa97a1fdac651fff6c68773b9acf0735b9c7f6ecdd54cbf1bf5dc2")
        );
        let layer = compute_file_piece_layer(&data, BLOCK_SIZE * 2);
        assert_eq!(layer.len(), 2);
        assert_eq!(
            layer[0],
            unhex("d9e13d0b676ad681164ef0b7b5910d1328ea83a047cad57e619d76bbe3a08525")
        );
        assert_eq!(
            layer[1],
            unhex("c878da4f6d2bc3d9e59af3c6ef3aaf72b248998c30a4b77a4e7de79a899daf72")
        );
        assert_eq!(
            compute_piece_hash(&data[BLOCK_SIZE * 2..], BLOCK_SIZE * 2),
            layer[1]
        );
    }

    #[test]
    fn root_from_piece_layer_reproduces_the_file_root_for_awkward_sizes() {
        for (len, piece_blocks) in [
            (40_000usize, 2usize),
            (1_000_000, 4),
            (BLOCK_SIZE * 8 + 1, 2),
            (BLOCK_SIZE * 6, 2),
            (BLOCK_SIZE * 3 + 5, 1),
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 % 253) as u8).collect();
            let piece_len = BLOCK_SIZE * piece_blocks;
            if data.len() <= piece_len {
                continue; // single-piece files have no piece layer; the root is used directly
            }
            let layer: Vec<u8> = compute_file_piece_layer(&data, piece_len).concat();
            assert_eq!(
                root_from_piece_layer(&layer, piece_len),
                Some(compute_file_merkle_root(&data)),
                "len {len}, piece {piece_len}"
            );
        }
    }

    #[test]
    fn root_from_piece_layer_rejects_a_tampered_layer_and_malformed_input() {
        let data = vector_data();
        let mut layer: Vec<u8> = compute_file_piece_layer(&data, BLOCK_SIZE * 2).concat();
        let root = compute_file_merkle_root(&data);
        layer[5] ^= 1;
        assert_ne!(root_from_piece_layer(&layer, BLOCK_SIZE * 2), Some(root));
        assert_eq!(root_from_piece_layer(&[], BLOCK_SIZE), None);
        assert_eq!(root_from_piece_layer(&[0u8; 33], BLOCK_SIZE), None);
    }

    fn file_and_tree(
        len: usize,
        piece_blocks: usize,
    ) -> (Vec<u8>, [u8; 32], PieceLayerTree, usize) {
        let data: Vec<u8> = (0..len).map(|i| (i * 13 % 251) as u8).collect();
        let piece_len = BLOCK_SIZE * piece_blocks;
        let layer: Vec<u8> = compute_file_piece_layer(&data, piece_len).concat();
        let tree = PieceLayerTree::new(&layer, piece_len).unwrap();
        (
            data.clone(),
            compute_file_merkle_root(&data),
            tree,
            piece_len,
        )
    }

    #[test]
    fn tree_root_equals_the_file_root_and_every_aligned_chunk_verifies_with_its_proof() {
        for (len, pb) in [
            (BLOCK_SIZE * 40 + 3, 2usize),
            (BLOCK_SIZE * 64, 1),
            (BLOCK_SIZE * 100 + 1, 4),
        ] {
            let (_, root, tree, _) = file_and_tree(len, pb);
            assert_eq!(tree.root(), root);
            let size = tree.level_size();
            for count in [1usize, 2, 4, 8, size] {
                if count > size {
                    continue;
                }
                for index in (0..size).step_by(count) {
                    let above = size.trailing_zeros() as usize - count.trailing_zeros() as usize;
                    let (hashes, proof) = tree.respond(index, count, above).unwrap();
                    assert!(
                        verify_piece_layer_chunk(&root, size, index, &hashes, &proof),
                        "len {len} count {count} idx {index}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_chunk_that_does_not_belong_or_is_tampered_or_short_of_proof_is_rejected() {
        let (_, root, tree, _) = file_and_tree(BLOCK_SIZE * 40, 2); // 20 pieces -> padded level of 32
        let size = tree.level_size();
        assert_eq!(size, 32);
        let (mut hashes, proof) = tree.respond(8, 4, 3).unwrap();
        assert!(verify_piece_layer_chunk(&root, size, 8, &hashes, &proof));
        // Claimed at the wrong position.
        assert!(!verify_piece_layer_chunk(&root, size, 12, &hashes, &proof));
        // Missing or extra proof hashes.
        assert!(!verify_piece_layer_chunk(
            &root,
            size,
            8,
            &hashes,
            &proof[..2]
        ));
        let mut longer = proof.clone();
        longer.push([0; 32]);
        assert!(!verify_piece_layer_chunk(&root, size, 8, &hashes, &longer));
        // A flipped bit in a hash or in the proof.
        hashes[1][0] ^= 1;
        assert!(!verify_piece_layer_chunk(&root, size, 8, &hashes, &proof));
        // Non-power-of-two or unaligned chunks.
        assert!(!verify_piece_layer_chunk(
            &root,
            size,
            8,
            &hashes[..3],
            &proof
        ));
        assert!(!verify_piece_layer_chunk(&root, size, 2, &hashes, &proof));
        // A different file's root.
        let (_, other_root, _, _) = file_and_tree(BLOCK_SIZE * 40 + 5, 2);
        let (h, p) = tree.respond(8, 4, 3).unwrap();
        assert!(!verify_piece_layer_chunk(&other_root, size, 8, &h, &p));
    }

    #[test]
    fn respond_refuses_ranges_and_proofs_outside_the_tree() {
        let (_, _, tree, _) = file_and_tree(BLOCK_SIZE * 8, 2); // 4 pieces, level of 4
        assert!(tree.respond(0, 3, 0).is_none(), "count not a power of two");
        assert!(tree.respond(1, 2, 0).is_none(), "unaligned");
        assert!(tree.respond(0, 8, 0).is_none(), "past the end");
        assert!(
            tree.respond(0, 2, 2).is_none(),
            "more uncle layers than exist"
        );
        assert!(tree.respond(0, 4, 0).is_some());
    }

    #[test]
    fn block_tree_serves_any_layer_with_proofs_that_verify() {
        let data: Vec<u8> = (0..(BLOCK_SIZE * 11 + 100))
            .map(|i| (i * 31 % 251) as u8)
            .collect();
        let leaves: Vec<[u8; 32]> = data.chunks(BLOCK_SIZE).map(hash_block).collect();
        let tree = BlockTree::from_leaves(leaves.clone()).unwrap();
        assert_eq!(tree.root(), compute_file_merkle_root(&data));
        // 12 real leaves padded to 16; ask for blocks 4..8 with the full proof (2 uncles).
        let (hashes, proof) = tree.respond(0, 4, 4, 2).unwrap();
        assert_eq!(hashes, leaves[4..8]);
        assert!(verify_piece_layer_chunk_at(
            &tree.root(),
            0,
            16,
            4,
            &hashes,
            &proof
        ));
        // A single block and its whole path (4 uncles).
        let (h, p) = tree.respond(0, 11, 1, 4).unwrap();
        assert_eq!(h[0], leaves[11]);
        assert_eq!(p.len(), 4);
        // Positions past the real end are padding.
        let (h, _) = tree.respond(0, 12, 4, 0).unwrap();
        assert!(h.iter().all(|x| *x == [0u8; 32]));
        // Higher layers work too: layer 2 (4 leaves per node) has 4 nodes.
        let (h, p) = tree.respond(2, 0, 2, 1).unwrap();
        assert_eq!(h.len(), 2);
        assert_eq!(p.len(), 1);
        // Invalid requests are refused.
        assert!(tree.respond(0, 3, 4, 0).is_none(), "misaligned");
        assert!(tree.respond(0, 0, 3, 0).is_none(), "not a power of two");
        assert!(tree.respond(0, 16, 1, 0).is_none(), "past the layer");
        assert!(
            tree.respond(0, 0, 4, 3).is_none(),
            "more uncles than layers"
        );
        assert!(tree.respond(9, 0, 1, 0).is_none(), "no such layer");
        // A single-block file: the block hash is the root.
        let one = BlockTree::from_leaves(vec![hash_block(b"x")]).unwrap();
        assert_eq!(one.respond(0, 0, 1, 0).unwrap().0, vec![hash_block(b"x")]);
        assert_eq!(one.root(), hash_block(b"x"));
    }

    /// Folds `hashes` (at `base`, starting at `index`) and `proof` up to a root, for tests.
    fn verify_piece_layer_chunk_at(
        root: &[u8; 32],
        base: u32,
        level_size: usize,
        index: usize,
        hashes: &[[u8; 32]],
        proof: &[[u8; 32]],
    ) -> bool {
        assert_eq!(base, 0);
        let mut layer = hashes.to_vec();
        while layer.len() > 1 {
            layer = layer
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| hash_parent(&c[0], &c[1]))
                .collect();
        }
        let mut node = layer[0];
        let mut pos = index / hashes.len();
        let _ = level_size;
        for u in proof {
            node = if pos.is_multiple_of(2) {
                hash_parent(&node, u)
            } else {
                hash_parent(u, &node)
            };
            pos /= 2;
        }
        &node == root
    }

    #[test]
    fn streamed_leaves_give_the_same_root_and_piece_layer() {
        for (len, piece) in [
            (1usize, 16384usize),
            (16384, 16384),
            (16385, 16384),
            (70_000, 32768),
            (200_000, 65536),
            (5 * 32768, 32768),
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
            let leaves: Vec<[u8; 32]> = data.chunks(BLOCK_SIZE).map(hash_block).collect();
            let (root, layer) = root_and_piece_layer(&leaves, piece);
            assert_eq!(
                root,
                compute_file_merkle_root(&data),
                "root for {len}/{piece}"
            );
            let expected = if len > piece {
                compute_file_piece_layer(&data, piece)
            } else {
                Vec::new()
            };
            assert_eq!(layer, expected, "layer for {len}/{piece}");
        }
    }
}
