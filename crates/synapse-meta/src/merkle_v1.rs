//! BEP 30 Merkle tree torrents (SHA-1).
//!
//! A Merkle torrent has a `root hash` in its info dictionary instead of a `pieces` string. The
//! tree's leaves are the SHA-1 hashes of the pieces, padded to a power of two with all-zero
//! hashes; an interior node is the SHA-1 of its two children concatenated (left, then right).
//! Nodes are numbered breadth first with the root as node 0, so the children of node `i` are
//! `2i + 1` and `2i + 2` and piece `p` is node `leaves - 1 + p`.
//!
//! Because the piece hashes are not in the torrent, the sender attaches to the first block of
//! every piece (`Tr_hashpiece`, see `synapse_wire::TrHashPiece`) a hash list: the piece's own
//! hash, its sibling and its uncles, up to and including the root. The receiver folds the list
//! up to the root and compares it to the `root hash` before trusting the piece hash.

use sha1::{Digest, Sha1};

pub type Hash = [u8; 20];

/// Computes the parent hash of two child hashes.
pub fn hash_parent_v1(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha1::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Leaves in the tree for `pieces` pieces: the next power of two.
fn leaf_count(pieces: usize) -> usize {
    pieces.max(1).next_power_of_two()
}

fn sibling(node: usize) -> usize {
    if node % 2 == 1 {
        node + 1
    } else {
        node - 1
    }
}

/// The full tree, built by a seeder from the hashes of all its pieces.
pub struct MerkleTreeV1 {
    /// Breadth-first: `nodes[0]` is the root, the last `leaves` entries are the leaves.
    nodes: Vec<Hash>,
    leaves: usize,
    pieces: usize,
}

impl MerkleTreeV1 {
    /// Builds the tree from the SHA-1 hash of every piece, in order. `None` if there are none.
    pub fn from_piece_hashes(piece_hashes: &[Hash]) -> Option<MerkleTreeV1> {
        if piece_hashes.is_empty() {
            return None;
        }
        let leaves = leaf_count(piece_hashes.len());
        let mut nodes = vec![[0u8; 20]; 2 * leaves - 1];
        nodes[leaves - 1..leaves - 1 + piece_hashes.len()].copy_from_slice(piece_hashes);
        for i in (0..leaves - 1).rev() {
            nodes[i] = hash_parent_v1(&nodes[2 * i + 1], &nodes[2 * i + 2]);
        }
        Some(MerkleTreeV1 {
            nodes,
            leaves,
            pieces: piece_hashes.len(),
        })
    }

    pub fn root(&self) -> Hash {
        self.nodes[0]
    }

    /// The hash of piece `piece`, if it is one of the tree's pieces.
    pub fn piece_hash(&self, piece: usize) -> Option<Hash> {
        (piece < self.pieces).then(|| self.nodes[self.leaves - 1 + piece])
    }

    /// The hash list to send with the first block of `piece`: `(node, hash)` for the piece
    /// itself, its sibling, each uncle on the way up, and finally the root.
    pub fn hashlist_for_piece(&self, piece: usize) -> Option<Vec<(u32, Hash)>> {
        if piece >= self.pieces {
            return None;
        }
        let mut node = self.leaves - 1 + piece;
        let mut list = vec![(node as u32, self.nodes[node])];
        while node != 0 {
            let sib = sibling(node);
            list.push((sib as u32, self.nodes[sib]));
            node = (node - 1) / 2;
        }
        if self.leaves > 1 {
            list.push((0, self.nodes[0]));
        }
        Some(list)
    }
}

/// Checks a hash list received for `piece` against the torrent's `root`, returning the piece's
/// own hash if the list proves it belongs to the tree. Rejects lists that name nodes outside
/// the tree, repeat a node, lack the sibling of any node on the path, or do not fold to `root`.
pub fn verify_hashlist(
    list: &[(u32, Hash)],
    piece: usize,
    pieces: usize,
    root: &Hash,
) -> Option<Hash> {
    if piece >= pieces || list.len() > 128 {
        return None;
    }
    let leaves = leaf_count(pieces);
    let node_count = 2 * leaves - 1;
    let mut known: std::collections::HashMap<usize, Hash> = std::collections::HashMap::new();
    for (node, hash) in list {
        let node = *node as usize;
        if node >= node_count || known.insert(node, *hash).is_some() {
            return None;
        }
    }
    let leaf = leaves - 1 + piece;
    let piece_hash = *known.get(&leaf)?;
    let mut node = leaf;
    let mut current = piece_hash;
    while node != 0 {
        let sib = *known.get(&sibling(node))?;
        current = if node % 2 == 1 {
            hash_parent_v1(&current, &sib)
        } else {
            hash_parent_v1(&sib, &current)
        };
        node = (node - 1) / 2;
    }
    // If the sender included the root explicitly it must be the same.
    if known.get(&0).is_some_and(|r| r != &current) {
        return None;
    }
    (&current == root).then_some(piece_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piece_hashes(n: usize) -> Vec<Hash> {
        (0..n).map(|i| Sha1::digest([i as u8; 8]).into()).collect()
    }

    #[test]
    fn tree_layout_matches_the_specification() {
        // 5 pieces -> 8 leaves, 15 nodes, leaves are nodes 7..14, padding leaves are zero.
        let hashes = piece_hashes(5);
        let tree = MerkleTreeV1::from_piece_hashes(&hashes).unwrap();
        assert_eq!(tree.nodes.len(), 15);
        assert_eq!(tree.nodes[7], hashes[0]);
        assert_eq!(tree.nodes[11], hashes[4]);
        assert_eq!(tree.nodes[12], [0u8; 20]);
        assert_eq!(
            tree.nodes[3],
            hash_parent_v1(&tree.nodes[7], &tree.nodes[8])
        );
        assert_eq!(
            tree.nodes[0],
            hash_parent_v1(&tree.nodes[1], &tree.nodes[2])
        );
        assert_eq!(tree.piece_hash(4), Some(hashes[4]));
        assert_eq!(tree.piece_hash(5), None);
    }

    #[test]
    fn hashlists_verify_for_every_piece_of_various_sizes() {
        for pieces in [1usize, 2, 3, 4, 5, 8, 9, 33] {
            let hashes = piece_hashes(pieces);
            let tree = MerkleTreeV1::from_piece_hashes(&hashes).unwrap();
            let root = tree.root();
            for (p, expected) in hashes.iter().enumerate() {
                let list = tree.hashlist_for_piece(p).unwrap();
                assert_eq!(&list[0].1, expected);
                assert_eq!(
                    verify_hashlist(&list, p, pieces, &root),
                    Some(*expected),
                    "{pieces} pieces, piece {p}"
                );
            }
        }
    }

    #[test]
    fn a_list_for_another_piece_or_root_or_with_forged_hashes_is_rejected() {
        let hashes = piece_hashes(6);
        let tree = MerkleTreeV1::from_piece_hashes(&hashes).unwrap();
        let root = tree.root();
        let list = tree.hashlist_for_piece(2).unwrap();
        // Right list, a piece in another subtree (its sibling is not in the list).
        assert_eq!(verify_hashlist(&list, 5, 6, &root), None);
        // Wrong root.
        assert_eq!(verify_hashlist(&list, 2, 6, &[9; 20]), None);
        // Forged piece hash (an attacker's data hashes to something else).
        let mut forged = list.clone();
        forged[0].1 = [1; 20];
        assert_eq!(verify_hashlist(&forged, 2, 6, &root), None);
        // A forged uncle, a missing sibling, a repeated node, an out-of-range node, a forged root.
        let mut bad_uncle = list.clone();
        bad_uncle[2].1[0] ^= 1;
        assert_eq!(verify_hashlist(&bad_uncle, 2, 6, &root), None);
        assert_eq!(verify_hashlist(&list[..1], 2, 6, &root), None);
        let mut dup = list.clone();
        dup.push(list[1]);
        assert_eq!(verify_hashlist(&dup, 2, 6, &root), None);
        let mut oob = list.clone();
        oob.push((999, [0; 20]));
        assert_eq!(verify_hashlist(&oob, 2, 6, &root), None);
        let mut bad_root = list.clone();
        bad_root.last_mut().unwrap().1 = [5; 20];
        assert_eq!(verify_hashlist(&bad_root, 2, 6, &root), None);
        // Piece index outside the torrent.
        assert_eq!(verify_hashlist(&list, 6, 6, &root), None);
    }
}
