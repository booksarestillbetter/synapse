//! BEP 52 BitTorrent v2 SHA-256 Merkle Tree Engine.
//!
//! Computes 16 KiB leaf block Merkle trees, piece layer hashes, and root validation
//! per the BitTorrent v2 specification (BEP 52).

use sha2::{Digest, Sha256};

pub const BLOCK_SIZE: usize = 16 * 1024; // 16 KiB leaf blocks

/// Computes the SHA-256 hash of a 16 KiB block.
pub fn hash_block(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    if data.len() < BLOCK_SIZE {
        // Pad with zeros up to BLOCK_SIZE
        let padding = vec![0u8; BLOCK_SIZE - data.len()];
        hasher.update(&padding);
    }
    hasher.finalize().into()
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

    let mut current_layer: Vec<[u8; 32]> = file_bytes
        .chunks(BLOCK_SIZE)
        .map(hash_block)
        .collect();

    // Round up to next power of 2 with zero hashes
    let num_leaves = current_layer.len().next_power_of_two();
    current_layer.resize(num_leaves, [0u8; 32]);

    while current_layer.len() > 1 {
        let mut next_layer = Vec::with_capacity(current_layer.len() / 2);
        for chunk in current_layer.chunks_exact(2) {
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
        let mut piece_layer: Vec<[u8; 32]> = piece_chunk
            .chunks(BLOCK_SIZE)
            .map(hash_block)
            .collect();

        piece_layer.resize(blocks_per_piece, [0u8; 32]);

        while piece_layer.len() > 1 {
            let mut next = Vec::with_capacity(piece_layer.len() / 2);
            for chunk in piece_layer.chunks_exact(2) {
                next.push(hash_parent(&chunk[0], &chunk[1]));
            }
            piece_layer = next;
        }

        piece_hashes.push(piece_layer[0]);
    }

    piece_hashes
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
    }
}
