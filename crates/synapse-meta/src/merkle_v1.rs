//! BEP 30 Merkle Tree Torrents v1 (SHA-1).
//!
//! Historical SHA-1 Merkle tree algorithm over 16 KiB blocks.
//! For modern BitTorrent v2 SHA-256 Merkle trees, see `synapse_meta::merkle` (BEP 52).

use sha1::{Digest, Sha1};

pub const BLOCK_SIZE_V1: usize = 16 * 1024; // 16 KiB leaf blocks

/// Computes the SHA-1 hash of a 16 KiB block.
pub fn hash_block_v1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    if data.len() < BLOCK_SIZE_V1 {
        let padding = vec![0u8; BLOCK_SIZE_V1 - data.len()];
        hasher.update(&padding);
    }
    hasher.finalize().into()
}

/// Computes the parent SHA-1 hash of two child 20-byte hashes.
pub fn hash_parent_v1(left: &[u8; 20], right: &[u8; 20]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Computes the 20-byte SHA-1 Merkle root for a file per BEP 30.
pub fn compute_file_merkle_root_v1(file_bytes: &[u8]) -> [u8; 20] {
    if file_bytes.is_empty() {
        return [0u8; 20];
    }

    let mut current_layer: Vec<[u8; 20]> = file_bytes
        .chunks(BLOCK_SIZE_V1)
        .map(hash_block_v1)
        .collect();

    let num_leaves = current_layer.len().next_power_of_two();
    current_layer.resize(num_leaves, [0u8; 20]);

    while current_layer.len() > 1 {
        let mut next_layer = Vec::with_capacity(current_layer.len() / 2);
        for chunk in current_layer.as_chunks::<2>().0 {
            next_layer.push(hash_parent_v1(&chunk[0], &chunk[1]));
        }
        current_layer = next_layer;
    }

    current_layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bep30_merkle_root_v1() {
        let data = vec![0x33; BLOCK_SIZE_V1];
        let root = compute_file_merkle_root_v1(&data);
        assert_eq!(root, hash_block_v1(&data));
    }
}
