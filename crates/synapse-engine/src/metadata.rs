//! Dynamic BEP 9 / BEP 53 Magnet Metadata Fetcher.
//!
//! Assembles `.torrent` metadata dictionaries transferred directly from swarm peers
//! via `ut_metadata` extension messages, verifies the cryptographic SHA-1 hash, and
//! constructs the active `Info` structure.

use bytes::{Bytes, BytesMut};
use sha1::{Digest, Sha1};
use synapse_meta::Info;
use synapse_wire::UT_METADATA_PIECE_LEN;

#[derive(Debug, Clone)]
pub struct MetadataFetcher {
    pub info_hash: [u8; 20],
    pub total_size: Option<u32>,
    pub pieces: Vec<Option<Bytes>>,
    pub pieces_received: usize,
    pub total_pieces: usize,
}

impl MetadataFetcher {
    pub fn new(info_hash: [u8; 20]) -> Self {
        Self {
            info_hash,
            total_size: None,
            pieces: Vec::new(),
            pieces_received: 0,
            total_pieces: 0,
        }
    }

    /// Sets the declared metadata size from peer extension handshake.
    pub fn set_metadata_size(&mut self, size: u32) {
        if self.total_size.is_none() && size > 0 {
            self.total_size = Some(size);
            let num_pieces = (size as usize).div_ceil(UT_METADATA_PIECE_LEN);
            self.total_pieces = num_pieces;
            self.pieces = vec![None; num_pieces];
        }
    }

    pub fn is_complete(&self) -> bool {
        self.total_pieces > 0 && self.pieces_received == self.total_pieces
    }

    /// Returns list of piece indices that have not yet been received.
    pub fn missing_pieces(&self) -> Vec<u32> {
        let mut missing = Vec::new();
        for (i, piece) in self.pieces.iter().enumerate() {
            if piece.is_none() {
                missing.push(i as u32);
            }
        }
        missing
    }

    /// Adds a received metadata piece chunk. If this completes the metadata,
    /// verifies the SHA-1 hash against `info_hash` and returns the parsed `Info`.
    pub fn add_piece(&mut self, piece_idx: u32, data: Bytes) -> Result<Option<Info>, &'static str> {
        let idx = piece_idx as usize;
        if idx >= self.pieces.len() {
            return Err("metadata piece index out of bounds");
        }

        if self.pieces[idx].is_none() {
            self.pieces[idx] = Some(data);
            self.pieces_received += 1;
        }

        if self.is_complete() {
            let mut full_metadata = BytesMut::new();
            for chunk in self.pieces.iter().flatten() {
                full_metadata.extend_from_slice(chunk);
            }

            if let Some(expected_size) = self.total_size {
                if full_metadata.len() < expected_size as usize {
                    return Err("assembled metadata length is shorter than declared total size");
                }
                full_metadata.truncate(expected_size as usize);
            }

            let computed_hash: [u8; 20] = Sha1::digest(&full_metadata).into();
            if computed_hash != self.info_hash {
                return Err("metadata hash mismatch: corrupt metadata received from peer");
            }

            let info = Info::from_info_dict_bytes(&full_metadata)
                .map_err(|_| "failed to parse assembled metadata bencode dict")?;

            Ok(Some(info))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use synapse_bencode::BEncode;

    fn build_dummy_info_dict(name: &str) -> (Vec<u8>, [u8; 20]) {
        let mut info_dict = BTreeMap::new();
        info_dict.insert(b"name".to_vec(), BEncode::String(name.as_bytes().to_vec()));
        info_dict.insert(b"piece length".to_vec(), BEncode::Int(16384));
        info_dict.insert(b"pieces".to_vec(), BEncode::String(vec![0x42; 20]));
        info_dict.insert(b"length".to_vec(), BEncode::Int(16384));

        let mut buf = Vec::new();
        BEncode::Dict(info_dict).encode(&mut buf).unwrap();
        let hash: [u8; 20] = Sha1::digest(&buf).into();
        (buf, hash)
    }

    #[test]
    fn test_metadata_fetcher_single_piece_success() {
        let (raw_metadata, info_hash) = build_dummy_info_dict("ubuntu.iso");
        let mut fetcher = MetadataFetcher::new(info_hash);
        fetcher.set_metadata_size(raw_metadata.len() as u32);

        assert_eq!(fetcher.total_pieces, 1);
        assert_eq!(fetcher.missing_pieces(), vec![0]);

        let result = fetcher.add_piece(0, Bytes::from(raw_metadata)).unwrap();
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.name, "ubuntu.iso");
        assert_eq!(info.hash, info_hash);
        assert!(fetcher.is_complete());
    }

    #[test]
    fn test_metadata_fetcher_hash_mismatch_fails() {
        let (raw_metadata, _actual_hash) = build_dummy_info_dict("ubuntu.iso");
        let fake_hash = [0x99; 20];
        let mut fetcher = MetadataFetcher::new(fake_hash);
        fetcher.set_metadata_size(raw_metadata.len() as u32);

        let err = fetcher.add_piece(0, Bytes::from(raw_metadata)).unwrap_err();
        assert!(err.contains("metadata hash mismatch"));
    }
}
