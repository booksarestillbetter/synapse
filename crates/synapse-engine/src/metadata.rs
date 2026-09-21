//! Dynamic BEP 9 / BEP 53 Magnet Metadata Fetcher.
//!
//! Assembles `.torrent` metadata dictionaries transferred directly from swarm peers
//! via `ut_metadata` extension messages, verifies the cryptographic SHA-1 hash, and
//! constructs the active `Info` structure.

use bytes::{Bytes, BytesMut};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use synapse_meta::Info;
use synapse_wire::UT_METADATA_PIECE_LEN;

/// Largest metadata (info dictionary) we will assemble from peers. Matches libtorrent's
/// `max_metadata_size`; a peer declaring more is ignored rather than trusted.
pub const MAX_METADATA_SIZE: u32 = 30 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct MetadataFetcher {
    pub info_hash: [u8; 20],
    /// The full SHA-256 info hash of a v2 or hybrid torrent (from a `btmh` magnet), which the
    /// fetched metadata may be checked against instead of the SHA-1.
    pub info_hash_v2: Option<[u8; 32]>,
    pub total_size: Option<u32>,
    pub pieces: Vec<Option<Bytes>>,
    pub pieces_received: usize,
    pub total_pieces: usize,
}

impl MetadataFetcher {
    pub fn new(info_hash: [u8; 20]) -> Self {
        Self {
            info_hash,
            info_hash_v2: None,
            total_size: None,
            pieces: Vec::new(),
            pieces_received: 0,
            total_pieces: 0,
        }
    }

    /// Also accept metadata matching this BEP 52 info hash. A pure-v2 magnet identifies its
    /// torrent only by the SHA-256 of the info dict, so without this its metadata could never
    /// be verified.
    pub fn with_v2_hash(mut self, info_hash_v2: Option<[u8; 32]>) -> Self {
        self.info_hash_v2 = info_hash_v2;
        self
    }

    /// Sets the declared metadata size from a peer's extension handshake. Returns whether
    /// a size is now in effect: a zero or over-limit (`MAX_METADATA_SIZE`) declaration is
    /// ignored, and the first acceptable declaration wins until [`Self::reset`].
    pub fn set_metadata_size(&mut self, size: u32) -> bool {
        if self.total_size.is_none() && size > 0 && size <= MAX_METADATA_SIZE {
            self.total_size = Some(size);
            let num_pieces = (size as usize).div_ceil(UT_METADATA_PIECE_LEN);
            self.total_pieces = num_pieces;
            self.pieces = vec![None; num_pieces];
        }
        self.total_size.is_some()
    }

    /// Discards everything assembled so far, including the declared size, so metadata can
    /// be fetched afresh from another peer after a corrupt or dishonest source.
    pub fn reset(&mut self) {
        self.total_size = None;
        self.pieces = Vec::new();
        self.pieces_received = 0;
        self.total_pieces = 0;
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

        // Every chunk is exactly UT_METADATA_PIECE_LEN bytes except the last, which carries
        // the remainder. Anything else is malformed and can only corrupt the assembly.
        let total = self.total_size.unwrap_or(0) as usize;
        let expected_len =
            UT_METADATA_PIECE_LEN.min(total.saturating_sub(idx * UT_METADATA_PIECE_LEN));
        if data.len() != expected_len {
            return Err("metadata piece has the wrong length");
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

            let sha1_matches = <[u8; 20]>::from(Sha1::digest(&full_metadata)) == self.info_hash;
            let sha256: [u8; 32] = Sha256::digest(&full_metadata).into();
            let sha256_matches = self.info_hash_v2 == Some(sha256);
            if !sha1_matches && !sha256_matches {
                self.reset();
                return Err("metadata hash mismatch: corrupt metadata received from peer");
            }

            match Info::from_info_dict_bytes(&full_metadata) {
                Ok(info) => Ok(Some(info)),
                Err(_) => {
                    self.reset();
                    Err("failed to parse assembled metadata bencode dict")
                }
            }
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
        // A failed assembly must not wedge the fetcher: it starts over for the next peer.
        assert_eq!(fetcher.total_size, None);
        assert_eq!(fetcher.pieces_received, 0);
        assert!(!fetcher.is_complete());
    }

    #[test]
    fn test_metadata_fetcher_rejects_oversize_declaration() {
        let mut fetcher = MetadataFetcher::new([1; 20]);
        assert!(!fetcher.set_metadata_size(MAX_METADATA_SIZE + 1));
        assert!(!fetcher.set_metadata_size(0));
        assert!(!fetcher.set_metadata_size(u32::MAX));
        assert_eq!(fetcher.total_size, None);
        assert!(fetcher.pieces.is_empty());
        assert!(fetcher.set_metadata_size(MAX_METADATA_SIZE));
        assert_eq!(
            fetcher.total_pieces,
            (MAX_METADATA_SIZE as usize).div_ceil(UT_METADATA_PIECE_LEN)
        );
    }

    #[test]
    fn test_metadata_fetcher_rejects_wrong_length_chunks() {
        let mut fetcher = MetadataFetcher::new([1; 20]);
        fetcher.set_metadata_size(UT_METADATA_PIECE_LEN as u32 + 100);
        // Full-size chunk expected at index 0, a 100-byte tail at index 1.
        assert!(fetcher.add_piece(0, Bytes::from(vec![0; 100])).is_err());
        assert!(fetcher
            .add_piece(0, Bytes::from(vec![0; UT_METADATA_PIECE_LEN + 1]))
            .is_err());
        assert!(fetcher
            .add_piece(1, Bytes::from(vec![0; UT_METADATA_PIECE_LEN]))
            .is_err());
        assert!(fetcher.add_piece(2, Bytes::from(vec![0; 1])).is_err());
        assert_eq!(fetcher.pieces_received, 0);
        assert!(fetcher
            .add_piece(0, Bytes::from(vec![0; UT_METADATA_PIECE_LEN]))
            .unwrap()
            .is_none());
        assert_eq!(fetcher.pieces_received, 1);
    }

    #[test]
    fn a_pure_v2_magnet_verifies_metadata_against_its_sha256_info_hash() {
        // Info dict of a single-file v2 torrent.
        let leaf = BTreeMap::from([
            (b"length".to_vec(), BEncode::Int(100_000)),
            (b"pieces root".to_vec(), BEncode::String(vec![7u8; 32])),
        ]);
        let tree = BTreeMap::from([(
            b"f".to_vec(),
            BEncode::Dict(BTreeMap::from([(b"".to_vec(), BEncode::Dict(leaf))])),
        )]);
        let dict = BTreeMap::from([
            (b"meta version".to_vec(), BEncode::Int(2)),
            (b"name".to_vec(), BEncode::String(b"v2".to_vec())),
            (b"piece length".to_vec(), BEncode::Int(32768)),
            (b"file tree".to_vec(), BEncode::Dict(tree)),
        ]);
        let mut raw = Vec::new();
        BEncode::Dict(dict).encode(&mut raw).unwrap();
        let v2: [u8; 32] = Sha256::digest(&raw).into();
        let mut truncated = [0u8; 20];
        truncated.copy_from_slice(&v2[..20]);

        // The magnet only carries the truncated hash as its identity; with the full hash the
        // metadata verifies and parses back to the same identity.
        let mut fetcher = MetadataFetcher::new(truncated).with_v2_hash(Some(v2));
        fetcher.set_metadata_size(raw.len() as u32);
        let info = fetcher
            .add_piece(0, Bytes::from(raw.clone()))
            .unwrap()
            .expect("metadata resolves");
        assert_eq!(info.hash, truncated);
        assert_eq!(info.info_hash_v2, Some(v2));

        // Without the v2 hash it cannot be verified (SHA-1 does not match) and is rejected.
        let mut blind = MetadataFetcher::new(truncated);
        blind.set_metadata_size(raw.len() as u32);
        assert!(blind.add_piece(0, Bytes::from(raw)).is_err());
    }
}
