//! BEP 46 Updating Torrents Via DHT Mutable Items.
//!
//! Tracks mutable torrent pointers in the DHT published by an Ed25519 public key.
//! When a content creator publishes an updated revision (higher sequence number),
//! the updater extracts the latest 20-byte `info_hash` or magnet link.

use synapse_bencode::BEncode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorrentUpdatePointer {
    pub public_key: [u8; 32],
    pub salt: Option<Vec<u8>>,
    pub latest_seq: u64,
    pub current_info_hash: Option<[u8; 20]>,
    pub magnet_uri: Option<String>,
}

impl TorrentUpdatePointer {
    pub fn new(public_key: [u8; 32], salt: Option<Vec<u8>>) -> Self {
        Self {
            public_key,
            salt,
            latest_seq: 0,
            current_info_hash: None,
            magnet_uri: None,
        }
    }

    /// Evaluates an incoming BEP 44 mutable item value.
    /// If the sequence number is newer, updates the current info_hash and returns true.
    pub fn process_update(&mut self, seq: u64, value_bytes: &[u8]) -> bool {
        if seq <= self.latest_seq && self.latest_seq > 0 {
            return false;
        }

        // Value can be a raw 20-byte info_hash, a magnet string, or a bencoded dictionary
        if value_bytes.len() == 20 {
            let mut hash = [0u8; 20];
            hash.copy_from_slice(value_bytes);
            self.current_info_hash = Some(hash);
            self.latest_seq = seq;
            return true;
        }

        if let Ok(bencode) = synapse_bencode::decode_buf(value_bytes) {
            if let Some(mut dict) = bencode.into_dict() {
                if let Some(ih_bytes) = dict.remove(b"ih".as_ref()).and_then(BEncode::into_bytes) {
                    if ih_bytes.len() == 20 {
                        let mut hash = [0u8; 20];
                        hash.copy_from_slice(&ih_bytes);
                        self.current_info_hash = Some(hash);
                        self.latest_seq = seq;
                        return true;
                    }
                }
            }
        }

        if let Ok(s) = std::str::from_utf8(value_bytes) {
            if s.starts_with("magnet:?") {
                self.magnet_uri = Some(s.to_string());
                self.latest_seq = seq;
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_bep46_updater_lifecycle() {
        let pk = [0x55; 32];
        let mut updater = TorrentUpdatePointer::new(pk, None);

        let hash1 = [0x11; 20];
        assert!(updater.process_update(1, &hash1));
        assert_eq!(updater.current_info_hash, Some(hash1));
        assert_eq!(updater.latest_seq, 1);

        // Stale update is rejected
        let hash_stale = [0x22; 20];
        assert!(!updater.process_update(1, &hash_stale));
        assert_eq!(updater.current_info_hash, Some(hash1));

        // Newer update via bencoded dict
        let mut dict = BTreeMap::new();
        let hash2 = [0x33; 20];
        dict.insert(b"ih".to_vec(), BEncode::String(hash2.to_vec()));
        let bencode_bytes = BEncode::Dict(dict).encode_to_buf();

        assert!(updater.process_update(2, &bencode_bytes));
        assert_eq!(updater.current_info_hash, Some(hash2));
        assert_eq!(updater.latest_seq, 2);
    }
}
