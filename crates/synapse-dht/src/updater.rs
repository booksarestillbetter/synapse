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

    /// Computes the 20-byte DHT target hash for this mutable item pointer.
    pub fn target_hash(&self) -> [u8; 20] {
        crate::storage::compute_mutable_target(&self.public_key, self.salt.as_deref())
    }

    /// Verifies that `item` carries a valid Ed25519 signature for `self.public_key` and
    /// `self.salt` over `(salt, seq, v)`, and if so applies the update via [`Self::process_update`].
    pub fn process_verified_item(&mut self, item: &crate::proto::GetItem) -> bool {
        let (Some(k), Some(sig), Some(seq)) = (item.k, item.sig, item.seq) else {
            return false;
        };
        if k != self.public_key {
            return false;
        }
        let payload = crate::storage::format_sign_payload(self.salt.as_deref(), seq, &item.v);
        if !crate::storage::verify_ed25519(&self.public_key, &payload, &sig) {
            return false;
        }
        self.process_update(seq, &item.v)
    }

    /// Queries a DHT node for updates to this torrent pointer using BEP 44 `get`.
    /// Returns true if a newer revision was received, cryptographically verified, and applied.
    pub async fn poll_node(
        &mut self,
        dht: &crate::node::DhtHandle,
        addr: std::net::SocketAddrV4,
    ) -> Result<bool, crate::node::DhtError> {
        let target = self.target_hash();
        let (_token, item_opt) = dht.get(addr, target, Some(self.latest_seq)).await?;
        if let Some(item) = item_opt {
            return Ok(self.process_verified_item(&item));
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
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

    #[test]
    fn test_bep46_verified_item_rejects_forged_signature_or_wrong_key() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let pk = sk.verifying_key().to_bytes();
        let salt = Some(b"my-feed".to_vec());
        let mut updater = TorrentUpdatePointer::new(pk, salt.clone());

        let mut dict = BTreeMap::new();
        let valid_hash = [0xAA; 20];
        dict.insert(b"ih".to_vec(), BEncode::String(valid_hash.to_vec()));
        let v = BEncode::Dict(dict).encode_to_buf();

        // 1. Forged signature is rejected
        let forged_item = crate::proto::GetItem {
            v: v.clone(),
            k: Some(pk),
            sig: Some([0x99; 64]),
            seq: Some(1),
        };
        assert!(!updater.process_verified_item(&forged_item));
        assert_eq!(updater.current_info_hash, None);

        // 2. Valid signature from wrong key is rejected
        let other_sk = SigningKey::from_bytes(&[0x24; 32]);
        let other_pk = other_sk.verifying_key().to_bytes();
        let other_sig = other_sk
            .sign(&crate::storage::format_sign_payload(salt.as_deref(), 1, &v))
            .to_bytes();
        let wrong_key_item = crate::proto::GetItem {
            v: v.clone(),
            k: Some(other_pk),
            sig: Some(other_sig),
            seq: Some(1),
        };
        assert!(!updater.process_verified_item(&wrong_key_item));
        assert_eq!(updater.current_info_hash, None);

        // 3. Valid signature from expected key is accepted
        let valid_sig = sk
            .sign(&crate::storage::format_sign_payload(salt.as_deref(), 1, &v))
            .to_bytes();
        let valid_item = crate::proto::GetItem {
            v,
            k: Some(pk),
            sig: Some(valid_sig),
            seq: Some(1),
        };
        assert!(updater.process_verified_item(&valid_item));
        assert_eq!(updater.current_info_hash, Some(valid_hash));
        assert_eq!(updater.latest_seq, 1);
    }
}
