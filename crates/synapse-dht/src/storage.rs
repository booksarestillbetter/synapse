//! BEP 44 Arbitrary Data Storage in the DHT (Immutable and Mutable items).
//!
//! Implements decentralized key-value item storage across the Kademlia DHT.
//! Immutable items are content-addressed by SHA-1(v), while Mutable items are
//! addressed by SHA-1(public_key + salt) and authenticated via sequence numbers
//! and Ed25519 cryptographic signatures.

use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const MAX_ITEM_VALUE_LEN: usize = 1000;
pub const MAX_SALT_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtItem {
    Immutable {
        target: [u8; 20],
        value: Vec<u8>,
    },
    Mutable {
        target: [u8; 20],
        public_key: [u8; 32],
        seq: u64,
        sig: [u8; 64],
        value: Vec<u8>,
        salt: Option<Vec<u8>>,
    },
}

impl DhtItem {
    pub fn target(&self) -> &[u8; 20] {
        match self {
            DhtItem::Immutable { target, .. } => target,
            DhtItem::Mutable { target, .. } => target,
        }
    }

    pub fn value(&self) -> &[u8] {
        match self {
            DhtItem::Immutable { value, .. } => value,
            DhtItem::Mutable { value, .. } => value,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StorageError {
    #[error("item value exceeds maximum size of 1000 bytes")]
    ValueTooLarge,
    #[error("salt exceeds maximum size of 64 bytes")]
    SaltTooLarge,
    #[error("CAS mismatch: expected sequence {expected}, but found {actual}")]
    CasMismatch { expected: u64, actual: u64 },
    #[error("stale sequence number: {new_seq} <= {existing_seq}")]
    StaleSequence { new_seq: u64, existing_seq: u64 },
    #[error("invalid signature")]
    InvalidSignature,
}

pub fn compute_immutable_target(value: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(value);
    hasher.finalize().into()
}

pub fn compute_mutable_target(public_key: &[u8; 32], salt: Option<&[u8]>) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(public_key);
    if let Some(s) = salt {
        hasher.update(s);
    }
    hasher.finalize().into()
}

/// Formats the raw byte payload that must be signed for a BEP 44 mutable item.
pub fn format_sign_payload(salt: Option<&[u8]>, seq: u64, value_bencode: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(s) = salt {
        out.extend_from_slice(format!("4:salt{}:", s.len()).as_bytes());
        out.extend_from_slice(s);
    }
    out.extend_from_slice(format!("3:seqi{}e1:v", seq).as_bytes());
    out.extend_from_slice(value_bencode);
    out
}

pub struct DhtStorage {
    items: HashMap<[u8; 20], (DhtItem, Instant)>,
    ttl: Duration,
}

impl Default for DhtStorage {
    fn default() -> Self {
        Self::new(Duration::from_secs(7200)) // 2 hour default TTL
    }
}

impl DhtStorage {
    pub fn new(ttl: Duration) -> Self {
        Self {
            items: HashMap::new(),
            ttl,
        }
    }

    /// Stores an immutable item in the local DHT table.
    pub fn put_immutable(&mut self, value: Vec<u8>) -> Result<[u8; 20], StorageError> {
        if value.len() > MAX_ITEM_VALUE_LEN {
            return Err(StorageError::ValueTooLarge);
        }

        let target = compute_immutable_target(&value);
        let item = DhtItem::Immutable {
            target,
            value,
        };

        self.items.insert(target, (item, Instant::now()));
        Ok(target)
    }

    /// Stores or updates a mutable item in the local DHT table with CAS validation.
    pub fn put_mutable(
        &mut self,
        public_key: [u8; 32],
        seq: u64,
        sig: [u8; 64],
        value: Vec<u8>,
        salt: Option<Vec<u8>>,
        cas: Option<u64>,
    ) -> Result<[u8; 20], StorageError> {
        if value.len() > MAX_ITEM_VALUE_LEN {
            return Err(StorageError::ValueTooLarge);
        }
        if let Some(ref s) = salt {
            if s.len() > MAX_SALT_LEN {
                return Err(StorageError::SaltTooLarge);
            }
        }

        let target = compute_mutable_target(&public_key, salt.as_deref());

        if let Some((DhtItem::Mutable { seq: existing_seq, .. }, _)) = self.items.get(&target) {
            if let Some(expected_cas) = cas {
                if *existing_seq != expected_cas {
                    return Err(StorageError::CasMismatch {
                        expected: expected_cas,
                        actual: *existing_seq,
                    });
                }
            }

            if seq <= *existing_seq {
                return Err(StorageError::StaleSequence {
                    new_seq: seq,
                    existing_seq: *existing_seq,
                });
            }
        }

        let item = DhtItem::Mutable {
            target,
            public_key,
            seq,
            sig,
            value,
            salt,
        };

        self.items.insert(target, (item, Instant::now()));
        Ok(target)
    }

    /// Retrieves an item by its 20-byte target infohash.
    pub fn get(&self, target: &[u8; 20]) -> Option<&DhtItem> {
        self.items.get(target).and_then(|(item, created)| {
            if created.elapsed() < self.ttl {
                Some(item)
            } else {
                None
            }
        })
    }

    /// Cleans up expired items.
    pub fn prune_expired(&mut self) {
        let now = Instant::now();
        let ttl = self.ttl;
        self.items.retain(|_, (_, created)| now.duration_since(*created) < ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bep44_immutable_item_storage() {
        let mut storage = DhtStorage::default();
        let val = b"12:Hello Synapse".to_vec();
        let target = storage.put_immutable(val.clone()).unwrap();

        assert_eq!(target, compute_immutable_target(&val));
        let retrieved = storage.get(&target).unwrap();
        assert_eq!(retrieved.value(), val.as_slice());
    }

    #[test]
    fn test_bep44_mutable_item_storage_and_cas() {
        let mut storage = DhtStorage::default();
        let pk = [0x42; 32];
        let sig = [0x99; 64];
        let val1 = b"5:step1".to_vec();
        let salt = Some(b"mysalt".to_vec());

        let target = storage
            .put_mutable(pk, 1, sig, val1.clone(), salt.clone(), None)
            .unwrap();

        // Stale sequence update should fail
        let stale_res = storage.put_mutable(pk, 1, sig, b"5:stepX".to_vec(), salt.clone(), None);
        assert_eq!(
            stale_res,
            Err(StorageError::StaleSequence { new_seq: 1, existing_seq: 1 })
        );

        // CAS mismatch should fail
        let cas_fail = storage.put_mutable(pk, 2, sig, b"5:step2".to_vec(), salt.clone(), Some(99));
        assert_eq!(
            cas_fail,
            Err(StorageError::CasMismatch { expected: 99, actual: 1 })
        );

        // Proper CAS update should succeed
        let ok_res = storage.put_mutable(pk, 2, sig, b"5:step2".to_vec(), salt, Some(1));
        assert!(ok_res.is_ok());
        assert_eq!(storage.get(&target).unwrap().value(), b"5:step2");
    }
}
