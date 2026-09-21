//! BEP 44 Arbitrary Data Storage in the DHT (Immutable and Mutable items).
//!
//! Implements decentralized key-value item storage across the Kademlia DHT.
//! Immutable items are content-addressed by SHA-1(v), while Mutable items are
//! addressed by SHA-1(public_key + salt) and authenticated via sequence numbers
//! and Ed25519 cryptographic signatures.

use ed25519_dalek::{Signature, VerifyingKey};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const MAX_ITEM_VALUE_LEN: usize = 1000;
/// Items held at once (libtorrent's `max_dht_items`); the oldest is evicted for a new one.
pub const MAX_ITEMS: usize = 700;
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
    #[error("invalid public key")]
    InvalidPublicKey,
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
        let item = DhtItem::Immutable { target, value };

        self.insert(target, item);
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

        // The signature covers salt, sequence number and the bencoded value; an item that
        // does not verify must never be stored or served (anyone could otherwise overwrite
        // anyone's mutable item).
        let verifying_key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| StorageError::InvalidPublicKey)?;
        let payload = format_sign_payload(salt.as_deref(), seq, &value);
        verifying_key
            .verify_strict(&payload, &Signature::from_bytes(&sig))
            .map_err(|_| StorageError::InvalidSignature)?;

        let target = compute_mutable_target(&public_key, salt.as_deref());

        if let Some((
            DhtItem::Mutable {
                seq: existing_seq, ..
            },
            _,
        )) = self.items.get(&target)
        {
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

        self.insert(target, item);
        Ok(target)
    }

    fn insert(&mut self, target: [u8; 20], item: DhtItem) {
        if !self.items.contains_key(&target) && self.items.len() >= MAX_ITEMS {
            let now = Instant::now();
            let ttl = self.ttl;
            self.items
                .retain(|_, (_, created)| now.duration_since(*created) < ttl);
            if self.items.len() >= MAX_ITEMS {
                if let Some(&oldest) = self
                    .items
                    .iter()
                    .min_by_key(|(_, (_, c))| *c)
                    .map(|(t, _)| t)
                {
                    self.items.remove(&oldest);
                }
            }
        }
        self.items.insert(target, (item, Instant::now()));
    }

    /// Number of items currently held (including any not yet pruned as expired).
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
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
        self.items
            .retain(|_, (_, created)| now.duration_since(*created) < ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn test_bep44_immutable_item_storage() {
        let mut storage = DhtStorage::default();
        let val = b"12:Hello Synapse".to_vec();
        let target = storage.put_immutable(val.clone()).unwrap();

        assert_eq!(target, compute_immutable_target(&val));
        let retrieved = storage.get(&target).unwrap();
        assert_eq!(retrieved.value(), val.as_slice());
    }

    /// A deterministic test keypair and a signature over `(salt, seq, v)`.
    fn signed(seed: u8, salt: Option<&[u8]>, seq: u64, v: &[u8]) -> ([u8; 32], [u8; 64]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let sig = sk.sign(&format_sign_payload(salt, seq, v)).to_bytes();
        (sk.verifying_key().to_bytes(), sig)
    }

    #[test]
    fn test_bep44_mutable_item_storage_and_cas() {
        let mut storage = DhtStorage::default();
        let salt = Some(b"mysalt".to_vec());
        let (pk, sig1) = signed(0x42, salt.as_deref(), 1, b"5:step1");

        let target = storage
            .put_mutable(pk, 1, sig1, b"5:step1".to_vec(), salt.clone(), None)
            .unwrap();

        // Stale sequence update should fail
        let stale_res = storage.put_mutable(pk, 1, sig1, b"5:step1".to_vec(), salt.clone(), None);
        assert_eq!(
            stale_res,
            Err(StorageError::StaleSequence {
                new_seq: 1,
                existing_seq: 1
            })
        );

        // CAS mismatch should fail
        let (_, sig2) = signed(0x42, salt.as_deref(), 2, b"5:step2");
        let cas_fail =
            storage.put_mutable(pk, 2, sig2, b"5:step2".to_vec(), salt.clone(), Some(99));
        assert_eq!(
            cas_fail,
            Err(StorageError::CasMismatch {
                expected: 99,
                actual: 1
            })
        );

        // Proper CAS update should succeed
        let ok_res = storage.put_mutable(pk, 2, sig2, b"5:step2".to_vec(), salt, Some(1));
        assert!(ok_res.is_ok());
        assert_eq!(storage.get(&target).unwrap().value(), b"5:step2");
    }

    #[test]
    fn mutable_items_with_bad_signatures_or_keys_are_refused() {
        let mut storage = DhtStorage::default();
        let (pk, sig) = signed(1, None, 1, b"3:abc");
        // Signature over different content.
        assert_eq!(
            storage.put_mutable(pk, 1, sig, b"3:xyz".to_vec(), None, None),
            Err(StorageError::InvalidSignature)
        );
        // Right content, wrong sequence number (the seq is part of the signed payload).
        assert_eq!(
            storage.put_mutable(pk, 2, sig, b"3:abc".to_vec(), None, None),
            Err(StorageError::InvalidSignature)
        );
        // Someone else's key cannot reuse a valid signature.
        let (other_pk, _) = signed(2, None, 1, b"3:abc");
        assert_eq!(
            storage.put_mutable(other_pk, 1, sig, b"3:abc".to_vec(), None, None),
            Err(StorageError::InvalidSignature)
        );
        // All-zero garbage.
        assert_eq!(
            storage.put_mutable(pk, 1, [0u8; 64], b"3:abc".to_vec(), None, None),
            Err(StorageError::InvalidSignature)
        );
        assert!(storage.is_empty());
        assert!(storage
            .put_mutable(pk, 1, sig, b"3:abc".to_vec(), None, None)
            .is_ok());
    }

    #[test]
    fn item_count_is_capped_by_evicting_the_oldest() {
        let mut storage = DhtStorage::default();
        let mut first = None;
        for i in 0..(MAX_ITEMS as u32 + 50) {
            let t = storage
                .put_immutable(format!("i{i}e").into_bytes())
                .unwrap();
            first.get_or_insert(t);
        }
        assert_eq!(storage.len(), MAX_ITEMS);
        assert!(
            storage.get(&first.unwrap()).is_none(),
            "the oldest item was evicted"
        );
    }

    #[test]
    fn oversized_values_and_salts_are_refused() {
        let mut storage = DhtStorage::default();
        assert_eq!(
            storage.put_immutable(vec![b'x'; MAX_ITEM_VALUE_LEN + 1]),
            Err(StorageError::ValueTooLarge)
        );
        let (pk, sig) = signed(3, None, 1, b"1:a");
        assert_eq!(
            storage.put_mutable(
                pk,
                1,
                sig,
                b"1:a".to_vec(),
                Some(vec![0; MAX_SALT_LEN + 1]),
                None
            ),
            Err(StorageError::SaltTooLarge)
        );
    }
}
