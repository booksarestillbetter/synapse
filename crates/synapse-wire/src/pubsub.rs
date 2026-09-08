//! BEP 50 Publish / Subscribe Extension for BitTorrent Wire Protocol.
//!
//! Enables gossip topic-based publish and subscribe messaging over the peer wire.

use std::collections::BTreeMap;
use synapse_bencode::BEncode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PubSubMessage {
    Subscribe {
        topic_hash: [u8; 20],
    },
    Unsubscribe {
        topic_hash: [u8; 20],
    },
    Publish {
        topic_hash: [u8; 20],
        payload: Vec<u8>,
    },
}

impl PubSubMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut dict = BTreeMap::new();
        match self {
            PubSubMessage::Subscribe { topic_hash } => {
                dict.insert(b"msg_type".to_vec(), BEncode::Int(0));
                dict.insert(b"topic".to_vec(), BEncode::String(topic_hash.to_vec()));
            }
            PubSubMessage::Unsubscribe { topic_hash } => {
                dict.insert(b"msg_type".to_vec(), BEncode::Int(1));
                dict.insert(b"topic".to_vec(), BEncode::String(topic_hash.to_vec()));
            }
            PubSubMessage::Publish { topic_hash, payload } => {
                dict.insert(b"msg_type".to_vec(), BEncode::Int(2));
                dict.insert(b"topic".to_vec(), BEncode::String(topic_hash.to_vec()));
                dict.insert(b"payload".to_vec(), BEncode::String(payload.clone()));
            }
        }
        BEncode::Dict(dict).encode_to_buf()
    }

    pub fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        let bencode = synapse_bencode::decode_buf(buf).map_err(|_| "invalid bencode")?;
        let mut dict = bencode.into_dict().ok_or("PubSub message must be a dictionary")?;

        let msg_type = dict
            .remove(b"msg_type".as_ref())
            .and_then(BEncode::into_int)
            .ok_or("missing msg_type")?;

        let topic_bytes = dict
            .remove(b"topic".as_ref())
            .and_then(BEncode::into_bytes)
            .ok_or("missing topic")?;

        if topic_bytes.len() != 20 {
            return Err("topic must be 20 bytes");
        }
        let mut topic_hash = [0u8; 20];
        topic_hash.copy_from_slice(&topic_bytes);

        match msg_type {
            0 => Ok(PubSubMessage::Subscribe { topic_hash }),
            1 => Ok(PubSubMessage::Unsubscribe { topic_hash }),
            2 => {
                let payload = dict
                    .remove(b"payload".as_ref())
                    .and_then(BEncode::into_bytes)
                    .unwrap_or_default();
                Ok(PubSubMessage::Publish { topic_hash, payload })
            }
            _ => Err("unknown msg_type in PubSub"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubsub_subscribe_roundtrip() {
        let msg = PubSubMessage::Subscribe {
            topic_hash: [0x55; 20],
        };
        let encoded = msg.encode();
        let decoded = PubSubMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_pubsub_publish_roundtrip() {
        let msg = PubSubMessage::Publish {
            topic_hash: [0x77; 20],
            payload: b"hello swarm gossip".to_vec(),
        };
        let encoded = msg.encode();
        let decoded = PubSubMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }
}
