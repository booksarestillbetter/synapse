//! BEP 10 Extension Protocol & BEP 9 / BEP 53 `ut_metadata` Metadata Exchange.
//!
//! Allows clients to advertise custom extension message IDs and dynamically request
//! and transfer `.torrent` metadata dictionaries directly from swarm peers.

use bytes::{BufMut, Bytes, BytesMut};
use std::collections::{BTreeMap, HashMap};
use synapse_bencode::{decode_buf_first, BEncode};
use crate::WireError;

pub const UT_METADATA_PIECE_LEN: usize = 16 * 1024; // 16 KiB per BEP 9

/// BEP 10 Extension Handshake dictionary (Message ID = 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionHandshake {
    /// Map of extension name -> message ID (e.g. "ut_metadata" -> 1, "ut_pex" -> 2).
    pub m: HashMap<String, u8>,
    /// Declared size in bytes of the .torrent metadata.
    pub metadata_size: Option<u32>,
    /// Client identifier version string.
    pub v: Option<String>,
    /// Maximum outstanding request queue size.
    pub reqq: Option<u32>,
}

impl ExtensionHandshake {
    pub fn new() -> Self {
        Self {
            m: HashMap::new(),
            metadata_size: None,
            v: Some("Synapse 2.0".to_string()),
            reqq: Some(250),
        }
    }

    pub fn with_ut_metadata(mut self, msg_id: u8, metadata_size: Option<u32>) -> Self {
        self.m.insert("ut_metadata".to_string(), msg_id);
        self.metadata_size = metadata_size;
        self
    }

    /// Advertises BEP 11 Peer Exchange (`ut_pex`).
    ///
    /// Per BEP 27, `ut_pex` MUST NEVER be advertised or sent on private torrents.
    pub fn with_ut_pex(mut self, msg_id: u8) -> Self {
        self.m.insert("ut_pex".to_string(), msg_id);
        self
    }

    /// Constructs an extension handshake for a torrent, strictly obeying BEP 27 privacy rules.
    ///
    /// If `is_private` is true, `ut_pex` is strictly omitted from the extension dictionary `m`.
    pub fn for_torrent(is_private: bool, metadata_size: Option<u32>) -> Self {
        let mut handshake = Self::new().with_ut_metadata(1, metadata_size);
        if !is_private {
            handshake = handshake.with_ut_pex(2);
        }
        handshake
    }

    pub fn encode(&self) -> Bytes {
        let mut m_dict = BTreeMap::new();
        for (name, id) in &self.m {
            m_dict.insert(name.as_bytes().to_vec(), BEncode::Int(*id as i64));
        }

        let mut root = BTreeMap::new();
        root.insert(b"m".to_vec(), BEncode::Dict(m_dict));

        if let Some(size) = self.metadata_size {
            root.insert(b"metadata_size".to_vec(), BEncode::Int(size as i64));
        }
        if let Some(ref v) = self.v {
            root.insert(b"v".to_vec(), BEncode::String(v.as_bytes().to_vec()));
        }
        if let Some(reqq) = self.reqq {
            root.insert(b"reqq".to_vec(), BEncode::Int(reqq as i64));
        }

        let mut buf = Vec::new();
        BEncode::Dict(root).encode(&mut buf).unwrap();
        Bytes::from(buf)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, WireError> {
        let bencode = decode_buf_first(payload)
            .map_err(|_| WireError::Protocol("malformed BEP 10 extension handshake"))?;
        let mut root = bencode.into_dict()
            .ok_or(WireError::Protocol("BEP 10 handshake is not a dictionary"))?;

        let mut m = HashMap::new();
        if let Some(m_entry) = root.remove(b"m".as_ref()).and_then(|e| e.into_dict()) {
            for (k, v) in m_entry {
                if let (Ok(name), Some(id)) = (String::from_utf8(k), v.into_int()) {
                    if (1..=255).contains(&id) {
                        m.insert(name, id as u8);
                    }
                }
            }
        }

        let metadata_size = root.remove(b"metadata_size".as_ref())
            .and_then(|e| e.into_int())
            .map(|s| s as u32);
        let v = root.remove(b"v".as_ref()).and_then(|e| e.into_string());
        let reqq = root.remove(b"reqq".as_ref()).and_then(|e| e.into_int()).map(|r| r as u32);

        Ok(Self {
            m,
            metadata_size,
            v,
            reqq,
        })
    }
}

impl Default for ExtensionHandshake {
    fn default() -> Self {
        Self::new()
    }
}

/// BEP 9 `ut_metadata` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtMetadataMessage {
    /// Request a 16 KiB piece of metadata (`msg_type = 0`).
    Request { piece: u32 },
    /// Data containing a 16 KiB chunk of metadata (`msg_type = 1`).
    Data {
        piece: u32,
        total_size: u32,
        data: Bytes,
    },
    /// Rejection of a requested metadata piece (`msg_type = 2`).
    Reject { piece: u32 },
}

impl UtMetadataMessage {
    pub fn encode(&self) -> Bytes {
        let mut dict = BTreeMap::new();
        match self {
            UtMetadataMessage::Request { piece } => {
                dict.insert(b"msg_type".to_vec(), BEncode::Int(0));
                dict.insert(b"piece".to_vec(), BEncode::Int(*piece as i64));
                let mut buf = Vec::new();
                BEncode::Dict(dict).encode(&mut buf).unwrap();
                Bytes::from(buf)
            }
            UtMetadataMessage::Data { piece, total_size, data } => {
                dict.insert(b"msg_type".to_vec(), BEncode::Int(1));
                dict.insert(b"piece".to_vec(), BEncode::Int(*piece as i64));
                dict.insert(b"total_size".to_vec(), BEncode::Int(*total_size as i64));
                let mut header = Vec::new();
                BEncode::Dict(dict).encode(&mut header).unwrap();

                let mut out = BytesMut::with_capacity(header.len() + data.len());
                out.put_slice(&header);
                out.put_slice(data);
                out.freeze()
            }
            UtMetadataMessage::Reject { piece } => {
                dict.insert(b"msg_type".to_vec(), BEncode::Int(2));
                dict.insert(b"piece".to_vec(), BEncode::Int(*piece as i64));
                let mut buf = Vec::new();
                BEncode::Dict(dict).encode(&mut buf).unwrap();
                Bytes::from(buf)
            }
        }
    }

    pub fn decode(payload: &[u8]) -> Result<Self, WireError> {
        let bencode = decode_buf_first(payload)
            .map_err(|_| WireError::Protocol("malformed ut_metadata message bencode"))?;

        let mut dict = bencode.into_dict()
            .ok_or(WireError::Protocol("ut_metadata header must be a bencode dict"))?;

        let msg_type = dict.remove(b"msg_type".as_ref())
            .and_then(|v| v.into_int())
            .ok_or(WireError::Protocol("missing msg_type in ut_metadata"))?;

        let piece = dict.remove(b"piece".as_ref())
            .and_then(|v| v.into_int())
            .ok_or(WireError::Protocol("missing piece index in ut_metadata"))? as u32;

        match msg_type {
            0 => Ok(UtMetadataMessage::Request { piece }),
            1 => {
                let total_size = dict.remove(b"total_size".as_ref())
                    .and_then(|v| v.into_int())
                    .ok_or(WireError::Protocol("missing total_size in ut_metadata data"))? as u32;

                // Find where the bencoded header ends to extract raw binary data payload
                let mut header_buf = Vec::new();
                // Re-encode dictionary to get exact header length
                let mut test_dict = BTreeMap::new();
                test_dict.insert(b"msg_type".to_vec(), BEncode::Int(1));
                test_dict.insert(b"piece".to_vec(), BEncode::Int(piece as i64));
                test_dict.insert(b"total_size".to_vec(), BEncode::Int(total_size as i64));
                BEncode::Dict(test_dict).encode(&mut header_buf).unwrap();

                let header_len = header_buf.len();
                if payload.len() < header_len {
                    return Err(WireError::Protocol("ut_metadata data payload too short"));
                }
                let data = Bytes::copy_from_slice(&payload[header_len..]);
                Ok(UtMetadataMessage::Data {
                    piece,
                    total_size,
                    data,
                })
            }
            2 => Ok(UtMetadataMessage::Reject { piece }),
            _ => Err(WireError::Protocol("unknown ut_metadata msg_type")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_handshake_roundtrip() {
        let handshake = ExtensionHandshake::new()
            .with_ut_metadata(1, Some(32768));

        let encoded = handshake.encode();
        let decoded = ExtensionHandshake::decode(&encoded).unwrap();

        assert_eq!(decoded.m.get("ut_metadata"), Some(&1));
        assert_eq!(decoded.metadata_size, Some(32768));
        assert_eq!(decoded.v, Some("Synapse 2.0".to_string()));
        assert_eq!(decoded.reqq, Some(250));
    }

    #[test]
    fn test_ut_metadata_request_and_reject_roundtrip() {
        let req = UtMetadataMessage::Request { piece: 3 };
        let encoded_req = req.encode();
        let decoded_req = UtMetadataMessage::decode(&encoded_req).unwrap();
        assert_eq!(decoded_req, req);

        let rej = UtMetadataMessage::Reject { piece: 5 };
        let encoded_rej = rej.encode();
        let decoded_rej = UtMetadataMessage::decode(&encoded_rej).unwrap();
        assert_eq!(decoded_rej, rej);
    }

    #[test]
    fn test_ut_metadata_data_roundtrip() {
        let raw_chunk = Bytes::from_static(b"d4:name10:test.video12:piece lengthi16384e6:pieces20:12345678901234567890e");
        let data_msg = UtMetadataMessage::Data {
            piece: 0,
            total_size: raw_chunk.len() as u32,
            data: raw_chunk.clone(),
        };

        let encoded = data_msg.encode();
        let decoded = UtMetadataMessage::decode(&encoded).unwrap();

        match decoded {
            UtMetadataMessage::Data { piece, total_size, data } => {
                assert_eq!(piece, 0);
                assert_eq!(total_size, raw_chunk.len() as u32);
                assert_eq!(data, raw_chunk);
            }
            _ => panic!("Expected UtMetadataMessage::Data"),
        }
    }

    #[test]
    fn test_extension_handshake_bep27_private_isolation() {
        // Public torrent handshake advertises ut_pex
        let public_hs = ExtensionHandshake::for_torrent(false, Some(1024));
        assert!(public_hs.m.contains_key("ut_pex"));
        assert!(public_hs.m.contains_key("ut_metadata"));

        let enc_public = public_hs.encode();
        let dec_public = ExtensionHandshake::decode(&enc_public).unwrap();
        assert!(dec_public.m.contains_key("ut_pex"));

        // Private torrent handshake MUST NOT advertise ut_pex
        let private_hs = ExtensionHandshake::for_torrent(true, Some(1024));
        assert!(!private_hs.m.contains_key("ut_pex"));
        assert!(private_hs.m.contains_key("ut_metadata"));

        let enc_private = private_hs.encode();
        let dec_private = ExtensionHandshake::decode(&enc_private).unwrap();
        assert!(!dec_private.m.contains_key("ut_pex"), "BEP 27 violation: ut_pex present in private extension handshake");
    }
}
