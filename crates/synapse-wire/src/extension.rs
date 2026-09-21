//! BEP 10 Extension Protocol & BEP 9 / BEP 53 `ut_metadata` Metadata Exchange.
//!
//! Allows clients to advertise custom extension message IDs and dynamically request
//! and transfer `.torrent` metadata dictionaries directly from swarm peers.

use crate::WireError;
use bytes::{BufMut, Bytes, BytesMut};
use std::collections::{BTreeMap, HashMap};
use synapse_bencode::{decode_buf_first, BEncode};

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
    /// Whether this peer is a pure or partial seed not requesting blocks (BEP 21).
    pub upload_only: Option<bool>,
}

impl ExtensionHandshake {
    pub fn new() -> Self {
        Self {
            m: HashMap::new(),
            metadata_size: None,
            v: Some("Synapse 2.0".to_string()),
            reqq: Some(250),
            upload_only: None,
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

    /// Advertises BEP 55 Holepunch Extension (`ut_holepunch`).
    pub fn with_ut_holepunch(mut self, msg_id: u8) -> Self {
        self.m.insert("ut_holepunch".to_string(), msg_id);
        self
    }

    /// Advertises BEP 54 Piece Revocation (`lt_donthave`).
    pub fn with_lt_donthave(mut self, msg_id: u8) -> Self {
        self.m.insert("lt_donthave".to_string(), msg_id);
        self
    }

    /// Marks this peer as a seed or partial seed that does not want to download anything (BEP 21).
    pub fn with_upload_only(mut self, upload_only: bool) -> Self {
        self.upload_only = Some(upload_only);
        self
    }

    /// Constructs an extension handshake for a torrent, strictly obeying BEP 27 privacy rules.
    ///
    /// If `is_private` is true, `ut_pex` is strictly omitted from the extension dictionary `m`.
    pub fn for_torrent(is_private: bool, metadata_size: Option<u32>) -> Self {
        let mut handshake = Self::new()
            .with_ut_metadata(1, metadata_size)
            .with_lt_donthave(4);
        if !is_private {
            handshake = handshake.with_ut_pex(2).with_ut_holepunch(3);
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
        if let Some(upload_only) = self.upload_only {
            root.insert(
                b"upload_only".to_vec(),
                BEncode::Int(if upload_only { 1 } else { 0 }),
            );
        }

        let mut buf = Vec::new();
        BEncode::Dict(root).encode(&mut buf).unwrap();
        Bytes::from(buf)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, WireError> {
        let bencode = decode_buf_first(payload)
            .map_err(|_| WireError::Protocol("malformed BEP 10 extension handshake"))?;
        let mut root = bencode
            .into_dict()
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

        let metadata_size = root
            .remove(b"metadata_size".as_ref())
            .and_then(|e| e.into_int())
            .map(|s| s as u32);
        let v = root.remove(b"v".as_ref()).and_then(|e| e.into_string());
        let reqq = root
            .remove(b"reqq".as_ref())
            .and_then(|e| e.into_int())
            .map(|r| r as u32);
        let upload_only = root
            .remove(b"upload_only".as_ref())
            .and_then(|e| e.into_int())
            .map(|val| val != 0);

        Ok(Self {
            m,
            metadata_size,
            v,
            reqq,
            upload_only,
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
            UtMetadataMessage::Data {
                piece,
                total_size,
                data,
            } => {
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

        let mut dict = bencode.into_dict().ok_or(WireError::Protocol(
            "ut_metadata header must be a bencode dict",
        ))?;

        let msg_type = dict
            .remove(b"msg_type".as_ref())
            .and_then(|v| v.into_int())
            .ok_or(WireError::Protocol("missing msg_type in ut_metadata"))?;

        let piece = dict
            .remove(b"piece".as_ref())
            .and_then(|v| v.into_int())
            .ok_or(WireError::Protocol("missing piece index in ut_metadata"))?
            as u32;

        match msg_type {
            0 => Ok(UtMetadataMessage::Request { piece }),
            1 => {
                let total_size = dict
                    .remove(b"total_size".as_ref())
                    .and_then(|v| v.into_int())
                    .ok_or(WireError::Protocol(
                        "missing total_size in ut_metadata data",
                    ))? as u32;

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

/// BEP 54 `lt_donthave` piece revocation message.
///
/// Sent by a peer to retract a piece it previously advertised via `Have` or `Bitfield`,
/// e.g. when an unverified piece fails disk hashing or is evicted from a sparse cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LtDontHave {
    pub piece: u32,
}

impl LtDontHave {
    pub fn new(piece: u32) -> Self {
        Self { piece }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.piece.to_be_bytes());
        Bytes::copy_from_slice(&buf)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, WireError> {
        if payload.len() != 4 {
            return Err(WireError::Protocol(
                "lt_donthave payload must be exactly 4 bytes",
            ));
        }
        let piece = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        Ok(Self { piece })
    }
}

/// The BEP 30 `Tr_hashpiece` message: a block of a Merkle torrent, and for the first block of a
/// piece (`begin == 0`) the hash list that proves the piece's hash against the torrent's root.
///
/// Payload: `index` (4), `begin` (4), the length of the bencoded hash list (4), the hash list
/// (a bencoded list of `[node, hash]` pairs; empty for any other block), then the block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrHashPiece {
    pub index: u32,
    pub begin: u32,
    pub hashlist: Vec<(u32, [u8; 20])>,
    pub data: Bytes,
}

/// Longest hash list accepted: a tree of a billion pieces is 30 levels, so ~32 nodes suffice.
const MAX_HASHLIST_ENTRIES: usize = 64;
const MAX_HASHLIST_BYTES: usize = MAX_HASHLIST_ENTRIES * 40;

/// The extension name a peer advertises for `Tr_hashpiece` in its LTEP handshake.
pub const TR_HASHPIECE: &str = "Tr_hashpiece";

impl TrHashPiece {
    pub fn encode(&self) -> Bytes {
        let list = BEncode::List(
            self.hashlist
                .iter()
                .map(|(node, hash)| {
                    BEncode::List(vec![
                        BEncode::Int(i64::from(*node)),
                        BEncode::String(hash.to_vec()),
                    ])
                })
                .collect(),
        );
        let mut list_bytes = Vec::new();
        list.encode(&mut list_bytes)
            .expect("in-memory encoding cannot fail");
        let mut out = Vec::with_capacity(12 + list_bytes.len() + self.data.len());
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.begin.to_be_bytes());
        out.extend_from_slice(&(list_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&list_bytes);
        out.extend_from_slice(&self.data);
        Bytes::from(out)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, WireError> {
        if payload.len() < 12 {
            return Err(WireError::Protocol("Tr_hashpiece payload too short"));
        }
        let index = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let begin = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let list_len =
            u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]) as usize;
        if list_len > MAX_HASHLIST_BYTES || payload.len() < 12 + list_len {
            return Err(WireError::Protocol(
                "Tr_hashpiece hash list length is invalid",
            ));
        }
        let list_bytes = &payload[12..12 + list_len];
        let mut hashlist = Vec::new();
        if !list_bytes.is_empty() {
            let decoded = synapse_bencode::decode_buf(list_bytes)
                .map_err(|_| WireError::Protocol("Tr_hashpiece hash list is not bencode"))?;
            let entries = decoded
                .into_list()
                .ok_or(WireError::Protocol("Tr_hashpiece hash list is not a list"))?;
            if entries.len() > MAX_HASHLIST_ENTRIES {
                return Err(WireError::Protocol(
                    "Tr_hashpiece hash list has too many entries",
                ));
            }
            for entry in entries {
                let pair =
                    entry
                        .into_list()
                        .filter(|p| p.len() == 2)
                        .ok_or(WireError::Protocol(
                            "Tr_hashpiece hash list entry is malformed",
                        ))?;
                let mut pair = pair.into_iter();
                let node = pair
                    .next()
                    .and_then(BEncode::into_int)
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or(WireError::Protocol("Tr_hashpiece node number is invalid"))?;
                let hash: [u8; 20] = pair
                    .next()
                    .and_then(BEncode::into_bytes)
                    .and_then(|h| h.try_into().ok())
                    .ok_or(WireError::Protocol("Tr_hashpiece hash must be 20 bytes"))?;
                hashlist.push((node, hash));
            }
        }
        Ok(Self {
            index,
            begin,
            hashlist,
            data: Bytes::copy_from_slice(&payload[12 + list_len..]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_handshake_roundtrip() {
        let handshake = ExtensionHandshake::new().with_ut_metadata(1, Some(32768));

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
        let raw_chunk = Bytes::from_static(
            b"d4:name10:test.video12:piece lengthi16384e6:pieces20:12345678901234567890e",
        );
        let data_msg = UtMetadataMessage::Data {
            piece: 0,
            total_size: raw_chunk.len() as u32,
            data: raw_chunk.clone(),
        };

        let encoded = data_msg.encode();
        let decoded = UtMetadataMessage::decode(&encoded).unwrap();

        match decoded {
            UtMetadataMessage::Data {
                piece,
                total_size,
                data,
            } => {
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
        assert!(
            !dec_private.m.contains_key("ut_pex"),
            "BEP 27 violation: ut_pex present in private extension handshake"
        );
    }

    #[test]
    fn test_extension_handshake_bep21_upload_only() {
        let hs = ExtensionHandshake::new().with_upload_only(true);
        assert_eq!(hs.upload_only, Some(true));

        let encoded = hs.encode();
        let decoded = ExtensionHandshake::decode(&encoded).unwrap();
        assert_eq!(decoded.upload_only, Some(true));

        let hs_false = ExtensionHandshake::new().with_upload_only(false);
        let encoded_false = hs_false.encode();
        let decoded_false = ExtensionHandshake::decode(&encoded_false).unwrap();
        assert_eq!(decoded_false.upload_only, Some(false));
    }

    #[test]
    fn test_lt_donthave_roundtrip() {
        let msg = LtDontHave::new(42);
        let encoded = msg.encode();
        assert_eq!(encoded.len(), 4);
        let decoded = LtDontHave::decode(&encoded).unwrap();
        assert_eq!(decoded.piece, 42);

        // Invalid length check
        assert!(LtDontHave::decode(&[1, 2, 3]).is_err());
    }

    #[test]
    fn tr_hashpiece_round_trips_and_rejects_malformed_payloads() {
        let msg = TrHashPiece {
            index: 7,
            begin: 0,
            hashlist: vec![(9, [1; 20]), (10, [2; 20]), (0, [3; 20])],
            data: Bytes::from_static(b"block bytes"),
        };
        assert_eq!(TrHashPiece::decode(&msg.encode()).unwrap(), msg);
        let later = TrHashPiece {
            index: 7,
            begin: 16384,
            hashlist: Vec::new(),
            data: Bytes::from_static(b"more"),
        };
        assert_eq!(TrHashPiece::decode(&later.encode()).unwrap(), later);
        // Truncated, list length beyond the payload, absurd list length, wrong shapes.
        let good = msg.encode();
        assert!(TrHashPiece::decode(&good[..11]).is_err());
        assert!(TrHashPiece::decode(&good[..14]).is_err());
        let mut huge = good.to_vec();
        huge[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(TrHashPiece::decode(&huge).is_err());
        for bad_list in [
            &b"i3e"[..],
            b"li1ee",
            b"lli1e3:abcee",
            b"lli-1e20:aaaaaaaaaaaaaaaaaaaaee",
        ] {
            let mut p = vec![0u8; 8];
            p.extend_from_slice(&(bad_list.len() as u32).to_be_bytes());
            p.extend_from_slice(bad_list);
            assert!(TrHashPiece::decode(&p).is_err(), "{bad_list:?}");
        }
    }
}
