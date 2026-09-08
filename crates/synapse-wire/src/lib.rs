//! BitTorrent peer wire protocol (BEP3 base protocol + BEP10 extension protocol)
//! framing, as a `tokio_util::codec::{Decoder, Encoder}` pair.
//!
//! Replaces the pre-rewrite codebase's hand-rolled `protocol/` crate and
//! `src/torrent/peer/{reader,writer}.rs` state machines (see `doc/REWRITE_ROADMAP.md`
//! Part 2) - this crate exists so a peer connection can be driven as
//! `Framed<TcpStream, PeerCodec>` on tokio instead of a manually-driven non-blocking
//! state machine. Message payloads (`Bitfield`, `Piece::data`, `Extension::payload`) use
//! `bytes::Bytes`, sliced zero-copy out of the codec's accumulator buffer rather than
//! copied into a fresh allocation per message.
//!
//! Wire format reference: the exact byte layouts here (message IDs, field order, the
//! handshake's fixed 68-byte shape) were checked against the pre-rewrite `protocol`
//! crate's `Message::encode`/`len` and `torrent/peer/reader.rs`'s decode logic, not
//! written from memory of the BEPs alone.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// Cap on a single non-handshake message's declared length (the 4-byte length prefix's
/// value, i.e. id byte + payload), checked before the message type is even known. Bounds
/// how much a peer can force us to buffer just by sending a length prefix, before we've
/// seen anything else. Individual message types apply tighter limits once their id is
/// known (see `decode_message`).
pub const MAX_MESSAGE_LEN: u32 = 8 * 1024 * 1024;

/// Practical cap on a `Piece` message's block payload. 16KiB is the conventional
/// BitTorrent block size; this leaves generous headroom above it for clients using
/// larger blocks without accepting an arbitrary peer-declared size.
pub const MAX_BLOCK_LEN: u32 = 1024 * 1024;

/// Same rationale/value as the pre-rewrite codebase's `MAX_EXT_MSG_BYTES` fix (see
/// `CHANGELOG.md`): a ut_metadata piece is capped at 16KiB by BEP9, and even a
/// large-swarm ut_pex update stays in the tens-to-low-hundreds-of-KB range.
pub const MAX_EXTENSION_LEN: u32 = 4 * 1024 * 1024;

pub mod bep40;
pub mod crypto;
pub mod extension;
pub mod holepunch;
pub mod lsd;
pub mod pex;
pub mod pubsub;
pub mod stun;
pub mod utp;

pub use bep40::{canonical_peer_priority, canonical_peer_score};
pub use crypto::{EncryptedStream, EncryptionMode, Rc4Cipher};
pub use extension::{ExtensionHandshake, UtMetadataMessage, UT_METADATA_PIECE_LEN};
pub use holepunch::{HolepunchMessage, HolepunchType};
pub use lsd::{format_lsd_announce, parse_lsd_announce, LsdAnnounce, LsdError, LSD_MULTICAST_IPV4, LSD_PORT};
pub use pex::{
    UtPexMessage, PEX_FLAG_ENCRYPTION_PREFERRED, PEX_FLAG_SEEDER, PEX_FLAG_UTP_SUPPORTED,
};
pub use pubsub::PubSubMessage;
pub use stun::{encode_stun_binding_request, parse_stun_binding_response, STUN_MAGIC_COOKIE};
pub use utp::{UtpHeader, UtpPacket, UtpType, UTP_HEADER_LEN, UTP_VERSION};

const HANDSHAKE_LEN: usize = 68;
const PROTOCOL_STR: &[u8] = b"BitTorrent protocol";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Handshake {
        reserved: [u8; 8],
        info_hash: [u8; 20],
        peer_id: [u8; 20],
    },
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    Uninterested,
    Have(u32),
    Bitfield(Bytes),
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        data: Bytes,
    },
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
    Port(u16),
    SuggestPiece(u32),
    HaveAll,
    HaveNone,
    RejectRequest {
        index: u32,
        begin: u32,
        length: u32,
    },
    AllowedFast(u32),
    Extension {
        id: u8,
        payload: Bytes,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(&'static str),
}

/// Codec state: the handshake is a one-time, non-length-prefixed 68-byte message that
/// must be the first thing read/written on a connection; every message after it uses
/// standard 4-byte-length-prefixed framing. `PeerCodec` tracks which mode it's in rather
/// than requiring callers to juggle two separate codecs.
pub struct PeerCodec {
    handshake_read: bool,
}

impl PeerCodec {
    pub fn new() -> PeerCodec {
        PeerCodec {
            handshake_read: false,
        }
    }
}

impl Default for PeerCodec {
    fn default() -> Self {
        PeerCodec::new()
    }
}

impl Decoder for PeerCodec {
    type Item = Message;
    type Error = WireError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Message>, WireError> {
        if !self.handshake_read {
            return decode_handshake(self, src);
        }
        decode_message(src)
    }
}

fn decode_handshake(
    codec: &mut PeerCodec,
    src: &mut BytesMut,
) -> Result<Option<Message>, WireError> {
    if src.len() < HANDSHAKE_LEN {
        src.reserve(HANDSHAKE_LEN - src.len());
        return Ok(None);
    }
    if src[0] != 19 {
        return Err(WireError::Protocol("invalid handshake protocol-string length"));
    }
    if &src[1..20] != PROTOCOL_STR {
        return Err(WireError::Protocol("unexpected handshake protocol string"));
    }

    let buf = src.split_to(HANDSHAKE_LEN).freeze();
    let mut reserved = [0u8; 8];
    reserved.copy_from_slice(&buf[20..28]);
    let mut info_hash = [0u8; 20];
    info_hash.copy_from_slice(&buf[28..48]);
    let mut peer_id = [0u8; 20];
    peer_id.copy_from_slice(&buf[48..68]);

    codec.handshake_read = true;
    Ok(Some(Message::Handshake {
        reserved,
        info_hash,
        peer_id,
    }))
}

fn decode_message(src: &mut BytesMut) -> Result<Option<Message>, WireError> {
    if src.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
    if len == 0 {
        src.advance(4);
        return Ok(Some(Message::KeepAlive));
    }
    if len > MAX_MESSAGE_LEN {
        return Err(WireError::Protocol("message length exceeds MAX_MESSAGE_LEN"));
    }
    let total = 4 + len as usize;
    if src.len() < total {
        src.reserve(total - src.len());
        return Ok(None);
    }

    let id = src[4];
    // `payload` is everything after the 4-byte length prefix and 1-byte id.
    let payload_len = len as usize - 1;

    let msg = match id {
        0..=3 if payload_len != 0 => {
            return Err(WireError::Protocol("fixed-size message has a non-zero payload"))
        }
        0 => Message::Choke,
        1 => Message::Unchoke,
        2 => Message::Interested,
        3 => Message::Uninterested,
        4 if payload_len == 4 => Message::Have(u32::from_be_bytes([
            src[5], src[6], src[7], src[8],
        ])),
        4 => return Err(WireError::Protocol("Have message has the wrong length")),
        5 => Message::Bitfield(Bytes::new()), // payload filled in below, after split_to
        6 if payload_len == 12 => Message::Request {
            index: u32::from_be_bytes([src[5], src[6], src[7], src[8]]),
            begin: u32::from_be_bytes([src[9], src[10], src[11], src[12]]),
            length: u32::from_be_bytes([src[13], src[14], src[15], src[16]]),
        },
        6 => return Err(WireError::Protocol("Request message has the wrong length")),
        7 if payload_len >= 8 => Message::Piece {
            index: u32::from_be_bytes([src[5], src[6], src[7], src[8]]),
            begin: u32::from_be_bytes([src[9], src[10], src[11], src[12]]),
            data: Bytes::new(), // filled in below
        },
        7 => return Err(WireError::Protocol("Piece message is too short")),
        8 if payload_len == 12 => Message::Cancel {
            index: u32::from_be_bytes([src[5], src[6], src[7], src[8]]),
            begin: u32::from_be_bytes([src[9], src[10], src[11], src[12]]),
            length: u32::from_be_bytes([src[13], src[14], src[15], src[16]]),
        },
        8 if payload_len == 12 => Message::Cancel {
            index: u32::from_be_bytes([src[5], src[6], src[7], src[8]]),
            begin: u32::from_be_bytes([src[9], src[10], src[11], src[12]]),
            length: u32::from_be_bytes([src[13], src[14], src[15], src[16]]),
        },
        8 => return Err(WireError::Protocol("Cancel message has the wrong length")),
        9 if payload_len == 2 => Message::Port(u16::from_be_bytes([src[5], src[6]])),
        9 => return Err(WireError::Protocol("Port message has the wrong length")),
        13 if payload_len == 4 => Message::SuggestPiece(u32::from_be_bytes([
            src[5], src[6], src[7], src[8],
        ])),
        13 => return Err(WireError::Protocol("SuggestPiece message has the wrong length")),
        14 if payload_len == 0 => Message::HaveAll,
        14 => return Err(WireError::Protocol("HaveAll message has a non-zero payload")),
        15 if payload_len == 0 => Message::HaveNone,
        15 => return Err(WireError::Protocol("HaveNone message has a non-zero payload")),
        16 if payload_len == 12 => Message::RejectRequest {
            index: u32::from_be_bytes([src[5], src[6], src[7], src[8]]),
            begin: u32::from_be_bytes([src[9], src[10], src[11], src[12]]),
            length: u32::from_be_bytes([src[13], src[14], src[15], src[16]]),
        },
        16 => return Err(WireError::Protocol("RejectRequest message has the wrong length")),
        17 if payload_len == 4 => Message::AllowedFast(u32::from_be_bytes([
            src[5], src[6], src[7], src[8],
        ])),
        17 => return Err(WireError::Protocol("AllowedFast message has the wrong length")),
        20 if payload_len >= 1 => Message::Extension {
            id: 0, // filled in below
            payload: Bytes::new(),
        },
        20 => return Err(WireError::Protocol("Extension message is too short")),
        _ => return Err(WireError::Protocol("unknown message id")),
    };

    // Checks above validated lengths against the buffer contents still sitting in
    // `src`; now actually take ownership of the frame and fill in any payload that was
    // deferred (`Bitfield`/`Piece::data`/`Extension`) via zero-copy `Bytes` slicing.
    if id == 7 && payload_len as u32 > MAX_BLOCK_LEN + 8 {
        return Err(WireError::Protocol("Piece block exceeds MAX_BLOCK_LEN"));
    }
    if id == 20 && payload_len as u32 > MAX_EXTENSION_LEN {
        return Err(WireError::Protocol("Extension payload exceeds MAX_EXTENSION_LEN"));
    }

    let frame = src.split_to(total).freeze();
    let msg = match (id, msg) {
        (5, _) => Message::Bitfield(frame.slice(5..total)),
        (7, Message::Piece { index, begin, .. }) => Message::Piece {
            index,
            begin,
            data: frame.slice(13..total),
        },
        (20, _) => Message::Extension {
            id: frame[5],
            payload: frame.slice(6..total),
        },
        (_, msg) => msg,
    };

    Ok(Some(msg))
}

impl Encoder<Message> for PeerCodec {
    type Error = WireError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), WireError> {
        match item {
            Message::Handshake {
                reserved,
                info_hash,
                peer_id,
            } => {
                dst.reserve(HANDSHAKE_LEN);
                dst.put_u8(19);
                dst.put_slice(PROTOCOL_STR);
                dst.put_slice(&reserved);
                dst.put_slice(&info_hash);
                dst.put_slice(&peer_id);
            }
            Message::KeepAlive => dst.put_u32(0),
            Message::Choke => {
                dst.put_u32(1);
                dst.put_u8(0);
            }
            Message::Unchoke => {
                dst.put_u32(1);
                dst.put_u8(1);
            }
            Message::Interested => {
                dst.put_u32(1);
                dst.put_u8(2);
            }
            Message::Uninterested => {
                dst.put_u32(1);
                dst.put_u8(3);
            }
            Message::Have(piece) => {
                dst.put_u32(5);
                dst.put_u8(4);
                dst.put_u32(piece);
            }
            Message::Bitfield(bits) => {
                dst.reserve(5 + bits.len());
                dst.put_u32(1 + bits.len() as u32);
                dst.put_u8(5);
                dst.put_slice(&bits);
            }
            Message::Request {
                index,
                begin,
                length,
            } => {
                dst.put_u32(13);
                dst.put_u8(6);
                dst.put_u32(index);
                dst.put_u32(begin);
                dst.put_u32(length);
            }
            Message::Piece { index, begin, data } => {
                dst.reserve(13 + data.len());
                dst.put_u32(9 + data.len() as u32);
                dst.put_u8(7);
                dst.put_u32(index);
                dst.put_u32(begin);
                dst.put_slice(&data);
            }
            Message::Cancel {
                index,
                begin,
                length,
            } => {
                dst.put_u32(13);
                dst.put_u8(8);
                dst.put_u32(index);
                dst.put_u32(begin);
                dst.put_u32(length);
            }
            Message::Port(port) => {
                dst.put_u32(3);
                dst.put_u8(9);
                dst.put_u16(port);
            }
            Message::SuggestPiece(piece) => {
                dst.put_u32(5);
                dst.put_u8(13);
                dst.put_u32(piece);
            }
            Message::HaveAll => {
                dst.put_u32(1);
                dst.put_u8(14);
            }
            Message::HaveNone => {
                dst.put_u32(1);
                dst.put_u8(15);
            }
            Message::RejectRequest {
                index,
                begin,
                length,
            } => {
                dst.put_u32(13);
                dst.put_u8(16);
                dst.put_u32(index);
                dst.put_u32(begin);
                dst.put_u32(length);
            }
            Message::AllowedFast(piece) => {
                dst.put_u32(5);
                dst.put_u8(17);
                dst.put_u32(piece);
            }
            Message::Extension { id, payload } => {
                dst.reserve(6 + payload.len());
                dst.put_u32(2 + payload.len() as u32);
                dst.put_u8(20);
                dst.put_u8(id);
                dst.put_slice(&payload);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: Message) -> Message {
        let mut codec = PeerCodec::new();
        codec.handshake_read = true; // skip handshake mode for non-handshake messages
        let mut buf = BytesMut::new();
        codec.encode(msg.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert!(buf.is_empty(), "decoder should consume the whole frame");
        decoded
    }

    #[test]
    fn handshake_roundtrip() {
        let mut codec = PeerCodec::new();
        let msg = Message::Handshake {
            reserved: [1, 2, 3, 4, 5, 6, 7, 8],
            info_hash: [9u8; 20],
            peer_id: [10u8; 20],
        };
        let mut buf = BytesMut::new();
        codec.encode(msg.clone(), &mut buf).unwrap();
        assert_eq!(buf.len(), HANDSHAKE_LEN);
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, msg);
        assert!(codec.handshake_read);
    }

    #[test]
    fn handshake_rejects_wrong_protocol_string() {
        let mut codec = PeerCodec::new();
        let mut buf = BytesMut::new();
        buf.put_u8(19);
        buf.put_slice(b"Not the right proto"); // 20 bytes, wrong content
        buf.put_slice(&[0u8; 48]);
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, WireError::Protocol(_)));
    }

    #[test]
    fn handshake_waits_for_a_full_frame() {
        let mut codec = PeerCodec::new();
        let mut buf = BytesMut::new();
        buf.put_u8(19);
        buf.put_slice(PROTOCOL_STR);
        // Missing the remaining 28 bytes (reserved + hash + peer id).
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn keepalive_roundtrip() {
        assert_eq!(roundtrip(Message::KeepAlive), Message::KeepAlive);
    }

    #[test]
    fn fixed_size_messages_roundtrip() {
        assert_eq!(roundtrip(Message::Choke), Message::Choke);
        assert_eq!(roundtrip(Message::Unchoke), Message::Unchoke);
        assert_eq!(roundtrip(Message::Interested), Message::Interested);
        assert_eq!(roundtrip(Message::Uninterested), Message::Uninterested);
        assert_eq!(roundtrip(Message::Have(42)), Message::Have(42));
        assert_eq!(roundtrip(Message::Port(6881)), Message::Port(6881));
    }

    #[test]
    fn test_fast_extension_messages_roundtrip() {
        assert_eq!(roundtrip(Message::HaveAll), Message::HaveAll);
        assert_eq!(roundtrip(Message::HaveNone), Message::HaveNone);
        assert_eq!(roundtrip(Message::SuggestPiece(128)), Message::SuggestPiece(128));
        assert_eq!(roundtrip(Message::AllowedFast(512)), Message::AllowedFast(512));
        assert_eq!(
            roundtrip(Message::RejectRequest {
                index: 10,
                begin: 16384,
                length: 16384,
            }),
            Message::RejectRequest {
                index: 10,
                begin: 16384,
                length: 16384,
            }
        );
    }

    #[test]
    fn bitfield_roundtrip() {
        let bits = Bytes::from_static(&[0xFF, 0x0F, 0x00]);
        assert_eq!(
            roundtrip(Message::Bitfield(bits.clone())),
            Message::Bitfield(bits)
        );
    }

    #[test]
    fn request_and_cancel_roundtrip() {
        let req = Message::Request {
            index: 1,
            begin: 2,
            length: 16_384,
        };
        assert_eq!(roundtrip(req.clone()), req);
        let cancel = Message::Cancel {
            index: 1,
            begin: 2,
            length: 16_384,
        };
        assert_eq!(roundtrip(cancel.clone()), cancel);
    }

    #[test]
    fn piece_roundtrip_is_zero_copy() {
        let data = Bytes::from(vec![7u8; 16_384]);
        let msg = Message::Piece {
            index: 5,
            begin: 0,
            data: data.clone(),
        };
        match roundtrip(msg) {
            Message::Piece { data: got, .. } => assert_eq!(got, data),
            other => panic!("expected Piece, got {other:?}"),
        }
    }

    #[test]
    fn extension_roundtrip() {
        let payload = Bytes::from_static(b"d1:md11:ut_metadatai1eee");
        let msg = Message::Extension {
            id: 1,
            payload: payload.clone(),
        };
        assert_eq!(
            roundtrip(msg),
            Message::Extension {
                id: 1,
                payload
            }
        );
    }

    #[test]
    fn incomplete_message_waits_for_more_data() {
        let mut codec = PeerCodec::new();
        codec.handshake_read = true;
        let mut buf = BytesMut::new();
        buf.put_u32(5); // Have message: 5 bytes to follow
        buf.put_u8(4);
        // Missing the 4-byte piece index.
        assert!(codec.decode(&mut buf).unwrap().is_none());
        buf.put_u32(99);
        assert_eq!(codec.decode(&mut buf).unwrap(), Some(Message::Have(99)));
    }

    #[test]
    fn rejects_message_length_over_max() {
        let mut codec = PeerCodec::new();
        codec.handshake_read = true;
        let mut buf = BytesMut::new();
        buf.put_u32(MAX_MESSAGE_LEN + 1);
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, WireError::Protocol(_)));
    }

    #[test]
    fn rejects_oversized_piece_block() {
        let mut codec = PeerCodec::new();
        codec.handshake_read = true;
        let mut buf = BytesMut::new();
        let oversized_len = 9 + MAX_BLOCK_LEN + 1;
        buf.put_u32(oversized_len);
        buf.put_u8(7);
        buf.put_u32(0);
        buf.put_u32(0);
        buf.put_bytes(0, (oversized_len - 9) as usize);
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, WireError::Protocol(_)));
    }

    #[test]
    fn rejects_wrong_length_for_fixed_size_message() {
        let mut codec = PeerCodec::new();
        codec.handshake_read = true;
        let mut buf = BytesMut::new();
        buf.put_u32(2); // Choke should always be length 1
        buf.put_u8(0);
        buf.put_u8(0xAA);
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, WireError::Protocol(_)));
    }

    #[test]
    fn rejects_unknown_message_id() {
        let mut codec = PeerCodec::new();
        codec.handshake_read = true;
        let mut buf = BytesMut::new();
        buf.put_u32(1);
        buf.put_u8(200);
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, WireError::Protocol(_)));
    }

    #[test]
    fn multiple_messages_in_one_buffer_decode_in_order() {
        let mut codec = PeerCodec::new();
        codec.handshake_read = true;
        let mut buf = BytesMut::new();
        codec.encode(Message::Choke, &mut buf).unwrap();
        codec.encode(Message::Unchoke, &mut buf).unwrap();
        codec.encode(Message::Have(3), &mut buf).unwrap();

        assert_eq!(codec.decode(&mut buf).unwrap(), Some(Message::Choke));
        assert_eq!(codec.decode(&mut buf).unwrap(), Some(Message::Unchoke));
        assert_eq!(codec.decode(&mut buf).unwrap(), Some(Message::Have(3)));
        assert_eq!(codec.decode(&mut buf).unwrap(), None);
    }
}
