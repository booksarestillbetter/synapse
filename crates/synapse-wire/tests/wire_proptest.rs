use bytes::{Bytes, BytesMut};
use proptest::prelude::*;
use tokio_util::codec::{Decoder, Encoder};

use synapse_wire::{Message, PeerCodec, UtpHeader, UtpPacket, UtpType};

fn arb_message() -> impl Strategy<Value = Message> {
    prop_oneof![
        Just(Message::KeepAlive),
        Just(Message::Choke),
        Just(Message::Unchoke),
        Just(Message::Interested),
        Just(Message::Uninterested),
        Just(Message::HaveAll),
        Just(Message::HaveNone),
        any::<u32>().prop_map(Message::Have),
        any::<u16>().prop_map(Message::Port),
        any::<u32>().prop_map(Message::SuggestPiece),
        any::<u32>().prop_map(Message::AllowedFast),
        prop::collection::vec(any::<u8>(), 0..128).prop_map(|b| Message::Bitfield(Bytes::from(b))),
        (any::<u32>(), any::<u32>(), any::<u32>()).prop_map(|(index, begin, length)| {
            Message::Request {
                index,
                begin,
                length,
            }
        }),
        (any::<u32>(), any::<u32>(), any::<u32>()).prop_map(|(index, begin, length)| {
            Message::Cancel {
                index,
                begin,
                length,
            }
        }),
        (any::<u32>(), any::<u32>(), any::<u32>()).prop_map(|(index, begin, length)| {
            Message::RejectRequest {
                index,
                begin,
                length,
            }
        }),
        (
            any::<u32>(),
            any::<u32>(),
            prop::collection::vec(any::<u8>(), 0..512),
        )
            .prop_map(|(index, begin, data)| Message::Piece {
                index,
                begin,
                data: Bytes::from(data),
            }),
        (any::<u8>(), prop::collection::vec(any::<u8>(), 0..256)).prop_map(|(id, payload)| {
            Message::Extension {
                id,
                payload: Bytes::from(payload),
            }
        }),
        (
            prop::array::uniform32(any::<u8>()),
            any::<u32>(),
            any::<u32>(),
            any::<u32>(),
            any::<u32>(),
        )
            .prop_map(|(pieces_root, base_layer, index, count, proof_layers)| {
                Message::HashRequest {
                    pieces_root,
                    base_layer,
                    index,
                    count,
                    proof_layers,
                }
            },),
        (
            prop::array::uniform32(any::<u8>()),
            any::<u32>(),
            any::<u32>(),
            any::<u32>(),
            any::<u32>(),
            prop::collection::vec(any::<u8>(), 0..128),
        )
            .prop_map(
                |(pieces_root, base_layer, index, count, proof_layers, hashes)| {
                    Message::Hashes {
                        pieces_root,
                        base_layer,
                        index,
                        count,
                        proof_layers,
                        hashes: Bytes::from(hashes),
                    }
                },
            ),
    ]
}

fn arb_utp_type() -> impl Strategy<Value = UtpType> {
    prop_oneof![
        Just(UtpType::Data),
        Just(UtpType::Fin),
        Just(UtpType::State),
        Just(UtpType::Reset),
        Just(UtpType::Syn),
    ]
}

proptest! {
    #[test]
    fn peer_handshake_codec_roundtrip(
        reserved in prop::array::uniform8(any::<u8>()),
        info_hash in prop::array::uniform20(any::<u8>()),
        peer_id in prop::array::uniform20(any::<u8>()),
    ) {
        let handshake = Message::Handshake {
            reserved,
            info_hash,
            peer_id,
        };

        let mut codec = PeerCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(handshake.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap();
        prop_assert_eq!(decoded, Some(handshake));
        prop_assert!(buf.is_empty());
    }

    #[test]
    fn peer_message_codec_roundtrip(msg in arb_message()) {
        let handshake = Message::Handshake {
            reserved: [0u8; 8],
            info_hash: [0x11u8; 20],
            peer_id: [0x22u8; 20],
        };

        let mut codec = PeerCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(handshake, &mut buf).unwrap();
        let _ = codec.decode(&mut buf).unwrap();

        // Now codec is ready for standard messages
        codec.encode(msg.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap();
        prop_assert_eq!(decoded, Some(msg));
        prop_assert!(buf.is_empty());
    }

    #[test]
    fn utp_packet_roundtrip(
        ptype in arb_utp_type(),
        connection_id in any::<u16>(),
        seq_nr in any::<u16>(),
        ack_nr in any::<u16>(),
        wnd_size in any::<u32>(),
        payload_bytes in prop::collection::vec(any::<u8>(), 0..512),
        sack_mask in prop::option::of(prop::collection::vec(any::<u8>(), 4..16)),
    ) {
        let mut header = UtpHeader::new(ptype, connection_id, seq_nr, ack_nr, wnd_size);
        header.timestamp_us = 12345;
        header.timestamp_diff_us = 6789;

        let packet = if let Some(mask) = sack_mask {
            UtpPacket::new(header, Bytes::from(payload_bytes)).with_sack(mask)
        } else {
            UtpPacket::new(header, Bytes::from(payload_bytes))
        };

        let encoded = packet.encode();
        let decoded = UtpPacket::decode(encoded).unwrap();

        prop_assert_eq!(decoded.header.ptype, packet.header.ptype);
        prop_assert_eq!(decoded.header.connection_id, packet.header.connection_id);
        prop_assert_eq!(decoded.header.seq_nr, packet.header.seq_nr);
        prop_assert_eq!(decoded.header.ack_nr, packet.header.ack_nr);
        prop_assert_eq!(decoded.header.wnd_size, packet.header.wnd_size);
        prop_assert_eq!(decoded.header.timestamp_us, packet.header.timestamp_us);
        prop_assert_eq!(decoded.header.timestamp_diff_us, packet.header.timestamp_diff_us);
        prop_assert_eq!(decoded.sack_bitmask, packet.sack_bitmask);
        prop_assert_eq!(decoded.payload, packet.payload);
    }
}
