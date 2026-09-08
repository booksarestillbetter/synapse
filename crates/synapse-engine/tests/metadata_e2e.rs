use std::collections::BTreeMap;
use std::sync::Arc;
use tempfile::TempDir;
use bytes::Bytes;
use sha1::{Digest, Sha1};

use diskio::DiskEngine;
use synapse_bencode::BEncode;
use synapse_engine::{MetadataFetcher, SwarmEngine};
use synapse_wire::{ExtensionHandshake, UtMetadataMessage, UT_METADATA_PIECE_LEN};

fn build_large_test_info_dict() -> (Vec<u8>, [u8; 20]) {
    let mut info_dict = BTreeMap::new();
    info_dict.insert(b"name".to_vec(), BEncode::String(b"ubuntu-22.04.iso".to_vec()));
    info_dict.insert(b"piece length".to_vec(), BEncode::Int(262144));
    
    // Create 40KB of fake piece hashes (2000 pieces) so metadata spans multiple 16KB ut_metadata chunks
    let fake_hashes = vec![0x37u8; 40000];
    info_dict.insert(b"pieces".to_vec(), BEncode::String(fake_hashes));
    info_dict.insert(b"length".to_vec(), BEncode::Int(524288000));

    let mut buf = Vec::new();
    BEncode::Dict(info_dict).encode(&mut buf).unwrap();
    let hash: [u8; 20] = Sha1::digest(&buf).into();
    (buf, hash)
}

#[tokio::test]
async fn test_ut_metadata_multi_chunk_exchange_and_magnet_flow() {
    let (raw_metadata, info_hash) = build_large_test_info_dict();
    let total_size = raw_metadata.len() as u32;
    assert!(total_size > UT_METADATA_PIECE_LEN as u32); // Must span multiple chunks

    // 1. Peer A (Leecher) receives ExtensionHandshake from Peer B (Seeder)
    let seeder_handshake = ExtensionHandshake::new().with_ut_metadata(3, Some(total_size));
    let encoded_handshake = seeder_handshake.encode();
    let decoded_handshake = ExtensionHandshake::decode(&encoded_handshake).unwrap();

    let remote_ut_metadata_id = *decoded_handshake.m.get("ut_metadata").unwrap();
    let remote_metadata_size = decoded_handshake.metadata_size.unwrap();
    assert_eq!(remote_ut_metadata_id, 3);
    assert_eq!(remote_metadata_size, total_size);

    // 2. Leecher initializes MetadataFetcher
    let mut fetcher = MetadataFetcher::new(info_hash);
    fetcher.set_metadata_size(remote_metadata_size);
    assert_eq!(fetcher.total_pieces, (total_size as usize).div_ceil(UT_METADATA_PIECE_LEN));

    // 3. Leecher requests each missing piece
    let missing = fetcher.missing_pieces();
    assert_eq!(missing.len(), fetcher.total_pieces);

    let mut resolved_info = None;
    for piece_idx in missing {
        let req_msg = UtMetadataMessage::Request { piece: piece_idx };
        let encoded_req = req_msg.encode();
        let decoded_req = UtMetadataMessage::decode(&encoded_req).unwrap();

        // Seeder handles Request and creates Data message
        if let UtMetadataMessage::Request { piece } = decoded_req {
            let start = piece as usize * UT_METADATA_PIECE_LEN;
            let end = (start + UT_METADATA_PIECE_LEN).min(raw_metadata.len());
            let chunk = Bytes::copy_from_slice(&raw_metadata[start..end]);

            let data_msg = UtMetadataMessage::Data {
                piece,
                total_size,
                data: chunk,
            };
            let encoded_data = data_msg.encode();
            let decoded_data = UtMetadataMessage::decode(&encoded_data).unwrap();

            // Leecher processes Data message
            if let UtMetadataMessage::Data { piece, data, .. } = decoded_data {
                if let Some(info) = fetcher.add_piece(piece, data).unwrap() {
                    resolved_info = Some(info);
                }
            }
        }
    }

    // 4. Verify reconstructed Info
    assert!(fetcher.is_complete());
    let info = resolved_info.expect("Reconstructed Info must be present");
    assert_eq!(info.hash, info_hash);
    assert_eq!(info.name, "ubuntu-22.04.iso");
    assert_eq!(info.piece_len, 262144);
    assert_eq!(info.pieces(), 2000);
    assert_eq!(info.piece_hashes().unwrap().len(), 2000);

    // 5. Test SwarmEngine magnet ingestion
    let dir = TempDir::new().unwrap();
    let disk = Arc::new(DiskEngine::auto().await);
    let peer_id = [0x77u8; 20];
    let swarm = Arc::new(SwarmEngine::new(disk, peer_id));

    let hex_hash = hex::encode(info_hash);
    let magnet_uri = format!("magnet:?xt=urn:btih:{}&dn=ubuntu-22.04.iso", hex_hash);

    let handle = swarm.add_magnet(&magnet_uri, dir.path().to_path_buf()).unwrap();
    assert_eq!(handle.info.hash, info_hash);
    assert_eq!(handle.info.name, "ubuntu-22.04.iso");
    assert_eq!(swarm.torrent_count(), 1);
}
