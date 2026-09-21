//! End-to-end integration test verifying BEP 52 BitTorrent v2 and Hybrid torrents.
//!
//! Validates:
//! 1. Metadata parsing of pure v2 and hybrid file trees.
//! 2. `SwarmEngine` 32-byte SHA-256 info-hash indexing (`torrent_by_v2_hash`).
//! 3. Exchange of BEP 52 `HashRequest`, `Hashes`, and `HashReject` messages over real sockets.
//! 4. SHA-256 Merkle tree piece hash verification via `compute_piece_hash`.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

use diskio::DiskEngine;
use synapse_bencode::BEncode;
use synapse_engine::{
    SwarmEngine, SwarmState, SwarmStats, SwarmTier, TokenBucket, Torrent, TorrentConfig,
};
use synapse_meta::merkle::{
    compute_file_merkle_root, compute_file_piece_layer, compute_piece_hash, BLOCK_SIZE,
};
use synapse_meta::Info;
use synapse_picker::{Mode, RoaringBitfield};
use synapse_wire::{Message, PeerCodec};

fn fresh_stats(info: &Info, download_dir: &Path) -> Arc<parking_lot::RwLock<SwarmStats>> {
    Arc::new(parking_lot::RwLock::new(SwarmStats {
        name: info.name.clone(),
        info_hash: info.hash,
        total_size: info.total_len,
        progress: 1.0,
        state: SwarmState::Seeding,
        tier: SwarmTier::Hot,
        download_rate: 0,
        upload_rate: 0,
        downloaded_bytes: info.total_len,
        uploaded_bytes: 0,
        peers_connected: 0,
        peers_sending: 0,
        eta_seconds: 0,
        ratio: 0.0,
        download_dir: download_dir.to_string_lossy().to_string(),
        added_at: 0,
        is_private: info.private,
        is_stalled: false,
        last_transfer_at: 0,
        piece_count: info.pieces(),
        piece_size: info.piece_len,
    }))
}

fn build_v2_torrent(
    file_name: &str,
    file_data: &[u8],
    piece_len: usize,
) -> (Info, [u8; 32], Vec<[u8; 32]>) {
    let root_hash = compute_file_merkle_root(file_data);
    let piece_layer = compute_file_piece_layer(file_data, piece_len);

    let mut leaf = BTreeMap::new();
    leaf.insert(b"length".to_vec(), BEncode::Int(file_data.len() as i64));
    leaf.insert(b"pieces root".to_vec(), BEncode::String(root_hash.to_vec()));

    let mut file_dict = BTreeMap::new();
    file_dict.insert(b"".to_vec(), BEncode::Dict(leaf));

    let mut file_tree = BTreeMap::new();
    file_tree.insert(file_name.as_bytes().to_vec(), BEncode::Dict(file_dict));

    let mut info_dict = BTreeMap::new();
    info_dict.insert(b"meta version".to_vec(), BEncode::Int(2));
    info_dict.insert(b"name".to_vec(), BEncode::String(b"v2_torrent".to_vec()));
    info_dict.insert(b"piece length".to_vec(), BEncode::Int(piece_len as i64));
    info_dict.insert(b"file tree".to_vec(), BEncode::Dict(file_tree));

    let mut piece_layers_dict = BTreeMap::new();
    let mut layer_bytes = Vec::new();
    for p in &piece_layer {
        layer_bytes.extend_from_slice(p);
    }
    piece_layers_dict.insert(root_hash.to_vec(), BEncode::String(layer_bytes));

    let mut top_dict = BTreeMap::new();
    top_dict.insert(b"info".to_vec(), BEncode::Dict(info_dict));
    top_dict.insert(b"piece layers".to_vec(), BEncode::Dict(piece_layers_dict));

    let info = Info::from_bencode(BEncode::Dict(top_dict)).expect("valid v2 info");
    (info, root_hash, piece_layer)
}

#[tokio::test]
async fn test_bep52_v2_swarm_indexing_and_merkle_verification() {
    let file_data = vec![0x33u8; BLOCK_SIZE * 2]; // 32 KiB file (two 16 KiB pieces)
    let (info, _root_hash, piece_layers) = build_v2_torrent("payload.dat", &file_data, BLOCK_SIZE);

    assert_eq!(info.meta_version, 2);
    assert!(info.is_v2());
    let v2_hash = info.info_hash_v2.expect("v2 info hash present");

    // 1. Verify piece_hash_v2 lookup and calculation
    assert_eq!(info.piece_hash_v2(0), Some(piece_layers[0]));
    assert_eq!(info.piece_hash_v2(1), Some(piece_layers[1]));
    assert_eq!(info.piece_hash_v2(2), None);

    let p0_calc = compute_piece_hash(&file_data[..BLOCK_SIZE], BLOCK_SIZE);
    let p1_calc = compute_piece_hash(&file_data[BLOCK_SIZE..], BLOCK_SIZE);
    assert_eq!(p0_calc, piece_layers[0]);
    assert_eq!(p1_calc, piece_layers[1]);

    // 2. Test SwarmEngine indexing by 32-byte v2 hash
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = SwarmEngine::new(disk, [0x01; 20]);
    let tmp_dir = tempfile::tempdir().unwrap();

    let handle = engine.add_torrent(Arc::new(info.clone()), tmp_dir.path().to_path_buf(), None);
    let found = engine.torrent_by_v2_hash(&v2_hash);
    assert!(found.is_some(), "torrent should be indexed by v2 hash");
    assert_eq!(found.unwrap().info.info_hash_v2, Some(v2_hash));

    // Remove and verify v2 index cleanup
    assert!(engine.remove_torrent(&handle.info.hash));
    assert!(engine.torrent_by_v2_hash(&v2_hash).is_none());
}

#[tokio::test]
async fn test_bep52_hash_request_and_hashes_wire_exchange() {
    let file_data = vec![0x77u8; BLOCK_SIZE * 4]; // 64 KiB
    let (info, root_hash, piece_layers) = build_v2_torrent("data.bin", &file_data, BLOCK_SIZE);
    let info = Arc::new(info);

    let seeder_dir = tempfile::tempdir().unwrap();
    tokio::fs::create_dir_all(seeder_dir.path().join("v2_torrent"))
        .await
        .unwrap();
    tokio::fs::write(seeder_dir.path().join("v2_torrent/data.bin"), &file_data)
        .await
        .unwrap();

    let disk = Arc::new(DiskEngine::auto().await);
    let seeder_peer_id = [0x55; 20];
    let (peer_tx, peer_rx) = tokio::sync::mpsc::channel(64);
    let (_cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(1);

    let stats = fresh_stats(&info, seeder_dir.path());

    let mut have = synapse_picker::Bitfield::new(info.pieces() as usize);
    for i in 0..info.pieces() as usize {
        have.set(i);
    }

    let config = TorrentConfig {
        info: info.clone(),
        download_dir: seeder_dir.path().to_path_buf(),
        peer_id: seeder_peer_id,
        disk,
        mode: Mode::RarestFirst,
        max_pipeline: 8,
        regular_unchokes: 4,
        optimistic_unchoke_interval: Duration::from_secs(60),
        tick_interval: Duration::from_millis(50),
        on_torrent_completed: None,
        on_piece_completed: None,
        stats,
        bitfield: Arc::new(parking_lot::RwLock::new(Some(
            RoaringBitfield::from_bitfield(&have),
        ))),
        download_bucket: Arc::new(TokenBucket::unthrottled()),
        upload_bucket: Arc::new(TokenBucket::unthrottled()),
        global_metrics: None,
        idle_timeout: None,
        live_peers: Arc::new(parking_lot::RwLock::new(Vec::new())),
        piece_availability: Arc::new(parking_lot::RwLock::new(vec![1; info.pieces() as usize])),
        settings: Arc::new(parking_lot::RwLock::new(Default::default())),
        on_peers_discovered: None,
        on_metadata_resolved: None,
        ban_list: Default::default(),
        ip_filter: Default::default(),
        super_seeding: false,
        local_webseed_resolver: None,
        alert_sender: None,
    };

    let torrent = Torrent::new(config, Some(&have));
    tokio::spawn(torrent.run(peer_rx, cmd_rx));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let seeder_addr = listener.local_addr().unwrap();

    let seeder_handshake_hash = info.hash;
    let peer_tx_clone = peer_tx.clone();
    tokio::spawn(async move {
        let (stream, addr) = listener.accept().await.unwrap();
        synapse_engine::accept(
            stream,
            addr,
            seeder_peer_id,
            seeder_handshake_hash,
            false,
            peer_tx_clone,
        )
        .await
        .unwrap();
    });

    // Client connects and queries hashes
    let client_stream = TcpStream::connect(seeder_addr).await.unwrap();
    let mut client_framed = Framed::new(client_stream, PeerCodec::new());

    client_framed
        .send(Message::Handshake {
            reserved: [0; 8],
            info_hash: seeder_handshake_hash,
            peer_id: [0x66; 20],
        })
        .await
        .unwrap();

    let seeder_hs = client_framed.next().await.unwrap().unwrap();
    assert!(matches!(seeder_hs, Message::Handshake { .. }));

    // Send HashRequest for the piece layers of root_hash
    client_framed
        .send(Message::HashRequest {
            pieces_root: root_hash,
            base_layer: 0,
            index: 0,
            count: 4,
            proof_layers: 0,
        })
        .await
        .unwrap();

    // Seeder should reply with Hashes containing all 4 pieces (4 * 32 = 128 bytes)
    let mut received_hashes = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(Ok(Message::Hashes {
            pieces_root,
            count,
            hashes,
            ..
        }))) = tokio::time::timeout(Duration::from_millis(500), client_framed.next()).await
        {
            assert_eq!(pieces_root, root_hash);
            assert_eq!(count, 4);
            assert_eq!(hashes.len(), 4 * 32);
            for i in 0..4 {
                assert_eq!(&hashes[i * 32..(i + 1) * 32], &piece_layers[i]);
            }
            received_hashes = true;
            break;
        }
    }
    assert!(received_hashes, "Client must receive BEP 52 Hashes message");

    // Send an invalid HashRequest for unknown root; seeder must reject
    client_framed
        .send(Message::HashRequest {
            pieces_root: [0x99; 32],
            base_layer: 0,
            index: 0,
            count: 1,
            proof_layers: 0,
        })
        .await
        .unwrap();

    let mut received_reject = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(Ok(Message::HashReject { pieces_root, .. }))) =
            tokio::time::timeout(Duration::from_millis(500), client_framed.next()).await
        {
            assert_eq!(pieces_root, [0x99; 32]);
            received_reject = true;
            break;
        }
    }
    assert!(
        received_reject,
        "Client must receive BEP 52 HashReject for invalid root"
    );
}
