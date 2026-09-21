//! End-to-end integration test verifying BEP 16 Super-Seeding mode in the engine.
//!
//! Validates:
//! 1. When `super_seeding: true` is configured on a complete seeder, it does NOT broadcast `HaveAll`.
//! 2. It offers individual `Have(piece_index)` selectively to connected peers to maximize swarm distribution.
//! 3. As peers acknowledge possessing offered pieces via `Have(piece_index)`, the seeder assigns subsequent pieces.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

use diskio::DiskEngine;
use synapse_bencode::BEncode;
use synapse_engine::{SwarmState, SwarmStats, SwarmTier, TokenBucket, Torrent, TorrentConfig};
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

fn build_multi_piece_info(piece_count: usize) -> Info {
    let mut pieces = Vec::with_capacity(piece_count * 20);
    for i in 0..piece_count {
        pieces.extend_from_slice(&[i as u8; 20]);
    }
    let piece_len = 16384;
    let total_len = (piece_count * piece_len) as i64;

    let mut info_dict = BTreeMap::new();
    info_dict.insert(
        b"name".to_vec(),
        BEncode::String(b"superseed_torrent".to_vec()),
    );
    info_dict.insert(b"piece length".to_vec(), BEncode::Int(piece_len as i64));
    info_dict.insert(b"pieces".to_vec(), BEncode::String(pieces));
    info_dict.insert(b"length".to_vec(), BEncode::Int(total_len));

    let mut top_dict = BTreeMap::new();
    top_dict.insert(b"info".to_vec(), BEncode::Dict(info_dict));

    Info::from_bencode(BEncode::Dict(top_dict)).expect("valid multi-piece info")
}

#[tokio::test]
async fn test_superseeding_selective_piece_advertisement() {
    let temp_dir = tempfile::tempdir().unwrap();
    let num_pieces = 4;
    let info = build_multi_piece_info(num_pieces);
    let seeder_peer_id = [0x55; 20];
    let (peer_tx, peer_rx) = tokio::sync::mpsc::channel(64);
    let (_cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(1);

    let stats = fresh_stats(&info, temp_dir.path());
    let mut have = synapse_picker::Bitfield::new(num_pieces);
    for i in 0..num_pieces {
        have.set(i);
    }

    let disk = Arc::new(DiskEngine::auto().await);
    let config = TorrentConfig {
        info: Arc::new(info.clone()),
        download_dir: temp_dir.path().to_path_buf(),
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
        piece_availability: Arc::new(parking_lot::RwLock::new(vec![1; num_pieces])),
        settings: Arc::new(parking_lot::RwLock::new(Default::default())),
        on_peers_discovered: None,
        on_metadata_resolved: None,
        ban_list: Default::default(),
        ip_filter: Default::default(),
        super_seeding: true, // Super-seeding enabled!
        local_webseed_resolver: None,
        alert_sender: None,
    };

    let torrent = Torrent::new(config, Some(&have));
    tokio::spawn(torrent.run(peer_rx, cmd_rx));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let seeder_addr = listener.local_addr().unwrap();
    let seeder_info_hash = info.hash;

    let peer_tx_clone = peer_tx.clone();
    tokio::spawn(async move {
        while let Ok((stream, addr)) = listener.accept().await {
            let tx = peer_tx_clone.clone();
            tokio::spawn(async move {
                let _ = synapse_engine::accept(
                    stream,
                    addr,
                    seeder_peer_id,
                    seeder_info_hash,
                    false,
                    tx,
                )
                .await;
            });
        }
    });

    // 1. Peer A connects
    let stream_a = TcpStream::connect(seeder_addr).await.unwrap();
    let mut peer_a = Framed::new(stream_a, PeerCodec::new());

    let mut reserved = [0u8; 8];
    reserved[7] |= 0x01; // Fast extension support

    peer_a
        .send(Message::Handshake {
            reserved,
            info_hash: seeder_info_hash,
            peer_id: [0xaa; 20],
        })
        .await
        .unwrap();

    let hs = peer_a.next().await.unwrap().unwrap();
    assert!(matches!(hs, Message::Handshake { .. }));

    // Read initial messages from super-seeder: Expect Extension HS and Have(p), but NEVER HaveAll!
    let mut initial_pieces_a = Vec::new();
    let mut saw_have_all = false;

    // Timeout loop for initial burst
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_millis(300) {
        if let Ok(Some(Ok(msg))) =
            tokio::time::timeout(Duration::from_millis(50), peer_a.next()).await
        {
            match msg {
                Message::HaveAll => {
                    saw_have_all = true;
                }
                Message::Have(piece) => {
                    initial_pieces_a.push(piece);
                }
                _ => {}
            }
        }
    }

    assert!(!saw_have_all, "Super-seeder must NOT send HaveAll");
    assert_eq!(
        initial_pieces_a.len(),
        1,
        "Super-seeder should offer exactly 1 piece initially"
    );
    let piece_assigned_to_a = initial_pieces_a[0];

    // 2. Peer B connects
    let stream_b = TcpStream::connect(seeder_addr).await.unwrap();
    let mut peer_b = Framed::new(stream_b, PeerCodec::new());

    peer_b
        .send(Message::Handshake {
            reserved,
            info_hash: seeder_info_hash,
            peer_id: [0xbb; 20],
        })
        .await
        .unwrap();

    let _hs_b = peer_b.next().await.unwrap().unwrap();

    let mut initial_pieces_b = Vec::new();
    let start_b = std::time::Instant::now();
    while start_b.elapsed() < Duration::from_millis(300) {
        if let Ok(Some(Ok(Message::Have(piece)))) =
            tokio::time::timeout(Duration::from_millis(50), peer_b.next()).await
        {
            initial_pieces_b.push(piece);
        }
    }

    assert_eq!(
        initial_pieces_b.len(),
        1,
        "Super-seeder should offer exactly 1 piece to Peer B"
    );
    let piece_assigned_to_b = initial_pieces_b[0];
    assert_ne!(
        piece_assigned_to_a, piece_assigned_to_b,
        "Super-seeder should offer different pieces to Peer A and Peer B"
    );

    // 3. Peer B sends Have(piece_assigned_to_a) (signaling that Peer A passed its piece to Peer B)
    peer_b
        .send(Message::Have(piece_assigned_to_a))
        .await
        .unwrap();

    // Now Peer A should receive its NEXT piece offer!
    let next_piece_for_a = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(Ok(Message::Have(p))) = peer_a.next().await {
                return p;
            }
        }
    })
    .await
    .expect("Peer A should receive next piece after confirmation");

    assert_ne!(next_piece_for_a, piece_assigned_to_a);
}
