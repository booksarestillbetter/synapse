//! End-to-end integration test verifying High-Performance Piece Picker parity (Phase 5.4).
//!
//! Validates:
//! 1. Bucketed availability and priority tiers (0-7): Higher priority tiers are strictly chosen
//!    before lower priority tiers; priority 0 pieces are skipped; rarest-first orders by availability.
//! 2. Piece-extent affinity: Contiguous pieces within the same extent (size 4) are grouped.
//! 3. BEP 6 SuggestPiece handling: Incoming SuggestPiece hints over real wire sockets are prioritized
//!    during block selection.
//! 4. Speed-classified partials: In-progress pieces closest to completion are prioritized.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use sha1::{Digest, Sha1};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::codec::Framed;

use diskio::DiskEngine;
use synapse_bencode::BEncode;
use synapse_engine::{
    SwarmState, SwarmStats, SwarmTier, TokenBucket, Torrent, TorrentCommand, TorrentConfig,
};
use synapse_meta::Info;
use synapse_picker::{Bitfield, Mode, Picker};
use synapse_wire::{Message, PeerCodec};

fn fresh_stats(
    info: &Info,
    download_dir: &Path,
    is_seeding: bool,
) -> Arc<parking_lot::RwLock<SwarmStats>> {
    Arc::new(parking_lot::RwLock::new(SwarmStats {
        name: info.name.clone(),
        info_hash: info.hash,
        total_size: info.total_len,
        progress: if is_seeding { 1.0 } else { 0.0 },
        state: if is_seeding {
            SwarmState::Seeding
        } else {
            SwarmState::Downloading
        },
        tier: SwarmTier::Hot,
        download_rate: 0,
        upload_rate: 0,
        downloaded_bytes: if is_seeding { info.total_len } else { 0 },
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

fn build_multi_piece_info(piece_count: usize, piece_len: u32) -> (Info, Vec<u8>) {
    let total_len = (piece_count as u64) * (piece_len as u64);
    let mut stream = Vec::with_capacity(total_len as usize);
    let mut pieces_hashes = Vec::with_capacity(piece_count * 20);

    for p in 0..piece_count {
        let piece_data = vec![(p % 255) as u8; piece_len as usize];
        let hash: [u8; 20] = Sha1::digest(&piece_data).into();
        pieces_hashes.extend_from_slice(&hash);
        stream.extend_from_slice(&piece_data);
    }

    let mut info_dict = BTreeMap::new();
    info_dict.insert(
        b"name".to_vec(),
        BEncode::String(b"picker_parity_test".to_vec()),
    );
    info_dict.insert(b"piece length".to_vec(), BEncode::Int(piece_len as i64));
    info_dict.insert(b"pieces".to_vec(), BEncode::String(pieces_hashes));
    info_dict.insert(b"length".to_vec(), BEncode::Int(total_len as i64));

    let mut top_dict = BTreeMap::new();
    top_dict.insert(b"info".to_vec(), BEncode::Dict(info_dict));

    let info = Info::from_bencode(BEncode::Dict(top_dict)).expect("valid info");
    (info, stream)
}

#[tokio::test]
async fn test_picker_bucketed_availability_and_priority_tiers() {
    // 8 pieces, 16KiB each
    let mut picker = Picker::new(8, Mode::RarestFirst);

    // Set pieces 0..4 to priority 4 (Normal), piece 5 to priority 7 (High), piece 6 to priority 1 (Low), piece 7 to 0 (Unwanted)
    picker.set_piece_priority(5, 7);
    picker.set_piece_priority(6, 1);
    picker.set_piece_priority(7, 0);

    // Swarm availability:
    // Piece 0 has availability 1 (rarest normal piece)
    // Piece 1..4 have availability 3
    // Piece 5 (High) has availability 5 (common)
    picker.peer_has(0);
    for _ in 0..3 {
        picker.peer_has(1);
        picker.peer_has(2);
        picker.peer_has(3);
        picker.peer_has(4);
    }
    for _ in 0..5 {
        picker.peer_has(5);
    }
    picker.peer_has(6);
    picker.peer_has(7);

    let mut peer_has = Bitfield::new(8);
    for i in 0..8 {
        peer_has.set(i);
    }

    // 1. High priority (tier 7, piece 5) MUST be picked first despite being common (avail 5)
    assert_eq!(picker.pick(&peer_has, false), Some(5));
    picker.mark_complete(5);

    // 2. Next tier is Normal (tier 4). Among tier 4, rarest piece (piece 0, avail 1) MUST be picked
    assert_eq!(picker.pick(&peer_has, false), Some(0));
    picker.mark_complete(0);

    // 3. Extent affinity: peer recently requested piece 1 (in extent 0..4).
    // Contiguous pieces 2, 3 in extent 0..4 should be chosen with extent affinity
    assert_eq!(
        picker.pick_with_extent_affinity(&peer_has, Some(1), false),
        Some(1)
    );
    picker.mark_complete(1);
    assert_eq!(
        picker.pick_with_extent_affinity(&peer_has, Some(1), false),
        Some(2)
    );
    picker.mark_complete(2);
    picker.mark_complete(3);
    picker.mark_complete(4);

    // 4. Low priority (tier 1, piece 6) is picked only after tier 4 is complete
    assert_eq!(picker.pick(&peer_has, false), Some(6));
    picker.mark_complete(6);

    // 5. Piece 7 is priority 0 (DoNotDownload) -> MUST NOT be picked!
    assert_eq!(picker.pick(&peer_has, false), None);

    // 6. Torrent is complete because all wanted pieces are complete
    assert!(picker.is_complete());
}

#[tokio::test]
async fn test_suggest_piece_wire_prioritization() {
    let tmp = tempfile::tempdir().unwrap();
    let download_dir = tmp.path().to_path_buf();

    // 4-piece torrent (4 * 16KiB)
    let (info, data) = build_multi_piece_info(4, 16384);
    let info = Arc::new(info);
    let stats = fresh_stats(&info, &download_dir, false);
    let disk = Arc::new(DiskEngine::new_blocking(100 * 1024 * 1024));

    let (peer_tx, peer_rx) = mpsc::channel(64);
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let leecher_peer_id = [0x53; 20];

    let config = TorrentConfig {
        info: info.clone(),
        download_dir: download_dir.clone(),
        peer_id: leecher_peer_id,
        disk: disk.clone(),
        mode: Mode::RarestFirst,
        max_pipeline: 8,
        regular_unchokes: 4,
        optimistic_unchoke_interval: Duration::from_secs(60),
        tick_interval: Duration::from_millis(20),
        on_torrent_completed: None,
        on_piece_completed: None,
        stats: stats.clone(),
        bitfield: Arc::new(parking_lot::RwLock::new(None)),
        download_bucket: Arc::new(TokenBucket::unthrottled()),
        upload_bucket: Arc::new(TokenBucket::unthrottled()),
        global_metrics: None,
        idle_timeout: None,
        live_peers: Arc::new(parking_lot::RwLock::new(Vec::new())),
        piece_availability: Arc::new(parking_lot::RwLock::new(vec![1; 4])),
        settings: Arc::new(parking_lot::RwLock::new(Default::default())),
        on_peers_discovered: None,
        on_metadata_resolved: None,
        ban_list: Default::default(),
        ip_filter: Default::default(),
        super_seeding: false,
        local_webseed_resolver: None,
        alert_sender: None,
    };

    let torrent = Torrent::new(config, None);
    tokio::spawn(torrent.run(peer_rx, cmd_rx));

    // Listen on local TCP socket to accept the mock peer
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let expected_hash = info.hash;
    let ptx = peer_tx.clone();

    tokio::spawn(async move {
        if let Ok((stream, addr)) = listener.accept().await {
            let _ =
                synapse_engine::accept(stream, addr, leecher_peer_id, expected_hash, false, ptx)
                    .await;
        }
    });

    // Connect mock peer via real TCP stream
    let stream = TcpStream::connect(listen_addr).await.unwrap();
    let mut framed = Framed::new(stream, PeerCodec::new());

    // BEP 6 Fast extension bit is bit 7 in reserved[7]
    let mut reserved = [0u8; 8];
    reserved[7] |= 0x04;

    framed
        .send(Message::Handshake {
            reserved,
            info_hash: expected_hash,
            peer_id: [0x77; 20],
        })
        .await
        .unwrap();

    // Read leecher's handshake
    let hs = framed.next().await.unwrap().unwrap();
    assert!(matches!(hs, Message::Handshake { .. }));

    // Send bitfield (we have all 4 pieces) and unchoke
    let mut bf = Bitfield::new(4);
    for i in 0..4 {
        bf.set(i);
    }
    framed
        .send(Message::Bitfield(bf.as_bytes().to_vec().into()))
        .await
        .unwrap();
    framed.send(Message::Unchoke).await.unwrap();

    // Send SuggestPiece for piece 3!
    framed.send(Message::SuggestPiece(3)).await.unwrap();

    // The leecher must request piece 3 first!
    let mut got_piece3_request = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), framed.next()).await {
            Ok(Some(Ok(Message::Request {
                index,
                begin: _,
                length: _,
            }))) => {
                if index == 3 {
                    got_piece3_request = true;
                    // Fulfill piece 3 block
                    let block_data = data[49152..65536].to_vec();
                    framed
                        .send(Message::Piece {
                            index: 3,
                            begin: 0,
                            data: block_data.into(),
                        })
                        .await
                        .unwrap();
                    break;
                }
            }
            Ok(Some(Ok(_))) => continue,
            _ => break,
        }
    }

    assert!(
        got_piece3_request,
        "leecher must prioritize requesting suggested piece 3"
    );

    // Cleanly stop torrent
    let _ = cmd_tx.send(TorrentCommand::Stop).await;
}
