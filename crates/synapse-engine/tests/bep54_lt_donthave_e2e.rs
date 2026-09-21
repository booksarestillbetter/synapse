//! End-to-end proof that BEP 54 `lt_donthave` piece revocation functions on the wire.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use diskio::DiskEngine;
use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::codec::Framed;

use synapse_bencode::BEncode;
use synapse_engine::{SwarmState, SwarmStats, SwarmTier, TokenBucket, Torrent, TorrentConfig};
use synapse_meta::Info;
use synapse_picker::{Bitfield, Mode, RoaringBitfield};
use synapse_wire::{ExtensionHandshake, LtDontHave, Message, PeerCodec};

fn fresh_stats(
    info: &Info,
    download_dir: &std::path::Path,
) -> Arc<parking_lot::RwLock<SwarmStats>> {
    Arc::new(parking_lot::RwLock::new(SwarmStats {
        info_hash: info.hash,
        name: info.name.clone(),
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

fn build_test_info() -> Info {
    let mut info_dict = BTreeMap::new();
    info_dict.insert(b"name".to_vec(), BEncode::String(b"donthave_test".to_vec()));
    info_dict.insert(b"piece length".to_vec(), BEncode::Int(16384));
    info_dict.insert(b"pieces".to_vec(), BEncode::String(vec![0x42; 40])); // 2 pieces
    info_dict.insert(b"length".to_vec(), BEncode::Int(32768));

    let mut top_dict = BTreeMap::new();
    top_dict.insert(b"info".to_vec(), BEncode::Dict(info_dict));

    Info::from_bencode(BEncode::Dict(top_dict)).expect("valid test info")
}

#[tokio::test(flavor = "multi_thread")]
async fn test_bep54_lt_donthave_wire_handling() {
    let info = build_test_info();
    let hash = info.hash;
    let temp_dir = tempfile::tempdir().unwrap();

    let mut have = Bitfield::new(info.pieces() as usize);
    have.set(0);
    have.set(1);

    let stats = fresh_stats(&info, temp_dir.path());
    let (peer_tx, peer_rx) = mpsc::channel(64);
    let (cmd_tx, cmd_rx) = mpsc::channel(16);

    let disk = Arc::new(DiskEngine::auto().await);
    let engine_peer_id = *b"-SY2200-testdonthave";

    let config = TorrentConfig {
        info: Arc::new(info.clone()),
        download_dir: temp_dir.path().to_path_buf(),
        disk: disk.clone(),
        mode: Mode::RarestFirst,
        peer_id: engine_peer_id,
        max_pipeline: 128,
        regular_unchokes: 4,
        optimistic_unchoke_interval: Duration::from_secs(30),
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
    let torrent_handle = tokio::spawn(torrent.run(peer_rx, cmd_rx));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();

    let peer_tx_clone = peer_tx.clone();
    tokio::spawn(async move {
        while let Ok((stream, addr)) = listener.accept().await {
            let tx = peer_tx_clone.clone();
            tokio::spawn(async move {
                let _ = synapse_engine::accept(stream, addr, engine_peer_id, hash, false, tx).await;
            });
        }
    });

    let stream = TcpStream::connect(listen_addr).await.unwrap();
    let mut peer_framed = Framed::new(stream, PeerCodec::new());

    let mut reserved = [0u8; 8];
    reserved[5] |= 0x10; // BEP 10 LTEP bit
    peer_framed
        .send(Message::Handshake {
            reserved,
            info_hash: hash,
            peer_id: *b"-UT3530-extpeer12345",
        })
        .await
        .unwrap();

    let resp_hs = peer_framed.next().await.unwrap().unwrap();
    assert!(matches!(resp_hs, Message::Handshake { .. }));

    // Send extension handshake advertising lt_donthave: 4
    let ext_hs = ExtensionHandshake::new().with_lt_donthave(4);
    peer_framed
        .send(Message::Extension {
            id: 0,
            payload: ext_hs.encode(),
        })
        .await
        .unwrap();

    // Read messages from engine until we see its extension handshake
    let mut engine_lt_donthave_id = None;
    for _ in 0..5 {
        if let Ok(Some(Ok(Message::Extension { id: 0, payload }))) =
            tokio::time::timeout(Duration::from_millis(500), peer_framed.next()).await
        {
            let decoded = ExtensionHandshake::decode(&payload).unwrap();
            engine_lt_donthave_id = decoded.m.get("lt_donthave").copied();
            break;
        }
    }

    assert_eq!(
        engine_lt_donthave_id,
        Some(4),
        "Engine should advertise lt_donthave: 4"
    );

    // Peer advertises Have(0)
    peer_framed.send(Message::Have(0)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Now send lt_donthave(0) to retract piece 0
    let dont_have = LtDontHave::new(0);
    peer_framed
        .send(Message::Extension {
            id: 4,
            payload: dont_have.encode(),
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Shutdown actor
    let _ = cmd_tx.send(synapse_engine::TorrentCommand::Stop).await;
    let _ = torrent_handle.await;
}
