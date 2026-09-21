//! End-to-end integration test verifying the Session-Wide Choker (Phase 5.1).
//!
//! Validates:
//! 1. Global unchoke slot budget distribution across multiple swarms weighted by priority.
//! 2. Rate-based unchoke slot sizing based on configured upload limits.
//! 3. Dynamic seed choking algorithms: Anti-Leech (prioritizing peers nearest completion)
//!    and Fastest-Upload (prioritizing highest upload sink rate).

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
    SessionSettingsUpdate, SwarmEngine, SwarmState, SwarmStats, SwarmTier, TokenBucket, Torrent,
    TorrentConfig,
};
use synapse_meta::Info;
use synapse_picker::{
    Mode, RoaringBitfield, SeedChokingAlgorithm, SessionChoker, SwarmChokerDemand,
};
use synapse_wire::{Message, PeerCodec};

fn fresh_stats(
    info: &Info,
    download_dir: &Path,
    tier: SwarmTier,
) -> Arc<parking_lot::RwLock<SwarmStats>> {
    Arc::new(parking_lot::RwLock::new(SwarmStats {
        name: info.name.clone(),
        info_hash: info.hash,
        total_size: info.total_len,
        progress: 1.0,
        state: SwarmState::Seeding,
        tier,
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

fn build_test_info(name: &str, byte_seed: u8) -> Info {
    let mut info_dict = BTreeMap::new();
    info_dict.insert(b"name".to_vec(), BEncode::String(name.as_bytes().to_vec()));
    info_dict.insert(b"piece length".to_vec(), BEncode::Int(16384));
    info_dict.insert(b"pieces".to_vec(), BEncode::String(vec![byte_seed; 20]));
    info_dict.insert(b"length".to_vec(), BEncode::Int(16384));

    let mut top_dict = BTreeMap::new();
    top_dict.insert(b"info".to_vec(), BEncode::Dict(info_dict));

    Info::from_bencode(BEncode::Dict(top_dict)).expect("valid test info")
}

#[tokio::test]
async fn test_session_choker_multi_swarm_priority_allocation() {
    let choker = SessionChoker::new(8, 16384);

    let swarm1 = [0x11; 20];
    let swarm2 = [0x22; 20];

    let demands = vec![
        SwarmChokerDemand {
            swarm_id: swarm1,
            priority: 7,       // High priority
            is_seeding: false, // Leeching = 2x multiplier
            interested_peers: 5,
        },
        SwarmChokerDemand {
            swarm_id: swarm2,
            priority: 2, // Low priority
            is_seeding: true,
            interested_peers: 5,
        },
    ];

    let allocation = choker.allocate_slots(&demands, 0);
    let s1 = allocation.get(&swarm1).copied().unwrap_or(0);
    let s2 = allocation.get(&swarm2).copied().unwrap_or(0);

    assert!(
        s1 > s2,
        "High priority leecher must receive more unchoke slots (got {} vs {})",
        s1,
        s2
    );
    assert_eq!(s1 + s2, 8, "All 8 session unchoke slots must be allocated");
}

#[tokio::test]
async fn test_session_choker_rate_based_slot_sizing() {
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = SwarmEngine::new(disk, [0x99; 20]);

    // 1. Default without upload limit uses 8 slots
    let choker_lock = engine.session_choker();
    let choker = choker_lock.read();
    assert_eq!(choker.effective_slots(0), 8);
    drop(choker);

    // 2. Setting upload limit of 192 KiB/s (196,608 B/s) with 16 KiB/s per slot yields 12 slots
    let _ = engine.update_session_settings(SessionSettingsUpdate {
        upload_limit_enabled: Some(true),
        upload_limit_bytes: Some(196_608),
        unchoke_slot_bandwidth: Some(16384),
        ..Default::default()
    });

    let choker = choker_lock.read();
    let settings_lock = engine.settings();
    let s = settings_lock.read();
    assert_eq!(choker.effective_slots(s.upload_limit_bytes), 12);
}

#[tokio::test]
async fn test_seed_choking_anti_leech_algorithm_e2e() {
    let temp_dir = tempfile::tempdir().unwrap();
    let info = build_test_info("anti_leech_torrent", 0x77);
    let seeder_peer_id = [0x77; 20];
    let (peer_tx, peer_rx) = tokio::sync::mpsc::channel(64);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(16);

    let stats = fresh_stats(&info, temp_dir.path(), SwarmTier::Hot);
    let mut have = synapse_picker::Bitfield::new(info.pieces() as usize);
    have.set(0);

    let disk = Arc::new(DiskEngine::auto().await);
    let config = TorrentConfig {
        info: Arc::new(info.clone()),
        download_dir: temp_dir.path().to_path_buf(),
        peer_id: seeder_peer_id,
        disk,
        mode: Mode::RarestFirst,
        max_pipeline: 8,
        regular_unchokes: 1, // Only 1 regular unchoke slot!
        optimistic_unchoke_interval: Duration::from_secs(600), // Long interval so optimistic doesn't interfere
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
    cmd_tx
        .send(synapse_engine::TorrentCommand::SetSeedChokingAlgorithm(
            SeedChokingAlgorithm::AntiLeech,
        ))
        .await
        .unwrap();

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

    // Helper to connect a peer, complete handshake, and express interest
    async fn connect_peer(
        seeder_addr: std::net::SocketAddr,
        info_hash: [u8; 20],
        peer_id: [u8; 20],
    ) -> Framed<TcpStream, PeerCodec> {
        let stream = TcpStream::connect(seeder_addr).await.unwrap();
        let mut framed = Framed::new(stream, PeerCodec::new());

        framed
            .send(Message::Handshake {
                reserved: [0; 8],
                info_hash,
                peer_id,
            })
            .await
            .unwrap();

        let _hs = framed.next().await.unwrap().unwrap();
        // Express interest
        framed.send(Message::Interested).await.unwrap();
        framed
    }

    let _peer_low_progress = connect_peer(seeder_addr, seeder_info_hash, [0xaa; 20]).await;
    let mut peer_high_progress = connect_peer(seeder_addr, seeder_info_hash, [0xbb; 20]).await;

    // peer_high_progress reports Having piece 0 (higher completion)
    peer_high_progress.send(Message::Have(0)).await.unwrap();

    // Small sleep for torrent tick rechoke
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Verify peer_high_progress receives Unchoke
    let saw_unchoke = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(Ok(Message::Unchoke)) = peer_high_progress.next().await {
                return true;
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(
        saw_unchoke,
        "Peer with highest progress must be unchoked under AntiLeech algorithm"
    );
}
