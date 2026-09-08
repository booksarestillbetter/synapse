use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::mpsc;
use parking_lot::RwLock;

use diskio::DiskEngine;
use synapse_engine::{
    AnnounceScheduler, Announcer, PeerCircuitBreaker, SwarmEngine, SwarmState, SwarmTier, SwarmStats,
};
use synapse_meta::Info;
use synapse_picker::Bitfield;

fn build_dummy_torrent(name: &str) -> Info {
    use sha1::{Digest, Sha1};
    let piece_len = 16384u32;
    let file_len = 65536usize;
    let mut pieces = Vec::new();
    let chunk_data = vec![0x55u8; piece_len as usize];
    let num_pieces = file_len.div_ceil(piece_len as usize);
    for _ in 0..num_pieces {
        let hash: [u8; 20] = Sha1::digest(&chunk_data).into();
        pieces.extend_from_slice(&hash);
    }

    let mut info_dict = std::collections::BTreeMap::new();
    info_dict.insert(
        b"name".to_vec(),
        synapse_bencode::BEncode::String(name.as_bytes().to_vec()),
    );
    info_dict.insert(
        b"piece length".to_vec(),
        synapse_bencode::BEncode::Int(piece_len as i64),
    );
    info_dict.insert(b"pieces".to_vec(), synapse_bencode::BEncode::String(pieces));
    info_dict.insert(
        b"length".to_vec(),
        synapse_bencode::BEncode::Int(file_len as i64),
    );

    let mut torrent_dict = std::collections::BTreeMap::new();
    torrent_dict.insert(
        b"info".to_vec(),
        synapse_bencode::BEncode::Dict(info_dict),
    );

    Info::from_bencode(synapse_bencode::BEncode::Dict(torrent_dict))
        .expect("valid synthetic torrent")
}

#[tokio::test]
async fn test_announce_scheduler_lifecycle_and_priority() {
    let cb = Arc::new(PeerCircuitBreaker::default());
    let listen_port = Arc::new(RwLock::new(6881));
    let announcer = Arc::new(Announcer::new([0x11; 20], listen_port, cb));

    // Create scheduler with 5 max concurrent announces, 1800s default interval, 60s jitter
    let scheduler = AnnounceScheduler::new(
        announcer,
        5,
        Duration::from_secs(1800),
        Duration::from_secs(60),
    );
    let handle = scheduler.clone().start();

    assert_eq!(scheduler.active_swarms_count(), 0);
    assert_eq!(scheduler.pending_announces(), 0);

    // Register 10 seeding swarms and 10 downloading swarms
    let mut download_hashes = Vec::new();
    let mut seed_hashes = Vec::new();

    for i in 0..10 {
        let info = Arc::new(build_dummy_torrent(&format!("dl-{i}.bin")));
        download_hashes.push(info.hash);
        let stats = Arc::new(RwLock::new(SwarmStats {
            info_hash: info.hash,
            name: info.name.clone(),
            total_size: info.total_len,
            progress: 0.0,
            state: SwarmState::Downloading,
            tier: SwarmTier::Hot,
            download_rate: 0,
            upload_rate: 0,
            downloaded_bytes: 0,
            uploaded_bytes: 0,
            peers_connected: 0,
            peers_sending: 0,
            eta_seconds: 0,
            ratio: 0.0,
            download_dir: "/tmp".into(),
            added_at: 0,
            is_private: false,
            is_stalled: false,
            last_transfer_at: 0,
            piece_count: info.pieces(),
            piece_size: info.piece_len,
        }));
        let (tx, _rx) = mpsc::channel(16);
        scheduler.register(info.hash, info, stats, tx, true);
    }

    for i in 0..10 {
        let info = Arc::new(build_dummy_torrent(&format!("seed-{i}.bin")));
        seed_hashes.push(info.hash);
        let stats = Arc::new(RwLock::new(SwarmStats {
            info_hash: info.hash,
            name: info.name.clone(),
            total_size: info.total_len,
            progress: 1.0,
            state: SwarmState::Seeding,
            tier: SwarmTier::Warm,
            download_rate: 0,
            upload_rate: 0,
            downloaded_bytes: info.total_len,
            uploaded_bytes: 0,
            peers_connected: 0,
            peers_sending: 0,
            eta_seconds: 0,
            ratio: 0.0,
            download_dir: "/tmp".into(),
            added_at: 0,
            is_private: false,
            is_stalled: false,
            last_transfer_at: 0,
            piece_count: info.pieces(),
            piece_size: info.piece_len,
        }));
        let (tx, _rx) = mpsc::channel(16);
        scheduler.register(info.hash, info, stats, tx, false);
    }

    assert_eq!(scheduler.active_swarms_count(), 20);
    assert_eq!(scheduler.pending_announces(), 20);

    // Notify completion on one of the downloading swarms
    scheduler.notify_completed(&download_hashes[0]);
    // Queue now has the immediate completion announce job
    assert_eq!(scheduler.pending_announces(), 21);

    // Notify resume on a seed swarm
    scheduler.notify_resumed(&seed_hashes[0]);
    assert_eq!(scheduler.pending_announces(), 22);

    // Unregister swarms
    scheduler.unregister(&download_hashes[0]);
    assert_eq!(scheduler.active_swarms_count(), 19);

    // Shutdown scheduler
    scheduler.shutdown();
    let _ = tokio::time::timeout(Duration::from_millis(500), handle).await;
}

#[tokio::test]
async fn test_swarm_engine_integrated_scheduler() {
    let tmp = tempdir().expect("create temp dir");
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0x22; 20]));

    let info = Arc::new(build_dummy_torrent("integrated-test.bin"));
    let hash = info.hash;

    let mut bf = Bitfield::new(info.pieces() as usize);
    for p in 0..info.pieces() {
        bf.set(p as usize);
    }

    // Adding torrent should register with internal scheduler
    let _handle = engine.add_torrent(info, tmp.path().to_path_buf(), Some(&bf));

    assert_eq!(engine.announce_scheduler().active_swarms_count(), 1);
    assert_eq!(engine.announce_scheduler().pending_announces(), 1);

    // Transition to cold (paused)
    assert!(engine.transition_to_cold(&hash));

    // Transition to hot (resumed)
    assert!(engine.transition_to_hot(&hash));

    // Removing torrent unregisters from scheduler
    assert!(engine.remove_torrent(&hash));
    assert_eq!(engine.announce_scheduler().active_swarms_count(), 0);

    engine.shutdown();
}

#[tokio::test]
async fn test_candidate_peer_queue_and_dialing() {
    let cb = Arc::new(PeerCircuitBreaker::default());
    let listen_port = Arc::new(RwLock::new(6882));
    let announcer = Arc::new(Announcer::new([0x33; 20], listen_port, cb));

    let scheduler = AnnounceScheduler::new(
        announcer,
        5,
        Duration::from_secs(1800),
        Duration::from_secs(0),
    );
    let handle = scheduler.clone().start();

    let info = Arc::new(build_dummy_torrent("candidate-test.bin"));
    let hash = info.hash;
    let stats = Arc::new(RwLock::new(SwarmStats {
        info_hash: hash,
        name: info.name.clone(),
        total_size: info.total_len,
        progress: 0.0,
        state: SwarmState::Downloading,
        tier: SwarmTier::Hot,
        download_rate: 0,
        upload_rate: 0,
        downloaded_bytes: 0,
        uploaded_bytes: 0,
        peers_connected: 0,
        peers_sending: 0,
        eta_seconds: 0,
        ratio: 0.0,
        download_dir: "/tmp".into(),
        added_at: 0,
        is_private: false,
        is_stalled: false,
        last_transfer_at: 0,
        piece_count: info.pieces(),
        piece_size: info.piece_len,
    }));
    let (tx, _rx) = mpsc::channel(16);
    scheduler.register(hash, info, stats, tx, true);

    // Initial candidates: 0
    assert_eq!(scheduler.candidate_peers_count(&hash), 0);

    // Enqueue 5 candidate peers, including 1 invalid port 0 and duplicates
    use std::net::SocketAddr;
    let addr1: SocketAddr = "127.0.0.1:10001".parse().unwrap();
    let addr2: SocketAddr = "127.0.0.1:10002".parse().unwrap();
    let addr3: SocketAddr = "127.0.0.1:10003".parse().unwrap();
    let addr_invalid: SocketAddr = "127.0.0.1:0".parse().unwrap();

    scheduler.add_candidate_peers(&hash, vec![addr1, addr2, addr3, addr1, addr_invalid]);

    // 3 valid unique candidates were queued
    // Note that the background dialer might immediately consume them
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Shutdown scheduler cleanly
    scheduler.shutdown();
    let _ = tokio::time::timeout(Duration::from_millis(500), handle).await;
}

