//! End-to-end tests for Granular Telemetry counters and Structured Alert Stream (Phase 5.6).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

use diskio::DiskEngine;
use synapse_engine::alert::Alert;
use synapse_engine::{
    GlobalEngineMetrics, SwarmEngine, SwarmState, SwarmStats, SwarmTier, Torrent, TorrentConfig,
};
use synapse_meta::Info;

fn fresh_stats(
    info: &Info,
    download_dir: &std::path::Path,
) -> Arc<parking_lot::RwLock<SwarmStats>> {
    Arc::new(parking_lot::RwLock::new(SwarmStats {
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
        download_dir: download_dir.to_string_lossy().to_string(),
        added_at: 0,
        is_private: info.private,
        is_stalled: false,
        last_transfer_at: 0,
        piece_count: info.pieces(),
        piece_size: info.piece_len,
    }))
}

fn build_dummy_torrent(name: &str, file_len: usize, piece_len: u32) -> (Info, Vec<u8>) {
    use sha1::{Digest, Sha1};
    let mut pieces = Vec::new();
    let chunk_data = vec![0x33u8; piece_len as usize];
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
    torrent_dict.insert(b"info".to_vec(), synapse_bencode::BEncode::Dict(info_dict));

    let info = Info::from_bencode(synapse_bencode::BEncode::Dict(torrent_dict))
        .expect("valid synthetic torrent");
    (info, chunk_data)
}

#[tokio::test]
async fn test_alert_stream_subscription_and_broadcast() {
    let tmp = tempdir().expect("create temp dir");
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0x42; 20]));

    let mut alerts = engine.subscribe_alerts();

    let (info, _chunk) = build_dummy_torrent("alert_test.bin", 32768, 16384);
    let info_hash = info.hash;

    // 1. Adding a torrent triggers Alert::TorrentAdded
    let _handle =
        engine.add_torrent_with_resume(Arc::new(info), tmp.path().to_path_buf(), None, None);

    let alert = tokio::time::timeout(Duration::from_secs(2), alerts.recv())
        .await
        .expect("timeout waiting for TorrentAdded alert")
        .expect("alert received");

    match alert {
        Alert::TorrentAdded { info_hash: h } => assert_eq!(h, info_hash),
        other => panic!("expected Alert::TorrentAdded, got {:?}", other),
    }

    // 2. Broadcast and verify each remaining alert variant
    let peer_addr: SocketAddr = "192.168.1.100:6881".parse().unwrap();

    engine.post_alert(Alert::PeerConnected {
        info_hash,
        addr: peer_addr,
    });
    match alerts.recv().await.unwrap() {
        Alert::PeerConnected { info_hash: h, addr } => {
            assert_eq!(h, info_hash);
            assert_eq!(addr, peer_addr);
        }
        other => panic!("unexpected alert: {:?}", other),
    }

    engine.post_alert(Alert::PeerDisconnected {
        info_hash,
        addr: peer_addr,
    });
    match alerts.recv().await.unwrap() {
        Alert::PeerDisconnected { info_hash: h, addr } => {
            assert_eq!(h, info_hash);
            assert_eq!(addr, peer_addr);
        }
        other => panic!("unexpected alert: {:?}", other),
    }

    engine.post_alert(Alert::PeerBanned {
        info_hash,
        ip: peer_addr.ip(),
    });
    match alerts.recv().await.unwrap() {
        Alert::PeerBanned { info_hash: h, ip } => {
            assert_eq!(h, info_hash);
            assert_eq!(ip, peer_addr.ip());
        }
        other => panic!("unexpected alert: {:?}", other),
    }

    engine.post_alert(Alert::PieceFinished {
        info_hash,
        piece_index: 0,
    });
    match alerts.recv().await.unwrap() {
        Alert::PieceFinished {
            info_hash: h,
            piece_index,
        } => {
            assert_eq!(h, info_hash);
            assert_eq!(piece_index, 0);
        }
        other => panic!("unexpected alert: {:?}", other),
    }

    engine.post_alert(Alert::HashFailed {
        info_hash,
        piece_index: 1,
    });
    match alerts.recv().await.unwrap() {
        Alert::HashFailed {
            info_hash: h,
            piece_index,
        } => {
            assert_eq!(h, info_hash);
            assert_eq!(piece_index, 1);
        }
        other => panic!("unexpected alert: {:?}", other),
    }

    engine.post_alert(Alert::TorrentFinished { info_hash });
    match alerts.recv().await.unwrap() {
        Alert::TorrentFinished { info_hash: h } => assert_eq!(h, info_hash),
        other => panic!("unexpected alert: {:?}", other),
    }

    engine.post_alert(Alert::TorrentError {
        info_hash,
        error: "disk full".to_string(),
    });
    match alerts.recv().await.unwrap() {
        Alert::TorrentError {
            info_hash: h,
            error,
        } => {
            assert_eq!(h, info_hash);
            assert_eq!(error, "disk full");
        }
        other => panic!("unexpected alert: {:?}", other),
    }

    engine.post_alert(Alert::StateChanged {
        info_hash,
        old_state: SwarmState::Downloading,
        new_state: SwarmState::Seeding,
    });
    match alerts.recv().await.unwrap() {
        Alert::StateChanged {
            info_hash: h,
            old_state,
            new_state,
        } => {
            assert_eq!(h, info_hash);
            assert_eq!(old_state, SwarmState::Downloading);
            assert_eq!(new_state, SwarmState::Seeding);
        }
        other => panic!("unexpected alert: {:?}", other),
    }

    engine.post_alert(Alert::TrackerAnnounce {
        info_hash,
        tracker_url: "http://tracker.example.com/announce".to_string(),
        event: "started".to_string(),
    });
    match alerts.recv().await.unwrap() {
        Alert::TrackerAnnounce {
            info_hash: h,
            tracker_url,
            event,
        } => {
            assert_eq!(h, info_hash);
            assert_eq!(tracker_url, "http://tracker.example.com/announce");
            assert_eq!(event, "started");
        }
        other => panic!("unexpected alert: {:?}", other),
    }
}

#[tokio::test]
async fn test_granular_telemetry_counters() {
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0x42; 20]));

    let m = engine.global_metrics();
    assert_eq!(m.chokes_total, 0);
    assert_eq!(m.unchokes_total, 0);
    assert_eq!(m.piece_requests_total, 0);
    assert_eq!(m.piece_rejects_total, 0);
    assert_eq!(m.hash_fails_total, 0);
    assert_eq!(m.peers_banned, 0);
    assert_eq!(m.utp_packet_loss_total, 0);
    assert_eq!(m.dht_dos_blocks_total, 0);

    assert_eq!(engine.disk_write_queue_bytes(), 0);
    assert_eq!(engine.utp_packet_loss_total(), 0);
    assert_eq!(engine.dht_dos_blocks_total(), 0);
}

#[tokio::test]
async fn test_torrent_runtime_alert_emission_and_metrics() {
    let tmp = tempdir().expect("create temp dir");
    let disk = Arc::new(DiskEngine::auto().await);
    let (info, _chunk) = build_dummy_torrent("torrent_test.bin", 32768, 16384);
    let info = Arc::new(info);
    let info_hash = info.hash;

    let global_metrics = Arc::new(GlobalEngineMetrics::default());
    let (alert_tx, mut alert_rx) = tokio::sync::broadcast::channel::<Alert>(64);

    let stats = fresh_stats(&info, tmp.path());

    let config = TorrentConfig {
        info: info.clone(),
        download_dir: tmp.path().to_path_buf(),
        peer_id: [0x11; 20],
        disk: disk.clone(),
        mode: synapse_picker::Mode::RarestFirst,
        max_pipeline: 8,
        regular_unchokes: 4,
        optimistic_unchoke_interval: Duration::from_secs(60),
        tick_interval: Duration::from_millis(50),
        on_torrent_completed: None,
        on_piece_completed: None,
        stats,
        bitfield: Arc::new(parking_lot::RwLock::new(None)),
        download_bucket: Arc::new(synapse_engine::TokenBucket::unthrottled()),
        upload_bucket: Arc::new(synapse_engine::TokenBucket::unthrottled()),
        global_metrics: Some(global_metrics.clone()),
        idle_timeout: None,
        live_peers: Arc::new(parking_lot::RwLock::new(Vec::new())),
        piece_availability: Arc::new(parking_lot::RwLock::new(vec![0; info.pieces() as usize])),
        settings: Arc::new(parking_lot::RwLock::new(Default::default())),
        on_peers_discovered: None,
        on_metadata_resolved: None,
        ban_list: Default::default(),
        ip_filter: Default::default(),
        super_seeding: false,
        local_webseed_resolver: None,
        alert_sender: Some(alert_tx),
    };

    let mut torrent = Torrent::new(config, None);

    let peer_addr: SocketAddr = "127.0.0.1:49999".parse().unwrap();

    // Test ban_address: should increment global_metrics.peers_banned and emit PeerBanned alert
    torrent.ban_address(peer_addr.ip());
    assert_eq!(
        global_metrics
            .peers_banned
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    let alert = alert_rx.recv().await.expect("receive PeerBanned alert");
    match alert {
        Alert::PeerBanned { info_hash: h, ip } => {
            assert_eq!(h, info_hash);
            assert_eq!(ip, peer_addr.ip());
        }
        other => panic!("unexpected alert: {:?}", other),
    }

    // Verify snapshot reflects the banned peer
    let snap = global_metrics.snapshot();
    assert_eq!(snap.peers_banned, 1);
}
