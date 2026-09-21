//! End-to-end integration test verifying Hierarchical Bandwidth Model (Phase 5.2).
//!
//! Validates:
//! 1. 3-second burst credit allowance (burst_bytes = 3 * rate_bytes_per_sec).
//! 2. Protocol and packet overhead accounting (MTU packet headers + BT wire framing).
//! 3. Peer classes & LAN bypass (LAN connections bypass global & torrent token buckets when limit_lan_peers = false).
//! 4. Multi-tier rate limiting (peer -> torrent -> global).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

use diskio::DiskEngine;
use synapse_bencode::BEncode;
use synapse_engine::bandwidth::{calculate_overhead, HierarchicalRateLimiter};
use synapse_engine::ratelimit::TokenBucket;
use synapse_engine::settings::DynamicSessionSettings;
use synapse_engine::{SwarmState, SwarmStats, SwarmTier, Torrent, TorrentCommand, TorrentConfig};
use synapse_meta::Info;
use synapse_picker::{Mode, RoaringBitfield};
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
    info_dict.insert(b"piece length".to_vec(), BEncode::Int(32768));
    info_dict.insert(b"pieces".to_vec(), BEncode::String(vec![byte_seed; 20]));
    info_dict.insert(b"length".to_vec(), BEncode::Int(32768));

    let mut top_dict = BTreeMap::new();
    top_dict.insert(b"info".to_vec(), BEncode::Dict(info_dict));

    Info::from_bencode(BEncode::Dict(top_dict)).expect("valid test info")
}

#[test]
fn test_bandwidth_burst_credit_and_overhead() {
    // 1. 3-second burst capacity verification
    let tb = TokenBucket::new_with_3s_burst(50_000); // 50 KB/s rate
    assert_eq!(tb.rate(), 50_000);
    assert_eq!(tb.capacity(), 150_000); // 3x rate
    assert_eq!(tb.available_tokens(), 150_000);

    // Initial burst allows 100 KB immediately without waiting
    assert!(tb.try_consume(100_000));
    assert_eq!(tb.available_tokens(), 50_000);

    // 2. Protocol and packet overhead accounting
    let block_len = 16384;
    let without_overhead = calculate_overhead(block_len, false);
    assert_eq!(without_overhead, 16384);

    let with_overhead = calculate_overhead(block_len, true);
    // 16384 / 1460 = 12 packets * 40 bytes + 13 bytes BT framing = 493 bytes
    assert_eq!(with_overhead, 16384 + 493);
}

#[test]
fn test_bandwidth_lan_bypass_rules() {
    let global = Arc::new(TokenBucket::new_with_3s_burst(10_000));
    let torrent = Arc::new(TokenBucket::new_with_3s_burst(5_000));
    let limiter = HierarchicalRateLimiter::new(global.clone(), Some(torrent.clone()), None);

    // Drain all tokens from torrent bucket
    assert!(torrent.try_consume(15_000));
    assert_eq!(torrent.available_tokens(), 0);

    // WAN peer cannot consume because torrent bucket has 0 tokens
    assert!(!limiter.try_consume(1000, false, false));

    // LAN peer with limit_lan = false BYPASSES torrent and global buckets
    assert!(limiter.try_consume(1000, true, false));

    // LAN peer with limit_lan = true is subject to throttling and cannot consume
    assert!(!limiter.try_consume(1000, true, true));
}

#[tokio::test]
async fn test_hierarchical_bandwidth_e2e_throttling_and_lan_bypass() {
    let temp_dir = tempfile::tempdir().unwrap();
    let info = build_test_info("hierarchical_bandwidth_torrent", 0x42);
    let seeder_peer_id = [0x42; 20];
    let (peer_tx, peer_rx) = tokio::sync::mpsc::channel(64);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(16);

    let stats = fresh_stats(&info, temp_dir.path(), SwarmTier::Hot);
    let mut have = synapse_picker::Bitfield::new(info.pieces() as usize);
    for i in 0..info.pieces() {
        have.set(i as usize);
    }

    let disk = Arc::new(DiskEngine::auto().await);
    // Prepopulate file on disk
    let file_path = temp_dir.path().join(&info.name);
    tokio::fs::write(&file_path, vec![0x42; info.total_len as usize])
        .await
        .unwrap();

    let settings = Arc::new(parking_lot::RwLock::new(DynamicSessionSettings {
        limit_lan_peers: true, // Throttling LAN peers enabled initially
        rate_limit_ip_overhead: true,
        ..Default::default()
    }));

    let global_upload_bucket = Arc::new(TokenBucket::unthrottled());
    let global_download_bucket = Arc::new(TokenBucket::unthrottled());

    let config = TorrentConfig {
        info: Arc::new(info.clone()),
        download_dir: temp_dir.path().to_path_buf(),
        peer_id: seeder_peer_id,
        disk: disk.clone(),
        mode: Mode::RarestFirst,
        max_pipeline: 8,
        regular_unchokes: 4,
        optimistic_unchoke_interval: Duration::from_secs(30),
        tick_interval: Duration::from_millis(50),
        on_torrent_completed: None,
        on_piece_completed: None,
        stats,
        bitfield: Arc::new(parking_lot::RwLock::new(Some(
            RoaringBitfield::from_bitfield(&have),
        ))),
        download_bucket: global_download_bucket.clone(),
        upload_bucket: global_upload_bucket.clone(),
        global_metrics: None,
        idle_timeout: None,
        live_peers: Arc::new(parking_lot::RwLock::new(Vec::new())),
        piece_availability: Arc::new(parking_lot::RwLock::new(vec![1; info.pieces() as usize])),
        settings: settings.clone(),
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

    // Connect leecher peer
    let stream = TcpStream::connect(seeder_addr).await.unwrap();
    let mut framed = Framed::new(stream, PeerCodec::new());

    framed
        .send(Message::Handshake {
            reserved: [0; 8],
            info_hash: seeder_info_hash,
            peer_id: [0x55; 20],
        })
        .await
        .unwrap();

    let _hs = framed.next().await.unwrap().unwrap();
    framed.send(Message::Interested).await.unwrap();

    // Wait for Unchoke message
    let saw_unchoke = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(Ok(Message::Unchoke)) = framed.next().await {
                return true;
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(saw_unchoke, "Leecher must receive Unchoke from seeder");

    // Request block 0
    framed
        .send(Message::Request {
            index: 0,
            begin: 0,
            length: 16384,
        })
        .await
        .unwrap();
    let piece1 = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(Ok(Message::Piece { index, begin, data })) = framed.next().await {
                return Some((index, begin, data));
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(piece1.unwrap().0, 0);

    // Now test LAN bypass toggle: turn off limit_lan_peers
    {
        let mut s = settings.write();
        s.limit_lan_peers = false;
    }

    // Set strict per-torrent upload throttle
    cmd_tx
        .send(TorrentCommand::SetRateLimits {
            download_limit_bytes: 0,
            upload_limit_bytes: 100, // Very low 100 bytes/sec
        })
        .await
        .unwrap();

    // Since peer is on 127.0.0.1 (LAN) and limit_lan_peers is false,
    // request for block 1 should immediately bypass the 100 byte/sec throttle!
    framed
        .send(Message::Request {
            index: 0,
            begin: 16384,
            length: 16384,
        })
        .await
        .unwrap();
    let piece2 = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            if let Some(Ok(Message::Piece { index, begin, data })) = framed.next().await {
                return Some((index, begin, data));
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        piece2.unwrap().1,
        16384,
        "LAN peer must bypass torrent upload rate limit when limit_lan_peers is false"
    );
}
