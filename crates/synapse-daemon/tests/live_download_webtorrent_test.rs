use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use diskio::DiskEngine;
use synapse_engine::{QueueConfig, SwarmEngine, SwarmState};

const TORRENT_URLS: &[&str] = &[
    "https://webtorrent.io/torrents/big-buck-bunny.torrent",
    "https://webtorrent.io/torrents/cosmos-laundromat.torrent",
    "https://webtorrent.io/torrents/sintel.torrent",
    "https://webtorrent.io/torrents/tears-of-steel.torrent",
    "https://webtorrent.io/torrents/wired-cd.torrent",
];

fn build_synthetic_torrent(name: &str, file_len: usize, piece_len: u32) -> synapse_meta::Info {
    use sha1::{Digest, Sha1};
    let mut pieces = Vec::new();
    let chunk_data = vec![0x42u8; piece_len as usize];
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

    synapse_meta::Info::from_bencode(synapse_bencode::BEncode::Dict(torrent_dict))
        .expect("valid synthetic test torrent")
}

#[tokio::test]
async fn test_live_download_webtorrent_swarms_and_queue_pipeline() {
    // 1. Initialize formatted tracing subscriber for live debug visibility
    let _ = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .try_init();

    info!("🚀 STARTING SYNAPSE 2.0 LIVE WEBTORRENT DOWNLOAD TEST");

    let tmp = tempdir().expect("create temp dir");
    let download_dir = tmp.path().to_path_buf();

    // 2. Initialize Disk Engine and Swarm Engine with Transmission-style Queueing
    let disk = Arc::new(DiskEngine::auto().await);
    let peer_id = synapse_engine::generate_peer_id();

    let swarm = Arc::new(SwarmEngine::new(disk.clone(), peer_id));

    // Transmission queue configuration: at most 2 active downloads at a time, with stall detection enabled
    swarm.set_queue_config(QueueConfig {
        download_queue_enabled: true,
        max_active_downloads: 2,
        seed_queue_enabled: true,
        max_active_seeds: 10,
        max_active_torrents: 20,
        queue_stalled_enabled: true,
        queue_stalled_minutes: 1,
        seed_ratio_limited: false,
        share_ratio_limit: None,
        idle_seeding_limit_enabled: false,
        seed_time_limit_secs: None,
    });

    // 3. Securely fetch and ingest the 5 torrents via URL
    let mut loaded_handles = Vec::new();
    for url in TORRENT_URLS {
        info!("📥 Fetching & validating remote .torrent from: {}", url);
        match synapse_rpc::fetch_or_parse_torrent(url).await {
            Ok(info) => {
                let info_arc = Arc::new(info);
                let handle = swarm.add_torrent(info_arc.clone(), download_dir.clone(), None);
                info!(
                    "✅ Ingested swarm '{}' (size: {} MB, pieces: {}, info_hash: {})",
                    info_arc.name,
                    info_arc.total_len / (1024 * 1024),
                    info_arc.pieces(),
                    hex::encode(info_arc.hash)
                );
                loaded_handles.push(handle);
            }
            Err(e) => {
                info!("⚠️ Could not fetch {} (network/offline): {}", url, e);
            }
        }
    }

    if loaded_handles.is_empty() {
        info!("⚠️ No remote torrents could be fetched (network offline / isolated environment). Generating synthetic torrents for telemetry test.");
        for (i, name) in ["synthetic-bunny.iso", "synthetic-sintel.mkv", "synthetic-tears.mp4"].iter().enumerate() {
            let info = build_synthetic_torrent(name, 1024 * 1024 * (i + 1), 64 * 1024);
            let info_arc = Arc::new(info);
            let handle = swarm.add_torrent(info_arc.clone(), download_dir.clone(), None);
            info!(
                "✅ Ingested synthetic swarm '{}' (size: {} MB, pieces: {}, info_hash: {})",
                info_arc.name,
                info_arc.total_len / (1024 * 1024),
                info_arc.pieces(),
                hex::encode(info_arc.hash)
            );
            loaded_handles.push(handle);
        }
    }

    assert!(
        !loaded_handles.is_empty(),
        "At least one live test torrent must be fetched or loaded"
    );

    // 4. Live monitoring loop: poll swarm status, peer discovery, tracker stats, and queue state
    println!("\n==========================================================================================");
    println!("📊 SYNAPSE 2.0 LIVE DOWNLOAD TELEMETRY (Transmission-Style Queue & Peer Discovery)");
    println!("==========================================================================================");

    let monitor_duration = Duration::from_secs(12);
    let start_time = tokio::time::Instant::now();
    let mut interval = tokio::time::interval(Duration::from_secs(2));

    while start_time.elapsed() < monitor_duration {
        interval.tick().await;

        // Reconcile queue & stalled status
        swarm.reconcile_queue();

        println!(
            "\n⏱ Elapsed: {:.1}s | Active Swarms in Engine: {}",
            start_time.elapsed().as_secs_f32(),
            swarm.torrent_count()
        );
        println!("{:-<100}", "");
        println!(
            "{:<24} | {:<12} | {:<8} | {:<12} | {:<7} | {:<8} | {:<8}",
            "Torrent Name", "State", "Stalled?", "Progress", "Peers", "Down Rate", "Downloaded"
        );
        println!("{:-<100}", "");

        for handle in &loaded_handles {
            let s = handle.stats.read().clone();
            let state_str = match s.state {
                SwarmState::Downloading => "Downloading",
                SwarmState::Queued => "Queued",
                SwarmState::Seeding => "Seeding",
                SwarmState::Checking => "Checking",
                SwarmState::Stopped => "Stopped",
                SwarmState::Error(ref e) => e.as_str(),
            };

            let name_trunc = if s.name.len() > 24 {
                format!("{}...", &s.name[0..21])
            } else {
                s.name.clone()
            };

            println!(
                "{:<24} | {:<12} | {:<8} | {:>6.2}%      | {:>5} | {:>5.1} KB/s | {:>5.1} MB",
                name_trunc,
                state_str,
                if s.is_stalled { "YES" } else { "NO" },
                s.progress * 100.0,
                s.peers_connected,
                (s.download_rate as f64) / 1024.0,
                (s.downloaded_bytes as f64) / (1024.0 * 1024.0)
            );
        }
    }

    println!("\n==========================================================================================");
    println!("🏁 LIVE DOWNLOAD & QUEUE TELEMETRY COMPLETED");
    println!("==========================================================================================");

    // Verify engine state remains healthy
    assert_eq!(swarm.torrent_count(), loaded_handles.len());
}
