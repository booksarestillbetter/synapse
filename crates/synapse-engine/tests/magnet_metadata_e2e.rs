//! End-to-end proof that BEP 9 `ut_metadata` exchange actually works: a "leecher"
//! `Torrent` actor constructed the same way `SwarmEngine::add_magnet` builds one --
//! from `Info::from_magnet`, with no files/pieces known yet -- connects over a real
//! TCP loopback socket to a normal "seeder" actor that already has full metadata, and
//! must come away with a byte-for-byte-correct, hash-verified `Info` delivered through
//! `on_metadata_resolved`.

use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest, Sha1};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use diskio::DiskEngine;
use synapse_engine::{PeerEvent, SwarmState, SwarmStats, SwarmTier, TokenBucket, Torrent, TorrentConfig};
use synapse_meta::Info;
use synapse_picker::{Bitfield, Mode, RoaringBitfield};

fn fresh_stats(info: &Info, download_dir: &std::path::Path) -> Arc<parking_lot::RwLock<SwarmStats>> {
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

fn build_test_info(file_data: &[u8], piece_len: u32, name: &str) -> Info {
    let mut pieces = Vec::new();
    for chunk in file_data.chunks(piece_len as usize) {
        let hash: [u8; 20] = Sha1::digest(chunk).into();
        pieces.extend_from_slice(&hash);
    }

    let mut info_dict = std::collections::BTreeMap::new();
    info_dict.insert(b"name".to_vec(), synapse_bencode::BEncode::String(name.as_bytes().to_vec()));
    info_dict.insert(b"piece length".to_vec(), synapse_bencode::BEncode::Int(piece_len as i64));
    info_dict.insert(b"pieces".to_vec(), synapse_bencode::BEncode::String(pieces));
    info_dict.insert(b"length".to_vec(), synapse_bencode::BEncode::Int(file_data.len() as i64));

    let mut torrent_dict = std::collections::BTreeMap::new();
    torrent_dict.insert(b"info".to_vec(), synapse_bencode::BEncode::Dict(info_dict));

    Info::from_bencode(synapse_bencode::BEncode::Dict(torrent_dict)).expect("valid test torrent")
}

#[tokio::test(flavor = "multi_thread")]
async fn magnet_leecher_resolves_metadata_from_a_seeder_over_ut_metadata() {
    let _ = tracing_subscriber::fmt::try_init();

    let file_data = b"a small file whose metadata gets fetched via BEP 9".to_vec();
    let piece_len = file_data.len() as u32; // single piece keeps this fast and deterministic
    let seeder_info = Arc::new(build_test_info(&file_data, piece_len, "magnet-test.bin"));

    let magnet_uri = format!("magnet:?xt=urn:btih:{}&dn=magnet-test.bin", hex::encode(seeder_info.hash));
    let leecher_info = Arc::new(Info::from_magnet(&magnet_uri).expect("valid magnet URI"));
    assert!(leecher_info.files.is_empty(), "magnet-derived Info must start with no files (the 'awaiting metadata' signal Torrent::new checks for)");
    assert_eq!(leecher_info.hash, seeder_info.hash);

    let seeder_dir = tempfile::tempdir().unwrap();
    let leecher_dir = tempfile::tempdir().unwrap();
    std::fs::write(seeder_dir.path().join("magnet-test.bin"), &file_data).unwrap();

    let seeder_disk = Arc::new(DiskEngine::auto().await);
    let leecher_disk = Arc::new(DiskEngine::auto().await);

    let mut seeder_have = Bitfield::new(seeder_info.pieces() as usize);
    for i in 0..seeder_info.pieces() {
        seeder_have.set(i as usize);
    }

    let tick = Duration::from_millis(20);
    let seeder_peer_id = [5u8; 20];
    let leecher_peer_id = [6u8; 20];

    let (seeder_tx, seeder_rx) = mpsc::channel::<PeerEvent>(64);
    let (_seeder_cmd_tx, seeder_cmd_rx) = mpsc::channel(1);
    let seeder = Torrent::new(
        TorrentConfig {
            info: seeder_info.clone(),
            download_dir: seeder_dir.path().to_path_buf(),
            peer_id: seeder_peer_id,
            disk: seeder_disk,
            mode: Mode::RarestFirst,
            max_pipeline: 8,
            regular_unchokes: 4,
            optimistic_unchoke_interval: Duration::from_secs(600),
            tick_interval: tick,
            on_torrent_completed: None,
            on_piece_completed: None,
            stats: fresh_stats(&seeder_info, seeder_dir.path()),
            bitfield: Arc::new(parking_lot::RwLock::new(Some(RoaringBitfield::from_bitfield(&seeder_have)))),
            download_bucket: Arc::new(TokenBucket::unthrottled()),
            upload_bucket: Arc::new(TokenBucket::unthrottled()),
            global_metrics: None,
            idle_timeout: None,
            live_peers: Arc::new(parking_lot::RwLock::new(Vec::new())),
            piece_availability: Arc::new(parking_lot::RwLock::new(vec![1; seeder_info.pieces() as usize])),
            settings: Arc::new(parking_lot::RwLock::new(Default::default())),
            on_peers_discovered: None,
            http_client: reqwest::Client::new(),
            on_metadata_resolved: None,
        },
        Some(&seeder_have),
    );
    tokio::spawn(seeder.run(seeder_rx, seeder_cmd_rx));

    let (leecher_tx, leecher_rx) = mpsc::channel::<PeerEvent>(64);
    let (_leecher_cmd_tx, leecher_cmd_rx) = mpsc::channel(1);
    let (metadata_tx, metadata_rx) = oneshot::channel::<Info>();
    let leecher = Torrent::new(
        TorrentConfig {
            info: leecher_info.clone(),
            download_dir: leecher_dir.path().to_path_buf(),
            peer_id: leecher_peer_id,
            disk: leecher_disk,
            mode: Mode::RarestFirst,
            max_pipeline: 8,
            regular_unchokes: 4,
            optimistic_unchoke_interval: Duration::from_secs(600),
            tick_interval: tick,
            on_torrent_completed: None,
            on_piece_completed: None,
            stats: fresh_stats(&leecher_info, leecher_dir.path()),
            bitfield: Arc::new(parking_lot::RwLock::new(None)),
            download_bucket: Arc::new(TokenBucket::unthrottled()),
            upload_bucket: Arc::new(TokenBucket::unthrottled()),
            global_metrics: None,
            idle_timeout: None,
            live_peers: Arc::new(parking_lot::RwLock::new(Vec::new())),
            piece_availability: Arc::new(parking_lot::RwLock::new(Vec::new())),
            settings: Arc::new(parking_lot::RwLock::new(Default::default())),
            on_peers_discovered: None,
            http_client: reqwest::Client::new(),
            on_metadata_resolved: Some(metadata_tx),
        },
        None,
    );
    tokio::spawn(leecher.run(leecher_rx, leecher_cmd_rx));

    // Seeder listens; leecher dials, using only the info_hash it already knows from the
    // magnet URI -- exactly like a real magnet add, before any piece metadata exists.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let seeder_addr = listener.local_addr().unwrap();
    let expected_hash = seeder_info.hash;
    tokio::spawn(async move {
        let (stream, addr) = listener.accept().await.unwrap();
        synapse_engine::accept(stream, addr, seeder_peer_id, move |h| h == expected_hash, false, seeder_tx)
            .await
            .expect("seeder-side handshake failed");
    });

    synapse_engine::connect(seeder_addr, leecher_peer_id, expected_hash, false, leecher_tx)
        .await
        .expect("leecher-side handshake failed");

    let resolved = tokio::time::timeout(Duration::from_secs(10), metadata_rx)
        .await
        .expect("timed out waiting for magnet metadata to resolve")
        .expect("metadata channel dropped without resolving");

    assert_eq!(resolved.hash, seeder_info.hash, "resolved Info must hash-verify against the original magnet info_hash");
    assert_eq!(resolved.name, seeder_info.name);
    assert_eq!(resolved.total_len, seeder_info.total_len);
    assert_eq!(resolved.pieces(), seeder_info.pieces());
}
