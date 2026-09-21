//! End-to-end integration test verifying BEP 47 padding file enforcement.
//!
//! Validates:
//! 1. Multi-file torrents with BEP 47 `.pad/` files are downloaded and verified over real sockets.
//! 2. Padding files are never created on disk by either seeder or leecher.
//! 3. Disk serving and rechecking synthesizes zeroes for padding slices without file errors.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest, Sha1};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use diskio::DiskEngine;
use synapse_bencode::BEncode;
use synapse_engine::{
    PeerEvent, SwarmState, SwarmStats, SwarmTier, TokenBucket, Torrent, TorrentConfig,
};
use synapse_meta::Info;
use synapse_picker::{Bitfield, Mode, RoaringBitfield};

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

fn build_bep47_padding_torrent() -> (Info, Vec<u8>, Vec<u8>) {
    let piece_len: u32 = 16_384;
    let file1_data = vec![0x41u8; 10_000]; // 10,000 bytes of 'A'
    let pad1_len = 16_384 - 10_000; // 6,384 bytes padding
    let file2_data = vec![0x42u8; 12_000]; // 12,000 bytes of 'B'
    let pad2_len = 16_384 - 12_000; // 4,384 bytes padding

    // Build contiguous byte stream for computing piece hashes
    let mut stream = Vec::new();
    stream.extend_from_slice(&file1_data);
    stream.extend_from_slice(&vec![0u8; pad1_len]);
    stream.extend_from_slice(&file2_data);
    stream.extend_from_slice(&vec![0u8; pad2_len]);

    assert_eq!(stream.len(), 32_768); // Exactly 2 pieces

    let mut pieces = Vec::new();
    for chunk in stream.chunks(piece_len as usize) {
        let hash: [u8; 20] = Sha1::digest(chunk).into();
        pieces.extend_from_slice(&hash);
    }

    // Build multi-file info dictionary
    let mut files_list = Vec::new();

    // File 1
    let mut f1 = BTreeMap::new();
    f1.insert(b"length".to_vec(), BEncode::Int(file1_data.len() as i64));
    f1.insert(
        b"path".to_vec(),
        BEncode::List(vec![BEncode::String(b"file1.txt".to_vec())]),
    );
    files_list.push(BEncode::Dict(f1));

    // Pad 1
    let mut p1 = BTreeMap::new();
    p1.insert(b"length".to_vec(), BEncode::Int(pad1_len as i64));
    p1.insert(
        b"path".to_vec(),
        BEncode::List(vec![
            BEncode::String(b".pad".to_vec()),
            BEncode::String(format!("{}", pad1_len).into_bytes()),
        ]),
    );
    files_list.push(BEncode::Dict(p1));

    // File 2
    let mut f2 = BTreeMap::new();
    f2.insert(b"length".to_vec(), BEncode::Int(file2_data.len() as i64));
    f2.insert(
        b"path".to_vec(),
        BEncode::List(vec![BEncode::String(b"file2.txt".to_vec())]),
    );
    files_list.push(BEncode::Dict(f2));

    // Pad 2
    let mut p2 = BTreeMap::new();
    p2.insert(b"length".to_vec(), BEncode::Int(pad2_len as i64));
    p2.insert(
        b"path".to_vec(),
        BEncode::List(vec![
            BEncode::String(b".pad".to_vec()),
            BEncode::String(format!("{}", pad2_len).into_bytes()),
        ]),
    );
    files_list.push(BEncode::Dict(p2));

    let mut info_dict = BTreeMap::new();
    info_dict.insert(b"name".to_vec(), BEncode::String(b"pad_torrent".to_vec()));
    info_dict.insert(b"piece length".to_vec(), BEncode::Int(piece_len as i64));
    info_dict.insert(b"pieces".to_vec(), BEncode::String(pieces));
    info_dict.insert(b"files".to_vec(), BEncode::List(files_list));

    let mut top_dict = BTreeMap::new();
    top_dict.insert(b"info".to_vec(), BEncode::Dict(info_dict));

    let info = Info::from_bencode(BEncode::Dict(top_dict)).expect("valid bep47 torrent");
    (info, file1_data, file2_data)
}

#[tokio::test]
async fn test_bep47_padding_file_download_and_disk_isolation() {
    let (info, file1_data, file2_data) = build_bep47_padding_torrent();
    let info = Arc::new(info);

    let seeder_dir = tempfile::tempdir().unwrap();
    let leecher_dir = tempfile::tempdir().unwrap();

    // Seeder only creates the real payload files (NO .pad files on disk!)
    tokio::fs::create_dir_all(seeder_dir.path().join("pad_torrent"))
        .await
        .unwrap();
    tokio::fs::write(seeder_dir.path().join("pad_torrent/file1.txt"), &file1_data)
        .await
        .unwrap();
    tokio::fs::write(seeder_dir.path().join("pad_torrent/file2.txt"), &file2_data)
        .await
        .unwrap();

    let seeder_disk = Arc::new(DiskEngine::auto().await);
    let leecher_disk = Arc::new(DiskEngine::auto().await);

    let mut seeder_have = Bitfield::new(info.pieces() as usize);
    for i in 0..info.pieces() as usize {
        seeder_have.set(i);
    }

    let seeder_peer_id = [0x11; 20];
    let leecher_peer_id = [0x22; 20];
    let tick = Duration::from_millis(20);

    let (_seeder_tx, seeder_rx) = mpsc::channel::<PeerEvent>(64);
    let (_seeder_cmd_tx, seeder_cmd_rx) = mpsc::channel(1);

    let seeder_config = TorrentConfig {
        info: info.clone(),
        download_dir: seeder_dir.path().to_path_buf(),
        peer_id: seeder_peer_id,
        disk: seeder_disk,
        mode: Mode::RarestFirst,
        max_pipeline: 8,
        regular_unchokes: 4,
        optimistic_unchoke_interval: Duration::from_secs(60),
        tick_interval: tick,
        on_torrent_completed: None,
        on_piece_completed: None,
        stats: fresh_stats(&info, seeder_dir.path(), true),
        bitfield: Arc::new(parking_lot::RwLock::new(Some(
            RoaringBitfield::from_bitfield(&seeder_have),
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

    let seeder = Torrent::new(seeder_config, Some(&seeder_have));
    tokio::spawn(seeder.run(seeder_rx, seeder_cmd_rx));

    let (_leecher_tx, leecher_rx) = mpsc::channel::<PeerEvent>(64);
    let (_leecher_cmd_tx, leecher_cmd_rx) = mpsc::channel(1);

    let leecher_stats = fresh_stats(&info, leecher_dir.path(), false);
    let leecher_config = TorrentConfig {
        info: info.clone(),
        download_dir: leecher_dir.path().to_path_buf(),
        peer_id: leecher_peer_id,
        disk: leecher_disk,
        mode: Mode::RarestFirst,
        max_pipeline: 8,
        regular_unchokes: 4,
        optimistic_unchoke_interval: Duration::from_secs(60),
        tick_interval: tick,
        on_torrent_completed: None,
        on_piece_completed: None,
        stats: leecher_stats.clone(),
        bitfield: Arc::new(parking_lot::RwLock::new(None)),
        download_bucket: Arc::new(TokenBucket::unthrottled()),
        upload_bucket: Arc::new(TokenBucket::unthrottled()),
        global_metrics: None,
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
        alert_sender: None,
    };

    let mut leecher = Torrent::new(leecher_config, None);
    let (done_tx, done_rx) = oneshot::channel();
    leecher.notify_on_complete(done_tx);
    tokio::spawn(leecher.run(leecher_rx, leecher_cmd_rx));

    // Bind seeder listener
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let seeder_addr = listener.local_addr().unwrap();

    let expected_hash = info.hash;
    tokio::spawn(async move {
        let (stream, addr) = listener.accept().await.unwrap();
        synapse_engine::accept(
            stream,
            addr,
            seeder_peer_id,
            expected_hash,
            false,
            _seeder_tx,
        )
        .await
        .expect("seeder accept");
    });

    synapse_engine::connect(
        seeder_addr,
        leecher_peer_id,
        expected_hash,
        false,
        _leecher_tx,
    )
    .await
    .expect("leecher connect");

    // Wait for download to finish
    tokio::time::timeout(Duration::from_secs(10), done_rx)
        .await
        .expect("download completed in time")
        .expect("done channel fired");

    // 1. Verify leecher payload files match byte-for-byte
    let dl_file1 = tokio::fs::read(leecher_dir.path().join("pad_torrent/file1.txt"))
        .await
        .unwrap();
    let dl_file2 = tokio::fs::read(leecher_dir.path().join("pad_torrent/file2.txt"))
        .await
        .unwrap();
    assert_eq!(dl_file1, file1_data);
    assert_eq!(dl_file2, file2_data);

    // 2. Verify that NO padding files exist on disk anywhere in seeder or leecher directory!
    assert!(
        !leecher_dir.path().join("pad_torrent/.pad").exists(),
        "padding directory must NOT exist on disk"
    );
    assert!(
        !seeder_dir.path().join("pad_torrent/.pad").exists(),
        "seeder must not have padding directory"
    );

    assert_eq!(leecher_stats.read().state, SwarmState::Seeding);
    assert_eq!(leecher_stats.read().progress, 1.0);
}
