//! End-to-end proof that the rewrite's core pipeline actually works: two `Torrent`
//! actors, connected over a real TCP loopback socket, driving `synapse-wire`'s codec,
//! `synapse-picker`'s picker/choker, `synapse-meta`'s piece/file layout, and
//! `diskio`'s disk engine together - a seeder that already has a file on disk, and a
//! leecher that downloads it from scratch and must produce a byte-identical copy.

use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest, Sha1};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use diskio::DiskEngine;
use synapse_engine::{
    PeerEvent, SwarmState, SwarmStats, SwarmTier, TokenBucket, Torrent, TorrentConfig,
};
use synapse_meta::Info;
use synapse_picker::{Bitfield, Mode, RoaringBitfield};

/// A fresh `SwarmStats` for a `Torrent` under test — this crate's `SwarmEngine::add_torrent`
/// normally builds one of these and shares it with the `Torrent` it spawns; this test
/// constructs `Torrent` directly (no `SwarmEngine` in the loop) so it needs to build its own.
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

fn build_test_info(file_data: &[u8], piece_len: u32, name: &str) -> Info {
    let mut pieces = Vec::new();
    for chunk in file_data.chunks(piece_len as usize) {
        let hash: [u8; 20] = Sha1::digest(chunk).into();
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
        synapse_bencode::BEncode::Int(file_data.len() as i64),
    );

    let mut torrent_dict = std::collections::BTreeMap::new();
    torrent_dict.insert(b"info".to_vec(), synapse_bencode::BEncode::Dict(info_dict));

    Info::from_bencode(synapse_bencode::BEncode::Dict(torrent_dict)).expect("valid test torrent")
}

fn deterministic_file(len: usize) -> Vec<u8> {
    // Not cryptographically anything - just content with no obvious repeating
    // structure, so a bug that mixed up block/piece offsets would very likely produce
    // a detectably wrong byte sequence rather than accidentally still matching.
    let mut state: u32 = 0x1234_5678;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state & 0xFF) as u8
        })
        .collect()
}

/// Runs a full seeder->leecher download over a real TCP loopback connection and
/// returns what the leecher wrote to disk, for the caller to assert against.
async fn run_download(file_data: &[u8], piece_len: u32) -> Vec<u8> {
    let info = Arc::new(build_test_info(file_data, piece_len, "testfile.bin"));

    let seeder_dir = tempfile::tempdir().unwrap();
    let leecher_dir = tempfile::tempdir().unwrap();
    std::fs::write(seeder_dir.path().join("testfile.bin"), file_data).unwrap();

    let seeder_disk = Arc::new(DiskEngine::auto().await);
    let leecher_disk = Arc::new(DiskEngine::auto().await);

    let mut seeder_have = Bitfield::new(info.pieces() as usize);
    for i in 0..info.pieces() {
        seeder_have.set(i as usize);
    }

    let tick = Duration::from_millis(50);
    let seeder_peer_id = [1u8; 20];
    let leecher_peer_id = [2u8; 20];

    let (seeder_tx, seeder_rx) = mpsc::channel::<PeerEvent>(64);
    let (_seeder_cmd_tx, seeder_cmd_rx) = mpsc::channel(1);
    let seeder = Torrent::new(
        TorrentConfig {
            info: info.clone(),
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
            stats: fresh_stats(&info, seeder_dir.path()),
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
        },
        Some(&seeder_have),
    );
    tokio::spawn(seeder.run(seeder_rx, seeder_cmd_rx));

    let (leecher_tx, leecher_rx) = mpsc::channel::<PeerEvent>(64);
    let (_leecher_cmd_tx, leecher_cmd_rx) = mpsc::channel(1);
    let mut leecher = Torrent::new(
        TorrentConfig {
            info: info.clone(),
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
            stats: fresh_stats(&info, leecher_dir.path()),
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
        },
        None,
    );
    let (done_tx, done_rx) = oneshot::channel();
    leecher.notify_on_complete(done_tx);
    tokio::spawn(leecher.run(leecher_rx, leecher_cmd_rx));

    // Seeder listens; leecher dials. Accepting the connection performs the receiving
    // side of the BEP3 handshake before the seeder's Torrent actor ever sees it.
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
            seeder_tx,
        )
        .await
        .expect("seeder-side handshake failed");
    });

    synapse_engine::connect(seeder_addr, leecher_peer_id, info.hash, false, leecher_tx)
        .await
        .expect("leecher-side handshake failed");

    tokio::time::timeout(Duration::from_secs(10), done_rx)
        .await
        .expect("timed out waiting for the download to complete")
        .expect("completion sender dropped without firing");

    std::fs::read(leecher_dir.path().join("testfile.bin")).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn leecher_downloads_a_complete_byte_identical_file_from_a_seeder() {
    let _ = tracing_subscriber::fmt::try_init();

    // Two pieces, two blocks each (32KiB pieces, 16KiB blocks) - big enough to
    // exercise multi-block piece assembly, small enough to run fast.
    const PIECE_LEN: u32 = 32 * 1024;
    let file_data = deterministic_file(2 * PIECE_LEN as usize);

    let downloaded = run_download(&file_data, PIECE_LEN).await;
    assert_eq!(
        downloaded, file_data,
        "downloaded file must be byte-identical to the seeder's copy"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn handles_a_final_piece_and_block_shorter_than_the_normal_size() {
    let _ = tracing_subscriber::fmt::try_init();

    // 32KiB pieces (2x 16KiB blocks each), but a total length that leaves a short
    // final piece with a single, short final block - exercises Info::piece_len's
    // last-piece special case and the BLOCK_LEN.min(...) clamp in the request loop.
    const PIECE_LEN: u32 = 32 * 1024;
    let file_data = deterministic_file(2 * PIECE_LEN as usize + 12_345);

    let downloaded = run_download(&file_data, PIECE_LEN).await;
    assert_eq!(
        downloaded, file_data,
        "downloaded file must be byte-identical even with an uneven final piece/block"
    );
}
