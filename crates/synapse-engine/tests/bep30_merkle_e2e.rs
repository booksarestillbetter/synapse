//! BEP 30: a Merkle torrent (a `root hash` instead of `pieces`) downloads over a real socket
//! with the piece hashes proven by the hash lists in `Tr_hashpiece` messages, and a seeder whose
//! data does not match the root hash refuses to serve.

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
use synapse_meta::merkle_v1::MerkleTreeV1;
use synapse_meta::Info;
use synapse_picker::{Bitfield, Mode, RoaringBitfield};

const PIECE_LEN: usize = 32_768;

fn content(len: usize) -> Vec<u8> {
    let mut x = 0x2545F491u32;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 11) as u8
        })
        .collect()
}

/// A single-file Merkle torrent over `data`.
fn merkle_info(data: &[u8]) -> Info {
    let hashes: Vec<[u8; 20]> = data
        .chunks(PIECE_LEN)
        .map(|c| Sha1::digest(c).into())
        .collect();
    let root = MerkleTreeV1::from_piece_hashes(&hashes).unwrap().root();
    let info = BTreeMap::from([
        (b"length".to_vec(), BEncode::Int(data.len() as i64)),
        (b"name".to_vec(), BEncode::String(b"m.bin".to_vec())),
        (b"piece length".to_vec(), BEncode::Int(PIECE_LEN as i64)),
        (b"root hash".to_vec(), BEncode::String(root.to_vec())),
    ]);
    Info::from_bencode(BEncode::Dict(BTreeMap::from([(
        b"info".to_vec(),
        BEncode::Dict(info),
    )])))
    .unwrap()
}

fn stats(info: &Info, dir: &Path) -> Arc<parking_lot::RwLock<SwarmStats>> {
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
        download_dir: dir.to_string_lossy().to_string(),
        added_at: 0,
        is_private: false,
        is_stalled: false,
        last_transfer_at: 0,
        piece_count: info.pieces(),
        piece_size: info.piece_len,
    }))
}

fn config(
    info: &Arc<Info>,
    dir: &Path,
    peer_id: u8,
    disk: Arc<DiskEngine>,
    have: Option<&Bitfield>,
) -> TorrentConfig {
    TorrentConfig {
        info: info.clone(),
        download_dir: dir.to_path_buf(),
        peer_id: [peer_id; 20],
        disk,
        mode: Mode::RarestFirst,
        max_pipeline: 8,
        regular_unchokes: 4,
        optimistic_unchoke_interval: Duration::from_secs(600),
        tick_interval: Duration::from_millis(50),
        on_torrent_completed: None,
        on_piece_completed: None,
        stats: stats(info, dir),
        bitfield: Arc::new(parking_lot::RwLock::new(
            have.map(RoaringBitfield::from_bitfield),
        )),
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
    }
}

/// Runs a seeder holding `on_disk` against a leecher of `info`; returns the leecher's dir if it
/// finished within `wait`.
async fn transfer(info: Arc<Info>, on_disk: &[u8], wait: Duration) -> Option<tempfile::TempDir> {
    let seeder_dir = tempfile::tempdir().unwrap();
    let leecher_dir = tempfile::tempdir().unwrap();
    std::fs::write(seeder_dir.path().join("m.bin"), on_disk).unwrap();

    let mut have = Bitfield::new(info.pieces() as usize);
    for i in 0..info.pieces() {
        have.set(i as usize);
    }
    let disk = Arc::new(DiskEngine::auto().await);
    let (seeder_tx, seeder_rx) = mpsc::channel::<PeerEvent>(64);
    let (_c1, seeder_cmd) = mpsc::channel(1);
    let seeder = Torrent::new(
        config(&info, seeder_dir.path(), 1, disk.clone(), Some(&have)),
        Some(&have),
    );
    tokio::spawn(seeder.run(seeder_rx, seeder_cmd));

    let (leecher_tx, leecher_rx) = mpsc::channel::<PeerEvent>(64);
    let (_c2, leecher_cmd) = mpsc::channel(1);
    let mut leecher = Torrent::new(config(&info, leecher_dir.path(), 2, disk, None), None);
    let (done_tx, done_rx) = oneshot::channel();
    leecher.notify_on_complete(done_tx);
    tokio::spawn(leecher.run(leecher_rx, leecher_cmd));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hash = info.hash;
    tokio::spawn(async move {
        let (s, a) = listener.accept().await.unwrap();
        synapse_engine::accept(s, a, [1u8; 20], hash, false, seeder_tx)
            .await
            .unwrap();
    });
    synapse_engine::connect(addr, [2u8; 20], hash, false, leecher_tx)
        .await
        .unwrap();
    tokio::time::timeout(wait, done_rx).await.ok()?.ok()?;
    Some(leecher_dir)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_merkle_torrent_downloads_intact_using_hash_lists() {
    // 5 pieces (the last short) -> 8 leaves, so the hash lists have real uncles.
    let data = content(PIECE_LEN * 4 + 12_345);
    let info = Arc::new(merkle_info(&data));
    assert!(info.is_merkle_v1());
    assert_eq!(info.pieces(), 5);
    let dir = transfer(info, &data, Duration::from_secs(20))
        .await
        .expect("the Merkle torrent did not finish");
    assert_eq!(std::fs::read(dir.path().join("m.bin")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_seeder_whose_data_does_not_match_the_root_hash_serves_nothing() {
    let data = content(PIECE_LEN * 3);
    let info = Arc::new(merkle_info(&data));
    let mut corrupt = data.clone();
    corrupt[PIECE_LEN + 5] ^= 0xFF;
    assert!(
        transfer(info, &corrupt, Duration::from_secs(3))
            .await
            .is_none(),
        "data that fails the root hash must never be handed out"
    );
}
