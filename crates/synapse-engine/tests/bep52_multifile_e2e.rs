//! A pure-v2 torrent with several files (each starting on a piece boundary, none a whole
//! number of pieces) must download byte-identical over a real socket, both when the metainfo
//! carries the piece layers and when the leecher has to fetch them from the seeder with proofs
//! (as it must for a magnet link).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use diskio::DiskEngine;
use synapse_bencode::BEncode;
use synapse_engine::{
    PeerEvent, SwarmState, SwarmStats, SwarmTier, TokenBucket, Torrent, TorrentConfig,
};
use synapse_meta::merkle::{compute_file_merkle_root, compute_file_piece_layer};
use synapse_meta::Info;
use synapse_picker::{Bitfield, Mode, RoaringBitfield};

const PIECE_LEN: usize = 32_768;
const FILES: [(&str, usize); 4] = [("a.bin", 40_000), ("b.bin", 5), ("c.bin", 70_000), ("z", 0)];

fn content(seed: u8, len: usize) -> Vec<u8> {
    let mut x = u32::from(seed).wrapping_mul(2654435761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 11) as u8
        })
        .collect()
}

fn build_info(with_layers: bool) -> Info {
    let mut tree = BTreeMap::new();
    let mut layers = BTreeMap::new();
    for (i, (name, len)) in FILES.iter().enumerate() {
        let data = content(i as u8, *len);
        let mut leaf = BTreeMap::from([(b"length".to_vec(), BEncode::Int(*len as i64))]);
        if *len > 0 {
            let root = compute_file_merkle_root(&data);
            leaf.insert(b"pieces root".to_vec(), BEncode::String(root.to_vec()));
            if *len > PIECE_LEN {
                let layer = compute_file_piece_layer(&data, PIECE_LEN).concat();
                layers.insert(root.to_vec(), BEncode::String(layer));
            }
        }
        tree.insert(
            name.as_bytes().to_vec(),
            BEncode::Dict(BTreeMap::from([(b"".to_vec(), BEncode::Dict(leaf))])),
        );
    }
    let info = BTreeMap::from([
        (b"meta version".to_vec(), BEncode::Int(2)),
        (b"name".to_vec(), BEncode::String(b"mv2".to_vec())),
        (b"piece length".to_vec(), BEncode::Int(PIECE_LEN as i64)),
        (b"file tree".to_vec(), BEncode::Dict(tree)),
    ]);
    let mut top = BTreeMap::from([(b"info".to_vec(), BEncode::Dict(info))]);
    if with_layers {
        top.insert(b"piece layers".to_vec(), BEncode::Dict(layers));
    }
    Info::from_bencode(BEncode::Dict(top)).unwrap()
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

async fn download(leecher_has_layers: bool) {
    let seed_info = Arc::new(build_info(true));
    let leech_info = Arc::new(build_info(leecher_has_layers));
    assert_eq!(seed_info.hash, leech_info.hash);
    // a: 2 pieces, b: 1, c: 3.
    assert_eq!(seed_info.pieces(), 6);

    let seeder_dir = tempfile::tempdir().unwrap();
    let leecher_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(seeder_dir.path().join("mv2")).unwrap();
    for (i, (name, len)) in FILES.iter().enumerate() {
        std::fs::write(
            seeder_dir.path().join("mv2").join(name),
            content(i as u8, *len),
        )
        .unwrap();
    }

    let mut have = Bitfield::new(seed_info.pieces() as usize);
    for i in 0..seed_info.pieces() {
        have.set(i as usize);
    }
    let (seeder_tx, seeder_rx) = mpsc::channel::<PeerEvent>(64);
    let (_c1, seeder_cmd) = mpsc::channel(1);
    let disk = Arc::new(DiskEngine::auto().await);
    let seeder = Torrent::new(
        config(&seed_info, seeder_dir.path(), 1, disk.clone(), Some(&have)),
        Some(&have),
    );
    tokio::spawn(seeder.run(seeder_rx, seeder_cmd));

    let (leecher_tx, leecher_rx) = mpsc::channel::<PeerEvent>(64);
    let (_c2, leecher_cmd) = mpsc::channel(1);
    let mut leecher = Torrent::new(config(&leech_info, leecher_dir.path(), 2, disk, None), None);
    let (done_tx, done_rx) = oneshot::channel();
    leecher.notify_on_complete(done_tx);
    tokio::spawn(leecher.run(leecher_rx, leecher_cmd));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hash = seed_info.hash;
    tokio::spawn(async move {
        let (s, a) = listener.accept().await.unwrap();
        synapse_engine::accept(s, a, [1u8; 20], hash, false, seeder_tx)
            .await
            .expect("seeder handshake");
    });
    synapse_engine::connect(addr, [2u8; 20], hash, false, leecher_tx)
        .await
        .expect("leecher handshake");

    tokio::time::timeout(Duration::from_secs(20), done_rx)
        .await
        .expect("download did not finish")
        .expect("completion sender dropped");

    for (i, (name, len)) in FILES.iter().enumerate() {
        let path = leecher_dir.path().join("mv2").join(name);
        if *len == 0 {
            continue; // empty files carry no pieces
        }
        assert_eq!(
            std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: {e}")),
            content(i as u8, *len),
            "{name} differs"
        );
    }
    let pad = std::fs::read_dir(leecher_dir.path().join("mv2"))
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().starts_with(".pad"));
    assert!(!pad, "padding must never be written to disk");
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_file_v2_torrent_downloads_intact_with_layers_in_the_metainfo() {
    download(true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_file_v2_torrent_fetches_every_files_layer_from_the_seeder_first() {
    download(false).await;
}

async fn ask_hashes(
    f: &mut tokio_util::codec::Framed<tokio::net::TcpStream, synapse_wire::PeerCodec>,
    root: [u8; 32],
    index: u32,
    count: u32,
    proof_layers: u32,
) -> synapse_wire::Message {
    use futures::{SinkExt, StreamExt};
    use synapse_wire::Message;
    f.send(Message::HashRequest {
        pieces_root: root,
        base_layer: 0,
        index,
        count,
        proof_layers,
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match f.next().await {
                Some(Ok(m @ (Message::Hashes { .. } | Message::HashReject { .. }))) => return m,
                Some(Ok(_)) => {}
                other => panic!("connection ended: {other:?}"),
            }
        }
    })
    .await
    .expect("no reply to the hash request")
}

/// A peer asking for block-level hashes (layer 0) of a file we hold completely gets them with
/// uncle proofs that verify against the file's `pieces root`; a file we do not hold is refused.
#[tokio::test(flavor = "multi_thread")]
async fn block_layer_hashes_are_served_with_proofs_only_for_complete_files() {
    use futures::SinkExt;
    use synapse_meta::merkle::{hash_block, verify_piece_layer_chunk, BLOCK_SIZE};
    use synapse_wire::{Message, PeerCodec};
    use tokio_util::codec::Framed;

    let info = Arc::new(build_info(true));
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("mv2")).unwrap();
    for (i, (name, len)) in FILES.iter().enumerate() {
        std::fs::write(dir.path().join("mv2").join(name), content(i as u8, *len)).unwrap();
    }
    // We hold a.bin (pieces 0-1) and b.bin (piece 2) but not c.bin (pieces 3-5).
    let mut have = Bitfield::new(info.pieces() as usize);
    for i in 0..3 {
        have.set(i);
    }
    let (tx, rx) = mpsc::channel::<PeerEvent>(64);
    let (_c, cmd) = mpsc::channel(1);
    let disk = Arc::new(DiskEngine::auto().await);
    let torrent = Torrent::new(config(&info, dir.path(), 1, disk, Some(&have)), Some(&have));
    tokio::spawn(torrent.run(rx, cmd));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hash = info.hash;
    tokio::spawn(async move {
        let (s, a) = listener.accept().await.unwrap();
        synapse_engine::accept(s, a, [1u8; 20], hash, false, tx)
            .await
            .unwrap();
    });
    let mut f = Framed::new(
        tokio::net::TcpStream::connect(addr).await.unwrap(),
        PeerCodec::new(),
    );
    f.send(Message::Handshake {
        reserved: [0; 8],
        info_hash: hash,
        peer_id: [9u8; 20],
    })
    .await
    .unwrap();

    let root_of = |name: &str| {
        let idx = FILES.iter().position(|(n, _)| *n == name).unwrap();
        compute_file_merkle_root(&content(idx as u8, FILES[idx].1))
    };
    // a.bin: 40 000 bytes = 3 blocks (last one short) -> 4 leaves. Blocks 0..4 with 0 uncles
    // (the whole tree), and blocks 0..2 with 1 uncle.
    let a = content(0, 40_000);
    let a_leaves: Vec<[u8; 32]> = a.chunks(BLOCK_SIZE).map(hash_block).collect();
    let root_a = root_of("a.bin");
    for (index, count, proof) in [(0u32, 4u32, 0u32), (0, 2, 1), (2, 2, 1), (3, 1, 2)] {
        match ask_hashes(&mut f, root_a, index, count, proof).await {
            Message::Hashes { hashes, .. } => {
                let cells: Vec<[u8; 32]> = hashes.as_chunks::<32>().0.to_vec();
                let (hs, uncles) = cells.split_at(count as usize);
                assert!(verify_piece_layer_chunk(
                    &root_a,
                    4,
                    index as usize,
                    hs,
                    uncles
                ));
                for (k, h) in hs.iter().enumerate() {
                    let expected = a_leaves.get(index as usize + k).copied().unwrap_or([0; 32]);
                    assert_eq!(*h, expected, "leaf {}", index as usize + k);
                }
            }
            other => panic!("expected hashes for ({index},{count},{proof}), got {other:?}"),
        }
    }
    // b.bin fits in one block: its single leaf is the root.
    match ask_hashes(&mut f, root_of("b.bin"), 0, 1, 0).await {
        Message::Hashes { hashes, .. } => assert_eq!(&hashes[..], &root_of("b.bin")[..]),
        other => panic!("expected hashes, got {other:?}"),
    }
    // Refusals: a file we do not hold completely, a bad range, an unknown root, too many hashes.
    assert!(matches!(
        ask_hashes(&mut f, root_of("c.bin"), 0, 4, 1).await,
        Message::HashReject { .. }
    ));
    assert!(matches!(
        ask_hashes(&mut f, root_a, 1, 2, 0).await,
        Message::HashReject { .. }
    ));
    assert!(matches!(
        ask_hashes(&mut f, [7; 32], 0, 1, 0).await,
        Message::HashReject { .. }
    ));
    assert!(matches!(
        ask_hashes(&mut f, root_a, 0, 1024, 0).await,
        Message::HashReject { .. }
    ));
}
