//! BEP 52 piece layers received from a peer must be verified against the file's
//! `pieces root` before use, must be bounded, and the hash messages must use the real
//! wire layout. Also checks v2 hashing against a file whose last block is short.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::codec::Framed;

use diskio::DiskEngine;
use synapse_bencode::BEncode;
use synapse_engine::{
    PeerEvent, SwarmState, SwarmStats, SwarmTier, TokenBucket, Torrent, TorrentConfig,
};
use synapse_meta::merkle::{compute_file_merkle_root, compute_file_piece_layer, BLOCK_SIZE};
use synapse_meta::Info;
use synapse_picker::Mode;
use synapse_wire::{Message, PeerCodec};

const PIECE_LEN: usize = BLOCK_SIZE * 2;

/// A single-file v2 torrent whose metainfo carries NO `piece layers`, so the layer can only
/// come from a peer. 40 000 bytes: three blocks, the last one short.
fn layerless_v2(data: &[u8]) -> Info {
    let root = compute_file_merkle_root(data);
    let leaf = BTreeMap::from([
        (b"length".to_vec(), BEncode::Int(data.len() as i64)),
        (b"pieces root".to_vec(), BEncode::String(root.to_vec())),
    ]);
    let tree = BTreeMap::from([(
        b"f.bin".to_vec(),
        BEncode::Dict(BTreeMap::from([(b"".to_vec(), BEncode::Dict(leaf))])),
    )]);
    let info = BTreeMap::from([
        (b"meta version".to_vec(), BEncode::Int(2)),
        (b"name".to_vec(), BEncode::String(b"v2".to_vec())),
        (b"piece length".to_vec(), BEncode::Int(PIECE_LEN as i64)),
        (b"file tree".to_vec(), BEncode::Dict(tree)),
    ]);
    Info::from_bencode(BEncode::Dict(BTreeMap::from([(
        b"info".to_vec(),
        BEncode::Dict(info),
    )])))
    .unwrap()
}

async fn connect(info: Arc<Info>) -> Framed<TcpStream, PeerCodec> {
    let dir = tempfile::tempdir().unwrap();
    let stats = Arc::new(parking_lot::RwLock::new(SwarmStats {
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
        download_dir: dir.path().to_string_lossy().to_string(),
        added_at: 0,
        is_private: false,
        is_stalled: false,
        last_transfer_at: 0,
        piece_count: info.pieces(),
        piece_size: info.piece_len,
    }));
    let (tx, rx) = mpsc::channel::<PeerEvent>(64);
    let (_cmd_tx, cmd_rx) = mpsc::channel(1);
    let torrent = Torrent::new(
        TorrentConfig {
            info: info.clone(),
            download_dir: dir.path().to_path_buf(),
            peer_id: [1u8; 20],
            disk: Arc::new(DiskEngine::auto().await),
            mode: Mode::RarestFirst,
            max_pipeline: 8,
            regular_unchokes: 4,
            optimistic_unchoke_interval: Duration::from_secs(600),
            tick_interval: Duration::from_millis(50),
            on_torrent_completed: None,
            on_piece_completed: None,
            stats,
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
    tokio::spawn(torrent.run(rx, cmd_rx));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hash = info.hash;
    tokio::spawn(async move {
        let (s, a) = listener.accept().await.unwrap();
        synapse_engine::accept(s, a, [1u8; 20], hash, false, tx)
            .await
            .unwrap();
    });
    let mut f = Framed::new(TcpStream::connect(addr).await.unwrap(), PeerCodec::new());
    f.send(Message::Handshake {
        reserved: [0; 8],
        info_hash: hash,
        peer_id: [9u8; 20],
    })
    .await
    .unwrap();
    assert!(matches!(
        f.next().await,
        Some(Ok(Message::Handshake { .. }))
    ));
    f
}

async fn ask(
    f: &mut Framed<TcpStream, PeerCodec>,
    root: [u8; 32],
    index: u32,
    count: u32,
) -> Option<Message> {
    f.send(Message::HashRequest {
        pieces_root: root,
        base_layer: 1,
        index,
        count,
        proof_layers: 0,
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(Ok(m)) = f.next().await {
            if matches!(m, Message::Hashes { .. } | Message::HashReject { .. }) {
                return Some(m);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_supplied_piece_layers_are_verified_before_use_and_bounded() {
    let data: Vec<u8> = (0..40_000usize).map(|i| (i % 251) as u8).collect();
    let info = Arc::new(layerless_v2(&data));
    let root = compute_file_merkle_root(&data);
    let good: Vec<u8> = compute_file_piece_layer(&data, PIECE_LEN).concat();
    let mut f = connect(info).await;

    // No layer known yet.
    assert!(matches!(
        ask(&mut f, root, 0, 2).await,
        Some(Message::HashReject { .. })
    ));

    let send = |layer: Vec<u8>, root, index, count| Message::Hashes {
        pieces_root: root,
        base_layer: 1,
        index,
        count,
        proof_layers: 0,
        hashes: layer.into(),
    };
    // 1. Right root, wrong hashes: must not be stored.
    f.send(send(vec![0xEE; 64], root, 0, 2)).await.unwrap();
    // 2. A hash claiming an absurd index (would have resized a buffer by ~137 GB).
    f.send(send(vec![0xEE; 32], root, u32::MAX, 1))
        .await
        .unwrap();
    // 3. A root that is not one of this torrent's files.
    f.send(send(good.clone(), [7u8; 32], 0, 2)).await.unwrap();
    // 4. A truncated (partial) layer.
    f.send(send(good[..32].to_vec(), root, 0, 1)).await.unwrap();
    assert!(
        matches!(
            ask(&mut f, root, 0, 2).await,
            Some(Message::HashReject { .. })
        ),
        "unverified layers must never be stored"
    );

    // The genuine layer verifies against the pieces root and is then served back.
    f.send(send(good.clone(), root, 0, 2)).await.unwrap();
    match ask(&mut f, root, 0, 2).await {
        Some(Message::Hashes { hashes, .. }) => assert_eq!(&hashes[..], &good[..]),
        other => panic!("expected the verified layer to be served, got {other:?}"),
    }
    // Requests larger than BEP 52's 512-hash limit are refused even for a known layer.
    assert!(matches!(
        ask(&mut f, root, 0, 513).await,
        Some(Message::HashReject { .. })
    ));
}

#[test]
fn v2_root_and_layer_of_a_file_with_a_short_last_block_match_an_independent_implementation() {
    let data: Vec<u8> = (0..40_000usize).map(|i| (i % 251) as u8).collect();
    let hex = |b: [u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    assert_eq!(
        hex(compute_file_merkle_root(&data)),
        "ab671631a9fa97a1fdac651fff6c68773b9acf0735b9c7f6ecdd54cbf1bf5dc2"
    );
}

/// A v2 torrent with no piece layer in its metainfo (as from a magnet) must fetch the layer
/// from a peer, chunk by chunk with proofs, and only start requesting pieces once it can
/// verify them. The layer here is random hashes; only the tree over them matters.
#[tokio::test(flavor = "multi_thread")]
async fn a_layerless_v2_torrent_fetches_its_piece_layer_with_proofs_before_requesting_pieces() {
    use synapse_meta::merkle::{root_from_piece_layer, PieceLayerTree};

    let pieces = 2050usize; // > 512, so several chunks and a non-trivial proof
    let layer: Vec<u8> = (0..pieces * 32)
        .map(|i| (i * 7 % 253) as u8 ^ (i / 32) as u8)
        .collect();
    let root = root_from_piece_layer(&layer, PIECE_LEN).unwrap();
    let file_len = (pieces * PIECE_LEN - 5) as u64;

    let leaf = BTreeMap::from([
        (b"length".to_vec(), BEncode::Int(file_len as i64)),
        (b"pieces root".to_vec(), BEncode::String(root.to_vec())),
    ]);
    let tree_dict = BTreeMap::from([(
        b"f.bin".to_vec(),
        BEncode::Dict(BTreeMap::from([(b"".to_vec(), BEncode::Dict(leaf))])),
    )]);
    let info_dict = BTreeMap::from([
        (b"meta version".to_vec(), BEncode::Int(2)),
        (b"name".to_vec(), BEncode::String(b"v2".to_vec())),
        (b"piece length".to_vec(), BEncode::Int(PIECE_LEN as i64)),
        (b"file tree".to_vec(), BEncode::Dict(tree_dict)),
    ]);
    let info = Arc::new(
        Info::from_bencode(BEncode::Dict(BTreeMap::from([(
            b"info".to_vec(),
            BEncode::Dict(info_dict),
        )])))
        .unwrap(),
    );
    assert_eq!(
        &info.hash[..],
        &info.info_hash_v2.unwrap()[..20],
        "pure v2 is keyed by the truncated SHA-256"
    );

    let mut f = connect(info.clone()).await;
    // Claim every piece and unchoke, so the only thing holding the leecher back is the layer.
    let bitfield = vec![0xFFu8; pieces.div_ceil(8)];
    f.send(Message::Bitfield(bitfield.into())).await.unwrap();
    f.send(Message::Unchoke).await.unwrap();

    let tree = PieceLayerTree::new(&layer, PIECE_LEN).unwrap();
    let mut answered = 0;
    let mut first_piece_request_after_layer = false;
    let outcome = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(Ok(msg)) = f.next().await {
            match msg {
                Message::HashRequest {
                    pieces_root,
                    base_layer,
                    index,
                    count,
                    proof_layers,
                } => {
                    assert_eq!(pieces_root, root);
                    assert_eq!(base_layer, 1, "piece layer of 32 KiB pieces");
                    assert!(count as usize <= 512);
                    let (hashes, proof) = tree
                        .respond(index as usize, count as usize, proof_layers as usize)
                        .expect("valid request");
                    let payload: Vec<u8> = hashes.into_iter().chain(proof).flatten().collect();
                    f.send(Message::Hashes {
                        pieces_root,
                        base_layer,
                        index,
                        count,
                        proof_layers,
                        hashes: payload.into(),
                    })
                    .await
                    .unwrap();
                    answered += 1;
                }
                Message::Request { .. } => {
                    // Pieces may only be requested once every chunk has been answered.
                    let chunks = pieces.div_ceil(512);
                    assert!(
                        answered >= chunks,
                        "requested a piece after {answered}/{chunks} layer chunks"
                    );
                    first_piece_request_after_layer = true;
                    break;
                }
                _ => {}
            }
        }
    })
    .await;
    assert!(
        outcome.is_ok(),
        "leecher never progressed to requesting pieces"
    );
    assert!(first_piece_request_after_layer);
}
