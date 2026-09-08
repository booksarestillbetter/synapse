use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

use diskio::DiskEngine;
use sha1::{Digest, Sha1};
use synapse_engine::SwarmEngine;
use synapse_meta::Info;

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
    torrent_dict.insert(
        b"info".to_vec(),
        synapse_bencode::BEncode::Dict(info_dict),
    );

    Info::from_bencode(synapse_bencode::BEncode::Dict(torrent_dict)).expect("valid test torrent")
}

#[tokio::test]
async fn test_swarm_engine_multi_torrent_routing() {
    let dir = TempDir::new().unwrap();
    let disk = Arc::new(DiskEngine::auto().await);
    let peer_id = [0x53u8; 20];

    let swarm = Arc::new(SwarmEngine::new(disk, peer_id));
    let _listener = swarm
        .clone()
        .start_listener(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();

    let info_a = Arc::new(build_test_info(b"content of torrent A", 16384, "torrent_a.dat"));
    let info_b = Arc::new(build_test_info(b"content of torrent B different", 16384, "torrent_b.dat"));

    let hash_a = info_a.hash;
    let hash_b = info_b.hash;

    assert_ne!(hash_a, hash_b);

    swarm.add_torrent(info_a, dir.path().join("a"), None);
    swarm.add_torrent(info_b, dir.path().join("b"), None);

    assert_eq!(swarm.torrent_count(), 2);
    let summaries = swarm.list_torrents();
    assert_eq!(summaries.len(), 2);

    // Verify initial tier is Hot
    let handle_a = swarm.get_torrent(&hash_a).unwrap();
    assert_eq!(handle_a.stats.read().tier, synapse_engine::SwarmTier::Hot);

    // Transition to Warm tier
    assert!(swarm.transition_to_warm(&hash_a));
    assert_eq!(handle_a.stats.read().tier, synapse_engine::SwarmTier::Warm);

    // Transition back to Hot tier
    assert!(swarm.transition_to_hot(&hash_a));
    assert_eq!(handle_a.stats.read().tier, synapse_engine::SwarmTier::Hot);

    // Give listener a moment to establish
    tokio::time::sleep(Duration::from_millis(50)).await;
}

#[tokio::test]
async fn test_private_torrent_bep27_flags() {
    let dir = TempDir::new().unwrap();
    let disk = Arc::new(DiskEngine::auto().await);
    let peer_id = [0x53u8; 20];
    let swarm = Arc::new(SwarmEngine::new(disk, peer_id));

    let mut info_dict = std::collections::BTreeMap::new();
    info_dict.insert(
        b"name".to_vec(),
        synapse_bencode::BEncode::String(b"private_movie.mkv".to_vec()),
    );
    info_dict.insert(
        b"piece length".to_vec(),
        synapse_bencode::BEncode::Int(16384),
    );
    info_dict.insert(b"pieces".to_vec(), synapse_bencode::BEncode::String(vec![0xAA; 20]));
    info_dict.insert(
        b"length".to_vec(),
        synapse_bencode::BEncode::Int(16384),
    );
    info_dict.insert(
        b"private".to_vec(),
        synapse_bencode::BEncode::Int(1),
    );

    let mut torrent_dict = std::collections::BTreeMap::new();
    torrent_dict.insert(
        b"info".to_vec(),
        synapse_bencode::BEncode::Dict(info_dict),
    );

    let info_private = Arc::new(Info::from_bencode(synapse_bencode::BEncode::Dict(torrent_dict)).expect("valid private torrent"));
    assert!(info_private.private);

    let hash = info_private.hash;
    swarm.add_torrent(info_private, dir.path().join("priv"), None);

    let handle = swarm.get_torrent(&hash).unwrap();
    assert!(handle.is_private());
    assert!(!handle.allows_dht());
    assert!(!handle.allows_pex());
    assert!(!handle.allows_lsd());
    assert!(handle.stats.read().is_private);
}
