use diskio::DiskEngine;
use sha1::{Digest, Sha1};
use std::sync::Arc;
use synapse_engine::{SessionStore, SwarmEngine, SwarmState, SwarmTier};
use synapse_meta::Info;
use synapse_picker::Bitfield;
use tempfile::tempdir;

fn build_dummy_torrent(name: &str, file_data: &[u8], piece_len: u32) -> Info {
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

    Info::from_bencode(synapse_bencode::BEncode::Dict(torrent_dict))
        .expect("valid synthetic torrent")
}

#[tokio::test]
async fn test_seeding_swarm_evicts_piece_hashes_on_add() {
    let tmp = tempdir().unwrap();
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = SwarmEngine::new(disk, [0x01; 20]);

    let data = vec![0x42u8; 64 * 1024];
    let piece_len = 16 * 1024;
    let info = build_dummy_torrent("seed-torrent", &data, piece_len);

    assert_eq!(info.pieces(), 4);
    assert!(info.has_piece_hashes());

    let mut completed_have = Bitfield::new(4);
    for i in 0..4 {
        completed_have.set(i);
    }

    let handle = engine.add_torrent(
        Arc::new(info),
        tmp.path().to_path_buf(),
        Some(&completed_have),
    );

    // Initial tier is Warm (0 active actor tasks)
    assert_eq!(handle.stats.read().tier, SwarmTier::Warm);
    assert_eq!(handle.stats.read().state, SwarmState::Seeding);
    assert_eq!(handle.stats.read().progress, 1.0);

    // Piece hashes must be evicted immediately to save RAM
    assert!(
        !handle.info.has_piece_hashes(),
        "piece hashes must be evicted for complete seed"
    );
    assert_eq!(handle.info.piece_hash(0), None);
    assert_eq!(handle.info.piece_hash(1), None);
    assert_eq!(handle.info.piece_hash(2), None);
    assert_eq!(handle.info.piece_hash(3), None);

    // pieces() and block_locations() must still function perfectly
    assert_eq!(handle.info.pieces(), 4);
    let locs = handle.info.block_locations(0, 0, piece_len);
    assert_eq!(locs.len(), 1);
    assert_eq!(locs[0].file, 0);
    assert_eq!(locs[0].file_offset, 0);
    assert_eq!(locs[0].piece_range, 0..(piece_len as usize));
}

#[tokio::test]
async fn test_recheck_transparently_reloads_evicted_hashes() {
    let tmp = tempdir().unwrap();
    let session_dir = tempdir().unwrap();
    let store = Arc::new(SessionStore::new(session_dir.path()).unwrap());
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = SwarmEngine::new(disk, [0x01; 20]).with_session_store(store.clone());

    let data = vec![0x77u8; 32 * 1024];
    let piece_len = 16 * 1024;

    // Write file to download directory so recheck passes
    let file_path = tmp.path().join("recheck-torrent");
    tokio::fs::write(&file_path, &data).await.unwrap();

    let info = build_dummy_torrent("recheck-torrent", &data, piece_len);
    let info_hash = info.hash;

    let mut completed_have = Bitfield::new(2);
    completed_have.set(0);
    completed_have.set(1);

    let handle = engine.add_torrent(
        Arc::new(info),
        tmp.path().to_path_buf(),
        Some(&completed_have),
    );

    // Verify hashes are evicted
    assert!(!handle.info.has_piece_hashes());

    // Trigger recheck
    let rechecked = engine.recheck_torrent(&info_hash);
    assert!(rechecked, "recheck_torrent must successfully dispatch");

    // Wait briefly for recheck to process in the actor task
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let stats = handle.stats.read();
    assert_eq!(stats.progress, 1.0);
    assert_eq!(stats.state, SwarmState::Seeding);

    // Hashes must be evicted again once re-verification completes
    assert!(
        !handle.info.has_piece_hashes(),
        "hashes must be evicted again after recheck passes"
    );
}

#[tokio::test]
async fn test_incomplete_download_does_not_evict_piece_hashes() {
    let tmp = tempdir().unwrap();
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = SwarmEngine::new(disk, [0x01; 20]);

    let data = vec![0x55u8; 64 * 1024];
    let piece_len = 16 * 1024;
    let info = build_dummy_torrent("download-torrent", &data, piece_len);

    assert_eq!(info.pieces(), 4);
    assert!(info.has_piece_hashes());

    let handle = engine.add_torrent(Arc::new(info), tmp.path().to_path_buf(), None);

    // Piece hashes must NOT be evicted
    assert!(
        handle.info.has_piece_hashes(),
        "piece hashes must NOT be evicted for incomplete download"
    );
    assert!(handle.info.piece_hash(0).is_some());
    assert!(handle.info.piece_hash(1).is_some());
    assert!(handle.info.piece_hash(2).is_some());
    assert!(handle.info.piece_hash(3).is_some());
}
