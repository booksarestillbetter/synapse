use std::sync::Arc;
use tempfile::tempdir;
use diskio::DiskEngine;
use synapse_engine::{SessionStore, SwarmEngine, TorrentSessionState};
use synapse_picker::Bitfield;

#[tokio::test]
async fn test_session_persistence_save_load_remove() {
    let tmp = tempdir().unwrap();
    let store = Arc::new(SessionStore::new(tmp.path()).unwrap());

    let info_hash = [0xAA; 20];
    let bitfield = Bitfield::from_bytes(&[0b10100000], 8).unwrap();

    let state = TorrentSessionState {
        info_hash_hex: hex::encode(info_hash),
        name: "TestTorrent".into(),
        download_dir: "/downloads/test".into(),
        bitfield_hex: hex::encode(bitfield.as_bytes()),
        total_pieces: 8,
        total_size: 1024 * 1024,
        uploaded_bytes: 500,
        downloaded_bytes: 1024,
        added_at: 1700000000,
        is_paused: false,
        magnet_uri: None,
        raw_bencode_hex: None,
    };

    // 1. Save
    store.save_torrent(&state).unwrap();

    // 2. Load all
    let loaded = store.load_all().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].name, "TestTorrent");
    assert_eq!(loaded[0].info_hash(), Some(info_hash));

    let loaded_bf = loaded[0].to_bitfield().unwrap();
    assert_eq!(loaded_bf.as_bytes(), bitfield.as_bytes());

    // 3. SwarmEngine integration
    let disk = Arc::new(DiskEngine::auto().await);
    let swarm = SwarmEngine::new(disk, [0x01; 20]).with_session_store(store.clone());

    // 4. Remove
    assert!(!swarm.remove_torrent(&info_hash)); // not currently in memory
    let remaining = store.load_all().unwrap();
    assert_eq!(remaining.len(), 0);
}

#[tokio::test]
async fn test_session_store_encryption_isolation() {
    let tmp = tempdir().unwrap();
    let key1 = [0x11u8; 32];
    let key2 = [0x22u8; 32];

    let store1 = SessionStore::with_key(tmp.path(), key1).unwrap();
    let info_hash = [0xBB; 20];
    let bitfield = Bitfield::from_bytes(&[0b11110000], 8).unwrap();
    let state = TorrentSessionState {
        info_hash_hex: hex::encode(info_hash),
        name: "EncryptedSecret".into(),
        download_dir: "/downloads/secret".into(),
        bitfield_hex: hex::encode(bitfield.as_bytes()),
        total_pieces: 8,
        total_size: 2048,
        uploaded_bytes: 0,
        downloaded_bytes: 2048,
        added_at: 1700000000,
        is_paused: false,
        magnet_uri: None,
        raw_bencode_hex: None,
    };
    store1.save_torrent(&state).unwrap();
    drop(store1);

    // Opening with the wrong key must fail authentication
    let store2 = SessionStore::with_key(tmp.path(), key2).unwrap();
    let loaded = store2.load_all().unwrap();
    assert_eq!(loaded.len(), 0, "Wrong decryption key must not yield any valid records");
    assert!(store2.load_torrent(&hex::encode(info_hash)).is_err(), "Single load with wrong key must error");
    drop(store2);

    // Reopening with correct key succeeds
    let store_correct = SessionStore::with_key(tmp.path(), key1).unwrap();
    let loaded_correct = store_correct.load_all().unwrap();
    assert_eq!(loaded_correct.len(), 1);
    assert_eq!(loaded_correct[0].name, "EncryptedSecret");
}

#[tokio::test]
async fn test_legacy_json_auto_migration() {
    let tmp = tempdir().unwrap();
    let torrents_dir = tmp.path().join("torrents");
    std::fs::create_dir_all(&torrents_dir).unwrap();

    let info_hash = [0xCC; 20];
    let legacy_state = TorrentSessionState {
        info_hash_hex: hex::encode(info_hash),
        name: "LegacyFlatFile".into(),
        download_dir: "/downloads/legacy".into(),
        bitfield_hex: hex::encode([0xFFu8]),
        total_pieces: 8,
        total_size: 4096,
        uploaded_bytes: 100,
        downloaded_bytes: 4096,
        added_at: 1690000000,
        is_paused: false,
        magnet_uri: None,
        raw_bencode_hex: None,
    };

    let legacy_file = torrents_dir.join(format!("{}.json", hex::encode(info_hash)));
    std::fs::write(&legacy_file, serde_json::to_string(&legacy_state).unwrap()).unwrap();

    // Initialize SessionStore - must automatically detect and migrate
    let store = SessionStore::new(tmp.path()).unwrap();
    let all = store.load_all().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].name, "LegacyFlatFile");

    // Verify torrents.migrated directory was created
    assert!(tmp.path().join("torrents.migrated").exists());
}

#[tokio::test]
async fn test_raw_bencode_hex_preservation_and_evicted_restore() {
    let tmp = tempdir().unwrap();
    let store = Arc::new(SessionStore::new(tmp.path()).unwrap());

    let info_hash = [0xCC; 20];
    let original_bencode_hex = hex::encode(b"d4:infod6:lengthi131072e4:name4:test12:piece lengthi16384e6:pieces0:ee");

    let state1 = TorrentSessionState {
        info_hash_hex: hex::encode(info_hash),
        name: "EvictedTorrent".into(),
        download_dir: "/downloads/test".into(),
        bitfield_hex: hex::encode([0xFFu8]),
        total_pieces: 8,
        total_size: 16384 * 8,
        uploaded_bytes: 0,
        downloaded_bytes: 16384 * 8,
        added_at: 1700000000,
        is_paused: false,
        magnet_uri: None,
        raw_bencode_hex: Some(original_bencode_hex.clone()),
    };

    // 1. Initial save with raw_bencode_hex
    store.save_torrent(&state1).unwrap();

    // 2. Subsequent update with raw_bencode_hex: None (e.g. sync_session_store or progress update)
    let mut state2 = state1.clone();
    state2.uploaded_bytes = 50000;
    state2.raw_bencode_hex = None;
    store.save_torrent(&state2).unwrap();

    // Verify raw_bencode_hex was preserved
    let reloaded = store.load_torrent(&hex::encode(info_hash)).unwrap().unwrap();
    assert_eq!(reloaded.uploaded_bytes, 50000);
    assert_eq!(reloaded.raw_bencode_hex, Some(original_bencode_hex));

    // 3. Verify restore_session restores the swarm even with evicted pieces
    let disk = Arc::new(DiskEngine::auto().await);
    let swarm = SwarmEngine::new(disk, [0x01; 20]).with_session_store(store.clone());
    let restored = swarm.restore_session().unwrap();
    assert_eq!(restored, 1);
    assert_eq!(swarm.torrent_count(), 1);
}

