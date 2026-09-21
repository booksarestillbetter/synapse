use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

use diskio::DiskEngine;
use synapse_engine::{SwarmEngine, SwarmState, SwarmTier};
use synapse_meta::Info;
use synapse_picker::Bitfield;

fn build_dummy_torrent(name: &str) -> Info {
    use sha1::{Digest, Sha1};
    let piece_len = 16384u32;
    let file_len = 65536usize;
    let mut pieces = Vec::new();
    let chunk_data = vec![0x77u8; piece_len as usize];
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
    torrent_dict.insert(b"info".to_vec(), synapse_bencode::BEncode::Dict(info_dict));

    Info::from_bencode(synapse_bencode::BEncode::Dict(torrent_dict))
        .expect("valid synthetic torrent")
}

#[tokio::test]
async fn test_completed_seed_starts_warm_with_zero_actors() {
    let tmp = tempdir().expect("create temp dir");
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0x33; 20]));

    let info = Arc::new(build_dummy_torrent("seed-standby.bin"));
    let hash = info.hash;

    let mut bf = Bitfield::new(info.pieces() as usize);
    for p in 0..info.pieces() {
        bf.set(p as usize);
    }

    let handle = engine.add_torrent(info, tmp.path().to_path_buf(), Some(&bf));

    // 1. Verify seed starts in Warm tier with 0 active actor tasks
    assert_eq!(handle.stats.read().state, SwarmState::Seeding);
    assert_eq!(handle.stats.read().tier, SwarmTier::Warm);
    assert!(
        !handle.is_active(),
        "Warm seed should not have an active actor task"
    );
    assert_eq!(engine.global_metrics().active_actors, 0);

    // 2. Wake-on-Peer: simulating an incoming peer connection
    let peer_tx = engine.get_or_wake_torrent(&hash);
    assert!(
        peer_tx.is_some(),
        "Waking should return a live peer event channel"
    );
    assert!(handle.is_active(), "Swarm should now be active");
    assert_eq!(handle.stats.read().tier, SwarmTier::Hot);
    assert_eq!(engine.global_metrics().active_actors, 1);

    // 3. Calling get_or_wake_torrent again reuses the existing active actor without duplicating
    let peer_tx2 = engine.get_or_wake_torrent(&hash);
    assert!(peer_tx2.is_some());
    assert_eq!(engine.global_metrics().active_actors, 1);

    engine.shutdown();
}

#[tokio::test]
async fn test_automatic_idle_demotion_to_warm() {
    let tmp = tempdir().expect("create temp dir");
    let disk = Arc::new(DiskEngine::auto().await);
    // Configure engine with short 50ms idle timeout for fast test execution
    let engine =
        Arc::new(SwarmEngine::new(disk, [0x44; 20]).with_idle_timeout(Duration::from_millis(50)));

    let info = Arc::new(build_dummy_torrent("idle-demote.bin"));
    let hash = info.hash;

    let mut bf = Bitfield::new(info.pieces() as usize);
    for p in 0..info.pieces() {
        bf.set(p as usize);
    }

    let handle = engine.add_torrent(info, tmp.path().to_path_buf(), Some(&bf));
    assert_eq!(engine.global_metrics().active_actors, 0);

    // Wake the torrent to Hot
    let peer_tx = engine.get_or_wake_torrent(&hash).expect("woken");
    assert_eq!(engine.global_metrics().active_actors, 1);
    assert_eq!(handle.stats.read().tier, SwarmTier::Hot);

    // Keep peer_tx alive for a moment, then wait for idle timeout (50ms) + 1 tick (250ms)
    tokio::time::sleep(Duration::from_millis(350)).await;

    // After 350ms with 0 connected peers, the actor should have demoted back to Warm
    assert_eq!(handle.stats.read().tier, SwarmTier::Warm);
    assert_eq!(engine.global_metrics().active_actors, 0);
    assert!(
        peer_tx.is_closed(),
        "Old actor channel should be closed after demotion"
    );

    // Waking again creates a fresh actor
    let fresh_tx = engine.get_or_wake_torrent(&hash).expect("woken again");
    assert!(!fresh_tx.is_closed());
    assert_eq!(handle.stats.read().tier, SwarmTier::Hot);
    assert_eq!(engine.global_metrics().active_actors, 1);

    engine.shutdown();
}

#[tokio::test]
async fn test_command_wake_on_warm_torrent() {
    let tmp = tempdir().expect("create temp dir");
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0x55; 20]));

    let info = Arc::new(build_dummy_torrent("recheck-wake.bin"));
    let hash = info.hash;

    let mut bf = Bitfield::new(info.pieces() as usize);
    for p in 0..info.pieces() {
        bf.set(p as usize);
    }

    let handle = engine.add_torrent(info, tmp.path().to_path_buf(), Some(&bf));
    assert_eq!(handle.stats.read().tier, SwarmTier::Warm);
    assert_eq!(engine.global_metrics().active_actors, 0);

    // Calling recheck_torrent should awaken the Warm swarm and dispatch the command
    let ok = engine.recheck_torrent(&hash);
    assert!(ok, "recheck_torrent succeeded on Warm swarm");
    assert_eq!(engine.global_metrics().active_actors, 1);
    assert_eq!(handle.stats.read().tier, SwarmTier::Hot);

    engine.shutdown();
}

#[tokio::test]
async fn test_stop_actor_terminates_torrent_and_cleans_up() {
    let tmp = tempdir().expect("create temp dir");
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0x66; 20]));

    let info = Arc::new(build_dummy_torrent("stop-actor-test.bin"));
    let hash = info.hash;

    let handle = engine.add_torrent(info, tmp.path().to_path_buf(), None);
    assert_eq!(handle.stats.read().state, SwarmState::Downloading);
    assert_eq!(handle.stats.read().tier, SwarmTier::Hot);
    assert_eq!(engine.global_metrics().active_actors, 1);

    let peer_tx = engine.get_or_wake_torrent(&hash).expect("peer tx");
    assert!(!peer_tx.is_closed());

    // 1. Transition to Cold should invoke stop_actor()
    let cold_ok = engine.transition_to_cold(&hash);
    assert!(cold_ok);
    assert_eq!(handle.stats.read().state, SwarmState::Stopped);
    assert_eq!(handle.stats.read().tier, SwarmTier::Cold);
    assert!(!handle.is_active());

    // Allow tokio event loop to process actor stop
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        peer_tx.is_closed(),
        "Actor event channel must be closed after stop_actor()"
    );
    assert_eq!(engine.global_metrics().active_actors, 0);

    // 2. Calling get_or_wake_torrent on a Cold torrent must return None (stays stopped)
    assert!(
        engine.get_or_wake_torrent(&hash).is_none(),
        "Cold torrent must not auto-wake on peer events"
    );

    // 3. Resuming via transition_to_hot awakens actor again
    assert!(engine.transition_to_hot(&hash));
    let peer_tx2 = engine.get_or_wake_torrent(&hash).expect("woken again");
    assert_eq!(engine.global_metrics().active_actors, 1);

    engine.shutdown();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        peer_tx2.is_closed(),
        "Engine shutdown must stop all active swarm actors"
    );
    assert_eq!(engine.global_metrics().active_actors, 0);
}

#[tokio::test]
async fn test_last_transfer_at_prevents_false_stalled_status() {
    let tmp = tempdir().expect("create temp dir");
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0x77; 20]));

    let info = Arc::new(build_dummy_torrent("stalled-check.bin"));
    let handle = engine.add_torrent(info, tmp.path().to_path_buf(), None);

    // Initial last_transfer_at is set to added_at
    let added_at = handle.stats.read().added_at;
    assert_eq!(handle.stats.read().last_transfer_at, added_at);

    // Simulate transfer activity occurred 10 seconds ago
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    handle.stats.write().last_transfer_at = now - 10;
    // Set added_at to 3600 seconds ago (1 hour ago)
    handle.stats.write().added_at = now - 3600;

    // Run reconcile_queue with stalled check enabled (1 minute threshold)
    engine.reconcile_queue();

    // The download rate is currently 0, but since last_transfer_at was only 10 seconds ago,
    // it must NOT be marked stalled!
    assert!(
        !handle.stats.read().is_stalled,
        "Torrent with recent data transfer must not be flagged as stalled"
    );

    engine.shutdown();
}
