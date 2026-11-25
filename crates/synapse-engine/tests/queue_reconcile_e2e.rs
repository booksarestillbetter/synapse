//! `SwarmEngine::reconcile_queue` against real torrents (the auto-manage unit tests only cover
//! the pure `QueueManager` predicates).

use std::collections::BTreeMap;
use std::sync::Arc;

use sha1::{Digest, Sha1};

use diskio::DiskEngine;
use synapse_bencode::BEncode;
use synapse_engine::queue::QueueConfig;
use synapse_engine::{SwarmEngine, SwarmState};
use synapse_meta::Info;

fn info(seed: u8) -> Info {
    let data = vec![seed; 32 * 1024];
    let pieces: Vec<u8> = data
        .chunks(16 * 1024)
        .flat_map(|c| Sha1::digest(c).to_vec())
        .collect();
    let d = BTreeMap::from([
        (
            b"name".to_vec(),
            BEncode::String(format!("t{seed}.bin").into_bytes()),
        ),
        (b"piece length".to_vec(), BEncode::Int(16 * 1024)),
        (b"pieces".to_vec(), BEncode::String(pieces)),
        (b"length".to_vec(), BEncode::Int(data.len() as i64)),
    ]);
    Info::from_bencode(BEncode::Dict(BTreeMap::from([(
        b"info".to_vec(),
        BEncode::Dict(d),
    )])))
    .unwrap()
}

fn states(engine: &SwarmEngine) -> Vec<SwarmState> {
    engine
        .list_torrents()
        .into_iter()
        .map(|t| t.state)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn brand_new_downloads_count_against_the_limit_even_before_they_have_throughput() {
    let engine = Arc::new(SwarmEngine::new(
        Arc::new(DiskEngine::auto().await),
        [1u8; 20],
    ));
    engine.set_queue_config(QueueConfig {
        max_active_downloads: 1,
        max_active_torrents: 100,
        dont_count_slow_torrents: true,
        queue_stalled_enabled: false,
        ..Default::default()
    });
    let dir = tempfile::tempdir().unwrap();
    for seed in 1..=4u8 {
        engine.add_torrent(Arc::new(info(seed)), dir.path().to_path_buf(), None);
    }
    let count = |s: &[SwarmState], want: SwarmState| s.iter().filter(|x| **x == want).count();
    assert_eq!(
        count(&states(&engine), SwarmState::Downloading),
        1,
        "limit is 1 at add time"
    );

    // With no throughput every torrent is "slow", but a torrent that only just started still
    // holds its slot. Reconciling repeatedly must not promote the queued ones.
    for _ in 0..5 {
        engine.reconcile_queue();
    }
    let now = states(&engine);
    assert_eq!(
        count(&now, SwarmState::Downloading),
        1,
        "queued torrents were promoted past the limit: {now:?}"
    );
    assert_eq!(count(&now, SwarmState::Queued), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_seed_is_not_stopped_for_being_old_while_it_is_still_active() {
    let engine = Arc::new(SwarmEngine::new(
        Arc::new(DiskEngine::auto().await),
        [1u8; 20],
    ));
    engine.set_queue_config(QueueConfig {
        idle_seeding_limit_enabled: true,
        seed_time_limit_secs: Some(1800),
        ..Default::default()
    });
    let dir = tempfile::tempdir().unwrap();
    let info = Arc::new(info(9));
    let hash = info.hash;
    let handle = engine.add_torrent(info, dir.path().to_path_buf(), None);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    {
        // Added two hours ago (a long download), finished and uploading right now.
        let mut s = handle.stats.write();
        s.state = SwarmState::Seeding;
        s.added_at = now - 7200;
        s.last_transfer_at = now - 5;
    }
    engine.reconcile_queue();
    assert_eq!(
        engine.get_torrent(&hash).unwrap().stats.read().state,
        SwarmState::Seeding
    );

    // Once it has genuinely been idle longer than the limit it is stopped.
    engine
        .get_torrent(&hash)
        .unwrap()
        .stats
        .write()
        .last_transfer_at = now - 3600;
    engine.reconcile_queue();
    assert_eq!(
        engine.get_torrent(&hash).unwrap().stats.read().state,
        SwarmState::Stopped
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn queued_downloads_promote_even_when_total_torrents_exceed_max_active_torrents() {
    let engine = Arc::new(SwarmEngine::new(
        Arc::new(DiskEngine::auto().await),
        [1u8; 20],
    ));
    engine.set_queue_config(QueueConfig {
        download_queue_enabled: true,
        max_active_downloads: 2,
        max_active_torrents: 4,
        dont_count_slow_torrents: true,
        queue_stalled_enabled: true,
        queue_stalled_minutes: 1,
        ..Default::default()
    });
    let dir = tempfile::tempdir().unwrap();

    // Add 5 idle seeding/stopped torrents so total torrents > max_active_torrents (4).
    for seed in 10..=14u8 {
        let h = engine.add_torrent(Arc::new(info(seed)), dir.path().to_path_buf(), None);
        let mut s = h.stats.write();
        s.state = if seed % 2 == 0 {
            SwarmState::Seeding
        } else {
            SwarmState::Stopped
        };
        s.upload_rate = 0;
    }

    // Add 4 downloads: first 2 should start Downloading, next 2 should be Queued.
    let mut dl_hashes = Vec::new();
    for seed in 20..=23u8 {
        let h = engine.add_torrent(Arc::new(info(seed)), dir.path().to_path_buf(), None);
        dl_hashes.push(h.info.hash);
    }
    assert_eq!(
        engine
            .get_torrent(&dl_hashes[0])
            .unwrap()
            .stats
            .read()
            .state,
        SwarmState::Downloading
    );
    assert_eq!(
        engine
            .get_torrent(&dl_hashes[1])
            .unwrap()
            .stats
            .read()
            .state,
        SwarmState::Downloading
    );
    assert_eq!(
        engine
            .get_torrent(&dl_hashes[2])
            .unwrap()
            .stats
            .read()
            .state,
        SwarmState::Queued
    );
    assert_eq!(
        engine
            .get_torrent(&dl_hashes[3])
            .unwrap()
            .stats
            .read()
            .state,
        SwarmState::Queued
    );

    // Simulate the queued torrents waiting longer than queue_stalled_minutes.
    let old_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - 300;
    for h in &dl_hashes[2..] {
        engine
            .get_torrent(h)
            .unwrap()
            .stats
            .write()
            .last_transfer_at = old_ts;
    }

    // Complete the first download -> third torrent must be promoted, fourth must stay Queued!
    {
        let h0 = engine.get_torrent(&dl_hashes[0]).unwrap();
        let mut s = h0.stats.write();
        s.state = SwarmState::Seeding;
        s.progress = 1.0;
    }
    engine.reconcile_queue();
    assert_eq!(
        engine
            .get_torrent(&dl_hashes[2])
            .unwrap()
            .stats
            .read()
            .state,
        SwarmState::Downloading
    );
    assert_eq!(
        engine
            .get_torrent(&dl_hashes[3])
            .unwrap()
            .stats
            .read()
            .state,
        SwarmState::Queued
    );

    // Reconcile again immediately: newly promoted torrent must NOT be marked stalled on next tick,
    // so the 4th torrent must remain Queued while 2 are Downloading.
    engine.reconcile_queue();
    assert!(
        !engine
            .get_torrent(&dl_hashes[2])
            .unwrap()
            .stats
            .read()
            .is_stalled
    );
    assert_eq!(
        engine
            .get_torrent(&dl_hashes[3])
            .unwrap()
            .stats
            .read()
            .state,
        SwarmState::Queued
    );

    // Pause an active download -> Stopped -> unpause -> Downloading.
    assert!(engine.transition_to_cold(&dl_hashes[1]));
    assert_eq!(
        engine
            .get_torrent(&dl_hashes[1])
            .unwrap()
            .stats
            .read()
            .state,
        SwarmState::Stopped
    );
    assert!(engine.transition_to_hot(&dl_hashes[1]));
    assert_eq!(
        engine
            .get_torrent(&dl_hashes[1])
            .unwrap()
            .stats
            .read()
            .state,
        SwarmState::Downloading
    );
}
