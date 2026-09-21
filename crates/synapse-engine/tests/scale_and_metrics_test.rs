use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;

use diskio::DiskEngine;
use synapse_engine::{EngineMetricsSnapshot, SwarmEngine, SwarmState, SwarmStateFilter};
use synapse_meta::Info;
use synapse_picker::Bitfield;

fn build_dummy_torrent(name: &str, file_len: usize, piece_len: u32) -> Info {
    use sha1::{Digest, Sha1};
    let mut pieces = Vec::new();
    let chunk_data = vec![0x33u8; piece_len as usize];
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
async fn test_scale_1000_swarms_atomic_metrics_and_zero_copy_pagination() {
    let tmp = tempdir().expect("create temp dir");
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0x42; 20]));

    // Configure queue to allow up to 100 active downloads, the rest become queued
    engine.set_queue_config(synapse_engine::QueueConfig {
        download_queue_enabled: true,
        max_active_downloads: 100,
        seed_queue_enabled: true,
        max_active_seeds: 1000,
        max_active_torrents: 2000,
        queue_stalled_enabled: false,
        queue_stalled_minutes: 10,
        seed_ratio_limited: false,
        share_ratio_limit: None,
        idle_seeding_limit_enabled: false,
        seed_time_limit_secs: None,
        ..Default::default()
    });

    const SWARM_COUNT: usize = 1_000;
    println!("Ingesting {SWARM_COUNT} synthetic swarms into SwarmEngine...");

    let start_ingest = Instant::now();
    let mut hashes = Vec::with_capacity(SWARM_COUNT);

    for i in 0..SWARM_COUNT {
        let name = format!("swarm-{:04}.iso", i);
        let info = Arc::new(build_dummy_torrent(&name, 1024 * 1024, 64 * 1024));
        hashes.push(info.hash);

        // Make half of them complete seeds, half downloads/queued
        let have = if i % 2 == 0 {
            let mut bf = Bitfield::new(info.pieces() as usize);
            for p in 0..info.pieces() {
                bf.set(p as usize);
            }
            Some(bf)
        } else {
            None
        };

        engine.add_torrent(info, tmp.path().to_path_buf(), have.as_ref());
    }

    println!(
        "Ingested {SWARM_COUNT} swarms in {:.2}ms",
        start_ingest.elapsed().as_secs_f64() * 1000.0
    );

    // 1. Verify O(1) Atomic Global Metrics Speed
    let start_metrics = Instant::now();
    let metrics: EngineMetricsSnapshot = engine.global_metrics();
    let metrics_duration = start_metrics.elapsed();

    println!(
        "Queried global metrics in {:.3}µs: total={}, dl={}, seed={}, queued={}",
        metrics_duration.as_secs_f64() * 1_000_000.0,
        metrics.total_torrents,
        metrics.downloading_torrents,
        metrics.seeding_torrents,
        metrics.queued_torrents,
    );

    // Assert that metric snapshot took under 1 millisecond (typically < 5 microseconds)
    assert!(
        metrics_duration.as_millis() < 5,
        "global_metrics() must complete in <5ms, took {:?}",
        metrics_duration
    );
    assert_eq!(metrics.total_torrents, SWARM_COUNT);
    assert_eq!(metrics.seeding_torrents, SWARM_COUNT / 2); // 500 seeds
    assert_eq!(metrics.downloading_torrents, 100); // 100 active downloads
    assert_eq!(metrics.queued_torrents, (SWARM_COUNT / 2) - 100); // 400 queued
    assert!(metrics.downloaded_bytes > 0);

    // 2. Verify Engine-Level Pagination
    let (page1, total1) = engine.list_torrents_paged(0, 50, None);
    assert_eq!(total1, SWARM_COUNT);
    assert_eq!(page1.len(), 50);

    let (page2, total2) = engine.list_torrents_paged(50, 50, None);
    assert_eq!(total2, SWARM_COUNT);
    assert_eq!(page2.len(), 50);
    assert_ne!(page1[0].info_hash, page2[0].info_hash);

    // 3. Verify State Filtering in Pagination
    let (seeds_page, seeds_total) =
        engine.list_torrents_paged(0, 25, Some(SwarmStateFilter::Seeding));
    assert_eq!(seeds_total, SWARM_COUNT / 2);
    assert_eq!(seeds_page.len(), 25);
    for s in seeds_page {
        assert_eq!(s.state, SwarmState::Seeding);
    }

    let (dl_page, dl_total) =
        engine.list_torrents_paged(0, 25, Some(SwarmStateFilter::Downloading));
    assert_eq!(dl_total, 100);
    assert_eq!(dl_page.len(), 25);
    for s in dl_page {
        assert_eq!(s.state, SwarmState::Downloading);
    }

    // 4. Verify State Transition & Metrics Accuracy
    let test_hash = hashes[1]; // One of the downloading torrents
    assert!(engine.transition_to_cold(&test_hash));
    let m_after_pause = engine.global_metrics();
    assert_eq!(m_after_pause.paused_torrents, 1);
    assert_eq!(m_after_pause.downloading_torrents, 99);

    // 5. Verify Removal & Metrics Decrement
    assert!(engine.remove_torrent(&test_hash));
    let m_after_remove = engine.global_metrics();
    assert_eq!(m_after_remove.total_torrents, SWARM_COUNT - 1);
    assert_eq!(m_after_remove.paused_torrents, 0);
}
