use std::sync::Arc;
use std::time::Instant;
use synapse_diskio::DiskEngine;
use synapse_engine::SwarmEngine;
use synapse_meta::Info;
use synapse_picker::Bitfield;
use tempfile::tempdir;

fn create_synthetic_info(index: usize) -> Info {
    let mut hash = [0u8; 20];
    hash[0..8].copy_from_slice(&(index as u64).to_be_bytes());
    hash[8..16].copy_from_slice(&(0x1337_c001_dead_beefu64).to_be_bytes());
    hash[16..20].copy_from_slice(&(index as u32).to_le_bytes());

    Info {
        name: format!("synthetic-scale-swarm-{index:06}"),
        announce: None,
        creator: None,
        comment: None,
        piece_len: 262144,
        total_len: 1048576,
        pieces: 4,
        hashes: parking_lot::RwLock::new(None),
        hash,
        files: Vec::new(),
        private: false,
        file_offsets: Vec::new(),
        url_list: Vec::new(),
        web_seeds: Vec::new(),
    }
}

#[tokio::test]
async fn test_scale_50k_swarms() {
    let tmp = tempdir().expect("tempdir");
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [2u8; 20]));

    const SWARM_COUNT: usize = 50_000;
    let have_complete = Bitfield::full(4);

    let start_load = Instant::now();
    let mut hashes = Vec::with_capacity(SWARM_COUNT);

    for i in 0..SWARM_COUNT {
        let info = Arc::new(create_synthetic_info(i));
        hashes.push(info.hash);
        // Initializing with complete bitfield puts them directly into SwarmTier::Warm (seeding standby)
        engine.add_torrent(info, tmp.path().to_path_buf(), Some(&have_complete));
    }
    let load_time = start_load.elapsed();
    println!("Loaded {SWARM_COUNT} swarms in {:.2?}", load_time);

    // 1. Verify 50,000 swarms are stored
    assert_eq!(engine.torrent_count(), SWARM_COUNT);

    // 2. Verify all are in Warm tier with zero active actor ticker tasks
    assert_eq!(engine.active_swarm_count(), 0);

    // 3. Verify global atomic metrics are O(1)
    let start_metrics = Instant::now();
    let metrics = engine.global_metrics();
    let metrics_time = start_metrics.elapsed();
    assert!(metrics_time.as_micros() < 500, "Metrics query took too long: {metrics_time:?}");
    assert_eq!(metrics.total_torrents, SWARM_COUNT);
    assert_eq!(metrics.seeding_torrents, SWARM_COUNT);
    assert_eq!(metrics.active_actors, 0);

    // 4. Verify zero-copy pagination returns page within low latency
    let start_page = Instant::now();
    let (page, total) = engine.list_torrents_paged(25_000, 50, None);
    let page_time = start_page.elapsed();
    assert_eq!(total, SWARM_COUNT);
    assert_eq!(page.len(), 50);
    assert!(page_time.as_millis() < 50, "Pagination took too long: {page_time:?}");

    // 5. Test wake-on-peer promotion to Hot tier
    let target_hash = hashes[12_345];
    assert!(engine.transition_to_hot(&target_hash));
    assert_eq!(engine.active_swarm_count(), 1);

    let updated_metrics = engine.global_metrics();
    assert_eq!(updated_metrics.active_actors, 1);
    assert_eq!(updated_metrics.seeding_torrents, SWARM_COUNT);

    // 6. Test demotion to Cold tier
    assert!(engine.transition_to_cold(&target_hash));
    assert_eq!(engine.active_swarm_count(), 0);

    let cold_metrics = engine.global_metrics();
    assert_eq!(cold_metrics.paused_torrents, 1);
    assert_eq!(cold_metrics.seeding_torrents, SWARM_COUNT - 1);
}
