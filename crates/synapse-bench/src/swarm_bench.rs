use std::sync::Arc;
use std::time::Instant;
use synapse_diskio::DiskEngine;
use synapse_engine::SwarmEngine;
use synapse_meta::Info;
use tempfile::tempdir;
use tracing::info;

fn create_synthetic_info(index: usize) -> Info {
    let mut hash = [0u8; 20];
    hash[0..8].copy_from_slice(&(index as u64).to_be_bytes());
    hash[8..16].copy_from_slice(&(0xcafe_beef_dead_f00du64).to_be_bytes());
    hash[16..20].copy_from_slice(&(index as u32).to_le_bytes());

    Info {
        name: format!("synthetic-swarm-{index:06}"),
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

pub async fn run_swarm_benchmark(count: usize) {
    info!("🧪 Starting Swarm Engine Scalability Benchmark (Count: {} swarms)", count);

    let tmp = tempdir().expect("Failed to create tempdir");
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [1u8; 20]));

    let start_add = Instant::now();
    let mut hashes = Vec::with_capacity(count);

    for i in 0..count {
        let info = create_synthetic_info(i);
        let hash = info.hash;
        engine.add_torrent(Arc::new(info), tmp.path().to_path_buf(), None);
        hashes.push(hash);
    }
    let add_duration = start_add.elapsed();
    let add_rate = (count as f64) / add_duration.as_secs_f64();
    info!("✅ Ingested {} swarms in {:.3}s ({:.1} swarms/sec)", count, add_duration.as_secs_f64(), add_rate);

    let active_after_ingest = engine.active_swarm_count();

    // Benchmark atomic O(1) global metrics query
    let metric_queries = 10_000;
    let start_metrics = Instant::now();
    for _ in 0..metric_queries {
        let _ = engine.global_metrics();
    }
    let metrics_duration = start_metrics.elapsed();
    let metrics_avg_ns = metrics_duration.as_nanos() as f64 / metric_queries as f64;

    // Benchmark zero-copy paginated read (50 swarms)
    let paged_queries = 1000;
    let start_paged = Instant::now();
    for i in 0..paged_queries {
        let offset = (i * 37) % count.saturating_sub(50).max(1);
        let (page, total) = engine.list_torrents_paged(offset, 50, None);
        assert_eq!(total, count);
        assert!(page.len() <= 50);
    }
    let paged_duration = start_paged.elapsed();
    let paged_avg_us = (paged_duration.as_micros() as f64) / paged_queries as f64;

    // Test tier transitions: Demote all to Cold Tier
    let start_demote = Instant::now();
    for hash in &hashes {
        engine.transition_to_cold(hash);
    }
    let demote_duration = start_demote.elapsed();
    let demote_rate = (count as f64) / demote_duration.as_secs_f64();
    let active_after_cold = engine.active_swarm_count();
    info!("✅ Demoted {} swarms to Cold Tier in {:.3}s ({:.1} transitions/sec)", count, demote_duration.as_secs_f64(), demote_rate);

    // Promote all to Hot Tier
    let start_promote = Instant::now();
    for hash in &hashes {
        engine.transition_to_hot(hash);
    }
    let promote_duration = start_promote.elapsed();
    let promote_rate = (count as f64) / promote_duration.as_secs_f64();
    let active_after_hot = engine.active_swarm_count();
    info!("✅ Promoted {} swarms to Hot Tier in {:.3}s ({:.1} transitions/sec)", count, promote_duration.as_secs_f64(), promote_rate);

    // List all
    let start_list = Instant::now();
    let listed = engine.list_torrents();
    let list_duration = start_list.elapsed();
    assert_eq!(listed.len(), count);
    info!("✅ Listed {} full swarm summaries in {:.3}ms", listed.len(), list_duration.as_secs_f64() * 1000.0);

    println!("\n===============================================================================");
    println!("📊 SYNAPSE 2.0 50K SWARM SCALABILITY BENCHMARK RESULTS (N = {})", count);
    println!("===============================================================================");
    println!("  • Ingestion Throughput:         {:>10.1} swarms/sec", add_rate);
    println!("  • Cold Tier Demotion:           {:>10.1} ops/sec", demote_rate);
    println!("  • Hot Tier Promotion:            {:>10.1} ops/sec", promote_rate);
    println!("  • Active Swarm Actors (Cold):   {:>10} active", active_after_cold);
    println!("  • Active Swarm Actors (Hot):    {:>10} active", active_after_hot);
    println!("  • Active Swarm Actors (Queued): {:>10} active", active_after_ingest);
    println!("  • Global O(1) Metrics Query:    {:>10.2} ns/query", metrics_avg_ns);
    println!("  • Paginated List (50 items):    {:>10.2} µs/page", paged_avg_us);
    println!("  • Full Scan List ({} items): {:>10.3} ms", count, list_duration.as_secs_f64() * 1000.0);
    println!("===============================================================================\n");
}
