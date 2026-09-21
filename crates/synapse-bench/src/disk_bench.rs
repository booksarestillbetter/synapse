use bytes::Bytes;
use std::sync::Arc;
use std::time::Instant;
use synapse_diskio::{DiskEngine, ReadJob, WriteJob};
use tempfile::tempdir;
use tracing::info;

pub async fn run_disk_benchmark(total_mb: usize, block_size_kb: usize) {
    info!(
        "🧪 Starting Disk I/O Subsystem Benchmark (Data: {} MB, Block: {} KB)",
        total_mb, block_size_kb
    );

    let tmp = tempdir().expect("Failed to create tempdir");
    let target_file = Arc::new(tmp.path().join("bench_payload.dat"));
    let block_size = block_size_kb * 1024;
    let total_bytes = (total_mb as u64) * 1024 * 1024;
    let block_count = (total_bytes as usize) / block_size;

    let payload = Bytes::from(vec![0xAAu8; block_size]);
    let engine = DiskEngine::auto().await;

    // Sequential Write Benchmark
    let start_write = Instant::now();
    let mut write_jobs = Vec::with_capacity(block_count);
    for i in 0..block_count {
        let offset = (i * block_size) as u64;
        write_jobs.push(WriteJob {
            path: target_file.clone(),
            offset,
            data: payload.clone(),
            file_len: total_bytes,
        });
    }

    engine
        .write_batch(write_jobs)
        .await
        .expect("Write batch failed");
    engine.sync(target_file.clone()).await.expect("Sync failed");
    let write_duration = start_write.elapsed();
    let write_throughput = (total_mb as f64) / write_duration.as_secs_f64();
    info!(
        "✅ Sequential Write: {} MB in {:.3}s ({:.1} MB/s)",
        total_mb,
        write_duration.as_secs_f64(),
        write_throughput
    );

    // Sequential Read Benchmark
    let start_read = Instant::now();
    for i in 0..block_count {
        let offset = (i * block_size) as u64;
        let read_buf = engine
            .read(ReadJob {
                path: target_file.clone(),
                offset,
                len: block_size,
            })
            .await
            .expect("Read block failed");
        assert_eq!(read_buf.len(), block_size);
    }
    let read_duration = start_read.elapsed();
    let read_throughput = (total_mb as f64) / read_duration.as_secs_f64();
    info!(
        "✅ Sequential Read: {} MB in {:.3}s ({:.1} MB/s)",
        total_mb,
        read_duration.as_secs_f64(),
        read_throughput
    );

    println!("\n========================================================");
    println!(
        "📊 SYNAPSE 2.0 DISK I/O ENGINE BENCHMARK (Size: {} MB)",
        total_mb
    );
    println!("========================================================");
    println!("  • Block Size:            {:>10} KB", block_size_kb);
    println!("  • Total Blocks:          {:>10}", block_count);
    println!("  • Write Throughput:      {:>10.1} MB/s", write_throughput);
    println!("  • Read Throughput:       {:>10.1} MB/s", read_throughput);
    println!("========================================================\n");
}
