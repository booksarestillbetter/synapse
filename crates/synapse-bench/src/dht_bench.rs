use rand::RngCore;
use std::net::SocketAddr;
use std::time::Instant;
use synapse_dht::node::spawn;
use synapse_dht::proto::NodeId;
use synapse_dht::routing::RoutingTable;
use tracing::info;

fn random_node_id() -> NodeId {
    let mut id = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

pub async fn run_dht_benchmark(iterations: usize) {
    info!(
        "🧪 Starting DHT Subsystem Benchmark (Iterations: {})",
        iterations
    );

    let local_id = random_node_id();
    let mut table = RoutingTable::new(local_id);

    // 1. Routing Table insertion & nearest-node lookup benchmark
    let start_rt = Instant::now();
    for i in 0..iterations {
        let mut id_bytes = [0u8; 20];
        let i_bytes = (i as u64).to_be_bytes();
        id_bytes[..8].copy_from_slice(&i_bytes);
        let addr = format!("127.0.0.1:{}", 10000 + (i % 50000))
            .parse()
            .unwrap();
        table.seen(id_bytes, addr, Instant::now());
    }
    let insert_duration = start_rt.elapsed();
    let insert_rate = (iterations as f64) / insert_duration.as_secs_f64();
    info!(
        "✅ Routing table inserted {} nodes in {:.3}s ({:.1} ops/sec)",
        iterations,
        insert_duration.as_secs_f64(),
        insert_rate
    );

    let start_lookup = Instant::now();
    for _ in 0..iterations {
        let target = random_node_id();
        let _closest = table.closest(&target, 8);
    }
    let lookup_duration = start_lookup.elapsed();
    let lookup_rate = (iterations as f64) / lookup_duration.as_secs_f64();
    info!(
        "✅ Performed {} nearest-node Kademlia lookups in {:.3}s ({:.1} lookups/sec)",
        iterations,
        lookup_duration.as_secs_f64(),
        lookup_rate
    );

    // 2. DHT Live Node Ping/Pong Loopback Benchmark
    let (node_a, _addr_a) = spawn(random_node_id(), "127.0.0.1:0".parse().unwrap())
        .await
        .expect("Spawn node A");
    let (_node_b, addr_b) = spawn(random_node_id(), "127.0.0.1:0".parse().unwrap())
        .await
        .expect("Spawn node B");

    let addr_b_v4 = match addr_b {
        SocketAddr::V4(v4) => v4,
        _ => panic!("Expected IPv4"),
    };

    let ping_count = iterations.min(1000); // UDP roundtrip benchmark
    let start_ping = Instant::now();
    for _ in 0..ping_count {
        let _pong = node_a.ping(addr_b_v4).await.expect("Ping failed");
    }
    let ping_duration = start_ping.elapsed();
    let ping_rate = (ping_count as f64) / ping_duration.as_secs_f64();
    let ping_avg_ms = (ping_duration.as_secs_f64() * 1000.0) / (ping_count as f64);
    info!(
        "✅ Completed {} UDP DHT ping roundtrips in {:.3}s ({:.1} rps, avg latency: {:.3}ms)",
        ping_count,
        ping_duration.as_secs_f64(),
        ping_rate,
        ping_avg_ms
    );

    println!("\n========================================================");
    println!("📊 SYNAPSE 2.0 DHT ENGINE BENCHMARK (N={})", iterations);
    println!("========================================================");
    println!("  • Routing Table Seen:    {:>10.1} ops/sec", insert_rate);
    println!(
        "  • Kademlia Closest:      {:>10.1} lookups/sec",
        lookup_rate
    );
    println!(
        "  • Live UDP Ping/Pong:    {:>10.1} req/sec ({:.2} ms/req)",
        ping_rate, ping_avg_ms
    );
    println!("========================================================\n");
}
