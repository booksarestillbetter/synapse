use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use synapse_diskio::DiskEngine;
use synapse_engine::SwarmEngine;
use synapse_rpc::proto::v2::synapse_control_client::SynapseControlClient;
use synapse_rpc::proto::v2::synapse_control_server::SynapseControlServer;
use synapse_rpc::proto::v2::{
    add_torrent_request, AddTorrentRequest, SessionStatsRequest, SubscribeTorrentsRequest,
};
use synapse_rpc::{EventBus, SynapseService};
use tokio_stream::StreamExt;
use tracing::info;

pub async fn run_rpc_benchmark(concurrency: usize, requests_per_worker: usize) {
    info!(
        "🧪 Starting gRPC Control Plane Benchmark (Workers: {}, Reqs/Worker: {})",
        concurrency, requests_per_worker
    );

    let disk = Arc::new(DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [1u8; 20]));
    let bus = Arc::new(EventBus::new(4096));
    let service = SynapseService::new(bus).with_swarm_engine(engine);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr: SocketAddr = listener.local_addr().expect("local_addr");
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(SynapseControlServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .expect("server run");
    });

    // Warm up
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    let endpoint = format!("http://{}", addr);

    // 1. Session stats stress benchmark
    let total_reqs = concurrency * requests_per_worker;
    let start_stats = Instant::now();
    let mut handles = Vec::new();

    for _ in 0..concurrency {
        let ep = endpoint.clone();
        let handle = tokio::spawn(async move {
            let mut client = SynapseControlClient::connect(ep).await.expect("connect");
            for _ in 0..requests_per_worker {
                let _resp = client
                    .get_session_stats(SessionStatsRequest {})
                    .await
                    .expect("get_session_stats");
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.expect("join handle");
    }
    let stats_duration = start_stats.elapsed();
    let stats_rps = (total_reqs as f64) / stats_duration.as_secs_f64();
    let stats_avg_ms = (stats_duration.as_secs_f64() * 1000.0) / (total_reqs as f64);
    info!(
        "✅ Performed {} GetSessionStats gRPC calls in {:.3}s ({:.1} req/sec, avg {:.3}ms)",
        total_reqs,
        stats_duration.as_secs_f64(),
        stats_rps,
        stats_avg_ms
    );

    // 2. AddTorrent burst benchmark
    let mut add_handles = Vec::new();
    let start_add = Instant::now();
    for worker_id in 0..concurrency {
        let ep = endpoint.clone();
        let handle = tokio::spawn(async move {
            let mut client = SynapseControlClient::connect(ep).await.expect("connect");
            for req_id in 0..requests_per_worker {
                let magnet = format!(
                    "magnet:?xt=urn:btih:{:040x}&dn=synthetic-item-{}-{}",
                    (worker_id * 100000 + req_id + 1),
                    worker_id,
                    req_id
                );
                let req = AddTorrentRequest {
                    source: Some(add_torrent_request::Source::MagnetUri(magnet)),
                    download_dir: Some("/tmp/bench_downloads".to_string()),
                    start_paused: Some(false),
                };
                let _resp = client.add_torrent(req).await.expect("add_torrent");
            }
        });
        add_handles.push(handle);
    }

    for h in add_handles {
        h.await.expect("join add handle");
    }
    let add_duration = start_add.elapsed();
    let add_rps = (total_reqs as f64) / add_duration.as_secs_f64();
    let add_avg_ms = (add_duration.as_secs_f64() * 1000.0) / (total_reqs as f64);
    info!(
        "✅ Dispatched {} AddTorrent gRPC mutations in {:.3}s ({:.1} req/sec, avg {:.3}ms)",
        total_reqs,
        add_duration.as_secs_f64(),
        add_rps,
        add_avg_ms
    );

    // 3. SubscribeTorrents delta streaming latency benchmark
    let mut stream_client = SynapseControlClient::connect(endpoint.clone())
        .await
        .expect("connect");
    let stream_req = SubscribeTorrentsRequest {
        chunk_size: 500,
        flush_window_ms: 100,
    };
    let mut stream = stream_client
        .subscribe_torrents(stream_req)
        .await
        .expect("subscribe")
        .into_inner();

    let start_stream = Instant::now();
    let mut received_events = 0;
    while let Some(Ok(_event)) = stream.next().await {
        received_events += 1;
        if received_events >= 1 {
            break;
        }
    }
    let stream_duration = start_stream.elapsed();
    info!(
        "✅ Streamed initial snapshot chunks in {:.3}ms",
        stream_duration.as_secs_f64() * 1000.0
    );

    println!("\n========================================================");
    println!("📊 SYNAPSE 2.0 gRPC CONTROL PLANE LOAD BENCHMARK");
    println!("========================================================");
    println!("  • Concurrency Workers:   {:>10}", concurrency);
    println!("  • Total RPC Requests:    {:>10}", total_reqs);
    println!(
        "  • GetSessionStats Throughput: {:>6.1} req/sec ({:.2} ms/req)",
        stats_rps, stats_avg_ms
    );
    println!(
        "  • AddTorrent Mutation Throughput: {:>6.1} req/sec ({:.2} ms/req)",
        add_rps, add_avg_ms
    );
    println!(
        "  • Snapshot Stream Latency: {:>8.2} ms",
        stream_duration.as_secs_f64() * 1000.0
    );
    println!("========================================================\n");
}
