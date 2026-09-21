use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod dht_bench;
mod disk_bench;
mod live_bench;
mod rpc_bench;
mod swarm_bench;
mod transfer_bench;

#[derive(Parser)]
#[command(
    name = "synapse-bench",
    version = "2.0.0",
    about = "High-performance Load Generator, Swarm Simulator & Benchmark Harness for Synapse 2.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Benchmark Swarm Engine scale and memory tier transitions (100 - 50,000 swarms)
    Swarm {
        #[arg(short, long, default_value_t = 10000)]
        count: usize,
    },
    /// Benchmark Disk I/O subsystem block reads and writes
    Disk {
        #[arg(short, long, default_value_t = 500)]
        size_mb: usize,
        #[arg(short, long, default_value_t = 16)]
        block_size_kb: usize,
    },
    /// Benchmark Kademlia DHT routing table lookup and packet throughput
    Dht {
        #[arg(short, long, default_value_t = 5000)]
        iterations: usize,
    },
    /// Benchmark synthetic P2P wire data transfer and SHA1 verification pipeline
    Transfer {
        #[arg(short, long, default_value_t = 100)]
        size_mb: usize,
    },
    /// Benchmark gRPC Control Plane under concurrent load
    Rpc {
        #[arg(short, long, default_value_t = 20)]
        concurrency: usize,
        #[arg(short, long, default_value_t = 100)]
        requests_per_worker: usize,
    },
    /// Live download monitoring of real WebTorrent swarms with Transmission-style queueing
    LiveDownload {
        /// Target torrent URL, magnet URI, local .torrent path, or sample name (bunny, sintel, cosmos, tears, wired)
        #[arg(short, long)]
        torrent: Option<String>,
        #[arg(short, long, default_value_t = 0)]
        duration_secs: u64,
        #[arg(short, long, default_value_t = 2)]
        max_downloads: usize,
        #[arg(long)]
        download_dir: Option<std::path::PathBuf>,
    },
    /// Run all benchmarks in sequence
    All,
}

#[tokio::main]
async fn main() {
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("synapse-debug.log");

    let file_layer = log_file.ok().map(|f| {
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(f)
    });

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            "debug,synapse_tracker=debug,synapse_engine=debug",
        ))
        .with(file_layer)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Swarm { count } => {
            swarm_bench::run_swarm_benchmark(count).await;
        }
        Commands::Disk {
            size_mb,
            block_size_kb,
        } => {
            disk_bench::run_disk_benchmark(size_mb, block_size_kb).await;
        }
        Commands::Dht { iterations } => {
            dht_bench::run_dht_benchmark(iterations).await;
        }
        Commands::Transfer { size_mb } => {
            transfer_bench::run_transfer_benchmark(size_mb).await;
        }
        Commands::Rpc {
            concurrency,
            requests_per_worker,
        } => {
            rpc_bench::run_rpc_benchmark(concurrency, requests_per_worker).await;
        }
        Commands::LiveDownload {
            torrent,
            duration_secs,
            max_downloads,
            download_dir,
        } => {
            live_bench::run_live_download_monitor(
                duration_secs,
                max_downloads,
                download_dir,
                torrent,
            )
            .await;
        }
        Commands::All => {
            println!("🚀 RUNNING FULL SYNAPSE 2.0 BENCHMARK & SIMULATION SUITE\n");
            swarm_bench::run_swarm_benchmark(5000).await;
            disk_bench::run_disk_benchmark(200, 16).await;
            dht_bench::run_dht_benchmark(2000).await;
            transfer_bench::run_transfer_benchmark(50).await;
            rpc_bench::run_rpc_benchmark(10, 50).await;
            println!("🎉 ALL BENCHMARKS COMPLETED SUCCESSFULLY!");
        }
    }
}
