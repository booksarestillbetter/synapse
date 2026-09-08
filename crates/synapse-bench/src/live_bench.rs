use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tracing::info;

use synapse_diskio::DiskEngine;
use synapse_engine::{QueueConfig, SwarmEngine, SwarmState};

pub const DEFAULT_WEBTORRENT_URLS: &[&str] = &[
    "https://webtorrent.io/torrents/big-buck-bunny.torrent",
    "https://webtorrent.io/torrents/cosmos-laundromat.torrent",
    "https://webtorrent.io/torrents/sintel.torrent",
    "https://webtorrent.io/torrents/tears-of-steel.torrent",
    "https://webtorrent.io/torrents/wired-cd.torrent",
];

fn resolve_preset_or_url(input: &str) -> String {
    let lower = input.to_lowercase();
    match lower.as_str() {
        "bunny" | "big-buck-bunny" => "https://webtorrent.io/torrents/big-buck-bunny.torrent".to_string(),
        "cosmos" | "cosmos-laundromat" => "https://webtorrent.io/torrents/cosmos-laundromat.torrent".to_string(),
        "sintel" => "https://webtorrent.io/torrents/sintel.torrent".to_string(),
        "tears" | "tears-of-steel" => "https://webtorrent.io/torrents/tears-of-steel.torrent".to_string(),
        "wired" | "wired-cd" => "https://webtorrent.io/torrents/wired-cd.torrent".to_string(),
        _ => {
            if input.starts_with("~/") || input == "~" {
                if let Some(home) = std::env::var_os("HOME") {
                    let mut path = std::path::PathBuf::from(home);
                    if input.len() > 2 {
                        path.push(&input[2..]);
                    }
                    return path.to_string_lossy().to_string();
                }
            }
            input.to_string()
        }
    }
}

pub async fn run_live_download_monitor(
    duration_secs: u64,
    max_active_downloads: usize,
    custom_dir: Option<PathBuf>,
    single_target: Option<String>,
) {
    println!("🚀 INITIALIZING SYNAPSE 2.0 LIVE DOWNLOAD MONITOR");

    let _temp_guard;
    let download_dir = if let Some(dir) = custom_dir {
        std::fs::create_dir_all(&dir).ok();
        dir
    } else {
        _temp_guard = tempdir().expect("create temp dir");
        _temp_guard.path().to_path_buf()
    };

    println!("📂 Target Download Directory: {}", download_dir.display());

    let disk = Arc::new(DiskEngine::auto().await);
    let mut peer_id = [0x53; 20];
    peer_id[0..8].copy_from_slice(b"-TR4050-");
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut peer_id[8..]);

    let swarm = Arc::new(SwarmEngine::new(disk, peer_id));
    swarm.set_queue_config(QueueConfig {
        download_queue_enabled: true,
        max_active_downloads: if single_target.is_some() { 1 } else { max_active_downloads },
        seed_queue_enabled: true,
        max_active_seeds: 10,
        max_active_torrents: 20,
        queue_stalled_enabled: true,
        queue_stalled_minutes: 1,
        seed_ratio_limited: false,
        share_ratio_limit: None,
        idle_seeding_limit_enabled: false,
        seed_time_limit_secs: None,
    });

    let target_urls: Vec<String> = if let Some(ref target) = single_target {
        vec![resolve_preset_or_url(target)]
    } else {
        DEFAULT_WEBTORRENT_URLS.iter().map(|s| s.to_string()).collect()
    };

    println!("🔄 Ingesting torrent(s)...");

    let mut loaded_handles = Vec::new();
    for url in &target_urls {
        info!("Fetching torrent from: {}", url);
        match synapse_rpc::fetch_or_parse_torrent(url).await {
            Ok(info) => {
                let info_arc = Arc::new(info);
                let handle = swarm.add_torrent(info_arc.clone(), download_dir.clone(), None);
                println!(
                    "  [+] Ingested: {:<30} (Size: {:>4} MB, Pieces: {}, Hash: {})",
                    info_arc.name,
                    info_arc.total_len / (1024 * 1024),
                    info_arc.pieces(),
                    hex::encode(info_arc.hash)
                );
                loaded_handles.push(handle);
            }
            Err(e) => {
                println!("  [-] Failed to load {}: {}", url, e);
            }
        }
    }

    if loaded_handles.is_empty() {
        eprintln!("❌ No torrents could be loaded. Exiting.");
        return;
    }

    let is_single = loaded_handles.len() == 1;

    let start_time = tokio::time::Instant::now();
    let mut interval = tokio::time::interval(Duration::from_millis(1000));

    loop {
        interval.tick().await;
        swarm.reconcile_queue();

        let elapsed = start_time.elapsed().as_secs_f32();
        if duration_secs > 0 && elapsed >= duration_secs as f32 {
            break;
        }

        if is_single {
            let handle = &loaded_handles[0];
            let s = handle.stats.read().clone();
            let total_pieces = handle.info.pieces() as usize;
            let have_pieces = (s.progress * total_pieces as f32).round() as usize;

            let state_str = match s.state {
                SwarmState::Downloading => "📥 Downloading",
                SwarmState::Queued => "⏳ Queued",
                SwarmState::Seeding => "🌱 Seeding (Complete)",
                SwarmState::Checking => "🔍 Checking",
                SwarmState::Stopped => "⏹ Stopped",
                SwarmState::Error(ref e) => e.as_str(),
            };

            let percent = (s.progress * 100.0).clamp(0.0, 100.0);
            let bar_len: usize = 30;
            let filled = ((percent / 100.0) * bar_len as f32).round() as usize;
            let empty = bar_len.saturating_sub(filled);
            let bar: String = format!("[{}{}]", "█".repeat(filled), "░".repeat(empty));

            print!("\x1B[2J\x1B[1;1H"); // ANSI clear screen & home cursor
            println!("==========================================================================================");
            println!("  SYNAPSE 2.0 LIVE TORRENT DOWNLOAD MONITOR");
            println!("==========================================================================================");
            println!("  Name:             {}", handle.info.name);
            println!("  Info Hash:        {}", hex::encode(handle.info.hash));
            println!("  Files Count:      {}", handle.info.files.len());
            println!("  Total Size:       {:.2} MB", (handle.info.total_len as f64) / (1024.0 * 1024.0));
            println!("  Download Dir:     {}", download_dir.display());
            println!("------------------------------------------------------------------------------------------");
            println!("  Status:           {}", state_str);
            println!("  Progress:         {} {:>6.2}%", bar, percent);
            println!("  Pieces:           {} / {} pieces", have_pieces, total_pieces);
            println!("  Downloaded:       {:.2} MB / {:.2} MB", (s.downloaded_bytes as f64) / (1024.0 * 1024.0), (s.total_size as f64) / (1024.0 * 1024.0));
            println!("  Uploaded:         {:.2} MB", (s.uploaded_bytes as f64) / (1024.0 * 1024.0));
            println!("  Download Speed:   {:.2} KB/s ({:.2} Mbps)", (s.download_rate as f64) / 1024.0, ((s.download_rate * 8) as f64) / (1024.0 * 1024.0));
            println!("  Upload Speed:     {:.2} KB/s", (s.upload_rate as f64) / 1024.0);
            println!("  Connected Peers:  {} (Sending: {})", s.peers_connected, s.peers_sending);
            println!("  ETA:              {}s", if s.eta_seconds > 0 { s.eta_seconds.to_string() } else { "N/A".to_string() });
            println!("  Elapsed Time:     {:.1}s", elapsed);
            println!("==========================================================================================");
            println!("  (Press Ctrl+C to stop)");

            if s.progress >= 1.0 {
                println!("\n🎉 Download 100% completed successfully!");
                break;
            }
        } else {
            println!(
                "\n⏱ Elapsed: {:>5.1}s / {:>3}s | Swarms: {}",
                elapsed,
                duration_secs,
                swarm.torrent_count()
            );
            println!("{:-<100}", "");
            println!(
                "{:<26} | {:<12} | {:<8} | {:<10} | {:<7} | {:<10} | {:<10}",
                "Torrent Name", "State", "Stalled?", "Progress", "Peers", "Down Rate", "Downloaded"
            );
            println!("{:-<100}", "");

            for handle in &loaded_handles {
                let s = handle.stats.read().clone();
                let state_str = match s.state {
                    SwarmState::Downloading => "Downloading",
                    SwarmState::Queued => "Queued",
                    SwarmState::Seeding => "Seeding",
                    SwarmState::Checking => "Checking",
                    SwarmState::Stopped => "Stopped",
                    SwarmState::Error(ref e) => e.as_str(),
                };

                let name_trunc = if s.name.len() > 26 {
                    format!("{}...", &s.name[0..23])
                } else {
                    s.name.clone()
                };

                println!(
                    "{:<26} | {:<12} | {:<8} | {:>6.2}%    | {:>5} | {:>6.1} KB/s | {:>6.1} MB",
                    name_trunc,
                    state_str,
                    if s.is_stalled { "YES" } else { "NO" },
                    s.progress * 100.0,
                    s.peers_connected,
                    (s.download_rate as f64) / 1024.0,
                    (s.downloaded_bytes as f64) / (1024.0 * 1024.0)
                );
            }
        }
    }

    println!("\n==========================================================================================");
    println!("🏁 LIVE DOWNLOAD MONITOR FINISHED");
    println!("==========================================================================================");
}
