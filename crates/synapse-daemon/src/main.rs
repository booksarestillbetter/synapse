//! Entry point for Synapse 2.0 BitTorrent Daemon.
//!
//! Wires together the high-performance async runtime, zero-copy disk engine (io_uring / POSIX),
//! multi-torrent SwarmEngine, and the Tonic gRPC / streaming delta control plane.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use clap::Parser;
use diskio::{DiskEngine, ReadJob, WriteJob};
use synapse_config::Config;
use synapse_engine::SwarmEngine;
use synapse_rpc::proto_v2::synapse_control_server::SynapseControlServer;
use synapse_rpc::{EventBus, SynapseService};

mod inspect;
mod logging;
mod migrate;

#[derive(Parser)]
#[command(
    name = "synapsed",
    about = "Synapse 2.0 — High-Scale Next-Gen BitTorrent Daemon"
)]
struct Args {
    /// Path to a config file. Defaults to the platform config dir's synapse.toml, or
    /// built-in defaults if that doesn't exist either.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Optional HTTP API & Web UI listen address override (e.g. 0.0.0.0:8080 or 127.0.0.1:8080)
    #[arg(long)]
    http_addr: Option<SocketAddr>,

    /// Optional HTTP API & Web UI listen port override (e.g. 8080 or 9091)
    #[arg(long)]
    http_port: Option<u16>,

    /// Enable DHT read-only mode (BEP 43: do not add self to other nodes' routing tables)
    #[arg(long)]
    dht_read_only: bool,

    #[command(subcommand)]
    command: Option<Subcommand>,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    /// Migrate session state and torrents from other BitTorrent clients
    Migrate {
        #[command(subcommand)]
        client: MigrateClient,
    },
    /// Inspect and validate .torrent files without loading or running them
    Inspect {
        /// Files or directories to examine (scans directories recursively for .torrent files)
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Print verbose details (file tree, tracker tiers, web seeds)
        #[arg(short, long)]
        verbose: bool,

        /// Directory of trusted signer certificates for checking BEP 35 signatures
        #[arg(long)]
        trust_dir: Option<PathBuf>,
    },
    /// Create a .torrent file from a file or directory
    Create {
        /// The file or directory to share
        path: PathBuf,

        /// Where to write the .torrent (default: <name>.torrent in the current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Tracker announce URL (repeat for more; each is its own tier unless --same-tier)
        #[arg(short, long = "tracker")]
        trackers: Vec<String>,

        /// Put all trackers in one tier
        #[arg(long)]
        same_tier: bool,

        /// Web seed URL (BEP 19)
        #[arg(short, long = "webseed")]
        web_seeds: Vec<String>,

        /// Comment stored in the torrent
        #[arg(short, long)]
        comment: Option<String>,

        /// Mark the torrent private (BEP 27)
        #[arg(long)]
        private: bool,

        /// `source` tag for trackers that require one
        #[arg(long)]
        source: Option<String>,

        /// Piece size in KiB (a power of two, at least 16); default depends on the total size
        #[arg(long)]
        piece_size: Option<u32>,

        /// Create a BitTorrent v2 torrent (BEP 52) instead of v1
        #[arg(long, conflicts_with = "hybrid")]
        v2: bool,

        /// Create a hybrid v1+v2 torrent
        #[arg(long)]
        hybrid: bool,
    },
}

#[derive(clap::Subcommand)]
enum MigrateClient {
    /// Migrate from Transmission (reads .torrent and .resume directories)
    Transmission {
        /// Source Transmission directory containing 'Torrents' and 'Resume' folders.
        /// Defaults to platform location (~/Library/Application Support/Transmission on macOS, ~/.config/transmission on Linux).
        #[arg(short, long)]
        transmission_dir: Option<PathBuf>,

        /// Destination Synapse session directory. Defaults to configured session_dir.
        #[arg(short, long)]
        synapse_dir: Option<PathBuf>,

        /// Preview migration items and verification without writing changes.
        #[arg(long)]
        dry_run: bool,
    },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = Args::parse();

    if let Some(Subcommand::Migrate { client }) = args.command {
        match client {
            MigrateClient::Transmission {
                transmission_dir,
                synapse_dir,
                dry_run,
            } => {
                let trans_dir = transmission_dir
                    .or_else(migrate::default_transmission_dir)
                    .unwrap_or_else(|| PathBuf::from("./Transmission"));

                let target_dir = synapse_dir.unwrap_or_else(migrate::default_synapse_session_dir);

                println!("📦 Synapse 2.0 Migration Tool — Transmission Importer");
                println!("📂 Source Transmission Directory: {}", trans_dir.display());
                println!("📂 Target Synapse Directory:      {}", target_dir.display());
                if dry_run {
                    println!("🔍 Mode: DRY-RUN (Previewing without modifying files)\n");
                } else {
                    println!("🚀 Mode: LIVE MIGRATION\n");
                }

                match migrate::migrate_transmission(&trans_dir, &target_dir, dry_run) {
                    Ok(result) => {
                        println!("{:-<100}", "");
                        println!(
                            "{:<40} {:<12} {:<12} {:<20} {:<12}",
                            "NAME", "HASH", "SIZE", "PROGRESS", "STATE"
                        );
                        println!("{:-<100}", "");
                        for entry in &result.found {
                            let size_mb = (entry.total_size as f64) / 1024.0 / 1024.0;
                            let pct = if entry.total_pieces > 0 {
                                (entry.completed_pieces as f64 / entry.total_pieces as f64) * 100.0
                            } else {
                                0.0
                            };
                            let state_str = if entry.is_paused {
                                "Paused"
                            } else if pct >= 100.0 {
                                "Seeding"
                            } else {
                                "Downloading"
                            };
                            let hash_short =
                                &entry.info_hash_hex[..8.min(entry.info_hash_hex.len())];
                            let name_truncated = if entry.name.len() > 38 {
                                format!("{}...", &entry.name[..35])
                            } else {
                                entry.name.clone()
                            };
                            println!(
                                "{:<40} {:<12} {:>8.1} MB {:>6.1}% ({:>4}/{:<4}) {:<12}",
                                name_truncated,
                                hash_short,
                                size_mb,
                                pct,
                                entry.completed_pieces,
                                entry.total_pieces,
                                state_str
                            );
                        }
                        println!("{:-<100}", "");
                        if dry_run {
                            println!("\n✅ Found {} torrent(s) ready to migrate. Run without --dry-run to write session files.", result.found.len());
                        } else {
                            println!(
                                "\n🎉 Successfully migrated {}/{} torrent(s) to Synapse!",
                                result.migrated,
                                result.found.len()
                            );
                            if !result.errors.is_empty() {
                                println!("⚠️ Warnings / Errors ({}):", result.errors.len());
                                for err in &result.errors {
                                    println!("  - {}", err);
                                }
                            }
                            println!("🚀 Start Synapse daemon to activate restored torrents: cargo run --release -p synapsed");
                        }
                        return std::process::ExitCode::SUCCESS;
                    }
                    Err(e) => {
                        eprintln!("❌ Migration failed: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                }
            }
        }
    } else if let Some(Subcommand::Create {
        path,
        output,
        trackers,
        same_tier,
        web_seeds,
        comment,
        private,
        source,
        piece_size,
        v2,
        hybrid,
    }) = args.command
    {
        let tiers = if same_tier {
            vec![trackers]
        } else {
            trackers.into_iter().map(|t| vec![t]).collect()
        };
        let opts = synapse_meta::create::CreateOptions {
            piece_length: piece_size.map(|k| k.saturating_mul(1024)),
            trackers: tiers,
            web_seeds,
            comment,
            created_by: Some(format!("Synapse/{}", env!("CARGO_PKG_VERSION"))),
            private,
            source,
            name: None,
            version: if hybrid {
                synapse_meta::create::TorrentVersion::Hybrid
            } else if v2 {
                synapse_meta::create::TorrentVersion::V2
            } else {
                synapse_meta::create::TorrentVersion::V1
            },
            creation_date: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs() as i64),
        };
        let mut last_pct = 101;
        let result = synapse_meta::create::create_torrent(&path, &opts, |done, total| {
            let pct = (done * 100).checked_div(total).unwrap_or(100) as i32;
            if pct != last_pct {
                last_pct = pct;
                eprint!("\rHashing... {pct}%");
            }
        });
        eprintln!();
        return match result {
            Ok(bytes) => {
                let out = output.unwrap_or_else(|| {
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "torrent".into());
                    PathBuf::from(format!("{name}.torrent"))
                });
                match std::fs::write(&out, &bytes) {
                    Ok(()) => {
                        let hash = synapse_meta::Info::from_torrent_bytes(&bytes)
                            .map(|i| hex::encode(i.hash))
                            .unwrap_or_default();
                        println!(
                            "Wrote {} ({} bytes), info hash {hash}",
                            out.display(),
                            bytes.len()
                        );
                        std::process::ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("cannot write {}: {e}", out.display());
                        std::process::ExitCode::FAILURE
                    }
                }
            }
            Err(e) => {
                eprintln!("cannot create the torrent: {e}");
                std::process::ExitCode::FAILURE
            }
        };
    } else if let Some(Subcommand::Inspect {
        paths,
        verbose,
        trust_dir,
    }) = args.command
    {
        if let Some(dir) = trust_dir {
            let (store, problems) = synapse_meta::TrustStore::load_dir(&dir);
            for p in problems {
                eprintln!("warning: {p}");
            }
            inspect::set_trust_store(store);
        }
        let result = inspect::inspect_paths(&paths);
        if result.diagnostics.is_empty() {
            println!("🔍 No .torrent files found in specified path(s).");
            return std::process::ExitCode::SUCCESS;
        }

        println!("🔬 Synapse 2.0 Torrent Inspector & Format Validator");
        println!("{:=<110}", "");
        for diag in &result.diagnostics {
            let status_icon = if diag.is_valid && diag.warnings.is_empty() {
                "✅ VALID"
            } else if diag.is_valid {
                "⚠️  VALID (WITH WARNINGS)"
            } else {
                "❌ INVALID / REJECTED"
            };

            let size_mb = (diag.total_size_bytes as f64) / 1024.0 / 1024.0;
            println!("📄 File:         {}", diag.file_path.display());
            println!("🏷️  Name:         {}", diag.name);
            println!(
                "🔑 Info Hash:    {}",
                if diag.info_hash_hex.is_empty() {
                    "N/A"
                } else {
                    &diag.info_hash_hex
                }
            );
            println!("📦 Format:       {}", diag.format_type);
            if let Some(ref root_v1) = diag.root_hash_v1_hex {
                println!("🌳 Merkle Root:  {} (BEP 30 SHA-1)", root_v1);
            }
            if diag.is_signed {
                println!(
                    "✍️  Signatures:   {} signature(s) embedded (BEP 35)",
                    diag.signatures_count
                );
            }
            println!(
                "📊 Payload Size: {:.2} MB ({} bytes, {} file(s))",
                size_mb, diag.total_size_bytes, diag.files_count
            );
            if diag.piece_length > 0 {
                println!(
                    "🧩 Pieces:       {} pieces × {} KB",
                    diag.total_pieces,
                    diag.piece_length / 1024
                );
            }
            println!(
                "🔒 Privacy:      {}",
                if diag.is_private {
                    "Private Swarm (DHT/PEX disabled)"
                } else {
                    "Public Swarm"
                }
            );
            let trackers_str = if diag.trackers.is_empty() {
                "None (Trackers omitted)".to_string()
            } else if verbose {
                diag.trackers.join("\n                 ")
            } else {
                diag.trackers.join(", ")
            };
            println!("📡 Trackers:     {}", trackers_str);
            if !diag.web_seeds.is_empty() {
                println!("🌐 Web Seeds:    {}", diag.web_seeds.join(", "));
            }
            if let Some(ref cr) = diag.creator {
                println!("🛠️  Created By:   {}", cr);
            }
            if let Some(ref cd) = diag.creation_date {
                println!("📅 Created At:   {}", cd);
            }
            if let Some(ref cm) = diag.comment {
                println!("💬 Comment:      {}", cm);
            }
            println!("🚦 Status:       {}", status_icon);

            if !diag.warnings.is_empty() {
                println!("⚠️  Warnings ({}):", diag.warnings.len());
                for w in &diag.warnings {
                    println!("   • {}", w);
                }
            }
            if !diag.errors.is_empty() {
                println!("❌ Errors ({}):", diag.errors.len());
                for e in &diag.errors {
                    println!("   • {}", e);
                }
            }
            println!("{:-<110}", "");
        }

        println!("\n📊 Batch Inspection Summary:");
        println!("   Total Torrents Scanned: {}", result.total_scanned);
        println!("   Valid Torrents:         {}", result.total_valid);
        println!("   Invalid / Errors:       {}", result.total_errors);
        println!("   Warnings Count:         {}", result.total_warnings);
        let total_mb = (result.total_payload_bytes as f64) / 1024.0 / 1024.0;
        println!("   Total Swarm Payload:    {:.2} MB\n", total_mb);

        return if result.total_errors == 0 {
            std::process::ExitCode::SUCCESS
        } else {
            std::process::ExitCode::FAILURE
        };
    }

    let mut config = match Config::load(args.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    if args.dht_read_only {
        config.network.dht_read_only = true;
    }

    // Outbound proxy (SOCKS5 / HTTP CONNECT). In anonymous mode nothing that could bypass it runs.
    match config.proxy.kind.to_ascii_lowercase().as_str() {
        "none" | "" => {}
        kind @ ("socks5" | "http") => {
            if config.proxy.host.trim().is_empty() {
                eprintln!("proxy.type is {kind} but proxy.host is empty");
                return std::process::ExitCode::FAILURE;
            }
            let settings = synapse_engine::proxy::ProxySettings {
                kind: if kind == "socks5" {
                    synapse_engine::proxy::ProxyKind::Socks5
                } else {
                    synapse_engine::proxy::ProxyKind::Http
                },
                host: config.proxy.host.trim().to_string(),
                port: config.proxy.port,
                auth: config
                    .proxy
                    .username
                    .clone()
                    .map(|u| (u, config.proxy.password.clone().unwrap_or_default())),
                proxy_peer_connections: config.proxy.proxy_peer_connections,
                proxy_http: config.proxy.proxy_tracker_connections,
                proxy_hostnames: config.proxy.proxy_hostnames,
                force_proxy: config.proxy.force_proxy,
            };
            if settings.force_proxy {
                config.network.enable_dht = false;
                config.network.enable_lsd = false;
                config.network.enable_zeroconf = false;
                config.network.enable_utp = false;
                config.network.enable_nat = false;
                config.privacy.disable_dht_globally = true;
            }
            synapse_engine::proxy::set_global(Some(settings));
        }
        other => {
            eprintln!("proxy.type must be none, socks5 or http (got {other:?})");
            return std::process::ExitCode::FAILURE;
        }
    }
    let force_proxy = synapse_engine::proxy::force_proxy();

    logging::init_logging(&config);

    tune_system_limits();

    tracing::info!("🐕 Synapse 2.0 Daemon starting...");

    // Initialize Zero-Copy Disk Engine
    let disk = Arc::new(DiskEngine::auto_with_max_open_files(config.disk.max_open_files).await);
    if let Err(e) = startup_self_check(&disk, &config.disk.session_dir).await {
        tracing::error!("disk engine startup self-check failed: {e}");
        return std::process::ExitCode::FAILURE;
    }
    tracing::info!("✅ Storage subsystem verified (io_uring / direct I/O active)");

    // Generate local daemon peer_id: -SY2200-<12 random bytes>
    // INVARIANT: Synapse follows strict Azureus-style BEP 20 identification (-SY2200-).
    // The peer ID prefix is intentionally hardcoded and non-customizable by end users
    // or configuration to prevent tracker fingerprint distortion, swarm desynchronization,
    // or client spoofing. Changes to this prefix must only occur upon engine version bumps.
    let peer_id = synapse_engine::generate_peer_id();

    // Initialize Session Store and Conduit Lifecycle Dispatcher
    let session_store = match synapse_engine::SessionStore::new(&config.disk.session_dir) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!("failed to initialize session store: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let instructions_cfg = &config.lifecycle.instructions;
    let instructions = match (instructions_cfg.enabled, instructions_cfg.url.clone()) {
        (true, Some(url)) if !url.trim().is_empty() => {
            tracing::info!("📡 Completion instructions webhook enabled: {}", url);
            Some(synapse_engine::InstructionsConfig {
                url,
                token: instructions_cfg.token.clone(),
                node_name: instructions_cfg.node_name.clone(),
                timeout: Duration::from_secs(instructions_cfg.timeout_secs.max(1)),
                fallback_dir: instructions_cfg.fallback_dir.clone(),
            })
        }
        (true, _) => {
            tracing::warn!("[lifecycle.instructions] enabled = true but no url configured — instructions webhook disabled");
            None
        }
        (false, _) => None,
    };

    let lifecycle_config = synapse_engine::LifecycleConfig {
        staging_dir: config.lifecycle.staging_dir.clone(),
        auto_hardlink: config.lifecycle.auto_hardlink,
        wal_path: config
            .lifecycle
            .wal_path
            .clone()
            .or_else(|| Some(config.disk.session_dir.join("completed_wal.jsonl"))),
        post_script: config.lifecycle.post_script.clone(),
        copy_script: config.lifecycle.copy_script.clone(),
        instructions,
    };
    let lifecycle = Arc::new(synapse_engine::ConduitLifecycleDispatcher::new(
        lifecycle_config,
    ));

    let dynamic_settings = settings_from_config(&config);

    // Initialize Multi-Torrent Swarm Engine
    let mut swarm_builder = SwarmEngine::new(disk.clone(), peer_id)
        .with_session_store(session_store)
        .with_lifecycle(lifecycle)
        .with_settings(dynamic_settings)
        .with_circuit_breaker(
            config.circuit_breaker.enabled,
            config.circuit_breaker.failure_threshold,
            Duration::from_secs(config.circuit_breaker.initial_backoff_seconds),
            Duration::from_secs(config.circuit_breaker.max_backoff_seconds),
        )
        .with_nat_enabled(config.network.enable_nat);
    if let Some(ref watch_dir) = config.disk.watch_dir {
        swarm_builder = swarm_builder.with_watch_dir(watch_dir.clone());
    }
    swarm_builder =
        swarm_builder.with_dht_state_path(config.disk.session_dir.join("dht_state.bencode"));
    {
        let mut trust = synapse_meta::TrustStore::new();
        if let Some(ref dir) = config.signing.trusted_signers_dir {
            let (store, problems) = synapse_meta::TrustStore::load_dir(dir);
            for p in problems {
                tracing::warn!("BEP 35 trust store: {p}");
            }
            tracing::info!("BEP 35: {} trusted signer(s) loaded", store.len());
            trust = store;
        }
        swarm_builder =
            swarm_builder.with_signature_policy(trust, config.signing.require_trusted_signature);
    }
    swarm_builder = swarm_builder.with_rss_feeds(config.rss.feeds.clone());
    let search_sources = config.search.engines.clone();
    swarm_builder =
        swarm_builder.with_rss_state_path(config.disk.session_dir.join("rss_state.json"));
    let swarm = Arc::new(swarm_builder);
    for source in search_sources {
        match swarm.search_manager().add_source(&source).await {
            Ok(engine) => tracing::info!("BEP 18: search engine '{}' loaded", engine.short_name),
            Err(e) => tracing::warn!("BEP 18: could not load search engine {source}: {e}"),
        }
    }

    synapse_engine::announcer::set_fallback_trackers_enabled(
        config.network.enable_fallback_trackers,
    );
    swarm.load_ip_filter_config(
        &config.network.blocked_ip_ranges,
        config
            .network
            .ip_filter_file
            .as_ref()
            .map(std::path::Path::new),
    );

    // Which addresses to listen on: every interface by default, or exactly the addresses listed
    // in `network.bind_interfaces`. IPv6 listeners are only started when `enable_ipv6` is set.
    let mut listen_addrs: Vec<SocketAddr> = Vec::new();
    if config.network.bind_interfaces.is_empty() {
        listen_addrs.push(SocketAddr::from(([0, 0, 0, 0], config.network.listen_port)));
        if config.network.enable_ipv6 {
            listen_addrs.push(SocketAddr::from(([0u16; 8], config.network.listen_port)));
        }
    } else {
        for entry in &config.network.bind_interfaces {
            match entry.parse::<std::net::IpAddr>() {
                Ok(ip) if ip.is_ipv6() && !config.network.enable_ipv6 => {
                    tracing::info!("Skipping IPv6 bind_interfaces entry {entry}: enable_ipv6 is false");
                }
                Ok(ip) => listen_addrs.push(SocketAddr::new(ip, config.network.listen_port)),
                Err(_) => tracing::warn!(
                    "bind_interfaces entry {entry:?} is not an IP address and is ignored (interface names are not supported)"
                ),
            }
        }
    }

    // The first address that binds becomes the primary listener (advertised port, NAT mapping,
    // uTP and DHT); IPv6 wildcard sockets are IPv6-only so they can share the port.
    let mut bound_any = force_proxy; // anonymous mode opens no listening socket
    for addr in listen_addrs.iter().filter(|_| !force_proxy) {
        match swarm.clone().start_listener(*addr).await {
            Ok(_) => {
                tracing::info!("📡 SwarmEngine listener active on {}", addr);
                bound_any = true;
            }
            Err(e) if addr.is_ipv6() => {
                tracing::debug!("IPv6 listener unavailable on {} ({})", addr, e);
            }
            Err(e) => {
                tracing::warn!("Could not bind BitTorrent listen address {}: {}", addr, e);
            }
        }
    }

    if !bound_any {
        tracing::error!(
            "Failed to bind any BitTorrent listen port (port {})",
            config.network.listen_port
        );
        return std::process::ExitCode::FAILURE;
    }

    // Session-wide unchoke slot allocation across swarms (and the seed choking algorithm).
    // Without this task the per-torrent choker never receives its allocation.
    let _session_choker_handle = swarm.clone().start_session_choker_loop();

    if force_proxy {
        tracing::info!("proxy.force_proxy: no listener, DHT, LSD, zeroconf, uTP or port mapping");
    } else {
        match swarm.clone().start_lsd().await {
            Ok(_) => tracing::info!("📡 Local Peer Discovery (LSD) active"),
            Err(e) => tracing::warn!(
                "Could not start Local Peer Discovery (LSD): {} (continuing without it)",
                e
            ),
        }
    }

    if config.network.enable_zeroconf {
        if let Ok(group) = synapse_engine::zeroconf::MDNS_IPV4.parse() {
            match swarm.clone().start_zeroconf(group).await {
                Ok(_) => tracing::info!("📡 Zeroconf (BEP 26) peer discovery active"),
                Err(e) => tracing::warn!(
                    "Could not start Zeroconf discovery (BEP 26): {e} (continuing without it)"
                ),
            }
        }
    }

    if config.privacy.disable_dht_globally {
        tracing::info!("DHT disabled via privacy.disable_dht_globally -- not starting a DHT node");
    } else {
        // DHT conventionally shares the same port number as the TCP peer listener (just UDP).
        let dht_bind = SocketAddr::from(([0, 0, 0, 0], config.network.listen_port));
        match swarm.clone().start_dht(dht_bind).await {
            Ok(addr) => tracing::info!("📡 DHT (Kademlia) node active on {}", addr),
            Err(e) => tracing::warn!("Could not start DHT node: {} (continuing without it)", e),
        }
    }

    match swarm.restore_session() {
        Ok(count) => tracing::info!("Restored {} active torrent swarms from session", count),
        Err(e) => tracing::warn!("Failed to restore session swarms: {e}"),
    }

    // Initialize Event Bus and gRPC Control Plane
    let event_bus = Arc::new(EventBus::new(4096));
    let flusher_bus = event_bus.clone();
    let _flusher_handle = flusher_bus.start_flusher(Duration::from_millis(100));
    let auth_token = config
        .http_api
        .auth_token
        .clone()
        .or_else(|| config.rpc.auth_token.clone());
    let service = SynapseService::new(event_bus.clone())
        .with_swarm_engine(swarm.clone())
        .with_auth_token(auth_token.clone());

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Reconciles the RPC layer's active_summaries/session_stats against the real SwarmEngine
    // state every second — the only place that happened before this was inside each RPC
    // handler's own immediate optimistic update, which is blind to anything the engine does on
    // its own between calls (piece progress, rate changes, a recheck finishing, an autonomous
    // seed transition). Runs regardless of which transport(s) are enabled below, since REST's
    // /api/v1/torrents reads the engine directly already and doesn't need this — this is
    // specifically for SubscribeTorrents/SubscribeSessionStats via active_summaries/session_stats.
    {
        let sync_service = service.clone();
        let mut shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        sync_service.sync_from_engine();
                        sync_service.refresh_session_stats();
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
    }

    // Periodically reconciles queue concurrency, auto-stops seeding torrents that reached ratio
    // or duration limits, enforces alt-speed (turtle mode) schedule transitions, and checkpoints
    // active swarm stats (uploaded/downloaded/ratio) to the session database every 30 seconds.
    {
        let swarm_reconciler = swarm.clone();
        let mut shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            let mut flush_counter: usize = 0;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        swarm_reconciler.recalculate_effective_rate_limits();
                        swarm_reconciler.reconcile_queue();
                        flush_counter += 1;
                        if flush_counter >= 30 {
                            flush_counter = 0;
                            swarm_reconciler.flush_session().await;
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
    }

    // BEP 39: look for updates to torrents that carry an update-url.
    if config.updates.enabled {
        let update_swarm = swarm.clone();
        let interval = Duration::from_secs(config.updates.check_interval_secs.max(3600));
        let mut shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let _ = update_swarm.check_for_updates().await;
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
    }

    // BEP 36 RSS / Atom Feed Automation Background Poller
    if config.rss.enabled && !config.rss.feeds.is_empty() {
        let rss_swarm = swarm.clone();
        let poll_interval = Duration::from_secs(config.rss.poll_interval_secs.max(60));
        let mut shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            tracing::info!(
                "📰 BEP 36 RSS feed poller active (interval: {:?})",
                poll_interval
            );
            let mut interval = tokio::time::interval(poll_interval);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let _ = rss_swarm.poll_rss_feeds().await;
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
    }

    if config.rpc.enabled {
        let rpc_addr: SocketAddr = match config.rpc.listen_addr.parse() {
            Ok(addr) => addr,
            Err(e) => {
                tracing::error!(
                    "Invalid RPC listen address {}: {}",
                    config.rpc.listen_addr,
                    e
                );
                return std::process::ExitCode::FAILURE;
            }
        };

        // `verify_auth` was previously defined but never invoked from any handler — every RPC
        // was reachable with no token at all regardless of config. A Tonic interceptor runs
        // ahead of every method on this service, so this is the one place that needs wiring
        // rather than touching all dozen handlers individually.
        let auth_service = service.clone();
        #[allow(clippy::result_large_err)]
        let interceptor =
            move |req: tonic::Request<()>| -> Result<tonic::Request<()>, tonic::Status> {
                auth_service.verify_auth(&req)?;
                Ok(req)
            };

        let mut grpc_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            tracing::info!("⚡ gRPC Control Plane listening on http://{}", rpc_addr);
            let shutdown_signal = async move {
                while grpc_shutdown.changed().await.is_ok() {
                    if *grpc_shutdown.borrow() {
                        break;
                    }
                }
            };
            if let Err(e) = tonic::transport::Server::builder()
                .add_service(SynapseControlServer::with_interceptor(service, interceptor))
                .serve_with_shutdown(rpc_addr, shutdown_signal)
                .await
            {
                tracing::error!("gRPC server error: {}", e);
            }
        });
    }

    // Optional Alternative REST HTTP API / Web UI / Swagger UI & Prometheus Metrics
    let cli_http_override = args.http_addr.is_some() || args.http_port.is_some();
    let http_server_enabled = config.http_api.enabled || config.web.enabled || cli_http_override;

    if http_server_enabled {
        let mut http_addr = config
            .web
            .listen_addr
            .or_else(|| {
                config.web.port.map(|p| {
                    let mut a = config.http_api.listen_addr;
                    a.set_port(p);
                    a
                })
            })
            .unwrap_or(config.http_api.listen_addr);

        if let Some(cli_addr) = args.http_addr {
            http_addr = cli_addr;
        } else if let Some(cli_port) = args.http_port {
            http_addr.set_port(cli_port);
        }

        let http_engine = swarm.clone();
        let http_auth = auth_token.clone();
        let metrics_enabled = config.metrics.enabled;
        let web_config = config.web.clone();
        let mut http_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            let web_enabled = web_config.enabled;
            let app = synapse_rpc::create_http_router_all(
                http_engine,
                http_auth,
                metrics_enabled,
                web_config,
            );
            tracing::info!("🌐 REST API & Web Server listening on http://{}", http_addr);
            if web_enabled {
                tracing::info!("   - Web Interface:          http://{}/", http_addr);
            }
            tracing::info!(
                "   - Interactive Swagger UI: http://{}/swagger-ui",
                http_addr
            );
            if metrics_enabled {
                tracing::info!("   - Prometheus Metrics:     http://{}/metrics", http_addr);
            }

            match tokio::net::TcpListener::bind(http_addr).await {
                Ok(listener) => {
                    let shutdown_signal = async move {
                        while http_shutdown.changed().await.is_ok() {
                            if *http_shutdown.borrow() {
                                break;
                            }
                        }
                    };
                    if let Err(e) = axum::serve(listener, app)
                        .with_graceful_shutdown(shutdown_signal)
                        .await
                    {
                        tracing::error!("HTTP server error: {}", e);
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to bind HTTP API address {}: {}", http_addr, e);
                }
            }
        });
    } else if config.metrics.enabled {
        tracing::debug!("[metrics] enabled = true, but [http_api] and [web] are disabled — HTTP server will not start");
    }

    // Optional Watch Directory Background Ingestor
    if let Some(watch_dir) = config.disk.watch_dir.clone() {
        let watch_swarm = swarm.clone();
        let dl_dir = config.disk.download_dir.clone();
        let mut watch_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            tracing::info!("👀 Watch directory active on {}", watch_dir.display());
            let imported_dir = watch_dir.join(".imported");
            let failed_dir = watch_dir.join(".failed");
            let _ = tokio::fs::create_dir_all(&imported_dir).await;
            let _ = tokio::fs::create_dir_all(&failed_dir).await;

            let mut failure_counts: std::collections::HashMap<PathBuf, u32> =
                std::collections::HashMap::new();

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(3)) => {},
                    _ = watch_shutdown.changed() => {
                        if *watch_shutdown.borrow() {
                            break;
                        }
                    }
                }

                let mut entries = match tokio::fs::read_dir(&watch_dir).await {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(ext) = path.extension() {
                            if ext == "torrent" {
                                let data = match synapse_rpc::url_fetcher::read_torrent_file(&path)
                                    .await
                                {
                                    Ok(d) if !d.is_empty() => d,
                                    _ => continue,
                                };

                                let bencode = match synapse_bencode::decode_buf(&data) {
                                    Ok(b) => b,
                                    Err(e) => {
                                        let count = failure_counts.entry(path.clone()).or_insert(0);
                                        *count += 1;
                                        if *count >= 3 {
                                            tracing::error!(
                                                "Failed to parse watch file after 3 attempts: {}. Moving to .failed: {e}",
                                                path.display()
                                            );
                                            let fname = path.file_name().unwrap_or_default();
                                            let dest = failed_dir.join(fname);
                                            let _ = tokio::fs::rename(&path, dest).await;
                                            failure_counts.remove(&path);
                                        }
                                        continue;
                                    }
                                };

                                match synapse_meta::Info::from_bencode(bencode) {
                                    Ok(info)
                                        if watch_swarm.check_signature_policy(&info).is_err() =>
                                    {
                                        tracing::warn!(
                                            "Refusing watch-directory torrent '{}': not signed by a trusted signer",
                                            info.name
                                        );
                                        failure_counts.remove(&path);
                                        let fname = path.file_name().unwrap_or_default();
                                        let rejected_dir = path
                                            .parent()
                                            .unwrap_or(std::path::Path::new("."))
                                            .join("rejected");
                                        let _ = tokio::fs::create_dir_all(&rejected_dir).await;
                                        let _ = tokio::fs::rename(&path, rejected_dir.join(fname))
                                            .await;
                                    }
                                    Ok(info) => {
                                        tracing::info!(
                                            "📥 Auto-ingesting .torrent from watch directory: {}",
                                            info.name
                                        );
                                        watch_swarm.add_torrent(
                                            Arc::new(info),
                                            dl_dir.clone(),
                                            None,
                                        );
                                        failure_counts.remove(&path);

                                        let fname = path.file_name().unwrap_or_default();
                                        let mut dest = imported_dir.join(fname);
                                        if dest.exists() {
                                            let ts = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap_or_default()
                                                .as_secs();
                                            dest = imported_dir.join(format!(
                                                "{}.{}",
                                                fname.to_string_lossy(),
                                                ts
                                            ));
                                        }
                                        let _ = tokio::fs::rename(&path, dest).await;
                                    }
                                    Err(e) => {
                                        let count = failure_counts.entry(path.clone()).or_insert(0);
                                        *count += 1;
                                        if *count >= 3 {
                                            tracing::error!(
                                                "Invalid torrent metadata in watch file after 3 attempts: {}. Moving to .failed: {e}",
                                                path.display()
                                            );
                                            let fname = path.file_name().unwrap_or_default();
                                            let dest = failed_dir.join(fname);
                                            let _ = tokio::fs::rename(&path, dest).await;
                                            failure_counts.remove(&path);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    tracing::info!("🚀 Synapse 2.0 ready. Standing by for commands and swarm connections.");

    wait_for_shutdown_or_reload(swarm.clone(), args.config.clone()).await;

    let _ = shutdown_tx.send(true);

    tracing::info!(
        "Shutting down: stopping torrent actors and flushing state to disk (5s timeout)..."
    );
    let shutdown_future = async {
        swarm.shutdown();
        swarm.flush_session().await;
        // Persist the DHT node id and known nodes, and give the gateway its port mappings back.
        swarm.persist_dht_state().await;
        swarm.release_port_mappings().await;
    };

    if tokio::time::timeout(Duration::from_secs(5), shutdown_future)
        .await
        .is_err()
    {
        tracing::warn!("⚠️ Graceful shutdown timed out after 5s — forcing process exit.");
    } else {
        tracing::info!("✅ Session state flushed successfully. Daemon shutdown complete.");
    }

    std::process::ExitCode::SUCCESS
}

async fn wait_for_shutdown_or_reload(swarm: Arc<SwarmEngine>, config_path: Option<PathBuf>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");
        let mut sigquit = signal(SignalKind::quit()).expect("failed to install SIGQUIT handler");
        let mut sighup = signal(SignalKind::hangup()).expect("failed to install SIGHUP handler");

        loop {
            tokio::select! {
                _ = sigterm.recv() => {
                    tracing::info!("Received SIGTERM (Docker/systemd stop signal). Initiating graceful shutdown...");
                    break;
                }
                _ = sigint.recv() => {
                    tracing::info!("Received SIGINT (Ctrl+C). Initiating graceful shutdown...");
                    break;
                }
                _ = sigquit.recv() => {
                    tracing::info!("Received SIGQUIT. Initiating graceful shutdown...");
                    break;
                }
                _ = sighup.recv() => {
                    tracing::info!("🔄 Received SIGHUP. Reloading configuration from disk...");
                    let cfg_res = Config::load(config_path.as_deref());
                    match cfg_res {
                        Ok(new_cfg) => {
                            let new_dynamic = settings_from_config(&new_cfg);
                            swarm.update_settings(new_dynamic);
                            tracing::info!("✅ Configuration and rate limits reloaded successfully via SIGHUP");
                        }
                        Err(e) => {
                            tracing::error!("Failed to reload configuration on SIGHUP: {e}");
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!("Failed to listen for shutdown signal: {e}");
        } else {
            tracing::info!("Received shutdown signal. Initiating graceful shutdown...");
        }
    }
}

async fn startup_self_check(
    engine: &DiskEngine,
    session_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::fs::create_dir_all(session_dir).await?;
    let path = Arc::new(session_dir.join(".synapsed_startup_check"));
    let payload = Bytes::from_static(b"synapsed startup self-check");

    engine
        .write_batch(vec![WriteJob {
            path: path.clone(),
            offset: 0,
            data: payload.clone(),
            file_len: payload.len() as u64,
        }])
        .await?;

    let read_back = engine
        .read(ReadJob {
            path: path.clone(),
            offset: 0,
            len: payload.len(),
        })
        .await?;
    if read_back != payload {
        return Err("startup self-check readback did not match what was written".into());
    }

    engine.sync(path).await?;
    Ok(())
}

/// Optimizes process file descriptor limits (`RLIMIT_NOFILE`) to handle high-scale peer swarms.
#[cfg(unix)]
fn tune_system_limits() {
    unsafe {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) == 0 {
            let target_limit: libc::rlim_t = 65_535;
            if rlim.rlim_cur < target_limit {
                let mut updated = rlim;
                updated.rlim_cur = target_limit;
                if updated.rlim_max != libc::RLIM_INFINITY && updated.rlim_max < target_limit {
                    updated.rlim_max = target_limit;
                }
                if libc::setrlimit(libc::RLIMIT_NOFILE, &updated) == 0 {
                    tracing::info!(
                        "🚀 Tuned RLIMIT_NOFILE: soft limit raised from {} to {}",
                        rlim.rlim_cur,
                        target_limit
                    );
                } else {
                    let fallback = if rlim.rlim_max == libc::RLIM_INFINITY {
                        target_limit
                    } else {
                        target_limit.min(rlim.rlim_max)
                    };
                    if fallback > rlim.rlim_cur {
                        updated.rlim_cur = fallback;
                        updated.rlim_max = rlim.rlim_max;
                        if libc::setrlimit(libc::RLIMIT_NOFILE, &updated) == 0 {
                            tracing::info!(
                                "🚀 Tuned RLIMIT_NOFILE: soft limit raised from {} to {}",
                                rlim.rlim_cur,
                                fallback
                            );
                        } else {
                            let err = std::io::Error::last_os_error();
                            tracing::warn!(
                                "⚠️ Failed to raise RLIMIT_NOFILE to {}: {} (current: {})",
                                fallback,
                                err,
                                rlim.rlim_cur
                            );
                        }
                    }
                }
            } else {
                tracing::debug!(
                    "RLIMIT_NOFILE is already optimal ({} >= {})",
                    rlim.rlim_cur,
                    target_limit
                );
            }
        }
    }
}

#[cfg(not(unix))]
fn tune_system_limits() {}

fn settings_from_config(config: &Config) -> synapse_engine::DynamicSessionSettings {
    synapse_engine::DynamicSessionSettings {
        download_limit_enabled: config.bandwidth.download_limit_enabled,
        download_limit_bytes: config.bandwidth.download_limit_bytes,
        upload_limit_enabled: config.bandwidth.upload_limit_enabled,
        upload_limit_bytes: config.bandwidth.upload_limit_bytes,

        alt_speed_enabled: config.bandwidth.alt_speed.enabled,
        alt_speed_down_bytes: config.bandwidth.alt_speed.download_limit_bytes,
        alt_speed_up_bytes: config.bandwidth.alt_speed.upload_limit_bytes,
        alt_speed_time_enabled: config.bandwidth.alt_speed.time_enabled,
        alt_speed_time_begin: config.bandwidth.alt_speed.time_begin_minutes,
        alt_speed_time_end: config.bandwidth.alt_speed.time_end_minutes,
        alt_speed_time_days: config.bandwidth.alt_speed.time_days,

        queue: synapse_engine::QueueConfig {
            download_queue_enabled: config.queue.download_queue_enabled,
            max_active_downloads: config.queue.download_queue_size,
            seed_queue_enabled: config.queue.seed_queue_enabled,
            max_active_seeds: config.queue.seed_queue_size,
            max_active_torrents: config.queue.max_active_torrents,
            queue_stalled_enabled: config.queue.queue_stalled_enabled,
            queue_stalled_minutes: config.queue.queue_stalled_minutes,
            seed_ratio_limited: config.queue.seed_ratio_limited,
            share_ratio_limit: config.queue.seed_ratio_limit,
            idle_seeding_limit_enabled: config.queue.idle_seeding_limit_enabled,
            seed_time_limit_secs: config
                .queue
                .idle_seeding_limit_minutes
                .map(|m| (m as u64) * 60),
            ..Default::default()
        },

        max_peers_per_torrent: config.network.max_peers_per_torrent,
        max_global_peers: config.network.max_global_peers,

        dht_enabled: config.network.enable_dht,
        dht_read_only: config.network.dht_read_only,
        pex_enabled: config.network.enable_pex,
        lsd_enabled: config.network.enable_lsd,
        zeroconf_enabled: config.network.enable_zeroconf,
        announce_ip: config.network.announce_ip,
        enable_utp: config.network.enable_utp,
        encryption: config.network.encryption.clone(),
        allow_local_web_seeds: config.network.allow_local_web_seeds,

        download_dir: config.disk.download_dir.clone(),
        incomplete_dir: config.disk.incomplete_dir.clone(),
        incomplete_dir_enabled: config.disk.incomplete_dir_enabled,
        start_added_torrents: config.lifecycle.start_added_torrents,
        trash_original_torrent_files: config.lifecycle.trash_original_torrent_files,
        ..Default::default()
    }
}
