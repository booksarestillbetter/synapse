# Synapse 2.0
[![Rust Build](https://github.com/booksarestillbetter/synapse/actions/workflows/rust.yml/badge.svg)](https://github.com/booksarestillbetter/synapse/actions/workflows/rust.yml)
[![Version 2.2.1](https://img.shields.io/badge/version-2.2.1-blue.svg)](CHANGELOG.md)
[![License: ISC](https://img.shields.io/badge/License-ISC-yellow.svg)](LICENSE)

Synapse 2.0 is an ultra-high-performance, headless BitTorrent daemon built from the ground up in modern async Rust (Tokio/Tonic). It runs completely standalone as a **next-generation BitTorrent engine**, and its gRPC/REST control plane is built to be driven by any compatible media-management front-end that wants a high-scale retriever backend — see [`docs/CLIENT_PROTOCOLS_AND_SDK.md`](docs/CLIENT_PROTOCOLS_AND_SDK.md). Synapse ships with a lightweight built-in web interface (zero setup, embedded in the daemon binary — see below), or drive it with [**Conduit**](https://github.com/booksarestillbetter/conduit) (recommended) for the full multi-node, Arr-aware experience; any other front-end implementing the client contract works the same way.

Engineered from first principles to comfortably scale past **50,000+ concurrent swarms** under 100 MB resident memory (RSS) and multi-gigabit NVMe line-rate throughput.

---

## Key Features & Supported BEPs

### 1. High-Density Swarm Virtualization & 50k Scalability
- **Three-Tier Swarm Virtualization (`synapse-engine`)**: Lifecycle management across `Hot` (active peer wire & I/O), `Warm` (periodic announcing, zero background actor tasks), and `Cold` (dormant in RAM at ~130 bytes/swarm, metadata paged from disk).
- **`RoaringBitfield` Run-Length Compressed Bitmaps (`synapse-picker`)**: Piece tracking utilizing Roaring Bitmaps with a zero-allocation fast-path for 100% complete seeders (0 bytes heap overhead), slashing bitfield memory by up to 95%.
- **Lockless $O(1)$ Atomic Global Telemetry (`synapse-engine`)**: Global bandwidth rates and byte counters aggregated continuously via 64-bit atomics, enabling 42-nanosecond stats queries without iterating over swarms.
- **Fair Multi-Tier Priority Scheduler (`synapse-engine`)**: Deficit Round Robin (DRR) scheduler across High/Normal/Low tiers with anti-starvation boosting.
- **Encrypted Embedded Session Store (`synapse-engine::session`)**: Embedded `redb` ACID database with authenticated **ChaCha20-Poly1305 AEAD** encryption, replacing raw JSON files with high-speed transactional persistence (`session.db`).

### 2. Multi-Homed Network Engine & Dual-Stack IPv6 DHT
- **Default Peer Wire Port `54345`**: Dual-stack TCP and UDP listener on port `54345`.
- **BEP 32 IPv6 Kademlia DHT (`synapse-dht`)**: Full compact node serialization (`NodeInfoV6`, 38 bytes) and compact peer codecs (`compact_peer6`, 18 bytes) supporting dual-stack `nodes`/`nodes6` KRPC queries and responses.
- **Iterative Network Walker (`synapse-dht`)**: 160-bucket Kademlia node with autonomous token rotation, defensive routing table management, and multi-hop recursive graph traversal (`iterative_find_node`, `iterative_get_peers`).
- **Multi-Homed Binding (`synapse-config` & `synapsed`)**: Simultaneous dual-stack binding across IPv4, IPv6, VPN, and LAN interfaces with fail-safe routing.

### 3. Complete BitTorrent Protocol Standards Matrix
- **BEP 52 BitTorrent v2 Protocol (`synapse-meta`)**: Next-generation BitTorrent v2 specification supporting **SHA-256 Merkle trees** (16 KiB leaf blocks), hierarchical `file tree` dictionaries, per-file `pieces root` verification, and v1+v2 hybrid swarms.
- **BEP 44 Arbitrary Data Storage in DHT (`synapse-dht`)**: Decentralized key-value storage in Kademlia DHT for immutable items (SHA-1 target) and mutable items authenticated via **Ed25519** public keys, sequence numbers, and atomic Compare-And-Swap (CAS).
- **BEP 46 Updating Torrents Via DHT Mutable Items (`synapse-dht`)**: Automated tracking and resolution of dynamic torrent revisions published under Ed25519 public keys.
- **BEP 51 DHT Infohash Indexing (`sample_infohashes`) (`synapse-dht`)**: `sample_infohashes` KRPC query and response parsing enabling crawler sampling and swarm indexing.
- **BEP 33 DHT Scrape (`synapse-dht`)**: Querying estimated seeder and leecher counts directly from DHT storage nodes.
- **BEP 42 DHT Security Extension (`synapse-dht`)**: IP-derived Node ID generation (`generate_secure_node_id`) and verification (`verify_secure_node_id`) using CRC32c checksums to protect routing tables against Sybil and eclipse attacks.
- **BEP 35 Torrent Digital Signatures (`synapse-meta`)**: Ed25519 and X.509 digital signature parsing and cryptographic provenance verification inside `.torrent` files.
- **BEP 36 Torrent RSS / Atom Feeds (`synapse-meta`)**: RSS 2.0 and Atom XML feed parser extracting torrent download URLs, enclosures, sizes, publication dates, and infohashes.
- **BEP 47 Padding Files & Whole-File Hashing (`synapse-meta`)**: Boundary alignment padding file detection (`.pad/`, `attr: "p"`) and full-file SHA-1 hashing.
- **BEP 41 UDP Tracker Protocol Extensions (`synapse-tracker`)**: Type-Length-Value (TLV) extension option frames (`0xBEFE`) appended to BEP 15 UDP announces for URLData (passkeys) and authentication tokens.
- **BEP 50 Peer Wire PubSub Extension (`synapse-wire`)**: Gossip topic publish and subscribe protocol over the peer wire.
- **BEP 54 STUN Discovery for UDP / uTP Sockets (`synapse-wire`)**: RFC 5389 / BEP 54 STUN binding requests and `XOR-MAPPED-ADDRESS` resolution over UDP.
- **BEP 40 Canonical Peer Priority (`synapse-wire`)**: Deterministic tie-breaking algorithm (`canonical_peer_priority`) resolving simultaneous cross-connection races between peers without duplicate sockets.
- **BEP 48 Tracker Scrape Protocol (`synapse-tracker`)**: Multi-hash HTTP (`/scrape`) and BEP 15 UDP binary scrape queries to fetch seeders, leechers, and completed counts without active announces.
- **BEP 43 Read-Only DHT Nodes (`synapse-dht`)**: Read-only DHT querying flag (`ro=1`) to prevent routing table pollution on constrained nodes.
- **BEP 29 Micro Transport Protocol (uTP) & LEDBAT (`synapse-wire` & `synapse-engine`)**: Delay-based LEDBAT congestion control over UDP. Detects bottleneck queue delay against a 100ms target to immediately yield bandwidth to interactive foreground traffic while maxing out throughput when the link is idle. Supports Selective ACK (`SACK`) extensions.
- **BEP 9 / BEP 53 Magnet Metadata Exchange (`ut_metadata`) (`synapse-wire` & `synapse-engine`)**: Direct ingestion of `magnet:?xt=urn:btih:...` URIs via BEP 10 extension handshakes and 16 KiB metadata chunk fetching with SHA-1 validation.
- **BEP 6 Fast Extension (`synapse-wire` & `synapse-engine`)**: Instant piece negotiation (`HaveAll`, `HaveNone`), `AllowedFast` deterministic piece calculation allowing choked peers to download initial blocks, `SuggestPiece`, and `RejectRequest`.
- **BEP 11 Peer Exchange (`ut_pex`) (`synapse-wire` & `synapse-engine`)**: Dual-stack IPv4/IPv6 peer gossip delta broadcasting and discovery.
- **BEP 14 / BEP 22 Local Peer Discovery (LSD) (`synapse-wire` & `synapse-engine`)**: Multicast SSDP local peer discovery over UDP (`239.192.152.143:6771` and `[ff15::efc0:988f]:6771`).
- **BEP 19 WebSeed (GetRight HTTP/FTP Seeding) (`synapse-engine`)**: Direct fetching of missing piece blocks via HTTP/HTTPS Range requests from `url-list` web mirrors.
- **BEP 21 Partial Seeds (`dont_have`) (`synapse-picker`)**: Deselected piece masking so partial seeders are not choked or treated as complete seeders.
- **BEP 55 Holepunch Extension (`ut_holepunch`) (`synapse-wire`)**: NAT-to-NAT direct uTP rendezvous relay coordination.
- **Automatic NAT Traversal (UPnP-IGD & NAT-PMP / PCP) (`synapse-engine`)**: Asynchronous router port mapping for incoming TCP, uTP, and DHT traffic.
- **Super-Seeding (Initial Seeding) Mode (`synapse-picker`)**: Piece announcement algorithm minimizing initial seeder upload bandwidth.

### 4. Granular File Priorities & Traffic Management
- **In-Flight Dynamic Session Settings & Transmission Parity (`synapse-engine`, `synapse-rpc`)**: Full parity with Transmission (`session-get`/`session-set`) and TransGUI (`daemonoptions.pas`), allowing seamless on-the-fly mutations of global rate limits, Turtle Mode (alt-speed), queue sizes, stalled detection, and directories without dropping peer sockets or restarting daemon tasks. See [`docs/SESSION_SETTINGS.md`](docs/SESSION_SETTINGS.md).
- **Per-File Selection & Priorities (`synapse-meta` & `synapse-picker`)**: Support for `DoNotDownload`, `Low`, `Normal`, and `High` priorities, automatically translating file byte offsets to piece ranges.
- **Token-Bucket Rate Limiter & Turtle Mode (`synapse-engine`)**: Lockless atomic token-bucket upload/download rate limiters with scheduled alternative speed windows and bitmask day calculations.
- **Queue Manager & Auto-Stop Rules (`synapse-engine`)**: Enforces concurrency limits (`max_active_downloads`, `max_active_seeds`), stalled torrent auto-bypass, and auto-pauses swarms upon reaching target share ratio or maximum seed duration.
- **Dual-Tier Circuit Breakers (`synapse-engine`, `synapse-tracker`)**: Prevents announce storms and peer socket/FD starvation using host-level tracker and endpoint-level peer circuit breakers with 3-state canary probing (`Healthy` -> `Tripped` -> `HalfOpenCanary`). See [`docs/CIRCUIT_BREAKER.md`](docs/CIRCUIT_BREAKER.md).
- **IP Blocklist Filter (`synapse-engine`)**: CIDR and range matching engine to reject blacklisted IP addresses.
- **Filesystem Watch Directory (`synapsed`)**: Background directory watcher automatically ingesting `.torrent` files and archiving them into `.imported`.

### 5. Privacy & Private Tracker Compliance (BEP 27)
- **Strict Private Swarm Isolation (`synapse-config` & `synapse-engine`)**: When a private torrent (`info.private = 1`) is loaded, Synapse automatically and permanently disables DHT announces, Peer Exchange (PEX), and Local Peer Discovery (LSD). `allow_pex_on_private` is permanently hardcoded to `false` and non-configurable.
- **Automatic Passkey Redaction (`synapse-tracker`)**: All logs, diagnostic traces, and gRPC events automatically mask passkeys and authentication tokens (`passkey=[REDACTED]`).

### 6. Control Plane: Web Interface, gRPC, REST API, Swagger UI & Prometheus Metrics
- **Lightweight Built-In Web Interface (`synapse-rpc::web`)**: Zero-dependency, single-page web application embedded directly in the daemon binary. Features TransGUI / qBittorrent-style layout: sortable torrent table, category status filters (All, Downloading, Seeding, Paused, Queued, Checking, Error) with real-time swarm counts, in-flight settings management, drag-and-drop torrent upload, and a 6-tab bottom inspector pane (General, Transfer, Trackers, Peers with client detection, Files with priorities, and real-time `<canvas>` piece map visualizer). Good enough to run Synapse with zero extra setup; for multi-node management and Arr integration, use [Conduit](https://github.com/booksarestillbetter/conduit) instead.
- **Sub-20 KB/s Delta Coalescing Stream (`synapse-rpc`)**: 100ms sparse delta coalescing engine (`SubscribeTorrents`) streaming state transitions across 50,000 swarms with minimal bandwidth.
- **Alternative REST HTTP API (OpenAPI 3.1 & Swagger UI)**: Built-in HTTP server providing full JSON REST endpoints and interactive browser documentation at `http://127.0.0.1:8080/swagger-ui`. Shared on the same port as the Web Interface without CORS complexity.
- **Prometheus Metrics Endpoint**: Optional metrics exporter (`[metrics] enabled = true` by default) rendering standard Prometheus text format at `/metrics`.

### 7. Multi-Target Logging Subsystem (Console, File & Syslog 514)
- **Structured Console Logging (`synapsed`)**: Pretty, Compact, and JSON structured formatting.
- **File Appender**: Direct disk logging to configurable log files with parent directory auto-creation.
- **RFC 5424 Network Syslog Export**: Asynchronous Syslog export over TCP or UDP to port 514 (`syslog_addr`) with non-blocking worker thread and automatic reconnection.

---

## Workspace Layout (`crates/`)

```
synapse/
├── Cargo.toml                  # Root workspace Cargo.toml (LTO, opt-level=3, stripped 6.7MB binary)
├── CHANGELOG.md                # Keep a Changelog
├── README.md                   # Complete platform documentation
├── docs/
│   ├── ARCHITECTURE.md         # System internals, 3-tier virtualization & 50k scaling architecture
│   ├── BENCHMARKS.md           # Performance benchmarks, 50k scale harness & reproduction guide
│   ├── BEP_SUPPORT_MATRIX.md   # Master protocol compliance matrix across all BEPs
│   ├── CIRCUIT_BREAKER.md      # Dual-tier peer & tracker circuit breakers, state machine & config
│   ├── CLIENT_PROTOCOLS_AND_SDK.md # Client SDK reference (Rust, Go, Python, TS), REST API & Swagger
│   ├── COMPLETION_INSTRUCTIONS.md # Wire spec for completion webhook placement
│   ├── HACKING.md              # Contributor & developer guide (quality gates, invariants)
│   ├── RPC.md                  # Control plane wire specification & Protobuf canonical schema
│   ├── SCALING_50K_TORRENTS.md # 50k swarm scale design and implementation breakdown
│   └── SESSION_SETTINGS.md     # Session settings, in-flight dynamic adjustment & Transmission parity
└── crates/
    ├── synapse-bencode/        # Zero-allocation bencode codec with MAX_DEPTH recursion defense
    ├── synapse-config/         # Configuration loader (disk, network, rpc, lifecycle, privacy, http_api, metrics)
    ├── synapse-meta/           # .torrent & magnet parser with path traversal protection & raw info dict parsing
    ├── synapse-wire/           # BEP 3/6/9/10/11/14/22/29/55 codecs, MSE/PE RC4, LSD, uTP, Holepunch (Port 54345)
    ├── synapse-picker/         # RoaringBitfield, rarest-first picker, sequential picker, priority, & super-seeding
    ├── synapse-diskio/         # Linux io_uring & POSIX portable disk engine with FD LRU cache
    ├── synapse-tracker/        # HTTP & BEP 15 UDP tracker clients, passkey redactor, & CanaryCircuitBreaker
    ├── synapse-dht/            # BEP 5 / BEP 32 IPv6 Kademlia DHT & Iterative Network Walker
    ├── synapse-engine/         # SwarmEngine, 3-tier virtualization, encrypted redb SessionStore, & rate limiters
    ├── synapse-rpc/            # Tonic gRPC, REST API, Swagger UI, & Prometheus metrics exporter
    ├── synapse-bench/          # Standalone simulation, load testing & performance benchmark suite
    └── synapse-daemon/         # synapsed binary entrypoint wiring storage, network, swarm, watch dir, and APIs
```

---

## Configuration (`synapse.toml`)

```toml
log_level = "info"

[disk]
session_dir = "~/.synapse/session"
download_dir = "~/Downloads"
watch_dir = "~/Torrents/Watch" # Optional: auto-ingest .torrent files
max_open_files = 500

[network]
listen_port = 54345
enable_ipv6 = true
enable_dht = true
encryption = "prefer_encrypted" # "force_encrypted" | "prefer_encrypted" | "plaintext"
max_peers_per_torrent = 80
max_global_peers = 2000

[rpc]
enabled = true
listen_addr = "0.0.0.0:50051"

[http_api]
enabled = false # Optional REST API + Swagger UI
listen_addr = "0.0.0.0:8080"
cors_enabled = true

[metrics]
enabled = true # Optional Prometheus metrics exporter
path = "/metrics"

[privacy]
prefer_private_safe_defaults = true
mask_passkeys_in_logs = true
disable_dht_globally = false

[lifecycle]
staging_dir = "/mnt/storage/staged"
auto_hardlink = true
post_script = "/usr/local/bin/on_torrent_completed.sh"
```

---

## Quick Start & CLI Tools

### Building the Entire Workspace
```bash
cargo build --workspace --release
```
*The optimized release profile (`opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `strip = true`) generates an ultra-compact `synapsed` binary of only **6.7 MB**.*

### Running All Unit & Integration Tests
```bash
cargo test --workspace
```
*All unit, property, REST API, cryptographic, and network integration tests execute with 0 failures and 0 warnings.*

### Quality Gates & Linting
```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

### Inspecting & Validating `.torrent` Files (Dry-Run Format Diagnostics)
Deeply validates single-file, multi-file, BitTorrent v2, and hybrid torrent files without starting or downloading anything:
```bash
# Scan a directory of .torrent files (including .torrent.added)
cargo run --release -p synapsed -- inspect /path/to/torrents/

# Verbose output (prints tracker tiers and web seeds)
cargo run --release -p synapsed -- inspect --verbose /path/to/torrents/
```

### Migrating From Transmission
Imports existing Transmission `.resume` and `.torrent` states into native Synapse encrypted sessions without re-downloading:
```bash
# Dry run preview
cargo run --release -p synapsed -- migrate transmission --dry-run

# Execute migration
cargo run --release -p synapsed -- migrate transmission
```

### Running the Daemon
```bash
cargo run --release -p synapsed -- -c /path/to/synapse.toml
```

### Running the Benchmark Suite
```bash
# Run all benchmarks (Swarm virtualization, Disk I/O, DHT storm, Wire transfer, gRPC)
cargo run --release -p synapse-bench -- all

# Run 50k swarm scale integration test
cargo test -p synapse-engine --test scale_50k_test -- --nocapture
```
*See [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) for full performance data, memory analysis, and charts.*

### Accessing Swagger UI & Prometheus Metrics (when enabled)
- **Interactive Swagger UI**: `http://127.0.0.1:8080/swagger-ui`
- **OpenAPI 3.1 JSON**: `http://127.0.0.1:8080/api-docs/openapi.json`
- **Prometheus Metrics**: `http://127.0.0.1:8080/metrics`

---

## Running with Docker

Prebuilt multi-arch images (`linux/amd64` + `linux/arm64`) are published to
[Docker Hub](https://hub.docker.com/r/booksarestillbetter/synapse):

```bash
docker run -d --name synapse --network host \
  -v ./data:/data \
  -v ./config:/etc/synapse \
  -v ./session:/var/lib/synapse \
  booksarestillbetter/synapse:latest
```

Or with the bundled `docker-compose.yml` (copy it, adjust the volume paths, then):

```bash
docker compose up -d
```

The image auto-seeds `/etc/synapse/synapse.toml` from `example_config.toml` on first run if
nothing is mounted there. See [`docs/CLIENT_PROTOCOLS_AND_SDK.md`](docs/CLIENT_PROTOCOLS_AND_SDK.md)
for how to connect a control-plane client once it's running, and
[`docs/COMPLETION_INSTRUCTIONS.md`](docs/COMPLETION_INSTRUCTIONS.md) for the optional
completion-webhook contract.
