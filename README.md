# Synapse 2.0
[![Rust Build](https://github.com/booksarestillbetter/synapse/actions/workflows/rust.yml/badge.svg)](https://github.com/booksarestillbetter/synapse/actions/workflows/rust.yml)
[![Version 2.2.18](https://img.shields.io/badge/version-2.2.18-blue.svg)](CHANGELOG.md)
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
- **BEP 32 IPv6 Kademlia DHT (`synapse-dht`)**: The daemon runs a dual-stack node (IPv4 socket plus an IPv6-only socket on the same port; IPv4-only if IPv6 is unavailable). Compact node serialization (`NodeInfoV6`, 38 bytes) and compact peer codecs (`compact_peer6`, 18 bytes) supporting dual-stack `nodes`/`nodes6` KRPC queries and responses.
- **Iterative Network Walker (`synapse-dht`)**: 160-bucket Kademlia node with autonomous token rotation, defensive routing table management, and multi-hop recursive graph traversal (`iterative_find_node`, `iterative_get_peers`).
- **Multi-Homed Binding (`synapse-config` & `synapsed`)**: Simultaneous dual-stack binding across IPv4, IPv6, VPN, and LAN interfaces with fail-safe routing.

### 3. BitTorrent Protocol Support
Row-by-row status, with the evidence behind each claim, is in [`docs/BEP_SUPPORT_MATRIX.md`](docs/BEP_SUPPORT_MATRIX.md). A feature is listed as supported only when the daemon reaches it on a live connection, announce or DHT path and an integration test drives it.

#### Supported

- **BEP 3 — BitTorrent Protocol Specification**: Baseline wire framing, piece requests, choking, unchoking, keepalives, and bencode parser.
- **BEP 5 — DHT Protocol (Kademlia)**: Wired into the daemon: bootstrap (from saved nodes first, then the public routers, over IPv4 and IPv6), iterative `get_peers`/`announce_peer`, routing table, tokens bound to IP and info hash, per-source rate limiting, reply quota, storage caps, one-node-per-IP/-/24 routing limits. The node id is derived from our external address once enough independent nodes agree on it (BEP 42 `ip_voter`), and the id and known nodes are persisted to `dht_state.bencode` in the session directory.
- **BEP 6 — Fast Extension**: `HaveAll`, `HaveNone`, deterministic `AllowedFast` piece sets, `SuggestPiece`, `RejectRequest`.
- **BEP 7 — IPv6 Tracker Extension**: `&ipv4=`/`&ipv6=` (and `&ip=`) announce parameters from `network.announce_ip`, and IPv6 peers read from HTTP (`peers6`) and UDP-over-IPv6 responses.
- **BEP 8 — Message Stream Encryption (MSE / PE)**: 768-bit Diffie-Hellman (Oakley Group 1) key exchange, RC4 drop1024 stream encryption, `crypto_provide`/`crypto_select` mode negotiation, initial payload (`IA`) buffering, and session encryption policy enforcement (`plaintext_only`, `prefer_encrypted`, `forced_encrypted`). Verified over real sockets.
- **BEP 9 — Extension for Peers to Send Metadata Files (`ut_metadata`)**: 16 KiB metadata piece exchange over BEP 10 extension channels for instant magnet URI resolution.
- **BEP 10 — Extension Protocol (`LTEP`)**: Handshake dictionary negotiation for dynamic peer wire extensions (`ut_metadata`, `ut_pex`, `ut_holepunch`, `lt_donthave`, `pubsub`, etc.).
- **BEP 11 — Peer Exchange (`ut_pex`)**: Dual-stack IPv4/IPv6 peer gossip delta broadcasting with privacy boundary isolation.
- **BEP 12 — Multitracker Extension**: Hierarchical tiered announce list parsing and failover ordering (`announce-list`).
- **BEP 14 — Local Peer Discovery (IPv4)**: SSDP multicast local peer discovery over `239.192.152.143:6771`.
- **BEP 15 — UDP Tracker Protocol**: Binary UDP connect, announce, retry backoff, and transaction ID validation.
- **BEP 16 — Super-Seeding (Initial Seeding)**: Selective piece advertisement (`Have`) to separate peers, tracking swarm propagation before assigning subsequent pieces, and unblocking peers upon external confirmation. Verified over real sockets in `superseed_e2e`.
- **BEP 17 — HTTP Seeding (Hoffman Style)**: Hoffman URL formatting (`path?pair=key...`), automated fallback dispatch in piece download pipeline, unit and live integration verified.
- **BEP 18 — Search Engine Specification**: `.btsearch` OpenSearch descriptions loaded from files or URLs (`[search] engines`, `/api/v1/search/engines`); `GET /api/v1/search?q=` queries them with the terms percent-encoded into the template and returns their RSS results.
- **BEP 19 — WebSeed (GetRight HTTP/FTP Seeding)**: `url-list` HTTP/HTTPS `Range: bytes={start}-{end}` piece mirror downloading.
- **BEP 20 — Peer ID Conventions**: Azureus-style peer identification (`-SY2200-...`).
- **BEP 21 — Extension for Partial Seeds (`dont_have`)**: `upload_only` flag advertised in extension handshake on seeding torrents, parsed on incoming handshakes to avoid seed-to-seed starvation and unnecessary requests. Verified over real sockets.
- **BEP 22 — Local Peer Discovery (IPv6)**: The IPv6 group `[ff15::efc0:988f]:6771` is joined and announced on alongside the IPv4 group (best effort: hosts without IPv6 multicast just use IPv4). Announcements are rate limited per source and capped per torrent.
- **BEP 23 — Tracker Returns Compact Peer List**: 6-byte IPv4 (`4-byte IP + 2-byte port`) compact peer representation.
- **BEP 24 — Tracker Returns External IP**: The `external ip` response key is read; an address at least two trackers agree on is available as `Announcer::external_ip`.
- **BEP 26 — Zeroconf Peer Advertising and Discovery**: mDNS/DNS-SD: `<peer-id>._bittorrent._tcp.local` with a `_<info-hash>._sub` subtype per public torrent, browsed for the torrents we share; off by default (`network.enable_zeroconf`). LAN sources only, rate limited, a host may only vouch for its own address, private torrents never involved.
- **BEP 27 — Private Torrents Specification**: Unconditional suppression of DHT, PEX, and LSD on private swarms (`info.private = 1`).
- **BEP 29 — Micro Transport Protocol (`uTP`) & LEDBAT**: uTP transport with LEDBAT congestion control, RFC 6298 RTT estimation, fast retransmit, SACK, SYN flood guard, a real receive window (1 MiB cap, out-of-order buffer bounded to 256 packets), and dual-transport dialing (uTP first, TCP fallback). It shares the peer port with the DHT (`UdpMux`). Verified with multi-megabyte transfers in both directions, a slow reader, and a path with 5% loss, reordering and duplication.
- **BEP 30 — Merkle Tree Torrents v1 (SHA-1)**: `root hash` torrents: SHA-1 tree over piece hashes (breadth-first node numbers), `Tr_hashpiece` messages with the hash list on each piece's first block, verification against the root, and a seeder that serves only data that reproduces the root. Exercised against this implementation only.
- **BEP 32 — IPv6 DHT Extension**: `start_dht` runs a dual-stack node: an IPv4 socket plus an IPv6-only socket on the same port (`spawn_dual`), falling back to IPv4-only when IPv6 is unavailable. `RoutingTableV6` with `/64` limits, `nodes6`/`values6`, and `want` negotiation, verified over real UDP. IPv6 bootstrap routers are pinged so they enter the IPv6 table.
- **BEP 33 — DHT Scrape**: `scrape` queries answered with seeders, leechers, and 256-byte Bloom filters (`BFsd`, `BFpe`) verified against official BEP 33 test vectors; `DhtHandle::scrape` client call. Verified over real UDP sockets.
- **BEP 34 — DNS Tracker Preferences (SRV Records)**: SRV lookup for UDP tracker URLs without an explicit port, using the system nameservers (never a hard-coded resolver), forged answers ignored, TCP fallback, cached, RFC 2782 ordering with failover across targets that must be public addresses. Not applied to HTTP trackers.
- **BEP 35 — Torrent Signing**: The `signatures` dictionary with X.509 certificates and RSA (PKCS#1 v1.5, SHA-256 or SHA-1) over the info dictionary plus the signature's own `info`; trusted by anchor certificate or named root from `signing.trusted_signers_dir`; `signing.require_trusted_signature` refuses other torrents; `GET /api/v1/torrents/{hash}/signatures`. Tested against OpenSSL-made certificates and signatures.
- **BEP 36 — Torrent RSS Feeds**: RSS 2.0 / Atom read with a real XML parser (entities, CDATA, Atom links, the torrent namespace); polling, title filter, persisted handled-item state, retry of failures, a per-poll cap; item downloads cannot reach the local network; `/api/v1/rss/*`.
- **BEP 38 — Finding Local Data Using Web Seeds**: `LocalWebSeedResolver` integration checking local mirror path hashes/pieces before remote network fetching. Verified in unit and engine tests.
- **BEP 39 — Updating Torrents via Feed URL**: `update-url` and `originator`; `update.enabled` polls each feed with our `info_hash`; an update signed by the originator is added automatically, others wait for `POST /api/v1/updates/{hash}/apply`. The URL comes from the torrent, so the local network is off limits.
- **BEP 40 — Canonical Peer Priority**: Deterministic tie-breaking on simultaneous duplicate connections via `canonical_peer_priority`, candidate peer dial queue prioritized via `canonical_peer_score`. Verified over real sockets.
- **BEP 41 — UDP Tracker Protocol Extensions**: The `URLData` option carries a UDP tracker URL's path and query on announces.
- **BEP 42 — DHT Security Extension**: Dual-stack IPv4 and IPv6 CRC32c secure node ID calculation, verification, and preferential bucket placement. Verified in `dht_ipv6_e2e` and unit tests.
- **BEP 43 — Read-Only DHT Nodes**: `ro=1` on our queries, silence to incoming queries, `ro` peers never routed; `network.dht_read_only`, `--dht-read-only`, `SYNAPSE_DHT_READ_ONLY`, and switchable while running.
- **BEP 44 — Arbitrary Data Storage in DHT**: `get`/`put` handlers for immutable and mutable items with Ed25519 signature verification (`verify_strict`), sequence-number and CAS rules, token bound to the item target, 1000-byte value / 64-byte salt / 700-item caps, and spec error codes (203/205/206/207/301/302). `DhtHandle::get`/`put` client calls.
- **BEP 46 — Updating Torrents via DHT Mutable Items**: `TorrentUpdatePointer::poll_node` resolves mutable item targets via BEP 44 `get` over the DHT, parsing updated `ih` or magnet URIs with sequence-number ordering. Verified over real UDP sockets.
- **BEP 47 — Padding Files & Whole-File Hashing**: Detection of `.pad/<size>` padding files via `is_padding_file`, complete isolation from disk I/O, and in-memory zero-synthesis during serving, rechecking, and webseed fetching. Verified over real sockets in `bep47_padding_e2e`.
- **BEP 48 — Tracker Scrape Protocol**: HTTP and UDP scrape client methods exposed on `Announcer` and `SwarmEngine::scrape_tracker`. Verified over HTTP and UDP.
- **BEP 51 — DHT Infohash Indexing (`sample_infohashes`)**: `sample_infohashes` answered from the announced-peer store (20 random hashes per reply, `num`, `interval`); `DhtHandle::sample_infohashes` client call. Verified over real UDP sockets.
- **BEP 52 — BitTorrent v2 Protocol**: Hybrid and v2-only torrents (single- and multi-file) are parsed, verified and created (piece layers per BEP 52 with unpadded short final blocks; per-file piece alignment with synthesized padding). Keyed by the truncated SHA-256. A v2 magnet fetches each file's piece layer in `hash request` chunks with uncle-hash proofs and requests no pieces until it has them. Hash requests are served with proofs, including block-level (layer 0) hashes for files we hold completely. When a piece fails, block hashes are requested from a peer that did not send the piece, proven against the file root, and only then used to ban the sender of a corrupt block. Exercised against this implementation only.
- **BEP 53 — Magnet URI Format**: BTIH, exact topics (`xt`), display names (`dn`), trackers (`tr`), web seeds (`ws`) and select-only (`so=`, bounded) file indices.
- **BEP 54 — The lt_donthave extension**: `lt_donthave` revokes a piece we advertised (sent when a recheck finds it corrupt); a peer's revocation lowers availability only for pieces it really had.
- **BEP 55 — Holepunch Extension (`ut_holepunch`)**: Wire codec, LTEP extension handshake advertisement (`ut_holepunch`), relay rendezvous dispatch (`Connect` to target and sender, or `Failed { err_code: 1 }` on unknown target), and direct uTP peer dialing hook (`on_peers_discovered`). Verified over real sockets in `bep55_holepunch_e2e`.

#### Not implemented

- **BEP 50 — Publish/Subscribe Protocol** (Not implemented): A DHT-based protocol (topics are mutable items, one-node routing tables per topic). It has no known implementation; the peer-wire relay that had been added under this number was not BEP 50 and has been removed.

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
- **Comprehensive Trust, Safety & Privacy Architecture**: See [`docs/TRUST_AND_SAFETY.md`](docs/TRUST_AND_SAFETY.md) for complete details on ChaCha20-Poly1305 encrypted session storage, wire protocol encryption, anti-cheat accounting, zero-telemetry guarantees, and logging hygiene.

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
│   ├── PARANOID_MODE.md        # Logging lockdown: what's still logged, what's suppressed, why
│   ├── POST_SCRIPTS.md         # Post-completion script hook: args, env vars, example script
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

### Creating `.torrent` Files

```bash
# v1 (default), or --v2 / --hybrid; --private, --source, -t <tracker> (repeatable), -w <webseed>
synapsed create ./my-release -o my-release.torrent -t https://tracker.example/announce --hybrid
```

The same is available over REST as `POST /api/v1/torrents/create` for content inside the download directory.

### Migrating From Transmission, qBittorrent, or Deluge
Imports existing torrent and resume state into native Synapse encrypted sessions without
re-downloading. Each finds its source client's default directory automatically (`-t`/`-q`/`-d`
to override); qBittorrent and Deluge both embed libtorrent and share one `.fastresume` parser,
differing only in where they keep it and one qBittorrent-specific save-path override:
```bash
# Dry run preview (any of the three)
cargo run --release -p synapsed -- migrate transmission --dry-run
cargo run --release -p synapsed -- migrate qbittorrent --dry-run
cargo run --release -p synapsed -- migrate deluge --dry-run

# Execute migration
cargo run --release -p synapsed -- migrate transmission
cargo run --release -p synapsed -- migrate qbittorrent
cargo run --release -p synapsed -- migrate deluge
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
for how to connect a control-plane client once it's running,
[`docs/COMPLETION_INSTRUCTIONS.md`](docs/COMPLETION_INSTRUCTIONS.md) for the optional
completion-webhook contract, and [`docs/POST_SCRIPTS.md`](docs/POST_SCRIPTS.md) for running your
own script on completion instead — all three (plus plain hardlinking) are independent, optional,
and need no management app to work.
