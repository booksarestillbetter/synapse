# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.2.3] - 2026-09-09

### Added

- **Wired up five subsystems that were fully implemented but never actually connected to the running daemon** (`synapse-engine::lsd`, `::pex`, `::webseed`, `::metadata`, `synapse-dht`, `synapse-engine::torrent`, `::swarm`, `::announcer`): a systematic sweep of every crate-root `pub` export (generalizing the `IpFilter` discovery above) found that `dht_enabled`/`pex_enabled`/`lsd_enabled` were fully plumbed through config, REST, gRPC, and the web UI, and `docs/BEP_SUPPORT_MATRIX.md` documented DHT (BEP 5/32/33/42/43/44/46/51), Peer Exchange (BEP 11), Local Peer Discovery (BEP 14/22), webseeding (BEP 17/19/38), and magnet metadata resolution (BEP 9/53) as all "Supported" -- but none of the corresponding modules were ever instantiated by the daemon. All five are now real, tested, working features:
  - **BEP 14/22 Local Peer Discovery**: `SwarmEngine::start_lsd` binds the LSD multicast group, periodically announces every registered public torrent, and ingests announcements from other local clients into the same candidate-peer pool trackers use.
  - **BEP 11 Peer Exchange**: incoming `ut_pex` messages -- previously received and unconditionally discarded (`torrent.rs`'s own comment said so) -- are now parsed and fed into peer discovery; each torrent broadcasts its own connect/disconnect delta to `ut_pex`-capable peers every 60s.
  - **BEP 19/17/38 Webseeding**: a torrent with an `url-list` and zero connected peers periodically pulls a missing piece directly over HTTP (Range requests), verifies its hash, and writes it to disk through the normal piece-completion path -- useful for bootstrapping a dead or brand-new swarm.
  - **BEP 9/53 magnet metadata resolution**: a magnet-added torrent (previously spawned as a permanently-inert zero-piece, zero-file `Torrent` actor with no way to ever acquire real metadata) now exchanges `ut_metadata` with connected peers, hash-verifies the assembled info dict, and transitions into a normal downloading torrent under the same info_hash. A normal (non-magnet) Synapse peer now also correctly advertises its metadata size and serves `ut_metadata` requests, which the previous, unused implementation never did either -- required for any of this to work against a real peer, not just against itself.
  - **BEP 5 Kademlia DHT**: `SwarmEngine::start_dht` binds a UDP DHT node, resolves the standard public bootstrap routers, and periodically walks the network for peers on every non-private swarm, feeding discoveries into the same candidate pool and announcing our own presence to the nodes it finds.
  - Fixed a real BEP 10 protocol bug caught while wiring PEX: outgoing extension messages must use the numeric ID *the recipient* declared for that extension in *their own* handshake, not the ID we declared for ourselves in ours -- the two are independently assigned per BEP 10 and often only coincidentally match.
  - The Prometheus `synapse_dht_nodes_total` metric, previously hardcoded to `0`, now reports the live DHT routing table size.
  - New integration tests (`webseed_e2e.rs`, `magnet_metadata_e2e.rs`) drive each new wire-level path over a real TCP/HTTP connection end-to-end, rather than only exercising the already-existing (and, for PEX, misleadingly passing) manager-level unit tests in isolation.
- **Extended the sweep workspace-wide** (all 14 crates, not just the ones touched above) and found a few more instances of the same pattern:
  - `synapse-engine::swarm`: `PrivacyConfig.disable_dht_globally` is now actually checked at startup -- when set, the daemon skips binding a DHT node at all, rather than the flag having no effect (harmless before this release since DHT never ran; no longer harmless now that it does).
  - `synapse-diskio::uring`: implemented the short-read/short-write retry the module's own comment flagged as "a known follow-up, not yet implemented" -- a short `io_uring` completion now resubmits an SQE for exactly the remaining bytes (resuming at the advanced file offset) instead of failing the whole operation. Type-checked and linted against `x86_64-unknown-linux-gnu` (this module is Linux-only and, per its own header comment, still not runtime-verified from this development environment).

### Fixed

- **Peer wire security hardening (`synapse-engine::peer`, `synapse-engine::torrent`, `synapse-engine::announcer`, `synapse-engine::ipfilter`)**:
  - Added a 15-second timeout around the BEP3 handshake read on both inbound (`accept_router`/`accept`) and outbound (`connect`) connections, closing a resource-exhaustion vector where a peer could open a TCP connection and never (or very slowly) complete the handshake.
  - `max_peers_per_torrent` and `max_global_peers` are now actually enforced: `Torrent::on_connected` rejects new peers once either cap is reached, and the outbound dialer (`AnnounceScheduler::dial_step`) bounds its per-swarm dial target by the configured `max_peers_per_torrent` instead of a hardcoded 40/30. Both settings were previously accepted and stored but never consulted anywhere in the connection path.
  - `IpFilter` is now wired into the live connection path instead of sitting unused: a new `blocked_ip_ranges` / `ip_filter_file` config surface (inline CIDR list plus an optional `ipfilter.dat`-style blocklist file, eMule/PeerGuardian range format or plain CIDR) is loaded at startup and enforced before any protocol negotiation on both inbound accepts (`SwarmEngine::start_listener`) and outbound dials (`AnnounceScheduler::dial_step`), matching the behavior already documented in `docs/TRUST_AND_SAFETY.md` §6.
- **Tracker passkeys were never actually redacted from logs (`synapse-engine::announcer`)**: `synapse_tracker::sanitize_tracker_url` exists, is unit-tested, and `docs/TRUST_AND_SAFETY.md` explicitly promises "automatic redaction... in all logs/metrics" -- but nothing ever called it. Every announce log line (`debug!`/`info!`/`warn!` on both the UDP and HTTP/HTTPS announce paths) logged the raw tracker URL, including any `passkey`/`auth`/`token`/`secret` query parameter a private tracker embedded in it. All ~7 log call sites now log the sanitized URL; the raw URL is still used for the actual announce request and for `TrackerReport`/`TrackerStatus` returned to the authenticated local API client, where the real value is legitimately needed.
- **`docs/BEP_SUPPORT_MATRIX.md`**: corrected BEP 26 (HTTP/REST Tracker Protocol) from "Supported" to "Partial" -- `RestTrackerClient` formats REST-style announce/scrape URLs but was never wired into the live announce path, and the request it builds omits standard fields (`uploaded`/`downloaded`/`left`/`event`) a tracker needs to track swarm state. Unlike the other entries in this table, there is no single canonical "BEP 26" specification to conform to, so this was left as a documented gap rather than a guessed implementation.
  - Removed a duplicate, dead `Cancel` match arm in `synapse-wire`'s `decode_message`.

## [2.2.2] - 2026-09-09

### Added

- **Circuit Breaker Slow Restore & Ramp-Up (`synapse-tracker::breaker`, `synapse-engine::circuit_breaker`, `synapse-engine::announcer`)**:
  - Implemented a 4-state circuit breaker lifecycle: `Healthy`, `Tripped`, `HalfOpenCanary`, and `Recovering`.
  - Added progressive recovery levee rate pacing: after a successful canary probe, requests to recovering hosts/endpoints are paced through a 30-second ramp window (1 req / 3s for early stage, 1 req / 1s for mid stage, 3 req / s for late stage) before full graduation to `Healthy` after $\ge 5$ consecutive successes.
  - Fast relapse abort: any failure during recovery immediately aborts back to `Tripped` with doubled exponential backoff.
  - Announce scheduler anti-herd dispersion: when trackers are tripped or rate-limited by the circuit breaker, announce jobs are staggered with randomized jitter (5–15s delay) to prevent stampeding and flap-trip-flap-trip oscillation across swarms.
  - Published comprehensive documentation in `docs/CIRCUIT_BREAKER.md`.
- **Circuit Breaker Capability Negotiation & Remote Control (`synapse-proto`, `synapse-rpc`, `synapse-tracker::breaker`, `synapse-client`)**:
  - New `GetCapabilities` RPC (and `features` field on `GET /api/v1/health`) lets an external control-plane client detect whether this daemon has the tracker circuit breaker, without parsing the version string.
  - New `ListCircuitBreakers` RPC and `GET /api/v1/circuit-breakers` REST endpoint expose live per-host breaker state (`healthy`/`tripped`/`half_open_canary`/`recovering`), consecutive success/failure counts, remaining backoff, and recovery ramp progress.
  - New `ForceCircuitBreakerAction` RPC and `POST /api/v1/circuit-breakers/{host}/trip` \| `/reset` REST endpoints allow manual override from an external control plane.
  - `TrackerStatus` (per-torrent tracker detail, both gRPC and REST) now also carries `cb_state`/`recovery_progress_pct`.
  - Added `CanaryCircuitBreaker::all_hosts`, `force_trip`, and `force_reset` to `synapse-tracker`, and matching wrapper methods to the `synapse-client` SDK.
  - Documented the new surface in `docs/CIRCUIT_BREAKER.md` §6 and `docs/CLIENT_PROTOCOLS_AND_SDK.md`.
- **Swarm Statistics & Paused State Persistence Across Restarts (`synapse-engine`, `synapsed`)**:
  - Preserved historical swarm metrics across daemon restarts: `uploaded_bytes`, `downloaded_bytes`, `ratio`, `added_at` timestamp, and `is_paused` lifecycle state.
  - Resolved session restore overwriting: `SwarmEngine::restore_session` now passes restored state via `add_torrent_with_resume`, preventing in-memory zero resets and eliminating the initial redundant database overwrite.
  - Added `ratio` field to `TorrentSessionState` with backwards-compatible serde deserialization and dynamic fallback calculation for legacy session files.
  - Added 30-second periodic session checkpointing in the daemon maintenance loop so long-running seeding swarms persist upload metrics continuously without awaiting graceful shutdown.

### Fixed

- **Ratio calculation for initial seeders**: fall back to `uploaded_bytes / total_size` when seeding from existing local files with 0 downloaded bytes.
- **Paused torrent lifecycle on restart**: paused torrents now cleanly restore into `SwarmState::Stopped` / `SwarmTier::Cold` without prematurely registering with the announce scheduler until resumed.

## [2.2.1] - 2026-09-09

### Fixed

- **Docker config discovery**: the default config template is now also stored in `/usr/share/synapse`
  and `/etc/synapse.default.toml` so a host volume mounted onto `/etc/synapse` can no longer mask it.
  The entrypoint now searches `SYNAPSE_CONFIG`, `/etc/synapse/synapse.toml`,
  `/etc/synapse/config/synapse.toml`, `/var/lib/synapse/synapse.toml`, and direct file mounts, and only
  passes `-c` to `synapsed` once a real file is confirmed to exist — previously a missing config could
  crash the daemon with a fatal `os error 2`. Ownership (`PUID:PGID`) is now also enforced on
  `/etc/synapse` and the active config file.
- **`http_api` / `web` no longer enabled by default**: `HttpApiConfig.enabled` and `WebConfig.enabled`
  now correctly default to `false`, honoring both the documented defaults and existing configs that set
  `enabled = false`. The HTTP server now only starts when explicitly enabled via `[http_api]`, `[web]`,
  or a CLI override. Added `SYNAPSE_HTTP_ENABLED` / `SYNAPSE_HTTP_API_ENABLED` environment variable
  support.

## [2.2.0] - 2026-09-08

Brings the `v2` branch's remaining work into `master` (merge commit `278d6a8`, "Merge branch
'v2' into 'master'"), following on from the `v2` work already summarized in 2.1.0.

### Added

- **Lightweight Built-In Web Interface & Client Management UI (`synapse-rpc::web`, `synapse-config`, `synapsed`)**:
  - Embedded a zero-dependency, self-contained single-page web interface (HTML5, CSS3, ES6, SVG) served directly by `synapsed` with zero external runtime dependencies.
  - Implemented TransGUI / qBittorrent-style layout:
    - **Top Toolbar**: Add torrent (drag-and-drop `.torrent` upload, magnet link, URL), Resume, Pause, Recheck integrity, Delete (with optional disk file purge), Turtle Mode toggle, Settings modal, live search filtering, and global DL/UL speed and free disk space telemetry.
    - **Sidebar Status Filters**: All, Downloading, Seeding, Paused, Queued, Checking, and Error with real-time swarm count badges.
    - **Sortable Torrent Grid**: Sortable by Queue `#`, Name, Size, Progress bar, Status, Seeds, Peers, Down Speed, Up Speed, ETA, and Ratio.
    - **Bottom Inspector Pane**: Six tabbed detail views mirroring TransGUI: General, Transfer stats, Trackers, Peers with parsed client names/versions, Files with priority selectors, and a real-time `<canvas>` piece map visualizer.
  - Unified HTTP server architecture: the Web UI, REST API (`/api/v1/...`), Swagger UI (`/swagger-ui`), and Prometheus metrics (`/metrics`) all run on the same port, eliminating cross-origin (CORS) complications.
  - Flexible configuration: configure via `[web]` in `synapse.toml` (`enabled`, `port`, `listen_addr`, `web_root`), environment variables (`SYNAPSE_WEB_PORT`, `SYNAPSE_WEB_LISTEN_ADDR`, `SYNAPSE_WEB_ENABLED`), or CLI flags (`--http-port`, `--http-addr`). Starting with `[web].enabled = true` automatically starts the HTTP server even if `[http_api]` is not explicitly enabled.
  - Extended REST API endpoints: added `POST /api/v1/torrents/upload` for binary `.torrent` uploads, `GET /api/v1/torrents/:info_hash/detail` for deep swarm telemetry, `POST /api/v1/torrents/:info_hash/recheck` for re-verification, `POST /api/v1/torrents/:info_hash/location` for directory relocation, and extended deletion to support purging disk data (`delete_data=true`).
- **Strict Invariant Peer ID Enforcement (`synapse-engine::peer`)**:
  - Enforced a hardcoded, non-customizable BEP 20 Azureus-style client identifier prefix (`-SY2200-` matching version 2.2.0) with random suffix generation, preventing user tampering and ensuring strict protocol telemetry fidelity.
- **First-Class `synapse-client` SDK Crate (`synapse-client`, `synapse-proto`)**:
  - Extracted the generated protobuf/Tonic bindings out of `synapse-rpc` into a standalone `synapse-proto` crate, and built `synapse-client` on top of it as the official high-level async Rust SDK: type-safe gRPC commands (add/remove torrents, file priorities, rate limits), Transmission-parity dynamic session settings and scheduled Turtle Mode, automatic reconnection with exponential backoff, and an in-memory live replica cache (`SynapseLiveCache`) backed by the 100ms sparse delta stream.
  - Updated SDK examples, wire protocol spec, and the embedded Swagger schema (`docs/CLIENT_PROTOCOLS_AND_SDK.md`, `docs/RPC.md`, `crates/synapse-rpc/src/swagger.rs`) to match.
- **Human-Readable Bandwidth Units (`synapse-config`, `synapse-rpc`, `synapse-engine`)**:
  - Bandwidth limits (global, per-torrent, alt-speed) now accept pretty byte-rate strings — `50m`, `1000m`, `1g`, `5g`, plus `k`/`kb`/`mb`/`gb` variants — across `synapse.toml`, the REST API, and `SYNAPSE_*` env var overrides, in addition to raw byte counts.
- **`root_dir` & Config Variable Interpolation (`synapse-config`)**:
  - Added a `root_dir` config key and `${root_dir}`-style variable interpolation so `session_dir`/`download_dir`/`watch_dir`/etc. can be expressed relative to one configurable root instead of repeating full paths — matched by an updated `docker-compose.yml` that mounts a single host volume root and an expanded `example_config.toml` walking through the auto-create behavior, new `[lifecycle]`/`[network]` options, and the `SYNAPSE_CONFIG` env var for pointing at a config file from Docker.
- **Piece Map & Tracker Telemetry (`synapse-rpc`, `synapse-engine`, `synapse-picker`)**:
  - `SubscribeTorrents` (gRPC) and the torrent-detail REST/RPC path now expose real `piece_count`, `piece_size`, per-piece availability, and bitfields for piece-map UI rendering, plus byte-accurate per-file progress computed from actual piece overlap (previously every file reported `100%`/fully-downloaded regardless of real state) and live per-tracker status reports (URL, status, seeder/leecher counts, next-announce countdown, failure reason, circuit-breaker state) replacing the previous hardcoded "Ready"/0/0/1800s placeholders. Also surfaces the live connected-peer list (address, client name) per torrent.
  - Published [`docs/SYNAPSE_VS_TRANSMISSION_QBITTORRENT_DELUGE.md`](docs/SYNAPSE_VS_TRANSMISSION_QBITTORRENT_DELUGE.md), a feature-by-feature comparison against the three clients Synapse is most commonly evaluated against.
- **Real Filesystem Free Space (`synapse-engine::fs`, `synapse-rpc`)**:
  - Session/torrent RPC responses now report actual free disk space for the configured download directory via a cross-platform `statvfs` (POSIX) wrapper, replacing a previously hardcoded/absent value.
- **BEP 6 Fast Extension, Fair Seeding Choker & Dual-Stack Listener**:
  - Implemented `AllowedFast`/`HaveAll`/`RejectRequest` messages and a non-blocking async upload worker, plus a fair round-robin choker specifically for seeding swarms (distinct from the downloading-swarm tit-for-tat choker) and simultaneous IPv4 + IPv6 listener binding.
- **BEP 10 Extension Handshake, Peer Candidate Pool & Continuous Dialer (`synapse-engine::announcer`)**:
  - Peers now receive a proper BEP 10 extension handshake (advertising `ut_metadata` always, `ut_pex` only when the torrent isn't private per BEP 27) immediately on connect, before the bitfield.
  - Replaced the old "dial everyone from the last announce, once" model with a persistent candidate peer pool per swarm and a 500ms-tick background dialer that maintains a target connection count (40 peers while downloading, 15 while seeding) and triggers an accelerated re-announce when a swarm is peer-starved (fewer than 3 connected, empty candidate pool, no active dials, and the next scheduled announce is more than 20s away).
- **Docker: `PUID`/`PGID` Support & Healthcheck Fix (`docker-entrypoint.sh`, `Dockerfile`)**:
  - Added a proper entrypoint script: maps the container's `synapse` user/group to `PUID`/`PGID` (or `USER_ID`/`GROUP_ID`) at startup via `usermod`/`groupmod` and drops privileges with `gosu`, falls back to running as root or as an explicitly-`--user`-specified UID when appropriate, and seeds `/etc/synapse/synapse.toml` from a bundled default template on first run.
  - Fixed the healthcheck to honor `http_api.enabled` instead of always probing the REST port even when it's disabled.

### Fixed

- **Peer Wire: Block Stealing, Snubbed-Peer Detection & True Multi-Peer Pipelining (`synapse-engine::torrent`)**:
  - Per-peer in-flight tracking moved from a single "current piece" pointer to a full `(piece, offset) -> Instant` map, so one peer can now legitimately have requests outstanding across several pieces at once instead of being artificially serialized to one piece at a time.
  - A peer with 2+ consecutive block timeouts is marked "snubbed" and its pipeline depth is clamped to 1 in-flight request until it delivers again; blocks already in flight to a snubbed (or sufficiently slow, or endgame-mode) peer become eligible for another peer to request the same block ("block stealing") instead of waiting out the full 5s timeout.
  - Persistently-choked peers (choked for 90+ seconds with zero in-flight requests) are now evicted in `Torrent::tick()` to free up connection slots for peers that will actually send data.
- **Download Stalls, HTTPS Tracker Support & Honest User-Agent (`synapse-tracker::http`, `synapse-engine::ratelimit`)**:
  - HTTP tracker announces/scrapes were rewritten on top of `reqwest` (replacing a hand-rolled raw-socket HTTP/1.1 client), which also finally enables `https://` tracker URLs — previously rejected outright pending this TLS integration.
  - The download-request rate limiter gained a non-blocking `try_consume`, so a saturated bucket now skips issuing that request this tick instead of blocking the whole per-torrent event loop on `consume().await`, which was serializing all request dispatch behind the token bucket and contributing to stalls.
  - Replaced the tracker HTTP client's `User-Agent: Transmission/4.0.5` (an artifact of an earlier client-parity experiment) with a real `Synapse/2.0.0` identifier.
- **Pause / Auto-Wake & Seeder Throughput (`synapse-engine::swarm`, `synapse-engine::torrent`, `synapse-daemon`)**:
  - Fixed paused (Cold/Stopped-tier) torrents auto-waking themselves back up on an inbound connection or an in-flight dial — `get_or_wake_torrent`/`wake_torrent_internal` now guard against waking a torrent the user explicitly paused, and `is_paused` is persisted to the session store across the Cold-tier transition (which also now zeroes the torrent's transfer rates and peer metrics rather than leaving stale numbers visible).
  - Cancelled in-flight requests are now redistributed across remaining unchoked peers immediately on receiving `Message::Choke`, instead of waiting for the next tick.
- **BEP 27 Private Torrent Isolation (`synapse-wire::extension`, `synapse-meta`, `synapse-engine`)**:
  - `private` metainfo flag parsing now accepts both bencoded-int and bencoded-string encodings (`1`/`"1"`/`0`/`"0"`) instead of only int, matching real-world trackers that encode it inconsistently.
  - `ut_pex` is now structurally impossible to advertise or send for a private torrent (gated at extension-handshake construction, `ExtensionHandshake::for_torrent`), rather than relying on call sites to remember to check the flag themselves.
- **Piece Hash & Session Recovery Hardening (`synapse-engine::swarm`, `synapse-engine::session`, `synapse-meta`)**:
  - Stopped evicting a queued (not-yet-started) download's piece hashes, which had been getting reloaded incorrectly (or not at all) when the torrent later woke; hashes are now reloaded correctly on wake.
  - Added auto-healing piece hash recovery: a damaged/incomplete session entry missing its piece hashes is repaired by recovering the full `Info` metadata from the original `.torrent` file in the watch directory, if still present, instead of leaving the swarm permanently unable to verify pieces.
  - Fixed `has_piece_hashes` incorrectly reporting `true` for an empty hash vector.
  - Fixed session persistence overwriting `raw_bencode_hex` with an already-evicted (empty) piece-hash state, and fixed seeding swarms not being correctly recovered as seeding (vs. re-verifying from scratch) on daemon restart.
- **Graceful Shutdown & Lifecycle Hardening (`synapse-daemon`)**:
  - `SIGTERM`/`SIGQUIT` now trigger the same instant graceful-shutdown path as `Ctrl+C`, which matters for Docker (`docker stop` sends `SIGTERM`) — previously only `SIGINT` was handled, so containerized shutdowns waited out the full `docker stop` grace period before being force-killed.
  - Added `SIGHUP` config reload, more careful background worker task lifecycle management around shutdown, and queue stalled-torrent detection integrated into the shutdown-aware task supervisor.
- Cross-platform `statvfs` field types needed a `#[allow(clippy::unnecessary_cast)]` (the cast is a no-op on some platforms but required on others).
- Docker volume mount/interpolation fixes: corrected `${root_dir}`-style variable interpolation syntax in `docker-compose.yml`, unified host volume roots under one `SYNAPSE_ROOT` variable, mounted `/media` with correct `/media/queue` permissions for downstream completion-hook consumers, and whitelisted `docker-entrypoint.sh` in `.dockerignore` (it was being excluded from the build context, breaking the image).

---

## [2.1.0] - 2026-09-06

### Added

- **Dynamic Session Settings & Transmission Parity (`synapse-engine`, `synapse-rpc`, `synapse-config`)**:
  - **In-Flight Dynamic Adjustments**: Full parity with Transmission (`session-get`/`session-set`) and TransGUI (`daemonoptions.pas`), allowing seamless in-flight mutations of bandwidth limits, turtle mode, queue sizes, stalled detection, peer limits, and directories without dropping peer sockets or restarting daemon tasks.
  - **Bandwidth Throttling & Scheduled Turtle Mode (Alt-Speed)**: Atomic token-bucket limiters with manual toggle and automated time/day bitmask schedule (conforming to Transmission's 7-day bitmask Sunday=1..Saturday=64 and midnight-minute arithmetic).
  - **Queue Concurrency & Stalled Torrent Detection**: Independent download queue and seed queue concurrency management, excluding stalled swarms from slot counts and advancing queued downloads automatically.
  - **Seeding Auto-Stop (Share Ratio & Idle Duration)**: Automated background reconciler pausing completed swarms once target share ratios or maximum seed durations are reached.
  - **Static Restart Validation**: Transparent warning returns when attempting to modify static parameters (peer port, RPC listen address, HTTP listen address) in flight.
  - **Environment Variable Overrides (`SYNAPSE_*`)**: Comprehensive env var overrides for all bandwidth, turtle mode, queue, network, and storage parameters.
  - **gRPC & REST API Control**: Added `GetSessionSettings` and `UpdateSessionSettings` to gRPC `SynapseControl`, and `GET /api/v1/session` / `PATCH /api/v1/session` to REST API and OpenAPI 3.1 schema.
  - Published comprehensive session settings reference in [`docs/SESSION_SETTINGS.md`](docs/SESSION_SETTINGS.md).
- **50,000+ Swarm Scalability & Virtualization Engine (`synapse-engine`, `synapse-picker`)**:
  - **Phase 1: Lockless O(1) Atomic Swarm Metrics**: Continuous global rate and byte tally aggregation via `AtomicU64`, achieving 42.85 ns query latency across 50,000 swarms without iteration.
  - **Phase 2: Fair Multi-Tier Swarm Priority Scheduler**: Deficit Round Robin (DRR) scheduler across High, Normal, and Low priority tiers with anti-starvation mechanisms.
  - **Phase 3: 3-Tier Swarm Virtualization (Hot, Warm, Cold)**: Swarm lifecycle tiering where Warm and Cold swarms spawn 0 background Tokio actor tasks, bounding CPU spin and socket descriptor usage.
  - **Phase 4: Flyweight Bitfield & Piece Memory Optimization**: Zero-allocation representations for complete seeds and empty swarms with run-length compressed Roaring Bitmaps, reducing idle swarm memory to ~130 bytes.
  - **Phase 5: Encrypted Embedded `redb` Session Store (`synapse-engine::session`)**: Replaced flat JSON files with an embedded ACID key-value database (`session.db`) encrypted using ChaCha20-Poly1305 AEAD (`SYNAPSE_SESSION_KEY`), completing 10,000 encrypted writes in 82 ms.
  - Verified by 50k integration harness (`scale_50k_test.rs`): 50,000 swarms ingested in 341 ms (146,623 swarms/sec).
- **Comprehensive Benchmark Suite & Documentation (`docs/BENCHMARKS.md`, `synapse-bench`)**:
  - Published comprehensive benchmark documentation covering 50,000 swarm scale results, memory footprints, disk I/O, DHT packet storms, and gRPC concurrency.
- **Dedicated Peer Wire Listen Port `54345`**:
  - Set default BitTorrent peer wire port to `54345` (dual-stack TCP & UDP) across config, Dockerfile, docker-compose, and daemon initialization.
- **Optimized Production Release Profile**:
  - Added full Link-Time Optimization (`lto = "fat"`), `opt-level = 3`, `codegen-units = 1`, `panic = "abort"`, and symbol stripping, shrinking `synapsed` binary size to **6.7 MB**.
- **Automated CI/CD Pipeline**:
  - Multi-stage build, test, and container image pipeline.

---

## [2.0.0] - 2026-08-31

### Added

- **Secure Remote URL & Base64 Torrent Ingestion (`synapse-rpc`, `synapse-daemon`)**:
  - Implemented `fetch_or_parse_torrent` with hardened URL validation: strictly allows only `http://`, `https://`, and `magnet:?` schemes while rejecting `file://`, `ftp://`, `javascript:`, and other injection vectors.
  - Complete protection against null-byte (`\0`) and newline/header injection (`\r\n`).
  - Hard-limited 10 MB payload streaming to prevent memory exhaustion and zip bombs.
  - Added full end-to-end integration test (`daemon_url_torrent_load_test.rs`) verifying remote HTTP `.torrent` downloading, magnet parsing, base64 payload loading, and anti-injection defenses.
- **Standalone Simulation, Load Testing & Benchmarking Suite (`synapse-bench`)**:
  - Implemented `synapse-bench` CLI supporting `swarm`, `disk`, `dht`, `transfer`, `rpc`, and `all` subcommands.
  - Added high-scale swarm virtualization benchmarks (up to 50,000 active swarms, 140,000+ swarms/sec ingestion).
  - Added disk I/O engine bandwidth benchmarks (1.0+ GB/s sequential reads).
  - Added Kademlia DHT packet storm and live UDP loopback benchmarks (19,500+ pings/sec, 0.05 ms latency).
  - Added gRPC concurrency and delta streaming latency benchmarks (69,000+ RPC calls/sec, 0.15 ms snapshot latency).
  - Published comprehensive benchmark and simulation documentation in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).
- **Completion Instructions Webhook (`synapse-engine::instructions`, `[lifecycle.instructions]`)**:
  - Optional, disabled-by-default hook that queries a configured URL for completed torrent target destinations and executes file placement (hardlink/copy/move) via interpreted `post_cmd` without shell injection risks.
  - Published wire protocol specification in [`docs/COMPLETION_INSTRUCTIONS.md`](docs/COMPLETION_INSTRUCTIONS.md).
- **Multi-Target Logging Subsystem & Live Daemon Simulation (`synapse-daemon`, `synapse-config`)**:
  - Structured console logging (Pretty, Compact, JSON), file appenders, and RFC 5424 network Syslog streaming over TCP/UDP to port 514 (`syslog_addr`).
  - Added end-to-end simulation test suite (`daemon_e2e_simulation.rs`).
- **Container Infrastructure**:
  - Added multi-stage build `Dockerfile` and `docker-compose.yml` configured for host networking and tuned `nofile` ulimits.
- **Master Protocol & Documentation Suite (`docs/`)**:
  - Published [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/CLIENT_PROTOCOLS_AND_SDK.md`](docs/CLIENT_PROTOCOLS_AND_SDK.md), [`docs/BEP_SUPPORT_MATRIX.md`](docs/BEP_SUPPORT_MATRIX.md), and updated [`example_config.toml`](example_config.toml).
- **Complete BEP Protocol Support**:
  - **BEP 52 BitTorrent v2 Protocol & SHA-256 Merkle Trees (`synapse-meta`)**: 16 KiB leaf block Merkle tree engine, hierarchical `file tree` dictionary parser, v1/v2 hybrid swarm support.
  - **BEP 44 / BEP 46 Arbitrary DHT Storage & Dynamic Torrent Updates (`synapse-dht`)**: Decentralized key-value storage for immutable and Ed25519-authenticated mutable items with sequence numbers, CAS atomic updates, and automated dynamic torrent resolution.
  - **BEP 51 DHT Infohash Indexing & BEP 33 DHT Scrape (`synapse-dht`)**: `sample_infohashes` KRPC indexing and direct scraper queries.
  - **BEP 42 DHT Security Extension (`synapse-dht`)**: CRC32c IP-derived Node IDs for IPv4/IPv6 preventing Sybil attacks.
  - **BEP 35 Torrent Digital Signatures & BEP 36 RSS/Atom Feeds (`synapse-meta`)**: Ed25519/X.509 signature verification and XML feed parser.
  - **BEP 41 UDP Tracker Protocol Extensions (`synapse-tracker`)**: `0xBEFE` Type-Length-Value option frames for passkeys and tokens.
  - **BEP 50 PubSub Extension & BEP 54 STUN Discovery (`synapse-wire`)**: Gossip publish/subscribe and UDP STUN binding.
  - **BEP 40 Canonical Peer Priority & BEP 48 Tracker Scrape (`synapse-wire`, `synapse-tracker`)**: Deterministic tie-breaking and multi-hash HTTP/UDP scrape.
  - **BEP 14 / BEP 22 Local Peer Discovery (LSD) & BEP 29 uTP / LEDBAT (`synapse-wire`, `synapse-engine`)**: SSDP multicast discovery and delay-based congestion control.
  - **BEP 6 Fast Extension, BEP 11 PEX, BEP 19 WebSeed, BEP 21 Partial Seeds, BEP 55 Holepunch, NAT-PMP / UPnP-IGD, and Super-Seeding (`synapse-engine`, `synapse-picker`)**.
- **Alternative REST HTTP API, Interactive Swagger UI & Prometheus Metrics (`synapse-rpc`, `synapsed`)**:
  - Built-in JSON REST endpoints, OpenAPI 3.1 schema (`/api-docs/openapi.json`), embedded Swagger UI (`/swagger-ui`), and Prometheus metrics (`/metrics`).
- **Transmission to Synapse Session Migration Tool (`synapsed migrate transmission`)**:
  - Auto-discovers Transmission directories on macOS and Linux, decodes bencoded `.resume` state files (piece bitfields, uploaded/downloaded statistics, download directory), and generates native Synapse session files (`<info_hash>.json`) for seamless zero-redownload migration.
- **Deep Torrent Format Inspector & Validation CLI (`synapsed inspect`)**:
  - Diagnostics engine validating single-file, multi-file, BitTorrent v2, and hybrid torrents without loading swarms. Validates piece hashing alignment, payload byte math, directory traversal security, tracker tiers, and BEP 19 web seeds. Supports `.torrent`, `.torrent.added`, and auto-detects bencoded files.

### Fixed

- **Deadlock, Stall & Concurrency Hardening**:
  - **Peer Channel Congestion**: Converted `PeerHandle::send` to use non-blocking `try_send` with a 200ms fallback timeout to prevent slow peer TCP buffers from freezing the swarm actor.
  - **Disk Cache Mutex Contention**: Moved directory creation, file opening, and disk preallocation outside `FileCache` mutex lock. Fixed clock eviction to guarantee eviction in two passes.
  - **Token-Bucket Sub-Token Starvation**: Refactored `TokenBucket::refill` to advance time only by consumed duration, preventing fractional time loss and rate-limiter stalls.
  - **Event Bus Delta Race Condition**: Converted delta flusher to use `pending_deltas.retain` to atomically drain deltas without dropping concurrent inserts.
  - **DHT Task Lifecycle**: Gracefully terminated background UDP loop when all `DhtHandle`s are dropped (`cmds.recv() -> None`).
  - **UDP Tracker Timeout**: Capped announce backoff schedules to a maximum of 35s per tracker to avoid prolonged swarm stalls.
  - **99% Download Stall (Endgame Mode & Request Timeout)**: Implemented BitTorrent Endgame duplicate request broadcasting across unchoked peers when missing pieces remain in-progress, automatic block cancellation on first arrival, and 5-second block request timeout eviction to prevent stalled downloads.
  - **Dynamic Tracker Announce Port**: Wired dynamic bound port reference (`Arc<RwLock<u16>>`) to UDP/HTTP announcers so the active listening port is always sent to trackers instead of 0.
  - **Corrupted Session Self-Healing**: Automatically detects and purges mismatched duplicate session JSON files on startup.
- **gRPC/REST Authentication**: Enforced bearer token authentication across gRPC interceptors and REST middleware.
- **Live Swarm Stats & Recheck Engine**: Fixed frozen stats by recomputing rate deltas, byte counts, and ratios every tick; implemented full disk SHA-1 piece verification and picker bitfield rebuilding in `handle_recheck`.
- **File Priorities & Location Management**: Wired `set_file_priority` directly to piece mask selection in `Picker`; implemented real file relocation with atomic rollbacks in `handle_set_location`.
- **Global Rate Limiting**: Wired atomic `TokenBucket` download and upload rate limiters across all swarms.
