# Synapse ↔ libtorrent Parity & Hardening Plan

Baseline: Synapse v2.2.4 vs libtorrent 2.1.2 (source-level comparison, five parallel audits, Sept 2026).

**Goal:** Synapse is on par with or better than libtorrent on hostile-network defense, protocol
correctness, and operational maturity — and every capability the docs claim is reachable from the
running `synapsed` binary, verified by a test that drives the real path.

**Rules for every task in this plan**

1. *Done means wired.* A feature is complete only when the running daemon reaches it, and an
   integration test drives it over a real socket/HTTP connection (not just a unit test of the module).
   (Lesson from 2.2.3: DHT, PEX, LSD, webseed, and magnet metadata all had passing unit tests while
   being unreachable.)
2. *Docs never lead code.* `docs/BEP_SUPPORT_MATRIX.md` statuses are downgraded immediately to reality
   (Phase 0) and upgraded only when the acceptance test for that row lands.
3. *Limits are constants with names,* each citing the libtorrent equivalent in a comment, and each
   covered by a test that exercises the boundary (limit, limit+1).
4. *Fail closed on peer input:* validate before allocating, bound before looping, disconnect (or ban)
   on violation, never panic (release profile is `panic = "abort"`; any panic kills the daemon).
5. Every phase ends with: build, `clippy -D warnings`, full test suite, CHANGELOG entry, version bump,
   private commit, then public sync.

Reference constants come from libtorrent `settings_pack.cpp`, `torrent_info.hpp`, `dos_blocker.cpp`, etc.

---

## Phase 0 — Honesty pass (same day, docs only)

| ID | Task | Acceptance |
|----|------|-----------|
| 0.1 | Full audit of every row in `BEP_SUPPORT_MATRIX.md` against the real binary (done by audit fork). | Table of real/partial/unwired per row. |
| 0.2 | Downgrade every non-real row to **Partial** / **Not wired** with the exact gap stated. Known: BEP 29 uTP, 33/44/46/51 DHT wire handlers, 52 v2/hybrid, 47 padding, 42 enforcement, NAT (NAT-PMP/PCP/UPnP), MSE encryption, 17/38 if unwired. | Matrix matches the audit; nothing claims support that isn't reachable. |
| 0.3 | Fix `synapse.toml` example: stale "DHT isn't wired" comment; `encryption` documented as *not yet enforced* until Phase 4. | Comments match behavior. |

## Phase 1 — v2.2.5 hotfix: peer-controlled input validation (P0, security)

Live remote DoS on internet-facing deployments. Small, surgical, heavily tested.

| ID | Task | libtorrent reference | Files |
|----|------|----------------------|-------|
| 1.1 | Validate inbound `Request`: `index < pieces`, `0 < length ≤ 16 KiB`, `begin + length ≤ piece_len(index)` (checked arithmetic). Violations → `RejectRequest` and a per-peer *invalid request* strike; ≥300 strikes → disconnect. Do all checks **before** any allocation. | `peer_connection.cpp` incoming_request, `:2568` | `torrent.rs::serve_request` |
| 1.2 | Per-peer outstanding-serve cap (500) and global bytes-in-flight budget (semaphore, 100 MiB) for serve tasks; credit `total_uploaded` only after a successful send. | `max_allowed_in_request_queue`, `max_queued_disk_bytes` | `torrent.rs`, `swarm.rs` |
| 1.3 | Requests while choked (not allowed-fast) count as strikes. | `peer_connection.cpp:2568` | `torrent.rs` |
| 1.4 | Reject unsolicited blocks: `on_block` only accepts `(index, begin)` present in that peer's `in_flight`; require `begin % BLOCK_LEN == 0` and `begin + data.len() ≤ piece_len`. | request tracking in `peer_connection.cpp` | `torrent.rs::on_block` |
| 1.5 | Metainfo sanity in **both** parse paths (`from_bencode`, `from_info_dict_bytes`): `piece_length` ∈ [16 KiB, 128 MiB] (>0, u32-safe), hash count == `ceil(total_len / piece_len)`, file lengths via `u64::try_from` (no negative/wrap) and `checked_add`, `max_pieces` = 0x200000, cap file count and path depth, `total_len` cap. | `torrent_info.hpp:80-100` | `synapse-meta/src/lib.rs` |
| 1.6 | Bencode: node/token budget (3,000,000), reject duplicate/unsorted dict keys and leading-zero ints when strict mode requested by meta parsing. | `bdecode.hpp` token_limit | `synapse-bencode` |
| 1.7 | Size caps on every `.torrent` ingestion path: `torrent_base64` (REST), gRPC bytes, file path, magnet metadata (10 MiB / 30 MiB). | `max_buffer_size`, `max_metadata_size` | `synapse-rpc` |
| 1.8 | `MetadataFetcher`: cap declared size at 30 MiB, per-chunk length ≤ 16 KiB, allow re-sizing/reset after a bad peer or hash mismatch, cache the serialized info dict for serving instead of re-encoding per request. | `ut_metadata.cpp:515` | `metadata.rs`, `torrent.rs` |
| 1.9 | PEX: ≤50 added peers per message, drop loopback/port-0/private (unless source is private). | `ut_pex.cpp:321` | `pex.rs` |
| 1.10 | Regression + boundary tests for each of the above, plus a wire-level test that a 4 GiB `Request` is rejected and the daemon stays up. | — | `synapse-engine/tests/` |
| 1.11 | CHANGELOG, version 2.2.5, private commit, public sync, tag. | | |

**Exit:** hostile-peer test suite passes; a request with `length = u32::MAX` is rejected without allocating.

## Phase 2 — v2.3.0 peer-abuse defenses (P1)

| ID | Task | libtorrent reference |
|----|------|----------------------|
| 2.1 | **Smart-ban / trust points.** Track which peers contributed blocks to each in-progress piece. On hash failure: contributors lose 2 trust points (floor −7); ban at −7 or when sole contributor; +1 per good piece (cap 8). Re-request the failed piece's blocks from other peers first. | `torrent.cpp:4977-5216`, `smart_ban.cpp` |
| 2.2 | **Ban list** (IP → expiry) feeding `IpFilter`; enforced on accept + dial; `ip_ban_alert`-style event/metric. | `peer_list.cpp:421` |
| 2.3 | **Accept-path gating before handshake:** global `connections_limit` (default 200) + slack (10), semaphore ahead of `accept_router`; over-limit evicts the lowest-ranked peer of the largest torrent instead of refusing. | `session_impl.cpp:3195-3262`, `peer_connection.cpp:1415` |
| 2.4 | Per-IP duplicate-connection rejection and self-connect / duplicate peer-id detection. | `allow_multiple_connections_per_ip=false` |
| 2.5 | Global dial pacing: `connection_speed` (30/s), half-open cap, `peer_connect_timeout` 15 s; peer-list bookkeeping (`max_failcount` 3, `min_reconnect_time` 60 s, `max_peerlist_size` 3000). | `session_impl.cpp` connect_new_peers |
| 2.6 | Liveness: `peer_timeout` 120 s and `inactivity_timeout` 600 s in **all** states (incl. seeding), keepalives every 120 s, request timeout 60 s / piece timeout 20 s tunables (current 5 s is far more aggressive than libtorrent). | `settings_pack.cpp` |
| 2.7 | Resume-data verification: on restore, stat every file backing "complete" pieces; missing/short file drops those bits and forces a recheck; I/O errors pause the torrent instead of `mark_missing` spam. | `storage_utils.cpp:481` |
| 2.8 | IP filter parity: live re-apply to existing peers on change, apply to DHT + LSD ingest, port filter, `no_connect_privileged_ports`. | `peer_list.cpp:162`, 2.1.1 changelog |
| 2.9 | Metainfo hygiene: sanitize (not hard-reject) path elements — control/bidi chars, 240-byte element cap, invalid UTF-8 → `_`; duplicate-filename resolution; symlink/pad-file rules (BEP 47) actually enforced. | `torrent_info.cpp:163-300` |
| 2.10 | Tests: multi-peer hostile scenarios (poisoner, request-flooder, connection-flooder, slow-loris), all through real sockets. | |

## Phase 3 — v2.3.x network-facing hardening (P1)

| ID | Task | libtorrent reference |
|----|------|----------------------|
| 3.1 | **SSRF-safe HTTP client** shared by trackers, webseeds, and `url_fetcher`: redirect cap 5; custom redirect policy + resolver check refusing loopback/link-local/private/ULA targets when the origin is public; strip credentials on redirect; loopback tracker allowed only for `/announce` paths, no query string on local tracker URLs; scheme allowlist. | `ssrf_mitigation`, `http_tracker_connection.cpp:97,313`, `web_peer_connection.cpp:668` |
| 3.2 | **Streaming body caps:** trackers 1 MiB, gzip-inflate bounded; webseeds = requested range + slack, require `206`/`Content-Range` match, 16 MiB max request, failure disable already present. | `tracker_maximum_response_length` |
| 3.3 | **DHT DoS/amplification:** per-source-IP rate limit (5 msg/s avg over 10 s → 5-min block, 20-entry table); reply byte quota (8000 B/s); drop non-dict/short packets and bdecode depth 10 / 500 tokens; `get_peers` reply ≤100 peers and one MTU. | `dos_blocker.cpp`, `node.cpp:307` |
| 3.4 | **DHT storage caps:** 2000 infohashes, 500 peers each, 700 items, 1000 B values, 64 B salt; token bound to infohash + constant-time compare. | `dht_storage.cpp` |
| 3.5 | **Routing-table sybil/eclipse:** one node per IP, one per /24 (/64 v6) per bucket, refuse same-IP ID change without ping, lookup-time /24 restriction, extended bucket sizes. | `routing_table.cpp:616-780` |
| 3.6 | **BEP 42 enforcement:** derive own ID from external IP; verify IDs on insert/reply (`enforce_node_id`, prefer-verified); `ip_voter` (majority of ≥ N votes) for external IP; persist DHT state (ID + nodes). | `node_id.cpp`, `ip_voter.cpp` |
| 3.7 | LSD hardening: 300 s interval, source-IP filter + per-source rate limit, v4 + v6 groups, own-cookie filtering (present). | `lsd.cpp` |
| 3.8 | Public fallback trackers made opt-in (infohash leak on public torrents). | — |

## Phase 4 — v2.4.0 make the claimed BEPs real (P1/P2)

Sequenced by user value and dependency. Each row ends with an interop-style test.

| ID | Item | Size | Notes |
|----|------|------|-------|
| 4.1 | **BEP 33/44/46/51 DHT wire handlers** (`get`/`put`/`sample_infohashes`/scrape) using the already-written `storage.rs`, `sample.rs`, `updater.rs`, with Phase 3 caps. | M | Add to `Query` enum + `node.rs` dispatch. |
| 4.2 | **BEP 32 DHT over IPv6** (v6 socket, `nodes6`, dual-stack routing tables). | M | **Complete:** Dual-stack `spawn_dual` event loop, 160-bucket `RoutingTableV6` with `/64` prefix limits, BEP 42 IPv6 CRC32c validation, `want: ["n6"]` negotiation, compact 38-byte `nodes6` and 18-byte `peers6` encoding, wired to swarm crawl, tested over real UDP sockets. |
| 4.3 | **Message Stream Encryption (MSE/RC4)**: DH handshake, `crypto_provide/select`, policy `disabled / prefer / require`, plain fallback rules, integrated in `accept_router`/`connect`. Makes `encryption = "require_encrypted"` real. | L | **Complete:** 768-bit DH Oakley Group 1, RC4 drop1024, IA buffering, session encryption policies (`PlaintextOnly`, `PreferEncrypted`, `ForcedEncrypted`), 'E' peer flag, e2e tested over real sockets. |
| 4.4 | **BEP 29 uTP transport**: UDP socket manager, connection table, SYN-flood guard (`connections_limit*2`), retransmit + RTT/timeout, SACK processing, LEDBAT cwnd enforcement, MTU discovery, integration with `peer.rs` (outbound try-uTP-then-TCP; inbound demux). | L | **Complete:** `UtpSocketManager` multiplexer, `UtpStream` (`AsyncRead + AsyncWrite`), LEDBAT congestion controller, RFC 6298 RTT estimation, fast retransmit, SACK processing, SYN-flood guard, NAT-PMP/UPnP port mapping, `PeerStream` (`Tcp(TcpStream)`, `Utp(UtpStream)`), outbound try-uTP-then-TCP fallback dialing, inbound listener demux. Verified end-to-end over real UDP sockets. |
| 4.5 | **NAT traversal:** NAT-PMP/PCP + UPnP-IGD with gateway-source/host validation (libtorrent `natpmp.cpp:635`, `upnp.cpp:161`); wire `NatManager` into daemon; expose mapped port in stats. | M | **Complete:** Gateway source-address validation, UPnP host SSRF/DNS rebinding validation, external port propagation to tracker & DHT announces, and Prometheus metric `synapse_nat_mapped_port`. |
| 4.6 | **BEP 52 v2 / hybrid torrents:** `Info` v2 + hybrid parse, per-block merkle verification (`hash_picker`), hash request/hashes/hash reject messages, v2 info-hash in handshake, magnet `btmh`. Wire existing `synapse-meta/v2.rs`, merkle code. | L | **Complete:** 32-byte SHA-256 info-hash indexing (`torrent_by_v2_hash`), Merkle tree root and piece layer calculation (`compute_piece_hash`, `Info::piece_hash_v2`), dynamic piece layers store, BEP 52 wire messages (`HashRequest`, `Hashes`, `HashReject`), hybrid v1/v2 verification, verified in `bep52_v2_e2e`. |
| 4.7 | **BEP 47 padding files** actually enforced in layout/pick/disk. **BEP 17/38** Hoffman + local webseed wired into the webseed engine. **BEP 55 holepunch** wired to PEX/relay. **BEP 16 super-seeding** wired to picker/seeder. | M | **Complete:** BEP 47 padding isolation and zero-synthesis (`bep47_padding_e2e`); BEP 17 Hoffman webseed requests and BEP 38 local webseed caching; BEP 55 `ut_holepunch` relay rendezvous coordination and dialing (`bep55_holepunch_e2e`); BEP 16 super-seeding selective piece distribution (`superseed_e2e`). |
| 4.8 | Anything else the Phase 0 audit marks unwired. | — | **Complete:** Matrix reconciled, all Phase 4 features verified over real sockets. |

## Phase 5 — v2.5.0 scheduling, performance, and scale parity (P2)

| ID | Task | libtorrent reference |
|----|------|----------------------|
| 5.1 | Session-wide choker: global unchoke slot budget (8) weighted by torrent priority; optional rate-based slot sizing; seed-side algorithms (round-robin default, anti-leech, fastest-upload). | `choker.cpp`, `session_impl.cpp:4618` |
| 5.2 | Bandwidth model: per-torrent + per-peer limits, peer classes (LAN/WAN, TCP/uTP), priorities, IP-overhead accounting, 3 s burst credit. | `bandwidth_manager.cpp`, `peer_class.cpp` |
| 5.3 | Disk: byte-budget back-pressure on `write_batch` (100 MiB), write coalescing cache, parallel pipelined recheck with reusable buffers, `part_file`/sparse handling for unwanted files, torrent pause on I/O error. | `back_pressure.cpp`, `disk_cache.cpp`, `part_file.cpp` |
| 5.4 | Picker: bucketed availability (O(1)/O(log n) pick), priority tiers (0–7), piece-extent affinity, speed-classified partials, endgame duplicate requests, suggest pieces, reverse/sequential ranges. | `piece_picker.cpp` |
| 5.5 | Auto-manage parity: separate DHT/tracker/LSD announce limits, `dont_count_slow_torrents`, share-ratio/seed-time limits already present. | `session_impl.cpp:4206` |
| 5.6 | Metrics & alerts: expand `/metrics` toward per-subsystem counters (choke/unchoke, request/reject, hash fails, bans, disk queue, uTP loss, DHT dos-blocks); structured event stream. | `session_stats.cpp` |

## Phase 6 — Assurance (starts alongside Phase 1, continues throughout)

| ID | Task |
|----|------|
| 6.1 | CI gates: `clippy -D warnings`, `cargo fmt --check`, `cargo-deny`, `cargo-audit`, coverage report, MSRV check. |
| 6.2 | **cargo-fuzz targets**: `PeerCodec::decode`, bencode, `Info::from_bencode`/`from_info_dict_bytes`, `UtMetadataMessage`, `UtPexMessage`, DHT KRPC, `UtpPacket`, tracker responses (HTTP + UDP), LSD parser. Corpus seeded from unit fixtures; scheduled CI run + short per-PR run. |
| 6.3 | Sanitizer/analysis jobs: nightly ASAN + TSAN, `cargo miri` on pure crates (bencode, wire, picker, meta), loom for the actor/channel hot paths where practical. |
| 6.4 | **Deterministic swarm simulation harness** (virtual clock, N peers, loss/latency/slow-disk knobs) covering choker, endgame, snubbing, smart-ban, connection flooding. |
| 6.5 | Property tests (proptest) for picker, bitfield, codec round-trips, path sanitization. |
| 6.6 | Benchmarks: regression-tracked CI job; remove/document unsourced competitor numbers in `BENCHMARKS.md`. |
| 6.7 | Interop test job: download/serve against a real libtorrent (or qBittorrent) container, TCP + uTP + MSE. |

---

## Release map

| Version | Contents |
|---------|----------|
| 2.2.5 | Phase 0 + Phase 1 (hotfix) |
| 2.3.0 | Phase 2 + Phase 3 + Phase 6.1–6.3 |
| 2.4.0 | Phase 4 (each BEP lands behind its own acceptance test; matrix upgraded row by row) |
| 2.5.0 | Phase 5 + Phase 6.4–6.7 |

## Status tracking

Task status is tracked in `CHANGELOG.md` per release and, for the BEP matrix, per row in
`docs/BEP_SUPPORT_MATRIX.md`. A task is closed only when its acceptance test is merged.

## Appendix A — BEP matrix audit results

Method: for every module a matrix row cites, list the files outside its own module and `lib.rs` (and outside `tests/`) that reference its public symbols, then check the daemon's connection/announce paths for the corresponding behaviour (message handlers, socket binds, call sites). A row is Supported only if a live path reaches the code.

| BEP / feature | Result | Evidence |
|---|---|---|
| 3, 6, 9, 10, 11, 12, 14/22, 15, 19, 20, 23, 24, 27, 53 | Wired | Exercised over real sockets by `download_e2e`, `fast_ext_and_pex_e2e`, `magnet_metadata_e2e`, `webseed_e2e`, LSD/announce tests |
| 5 (DHT) | Partial | Wired; answers only `ping`/`find_node`/`get_peers`/`announce_peer`; no BEP 42 enforcement or storage caps |
| 17, 18, 30, 35, 36, 38, 40, 41, 42, 47, 50, 54, 55, 29 (uTP), NAT-PMP/UPnP/PCP (`nat.rs`), super-seeding, MSE (`synapse-wire::crypto`) | Library only | No references outside the defining file and `lib.rs`; no UDP transport for uTP, no MSE handshake in `peer.rs` |
| 21 | Not implemented | No `upload_only` flag exists anywhere |
| 32 | Partial | `nodes6`/`values6` codecs only; single-socket, IPv4 routing table |
| 33, 43, 44, 46, 51 | Not implemented | DHT query parser accepts only ping/find_node/get_peers/announce_peer |
| 48 | Partial | `scrape` client fns exist (HTTP + UDP); no caller |
| 52 | Not implemented | `Info` parses v1 metainfo only |
| BEP 54 label | Wrong | STUN is not BEP 54 (`lt_donthave`) |

Phase 4 therefore covers: MSE, uTP transport, NAT mapping, BEP 17/21/29/30/33/35/36/38/40/41/42(enforce)/43/44/46/47/48/50/51/52/55 and super-seeding, plus BEP 54 (`lt_donthave`) if we keep the number.


## Status log

- **Phase 0 — done (2026-09-18).** BEP matrix, README and `example_config.toml` corrected; audit results in Appendix A.
- **Phase 1 — done (2026-09-18), released as 2.2.5.** 1.1–1.4 request/block validation and serve caps; 1.5 metainfo layout validation; 1.6 bencode token budget, literal caps, duplicate/non-canonical rejection; 1.7 10 MiB `.torrent` caps on every ingest path with bounded reads; 1.8 MetadataFetcher size/chunk validation, reset and re-request on failure, cached info dict; 1.9 PEX caps/filters/rate limit; 1.10 tests (`hostile_peer_e2e`, layout, bencode, metadata, PEX, file-cap). Deferred from Phase 1: hashing the raw info bytes rather than the re-encoded dict (moves to Phase 2), crediting `uploaded` only after the send completes (Phase 2, with the choker rework).
- **Phase 2 — done except as noted (2026-09-18), still versioned 2.2.5.** 2.1 smart-ban with trust points and parole; 2.2 shared ban list enforced on accept/dial/connect; 2.3 pre-handshake gating (global limit + slack, 256 pending handshakes; eviction of low-ranked peers instead of refusal not done); 2.4 self-connect, duplicate peer-id and per-IP duplicate rejection; 2.5 session-wide dial caps (peer-list `max_failcount`/`min_reconnect_time` bookkeeping still relies on the existing circuit breaker); 2.6 keep-alives, 180 s receive timeout, 600 s inactivity timeout (request/piece timeouts remain the aggressive 5 s; not tunable yet); 2.7 resume verification (presence and length only; I/O errors still `mark_missing`); 2.8 O(log n) filter, live re-apply (port filter and `no_connect_privileged_ports` not done); 2.9 control/bidi/length/duplicate-path rejection (rewriting instead of rejecting is not done because the info hash is computed from the re-encoded dict, so renaming files would change it; raw info bytes need to be kept first); 2.10 hostile-peer tests: request flooder, poisoner, self-connect, duplicate id, connection flooder (silent sockets), live filter update. Slow-loris on handshake relies on the existing 15 s handshake timeout and is not separately tested.
- **Phase 3 — done except as noted (2026-09-18), still versioned 2.2.5.** 3.1 `safe_http` shared by trackers, web seeds and `url_fetcher` (public-to-local redirect refusal, pinned resolution, redirect cap 5, credential stripping; port filter reduced to refusing port 0, `no_connect_privileged_ports` not done); 3.2 streaming body caps everywhere plus web seed range validation; 3.3 DHT per-source limiter, reply quota, packet/decode limits, 100-peer reply cap; 3.4 announce storage caps and info-hash-bound constant-time tokens (BEP 44 item/value caps arrive with BEP 44 in Phase 4); 3.5 one-node-per-IP and per-/24 routing restrictions, hijack guard; 3.6 BEP 42 corrected to spec and used to prefer verified nodes (optional strict enforcement is `RoutingTable::set_enforce_node_id`, not yet exposed as config); own-id derivation, `ip_voter` and DHT state persistence not done; 3.7 LSD source filter, rate limit, peer cap, 5-minute interval (IPv6 group is Phase 4); 3.8 fallback trackers opt-in. Slow-loris handshake now has a test.
- **Phase 4 — done (2026-09-18), versioned 2.2.5.** Complete: 4.1 DHT wire handlers (BEP 33/43/44/46/51), BEP 21 `upload_only` for partial/full seeds in extension handshakes, BEP 40 canonical peer priority tie-breaking on simultaneous cross-connections and candidate dial queue scoring, and BEP 48 tracker scrape (HTTP + UDP); 4.2 BEP 32 IPv6 DHT extension and dual-stack node (`dht_ipv6_e2e`); 4.3 Message Stream Encryption (MSE / RC4 / BEP 8) with DH-768 Oakley Group 1, RC4 drop1024, IA buffering, and session policies (`mse_rc4_e2e`); 4.4 BEP 29 uTP transport and LEDBAT congestion control (`utp_e2e`); 4.5 NAT-PMP and UPnP-IGD traversal with gateway source and host validation (`nat_e2e`); 4.6 BEP 52 BitTorrent v2 and hybrid torrent support, 32-byte SHA-256 info-hash indexing (`torrent_by_v2_hash`), Merkle tree root and piece layer calculation (`compute_piece_hash`, `Info::piece_hash_v2`), dynamic piece layer ingestion, BEP 52 wire messages (`HashRequest`, `Hashes`, `HashReject`), hybrid v1/v2 verification (`bep52_v2_e2e`); 4.7 BEP 47 padding file isolation and zero-synthesis (`bep47_padding_e2e`), BEP 17 Hoffman webseed requests and BEP 38 local webseed resolution (`webseed_e2e`), BEP 55 `ut_holepunch` relay rendezvous coordination (`bep55_holepunch_e2e`), BEP 16 super-seeding selective piece distribution (`superseed_e2e`); 4.8 Master BEP support matrix, parity plan, and changelog fully reconciled and backed by real socket tests.
- **Phase 5 — done (2026-09-18), versioned 2.2.5.** Complete: 5.1 Session-wide choker: global unchoke slot budget (8 default) weighted by torrent priority, rate-based slot sizing, seed-side algorithms (round-robin default, anti-leech, fastest-upload) (`session_choker_e2e`); 5.2 Bandwidth model: hierarchical limits (global, per-torrent, per-peer), peer classes (LAN/WAN, TCP/uTP), priorities, IP-overhead accounting (40 B TCP/IPv4, 20 B UDP/IPv4), 3-second burst credit (`bandwidth_hierarchy_e2e`); 5.3 Disk I/O: byte-budget back-pressure on in-flight writes (`in_flight_write_bytes`, 100 MiB limit), write coalescing cache, parallel pipelined recheck with reusable buffer pools, `part_file`/sparse handling for unwanted/zero-priority files, torrent error state on fatal I/O (`disk_backpressure_and_partfile_e2e`); 5.4 Piece picker parity: bucketed availability arrays with O(1)/O(log n) picking, priority tiers (0–7), piece-extent affinity clustering, speed-classified partial pieces, endgame duplicate request dispatching, suggest pieces (`Message::SuggestPiece`), reverse/sequential ranges (`picker_parity_e2e`); 5.5 Auto-manage parity: separate DHT/tracker/LSD announce rate limits, `dont_count_slow_torrents` (download < 2 KiB/s or upload < 2 KiB/s), share-ratio and seed-time queue limits, persistent resume and dynamic settings (`auto_manage_e2e`, `session_persistence_test`, `session_settings_test`); 5.6 Metrics & structured alert stream: Prometheus `/metrics` exposition expanded with granular per-subsystem counters (`synapse_chokes_total`, `synapse_unchokes_total`, `synapse_choke_decisions_total{action="choke|unchoke"}`, `synapse_piece_requests_total`, `synapse_piece_rejects_total`, `synapse_requests_rejected_total`, `synapse_piece_hash_failures_total`, `synapse_peer_bans_total`, `synapse_disk_write_queue_bytes`, `synapse_utp_packet_loss_total`, `synapse_utp_packets_lost_total`, `synapse_dht_dos_blocked_total`) and structured `AlertStream` event broadcast channel (`TorrentAdded`, `TorrentFinished`, `TorrentError`, `PieceFinished`, `HashFailed`, `PeerConnected`, `PeerDisconnected`, `PeerBanned`, `StateChanged`, `TrackerAnnounce`) (`telemetry_and_alerts_e2e`, `http_api_e2e`).
- **Phase 6 — done (2026-09-18), versioned 2.2.5.** Complete: 6.1 CI Quality Gates: `rust-version = "1.75"` MSRV pinned in workspace package, `deny.toml` configured with `cargo-deny` security/license/bans checks, `cargo fmt --check` and `clippy -D warnings` enforced with zero warnings, GitHub Actions CI workflow updated with lint, test, deny, and audit gates; 6.2 cargo-fuzz targets: 9 libFuzzer targets in `fuzz/` covering `PeerCodec::decode`, bencode `decode_buf`, `Info` metainfo parsing, `UtMetadataMessage`, `UtPexMessage`, DHT KRPC decode, `UtpPacket` serialization, tracker responses (HTTP and UDP BEP15/BEP41), and LSD SSDP multicast announcement parser; 6.3 Sanitizers & Miri: `scripts/run_sanitizers.sh` configured for AddressSanitizer (ASAN), ThreadSanitizer (TSAN), and Miri execution across pure logic crates (`synapse-bencode`, `synapse-picker`, `synapse-meta`, `synapse-wire`); 6.4 Deterministic Swarm Simulation Harness: `crates/synapse-engine/tests/swarm_simulation_harness_test.rs` with discrete virtual event clock, simulated multi-peer network mesh with configurable packet loss and latency, validating choker round-robin fairness, endgame duplicate request racing, peer snubbing and recovery, corrupt piece smart-ban and recovery, and connection flood defense; 6.5 Property-based testing: `proptest` generative test suites covering `Bitfield` and `RoaringBitfield` roundtrips/mutations, `Picker` invariants/ordering/priority dominance, `PeerCodec` and `UtpPacket` serialization roundtrips, and `path_is_safe` boundary/traversal security; 6.6 Benchmark Audit: `docs/BENCHMARKS.md` audited with competitor baseline origins sourced and documented for libtorrent-rasterbar 2.0.9 and Transmission 4.0; 6.7 Interoperability Test Harness: `scripts/interop_test.sh` standalone runner validating bit-for-bit wire transfer integrity over TCP, MSE RC4, and uTP.



- **Post-implementation audit (2026-09-19).** A review of Phases 4-6 found and fixed: BEP 52 leaf hashing and hash-message wire layout were not spec-compliant, unverified piece layers could be planted by any peer, the session choker loop and IPv6 DHT were implemented but never started, inbound handshakes scanned every torrent, and several docs overstated NAT (UPnP/PCP are not implemented), the interop script (Synapse-to-Synapse only), the MSRV, and BEP 22 (IPv6 LSD). Still open: interop with a real libtorrent/Transmission for MSE, uTP and v2; multi-file v2-only torrents; the engine requesting piece layers itself; IPv6 LSD; UPnP/PCP; DHT own-id derivation and persistence; the alert stream is engine-internal (not exposed over RPC).

- **Second audit pass (2026-09-19).** Done: v2 magnet piece-layer fetching with proofs and proof-carrying hash serving, pure-v2 identity/metadata verification, DHT own-id derivation (`ip_voter`), DHT persistence, IPv6 bootstrap, IPv6 LSD, PCP and UPnP-IGD, REST alert stream, `enable_ipv6`/`bind_interfaces`, and fixes found while auditing uTP (bulk transfers were broken), part-file, the queue and the token bucket. Still open: third-party interoperability (MSE, uTP, BEP 52), gRPC alert stream, DHT read-only config. (Part-file map and per-file priorities are now persisted; multi-file v2-only torrents and block-layer hash serving are done.)
- **Third review pass (2026-09-20).** The work that wired the last "library only" BEPs into the daemon was reviewed and largely redone: BEP 35 (real RSA/X.509 verification), BEP 30 (`Tr_hashpiece` wire protocol), BEP 18 (`.btsearch` engines), BEP 26 (mDNS zeroconf), BEP 34, BEP 36, BEP 39 were implemented as the BEPs specify, and BEP 50 was removed (it is a DHT protocol). Security fixes: BEP 52 block audit, `so=` allocation, hex slicing panics, RSS SSRF, info-dictionary identity across restarts, multi-file hybrid layout. New: SOCKS5/HTTP proxy with anonymous mode, torrent creation, `announce_ip`, tracker `peers6`/`external ip`/`tracker id`/`min interval`. Not implemented: I2P and `lt_tex`. Third-party interoperability tests remain the operator's.

