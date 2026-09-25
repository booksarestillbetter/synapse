# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [2.2.18] - 2026-09-25

### Added

- **qBittorrent and Deluge migration importers** (`synapsed migrate qbittorrent`, `synapsed migrate deluge`): import existing torrents and resume state into native Synapse encrypted sessions without re-downloading, alongside the existing `migrate transmission`. Both clients embed libtorrent directly and write its `.fastresume` bencoded format, so they share one parser and scanner (`migrate::migrate_libtorrent_client`) — piece state there is one *byte* per piece (0/nonzero), not bit-packed like Transmission's `.resume`, which is called out in the parser's own docs since getting it backwards would silently report wrong piece counts instead of failing loudly. qBittorrent's `qBt-savePath` override is preferred over libtorrent's own `save_path` when present. The CLI's found/migrated summary table is now shared by all three importers via a small `MigratedTorrent` trait instead of being duplicated per client.

## [2.2.17] - 2026-09-24

### Added

- **Paranoid mode** (`[privacy].paranoid_mode`, off by default): a logging lockdown that suppresses every log line except daemon startup, each listener coming up (or failing to), and shutdown — no torrent names, hashes, peer addresses, tracker announces, file paths, or transfer stats reach the console, a log file, or syslog, however `[logging].level` or `RUST_LOG` are set (both are ignored while it's on). Enforced as a default-deny allowlist (only a dedicated `lifecycle` tracing target passes) rather than a denylist of individual log statements, so it isn't defeated by a new log line elsewhere that forgets to be careful about what it prints. `SYNAPSE_PARANOID_MODE` env var override. See [`docs/PARANOID_MODE.md`](docs/PARANOID_MODE.md).

## [2.2.16] - 2026-09-21

Queue, picking, tracker and blocklist controls over gRPC, and three fixes found while adding them.

### Added

**Control API (gRPC)**
- `MoveInQueue` (top, up, down, bottom), with a `queue_position` on every torrent in the list and its updates: position decides which queued torrent starts next when a download slot frees up. `SetSequentialDownload` per torrent (saved with the session), `ReannounceTorrents`, `ReplaceTrackers` (an empty list restores the torrent's own; saved with the session) and `ReloadIpFilter` (re-reads the configured CIDR list and blocklist file, returns the rule count). Each is listed by `GetCapabilities` (`queue_move_v1`, `sequential_download_v1`, `reannounce_v1`, `replace_trackers_v1`, `ip_filter_reload_v1`) so a manager can tell whether the daemon has it.

**Post-completion scripts (`post_script`/`copy_script`)**
- Now receive everything a completion instructions webhook does: `SYNAPSE_DOWNLOAD_DIR`, `SYNAPSE_FILE_COUNT`, `SYNAPSE_FILES` (newline-joined relative paths), `SYNAPSE_TRACKERS` (newline-joined announce URLs), and `SYNAPSE_EVENT_JSON` (the full completion event as JSON) — a script no longer has to guess at, or call back for, information synapse already had. New [`docs/POST_SCRIPTS.md`](docs/POST_SCRIPTS.md) documents every argument and variable with a working example; previously this hook wasn't documented anywhere outside the source.

### Changed

- **The lifecycle/staging/completion-instructions system is unambiguously independent of Conduit.** It always was at runtime — every completion option (`auto_hardlink`, `[lifecycle.instructions]`, `post_script`/`copy_script`) is separately optional and none of them fail, degrade, or do anything differently without Conduit or any other management app present — but the internal type names (`ConduitPlugin`, `ConduitLifecycleDispatcher`, `ConduitInstructionsPlugin`) and some doc/comparison-table wording said otherwise. Renamed to `StagingPlugin`, `LifecycleDispatcher`, and `InstructionsWebhookPlugin`; `docs/SYNAPSE_VS_TRANSMISSION_QBITTORRENT_DELUGE.md` and `docs/HACKING.md` no longer brand native, built-in features as "Conduit" features. Conduit remains one example of something you can point `[lifecycle.instructions]` at, and one example of a gRPC/REST client — never a requirement.

### Fixed

- **eMule-format blocklists** with zero-padded addresses (`001.002.003.000 - 001.002.003.255 , 000 , name`, how real `ipfilter.dat` files are written) failed to parse and every line was skipped.
- **Duplicate announce chains.** A completed, resumed or peer-starved announce queued an extra job without retiring the regular one, so a torrent could end up announcing on two or more parallel schedules; a job that has been superseded by a later schedule is now dropped.
- Queued torrents are started in queue order; before, the order followed the internal map.

## [2.2.5] - 2026-09-18

Adds the remaining BitTorrent Enhancement Proposals and the missing pieces of a complete client (proxy support, torrent creation, signed torrents, RSS, search), and hardens the daemon against hostile peers, `.torrent` files and feeds. `docs/BEP_SUPPORT_MATRIX.md` records what each BEP does today and how it was verified.

### Added

**Protocols**
- **BEP 52 (BitTorrent v2) and hybrid torrents.** Pure-v2 torrents are keyed by the SHA-256 truncated to 20 bytes (magnets included, whose metadata is verified against it). Merkle roots and piece layers follow the spec (a short final block is hashed as it is, not padded). `hash request` / `hashes` / `hash reject` use the specified wire layout. A v2 magnet fetches each file's piece layer from peers in chunks of up to 512 hashes, each proven against the file root with its uncle hashes, and requests no pieces until it has them; hash requests are served with proofs, including block-level (layer 0) hashes for files we hold completely. When a piece fails, block hashes are requested from a peer that did not send it, proven against the root, and only then used to ban the sender of a corrupt block. Multi-file v2-only torrents are supported (files are piece-aligned with synthesized padding that is never written to disk), and multi-file hybrid torrents load with the v1 file list as their layout.
- **BEP 30 (Merkle tree torrents).** `root hash` torrents: the SHA-1 tree over piece hashes with breadth-first node numbers, `Tr_hashpiece` messages carrying the hash list with each piece's first block, verification against the root hash, and a seeder that serves only data that reproduces the root.
- **BEP 35 (signed torrents).** The `signatures` dictionary with X.509 certificates and RSA signatures (PKCS#1 v1.5, SHA-256 or SHA-1) over the info dictionary plus the signature's own `info`, trusted by anchor certificate or named root from `signing.trusted_signers_dir`. `signing.require_trusted_signature` refuses every other torrent (magnets included) on all add paths; `GET /api/v1/torrents/{hash}/signatures` and the inspector report each signature as trusted, untrusted or invalid. Tested with OpenSSL-made certificates and signatures.
- **BEP 18 (search engines).** `.btsearch` OpenSearch descriptions loaded from files or URLs (`[search] engines`, `/api/v1/search/engines`); `GET /api/v1/search?q=` queries them with the terms percent-encoded into the URL template and returns their RSS results (`scope=local` searches this daemon's own torrents).
- **BEP 26 (Zeroconf peer discovery).** mDNS/DNS-SD: `<peer-id>._bittorrent._tcp.local` with a `_<info-hash>._sub` subtype per public torrent, browsed for the torrents we share. Off by default (`network.enable_zeroconf`); LAN sources only, rate limited, a host may only vouch for its own address, private torrents never involved.
- **BEP 34 (DNS SRV tracker preferences).** UDP tracker URLs without a port are resolved through the system nameservers (never a built-in public resolver), with forged answers ignored, TCP fallback, caching, RFC 2782 ordering and failover across targets that must be public addresses.
- **BEP 36 (torrent RSS feeds).** RSS 2.0 and Atom read with an XML parser (entities, CDATA, Atom links, the `torrent:` namespace); scheduled polling, title filter, persisted handled-item state, retry of failed items and a per-poll cap; `[rss]` configuration and `/api/v1/rss/*`.
- **BEP 39 (update feeds).** `update-url` and `originator` are read; `updates.enabled` polls each feed with our `info_hash`. An update signed by the torrent's originator is added automatically, others wait for `POST /api/v1/updates/{hash}/apply`; `GET /api/v1/updates`, `POST /api/v1/updates/check`.
- **BEP 41 and BEP 7.** The `URLData` option carries a UDP tracker URL's path and query; `&ip=`, `&ipv4=` and `&ipv6=` are sent from `network.announce_ip`, and IPv6 peers (`peers6`, and 18-byte UDP-over-IPv6 entries) are read.
- **BEP 24, BEP 3 tracker fields.** `external ip`, `tracker id` (sent back on later announces), `min interval` and `warning message` are read from HTTP tracker responses; intervals, ports and peer counts are bounded.
- **BEP 53 (`so=`).** Select-only file indices in magnet links (bounded) set the initial file priorities, and survive metadata resolution.
- **BEP 54 (`lt_donthave`).** Sent when a recheck finds an advertised piece corrupt; a peer's revocation lowers availability only for pieces it really had.
- **BEP 29 (uTP) and LEDBAT.** A socket multiplexer with delay-based congestion control, RFC 6298 RTT/RTO with backoff, SACK and fast retransmit, a send queue, bounded receive and reorder buffers, a SYN flood guard, and outbound uTP-then-TCP dialing; `enable_utp` is a live setting.
- **BEP 8 (MSE / RC4).** 768-bit Diffie-Hellman with RC4 drop1024, plaintext or RC4 negotiation, initial payload buffering, policy enforcement (`plaintext_only`, `prefer_encrypted`, `forced_encrypted`), fallback for legacy peers, and the encrypted flag in peer snapshots.
- **BEP 32, 33, 43, 44, 46, 51 (DHT).** A dual-stack node (one port, IPv4 and IPv6 sockets) with a 160-bucket IPv6 routing table, `want` negotiation, compact `nodes6`/`peers6`; `get`/`put` with Ed25519 signatures, sequence and CAS rules; `sample_infohashes`; Bloom-filter scrapes matching the official vectors; mutable torrent updates; read-only mode (`network.dht_read_only`, `--dht-read-only`, `SYNAPSE_DHT_READ_ONLY`, switchable while running). The node id is derived from the external address once enough nodes agree on it (BEP 42 `ip_voter`), the id and known nodes persist across restarts, and IPv6 bootstrap routers are used.
- **BEP 14/22 (LSD)** over IPv6 as well as IPv4.
- **BEP 47, 17, 19, 38, 55, 16, 21, 40, 48.** Padding files are never written and are synthesized as zeroes when serving, rechecking and web seeding; Hoffman-style web seed URLs with fallback and local mirror lookup; `ut_holepunch` relaying; super-seeding; `upload_only` partial seeds; canonical peer priority for connection races and dial ordering; HTTP and UDP tracker scrapes.
- **Port mapping** through PCP (RFC 6887), NAT-PMP (RFC 6886) on the real default gateway, then UPnP-IGD (SSDP, SOAP). Replies from anything but the gateway are ignored, mappings are renewed, rediscovered on failure and released on shutdown; the mapped port is used in tracker and DHT announces and exposed as `synapse_nat_mapped_port` (`network.enable_nat`).

**Networking and privacy**
- **Proxy support** (`[proxy]`): SOCKS5 (with username/password) or HTTP CONNECT for peer connections and for HTTP requests to trackers, web seeds, feeds, search engines and update feeds, with host names left to the proxy. uTP and UDP trackers are not used for traffic a proxy carries, and `force_proxy` starts no listener, DHT, LSD, zeroconf, uTP or port mapping, so nothing can bypass the proxy.
- `network.announce_ip` for VPN and NAT setups (with `dht_read_only` and `zeroconf_enabled`, also readable and changeable at runtime through the gRPC and REST session settings), and `network.enable_ipv6` / `network.bind_interfaces` (IP addresses) honoured by the daemon, with IPv4 and IPv6 listeners sharing one port.
- DHT and uTP share one UDP port (`synapse_wire::UdpMux`, demultiplexed by first byte).

**Torrent files**
- **Torrent creation**: `synapsed create` and `POST /api/v1/torrents/create` (v1, v2 or hybrid; streamed, deterministic, BEP 47 padding; the REST form only reads the download directory). `synapsed inspect` reports payload size, readable dates and signatures.

**Peer, piece and disk engine**
- Session-wide choker with dynamic slot sizing and the `RoundRobin`, `AntiLeech` and `FastestUpload` seed algorithms; a three-tier (global, torrent, peer) token-bucket hierarchy with LAN/WAN and TCP/uTP classes, packet overhead accounting and burst credit.
- Availability-bucketed piece picker, eight priority tiers, extent affinity, speed-classified partial pieces, endgame duplicate requests, `SuggestPiece`/`RejectRequest`, sequential and reverse modes.
- Bounded write budget shared by both disk engines with adaptive backpressure, write coalescing, pipelined parallel recheck, and a part file for skipped files whose slice map and per-file priorities persist across restarts.
- Auto-manage with per-subsystem announce rate limits, `dont_count_slow_torrents`, and share-ratio and seed-time limits.

**Observability**
- Structured alerts (`TorrentAdded`, `TorrentFinished`, `TorrentError`, `PieceFinished`, `HashFailed`, `PeerConnected`, `PeerDisconnected`, `PeerBanned`, `StateChanged`, `TrackerAnnounce`) over `GET /api/v1/alerts` (Server-Sent Events) and gRPC `SubscribeAlerts`, both filterable by info hash.
- Prometheus counters for chokes, requests, rejects, hash failures, bans, disk write queue, uTP loss, DHT drops and the mapped port. OpenAPI entries for every route.

**Quality**
- CI gates (`cargo fmt`, `clippy -D warnings`, tests, `cargo-deny`, `cargo audit`), a declared MSRV (Rust 1.88), nine libFuzzer targets, an ASAN/TSAN/Miri runner, a deterministic swarm simulation harness, property tests for the picker, bitfields, wire codecs and path safety, and real-socket end-to-end tests for each protocol above. `scripts/interop_test.sh` runs the Synapse-to-Synapse suites; it does not test against any other client.

### Changed

- **Documentation matches the daemon.** `docs/BEP_SUPPORT_MATRIX.md` and the README list each BEP as Supported, Partial, Library only or Not implemented with the evidence behind it; entries that were library code nothing used, or not implemented at all, no longer claim support.
- **Public fallback trackers are opt-in** (`network.enable_fallback_trackers`, default off): announcing every public torrent to built-in third-party trackers disclosed each info hash to services the user never chose.
- **Queueing:** a newly started download counts against the active-download limit for 120 s (it has no throughput yet); idle-seeding limits measure time since the last transfer, not since the torrent was added.
- **Rate limiting:** a request larger than a bucket can hold is admitted from a full bucket and leaves it in debt instead of waiting forever; tiers are taken all-or-nothing and a queued upload no longer holds its peer's and torrent's budget.
- **Peer wire frames are capped at 1 MiB** (previously 8 MiB); we announce to LSD every 5 minutes instead of every minute; the daemon starts the session choker and the dual-stack DHT (both existed but were never started).
- **Builds need no system `protoc`**: `synapse-proto` uses a bundled one unless `PROTOC` is set. Dependencies were updated to clear advisories (`rustls`, `quick-xml`, a yanked `chacha20`); the `rsa` timing advisory is recorded as not reachable (only public-key verification is used). The GitHub release job builds `synapsed` and uploads it.
- The exact info dictionary is kept for v2, hybrid, signed and Merkle torrents, and for any torrent whose info dictionary has keys Synapse does not model, so a torrent's identity survives being persisted and it can serve its own metadata.
- Each inbound connection resolves its torrent through an index instead of copying every info hash; the serialized info dictionary is cached instead of re-encoded per request.

### Fixed

- **Torrents with extra info-dictionary keys** (`source`, `x_cross_seed`, `md5sum`, ...) changed their info hash when persisted, so they were skipped on the next start and could not serve metadata.
- **uTP could not carry bulk data**: the rest of a write was discarded when the congestion window was full, so anything beyond a few kilobytes stalled. Selectively acknowledged packets were double counted, the advertised window was the sender's congestion window instead of the receiver's free space, and buffers were unbounded.
- **uTP: a repeated SYN killed the established connection.** The initiator retransmits its SYN when our handshake STATE is lost (and a datagram can be duplicated), but the SYN carries the initiator's connection id while the accepted connection is keyed by the other id, so the repeat was taken for a new connection that replaced the old one, which then stalled forever (about 7% of transfers over a 5%-loss path). A repeated SYN is now matched to its connection and answered with the STATE again.
- **DHT could not start whenever uTP was enabled** (both bound the peer port), and its IPv6 socket could not share the IPv4 socket's port on Linux.
- **BEP 42 was implemented incorrectly** (the IP was XORed into the wrong bits), so generated node ids would never verify; it now matches the published vectors. `DhtStorage` accepted mutable items without verifying their signatures, and `announce_peer` ports above 65535 wrapped.
- **BEP 52:** short final blocks and pieces were hashed with the wrong padding and tree width; the hash messages used the wrong wire layout; unverified piece layers could be planted by any peer (and a hostile `index` could resize a buffer by ~137 GB); a v2 torrent was persisted as v1 and lost its identity.
- **Skipping a file** deselected pieces it shares with a wanted neighbour, which then could never complete; per-file priorities and the part-file map were not saved, so skipped files came back as wanted and their data was re-downloaded; part-file blocks could not be read back and were never moved into the real file when it became wanted.
- **The Linux build failed**: the `io_uring` disk engine lacked the write-buffer accessors the dispatcher calls. A write batch larger than the write budget, or a budget lowered at runtime, could deadlock.
- **Resume data** claimed pieces whose files were missing or truncated; it is now checked against the files on disk (part-file data counts as present).
- **BEP 9:** a failed metadata assembly left the magnet stuck forever; it now resets, drops the peer that completed it and asks others.
- **NAT-PMP** now uses the real default gateway, ignores datagrams from other sources, and renews mappings.
- Panics reachable from input: slicing a non-ASCII 40- or 64-byte string in a magnet or feed, `Info::piece_len` underflow on an inconsistent persisted record, and `so=0-4294967295` allocating without bound.
- `lt_donthave` could drive rarest-first availability to zero; a peer could get an innocent peer banned through unproven block hashes; the local web-seed cache check read every piece from the start of the file; tracker parsers truncated intervals and ports instead of rejecting them.

### Security

- **A peer could make the daemon allocate up to 4 GiB with one message**: `Request` messages were served without validating `index`, `begin` or `length`, and the buffer was allocated from the peer-supplied `length`. Requests are validated (`index < pieces`, `0 < length <= 16 KiB`, `begin + length <= piece length`) before anything is allocated; invalid, choked or unavailable requests get `RejectRequest` and count as strikes, a peer over 300 strikes is disconnected, and concurrent serves are capped at 500 per peer and 2048 per torrent.
- **Unsolicited and mis-sized blocks** are no longer accepted, credited or written; a block must match an outstanding request from that peer at the exact size.
- **Inconsistent `.torrent` metadata** is rejected: `0 < piece length <= 128 MiB`, non-negative file lengths whose sum does not overflow, `ceil(total / piece length)` equal to the hash count, at most 2,097,152 pieces, 1,000,000 files and 128 path components (`.torrent` files, BEP 9 metadata and Merkle layouts alike). Path components with control characters, bidirectional overrides or over 255 bytes, and duplicate paths, are rejected.
- **Bencode limits**: 3,000,000 values, 20-character integer and length literals, no duplicate keys, no non-canonical integers.
- **`.torrent` size caps everywhere** (10 MiB: files, the watch directory, gRPC, REST, HTTP downloads), read through bounded readers.
- **BEP 9 metadata** is limited to 30 MiB with exact 16 KiB chunks. **PEX** accepts at most 50 peers per family per message, drops unroutable addresses, and ignores a peer sending it more than once per 10 s.
- **Smart-ban**: each block records who sent it; a failed piece bans a sole contributor, or costs several contributors trust points and puts them on parole (only pieces no one else touches), with 24-hour per-IP bans shared across torrents and enforced on accept, dial and connect. Duplicate blocks no longer overwrite the first.
- **Connection gating**: connections are refused before any handshake work past the global limit plus 10, with at most 256 handshakes in flight and 128 concurrent dials; self-connections and a second connection from the same peer id or IP are refused; keep-alives after 60 s of silence, closed after 180 s, and peers exchanging no piece data for 600 s are dropped in every state.
- **IP filter** lookups are O(log n) over merged ranges, and a filter or ban change drops matching connected peers within 5 seconds.
- **SSRF-safe, size-capped HTTP** (`synapse_tracker::safe_http`) for trackers, web seeds, `.torrent` URLs, feeds, search engines and update feeds: hosts are resolved once and the connection pinned to the checked addresses, at most 5 redirects, no redirect from a public host to a private one, credentials stripped when a redirect changes host, bodies abandoned the moment they exceed their cap. Non-public tracker URLs need an `announce`/`scrape` path; web seeds on non-public addresses need `network.allow_local_web_seeds`; web seed replies must be the exact range asked. Feed items and update URLs (which come from remote content) can never target the local network.
- **DHT**: per-source rate limits and a global reply budget, 1500-byte packet and depth-10/500-value KRPC limits, capped peer storage, announce tokens bound to requester IP and info hash and compared in constant time, one node per IP and per /24 per bucket, BEP 42 preferred.
- **LSD and zeroconf** ignore announcements from public source addresses, limit each source's rate, and cap remembered peers per torrent.
- **BEP 52 layer and hash requests** are bounded (512 hashes) and answered only for this torrent's roots; `hash` messages that fail their proof cost the sender strikes.

### Removed

- The peer-wire "pubsub" relay that had been added under BEP 50 (BEP 50 is a DHT protocol; it is listed as not implemented).
- The REST tracker client that had been labelled BEP 26, which also redirected any announce URL containing `/api/`.
- An Ed25519 signature scheme labelled BEP 35, which verified a torrent against a key embedded in the same torrent.
- A local-only lookalike of BEP 18 search, and an unused STUN codec.
- The refusal to load multi-file v2-only torrents.

### Not implemented

I2P, libtorrent's `lt_tex` tracker exchange, and BEP 50. Interoperability with third-party clients has not been tested for MSE, uTP, BEP 52, BEP 30 or BEP 26 (BEP 35 was checked against OpenSSL); their wire formats follow the specifications and have been exercised against this implementation.

## [2.2.4] - 2026-09-10

### Added

- **Discovery telemetry for DHT/PEX/LSD/Trackers/Webseeds (`synapse-engine::announcer`, `::swarm`, `::torrent`, `synapse-rpc`)**: each swarm's candidate peer pool and in-flight dial count are now attributed by discovery origin (`PeerDiscoverySource::{Tracker,Dht,Pex,Lsd}`), and surfaced end-to-end — new `discovered_from_{tracker,dht,pex,lsd}` counters, `candidate_peers`/`active_dials` on the per-torrent detail response (REST, gRPC `TorrentDetailEvent`, and the built-in web UI), plus `dht_nodes`/`dht_enabled`/`pex_enabled`/`lsd_enabled` on session stats. The web UI's torrent inspector shows swarm privacy (BEP 27), which discovery subsystems are active, active webseed mirrors, and a live per-source discovery breakdown. `PeerSnapshot` also gained `supports_pex`, derived from each connected peer's own extension handshake.
- **`AddTorrent` can now reference a local `.torrent` file path on the daemon filesystem** (`synapse-client`, `synapse-rpc::service`) via the existing `Source::FilePath` oneof, not just a magnet URI or uploaded bytes.

### Fixed

- **File priority was accepted by the API and silently discarded** (`synapse-engine::swarm`, `synapse-rpc::http_api`): `set_file_priority` sent a `TorrentCommand` to the torrent actor but never persisted the value anywhere durable for the detail endpoint to read back, so `GET .../detail` always reported every file as priority `4` (Normal) regardless of what was actually set. Priorities are now tracked per-torrent (`TorrentHandle::file_priorities`) and a new `POST /api/v1/torrents/{hash}/files/{index}/priority` REST endpoint (plus matching web UI dropdown) lets a file's priority actually be changed and correctly read back.
- **Default download directory ignored the configured setting**: `add_torrent`/`upload_torrent` (REST) and `AddTorrent` (gRPC) all fell back to a hardcoded `"."` or `"/downloads"` when no `download_dir` was supplied, instead of the daemon's actual configured `settings.download_dir`. Same fix applied to whether a torrent starts paused: previously only an explicit `paused: true` in the request would pause it; now the daemon's `start_added_torrents` setting is honored as the default when the request doesn't specify.
- **`disk.max_open_files` was configured but never passed to the disk engine** (`synapse-diskio`, `synapse-daemon`): `DiskEngine::auto()` always used a hardcoded default LRU file-descriptor cache size on both the `io_uring` and blocking backends. New `DiskEngine::auto_with_max_open_files` is now what the daemon actually calls, using the configured value.

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
