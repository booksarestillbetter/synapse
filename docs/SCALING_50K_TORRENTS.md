# Synapse 2.0: Scaling Architecture for 10,000 to 50,000+ Torrents

## 1. Executive Architecture Overview

Synapse 2.0 is built on an actor-per-torrent model utilizing Tokio, `io_uring`/blocking disk engines, and `RoaringBitfield`. While this architecture delivers multi-gigabit throughput on active swarms, scaling to **10,000 to 50,000+ torrents** (a common workload for long-term seeding and private tracker seedboxes) introduces distinct scaling bottlenecks across the async runtime, tracker networking, memory usage, and storage I/O.

This document outlines the phased roadmap to scale Synapse to 50,000+ torrents while maintaining a sub-second UI response time, sub-300MB idle RAM usage, and zero tracker rate-limit bans.

---

## 2. Resource Footprint & Comparison

| Metric | Baseline Architecture (50k Torrents) | Scaled Architecture (Target) |
|---|---|---|
| **Tokio Tasks** | ~150,000 concurrent tasks | 150 – 300 active tasks |
| **Scheduler Wakeups** | 200,000 wakeups/sec (4 Hz per torrent) | 200 – 500 wakeups/sec |
| **Announce Requests** | 2,500 req/sec (fixed 20s loop) | 5 – 20 req/sec (centralized queue + jitter) |
| **Idle RAM (50k Swarms)** | ~3.5 GB – 5.0 GB (all hashes loaded) | ~150 MB – 300 MB (hash eviction on seeds) |
| **Session Stats Query** | 40 ms – 120 ms (cloning 50k structs) | < 0.005 ms (O(1) atomic counters) |
| **Startup Resume Time** | 20 – 45 seconds (flat directory read) | < 1 second (sharded or SQLite WAL) |
| **Max Open Files** | 500 FDs (bounded by `FileCache`) | 500 FDs (bounded by `FileCache`) |

---

## 3. High-Level Architecture Diagram

```mermaid
flowchart TD
    subgraph Client & RPC
        UI[Web UI / Swagger / gRPC] -->|GET /api/v1/session/stats| Metrics[Global Atomic Metrics O(1)]
        UI -->|GET /api/v1/torrents?page=1&limit=50| PagedAPI[Engine-Level Paged Query]
    end

    subgraph Swarm Tiering Engine
        Hot[Hot Tier: 50-100 Active Swarms<br/>Full Actor + 250ms Ticker + Sockets]
        Warm[Warm Tier: 500-1000 Standby Seeds<br/>No Ticker + Wake-on-Peer Event]
        Cold[Cold Tier: 48,000+ Dormant Torrents<br/>Zero Tasks + Compressed RoaringBitfield]
    end

    subgraph Centralized Control Services
        Scheduler[Centralized Announce Scheduler<br/>Min-Heap Priority Queue + Jitter]
        Tracker[UDP/HTTP Trackers]
        Disk[DiskEngine with 500-FD LRU Cache]
        Store[(Sharded Session Store / SQLite WAL)]
    end

    Hot --> Metrics
    Warm --> Scheduler
    Scheduler --> Tracker
    Cold --> Store
    Hot --> Disk

    Cold -.->|Incoming Handshake via accept_router| Warm
    Warm -.->|Peer Unchoked & Transferring| Hot
    Hot -.->|Transfer Idle 60s| Warm
    Warm -.->|Inactive 30m| Cold
```

---

## 4. Phased Implementation Roadmap

### Phase 1: O(1) Atomic Global Metrics & Engine-Level Pagination
*Goal: Eliminate massive memory allocations and UI latency when querying large swarm counts.*

1. **Global Atomic Engine Counters**:
   - Implement `GlobalEngineMetrics` inside `SwarmEngine` using `AtomicU64` and `AtomicUsize`.
   - Update counters incrementally when torrents are added, removed, or transition states.
   - Update total upload/download rates incrementally on every rate calculation.
   - Make `/api/v1/session/stats` and `/metrics` O(1) lookups that never lock `DashMap` or clone `SwarmStats`.
2. **Engine-Level Paging**:
   - Implement `SwarmEngine::list_torrents_paged(offset, limit, filter)`.
   - Iterate the underlying map and only clone the 50 requested items into the response `Vec`.
   - Add state filtering (`?state=downloading`, `?state=seeding`, `?state=paused`).

---

### Phase 2: Centralized Priority Announce Scheduler
*Goal: Prevent tracker bans and network saturation by replacing per-torrent loops with a global scheduler.*

1. **Global Announce Manager**:
   - Replace the independent per-torrent `tokio::spawn` loops with a centralized `AnnounceScheduler`.
   - Backed by a `BinaryHeap<AnnounceJob>` ordered by `next_announce_at`.
2. **BEP 3 & BEP 15 Compliance**:
   - Parse and honor tracker `interval` (typically 1800s) and `min_interval` (typically 300s).
   - Implement exponential backoff for unreachable or failing trackers.
3. **Startup Jitter & Rate Limiter**:
   - When loading 50,000 torrents on startup, spread initial announces with randomized jitter across a configurable window (e.g. 15–30 minutes).
   - Enforce a strict global announce rate limit (e.g., max 20 announces/sec across the whole daemon).
   - Prioritize active downloading swarms over completed dormant seeds.

---

### Phase 3: Swarm Tiering & Passive Seeding (Wake-on-Peer)
*Goal: Reduce active Tokio tasks from 150,000 down to a few hundred.*

1. **Dormancy States**:
   - **Hot**: Actively transferring data with connected peers. Runs the full actor loop.
   - **Warm**: Standby seed with established tracker presence, but no active data transfer. Actor ticker stopped.
   - **Cold**: Dormant seed or paused torrent. Holds only in-memory metadata; zero Tokio tasks.
2. **Wake-on-Peer Routing**:
   - In `synapse-engine::accept_router`, when an incoming TCP connection completes the BitTorrent handshake and specifies an `info_hash` matching a Cold/Warm torrent, dynamically awaken the torrent actor and route the socket.
   - Demote Hot torrents to Warm when all peers disconnect or remain idle for $>60$ seconds.
   - Demote Warm torrents to Cold after extended inactivity ($>30$ minutes).

---

### Phase 4: Memory Optimization & Piece Hash Eviction
*Goal: Reduce idle RAM usage for 50,000 torrents from ~4 GB to under 250 MB.*

1. **Piece Hash Eviction on Completed Torrents**:
   - In `synapse-meta::Info`, allow `hashes: Arc<Vec<[u8; 20]>>` to be dropped or set to `None` once a torrent is verified 100% complete.
   - During seeding, piece requests from peers only need disk offsets (`block_locations`), not SHA-1 verification hashes.
   - If a manual re-check is triggered, reload the original `.torrent` file from the session store on demand.
2. **Compact Completion Bitfields**:
   - For 100% complete torrents, represent completion with a 0-byte `BitfieldState::AllHave` enum variant rather than storing full bitfield vectors.

---

### Phase 5: Fast Encrypted Embedded Database (SQLite/redb) & OS Tuning
*Goal: Prevent filesystem directory degradation, deliver instant boot times, and encrypt all session state at rest.*

1. **Encrypted Embedded Storage Engine**:
   - Transition away from 50,000 individual flat `.json` filesystem inodes to a fast, single-file embedded database engine (e.g. SQLite WAL mode with SQLCipher, or `redb` with transparent ChaCha20-Poly1305 / AES-256-GCM envelope encryption).
   - Encrypts all torrent names, info-hashes, download paths, private tracker URLs, and piece completion bitfields at rest.
   - Boot-up resume time: loads 50,000 indexed records in $<100\text{ ms}$ via single sequential scan instead of 50,000 random `File::open` syscalls.
   - WAL (Write-Ahead Logging) eliminates random `fsync` stalls across multiple worker threads.
2. **OS Resource Tuning**:
   - In `synapsed::main`, raise the process `RLIMIT_NOFILE` to `65,535` on startup using `libc::setrlimit`.
   - Enforce global peer connection limits (`max_global_peers = 2000`).
3. **50k Swarm Benchmark Suite**:
   - Add a high-scale simulation test in `synapse-bench` to instantiate 50,000 synthetic swarms and verify CPU usage remains $<1\%$ at idle and memory stays $<300\text{ MB}$.
