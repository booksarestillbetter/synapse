# AGENT.md — Working in this Repo (Synapse 2.0)

This file orients an LLM coding agent working on Synapse 2.0. Read this before making changes;
read `docs/ARCHITECTURE.md` for system internals and `docs/SCALING_50K_TORRENTS.md` for the
50k-swarm scaling design.

## What this is

Synapse 2.0 is an ultra-high-scale, headless BitTorrent daemon built in Rust. It runs standalone
as a next-generation BitTorrent engine, and its gRPC/REST control plane is designed to be driven
by any downstream media-management front-end that wants a high-scale retriever backend — see
`docs/CLIENT_PROTOCOLS_AND_SDK.md` and `docs/COMPLETION_INSTRUCTIONS.md` for the client/webhook
contracts a front-end implements.

It is maintained under the GitHub account **booksarestillbetter**. Don't attribute code or design decisions to the original author by name anywhere in docs, commit messages, or comments you write — use generic phrasing ("the project's original author") or, for current direction/ownership, `booksarestillbetter`.

The codebase is built on **Tokio multi-threaded async**, **Linux `io_uring`** zero-copy direct I/O (with POSIX `pwrite`/`pread` worker thread fallback on macOS/BSD), **Tonic gRPC** with high-speed sparse delta streaming, and lockless multi-torrent orchestration.

## Repo layout (`crates/`)

```
synapse/
├── Cargo.toml                  # Root workspace Cargo.toml (LTO, opt-level=3, stripped binary)
├── docs/
│   ├── ARCHITECTURE.md         # System internals, 3-tier virtualization & 50k scaling architecture
│   ├── BENCHMARKS.md           # Performance benchmarks, 50k scale harness & reproduction guide
│   ├── BEP_SUPPORT_MATRIX.md   # Master protocol compliance matrix across all BEPs
│   ├── CLIENT_PROTOCOLS_AND_SDK.md # Client SDK reference (Rust, Go, Python, TS), REST API & Swagger
│   ├── COMPLETION_INSTRUCTIONS.md # Wire spec for the completion-webhook contract
│   ├── HACKING.md              # Contributor & developer guide (quality gates, invariants)
│   ├── RPC.md                  # Control plane wire specification & Protobuf canonical schema
│   ├── SCALING_50K_TORRENTS.md # 50k swarm scale design and implementation breakdown
│   └── SESSION_SETTINGS.md     # Session settings, in-flight dynamic adjustment & Transmission parity
└── crates/
    ├── synapse-bencode/        # Zero-dependency, zero-copy bencode encoder/decoder
    ├── synapse-config/         # Daemon configuration loader & multi-homed network settings
    ├── synapse-meta/           # .torrent and magnet parser with path traversal protection
    ├── synapse-wire/           # BEP 3/6/9/10/11/14/22/29/55 codecs, MSE/PE stream encryption
    ├── synapse-picker/         # RoaringBitfield, rarest-first & sequential picker, tit-for-tat choker
    ├── synapse-diskio/         # Linux io_uring & POSIX portable disk engine with FD LRU cache
    ├── synapse-tracker/        # HTTP & BEP 15 UDP tracker clients, passkey redactor, & Canary Circuit Breaker
    ├── synapse-dht/            # BEP 5 / BEP 32 IPv6 Kademlia DHT & Iterative Network Walker
    ├── synapse-engine/         # SwarmEngine, 3-tier virtualization, encrypted redb SessionStore, & rate limiters
    ├── synapse-rpc/            # Tonic gRPC SynapseControl service, REST API, Swagger UI, & Prometheus metrics
    ├── synapse-bench/          # Standalone simulation, load testing & performance benchmark suite
    └── synapse-daemon/         # synapsed binary entrypoint (wires storage, network, swarm, watch dir, and APIs)
```

## Key Subsystems

- **Disk Engine (`synapse-diskio`)**: Zero-copy I/O using direct Linux `io_uring` submission queue rings or POSIX `pread`/`pwrite` threadpool on macOS. Clock-eviction file descriptor cache.
- **Wire & Protocol Encryption (`synapse-wire`)**: Zero-copy `bytes::Bytes` message framing with strict bounds, and PE/MSE RC4 stream encryption cipher to evade ISP throttling.
- **Picker & Choker (`synapse-picker`)**: MSB-first bitfield, rarest-first and sequential piece pickers, tit-for-tat choker with rotating optimistic unchoking.
- **Trackers & DHT (`synapse-tracker`, `synapse-dht`)**: BEP 15 UDP client with anti-spoofing, HTTP client, Canary Circuit Breaker (auto-isolation into Swarm Pressure Relief), and 160-bucket Kademlia DHT node with recursive multi-hop Iterative Network Walker (`iterative_find_node`, `iterative_get_peers`).
- **Swarm Engine (`synapse-engine`)**: Lockless `DashMap` swarm table, single unified inbound TCP handshake demuxer (`accept_router`), atomic session state persistence (`SessionStore`), and a pluggable post-completion lifecycle dispatcher (hardlink/staging + the completion-webhook contract in `docs/COMPLETION_INSTRUCTIONS.md`).
- **Control Plane (`synapse-rpc`)**: Tonic gRPC service (`SynapseControl`) with two-tier subscriptions: `SubscribeTorrents` (initial snapshot + 100ms sparse delta coalescing reducing 50,000-torrent bandwidth to < 20 KB/s) and `SubscribeTorrentDetail` for deep peer telemetry.

## Build, test, run

```sh
cargo build --workspace                    # build daemon and all crates
cargo test --workspace                     # run the full unit and integration test suite
cargo run --release -p synapsed -- -c config.toml # run the daemon binary
```

## Front-End Integration

Synapse's control plane (gRPC `SynapseControl` + optional REST) is designed to be driven by any
compatible front-end, not just one specific product. Two integration surfaces exist:

- **Live control & telemetry**: `docs/CLIENT_PROTOCOLS_AND_SDK.md` — the gRPC/REST wire contract
  and example SDK usage (Rust, Go, Python, TS) for listing, adding, and controlling torrents.
- **Completion notifications**: `docs/COMPLETION_INSTRUCTIONS.md` — an optional webhook contract
  ("ask a URL where a completed torrent's files should go") that any front-end can implement; on
  piece/download completion Synapse dispatches instant lifecycle notifications, can execute
  staging hardlinks with zero shell scripts, and logs completion events to an offline WAL
  (`completed_wal.jsonl`) if the configured endpoint is temporarily unreachable.

A dedicated first-party client is planned; until then, any front-end implementing the above
contracts works the same way.
