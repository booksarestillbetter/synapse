# Synapse 2.0 — Contributor & Developer Guide (HACKING)

Welcome to the internal development guide for Synapse 2.0! This guide covers the workspace architecture, development workflow, testing standards, and core invariants for contributing to the codebase.

---

## 1. Workspace Architecture

Synapse 2.0 is partitioned into 12 modular crates under `crates/`, each with strict encapsulation and separation of concerns:

| Crate | Directory | Purpose |
| :--- | :--- | :--- |
| **`synapse-bencode`** | `crates/synapse-bencode` | High-performance BEncode codec with recursion depth limits (`MAX_DEPTH = 64`) to defend against stack-overflow attacks. |
| **`synapse-config`** | `crates/synapse-config` | Complete TOML configuration parser (`synapse.toml`) with sensible defaults for disk, network, RPC, logging, and lifecycle hooks. |
| **`synapse-meta`** | `crates/synapse-meta` | Torrent metadata parser: BEP 3 (v1), BEP 52 (v2 Merkle trees), BEP 35 (signatures), BEP 36 (feeds), BEP 47 (padding files), and magnet links. |
| **`synapse-wire`** | `crates/synapse-wire` | Zero-copy peer wire protocol engine: message framing, MSE/PE RC4 crypto, BEP 6 Fast Ext, BEP 10 Ext, BEP 11 PEX, BEP 29 uTP/LEDBAT, BEP 54 STUN, and BEP 55 Holepunch. |
| **`synapse-picker`** | `crates/synapse-picker` | Bitfield and piece selection: `RoaringBitfield`, rarest-first, sequential, file priority piece masks, and super-seeding (initial seeding). |
| **`synapse-diskio`** | `crates/synapse-diskio` | High-throughput direct disk engine: Linux `io_uring` kernel submission with fallocate caching, and POSIX portable thread-pool fallback. |
| **`synapse-tracker`** | `crates/synapse-tracker` | Multi-tier announce engine: HTTP/HTTPS & BEP 15 UDP trackers, BEP 41 TLV options, BEP 48 scrape, passkey redactor, and circuit breaker. |
| **`synapse-dht`** | `crates/synapse-dht` | Dual-stack Kademlia DHT: BEP 5 (IPv4) & BEP 32 (IPv6), BEP 42 secure Node IDs, BEP 44 arbitrary KV storage, BEP 46 dynamic torrents, and BEP 51 sample indexing. |
| **`synapse-engine`** | `crates/synapse-engine` | Multi-torrent `SwarmEngine`: Hot/Warm/Cold swarm virtualization, Endgame mode, token-bucket rate limits, QueueManager, PCP/NAT-PMP/UPnP, and Conduit lifecycle hooks. |
| **`synapse-rpc`** | `crates/synapse-rpc` | Dual control plane: Tonic gRPC (`proto/synapse.proto`), REST HTTP API with embedded Swagger UI (`/swagger-ui`), and Prometheus metrics exporter (`/metrics`). |
| **`synapse-daemon`** | `crates/synapse-daemon` | Production `synapsed` binary entrypoint, multi-target logging (Console, File, Syslog 514), watch directory scanner, session migration tool, and torrent inspector. |
| **`synapse-bench`** | `crates/synapse-bench` | Standalone high-scale benchmarking CLI (`swarm`, `disk`, `dht`, `transfer`, `rpc`, `all`) and live WebTorrent download harness. |

---

## 2. Developer Workflow & Quality Gates

All contributions must compile cleanly with zero warnings under Rust 2021 edition:

### Building
```bash
# Debug build across entire workspace
cargo build --workspace

# Release build of the daemon and benchmark binaries
cargo build --release -p synapsed -p synapse-bench
```

### Running Tests
```bash
# Run all unit tests, integration tests, and doc-tests
cargo test --workspace

# Run a specific crate's test suite
cargo test -p synapse-meta
cargo test -p synapse-engine
```

### Running Clippy & Format
```bash
# Must pass with zero warnings
cargo clippy --workspace --all-targets -- -D warnings

# Format verification
cargo fmt --all -- --check
```

---

## 3. Core Architectural Invariants

When writing or modifying code in Synapse 2.0, you must uphold the following architectural rules:

1. **Zero Unsafe Outside `io_uring`**:
   No `unsafe` blocks are permitted in any crate except for the Linux direct I/O ring submission call in `crates/synapse-diskio/src/uring.rs:314`. All other network, parsing, and buffer operations must use safe Rust with bounded slices (`bytes::Bytes`).

2. **No Synchronous Locks Across `.await`**:
   `parking_lot::RwLock` and `parking_lot::Mutex` must only protect instant in-memory structures (e.g. counters, bitfields, endpoint maps) and must **never** be held across an asynchronous `.await` boundary.

3. **Strict BEP 27 Private Swarm Isolation**:
   When a swarm is loaded with `info.private = 1`, all DHT announces, Peer Exchange (PEX), and Local Peer Discovery (LSD) must be unconditionally disabled. This invariant is non-configurable to protect private tracker user credentials and security.

4. **Sanitized Path Safety**:
   All paths extracted from `.torrent` dictionaries or user inputs must be validated against directory traversal attacks via `synapse_meta::path_is_safe`. Absolute paths, parent path components (`..`), and null bytes must always be rejected.

5. **Resource Limits on Untrusted Input**:
   - BEncode recursion depth is strictly capped at `MAX_DEPTH = 64`.
   - Remote URL and metadata chunk downloads are capped at 10 MB to prevent memory exhaustion and zip-bomb attacks.
   - TCP peer buffers use `try_send` with fallback timeouts to prevent slow peers from stalling swarm actors.
