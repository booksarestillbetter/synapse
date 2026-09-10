# Synapse 2.0 Trust, Safety & Privacy Architecture

This document provides a comprehensive security, privacy, and integrity overview of the Synapse 2.0 BitTorrent daemon. It is written for system administrators, private tracker staff, security researchers, and privacy-conscious users who want to understand how Synapse handles data at rest, data in transit, tracker reporting, logging, and identity.

---

## Table of Contents
1. [Core Philosophy: Zero Telemetry & Memory Safety](#1-core-philosophy-zero-telemetry--memory-safety)
2. [Tracker Integrity & Fair Seeding (BEP 3 & BEP 15)](#2-tracker-integrity--fair-seeding-bep-3--bep-15)
   - [Monotonic Cumulative Accounting vs. Deltas](#monotonic-cumulative-accounting-vs-deltas)
   - [Why Double-Sending or Retrying Cannot Cheat](#why-double-sending-or-retrying-cannot-cheat)
   - [Tracker-Governed Intervals & Anti-Herd Jitter](#tracker-governed-intervals--anti-herd-jitter)
   - [Socket-Bound Byte Accounting](#socket-bound-byte-accounting)
   - [Lifecycle Event Accuracy & Anti-Ghost Seeding](#lifecycle-event-accuracy--anti-ghost-seeding)
   - [BEP 20 Invariant Peer Identification](#bep-20-invariant-peer-identification)
3. [Data at Rest: Encrypted Session Storage (`session.db`)](#3-data-at-rest-encrypted-session-storage-sessiondb)
   - [ChaCha20-Poly1305 AEAD Encryption](#chacha20-poly1305-aead-encryption)
   - [Key Management & Ephemeral Memory Mode](#key-management--ephemeral-memory-mode)
   - [Cryptographic Tamper-Proofing](#cryptographic-tamper-proofing)
4. [Data in Transit: Peer Wire Encryption (MSE / PE)](#4-data-in-transit-peer-wire-encryption-mse--pe)
   - [Protocol Encryption & DPI Bypass](#protocol-encryption--dpi-bypass)
   - [Configurable Encryption Enforcement](#configurable-encryption-enforcement)
   - [Secure Tracker Communication (TLS)](#secure-tracker-communication-tls)
5. [Private Swarm & Tracker Privacy (BEP 27)](#5-private-swarm--tracker-privacy-bep-27)
   - [Non-Bypassable Swarm Isolation](#non-bypassable-swarm-isolation)
   - [Automatic Passkey Redaction in Logs & Metrics](#automatic-passkey-redaction-in-logs--metrics)
6. [Network Defense: IP Filtering & Blocklists](#6-network-defense-ip-filtering--blocklists)
7. [Control Plane Security (gRPC, REST, Web UI)](#7-control-plane-security-grpc-rest-web-ui)
   - [Authentication & Constant-Time Validation](#authentication--constant-time-validation)
   - [Safe Network Binding Defaults](#safe-network-binding-defaults)
   - [Path Traversal Defense](#path-traversal-defense)
8. [Logging & Observability Hygiene](#8-logging--observability-hygiene)

---

## 1. Core Philosophy: Zero Telemetry & Memory Safety

- **100% Verifiable Open Source**: Synapse contains zero proprietary binary blobs, third-party analytics SDKs, advertising frameworks, crash-reporting daemons, or background auto-updaters.
- **Zero Phone-Home Telemetry**: Synapse never pings external developers, never collects usage metrics, and never sends diagnostic data over the internet. Network I/O is strictly confined to:
  1. Configured BitTorrent swarms and trackers.
  2. Optional DHT / LSD discovery if public swarms are active.
  3. Inbound/outbound control API calls explicitly initiated by you.
- **Rust Memory Safety**: The entire daemon is written in modern, memory-safe Rust. Buffer overflows, off-by-one errors, use-after-free, and pointer aliasing bugs that historically plagued C/C++ clients are eliminated at compile time by the Rust borrow checker.

---

## 2. Tracker Integrity & Fair Seeding (BEP 3 & BEP 15)

Synapse is designed to be an exemplary citizen on private and public trackers alike. It adheres strictly to the official BitTorrent specifications ([BEP 3](https://www.bittorrent.org/beps/bep_0003.html) for HTTP trackers and [BEP 15](https://www.bittorrent.org/beps/bep_0015.html) for UDP trackers).

### Monotonic Cumulative Accounting vs. Deltas
A common fear among users and tracker operators is whether a client reports incremental "deltas" (e.g. *"I uploaded 25 MB"*) which could accidentally be counted twice if a network request retries.

Under the BitTorrent protocol, **clients never report deltas**. Clients report **monotonically increasing cumulative lifetime totals**:
- `uploaded`: Total bytes transmitted to peers on this torrent.
- `downloaded`: Total bytes verified and written to disk on this torrent.
- `left`: Total bytes remaining until 100% completion (strictly `0` when seeding).

### Why Double-Sending or Retrying Cannot Cheat
When the tracker receives an announce, the tracker server computes the difference against the previously stored value:
$$\Delta = \text{new uploaded} - \text{last recorded uploaded}$$
$$\text{credit added} = \Delta$$

If a network timeout causes Synapse to retry an announce, or if two announces arrive close together:
1. First announce arrives: `uploaded = 500,000,000`. Tracker grants credit for the increase and records `500,000,000`.
2. Second announce arrives: `uploaded = 500,000,000`.
3. Tracker calculates: `500,000,000 - 500,000,000 = 0`.
4. **Credit added: 0 bytes.**

Because accounting is cumulative, **double-sending is mathematically incapable of inflating your stats or cheating the community**.

### Tracker-Governed Intervals & Anti-Herd Jitter
- **Tracker in Charge**: Synapse does not guess when to announce. Each tracker response returns an `interval` field (typically 1800s / 30 mins). Synapse's centralized `AnnounceScheduler` respects this interval as a strict requirement.
- **Anti-Thundering Herd Jitter**: To prevent thousands of clients from hitting the tracker simultaneously, Synapse applies a BEP 3-compliant randomized $\pm 10\%$ jitter to announce schedules.
- **Circuit Breaker Levee**: If a tracker experiences downtime, Synapse trips into exponential backoff (up to 30 minutes). When the tracker recovers, Synapse's 4-state recovery levee throttles announces (1 req / 3s $\rightarrow$ 1 req / 1s $\rightarrow$ 3 req / s) with randomized 5–15s jitter across swarms, preventing the recovering server from being overwhelmed.

### Socket-Bound Byte Accounting
In Synapse (`synapse-engine::torrent`), `uploaded_bytes` is incremented **only when a block is successfully handed to the kernel TCP/uTP socket write buffer** in response to a peer's `Request` message. Synapse never estimates, inflates, or fabricates upload statistics.

### Lifecycle Event Accuracy & Anti-Ghost Seeding
- **`event=started`**: Dispatched once when a torrent is initiated or unpaused.
- **`event=completed`**: Dispatched the exact millisecond the final piece finishes and passes cryptographic SHA-1 verification.
- **`event=stopped`**: Dispatched upon graceful daemon shutdown or when a torrent is paused. This cleanly removes your IP and port from the tracker's active peer list, preventing "ghost seeding" where other peers waste connections trying to dial an inactive port.

### BEP 20 Invariant Peer Identification
To protect users from being misidentified or banned by tracker automated anti-cheat systems, Synapse enforces a fixed Azureus-style BEP 20 peer ID prefix:
```text
-SY2200-<12 cryptographically random bytes>
```
The 12-byte random suffix is generated fresh at startup using the operating system's CSPRNG (`OsRng`). The prefix is hardcoded and invariant, ensuring that peers and trackers receive clean, tamper-free client identification matching the running version.

---

## 3. Data at Rest: Encrypted Session Storage (`session.db`)

Traditional BitTorrent clients store session state (including torrent names, file paths, active trackers, info-hashes, and bitfield progress) in plaintext files or standard unencrypted SQLite databases on disk. Anyone with filesystem access or a seized drive can immediately read your entire torrent history.

Synapse 2.0 solves this with an **Encrypted Embedded Session Architecture**:

```
+-------------------------------------------------------------+
|                      Synapse Swarm Engine                   |
+-------------------------------------------------------------+
                               |
                   Serde JSON Serialization
                               |
                               v
+-------------------------------------------------------------+
|        ChaCha20-Poly1305 Authenticated Encryption (AEAD)    |
|   (256-bit Key from session.key or SYNAPSE_SESSION_KEY)     |
+-------------------------------------------------------------+
                               |
              Encrypted Binary Ciphertext + Nonce
                               |
                               v
+-------------------------------------------------------------+
|                    Embedded redb Database                   |
|                        (session.db)                         |
+-------------------------------------------------------------+
```

### ChaCha20-Poly1305 AEAD Encryption
- Every individual swarm state record is encrypted using **ChaCha20-Poly1305** authenticated encryption with associated data (AEAD).
- A fresh, unique 96-bit random nonce is generated by `OsRng` for every database write.
- Info hashes, names, download paths, bitfields, upload/download metrics, and resume states are encrypted before touching disk.

### Key Management & Ephemeral Memory Mode
1. **Default Mode (`session.key`)**:
   - On first startup, Synapse generates a cryptographically secure 256-bit key from `OsRng` and writes it to `session_dir/session.key`.
   - On UNIX systems, Synapse automatically restricts permissions on this file to **`0600`** (`-rw-------`, owner-only read/write).
2. **Ephemeral / Stateless Mode (`SYNAPSE_SESSION_KEY`)**:
   - For high-security environments, Docker containers, or diskless nodes, you can provide the 32-byte key via the environment variable:
     ```bash
     export SYNAPSE_SESSION_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
     ```
   - When set, **no key file is ever written to disk**. If the system is powered down or the container destroyed, the on-disk `session.db` cannot be decrypted by anyone.

### Cryptographic Tamper-Proofing
Because ChaCha20-Poly1305 includes a 128-bit Poly1305 message authentication code (MAC), any attempt to modify, corrupt, or inject malicious payloads into `session.db` is immediately detected and rejected with an authentication error on startup.

---

## 4. Data in Transit: Peer Wire Encryption (MSE / PE)

To protect your traffic from ISP traffic shaping, deep packet inspection (DPI), and hostile network monitoring, Synapse implements full **BitTorrent Protocol Encryption / Message Stream Encryption (MSE / PE)**:

### Protocol Encryption & DPI Bypass
- **Diffie-Hellman Key Exchange**: Uses 768-bit Diffie-Hellman key negotiation on connect to establish shared symmetric secrets without transmitting keys over the wire.
- **RC4-drop1024 Stream Cipher**: Discards the initial 1024 bytes of keystream to eliminate known RC4 bias weaknesses, encrypting both the initial handshake and all subsequent peer payload blocks.
- **Obfuscation**: Scrambles message headers, length prefixes, and piece payloads so firewalls cannot identify BitTorrent signatures.

### Configurable Encryption Enforcement
Configured in `synapse.toml` under `[network].encryption` or dynamically via the Web UI / RPC:
- `required` (**Forced Encryption**): Drops any peer that does not support MSE/PE encryption. No plaintext BitTorrent traffic will ever leave your node.
- `prefer_encrypted` (**Default**): Automatically attempts encrypted connections to all peers, falling back to plaintext only if the remote peer is legacy-only.
- `tolerated`: Accepts incoming encrypted or plaintext connections.
- `disabled`: Forces plaintext only (not recommended).

### Secure Tracker Communication (TLS)
All HTTPS tracker announces and scrapes use modern TLS 1.2/1.3 with certificate verification via system trust roots or Mozilla CA bundles.

---

## 5. Private Swarm & Tracker Privacy (BEP 27)

Private torrent communities depend on strict isolation: unauthorized peers outside the tracker must never be allowed into the swarm.

### Non-Bypassable Swarm Isolation
When a torrent contains the `private = 1` flag in its metadata ([BEP 27](https://www.bittorrent.org/beps/bep_0027.html)), Synapse permanently enforces three strict rules:
1. **DHT Announce Disabled**: The Distributed Hash Table bit in the peer handshake is cleared. Synapse never advertises private info-hashes to the public DHT routing table.
2. **Peer Exchange (PEX) Disabled**: Synapse refuses to negotiate BEP 11 `ut_pex` on private swarms. It will neither send local peer lists to peers nor accept peer lists from others.
3. **Local Service Discovery (LSD) Disabled**: Synapse suppresses multicast announcements over the local network (UDP `239.192.152.143:6771`), preventing local network eavesdropping.

> [!IMPORTANT]
> In Synapse, private swarm isolation is non-configurable and hardcoded. There is no config option to accidentally leak private swarms to DHT or PEX.

### Automatic Passkey Redaction in Logs & Metrics
Private trackers authenticate members by embedding secret passkeys in tracker URLs (e.g. `https://tracker.site.org/announce?passkey=32charalphanumeric`).

Synapse includes an automated URL sanitizer (`synapse-tracker::sanitize_tracker_url`):
- Any parameter named `pass`, `passkey`, `auth`, `token`, `key`, or `secret` is scrubbed and replaced with `[REDACTED]`.
- Example logged URL:
  ```text
  http://tracker.private-site.org/announce?info_hash=...&passkey=[REDACTED]
  ```
- Your secret credentials will never leak into log files, Docker container logs, terminal outputs, or system journals.

---

## 6. Network Defense: IP Filtering & Blocklists

Synapse includes a zero-dependency kernel-grade IP blocklist engine (`synapse-engine::ipfilter`):
- **CIDR & Numeric Range Parsing**: Evaluates both IPv4 and IPv6 addresses against subnets (e.g., `192.0.2.0/24`) and inclusive numerical ranges.
- **Immediate Socket Termination**: Incoming connection handshakes and outbound dials are checked before any protocol negotiation occurs. Blocked IPs are dropped immediately with zero byte exposure.
- **Dual-Stack Support**: Fast binary search lookups across both IPv4 and IPv6 blocklists without stalling Tokio worker threads.

---

## 7. Control Plane Security (gRPC, REST, Web UI)

Synapse is designed to run securely on servers and containers without exposing administrative interfaces to attackers.

### Authentication & Constant-Time Validation
- **Bearer Token Authentication**: The control plane (gRPC, REST API, Web Interface) supports token authentication via `Authorization: Bearer <token>`.
- **Constant-Time Verification**: All token comparisons use constant-time equality checks (`subtle::ConstantTimeEq`), preventing timing attacks where attackers guess tokens byte-by-byte based on response latency.

### Safe Network Binding Defaults
- **Default Localhost**: The REST API and Web UI default to binding `127.0.0.1:8080`, and gRPC defaults to `127.0.0.1:50051`.
- Synapse never binds to `0.0.0.0` unless you explicitly configure it to do so in `synapse.toml` or via CLI flags.

### Path Traversal Defense
- All endpoints accepting file paths (such as `download_dir`, watch files, torrent inspection, or data directory moves) strictly validate path boundaries to prevent directory traversal attacks (e.g., `../../etc/passwd`).

---

## 8. Logging & Observability Hygiene

For privacy-conscious operators, logging should be minimal, controllable, and leak-free:

- **Configurable Log Levels**: Use standard `RUST_LOG` filtering (`warn`, `info`, `debug`, `trace`). Running with `RUST_LOG=warn` or `RUST_LOG=error` suppresses all routine transfer details.
- **No Persistent File Logging by Default**: `synapsed` logs to standard output/standard error, allowing container runtimes (Docker, Podman) or system service managers (`systemd-journald`) to enforce log retention and rotation according to your local privacy policies.
- **Pull-Based Metrics**: Synapse exposes Prometheus metrics on `/metrics` (when `[http_api]` is enabled). Metrics are strictly pull-based—Synapse never pushes metrics to external servers.

---

## Summary Matrix

| Security & Privacy Feature | Synapse 2.0 Implementation |
| :--- | :--- |
| **Telemetry / Phone Home** | **None (Zero bytes transmitted outside user control)** |
| **Tracker Protocol Accounting** | **Monotonic cumulative counters (BEP 3/15), zero-delta duplicate safe** |
| **Upload Byte Verification** | **Strictly bound to physical socket write calls** |
| **Peer ID Format** | **Invariant BEP 20 Azureus ID (`-SY2200-` + random CSPRNG suffix)** |
| **Data at Rest** | **Encrypted `session.db` via ChaCha20-Poly1305 AEAD** |
| **Key Storage** | **`0600` permission file or pure in-memory `SYNAPSE_SESSION_KEY`** |
| **Data in Transit** | **MSE / PE Message Stream Encryption (RC4-drop1024 + Diffie-Hellman)** |
| **Private Torrents (BEP 27)** | **Hardcoded isolation: DHT disabled, PEX disabled, LSD disabled** |
| **Passkey Logging** | **Automatic redaction (`passkey=[REDACTED]`) in all logs/metrics** |
| **IP Filtering** | **Native IPv4/IPv6 CIDR and range blocklist engine** |
| **Control Plane Auth** | **Constant-time Bearer Token validation** |
| **Default Listen Bindings** | **Strictly `127.0.0.1` localhost** |
