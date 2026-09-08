# Synapse 2.0 Session Settings & Transmission Parity Reference

This document provides a comprehensive reference for session configuration in Synapse 2.0. Synapse provides full feature parity with Transmission daemon (`session-get` / `session-set`) and Transmission GUI clients (such as TransGUI `daemonoptions.pas`), allowing rich in-flight dynamic configuration adjustments without restarting the daemon or dropping active peer sockets.

---

## 1. Dynamic (In-Flight) vs. Static (Restart Required) Settings

Synapse categorizes all configuration into two tiers:

- **Dynamic (In-Flight)**: Can be modified on-the-fly via gRPC (`UpdateSessionSettings`), REST (`PATCH /api/v1/session`), or Transmission RPC (`session-set`). Changes take effect immediately within the running daemon.
- **Static (Restart Required)**: Requires a full process restart because it binds sockets, sets authentication tokens, or modifies database files. If a client attempts to mutate a static field in flight, Synapse applies all valid dynamic fields and returns an explicit warning identifying the parameters that require a restart.

| Setting Name | Type | In-Flight? | Transmission Parity Key | Description |
| :--- | :--- | :---: | :--- | :--- |
| `download_limit_enabled` | `bool` | **Yes** | `speed-limit-down-enabled` | Enable global download bandwidth rate limit |
| `download_limit_bytes` | `u64` | **Yes** | `speed-limit-down` | Global download limit (bytes/second; Transmission uses KB/s) |
| `upload_limit_enabled` | `bool` | **Yes** | `speed-limit-up-enabled` | Enable global upload bandwidth rate limit |
| `upload_limit_bytes` | `u64` | **Yes** | `speed-limit-up` | Global upload limit (bytes/second; Transmission uses KB/s) |
| `alt_speed_enabled` | `bool` | **Yes** | `alt-speed-enabled` | Manual Turtle Mode toggle (overrides scheduled speed) |
| `alt_speed_down_bytes` | `u64` | **Yes** | `alt-speed-down` | Turtle Mode download limit (bytes/second) |
| `alt_speed_up_bytes` | `u64` | **Yes** | `alt-speed-up` | Turtle Mode upload limit (bytes/second) |
| `alt_speed_time_enabled` | `bool` | **Yes** | `alt-speed-time-enabled` | Enable scheduled Turtle Mode timer |
| `alt_speed_time_begin` | `u32` | **Yes** | `alt-speed-time-begin` | Scheduled start time in minutes from midnight (0..1439) |
| `alt_speed_time_end` | `u32` | **Yes** | `alt-speed-time-end` | Scheduled end time in minutes from midnight (0..1439) |
| `alt_speed_time_days` | `u32` | **Yes** | `alt-speed-time-day` | Days of week bitmask (Sun=1, Mon=2, Tue=4, Wed=8, Thu=16, Fri=32, Sat=64) |
| `download_queue_enabled` | `bool` | **Yes** | `download-queue-enabled` | Enable download queue concurrency limits |
| `download_queue_size` | `usize` | **Yes** | `download-queue-size` | Maximum concurrently active downloads |
| `seed_queue_enabled` | `bool` | **Yes** | `seed-queue-enabled` | Enable seed queue concurrency limits |
| `seed_queue_size` | `usize` | **Yes** | `seed-queue-size` | Maximum concurrently active seeds |
| `max_active_torrents` | `usize` | **Yes** | `queue-stalled-enabled` (related) | Total maximum active torrents (downloading + seeding) |
| `queue_stalled_enabled` | `bool` | **Yes** | `queue-stalled-enabled` | Exclude stalled torrents from download queue concurrency count |
| `queue_stalled_minutes` | `u32` | **Yes** | `queue-stalled-minutes` | Idle time without transfer before torrent is considered stalled |
| `seed_ratio_limited` | `bool` | **Yes** | `seedRatioLimited` | Enable automatic stopping upon reaching target share ratio |
| `seed_ratio_limit` | `f64` | **Yes** | `seedRatioLimit` | Target share ratio (e.g. 2.0 = 200% upload) |
| `idle_seeding_limit_enabled` | `bool` | **Yes** | `idle-seeding-limit-enabled` | Enable automatic stopping upon reaching maximum seeding duration |
| `idle_seeding_limit_minutes` | `u32` | **Yes** | `idle-seeding-limit` | Maximum seeding duration in minutes before auto-stopping |
| `max_peers_per_torrent` | `usize` | **Yes** | `peer-limit-per-torrent` | Concurrency limit of peers connected to each torrent |
| `max_global_peers` | `usize` | **Yes** | `peer-limit-global` | Concurrency limit of total connected peers across all swarms |
| `dht_enabled` | `bool` | **Yes** | `dht-enabled` | Enable Kademlia Mainline DHT |
| `pex_enabled` | `bool` | **Yes** | `pex-enabled` | Enable Peer Exchange (BEP 11) |
| `lsd_enabled` | `bool` | **Yes** | `lpd-enabled` | Enable Local Peer Discovery (BEP 14/22) |
| `encryption` | `string` | **Yes** | `encryption` | Protocol encryption mode (`prefer_encrypted`, `require_encrypted`, `disabled`) |
| `download_dir` | `string` | **Yes** | `download-dir` | Default directory for completed files |
| `incomplete_dir` | `string` | **Yes** | `incomplete-dir` | Directory for unfinished torrent downloads |
| `incomplete_dir_enabled` | `bool` | **Yes** | `incomplete-dir-enabled` | Store unfinished torrent downloads in incomplete directory |
| `start_added_torrents` | `bool` | **Yes** | `start-added-torrents` | Automatically start newly added torrents |
| `trash_original_torrent_files` | `bool` | **Yes** | `trash-original-torrent-files` | Delete `.torrent` file after successful ingestion |
| `peer_port` / `listen_port` | `u16` | **No** | `peer-port` | Listening port for inbound peer wire connections (Default: `54345`) |
| `rpc_listen_addr` | `string` | **No** | `rpc-port` / `rpc-bind-address` | gRPC service listen address (Default: `0.0.0.0:50051`) |
| `http_listen_addr` | `string` | **No** | N/A | REST API / Swagger UI listen address (Default: `0.0.0.0:8080`) |
| `session_dir` | `string` | **No** | N/A | Embedded session database directory (`session.db`) |

---

## 2. Bandwidth Throttling & Turtle Mode (Alt-Speed)

### Token-Bucket Rate Limiter
Synapse enforces rate limits through lockless atomic token buckets (`TokenBucket`) per second.
- When `download_limit_enabled` or `upload_limit_enabled` is true, the engine replenishes tokens up to `download_limit_bytes` and `upload_limit_bytes`.
- When disabled, buckets are marked unthrottled (`usize::MAX`), eliminating locking overhead on multi-gigabit links.

### Bitrate Format Support
All bandwidth limits (`download_limit`, `upload_limit`, `alt_speed_down`, `alt_speed_up`) support both raw bytes and standard networking bitrate strings:
- **`50m` / `50mbps`**: $50 \times 10^6 / 8 = 6,250,000$ B/s (6.25 MB/s)
- **`1000m`**: $1000 \times 10^6 / 8 = 125,000,000$ B/s (125 MB/s = 1 Gbps)
- **`1g` / `1gbps`**: $10^9 / 8 = 125,000,000$ B/s (125 MB/s)
- **`5g`**: $5 \times 10^9 / 8 = 625,000,000$ B/s (625 MB/s)
- **`100k` / `100kbps`**: $100 \times 10^3 / 8 = 12,500$ B/s
- **Floats**: `2.5g` ($312.5$ MB/s), `0.5m` ($62.5$ KB/s)
- **Raw bytes**: `10485760` (10 MB/s for backward compatibility)
- **`0` / `unlimited` / `off`**: Disables throttling (unlimited)

REST responses (`GET /api/v1/session`) return both `download_limit_bytes` and human-readable `download_limit_pretty` (e.g. `"50 Mbps"`). The `PATCH /api/v1/session` endpoint accepts strings like `"50m"` or integers.

### Turtle Mode (Alternative Speed Limits)
Turtle Mode allows temporarily or conditionally throttling bandwidth to lower thresholds (e.g. during daytime or work hours).
- **Manual Toggle**: Setting `alt_speed_enabled = true` forces Turtle Mode active immediately.
- **Scheduled Timer**: Setting `alt_speed_time_enabled = true` activates Turtle Mode automatically within configured time windows and day masks.

#### Schedule Bitmask & Time Calculation
The day mask is encoded as a 7-bit integer conforming to the Transmission standard:
- **Sunday**: `1` (`1 << 0`)
- **Monday**: `2` (`1 << 1`)
- **Tuesday**: `4` (`1 << 2`)
- **Wednesday**: `8` (`1 << 3`)
- **Thursday**: `16` (`1 << 4`)
- **Friday**: `32` (`1 << 5`)
- **Saturday**: `64` (`1 << 6`)
- **Every Day**: `127` (`1 + 2 + 4 + 8 + 16 + 32 + 64`)
- **Weekdays**: `62` (`2 + 4 + 8 + 16 + 32`)
- **Weekends**: `65` (`1 + 64`)

Time of day is expressed in minutes from midnight:
- `09:00 AM` = $9 \times 60 = 540$
- `05:00 PM` = $17 \times 60 = 1020$

Overnight spans (where `time_begin > time_end`, such as 22:00 to 06:00) are automatically handled via wraparound modulo arithmetic.

---

## 3. Queue Management & Concurrency Policies

The Synapse Queue Manager (`QueueManager`) coordinates active torrents against hardware and network bandwidth budgets:

### Download & Seed Queues
1. **Download Concurrency**: When `download_queue_enabled` is true, at most `download_queue_size` (default: `5`) downloading swarms are active. Additional swarms remain in `Queued` state.
2. **Seed Concurrency**: When `seed_queue_enabled` is true, at most `seed_queue_size` (default: `10`) seeding swarms are active.
3. **Max Active Torrents**: `max_active_torrents` (default: `20`) caps the total sum of downloading + seeding torrents.

### Stalled Torrent Detection
When `queue_stalled_enabled` is true:
- A downloading swarm that has had zero byte transfer for longer than `queue_stalled_minutes` (default: `1` minute) is considered stalled.
- Stalled downloads do **not** count towards `download_queue_size`, allowing queued downloads with healthy seeds to start immediately.

### Seeding Auto-Stop (Share Ratio & Idle Duration)
The daemon background reconciler checks seeding swarms every second:
- **Share Ratio**: When `seed_ratio_limited` is true and a torrent's uploaded/downloaded ratio reaches `seed_ratio_limit` (e.g. `2.0`), the swarm is automatically paused (`Stopped`).
- **Idle Duration**: When `idle_seeding_limit_enabled` is true and a completed torrent has been seeding for longer than `idle_seeding_limit_minutes`, the swarm is automatically paused (`Stopped`).

---

## 4. Configuration File (`synapse.toml`)

```toml
[queue]
# Concurrency limits for active downloads and seeds
download_queue_enabled = true
download_queue_size = 5
seed_queue_enabled = true
seed_queue_size = 10
max_active_torrents = 20

# Stalled torrent detection
queue_stalled_enabled = true
queue_stalled_minutes = 1

# Seeding auto-stop rules
seed_ratio_limited = false
seed_ratio_limit = 2.0
idle_seeding_limit_enabled = false
idle_seeding_limit_minutes = 30

[bandwidth]
download_limit_enabled = false
download_limit = "50m"              # 50 Mbps = 6.25 MB/s (or download_limit_bytes)
upload_limit_enabled = false
upload_limit = "1000m"             # 1000 Mbps = 1 Gbps = 125 MB/s

[bandwidth.alt_speed]
enabled = false                    # Manual Turtle Mode toggle
download_limit = "5m"              # 5 Mbps (or download_limit_bytes = 625000)
upload_limit = "1m"                # 1 Mbps (or upload_limit_bytes = 125000)
time_enabled = false               # Scheduled Turtle Mode
time_begin_minutes = 540           # 09:00 AM (9 * 60)
time_end_minutes = 1020            # 05:00 PM (17 * 60)
time_days = 127                    # All days (127), Weekdays (62), Weekends (65)

[disk]
download_dir = "/data/downloads"
incomplete_dir = "/data/incomplete"
incomplete_dir_enabled = false

[lifecycle]
start_added_torrents = true
trash_original_torrent_files = false
```

---

## 5. Environment Variable Overrides

All settings can be overridden via `SYNAPSE_*` environment variables, which take precedence over `synapse.toml`:

| Environment Variable | Equivalent Config Setting | Example Value |
| :--- | :--- | :--- |
| `SYNAPSE_PEER_PORT` | `network.listen_port` | `54345` |
| `SYNAPSE_RPC_ADDR` | `rpc.listen_addr` | `0.0.0.0:50051` |
| `SYNAPSE_HTTP_ADDR` | `http_api.listen_addr` | `0.0.0.0:8080` |
| `SYNAPSE_DOWNLOAD_DIR` | `disk.download_dir` | `/media/downloads` |
| `SYNAPSE_INCOMPLETE_DIR` | `disk.incomplete_dir` | `/media/incomplete` |
| `SYNAPSE_INCOMPLETE_DIR_ENABLED`| `disk.incomplete_dir_enabled` | `true` |
| `SYNAPSE_DOWNLOAD_LIMIT_ENABLED` | `bandwidth.download_limit_enabled` | `true` |
| `SYNAPSE_DOWNLOAD_LIMIT` | `bandwidth.download_limit_bytes` | `50m` (50 Mbps) or `10485760` (bytes) |
| `SYNAPSE_UPLOAD_LIMIT_ENABLED` | `bandwidth.upload_limit_enabled` | `true` |
| `SYNAPSE_UPLOAD_LIMIT` | `bandwidth.upload_limit_bytes` | `1000m` (1 Gbps) or `1g` |
| `SYNAPSE_ALT_SPEED_ENABLED` | `bandwidth.alt_speed.enabled` | `true` |
| `SYNAPSE_ALT_SPEED_DOWN` | `bandwidth.alt_speed.download_limit_bytes` | `5m` (5 Mbps) |
| `SYNAPSE_ALT_SPEED_UP` | `bandwidth.alt_speed.upload_limit_bytes` | `1m` (1 Mbps) |
| `SYNAPSE_ALT_SPEED_TIME_ENABLED`| `bandwidth.alt_speed.time_enabled` | `true` |
| `SYNAPSE_ALT_SPEED_TIME_BEGIN` | `bandwidth.alt_speed.time_begin_minutes` | `540` |
| `SYNAPSE_ALT_SPEED_TIME_END` | `bandwidth.alt_speed.time_end_minutes` | `1020` |
| `SYNAPSE_ALT_SPEED_TIME_DAYS` | `bandwidth.alt_speed.time_days` | `62` |
| `SYNAPSE_DOWNLOAD_QUEUE_ENABLED` | `queue.download_queue_enabled` | `true` |
| `SYNAPSE_DOWNLOAD_QUEUE_SIZE` | `queue.download_queue_size` | `5` |
| `SYNAPSE_SEED_QUEUE_ENABLED` | `queue.seed_queue_enabled` | `true` |
| `SYNAPSE_SEED_QUEUE_SIZE` | `queue.seed_queue_size` | `10` |
| `SYNAPSE_MAX_ACTIVE_TORRENTS` | `queue.max_active_torrents` | `20` |
| `SYNAPSE_QUEUE_STALLED_ENABLED` | `queue.queue_stalled_enabled` | `true` |
| `SYNAPSE_QUEUE_STALLED_MINUTES` | `queue.queue_stalled_minutes` | `2` |
| `SYNAPSE_SEED_RATIO_LIMITED` | `queue.seed_ratio_limited` | `true` |
| `SYNAPSE_SEED_RATIO_LIMIT` | `queue.seed_ratio_limit` | `2.5` |
| `SYNAPSE_IDLE_SEEDING_LIMIT_ENABLED` | `queue.idle_seeding_limit_enabled` | `true` |
| `SYNAPSE_IDLE_SEEDING_LIMIT_MINUTES` | `queue.idle_seeding_limit_minutes` | `60` |

---

## 6. REST API Endpoints (`/api/v1/session`)

### `GET /api/v1/session`
Retrieves full active session settings and dynamic state.

### `PATCH /api/v1/session`
Updates any subset of session settings in flight.

**Request Body**:
```json
{
  "alt_speed_enabled": true,
  "download_queue_size": 8,
  "peer_port": 54345
}
```

**Response `200 OK`**:
```json
{
  "success": true,
  "warnings": [
    "peer_port requires a daemon restart to take effect (current listen port remains 54345)"
  ]
}
```

---

## 7. gRPC Control Plane (`synapse.v2.SynapseControl`)

Protobuf RPC methods:
```protobuf
service SynapseControl {
  rpc GetSessionSettings(SessionSettingsRequest) returns (SessionSettingsResponse);
  rpc UpdateSessionSettings(UpdateSessionSettingsRequest) returns (UpdateSessionSettingsResponse);
}
```
Client SDKs (Rust, Go, Python, TypeScript) can inspect and update all settings dynamically through type-safe protobuf structs.
