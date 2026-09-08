# Synapse 2.0 — Client Protocols & SDK Reference

Synapse 2.0 exposes two full-featured, modern control planes for external frontends, web UIs, automation scripts, and mobile/desktop clients:

1. **High-Performance gRPC Control Plane** (Sub-20 KB/s delta-stream over Tonic gRPC / HTTP/2 on port `50051`).
2. **Alternative JSON REST HTTP API & Swagger UI** (Standard HTTP/1.1 & HTTP/2 REST endpoints on port `8080`).
3. **Prometheus Metrics Exporter** (Observability metrics in Prometheus exposition format on `/metrics`).

### Authentication

Set `[rpc] auth_token = "..."` in `synapse.toml` to require it (unset means both control planes
are open — fine for `127.0.0.1`-only binds, not for anything reachable off-host). Every
request on both transports needs the same header, checked against that value:

```
authorization: Bearer <token>
```

Enforced on every gRPC method (via a Tonic interceptor) and on `/api/v1/*` REST routes. Health
(`/api/v1/health`), Swagger UI, `/api-docs/openapi.json`, and `/metrics` stay open regardless —
health checks and Prometheus scraping are conventionally same-trust-network concerns, and
gating `/metrics` would break a scrape config that doesn't send arbitrary headers.

---

## 1. High-Performance gRPC Control Plane (`synapse.v2`)

The primary interface for rich frontends, commanders (Conduit), and management UIs is **Tonic gRPC over HTTP/2** (`synapse.v2` package).

### 1.1 Sparse Delta Streaming (`SubscribeTorrents`)
Instead of polling the entire torrent list every second, Synapse implements a **100ms sparse delta coalescer**. 
- On initial connection, the client receives a snapshot of all active swarms partitioned into `TorrentSnapshotChunk` messages.
- On subsequent ticks, Synapse transmits **only fields that changed** via `TorrentDelta` (e.g. rate deltas, state transitions, progress, peer counts).
- For a client hosting 50,000 swarms, background bandwidth consumption is **under 20 KB/s**.

### 1.2 Protobuf Service Definition (`synapse.v2`)

The snippet below was previously a hand-maintained approximation that had drifted from the
real schema (wrong field names throughout `PeerDetail`, `AddTorrentRequest`, `RemoveTorrentRequest`,
`SetLocationRequest`, `RateLimitsRequest`; `TrackerDetail`/`FileDetail` renamed to
`TrackerStatus`/`FileProgress` on the wire). It's now copied verbatim from
`crates/synapse-rpc/proto/synapse.proto` — if this doc and that file ever disagree again,
the `.proto` file is authoritative; regenerate this snippet from it rather than hand-editing.

```protobuf
syntax = "proto3";
package synapse.v2;

service SynapseControl {
  rpc SubscribeTorrents(SubscribeTorrentsRequest) returns (stream TorrentListEvent);
  rpc SubscribeSessionStats(SessionStatsRequest) returns (stream SessionStatsUpdate);

  rpc SubscribeTorrentDetail(TorrentDetailRequest) returns (stream TorrentDetailEvent);

  rpc AddTorrent(AddTorrentRequest) returns (AddTorrentResponse);
  rpc RemoveTorrent(RemoveTorrentRequest) returns (CommandResponse);
  rpc PauseTorrent(TorrentHashRequest) returns (CommandResponse);
  rpc ResumeTorrent(TorrentHashRequest) returns (CommandResponse);
  rpc RecheckTorrent(TorrentHashRequest) returns (CommandResponse);
  rpc SetFilePriority(FilePriorityRequest) returns (CommandResponse);
  rpc SetLocation(SetLocationRequest) returns (CommandResponse);
  rpc SetRateLimits(RateLimitsRequest) returns (CommandResponse);
  rpc GetSessionStats(SessionStatsRequest) returns (SessionStatsUpdate);
  rpc GetSessionSettings(SessionSettingsRequest) returns (SessionSettingsResponse);
  rpc UpdateSessionSettings(UpdateSessionSettingsRequest) returns (UpdateSessionSettingsResponse);
}

enum TorrentState {
  STATE_STOPPED = 0;
  STATE_CHECKING = 1;
  STATE_QUEUED = 2;
  STATE_DOWNLOADING = 3;
  STATE_SEEDING = 4;
  STATE_ERROR = 5;
}

message SubscribeTorrentsRequest {
  uint32 chunk_size = 1;
  uint32 flush_window_ms = 2;
}

message SessionStatsRequest {}

message SessionStatsUpdate {
  uint64 rate_download = 1;
  uint64 rate_upload = 2;
  uint64 total_downloaded = 3;
  uint64 total_uploaded = 4;
  uint32 torrent_count = 5;
  uint32 active_downloading = 6;
  uint32 active_seeding = 7;
  uint64 free_disk_space_bytes = 8;
  int64 timestamp_ms = 9;
}

message TorrentSummary {
  string hash = 1;
  string name = 2;
  uint64 total_size = 3;
  float progress = 4;
  TorrentState state = 5;
  uint64 rate_download = 6;
  uint64 rate_upload = 7;
  uint32 peers_connected = 8;
  uint32 peers_sending = 9;
  uint64 eta_seconds = 10;
  float ratio = 11;
  optional string error_message = 12;
  string download_dir = 13;
  int64 added_at = 14;
}

message TorrentDelta {
  string hash = 1;
  optional float progress = 2;
  optional TorrentState state = 3;
  optional uint64 rate_download = 4;
  optional uint64 rate_upload = 5;
  optional uint32 peers_connected = 6;
  optional uint32 peers_sending = 7;
  optional uint64 eta_seconds = 8;
  optional float ratio = 9;
  optional string error_message = 10;
}

message TorrentSnapshotChunk {
  repeated TorrentSummary items = 1;
  uint32 chunk_index = 2;
  uint32 total_chunks = 3;
  bool is_last_chunk = 4;
}

message TorrentListEvent {
  uint64 sequence_id = 1;
  int64 timestamp_ms = 2;
  oneof event {
    TorrentSnapshotChunk snapshot = 3;
    TorrentSummary added = 4;
    TorrentDelta updated = 5;
    string removed_hash = 6;
  }
}

message TorrentDetailRequest {
  string hash = 1;
  uint32 refresh_interval_ms = 2;
}

message PeerDetail {
  string address = 1;
  string client_name = 2;
  string flags = 3;
  uint64 rate_to_client = 4;
  uint64 rate_to_peer = 5;
  float progress = 6;
  bool is_encrypted = 7;
  bool is_utp = 8;
  optional string country_code = 9;
  optional string as_name = 10;
}

message TrackerStatus {
  string url = 1;
  string status = 2;
  uint32 seeders = 3;
  uint32 leechers = 4;
  int64 next_announce_in = 5;
  optional string failure_reason = 6;
  bool is_circuit_broken = 7;
}

message FileProgress {
  uint32 index = 1;
  string path = 2;
  uint64 size_bytes = 3;
  uint64 bytes_completed = 4;
  float progress = 5;
  uint32 priority = 6; // 0=skip, 1=low, 4=normal, 7=high
}

message TorrentDetailEvent {
  string hash = 1;
  int64 timestamp_ms = 2;
  repeated PeerDetail active_peers = 3;
  repeated TrackerStatus trackers = 4;
  repeated FileProgress files = 5;
  bytes piece_bitfield = 6;
}

message AddTorrentRequest {
  oneof source {
    bytes torrent_bytes = 1;
    string magnet_uri = 2;
    string file_path = 3;
  }
  optional string download_dir = 4;
  optional bool start_paused = 5;
}

message AddTorrentResponse {
  bool success = 1;
  string hash = 2;
  string name = 3;
  optional string error = 4;
}

message RemoveTorrentRequest {
  string hash = 1;
  bool delete_data = 2;
}

message TorrentHashRequest {
  string hash = 1;
}

message FilePriorityRequest {
  string hash = 1;
  uint32 file_index = 2;
  uint32 priority = 3;
}

message SetLocationRequest {
  string hash = 1;
  string new_download_dir = 2;
  bool move_existing_files = 3;
}

message RateLimitsRequest {
  optional uint64 global_download_limit = 1;
  optional uint64 global_upload_limit = 2;
  optional string per_torrent_hash = 3;
  optional uint64 torrent_download_limit = 4;
  optional uint64 torrent_upload_limit = 5;
}

message CommandResponse {
  bool success = 1;
  optional string error = 2;
}

message SessionSettingsRequest {}

message SessionSettingsResponse {
  bool download_limit_enabled = 1;
  uint64 download_limit_bytes = 2;
  bool upload_limit_enabled = 3;
  uint64 upload_limit_bytes = 4;

  bool alt_speed_enabled = 5;
  uint64 alt_speed_down_bytes = 6;
  uint64 alt_speed_up_bytes = 7;
  bool alt_speed_time_enabled = 8;
  uint32 alt_speed_time_begin = 9;
  uint32 alt_speed_time_end = 10;
  uint32 alt_speed_time_days = 11;

  bool download_queue_enabled = 12;
  uint32 download_queue_size = 13;
  bool seed_queue_enabled = 14;
  uint32 seed_queue_size = 15;
  uint32 max_active_torrents = 16;
  bool queue_stalled_enabled = 17;
  uint32 queue_stalled_minutes = 18;
  bool seed_ratio_limited = 19;
  double seed_ratio_limit = 20;
  bool idle_seeding_limit_enabled = 21;
  uint32 idle_seeding_limit_minutes = 22;

  uint32 max_peers_per_torrent = 23;
  uint32 max_global_peers = 24;
  bool dht_enabled = 25;
  bool pex_enabled = 26;
  bool lsd_enabled = 27;
  string encryption = 28;

  string download_dir = 29;
  optional string incomplete_dir = 30;
  bool incomplete_dir_enabled = 31;
  bool start_added_torrents = 32;
  bool trash_original_torrent_files = 33;
  bool is_alt_speed_active = 34;
}

message UpdateSessionSettingsRequest {
  optional bool download_limit_enabled = 1;
  optional uint64 download_limit_bytes = 2;
  optional bool upload_limit_enabled = 3;
  optional uint64 upload_limit_bytes = 4;

  optional bool alt_speed_enabled = 5;
  optional uint64 alt_speed_down_bytes = 6;
  optional uint64 alt_speed_up_bytes = 7;
  optional bool alt_speed_time_enabled = 8;
  optional uint32 alt_speed_time_begin = 9;
  optional uint32 alt_speed_time_end = 10;
  optional uint32 alt_speed_time_days = 11;

  optional bool download_queue_enabled = 12;
  optional uint32 download_queue_size = 13;
  optional bool seed_queue_enabled = 14;
  optional uint32 seed_queue_size = 15;
  optional uint32 max_active_torrents = 16;
  optional bool queue_stalled_enabled = 17;
  optional uint32 queue_stalled_minutes = 18;
  optional bool seed_ratio_limited = 19;
  optional double seed_ratio_limit = 20;
  optional bool idle_seeding_limit_enabled = 21;
  optional uint32 idle_seeding_limit_minutes = 22;

  optional uint32 max_peers_per_torrent = 23;
  optional uint32 max_global_peers = 24;
  optional bool dht_enabled = 25;
  optional bool pex_enabled = 26;
  optional bool lsd_enabled = 27;
  optional string encryption = 28;

  optional string download_dir = 29;
  optional string incomplete_dir = 30;
  optional bool incomplete_dir_enabled = 31;
  optional bool start_added_torrents = 32;
  optional bool trash_original_torrent_files = 33;

  optional uint32 peer_port = 34;
  optional string rpc_listen_addr = 35;
  optional string http_listen_addr = 36;
}

message UpdateSessionSettingsResponse {
  bool success = 1;
  repeated string warnings = 2;
  optional string error = 3;
}
```

---

## 2. Alternative JSON REST HTTP API

For environments where gRPC is impractical (simple scripts, webhooks, cURL, third-party services), Synapse includes an optional, zero-overhead REST API built on Axum.

### 2.1 Enabling the REST API
In `synapse.toml`:
```toml
[http_api]
enabled = true
listen_addr = "127.0.0.1:8080"
```

### 2.2 Endpoints Reference

| Method | Path | Description | Request Body | Response |
|---|---|---|---|---|
| `GET` | `/api/v1/health` | Health check & version | None | `{"status":"ok","version":"2.0.0"}` |
| `GET` | `/api/v1/session` | Full dynamic session settings, bitrates & turtle state | None | `{"download_limit_pretty":"50 Mbps","alt_speed_enabled":false,...}` |
| `PATCH` | `/api/v1/session` | In-flight session settings update (accepts "50m", "1g", etc.) | JSON object with desired updates | `{"success":true,"warnings":[]}` |
| `GET` | `/api/v1/session/stats` | Global throughput & swarm counts | None | `{"total_torrents":10,"download_rate":0,"upload_rate":0,...}` |
| `GET` | `/api/v1/torrents` | List all torrents with live progress | None | `{"torrents":[{"info_hash":"...","name":"...","progress":1.0,...}]}` |
| `POST` | `/api/v1/torrents` | Add torrent via magnet or raw `.torrent` | `{"magnet":"magnet:?xt=...","download_dir":null,"paused":false}` | `{"success":true,"message":"..."}` |
| `GET` | `/api/v1/torrents/{info_hash}` | Get deep swarm inspection | None | `{"info_hash":"...","files":[...],"peers":[...]}` |
| `DELETE` | `/api/v1/torrents/{info_hash}` | Remove torrent | None | `{"success":true,"message":"..."}` |
| `POST` | `/api/v1/torrents/{info_hash}/pause` | Pause torrent swarm | None | `{"success":true,"message":"..."}` |
| `POST` | `/api/v1/torrents/{info_hash}/resume` | Resume torrent swarm | None | `{"success":true,"message":"..."}` |

### 2.3 OpenAPI 3.1 Specification & Interactive Swagger UI
- **Swagger UI Browser Interface**: `http://127.0.0.1:8080/swagger-ui`
- **OpenAPI 3.1 JSON Schema**: `http://127.0.0.1:8080/api-docs/openapi.json`

---

## 3. Prometheus Observability Metrics

Synapse exports real-time health and throughput metrics formatted for Prometheus scrapers and Grafana dashboards.

### 3.1 Enabling the Prometheus Endpoint
In `synapse.toml`:
```toml
[metrics]
enabled = true
listen_addr = "127.0.0.1:8080"
path = "/metrics"
```

### 3.2 Metrics Catalog

```prometheus
# HELP synapse_torrents_total Total number of registered torrents
# TYPE synapse_torrents_total gauge
synapse_torrents_total 42

# HELP synapse_torrents_downloading Torrents actively downloading
# TYPE synapse_torrents_downloading gauge
synapse_torrents_downloading 5

# HELP synapse_torrents_seeding Torrents actively seeding
# TYPE synapse_torrents_seeding gauge
synapse_torrents_seeding 30

# HELP synapse_torrents_paused Torrents in cold paused state
# TYPE synapse_torrents_paused gauge
synapse_torrents_paused 7

# HELP synapse_download_bytes_per_second Current global download rate
# TYPE synapse_download_bytes_per_second gauge
synapse_download_bytes_per_second 104857600

# HELP synapse_upload_bytes_per_second Current global upload rate
# TYPE synapse_upload_bytes_per_second gauge
synapse_upload_bytes_per_second 52428800

# HELP synapse_peers_connected Total connected P2P peers
# TYPE synapse_peers_connected gauge
synapse_peers_connected 384

# HELP synapse_dht_nodes_routing Routing table active DHT nodes
# TYPE synapse_dht_nodes_routing gauge
synapse_dht_nodes_routing 512

# HELP synapse_circuit_breakers_tripped Currently tripped tracker/peer circuit breakers
# TYPE synapse_circuit_breakers_tripped gauge
synapse_circuit_breakers_tripped 0
```

---

## 4. Client SDK Implementation Examples

### 4.1 Rust Client (`synapse-client` SDK Crate)

Synapse provides a first-class, lightweight client crate `synapse-client` (and companion protobuf definitions `synapse-proto`) with zero daemon/engine dependencies.

Add to `Cargo.toml`:
```toml
[dependencies]
synapse-client = { path = "../synapse/crates/synapse-client" } # or via crates.io
```

```rust
use synapse_client::{SynapseClient, SynapseLiveCache};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to Synapse 2.0 daemon (or use connect_lazy)
    let client = SynapseClient::connect("http://127.0.0.1:50051")
        .await?
        .with_auth_token("secret-bearer-token");

    // Add torrent via Magnet URI, remote HTTP URL, or raw bytes
    let add_resp = client.add_magnet(
        "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=Ubuntu",
        None,
        false,
    ).await?;
    println!("Added swarm info-hash: {}", add_resp.hash);

    // Spawn an auto-reconnecting live replica cache synchronized via 100ms delta push streams
    let cache = SynapseLiveCache::spawn(client.clone());

    // Instant O(1) in-memory cache reads without network polling
    tokio::time::sleep(Duration::from_millis(200)).await;
    for summary in cache.list_torrents() {
        println!("{}: {:.1}% (state: {})", summary.name, summary.progress * 100.0, summary.state);
    }

    // Transmission-Parity Dynamic Session Mutation & Turtle Mode
    client.set_turtle_mode(true).await?;
    client.set_bandwidth_limits(Some(10_000_000), Some(2_000_000)).await?;
    client.set_queue_concurrency(Some(10), Some(5), Some(15)).await?;

    let settings = client.get_session_settings().await?;
    println!("Alt-speed active: {}, Download queue: {}", settings.is_alt_speed_active, settings.download_queue_size);

    Ok(())
}
```

### 4.2 TypeScript / JavaScript (REST API)

```typescript
const BASE_URL = 'http://127.0.0.1:8080/api/v1';

async function addTorrent(magnetUri: string) {
  const res = await fetch(`${BASE_URL}/torrents`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    // REST's AddTorrentRequest field is `magnet`, not `magnet_uri` (see http_api.rs) — a
    // distinct, simpler struct from the gRPC AddTorrentRequest's oneof above.
    body: JSON.stringify({ magnet: magnetUri, paused: false })
  });
  return await res.json();
}

async function getTorrents() {
  const res = await fetch(`${BASE_URL}/torrents`);
  return await res.json();
}

async function getSessionSettings() {
  const res = await fetch(`${BASE_URL}/session`);
  return await res.json();
}

async function updateSessionSettings(settings: Record<string, any>) {
  const res = await fetch(`${BASE_URL}/session`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings)
  });
  return await res.json();
}
```

### 4.3 Python (REST API)

```python
import requests

BASE_URL = "http://127.0.0.1:8080/api/v1"

def add_torrent(magnet_uri: str):
    response = requests.post(f"{BASE_URL}/torrents", json={
        "magnet": magnet_uri,
        "paused": False
    })
    return response.json()

def list_torrents():
    return requests.get(f"{BASE_URL}/torrents").json()

def get_session_settings():
    return requests.get(f"{BASE_URL}/session").json()

def update_session_settings(updates: dict):
    return requests.patch(f"{BASE_URL}/session", json=updates).json()

if __name__ == "__main__":
    torrents = list_torrents()
    print(f"Total swarms: {len(torrents)}")
    settings = get_session_settings()
    print(f"Turtle Mode active: {settings.get('is_alt_speed_active')}")
    resp = update_session_settings({"alt_speed_enabled": True, "download_queue_size": 10})
    print(f"Updated settings: {resp}")
```

### 4.4 Go (REST API)

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

const baseURL = "http://127.0.0.1:8080/api/v1"

type AddTorrentReq struct {
	Magnet string `json:"magnet"`
	Paused bool   `json:"paused"`
}

type SessionSettingsUpdate struct {
	AltSpeedEnabled   *bool   `json:"alt_speed_enabled,omitempty"`
	DownloadQueueSize *int    `json:"download_queue_size,omitempty"`
	SpeedLimitDown    *uint64 `json:"download_limit_bytes,omitempty"`
}

func addTorrent(magnetURI string) error {
	reqBody, _ := json.Marshal(AddTorrentReq{Magnet: magnetURI, Paused: false})
	resp, err := http.Post(baseURL+"/torrents", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Printf("HTTP Status: %s\n", resp.Status)
	return nil
}

func updateSessionSettings(update SessionSettingsUpdate) error {
	body, _ := json.Marshal(update)
	req, _ := http.NewRequest(http.MethodPatch, baseURL+"/session", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Printf("Patch Status: %s\n", resp.Status)
	return nil
}

func main() {
	resp, err := http.Get(baseURL + "/torrents")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Printf("Queried swarms: %s\n", resp.Status)
}
```

