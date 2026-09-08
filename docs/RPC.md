# Synapse 2.0 — Control Plane & RPC Wire Specification

Synapse 2.0 features a modern, dual-protocol control plane designed for high-density, low-latency daemon management:

1. **High-Speed Multiplexed gRPC (`HTTP/2` + Protobuf)**: Primary control channel engineered for high-scale controllers (such as Conduit and cluster orchestrators) tracking tens of thousands of active swarms with sparse sub-20 KB/s delta streams.
2. **Standard REST HTTP API (OpenAPI 3.1 & Swagger UI)**: Built-in JSON HTTP endpoints for standard scripting, webhooks, and browser access.
3. **Prometheus Metrics Exporter**: Telemetry scrape endpoint for cluster monitoring, alerting, and Grafana dashboards.

For client library SDK examples in Rust, Python, Go, and TypeScript, see:  
📖 **[`docs/CLIENT_PROTOCOLS_AND_SDK.md`](docs/CLIENT_PROTOCOLS_AND_SDK.md)**

---

## 1. Network Endpoints & Default Ports

| Protocol | Default Address | Config Section | Description |
| :--- | :--- | :--- | :--- |
| **gRPC** | `0.0.0.0:50051` | `[rpc]` | Tonic gRPC server with optional Bearer token authentication |
| **REST API** | `0.0.0.0:8080` | `[http_api]` | JSON REST API with OpenAPI 3.1 schema at `/api-docs/openapi.json` |
| **Swagger UI**| `0.0.0.0:8080/swagger-ui` | `[http_api]` | Interactive in-browser API explorer |
| **Prometheus**| `0.0.0.0:8080/metrics` | `[metrics]` | Scrape endpoint in standard Prometheus text exposition format |
| **BitTorrent Wire** | `0.0.0.0:54345` | `[network]` | P2P peer wire protocol listener (Dual-stack TCP & UDP) |

### Authentication
When configured (`[rpc] auth_token = "secret"`), clients must supply the HTTP Bearer header:
```
Authorization: Bearer <auth_token>
```
This is enforced across both gRPC invocations and `/api/v1/*` REST routes. Health (`/api/v1/health`), Swagger UI, and `/metrics` remain open for cluster observability.

---

## 2. Protobuf Canonical Schema (`synapse.v2`)

The authoritative schema is defined in [`crates/synapse-rpc/proto/synapse.proto`](crates/synapse-rpc/proto/synapse.proto).

### Core Service Definition
```protobuf
syntax = "proto3";
package synapse.v2;

service SynapseControl {
  // Telemetry & Delta Streaming
  rpc SubscribeTorrents(SubscribeTorrentsRequest) returns (stream TorrentListEvent);
  rpc SubscribeSessionStats(SessionStatsRequest) returns (stream SessionStatsUpdate);
  rpc SubscribeTorrentDetail(TorrentDetailRequest) returns (stream TorrentDetailEvent);
  rpc GetSessionStats(SessionStatsRequest) returns (SessionStatsUpdate);

  // Swarm Lifecycle Control
  rpc AddTorrent(AddTorrentRequest) returns (AddTorrentResponse);
  rpc RemoveTorrent(RemoveTorrentRequest) returns (CommandResponse);
  rpc PauseTorrent(TorrentHashRequest) returns (CommandResponse);
  rpc ResumeTorrent(TorrentHashRequest) returns (CommandResponse);
  rpc RecheckTorrent(TorrentHashRequest) returns (CommandResponse);

  // Swarm Configuration
  rpc SetFilePriority(FilePriorityRequest) returns (CommandResponse);
  rpc SetLocation(SetLocationRequest) returns (CommandResponse);
  rpc SetRateLimits(RateLimitsRequest) returns (CommandResponse);

  // Dynamic Session Settings (Transmission Parity)
  rpc GetSessionSettings(SessionSettingsRequest) returns (SessionSettingsResponse);
  rpc UpdateSessionSettings(UpdateSessionSettingsRequest) returns (UpdateSessionSettingsResponse);
}
```

---

## 3. High-Performance Delta Streaming Protocol

Synapse avoids polling overhead via a two-tier subscription stream:

### 3.1 Initial Snapshot Sync
Upon establishing a `SubscribeTorrents` stream:
1. The daemon chunks all loaded swarms into `TorrentSnapshotChunk` messages (default: 100 swarms/chunk).
2. Each chunk contains a `TorrentSummary` with total size, progress ratio, rates, and active states.
3. The client reconstructs its local table and sets `sequence_id` baseline.

### 3.2 Sparse Delta Updates
Once initialized, the daemon transmits only `TorrentDelta` messages coalesced over a 100ms flush window:
- Only fields that changed are populated (e.g. download rate, uploaded bytes, state transitions).
- Swarms with zero state changes emit zero wire frames.
- Background network overhead for 50,000 tracked swarms is strictly bounded to **< 20 KB/s**.

---

## 4. REST API Route Map

All REST endpoints operate over JSON:

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Service health status check |
| `GET` | `/api/v1/session` | Get dynamic session settings (bandwidth, turtle mode, queues) |
| `PATCH` | `/api/v1/session` | Update in-flight session settings dynamically |
| `GET` | `/api/v1/session/stats` | Global engine throughput and active swarm counts |
| `GET` | `/api/v1/torrents` | List all loaded swarms with pagination |
| `POST` | `/api/v1/torrents` | Ingest torrent (raw base64 bytes, URL, or magnet link) |
| `GET` | `/api/v1/torrents/{hash}` | Query detailed stats and peer list for a swarm |
| `POST` | `/api/v1/torrents/{hash}/pause` | Pause an active swarm |
| `POST` | `/api/v1/torrents/{hash}/resume` | Resume a stopped swarm |
| `POST` | `/api/v1/torrents/{hash}/recheck` | Trigger asynchronous piece hash recheck on disk |
| `DELETE`| `/api/v1/torrents/{hash}` | Remove torrent (with optional `delete_data=true`) |
| `POST` | `/api/v1/torrents/{hash}/location`| Relocate swarm files on disk |
| `POST` | `/api/v1/torrents/{hash}/priority`| Set file download priorities |
| `GET` | `/metrics` | Prometheus metrics exporter |
| `GET` | `/swagger-ui` | Embedded Swagger UI interface |
| `GET` | `/api-docs/openapi.json` | OpenAPI 3.1 JSON schema |

---

## 5. Dynamic Session Settings (Transmission Parity)

Synapse 2.0 provides in-flight mutable session configuration matching Transmission daemon (`session-get`/`session-set`) capabilities.

### 5.1 Querying Settings (`GetSessionSettings`)
- **gRPC**: `SynapseControl.GetSessionSettings(SessionSettingsRequest)` returns `SessionSettingsResponse`.
- **REST**: `GET /api/v1/session` returns the complete session configuration JSON.
- Returns all bandwidth limits, Turtle Mode state (`alt_speed_enabled`, `is_alt_speed_active`), scheduled timer configurations, download & seed queue sizes, stalled torrent policies, peer limits, protocol flags (DHT/PEX/LSD/encryption), and target storage directories.

### 5.2 Updating Settings In-Flight (`UpdateSessionSettings`)
- **gRPC**: `SynapseControl.UpdateSessionSettings(UpdateSessionSettingsRequest)` returns `UpdateSessionSettingsResponse`.
- **REST**: `PATCH /api/v1/session` accepts a JSON object with any subset of fields.
- **Immediate Effect**: All dynamic fields (rate limits, queue concurrency, turtle mode toggles) take effect immediately without restarting the daemon or dropping active peer sockets.
- **Static Warning Semantics**: If a client supplies values for static parameters requiring a full restart (`peer_port`, `rpc_listen_addr`, `http_listen_addr`), Synapse applies all valid dynamic fields and populates the `warnings` array notifying the caller which properties require a restart.

For complete parameter matrices, schedule bitmask formulas, and Transmission GUI parity mappings, refer to [`docs/SESSION_SETTINGS.md`](docs/SESSION_SETTINGS.md).

