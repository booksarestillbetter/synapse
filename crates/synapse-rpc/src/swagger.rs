//! OpenAPI 3.1 Specification and Interactive Swagger UI HTML Generator.

pub const OPENAPI_JSON: &str = r#"{
  "openapi": "3.1.0",
  "info": {
    "title": "Synapse 2.0 REST API",
    "description": "Comprehensive alternative REST API for Synapse 2.0 headless BitTorrent daemon.",
    "version": "2.0.0",
    "license": {
      "name": "ISC"
    }
  },
  "paths": {
    "/api/v1/health": {
      "get": {
        "summary": "Health check",
        "description": "Returns system health status and version information.",
        "responses": {
          "200": {
            "description": "Healthy",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "status": { "type": "string", "example": "ok" },
                    "version": { "type": "string", "example": "2.0.0" },
                    "features": {
                      "type": "array",
                      "items": { "type": "string" },
                      "example": ["tracker_circuit_breaker_v1"]
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/session": {
      "get": {
        "summary": "Get session settings",
        "description": "Retrieves active dynamic session settings including bandwidth limits, turtle mode, queue policies, and directory paths.",
        "responses": {
          "200": {
            "description": "Dynamic session settings retrieved successfully",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "download_limit_enabled": { "type": "boolean" },
                    "download_limit_bytes": { "type": "integer" },
                    "download_limit_pretty": { "type": "string", "example": "50 Mbps" },
                    "upload_limit_enabled": { "type": "boolean" },
                    "upload_limit_bytes": { "type": "integer" },
                    "upload_limit_pretty": { "type": "string", "example": "1 Gbps" },
                    "alt_speed_enabled": { "type": "boolean" },
                    "alt_speed_down_bytes": { "type": "integer" },
                    "alt_speed_down_pretty": { "type": "string", "example": "5 Mbps" },
                    "alt_speed_up_bytes": { "type": "integer" },
                    "alt_speed_up_pretty": { "type": "string", "example": "1 Mbps" },
                    "alt_speed_time_enabled": { "type": "boolean" },
                    "alt_speed_time_begin": { "type": "integer" },
                    "alt_speed_time_end": { "type": "integer" },
                    "alt_speed_time_days": { "type": "integer" },
                    "is_alt_speed_active": { "type": "boolean" },
                    "download_queue_enabled": { "type": "boolean" },
                    "download_queue_size": { "type": "integer" },
                    "seed_queue_enabled": { "type": "boolean" },
                    "seed_queue_size": { "type": "integer" },
                    "max_active_torrents": { "type": "integer" },
                    "queue_stalled_enabled": { "type": "boolean" },
                    "queue_stalled_minutes": { "type": "integer" },
                    "seed_ratio_limited": { "type": "boolean" },
                    "seed_ratio_limit": { "type": "number" },
                    "idle_seeding_limit_enabled": { "type": "boolean" },
                    "idle_seeding_limit_minutes": { "type": "integer" },
                    "max_peers_per_torrent": { "type": "integer" },
                    "max_global_peers": { "type": "integer" },
                    "dht_enabled": { "type": "boolean" },
                    "pex_enabled": { "type": "boolean" },
                    "lsd_enabled": { "type": "boolean" },
                    "encryption": { "type": "string" },
                    "download_dir": { "type": "string" },
                    "incomplete_dir": { "type": "string", "nullable": true },
                    "incomplete_dir_enabled": { "type": "boolean" },
                    "start_added_torrents": { "type": "boolean" },
                    "trash_original_torrent_files": { "type": "boolean" }
                  }
                }
              }
            }
          }
        }
      },
      "patch": {
        "summary": "Update session settings",
        "description": "Updates in-flight session settings dynamically. Static parameters (peer port, listen addresses) will return a warning requiring restart.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "download_limit_enabled": { "type": "boolean" },
                  "download_limit_bytes": { "type": "integer" },
                  "upload_limit_enabled": { "type": "boolean" },
                  "upload_limit_bytes": { "type": "integer" },
                  "alt_speed_enabled": { "type": "boolean" },
                  "alt_speed_down_bytes": { "type": "integer" },
                  "alt_speed_up_bytes": { "type": "integer" },
                  "alt_speed_time_enabled": { "type": "boolean" },
                  "alt_speed_time_begin": { "type": "integer" },
                  "alt_speed_time_end": { "type": "integer" },
                  "alt_speed_time_days": { "type": "integer" },
                  "download_queue_enabled": { "type": "boolean" },
                  "download_queue_size": { "type": "integer" },
                  "seed_queue_enabled": { "type": "boolean" },
                  "seed_queue_size": { "type": "integer" },
                  "max_active_torrents": { "type": "integer" },
                  "queue_stalled_enabled": { "type": "boolean" },
                  "queue_stalled_minutes": { "type": "integer" },
                  "seed_ratio_limited": { "type": "boolean" },
                  "seed_ratio_limit": { "type": "number" },
                  "idle_seeding_limit_enabled": { "type": "boolean" },
                  "idle_seeding_limit_minutes": { "type": "integer" },
                  "max_peers_per_torrent": { "type": "integer" },
                  "max_global_peers": { "type": "integer" },
                  "dht_enabled": { "type": "boolean" },
                  "pex_enabled": { "type": "boolean" },
                  "lsd_enabled": { "type": "boolean" },
                  "encryption": { "type": "string" },
                  "download_dir": { "type": "string" },
                  "incomplete_dir": { "type": "string" },
                  "incomplete_dir_enabled": { "type": "boolean" },
                  "start_added_torrents": { "type": "boolean" },
                  "trash_original_torrent_files": { "type": "boolean" },
                  "peer_port": { "type": "integer" },
                  "rpc_listen_addr": { "type": "string" },
                  "http_listen_addr": { "type": "string" }
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Settings updated successfully",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "success": { "type": "boolean" },
                    "warnings": {
                      "type": "array",
                      "items": { "type": "string" }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/session/stats": {
      "get": {
        "summary": "Global session statistics",
        "description": "Returns aggregate throughput rates, swarm counts, DHT node telemetry, discovery subsystem states, and disk I/O metrics.",
        "responses": {
          "200": {
            "description": "Session statistics retrieved successfully",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "total_torrents": { "type": "integer" },
                    "downloading_torrents": { "type": "integer" },
                    "seeding_torrents": { "type": "integer" },
                    "paused_torrents": { "type": "integer" },
                    "queued_torrents": { "type": "integer" },
                    "downloaded_bytes": { "type": "integer" },
                    "uploaded_bytes": { "type": "integer" },
                    "download_rate": { "type": "integer" },
                    "upload_rate": { "type": "integer" },
                    "peers_connected": { "type": "integer" },
                    "active_actors": { "type": "integer" },
                    "free_disk_space_bytes": { "type": "integer" },
                    "dht_nodes": { "type": "integer" },
                    "dht_enabled": { "type": "boolean" },
                    "pex_enabled": { "type": "boolean" },
                    "lsd_enabled": { "type": "boolean" },
                    "version": { "type": "string" }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/torrents": {
      "get": {
        "summary": "List all torrents",
        "description": "Retrieves all managed torrent swarms with live state and completion metrics.",
        "responses": {
          "200": { "description": "List of active swarms" }
        }
      },
      "post": {
        "summary": "Add a new torrent",
        "description": "Adds a torrent via Magnet URI or Base64-encoded .torrent file.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "url": { "type": "string", "description": "Remote HTTP/HTTPS .torrent URL or Magnet URI" },
                  "magnet": { "type": "string", "description": "Magnet URI" },
                  "torrent_base64": { "type": "string", "description": "Base64-encoded raw .torrent file bytes" },
                  "download_dir": { "type": "string", "description": "Optional custom download directory override" },
                  "paused": { "type": "boolean", "default": false }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "description": "Torrent added successfully" },
          "400": { "description": "Invalid magnet URI or malformed torrent bytes" }
        }
      }
    },
    "/api/v1/torrents/{info_hash}": {
      "get": {
        "summary": "Inspect torrent summary",
        "parameters": [
          { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": {
          "200": { "description": "Torrent summary info" },
          "404": { "description": "Torrent not found" }
        }
      },
      "delete": {
        "summary": "Remove torrent",
        "parameters": [
          { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } },
          { "name": "delete_data", "in": "query", "required": false, "schema": { "type": "boolean", "default": false } }
        ],
        "responses": {
          "200": { "description": "Torrent removed successfully" },
          "404": { "description": "Torrent not found" }
        }
      }
    },
    "/api/v1/torrents/{info_hash}/detail": {
      "get": {
        "summary": "Inspect comprehensive torrent details",
        "description": "Returns in-depth swarm details including files, trackers, candidate peer pool size, active dials, DHT/PEX/LSD/webseed discovery metrics, and connected peer telemetry.",
        "parameters": [
          { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": {
          "200": {
            "description": "Torrent comprehensive detail retrieved successfully",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "info_hash": { "type": "string" },
                    "name": { "type": "string" },
                    "download_dir": { "type": "string" },
                    "total_bytes": { "type": "integer" },
                    "progress": { "type": "number" },
                    "download_rate": { "type": "integer" },
                    "upload_rate": { "type": "integer" },
                    "downloaded_bytes": { "type": "integer" },
                    "uploaded_bytes": { "type": "integer" },
                    "ratio": { "type": "number" },
                    "eta_seconds": { "type": "integer" },
                    "peers_connected": { "type": "integer" },
                    "peers_sending": { "type": "integer" },
                    "candidate_peers": { "type": "integer", "description": "Candidate peer pool size available for dialing" },
                    "active_dials": { "type": "integer", "description": "Number of currently active outbound TCP/uTP connection attempts" },
                    "discovery": {
                      "type": "object",
                      "properties": {
                        "is_private": { "type": "boolean" },
                        "allows_dht": { "type": "boolean" },
                        "allows_pex": { "type": "boolean" },
                        "allows_lsd": { "type": "boolean" },
                        "candidate_peers": { "type": "integer" },
                        "active_dials": { "type": "integer" },
                        "pex_peers": { "type": "integer", "description": "Connected peers supporting BEP 11 / ut_pex" },
                        "discovered_from_tracker": { "type": "integer" },
                        "discovered_from_dht": { "type": "integer" },
                        "discovered_from_pex": { "type": "integer" },
                        "discovered_from_lsd": { "type": "integer" },
                        "webseeds": {
                          "type": "array",
                          "items": { "type": "string" }
                        }
                      }
                    },
                    "state": { "type": "string" },
                    "tier": { "type": "string" },
                    "piece_count": { "type": "integer" },
                    "piece_size": { "type": "integer" },
                    "piece_bitfield": { "type": "string" },
                    "files": { "type": "array", "items": { "type": "object" } },
                    "trackers": { "type": "array", "items": { "type": "object" } },
                    "active_peers": { "type": "array", "items": { "type": "object" } }
                  }
                }
              }
            }
          },
          "404": { "description": "Torrent not found" }
        }
      }
    },
    "/api/v1/torrents/{info_hash}/pause": {
      "post": {
        "summary": "Pause torrent",
        "parameters": [
          { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": {
          "200": { "description": "Torrent paused" },
          "404": { "description": "Torrent not found" }
        }
      }
    },
    "/api/v1/torrents/{info_hash}/resume": {
      "post": {
        "summary": "Resume torrent",
        "parameters": [
          { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": {
          "200": { "description": "Torrent resumed" },
          "404": { "description": "Torrent not found" }
        }
      }
    },
    "/api/v1/torrents/{info_hash}/files": {
      "get": {
        "summary": "List files in torrent",
        "parameters": [
          { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": {
          "200": { "description": "Files retrieved successfully" },
          "404": { "description": "Torrent not found" }
        }
      }
    },
    "/api/v1/torrents/{info_hash}/files/{index}/priority": {
      "post": {
        "summary": "Set file download priority",
        "description": "Sets the download priority for a specific file index in a multi-file torrent (0=skip/do not download, 1=low, 4=normal, 7=high).",
        "parameters": [
          { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } },
          { "name": "index", "in": "path", "required": true, "schema": { "type": "integer" } }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "priority": { "type": "integer", "enum": [0, 1, 4, 7], "example": 4 }
                },
                "required": ["priority"]
              }
            }
          }
        },
        "responses": {
          "200": { "description": "File priority updated successfully" },
          "404": { "description": "Torrent not found" }
        }
      }
    },
    "/api/v1/torrents/{info_hash}/peers": {
      "get": {
        "summary": "List connected peers",
        "parameters": [
          { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": {
          "200": { "description": "Peers retrieved successfully" },
          "404": { "description": "Torrent not found" }
        }
      }
    },
    "/api/v1/circuit-breakers": {
      "get": {
        "summary": "List tracker circuit breakers",
        "description": "Returns the live circuit breaker status for every tracker host currently being tracked.",
        "responses": {
          "200": {
            "description": "Circuit breaker statuses retrieved successfully",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "host": { "type": "string", "example": "tracker.example.org" },
                      "state": { "type": "string", "enum": ["healthy", "tripped", "half_open_canary", "recovering"] },
                      "consecutive_successes": { "type": "integer" },
                      "consecutive_failures": { "type": "integer" },
                      "backoff_remaining_ms": { "type": "integer" },
                      "recovery_progress_pct": { "type": "number", "nullable": true }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/api/v1/circuit-breakers/{host}/trip": {
      "post": {
        "summary": "Force-trip a tracker's circuit breaker",
        "description": "Forces the given tracker host's circuit breaker into the Tripped state, as if it had just failed its configured failure threshold.",
        "parameters": [
          { "name": "host", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": {
          "200": { "description": "Circuit breaker force-tripped" }
        }
      }
    },
    "/api/v1/circuit-breakers/{host}/reset": {
      "post": {
        "summary": "Force-reset a tracker's circuit breaker",
        "description": "Clears the given tracker host's circuit breaker state entirely, returning it to Healthy on the next check.",
        "parameters": [
          { "name": "host", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": {
          "200": { "description": "Circuit breaker force-reset" }
        }
      }
    },
    "/metrics": {
      "get": {
        "summary": "Prometheus Metrics",
        "description": "Standard Prometheus text format metrics exposition.",
        "responses": {
          "200": {
            "description": "Metrics retrieved",
            "content": { "text/plain": {} }
          }
        }
      }
    }
  }
}"#;

pub fn get_swagger_ui_html() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Synapse 2.0 — Interactive API Docs</title>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css" />
  <style>
    html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin: 0; background: #fafafa; }
    .topbar { display: none !important; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function() {
      window.ui = SwaggerUIBundle({
        url: "/api-docs/openapi.json",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "BaseLayout"
      });
    };
  </script>
</body>
</html>"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_json_is_valid_json() {
        let parsed: serde_json::Value = serde_json::from_str(OPENAPI_JSON).unwrap();
        assert_eq!(parsed["openapi"], "3.1.0");
        assert_eq!(parsed["info"]["version"], "2.0.0");
    }

    #[test]
    fn test_swagger_ui_html_structure() {
        let html = get_swagger_ui_html();
        assert!(html.contains("SwaggerUIBundle"));
        assert!(html.contains("/api-docs/openapi.json"));
    }
}
