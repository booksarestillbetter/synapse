//! OpenAPI 3.1 Specification and Interactive Swagger UI HTML Generator.

pub const OPENAPI_JSON: &str = r#"{
  "openapi": "3.1.0",
  "info": {
    "title": "Synapse 2.0 REST API",
    "description": "Comprehensive REST API for Synapse 2.0 headless BitTorrent daemon.",
    "version": "2.0.0",
    "license": {
      "name": "ISC"
    }
  },
  "paths": {
    "/healthz": {
      "get": {
        "summary": "Liveness probe",
        "description": "Lightweight liveness probe returning 200 OK while the HTTP server is responsive.",
        "responses": {
          "200": {
            "description": "Alive",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "status": { "type": "string", "example": "ok" },
                    "version": { "type": "string", "example": "2.0.0" }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/readyz": {
      "get": {
        "summary": "Readiness probe",
        "description": "Verifies active download directory availability, session store health, and required BitTorrent listener readiness.",
        "responses": {
          "200": {
            "description": "Ready",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "status": { "type": "string", "example": "ready" },
                    "version": { "type": "string", "example": "2.0.0" },
                    "checks": {
                      "type": "object",
                      "properties": {
                        "download_dir": { "type": "boolean" },
                        "session_db": { "type": "boolean" },
                        "listener": { "type": "boolean" }
                      }
                    }
                  }
                }
              }
            }
          },
          "503": { "description": "Not ready" }
        }
      }
    },
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
        "description": "Retrieves active dynamic session settings including bandwidth limits, turtle mode, queue policies, transport, concurrency caps, and directory paths.",
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
                    "dht_read_only": { "type": "boolean" },
                    "pex_enabled": { "type": "boolean" },
                    "lsd_enabled": { "type": "boolean" },
                    "zeroconf_enabled": { "type": "boolean" },
                    "announce_ip": { "type": "string", "nullable": true },
                    "enable_utp": { "type": "boolean" },
                    "encryption": { "type": "string" },
                    "download_dir": { "type": "string" },
                    "incomplete_dir": { "type": "string", "nullable": true },
                    "incomplete_dir_enabled": { "type": "boolean" },
                    "start_added_torrents": { "type": "boolean" },
                    "trash_original_torrent_files": { "type": "boolean" },
                    "unchoke_slots_global": { "type": "integer" },
                    "seed_choking_algorithm": { "type": "string" },
                    "unchoke_slot_bandwidth": { "type": "integer" },
                    "limit_lan_peers": { "type": "boolean" },
                    "rate_limit_ip_overhead": { "type": "boolean" },
                    "max_concurrent_tracker_announces": { "type": "integer" },
                    "max_concurrent_dht_announces": { "type": "integer" },
                    "max_concurrent_lsd_announces": { "type": "integer" }
                  }
                }
              }
            }
          }
        }
      },
      "patch": {
        "summary": "Update session settings",
        "description": "Updates in-flight session settings dynamically. Static parameters (peer port, listen addresses) return a warning requiring restart.",
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
                  "dht_read_only": { "type": "boolean" },
                  "pex_enabled": { "type": "boolean" },
                  "lsd_enabled": { "type": "boolean" },
                  "zeroconf_enabled": { "type": "boolean" },
                  "announce_ip": { "type": "string", "nullable": true },
                  "enable_utp": { "type": "boolean" },
                  "encryption": { "type": "string" },
                  "download_dir": { "type": "string" },
                  "incomplete_dir": { "type": "string" },
                  "incomplete_dir_enabled": { "type": "boolean" },
                  "start_added_torrents": { "type": "boolean" },
                  "trash_original_torrent_files": { "type": "boolean" },
                  "unchoke_slots_global": { "type": "integer" },
                  "seed_choking_algorithm": { "type": "string" },
                  "unchoke_slot_bandwidth": { "type": "integer" },
                  "limit_lan_peers": { "type": "boolean" },
                  "rate_limit_ip_overhead": { "type": "boolean" },
                  "max_concurrent_tracker_announces": { "type": "integer" },
                  "max_concurrent_dht_announces": { "type": "integer" },
                  "max_concurrent_lsd_announces": { "type": "integer" },
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
        "summary": "List paginated torrents",
        "description": "Retrieves managed torrent swarms with deterministic pagination and optional state filtering.",
        "parameters": [
          { "name": "page", "in": "query", "required": false, "schema": { "type": "integer", "minimum": 1, "default": 1 } },
          { "name": "limit", "in": "query", "required": false, "schema": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 } },
          { "name": "state", "in": "query", "required": false, "schema": { "type": "string", "enum": ["downloading", "seeding", "paused", "stopped", "queued", "checking", "error"] } }
        ],
        "responses": {
          "200": { "description": "Paginated list of swarms" }
        }
      },
      "post": {
        "summary": "Add a new torrent",
        "description": "Adds a torrent via Magnet URI, remote .torrent URL, or Base64-encoded .torrent file.",
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
    "/api/v1/torrents/stream": {
      "get": {
        "summary": "Stream paginated torrent deltas and session stats (SSE)",
        "description": "Server-Sent Events stream emitting an initial `snapshot` event followed by sparse `delta` updates for changed torrents in the active page plus `stats` events.",
        "parameters": [
          { "name": "page", "in": "query", "required": false, "schema": { "type": "integer", "minimum": 1, "default": 1 } },
          { "name": "limit", "in": "query", "required": false, "schema": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 } },
          { "name": "state", "in": "query", "required": false, "schema": { "type": "string", "enum": ["downloading", "seeding", "paused", "stopped", "queued", "checking", "error"] } },
          { "name": "interval_ms", "in": "query", "required": false, "schema": { "type": "integer", "minimum": 250, "maximum": 5000, "default": 1000 } }
        ],
        "responses": {
          "200": { "description": "Torrent delta SSE stream", "content": { "text/event-stream": { "schema": { "type": "string" } } } }
        }
      }
    },
    "/api/v1/torrents/batch/pause": {
      "post": {
        "summary": "Pause multiple torrents",
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": { "type": "object", "properties": { "hashes": { "type": "array", "items": { "type": "string" } } }, "required": ["hashes"] } } }
        },
        "responses": {
          "200": { "description": "Batch pause result" },
          "400": { "description": "Malformed info hash" }
        }
      }
    },
    "/api/v1/torrents/batch/resume": {
      "post": {
        "summary": "Resume multiple torrents",
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": { "type": "object", "properties": { "hashes": { "type": "array", "items": { "type": "string" } } }, "required": ["hashes"] } } }
        },
        "responses": {
          "200": { "description": "Batch resume result" },
          "400": { "description": "Malformed info hash" }
        }
      }
    },
    "/api/v1/torrents/batch/remove": {
      "post": {
        "summary": "Remove multiple torrents",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "hashes": { "type": "array", "items": { "type": "string" } },
                  "delete_data": { "type": "boolean", "default": false }
                },
                "required": ["hashes"]
              }
            }
          }
        },
        "responses": {
          "200": { "description": "Batch remove result" },
          "400": { "description": "Malformed info hash" }
        }
      }
    },
    "/api/v1/torrents/batch/recheck": {
      "post": {
        "summary": "Recheck multiple torrents",
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": { "type": "object", "properties": { "hashes": { "type": "array", "items": { "type": "string" } } }, "required": ["hashes"] } } }
        },
        "responses": {
          "200": { "description": "Batch recheck result" },
          "400": { "description": "Malformed info hash" }
        }
      }
    },
    "/api/v1/torrents/upload": {
      "post": {
        "summary": "Upload raw .torrent file",
        "parameters": [
          { "name": "download_dir", "in": "query", "required": false, "schema": { "type": "string" } },
          { "name": "paused", "in": "query", "required": false, "schema": { "type": "boolean", "default": false } }
        ],
        "requestBody": {
          "required": true,
          "content": { "application/octet-stream": { "schema": { "type": "string", "format": "binary" } } }
        },
        "responses": {
          "200": { "description": "Torrent uploaded and added" },
          "400": { "description": "Invalid bencode or torrent payload" },
          "413": { "description": "Payload too large" }
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
        "description": "Returns in-depth swarm details including files, trackers with circuit breaker telemetry, candidate peer pool size, active dials, discovery metrics, and connected peer telemetry.",
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
                    "candidate_peers": { "type": "integer" },
                    "active_dials": { "type": "integer" },
                    "discovery": {
                      "type": "object",
                      "properties": {
                        "is_private": { "type": "boolean" },
                        "allows_dht": { "type": "boolean" },
                        "allows_pex": { "type": "boolean" },
                        "allows_lsd": { "type": "boolean" },
                        "candidate_peers": { "type": "integer" },
                        "active_dials": { "type": "integer" },
                        "pex_peers": { "type": "integer" },
                        "discovered_from_tracker": { "type": "integer" },
                        "discovered_from_dht": { "type": "integer" },
                        "discovered_from_pex": { "type": "integer" },
                        "discovered_from_lsd": { "type": "integer" },
                        "webseeds": { "type": "array", "items": { "type": "string" } }
                      }
                    },
                    "state": { "type": "string" },
                    "tier": { "type": "string" },
                    "piece_count": { "type": "integer" },
                    "piece_size": { "type": "integer" },
                    "piece_bitfield": { "type": "string" },
                    "files": { "type": "array", "items": { "type": "object" } },
                    "trackers": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "url": { "type": "string" },
                          "status": { "type": "string" },
                          "seeders": { "type": "integer" },
                          "leechers": { "type": "integer" },
                          "next_announce_in": { "type": "integer" },
                          "failure_reason": { "type": "string", "nullable": true },
                          "is_circuit_broken": { "type": "boolean" },
                          "cb_state": { "type": "string", "nullable": true },
                          "recovery_progress_pct": { "type": "number", "nullable": true },
                          "last_announce_time": { "type": "integer", "nullable": true }
                        }
                      }
                    },
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
        "parameters": [ { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "200": { "description": "Torrent paused" }, "404": { "description": "Torrent not found" } }
      }
    },
    "/api/v1/torrents/{info_hash}/resume": {
      "post": {
        "summary": "Resume torrent",
        "parameters": [ { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "200": { "description": "Torrent resumed" }, "404": { "description": "Torrent not found" } }
      }
    },
    "/api/v1/torrents/{info_hash}/recheck": {
      "post": {
        "summary": "Force piece hash recheck",
        "parameters": [ { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "200": { "description": "Recheck started" }, "404": { "description": "Torrent not found" } }
      }
    },
    "/api/v1/torrents/{info_hash}/location": {
      "post": {
        "summary": "Relocate torrent download directory",
        "parameters": [ { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": { "type": "object", "properties": { "new_download_dir": { "type": "string" }, "move_existing_files": { "type": "boolean", "default": true } }, "required": ["new_download_dir"] } } }
        },
        "responses": { "200": { "description": "Location updated" }, "403": { "description": "Destination outside allowed base directory" }, "404": { "description": "Torrent not found" } }
      }
    },
    "/api/v1/torrents/{info_hash}/files/{index}/priority": {
      "post": {
        "summary": "Set file download priority",
        "description": "Sets the download priority for a specific file index in a multi-file torrent (0=skip, 1=low, 4=normal, 7=high).",
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
                "properties": { "priority": { "type": "integer", "enum": [0, 1, 4, 7], "example": 4 } },
                "required": ["priority"]
              }
            }
          }
        },
        "responses": { "200": { "description": "File priority updated successfully" }, "404": { "description": "Torrent not found" } }
      }
    },
    "/api/v1/torrents/{info_hash}/queue-move": {
      "post": {
        "summary": "Move torrent in download queue",
        "parameters": [ { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": { "type": "object", "properties": { "direction": { "type": "string", "enum": ["top", "up", "down", "bottom"] } }, "required": ["direction"] } } }
        },
        "responses": { "200": { "description": "Queue position updated" }, "404": { "description": "Torrent not found" } }
      }
    },
    "/api/v1/torrents/{info_hash}/sequential": {
      "post": {
        "summary": "Toggle sequential piece picking",
        "parameters": [ { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "properties": { "enabled": { "type": "boolean" } }, "required": ["enabled"] } } } },
        "responses": { "200": { "description": "Sequential flag updated" }, "404": { "description": "Torrent not found" } }
      }
    },
    "/api/v1/torrents/{info_hash}/super-seed": {
      "post": {
        "summary": "Toggle super-seeding mode",
        "parameters": [ { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "properties": { "enabled": { "type": "boolean" } }, "required": ["enabled"] } } } },
        "responses": { "200": { "description": "Super-seeding updated" }, "404": { "description": "Torrent not found" } }
      }
    },
    "/api/v1/torrents/{info_hash}/first-last-priority": {
      "post": {
        "summary": "Toggle first/last piece priority",
        "parameters": [ { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "properties": { "enabled": { "type": "boolean" } }, "required": ["enabled"] } } } },
        "responses": { "200": { "description": "First/last priority updated" }, "404": { "description": "Torrent not found" } }
      }
    },
    "/api/v1/torrents/{info_hash}/reannounce": {
      "post": {
        "summary": "Force immediate tracker reannounce",
        "parameters": [ { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "200": { "description": "Reannounce triggered" }, "404": { "description": "Torrent not found or not announcing" } }
      }
    },
    "/api/v1/torrents/{info_hash}/trackers": {
      "post": {
        "summary": "Replace torrent tracker list",
        "parameters": [ { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "properties": { "trackers": { "type": "array", "items": { "type": "string" } } }, "required": ["trackers"] } } } },
        "responses": { "200": { "description": "Trackers updated" }, "404": { "description": "Torrent not found" } }
      }
    },
    "/api/v1/torrents/{info_hash}/metadata": {
      "patch": {
        "summary": "Update torrent category, tags, and seed limits",
        "parameters": [ { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "properties": { "category": { "type": "string", "nullable": true }, "tags": { "type": "array", "items": { "type": "string" } }, "seed_ratio_limit": { "type": "number", "nullable": true }, "seed_time_limit_secs": { "type": "integer", "nullable": true } } } } } },
        "responses": { "200": { "description": "Metadata updated" }, "404": { "description": "Torrent not found" } }
      }
    },
    "/api/v1/torrents/{info_hash}/export": {
      "get": {
        "summary": "Export .torrent file bytes",
        "parameters": [ { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "200": { "description": "Raw .torrent download", "content": { "application/x-bittorrent": {} } }, "404": { "description": "Torrent or metainfo not found" } }
      }
    },
    "/api/v1/torrents/{info_hash}/signatures": {
      "get": {
        "summary": "BEP 35 signature status",
        "description": "The signatures a torrent carries and whether each verifies against trusted signers.",
        "parameters": [ { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "200": { "description": "Signature status" }, "400": { "description": "Invalid info_hash" }, "404": { "description": "No such torrent" } }
      }
    },
    "/api/v1/ip-filter/reload": {
      "post": {
        "summary": "Reload IP filter blocklist",
        "responses": { "200": { "description": "IP filter reloaded with active rule count" } }
      }
    },
    "/api/v1/alerts": {
      "get": {
        "summary": "Stream engine alerts (Server-Sent Events)",
        "description": "A live text/event-stream of engine alerts with optional `?info_hash=` filter.",
        "parameters": [
          { "name": "info_hash", "in": "query", "required": false, "schema": { "type": "string" } }
        ],
        "responses": {
          "200": { "description": "Event stream", "content": { "text/event-stream": { "schema": { "type": "string" } } } },
          "400": { "description": "Invalid info_hash" }
        }
      }
    },
    "/api/v1/search": {
      "get": {
        "summary": "Search (BEP 18)",
        "parameters": [
          { "name": "q", "in": "query", "required": false, "schema": { "type": "string" } },
          { "name": "engine", "in": "query", "required": false, "schema": { "type": "string" } },
          { "name": "scope", "in": "query", "required": false, "schema": { "type": "string", "enum": ["engines", "local"] } }
        ],
        "responses": { "200": { "description": "Results" }, "400": { "description": "Missing query" }, "404": { "description": "No search engines configured" } }
      }
    },
    "/api/v1/search/engines": {
      "get": { "summary": "List search engines", "responses": { "200": { "description": "Configured engines" } } },
      "post": {
        "summary": "Add a search engine",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "properties": { "source": { "type": "string" } }, "required": ["source"] } } } },
        "responses": { "200": { "description": "Engine added" }, "400": { "description": "Unusable description" } }
      }
    },
    "/api/v1/search/engines/{name}": {
      "delete": {
        "summary": "Remove a search engine",
        "parameters": [ { "name": "name", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "204": { "description": "Removed" }, "404": { "description": "No such engine" } }
      }
    },
    "/api/v1/rss/feeds": {
      "get": { "summary": "List RSS/Atom feeds (BEP 36)", "responses": { "200": { "description": "Configured feeds and their status" } } },
      "post": {
        "summary": "Add or replace a feed",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "properties": { "url": { "type": "string" }, "name": { "type": "string" }, "auto_download": { "type": "boolean" }, "filter": { "type": "string" } }, "required": ["url"] } } } },
        "responses": { "200": { "description": "Feed registered" }, "400": { "description": "Empty url" } }
      },
      "delete": {
        "summary": "Remove a feed",
        "parameters": [ { "name": "url", "in": "query", "required": true, "schema": { "type": "string" } } ],
        "responses": { "200": { "description": "Removed" }, "404": { "description": "No such feed" } }
      }
    },
    "/api/v1/rss/poll": {
      "post": {
        "summary": "Poll feeds now",
        "parameters": [ { "name": "url", "in": "query", "required": false, "schema": { "type": "string" } } ],
        "responses": { "200": { "description": "Poll result" } }
      }
    },
    "/api/v1/torrents/create": {
      "post": {
        "summary": "Create a .torrent",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "properties": { "path": { "type": "string" }, "trackers": { "type": "array", "items": { "type": "string" } }, "same_tier": { "type": "boolean" }, "web_seeds": { "type": "array", "items": { "type": "string" } }, "comment": { "type": "string" }, "private": { "type": "boolean" }, "source": { "type": "string" }, "piece_size_kib": { "type": "integer" }, "version": { "type": "string", "enum": ["v1", "v2", "hybrid"] } }, "required": ["path"] } } } },
        "responses": { "200": { "description": "The torrent" }, "400": { "description": "Invalid request" }, "403": { "description": "Path outside download directory" }, "404": { "description": "No such path" } }
      }
    },
    "/api/v1/updates": {
      "get": { "summary": "Pending torrent updates (BEP 39)", "responses": { "200": { "description": "Pending updates" } } }
    },
    "/api/v1/updates/check": {
      "post": { "summary": "Check update feeds now", "responses": { "200": { "description": "Updates found count" } } }
    },
    "/api/v1/updates/{info_hash}/apply": {
      "post": {
        "summary": "Add the update found for a torrent",
        "parameters": [ { "name": "info_hash", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "204": { "description": "Update added" }, "404": { "description": "No pending update" } }
      }
    },
    "/api/v1/circuit-breakers": {
      "get": {
        "summary": "List tracker circuit breakers",
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
                      "host": { "type": "string" },
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
        "parameters": [ { "name": "host", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "200": { "description": "Circuit breaker force-tripped" } }
      }
    },
    "/api/v1/circuit-breakers/{host}/reset": {
      "post": {
        "summary": "Force-reset a tracker's circuit breaker",
        "parameters": [ { "name": "host", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "200": { "description": "Circuit breaker force-reset" } }
      }
    },
    "/metrics": {
      "get": {
        "summary": "Prometheus Metrics",
        "responses": { "200": { "description": "Metrics retrieved", "content": { "text/plain": {} } } }
      }
    }
  }
}"#;

pub fn get_swagger_ui_html() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Synapse 2.0 — API Explorer</title>
  <style>
    :root { --bg: #0f172a; --panel: #1e293b; --border: #334155; --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); }
    header { padding: 16px 24px; background: var(--panel); border-bottom: 1px solid var(--border); display: flex; flex-wrap: wrap; gap: 12px; align-items: center; justify-content: space-between; }
    header h1 { margin: 0; font-size: 18px; }
    .controls { display: flex; gap: 8px; flex-wrap: wrap; }
    input, textarea, button { background: var(--bg); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 6px 10px; font-size: 13px; }
    button { cursor: pointer; background: #0284c7; border-color: #0284c7; font-weight: 600; }
    main { max-width: 1100px; margin: 20px auto; padding: 0 16px 40px; }
    .op { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 10px; overflow: hidden; }
    .op-head { display: flex; gap: 10px; align-items: center; padding: 10px 14px; cursor: pointer; }
    .method { font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 4px; text-transform: uppercase; min-width: 64px; text-align: center; }
    .GET { background: #0369a1; } .POST { background: #15803d; } .PATCH { background: #b45309; } .DELETE { background: #b91c1c; }
    .path { font-family: monospace; font-size: 13px; font-weight: 600; }
    .summary { color: var(--muted); font-size: 13px; margin-left: auto; }
    .op-body { display: none; padding: 12px 14px; border-top: 1px solid var(--border); font-size: 13px; }
    .op.open .op-body { display: block; }
    pre { background: var(--bg); padding: 10px; border-radius: 6px; overflow: auto; max-height: 280px; border: 1px solid var(--border); }
    textarea { width: 100%; min-height: 76px; font-family: monospace; margin: 6px 0; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Synapse 2.0 REST API Explorer</h1>
      <div id="api-meta" style="font-size:12px;color:#94a3b8">Loading specification...</div>
    </div>
    <div class="controls">
      <input id="filter" type="search" placeholder="Filter endpoints..." />
      <input id="bearer" type="password" placeholder="Bearer token (optional)" />
    </div>
  </header>
  <main id="ops"></main>
  <script>
    const esc = (s) => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    async function init() {
      const resp = await fetch('/api-docs/openapi.json');
      const spec = await resp.json();
      document.getElementById('api-meta').innerText = `${spec.info.title} v${spec.info.version} (OpenAPI ${spec.openapi})`;
      const root = document.getElementById('ops');
      const filterInput = document.getElementById('filter');
      function render() {
        const q = filterInput.value.trim().toLowerCase();
        root.innerHTML = '';
        for (const [path, methods] of Object.entries(spec.paths || {})) {
          for (const [verb, op] of Object.entries(methods)) {
            const hay = `${verb} ${path} ${op.summary || ''}`.toLowerCase();
            if (q && !hay.includes(q)) continue;
            const mUpper = verb.toUpperCase();
            const card = document.createElement('div');
            card.className = 'op';
            card.innerHTML = `
              <div class="op-head">
                <span class="method ${esc(mUpper)}">${esc(mUpper)}</span>
                <span class="path">${esc(path)}</span>
                <span class="summary">${esc(op.summary || '')}</span>
              </div>
              <div class="op-body">
                <p>${esc(op.description || op.summary || '')}</p>
                <div style="display:flex;gap:8px;align-items:center;margin:8px 0;">
                  <input class="req-path" value="${esc(path)}" style="flex:1;font-family:monospace" />
                  <button class="try-btn">Send ${esc(mUpper)}</button>
                </div>
                ${op.requestBody ? '<textarea class="req-body" placeholder="{ }">{}</textarea>' : ''}
                <pre class="schema">${esc(JSON.stringify(op, null, 2))}</pre>
                <pre class="res-out" style="display:none"></pre>
              </div>`;
            card.querySelector('.op-head').addEventListener('click', () => card.classList.toggle('open'));
            card.querySelector('.try-btn').addEventListener('click', async () => {
              const target = card.querySelector('.req-path').value.trim();
              const headers = {};
              const token = document.getElementById('bearer').value.trim();
              if (token) headers['Authorization'] = `Bearer ${token}`;
              const initReq = { method: mUpper, headers };
              const bodyEl = card.querySelector('.req-body');
              if (bodyEl && mUpper !== 'GET') {
                headers['Content-Type'] = 'application/json';
                initReq.body = bodyEl.value;
              }
              const out = card.querySelector('.res-out');
              out.style.display = 'block';
              try {
                const r = await fetch(target, initReq);
                const text = await r.text();
                out.innerText = `HTTP ${r.status}\n${text.slice(0, 4000)}`;
              } catch (err) {
                out.innerText = `Error: ${err.message}`;
              }
            });
            root.appendChild(card);
          }
        }
      }
      filterInput.addEventListener('input', render);
      render();
    }
    init();
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

        let paths = parsed["paths"].as_object().expect("paths object");
        for expected in [
            "/healthz",
            "/readyz",
            "/api/v1/health",
            "/api/v1/session",
            "/api/v1/session/stats",
            "/api/v1/torrents",
            "/api/v1/torrents/stream",
            "/api/v1/torrents/batch/pause",
            "/api/v1/torrents/batch/resume",
            "/api/v1/torrents/batch/remove",
            "/api/v1/torrents/batch/recheck",
            "/api/v1/torrents/upload",
            "/api/v1/torrents/create",
            "/api/v1/torrents/{info_hash}",
            "/api/v1/torrents/{info_hash}/detail",
            "/api/v1/torrents/{info_hash}/pause",
            "/api/v1/torrents/{info_hash}/resume",
            "/api/v1/torrents/{info_hash}/recheck",
            "/api/v1/torrents/{info_hash}/location",
            "/api/v1/torrents/{info_hash}/files/{index}/priority",
            "/api/v1/torrents/{info_hash}/queue-move",
            "/api/v1/torrents/{info_hash}/sequential",
            "/api/v1/torrents/{info_hash}/super-seed",
            "/api/v1/torrents/{info_hash}/first-last-priority",
            "/api/v1/torrents/{info_hash}/reannounce",
            "/api/v1/torrents/{info_hash}/trackers",
            "/api/v1/torrents/{info_hash}/metadata",
            "/api/v1/torrents/{info_hash}/export",
            "/api/v1/torrents/{info_hash}/signatures",
            "/api/v1/ip-filter/reload",
            "/api/v1/alerts",
            "/api/v1/search",
            "/api/v1/search/engines",
            "/api/v1/search/engines/{name}",
            "/api/v1/rss/feeds",
            "/api/v1/rss/poll",
            "/api/v1/updates",
            "/api/v1/updates/check",
            "/api/v1/updates/{info_hash}/apply",
            "/api/v1/circuit-breakers",
            "/api/v1/circuit-breakers/{host}/trip",
            "/api/v1/circuit-breakers/{host}/reset",
            "/metrics",
        ] {
            assert!(
                paths.contains_key(expected),
                "OPENAPI_JSON missing route {expected}"
            );
        }

        let session_props = parsed["paths"]["/api/v1/session"]["get"]["responses"]["200"]
            ["content"]["application/json"]["schema"]["properties"]
            .as_object()
            .unwrap();
        for field in [
            "dht_read_only",
            "zeroconf_enabled",
            "announce_ip",
            "enable_utp",
            "unchoke_slots_global",
            "seed_choking_algorithm",
            "unchoke_slot_bandwidth",
            "limit_lan_peers",
            "rate_limit_ip_overhead",
            "max_concurrent_tracker_announces",
            "max_concurrent_dht_announces",
            "max_concurrent_lsd_announces",
        ] {
            assert!(
                session_props.contains_key(field),
                "OPENAPI_JSON /api/v1/session GET schema missing {field}"
            );
        }
    }

    #[test]
    fn test_swagger_ui_html_structure() {
        let html = get_swagger_ui_html();
        assert!(html.contains("/api-docs/openapi.json"));
        assert!(!html.contains("unpkg.com"));
        assert!(!html.contains("https://"));
        assert!(!html.contains("http://"));
    }
}
