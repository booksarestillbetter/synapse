//! Embedded Web UI for Synapse 2.0 (TransGUI / qBittorrent style).
//!
//! Provides a zero-dependency, self-contained single-page application (SPA)
//! served directly on the daemon HTTP port when `web.enabled = true`.

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
};
use crate::http_api::ApiState;

pub async fn web_index_handler(State(state): State<ApiState>) -> Response {
    if !state.web_config.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Some(ref root) = state.web_config.web_root {
        let index_path = root.join("index.html");
        if let Ok(content) = tokio::fs::read_to_string(&index_path).await {
            return Html(content).into_response();
        }
    }
    Html(INDEX_HTML).into_response()
}

pub async fn web_css_handler(State(state): State<ApiState>) -> Response {
    if !state.web_config.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Some(ref root) = state.web_config.web_root {
        let path = root.join("style.css");
        if let Ok(content) = tokio::fs::read_to_string(&path).await {
            return ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], content).into_response();
        }
    }
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], STYLE_CSS).into_response()
}

pub async fn web_js_handler(State(state): State<ApiState>) -> Response {
    if !state.web_config.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Some(ref root) = state.web_config.web_root {
        let path = root.join("app.js");
        if let Ok(content) = tokio::fs::read_to_string(&path).await {
            return ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8")], content).into_response();
        }
    }
    ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8")], APP_JS).into_response()
}

pub async fn web_favicon_handler() -> Response {
    ([(header::CONTENT_TYPE, "image/svg+xml")], FAVICON_SVG).into_response()
}

pub const FAVICON_SVG: &str = r###"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><circle cx="16" cy="16" r="14" fill="#2563eb"/><path d="M16 8v16M10 16l6 6 6-6" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>"###;

pub const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Synapse 2.0 Web Client</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.ico">
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <!-- Header Toolbar -->
  <header class="toolbar">
    <div class="logo-area">
      <span class="logo-icon">⚡</span>
      <span class="logo-text">Synapse <small>2.0</small></span>
      <span class="status-indicator" id="conn-status" title="Connected to Synapse Daemon"></span>
    </div>

    <div class="action-buttons">
      <button class="btn btn-primary" id="btn-add-torrent" title="Add Torrent (Ctrl+O)">
        <span class="btn-icon">➕</span> Add Torrent
      </button>
      <div class="btn-separator"></div>
      <button class="btn" id="btn-resume" title="Start / Resume selected (Space)" disabled>
        <span class="btn-icon">▶</span> Resume
      </button>
      <button class="btn" id="btn-pause" title="Pause selected (Space)" disabled>
        <span class="btn-icon">⏸</span> Pause
      </button>
      <button class="btn btn-danger" id="btn-delete" title="Delete selected (Del)" disabled>
        <span class="btn-icon">🗑</span> Delete
      </button>
      <div class="btn-separator"></div>
      <button class="btn btn-toggle" id="btn-turtle" title="Toggle Alt-Speed / Turtle Mode">
        <span class="btn-icon">🐢</span> <span id="turtle-label">Turtle Mode</span>
      </button>
      <button class="btn" id="btn-settings" title="Preferences & In-Flight Settings">
        <span class="btn-icon">⚙</span> Settings
      </button>
    </div>

    <div class="search-area">
      <input type="text" id="search-input" placeholder="🔍 Filter torrents..." autocomplete="off">
    </div>

    <div class="global-stats" id="global-stats">
      <div class="stat-item"><span class="stat-label">DL:</span> <span class="stat-val dl" id="stat-dl-rate">0 B/s</span></div>
      <div class="stat-item"><span class="stat-label">UL:</span> <span class="stat-val ul" id="stat-ul-rate">0 B/s</span></div>
      <div class="stat-item"><span class="stat-label">Free:</span> <span class="stat-val" id="stat-free-disk">-</span></div>
    </div>
  </header>

  <!-- Main Container -->
  <div class="main-layout">
    <!-- Left Category Sidebar -->
    <aside class="sidebar">
      <div class="sidebar-section">
        <div class="sidebar-title">Status</div>
        <ul class="category-list" id="category-list">
          <li class="category-item active" data-state="all">
            <span class="cat-icon">📁</span> <span class="cat-name">All Torrents</span>
            <span class="cat-count" id="count-all">0</span>
          </li>
          <li class="category-item" data-state="downloading">
            <span class="cat-icon">⬇</span> <span class="cat-name">Downloading</span>
            <span class="cat-count" id="count-downloading">0</span>
          </li>
          <li class="category-item" data-state="seeding">
            <span class="cat-icon">⬆</span> <span class="cat-name">Seeding</span>
            <span class="cat-count" id="count-seeding">0</span>
          </li>
          <li class="category-item" data-state="paused">
            <span class="cat-icon">⏸</span> <span class="cat-name">Paused</span>
            <span class="cat-count" id="count-paused">0</span>
          </li>
          <li class="category-item" data-state="queued">
            <span class="cat-icon">⏳</span> <span class="cat-name">Queued</span>
            <span class="cat-count" id="count-queued">0</span>
          </li>
          <li class="category-item" data-state="checking">
            <span class="cat-icon">🔍</span> <span class="cat-name">Checking</span>
            <span class="cat-count" id="count-checking">0</span>
          </li>
          <li class="category-item" data-state="error">
            <span class="cat-icon">⚠</span> <span class="cat-name">Error</span>
            <span class="cat-count" id="count-error">0</span>
          </li>
        </ul>
      </div>

      <div class="sidebar-section">
        <div class="sidebar-title">Daemon Info</div>
        <div class="daemon-info-card">
          <div><small>Engine:</small> <strong>Synapse 2.0</strong></div>
          <div><small>Peer ID:</small> <code>-SY2200-</code></div>
          <div id="daemon-version"><small>Version:</small> 2.2.3</div>
          <div id="daemon-dht"><small>DHT Nodes:</small> <span id="stat-dht-nodes">0</span></div>
        </div>
      </div>
    </aside>

    <!-- Content Workspace -->
    <main class="content-area">
      <!-- Torrent Data Grid -->
      <div class="table-container" id="grid-container">
        <table class="torrent-table" id="torrent-table">
          <thead>
            <tr>
              <th data-sort="num" style="width: 40px;">#</th>
              <th data-sort="name" class="sort-asc">Name</th>
              <th data-sort="size" style="width: 90px;">Size</th>
              <th data-sort="progress" style="width: 140px;">Progress</th>
              <th data-sort="status" style="width: 100px;">Status</th>
              <th data-sort="seeds" style="width: 70px;">Seeds</th>
              <th data-sort="peers" style="width: 70px;">Peers</th>
              <th data-sort="down_speed" style="width: 95px;">Down Speed</th>
              <th data-sort="up_speed" style="width: 95px;">Up Speed</th>
              <th data-sort="eta" style="width: 80px;">ETA</th>
              <th data-sort="ratio" style="width: 65px;">Ratio</th>
            </tr>
          </thead>
          <tbody id="torrent-tbody">
            <tr class="empty-row"><td colspan="11">No torrents loaded in session. Click "+ Add Torrent" to start.</td></tr>
          </tbody>
        </table>
      </div>

      <!-- Resizer Splitter -->
      <div class="inspector-resizer" id="inspector-resizer"></div>

      <!-- Bottom Inspector Panel -->
      <section class="inspector-panel" id="inspector-panel">
        <div class="inspector-tabs">
          <button class="tab-btn active" data-tab="general">General</button>
          <button class="tab-btn" data-tab="transfer">Transfer</button>
          <button class="tab-btn" data-tab="trackers">Trackers</button>
          <button class="tab-btn" data-tab="peers">Peers</button>
          <button class="tab-btn" data-tab="files">Files</button>
          <button class="tab-btn" data-tab="pieces">Piece Map</button>
          <div class="tab-spacer"></div>
          <button class="btn btn-sm" id="btn-recheck-torrent" title="Force recheck integrity">Force Recheck</button>
          <button class="tab-close" id="btn-close-inspector" title="Close Inspector">✕</button>
        </div>

        <div class="inspector-body">
          <!-- General Tab -->
          <div class="tab-content active" id="tab-general">
            <div class="detail-grid">
              <div class="detail-item"><span class="lbl">Name:</span> <span class="val" id="det-name">-</span></div>
              <div class="detail-item"><span class="lbl">Hash:</span> <span class="val code" id="det-hash">-</span></div>
              <div class="detail-item"><span class="lbl">Save Path:</span> <span class="val" id="det-path">-</span></div>
              <div class="detail-item"><span class="lbl">Total Size:</span> <span class="val" id="det-size">-</span></div>
              <div class="detail-item"><span class="lbl">Pieces:</span> <span class="val" id="det-pieces">-</span></div>
              <div class="detail-item"><span class="lbl">State / Tier:</span> <span class="val" id="det-state">-</span></div>
              <div class="detail-item"><span class="lbl">Swarm Privacy:</span> <span class="val" id="det-privacy">-</span></div>
              <div class="detail-item"><span class="lbl">Discovery:</span> <span class="val" id="det-discovery">-</span></div>
              <div class="detail-item"><span class="lbl">Webseeds:</span> <span class="val" id="det-webseeds">-</span></div>
            </div>
          </div>

          <!-- Transfer Tab -->
          <div class="tab-content" id="tab-transfer">
            <div class="detail-grid">
              <div class="detail-item"><span class="lbl">Downloaded:</span> <span class="val" id="det-downloaded">-</span></div>
              <div class="detail-item"><span class="lbl">Uploaded:</span> <span class="val" id="det-uploaded">-</span></div>
              <div class="detail-item"><span class="lbl">Download Rate:</span> <span class="val dl" id="det-dl-rate">-</span></div>
              <div class="detail-item"><span class="lbl">Upload Rate:</span> <span class="val ul" id="det-ul-rate">-</span></div>
              <div class="detail-item"><span class="lbl">Share Ratio:</span> <span class="val" id="det-ratio">-</span></div>
              <div class="detail-item"><span class="lbl">ETA:</span> <span class="val" id="det-eta">-</span></div>
              <div class="detail-item"><span class="lbl">Connected Peers:</span> <span class="val" id="det-peer-count">-</span></div>
              <div class="detail-item"><span class="lbl">Discovered:</span> <span class="val" id="det-discovered-counts">-</span></div>
            </div>
          </div>

          <!-- Trackers Tab -->
          <div class="tab-content" id="tab-trackers">
            <table class="sub-table" id="trackers-table">
              <thead><tr><th>Announce URL</th><th>Status</th><th>Seeders</th><th>Leechers</th><th>Next Announce</th></tr></thead>
              <tbody id="trackers-tbody"><tr><td colspan="5">Select a torrent to inspect trackers</td></tr></tbody>
            </table>
          </div>

          <!-- Peers Tab -->
          <div class="tab-content" id="tab-peers">
            <table class="sub-table" id="peers-table">
              <thead><tr><th>IP Address</th><th>Client Name</th><th>Flags</th><th>Down Rate</th><th>Up Rate</th><th>Progress</th><th>Security</th></tr></thead>
              <tbody id="peers-tbody"><tr><td colspan="7">No active peers connected</td></tr></tbody>
            </table>
          </div>

          <!-- Files Tab -->
          <div class="tab-content" id="tab-files">
            <table class="sub-table" id="files-table">
              <thead><tr><th style="width: 40px;">#</th><th>Path</th><th style="width: 100px;">Size</th><th style="width: 140px;">Progress</th><th style="width: 100px;">Priority</th></tr></thead>
              <tbody id="files-tbody"><tr><td colspan="5">Select a torrent to inspect files</td></tr></tbody>
            </table>
          </div>

          <!-- Pieces Tab -->
          <div class="tab-content" id="tab-pieces">
            <div class="pieces-wrapper">
              <div class="pieces-header">
                <span>Piece Map Telemetry (<span id="piece-stat-counts">0 / 0 pieces</span>)</span>
                <div class="pieces-legend">
                  <span class="legend-box comp"></span> Completed
                  <span class="legend-box miss"></span> Missing
                </div>
              </div>
              <canvas id="piece-map-canvas" width="800" height="120"></canvas>
            </div>
          </div>
        </div>
      </section>
    </main>
  </div>

  <!-- Add Torrent Modal -->
  <dialog class="modal" id="modal-add-torrent">
    <div class="modal-header">
      <h3>➕ Add New Torrent</h3>
      <button class="modal-close" onclick="document.getElementById('modal-add-torrent').close()">✕</button>
    </div>
    <div class="modal-body">
      <div class="modal-tabs">
        <button class="tab-btn active" onclick="switchAddTab('file')">File Upload</button>
        <button class="tab-btn" onclick="switchAddTab('magnet')">Magnet Link</button>
        <button class="tab-btn" onclick="switchAddTab('url')">Torrent URL</button>
      </div>

      <div class="tab-pane" id="pane-file">
        <div class="drop-zone" id="drop-zone">
          <p>Drag & drop a <code>.torrent</code> file here, or click to browse</p>
          <input type="file" id="file-input" accept=".torrent" style="display: none;">
          <button type="button" class="btn" onclick="document.getElementById('file-input').click()">Browse File...</button>
          <div id="file-name-display" style="margin-top: 8px; font-weight: bold; color: var(--accent);"></div>
        </div>
      </div>

      <div class="tab-pane hidden" id="pane-magnet">
        <label>Magnet URI:</label>
        <textarea id="input-magnet" rows="3" placeholder="magnet:?xt=urn:btih:..."></textarea>
      </div>

      <div class="tab-pane hidden" id="pane-url">
        <label>Remote .torrent URL:</label>
        <input type="url" id="input-url" placeholder="https://example.com/file.torrent">
      </div>

      <div class="form-group" style="margin-top: 14px;">
        <label>Download Directory:</label>
        <input type="text" id="input-download-dir" placeholder="Default session directory">
      </div>

      <div class="form-group checkbox-group">
        <label><input type="checkbox" id="check-start-paused"> Start torrent paused</label>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn" onclick="document.getElementById('modal-add-torrent').close()">Cancel</button>
      <button class="btn btn-primary" id="btn-submit-add">Add Torrent</button>
    </div>
  </dialog>

  <!-- Delete Torrent Modal -->
  <dialog class="modal" id="modal-delete-torrent">
    <div class="modal-header">
      <h3>🗑 Remove Torrent</h3>
      <button class="modal-close" onclick="document.getElementById('modal-delete-torrent').close()">✕</button>
    </div>
    <div class="modal-body">
      <p>Are you sure you want to remove <strong id="delete-torrent-name">selected torrent</strong>?</p>
      <div class="form-group checkbox-group danger-check" style="margin-top: 12px;">
        <label><input type="checkbox" id="check-delete-data"> <strong>Also delete files from disk</strong> (irreversible)</label>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn" onclick="document.getElementById('modal-delete-torrent').close()">Cancel</button>
      <button class="btn btn-danger" id="btn-submit-delete">Delete</button>
    </div>
  </dialog>

  <!-- Preferences / Settings Modal -->
  <dialog class="modal modal-lg" id="modal-settings">
    <div class="modal-header">
      <h3>⚙ Synapse Preferences & Dynamic Settings</h3>
      <button class="modal-close" onclick="document.getElementById('modal-settings').close()">✕</button>
    </div>
    <div class="modal-body">
      <div class="modal-tabs">
        <button class="tab-btn active" onclick="switchSettingsTab('bandwidth')">Bandwidth</button>
        <button class="tab-btn" onclick="switchSettingsTab('queue')">Queue</button>
        <button class="tab-btn" onclick="switchSettingsTab('peers')">Peers & Swarm</button>
        <button class="tab-btn" onclick="switchSettingsTab('storage')">Storage</button>
        <button class="tab-btn" onclick="switchSettingsTab('security')">Security</button>
      </div>

      <!-- Bandwidth Settings -->
      <div class="tab-pane" id="spane-bandwidth">
        <h4>Global Transfer Speed Limits</h4>
        <div class="form-row">
          <label><input type="checkbox" id="cfg-down-limit-enabled"> Limit Download:</label>
          <input type="number" id="cfg-down-limit-val" min="0" step="128"> <span>KB/s</span>
        </div>
        <div class="form-row">
          <label><input type="checkbox" id="cfg-up-limit-enabled"> Limit Upload:</label>
          <input type="number" id="cfg-up-limit-val" min="0" step="128"> <span>KB/s</span>
        </div>

        <h4 style="margin-top: 16px;">Alt-Speed (Turtle Mode)</h4>
        <div class="form-row">
          <label><input type="checkbox" id="cfg-alt-enabled"> Enable Turtle Mode</label>
        </div>
        <div class="form-row">
          <label>Alt Download Limit:</label>
          <input type="number" id="cfg-alt-down-val" min="0" step="64"> <span>KB/s</span>
        </div>
        <div class="form-row">
          <label>Alt Upload Limit:</label>
          <input type="number" id="cfg-alt-up-val" min="0" step="64"> <span>KB/s</span>
        </div>
      </div>

      <!-- Queue Settings -->
      <div class="tab-pane hidden" id="spane-queue">
        <h4>Transmission-Parity Queue Management</h4>
        <div class="form-row">
          <label><input type="checkbox" id="cfg-dl-queue-enabled"> Enable Download Queue</label>
        </div>
        <div class="form-row">
          <label>Max Active Downloads:</label>
          <input type="number" id="cfg-max-downloads" min="1" max="1000">
        </div>
        <div class="form-row">
          <label><input type="checkbox" id="cfg-seed-queue-enabled"> Enable Seed Queue</label>
        </div>
        <div class="form-row">
          <label>Max Active Seeds:</label>
          <input type="number" id="cfg-max-seeds" min="1" max="1000">
        </div>
        <div class="form-row">
          <label>Max Total Active Torrents:</label>
          <input type="number" id="cfg-max-total-torrents" min="1" max="10000">
        </div>
        <div class="form-row">
          <label><input type="checkbox" id="cfg-stall-enabled"> Consider torrents stalled after:</label>
          <input type="number" id="cfg-stall-minutes" min="1" max="1440"> <span>minutes</span>
        </div>
      </div>

      <!-- Peers & Swarm Settings -->
      <div class="tab-pane hidden" id="spane-peers">
        <h4>Peer Connections & Discovery</h4>
        <div class="form-row">
          <label>Max Peers Per Torrent:</label>
          <input type="number" id="cfg-max-peers-torrent" min="5" max="500">
        </div>
        <div class="form-row">
          <label>Max Global Peers:</label>
          <input type="number" id="cfg-max-peers-global" min="10" max="5000">
        </div>
        <div class="form-row">
          <label><input type="checkbox" id="cfg-dht-enabled"> Enable Mainline DHT (BEP 5)</label>
        </div>
        <div class="form-row">
          <label><input type="checkbox" id="cfg-pex-enabled"> Enable Peer Exchange (PEX, BEP 11)</label>
        </div>
        <div class="form-row">
          <label><input type="checkbox" id="cfg-lsd-enabled"> Enable Local Peer Discovery (LSD, BEP 14)</label>
        </div>
        <div class="form-row">
          <label>Encryption:</label>
          <select id="cfg-encryption">
            <option value="preferred">Preferred</option>
            <option value="required">Required (Encrypted Only)</option>
            <option value="disabled">Disabled</option>
          </select>
        </div>
      </div>

      <!-- Storage Settings -->
      <div class="tab-pane hidden" id="spane-storage">
        <h4>Storage Subsystem & Paths</h4>
        <div class="form-group">
          <label>Default Download Directory:</label>
          <input type="text" id="cfg-download-dir">
        </div>
        <div class="form-row">
          <label><input type="checkbox" id="cfg-incomplete-enabled"> Store incomplete torrents in:</label>
        </div>
        <div class="form-group">
          <input type="text" id="cfg-incomplete-dir" placeholder="/data/incomplete">
        </div>
        <div class="form-row">
          <label><input type="checkbox" id="cfg-start-added"> Automatically start newly added torrents</label>
        </div>
      </div>

      <!-- Security Settings -->
      <div class="tab-pane hidden" id="spane-security">
        <h4>Authentication & Access Control</h4>
        <div class="form-group">
          <label>Bearer Authorization Token:</label>
          <input type="password" id="cfg-auth-token" placeholder="Leave blank if daemon requires no token">
          <small style="display:block; margin-top: 4px; color: var(--text-muted);">
            Stored securely in your browser's local storage for API requests. Required if Synapse has an authentication token configured.
          </small>
        </div>
        <div style="margin-top: 16px;">
          <button type="button" class="btn btn-danger" id="btn-clear-token">Clear Stored Token (Log Out)</button>
        </div>
      </div>
    </div>
    <div class="modal-footer">
      <span id="settings-status" style="margin-right: auto; font-size: 13px; color: var(--accent);"></span>
      <button class="btn" onclick="document.getElementById('modal-settings').close()">Close</button>
      <button class="btn btn-primary" id="btn-save-settings">Save Changes</button>
    </div>
  </dialog>

  <!-- Notification Toast Container -->
  <div class="toast-container" id="toast-container"></div>

  <script src="/app.js"></script>
</body>
</html>
"#;

pub const STYLE_CSS: &str = r#"
:root {
  --bg-primary: #0f172a;
  --bg-secondary: #1e293b;
  --bg-tertiary: #334155;
  --text-main: #f8fafc;
  --text-muted: #94a3b8;
  --accent: #38bdf8;
  --accent-hover: #0284c7;
  --accent-active: #0369a1;
  --border: #334155;
  --border-subtle: #1e293b;
  --success: #22c55e;
  --warning: #f59e0b;
  --danger: #ef4444;
  --dl-color: #38bdf8;
  --ul-color: #4ade80;
  --row-hover: rgba(56, 189, 248, 0.08);
  --row-selected: rgba(56, 189, 248, 0.2);
  --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  background-color: var(--bg-primary);
  color: var(--text-main);
  font-family: var(--font-family);
  font-size: 13px;
  line-height: 1.4;
  height: 100vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  user-select: none;
}

/* Custom Scrollbars */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

/* Header Toolbar */
.toolbar {
  background-color: var(--bg-secondary);
  border-bottom: 1px solid var(--border);
  height: 48px;
  display: flex;
  align-items: center;
  padding: 0 12px;
  gap: 8px;
  flex-shrink: 0;
}

.logo-area {
  display: flex;
  align-items: center;
  gap: 6px;
  font-weight: 700;
  font-size: 16px;
  margin-right: 12px;
}

.logo-icon { font-size: 18px; }
.logo-text small { font-size: 11px; color: var(--accent); font-weight: 600; }

.status-indicator {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background-color: var(--success);
  margin-left: 4px;
}
.status-indicator.offline { background-color: var(--danger); }

.action-buttons {
  display: flex;
  align-items: center;
  gap: 4px;
}

.btn-separator {
  width: 1px;
  height: 20px;
  background-color: var(--border);
  margin: 0 4px;
}

.btn {
  background-color: var(--bg-tertiary);
  color: var(--text-main);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 5px 10px;
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 5px;
  transition: all 0.15s ease;
}
.btn:hover:not(:disabled) { background-color: #475569; border-color: #64748b; }
.btn:disabled { opacity: 0.45; cursor: not-allowed; }
.btn-primary { background-color: #0284c7; border-color: #0369a1; color: #fff; }
.btn-primary:hover:not(:disabled) { background-color: #0369a1; }
.btn-danger { background-color: rgba(239, 68, 68, 0.2); border-color: var(--danger); color: #fca5a5; }
.btn-danger:hover:not(:disabled) { background-color: var(--danger); color: #fff; }
.btn-toggle.active { background-color: #f59e0b; border-color: #d97706; color: #000; font-weight: 600; }
.btn-sm { padding: 3px 8px; font-size: 11px; }

.search-area {
  margin-left: auto;
  margin-right: 12px;
}
.search-area input {
  background-color: var(--bg-primary);
  color: var(--text-main);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 5px 10px;
  font-size: 12px;
  width: 180px;
  outline: none;
}
.search-area input:focus { border-color: var(--accent); width: 220px; }

.global-stats {
  display: flex;
  align-items: center;
  gap: 14px;
  font-family: var(--font-mono);
  font-size: 11px;
}
.stat-item { display: flex; gap: 4px; }
.stat-label { color: var(--text-muted); }
.stat-val.dl { color: var(--dl-color); font-weight: 600; }
.stat-val.ul { color: var(--ul-color); font-weight: 600; }

/* Main Layout */
.main-layout {
  display: flex;
  flex: 1;
  overflow: hidden;
}

/* Sidebar */
.sidebar {
  width: 220px;
  background-color: var(--bg-primary);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  overflow-y: auto;
}

.sidebar-section { padding: 12px 8px; }
.sidebar-title {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-muted);
  font-weight: 700;
  padding: 0 8px 6px 8px;
}

.category-list { list-style: none; }
.category-item {
  display: flex;
  align-items: center;
  padding: 6px 10px;
  border-radius: 4px;
  cursor: pointer;
  margin-bottom: 2px;
  color: var(--text-muted);
}
.category-item:hover { background-color: rgba(255, 255, 255, 0.04); color: var(--text-main); }
.category-item.active { background-color: var(--bg-secondary); color: var(--accent); font-weight: 600; }
.cat-icon { margin-right: 8px; font-size: 13px; }
.cat-name { flex: 1; }
.cat-count {
  background-color: var(--bg-tertiary);
  color: var(--text-main);
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 10px;
  font-family: var(--font-mono);
}

.daemon-info-card {
  background-color: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 8px;
  font-size: 11px;
  line-height: 1.6;
}
.daemon-info-card code { color: var(--accent); }

/* Content Area */
.content-area {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  background-color: var(--bg-primary);
}

.table-container {
  flex: 1;
  overflow: auto;
  position: relative;
}

.torrent-table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
}

.torrent-table th {
  background-color: var(--bg-secondary);
  color: var(--text-muted);
  font-weight: 600;
  font-size: 11px;
  padding: 7px 8px;
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 10;
  white-space: nowrap;
  cursor: pointer;
}
.torrent-table th:hover { color: var(--text-main); }
.torrent-table th.sort-asc::after { content: " ▲"; font-size: 8px; }
.torrent-table th.sort-desc::after { content: " ▼"; font-size: 8px; }

.torrent-table td {
  padding: 6px 8px;
  border-bottom: 1px solid var(--border-subtle);
  white-space: nowrap;
  font-size: 12px;
}
.torrent-table tbody tr { cursor: pointer; }
.torrent-table tbody tr:hover { background-color: var(--row-hover); }
.torrent-table tbody tr.selected { background-color: var(--row-selected) !important; outline: 1px solid var(--accent); }

.empty-row td {
  text-align: center;
  padding: 60px 0;
  color: var(--text-muted);
  font-style: italic;
}

/* Progress bar inside table */
.prog-wrapper {
  display: flex;
  align-items: center;
  gap: 6px;
}
.prog-bar {
  flex: 1;
  height: 12px;
  background-color: var(--bg-tertiary);
  border-radius: 3px;
  overflow: hidden;
  position: relative;
}
.prog-fill {
  height: 100%;
  background: linear-gradient(90deg, #0284c7, #38bdf8);
  border-radius: 3px;
  transition: width 0.2s ease;
}
.prog-fill.complete { background: linear-gradient(90deg, #16a34a, #22c55e); }
.prog-text { font-family: var(--font-mono); font-size: 10px; width: 36px; text-align: right; }

/* Status Badges */
.badge {
  display: inline-block;
  padding: 2px 6px;
  border-radius: 3px;
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.badge-downloading { background-color: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); }
.badge-seeding { background-color: rgba(34, 197, 94, 0.15); color: #22c55e; border: 1px solid rgba(34, 197, 94, 0.4); }
.badge-paused { background-color: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.4); }
.badge-queued { background-color: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }
.badge-checking { background-color: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid rgba(234, 179, 8, 0.4); }
.badge-error { background-color: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); }

/* Resizer */
.inspector-resizer {
  height: 4px;
  background-color: var(--border);
  cursor: ns-resize;
  flex-shrink: 0;
}
.inspector-resizer:hover { background-color: var(--accent); }

/* Bottom Inspector Panel */
.inspector-panel {
  height: 230px;
  background-color: var(--bg-secondary);
  border-top: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
}
.inspector-panel.hidden { display: none; }

.inspector-tabs {
  display: flex;
  background-color: var(--bg-primary);
  border-bottom: 1px solid var(--border);
  padding: 0 8px;
  align-items: center;
}

.tab-btn {
  background: none;
  border: none;
  color: var(--text-muted);
  padding: 7px 12px;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
  border-bottom: 2px solid transparent;
}
.tab-btn:hover { color: var(--text-main); }
.tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
.tab-spacer { flex: 1; }
.tab-close {
  background: none;
  border: none;
  color: var(--text-muted);
  font-size: 14px;
  cursor: pointer;
  padding: 4px 8px;
  margin-left: 8px;
}
.tab-close:hover { color: var(--danger); }

.inspector-body {
  flex: 1;
  overflow: auto;
  padding: 12px;
}

.tab-content { display: none; }
.tab-content.active { display: block; }

.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 8px 16px;
}
.detail-item { display: flex; font-size: 12px; }
.detail-item .lbl { width: 120px; color: var(--text-muted); }
.detail-item .val { flex: 1; color: var(--text-main); overflow: hidden; text-overflow: ellipsis; }
.detail-item .val.code { font-family: var(--font-mono); font-size: 11px; color: var(--accent); }

.sub-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 11px;
}
.sub-table th {
  background-color: var(--bg-primary);
  color: var(--text-muted);
  padding: 4px 8px;
  text-align: left;
  border-bottom: 1px solid var(--border);
}
.sub-table td {
  padding: 4px 8px;
  border-bottom: 1px solid var(--border-subtle);
}
.prio-select {
  background: var(--bg-tertiary);
  color: var(--text-main);
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: 2px 4px;
  font-size: 11px;
  outline: none;
  cursor: pointer;
}
.prio-select:hover {
  border-color: var(--primary);
}

/* Piece Map */
.pieces-wrapper { display: flex; flex-direction: column; gap: 8px; }
.pieces-header { display: flex; justify-content: space-between; font-size: 11px; color: var(--text-muted); }
.pieces-legend { display: flex; gap: 12px; align-items: center; }
.legend-box { width: 12px; height: 12px; border-radius: 2px; display: inline-block; }
.legend-box.comp { background-color: #38bdf8; }
.legend-box.miss { background-color: #334155; }
#piece-map-canvas {
  width: 100%;
  height: 120px;
  background-color: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: 4px;
}

/* Modals */
.modal {
  margin: auto;
  background-color: var(--bg-secondary);
  color: var(--text-main);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0;
  width: 480px;
  max-width: 90vw;
  box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.6);
  outline: none;
}
.modal-lg { width: 620px; }

.modal::backdrop {
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(2px);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
}
.modal-header h3 { font-size: 14px; font-weight: 600; }
.modal-close { background: none; border: none; color: var(--text-muted); font-size: 16px; cursor: pointer; }
.modal-close:hover { color: var(--text-main); }

.modal-body { padding: 16px; max-height: 70vh; overflow-y: auto; }
.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  padding: 12px 16px;
  border-top: 1px solid var(--border);
  background-color: var(--bg-primary);
}

.modal-tabs {
  display: flex;
  border-bottom: 1px solid var(--border);
  margin-bottom: 14px;
}

.form-group { margin-bottom: 12px; display: flex; flex-direction: column; gap: 4px; }
.form-group label { font-size: 11px; color: var(--text-muted); font-weight: 500; }
.form-group input, .form-group textarea, .form-group select {
  background-color: var(--bg-primary);
  border: 1px solid var(--border);
  color: var(--text-main);
  border-radius: 4px;
  padding: 6px 10px;
  font-size: 12px;
  font-family: inherit;
  outline: none;
}
.form-group input:focus, .form-group textarea:focus, .form-group select:focus {
  border-color: var(--accent);
}

.form-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 10px;
}
.form-row label { width: 220px; font-size: 12px; }
.form-row input[type="number"] {
  background-color: var(--bg-primary);
  border: 1px solid var(--border);
  color: var(--text-main);
  border-radius: 4px;
  padding: 4px 8px;
  width: 90px;
}
.form-row select {
  background-color: var(--bg-primary);
  border: 1px solid var(--border);
  color: var(--text-main);
  border-radius: 4px;
  padding: 4px 8px;
}

.checkbox-group label {
  display: flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  font-size: 12px;
}

.drop-zone {
  border: 2px dashed var(--border);
  border-radius: 6px;
  padding: 30px;
  text-align: center;
  cursor: pointer;
  background-color: var(--bg-primary);
  transition: all 0.2s ease;
}
.drop-zone:hover, .drop-zone.dragover { border-color: var(--accent); background-color: rgba(56, 189, 248, 0.05); }

.tab-pane.hidden { display: none; }

/* Toast Notifications */
.toast-container {
  position: fixed;
  bottom: 16px;
  right: 16px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  z-index: 1000;
}
.toast {
  background-color: var(--bg-secondary);
  border-left: 4px solid var(--accent);
  color: var(--text-main);
  padding: 8px 14px;
  border-radius: 4px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
  font-size: 12px;
  animation: fadeIn 0.2s ease;
}
.toast.success { border-left-color: var(--success); }
.toast.error { border-left-color: var(--danger); }
@keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
"#;

pub const APP_JS: &str = r#"
// Synapse 2.0 Web Client Controller (TransGUI & qBittorrent Parity)

let torrents = [];
let selectedHashes = new Set();
let activeFilter = 'all';
let sortField = 'name';
let sortAsc = true;
let sessionSettings = null;
let pollTimer = null;
let activeInspectorTab = 'general';
let selectedFile = null;

// Formatting Utilities
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatSpeed(bytesPerSec) {
  if (!bytesPerSec || bytesPerSec === 0) return '0 B/s';
  return formatBytes(bytesPerSec) + '/s';
}

function formatEta(seconds) {
  if (seconds === undefined || seconds === null || seconds < 0 || seconds >= 8640000) return '∞';
  if (seconds === 0) return 'Done';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerText = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 3500);
}

// REST API Client
let authToken = localStorage.getItem('synapse_auth_token') || '';

async function api(path, options = {}) {
  const headers = {
    'Accept': 'application/json',
    ...(options.headers || {})
  };
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }
  try {
    const res = await fetch(path, { ...options, headers });
    if (res.status === 401) {
      const token = prompt('Synapse requires an authorization token. Please enter your Bearer token:');
      if (token) {
        authToken = token.trim();
        localStorage.setItem('synapse_auth_token', authToken);
        return api(path, options);
      }
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({ message: res.statusText }));
      throw new Error(err.message || `HTTP ${res.status}`);
    }
    return await res.json();
  } catch (e) {
    document.getElementById('conn-status').classList.add('offline');
    throw e;
  }
}

// Fetch session stats & torrent list
async function fetchUpdate() {
  try {
    const [stats, torrentData] = await Promise.all([
      api('/api/v1/session/stats'),
      api('/api/v1/torrents?limit=10000')
    ]);

    document.getElementById('conn-status').classList.remove('offline');
    torrents = torrentData.torrents || [];

    // Update global toolbar metrics and DHT nodes
    document.getElementById('stat-dl-rate').innerText = formatSpeed(stats.download_rate);
    document.getElementById('stat-ul-rate').innerText = formatSpeed(stats.upload_rate);
    document.getElementById('stat-free-disk').innerText = formatBytes(stats.free_disk_space_bytes);

    const dhtEl = document.getElementById('stat-dht-nodes');
    if (dhtEl) {
      if (stats.dht_enabled === false) {
        dhtEl.innerText = 'Disabled';
      } else {
        dhtEl.innerText = `${stats.dht_nodes || 0}`;
      }
    }

    updateCategoryCounts();
    renderTorrentTable();

    if (selectedHashes.size === 1) {
      updateInspector([...selectedHashes][0]);
    }
  } catch (e) {
    console.warn('Poll update error:', e);
  }
}

function updateCategoryCounts() {
  const counts = { all: torrents.length, downloading: 0, seeding: 0, paused: 0, queued: 0, checking: 0, error: 0 };
  for (const t of torrents) {
    const st = (t.state || '').toLowerCase();
    if (st.includes('downloading')) counts.downloading++;
    else if (st.includes('seeding')) counts.seeding++;
    else if (st.includes('paused') || st.includes('stopped')) counts.paused++;
    else if (st.includes('queued')) counts.queued++;
    else if (st.includes('checking')) counts.checking++;
    else if (st.includes('error')) counts.error++;
  }
  for (const [k, v] of Object.entries(counts)) {
    const el = document.getElementById(`count-${k}`);
    if (el) el.innerText = v;
  }
}

function renderTorrentTable() {
  const tbody = document.getElementById('torrent-tbody');
  const search = document.getElementById('search-input').value.toLowerCase().trim();

  let filtered = torrents.filter(t => {
    if (activeFilter !== 'all') {
      const st = (t.state || '').toLowerCase();
      if (activeFilter === 'downloading' && !st.includes('downloading')) return false;
      if (activeFilter === 'seeding' && !st.includes('seeding')) return false;
      if (activeFilter === 'paused' && !(st.includes('paused') || st.includes('stopped'))) return false;
      if (activeFilter === 'queued' && !st.includes('queued')) return false;
      if (activeFilter === 'checking' && !st.includes('checking')) return false;
      if (activeFilter === 'error' && !st.includes('error')) return false;
    }
    if (search && !t.name.toLowerCase().includes(search) && !t.info_hash.toLowerCase().includes(search)) {
      return false;
    }
    return true;
  });

  filtered.sort((a, b) => {
    let vA = a[sortField];
    let vB = b[sortField];
    if (sortField === 'progress') { vA = a.progress; vB = b.progress; }
    if (typeof vA === 'string') return sortAsc ? vA.localeCompare(vB) : vB.localeCompare(vA);
    return sortAsc ? (vA - vB) : (vB - vA);
  });

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="11">No matching torrents found.</td></tr>';
    updateToolbarButtons();
    return;
  }

  tbody.innerHTML = '';
  filtered.forEach((t, idx) => {
    const tr = document.createElement('tr');
    tr.dataset.hash = t.info_hash;
    if (selectedHashes.has(t.info_hash)) tr.classList.add('selected');

    const pct = (t.progress * 100).toFixed(1);
    const isComplete = t.progress >= 1.0;
    const stClean = cleanState(t.state);
    const badgeClass = getBadgeClass(stClean);

    tr.innerHTML = `
      <td>${idx + 1}</td>
      <td title="${t.name}"><strong>${escapeHtml(t.name)}</strong></td>
      <td>${formatBytes(t.total_bytes)}</td>
      <td>
        <div class="prog-wrapper">
          <div class="prog-bar">
            <div class="prog-fill ${isComplete ? 'complete' : ''}" style="width: ${pct}%"></div>
          </div>
          <span class="prog-text">${pct}%</span>
        </div>
      </td>
      <td><span class="badge ${badgeClass}">${stClean}</span></td>
      <td>${t.peers_connected || 0}</td>
      <td>${t.peers_connected || 0}</td>
      <td style="color: var(--dl-color);">${formatSpeed(t.download_rate)}</td>
      <td style="color: var(--ul-color);">${formatSpeed(t.upload_rate)}</td>
      <td>${t.eta_seconds !== undefined ? formatEta(t.eta_seconds) : (t.download_rate > 0 ? formatEta(Math.round((t.total_bytes * (1 - t.progress)) / t.download_rate)) : '∞')}</td>
      <td>${(t.uploaded_bytes && t.downloaded_bytes && t.downloaded_bytes > 0) ? (t.uploaded_bytes / t.downloaded_bytes).toFixed(2) : '0.00'}</td>
    `;

    tr.addEventListener('click', (e) => handleRowClick(e, t.info_hash));
    tr.addEventListener('dblclick', () => {
      document.getElementById('inspector-panel').classList.remove('hidden');
      updateInspector(t.info_hash);
    });
    tbody.appendChild(tr);
  });

  updateToolbarButtons();
}

function cleanState(st) {
  if (!st) return 'Unknown';
  if (st.includes('Downloading')) return 'Downloading';
  if (st.includes('Seeding')) return 'Seeding';
  if (st.includes('Paused') || st.includes('Stopped')) return 'Paused';
  if (st.includes('Queued')) return 'Queued';
  if (st.includes('Checking')) return 'Checking';
  if (st.includes('Error')) return 'Error';
  return st;
}

function getBadgeClass(st) {
  switch (st) {
    case 'Downloading': return 'badge-downloading';
    case 'Seeding': return 'badge-seeding';
    case 'Paused': return 'badge-paused';
    case 'Queued': return 'badge-queued';
    case 'Checking': return 'badge-checking';
    case 'Error': return 'badge-error';
    default: return 'badge-queued';
  }
}

function handleRowClick(e, hash) {
  if (e.ctrlKey || e.metaKey) {
    if (selectedHashes.has(hash)) selectedHashes.delete(hash);
    else selectedHashes.add(hash);
  } else if (e.shiftKey && selectedHashes.size > 0) {
    // range select
    selectedHashes.add(hash);
  } else {
    selectedHashes.clear();
    selectedHashes.add(hash);
  }

  document.querySelectorAll('#torrent-tbody tr').forEach(tr => {
    if (selectedHashes.has(tr.dataset.hash)) tr.classList.add('selected');
    else tr.classList.remove('selected');
  });

  updateToolbarButtons();

  if (selectedHashes.size === 1) {
    document.getElementById('inspector-panel').classList.remove('hidden');
    updateInspector(hash);
  } else if (selectedHashes.size === 0) {
    document.getElementById('inspector-panel').classList.add('hidden');
  }
}

function updateToolbarButtons() {
  const hasSelection = selectedHashes.size > 0;
  document.getElementById('btn-resume').disabled = !hasSelection;
  document.getElementById('btn-pause').disabled = !hasSelection;
  document.getElementById('btn-delete').disabled = !hasSelection;
}

// Inspector details
async function updateInspector(hash) {
  try {
    const d = await api(`/api/v1/torrents/${hash}/detail`);

    // General
    document.getElementById('det-name').innerText = d.name || '-';
    document.getElementById('det-hash').innerText = d.info_hash || '-';
    document.getElementById('det-path').innerText = d.download_dir || '-';
    document.getElementById('det-size').innerText = formatBytes(d.total_bytes);
    document.getElementById('det-pieces').innerText = `${d.piece_count || 0} pieces @ ${formatBytes(d.piece_size || 0)}`;
    document.getElementById('det-state').innerText = `${cleanState(d.state)} (${d.tier || 'Hot'})`;

    const disc = d.discovery || {};
    const privacyEl = document.getElementById('det-privacy');
    if (privacyEl) {
      privacyEl.innerText = disc.is_private ? '🔒 Private (BEP 27)' : '🌐 Public Swarm';
    }
    const discEl = document.getElementById('det-discovery');
    if (discEl) {
      if (disc.is_private) {
        discEl.innerText = 'DHT / PEX / LSD Prohibited';
      } else {
        const parts = [];
        parts.push(disc.dht_enabled ? 'DHT' : 'DHT off');
        parts.push(disc.pex_enabled ? `PEX (${disc.pex_peers || 0} active)` : 'PEX off');
        parts.push(disc.lsd_enabled ? 'LSD' : 'LSD off');
        discEl.innerText = parts.join(' | ');
      }
    }
    const webseedsEl = document.getElementById('det-webseeds');
    if (webseedsEl) {
      webseedsEl.innerText = (disc.webseeds_count || 0) > 0 ? `${disc.webseeds_count} HTTP mirror(s)` : 'None';
    }

    // Transfer
    document.getElementById('det-downloaded').innerText = formatBytes(d.downloaded_bytes);
    document.getElementById('det-uploaded').innerText = formatBytes(d.uploaded_bytes);
    document.getElementById('det-dl-rate').innerText = formatSpeed(d.download_rate);
    document.getElementById('det-ul-rate').innerText = formatSpeed(d.upload_rate);
    document.getElementById('det-ratio').innerText = d.ratio !== undefined ? d.ratio.toFixed(2) : '0.00';
    document.getElementById('det-eta').innerText = formatEta(d.eta_seconds);

    const inPool = d.candidate_peers !== undefined ? ` (${d.candidate_peers} in pool, ${d.active_dials || 0} dialing)` : '';
    document.getElementById('det-peer-count').innerText = `${d.peers_connected || 0} connected${inPool}`;

    const discCountsEl = document.getElementById('det-discovered-counts');
    if (discCountsEl) {
      discCountsEl.innerText = `Trackers: ${disc.discovered_from_tracker || 0} | DHT: ${disc.discovered_from_dht || 0} | PEX: ${disc.discovered_from_pex || 0} | LSD: ${disc.discovered_from_lsd || 0}`;
    }

    // Trackers
    const tBody = document.getElementById('trackers-tbody');
    if (d.trackers && d.trackers.length > 0) {
      tBody.innerHTML = d.trackers.map(tr => `
        <tr>
          <td><code>${escapeHtml(tr.url)}</code></td>
          <td>${tr.status || 'Active'}</td>
          <td>${tr.seeders || '-'}</td>
          <td>${tr.leechers || '-'}</td>
          <td>${tr.next_announce_in ? tr.next_announce_in + 's' : '-'}</td>
        </tr>
      `).join('');
    } else {
      tBody.innerHTML = '<tr><td colspan="5">No announce trackers configured</td></tr>';
    }

    // Peers
    const pBody = document.getElementById('peers-tbody');
    if (d.active_peers && d.active_peers.length > 0) {
      pBody.innerHTML = d.active_peers.map(p => `
        <tr>
          <td><code>${escapeHtml(p.address)}</code></td>
          <td>${escapeHtml(p.client_name || 'Unknown')}</td>
          <td><code>${escapeHtml(p.flags || '-')}</code></td>
          <td style="color: var(--dl-color);">${formatSpeed(p.rate_to_client)}</td>
          <td style="color: var(--ul-color);">${formatSpeed(p.rate_to_peer)}</td>
          <td>${((p.progress || 0) * 100).toFixed(1)}%</td>
          <td>${p.is_encrypted ? '🔒 TLS/Enc' : 'Plain'} ${p.is_utp ? '(uTP)' : '(TCP)'}</td>
        </tr>
      `).join('');
    } else {
      pBody.innerHTML = '<tr><td colspan="7">No active remote peers connected</td></tr>';
    }

    // Files
    const fBody = document.getElementById('files-tbody');
    if (d.files && d.files.length > 0) {
      fBody.innerHTML = d.files.map(f => `
        <tr>
          <td>${f.index + 1}</td>
          <td title="${f.path}">${escapeHtml(f.path)}</td>
          <td>${formatBytes(f.size_bytes)}</td>
          <td>
            <div class="prog-wrapper">
              <div class="prog-bar"><div class="prog-fill" style="width: ${(f.progress * 100).toFixed(1)}%"></div></div>
              <span class="prog-text">${(f.progress * 100).toFixed(0)}%</span>
            </div>
          </td>
          <td>
            <select class="prio-select" onchange="setFilePriority('${hash}', ${f.index}, this.value)">
              <option value="0" ${f.priority === 0 ? 'selected' : ''}>Skip</option>
              <option value="1" ${f.priority === 1 ? 'selected' : ''}>Low</option>
              <option value="4" ${f.priority === 4 ? 'selected' : ''}>Normal</option>
              <option value="7" ${f.priority === 7 ? 'selected' : ''}>High</option>
            </select>
          </td>
        </tr>
      `).join('');
    } else {
      fBody.innerHTML = '<tr><td colspan="5">Single file swarm</td></tr>';
    }

    // Pieces canvas
    renderPieceMap(d.piece_count, d.piece_bitfield);
  } catch (e) {
    console.error('Inspector fetch failed:', e);
  }
}

async function setFilePriority(hash, fileIndex, priority) {
  try {
    await api(`/api/v1/torrents/${hash}/files/${fileIndex}/priority`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ priority: parseInt(priority, 10) })
    });
  } catch (e) {
    alert('Failed to set file priority: ' + e.message);
  }
}

function formatPriority(p) {
  if (p === 0) return 'Skip';
  if (p === 1) return 'Low';
  if (p === 7) return 'High';
  return 'Normal';
}

function renderPieceMap(pieceCount, bitfieldHex) {
  const canvas = document.getElementById('piece-map-canvas');
  if (!canvas || !pieceCount) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width = canvas.parentElement.clientWidth || 800;
  const h = canvas.height = 120;
  ctx.clearRect(0, 0, w, h);

  const bitfield = [];
  let completed = 0;
  if (bitfieldHex) {
    for (let i = 0; i < bitfieldHex.length; i += 2) {
      const byte = parseInt(bitfieldHex.substr(i, 2), 16);
      for (let b = 7; b >= 0; b--) {
        if (bitfield.length < pieceCount) {
          const has = (byte & (1 << b)) !== 0;
          bitfield.push(has);
          if (has) completed++;
        }
      }
    }
  }

  document.getElementById('piece-stat-counts').innerText = `${completed} / ${pieceCount} pieces (${((completed / pieceCount) * 100).toFixed(1)}%)`;

  const cellW = Math.max(3, Math.floor(w / Math.min(pieceCount, 150)));
  const cellH = 10;
  const cols = Math.floor(w / cellW);

  for (let i = 0; i < pieceCount; i++) {
    const col = i % cols;
    const row = Math.floor(i / cols);
    const x = col * cellW;
    const y = row * (cellH + 2);
    if (y + cellH > h) break;

    ctx.fillStyle = bitfield[i] ? '#38bdf8' : '#334155';
    ctx.fillRect(x, y, cellW - 1, cellH);
  }
}

// Actions
async function resumeSelected() {
  for (const h of selectedHashes) {
    await api(`/api/v1/torrents/${h}/resume`, { method: 'POST' });
  }
  showToast('Resumed selected torrent(s)', 'success');
  fetchUpdate();
}

async function pauseSelected() {
  for (const h of selectedHashes) {
    await api(`/api/v1/torrents/${h}/pause`, { method: 'POST' });
  }
  showToast('Paused selected torrent(s)', 'info');
  fetchUpdate();
}

function openDeleteModal() {
  if (selectedHashes.size === 0) return;
  const names = torrents.filter(t => selectedHashes.has(t.info_hash)).map(t => t.name).join(', ');
  document.getElementById('delete-torrent-name').innerText = names;
  document.getElementById('check-delete-data').checked = false;
  document.getElementById('modal-delete-torrent').showModal();
}

async function submitDelete() {
  const deleteData = document.getElementById('check-delete-data').checked;
  for (const h of selectedHashes) {
    await api(`/api/v1/torrents/${h}?delete_data=${deleteData}`, { method: 'DELETE' });
  }
  document.getElementById('modal-delete-torrent').close();
  selectedHashes.clear();
  showToast('Torrent(s) deleted successfully', 'success');
  fetchUpdate();
}

async function forceRecheck() {
  if (selectedHashes.size !== 1) return;
  const h = [...selectedHashes][0];
  await api(`/api/v1/torrents/${h}/recheck`, { method: 'POST' });
  showToast('Piece verification recheck dispatched', 'info');
  fetchUpdate();
}

// Add torrent handling
function switchAddTab(type) {
  document.querySelectorAll('#modal-add-torrent .modal-tabs .tab-btn').forEach((b, idx) => {
    b.classList.toggle('active', (type === 'file' && idx === 0) || (type === 'magnet' && idx === 1) || (type === 'url' && idx === 2));
  });
  document.getElementById('pane-file').classList.toggle('hidden', type !== 'file');
  document.getElementById('pane-magnet').classList.toggle('hidden', type !== 'magnet');
  document.getElementById('pane-url').classList.toggle('hidden', type !== 'url');
}

async function submitAddTorrent() {
  const downloadDir = document.getElementById('input-download-dir').value.trim() || undefined;
  const paused = document.getElementById('check-start-paused').checked;

  if (selectedFile) {
    const arrayBuffer = await selectedFile.arrayBuffer();
    const bytes = new Uint8Array(arrayBuffer);
    const query = new URLSearchParams();
    if (downloadDir) query.set('download_dir', downloadDir);
    if (paused) query.set('paused', 'true');

    const uploadHeaders = { 'Content-Type': 'application/x-bittorrent' };
    if (authToken) {
      uploadHeaders['Authorization'] = `Bearer ${authToken}`;
    }
    const res = await fetch(`/api/v1/torrents/upload?${query.toString()}`, {
      method: 'POST',
      headers: uploadHeaders,
      body: bytes
    });
    if (!res.ok) {
      if (res.status === 401) {
        showToast('Unauthorized: Set your authorization token in Settings -> Security', 'error');
      } else {
        showToast('Upload failed: HTTP ' + res.status, 'error');
      }
      return;
    }
    showToast('Uploaded and added .torrent file', 'success');
  } else {
    const magnet = document.getElementById('input-magnet').value.trim();
    const url = document.getElementById('input-url').value.trim();
    if (!magnet && !url) {
      showToast('Please provide a file, magnet URI, or URL', 'error');
      return;
    }
    await api('/api/v1/torrents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ magnet: magnet || undefined, url: url || undefined, download_dir: downloadDir, paused })
    });
    showToast('Torrent added successfully', 'success');
  }

  document.getElementById('modal-add-torrent').close();
  selectedFile = null;
  document.getElementById('file-name-display').innerText = '';
  document.getElementById('input-magnet').value = '';
  document.getElementById('input-url').value = '';
  fetchUpdate();
}

// Settings modal
async function openSettings() {
  try {
    sessionSettings = await api('/api/v1/session');

    // Bandwidth
    document.getElementById('cfg-down-limit-enabled').checked = sessionSettings.download_limit_enabled;
    document.getElementById('cfg-down-limit-val').value = Math.round(sessionSettings.download_limit_bytes / 1024);
    document.getElementById('cfg-up-limit-enabled').checked = sessionSettings.upload_limit_enabled;
    document.getElementById('cfg-up-limit-val').value = Math.round(sessionSettings.upload_limit_bytes / 1024);

    document.getElementById('cfg-alt-enabled').checked = sessionSettings.alt_speed_enabled;
    document.getElementById('cfg-alt-down-val').value = Math.round(sessionSettings.alt_speed_down_bytes / 1024);
    document.getElementById('cfg-alt-up-val').value = Math.round(sessionSettings.alt_speed_up_bytes / 1024);

    // Queue
    document.getElementById('cfg-dl-queue-enabled').checked = sessionSettings.download_queue_enabled;
    document.getElementById('cfg-max-downloads').value = sessionSettings.download_queue_size;
    document.getElementById('cfg-seed-queue-enabled').checked = sessionSettings.seed_queue_enabled;
    document.getElementById('cfg-max-seeds').value = sessionSettings.seed_queue_size;
    document.getElementById('cfg-max-total-torrents').value = sessionSettings.max_active_torrents;
    document.getElementById('cfg-stall-enabled').checked = sessionSettings.queue_stalled_enabled;
    document.getElementById('cfg-stall-minutes').value = sessionSettings.queue_stalled_minutes;

    // Peers
    document.getElementById('cfg-max-peers-torrent').value = sessionSettings.max_peers_per_torrent;
    document.getElementById('cfg-max-peers-global').value = sessionSettings.max_global_peers;
    document.getElementById('cfg-dht-enabled').checked = sessionSettings.dht_enabled;
    document.getElementById('cfg-pex-enabled').checked = sessionSettings.pex_enabled;
    document.getElementById('cfg-lsd-enabled').checked = sessionSettings.lsd_enabled;
    document.getElementById('cfg-encryption').value = sessionSettings.encryption || 'preferred';

    // Storage
    document.getElementById('cfg-download-dir').value = sessionSettings.download_dir;
    document.getElementById('cfg-incomplete-enabled').checked = sessionSettings.incomplete_dir_enabled;
    document.getElementById('cfg-incomplete-dir').value = sessionSettings.incomplete_dir || '';
    document.getElementById('cfg-start-added').checked = sessionSettings.start_added_torrents;

    // Security
    const tokenInput = document.getElementById('cfg-auth-token');
    if (tokenInput) {
      tokenInput.value = authToken;
    }

    document.getElementById('settings-status').innerText = '';
    document.getElementById('modal-settings').showModal();
  } catch (e) {
    showToast('Failed to load session settings: ' + e.message, 'error');
  }
}

async function saveSettings() {
  const tokenInput = document.getElementById('cfg-auth-token');
  if (tokenInput) {
    const newToken = tokenInput.value.trim();
    if (newToken !== authToken) {
      authToken = newToken;
      if (authToken) {
        localStorage.setItem('synapse_auth_token', authToken);
      } else {
        localStorage.removeItem('synapse_auth_token');
      }
      fetchUpdate();
    }
  }

  const payload = {
    download_limit_enabled: document.getElementById('cfg-down-limit-enabled').checked,
    download_limit_bytes: parseInt(document.getElementById('cfg-down-limit-val').value, 10) * 1024,
    upload_limit_enabled: document.getElementById('cfg-up-limit-enabled').checked,
    upload_limit_bytes: parseInt(document.getElementById('cfg-up-limit-val').value, 10) * 1024,

    alt_speed_enabled: document.getElementById('cfg-alt-enabled').checked,
    alt_speed_down_bytes: parseInt(document.getElementById('cfg-alt-down-val').value, 10) * 1024,
    alt_speed_up_bytes: parseInt(document.getElementById('cfg-alt-up-val').value, 10) * 1024,

    download_queue_enabled: document.getElementById('cfg-dl-queue-enabled').checked,
    download_queue_size: parseInt(document.getElementById('cfg-max-downloads').value, 10),
    seed_queue_enabled: document.getElementById('cfg-seed-queue-enabled').checked,
    seed_queue_size: parseInt(document.getElementById('cfg-max-seeds').value, 10),
    max_active_torrents: parseInt(document.getElementById('cfg-max-total-torrents').value, 10),
    queue_stalled_enabled: document.getElementById('cfg-stall-enabled').checked,
    queue_stalled_minutes: parseInt(document.getElementById('cfg-stall-minutes').value, 10),

    max_peers_per_torrent: parseInt(document.getElementById('cfg-max-peers-torrent').value, 10),
    max_global_peers: parseInt(document.getElementById('cfg-max-peers-global').value, 10),
    dht_enabled: document.getElementById('cfg-dht-enabled').checked,
    pex_enabled: document.getElementById('cfg-pex-enabled').checked,
    lsd_enabled: document.getElementById('cfg-lsd-enabled').checked,
    encryption: document.getElementById('cfg-encryption').value,

    download_dir: document.getElementById('cfg-download-dir').value.trim() || undefined,
    incomplete_dir: document.getElementById('cfg-incomplete-dir').value.trim() || undefined,
    incomplete_dir_enabled: document.getElementById('cfg-incomplete-enabled').checked,
    start_added_torrents: document.getElementById('cfg-start-added').checked
  };

  try {
    await api('/api/v1/session', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    showToast('Session settings applied in-flight', 'success');
    document.getElementById('modal-settings').close();
    updateTurtleButtonState();
  } catch (e) {
    document.getElementById('settings-status').innerText = 'Error: ' + e.message;
  }
}

async function toggleTurtleMode() {
  try {
    const s = await api('/api/v1/session');
    const newState = !s.alt_speed_enabled;
    await api('/api/v1/session', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alt_speed_enabled: newState })
    });
    updateTurtleButtonState(newState);
    showToast(newState ? '🐢 Turtle Mode activated' : '⚡ Normal speed limits restored', 'info');
  } catch (e) {
    showToast('Failed to toggle turtle mode: ' + e.message, 'error');
  }
}

async function updateTurtleButtonState(explicitState) {
  const btn = document.getElementById('btn-turtle');
  if (explicitState !== undefined) {
    btn.classList.toggle('active', explicitState);
    return;
  }
  try {
    const s = await api('/api/v1/session');
    btn.classList.toggle('active', s.alt_speed_enabled || s.is_alt_speed_active);
  } catch (_) {}
}

function switchSettingsTab(tab) {
  const tabs = ['bandwidth', 'queue', 'peers', 'storage', 'security'];
  tabs.forEach((t, i) => {
    const btns = document.querySelectorAll('#modal-settings .modal-tabs .tab-btn');
    if (btns[i]) btns[i].classList.toggle('active', t === tab);
    const pane = document.getElementById(`spane-${t}`);
    if (pane) pane.classList.toggle('hidden', t !== tab);
  });
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Initial Setup & Listeners
window.addEventListener('DOMContentLoaded', () => {
  // Sidebar categories
  document.querySelectorAll('.category-item').forEach(el => {
    el.addEventListener('click', () => {
      document.querySelectorAll('.category-item').forEach(c => c.classList.remove('active'));
      el.classList.add('active');
      activeFilter = el.dataset.state;
      renderTorrentTable();
    });
  });

  // Table header sorting
  document.querySelectorAll('.torrent-table th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const field = th.dataset.sort;
      if (sortField === field) {
        sortAsc = !sortAsc;
      } else {
        sortField = field;
        sortAsc = true;
      }
      document.querySelectorAll('.torrent-table th').forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
      th.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
      renderTorrentTable();
    });
  });

  // Search filter
  document.getElementById('search-input').addEventListener('input', () => renderTorrentTable());

  // Action Buttons
  document.getElementById('btn-add-torrent').addEventListener('click', () => {
    selectedFile = null;
    document.getElementById('file-name-display').innerText = '';
    document.getElementById('modal-add-torrent').showModal();
  });
  document.getElementById('btn-resume').addEventListener('click', resumeSelected);
  document.getElementById('btn-pause').addEventListener('click', pauseSelected);
  document.getElementById('btn-delete').addEventListener('click', openDeleteModal);
  document.getElementById('btn-submit-delete').addEventListener('click', submitDelete);
  document.getElementById('btn-turtle').addEventListener('click', toggleTurtleMode);
  document.getElementById('btn-settings').addEventListener('click', openSettings);
  document.getElementById('btn-save-settings').addEventListener('click', saveSettings);
  document.getElementById('btn-submit-add').addEventListener('click', submitAddTorrent);
  document.getElementById('btn-recheck-torrent').addEventListener('click', forceRecheck);
  const btnClearToken = document.getElementById('btn-clear-token');
  if (btnClearToken) {
    btnClearToken.addEventListener('click', () => {
      authToken = '';
      localStorage.removeItem('synapse_auth_token');
      const tokenInput = document.getElementById('cfg-auth-token');
      if (tokenInput) tokenInput.value = '';
      showToast('Authentication token cleared', 'info');
      document.getElementById('modal-settings').close();
      fetchUpdate();
    });
  }

  // Inspector Tabs
  document.querySelectorAll('.inspector-tabs .tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.inspector-tabs .tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      activeInspectorTab = btn.dataset.tab;
      document.getElementById(`tab-${activeInspectorTab}`).classList.add('active');
      if (activeInspectorTab === 'pieces' && selectedHashes.size === 1) {
        updateInspector([...selectedHashes][0]);
      }
    });
  });

  document.getElementById('btn-close-inspector').addEventListener('click', () => {
    document.getElementById('inspector-panel').classList.add('hidden');
  });

  // File Upload Drag and Drop
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');

  dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      selectedFile = e.dataTransfer.files[0];
      document.getElementById('file-name-display').innerText = `Selected: ${selectedFile.name} (${formatBytes(selectedFile.size)})`;
    }
  });
  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      selectedFile = fileInput.files[0];
      document.getElementById('file-name-display').innerText = `Selected: ${selectedFile.name} (${formatBytes(selectedFile.size)})`;
    }
  });

  // Keyboard Shortcuts
  window.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
    if (e.key === ' ' && selectedHashes.size > 0) {
      e.preventDefault();
      // toggle pause/resume
      const first = torrents.find(t => selectedHashes.has(t.info_hash));
      if (first && cleanState(first.state) === 'Paused') resumeSelected();
      else pauseSelected();
    } else if (e.key === 'Delete' && selectedHashes.size > 0) {
      e.preventDefault();
      openDeleteModal();
    } else if (e.key === 'Escape') {
      selectedHashes.clear();
      renderTorrentTable();
      document.getElementById('inspector-panel').classList.add('hidden');
    }
  });

  // Poll loop
  fetchUpdate();
  pollTimer = setInterval(fetchUpdate, 1500);
  updateTurtleButtonState();
});
"#;
