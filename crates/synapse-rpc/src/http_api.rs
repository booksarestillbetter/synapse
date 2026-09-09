//! Alternative REST API, OpenAPI Schema, Swagger UI and Prometheus Metrics Service.
//!
//! Provides a full-featured HTTP control plane for web browsers, scripting, and monitoring.

use std::sync::Arc;
use axum::{
    extract::{Path, Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use synapse_engine::SwarmEngine;
use crate::metrics::{render_prometheus_metrics, PrometheusSnapshot};
use crate::swagger::{get_swagger_ui_html, OPENAPI_JSON};

#[derive(Clone)]
pub struct ApiState {
    pub engine: Arc<SwarmEngine>,
    pub auth_token: Option<String>,
    pub web_config: synapse_config::WebConfig,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DeleteTorrentQuery {
    pub delete_data: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct UploadTorrentQuery {
    pub download_dir: Option<String>,
    pub paused: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetLocationRequest {
    pub new_download_dir: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PaginationQuery {
    pub page: Option<usize>,
    pub limit: Option<usize>,
    pub state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddTorrentRequest {
    pub magnet: Option<String>,
    pub url: Option<String>,
    pub torrent_base64: Option<String>,
    pub download_dir: Option<String>,
    pub paused: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionSettingsApiResponse {
    pub download_limit_enabled: bool,
    pub download_limit_bytes: u64,
    pub download_limit_pretty: String,
    pub upload_limit_enabled: bool,
    pub upload_limit_bytes: u64,
    pub upload_limit_pretty: String,

    pub alt_speed_enabled: bool,
    pub alt_speed_down_bytes: u64,
    pub alt_speed_down_pretty: String,
    pub alt_speed_up_bytes: u64,
    pub alt_speed_up_pretty: String,
    pub alt_speed_time_enabled: bool,
    pub alt_speed_time_begin: u32,
    pub alt_speed_time_end: u32,
    pub alt_speed_time_days: u32,
    pub is_alt_speed_active: bool,

    pub download_queue_enabled: bool,
    pub download_queue_size: usize,
    pub seed_queue_enabled: bool,
    pub seed_queue_size: usize,
    pub max_active_torrents: usize,
    pub queue_stalled_enabled: bool,
    pub queue_stalled_minutes: u32,
    pub seed_ratio_limited: bool,
    pub seed_ratio_limit: f64,
    pub idle_seeding_limit_enabled: bool,
    pub idle_seeding_limit_minutes: u32,

    pub max_peers_per_torrent: usize,
    pub max_global_peers: usize,
    pub dht_enabled: bool,
    pub pex_enabled: bool,
    pub lsd_enabled: bool,
    pub encryption: String,

    pub download_dir: String,
    pub incomplete_dir: Option<String>,
    pub incomplete_dir_enabled: bool,
    pub start_added_torrents: bool,
    pub trash_original_torrent_files: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateSessionSettingsResponse {
    pub success: bool,
    pub warnings: Vec<String>,
}

pub fn create_http_router(engine: Arc<SwarmEngine>) -> Router {
    create_http_router_with_auth(engine, None)
}

/// `state.auth_token` was previously stored but never read anywhere in this file — every
/// handler was reachable with no `Authorization` header regardless of config. Torrent
/// data/action routes now require it when configured; health, docs, and `/metrics` stay open
/// (health checks and Prometheus scraping are conventionally treated as same-trust-network
/// concerns, not bearer-token-gated, and gating them would break a scrape config that doesn't
/// send arbitrary headers).
pub fn create_http_router_with_auth(engine: Arc<SwarmEngine>, auth_token: Option<String>) -> Router {
    create_http_router_full(engine, auth_token, true)
}

pub fn create_http_router_full(
    engine: Arc<SwarmEngine>,
    auth_token: Option<String>,
    metrics_enabled: bool,
) -> Router {
    create_http_router_all(
        engine,
        auth_token,
        metrics_enabled,
        synapse_config::WebConfig::default(),
    )
}

pub fn create_http_router_all(
    engine: Arc<SwarmEngine>,
    auth_token: Option<String>,
    metrics_enabled: bool,
    web_config: synapse_config::WebConfig,
) -> Router {
    let state = ApiState {
        engine,
        auth_token,
        web_config: web_config.clone(),
    };

    let protected = Router::new()
        .route(
            "/api/v1/session",
            get(get_session_settings_handler).patch(update_session_settings_handler),
        )
        .route("/api/v1/session/stats", get(session_stats_handler))
        .route(
            "/api/v1/torrents",
            get(list_torrents_handler).post(add_torrent_handler),
        )
        .route("/api/v1/torrents/upload", post(upload_torrent_handler))
        .route(
            "/api/v1/torrents/:info_hash",
            get(get_torrent_handler).delete(delete_torrent_handler),
        )
        .route(
            "/api/v1/torrents/:info_hash/detail",
            get(get_torrent_detail_handler),
        )
        .route("/api/v1/torrents/:info_hash/pause", post(pause_torrent_handler))
        .route("/api/v1/torrents/:info_hash/resume", post(resume_torrent_handler))
        .route("/api/v1/torrents/:info_hash/recheck", post(recheck_torrent_handler))
        .route("/api/v1/torrents/:info_hash/location", post(set_location_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let mut public = Router::new()
        .route("/api/v1/health", get(health_handler))
        .route("/api-docs/openapi.json", get(openapi_json_handler))
        .route("/swagger-ui", get(swagger_ui_handler));

    if metrics_enabled {
        public = public.route("/metrics", get(metrics_handler));
    }

    if web_config.enabled {
        public = public
            .route("/", get(crate::web::web_index_handler))
            .route("/index.html", get(crate::web::web_index_handler))
            .route("/web", get(crate::web::web_index_handler))
            .route("/style.css", get(crate::web::web_css_handler))
            .route("/app.js", get(crate::web::web_js_handler))
            .route("/favicon.ico", get(crate::web::web_favicon_handler));
    }

    protected.merge(public).with_state(state)
}

async fn require_auth(State(state): State<ApiState>, req: Request, next: Next) -> Result<Response, StatusCode> {
    let Some(ref expected) = state.auth_token else {
        return Ok(next.run(req).await);
    };
    let authorized = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").unwrap_or(v).trim() == expected)
        .unwrap_or(false);
    if !authorized {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(req).await)
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn get_session_settings_handler(
    State(state): State<ApiState>,
) -> Json<SessionSettingsApiResponse> {
    let s = state.engine.get_session_settings();
    let is_alt_speed_active = state.engine.is_alt_speed_active();

    Json(SessionSettingsApiResponse {
        download_limit_enabled: s.download_limit_enabled,
        download_limit_bytes: s.download_limit_bytes,
        download_limit_pretty: synapse_config::format_bytes_as_bitrate(s.download_limit_bytes),
        upload_limit_enabled: s.upload_limit_enabled,
        upload_limit_bytes: s.upload_limit_bytes,
        upload_limit_pretty: synapse_config::format_bytes_as_bitrate(s.upload_limit_bytes),

        alt_speed_enabled: s.alt_speed_enabled,
        alt_speed_down_bytes: s.alt_speed_down_bytes,
        alt_speed_down_pretty: synapse_config::format_bytes_as_bitrate(s.alt_speed_down_bytes),
        alt_speed_up_bytes: s.alt_speed_up_bytes,
        alt_speed_up_pretty: synapse_config::format_bytes_as_bitrate(s.alt_speed_up_bytes),
        alt_speed_time_enabled: s.alt_speed_time_enabled,
        alt_speed_time_begin: s.alt_speed_time_begin,
        alt_speed_time_end: s.alt_speed_time_end,
        alt_speed_time_days: s.alt_speed_time_days,
        is_alt_speed_active,

        download_queue_enabled: s.queue.download_queue_enabled,
        download_queue_size: s.queue.max_active_downloads,
        seed_queue_enabled: s.queue.seed_queue_enabled,
        seed_queue_size: s.queue.max_active_seeds,
        max_active_torrents: s.queue.max_active_torrents,
        queue_stalled_enabled: s.queue.queue_stalled_enabled,
        queue_stalled_minutes: s.queue.queue_stalled_minutes,
        seed_ratio_limited: s.queue.seed_ratio_limited,
        seed_ratio_limit: s.queue.share_ratio_limit.unwrap_or(0.0),
        idle_seeding_limit_enabled: s.queue.idle_seeding_limit_enabled,
        idle_seeding_limit_minutes: s.queue.idle_seeding_limit_minutes().unwrap_or(0),

        max_peers_per_torrent: s.max_peers_per_torrent,
        max_global_peers: s.max_global_peers,
        dht_enabled: s.dht_enabled,
        pex_enabled: s.pex_enabled,
        lsd_enabled: s.lsd_enabled,
        encryption: s.encryption,

        download_dir: s.download_dir.to_string_lossy().into_owned(),
        incomplete_dir: s.incomplete_dir.map(|p| p.to_string_lossy().into_owned()),
        incomplete_dir_enabled: s.incomplete_dir_enabled,
        start_added_torrents: s.start_added_torrents,
        trash_original_torrent_files: s.trash_original_torrent_files,
    })
}

async fn update_session_settings_handler(
    State(state): State<ApiState>,
    Json(payload): Json<synapse_engine::SessionSettingsUpdate>,
) -> Json<UpdateSessionSettingsResponse> {
    let warnings = state.engine.update_session_settings(payload);
    Json(UpdateSessionSettingsResponse {
        success: true,
        warnings,
    })
}

async fn session_stats_handler(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let m = state.engine.global_metrics();

    Json(serde_json::json!({
        "total_torrents": m.total_torrents,
        "downloading_torrents": m.downloading_torrents,
        "seeding_torrents": m.seeding_torrents,
        "paused_torrents": m.paused_torrents,
        "queued_torrents": m.queued_torrents,
        "downloaded_bytes": m.downloaded_bytes,
        "uploaded_bytes": m.uploaded_bytes,
        "download_rate": m.download_rate,
        "upload_rate": m.upload_rate,
        "peers_connected": m.peers_connected,
        "active_actors": m.active_actors,
        "free_disk_space_bytes": state.engine.free_disk_space_bytes(),
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn list_torrents_handler(
    State(state): State<ApiState>,
    Query(query): Query<PaginationQuery>,
) -> Json<serde_json::Value> {
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).max(1);
    let offset = (page - 1) * limit;

    let filter = query.state.as_deref().and_then(|s| match s.to_lowercase().as_str() {
        "downloading" => Some(synapse_engine::SwarmStateFilter::Downloading),
        "seeding" => Some(synapse_engine::SwarmStateFilter::Seeding),
        "paused" | "stopped" => Some(synapse_engine::SwarmStateFilter::Paused),
        "queued" => Some(synapse_engine::SwarmStateFilter::Queued),
        "checking" => Some(synapse_engine::SwarmStateFilter::Checking),
        "error" => Some(synapse_engine::SwarmStateFilter::Error),
        _ => None,
    });

    let (paged_swarms, total) = state.engine.list_torrents_paged(offset, limit, filter);

    let list: Vec<serde_json::Value> = paged_swarms
        .into_iter()
        .map(|s| {
            serde_json::json!({
                "info_hash": hex::encode(s.info_hash),
                "name": s.name,
                "total_bytes": s.total_size,
                "progress": s.progress,
                "download_rate": s.download_rate,
                "upload_rate": s.upload_rate,
                "downloaded_bytes": s.downloaded_bytes,
                "uploaded_bytes": s.uploaded_bytes,
                "peers_connected": s.peers_connected,
                "peers_sending": s.peers_sending,
                "eta_seconds": s.eta_seconds,
                "ratio": s.ratio,
                "download_dir": s.download_dir,
                "state": format!("{:?}", s.state),
                "tier": format!("{:?}", s.tier),
            })
        })
        .collect();

    Json(serde_json::json!({
        "torrents": list,
        "total": total,
        "page": page,
        "limit": limit
    }))
}

async fn add_torrent_handler(
    State(state): State<ApiState>,
    Json(payload): Json<AddTorrentRequest>,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ActionResponse>)> {
    let dir = payload
        .download_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let info = if let Some(ref url) = payload.url {
        match crate::url_fetcher::fetch_or_parse_torrent(url).await {
            Ok(info) => info,
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ActionResponse {
                        success: false,
                        message: format!("Failed to fetch or parse torrent from URL: {e}"),
                    }),
                ));
            }
        }
    } else if let Some(ref magnet) = payload.magnet {
        match synapse_meta::Info::from_magnet(magnet) {
            Ok(info) => info,
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ActionResponse {
                        success: false,
                        message: format!("Invalid magnet link: {e}"),
                    }),
                ));
            }
        }
    } else if let Some(ref b64) = payload.torrent_base64 {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64.trim()).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ActionResponse {
                    success: false,
                    message: format!("Invalid base64 payload: {e}"),
                }),
            )
        })?;
        let bencode = synapse_bencode::decode_buf(&bytes).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ActionResponse {
                    success: false,
                    message: format!("Invalid bencode: {e}"),
                }),
            )
        })?;
        synapse_meta::Info::from_bencode(bencode).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ActionResponse {
                    success: false,
                    message: format!("Invalid .torrent metadata: {e}"),
                }),
            )
        })?
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ActionResponse {
                success: false,
                message: "Missing 'url', 'magnet', or 'torrent_base64' in request body".to_string(),
            }),
        ));
    };

    let handle = state.engine.add_torrent(std::sync::Arc::new(info), dir, None);
    let hash = handle.stats.read().info_hash;
    if payload.paused.unwrap_or(false) {
        state.engine.transition_to_cold(&hash);
    }

    Ok(Json(ActionResponse {
        success: true,
        message: format!("Torrent added successfully with info_hash={}", hex::encode(hash)),
    }))
}

async fn get_torrent_handler(
    State(state): State<ApiState>,
    Path(info_hash_str): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let hash_bytes = hex::decode(&info_hash_str).map_err(|_| StatusCode::BAD_REQUEST)?;
    if hash_bytes.len() != 20 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&hash_bytes);

    if let Some(handle) = state.engine.get_torrent(&hash) {
        let stats = handle.stats.read().clone();
        Ok(Json(serde_json::json!({
            "info_hash": hex::encode(stats.info_hash),
            "name": stats.name,
            "total_bytes": stats.total_size,
            "progress": stats.progress,
            "download_rate": stats.download_rate,
            "upload_rate": stats.upload_rate,
            "peers_connected": stats.peers_connected,
            "state": format!("{:?}", stats.state),
            "tier": format!("{:?}", stats.tier),
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn delete_torrent_handler(
    State(state): State<ApiState>,
    Path(info_hash_str): Path<String>,
    Query(query): Query<DeleteTorrentQuery>,
) -> Result<Json<ActionResponse>, StatusCode> {
    let hash_bytes = hex::decode(&info_hash_str).map_err(|_| StatusCode::BAD_REQUEST)?;
    if hash_bytes.len() != 20 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&hash_bytes);

    let target_path = if let Some(handle) = state.engine.get_torrent(&hash) {
        let stats = handle.stats.read();
        Some(std::path::PathBuf::from(&stats.download_dir).join(&stats.name))
    } else {
        None
    };

    if state.engine.remove_torrent(&hash) {
        if query.delete_data.unwrap_or(false) {
            if let Some(path) = target_path {
                if path.is_dir() {
                    let _ = std::fs::remove_dir_all(&path);
                } else if path.is_file() {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        Ok(Json(ActionResponse {
            success: true,
            message: "Torrent removed successfully".to_string(),
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn get_torrent_detail_handler(
    State(state): State<ApiState>,
    Path(info_hash_str): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let hash_bytes = hex::decode(&info_hash_str).map_err(|_| StatusCode::BAD_REQUEST)?;
    if hash_bytes.len() != 20 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&hash_bytes);

    let Some(handle) = state.engine.get_torrent(&hash) else {
        return Err(StatusCode::NOT_FOUND);
    };

    let stats = handle.stats.read().clone();
    let piece_count = handle.info.pieces();
    let piece_size = handle.info.piece_len;
    let total_pieces = piece_count as usize;
    let is_seeding = stats.state == synapse_engine::SwarmState::Seeding;

    let bf_guard = handle.compressed_bitfield.read();
    let uncompressed_bf = bf_guard.as_ref().map(|b| b.to_bitfield());
    let piece_bitfield_bytes = if let Some(ref bf) = uncompressed_bf {
        bf.as_bytes().to_vec()
    } else if is_seeding {
        let mut full_bf = synapse_picker::Bitfield::new(total_pieces);
        for i in 0..total_pieces {
            full_bf.set(i);
        }
        full_bf.as_bytes().to_vec()
    } else {
        let empty_bf = synapse_picker::Bitfield::new(total_pieces);
        empty_bf.as_bytes().to_vec()
    };
    let piece_bitfield_hex = hex::encode(&piece_bitfield_bytes);

    let mut files_json = Vec::new();
    for (idx, f) in handle.info.files.iter().enumerate() {
        let (bytes_completed, progress) = if is_seeding {
            (f.length, 1.0)
        } else if f.length == 0 {
            (0, 1.0)
        } else if let Some(ref bf) = uncompressed_bf {
            let f_start = handle.info.file_offsets.get(idx).copied().unwrap_or(0);
            let f_end = f_start + f.length;
            let piece_len = handle.info.piece_len as u64;
            let first_piece = (f_start / piece_len) as usize;
            let last_piece = ((f_end.saturating_sub(1)) / piece_len) as usize;
            let mut done = 0u64;
            for p in first_piece..=last_piece.min(total_pieces.saturating_sub(1)) {
                if bf.has(p) {
                    let p_start = p as u64 * piece_len;
                    let p_end = (p_start + piece_len).min(handle.info.total_len);
                    let overlap_start = f_start.max(p_start);
                    let overlap_end = f_end.min(p_end);
                    if overlap_end > overlap_start {
                        done += overlap_end - overlap_start;
                    }
                }
            }
            let prog = if f.length > 0 { (done as f64 / f.length as f64) as f32 } else { 1.0 };
            (done, prog.min(1.0))
        } else {
            (0, 0.0)
        };

        files_json.push(serde_json::json!({
            "index": idx,
            "path": f.path.to_string_lossy(),
            "size_bytes": f.length,
            "bytes_completed": bytes_completed,
            "progress": progress,
            "priority": 4,
        }));
    }

    let mut trackers_json = Vec::new();
    let reports = state.engine.get_tracker_reports(&hash);
    for rep in reports {
        trackers_json.push(serde_json::json!({
            "url": rep.url,
            "status": rep.status,
            "seeders": rep.seeders,
            "leechers": rep.leechers,
            "next_announce_in": rep.next_announce_in,
            "failure_reason": rep.failure_reason,
        }));
    }

    let mut peers_json = Vec::new();
    let live_peers_snapshot = handle.live_peers.read().clone();
    for p in live_peers_snapshot {
        peers_json.push(serde_json::json!({
            "address": p.addr.to_string(),
            "client_name": p.client_name,
            "flags": p.flags,
            "rate_to_client": p.rate_to_client,
            "rate_to_peer": p.rate_to_peer,
            "progress": p.progress,
            "is_encrypted": p.is_encrypted,
            "is_utp": p.is_utp,
        }));
    }

    Ok(Json(serde_json::json!({
        "info_hash": hex::encode(stats.info_hash),
        "name": stats.name,
        "download_dir": stats.download_dir,
        "total_bytes": stats.total_size,
        "progress": stats.progress,
        "download_rate": stats.download_rate,
        "upload_rate": stats.upload_rate,
        "downloaded_bytes": stats.downloaded_bytes,
        "uploaded_bytes": stats.uploaded_bytes,
        "ratio": stats.ratio,
        "eta_seconds": stats.eta_seconds,
        "peers_connected": stats.peers_connected,
        "peers_sending": stats.peers_sending,
        "state": format!("{:?}", stats.state),
        "tier": format!("{:?}", stats.tier),
        "piece_count": piece_count,
        "piece_size": piece_size,
        "piece_bitfield": piece_bitfield_hex,
        "files": files_json,
        "trackers": trackers_json,
        "active_peers": peers_json,
    })))
}

async fn upload_torrent_handler(
    State(state): State<ApiState>,
    Query(query): Query<UploadTorrentQuery>,
    bytes: axum::body::Bytes,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ActionResponse>)> {
    if bytes.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ActionResponse {
                success: false,
                message: "Empty torrent payload".to_string(),
            }),
        ));
    }

    let bencode = synapse_bencode::decode_buf(&bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ActionResponse {
                success: false,
                message: format!("Invalid bencode: {e}"),
            }),
        )
    })?;

    let info = synapse_meta::Info::from_bencode(bencode).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ActionResponse {
                success: false,
                message: format!("Invalid .torrent metadata: {e}"),
            }),
        )
    })?;

    let dir = query
        .download_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let handle = state.engine.add_torrent(std::sync::Arc::new(info), dir, None);
    let hash = handle.stats.read().info_hash;
    if query.paused.unwrap_or(false) {
        state.engine.transition_to_cold(&hash);
    }

    Ok(Json(ActionResponse {
        success: true,
        message: format!("Torrent added successfully with info_hash={}", hex::encode(hash)),
    }))
}

async fn recheck_torrent_handler(
    State(state): State<ApiState>,
    Path(info_hash_str): Path<String>,
) -> Result<Json<ActionResponse>, StatusCode> {
    let hash_bytes = hex::decode(&info_hash_str).map_err(|_| StatusCode::BAD_REQUEST)?;
    if hash_bytes.len() != 20 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&hash_bytes);

    if state.engine.recheck_torrent(&hash) {
        Ok(Json(ActionResponse {
            success: true,
            message: "Recheck dispatched".to_string(),
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn set_location_handler(
    State(state): State<ApiState>,
    Path(info_hash_str): Path<String>,
    Json(payload): Json<SetLocationRequest>,
) -> Result<Json<ActionResponse>, StatusCode> {
    let hash_bytes = hex::decode(&info_hash_str).map_err(|_| StatusCode::BAD_REQUEST)?;
    if hash_bytes.len() != 20 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&hash_bytes);

    if state.engine.set_location(&hash, &payload.new_download_dir) {
        Ok(Json(ActionResponse {
            success: true,
            message: "Location updated".to_string(),
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn pause_torrent_handler(
    State(state): State<ApiState>,
    Path(info_hash_str): Path<String>,
) -> Result<Json<ActionResponse>, StatusCode> {
    let hash_bytes = hex::decode(&info_hash_str).map_err(|_| StatusCode::BAD_REQUEST)?;
    if hash_bytes.len() != 20 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&hash_bytes);

    if state.engine.transition_to_cold(&hash) {
        Ok(Json(ActionResponse {
            success: true,
            message: "Torrent paused".to_string(),
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn resume_torrent_handler(
    State(state): State<ApiState>,
    Path(info_hash_str): Path<String>,
) -> Result<Json<ActionResponse>, StatusCode> {
    let hash_bytes = hex::decode(&info_hash_str).map_err(|_| StatusCode::BAD_REQUEST)?;
    if hash_bytes.len() != 20 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&hash_bytes);

    if state.engine.transition_to_hot(&hash) {
        Ok(Json(ActionResponse {
            success: true,
            message: "Torrent resumed".to_string(),
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn openapi_json_handler() -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        OPENAPI_JSON,
    )
        .into_response()
}

async fn swagger_ui_handler() -> Html<String> {
    Html(get_swagger_ui_html())
}

async fn metrics_handler(State(state): State<ApiState>) -> Response {
    let m = state.engine.global_metrics();

    let snapshot = PrometheusSnapshot {
        total_torrents: m.total_torrents,
        downloading_torrents: m.downloading_torrents,
        seeding_torrents: m.seeding_torrents,
        paused_torrents: m.paused_torrents,
        bytes_downloaded: m.downloaded_bytes,
        bytes_uploaded: m.uploaded_bytes,
        download_rate: m.download_rate,
        upload_rate: m.upload_rate,
        connected_peers: m.peers_connected,
        circuit_breakers_tripped: state.engine.circuit_breaker().tripped_count()
            + state.engine.tracker_circuit_breaker().tripped_count(),
        dht_nodes: 0,
    };

    let text = render_prometheus_metrics(&snapshot);
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        text,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_rest_health_and_swagger_endpoints() {
        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
        let app = create_http_router(engine);

        // Test /api/v1/health
        let req = Request::builder()
            .uri("/api/v1/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Test /swagger-ui
        let req2 = Request::builder()
            .uri("/swagger-ui")
            .body(Body::empty())
            .unwrap();
        let resp2 = app.clone().oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);

        // Test /metrics
        let req3 = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp3 = app.clone().oneshot(req3).await.unwrap();
        assert_eq!(resp3.status(), StatusCode::OK);

        // Test GET /api/v1/session
        let req4 = Request::builder()
            .uri("/api/v1/session")
            .body(Body::empty())
            .unwrap();
        let resp4 = app.clone().oneshot(req4).await.unwrap();
        assert_eq!(resp4.status(), StatusCode::OK);

        // Test PATCH /api/v1/session
        let patch_body = serde_json::json!({
            "alt_speed_enabled": true,
            "alt_speed_down_bytes": 150000,
            "peer_port": 54345
        });
        let req5 = Request::builder()
            .method("PATCH")
            .uri("/api/v1/session")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&patch_body).unwrap()))
            .unwrap();
        let resp5 = app.clone().oneshot(req5).await.unwrap();
        assert_eq!(resp5.status(), StatusCode::OK);

        // Test PATCH /api/v1/session with pretty bitrates
        let patch_pretty = serde_json::json!({
            "download_limit": "50m",
            "upload_limit": "1g",
            "alt_speed_down": "1000m"
        });
        let req6 = Request::builder()
            .method("PATCH")
            .uri("/api/v1/session")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&patch_pretty).unwrap()))
            .unwrap();
        let resp6 = app.clone().oneshot(req6).await.unwrap();
        assert_eq!(resp6.status(), StatusCode::OK);

        // Test GET /api/v1/session returns pretty bitrates
        let req7 = Request::builder()
            .uri("/api/v1/session")
            .body(Body::empty())
            .unwrap();
        let resp7 = app.oneshot(req7).await.unwrap();
        assert_eq!(resp7.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp7.into_body(), 1024 * 1024).await.unwrap();
        let session_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(session_json["download_limit_bytes"], 6_250_000);
        assert_eq!(session_json["download_limit_pretty"], "50 Mbps");
        assert_eq!(session_json["upload_limit_bytes"], 125_000_000);
        assert_eq!(session_json["upload_limit_pretty"], "1 Gbps");
        assert_eq!(session_json["alt_speed_down_bytes"], 125_000_000);
        assert_eq!(session_json["alt_speed_down_pretty"], "1 Gbps");
    }
}
