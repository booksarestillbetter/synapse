//! Alternative REST API, OpenAPI Schema, Swagger UI and Prometheus Metrics Service.
//!
//! Provides a full-featured HTTP control plane for web browsers, scripting, and monitoring.

use crate::metrics::{render_prometheus_metrics, PrometheusSnapshot};
use crate::swagger::{get_swagger_ui_html, OPENAPI_JSON};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use synapse_engine::SwarmEngine;

#[derive(Clone)]
pub struct AuthRateLimiter {
    inner: Arc<parking_lot::Mutex<HashMap<String, (u32, Instant)>>>,
    max_failures: u32,
    total_failures: Arc<AtomicU64>,
}

impl Default for AuthRateLimiter {
    fn default() -> Self {
        Self::with_max_failures(Self::MAX_FAILURES)
    }
}

impl AuthRateLimiter {
    const WINDOW: Duration = Duration::from_secs(60);
    const MAX_FAILURES: u32 = 15;
    const MAX_KEYS: usize = 4096;

    pub fn with_max_failures(max_failures: u32) -> Self {
        Self {
            inner: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            max_failures,
            total_failures: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn total_failures(&self) -> u64 {
        self.total_failures.load(Ordering::Relaxed)
    }

    pub fn is_blocked(&self, key: &str) -> bool {
        let mut guard = self.inner.lock();
        let now = Instant::now();
        if let Some((count, start)) = guard.get(key) {
            if now.duration_since(*start) < Self::WINDOW {
                return *count >= self.max_failures;
            }
            guard.remove(key);
        }
        false
    }

    pub fn record_failure(&self, key: &str) {
        self.total_failures.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.inner.lock();
        let now = Instant::now();
        if guard.len() >= Self::MAX_KEYS {
            guard.retain(|_, (_, start)| now.duration_since(*start) < Self::WINDOW);
            if guard.len() >= Self::MAX_KEYS {
                if let Some(oldest) = guard
                    .iter()
                    .min_by_key(|(_, (_, s))| *s)
                    .map(|(k, _)| k.clone())
                {
                    guard.remove(&oldest);
                }
            }
        }
        let entry = guard.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) >= Self::WINDOW {
            *entry = (1, now);
        } else {
            entry.0 = entry.0.saturating_add(1);
        }
    }
}

#[derive(Clone)]
pub struct ApiState {
    pub engine: Arc<SwarmEngine>,
    pub auth_token: Option<String>,
    pub web_config: synapse_config::WebConfig,
    pub base_download_dir: std::path::PathBuf,
    pub rate_limiter: AuthRateLimiter,
    pub allowed_hosts: Vec<String>,
    pub trusted_proxies: Vec<std::net::IpAddr>,
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
    #[serde(default)]
    pub move_existing_files: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetFilePriorityRequest {
    pub priority: u8,
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
    pub features: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LivenessResponse {
    pub status: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadinessChecks {
    pub download_dir: bool,
    pub session_db: bool,
    pub listener: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadinessResponse {
    pub status: String,
    pub version: String,
    pub checks: ReadinessChecks,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CircuitBreakerStatusApi {
    pub host: String,
    pub state: String,
    pub consecutive_successes: u32,
    pub consecutive_failures: u32,
    pub backoff_remaining_ms: u64,
    pub recovery_progress_pct: Option<f32>,
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
    pub dht_read_only: bool,
    pub pex_enabled: bool,
    pub lsd_enabled: bool,
    pub zeroconf_enabled: bool,
    pub announce_ip: Option<String>,
    pub enable_utp: bool,
    pub encryption: String,

    pub download_dir: String,
    pub incomplete_dir: Option<String>,
    pub incomplete_dir_enabled: bool,
    pub start_added_torrents: bool,
    pub trash_original_torrent_files: bool,

    pub unchoke_slots_global: usize,
    pub seed_choking_algorithm: String,
    pub unchoke_slot_bandwidth: u64,
    pub limit_lan_peers: bool,
    pub rate_limit_ip_overhead: bool,
    pub max_concurrent_tracker_announces: usize,
    pub max_concurrent_dht_announces: usize,
    pub max_concurrent_lsd_announces: usize,
}

#[derive(Debug, Deserialize)]
pub struct BatchHashesRequest {
    pub hashes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct BatchRemoveRequest {
    pub hashes: Vec<String>,
    #[serde(default)]
    pub delete_data: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchActionResponse {
    pub success: bool,
    pub succeeded: usize,
    pub failed_hashes: Vec<String>,
    pub message: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct TorrentStreamQuery {
    pub page: Option<usize>,
    pub limit: Option<usize>,
    pub state: Option<String>,
    pub interval_ms: Option<u64>,
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
pub fn create_http_router_with_auth(
    engine: Arc<SwarmEngine>,
    auth_token: Option<String>,
) -> Router {
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
        Vec::new(),
    )
}

pub fn create_http_router_all(
    engine: Arc<SwarmEngine>,
    auth_token: Option<String>,
    metrics_enabled: bool,
    web_config: synapse_config::WebConfig,
    allowed_hosts: Vec<String>,
) -> Router {
    create_http_router_with_options(
        engine,
        auth_token,
        metrics_enabled,
        web_config,
        allowed_hosts,
        Vec::new(),
        AuthRateLimiter::default(),
    )
}

const DEFAULT_API_BODY_LIMIT: usize = 64 * 1024;
const BATCH_API_BODY_LIMIT: usize = 1024 * 1024;
const UPLOAD_TORRENT_BODY_LIMIT: usize = 11 * 1024 * 1024;
const ADD_TORRENT_JSON_BODY_LIMIT: usize = 14 * 1024 * 1024;

pub fn create_http_router_with_options(
    engine: Arc<SwarmEngine>,
    auth_token: Option<String>,
    metrics_enabled: bool,
    web_config: synapse_config::WebConfig,
    allowed_hosts: Vec<String>,
    trusted_proxies: Vec<std::net::IpAddr>,
    rate_limiter: AuthRateLimiter,
) -> Router {
    let base_download_dir = engine.settings().read().download_dir.clone();
    let auth_token = auth_token.filter(|t| !t.trim().is_empty());
    let state = ApiState {
        engine,
        auth_token,
        web_config: web_config.clone(),
        base_download_dir,
        rate_limiter,
        allowed_hosts,
        trusted_proxies,
    };

    let standard_routes = Router::new()
        .route(
            "/api/v1/session",
            get(get_session_settings_handler).patch(update_session_settings_handler),
        )
        .route("/api/v1/session/stats", get(session_stats_handler))
        .route(
            "/api/v1/torrents/:info_hash",
            get(get_torrent_handler).delete(delete_torrent_handler),
        )
        .route(
            "/api/v1/torrents/:info_hash/detail",
            get(get_torrent_detail_handler),
        )
        .route(
            "/api/v1/torrents/:info_hash/pause",
            post(pause_torrent_handler),
        )
        .route(
            "/api/v1/torrents/:info_hash/resume",
            post(resume_torrent_handler),
        )
        .route(
            "/api/v1/torrents/:info_hash/recheck",
            post(recheck_torrent_handler),
        )
        .route(
            "/api/v1/torrents/:info_hash/location",
            post(set_location_handler),
        )
        .route(
            "/api/v1/torrents/:info_hash/files/:index/priority",
            post(set_file_priority_handler),
        )
        .route(
            "/api/v1/torrents/:info_hash/queue-move",
            post(queue_move_handler),
        )
        .route(
            "/api/v1/torrents/:info_hash/sequential",
            post(set_sequential_handler),
        )
        .route(
            "/api/v1/torrents/:info_hash/super-seed",
            post(set_super_seed_handler),
        )
        .route(
            "/api/v1/torrents/:info_hash/first-last-priority",
            post(set_first_last_priority_handler),
        )
        .route(
            "/api/v1/torrents/:info_hash/reannounce",
            post(reannounce_torrent_handler),
        )
        .route(
            "/api/v1/torrents/:info_hash/trackers",
            post(replace_trackers_handler),
        )
        .route(
            "/api/v1/torrents/:info_hash/metadata",
            axum::routing::patch(update_metadata_handler),
        )
        .route(
            "/api/v1/torrents/:info_hash/export",
            get(export_torrent_handler),
        )
        .route("/api/v1/ip-filter/reload", post(reload_ip_filter_handler))
        .route("/api/v1/alerts", get(alerts_stream_handler))
        .route("/api/v1/search", get(search_torrents_handler))
        .route("/api/v1/torrents/create", post(create_torrent_handler))
        .route("/api/v1/updates", get(list_updates_handler))
        .route("/api/v1/updates/check", post(check_updates_handler))
        .route(
            "/api/v1/updates/:info_hash/apply",
            post(apply_update_handler),
        )
        .route(
            "/api/v1/search/engines",
            get(list_search_engines_handler).post(add_search_engine_handler),
        )
        .route(
            "/api/v1/search/engines/:name",
            axum::routing::delete(remove_search_engine_handler),
        )
        .route(
            "/api/v1/torrents/:info_hash/signatures",
            get(torrent_signatures_handler),
        )
        .route(
            "/api/v1/circuit-breakers",
            get(list_circuit_breakers_handler),
        )
        .route(
            "/api/v1/circuit-breakers/:host/trip",
            post(trip_circuit_breaker_handler),
        )
        .route(
            "/api/v1/circuit-breakers/:host/reset",
            post(reset_circuit_breaker_handler),
        )
        .route(
            "/api/v1/rss/feeds",
            get(list_rss_feeds_handler)
                .post(add_rss_feed_handler)
                .delete(remove_rss_feed_handler),
        )
        .route("/api/v1/rss/poll", post(poll_rss_feeds_handler))
        .route("/api/v1/torrents/stream", get(torrents_stream_handler))
        .layer(DefaultBodyLimit::max(DEFAULT_API_BODY_LIMIT));

    let batch_routes = Router::new()
        .route(
            "/api/v1/torrents/batch/pause",
            post(batch_pause_torrents_handler),
        )
        .route(
            "/api/v1/torrents/batch/resume",
            post(batch_resume_torrents_handler),
        )
        .route(
            "/api/v1/torrents/batch/remove",
            post(batch_remove_torrents_handler),
        )
        .route(
            "/api/v1/torrents/batch/recheck",
            post(batch_recheck_torrents_handler),
        )
        .layer(DefaultBodyLimit::max(BATCH_API_BODY_LIMIT));

    let add_route = Router::new()
        .route(
            "/api/v1/torrents",
            get(list_torrents_handler).post(add_torrent_handler),
        )
        .layer(DefaultBodyLimit::max(ADD_TORRENT_JSON_BODY_LIMIT));

    let upload_route = Router::new()
        .route("/api/v1/torrents/upload", post(upload_torrent_handler))
        .layer(DefaultBodyLimit::max(UPLOAD_TORRENT_BODY_LIMIT));

    let protected = standard_routes
        .merge(batch_routes)
        .merge(add_route)
        .merge(upload_route)
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let mut public = Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/readyz", get(readyz_handler))
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

    let public = public.layer(DefaultBodyLimit::max(DEFAULT_API_BODY_LIMIT));

    protected.merge(public).with_state(state)
}

#[derive(Deserialize)]
struct AlertsQuery {
    /// Only alerts for this torrent (40 hex characters).
    info_hash: Option<String>,
}

/// JSON form of an alert: `{"type": ..., "info_hash": "<hex>", "data": {...}}`, with the info
/// hash rendered as hex rather than a byte array.
pub(crate) fn alert_to_json(alert: &synapse_engine::Alert) -> serde_json::Value {
    let mut v = serde_json::to_value(alert).unwrap_or_default();
    if let Some(data) = v.get_mut("data").and_then(|d| d.as_object_mut()) {
        data.remove("info_hash");
    }
    v["info_hash"] = serde_json::Value::String(alert.info_hash_hex());
    v
}

/// `GET /api/v1/alerts`: a live Server-Sent Events stream of engine alerts (torrent added,
/// finished, error, piece finished, hash failure, peer connected/disconnected/banned, state
/// change, tracker announce). Optional `?info_hash=` restricts it to one torrent. A client that
/// falls too far behind receives a `lagged` event with the number of alerts it missed rather
/// than the connection being dropped.
async fn alerts_stream_handler(
    State(state): State<ApiState>,
    Query(query): Query<AlertsQuery>,
) -> Result<
    axum::response::sse::Sse<
        impl futures::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
    >,
    (StatusCode, Json<ActionResponse>),
> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use tokio_stream::wrappers::{errors::BroadcastStreamRecvError, BroadcastStream};
    use tokio_stream::StreamExt;

    let filter = match query.info_hash {
        Some(ref h) => Some(parse_info_hash_hex(h).ok_or((
            StatusCode::BAD_REQUEST,
            Json(ActionResponse {
                success: false,
                message: "info_hash must be 40 hexadecimal characters".to_string(),
            }),
        ))?),
        None => None,
    };
    let lag_engine = state.engine.clone();
    let stream =
        BroadcastStream::new(state.engine.subscribe_alerts()).filter_map(move |item| match item {
            Ok(alert) => {
                if filter.is_some_and(|f| f != alert.info_hash()) {
                    return None;
                }
                let json = alert_to_json(&alert);
                let name = json["type"].as_str().unwrap_or("alert").to_string();
                Some(Ok(Event::default().event(name).data(json.to_string())))
            }
            Err(BroadcastStreamRecvError::Lagged(skipped)) => {
                lag_engine.record_event_bus_lag(skipped);
                Some(Ok(Event::default()
                    .event("lagged")
                    .data(serde_json::json!({ "skipped": skipped }).to_string())))
            }
        });
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// Parses a 40-character hex info hash.
fn parse_info_hash_hex(s: &str) -> Option<[u8; 20]> {
    hex::decode(s).ok()?.try_into().ok()
}

/// Constant-time comparison over SHA-256 digests so neither byte content nor secret
/// length leaks through comparison timing, rejecting empty secrets/tokens.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    if a.is_empty() || b.is_empty() {
        return false;
    }
    let da = Sha256::digest(a);
    let db = Sha256::digest(b);
    da.ct_eq(&db).into()
}

fn canonicalize_with_nonexistent_tail(
    path: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("failed to determine current directory: {e}"))?
            .join(path)
    };

    let mut existing = abs.as_path();
    let mut tail_components = Vec::new();
    while !existing.exists() {
        if let Some(name) = existing.file_name() {
            tail_components.push(name.to_os_string());
        } else {
            break;
        }
        if let Some(parent) = existing.parent() {
            existing = parent;
        } else {
            break;
        }
    }

    let mut canonical = if existing.exists() {
        std::fs::canonicalize(existing)
            .map_err(|e| format!("failed to canonicalize path '{}': {e}", existing.display()))?
    } else {
        abs
    };

    for comp in tail_components.into_iter().rev() {
        canonical.push(comp);
    }
    Ok(canonical)
}

/// Validates that `candidate` resolves strictly within `base` (no `..` traversal, no NUL bytes,
/// and no symlinks escaping `base`).
pub fn validate_path_under_base(
    base: &std::path::Path,
    candidate: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    let raw = candidate.as_os_str().to_string_lossy();
    if raw.trim().is_empty() {
        return Err("path must not be empty".to_string());
    }
    if raw.contains('\0') {
        return Err("path must not contain NUL bytes".to_string());
    }
    for comp in candidate.components() {
        if matches!(comp, std::path::Component::ParentDir) {
            return Err(
                "path must not contain '..' parent directory traversal components".to_string(),
            );
        }
    }

    let canonical_base = canonicalize_with_nonexistent_tail(base)?;
    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        canonical_base.join(candidate)
    };

    // Walk components of `joined` to detect any symlink along the path (including a dangling leaf
    // symlink) that points outside `canonical_base`.
    let mut cur = std::path::PathBuf::new();
    for comp in joined.components() {
        cur.push(comp.as_os_str());
        if let Ok(meta) = std::fs::symlink_metadata(&cur) {
            if meta.file_type().is_symlink() {
                let target = std::fs::canonicalize(&cur).map_err(|_| {
                    "symlink target inside download directory cannot be resolved".to_string()
                })?;
                if cur.starts_with(&canonical_base) && !target.starts_with(&canonical_base) {
                    return Err("symlink escapes the configured download directory".to_string());
                }
            }
        }
    }

    let resolved = canonicalize_with_nonexistent_tail(&joined)?;
    if !resolved.starts_with(&canonical_base) {
        return Err("the path must be inside the download directory".to_string());
    }
    Ok(resolved)
}

pub fn is_safe_single_component_name(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return false;
    }
    let mut comps = std::path::Path::new(name).components();
    matches!(comps.next(), Some(std::path::Component::Normal(_))) && comps.next().is_none()
}

fn parse_host_and_port(host_hdr: &str) -> (&str, Option<u16>) {
    let trimmed = host_hdr.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &trimmed[..=end + 1];
            let after = &rest[end + 1..];
            let port = after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return (host, port);
        }
    }
    if let Some((h, p)) = trimmed.rsplit_once(':') {
        if !h.contains(':') {
            if let Ok(port) = p.parse::<u16>() {
                return (h, Some(port));
            }
        }
    }
    (trimmed, None)
}

fn is_loopback_host(host: &str) -> bool {
    matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "[::1]" | "::1"
    )
}

/// A `Host`/`Origin` host is acceptable for DNS-rebinding purposes when it's loopback, or when
/// it's explicitly listed in `http_api.allowed_hosts` (e.g. the hostname of a reverse proxy
/// fronting this daemon).
fn is_allowed_host(host: &str, allowed_hosts: &[String]) -> bool {
    is_loopback_host(host) || allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(host))
}

pub(crate) fn canonical_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

fn is_internal_proxy_hop(ip: std::net::IpAddr) -> bool {
    match canonical_ip(ip) {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
        }
    }
}

fn is_trusted_proxy(ip: std::net::IpAddr, trusted_proxies: &[std::net::IpAddr]) -> bool {
    let canonical = canonical_ip(ip);
    trusted_proxies
        .iter()
        .any(|&p| canonical_ip(p) == canonical)
}

/// Identifies the real caller for rate-limiting. `X-Forwarded-For` is ONLY honored when the
/// direct peer is explicitly listed in `trusted_proxies` (canonicalizing IPv4-mapped IPv6
/// addresses); walking right-to-left skips configured/internal proxy hops to find the real
/// client address.
fn extract_client_ip(req: &Request, trusted_proxies: &[std::net::IpAddr]) -> String {
    let peer_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| canonical_ip(ci.0.ip()));

    if let Some(ip) = peer_ip {
        if is_trusted_proxy(ip, trusted_proxies) {
            if let Some(xff) = req
                .headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
            {
                for candidate in xff.split(',').rev().map(str::trim) {
                    if let Ok(parsed) = candidate.parse::<std::net::IpAddr>() {
                        let parsed = canonical_ip(parsed);
                        if !is_trusted_proxy(parsed, trusted_proxies)
                            && !is_internal_proxy_hop(parsed)
                        {
                            return parsed.to_string();
                        }
                    }
                }
            }
        }
        return ip.to_string();
    }

    "unknown".to_string()
}

fn verify_same_origin_csrf(
    req: &Request,
    require_loopback_host: bool,
    allowed_hosts: &[String],
) -> Result<(), StatusCode> {
    use axum::http::Method;

    // Enforce Host DNS-rebinding check on ALL HTTP methods (including GET/HEAD/OPTIONS)
    // whenever the server is unauthenticated.
    if require_loopback_host {
        if let Some(host_hdr) = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
        {
            let (host_only, _) = parse_host_and_port(host_hdr);
            if !is_allowed_host(host_only, allowed_hosts) {
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }

    if !matches!(
        *req.method(),
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        return Ok(());
    }

    if let Some(sec_fetch) = req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
    {
        if sec_fetch.eq_ignore_ascii_case("cross-site") {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let origin_or_referer = req
        .headers()
        .get(header::ORIGIN)
        .or_else(|| req.headers().get(header::REFERER))
        .and_then(|v| v.to_str().ok());

    if let Some(raw_url) = origin_or_referer {
        let trimmed = raw_url.trim();
        if trimmed.eq_ignore_ascii_case("null") {
            return Err(StatusCode::FORBIDDEN);
        }
        let parsed = url::Url::parse(trimmed).map_err(|_| StatusCode::FORBIDDEN)?;
        let origin_host = parsed.host_str().ok_or(StatusCode::FORBIDDEN)?;
        let origin_port = parsed.port_or_known_default();

        if let Some(host_hdr) = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
        {
            let (host_only, host_port) = parse_host_and_port(host_hdr);
            if !origin_host.eq_ignore_ascii_case(host_only) {
                return Err(StatusCode::FORBIDDEN);
            }
            match host_port {
                Some(hp) => {
                    if origin_port != Some(hp) {
                        return Err(StatusCode::FORBIDDEN);
                    }
                }
                None => {
                    if parsed.port().is_some() && !matches!(origin_port, Some(80) | Some(443)) {
                        return Err(StatusCode::FORBIDDEN);
                    }
                }
            }
        } else if !is_allowed_host(origin_host, allowed_hosts) {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    Ok(())
}

async fn require_auth(
    State(state): State<ApiState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    verify_same_origin_csrf(&req, state.auth_token.is_none(), &state.allowed_hosts)?;

    let Some(ref expected) = state.auth_token else {
        return Ok(next.run(req).await);
    };
    let client_key = extract_client_ip(&req, &state.trusted_proxies);
    if state.rate_limiter.is_blocked(&client_key) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let expected_trimmed = expected.trim();
    if expected_trimmed.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let authorized = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            let provided = v.strip_prefix("Bearer ").unwrap_or(v).trim();
            constant_time_eq(provided.as_bytes(), expected_trimmed.as_bytes())
        })
        .unwrap_or(false);
    if !authorized {
        state.rate_limiter.record_failure(&client_key);
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(req).await)
}

async fn healthz_handler() -> (StatusCode, Json<LivenessResponse>) {
    (
        StatusCode::OK,
        Json(LivenessResponse {
            status: "ok".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),
    )
}

async fn readyz_handler(State(state): State<ApiState>) -> (StatusCode, Json<ReadinessResponse>) {
    let configured_dir = state.engine.settings().read().download_dir.clone();
    let download_dir_path = if configured_dir.as_os_str().is_empty() {
        state.base_download_dir.clone()
    } else {
        configured_dir
    };
    let download_dir = tokio::fs::metadata(&download_dir_path)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false);
    let session_db = state.engine.is_session_store_healthy().await;
    let listener = !state.engine.is_listener_required() || state.engine.listen_port() != 0;
    let ready = download_dir && session_db && listener;
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(ReadinessResponse {
            status: if ready {
                "ready".to_string()
            } else {
                "not_ready".to_string()
            },
            version: env!("CARGO_PKG_VERSION").to_string(),
            checks: ReadinessChecks {
                download_dir,
                session_db,
                listener,
            },
        }),
    )
}

async fn health_handler(State(state): State<ApiState>) -> (StatusCode, Json<HealthResponse>) {
    let dir_ok = tokio::fs::metadata(&state.base_download_dir)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false);
    let status_code = if dir_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status_code,
        Json(HealthResponse {
            status: if dir_ok {
                "ok".to_string()
            } else {
                "degraded".to_string()
            },
            version: env!("CARGO_PKG_VERSION").to_string(),
            features: vec!["tracker_circuit_breaker_v1".to_string()],
        }),
    )
}

fn circuit_state_label(state: synapse_tracker::CircuitState) -> &'static str {
    match state {
        synapse_tracker::CircuitState::Healthy => "healthy",
        synapse_tracker::CircuitState::Tripped => "tripped",
        synapse_tracker::CircuitState::HalfOpenCanary => "half_open_canary",
        synapse_tracker::CircuitState::Recovering => "recovering",
    }
}

async fn list_circuit_breakers_handler(
    State(state): State<ApiState>,
) -> Json<Vec<CircuitBreakerStatusApi>> {
    let breaker = state.engine.tracker_circuit_breaker();
    let breakers = breaker
        .all_hosts()
        .into_iter()
        .map(|(host, info)| CircuitBreakerStatusApi {
            host,
            state: circuit_state_label(info.state).to_string(),
            consecutive_successes: info.consecutive_successes,
            consecutive_failures: info.consecutive_failures,
            backoff_remaining_ms: breaker.backoff_remaining_ms(&info),
            recovery_progress_pct: breaker.recovery_progress_pct(&info),
        })
        .collect();
    Json(breakers)
}

async fn trip_circuit_breaker_handler(
    State(state): State<ApiState>,
    Path(host): Path<String>,
) -> Json<ActionResponse> {
    state.engine.tracker_circuit_breaker().force_trip(&host);
    Json(ActionResponse {
        success: true,
        message: format!("Circuit breaker for '{}' force-tripped", host),
    })
}

async fn reset_circuit_breaker_handler(
    State(state): State<ApiState>,
    Path(host): Path<String>,
) -> Json<ActionResponse> {
    state.engine.tracker_circuit_breaker().force_reset(&host);
    Json(ActionResponse {
        success: true,
        message: format!("Circuit breaker for '{}' force-reset", host),
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
        dht_read_only: s.dht_read_only,
        pex_enabled: s.pex_enabled,
        lsd_enabled: s.lsd_enabled,
        zeroconf_enabled: s.zeroconf_enabled,
        announce_ip: s.announce_ip.map(|ip| ip.to_string()),
        enable_utp: s.enable_utp,
        encryption: s.encryption,

        download_dir: s.download_dir.to_string_lossy().into_owned(),
        incomplete_dir: s.incomplete_dir.map(|p| p.to_string_lossy().into_owned()),
        incomplete_dir_enabled: s.incomplete_dir_enabled,
        start_added_torrents: s.start_added_torrents,
        trash_original_torrent_files: s.trash_original_torrent_files,

        unchoke_slots_global: s.unchoke_slots_global,
        seed_choking_algorithm: s.seed_choking_algorithm,
        unchoke_slot_bandwidth: s.unchoke_slot_bandwidth,
        limit_lan_peers: s.limit_lan_peers,
        rate_limit_ip_overhead: s.rate_limit_ip_overhead,
        max_concurrent_tracker_announces: s.max_concurrent_tracker_announces,
        max_concurrent_dht_announces: s.max_concurrent_dht_announces,
        max_concurrent_lsd_announces: s.max_concurrent_lsd_announces,
    })
}

async fn update_session_settings_handler(
    State(state): State<ApiState>,
    Json(mut payload): Json<synapse_engine::SessionSettingsUpdate>,
) -> Result<Json<UpdateSessionSettingsResponse>, (StatusCode, Json<UpdateSessionSettingsResponse>)>
{
    if let Some(ref dl_dir) = payload.download_dir {
        if !dl_dir.trim().is_empty() {
            match validate_path_under_base(
                &state.base_download_dir,
                std::path::Path::new(dl_dir.trim()),
            ) {
                Ok(canonical) => {
                    payload.download_dir = Some(canonical.to_string_lossy().into_owned());
                }
                Err(msg) => {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(UpdateSessionSettingsResponse {
                            success: false,
                            warnings: vec![format!("download_dir rejected: {msg}")],
                        }),
                    ));
                }
            }
        }
    }
    if let Some(ref inc_dir) = payload.incomplete_dir {
        if !inc_dir.trim().is_empty() {
            match validate_path_under_base(
                &state.base_download_dir,
                std::path::Path::new(inc_dir.trim()),
            ) {
                Ok(canonical) => {
                    payload.incomplete_dir = Some(canonical.to_string_lossy().into_owned());
                }
                Err(msg) => {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(UpdateSessionSettingsResponse {
                            success: false,
                            warnings: vec![format!("incomplete_dir rejected: {msg}")],
                        }),
                    ));
                }
            }
        }
    }
    let warnings = state.engine.update_session_settings(payload);
    Ok(Json(UpdateSessionSettingsResponse {
        success: true,
        warnings,
    }))
}

#[derive(Serialize)]
struct SessionStatsResponse {
    total_torrents: usize,
    downloading_torrents: usize,
    seeding_torrents: usize,
    paused_torrents: usize,
    queued_torrents: usize,
    downloaded_bytes: u64,
    uploaded_bytes: u64,
    download_rate: u64,
    upload_rate: u64,
    peers_connected: usize,
    active_actors: usize,
    free_disk_space_bytes: u64,
    dht_nodes: usize,
    dht_enabled: bool,
    pex_enabled: bool,
    lsd_enabled: bool,
    version: &'static str,
}

#[derive(Clone, Serialize)]
struct TorrentListItem {
    info_hash: String,
    name: String,
    total_bytes: u64,
    progress: f32,
    download_rate: u64,
    upload_rate: u64,
    downloaded_bytes: u64,
    uploaded_bytes: u64,
    peers_connected: usize,
    peers_sending: usize,
    eta_seconds: u64,
    ratio: f32,
    download_dir: String,
    state: String,
    tier: String,
    category: Option<String>,
    tags: Vec<String>,
    seed_ratio_limit: Option<f64>,
    seed_time_limit_secs: Option<u64>,
    sequential: bool,
    super_seeding: bool,
    first_last_piece_priority: bool,
}

#[derive(Serialize)]
struct TorrentListDelta {
    info_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    progress: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    download_rate: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upload_rate: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    downloaded_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uploaded_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peers_connected: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peers_sending: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eta_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ratio: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    download_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed_ratio_limit: Option<Option<f64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed_time_limit_secs: Option<Option<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sequential: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    super_seeding: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_last_piece_priority: Option<bool>,
}

fn compute_item_delta(prev: &TorrentListItem, curr: &TorrentListItem) -> Option<TorrentListDelta> {
    let mut changed = false;
    macro_rules! diff_field {
        ($field:ident, $cond:expr) => {
            if $cond {
                changed = true;
                Some(curr.$field.clone())
            } else {
                None
            }
        };
    }

    let delta = TorrentListDelta {
        info_hash: curr.info_hash.clone(),
        name: diff_field!(name, prev.name != curr.name),
        total_bytes: diff_field!(total_bytes, prev.total_bytes != curr.total_bytes),
        progress: diff_field!(progress, prev.progress.to_bits() != curr.progress.to_bits()),
        download_rate: diff_field!(download_rate, prev.download_rate != curr.download_rate),
        upload_rate: diff_field!(upload_rate, prev.upload_rate != curr.upload_rate),
        downloaded_bytes: diff_field!(
            downloaded_bytes,
            prev.downloaded_bytes != curr.downloaded_bytes
        ),
        uploaded_bytes: diff_field!(uploaded_bytes, prev.uploaded_bytes != curr.uploaded_bytes),
        peers_connected: diff_field!(
            peers_connected,
            prev.peers_connected != curr.peers_connected
        ),
        peers_sending: diff_field!(peers_sending, prev.peers_sending != curr.peers_sending),
        eta_seconds: diff_field!(eta_seconds, prev.eta_seconds != curr.eta_seconds),
        ratio: diff_field!(ratio, prev.ratio.to_bits() != curr.ratio.to_bits()),
        download_dir: diff_field!(download_dir, prev.download_dir != curr.download_dir),
        state: diff_field!(state, prev.state != curr.state),
        tier: diff_field!(tier, prev.tier != curr.tier),
        category: diff_field!(category, prev.category != curr.category),
        tags: diff_field!(tags, prev.tags != curr.tags),
        seed_ratio_limit: diff_field!(
            seed_ratio_limit,
            prev.seed_ratio_limit.map(f64::to_bits) != curr.seed_ratio_limit.map(f64::to_bits)
        ),
        seed_time_limit_secs: diff_field!(
            seed_time_limit_secs,
            prev.seed_time_limit_secs != curr.seed_time_limit_secs
        ),
        sequential: diff_field!(sequential, prev.sequential != curr.sequential),
        super_seeding: diff_field!(super_seeding, prev.super_seeding != curr.super_seeding),
        first_last_piece_priority: diff_field!(
            first_last_piece_priority,
            prev.first_last_piece_priority != curr.first_last_piece_priority
        ),
    };

    changed.then_some(delta)
}

#[derive(Serialize)]
struct TorrentListResponse {
    torrents: Vec<TorrentListItem>,
    total: usize,
    page: usize,
    limit: usize,
}

async fn build_session_stats_response(engine: &SwarmEngine) -> SessionStatsResponse {
    let m = engine.global_metrics();
    let dht_nodes = engine.dht_node_count_fast();
    let (dht_enabled, pex_enabled, lsd_enabled) = {
        let settings = engine.settings();
        let s = settings.read();
        (s.dht_enabled, s.pex_enabled, s.lsd_enabled)
    };

    SessionStatsResponse {
        total_torrents: m.total_torrents,
        downloading_torrents: m.downloading_torrents,
        seeding_torrents: m.seeding_torrents,
        paused_torrents: m.paused_torrents,
        queued_torrents: m.queued_torrents,
        downloaded_bytes: m.downloaded_bytes,
        uploaded_bytes: m.uploaded_bytes,
        download_rate: m.download_rate,
        upload_rate: m.upload_rate,
        peers_connected: m.peers_connected,
        active_actors: m.active_actors,
        free_disk_space_bytes: engine.free_disk_space_bytes_async().await,
        dht_nodes,
        dht_enabled,
        pex_enabled,
        lsd_enabled,
        version: env!("CARGO_PKG_VERSION"),
    }
}

fn parse_state_filter(state: Option<&str>) -> Option<synapse_engine::SwarmStateFilter> {
    state.and_then(|s| match s.to_lowercase().as_str() {
        "downloading" => Some(synapse_engine::SwarmStateFilter::Downloading),
        "seeding" => Some(synapse_engine::SwarmStateFilter::Seeding),
        "paused" | "stopped" => Some(synapse_engine::SwarmStateFilter::Paused),
        "queued" => Some(synapse_engine::SwarmStateFilter::Queued),
        "checking" => Some(synapse_engine::SwarmStateFilter::Checking),
        "error" => Some(synapse_engine::SwarmStateFilter::Error),
        _ => None,
    })
}

fn build_torrent_list_items(
    engine: &SwarmEngine,
    offset: usize,
    limit: usize,
    filter: Option<synapse_engine::SwarmStateFilter>,
) -> (Vec<TorrentListItem>, usize) {
    let (paged_swarms, total) = engine.list_torrents_paged(offset, limit, filter);

    let list = paged_swarms
        .into_iter()
        .map(|s| {
            let (meta, sequential, super_seeding, first_last) = engine
                .get_torrent(&s.info_hash)
                .map(|h| {
                    (
                        h.metadata.read().clone(),
                        h.sequential.load(std::sync::atomic::Ordering::Relaxed),
                        h.super_seeding.load(std::sync::atomic::Ordering::Relaxed),
                        h.first_last_piece_priority
                            .load(std::sync::atomic::Ordering::Relaxed),
                    )
                })
                .unwrap_or_default();
            TorrentListItem {
                info_hash: hex::encode(s.info_hash),
                name: s.name,
                total_bytes: s.total_size,
                progress: s.progress,
                download_rate: s.download_rate,
                upload_rate: s.upload_rate,
                downloaded_bytes: s.downloaded_bytes,
                uploaded_bytes: s.uploaded_bytes,
                peers_connected: s.peers_connected,
                peers_sending: s.peers_sending,
                eta_seconds: s.eta_seconds,
                ratio: s.ratio,
                download_dir: s.download_dir,
                state: format!("{:?}", s.state),
                tier: format!("{:?}", s.tier),
                category: meta.category,
                tags: meta.tags,
                seed_ratio_limit: meta.seed_ratio_limit,
                seed_time_limit_secs: meta.seed_time_limit_secs,
                sequential,
                super_seeding,
                first_last_piece_priority: first_last,
            }
        })
        .collect();

    (list, total)
}

async fn session_stats_handler(State(state): State<ApiState>) -> Json<SessionStatsResponse> {
    Json(build_session_stats_response(&state.engine).await)
}

async fn list_torrents_handler(
    State(state): State<ApiState>,
    Query(query): Query<PaginationQuery>,
) -> Json<TorrentListResponse> {
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let offset = page.saturating_sub(1).saturating_mul(limit);
    let filter = parse_state_filter(query.state.as_deref());

    let (torrents, total) = build_torrent_list_items(&state.engine, offset, limit, filter);

    Json(TorrentListResponse {
        torrents,
        total,
        page,
        limit,
    })
}

async fn torrents_stream_handler(
    State(state): State<ApiState>,
    Query(query): Query<TorrentStreamQuery>,
) -> axum::response::sse::Sse<
    impl futures::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use tokio_stream::wrappers::ReceiverStream;

    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let offset = page.saturating_sub(1).saturating_mul(limit);
    let filter = parse_state_filter(query.state.as_deref());
    let interval_ms = query.interval_ms.unwrap_or(1000).clamp(250, 5000);

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(64);
    let engine = state.engine.clone();

    tokio::spawn(async move {
        let (items, total) = build_torrent_list_items(&engine, offset, limit, filter);
        let stats = build_session_stats_response(&engine).await;
        let mut last_stats_json = serde_json::to_string(&stats).unwrap_or_default();
        let mut last_total = total;

        let snapshot_payload = serde_json::json!({
            "torrents": &items,
            "total": total,
            "page": page,
            "limit": limit,
            "stats": stats,
        })
        .to_string();

        let mut last_items: HashMap<String, TorrentListItem> = items
            .into_iter()
            .map(|it| (it.info_hash.clone(), it))
            .collect();

        if tx
            .send(Ok(Event::default()
                .event("snapshot")
                .data(snapshot_payload)))
            .await
            .is_err()
        {
            return;
        }

        let mut alert_rx = engine.subscribe_alerts();
        let mut alerts_open = true;
        let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;

        loop {
            tokio::select! {
                _ = tx.closed() => break,
                _ = ticker.tick() => {}
                res = alert_rx.recv(), if alerts_open => {
                    match res {
                        Ok(alert) => {
                            if !matches!(
                                alert,
                                synapse_engine::Alert::TorrentAdded { .. }
                                    | synapse_engine::Alert::TorrentFinished { .. }
                                    | synapse_engine::Alert::TorrentError { .. }
                                    | synapse_engine::Alert::StateChanged { .. }
                            ) {
                                continue;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            engine.record_event_bus_lag(skipped);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            alerts_open = false;
                            continue;
                        }
                    }
                }
            }

            let (curr_items, total) = build_torrent_list_items(&engine, offset, limit, filter);
            let stats = build_session_stats_response(&engine).await;
            let stats_json = serde_json::to_string(&stats).unwrap_or_default();

            let mut added = Vec::new();
            let mut updated = Vec::new();
            let mut next_items = HashMap::with_capacity(curr_items.len());
            for item in curr_items {
                let key = item.info_hash.clone();
                if let Some(prev) = last_items.remove(&key) {
                    if let Some(delta) = compute_item_delta(&prev, &item) {
                        updated.push(delta);
                    }
                } else {
                    added.push(item.clone());
                }
                next_items.insert(key, item);
            }
            let removed: Vec<String> = last_items.into_keys().collect();
            last_items = next_items;

            if !added.is_empty()
                || !updated.is_empty()
                || !removed.is_empty()
                || total != last_total
            {
                last_total = total;
                let delta_payload = serde_json::json!({
                    "added": added,
                    "updated": updated,
                    "removed": removed,
                    "total": total,
                    "page": page,
                    "limit": limit,
                })
                .to_string();
                if tx
                    .send(Ok(Event::default().event("delta").data(delta_payload)))
                    .await
                    .is_err()
                {
                    break;
                }
            }

            if stats_json != last_stats_json {
                last_stats_json = stats_json;
                if tx
                    .send(Ok(Event::default()
                        .event("stats")
                        .data(last_stats_json.clone())))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    });

    Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::default())
}

#[derive(Clone, Copy)]
enum HttpBatchOp {
    Pause,
    Resume,
    Recheck,
}

type BatchApiError = (StatusCode, Json<BatchActionResponse>);
type ParsedBatchHashes = Vec<(String, [u8; 20])>;

fn parse_batch_hashes(hashes: &[String]) -> Result<ParsedBatchHashes, BatchApiError> {
    hashes
        .iter()
        .map(|raw| {
            let hash_hex = raw.to_lowercase();
            let arr = parse_info_hash_hex(&hash_hex).ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(BatchActionResponse {
                        success: false,
                        succeeded: 0,
                        failed_hashes: Vec::new(),
                        message: format!("Invalid info hash: {raw}"),
                    }),
                )
            })?;
            Ok((hash_hex, arr))
        })
        .collect()
}

fn run_batch_state_op(
    engine: &SwarmEngine,
    raw_hashes: &[String],
    op: HttpBatchOp,
    verb: &str,
) -> Result<Json<BatchActionResponse>, (StatusCode, Json<BatchActionResponse>)> {
    let parsed = parse_batch_hashes(raw_hashes)?;
    let mut succeeded = 0usize;
    let mut failed_hashes = Vec::new();
    for (hash_hex, arr) in parsed {
        let ok = match op {
            HttpBatchOp::Pause => engine.transition_to_cold(&arr),
            HttpBatchOp::Resume => engine.transition_to_hot(&arr),
            HttpBatchOp::Recheck => engine.recheck_torrent(&arr),
        };
        if ok {
            succeeded += 1;
        } else {
            failed_hashes.push(hash_hex);
        }
    }
    let all_ok = failed_hashes.is_empty();
    let failed_count = failed_hashes.len();
    Ok(Json(BatchActionResponse {
        success: all_ok,
        succeeded,
        failed_hashes,
        message: if all_ok {
            format!("{verb} {succeeded} torrent(s)")
        } else {
            format!("{verb} {succeeded} torrent(s); {failed_count} not found")
        },
    }))
}

async fn batch_pause_torrents_handler(
    State(state): State<ApiState>,
    Json(payload): Json<BatchHashesRequest>,
) -> Result<Json<BatchActionResponse>, (StatusCode, Json<BatchActionResponse>)> {
    run_batch_state_op(&state.engine, &payload.hashes, HttpBatchOp::Pause, "Paused")
}

async fn batch_resume_torrents_handler(
    State(state): State<ApiState>,
    Json(payload): Json<BatchHashesRequest>,
) -> Result<Json<BatchActionResponse>, (StatusCode, Json<BatchActionResponse>)> {
    run_batch_state_op(
        &state.engine,
        &payload.hashes,
        HttpBatchOp::Resume,
        "Resumed",
    )
}

async fn batch_recheck_torrents_handler(
    State(state): State<ApiState>,
    Json(payload): Json<BatchHashesRequest>,
) -> Result<Json<BatchActionResponse>, (StatusCode, Json<BatchActionResponse>)> {
    run_batch_state_op(
        &state.engine,
        &payload.hashes,
        HttpBatchOp::Recheck,
        "Rechecking",
    )
}

async fn batch_remove_torrents_handler(
    State(state): State<ApiState>,
    Json(payload): Json<BatchRemoveRequest>,
) -> Result<Json<BatchActionResponse>, (StatusCode, Json<BatchActionResponse>)> {
    let parsed = parse_batch_hashes(&payload.hashes)?;
    let mut succeeded = 0usize;
    let mut failed_hashes = Vec::new();
    let mut to_delete: Vec<(String, String)> = Vec::new();

    for (hash_hex, arr) in parsed {
        let target_info = if payload.delete_data {
            state.engine.get_torrent(&arr).map(|h| {
                let s = h.stats.read();
                (s.download_dir.clone(), s.name.clone())
            })
        } else {
            None
        };
        if state.engine.remove_torrent(&arr) {
            succeeded += 1;
            if let Some(info) = target_info {
                to_delete.push(info);
            }
        } else {
            failed_hashes.push(hash_hex);
        }
    }

    if !to_delete.is_empty() {
        let base = state.base_download_dir.clone();
        let _ = tokio::task::spawn_blocking(move || {
            for (dl_dir_str, torrent_name) in to_delete {
                delete_torrent_data_under_base(&base, &dl_dir_str, &torrent_name);
            }
        })
        .await;
    }

    let all_ok = failed_hashes.is_empty();
    let failed_count = failed_hashes.len();
    Ok(Json(BatchActionResponse {
        success: all_ok,
        succeeded,
        failed_hashes,
        message: if all_ok {
            format!("Removed {succeeded} torrent(s)")
        } else {
            format!("Removed {succeeded} torrent(s); {failed_count} not found")
        },
    }))
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
    /// Restrict a search of the configured engines to one, by name.
    pub engine: Option<String>,
    /// `local` searches the torrents this daemon holds instead of the configured engines.
    pub scope: Option<String>,
}

/// `GET /api/v1/search?q=...`: queries the BEP 18 search engines the operator configured and
/// returns their results, or with `scope=local` searches the torrents this daemon holds.
async fn search_torrents_handler(
    State(state): State<ApiState>,
    Query(query): Query<SearchQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let q = query.q.as_deref().unwrap_or("").trim().to_string();

    if query.scope.as_deref() != Some("local") {
        if q.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "q is required"})),
            )
                .into_response();
        }
        let manager = state.engine.search_manager();
        if manager.is_empty() {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "no search engines are configured (see [search] engines, or POST /api/v1/search/engines)"})),
            )
                .into_response();
        }
        let results = manager.search(&q, query.engine.as_deref()).await;
        return Json(serde_json::json!({ "query": q, "engines": results })).into_response();
    }

    let (swarms, _) = state.engine.list_torrents_paged(0, 10_000, None);
    let q_lower = q.to_lowercase();
    let items: Vec<synapse_meta::SearchItem> = swarms
        .into_iter()
        .filter(|s| {
            q_lower.is_empty()
                || s.name.to_lowercase().contains(&q_lower)
                || hex::encode(s.info_hash).contains(&q_lower)
        })
        .map(|s| synapse_meta::SearchItem {
            name: s.name,
            size: s.total_size,
            seeds: s.peers_sending as u32,
            leechers: s.peers_connected.saturating_sub(s.peers_sending) as u32,
            info_hash: Some(s.info_hash),
            download_url: None,
            category: None,
        })
        .collect();
    Json(synapse_meta::SearchResponse {
        total_results: items.len() as u32,
        items,
    })
    .into_response()
}

async fn list_search_engines_handler(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let engines = state.engine.search_manager().list();
    Json(serde_json::json!({ "count": engines.len(), "engines": engines }))
}

#[derive(Debug, Deserialize)]
pub struct AddSearchEngine {
    /// A `.btsearch` file path or http(s) URL.
    pub source: String,
}

async fn add_search_engine_handler(
    State(state): State<ApiState>,
    Json(payload): Json<AddSearchEngine>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ActionResponse>)> {
    match state
        .engine
        .search_manager()
        .add_url_source(payload.source.trim())
        .await
    {
        Ok(engine) => Ok(Json(
            serde_json::json!({ "success": true, "engine": engine }),
        )),
        Err(message) => Err((
            StatusCode::BAD_REQUEST,
            Json(ActionResponse {
                success: false,
                message,
            }),
        )),
    }
}

async fn remove_search_engine_handler(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> StatusCode {
    if state.engine.search_manager().remove(&name) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateTorrentRequest {
    /// The file or directory to make a torrent of. It must be inside the download directory.
    pub path: String,
    #[serde(default)]
    pub trackers: Vec<String>,
    /// Put all trackers in one tier instead of one tier each.
    #[serde(default)]
    pub same_tier: bool,
    #[serde(default)]
    pub web_seeds: Vec<String>,
    pub comment: Option<String>,
    #[serde(default)]
    pub private: bool,
    pub source: Option<String>,
    /// Piece size in KiB (a power of two, at least 16).
    pub piece_size_kib: Option<u32>,
    /// `v1` (default), `v2` or `hybrid`.
    pub version: Option<String>,
}

/// `POST /api/v1/torrents/create`: hashes a file or directory in the download directory and returns
/// the `.torrent` (base64), ready to pass to `POST /api/v1/torrents` as `torrent_base64`.
async fn create_torrent_handler(
    State(state): State<ApiState>,
    Json(req): Json<CreateTorrentRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ActionResponse>)> {
    let fail = |code: StatusCode, message: String| {
        (
            code,
            Json(ActionResponse {
                success: false,
                message,
            }),
        )
    };
    // Only content already under the download directory: this endpoint must not become a way to
    // probe arbitrary files on the host. Check path containment BEFORE testing file existence so
    // any out-of-bounds path uniformly returns 403 FORBIDDEN (eliminating a file-existence oracle).
    let path = validate_path_under_base(&state.base_download_dir, std::path::Path::new(&req.path))
        .map_err(|_| {
            fail(
                StatusCode::FORBIDDEN,
                "the path must be inside the download directory".into(),
            )
        })?;
    if !path.exists() {
        return Err(fail(
            StatusCode::NOT_FOUND,
            format!("{}: path does not exist", req.path),
        ));
    }
    let version = match req.version.as_deref().unwrap_or("v1") {
        "v1" => synapse_meta::create::TorrentVersion::V1,
        "v2" => synapse_meta::create::TorrentVersion::V2,
        "hybrid" => synapse_meta::create::TorrentVersion::Hybrid,
        other => {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                format!("unknown version '{other}' (use v1, v2 or hybrid)"),
            ))
        }
    };
    let trackers = if req.same_tier {
        vec![req.trackers]
    } else {
        req.trackers.into_iter().map(|t| vec![t]).collect()
    };
    let opts = synapse_meta::create::CreateOptions {
        piece_length: req.piece_size_kib.map(|k| k.saturating_mul(1024)),
        trackers,
        web_seeds: req.web_seeds,
        comment: req.comment,
        created_by: Some(format!("Synapse/{}", env!("CARGO_PKG_VERSION"))),
        private: req.private,
        source: req.source,
        name: None,
        version,
        creation_date: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs() as i64),
    };
    let bytes = tokio::task::spawn_blocking(move || {
        synapse_meta::create::create_torrent(&path, &opts, |_, _| {})
    })
    .await
    .map_err(|e| fail(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| fail(StatusCode::BAD_REQUEST, e.to_string()))?;
    let info = synapse_meta::Info::from_torrent_bytes(&bytes)
        .map_err(|e| fail(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    use base64::Engine as _;
    Ok(Json(serde_json::json!({
        "info_hash": hex::encode(info.hash),
        "name": info.name,
        "size": bytes.len(),
        "torrent_base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
    })))
}

/// BEP 39: updates found for torrents that carry an `update-url`.
async fn list_updates_handler(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let updates = state.engine.update_manager().pending();
    Json(serde_json::json!({ "count": updates.len(), "updates": updates }))
}

/// Asks every update feed now.
async fn check_updates_handler(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let found = state.engine.check_for_updates().await;
    Json(serde_json::json!({ "found": found }))
}

/// Adds the update found for `info_hash` (the old torrent).
async fn apply_update_handler(
    State(state): State<ApiState>,
    Path(info_hash): Path<String>,
) -> StatusCode {
    let Some(hash) = parse_info_hash_hex(&info_hash) else {
        return StatusCode::BAD_REQUEST;
    };
    if state.engine.apply_pending_update(&hash) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

/// BEP 35: the signatures a torrent carries and whether each verifies and is trusted.
async fn torrent_signatures_handler(
    State(state): State<ApiState>,
    Path(info_hash): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let hash = parse_info_hash_hex(&info_hash).ok_or(StatusCode::BAD_REQUEST)?;
    let statuses = state
        .engine
        .torrent_signatures(&hash)
        .ok_or(StatusCode::NOT_FOUND)?;
    let signatures: Vec<serde_json::Value> = statuses
        .into_iter()
        .map(|(signer, status)| match status {
            synapse_meta::SignatureStatus::Trusted { .. } => {
                serde_json::json!({"signer": signer, "status": "trusted"})
            }
            synapse_meta::SignatureStatus::Untrusted { reason } => {
                serde_json::json!({"signer": signer, "status": "untrusted", "reason": reason})
            }
            synapse_meta::SignatureStatus::Invalid { reason } => {
                serde_json::json!({"signer": signer, "status": "invalid", "reason": reason})
            }
        })
        .collect();
    Ok(Json(serde_json::json!({
        "signed": !signatures.is_empty(),
        "signatures": signatures,
    })))
}

async fn add_torrent_handler(
    State(state): State<ApiState>,
    Json(payload): Json<AddTorrentRequest>,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ActionResponse>)> {
    let dir = match payload
        .download_dir
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
    {
        Some(custom_dir) => {
            validate_path_under_base(&state.base_download_dir, std::path::Path::new(custom_dir))
                .map_err(|msg| {
                    (
                        StatusCode::FORBIDDEN,
                        Json(ActionResponse {
                            success: false,
                            message: format!("download_dir rejected: {msg}"),
                        }),
                    )
                })?
        }
        None => state.engine.settings().read().download_dir.clone(),
    };

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
        // base64 inflates by 4/3; reject before decoding so a huge string is never expanded.
        if b64.len() > synapse_meta::MAX_TORRENT_FILE_BYTES.div_ceil(3) * 4 + 4 {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(ActionResponse {
                    success: false,
                    message: "torrent_base64 payload exceeds the maximum accepted size".to_string(),
                }),
            ));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ActionResponse {
                        success: false,
                        message: format!("Invalid base64 payload: {e}"),
                    }),
                )
            })?;
        if bytes.len() > synapse_meta::MAX_TORRENT_FILE_BYTES {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(ActionResponse {
                    success: false,
                    message: "Torrent payload exceeds the maximum accepted size".to_string(),
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

    if let Err(message) = state.engine.check_signature_policy(&info) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ActionResponse {
                success: false,
                message,
            }),
        ));
    }
    let already_added = state.engine.get_torrent(&info.hash).is_some();
    let handle = state
        .engine
        .add_torrent(std::sync::Arc::new(info), dir, None);
    let hash = handle.stats.read().info_hash;
    // Only a genuinely new torrent should have the request's paused/start-added preference
    // applied; re-adding one already running must leave its current state untouched.
    if !already_added {
        let start_added = state.engine.settings().read().start_added_torrents;
        if payload.paused.unwrap_or(!start_added) {
            state.engine.transition_to_cold(&hash);
        }
    }

    Ok(Json(ActionResponse {
        success: true,
        message: if already_added {
            format!("Torrent already added with info_hash={}", hex::encode(hash))
        } else {
            format!(
                "Torrent added successfully with info_hash={}",
                hex::encode(hash)
            )
        },
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
        let meta = handle.metadata.read().clone();
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
            "category": meta.category,
            "tags": meta.tags,
            "seed_ratio_limit": meta.seed_ratio_limit,
            "seed_time_limit_secs": meta.seed_time_limit_secs,
            "sequential": handle.sequential.load(std::sync::atomic::Ordering::Relaxed),
            "super_seeding": handle.super_seeding.load(std::sync::atomic::Ordering::Relaxed),
            "first_last_piece_priority": handle.first_last_piece_priority.load(std::sync::atomic::Ordering::Relaxed),
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub(crate) fn delete_torrent_data_under_base(
    base_download_dir: &std::path::Path,
    dl_dir_str: &str,
    torrent_name: &str,
) {
    if !is_safe_single_component_name(torrent_name) {
        return;
    }
    if let (Ok(canonical_base), Ok(canonical_dl_dir)) = (
        canonicalize_with_nonexistent_tail(base_download_dir),
        validate_path_under_base(base_download_dir, std::path::Path::new(dl_dir_str)),
    ) {
        let candidate = canonical_dl_dir.join(torrent_name);
        if candidate != canonical_dl_dir
            && candidate != canonical_base
            && candidate.starts_with(&canonical_base)
        {
            if let Ok(meta) = std::fs::symlink_metadata(&candidate) {
                if meta.file_type().is_symlink() || meta.file_type().is_file() {
                    let _ = std::fs::remove_file(&candidate);
                } else if meta.file_type().is_dir() {
                    let _ = std::fs::remove_dir_all(&candidate);
                }
            }
        }
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

    let target_info = if let Some(handle) = state.engine.get_torrent(&hash) {
        let stats = handle.stats.read();
        Some((stats.download_dir.clone(), stats.name.clone()))
    } else {
        None
    };

    if state.engine.remove_torrent(&hash) {
        if query.delete_data.unwrap_or(false) {
            if let Some((dl_dir_str, torrent_name)) = target_info {
                let base = state.base_download_dir.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    delete_torrent_data_under_base(&base, &dl_dir_str, &torrent_name);
                })
                .await;
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
            let prog = if f.length > 0 {
                (done as f64 / f.length as f64) as f32
            } else {
                1.0
            };
            (done, prog.min(1.0))
        } else {
            (0, 0.0)
        };

        let priority = handle.file_priorities.read().get(idx).copied().unwrap_or(4);
        files_json.push(serde_json::json!({
            "index": idx,
            "path": f.path.to_string_lossy(),
            "size_bytes": f.length,
            "bytes_completed": bytes_completed,
            "progress": progress,
            "priority": priority,
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
            "is_circuit_broken": rep.is_circuit_broken,
            "cb_state": rep.cb_state.map(circuit_state_label),
            "recovery_progress_pct": rep.recovery_progress_pct,
            "last_announce_time": rep.last_announce_time,
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

    let discovery = state.engine.swarm_discovery_stats(&hash);
    let meta = handle.metadata.read().clone();

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
        "candidate_peers": discovery.candidate_peers,
        "active_dials": discovery.active_dials,
        "discovery": discovery,
        "state": format!("{:?}", stats.state),
        "tier": format!("{:?}", stats.tier),
        "category": meta.category,
        "tags": meta.tags,
        "seed_ratio_limit": meta.seed_ratio_limit,
        "seed_time_limit_secs": meta.seed_time_limit_secs,
        "sequential": handle.sequential.load(std::sync::atomic::Ordering::Relaxed),
        "super_seeding": handle.super_seeding.load(std::sync::atomic::Ordering::Relaxed),
        "first_last_piece_priority": handle.first_last_piece_priority.load(std::sync::atomic::Ordering::Relaxed),
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

    if bytes.len() > synapse_meta::MAX_TORRENT_FILE_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ActionResponse {
                success: false,
                message: "Torrent payload exceeds the maximum accepted size".to_string(),
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

    let dir = match query
        .download_dir
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
    {
        Some(custom_dir) => {
            validate_path_under_base(&state.base_download_dir, std::path::Path::new(custom_dir))
                .map_err(|msg| {
                    (
                        StatusCode::FORBIDDEN,
                        Json(ActionResponse {
                            success: false,
                            message: format!("download_dir rejected: {msg}"),
                        }),
                    )
                })?
        }
        None => state.engine.settings().read().download_dir.clone(),
    };

    if let Err(message) = state.engine.check_signature_policy(&info) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ActionResponse {
                success: false,
                message,
            }),
        ));
    }
    let handle = state
        .engine
        .add_torrent(std::sync::Arc::new(info), dir, None);
    let hash = handle.stats.read().info_hash;
    let start_added = state.engine.settings().read().start_added_torrents;
    if query.paused.unwrap_or(!start_added) {
        state.engine.transition_to_cold(&hash);
    }

    Ok(Json(ActionResponse {
        success: true,
        message: format!(
            "Torrent added successfully with info_hash={}",
            hex::encode(hash)
        ),
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

    let validated = validate_path_under_base(
        &state.base_download_dir,
        std::path::Path::new(payload.new_download_dir.trim()),
    )
    .map_err(|_| StatusCode::FORBIDDEN)?;
    let validated_str = validated.to_string_lossy().into_owned();
    let move_files = payload.move_existing_files.unwrap_or(true);
    let engine = state.engine.clone();
    let ok = tokio::task::spawn_blocking(move || {
        engine.set_location_with_options(&hash, &validated_str, move_files)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if ok {
        Ok(Json(ActionResponse {
            success: true,
            message: "Location updated".to_string(),
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn set_file_priority_handler(
    State(state): State<ApiState>,
    Path((info_hash_str, file_index)): Path<(String, u32)>,
    Json(payload): Json<SetFilePriorityRequest>,
) -> Result<Json<ActionResponse>, StatusCode> {
    let hash_bytes = hex::decode(&info_hash_str).map_err(|_| StatusCode::BAD_REQUEST)?;
    if hash_bytes.len() != 20 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&hash_bytes);

    if state
        .engine
        .set_file_priority(&hash, file_index, payload.priority)
    {
        Ok(Json(ActionResponse {
            success: true,
            message: format!(
                "Priority for file {} updated to {}",
                file_index, payload.priority
            ),
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

fn parse_info_hash(info_hash_str: &str) -> Result<[u8; 20], StatusCode> {
    let hash_bytes = hex::decode(info_hash_str.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;
    if hash_bytes.len() != 20 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&hash_bytes);
    Ok(hash)
}

#[derive(Debug, Deserialize)]
pub struct QueueMoveRequest {
    pub direction: String,
}

#[derive(Debug, Deserialize)]
pub struct ToggleRequest {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct ReplaceTrackersBody {
    pub trackers: Vec<String>,
}

fn deserialize_double_option<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize)]
pub struct UpdateMetadataRequest {
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub category: Option<Option<String>>,
    pub tags: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub seed_ratio_limit: Option<Option<f64>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub seed_time_limit_secs: Option<Option<u64>>,
}

async fn queue_move_handler(
    State(state): State<ApiState>,
    Path(info_hash_str): Path<String>,
    Json(payload): Json<QueueMoveRequest>,
) -> Result<Json<ActionResponse>, StatusCode> {
    let hash = parse_info_hash(&info_hash_str)?;
    let dir = match payload.direction.to_lowercase().as_str() {
        "top" => synapse_engine::QueueMove::Top,
        "up" => synapse_engine::QueueMove::Up,
        "down" => synapse_engine::QueueMove::Down,
        "bottom" => synapse_engine::QueueMove::Bottom,
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    if state.engine.move_in_queue(&[hash], dir) == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(Json(ActionResponse {
        success: true,
        message: format!("Moved torrent {} in queue", payload.direction),
    }))
}

async fn set_sequential_handler(
    State(state): State<ApiState>,
    Path(info_hash_str): Path<String>,
    Json(payload): Json<ToggleRequest>,
) -> Result<Json<ActionResponse>, StatusCode> {
    let hash = parse_info_hash(&info_hash_str)?;
    if state.engine.set_sequential_download(&hash, payload.enabled) {
        Ok(Json(ActionResponse {
            success: true,
            message: format!("Sequential download set to {}", payload.enabled),
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn set_super_seed_handler(
    State(state): State<ApiState>,
    Path(info_hash_str): Path<String>,
    Json(payload): Json<ToggleRequest>,
) -> Result<Json<ActionResponse>, StatusCode> {
    let hash = parse_info_hash(&info_hash_str)?;
    if state.engine.set_super_seeding(&hash, payload.enabled) {
        Ok(Json(ActionResponse {
            success: true,
            message: format!("Super-seeding set to {}", payload.enabled),
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn set_first_last_priority_handler(
    State(state): State<ApiState>,
    Path(info_hash_str): Path<String>,
    Json(payload): Json<ToggleRequest>,
) -> Result<Json<ActionResponse>, StatusCode> {
    let hash = parse_info_hash(&info_hash_str)?;
    if state
        .engine
        .set_first_last_piece_priority(&hash, payload.enabled)
    {
        Ok(Json(ActionResponse {
            success: true,
            message: format!("First/last piece priority set to {}", payload.enabled),
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn reannounce_torrent_handler(
    State(state): State<ApiState>,
    Path(info_hash_str): Path<String>,
) -> Result<Json<ActionResponse>, StatusCode> {
    let hash = parse_info_hash(&info_hash_str)?;
    if state.engine.get_torrent(&hash).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    let ok = state.engine.reannounce_torrent(&hash);
    Ok(Json(ActionResponse {
        success: ok,
        message: if ok {
            "Reannounce triggered".to_string()
        } else {
            "Torrent is not currently announcing (stopped or queued)".to_string()
        },
    }))
}

async fn replace_trackers_handler(
    State(state): State<ApiState>,
    Path(info_hash_str): Path<String>,
    Json(payload): Json<ReplaceTrackersBody>,
) -> Result<Json<ActionResponse>, StatusCode> {
    let hash = parse_info_hash(&info_hash_str)?;
    match state.engine.replace_trackers(&hash, &payload.trackers) {
        None => Err(StatusCode::NOT_FOUND),
        Some(0) if !payload.trackers.is_empty() => Err(StatusCode::BAD_REQUEST),
        Some(count) => Ok(Json(ActionResponse {
            success: true,
            message: format!("Updated trackers ({count} active)"),
        })),
    }
}

async fn update_metadata_handler(
    State(state): State<ApiState>,
    Path(info_hash_str): Path<String>,
    Json(payload): Json<UpdateMetadataRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let hash = parse_info_hash(&info_hash_str)?;
    let patch = synapse_engine::TorrentMetadataPatch {
        category: payload.category,
        tags: payload.tags,
        seed_ratio_limit: payload.seed_ratio_limit,
        seed_time_limit_secs: payload.seed_time_limit_secs,
    };
    let Some(updated) = state.engine.set_torrent_metadata(&hash, patch) else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok(Json(serde_json::json!({
        "success": true,
        "metadata": updated,
    })))
}

async fn export_torrent_handler(
    State(state): State<ApiState>,
    Path(info_hash_str): Path<String>,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    let hash = parse_info_hash(&info_hash_str)?;
    let engine = state.engine.clone();
    let Some((name, bytes)) =
        tokio::task::spawn_blocking(move || engine.export_torrent_bytes(&hash))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };
    let safe_name: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let filename = if safe_name.is_empty() {
        format!("{info_hash_str}.torrent")
    } else {
        format!("{safe_name}.torrent")
    };
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/x-bittorrent"),
    );
    if let Ok(disp) =
        axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
    {
        headers.insert(axum::http::header::CONTENT_DISPOSITION, disp);
    }
    Ok((StatusCode::OK, headers, bytes))
}

async fn reload_ip_filter_handler(
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let engine = state.engine.clone();
    let rules = tokio::task::spawn_blocking(move || engine.reload_ip_filter())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({
        "success": true,
        "rules": rules,
    })))
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
    let free_disk_space_bytes = state.engine.free_disk_space_bytes_async().await;

    let snapshot = PrometheusSnapshot {
        total_torrents: m.total_torrents,
        downloading_torrents: m.downloading_torrents,
        seeding_torrents: m.seeding_torrents,
        paused_torrents: m.paused_torrents,
        queued_torrents: m.queued_torrents,
        checking_torrents: m.checking_torrents,
        error_torrents: m.error_torrents,
        bytes_downloaded: m.downloaded_bytes,
        bytes_uploaded: m.uploaded_bytes,
        download_rate: m.download_rate,
        upload_rate: m.upload_rate,
        connected_peers: m.peers_connected,
        circuit_breakers_tripped: state.engine.circuit_breaker().tripped_count()
            + state.engine.tracker_circuit_breaker().tripped_count(),
        dht_nodes: state.engine.dht_node_count_fast(),
        nat_mapped_port: state.engine.mapped_external_port(
            state.engine.listen_port(),
            synapse_engine::PortProtocol::Tcp,
        ),
        chokes_total: m.chokes_total,
        unchokes_total: m.unchokes_total,
        piece_requests_total: m.piece_requests_total,
        piece_rejects_total: m.piece_rejects_total,
        hash_fails_total: m.hash_fails_total,
        peer_bans_total: m.peers_banned,
        disk_write_queue_bytes: state.engine.disk_write_queue_bytes(),
        utp_packet_loss_total: state.engine.utp_packet_loss_total(),
        dht_dos_blocks_total: state.engine.dht_dos_blocks_total(),
        event_bus_lag_total: m.event_bus_lag_total,
        auth_failures_total: state.rate_limiter.total_failures(),
        free_disk_space_bytes,
        session_flush_duration_ms: m.last_flush_duration_ms,
        rpc_sync_duration_ms: m.last_sync_duration_ms,
    };

    let text = render_prometheus_metrics(&snapshot);
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        text,
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct RemoveRssFeedQuery {
    pub url: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct PollRssFeedQuery {
    pub url: Option<String>,
}

async fn list_rss_feeds_handler(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let feeds = state.engine.feed_manager().list_feeds();
    let total = feeds.len();
    Json(serde_json::json!({
        "feeds": feeds,
        "count": total,
    }))
}

async fn add_rss_feed_handler(
    State(state): State<ApiState>,
    Json(payload): Json<synapse_config::RssFeedConfig>,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ActionResponse>)> {
    if payload.url.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ActionResponse {
                success: false,
                message: "url cannot be empty".into(),
            }),
        ));
    }
    state.engine.feed_manager().add_feed(payload);
    Ok(Json(ActionResponse {
        success: true,
        message: "Feed registered successfully".into(),
    }))
}

async fn remove_rss_feed_handler(
    State(state): State<ApiState>,
    Query(query): Query<RemoveRssFeedQuery>,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ActionResponse>)> {
    let removed = state.engine.feed_manager().remove_feed(&query.url);
    if removed {
        Ok(Json(ActionResponse {
            success: true,
            message: "Feed removed successfully".into(),
        }))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ActionResponse {
                success: false,
                message: format!("Feed '{}' not found", query.url),
            }),
        ))
    }
}

async fn poll_rss_feeds_handler(
    State(state): State<ApiState>,
    Query(query): Query<PollRssFeedQuery>,
) -> Json<serde_json::Value> {
    if let Some(ref url) = query.url {
        match state
            .engine
            .feed_manager()
            .poll_single_feed(url, &state.engine)
            .await
        {
            Ok(items) => Json(serde_json::json!({
                "success": true,
                "url": url,
                "items_count": items.len(),
            })),
            Err(e) => Json(serde_json::json!({
                "success": false,
                "url": url,
                "error": e,
            })),
        }
    } else {
        let results = state.engine.poll_rss_feeds().await;
        let successful = results.iter().filter(|r| r.is_ok()).count();
        Json(serde_json::json!({
            "success": true,
            "total_feeds": results.len(),
            "successful_feeds": successful,
        }))
    }
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
        let bytes = axum::body::to_bytes(resp7.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let session_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(session_json["download_limit_bytes"], 6_250_000);
        assert_eq!(session_json["download_limit_pretty"], "50 Mbps");
        assert_eq!(session_json["upload_limit_bytes"], 125_000_000);
        assert_eq!(session_json["upload_limit_pretty"], "1 Gbps");
        assert_eq!(session_json["alt_speed_down_bytes"], 125_000_000);
        assert_eq!(session_json["alt_speed_down_pretty"], "1 Gbps");
    }

    #[test]
    fn test_constant_time_eq_rejects_empty_and_mismatched_tokens() {
        assert!(!constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"secret", b""));
        assert!(!constant_time_eq(b"", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secret-longer"));
        assert!(!constant_time_eq(b"secret1", b"secret2"));
        assert!(constant_time_eq(
            b"super-secret-token",
            b"super-secret-token"
        ));
    }

    #[tokio::test]
    async fn test_csrf_rejects_cross_site_origin_and_sec_fetch_site() {
        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
        let app = create_http_router_with_auth(engine, Some("valid-token".into()));

        // 1. Sec-Fetch-Site: cross-site on state-changing request -> 403 FORBIDDEN
        let req_cross_site = Request::builder()
            .method("PATCH")
            .uri("/api/v1/session")
            .header("Authorization", "Bearer valid-token")
            .header("Sec-Fetch-Site", "cross-site")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"alt_speed_enabled": true}"#))
            .unwrap();
        let resp = app.clone().oneshot(req_cross_site).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // 2. Mismatched Origin vs Host on POST -> 403 FORBIDDEN
        let req_bad_origin = Request::builder()
            .method("POST")
            .uri("/api/v1/torrents")
            .header("Authorization", "Bearer valid-token")
            .header("Host", "127.0.0.1:9090")
            .header("Origin", "https://evil.example.com")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"magnet": "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567"}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(req_bad_origin).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // 3. Matching Origin vs Host -> allowed (200 OK)
        let req_good_origin = Request::builder()
            .method("PATCH")
            .uri("/api/v1/session")
            .header("Authorization", "Bearer valid-token")
            .header("Host", "127.0.0.1:9090")
            .header("Origin", "http://127.0.0.1:9090")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"alt_speed_enabled": false}"#))
            .unwrap();
        let resp = app.oneshot(req_good_origin).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_path_containment_and_uniform_403_in_create_torrent() {
        let tmp = tempfile::tempdir().unwrap();
        let base_dir = tmp.path().join("downloads");
        std::fs::create_dir_all(&base_dir).unwrap();

        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
        engine.settings().write().download_dir = base_dir.clone();
        let app = create_http_router(engine.clone());

        // 1. Out-of-bounds existing path (/etc) and non-existent path (/nonexistent_secret_xyz)
        // must BOTH return 403 FORBIDDEN (no file-existence oracle).
        for probe in ["/etc", "/nonexistent_secret_xyz_12345", "../outside"] {
            let req = Request::builder()
                .method("POST")
                .uri("/api/v1/torrents/create")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "path": probe })).unwrap(),
                ))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "expected 403 FORBIDDEN for out-of-bounds path {probe}"
            );
        }

        // 2. Non-existent path strictly INSIDE download_dir returns 404 NOT_FOUND
        let inside_missing = base_dir.join("missing_file.iso");
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/torrents/create")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(
                    &serde_json::json!({ "path": inside_missing.to_string_lossy() }),
                )
                .unwrap(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // 3. Symlink inside download_dir pointing outside download_dir returns 403 FORBIDDEN
        #[cfg(unix)]
        {
            let outside_target = tmp.path().join("outside_secret.txt");
            std::fs::write(&outside_target, b"secret").unwrap();
            let symlink_inside = base_dir.join("escape_link.txt");
            std::os::unix::fs::symlink(&outside_target, &symlink_inside).unwrap();

            let req = Request::builder()
                .method("POST")
                .uri("/api/v1/torrents/create")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(
                        &serde_json::json!({ "path": symlink_inside.to_string_lossy() }),
                    )
                    .unwrap(),
                ))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }

        // 4. PATCH /api/v1/session with download_dir escaping base_dir -> 403 FORBIDDEN
        let req_patch_escape = Request::builder()
            .method("PATCH")
            .uri("/api/v1/session")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"download_dir": "/etc"}"#))
            .unwrap();
        let resp = app.clone().oneshot(req_patch_escape).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // 5. POST /api/v1/torrents with download_dir escaping base_dir -> 403 FORBIDDEN
        let req_add_escape = Request::builder()
            .method("POST")
            .uri("/api/v1/torrents")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"magnet": "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567", "download_dir": "../escape"}"#))
            .unwrap();
        let resp = app.oneshot(req_add_escape).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_delete_torrent_delete_data_refuses_unsafe_names_and_symlinks() {
        assert!(!is_safe_single_component_name(""));
        assert!(!is_safe_single_component_name("."));
        assert!(!is_safe_single_component_name(".."));
        assert!(!is_safe_single_component_name("../etc"));
        assert!(!is_safe_single_component_name("foo/bar"));
        assert!(!is_safe_single_component_name("foo\\bar"));
        assert!(!is_safe_single_component_name("foo\0bar"));
        assert!(is_safe_single_component_name("ubuntu-24.04.iso"));

        #[cfg(unix)]
        {
            let tmp = tempfile::tempdir().unwrap();
            let base_dir = tmp.path().join("downloads");
            let outside_dir = tmp.path().join("outside_victim");
            std::fs::create_dir_all(&base_dir).unwrap();
            std::fs::create_dir_all(&outside_dir).unwrap();
            let victim_file = outside_dir.join("keep_me.txt");
            std::fs::write(&victim_file, b"important data").unwrap();

            // Place a symlink inside base_dir named after the torrent pointing to outside_dir
            let symlink_path = base_dir.join("evil-torrent");
            std::os::unix::fs::symlink(&outside_dir, &symlink_path).unwrap();

            let disk = Arc::new(diskio::DiskEngine::auto().await);
            let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
            engine.settings().write().download_dir = base_dir.clone();
            let app = create_http_router(engine.clone());

            let info = synapse_meta::Info::from_magnet(
                "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=evil-torrent",
            )
            .unwrap();
            engine.add_torrent(Arc::new(info), base_dir.clone(), None);

            let req = Request::builder()
                .method("DELETE")
                .uri("/api/v1/torrents/0123456789abcdef0123456789abcdef01234567?delete_data=true")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);

            // The symlink itself may be unlinked, but the outside directory and its files MUST survive!
            assert!(
                victim_file.exists(),
                "delete_data=true must never follow a directory symlink to delete outside files"
            );
        }
    }

    fn request_from_peer(peer: &str, xff: Option<&str>) -> axum::extract::Request {
        let mut builder = Request::builder().uri("/");
        if let Some(xff) = xff {
            builder = builder.header("x-forwarded-for", xff);
        }
        let mut req = builder.body(Body::empty()).unwrap();
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            peer.parse::<std::net::SocketAddr>().unwrap(),
        ));
        req
    }

    #[test]
    fn client_ip_ignores_a_spoofed_prefix_and_uses_the_hop_the_trusted_proxy_appended() {
        let trusted = ["127.0.0.1".parse().unwrap()];
        let req = request_from_peer("127.0.0.1:1234", Some("203.0.113.9, 10.0.0.5"));
        // Default empty trusted_proxies ignores XFF even on loopback.
        assert_eq!(extract_client_ip(&req, &[]), "127.0.0.1");
        assert_eq!(extract_client_ip(&req, &trusted), "203.0.113.9");
    }

    #[test]
    fn client_ip_falls_back_to_the_peer_when_forwarded_for_is_entirely_private() {
        let trusted = ["127.0.0.1".parse().unwrap()];
        let req = request_from_peer("127.0.0.1:1234", Some("10.0.0.1, 10.0.0.2"));
        assert_eq!(extract_client_ip(&req, &trusted), "127.0.0.1");
    }

    #[test]
    fn client_ip_from_an_untrusted_peer_ignores_forwarded_for_entirely() {
        let trusted = ["127.0.0.1".parse().unwrap()];
        let req = request_from_peer("203.0.113.1:1234", Some("1.2.3.4"));
        assert_eq!(extract_client_ip(&req, &trusted), "203.0.113.1");
    }

    #[tokio::test]
    async fn get_dns_rebinding_and_origin_port_mismatch_and_relative_settings_are_handled() {
        let tmp = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
        engine.settings().write().download_dir = tmp.path().to_path_buf();
        let app = create_http_router(engine.clone());

        // GET with non-loopback Host must be rejected (403) when unauthenticated.
        let get_rebind = Request::builder()
            .method("GET")
            .uri("/api/v1/torrents")
            .header("Host", "evil.example.com:8080")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(get_rebind).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

        // POST with matching host but wrong Origin port must be rejected (403).
        let bad_port_origin = Request::builder()
            .method("PATCH")
            .uri("/api/v1/session")
            .header("Host", "127.0.0.1:8080")
            .header("Origin", "http://127.0.0.1:9999")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"alt_speed_enabled": true}"#))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(bad_port_origin).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

        // PATCH with relative download_dir under base must persist canonicalized absolute path.
        let canonical_base = std::fs::canonicalize(tmp.path()).unwrap();
        let rel_patch = Request::builder()
            .method("PATCH")
            .uri("/api/v1/session")
            .header("Host", "127.0.0.1:8080")
            .header("Origin", "http://127.0.0.1:8080")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"download_dir": "movies"}"#))
            .unwrap();
        let resp = app.oneshot(rel_patch).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            engine.settings().read().download_dir,
            canonical_base.join("movies")
        );
    }

    #[test]
    fn allowed_host_accepts_loopback_and_configured_hosts_only() {
        let allowed = vec!["synapse.example.com".to_string()];
        assert!(is_allowed_host("localhost", &allowed));
        assert!(is_allowed_host("Synapse.Example.com", &allowed));
        assert!(!is_allowed_host("evil.example.com", &allowed));
        assert!(!is_allowed_host("synapse.example.com", &[]));
    }

    #[tokio::test]
    async fn spoofed_forwarded_for_cannot_bypass_the_auth_failure_rate_limit() {
        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
        let app = create_http_router_all(
            engine,
            Some("super-secret-token".to_string()),
            false,
            synapse_config::WebConfig::default(),
            Vec::new(),
        );

        // 20 failed attempts, each from a direct (untrusted) peer claiming a different
        // X-Forwarded-For value. If the header were trusted, every attempt would land in its
        // own bucket and never trip the limiter; since the peer isn't a trusted proxy, they all
        // key on the one real peer IP and the account-wide limiter kicks in well before 20.
        let mut saw_rate_limited = false;
        for i in 0..20 {
            let mut req = request_from_peer("203.0.113.50:1234", Some(&format!("10.0.{i}.1")));
            *req.uri_mut() = "/api/v1/torrents".parse().unwrap();
            req.headers_mut()
                .insert(header::AUTHORIZATION, "Bearer wrong-token".parse().unwrap());
            let resp = app.clone().oneshot(req).await.unwrap();
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                saw_rate_limited = true;
                break;
            }
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        assert!(
            saw_rate_limited,
            "repeated auth failures from one real peer must eventually be rate-limited \
             regardless of the X-Forwarded-For value they send"
        );
    }

    #[tokio::test]
    async fn patch_metadata_explicit_null_clears_while_omitted_fields_stay_intact() {
        let tmp = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
        engine.settings().write().download_dir = tmp.path().to_path_buf();
        let app = create_http_router(engine.clone());

        let info = synapse_meta::Info::from_magnet(
            "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=meta-test",
        )
        .unwrap();
        let hash_hex = hex::encode(info.hash);
        engine.add_torrent(Arc::new(info), tmp.path().to_path_buf(), None);

        // Set all metadata fields first.
        let set_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/torrents/{hash_hex}/metadata"))
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"category":"linux","tags":["iso"],"seed_ratio_limit":2.5,"seed_time_limit_secs":3600}"#,
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(set_req).await.unwrap().status(),
            StatusCode::OK
        );

        // Explicitly pass `null` to clear category & seed_ratio_limit while omitting seed_time_limit_secs & tags.
        let clear_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/torrents/{hash_hex}/metadata"))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"category":null,"seed_ratio_limit":null}"#))
            .unwrap();
        let resp = app.oneshot(clear_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["metadata"]["category"], serde_json::Value::Null);
        assert_eq!(
            json["metadata"]["seed_ratio_limit"],
            serde_json::Value::Null
        );
        assert_eq!(json["metadata"]["seed_time_limit_secs"], 3600);
        assert_eq!(json["metadata"]["tags"], serde_json::json!(["iso"]));
    }

    #[tokio::test]
    async fn body_limits_allow_large_torrents_and_cap_standard_routes() {
        use base64::Engine;

        let tmp = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
        engine.settings().write().download_dir = tmp.path().to_path_buf();
        let app = create_http_router(engine.clone());

        // > 2 MiB valid .torrent payload (120,000 pieces * 20 bytes = 2.4 MB).
        let piece_count = 120_000usize;
        let mut info_dict = std::collections::BTreeMap::new();
        info_dict.insert(
            b"name".to_vec(),
            synapse_bencode::BEncode::String(b"large-meta.bin".to_vec()),
        );
        info_dict.insert(
            b"piece length".to_vec(),
            synapse_bencode::BEncode::Int(16_384),
        );
        info_dict.insert(
            b"pieces".to_vec(),
            synapse_bencode::BEncode::String(vec![0u8; piece_count * 20]),
        );
        info_dict.insert(
            b"length".to_vec(),
            synapse_bencode::BEncode::Int((piece_count * 16_384) as i64),
        );
        let mut root_dict = std::collections::BTreeMap::new();
        root_dict.insert(b"info".to_vec(), synapse_bencode::BEncode::Dict(info_dict));
        let mut torrent_bytes = Vec::new();
        synapse_bencode::BEncode::Dict(root_dict)
            .encode(&mut torrent_bytes)
            .unwrap();
        assert!(torrent_bytes.len() > 2 * 1024 * 1024);

        let upload_req = Request::builder()
            .method("POST")
            .uri("/api/v1/torrents/upload")
            .body(Body::from(torrent_bytes.clone()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(upload_req).await.unwrap().status(),
            StatusCode::OK
        );

        let add_json = serde_json::json!({
            "torrent_base64": base64::engine::general_purpose::STANDARD.encode(&torrent_bytes),
        });
        let add_req = Request::builder()
            .method("POST")
            .uri("/api/v1/torrents")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&add_json).unwrap()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(add_req).await.unwrap().status(),
            StatusCode::OK
        );

        // Standard route (> 64 KiB) must be rejected with 413 Payload Too Large.
        let oversized_patch = vec![b' '; 70 * 1024];
        let patch_req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/session")
            .header("Content-Type", "application/json")
            .body(Body::from(oversized_patch))
            .unwrap();
        assert_eq!(
            app.oneshot(patch_req).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn metrics_handler_reports_live_utp_and_dht_counters() {
        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
        engine
            .metrics_ref()
            .utp_packet_loss_total
            .store(7, std::sync::atomic::Ordering::Relaxed);
        engine
            .metrics_ref()
            .dht_dos_blocks_total
            .store(9, std::sync::atomic::Ordering::Relaxed);

        let app = create_http_router(engine);
        let req = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("synapse_utp_packet_loss_total 7"));
        assert!(text.contains("synapse_dht_dos_blocked_total 9"));
    }

    #[tokio::test]
    async fn list_torrents_caps_limit_at_500_and_preserves_schema() {
        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
        engine.settings().write().download_dir = dir.path().to_path_buf();

        let mut info_dict = std::collections::BTreeMap::new();
        info_dict.insert(
            b"name".to_vec(),
            synapse_bencode::BEncode::String(b"schema-test.bin".to_vec()),
        );
        info_dict.insert(
            b"piece length".to_vec(),
            synapse_bencode::BEncode::Int(16_384),
        );
        info_dict.insert(
            b"pieces".to_vec(),
            synapse_bencode::BEncode::String(vec![0u8; 20]),
        );
        info_dict.insert(b"length".to_vec(), synapse_bencode::BEncode::Int(16_384));
        let mut root_dict = std::collections::BTreeMap::new();
        root_dict.insert(b"info".to_vec(), synapse_bencode::BEncode::Dict(info_dict));
        let info = Arc::new(
            synapse_meta::Info::from_bencode(synapse_bencode::BEncode::Dict(root_dict)).unwrap(),
        );
        engine.add_torrent(info.clone(), dir.path().to_path_buf(), None);

        let app = create_http_router(engine);
        let req = Request::builder()
            .uri("/api/v1/torrents?limit=10000")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(val["limit"], 500);
        assert_eq!(val["total"], 1);
        assert_eq!(val["page"], 1);
        let item = &val["torrents"][0];
        assert_eq!(item["info_hash"], hex::encode(info.hash));
        assert_eq!(item["name"], "schema-test.bin");
        assert_eq!(item["total_bytes"], 16_384);
        assert!(item["state"].is_string());
        assert!(item["tier"].is_string());

        let stats_req = Request::builder()
            .uri("/api/v1/session/stats")
            .body(Body::empty())
            .unwrap();
        let stats_resp = app.oneshot(stats_req).await.unwrap();
        assert_eq!(stats_resp.status(), StatusCode::OK);
        let stats_body = axum::body::to_bytes(stats_resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let stats_val: serde_json::Value = serde_json::from_slice(&stats_body).unwrap();
        assert_eq!(stats_val["total_torrents"], 1);
        assert!(stats_val["dht_nodes"].is_u64());
        assert!(stats_val["version"].is_string());
    }

    fn build_http_test_info(name: &str, tracker_url: Option<&str>) -> Arc<synapse_meta::Info> {
        let mut info_dict = std::collections::BTreeMap::new();
        info_dict.insert(
            b"name".to_vec(),
            synapse_bencode::BEncode::String(name.as_bytes().to_vec()),
        );
        info_dict.insert(
            b"piece length".to_vec(),
            synapse_bencode::BEncode::Int(16_384),
        );
        info_dict.insert(
            b"pieces".to_vec(),
            synapse_bencode::BEncode::String(vec![0u8; 20]),
        );
        info_dict.insert(b"length".to_vec(), synapse_bencode::BEncode::Int(16_384));
        let mut root_dict = std::collections::BTreeMap::new();
        if let Some(url) = tracker_url {
            root_dict.insert(
                b"announce".to_vec(),
                synapse_bencode::BEncode::String(url.as_bytes().to_vec()),
            );
        }
        root_dict.insert(b"info".to_vec(), synapse_bencode::BEncode::Dict(info_dict));
        Arc::new(
            synapse_meta::Info::from_bencode(synapse_bencode::BEncode::Dict(root_dict)).unwrap(),
        )
    }

    #[tokio::test]
    async fn session_and_detail_expose_new_parity_fields() {
        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
        engine.settings().write().download_dir = dir.path().to_path_buf();
        {
            let settings_lock = engine.settings();
            let mut s = settings_lock.write();
            s.dht_read_only = true;
            s.zeroconf_enabled = false;
            s.announce_ip = Some("127.0.0.1".parse().unwrap());
            s.enable_utp = true;
            s.unchoke_slots_global = 12;
            s.seed_choking_algorithm = "fastest_upload".into();
            s.unchoke_slot_bandwidth = 32_768;
            s.limit_lan_peers = true;
            s.rate_limit_ip_overhead = true;
            s.max_concurrent_tracker_announces = 24;
            s.max_concurrent_dht_announces = 12;
            s.max_concurrent_lsd_announces = 6;
        }

        let info = build_http_test_info("parity-fields.bin", Some("http://127.0.0.1:9/announce"));
        let hash_hex = hex::encode(info.hash);
        engine.add_torrent(info, dir.path().to_path_buf(), None);
        engine.tracker_circuit_breaker().force_trip("127.0.0.1");

        let app = create_http_router(engine);

        let sess_req = Request::builder()
            .uri("/api/v1/session")
            .body(Body::empty())
            .unwrap();
        let sess_resp = app.clone().oneshot(sess_req).await.unwrap();
        assert_eq!(sess_resp.status(), StatusCode::OK);
        let sess_body = axum::body::to_bytes(sess_resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let sess: serde_json::Value = serde_json::from_slice(&sess_body).unwrap();
        assert_eq!(sess["dht_read_only"], true);
        assert_eq!(sess["zeroconf_enabled"], false);
        assert_eq!(sess["announce_ip"], "127.0.0.1");
        assert_eq!(sess["enable_utp"], true);
        assert_eq!(sess["unchoke_slots_global"], 12);
        assert_eq!(sess["seed_choking_algorithm"], "fastest_upload");
        assert_eq!(sess["unchoke_slot_bandwidth"], 32_768);
        assert_eq!(sess["limit_lan_peers"], true);
        assert_eq!(sess["rate_limit_ip_overhead"], true);
        assert_eq!(sess["max_concurrent_tracker_announces"], 24);
        assert_eq!(sess["max_concurrent_dht_announces"], 12);
        assert_eq!(sess["max_concurrent_lsd_announces"], 6);

        let det_req = Request::builder()
            .uri(format!("/api/v1/torrents/{hash_hex}/detail"))
            .body(Body::empty())
            .unwrap();
        let det_resp = app.oneshot(det_req).await.unwrap();
        assert_eq!(det_resp.status(), StatusCode::OK);
        let det_body = axum::body::to_bytes(det_resp.into_body(), 256 * 1024)
            .await
            .unwrap();
        let det: serde_json::Value = serde_json::from_slice(&det_body).unwrap();
        let trackers = det["trackers"].as_array().expect("trackers array");
        assert_eq!(trackers.len(), 1);
        let t_obj = trackers[0].as_object().unwrap();
        assert!(t_obj.contains_key("is_circuit_broken"));
        assert!(t_obj.contains_key("cb_state"));
        assert!(t_obj.contains_key("recovery_progress_pct"));
        assert!(t_obj.contains_key("last_announce_time"));
    }

    #[tokio::test]
    async fn batch_torrent_endpoints_operate_cleanly_and_report_failures() {
        let dir = tempfile::tempdir().unwrap();
        let dl_dir = dir.path().join("dl");
        std::fs::create_dir_all(&dl_dir).unwrap();

        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
        engine.settings().write().download_dir = dl_dir.clone();

        let info_a = build_http_test_info("batch-a.bin", None);
        let info_b = build_http_test_info("batch-b.bin", None);
        let h_a = hex::encode(info_a.hash);
        let h_b = hex::encode(info_b.hash);
        engine.add_torrent(info_a.clone(), dl_dir.clone(), None);
        engine.add_torrent(info_b, dl_dir.clone(), None);

        let app = create_http_router(engine.clone());

        // Malformed hash returns 400 BAD_REQUEST without side effects.
        let bad_req = Request::builder()
            .method("POST")
            .uri("/api/v1/torrents/batch/pause")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"hashes":["not-hex"]}"#))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(bad_req).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );

        let missing_hex = "ee".repeat(20);
        let body_with_missing = serde_json::json!({
            "hashes": [h_a, h_b, missing_hex],
        })
        .to_string();

        for (uri, expected_state) in [
            (
                "/api/v1/torrents/batch/pause",
                synapse_engine::SwarmState::Stopped,
            ),
            (
                "/api/v1/torrents/batch/resume",
                synapse_engine::SwarmState::Downloading,
            ),
            (
                "/api/v1/torrents/batch/recheck",
                synapse_engine::SwarmState::Checking,
            ),
        ] {
            let req = Request::builder()
                .method("POST")
                .uri(uri)
                .header("Content-Type", "application/json")
                .body(Body::from(body_with_missing.clone()))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
                .await
                .unwrap();
            let parsed: BatchActionResponse = serde_json::from_slice(&bytes).unwrap();
            assert!(!parsed.success);
            assert_eq!(parsed.succeeded, 2);
            assert_eq!(parsed.failed_hashes, vec![missing_hex.clone()]);
            assert_eq!(
                engine.get_torrent(&info_a.hash).unwrap().stats.read().state,
                expected_state
            );
        }

        let payload_a = dl_dir.join(&info_a.name);
        std::fs::write(&payload_a, vec![0x33u8; 32]).unwrap();
        let rem_req = Request::builder()
            .method("POST")
            .uri("/api/v1/torrents/batch/remove")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "hashes": [h_a, h_b, missing_hex],
                    "delete_data": true,
                })
                .to_string(),
            ))
            .unwrap();
        let rem_resp = app.oneshot(rem_req).await.unwrap();
        assert_eq!(rem_resp.status(), StatusCode::OK);
        let rem_bytes = axum::body::to_bytes(rem_resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let rem: BatchActionResponse = serde_json::from_slice(&rem_bytes).unwrap();
        assert!(!rem.success);
        assert_eq!(rem.succeeded, 2);
        assert_eq!(rem.failed_hashes, vec![missing_hex]);
        assert!(engine.list_torrents().is_empty());
        assert!(!payload_a.exists());
    }

    #[tokio::test]
    async fn torrents_stream_emits_initial_snapshot_and_incremental_deltas() {
        use futures::StreamExt;

        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
        engine.settings().write().download_dir = dir.path().to_path_buf();

        let info_1 = build_http_test_info("stream-one.bin", None);
        let hash_1 = hex::encode(info_1.hash);
        engine.add_torrent(info_1.clone(), dir.path().to_path_buf(), None);

        let app = create_http_router(engine.clone());
        let req = Request::builder()
            .uri("/api/v1/torrents/stream?page=1&limit=25&interval_ms=250")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream"));

        let mut stream = resp.into_body().into_data_stream();

        let first = tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await
            .expect("snapshot timed out")
            .expect("stream closed")
            .unwrap();
        let first_text = String::from_utf8_lossy(&first).to_string();
        assert!(first_text.contains("event: snapshot"), "{first_text}");
        assert!(first_text.contains(&hash_1), "{first_text}");
        assert!(first_text.contains("\"stats\""), "{first_text}");

        // Pause torrent 1 and add torrent 2 -> must emit delta with updated/added.
        engine.transition_to_cold(&info_1.hash);
        let info_2 = build_http_test_info("stream-two.bin", None);
        let hash_2 = hex::encode(info_2.hash);
        engine.add_torrent(info_2.clone(), dir.path().to_path_buf(), None);

        let mut collected = String::new();
        tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(chunk) = stream.next().await {
                let bytes = chunk.unwrap();
                collected.push_str(&String::from_utf8_lossy(&bytes));
                if collected.contains("event: delta")
                    && collected.contains(&hash_2)
                    && collected.contains(&hash_1)
                {
                    break;
                }
            }
        })
        .await
        .expect("timed out waiting for add/update delta event");

        // Remove torrent 2 -> must emit delta with removed=[hash_2].
        engine.remove_torrent(&info_2.hash);
        let mut removed_buf = String::new();
        tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(chunk) = stream.next().await {
                let bytes = chunk.unwrap();
                removed_buf.push_str(&String::from_utf8_lossy(&bytes));
                if removed_buf.contains("event: delta")
                    && removed_buf.contains("\"removed\"")
                    && removed_buf.contains(&hash_2)
                {
                    break;
                }
            }
        })
        .await
        .expect("timed out waiting for remove delta event");
    }

    #[tokio::test]
    async fn healthz_and_readyz_probes_distinguish_liveness_from_readiness() {
        let dir = tempfile::tempdir().unwrap();
        let dl_dir = dir.path().join("downloads");
        let sess_dir = dir.path().join("session");
        std::fs::create_dir_all(&dl_dir).unwrap();
        let store =
            Arc::new(synapse_engine::SessionStore::with_key(&sess_dir, [0x7Au8; 32]).unwrap());

        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]).with_session_store(store));
        engine.settings().write().download_dir = dl_dir.clone();
        engine.set_listener_required(false);

        let app = create_http_router(engine.clone());

        // Healthy readyz + healthz
        let live_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(live_resp.status(), StatusCode::OK);

        let ready_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ready_resp.status(), StatusCode::OK);
        let ready_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(ready_resp.into_body(), 16 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ready_body["status"], "ready");
        assert_eq!(ready_body["checks"]["download_dir"], true);
        assert_eq!(ready_body["checks"]["session_db"], true);
        assert_eq!(ready_body["checks"]["listener"], true);

        // Require listener without binding -> healthz still 200 OK, readyz 503 with listener=false
        engine.set_listener_required(true);
        let live_resp2 = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(live_resp2.status(), StatusCode::OK);

        let not_ready_listener = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(not_ready_listener.status(), StatusCode::SERVICE_UNAVAILABLE);
        let listener_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(not_ready_listener.into_body(), 16 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(listener_body["checks"]["listener"], false);

        // Bind listener -> readyz recovers, then delete download_dir -> readyz fails with download_dir=false
        engine
            .clone()
            .start_listener(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let recovered = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recovered.status(), StatusCode::OK);

        std::fs::remove_dir_all(&dl_dir).unwrap();
        let live_missing_dir = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(live_missing_dir.status(), StatusCode::OK);

        let not_ready_dir = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(not_ready_dir.status(), StatusCode::SERVICE_UNAVAILABLE);
        let dir_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(not_ready_dir.into_body(), 16 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(dir_body["checks"]["download_dir"], false);
        assert_eq!(dir_body["checks"]["listener"], true);
    }

    #[tokio::test]
    async fn metrics_handler_exposes_extended_operational_metrics() {
        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
        engine.settings().write().download_dir = dir.path().to_path_buf();

        // Trigger auth failure counter, lag counter, sync duration, and Checking state metric.
        let app = create_http_router_with_auth(engine.clone(), Some("secret-token".to_string()));
        let bad_auth = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/session")
                    .header("Authorization", "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_auth.status(), StatusCode::UNAUTHORIZED);

        engine.record_event_bus_lag(7);
        engine.record_rpc_sync_duration_ms(12);
        engine.metrics_ref().record_state_transition(
            &synapse_engine::SwarmState::Downloading,
            &synapse_engine::SwarmState::Checking,
        );
        engine
            .metrics_ref()
            .last_flush_duration_ms
            .store(5, Ordering::Relaxed);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let text = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), 64 * 1024)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        assert!(text.contains("synapse_torrents_total{state=\"queued\"} 0"));
        assert!(text.contains("synapse_torrents_total{state=\"checking\"} 1"));
        assert!(text.contains("synapse_torrents_total{state=\"error\"} 0"));
        assert!(text.contains("synapse_event_bus_lag_total 7"));
        assert!(text.contains("synapse_auth_failures_total 1"));
        assert!(text.contains("synapse_free_disk_space_bytes "));
        assert!(text.contains("synapse_session_flush_duration_ms 5"));
        assert!(text.contains("synapse_rpc_sync_duration_ms 12"));
    }
}
