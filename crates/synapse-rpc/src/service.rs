use crate::event_bus::EventBus;
use crate::proto::v2::synapse_control_server::SynapseControl;
use crate::proto::v2::*;
use dashmap::DashMap;
use futures::Stream;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

#[derive(Clone)]
pub struct SynapseService {
    event_bus: Arc<EventBus>,
    active_summaries: Arc<DashMap<String, TorrentSummary>>,
    session_stats: Arc<parking_lot::RwLock<SessionStatsUpdate>>,
    swarm_engine: Option<Arc<synapse_engine::SwarmEngine>>,
    base_download_dir: Option<std::path::PathBuf>,
    auth_token: Option<String>,
    rate_limiter: crate::http_api::AuthRateLimiter,
    sync_tick: Arc<std::sync::atomic::AtomicU64>,
    last_roster_version: Arc<std::sync::atomic::AtomicU64>,
    last_queue_version: Arc<std::sync::atomic::AtomicU64>,
    cached_queue_positions: Arc<parking_lot::RwLock<std::collections::HashMap<[u8; 20], u32>>>,
}

/// `sync_from_engine` runs once a second; re-read every torrent's tracker hosts this often.
const TRACKER_HOSTS_REFRESH_TICKS: u64 = 60;

impl SynapseService {
    pub fn new(event_bus: Arc<EventBus>) -> Self {
        let default_stats = SessionStatsUpdate {
            rate_download: 0,
            rate_upload: 0,
            total_downloaded: 0,
            total_uploaded: 0,
            torrent_count: 0,
            active_downloading: 0,
            active_seeding: 0,
            free_disk_space_bytes: 0,
            timestamp_ms: 0,
            dht_nodes: 0,
        };

        Self {
            event_bus,
            active_summaries: Arc::new(DashMap::new()),
            session_stats: Arc::new(parking_lot::RwLock::new(default_stats)),
            swarm_engine: None,
            base_download_dir: None,
            sync_tick: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            auth_token: None,
            rate_limiter: crate::http_api::AuthRateLimiter::default(),
            last_roster_version: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            last_queue_version: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            cached_queue_positions: Arc::new(parking_lot::RwLock::new(
                std::collections::HashMap::new(),
            )),
        }
    }

    pub fn with_swarm_engine(mut self, engine: Arc<synapse_engine::SwarmEngine>) -> Self {
        let free_space = engine.free_disk_space_bytes();
        self.session_stats.write().free_disk_space_bytes = free_space;
        self.base_download_dir = Some(engine.settings().read().download_dir.clone());
        self.swarm_engine = Some(engine);
        self
    }

    pub fn with_auth_token(mut self, auth_token: Option<String>) -> Self {
        self.auth_token = auth_token.filter(|t| !t.trim().is_empty());
        self
    }

    pub fn with_rate_limiter(mut self, rate_limiter: crate::http_api::AuthRateLimiter) -> Self {
        self.rate_limiter = rate_limiter;
        self
    }

    #[allow(clippy::result_large_err)]
    pub fn verify_auth<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if let Some(ref expected) = self.auth_token {
            let client_key = request
                .remote_addr()
                .map(|a| crate::http_api::canonical_ip(a.ip()).to_string())
                .unwrap_or_else(|| "unknown".to_string());
            if self.rate_limiter.is_blocked(&client_key) {
                return Err(Status::resource_exhausted(
                    "Too many failed authentication attempts",
                ));
            }
            let expected_trimmed = expected.trim();
            if expected_trimmed.is_empty() {
                return Err(Status::unauthenticated(
                    "Invalid or missing authorization token",
                ));
            }
            if let Some(auth_header) = request.metadata().get("authorization") {
                if let Ok(val) = auth_header.to_str() {
                    let token = val.strip_prefix("Bearer ").unwrap_or(val).trim();
                    if crate::http_api::constant_time_eq(
                        token.as_bytes(),
                        expected_trimmed.as_bytes(),
                    ) {
                        return Ok(());
                    }
                }
            }
            self.rate_limiter.record_failure(&client_key);
            return Err(Status::unauthenticated(
                "Invalid or missing authorization token",
            ));
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn validate_dir_path(&self, raw: &str) -> Result<std::path::PathBuf, Status> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.contains('\0') {
            return Err(Status::permission_denied(
                "path must not be empty or contain NUL bytes",
            ));
        }
        let candidate = std::path::Path::new(trimmed);
        for comp in candidate.components() {
            if matches!(comp, std::path::Component::ParentDir) {
                return Err(Status::permission_denied(
                    "path must not contain '..' parent directory traversal",
                ));
            }
        }
        if let Some(ref base) = self.base_download_dir {
            crate::http_api::validate_path_under_base(base, candidate)
                .map_err(Status::permission_denied)
        } else {
            Ok(candidate.to_path_buf())
        }
    }

    pub fn upsert_torrent(&self, summary: TorrentSummary) {
        self.active_summaries
            .insert(summary.hash.clone(), summary.clone());
        self.event_bus.emit_summary_added(summary);
    }

    pub fn update_stats(&self, stats: SessionStatsUpdate) {
        *self.session_stats.write() = stats;
    }

    /// Syncs engine state only when at least one `SubscribeTorrents` client is connected.
    pub fn sync_from_engine_if_subscribed(&self) {
        if self.event_bus.subscriber_count() == 0 {
            return;
        }
        self.sync_from_engine();
    }

    /// Diffs live engine state against `active_summaries` and emits accurate add/update/remove
    /// events for anything that changed *without* an RPC call driving it — piece-progress
    /// ticking up, rate/peer/ETA/ratio moving, recheck finishing, an autonomous transition to
    /// Seeding. Every RPC handler above already does an immediate optimistic update+emit for
    /// responsiveness on the action it just performed, but that's necessarily blind to
    /// everything the engine does on its own between calls — this is the belt-and-suspenders
    /// pass that catches the rest, called on a fixed interval (see main.rs) rather than only
    /// reactively. `SubscribeTorrents`/`GetSessionStats`'s streaming sibling both read from the
    /// state this keeps current, not from the engine directly.
    pub fn sync_from_engine(&self) {
        let Some(ref engine) = self.swarm_engine else {
            return;
        };
        let sync_start = std::time::Instant::now();
        let queue_v = engine.queue_version();
        if queue_v
            != self
                .last_queue_version
                .load(std::sync::atomic::Ordering::Acquire)
        {
            let positions = engine.queue_positions();
            *self.cached_queue_positions.write() = positions;
            self.last_queue_version
                .store(queue_v, std::sync::atomic::Ordering::Release);
        }

        let roster_v = engine.roster_version();
        let tick = self
            .sync_tick
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let positions = self.cached_queue_positions.read();

        engine.for_each_torrent_handle(|info_hash, handle| {
            let mut hex_buf = [0u8; 40];
            hex::encode_to_slice(info_hash, &mut hex_buf)
                .expect("20-byte info_hash fits 40 hex bytes");
            let hash_str = std::str::from_utf8(&hex_buf).expect("hex encoding is ASCII");
            let queue_pos = positions.get(info_hash).copied().unwrap_or(0);

            let existing_ref = self.active_summaries.get(hash_str);
            let refresh_hosts = tick.is_multiple_of(TRACKER_HOSTS_REFRESH_TICKS)
                || existing_ref
                    .as_ref()
                    .is_none_or(|o| o.value().tracker_hosts.is_empty());

            if let Some(ref existing) = existing_ref {
                if !refresh_hosts {
                    let old = existing.value();
                    let s = handle.stats.read();
                    let (mapped_state, expected_err): (i32, Option<&str>) = match &s.state {
                        synapse_engine::SwarmState::Stopped => {
                            (TorrentState::StateStopped as i32, None)
                        }
                        synapse_engine::SwarmState::Checking => {
                            (TorrentState::StateChecking as i32, None)
                        }
                        synapse_engine::SwarmState::Queued => {
                            (TorrentState::StateQueued as i32, None)
                        }
                        synapse_engine::SwarmState::Downloading => {
                            (TorrentState::StateDownloading as i32, None)
                        }
                        synapse_engine::SwarmState::Seeding => {
                            (TorrentState::StateSeeding as i32, None)
                        }
                        synapse_engine::SwarmState::Error(msg) => {
                            (TorrentState::StateError as i32, Some(msg.as_str()))
                        }
                    };
                    let meta = handle.metadata.read();
                    let super_seeding = handle
                        .super_seeding
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let first_last = handle
                        .first_last_piece_priority
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let unchanged = old.state == mapped_state
                        && old.error_message.as_deref() == expected_err
                        && (old.progress - s.progress).abs() <= f32::EPSILON
                        && old.rate_download == s.download_rate
                        && old.rate_upload == s.upload_rate
                        && old.peers_connected == s.peers_connected as u32
                        && old.peers_sending == s.peers_sending as u32
                        && old.eta_seconds == s.eta_seconds
                        && (old.ratio - s.ratio).abs() <= f32::EPSILON
                        && old.queue_position == queue_pos
                        && old.name == s.name
                        && old.download_dir == s.download_dir
                        && old.total_size == s.total_size
                        && old.piece_count == s.piece_count
                        && old.piece_size == s.piece_size
                        && old.category == meta.category
                        && old.tags == meta.tags
                        && old.seed_ratio_limit == meta.seed_ratio_limit
                        && old.seed_time_limit_secs == meta.seed_time_limit_secs
                        && old.super_seeding == super_seeding
                        && old.first_last_piece_priority == first_last;
                    if unchanged {
                        return;
                    }
                }
            }

            let existing = existing_ref.map(|r| {
                let cloned = r.value().clone();
                drop(r);
                cloned
            });

            let mut new_summary = {
                let stats = handle.stats.read();
                swarm_stats_to_summary(&stats)
            };
            new_summary.queue_position = queue_pos;
            {
                let meta = handle.metadata.read();
                new_summary.category = meta.category.clone();
                new_summary.tags = meta.tags.clone();
                new_summary.seed_ratio_limit = meta.seed_ratio_limit;
                new_summary.seed_time_limit_secs = meta.seed_time_limit_secs;
            }
            new_summary.super_seeding = handle
                .super_seeding
                .load(std::sync::atomic::Ordering::Relaxed);
            new_summary.first_last_piece_priority = handle
                .first_last_piece_priority
                .load(std::sync::atomic::Ordering::Relaxed);

            new_summary.tracker_hosts = match (&existing, refresh_hosts) {
                (Some(old), false) => old.tracker_hosts.clone(),
                _ => {
                    let reports = engine.tracker_reports_for_handle(handle);
                    tracker_hosts_from_urls(reports.iter().map(|r| r.url.as_str()))
                }
            };

            match existing {
                Some(old) => {
                    let meta_changed = summary_metadata_changed(&old, &new_summary);
                    let delta = diff_summary(&old, &new_summary);
                    if delta.is_some() || meta_changed {
                        self.active_summaries
                            .insert(new_summary.hash.clone(), new_summary.clone());
                    }
                    if meta_changed {
                        self.event_bus.emit_summary_added(new_summary);
                    } else if let Some(delta) = delta {
                        self.event_bus.record_delta(delta);
                    }
                }
                None => self.upsert_torrent(new_summary),
            }
        });

        drop(positions);

        if roster_v
            != self
                .last_roster_version
                .load(std::sync::atomic::Ordering::Acquire)
            || self.active_summaries.len() != engine.torrent_count()
        {
            self.last_roster_version
                .store(roster_v, std::sync::atomic::Ordering::Release);
            let stale: Vec<String> = self
                .active_summaries
                .iter()
                .filter_map(|r| {
                    let k = r.key();
                    (!parse_hash(k).is_some_and(|h| engine.has_torrent(&h))).then(|| k.clone())
                })
                .collect();
            for hash in stale {
                self.active_summaries.remove(&hash);
                self.event_bus.emit_removed(hash);
            }
        }
        engine.record_rpc_sync_duration_ms(sync_start.elapsed().as_millis() as u64);
    }

    /// Companion to `sync_from_engine` for the aggregate session stats — uses O(1) engine
    /// atomic counters so `SubscribeSessionStats` stays O(1) even at 50k swarms.
    pub async fn refresh_session_stats(&self) {
        let Some(ref engine) = self.swarm_engine else {
            return;
        };
        let m = engine.global_metrics();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let free_space = engine.free_disk_space_bytes_async().await;
        let dht_nodes = engine.dht_node_count_fast() as u32;
        self.update_stats(SessionStatsUpdate {
            rate_download: m.download_rate,
            rate_upload: m.upload_rate,
            total_downloaded: m.downloaded_bytes,
            total_uploaded: m.uploaded_bytes,
            torrent_count: m.total_torrents as u32,
            active_downloading: m.downloading_torrents as u32,
            active_seeding: m.seeding_torrents as u32,
            free_disk_space_bytes: free_space,
            timestamp_ms: now_ms,
            dht_nodes,
        });
    }
}

fn swarm_stats_to_summary(s: &synapse_engine::SwarmStats) -> TorrentSummary {
    use synapse_engine::SwarmState;
    let (state, error_message) = match &s.state {
        SwarmState::Stopped => (TorrentState::StateStopped, None),
        SwarmState::Checking => (TorrentState::StateChecking, None),
        SwarmState::Queued => (TorrentState::StateQueued, None),
        SwarmState::Downloading => (TorrentState::StateDownloading, None),
        SwarmState::Seeding => (TorrentState::StateSeeding, None),
        SwarmState::Error(msg) => (TorrentState::StateError, Some(msg.clone())),
    };
    TorrentSummary {
        hash: hex::encode(s.info_hash),
        name: s.name.clone(),
        total_size: s.total_size,
        progress: s.progress,
        state: state as i32,
        rate_download: s.download_rate,
        rate_upload: s.upload_rate,
        peers_connected: s.peers_connected as u32,
        peers_sending: s.peers_sending as u32,
        eta_seconds: s.eta_seconds,
        ratio: s.ratio,
        error_message,
        download_dir: s.download_dir.clone(),
        added_at: s.added_at,
        piece_count: s.piece_count,
        piece_size: s.piece_size,
        queue_position: 0,
        tracker_hosts: Vec::new(),
        category: None,
        tags: Vec::new(),
        seed_ratio_limit: None,
        seed_time_limit_secs: None,
        super_seeding: false,
        first_last_piece_priority: false,
    }
}

/// Distinct tracker hosts (`host[:port]`, never the path/query where passkeys live) for a
/// torrent's announce URLs, in a stable order.
fn tracker_hosts_from_urls<'a>(urls: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut hosts: Vec<String> = urls
        .into_iter()
        .filter_map(|raw| {
            let u = url::Url::parse(raw.trim()).ok()?;
            let host = u.host_str()?;
            Some(match u.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            })
        })
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// Decodes a 40-character hex info hash.
fn parse_hash(hex_hash: &str) -> Option<[u8; 20]> {
    let bytes = hex::decode(hex_hash).ok()?;
    <[u8; 20]>::try_from(bytes.as_slice()).ok()
}

fn command_result(ok: bool, error: impl Into<String>) -> Response<CommandResponse> {
    Response::new(CommandResponse {
        success: ok,
        error: (!ok).then(|| error.into()),
    })
}

fn circuit_state_to_proto(state: synapse_tracker::CircuitState) -> CircuitBreakerState {
    match state {
        synapse_tracker::CircuitState::Healthy => CircuitBreakerState::CbHealthy,
        synapse_tracker::CircuitState::Tripped => CircuitBreakerState::CbTripped,
        synapse_tracker::CircuitState::HalfOpenCanary => CircuitBreakerState::CbHalfOpenCanary,
        synapse_tracker::CircuitState::Recovering => CircuitBreakerState::CbRecovering,
    }
}

fn host_status_to_proto(
    host: String,
    breaker: &synapse_tracker::CanaryCircuitBreaker,
    info: synapse_tracker::HostCircuitInfo,
) -> CircuitBreakerStatus {
    CircuitBreakerStatus {
        host,
        state: circuit_state_to_proto(info.state) as i32,
        consecutive_successes: info.consecutive_successes,
        consecutive_failures: info.consecutive_failures,
        backoff_remaining_ms: breaker.backoff_remaining_ms(&info),
        recovery_progress_pct: breaker.recovery_progress_pct(&info),
    }
}

fn summary_metadata_changed(old: &TorrentSummary, new: &TorrentSummary) -> bool {
    old.name != new.name
        || old.total_size != new.total_size
        || old.download_dir != new.download_dir
        || old.piece_count != new.piece_count
        || old.piece_size != new.piece_size
        || old.tracker_hosts != new.tracker_hosts
        || old.category != new.category
        || old.tags != new.tags
        || old.seed_ratio_limit != new.seed_ratio_limit
        || old.seed_time_limit_secs != new.seed_time_limit_secs
        || old.super_seeding != new.super_seeding
        || old.first_last_piece_priority != new.first_last_piece_priority
}

/// `None` when nothing actually changed — callers use this to avoid emitting a no-op delta
/// every sync tick for a torrent that's genuinely idle (e.g. fully seeded, no peers).
fn diff_summary(old: &TorrentSummary, new: &TorrentSummary) -> Option<TorrentDelta> {
    let mut delta = TorrentDelta {
        hash: new.hash.clone(),
        ..Default::default()
    };
    let mut changed = false;

    if (old.progress - new.progress).abs() > f32::EPSILON {
        delta.progress = Some(new.progress);
        changed = true;
    }
    if old.state != new.state {
        delta.state = Some(new.state);
        changed = true;
    }
    if old.rate_download != new.rate_download {
        delta.rate_download = Some(new.rate_download);
        changed = true;
    }
    if old.rate_upload != new.rate_upload {
        delta.rate_upload = Some(new.rate_upload);
        changed = true;
    }
    if old.peers_connected != new.peers_connected {
        delta.peers_connected = Some(new.peers_connected);
        changed = true;
    }
    if old.peers_sending != new.peers_sending {
        delta.peers_sending = Some(new.peers_sending);
        changed = true;
    }
    if old.eta_seconds != new.eta_seconds {
        delta.eta_seconds = Some(new.eta_seconds);
        changed = true;
    }
    if (old.ratio - new.ratio).abs() > f32::EPSILON {
        delta.ratio = Some(new.ratio);
        changed = true;
    }
    if old.error_message != new.error_message {
        delta.error_message = Some(new.error_message.clone().unwrap_or_default());
        changed = true;
    }
    if old.queue_position != new.queue_position {
        delta.queue_position = Some(new.queue_position);
        changed = true;
    }

    changed.then_some(delta)
}

#[tonic::async_trait]
impl SynapseControl for SynapseService {
    type SubscribeTorrentsStream =
        Pin<Box<dyn Stream<Item = Result<TorrentListEvent, Status>> + Send + 'static>>;

    async fn subscribe_torrents(
        &self,
        request: Request<SubscribeTorrentsRequest>,
    ) -> Result<Response<Self::SubscribeTorrentsStream>, Status> {
        self.verify_auth(&request)?;
        let req = request.into_inner();
        let chunk_size = if req.chunk_size == 0 {
            500
        } else {
            req.chunk_size as usize
        };

        if self.swarm_engine.is_some() && self.event_bus.subscriber_count() == 0 {
            self.sync_from_engine();
        }
        let rx = self.event_bus.subscribe();
        let summaries: Vec<TorrentSummary> = self
            .active_summaries
            .iter()
            .map(|r| r.value().clone())
            .collect();

        let chunks: Vec<Vec<TorrentSummary>> =
            summaries.chunks(chunk_size).map(|c| c.to_vec()).collect();

        let total_chunks = chunks.len().max(1) as u32;
        let mut snapshot_events = Vec::new();

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        if chunks.is_empty() {
            snapshot_events.push(TorrentListEvent {
                sequence_id: 0,
                timestamp_ms: now_ms,
                event: Some(torrent_list_event::Event::Snapshot(TorrentSnapshotChunk {
                    items: Vec::new(),
                    chunk_index: 0,
                    total_chunks: 1,
                    is_last_chunk: true,
                })),
            });
        } else {
            for (idx, chunk) in chunks.into_iter().enumerate() {
                let is_last = (idx + 1) == total_chunks as usize;
                snapshot_events.push(TorrentListEvent {
                    sequence_id: 0,
                    timestamp_ms: now_ms,
                    event: Some(torrent_list_event::Event::Snapshot(TorrentSnapshotChunk {
                        items: chunk,
                        chunk_index: idx as u32,
                        total_chunks,
                        is_last_chunk: is_last,
                    })),
                });
            }
        }

        let event_bus = self.event_bus.clone();
        let swarm_for_lag = self.swarm_engine.clone();
        let live_stream = BroadcastStream::new(rx).filter_map(move |res| match res {
            Ok(item) => Some(Ok(item)),
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(skipped)) => {
                event_bus.record_lag(skipped);
                if let Some(ref engine) = swarm_for_lag {
                    engine.record_event_bus_lag(skipped);
                }
                Some(Err(Status::resource_exhausted(format!(
                    "torrent event stream lagged by {} events; resync required",
                    skipped
                ))))
            }
        });

        let snapshot_stream = tokio_stream::iter(snapshot_events.into_iter().map(Ok));
        let combined = snapshot_stream.chain(live_stream);

        Ok(Response::new(Box::pin(combined)))
    }

    type SubscribeSessionStatsStream =
        Pin<Box<dyn Stream<Item = Result<SessionStatsUpdate, Status>> + Send + 'static>>;

    async fn subscribe_session_stats(
        &self,
        request: Request<SessionStatsRequest>,
    ) -> Result<Response<Self::SubscribeSessionStatsStream>, Status> {
        self.verify_auth(&request)?;
        let stats_lock = self.session_stats.clone();
        let stream = async_stream::stream! {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(1000));
            loop {
                interval.tick().await;
                let mut current = *stats_lock.read();
                current.timestamp_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                yield Ok(current);
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    type SubscribeTorrentDetailStream =
        Pin<Box<dyn Stream<Item = Result<TorrentDetailEvent, Status>> + Send + 'static>>;

    async fn subscribe_torrent_detail(
        &self,
        request: Request<TorrentDetailRequest>,
    ) -> Result<Response<Self::SubscribeTorrentDetailStream>, Status> {
        self.verify_auth(&request)?;
        let req = request.into_inner();
        let hash = req.hash;
        let interval_ms = if req.refresh_interval_ms == 0 {
            1000
        } else {
            (req.refresh_interval_ms as u64).max(100)
        };
        let swarm_opt = self.swarm_engine.clone();

        let stream = async_stream::stream! {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(interval_ms));
            let hash_bytes = hex::decode(&hash).ok().and_then(|b| {
                if b.len() == 20 {
                    let mut arr = [0u8; 20];
                    arr.copy_from_slice(&b);
                    Some(arr)
                } else {
                    None
                }
            });

            loop {
                interval.tick().await;
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;

                let mut files = Vec::new();
                let mut trackers = Vec::new();
                let mut active_peers = Vec::new();
                let mut piece_bitfield = Vec::new();
                let mut piece_count = 0u32;
                let mut piece_size = 0u32;
                let mut availability = Vec::new();
                if let (Some(ref swarm), Some(ref hb)) = (&swarm_opt, &hash_bytes) {
                    if let Some(handle) = swarm.get_torrent(hb) {
                        piece_count = handle.info.pieces();
                        piece_size = handle.info.piece_len;
                        let total_pieces = piece_count as usize;
                        let is_seeding = handle.stats.read().state == synapse_engine::SwarmState::Seeding;

                        let bf_guard = handle.compressed_bitfield.read();
                        let uncompressed_bf = bf_guard.as_ref().map(|b| b.to_bitfield());
                        if let Some(ref bf) = uncompressed_bf {
                            piece_bitfield = bf.as_bytes().to_vec();
                        } else if is_seeding {
                            let mut full_bf = synapse_picker::Bitfield::new(total_pieces);
                            for i in 0..total_pieces {
                                full_bf.set(i);
                            }
                            piece_bitfield = full_bf.as_bytes().to_vec();
                        } else {
                            let empty_bf = synapse_picker::Bitfield::new(total_pieces);
                            piece_bitfield = empty_bf.as_bytes().to_vec();
                        }

                        availability = handle.piece_availability_snapshot();

                        let file_priorities = handle.file_priorities.read().clone();
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
                                let prog = (done as f64 / f.length as f64) as f32;
                                (done, prog.min(1.0))
                            } else {
                                (0, 0.0)
                            };

                            files.push(FileProgress {
                                index: idx as u32,
                                path: f.path.to_string_lossy().to_string(),
                                size_bytes: f.length,
                                bytes_completed,
                                progress,
                                priority: u32::from(file_priorities.get(idx).copied().unwrap_or(4)),
                            });
                        }

                        let reports = swarm.get_tracker_reports(hb);
                        for rep in reports {
                            trackers.push(TrackerStatus {
                                url: rep.url,
                                status: rep.status,
                                seeders: rep.seeders,
                                leechers: rep.leechers,
                                next_announce_in: rep.next_announce_in,
                                failure_reason: rep.failure_reason,
                                is_circuit_broken: rep.is_circuit_broken,
                                cb_state: rep.cb_state.map(circuit_state_to_proto).map(|s| s as i32),
                                recovery_progress_pct: rep.recovery_progress_pct,
                                last_announce_time: rep.last_announce_time,
                            });
                        }

                        let live_peers_snapshot = handle.live_peers.read().clone();
                        for p in live_peers_snapshot {
                            active_peers.push(PeerDetail {
                                address: p.addr.to_string(),
                                client_name: p.client_name,
                                flags: p.flags,
                                rate_to_client: p.rate_to_client,
                                rate_to_peer: p.rate_to_peer,
                                progress: p.progress,
                                is_encrypted: p.is_encrypted,
                                is_utp: p.is_utp,
                                country_code: None,
                                as_name: None,
                            });
                        }
                    }
                }

                let discovery = if let (Some(ref swarm), Some(ref hb)) = (&swarm_opt, &hash_bytes) {
                    swarm.swarm_discovery_stats(hb)
                } else {
                    synapse_engine::SwarmDiscoveryStats::default()
                };

                let detail = TorrentDetailEvent {
                    hash: hash.clone(),
                    timestamp_ms: now_ms,
                    active_peers,
                    trackers,
                    files,
                    piece_bitfield,
                    piece_count,
                    piece_size,
                    availability,
                    candidate_peers: discovery.candidate_peers as u32,
                    active_dials: discovery.active_dials as u32,
                    is_private: discovery.is_private,
                    allows_dht: discovery.dht_allowed,
                    allows_pex: discovery.pex_allowed,
                    allows_lsd: discovery.lsd_allowed,
                    pex_peers: discovery.pex_peers as u32,
                    discovered_from_tracker: discovery.discovered_from_tracker,
                    discovered_from_dht: discovery.discovered_from_dht,
                    discovered_from_pex: discovery.discovered_from_pex,
                    discovered_from_lsd: discovery.discovered_from_lsd,
                    webseeds: discovery.webseeds,
                };
                yield Ok(detail);
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    type SubscribeAlertsStream =
        Pin<Box<dyn Stream<Item = Result<AlertEvent, Status>> + Send + 'static>>;

    async fn subscribe_alerts(
        &self,
        request: Request<SubscribeAlertsRequest>,
    ) -> Result<Response<Self::SubscribeAlertsStream>, Status> {
        self.verify_auth(&request)?;
        let req = request.into_inner();
        let filter_hash = req.info_hash.and_then(|h| {
            let trimmed = h.trim();
            if trimmed.is_empty() {
                None
            } else {
                hex::decode(trimmed).ok().and_then(|bytes| {
                    if bytes.len() == 20 {
                        let mut arr = [0u8; 20];
                        arr.copy_from_slice(&bytes);
                        Some(arr)
                    } else {
                        None
                    }
                })
            }
        });

        let rx_opt = self.swarm_engine.as_ref().map(|s| s.subscribe_alerts());

        let stream = async_stream::stream! {
            if let Some(mut rx) = rx_opt {
                loop {
                    match rx.recv().await {
                        Ok(alert) => {
                            if let Some(ref filter) = filter_hash {
                                if *filter != alert.info_hash() {
                                    continue;
                                }
                            }
                            let now_ms = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as i64;
                            let json = crate::http_api::alert_to_json(&alert);
                            let event_type = json["type"].as_str().unwrap_or("alert").to_string();
                            let info_hash_hex = hex::encode(alert.info_hash());

                            yield Ok(AlertEvent {
                                event_type,
                                payload_json: json.to_string(),
                                timestamp_ms: now_ms,
                                info_hash: Some(info_hash_hex),
                            });
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_skipped)) => {
                            continue;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    async fn add_torrent(
        &self,
        request: Request<AddTorrentRequest>,
    ) -> Result<Response<AddTorrentResponse>, Status> {
        self.verify_auth(&request)?;
        let req = request.into_inner();
        let dl_dir = match req
            .download_dir
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
        {
            Some(custom_dir) => {
                let validated = self.validate_dir_path(custom_dir)?;
                validated.to_string_lossy().into_owned()
            }
            None => self
                .swarm_engine
                .as_ref()
                .map(|s| {
                    s.settings()
                        .read()
                        .download_dir
                        .to_string_lossy()
                        .into_owned()
                })
                .unwrap_or_else(|| "/downloads".into()),
        };

        let (hash, name, total_size, info_opt) = match req.source {
            Some(add_torrent_request::Source::MagnetUri(uri)) => {
                if let Ok(info) = synapse_meta::Info::from_magnet(&uri) {
                    (
                        hex::encode(info.hash),
                        info.name.clone(),
                        info.total_len,
                        Some(info),
                    )
                } else {
                    return Ok(Response::new(AddTorrentResponse {
                        success: false,
                        hash: String::new(),
                        name: String::new(),
                        error: Some("Invalid magnet URI".into()),
                    }));
                }
            }
            Some(add_torrent_request::Source::TorrentBytes(bytes)) => {
                if bytes.len() > synapse_meta::MAX_TORRENT_FILE_BYTES {
                    return Ok(Response::new(AddTorrentResponse {
                        success: false,
                        hash: String::new(),
                        name: String::new(),
                        error: Some("Torrent payload exceeds the maximum accepted size".into()),
                    }));
                }
                if let Ok(bencode) = synapse_bencode::decode_buf(&bytes) {
                    if let Ok(info) = synapse_meta::Info::from_bencode(bencode) {
                        (
                            hex::encode(info.hash),
                            info.name.clone(),
                            info.total_len,
                            Some(info),
                        )
                    } else {
                        return Ok(Response::new(AddTorrentResponse {
                            success: false,
                            hash: String::new(),
                            name: String::new(),
                            error: Some("Invalid torrent metadata in bencode".into()),
                        }));
                    }
                } else {
                    return Ok(Response::new(AddTorrentResponse {
                        success: false,
                        hash: String::new(),
                        name: String::new(),
                        error: Some("Failed to decode bencode bytes".into()),
                    }));
                }
            }
            Some(add_torrent_request::Source::TorrentUrl(url)) => {
                match crate::url_fetcher::fetch_or_parse_torrent(&url).await {
                    Ok(info) => (
                        hex::encode(info.hash),
                        info.name.clone(),
                        info.total_len,
                        Some(info),
                    ),
                    Err(e) => {
                        return Ok(Response::new(AddTorrentResponse {
                            success: false,
                            hash: String::new(),
                            name: String::new(),
                            error: Some(format!("Failed to fetch or parse torrent URL: {e}")),
                        }));
                    }
                }
            }
            Some(add_torrent_request::Source::FilePath(path)) => {
                let safe_path = self.validate_dir_path(&path)?;
                let is_torrent_ext = safe_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("torrent"));
                if !is_torrent_ext {
                    return Err(Status::permission_denied(
                        "FilePath must be a valid .torrent file inside the download directory",
                    ));
                }
                match tokio::fs::symlink_metadata(&safe_path).await {
                    Ok(meta) if meta.file_type().is_file() => {}
                    Ok(_) => {
                        return Err(Status::permission_denied(
                            "FilePath must point to a regular file, not a symlink or directory",
                        ));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(Response::new(AddTorrentResponse {
                            success: false,
                            hash: String::new(),
                            name: String::new(),
                            error: Some(format!("Torrent file not found: {e}")),
                        }));
                    }
                    Err(e) => {
                        return Err(Status::permission_denied(format!(
                            "Cannot inspect FilePath: {e}"
                        )));
                    }
                }
                match crate::url_fetcher::read_torrent_file(&safe_path).await {
                    Ok(bytes) => {
                        if let Ok(bencode) = synapse_bencode::decode_buf(&bytes) {
                            if let Ok(info) = synapse_meta::Info::from_bencode(bencode) {
                                (
                                    hex::encode(info.hash),
                                    info.name.clone(),
                                    info.total_len,
                                    Some(info),
                                )
                            } else {
                                return Ok(Response::new(AddTorrentResponse {
                                    success: false,
                                    hash: String::new(),
                                    name: String::new(),
                                    error: Some("Invalid torrent metadata in file".into()),
                                }));
                            }
                        } else {
                            return Ok(Response::new(AddTorrentResponse {
                                success: false,
                                hash: String::new(),
                                name: String::new(),
                                error: Some("Failed to decode bencode from file".into()),
                            }));
                        }
                    }
                    Err(e) => {
                        return Ok(Response::new(AddTorrentResponse {
                            success: false,
                            hash: String::new(),
                            name: String::new(),
                            error: Some(format!("Failed to read torrent file: {e}")),
                        }));
                    }
                }
            }
            _ => ("unknown_hash".to_string(), "Unknown".to_string(), 0, None),
        };

        let start_paused = req.start_paused.unwrap_or_else(|| {
            self.swarm_engine
                .as_ref()
                .map(|s| !s.settings().read().start_added_torrents)
                .unwrap_or(false)
        });

        let (piece_count, piece_size) = if let Some(ref info) = info_opt {
            (info.pieces(), info.piece_len)
        } else {
            (0, 0)
        };

        if let Some(info) = info_opt {
            if let Some(ref swarm) = self.swarm_engine {
                if let Err(error) = swarm.check_signature_policy(&info) {
                    return Ok(Response::new(AddTorrentResponse {
                        success: false,
                        hash: String::new(),
                        name: String::new(),
                        error: Some(error),
                    }));
                }
                let info_hash = info.hash;
                swarm.add_torrent(Arc::new(info), std::path::PathBuf::from(&dl_dir), None);
                if start_paused {
                    swarm.transition_to_cold(&info_hash);
                }
            }
        }

        let summary = TorrentSummary {
            hash: hash.clone(),
            name: name.clone(),
            total_size,
            progress: 0.0,
            state: if start_paused {
                TorrentState::StateStopped as i32
            } else {
                TorrentState::StateDownloading as i32
            },
            rate_download: 0,
            rate_upload: 0,
            peers_connected: 0,
            peers_sending: 0,
            eta_seconds: 0,
            ratio: 0.0,
            error_message: None,
            download_dir: dl_dir,
            added_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            piece_count,
            piece_size,
            queue_position: 0,
            // Filled in by the next `sync_from_engine` pass (announce data isn't known yet).
            tracker_hosts: Vec::new(),
            category: None,
            tags: Vec::new(),
            seed_ratio_limit: None,
            seed_time_limit_secs: None,
            super_seeding: false,
            first_last_piece_priority: false,
        };

        self.upsert_torrent(summary);

        Ok(Response::new(AddTorrentResponse {
            success: true,
            hash,
            name: name.clone(),
            error: None,
        }))
    }

    async fn remove_torrent(
        &self,
        request: Request<RemoveTorrentRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        self.verify_auth(&request)?;
        let req = request.into_inner();
        let hash = req.hash.to_lowercase();
        if let Some(arr) = parse_hash(&hash) {
            if let Some(ref swarm) = self.swarm_engine {
                let target_info = swarm.get_torrent(&arr).map(|h| {
                    let s = h.stats.read();
                    (s.download_dir.clone(), s.name.clone())
                });
                if swarm.remove_torrent(&arr) && req.delete_data {
                    if let Some((dl_dir_str, torrent_name)) = target_info {
                        let base = self
                            .base_download_dir
                            .clone()
                            .unwrap_or_else(|| swarm.settings().read().download_dir.clone());
                        let _ = tokio::task::spawn_blocking(move || {
                            crate::http_api::delete_torrent_data_under_base(
                                &base,
                                &dl_dir_str,
                                &torrent_name,
                            );
                        })
                        .await;
                    }
                }
            }
        }
        if hash != req.hash {
            self.active_summaries.remove(&req.hash);
        }
        self.active_summaries.remove(&hash);
        self.event_bus.emit_removed(hash);
        Ok(Response::new(CommandResponse {
            success: true,
            error: None,
        }))
    }

    async fn pause_torrent(
        &self,
        request: Request<TorrentHashRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        self.verify_auth(&request)?;
        let raw_hash = request.into_inner().hash;
        let hash = raw_hash.to_lowercase();
        if let Some(arr) = parse_hash(&hash) {
            if let Some(ref swarm) = self.swarm_engine {
                swarm.transition_to_cold(&arr);
            }
        }
        if let Some(mut item) = self.active_summaries.get_mut(&hash) {
            let cleared_error = item.error_message.take().map(|_| String::new());
            item.state = TorrentState::StateStopped as i32;
            item.rate_download = 0;
            item.rate_upload = 0;
            item.peers_connected = 0;
            item.peers_sending = 0;
            self.event_bus.record_delta(TorrentDelta {
                hash,
                state: Some(TorrentState::StateStopped as i32),
                rate_download: Some(0),
                rate_upload: Some(0),
                peers_connected: Some(0),
                peers_sending: Some(0),
                error_message: cleared_error,
                ..Default::default()
            });
        }
        Ok(Response::new(CommandResponse {
            success: true,
            error: None,
        }))
    }

    async fn resume_torrent(
        &self,
        request: Request<TorrentHashRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        self.verify_auth(&request)?;
        let raw_hash = request.into_inner().hash;
        let hash = raw_hash.to_lowercase();
        if let Some(arr) = parse_hash(&hash) {
            if let Some(ref swarm) = self.swarm_engine {
                swarm.transition_to_hot(&arr);
            }
        }
        if let Some(mut item) = self.active_summaries.get_mut(&hash) {
            let cleared_error = item.error_message.take().map(|_| String::new());
            let target_state = if item.progress >= 1.0 {
                TorrentState::StateSeeding as i32
            } else {
                TorrentState::StateDownloading as i32
            };
            item.state = target_state;
            self.event_bus.record_delta(TorrentDelta {
                hash,
                state: Some(target_state),
                error_message: cleared_error,
                ..Default::default()
            });
        }
        Ok(Response::new(CommandResponse {
            success: true,
            error: None,
        }))
    }

    async fn recheck_torrent(
        &self,
        request: Request<TorrentHashRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        self.verify_auth(&request)?;
        let hash = request.into_inner().hash.to_lowercase();
        if let Some(arr) = parse_hash(&hash) {
            if let Some(ref swarm) = self.swarm_engine {
                swarm.recheck_torrent(&arr);
            }
        }
        if let Some(mut item) = self.active_summaries.get_mut(&hash) {
            let cleared_error = item.error_message.take().map(|_| String::new());
            item.state = TorrentState::StateChecking as i32;
            self.event_bus.record_delta(TorrentDelta {
                hash,
                state: Some(TorrentState::StateChecking as i32),
                error_message: cleared_error,
                ..Default::default()
            });
        }
        Ok(Response::new(CommandResponse {
            success: true,
            error: None,
        }))
    }

    async fn set_file_priority(
        &self,
        request: Request<FilePriorityRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        self.verify_auth(&request)?;
        let req = request.into_inner();
        if let Ok(bytes) = hex::decode(&req.hash) {
            if bytes.len() == 20 {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&bytes);
                if let Some(ref swarm) = self.swarm_engine {
                    swarm.set_file_priority(&arr, req.file_index, req.priority as u8);
                }
            }
        }
        Ok(Response::new(CommandResponse {
            success: true,
            error: None,
        }))
    }

    async fn set_location(
        &self,
        request: Request<SetLocationRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        self.verify_auth(&request)?;
        let req = request.into_inner();
        let hash = req.hash.to_lowercase();
        let validated = self.validate_dir_path(&req.new_download_dir)?;
        let validated_str = validated.to_string_lossy().into_owned();
        if let Some(ref swarm) = self.swarm_engine {
            let Some(arr) = parse_hash(&hash) else {
                return Err(Status::invalid_argument("malformed info hash"));
            };
            let engine = swarm.clone();
            let dir_arg = validated_str.clone();
            let move_files = req.move_existing_files.unwrap_or(true);
            let ok = tokio::task::spawn_blocking(move || {
                engine.set_location_with_options(&arr, &dir_arg, move_files)
            })
            .await
            .map_err(|e| Status::internal(format!("set_location failed: {e}")))?;
            if !ok {
                return Ok(command_result(
                    false,
                    "torrent not found or failed to set location",
                ));
            }
        }
        let updated = if let Some(mut item) = self.active_summaries.get_mut(&hash) {
            item.download_dir = validated_str;
            Some(item.clone())
        } else {
            None
        };
        if let Some(summary) = updated {
            self.event_bus.emit_summary_added(summary);
        }
        Ok(Response::new(CommandResponse {
            success: true,
            error: None,
        }))
    }

    async fn set_rate_limits(
        &self,
        request: Request<RateLimitsRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        self.verify_auth(&request)?;
        let req = request.into_inner();
        if let Some(ref swarm) = self.swarm_engine {
            if req.global_download_limit.is_some() || req.global_upload_limit.is_some() {
                swarm.update_global_rate_limits(req.global_download_limit, req.global_upload_limit);
            }
            if let Some(ref raw_hash) = req.per_torrent_hash {
                let Some(arr) = parse_hash(raw_hash.trim()) else {
                    return Err(Status::invalid_argument("malformed per_torrent_hash"));
                };
                if !swarm.set_torrent_rate_limits(
                    &arr,
                    req.torrent_download_limit,
                    req.torrent_upload_limit,
                ) {
                    return Ok(command_result(false, "torrent not found"));
                }
            }
        }
        Ok(Response::new(CommandResponse {
            success: true,
            error: None,
        }))
    }

    async fn get_session_stats(
        &self,
        request: Request<SessionStatsRequest>,
    ) -> Result<Response<SessionStatsUpdate>, Status> {
        self.verify_auth(&request)?;
        if let Some(ref engine) = self.swarm_engine {
            let m = engine.global_metrics();
            let free_space = engine.free_disk_space_bytes_async().await;
            let dht_nodes = engine.dht_node_count_fast() as u32;
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            return Ok(Response::new(SessionStatsUpdate {
                rate_download: m.download_rate,
                rate_upload: m.upload_rate,
                total_downloaded: m.downloaded_bytes,
                total_uploaded: m.uploaded_bytes,
                torrent_count: m.total_torrents as u32,
                active_downloading: m.downloading_torrents as u32,
                active_seeding: m.seeding_torrents as u32,
                free_disk_space_bytes: free_space,
                timestamp_ms: now_ms,
                dht_nodes,
            }));
        }
        let stats = *self.session_stats.read();
        Ok(Response::new(stats))
    }

    async fn get_session_settings(
        &self,
        request: Request<SessionSettingsRequest>,
    ) -> Result<Response<SessionSettingsResponse>, Status> {
        self.verify_auth(&request)?;
        let Some(ref engine) = self.swarm_engine else {
            return Err(Status::unavailable("SwarmEngine not configured"));
        };

        let s = engine.get_session_settings();
        let is_alt_speed_active = engine.is_alt_speed_active();

        Ok(Response::new(SessionSettingsResponse {
            download_limit_enabled: s.download_limit_enabled,
            download_limit_bytes: s.download_limit_bytes,
            upload_limit_enabled: s.upload_limit_enabled,
            upload_limit_bytes: s.upload_limit_bytes,

            alt_speed_enabled: s.alt_speed_enabled,
            alt_speed_down_bytes: s.alt_speed_down_bytes,
            alt_speed_up_bytes: s.alt_speed_up_bytes,
            alt_speed_time_enabled: s.alt_speed_time_enabled,
            alt_speed_time_begin: s.alt_speed_time_begin,
            alt_speed_time_end: s.alt_speed_time_end,
            alt_speed_time_days: s.alt_speed_time_days,

            download_queue_enabled: s.queue.download_queue_enabled,
            download_queue_size: s.queue.max_active_downloads as u32,
            seed_queue_enabled: s.queue.seed_queue_enabled,
            seed_queue_size: s.queue.max_active_seeds as u32,
            max_active_torrents: s.queue.max_active_torrents as u32,
            queue_stalled_enabled: s.queue.queue_stalled_enabled,
            queue_stalled_minutes: s.queue.queue_stalled_minutes,
            seed_ratio_limited: s.queue.seed_ratio_limited,
            seed_ratio_limit: s.queue.share_ratio_limit.unwrap_or(0.0),
            idle_seeding_limit_enabled: s.queue.idle_seeding_limit_enabled,
            idle_seeding_limit_minutes: s.queue.idle_seeding_limit_minutes().unwrap_or(0),

            max_peers_per_torrent: s.max_peers_per_torrent as u32,
            max_global_peers: s.max_global_peers as u32,
            dht_enabled: s.dht_enabled,
            pex_enabled: s.pex_enabled,
            lsd_enabled: s.lsd_enabled,
            encryption: s.encryption,

            download_dir: s.download_dir.to_string_lossy().into_owned(),
            incomplete_dir: s.incomplete_dir.map(|p| p.to_string_lossy().into_owned()),
            incomplete_dir_enabled: s.incomplete_dir_enabled,
            start_added_torrents: s.start_added_torrents,
            trash_original_torrent_files: s.trash_original_torrent_files,
            is_alt_speed_active,
            enable_utp: s.enable_utp,
            dht_read_only: s.dht_read_only,
            zeroconf_enabled: s.zeroconf_enabled,
            announce_ip: s.announce_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        }))
    }

    async fn update_session_settings(
        &self,
        request: Request<UpdateSessionSettingsRequest>,
    ) -> Result<Response<UpdateSessionSettingsResponse>, Status> {
        self.verify_auth(&request)?;
        let Some(ref engine) = self.swarm_engine else {
            return Err(Status::unavailable("SwarmEngine not configured"));
        };

        let mut req = request.into_inner();
        if let Some(ref dl_dir) = req.download_dir {
            if !dl_dir.trim().is_empty() {
                let canonical = self.validate_dir_path(dl_dir)?;
                req.download_dir = Some(canonical.to_string_lossy().into_owned());
            }
        }
        if let Some(ref inc_dir) = req.incomplete_dir {
            if !inc_dir.trim().is_empty() {
                let canonical = self.validate_dir_path(inc_dir)?;
                req.incomplete_dir = Some(canonical.to_string_lossy().into_owned());
            }
        }
        let update = synapse_engine::SessionSettingsUpdate {
            download_limit_enabled: req.download_limit_enabled,
            download_limit_bytes: req.download_limit_bytes,
            upload_limit_enabled: req.upload_limit_enabled,
            upload_limit_bytes: req.upload_limit_bytes,

            alt_speed_enabled: req.alt_speed_enabled,
            alt_speed_down_bytes: req.alt_speed_down_bytes,
            alt_speed_up_bytes: req.alt_speed_up_bytes,
            alt_speed_time_enabled: req.alt_speed_time_enabled,
            alt_speed_time_begin: req.alt_speed_time_begin,
            alt_speed_time_end: req.alt_speed_time_end,
            alt_speed_time_days: req.alt_speed_time_days,

            download_queue_enabled: req.download_queue_enabled,
            download_queue_size: req.download_queue_size.map(|v| v as usize),
            seed_queue_enabled: req.seed_queue_enabled,
            seed_queue_size: req.seed_queue_size.map(|v| v as usize),
            max_active_torrents: req.max_active_torrents.map(|v| v as usize),
            queue_stalled_enabled: req.queue_stalled_enabled,
            queue_stalled_minutes: req.queue_stalled_minutes,
            seed_ratio_limited: req.seed_ratio_limited,
            seed_ratio_limit: req.seed_ratio_limit,
            idle_seeding_limit_enabled: req.idle_seeding_limit_enabled,
            idle_seeding_limit_minutes: req.idle_seeding_limit_minutes,

            max_peers_per_torrent: req.max_peers_per_torrent.map(|v| v as usize),
            max_global_peers: req.max_global_peers.map(|v| v as usize),
            dht_enabled: req.dht_enabled,
            pex_enabled: req.pex_enabled,
            lsd_enabled: req.lsd_enabled,
            enable_utp: req.enable_utp,
            dht_read_only: req.dht_read_only,
            zeroconf_enabled: req.zeroconf_enabled,
            announce_ip: req.announce_ip,
            encryption: req.encryption,

            download_dir: req.download_dir,
            incomplete_dir: req.incomplete_dir,
            incomplete_dir_enabled: req.incomplete_dir_enabled,
            start_added_torrents: req.start_added_torrents,
            trash_original_torrent_files: req.trash_original_torrent_files,

            peer_port: req.peer_port.map(|p| p as u16),
            rpc_listen_addr: req.rpc_listen_addr,
            http_listen_addr: req.http_listen_addr,
            ..Default::default()
        };

        let warnings = engine.update_session_settings(update);
        Ok(Response::new(UpdateSessionSettingsResponse {
            success: true,
            warnings,
            error: None,
        }))
    }

    async fn get_capabilities(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<CapabilitiesResponse>, Status> {
        self.verify_auth(&request)?;
        Ok(Response::new(CapabilitiesResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            features: [
                "tracker_circuit_breaker_v1",
                "queue_move_v1",
                "sequential_download_v1",
                "reannounce_v1",
                "replace_trackers_v1",
                "ip_filter_reload_v1",
                "super_seeding_v1",
                "first_last_piece_priority_v1",
                "torrent_metadata_v1",
                "torrent_export_v1",
            ]
            .map(String::from)
            .to_vec(),
        }))
    }

    async fn list_circuit_breakers(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<CircuitBreakerListResponse>, Status> {
        self.verify_auth(&request)?;
        let Some(ref engine) = self.swarm_engine else {
            return Ok(Response::new(CircuitBreakerListResponse {
                breakers: vec![],
            }));
        };
        let breaker = engine.tracker_circuit_breaker();
        let breakers = breaker
            .all_hosts()
            .into_iter()
            .map(|(host, info)| host_status_to_proto(host, breaker, info))
            .collect();
        Ok(Response::new(CircuitBreakerListResponse { breakers }))
    }

    async fn force_circuit_breaker_action(
        &self,
        request: Request<CircuitBreakerActionRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        self.verify_auth(&request)?;
        let Some(ref engine) = self.swarm_engine else {
            return Err(Status::unavailable("SwarmEngine not configured"));
        };
        let req = request.into_inner();
        let breaker = engine.tracker_circuit_breaker();
        match circuit_breaker_action_request::Action::try_from(req.action) {
            Ok(circuit_breaker_action_request::Action::Trip) => breaker.force_trip(&req.host),
            Ok(circuit_breaker_action_request::Action::Reset) => breaker.force_reset(&req.host),
            Err(_) => return Err(Status::invalid_argument("unknown circuit breaker action")),
        }
        Ok(Response::new(CommandResponse {
            success: true,
            error: None,
        }))
    }

    async fn move_in_queue(
        &self,
        request: Request<MoveInQueueRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        self.verify_auth(&request)?;
        let Some(ref engine) = self.swarm_engine else {
            return Err(Status::unavailable("SwarmEngine not configured"));
        };
        let req = request.into_inner();
        let direction = match move_in_queue_request::Direction::try_from(req.direction) {
            Ok(move_in_queue_request::Direction::Top) => synapse_engine::QueueMove::Top,
            Ok(move_in_queue_request::Direction::Up) => synapse_engine::QueueMove::Up,
            Ok(move_in_queue_request::Direction::Down) => synapse_engine::QueueMove::Down,
            Ok(move_in_queue_request::Direction::Bottom) => synapse_engine::QueueMove::Bottom,
            Err(_) => return Err(Status::invalid_argument("unknown queue direction")),
        };
        let hashes: Vec<[u8; 20]> = req.hashes.iter().filter_map(|h| parse_hash(h)).collect();
        if hashes.len() != req.hashes.len() {
            return Err(Status::invalid_argument("malformed info hash"));
        }
        let found = engine.move_in_queue(&hashes, direction);
        if found == 0 {
            return Ok(command_result(false, "no such torrent"));
        }
        self.sync_from_engine();
        Ok(command_result(true, ""))
    }

    async fn set_sequential_download(
        &self,
        request: Request<SequentialDownloadRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        self.verify_auth(&request)?;
        let Some(ref engine) = self.swarm_engine else {
            return Err(Status::unavailable("SwarmEngine not configured"));
        };
        let req = request.into_inner();
        let mut missing = 0usize;
        for h in &req.hashes {
            let Some(hash) = parse_hash(h) else {
                return Err(Status::invalid_argument("malformed info hash"));
            };
            if !engine.set_sequential_download(&hash, req.enabled) {
                missing += 1;
            }
        }
        if missing > 0 {
            return Ok(command_result(
                false,
                format!("{missing} torrent(s) not found"),
            ));
        }
        Ok(command_result(true, ""))
    }

    async fn reannounce_torrents(
        &self,
        request: Request<TorrentHashesRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        self.verify_auth(&request)?;
        let Some(ref engine) = self.swarm_engine else {
            return Err(Status::unavailable("SwarmEngine not configured"));
        };
        let req = request.into_inner();
        let mut skipped = 0usize;
        for h in &req.hashes {
            let Some(hash) = parse_hash(h) else {
                return Err(Status::invalid_argument("malformed info hash"));
            };
            if !engine.reannounce_torrent(&hash) {
                skipped += 1;
            }
        }
        if skipped > 0 {
            return Ok(command_result(
                false,
                format!("{skipped} torrent(s) not found or not announcing (stopped or queued)"),
            ));
        }
        Ok(command_result(true, ""))
    }

    async fn replace_trackers(
        &self,
        request: Request<ReplaceTrackersRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        self.verify_auth(&request)?;
        let Some(ref engine) = self.swarm_engine else {
            return Err(Status::unavailable("SwarmEngine not configured"));
        };
        let req = request.into_inner();
        let Some(hash) = parse_hash(&req.hash) else {
            return Err(Status::invalid_argument("malformed info hash"));
        };
        match engine.replace_trackers(&hash, &req.trackers) {
            None => Ok(command_result(false, "no such torrent")),
            Some(0) if !req.trackers.is_empty() => Ok(command_result(
                false,
                "none of the given tracker URLs were valid",
            )),
            Some(_) => Ok(command_result(true, "")),
        }
    }

    async fn reload_ip_filter(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<ReloadIpFilterResponse>, Status> {
        self.verify_auth(&request)?;
        let Some(ref engine) = self.swarm_engine else {
            return Err(Status::unavailable("SwarmEngine not configured"));
        };
        // Reading and parsing a large blocklist is blocking file I/O.
        let engine = engine.clone();
        let rules = tokio::task::spawn_blocking(move || engine.reload_ip_filter())
            .await
            .map_err(|e| Status::internal(format!("reload failed: {e}")))?;
        Ok(Response::new(ReloadIpFilterResponse {
            rules: rules as u32,
        }))
    }

    async fn set_super_seeding(
        &self,
        request: Request<SuperSeedingRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        self.verify_auth(&request)?;
        let Some(ref engine) = self.swarm_engine else {
            return Err(Status::unavailable("SwarmEngine not configured"));
        };
        let req = request.into_inner();
        let mut missing = 0usize;
        for h in &req.hashes {
            let Some(hash) = parse_hash(h) else {
                return Err(Status::invalid_argument("malformed info hash"));
            };
            if !engine.set_super_seeding(&hash, req.enabled) {
                missing += 1;
            }
        }
        if missing > 0 {
            return Ok(command_result(
                false,
                format!("{missing} torrent(s) not found"),
            ));
        }
        Ok(command_result(true, ""))
    }

    async fn set_first_last_piece_priority(
        &self,
        request: Request<FirstLastPiecePriorityRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        self.verify_auth(&request)?;
        let Some(ref engine) = self.swarm_engine else {
            return Err(Status::unavailable("SwarmEngine not configured"));
        };
        let req = request.into_inner();
        let mut missing = 0usize;
        for h in &req.hashes {
            let Some(hash) = parse_hash(h) else {
                return Err(Status::invalid_argument("malformed info hash"));
            };
            if !engine.set_first_last_piece_priority(&hash, req.enabled) {
                missing += 1;
            }
        }
        if missing > 0 {
            return Ok(command_result(
                false,
                format!("{missing} torrent(s) not found"),
            ));
        }
        Ok(command_result(true, ""))
    }

    async fn update_torrent_metadata(
        &self,
        request: Request<UpdateTorrentMetadataRequest>,
    ) -> Result<Response<TorrentMetadataResponse>, Status> {
        self.verify_auth(&request)?;
        let Some(ref engine) = self.swarm_engine else {
            return Err(Status::unavailable("SwarmEngine not configured"));
        };
        let req = request.into_inner();
        let Some(hash) = parse_hash(&req.hash) else {
            return Err(Status::invalid_argument("malformed info hash"));
        };
        let patch = synapse_engine::TorrentMetadataPatch {
            category: req.category.map(|c| {
                let t = c.trim().to_string();
                if t.is_empty() {
                    None
                } else {
                    Some(t)
                }
            }),
            tags: req.tags.map(|t| t.tags),
            seed_ratio_limit: req.seed_ratio_limit.map(|w| w.value),
            seed_time_limit_secs: req.seed_time_limit_secs.map(|w| w.value),
        };
        match engine.set_torrent_metadata(&hash, patch) {
            None => Ok(Response::new(TorrentMetadataResponse {
                success: false,
                error: Some("no such torrent".to_string()),
                category: None,
                tags: Vec::new(),
                seed_ratio_limit: None,
                seed_time_limit_secs: None,
            })),
            Some(updated) => {
                self.sync_from_engine();
                Ok(Response::new(TorrentMetadataResponse {
                    success: true,
                    error: None,
                    category: updated.category,
                    tags: updated.tags,
                    seed_ratio_limit: updated.seed_ratio_limit,
                    seed_time_limit_secs: updated.seed_time_limit_secs,
                }))
            }
        }
    }

    async fn export_torrent(
        &self,
        request: Request<ExportTorrentRequest>,
    ) -> Result<Response<ExportTorrentResponse>, Status> {
        self.verify_auth(&request)?;
        let Some(ref engine) = self.swarm_engine else {
            return Err(Status::unavailable("SwarmEngine not configured"));
        };
        let req = request.into_inner();
        let Some(hash) = parse_hash(&req.hash) else {
            return Err(Status::invalid_argument("malformed info hash"));
        };
        let engine = engine.clone();
        let exported = tokio::task::spawn_blocking(move || engine.export_torrent_bytes(&hash))
            .await
            .map_err(|e| Status::internal(format!("export_torrent failed: {e}")))?;
        match exported {
            None => Ok(Response::new(ExportTorrentResponse {
                success: false,
                error: Some("no such torrent, or it has no retrievable metainfo".to_string()),
                filename: String::new(),
                torrent_bytes: Vec::new(),
            })),
            Some((filename, bytes)) => Ok(Response::new(ExportTorrentResponse {
                success: true,
                error: None,
                filename,
                torrent_bytes: bytes,
            })),
        }
    }

    async fn pause_torrents(
        &self,
        request: Request<TorrentHashesRequest>,
    ) -> Result<Response<BatchCommandResponse>, Status> {
        self.verify_auth(&request)?;
        let parsed = parse_hashes_list(&request.into_inner().hashes)
            .ok_or_else(|| Status::invalid_argument("malformed info hash"))?;
        Ok(self.batch_state_action(parsed, BatchStateAction::Pause))
    }

    async fn resume_torrents(
        &self,
        request: Request<TorrentHashesRequest>,
    ) -> Result<Response<BatchCommandResponse>, Status> {
        self.verify_auth(&request)?;
        let parsed = parse_hashes_list(&request.into_inner().hashes)
            .ok_or_else(|| Status::invalid_argument("malformed info hash"))?;
        Ok(self.batch_state_action(parsed, BatchStateAction::Resume))
    }

    async fn recheck_torrents(
        &self,
        request: Request<TorrentHashesRequest>,
    ) -> Result<Response<BatchCommandResponse>, Status> {
        self.verify_auth(&request)?;
        let parsed = parse_hashes_list(&request.into_inner().hashes)
            .ok_or_else(|| Status::invalid_argument("malformed info hash"))?;
        Ok(self.batch_state_action(parsed, BatchStateAction::Recheck))
    }

    async fn remove_torrents(
        &self,
        request: Request<RemoveTorrentsRequest>,
    ) -> Result<Response<BatchCommandResponse>, Status> {
        self.verify_auth(&request)?;
        let req = request.into_inner();
        let parsed = parse_hashes_list(&req.hashes)
            .ok_or_else(|| Status::invalid_argument("malformed info hash"))?;
        let mut succeeded = 0u32;
        let mut failed_hashes = Vec::new();
        let mut to_delete: Vec<(String, String)> = Vec::new();

        for (raw, hash, arr) in parsed {
            let removed = if let Some(ref swarm) = self.swarm_engine {
                let target_info = swarm.get_torrent(&arr).map(|h| {
                    let s = h.stats.read();
                    (s.download_dir.clone(), s.name.clone())
                });
                let ok = swarm.remove_torrent(&arr);
                if ok && req.delete_data {
                    if let Some(info) = target_info {
                        to_delete.push(info);
                    }
                }
                if hash != raw {
                    self.active_summaries.remove(&raw);
                }
                self.active_summaries.remove(&hash);
                ok
            } else {
                let mut existed = self.active_summaries.remove(&hash).is_some();
                if hash != raw {
                    existed |= self.active_summaries.remove(&raw).is_some();
                }
                existed
            };

            if removed {
                self.event_bus.emit_removed(hash);
                succeeded += 1;
            } else {
                failed_hashes.push(hash);
            }
        }

        if req.delete_data && !to_delete.is_empty() {
            if let Some(ref swarm) = self.swarm_engine {
                let base = self
                    .base_download_dir
                    .clone()
                    .unwrap_or_else(|| swarm.settings().read().download_dir.clone());
                let _ = tokio::task::spawn_blocking(move || {
                    for (dl_dir_str, torrent_name) in to_delete {
                        crate::http_api::delete_torrent_data_under_base(
                            &base,
                            &dl_dir_str,
                            &torrent_name,
                        );
                    }
                })
                .await;
            }
        }

        Ok(Response::new(batch_command_response(
            succeeded,
            failed_hashes,
        )))
    }
}

#[derive(Clone, Copy)]
enum BatchStateAction {
    Pause,
    Resume,
    Recheck,
}

fn parse_hashes_list(raw_hashes: &[String]) -> Option<Vec<(String, String, [u8; 20])>> {
    raw_hashes
        .iter()
        .map(|raw| {
            let hash = raw.to_lowercase();
            let arr = parse_hash(&hash)?;
            Some((raw.clone(), hash, arr))
        })
        .collect()
}

fn batch_command_response(succeeded: u32, failed_hashes: Vec<String>) -> BatchCommandResponse {
    let error = (!failed_hashes.is_empty())
        .then(|| format!("{} torrent(s) not found", failed_hashes.len()));
    BatchCommandResponse {
        success: failed_hashes.is_empty(),
        succeeded,
        failed_hashes,
        error,
    }
}

impl SynapseService {
    fn batch_state_action(
        &self,
        parsed: Vec<(String, String, [u8; 20])>,
        action: BatchStateAction,
    ) -> Response<BatchCommandResponse> {
        let mut succeeded = 0u32;
        let mut failed_hashes = Vec::new();

        for (_, hash, arr) in parsed {
            let ok = if let Some(ref swarm) = self.swarm_engine {
                match action {
                    BatchStateAction::Pause => swarm.transition_to_cold(&arr),
                    BatchStateAction::Resume => swarm.transition_to_hot(&arr),
                    BatchStateAction::Recheck => swarm.recheck_torrent(&arr),
                }
            } else {
                self.active_summaries.contains_key(&hash)
            };

            if !ok {
                failed_hashes.push(hash);
                continue;
            }
            succeeded += 1;

            if let Some(mut item) = self.active_summaries.get_mut(&hash) {
                let cleared_error = item.error_message.take().map(|_| String::new());
                let target_state = match action {
                    BatchStateAction::Pause => TorrentState::StateStopped as i32,
                    BatchStateAction::Resume => {
                        if item.progress >= 1.0 {
                            TorrentState::StateSeeding as i32
                        } else {
                            TorrentState::StateDownloading as i32
                        }
                    }
                    BatchStateAction::Recheck => TorrentState::StateChecking as i32,
                };
                item.state = target_state;
                let mut delta = TorrentDelta {
                    hash: hash.clone(),
                    state: Some(target_state),
                    error_message: cleared_error,
                    ..Default::default()
                };
                if matches!(action, BatchStateAction::Pause) {
                    item.rate_download = 0;
                    item.rate_upload = 0;
                    item.peers_connected = 0;
                    item.peers_sending = 0;
                    delta.rate_download = Some(0);
                    delta.rate_upload = Some(0);
                    delta.peers_connected = Some(0);
                    delta.peers_sending = Some(0);
                }
                self.event_bus.record_delta(delta);
            }
        }

        Response::new(batch_command_response(succeeded, failed_hashes))
    }
}

#[cfg(test)]
mod tracker_host_tests {
    use super::*;

    #[test]
    fn hosts_only_deduplicated_and_never_the_passkey() {
        let hosts = tracker_hosts_from_urls([
            "https://tracker.example.org/abc123PASSKEY/announce",
            "https://tracker.example.org/other/announce?passkey=zzz",
            "udp://open.tracker.net:6969/announce",
            "not a url",
        ]);
        assert_eq!(
            hosts,
            vec![
                "open.tracker.net:6969".to_string(),
                "tracker.example.org".to_string()
            ]
        );
        assert!(hosts
            .iter()
            .all(|h| !h.contains("PASSKEY") && !h.contains("zzz")));
    }

    #[tokio::test]
    async fn all_23_grpc_endpoints_reject_unauthenticated_requests_when_token_is_set() {
        use tonic::Code;

        let tmp = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(synapse_engine::SwarmEngine::new(disk, [0x11; 20]));
        engine.settings().write().download_dir = tmp.path().to_path_buf();

        let service = SynapseService::new(Arc::new(EventBus::new(16)))
            .with_swarm_engine(engine)
            .with_auth_token(Some("top-secret-grpc-token".to_string()))
            .with_rate_limiter(crate::http_api::AuthRateLimiter::with_max_failures(100));

        // Verify all 23 RPC handlers reject unauthenticated calls with Code::Unauthenticated
        assert_eq!(
            service
                .subscribe_torrents(Request::new(SubscribeTorrentsRequest::default()))
                .await
                .err()
                .unwrap()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .subscribe_session_stats(Request::new(SessionStatsRequest::default()))
                .await
                .err()
                .unwrap()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .subscribe_torrent_detail(Request::new(TorrentDetailRequest::default()))
                .await
                .err()
                .unwrap()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .subscribe_alerts(Request::new(SubscribeAlertsRequest::default()))
                .await
                .err()
                .unwrap()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .add_torrent(Request::new(AddTorrentRequest::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .remove_torrent(Request::new(RemoveTorrentRequest::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .pause_torrent(Request::new(TorrentHashRequest::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .resume_torrent(Request::new(TorrentHashRequest::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .recheck_torrent(Request::new(TorrentHashRequest::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .set_file_priority(Request::new(FilePriorityRequest::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .set_location(Request::new(SetLocationRequest::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .set_rate_limits(Request::new(RateLimitsRequest::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .get_session_stats(Request::new(SessionStatsRequest::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .get_session_settings(Request::new(SessionSettingsRequest::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .update_session_settings(Request::new(UpdateSessionSettingsRequest::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .get_capabilities(Request::new(Empty::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .list_circuit_breakers(Request::new(Empty::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .force_circuit_breaker_action(Request::new(CircuitBreakerActionRequest::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .move_in_queue(Request::new(MoveInQueueRequest::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .set_sequential_download(Request::new(SequentialDownloadRequest::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .reannounce_torrents(Request::new(TorrentHashesRequest::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .replace_trackers(Request::new(ReplaceTrackersRequest::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            service
                .reload_ip_filter(Request::new(Empty::default()))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );

        // Verify valid bearer token succeeds
        let mut authed_req = Request::new(Empty::default());
        authed_req.metadata_mut().insert(
            "authorization",
            "Bearer top-secret-grpc-token".parse().unwrap(),
        );
        assert!(service.get_capabilities(authed_req).await.is_ok());

        // Verify path traversal on set_location and FilePath is rejected with PermissionDenied
        let mut bad_loc = Request::new(SetLocationRequest {
            hash: "0123456789abcdef0123456789abcdef01234567".into(),
            new_download_dir: "/etc".into(),
            move_existing_files: Some(false),
        });
        bad_loc.metadata_mut().insert(
            "authorization",
            "Bearer top-secret-grpc-token".parse().unwrap(),
        );
        assert_eq!(
            service.set_location(bad_loc).await.unwrap_err().code(),
            Code::PermissionDenied
        );

        let mut bad_file = Request::new(AddTorrentRequest {
            source: Some(add_torrent_request::Source::FilePath("/etc/passwd".into())),
            download_dir: None,
            start_paused: None,
        });
        bad_file.metadata_mut().insert(
            "authorization",
            "Bearer top-secret-grpc-token".parse().unwrap(),
        );
        assert_eq!(
            service.add_torrent(bad_file).await.unwrap_err().code(),
            Code::PermissionDenied
        );

        // Verify FilePath outside base_download_dir is rejected even with a .torrent extension
        let outside_dir = tempfile::tempdir().unwrap();
        let outside_path = outside_dir.path().join("outside.torrent");
        std::fs::write(
            &outside_path,
            b"d4:infod4:name1:ae12:piece lengthi16384e6:pieces20:aaaaaaaaaaaaaaaaaaaaee",
        )
        .unwrap();
        let mut outside_torrent = Request::new(AddTorrentRequest {
            source: Some(add_torrent_request::Source::FilePath(
                outside_path.to_string_lossy().into_owned(),
            )),
            download_dir: None,
            start_paused: None,
        });
        outside_torrent.metadata_mut().insert(
            "authorization",
            "Bearer top-secret-grpc-token".parse().unwrap(),
        );
        assert_eq!(
            service
                .add_torrent(outside_torrent)
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );

        // Verify gRPC auth rate limiter blocks after repeated failed attempts
        let rate_limited_service = SynapseService::new(Arc::new(EventBus::new(16)))
            .with_auth_token(Some("top-secret-grpc-token".into()));
        let mut saw_exhausted = false;
        for _ in 0..20 {
            let mut bad_req = Request::new(Empty::default());
            bad_req
                .metadata_mut()
                .insert("authorization", "Bearer wrong".parse().unwrap());
            match rate_limited_service.get_capabilities(bad_req).await {
                Err(status) if status.code() == Code::ResourceExhausted => {
                    saw_exhausted = true;
                    break;
                }
                Err(status) => assert_eq!(status.code(), Code::Unauthenticated),
                Ok(_) => panic!("unexpected auth success"),
            }
        }
        assert!(
            saw_exhausted,
            "gRPC auth rate limiter must block brute force"
        );
    }

    fn make_single_file_info(name: &str) -> synapse_meta::Info {
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
            synapse_bencode::BEncode::String(vec![0xAB; 20]),
        );
        info_dict.insert(b"length".to_vec(), synapse_bencode::BEncode::Int(16_384));
        let mut top = std::collections::BTreeMap::new();
        top.insert(b"info".to_vec(), synapse_bencode::BEncode::Dict(info_dict));
        synapse_meta::Info::from_bencode(synapse_bencode::BEncode::Dict(top)).unwrap()
    }

    #[tokio::test]
    async fn remove_torrent_respects_delete_data_under_base_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(synapse_engine::SwarmEngine::new(disk, [0x21; 20]));
        engine.settings().write().download_dir = tmp.path().to_path_buf();
        let service =
            SynapseService::new(Arc::new(EventBus::new(16))).with_swarm_engine(engine.clone());

        let keep_info = Arc::new(make_single_file_info("keep-file.bin"));
        let keep_path = tmp.path().join("keep-file.bin");
        std::fs::write(&keep_path, b"keep").unwrap();
        engine.add_torrent(keep_info.clone(), tmp.path().to_path_buf(), None);

        let del_info = Arc::new(make_single_file_info("delete-file.bin"));
        let del_path = tmp.path().join("delete-file.bin");
        std::fs::write(&del_path, b"delete").unwrap();
        engine.add_torrent(del_info.clone(), tmp.path().to_path_buf(), None);

        service
            .remove_torrent(Request::new(RemoveTorrentRequest {
                hash: hex::encode(keep_info.hash).to_uppercase(),
                delete_data: false,
            }))
            .await
            .unwrap();
        assert!(keep_path.exists());

        service
            .remove_torrent(Request::new(RemoveTorrentRequest {
                hash: hex::encode(del_info.hash).to_uppercase(),
                delete_data: true,
            }))
            .await
            .unwrap();
        assert!(!del_path.exists());
    }

    #[tokio::test]
    async fn grpc_set_location_and_rate_limits_honor_partial_and_move_flags() {
        let tmp = tempfile::tempdir().unwrap();
        let dir_a = tmp.path().join("a");
        let dir_b = tmp.path().join("b");
        let dir_c = tmp.path().join("c");
        std::fs::create_dir_all(&dir_a).unwrap();

        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(synapse_engine::SwarmEngine::new(disk, [0x22; 20]));
        engine.settings().write().download_dir = tmp.path().to_path_buf();
        let event_bus = Arc::new(EventBus::new(32));
        let service = SynapseService::new(event_bus.clone()).with_swarm_engine(engine.clone());

        let info = Arc::new(make_single_file_info("moved.bin"));
        std::fs::write(dir_a.join("moved.bin"), vec![0x55; 16_384]).unwrap();
        let mut bf = synapse_picker::Bitfield::new(1);
        bf.set(0);
        let resume = synapse_engine::SwarmResumeOptions {
            is_paused: true,
            ..Default::default()
        };
        let handle =
            engine.add_torrent_with_resume(info.clone(), dir_a.clone(), Some(&bf), Some(resume));
        engine.transition_to_cold(&info.hash);
        service.sync_from_engine();

        // Move files = true on paused torrent stays Cold and relocates file + summary.
        let resp = service
            .set_location(Request::new(SetLocationRequest {
                hash: hex::encode(info.hash),
                new_download_dir: dir_b.to_string_lossy().into_owned(),
                move_existing_files: Some(true),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.success);
        assert!(dir_b.join("moved.bin").exists());
        assert!(!dir_a.join("moved.bin").exists());
        assert_eq!(handle.stats.read().tier, synapse_engine::SwarmTier::Cold);

        // Move files = false updates download_dir without moving disk files.
        let resp2 = service
            .set_location(Request::new(SetLocationRequest {
                hash: hex::encode(info.hash),
                new_download_dir: dir_c.to_string_lossy().into_owned(),
                move_existing_files: Some(false),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(resp2.success);
        assert!(dir_b.join("moved.bin").exists());
        assert!(!dir_c.join("moved.bin").exists());
        let expected_c = std::fs::canonicalize(&dir_c).unwrap();
        assert_eq!(
            handle.stats.read().download_dir,
            expected_c.to_string_lossy()
        );

        // Partial global + per-torrent rate limits.
        service
            .set_rate_limits(Request::new(RateLimitsRequest {
                global_download_limit: Some(50_000),
                global_upload_limit: Some(80_000),
                per_torrent_hash: None,
                torrent_download_limit: None,
                torrent_upload_limit: None,
            }))
            .await
            .unwrap();
        service
            .set_rate_limits(Request::new(RateLimitsRequest {
                global_download_limit: Some(90_000),
                global_upload_limit: None,
                per_torrent_hash: Some(hex::encode(info.hash)),
                torrent_download_limit: Some(12_000),
                torrent_upload_limit: None,
            }))
            .await
            .unwrap();
        assert_eq!(engine.settings().read().download_limit_bytes, 90_000);
        assert_eq!(engine.settings().read().upload_limit_bytes, 80_000);
        assert_eq!(
            handle
                .download_limit_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            12_000
        );
    }

    #[tokio::test]
    async fn sync_diff_and_detail_propagate_metadata_error_clearing_and_priorities() {
        let bus = Arc::new(EventBus::new(16));
        let mut rx = bus.subscribe();

        // diff_summary clears error via Some("") and EventBus preserves queue_position.
        let old = TorrentSummary {
            hash: "01".repeat(20),
            name: "n".into(),
            error_message: Some("disk full".into()),
            queue_position: 1,
            ..Default::default()
        };
        let new = TorrentSummary {
            hash: "01".repeat(20),
            name: "n".into(),
            error_message: None,
            queue_position: 3,
            ..Default::default()
        };
        let delta = diff_summary(&old, &new).expect("delta expected");
        assert_eq!(delta.error_message.as_deref(), Some(""));
        assert_eq!(delta.queue_position, Some(3));
        bus.record_delta(delta.clone());
        bus.record_delta(TorrentDelta {
            hash: old.hash.clone(),
            progress: Some(0.5),
            ..Default::default()
        });

        let flusher = bus
            .clone()
            .start_flusher(std::time::Duration::from_millis(10));
        let ev = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        flusher.abort();
        match ev.event {
            Some(torrent_list_event::Event::Updated(d)) => {
                assert_eq!(d.error_message.as_deref(), Some(""));
                assert_eq!(d.queue_position, Some(3));
                assert_eq!(d.progress, Some(0.5));
            }
            other => panic!("unexpected event: {other:?}"),
        }

        // sync_from_engine emits Added when metadata changes, and detail reflects file_priorities.
        let tmp = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(synapse_engine::SwarmEngine::new(disk, [0x23; 20]));
        engine.settings().write().download_dir = tmp.path().to_path_buf();
        let bus2 = Arc::new(EventBus::new(16));
        let service = SynapseService::new(bus2.clone()).with_swarm_engine(engine.clone());

        let info = Arc::new(make_single_file_info("prio.bin"));
        engine.add_torrent(info.clone(), tmp.path().to_path_buf(), None);
        service.sync_from_engine();

        let mut rx2 = bus2.subscribe();
        engine.set_torrent_metadata(
            &info.hash,
            synapse_engine::TorrentMetadataPatch {
                category: Some(Some("linux".into())),
                ..Default::default()
            },
        );
        service.sync_from_engine();
        let meta_ev = rx2.try_recv().expect("metadata change should emit Added");
        assert!(matches!(
            meta_ev.event,
            Some(torrent_list_event::Event::Added(ref s)) if s.category.as_deref() == Some("linux")
        ));

        engine.set_file_priority(&info.hash, 0, 7);
        let mut detail_stream = service
            .subscribe_torrent_detail(Request::new(TorrentDetailRequest {
                hash: hex::encode(info.hash),
                refresh_interval_ms: 100,
            }))
            .await
            .unwrap()
            .into_inner();
        let first_detail =
            tokio::time::timeout(std::time::Duration::from_secs(1), detail_stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        assert_eq!(first_detail.files.len(), 1);
        assert_eq!(first_detail.files[0].priority, 7);
    }

    #[tokio::test]
    async fn sync_if_subscribed_skips_idle_and_stats_match_global_metrics() {
        let tmp = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = Arc::new(synapse_engine::SwarmEngine::new(disk, [0x24; 20]));
        engine.settings().write().download_dir = tmp.path().to_path_buf();
        let bus = Arc::new(EventBus::new(16));
        let service = SynapseService::new(bus.clone()).with_swarm_engine(engine.clone());

        let info = Arc::new(make_single_file_info("sub-stats.bin"));
        engine.add_torrent(info.clone(), tmp.path().to_path_buf(), None);

        // With 0 subscribers, sync_from_engine_if_subscribed does no work.
        service.sync_from_engine_if_subscribed();
        assert_eq!(service.active_summaries.len(), 0);

        // subscribe_torrents initializes active_summaries synchronously when subscriber count was 0.
        let mut stream = service
            .subscribe_torrents(Request::new(SubscribeTorrentsRequest {
                chunk_size: 100,
                flush_window_ms: 50,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(service.active_summaries.len(), 1);
        let first = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(
            first.event,
            Some(torrent_list_event::Event::Snapshot(snap)) if snap.items.len() == 1
        ));

        service.sync_from_engine_if_subscribed();
        service.refresh_session_stats().await;
        let expected_metrics = engine.global_metrics();
        let expected_dht = engine.dht_node_count_fast() as u32;
        let unary = service
            .get_session_stats(Request::new(SessionStatsRequest {}))
            .await
            .unwrap()
            .into_inner();
        let streamed = *service.session_stats.read();
        assert_eq!(unary.torrent_count, expected_metrics.total_torrents as u32);
        assert_eq!(
            unary.active_downloading,
            expected_metrics.downloading_torrents as u32
        );
        assert_eq!(unary.dht_nodes, expected_dht);
        assert_eq!(streamed.torrent_count, unary.torrent_count);
        assert_eq!(streamed.active_downloading, unary.active_downloading);
        assert_eq!(streamed.dht_nodes, unary.dht_nodes);
    }
}
