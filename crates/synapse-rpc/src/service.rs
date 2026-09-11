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
    auth_token: Option<String>,
}

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
            auth_token: None,
        }
    }

    pub fn with_swarm_engine(mut self, engine: Arc<synapse_engine::SwarmEngine>) -> Self {
        let free_space = engine.free_disk_space_bytes();
        self.session_stats.write().free_disk_space_bytes = free_space;
        self.swarm_engine = Some(engine);
        self
    }

    pub fn with_auth_token(mut self, auth_token: Option<String>) -> Self {
        self.auth_token = auth_token;
        self
    }

    #[allow(clippy::result_large_err)]
    pub fn verify_auth<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if let Some(ref expected) = self.auth_token {
            if let Some(auth_header) = request.metadata().get("authorization") {
                if let Ok(val) = auth_header.to_str() {
                    let token = val.strip_prefix("Bearer ").unwrap_or(val).trim();
                    if token == expected {
                        return Ok(());
                    }
                }
            }
            return Err(Status::unauthenticated("Invalid or missing authorization token"));
        }
        Ok(())
    }

    pub fn upsert_torrent(&self, summary: TorrentSummary) {
        self.active_summaries.insert(summary.hash.clone(), summary.clone());
        self.event_bus.emit_summary_added(summary);
    }

    pub fn update_stats(&self, stats: SessionStatsUpdate) {
        *self.session_stats.write() = stats;
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
        let Some(ref engine) = self.swarm_engine else { return };
        let live = engine.list_torrents();
        let mut seen = std::collections::HashSet::with_capacity(live.len());

        for stats in &live {
            let hash = hex::encode(stats.info_hash);
            seen.insert(hash.clone());
            let new_summary = swarm_stats_to_summary(stats);

            let existing = self.active_summaries.get(&hash).map(|r| r.value().clone());
            match existing {
                Some(old) => {
                    if let Some(delta) = diff_summary(&old, &new_summary) {
                        self.active_summaries.insert(hash, new_summary);
                        self.event_bus.record_delta(delta);
                    }
                }
                None => self.upsert_torrent(new_summary),
            }
        }

        let stale: Vec<String> = self
            .active_summaries
            .iter()
            .map(|r| r.key().clone())
            .filter(|h| !seen.contains(h))
            .collect();
        for hash in stale {
            self.active_summaries.remove(&hash);
            self.event_bus.emit_removed(hash);
        }
    }

    /// Companion to `sync_from_engine` for the aggregate session stats — same live-engine
    /// source `get_session_stats`'s unary handler already uses, just also pushed into
    /// `session_stats` so `SubscribeSessionStats` (the streaming sibling that was still
    /// hardcoded at its `SynapseService::new()` default forever) reflects reality too.
    pub fn refresh_session_stats(&self) {
        let Some(ref engine) = self.swarm_engine else { return };
        let swarms = engine.list_torrents();
        let downloading = swarms.iter().filter(|s| matches!(s.state, synapse_engine::SwarmState::Downloading)).count() as u32;
        let seeding = swarms.iter().filter(|s| matches!(s.state, synapse_engine::SwarmState::Seeding)).count() as u32;
        let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64;
        let free_space = engine.free_disk_space_bytes();
        self.update_stats(SessionStatsUpdate {
            rate_download: swarms.iter().map(|s| s.download_rate).sum(),
            rate_upload: swarms.iter().map(|s| s.upload_rate).sum(),
            total_downloaded: swarms.iter().map(|s| s.downloaded_bytes).sum(),
            total_uploaded: swarms.iter().map(|s| s.uploaded_bytes).sum(),
            torrent_count: swarms.len() as u32,
            active_downloading: downloading,
            active_seeding: seeding,
            free_disk_space_bytes: free_space,
            timestamp_ms: now_ms,
            dht_nodes: 0,
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
    }
}

fn circuit_state_to_proto(state: synapse_tracker::CircuitState) -> CircuitBreakerState {
    match state {
        synapse_tracker::CircuitState::Healthy => CircuitBreakerState::CbHealthy,
        synapse_tracker::CircuitState::Tripped => CircuitBreakerState::CbTripped,
        synapse_tracker::CircuitState::HalfOpenCanary => CircuitBreakerState::CbHalfOpenCanary,
        synapse_tracker::CircuitState::Recovering => CircuitBreakerState::CbRecovering,
    }
}

fn host_status_to_proto(host: String, breaker: &synapse_tracker::CanaryCircuitBreaker, info: synapse_tracker::HostCircuitInfo) -> CircuitBreakerStatus {
    CircuitBreakerStatus {
        host,
        state: circuit_state_to_proto(info.state) as i32,
        consecutive_successes: info.consecutive_successes,
        consecutive_failures: info.consecutive_failures,
        backoff_remaining_ms: breaker.backoff_remaining_ms(&info),
        recovery_progress_pct: breaker.recovery_progress_pct(&info),
    }
}

/// `None` when nothing actually changed — callers use this to avoid emitting a no-op delta
/// every sync tick for a torrent that's genuinely idle (e.g. fully seeded, no peers).
fn diff_summary(old: &TorrentSummary, new: &TorrentSummary) -> Option<TorrentDelta> {
    let mut delta = TorrentDelta { hash: new.hash.clone(), ..Default::default() };
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
        delta.error_message = new.error_message.clone();
        changed = true;
    }
    if old.download_dir != new.download_dir {
        // download_dir isn't part of TorrentDelta's schema (only set_location's immediate RPC
        // handler updates it optimistically) — still worth tracking here so `existing` in the
        // caller's Some(old) branch gets the field refreshed even though no delta event carries
        // it, otherwise a later comparison would keep re-diffing a field that never converges.
        changed = true;
    }

    changed.then_some(delta)
}

#[tonic::async_trait]
impl SynapseControl for SynapseService {
    type SubscribeTorrentsStream = Pin<
        Box<dyn Stream<Item = Result<TorrentListEvent, Status>> + Send + 'static>,
    >;

    async fn subscribe_torrents(
        &self,
        request: Request<SubscribeTorrentsRequest>,
    ) -> Result<Response<Self::SubscribeTorrentsStream>, Status> {
        let req = request.into_inner();
        let chunk_size = if req.chunk_size == 0 { 500 } else { req.chunk_size as usize };

        let summaries: Vec<TorrentSummary> = self
            .active_summaries
            .iter()
            .map(|r| r.value().clone())
            .collect();

        let chunks: Vec<Vec<TorrentSummary>> = summaries
            .chunks(chunk_size)
            .map(|c| c.to_vec())
            .collect();

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

        let rx = self.event_bus.subscribe();
        let live_stream = BroadcastStream::new(rx).filter_map(|res| match res {
            Ok(item) => Some(Ok(item)),
            Err(_) => None,
        });

        let snapshot_stream = tokio_stream::iter(snapshot_events.into_iter().map(Ok));
        let combined = snapshot_stream.chain(live_stream);

        Ok(Response::new(Box::pin(combined)))
    }

    type SubscribeSessionStatsStream = Pin<
        Box<dyn Stream<Item = Result<SessionStatsUpdate, Status>> + Send + 'static>,
    >;

    async fn subscribe_session_stats(
        &self,
        _request: Request<SessionStatsRequest>,
    ) -> Result<Response<Self::SubscribeSessionStatsStream>, Status> {
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

    type SubscribeTorrentDetailStream = Pin<
        Box<dyn Stream<Item = Result<TorrentDetailEvent, Status>> + Send + 'static>,
    >;

    async fn subscribe_torrent_detail(
        &self,
        request: Request<TorrentDetailRequest>,
    ) -> Result<Response<Self::SubscribeTorrentDetailStream>, Status> {
        let req = request.into_inner();
        let hash = req.hash;
        let interval_ms = if req.refresh_interval_ms == 0 { 1000 } else { req.refresh_interval_ms as u64 };
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

                        availability = handle.piece_availability.read().clone();
                        if availability.is_empty() && total_pieces > 0 {
                            availability = vec![if is_seeding { 1 } else { 0 }; total_pieces];
                        }

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
                                priority: 4, // 4 = normal priority
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

    async fn add_torrent(
        &self,
        request: Request<AddTorrentRequest>,
    ) -> Result<Response<AddTorrentResponse>, Status> {
        let req = request.into_inner();
        let (hash, name, total_size, info_opt) = match req.source {
            Some(add_torrent_request::Source::MagnetUri(uri)) => {
                if let Ok(info) = synapse_meta::Info::from_magnet(&uri) {
                    (hex::encode(info.hash), info.name.clone(), info.total_len, Some(info))
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
                if let Ok(bencode) = synapse_bencode::decode_buf(&bytes) {
                    if let Ok(info) = synapse_meta::Info::from_bencode(bencode) {
                        (hex::encode(info.hash), info.name.clone(), info.total_len, Some(info))
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
                    Ok(info) => (hex::encode(info.hash), info.name.clone(), info.total_len, Some(info)),
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
                match tokio::fs::read(&path).await {
                    Ok(bytes) => {
                        if let Ok(bencode) = synapse_bencode::decode_buf(&bytes) {
                            if let Ok(info) = synapse_meta::Info::from_bencode(bencode) {
                                (hex::encode(info.hash), info.name.clone(), info.total_len, Some(info))
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

        let dl_dir = req
            .download_dir
            .filter(|d| !d.trim().is_empty())
            .unwrap_or_else(|| {
                self.swarm_engine
                    .as_ref()
                    .map(|s| s.settings().read().download_dir.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "/downloads".into())
            });

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
            added_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64,
            piece_count,
            piece_size,
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
        let req = request.into_inner();
        if let Ok(bytes) = hex::decode(&req.hash) {
            if bytes.len() == 20 {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&bytes);
                if let Some(ref swarm) = self.swarm_engine {
                    swarm.remove_torrent(&arr);
                }
            }
        }
        self.active_summaries.remove(&req.hash);
        self.event_bus.emit_removed(req.hash);
        Ok(Response::new(CommandResponse {
            success: true,
            error: None,
        }))
    }

    async fn pause_torrent(
        &self,
        request: Request<TorrentHashRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        let raw_hash = request.into_inner().hash;
        let hash = raw_hash.to_lowercase();
        if let Ok(bytes) = hex::decode(&hash) {
            if bytes.len() == 20 {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&bytes);
                if let Some(ref swarm) = self.swarm_engine {
                    swarm.transition_to_cold(&arr);
                }
            }
        }
        if let Some(mut item) = self.active_summaries.get_mut(&hash) {
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
        let raw_hash = request.into_inner().hash;
        let hash = raw_hash.to_lowercase();
        if let Ok(bytes) = hex::decode(&hash) {
            if bytes.len() == 20 {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&bytes);
                if let Some(ref swarm) = self.swarm_engine {
                    swarm.transition_to_hot(&arr);
                }
            }
        }
        if let Some(mut item) = self.active_summaries.get_mut(&hash) {
            let target_state = if item.progress >= 1.0 {
                TorrentState::StateSeeding as i32
            } else {
                TorrentState::StateDownloading as i32
            };
            item.state = target_state;
            self.event_bus.record_delta(TorrentDelta {
                hash,
                state: Some(target_state),
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
        let hash = request.into_inner().hash;
        if let Ok(bytes) = hex::decode(&hash) {
            if bytes.len() == 20 {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&bytes);
                if let Some(ref swarm) = self.swarm_engine {
                    swarm.recheck_torrent(&arr);
                }
            }
        }
        if let Some(mut item) = self.active_summaries.get_mut(&hash) {
            item.state = TorrentState::StateChecking as i32;
            self.event_bus.record_delta(TorrentDelta {
                hash,
                state: Some(TorrentState::StateChecking as i32),
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
        let req = request.into_inner();
        if let Ok(bytes) = hex::decode(&req.hash) {
            if bytes.len() == 20 {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&bytes);
                if let Some(ref swarm) = self.swarm_engine {
                    swarm.set_location(&arr, &req.new_download_dir);
                }
            }
        }
        if let Some(mut item) = self.active_summaries.get_mut(&req.hash) {
            item.download_dir = req.new_download_dir;
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
        let req = request.into_inner();
        if let Some(ref swarm) = self.swarm_engine {
            swarm.set_rate_limits(
                req.global_download_limit.unwrap_or(0),
                req.global_upload_limit.unwrap_or(0),
            );
        }
        Ok(Response::new(CommandResponse {
            success: true,
            error: None,
        }))
    }

    async fn get_session_stats(
        &self,
        _request: Request<SessionStatsRequest>,
    ) -> Result<Response<SessionStatsUpdate>, Status> {
        if let Some(ref engine) = self.swarm_engine {
            let swarms = engine.list_torrents();
            let total = swarms.len() as u32;
            let downloading = swarms
                .iter()
                .filter(|s| matches!(s.state, synapse_engine::SwarmState::Downloading))
                .count() as u32;
            let seeding = swarms
                .iter()
                .filter(|s| matches!(s.state, synapse_engine::SwarmState::Seeding))
                .count() as u32;
            let total_dl: u64 = swarms.iter().map(|s| s.downloaded_bytes).sum();
            let total_ul: u64 = swarms.iter().map(|s| s.uploaded_bytes).sum();
            let rate_dl: u64 = swarms.iter().map(|s| s.download_rate).sum();
            let rate_ul: u64 = swarms.iter().map(|s| s.upload_rate).sum();
            let free_space = engine.free_disk_space_bytes();
            let dht_nodes = engine.dht_node_count().await as u32;
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            return Ok(Response::new(SessionStatsUpdate {
                rate_download: rate_dl,
                rate_upload: rate_ul,
                total_downloaded: total_dl,
                total_uploaded: total_ul,
                torrent_count: total,
                active_downloading: downloading,
                active_seeding: seeding,
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

        let req = request.into_inner();
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
            encryption: req.encryption,

            download_dir: req.download_dir,
            incomplete_dir: req.incomplete_dir,
            incomplete_dir_enabled: req.incomplete_dir_enabled,
            start_added_torrents: req.start_added_torrents,
            trash_original_torrent_files: req.trash_original_torrent_files,

            peer_port: req.peer_port.map(|p| p as u16),
            rpc_listen_addr: req.rpc_listen_addr,
            http_listen_addr: req.http_listen_addr,
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
        _request: Request<Empty>,
    ) -> Result<Response<CapabilitiesResponse>, Status> {
        Ok(Response::new(CapabilitiesResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            features: vec!["tracker_circuit_breaker_v1".to_string()],
        }))
    }

    async fn list_circuit_breakers(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<CircuitBreakerListResponse>, Status> {
        let Some(ref engine) = self.swarm_engine else {
            return Ok(Response::new(CircuitBreakerListResponse { breakers: vec![] }));
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
}
