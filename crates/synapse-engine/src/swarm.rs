use dashmap::DashMap;
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use diskio::DiskEngine;
use synapse_meta::Info;
use synapse_picker::Bitfield;

use crate::announcer::{AnnounceScheduler, Announcer, TrackerReport};
use crate::circuit_breaker::PeerCircuitBreaker;
use crate::lifecycle::ConduitLifecycleDispatcher;
use crate::peer::{accept_router, PeerEvent};
use crate::queue::{QueueAction, QueueConfig, QueueManager};
use crate::ratelimit::TokenBucket;
use crate::session::{SessionStore, TorrentSessionState};
use crate::settings::{DynamicSessionSettings, SessionSettingsUpdate};
use crate::torrent::{PeerSnapshot, Torrent, TorrentCommand, TorrentConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SwarmTier {
    Hot,
    Warm,
    Cold,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SwarmState {
    Stopped,
    Checking,
    Queued,
    Downloading,
    Seeding,
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SwarmStateFilter {
    Downloading,
    Seeding,
    Paused,
    Queued,
    Checking,
    Error,
}

impl SwarmStateFilter {
    pub fn matches(&self, state: &SwarmState, tier: SwarmTier) -> bool {
        match self {
            SwarmStateFilter::Downloading => matches!(state, SwarmState::Downloading),
            SwarmStateFilter::Seeding => matches!(state, SwarmState::Seeding),
            SwarmStateFilter::Paused => matches!(state, SwarmState::Stopped) || tier == SwarmTier::Cold,
            SwarmStateFilter::Queued => matches!(state, SwarmState::Queued),
            SwarmStateFilter::Checking => matches!(state, SwarmState::Checking),
            SwarmStateFilter::Error => matches!(state, SwarmState::Error(_)),
        }
    }
}

/// Thread-safe, lock-free global metrics counter for high-scale swarm monitoring.
#[derive(Debug, Default)]
pub struct GlobalEngineMetrics {
    pub total_torrents: AtomicUsize,
    pub downloading_count: AtomicUsize,
    pub seeding_count: AtomicUsize,
    pub paused_count: AtomicUsize,
    pub queued_count: AtomicUsize,
    pub total_downloaded_bytes: AtomicU64,
    pub total_uploaded_bytes: AtomicU64,
    pub global_download_rate: AtomicU64,
    pub global_upload_rate: AtomicU64,
    pub global_peers_connected: AtomicUsize,
    pub active_actors: AtomicUsize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EngineMetricsSnapshot {
    pub total_torrents: usize,
    pub downloading_torrents: usize,
    pub seeding_torrents: usize,
    pub paused_torrents: usize,
    pub queued_torrents: usize,
    pub downloaded_bytes: u64,
    pub uploaded_bytes: u64,
    pub download_rate: u64,
    pub upload_rate: u64,
    pub peers_connected: usize,
    pub active_actors: usize,
}

impl GlobalEngineMetrics {
    pub fn snapshot(&self) -> EngineMetricsSnapshot {
        EngineMetricsSnapshot {
            total_torrents: self.total_torrents.load(Ordering::Relaxed),
            downloading_torrents: self.downloading_count.load(Ordering::Relaxed),
            seeding_torrents: self.seeding_count.load(Ordering::Relaxed),
            paused_torrents: self.paused_count.load(Ordering::Relaxed),
            queued_torrents: self.queued_count.load(Ordering::Relaxed),
            downloaded_bytes: self.total_downloaded_bytes.load(Ordering::Relaxed),
            uploaded_bytes: self.total_uploaded_bytes.load(Ordering::Relaxed),
            download_rate: self.global_download_rate.load(Ordering::Relaxed),
            upload_rate: self.global_upload_rate.load(Ordering::Relaxed),
            peers_connected: self.global_peers_connected.load(Ordering::Relaxed),
            active_actors: self.active_actors.load(Ordering::Relaxed),
        }
    }

    pub fn record_add(&self, state: &SwarmState, tier: SwarmTier, downloaded: u64, uploaded: u64) {
        self.total_torrents.fetch_add(1, Ordering::Relaxed);
        self.total_downloaded_bytes.fetch_add(downloaded, Ordering::Relaxed);
        self.total_uploaded_bytes.fetch_add(uploaded, Ordering::Relaxed);
        match state {
            SwarmState::Downloading => { self.downloading_count.fetch_add(1, Ordering::Relaxed); }
            SwarmState::Seeding => { self.seeding_count.fetch_add(1, Ordering::Relaxed); }
            SwarmState::Queued => { self.queued_count.fetch_add(1, Ordering::Relaxed); }
            SwarmState::Stopped => { self.paused_count.fetch_add(1, Ordering::Relaxed); }
            _ => {
                if tier == SwarmTier::Cold {
                    self.paused_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    pub fn record_remove(&self, s: &SwarmStats) {
        let _ = self.total_torrents.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
        let _ = self.total_downloaded_bytes.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(s.downloaded_bytes)));
        let _ = self.total_uploaded_bytes.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(s.uploaded_bytes)));
        let _ = self.global_download_rate.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(s.download_rate)));
        let _ = self.global_upload_rate.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(s.upload_rate)));
        let _ = self.global_peers_connected.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(s.peers_connected)));

        match s.state {
            SwarmState::Downloading => {
                let _ = self.downloading_count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
            }
            SwarmState::Seeding => {
                let _ = self.seeding_count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
            }
            SwarmState::Queued => {
                let _ = self.queued_count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
            }
            SwarmState::Stopped => {
                let _ = self.paused_count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
            }
            _ => {
                if s.tier == SwarmTier::Cold {
                    let _ = self.paused_count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
                }
            }
        }
    }

    pub fn record_state_transition(&self, old_state: &SwarmState, new_state: &SwarmState) {
        if old_state == new_state {
            return;
        }
        match old_state {
            SwarmState::Downloading => {
                let _ = self.downloading_count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
            }
            SwarmState::Seeding => {
                let _ = self.seeding_count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
            }
            SwarmState::Queued => {
                let _ = self.queued_count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
            }
            SwarmState::Stopped => {
                let _ = self.paused_count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
            }
            _ => {}
        }
        match new_state {
            SwarmState::Downloading => { self.downloading_count.fetch_add(1, Ordering::Relaxed); }
            SwarmState::Seeding => { self.seeding_count.fetch_add(1, Ordering::Relaxed); }
            SwarmState::Queued => { self.queued_count.fetch_add(1, Ordering::Relaxed); }
            SwarmState::Stopped => { self.paused_count.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }
    }

    pub fn record_rate_change(
        &self,
        old_dl: u64,
        new_dl: u64,
        old_ul: u64,
        new_ul: u64,
        old_peers: usize,
        new_peers: usize,
    ) {
        if new_dl >= old_dl {
            self.global_download_rate.fetch_add(new_dl - old_dl, Ordering::Relaxed);
        } else {
            let diff = old_dl - new_dl;
            let _ = self.global_download_rate.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |val| Some(val.saturating_sub(diff)));
        }
        if new_ul >= old_ul {
            self.global_upload_rate.fetch_add(new_ul - old_ul, Ordering::Relaxed);
        } else {
            let diff = old_ul - new_ul;
            let _ = self.global_upload_rate.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |val| Some(val.saturating_sub(diff)));
        }
        if new_peers >= old_peers {
            self.global_peers_connected.fetch_add(new_peers - old_peers, Ordering::Relaxed);
        } else {
            let diff = old_peers - new_peers;
            let _ = self.global_peers_connected.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |val| Some(val.saturating_sub(diff)));
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SwarmStats {
    pub info_hash: [u8; 20],
    pub name: String,
    pub total_size: u64,
    pub progress: f32,
    pub state: SwarmState,
    pub tier: SwarmTier,
    pub download_rate: u64,
    pub upload_rate: u64,
    pub downloaded_bytes: u64,
    pub uploaded_bytes: u64,
    pub peers_connected: usize,
    pub peers_sending: usize,
    pub eta_seconds: u64,
    pub ratio: f32,
    pub download_dir: String,
    pub added_at: i64,
    pub is_private: bool,
    pub is_stalled: bool,
    pub last_transfer_at: i64,
    #[serde(default)]
    pub piece_count: u32,
    #[serde(default)]
    pub piece_size: u32,
}

#[derive(Clone)]
pub struct ActiveActor {
    pub peer_event_tx: mpsc::Sender<PeerEvent>,
    pub command_tx: mpsc::Sender<TorrentCommand>,
    pub stop_tx: Option<Arc<oneshot::Sender<()>>>,
}

pub struct TorrentHandle {
    pub info: Arc<Info>,
    pub stats: Arc<RwLock<SwarmStats>>,
    pub compressed_bitfield: Arc<RwLock<Option<synapse_picker::RoaringBitfield>>>,
    pub active_actor: Arc<RwLock<Option<ActiveActor>>>,
    pub live_peers: Arc<RwLock<Vec<PeerSnapshot>>>,
    pub piece_availability: Arc<RwLock<Vec<u32>>>,
}

impl TorrentHandle {
    pub fn peer_event_tx(&self) -> Option<mpsc::Sender<PeerEvent>> {
        self.active_actor.read().as_ref().map(|a| a.peer_event_tx.clone())
    }

    pub fn command_tx(&self) -> Option<mpsc::Sender<TorrentCommand>> {
        self.active_actor.read().as_ref().map(|a| a.command_tx.clone())
    }

    pub fn is_active(&self) -> bool {
        self.active_actor.read().as_ref().is_some_and(|a| !a.peer_event_tx.is_closed())
    }

    /// Cleanly terminates the running torrent actor task, closing all peer sockets and releasing FDs.
    pub fn stop_actor(&self) {
        if let Some(actor) = self.active_actor.write().take() {
            let _ = actor.command_tx.try_send(TorrentCommand::Stop);
        }
        self.live_peers.write().clear();
    }

    pub fn is_private(&self) -> bool {
        self.info.private
    }

    pub fn allows_dht(&self) -> bool {
        !self.info.private
    }

    pub fn allows_pex(&self) -> bool {
        !self.info.private
    }

    pub fn allows_lsd(&self) -> bool {
        !self.info.private
    }
}

#[derive(Clone)]
pub struct SwarmEngine {
    torrents: Arc<DashMap<[u8; 20], Arc<TorrentHandle>>>,
    disk: Arc<DiskEngine>,
    peer_id: [u8; 20],
    listen_port: Arc<RwLock<u16>>,
    session_store: Option<Arc<SessionStore>>,
    lifecycle: Option<Arc<ConduitLifecycleDispatcher>>,
    download_bucket: Arc<TokenBucket>,
    upload_bucket: Arc<TokenBucket>,
    circuit_breaker: Arc<PeerCircuitBreaker>,
    queue_manager: Arc<RwLock<QueueManager>>,
    settings: Arc<RwLock<DynamicSessionSettings>>,
    metrics: Arc<GlobalEngineMetrics>,
    announce_scheduler: Arc<AnnounceScheduler>,
    idle_timeout: Duration,
    watch_dir: Option<PathBuf>,
}

impl SwarmEngine {
    pub fn new(disk: Arc<DiskEngine>, peer_id: [u8; 20]) -> Self {
        let listen_port = Arc::new(RwLock::new(0));
        let circuit_breaker = Arc::new(PeerCircuitBreaker::default());
        let announcer = Arc::new(Announcer::new(
            peer_id,
            listen_port.clone(),
            circuit_breaker.clone(),
        ));
        let announce_scheduler = AnnounceScheduler::new(
            announcer,
            32,
            Duration::from_secs(1800),
            Duration::from_secs(600),
        );
        announce_scheduler.clone().start();

        let engine = Self {
            torrents: Arc::new(DashMap::new()),
            disk,
            peer_id,
            listen_port,
            session_store: None,
            lifecycle: None,
            download_bucket: Arc::new(TokenBucket::unthrottled()),
            upload_bucket: Arc::new(TokenBucket::unthrottled()),
            circuit_breaker,
            queue_manager: Arc::new(RwLock::new(QueueManager::new(QueueConfig::default()))),
            settings: Arc::new(RwLock::new(DynamicSessionSettings::default())),
            metrics: Arc::new(GlobalEngineMetrics::default()),
            announce_scheduler: announce_scheduler.clone(),
            idle_timeout: Duration::from_secs(60),
            watch_dir: None,
        };

        let engine_clone = engine.clone();
        announce_scheduler.set_peer_router(Arc::new(move |hash| {
            engine_clone.get_or_wake_torrent(hash)
        }));

        engine
    }

    pub fn with_watch_dir(mut self, watch_dir: PathBuf) -> Self {
        self.watch_dir = Some(watch_dir);
        self
    }

    /// Attempts to recover the full `Info` struct for a swarm:
    /// 1. First from the session store's raw bencode snapshot.
    /// 2. If the snapshot was corrupted/evicted in an older version, falls back to scanning
    ///    `watch_dir`, `watch_dir/.imported/`, and `watch_dir/.failed/` for matching `.torrent` files.
    ///    Upon matching, repairs the session store so future restarts load instantly.
    pub fn try_recover_info(&self, info_hash: &[u8; 20]) -> Option<Info> {
        // 1. Try session store
        if let Some(ref store) = self.session_store {
            let hex_hash = hex::encode(info_hash);
            if let Ok(Some(state)) = store.load_torrent(&hex_hash) {
                if let Some(ref raw_hex) = state.raw_bencode_hex {
                    if let Ok(bytes) = hex::decode(raw_hex) {
                        if let Ok(bencode) = synapse_bencode::decode_buf(&bytes) {
                            if let Ok(reloaded) = Info::from_bencode(bencode) {
                                if &reloaded.hash == info_hash && reloaded.has_piece_hashes() {
                                    return Some(reloaded);
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Try scanning watch_dir and watch_dir/.imported for original .torrent file
        if let Some(ref watch_dir) = self.watch_dir {
            let candidates = [
                watch_dir.clone(),
                watch_dir.join(".imported"),
                watch_dir.join(".failed"),
            ];
            for dir in &candidates {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            if let Ok(bytes) = std::fs::read(&path) {
                                if let Ok(bencode) = synapse_bencode::decode_buf(&bytes) {
                                    if let Ok(reloaded) = Info::from_bencode(bencode) {
                                        if &reloaded.hash == info_hash && reloaded.has_piece_hashes() {
                                            tracing::info!(
                                                "Auto-healed corrupted session metadata for '{}' ({}) from {}",
                                                reloaded.name,
                                                hex::encode(info_hash),
                                                path.display()
                                            );
                                            // Repair session store so subsequent restarts don't need to rescan
                                            if let Some(ref store) = self.session_store {
                                                let hex_hash = hex::encode(info_hash);
                                                if let Ok(Some(mut state)) = store.load_torrent(&hex_hash) {
                                                    state.raw_bencode_hex = Some(hex::encode(&bytes));
                                                    let _ = store.save_torrent(&state);
                                                }
                                            }
                                            return Some(reloaded);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Attempts to recover full piece hashes for a swarm using `try_recover_info`.
    pub fn try_recover_piece_hashes(&self, info_hash: &[u8; 20]) -> Option<Vec<[u8; 20]>> {
        self.try_recover_info(info_hash)
            .and_then(|info| info.piece_hashes().map(|h| (*h).clone()))
    }

    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    pub fn with_session_store(mut self, store: Arc<SessionStore>) -> Self {
        self.session_store = Some(store);
        self
    }

    pub fn with_lifecycle(mut self, lifecycle: Arc<ConduitLifecycleDispatcher>) -> Self {
        self.lifecycle = Some(lifecycle);
        self
    }

    pub fn with_settings(self, settings: DynamicSessionSettings) -> Self {
        *self.settings.write() = settings.clone();
        *self.queue_manager.write() = QueueManager::new(settings.queue);
        self.recalculate_effective_rate_limits();
        self
    }

    /// Replaces the active session and queue settings dynamically and recalculates rate limits.
    pub fn update_settings(&self, settings: DynamicSessionSettings) {
        *self.settings.write() = settings.clone();
        *self.queue_manager.write() = QueueManager::new(settings.queue);
        self.recalculate_effective_rate_limits();
    }

    pub fn circuit_breaker(&self) -> &Arc<PeerCircuitBreaker> {
        &self.circuit_breaker
    }

    pub fn queue_manager(&self) -> &Arc<RwLock<QueueManager>> {
        &self.queue_manager
    }

    pub fn set_queue_config(&self, config: QueueConfig) {
        self.queue_manager.write().set_config(config);
    }

    pub fn global_metrics(&self) -> EngineMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn metrics_ref(&self) -> &Arc<GlobalEngineMetrics> {
        &self.metrics
    }

    pub fn announce_scheduler(&self) -> &Arc<AnnounceScheduler> {
        &self.announce_scheduler
    }

    /// Returns the live tracker status reports for the specified torrent info hash.
    pub fn get_tracker_reports(&self, info_hash: &[u8; 20]) -> Vec<TrackerReport> {
        let reports = self.announce_scheduler.get_tracker_reports(info_hash);
        if !reports.is_empty() {
            return reports;
        }
        if let Some(handle) = self.torrents.get(info_hash) {
            let candidate_urls = Announcer::candidate_trackers(&handle.info);
            candidate_urls
                .into_iter()
                .map(|u| TrackerReport {
                    url: u.to_string(),
                    status: "Stopped".into(),
                    seeders: 0,
                    leechers: 0,
                    next_announce_in: 0,
                    failure_reason: None,
                    is_circuit_broken: false,
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn shutdown(&self) {
        self.announce_scheduler.shutdown();
        for entry in self.torrents.iter() {
            entry.value().stop_actor();
        }
    }

    /// Dynamically awakens a Warm torrent into the Hot tier and returns its peer event sender.
    /// Cold/stopped torrents are never woken automatically.
    pub fn get_or_wake_torrent(&self, info_hash: &[u8; 20]) -> Option<mpsc::Sender<PeerEvent>> {
        let handle = self.torrents.get(info_hash)?;
        {
            let stats = handle.stats.read();
            if stats.tier == SwarmTier::Cold || stats.state == SwarmState::Stopped {
                return None;
            }
        }
        {
            let actor_guard = handle.active_actor.read();
            if let Some(ref actor) = *actor_guard {
                if !actor.peer_event_tx.is_closed() {
                    return Some(actor.peer_event_tx.clone());
                }
            }
        }
        self.wake_torrent_internal(handle.value())
            .map(|a| a.peer_event_tx)
    }

    /// Dynamically awakens a Warm torrent into the Hot tier and returns its command sender.
    /// Cold/stopped torrents are never woken automatically.
    pub fn get_or_wake_command_tx(&self, info_hash: &[u8; 20]) -> Option<mpsc::Sender<TorrentCommand>> {
        let handle = self.torrents.get(info_hash)?;
        {
            let stats = handle.stats.read();
            if stats.tier == SwarmTier::Cold || stats.state == SwarmState::Stopped {
                return None;
            }
        }
        {
            let actor_guard = handle.active_actor.read();
            if let Some(ref actor) = *actor_guard {
                if !actor.command_tx.is_closed() {
                    return Some(actor.command_tx.clone());
                }
            }
        }
        self.wake_torrent_internal(handle.value())
            .map(|a| a.command_tx)
    }

    /// Explicitly awakens a torrent into the Hot tier and returns its handle.
    pub fn wake_torrent(&self, info_hash: &[u8; 20]) -> Option<Arc<TorrentHandle>> {
        let handle = self.torrents.get(info_hash)?.clone();
        let _ = self.wake_torrent_internal(&handle);
        Some(handle)
    }

    fn wake_torrent_internal(&self, handle: &Arc<TorrentHandle>) -> Option<ActiveActor> {
        {
            let stats = handle.stats.read();
            if stats.tier == SwarmTier::Cold || stats.state == SwarmState::Stopped {
                return None;
            }
        }
        let mut actor_guard = handle.active_actor.write();
        if let Some(ref actor) = *actor_guard {
            if !actor.peer_event_tx.is_closed() {
                return Some(actor.clone());
            }
        }

        // If hashes were evicted (e.g. while seeding/warm) or missing, and this torrent is not seeding,
        // recover them from the session store or watch directory.
        if !handle.info.has_piece_hashes() {
            if let Some(hashes) = self.try_recover_piece_hashes(&handle.info.hash) {
                handle.info.restore_piece_hashes(hashes);
            }
        }

        let info = handle.info.clone();
        let download_dir = std::path::PathBuf::from(&handle.stats.read().download_dir);
        let have = handle.compressed_bitfield.read().as_ref().map(|b| b.to_bitfield());

        let (peer_tx, peer_rx) = mpsc::channel(256);
        let (command_tx, command_rx) = mpsc::channel(32);
        let (piece_tx, mut piece_rx) = mpsc::channel(128);

        let (complete_tx, complete_rx) = oneshot::channel();
        if let Some(lifecycle) = self.lifecycle.clone() {
            let info_clone = info.clone();
            let dl_dir = download_dir.clone();
            tokio::spawn(async move {
                if complete_rx.await.is_ok() {
                    info!("Torrent {} completed! Triggering Conduit lifecycle dispatcher", info_clone.name);
                    let mut trackers: Vec<String> = Vec::new();
                    if let Some(ref a) = info_clone.announce {
                        trackers.push(a.to_string());
                    }
                    for tier in &info_clone.url_list {
                        for url in tier {
                            let s = url.to_string();
                            if !trackers.contains(&s) {
                                trackers.push(s);
                            }
                        }
                    }
                    let _ = lifecycle.on_torrent_completed(
                        info_clone.hash,
                        &info_clone.name,
                        info_clone.total_len,
                        &dl_dir,
                        &info_clone.files,
                        &trackers,
                    ).await;
                }
            });
        }

        let config = TorrentConfig {
            info: info.clone(),
            download_dir: download_dir.clone(),
            peer_id: self.peer_id,
            disk: self.disk.clone(),
            mode: synapse_picker::Mode::RarestFirst,
            max_pipeline: 64,
            regular_unchokes: 8,
            optimistic_unchoke_interval: Duration::from_secs(30),
            tick_interval: Duration::from_millis(250),
            on_torrent_completed: Some(complete_tx),
            on_piece_completed: Some(piece_tx),
            stats: handle.stats.clone(),
            bitfield: handle.compressed_bitfield.clone(),
            download_bucket: self.download_bucket.clone(),
            upload_bucket: self.upload_bucket.clone(),
            global_metrics: Some(self.metrics.clone()),
            idle_timeout: Some(self.idle_timeout),
            live_peers: handle.live_peers.clone(),
            piece_availability: handle.piece_availability.clone(),
        };

        let torrent = Torrent::new(config, have.as_ref());
        self.metrics.active_actors.fetch_add(1, Ordering::Relaxed);
        {
            let mut s = handle.stats.write();
            s.tier = SwarmTier::Hot;
        }

        tokio::spawn(async move {
            torrent.run(peer_rx, command_rx).await;
        });

        let bitfield_worker = handle.compressed_bitfield.clone();
        let stats_worker = handle.stats.clone();
        let metrics_worker = self.metrics.clone();
        let scheduler_worker = self.announce_scheduler.clone();
        let total_pieces = info.pieces() as usize;
        let total_len = info.total_len;
        let hash_worker = info.hash;
        let store_worker = self.session_store.clone();
        let name_worker = info.name.clone();
        let dl_dir_str = download_dir.to_string_lossy().to_string();
        let raw_bencode_hex_worker = if info.has_piece_hashes() {
            Some(hex::encode(info.to_torrent_bytes()))
        } else {
            None
        };
        let added_at = handle.stats.read().added_at;

        let last_saved_secs = Arc::new(AtomicU64::new(0));
        const SAVE_THROTTLE: Duration = Duration::from_secs(5);

        tokio::spawn(async move {
            while let Some(piece_idx) = piece_rx.recv().await {
                let completed_count = {
                    let mut bf_guard = bitfield_worker.write();
                    if let Some(ref mut bf) = *bf_guard {
                        bf.set(piece_idx as usize);
                        bf.count_ones()
                    } else {
                        let mut bf = synapse_picker::RoaringBitfield::new(total_pieces);
                        bf.set(piece_idx as usize);
                        *bf_guard = Some(bf);
                        1
                    }
                };

                let progress = if total_pieces > 0 {
                    (completed_count as f32) / (total_pieces as f32)
                } else {
                    1.0
                };
                let dl_bytes = ((progress as f64) * (total_len as f64)) as u64;

                let was_dl = {
                    let mut s = stats_worker.write();
                    let was_downloading = s.state == SwarmState::Downloading;
                    s.progress = progress;
                    s.downloaded_bytes = dl_bytes;
                    if progress >= 1.0 {
                        s.state = SwarmState::Seeding;
                    }
                    was_downloading
                };
                if was_dl && progress >= 1.0 {
                    metrics_worker.record_state_transition(&SwarmState::Downloading, &SwarmState::Seeding);
                    scheduler_worker.notify_completed(&hash_worker);
                }

                if let Some(ref store) = store_worker {
                    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                    let prev = last_saved_secs.load(Ordering::Relaxed);
                    let should_save = progress >= 1.0 || now_secs.saturating_sub(prev) >= SAVE_THROTTLE.as_secs();

                    if should_save {
                        last_saved_secs.store(now_secs, Ordering::Relaxed);
                        let store = store.clone();
                        let bf_snapshot = bitfield_worker.read().clone();
                        let name_c = name_worker.clone();
                        let dl_dir_c = dl_dir_str.clone();
                        let raw_hex_c = raw_bencode_hex_worker.clone();
                        let uploaded_bytes = stats_worker.read().uploaded_bytes;
                        tokio::task::spawn_blocking(move || {
                            let bitfield_hex = bf_snapshot
                                .map(|b| hex::encode(b.to_bitfield().as_bytes()))
                                .unwrap_or_default();
                            let state = TorrentSessionState {
                                info_hash_hex: hex::encode(hash_worker),
                                name: name_c,
                                download_dir: dl_dir_c,
                                bitfield_hex,
                                total_pieces,
                                total_size: total_len,
                                uploaded_bytes,
                                downloaded_bytes: dl_bytes,
                                added_at,
                                is_paused: false,
                                magnet_uri: None,
                                raw_bencode_hex: raw_hex_c,
                            };
                            let _ = store.save_torrent(&state);
                        });
                    }
                }
            }
        });

        let actor = ActiveActor {
            peer_event_tx: peer_tx,
            command_tx,
            stop_tx: None,
        };
        *actor_guard = Some(actor.clone());
        Some(actor)
    }

    /// Transmission-style queue reconciliation: detects stalled downloads and promotes queued torrents.
    pub fn reconcile_queue(&self) {
        let qm = self.queue_manager.read();
        let mut active_non_stalled = 0;
        let mut queued_hashes = Vec::new();

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for entry in self.torrents.iter() {
            let handle = entry.value();
            let mut stats = handle.stats.write();
            if stats.state == SwarmState::Downloading {
                let last_activity = if stats.last_transfer_at > 0 {
                    stats.last_transfer_at as u64
                } else {
                    stats.added_at as u64
                };
                let elapsed_secs = now_secs.saturating_sub(last_activity);
                let stalled = qm.is_stalled(
                    stats.peers_connected,
                    stats.download_rate,
                    stats.downloaded_bytes,
                    stats.total_size,
                    Duration::from_secs(elapsed_secs),
                );
                stats.is_stalled = stalled;
                if !stalled {
                    active_non_stalled += 1;
                }
            } else if stats.state == SwarmState::Seeding {
                let elapsed_secs = now_secs.saturating_sub(stats.added_at as u64);
                let action = qm.evaluate_seeder(1, self.torrents.len(), stats.ratio as f64, elapsed_secs);
                if matches!(action, QueueAction::AutoStopRatioReached | QueueAction::AutoStopSeedTimeReached) {
                    stats.state = SwarmState::Stopped;
                    stats.tier = SwarmTier::Cold;
                    self.metrics.record_state_transition(&SwarmState::Seeding, &SwarmState::Stopped);
                    drop(stats);
                    handle.stop_actor();
                }
            } else if stats.state == SwarmState::Queued {
                queued_hashes.push(stats.info_hash);
            }
        }

        for hash in queued_hashes {
            if qm.evaluate_downloader(active_non_stalled, self.torrents.len()) == QueueAction::Allow {
                if let Some(handle) = self.torrents.get(&hash) {
                    let mut s = handle.stats.write();
                    s.state = SwarmState::Downloading;
                    s.tier = SwarmTier::Hot;
                    self.metrics.record_state_transition(&SwarmState::Queued, &SwarmState::Downloading);
                    drop(s);
                    let _ = self.wake_torrent_internal(&handle);
                    let peer_tx = handle.peer_event_tx().unwrap_or_else(|| mpsc::channel(1).0);
                    self.announce_scheduler.register(
                        hash,
                        handle.info.clone(),
                        handle.stats.clone(),
                        peer_tx,
                        true,
                    );
                    active_non_stalled += 1;
                }
            }
        }
    }

    pub fn session_store(&self) -> Option<&Arc<SessionStore>> {
        self.session_store.as_ref()
    }

    pub fn lifecycle(&self) -> Option<&Arc<ConduitLifecycleDispatcher>> {
        self.lifecycle.as_ref()
    }

    pub fn torrent_count(&self) -> usize {
        self.torrents.len()
    }

    /// Returns the number of currently active swarm actors running background tick loops.
    pub fn active_swarm_count(&self) -> usize {
        self.torrents.iter().filter(|t| t.value().is_active()).count()
    }

    pub fn get_torrent(&self, info_hash: &[u8; 20]) -> Option<Arc<TorrentHandle>> {
        self.torrents.get(info_hash).map(|r| r.value().clone())
    }

    pub fn list_torrents(&self) -> Vec<SwarmStats> {
        self.torrents
            .iter()
            .map(|r| r.value().stats.read().clone())
            .collect()
    }

    /// High-performance engine-level pagination that avoids cloning the entire swarm collection.
    pub fn list_torrents_paged(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<SwarmStateFilter>,
    ) -> (Vec<SwarmStats>, usize) {
        if let Some(f) = filter {
            let mut matching_count = 0;
            let mut items = Vec::with_capacity(limit.min(100));
            for entry in self.torrents.iter() {
                let stats = entry.value().stats.read();
                if f.matches(&stats.state, stats.tier) {
                    if matching_count >= offset && items.len() < limit {
                        items.push(stats.clone());
                    }
                    matching_count += 1;
                }
            }
            (items, matching_count)
        } else {
            let total = self.torrents.len();
            let items: Vec<SwarmStats> = self
                .torrents
                .iter()
                .skip(offset)
                .take(limit)
                .map(|r| r.value().stats.read().clone())
                .collect();
            (items, total)
        }
    }

    pub fn add_magnet(
        &self,
        magnet_uri: &str,
        download_dir: std::path::PathBuf,
    ) -> Result<Arc<TorrentHandle>, synapse_meta::MetaError> {
        let info = Arc::new(synapse_meta::Info::from_magnet(magnet_uri)?);
        Ok(self.add_torrent(info, download_dir, None))
    }

    pub fn add_torrent(
        &self,
        info: Arc<Info>,
        download_dir: std::path::PathBuf,
        have: Option<&Bitfield>,
    ) -> Arc<TorrentHandle> {
        let info_hash = info.hash;

        let total_size = info.total_len;
        let name = info.name.clone();
        let added_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let initial_progress = if let Some(h) = have {
            if h.is_complete() { 1.0 } else { (h.count_ones() as f32) / (info.pieces() as f32) }
        } else { 0.0 };
        let initial_downloaded = ((initial_progress as f64) * (total_size as f64)) as u64;

        // Seeding swarms (100% complete) initialize in the Warm tier (standby seed)
        // without spawning an idle actor ticker task until peers connect.
        let (initial_state, initial_tier) = if initial_progress >= 1.0 {
            (SwarmState::Seeding, SwarmTier::Warm)
        } else {
            let qm = self.queue_manager.read();
            let active_dl = self.torrents.iter().filter(|t| {
                let s = t.value().stats.read();
                s.state == SwarmState::Downloading && !s.is_stalled
            }).count();
            if qm.evaluate_downloader(active_dl, self.torrents.len()) == QueueAction::Allow {
                (SwarmState::Downloading, SwarmTier::Hot)
            } else {
                (SwarmState::Queued, SwarmTier::Warm)
            }
        };

        let initial_stats = SwarmStats {
            info_hash,
            name: name.clone(),
            total_size,
            progress: initial_progress,
            state: initial_state.clone(),
            tier: initial_tier,
            download_rate: 0,
            upload_rate: 0,
            downloaded_bytes: initial_downloaded,
            uploaded_bytes: 0,
            peers_connected: 0,
            peers_sending: 0,
            eta_seconds: 0,
            ratio: 0.0,
            download_dir: download_dir.to_string_lossy().to_string(),
            added_at,
            is_private: info.private,
            is_stalled: false,
            last_transfer_at: added_at,
            piece_count: info.pieces(),
            piece_size: info.piece_len,
        };

        self.metrics.record_add(&initial_state, initial_tier, initial_downloaded, 0);

        let stats = Arc::new(RwLock::new(initial_stats));
        let compressed_bitfield = Arc::new(RwLock::new(have.map(synapse_picker::RoaringBitfield::from_bitfield)));

        if let Some(ref store) = self.session_store {
            let bitfield_hex = have.map(|h| hex::encode(h.as_bytes())).unwrap_or_default();
            let state = TorrentSessionState {
                info_hash_hex: hex::encode(info_hash),
                name: name.clone(),
                download_dir: download_dir.to_string_lossy().to_string(),
                bitfield_hex,
                total_pieces: info.pieces() as usize,
                total_size,
                uploaded_bytes: 0,
                downloaded_bytes: initial_downloaded,
                added_at,
                is_paused: false,
                magnet_uri: None,
                raw_bencode_hex: Some(hex::encode(info.to_torrent_bytes())),
            };
            let _ = store.save_torrent(&state);
        }

        let initial_availability = if initial_state == SwarmState::Seeding {
            vec![1u32; info.pieces() as usize]
        } else {
            vec![0u32; info.pieces() as usize]
        };
        let piece_availability = Arc::new(RwLock::new(initial_availability));

        let handle = Arc::new(TorrentHandle {
            info: info.clone(),
            stats: stats.clone(),
            compressed_bitfield,
            active_actor: Arc::new(RwLock::new(None)),
            live_peers: Arc::new(RwLock::new(Vec::new())),
            piece_availability,
        });

        if initial_state == SwarmState::Seeding {
            info.evict_piece_hashes();
        }

        self.torrents.insert(info_hash, handle.clone());

        // Awaken actor immediately if Hot
        let peer_tx = if initial_tier == SwarmTier::Hot {
            self.wake_torrent_internal(&handle)
                .map(|a| a.peer_event_tx)
                .unwrap_or_else(|| {
                    let (tx, _) = mpsc::channel(1);
                    tx
                })
        } else {
            let (tx, _) = mpsc::channel(1);
            tx
        };

        let is_dl = initial_state == SwarmState::Downloading;
        self.announce_scheduler.register(
            info_hash,
            info,
            stats,
            peer_tx,
            is_dl,
        );

        handle
    }

    /// Flushes all active swarm session states to disk synchronously or during shutdown.
    pub async fn flush_session(&self) {
        if let Some(ref store) = self.session_store {
            let snapshots: Vec<TorrentSessionState> = self
                .torrents
                .iter()
                .map(|r| {
                    let h = r.value();
                    let s = h.stats.read().clone();
                    let bf = h.compressed_bitfield.read().clone();
                    let bitfield_hex = bf
                        .map(|b| hex::encode(b.to_bitfield().as_bytes()))
                        .unwrap_or_default();
                    TorrentSessionState {
                        info_hash_hex: hex::encode(s.info_hash),
                        name: s.name,
                        download_dir: s.download_dir,
                        bitfield_hex,
                        total_pieces: h.info.pieces() as usize,
                        total_size: s.total_size,
                        uploaded_bytes: s.uploaded_bytes,
                        downloaded_bytes: s.downloaded_bytes,
                        added_at: s.added_at,
                        is_paused: matches!(s.tier, SwarmTier::Cold),
                        magnet_uri: None,
                        raw_bencode_hex: if h.info.has_piece_hashes() {
                            Some(hex::encode(h.info.to_torrent_bytes()))
                        } else {
                            None
                        },
                    }
                })
                .collect();

            let store = store.clone();
            let _ = tokio::task::spawn_blocking(move || {
                for snap in snapshots {
                    let _ = store.save_torrent(&snap);
                }
            })
            .await;
        }
    }

    /// Rechecks torrent files on disk and verifies integrity — dispatched to the torrent's own
    /// task via `TorrentCommand::Recheck` (see `Torrent::handle_recheck`), which owns the
    /// picker/bitfield state a real recheck needs to rebuild. Previously this just flipped the
    /// reported state to `Checking` for cosmetic effect and never touched the files on disk.
    pub fn recheck_torrent(&self, info_hash: &[u8; 20]) -> bool {
        if let Some(handle) = self.torrents.get(info_hash) {
            // If hashes were evicted for memory savings during seeding, recover them on-demand
            if !handle.info.has_piece_hashes() {
                if let Some(hashes) = self.try_recover_piece_hashes(info_hash) {
                    handle.info.restore_piece_hashes(hashes);
                }
            }
        }

        if let Some(tx) = self.get_or_wake_command_tx(info_hash) {
            if let Some(handle) = self.torrents.get(info_hash) {
                handle.stats.write().state = SwarmState::Checking;
            }
            let _ = tx.try_send(TorrentCommand::Recheck);
            true
        } else {
            false
        }
    }

    /// Sets download priority for a specific file inside a multi-file torrent — dispatched to
    /// `Torrent::apply_file_priority` via `TorrentCommand::SetFilePriority`, which actually
    /// masks the file's pieces in the picker. Previously this only checked the torrent existed
    /// and never touched what got downloaded.
    pub fn set_file_priority(&self, info_hash: &[u8; 20], file_index: u32, priority: u8) -> bool {
        if let Some(tx) = self.get_or_wake_command_tx(info_hash) {
            let _ = tx.try_send(TorrentCommand::SetFilePriority(file_index, priority));
            true
        } else {
            false
        }
    }

    /// Moves an active swarm's downloaded files to a new directory — dispatched to
    /// `Torrent::handle_set_location` via `TorrentCommand::SetLocation`, which does the actual
    /// file move. Previously this only relabeled `stats.download_dir` without moving anything
    /// on disk, silently diverging from where the files actually were.
    pub fn set_location(&self, info_hash: &[u8; 20], new_download_dir: &str) -> bool {
        if let Some(tx) = self.get_or_wake_command_tx(info_hash) {
            let _ = tx.try_send(TorrentCommand::SetLocation(std::path::PathBuf::from(new_download_dir)));
            true
        } else {
            false
        }
    }

    /// Configures global download and upload rate limits in bytes per second (0 = unlimited).
    pub fn set_rate_limits(&self, download_limit_bytes: u64, upload_limit_bytes: u64) {
        {
            let mut s = self.settings.write();
            s.download_limit_bytes = download_limit_bytes;
            s.download_limit_enabled = download_limit_bytes > 0;
            s.upload_limit_bytes = upload_limit_bytes;
            s.upload_limit_enabled = upload_limit_bytes > 0;
        }
        self.recalculate_effective_rate_limits();
    }

    pub fn settings(&self) -> Arc<RwLock<DynamicSessionSettings>> {
        self.settings.clone()
    }

    pub fn get_session_settings(&self) -> DynamicSessionSettings {
        self.settings.read().clone()
    }

    /// Returns the available disk space in bytes on the filesystem backing the configured `download_dir`.
    pub fn free_disk_space_bytes(&self) -> u64 {
        let download_dir = self.settings.read().download_dir.clone();
        crate::fs::get_available_disk_space(&download_dir)
    }

    /// Returns the available disk space in bytes for a specific target path.
    pub fn free_disk_space_for_path(&self, path: &std::path::Path) -> u64 {
        crate::fs::get_available_disk_space(path)
    }

    /// Checks if Turtle Mode (alt speed) is currently active (either manually toggled or via time schedule).
    pub fn is_alt_speed_active(&self) -> bool {
        let s = self.settings.read();
        if s.alt_speed_enabled {
            return true;
        }
        if s.alt_speed_time_enabled {
            let (current_mins, current_day) = crate::settings::current_time_mins_and_day();
            return crate::settings::is_in_alt_speed_schedule(
                current_mins,
                current_day,
                s.alt_speed_time_begin,
                s.alt_speed_time_end,
                s.alt_speed_time_days,
            );
        }
        false
    }

    /// Recalculates effective token-bucket rates based on active throttle and turtle mode settings.
    pub fn recalculate_effective_rate_limits(&self) {
        let is_alt = self.is_alt_speed_active();
        let s = self.settings.read();
        if is_alt {
            self.download_bucket.set_rate(s.alt_speed_down_bytes, s.alt_speed_down_bytes);
            self.upload_bucket.set_rate(s.alt_speed_up_bytes, s.alt_speed_up_bytes);
        } else {
            let dl = if s.download_limit_enabled { s.download_limit_bytes } else { 0 };
            let ul = if s.upload_limit_enabled { s.upload_limit_bytes } else { 0 };
            self.download_bucket.set_rate(dl, dl);
            self.upload_bucket.set_rate(ul, ul);
        }
    }

    /// Applies dynamic settings updates in flight. Returns a list of warning messages
    /// for any provided parameters that require a full daemon restart.
    pub fn update_session_settings(&self, update: SessionSettingsUpdate) -> Vec<String> {
        let mut warnings = Vec::new();
        if update.peer_port.is_some() {
            warnings.push("peer_port requires daemon restart to rebind network socket".to_string());
        }
        if update.rpc_listen_addr.is_some() {
            warnings.push("rpc_listen_addr requires daemon restart to rebind gRPC listener".to_string());
        }
        if update.http_listen_addr.is_some() {
            warnings.push("http_listen_addr requires daemon restart to rebind REST API listener".to_string());
        }

        {
            let mut s = self.settings.write();
            if let Some(v) = update.download_limit_enabled { s.download_limit_enabled = v; }
            if let Some(v) = update.download_limit_bytes { s.download_limit_bytes = v; }
            if let Some(v) = update.upload_limit_enabled { s.upload_limit_enabled = v; }
            if let Some(v) = update.upload_limit_bytes { s.upload_limit_bytes = v; }

            if let Some(v) = update.alt_speed_enabled { s.alt_speed_enabled = v; }
            if let Some(v) = update.alt_speed_down_bytes { s.alt_speed_down_bytes = v; }
            if let Some(v) = update.alt_speed_up_bytes { s.alt_speed_up_bytes = v; }
            if let Some(v) = update.alt_speed_time_enabled { s.alt_speed_time_enabled = v; }
            if let Some(v) = update.alt_speed_time_begin { s.alt_speed_time_begin = v; }
            if let Some(v) = update.alt_speed_time_end { s.alt_speed_time_end = v; }
            if let Some(v) = update.alt_speed_time_days { s.alt_speed_time_days = v; }

            if let Some(v) = update.download_queue_enabled { s.queue.download_queue_enabled = v; }
            if let Some(v) = update.download_queue_size { s.queue.max_active_downloads = v; }
            if let Some(v) = update.seed_queue_enabled { s.queue.seed_queue_enabled = v; }
            if let Some(v) = update.seed_queue_size { s.queue.max_active_seeds = v; }
            if let Some(v) = update.max_active_torrents { s.queue.max_active_torrents = v; }
            if let Some(v) = update.queue_stalled_enabled { s.queue.queue_stalled_enabled = v; }
            if let Some(v) = update.queue_stalled_minutes { s.queue.queue_stalled_minutes = v; }
            if let Some(v) = update.seed_ratio_limited { s.queue.seed_ratio_limited = v; }
            if let Some(v) = update.seed_ratio_limit { s.queue.share_ratio_limit = Some(v); }
            if let Some(v) = update.idle_seeding_limit_enabled { s.queue.idle_seeding_limit_enabled = v; }
            if let Some(v) = update.idle_seeding_limit_minutes { s.queue.seed_time_limit_secs = Some((v as u64) * 60); }

            if let Some(v) = update.max_peers_per_torrent { s.max_peers_per_torrent = v; }
            if let Some(v) = update.max_global_peers { s.max_global_peers = v; }
            if let Some(v) = update.dht_enabled { s.dht_enabled = v; }
            if let Some(v) = update.pex_enabled { s.pex_enabled = v; }
            if let Some(v) = update.lsd_enabled { s.lsd_enabled = v; }
            if let Some(v) = update.encryption { s.encryption = v; }

            if let Some(v) = update.download_dir { s.download_dir = std::path::PathBuf::from(v); }
            if let Some(v) = update.incomplete_dir { s.incomplete_dir = Some(std::path::PathBuf::from(v)); }
            if let Some(v) = update.incomplete_dir_enabled { s.incomplete_dir_enabled = v; }
            if let Some(v) = update.start_added_torrents { s.start_added_torrents = v; }
            if let Some(v) = update.trash_original_torrent_files { s.trash_original_torrent_files = v; }

            self.queue_manager.write().set_config(s.queue.clone());
        }

        self.recalculate_effective_rate_limits();
        warnings
    }

    /// Transitions an active torrent to the Warm tier (idle seeding with compressed Roaring Bitfield).
    pub fn transition_to_warm(&self, info_hash: &[u8; 20]) -> bool {
        if let Some(handle) = self.torrents.get(info_hash) {
            let mut stats = handle.stats.write();
            stats.tier = SwarmTier::Warm;
            drop(stats);
            handle.stop_actor();
            true
        } else {
            false
        }
    }

    /// Transitions an active torrent to the Cold tier (paused / stopped).
    pub fn transition_to_cold(&self, info_hash: &[u8; 20]) -> bool {
        if let Some(handle) = self.torrents.get(info_hash) {
            let mut stats = handle.stats.write();
            let old_state = stats.state.clone();
            let old_dl = stats.download_rate;
            let old_ul = stats.upload_rate;
            let old_peers = stats.peers_connected;
            stats.tier = SwarmTier::Cold;
            stats.state = SwarmState::Stopped;
            stats.download_rate = 0;
            stats.upload_rate = 0;
            stats.peers_connected = 0;
            stats.peers_sending = 0;
            self.metrics.record_rate_change(old_dl, 0, old_ul, 0, old_peers, 0);
            self.metrics.record_state_transition(&old_state, &SwarmState::Stopped);
            drop(stats);
            handle.stop_actor();
            self.announce_scheduler.unregister(info_hash);

            if let Some(ref store) = self.session_store {
                let hex_hash = hex::encode(info_hash);
                if let Ok(Some(mut state)) = store.load_torrent(&hex_hash) {
                    state.is_paused = true;
                    let _ = store.save_torrent(&state);
                }
            }
            true
        } else {
            false
        }
    }

    /// Transitions a torrent back to the Hot tier for active transfers.
    pub fn transition_to_hot(&self, info_hash: &[u8; 20]) -> bool {
        if let Some(handle) = self.torrents.get(info_hash) {
            let mut stats = handle.stats.write();
            let old_state = stats.state.clone();
            let target_state = if stats.progress >= 1.0 {
                SwarmState::Seeding
            } else {
                SwarmState::Downloading
            };
            stats.tier = SwarmTier::Hot;
            stats.state = target_state.clone();
            self.metrics.record_state_transition(&old_state, &target_state);
            drop(stats);

            let is_dl = target_state == SwarmState::Downloading;
            let _ = self.wake_torrent_internal(&handle);
            let peer_tx = handle.peer_event_tx().unwrap_or_else(|| mpsc::channel(1).0);
            self.announce_scheduler.register(
                *info_hash,
                handle.info.clone(),
                handle.stats.clone(),
                peer_tx,
                is_dl,
            );
            self.announce_scheduler.notify_resumed(info_hash);
            true
        } else {
            false
        }
    }

    pub fn remove_torrent(&self, info_hash: &[u8; 20]) -> bool {
        self.announce_scheduler.unregister(info_hash);
        if let Some(ref store) = self.session_store {
            let _ = store.remove_torrent(info_hash);
        }
        if let Some((_, handle)) = self.torrents.remove(info_hash) {
            handle.stop_actor();
            let s = handle.stats.read();
            self.metrics.record_remove(&s);
            true
        } else {
            false
        }
    }

    pub fn restore_session(&self) -> std::io::Result<usize> {
        let Some(ref store) = self.session_store else {
            return Ok(0);
        };
        let states = store.load_all()?;
        let mut restored = 0;
        for state in states {
            if let Some(info_hash) = state.info_hash() {
                if self.torrents.contains_key(&info_hash) {
                    continue;
                }
                // First try recovering pristine Info (from session store if valid, or watch_dir auto-heal)
                let info_result = if let Some(recovered) = self.try_recover_info(&info_hash) {
                    Some(recovered)
                } else if let Some(ref hex_str) = state.raw_bencode_hex {
                    if let Ok(bytes) = hex::decode(hex_str) {
                        if let Ok(bencode) = synapse_bencode::decode_buf(&bytes) {
                            if let Ok(mut info) = Info::from_bencode(bencode) {
                                if info.hash != info_hash {
                                    // If piece hashes were evicted prior to session persistence,
                                    // info.pieces will be 0 while state.total_pieces is > 0.
                                    if info.pieces == 0 && state.total_pieces > 0 {
                                        tracing::info!(
                                            "Restoring seeding swarm '{}' ({}) whose piece hashes were previously evicted",
                                            state.name,
                                            state.info_hash_hex
                                        );
                                        info.hash = info_hash;
                                        info.pieces = state.total_pieces as u32;
                                    } else {
                                        tracing::warn!(
                                            "Session file hash mismatch for '{}' (header hash: {}, payload hash: {}). Skipping without purging.",
                                            state.name,
                                            state.info_hash_hex,
                                            hex::encode(info.hash)
                                        );
                                        continue;
                                    }
                                }
                                if !info.has_piece_hashes() {
                                    if let Some(hashes) = self.try_recover_piece_hashes(&info_hash) {
                                        if info.pieces == 0 {
                                            info.pieces = hashes.len() as u32;
                                        }
                                        info.restore_piece_hashes(hashes);
                                    }
                                }
                                Some(info)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(info) = info_result {
                    let have = state.to_bitfield();
                    self.add_torrent(
                        Arc::new(info),
                        std::path::PathBuf::from(&state.download_dir),
                        have.as_ref(),
                    );
                    restored += 1;
                }
            }
        }
        Ok(restored)
    }

    pub async fn start_listener(
        self: Arc<Self>,
        bind_addr: SocketAddr,
    ) -> Result<tokio::task::JoinHandle<()>, std::io::Error> {
        let listener = TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        *self.listen_port.write() = local_addr.port();
        info!("SwarmEngine inbound TCP listener active on {}", local_addr);

        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, remote_addr)) => {
                        let engine = self.clone();
                        tokio::spawn(async move {
                            let _ = accept_router(
                                socket,
                                remote_addr,
                                engine.peer_id,
                                |hash| {
                                    let tx = engine.get_or_wake_torrent(&hash)?;
                                    let is_private = engine
                                        .torrents
                                        .get(&hash)
                                        .map(|h| h.is_private())
                                        .unwrap_or(false);
                                    Some((tx, is_private))
                                },
                            ).await;
                        });
                    }
                    Err(e) => {
                        warn!("Error accepting inbound peer connection: {}", e);
                    }
                }
            }
        });

        Ok(handle)
    }
}
