use crate::atomic_compat::FetchUpdateCompat;
use dashmap::{DashMap, DashSet};
use parking_lot::{Mutex, RwLock};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use diskio::{DiskEngine, ReadJob};
use sha1::{Digest, Sha1};
use synapse_meta::Info;
use synapse_picker::Bitfield;

use crate::announcer::{AnnounceScheduler, Announcer, TrackerReport};
use crate::circuit_breaker::PeerCircuitBreaker;
use crate::ipfilter::IpFilter;
use crate::lifecycle::LifecycleDispatcher;
use crate::lsd::LsdManager;
use crate::peer::{accept_router_indexed, PeerEvent};
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
            SwarmStateFilter::Paused => {
                matches!(state, SwarmState::Stopped) || tier == SwarmTier::Cold
            }
            SwarmStateFilter::Queued => matches!(state, SwarmState::Queued),
            SwarmStateFilter::Checking => matches!(state, SwarmState::Checking),
            SwarmStateFilter::Error => matches!(state, SwarmState::Error(_)),
        }
    }
}

/// Thread-safe, lock-free global metrics counter for high-scale swarm monitoring.
/// Clears every bit of a resumed `have` bitfield whose backing data cannot exist on disk:
/// a piece counts as complete only if every file it touches exists and is at least long
/// enough to contain its bytes. Catches a download directory that was wiped, moved, or
/// truncated since the session was saved, which would otherwise leave the torrent
/// claiming (and serving) data it does not have. Returns how many pieces were dropped.
///
/// This checks presence and length only; a full content check is the explicit recheck.
fn verify_resume_bitfield(
    info: &Info,
    download_dir: &std::path::Path,
    have: &mut Bitfield,
) -> usize {
    let part_file = crate::part_file::PartFileManager::new(download_dir.to_path_buf(), info.hash);
    let file_lens: Vec<Option<u64>> = info
        .files
        .iter()
        .map(|f| {
            std::fs::metadata(download_dir.join(&f.path))
                .ok()
                .filter(|m| m.is_file())
                .map(|m| m.len())
        })
        .collect();
    let mut dropped = 0;
    for piece in 0..info.pieces() {
        if !have.has(piece as usize) {
            continue;
        }
        let backed = info
            .block_locations(piece, 0, info.piece_len(piece))
            .iter()
            .all(|loc| {
                let span = loc.piece_range.len() as u64;
                file_lens[loc.file].is_some_and(|len| len >= loc.file_offset + span)
                    // Bytes of a skipped file's boundary piece live in the part file instead.
                    || part_file.covers(loc.file, loc.file_offset, span)
            });
        if !backed {
            have.unset(piece as usize);
            dropped += 1;
        }
    }
    dropped
}

/// How long a newly started download counts against the active-download limit even though its
/// throughput is still below the "slow" threshold (libtorrent's `auto_manage_startup`).
const AUTO_MANAGE_STARTUP: Duration = Duration::from_secs(120);

/// Inbound connections allowed to sit mid-handshake at once.
const MAX_PENDING_HANDSHAKES: usize = 64;

/// Connections accepted beyond `max_global_peers` before new ones are refused pre-handshake
/// (libtorrent's `connections_limit` slack).
const CONNECTION_SLACK: usize = 10;

#[derive(Debug, Default)]
pub struct GlobalEngineMetrics {
    pub total_torrents: AtomicUsize,
    pub downloading_count: AtomicUsize,
    pub seeding_count: AtomicUsize,
    pub paused_count: AtomicUsize,
    pub queued_count: AtomicUsize,
    pub checking_count: AtomicUsize,
    pub error_count: AtomicUsize,
    pub total_downloaded_bytes: AtomicU64,
    pub total_uploaded_bytes: AtomicU64,
    pub global_download_rate: AtomicU64,
    pub global_upload_rate: AtomicU64,
    pub global_peers_connected: AtomicUsize,
    pub active_actors: AtomicUsize,
    /// Addresses banned by smart-ban (peers caught poisoning pieces).
    pub peers_banned: AtomicU64,
    pub chokes_total: AtomicU64,
    pub unchokes_total: AtomicU64,
    pub piece_requests_total: AtomicU64,
    pub piece_rejects_total: AtomicU64,
    pub hash_fails_total: AtomicU64,
    pub utp_packet_loss_total: AtomicU64,
    pub dht_dos_blocks_total: AtomicU64,
    pub event_bus_lag_total: AtomicU64,
    pub last_flush_duration_ms: AtomicU64,
    pub last_sync_duration_ms: AtomicU64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EngineMetricsSnapshot {
    pub total_torrents: usize,
    pub downloading_torrents: usize,
    pub seeding_torrents: usize,
    pub paused_torrents: usize,
    pub queued_torrents: usize,
    #[serde(default)]
    pub checking_torrents: usize,
    #[serde(default)]
    pub error_torrents: usize,
    pub downloaded_bytes: u64,
    pub uploaded_bytes: u64,
    pub download_rate: u64,
    pub upload_rate: u64,
    pub peers_connected: usize,
    pub active_actors: usize,
    #[serde(default)]
    pub peers_banned: u64,
    #[serde(default)]
    pub chokes_total: u64,
    #[serde(default)]
    pub unchokes_total: u64,
    #[serde(default)]
    pub piece_requests_total: u64,
    #[serde(default)]
    pub piece_rejects_total: u64,
    #[serde(default)]
    pub hash_fails_total: u64,
    #[serde(default)]
    pub utp_packet_loss_total: u64,
    #[serde(default)]
    pub dht_dos_blocks_total: u64,
    #[serde(default)]
    pub event_bus_lag_total: u64,
    #[serde(default)]
    pub last_flush_duration_ms: u64,
    #[serde(default)]
    pub last_sync_duration_ms: u64,
}

impl GlobalEngineMetrics {
    pub fn snapshot(&self) -> EngineMetricsSnapshot {
        EngineMetricsSnapshot {
            total_torrents: self.total_torrents.load(Ordering::Relaxed),
            downloading_torrents: self.downloading_count.load(Ordering::Relaxed),
            seeding_torrents: self.seeding_count.load(Ordering::Relaxed),
            paused_torrents: self.paused_count.load(Ordering::Relaxed),
            queued_torrents: self.queued_count.load(Ordering::Relaxed),
            checking_torrents: self.checking_count.load(Ordering::Relaxed),
            error_torrents: self.error_count.load(Ordering::Relaxed),
            downloaded_bytes: self.total_downloaded_bytes.load(Ordering::Relaxed),
            uploaded_bytes: self.total_uploaded_bytes.load(Ordering::Relaxed),
            download_rate: self.global_download_rate.load(Ordering::Relaxed),
            upload_rate: self.global_upload_rate.load(Ordering::Relaxed),
            peers_connected: self.global_peers_connected.load(Ordering::Relaxed),
            active_actors: self.active_actors.load(Ordering::Relaxed),
            peers_banned: self.peers_banned.load(Ordering::Relaxed),
            chokes_total: self.chokes_total.load(Ordering::Relaxed),
            unchokes_total: self.unchokes_total.load(Ordering::Relaxed),
            piece_requests_total: self.piece_requests_total.load(Ordering::Relaxed),
            piece_rejects_total: self.piece_rejects_total.load(Ordering::Relaxed),
            hash_fails_total: self.hash_fails_total.load(Ordering::Relaxed),
            utp_packet_loss_total: self.utp_packet_loss_total.load(Ordering::Relaxed),
            dht_dos_blocks_total: self.dht_dos_blocks_total.load(Ordering::Relaxed),
            event_bus_lag_total: self.event_bus_lag_total.load(Ordering::Relaxed),
            last_flush_duration_ms: self.last_flush_duration_ms.load(Ordering::Relaxed),
            last_sync_duration_ms: self.last_sync_duration_ms.load(Ordering::Relaxed),
        }
    }

    pub fn record_add(&self, state: &SwarmState, _tier: SwarmTier, downloaded: u64, uploaded: u64) {
        self.total_torrents.fetch_add(1, Ordering::Relaxed);
        self.total_downloaded_bytes
            .fetch_add(downloaded, Ordering::Relaxed);
        self.total_uploaded_bytes
            .fetch_add(uploaded, Ordering::Relaxed);
        match state {
            SwarmState::Downloading => {
                self.downloading_count.fetch_add(1, Ordering::Relaxed);
            }
            SwarmState::Seeding => {
                self.seeding_count.fetch_add(1, Ordering::Relaxed);
            }
            SwarmState::Queued => {
                self.queued_count.fetch_add(1, Ordering::Relaxed);
            }
            SwarmState::Stopped => {
                self.paused_count.fetch_add(1, Ordering::Relaxed);
            }
            SwarmState::Checking => {
                self.checking_count.fetch_add(1, Ordering::Relaxed);
            }
            SwarmState::Error(_) => {
                self.error_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn record_remove(&self, s: &SwarmStats) {
        let _ =
            self.total_torrents
                .fetch_update_compat(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(1))
                });
        let _ = self.total_downloaded_bytes.fetch_update_compat(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |v| Some(v.saturating_sub(s.downloaded_bytes)),
        );
        let _ = self.total_uploaded_bytes.fetch_update_compat(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |v| Some(v.saturating_sub(s.uploaded_bytes)),
        );
        let _ = self.global_download_rate.fetch_update_compat(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |v| Some(v.saturating_sub(s.download_rate)),
        );
        let _ = self.global_upload_rate.fetch_update_compat(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |v| Some(v.saturating_sub(s.upload_rate)),
        );
        let _ = self.global_peers_connected.fetch_update_compat(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |v| Some(v.saturating_sub(s.peers_connected)),
        );

        match s.state {
            SwarmState::Downloading => {
                let _ = self.downloading_count.fetch_update_compat(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
            }
            SwarmState::Seeding => {
                let _ = self.seeding_count.fetch_update_compat(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
            }
            SwarmState::Queued => {
                let _ = self.queued_count.fetch_update_compat(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
            }
            SwarmState::Stopped => {
                let _ = self.paused_count.fetch_update_compat(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
            }
            SwarmState::Checking => {
                let _ = self.checking_count.fetch_update_compat(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
            }
            SwarmState::Error(_) => {
                let _ = self.error_count.fetch_update_compat(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
            }
        }
    }

    pub fn record_state_transition(&self, old_state: &SwarmState, new_state: &SwarmState) {
        if std::mem::discriminant(old_state) == std::mem::discriminant(new_state) {
            return;
        }
        match old_state {
            SwarmState::Downloading => {
                let _ = self.downloading_count.fetch_update_compat(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
            }
            SwarmState::Seeding => {
                let _ = self.seeding_count.fetch_update_compat(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
            }
            SwarmState::Queued => {
                let _ = self.queued_count.fetch_update_compat(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
            }
            SwarmState::Stopped => {
                let _ = self.paused_count.fetch_update_compat(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
            }
            SwarmState::Checking => {
                let _ = self.checking_count.fetch_update_compat(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
            }
            SwarmState::Error(_) => {
                let _ = self.error_count.fetch_update_compat(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
            }
        }
        match new_state {
            SwarmState::Downloading => {
                self.downloading_count.fetch_add(1, Ordering::Relaxed);
            }
            SwarmState::Seeding => {
                self.seeding_count.fetch_add(1, Ordering::Relaxed);
            }
            SwarmState::Queued => {
                self.queued_count.fetch_add(1, Ordering::Relaxed);
            }
            SwarmState::Stopped => {
                self.paused_count.fetch_add(1, Ordering::Relaxed);
            }
            SwarmState::Checking => {
                self.checking_count.fetch_add(1, Ordering::Relaxed);
            }
            SwarmState::Error(_) => {
                self.error_count.fetch_add(1, Ordering::Relaxed);
            }
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
            self.global_download_rate
                .fetch_add(new_dl - old_dl, Ordering::Relaxed);
        } else {
            let diff = old_dl - new_dl;
            let _ = self.global_download_rate.fetch_update_compat(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |val| Some(val.saturating_sub(diff)),
            );
        }
        if new_ul >= old_ul {
            self.global_upload_rate
                .fetch_add(new_ul - old_ul, Ordering::Relaxed);
        } else {
            let diff = old_ul - new_ul;
            let _ = self.global_upload_rate.fetch_update_compat(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |val| Some(val.saturating_sub(diff)),
            );
        }
        if new_peers >= old_peers {
            self.global_peers_connected
                .fetch_add(new_peers - old_peers, Ordering::Relaxed);
        } else {
            let diff = old_peers - new_peers;
            let _ = self.global_peers_connected.fetch_update_compat(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |val| Some(val.saturating_sub(diff)),
            );
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

type WatchDirIndex = std::collections::HashMap<[u8; 20], (Info, Vec<u8>)>;

/// Parses user-supplied tracker URLs, dropping blanks and anything that isn't a valid URL.
fn parse_tracker_urls(list: &[String]) -> Vec<url::Url> {
    let mut out: Vec<url::Url> = Vec::new();
    for raw in list {
        if let Ok(u) = url::Url::parse(raw.trim()) {
            if !out.contains(&u) {
                out.push(u);
            }
        }
    }
    out
}

/// Per-torrent user metadata and seed limits (persisted across restarts).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TorrentMetadata {
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub seed_ratio_limit: Option<f64>,
    pub seed_time_limit_secs: Option<u64>,
}

/// Partial update for `TorrentMetadata`.
#[derive(Debug, Clone, Default)]
pub struct TorrentMetadataPatch {
    pub category: Option<Option<String>>,
    pub tags: Option<Vec<String>>,
    pub seed_ratio_limit: Option<Option<f64>>,
    pub seed_time_limit_secs: Option<Option<u64>>,
}

/// Options for restoring historical swarm metrics and lifecycle state upon restart.
#[derive(Debug, Clone, Default)]
pub struct SwarmResumeOptions {
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub ratio: Option<f32>,
    pub added_at: Option<i64>,
    pub is_paused: bool,
    /// Per-file priorities saved with the session; empty (or the wrong length) means defaults.
    pub file_priorities: Vec<u8>,
    /// Sequential piece picking, saved with the session.
    pub sequential: bool,
    /// API-set tracker replacement, saved with the session.
    pub tracker_override: Option<Vec<String>>,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub seed_ratio_limit: Option<f64>,
    pub seed_time_limit_secs: Option<u64>,
    pub super_seeding: bool,
    pub first_last_piece_priority: bool,
    pub magnet_uri: Option<String>,
    pub queue_position: Option<u32>,
    /// Per-torrent download rate limit in bytes/sec (0 = unlimited), set through the API.
    pub download_limit_bytes: u64,
    /// Per-torrent upload rate limit in bytes/sec (0 = unlimited), set through the API.
    pub upload_limit_bytes: u64,
}

/// Which way to move torrents in the download queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueMove {
    Top,
    Up,
    Down,
    Bottom,
}

/// Reorders `order` so the `selected` entries move as a group, keeping their relative order
/// (Transmission's `queue-move-*` semantics). Returns whether anything changed.
pub fn apply_queue_move(
    order: &mut Vec<[u8; 20]>,
    selected: &std::collections::HashSet<[u8; 20]>,
    direction: QueueMove,
) -> bool {
    let before = order.clone();
    match direction {
        QueueMove::Top | QueueMove::Bottom => {
            let (mut picked, rest): (Vec<_>, Vec<_>) =
                order.iter().copied().partition(|h| selected.contains(h));
            let mut rest = rest;
            *order = if direction == QueueMove::Top {
                picked.append(&mut rest);
                picked
            } else {
                rest.append(&mut picked);
                rest
            };
        }
        QueueMove::Up => {
            for i in 1..order.len() {
                if selected.contains(&order[i]) && !selected.contains(&order[i - 1]) {
                    order.swap(i, i - 1);
                }
            }
        }
        QueueMove::Down => {
            for i in (0..order.len().saturating_sub(1)).rev() {
                if selected.contains(&order[i]) && !selected.contains(&order[i + 1]) {
                    order.swap(i, i + 1);
                }
            }
        }
    }
    *order != before
}

/// Comprehensive telemetry for swarm discovery mechanisms (DHT, PEX, LSD, Trackers, Webseeds).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SwarmDiscoveryStats {
    pub candidate_peers: usize,
    pub active_dials: usize,
    pub dht_enabled: bool,
    pub dht_allowed: bool,
    pub pex_enabled: bool,
    pub pex_allowed: bool,
    pub pex_peers: usize,
    pub lsd_enabled: bool,
    pub lsd_allowed: bool,
    pub is_private: bool,
    pub webseeds_count: usize,
    pub webseeds: Vec<String>,
    pub discovered_from_tracker: u64,
    pub discovered_from_dht: u64,
    pub discovered_from_pex: u64,
    pub discovered_from_lsd: u64,
}

#[derive(Clone)]
pub struct ActiveActor {
    pub peer_event_tx: mpsc::Sender<PeerEvent>,
    pub command_tx: mpsc::Sender<TorrentCommand>,
    pub stop_tx: tokio::sync::watch::Sender<bool>,
}

pub struct TorrentHandle {
    pub info: Arc<Info>,
    pub stats: Arc<RwLock<SwarmStats>>,
    pub compressed_bitfield: Arc<RwLock<Option<synapse_picker::RoaringBitfield>>>,
    pub active_actor: Arc<RwLock<Option<ActiveActor>>>,
    pub live_peers: Arc<RwLock<Vec<PeerSnapshot>>>,
    pub piece_availability: Arc<RwLock<Vec<u32>>>,
    pub file_priorities: Arc<RwLock<Vec<u8>>>,
    /// Pick pieces in order rather than rarest-first. Lives here (not on the actor) so it
    /// survives the actor being evicted and woken again.
    pub sequential: Arc<std::sync::atomic::AtomicBool>,
    /// Prioritize first and last pieces (headers/footers) before general picking.
    pub first_last_piece_priority: Arc<std::sync::atomic::AtomicBool>,
    /// BEP super-seeding mode toggle.
    pub super_seeding: Arc<std::sync::atomic::AtomicBool>,
    /// Original magnet URI while metadata is unresolved, so unresolved magnets survive restart.
    pub magnet_uri: Arc<RwLock<Option<String>>>,
    /// User-assigned category, tags, and per-torrent seed limits.
    pub metadata: Arc<RwLock<TorrentMetadata>>,
    /// API-set replacement tracker list, kept as strings so it can be saved with the session.
    pub tracker_override: Arc<RwLock<Option<Vec<String>>>>,
    /// Per-torrent download speed limit in bytes/sec (0 = unlimited).
    pub download_limit_bytes: Arc<std::sync::atomic::AtomicU64>,
    /// Per-torrent upload speed limit in bytes/sec (0 = unlimited).
    pub upload_limit_bytes: Arc<std::sync::atomic::AtomicU64>,
    /// Tracks whether mutable session state changed since the last persisted flush.
    pub dirty: Arc<AtomicBool>,
    /// Last `downloaded_bytes` value persisted to `SessionStore`.
    pub last_flushed_downloaded: Arc<AtomicU64>,
    /// Last `uploaded_bytes` value persisted to `SessionStore`.
    pub last_flushed_uploaded: Arc<AtomicU64>,
    /// Incrementally maintained missing bytes across wanted files for O(1) announce `left`.
    pub missing_wanted_bytes: Arc<AtomicU64>,
    /// If `incomplete_dir_enabled` routed this torrent into a staging directory, holds the
    /// target final destination until completion relocates the files and clears it.
    pub final_download_dir: Arc<RwLock<Option<PathBuf>>>,
}

impl TorrentHandle {
    pub fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Release);
    }

    /// Returns a cloned piece availability vector, synthesizing a uniform view on demand for
    /// dormant Warm/Cold torrents whose `piece_availability` allocation was elided/reclaimed.
    pub fn piece_availability_snapshot(&self) -> Vec<u32> {
        {
            let guard = self.piece_availability.read();
            if !guard.is_empty() {
                return guard.clone();
            }
        }
        let pieces = self.info.pieces() as usize;
        if pieces == 0 {
            return Vec::new();
        }
        let is_seeding = {
            let s = self.stats.read();
            s.state == SwarmState::Seeding || s.progress >= 1.0
        };
        vec![if is_seeding { 1 } else { 0 }; pieces]
    }

    pub fn peer_event_tx(&self) -> Option<mpsc::Sender<PeerEvent>> {
        self.active_actor
            .read()
            .as_ref()
            .map(|a| a.peer_event_tx.clone())
    }

    pub fn command_tx(&self) -> Option<mpsc::Sender<TorrentCommand>> {
        self.active_actor
            .read()
            .as_ref()
            .map(|a| a.command_tx.clone())
    }

    pub fn is_active(&self) -> bool {
        self.active_actor
            .read()
            .as_ref()
            .is_some_and(|a| !a.peer_event_tx.is_closed())
    }

    /// Cleanly terminates the running torrent actor task, closing all peer sockets and releasing FDs.
    pub fn stop_actor(&self) {
        if let Some(actor) = self.active_actor.write().take() {
            let _ = actor.stop_tx.send(true);
            let _ = actor.command_tx.try_send(TorrentCommand::Stop);
        }
        {
            let mut lp = self.live_peers.write();
            lp.clear();
            lp.shrink_to_fit();
        }
        {
            let mut pa = self.piece_availability.write();
            pa.clear();
            pa.shrink_to_fit();
        }
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
    v2_torrents: Arc<DashMap<[u8; 32], Arc<TorrentHandle>>>,
    /// MSE `req2` hash -> info hash, for every registered torrent, so an inbound encrypted
    /// handshake resolves its torrent in O(1) instead of hashing every torrent.
    mse_req2_index: Arc<DashMap<[u8; 20], [u8; 20]>>,
    /// Active Hot-tier torrents with running actor loops, for O(active) choker/queue ticks.
    active_torrents: Arc<DashSet<[u8; 20]>>,
    /// Currently downloading torrents, for O(downloading) queue reconciliation.
    downloading_torrents: Arc<DashSet<[u8; 20]>>,
    /// Currently queued torrents awaiting download slots.
    queued_torrents: Arc<DashSet<[u8; 20]>>,
    /// Seeding torrents carrying per-torrent ratio or idle-seed-time limits.
    limited_seeds: Arc<DashSet<[u8; 20]>>,
    /// Insertion-ordered list of registered info-hashes for O(1) slice pagination.
    torrent_order: Arc<RwLock<Vec<[u8; 20]>>>,
    /// Serializes full session flushes against each other cleanly.
    persist_lock: Arc<tokio::sync::Mutex<()>>,
    /// Monotonic version bumped whenever torrents are added, removed, or replaced.
    roster_version: Arc<AtomicU64>,
    /// Monotonic version bumped whenever torrent queue ordering changes.
    queue_version: Arc<AtomicU64>,
    disk: Arc<DiskEngine>,
    peer_id: [u8; 20],
    listen_port: Arc<RwLock<u16>>,
    session_store: Option<Arc<SessionStore>>,
    lifecycle: Option<Arc<LifecycleDispatcher>>,
    download_bucket: Arc<TokenBucket>,
    upload_bucket: Arc<TokenBucket>,
    circuit_breaker: Arc<PeerCircuitBreaker>,
    queue_manager: Arc<RwLock<QueueManager>>,
    /// Download-queue order, front first. Reconciled lazily against `torrents` (see
    /// `sync_queue_order`) so add/remove paths don't have to maintain it.
    queue_order: Arc<Mutex<Vec<[u8; 20]>>>,
    /// Where the IP filter was loaded from, so it can be re-read on demand.
    ip_filter_source: Arc<Mutex<(Vec<String>, Option<PathBuf>)>>,
    settings: Arc<RwLock<DynamicSessionSettings>>,
    metrics: Arc<GlobalEngineMetrics>,
    announce_scheduler: Arc<AnnounceScheduler>,
    idle_timeout: Duration,
    watch_dir: Option<PathBuf>,
    /// Where the DHT node id and known nodes are persisted (`None` disables persistence).
    dht_state_path: Option<PathBuf>,
    /// Gateway discovery override (tests); `None` uses the system default gateway and SSDP.
    nat_discovery: Option<crate::portmap::Discovery>,
    /// When `reconcile_queue` first saw each torrent downloading, so a torrent that has only just
    /// started (and so has no throughput yet) still counts against the active-download limit.
    download_first_seen: Arc<parking_lot::Mutex<std::collections::HashMap<[u8; 20], Instant>>>,
    /// Port mappings currently held on the gateway, by (internal port, protocol).
    active_mappings: Arc<
        parking_lot::Mutex<
            std::collections::HashMap<(u16, crate::nat::PortProtocol), crate::portmap::Mapping>,
        >,
    >,
    ip_filter: Arc<RwLock<IpFilter>>,
    /// Addresses banned for poisoning pieces (smart-ban); shared with every torrent actor.
    ban_list: Arc<crate::banlist::BanList>,
    /// Inbound connections currently mid-handshake; see `MAX_PENDING_HANDSHAKES`.
    pending_handshakes: Arc<tokio::sync::Semaphore>,
    lsd_manager: Arc<Mutex<LsdManager>>,
    zeroconf_manager: Arc<Mutex<crate::zeroconf::ZeroconfManager>>,
    zeroconf_peer_override: Arc<RwLock<Option<SocketAddr>>>,
    zeroconf_addr_override: Arc<RwLock<Option<Vec<std::net::IpAddr>>>>,
    dht: Arc<RwLock<Option<synapse_dht::DhtHandle>>>,
    nat_manager: Arc<RwLock<crate::nat::NatManager>>,
    utp_manager: Arc<RwLock<Option<Arc<crate::utp::UtpSocketManager>>>>,
    /// The DHT half of the shared UDP port, set aside by `start_listener` (which owns the
    /// uTP half) until `start_dht` claims it: (port, transport).
    dht_transport: Arc<parking_lot::Mutex<Option<(u16, synapse_wire::UdpTransport)>>>,
    session_choker: Arc<RwLock<synapse_picker::SessionChoker>>,
    pub alert_stream: Arc<crate::alert::AlertStream>,
    pub feed_manager: Arc<crate::feed::FeedManager>,
    signature_policy: Arc<RwLock<SignaturePolicy>>,
    pub search_manager: Arc<crate::search::SearchManager>,
    pub(crate) update_manager: Arc<crate::update::UpdateManager>,
    free_disk_cache: Arc<parking_lot::Mutex<Option<(PathBuf, Instant, u64)>>>,
    free_disk_refreshing: Arc<AtomicBool>,
    dht_concurrency_notify: Arc<tokio::sync::Notify>,
    local_webseed_resolver: Arc<RwLock<Option<Arc<crate::local_webseed::LocalWebSeedResolver>>>>,
    listener_required: Arc<AtomicBool>,
}

/// BEP 35: which signers are trusted, and whether unsigned torrents are refused.
#[derive(Default)]
struct SignaturePolicy {
    trust: synapse_meta::TrustStore,
    require_trusted: bool,
}

impl SwarmEngine {
    pub fn new(disk: Arc<DiskEngine>, peer_id: [u8; 20]) -> Self {
        // Never identify as another client, whatever the caller passed in.
        let peer_id = crate::peer::with_synapse_prefix(peer_id);
        let listen_port = Arc::new(RwLock::new(0));
        let circuit_breaker = Arc::new(PeerCircuitBreaker::default());
        // Off by default: NAT-PMP/UPnP/PCP discovery broadcasts on the LAN the instant
        // `start_listener` runs. The real daemon always calls `.with_nat_enabled(config
        // .network.enable_nat)` right after construction (main.rs), so this default never
        // reaches it either way — but every test that just wants a listener, with nothing to
        // do with port mapping, used to get real LAN traffic as an unannounced side effect of
        // calling `SwarmEngine::new()`. Opt in explicitly (as `portmap_e2e.rs` does) if a test
        // actually exercises NAT discovery.
        let nat_manager = Arc::new(RwLock::new(crate::nat::NatManager::new(false)));
        let settings = Arc::new(RwLock::new(DynamicSessionSettings::default()));
        let announcer = Arc::new(
            Announcer::new(peer_id, listen_port.clone(), circuit_breaker.clone())
                .with_nat_manager(nat_manager.clone())
                .with_settings(settings.clone()),
        );
        let initial_tracker_conc = settings.read().max_concurrent_tracker_announces.max(1);
        let announce_scheduler = AnnounceScheduler::new(
            announcer,
            initial_tracker_conc,
            Duration::from_secs(1800),
            Duration::from_secs(600),
        );
        announce_scheduler.clone().start();
        announce_scheduler.set_settings(settings.clone());

        let ip_filter = Arc::new(RwLock::new(IpFilter::new()));
        announce_scheduler.set_ip_filter(ip_filter.clone());
        let ban_list = Arc::new(crate::banlist::BanList::new());
        announce_scheduler.set_ban_list(ban_list.clone());

        let lsd_cookie: String = {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            (0..8)
                .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
                .collect()
        };
        let lsd_manager = Arc::new(Mutex::new(LsdManager::new(0, lsd_cookie)));

        let engine = Self {
            torrents: Arc::new(DashMap::new()),
            v2_torrents: Arc::new(DashMap::new()),
            mse_req2_index: Arc::new(DashMap::new()),
            active_torrents: Arc::new(DashSet::new()),
            downloading_torrents: Arc::new(DashSet::new()),
            queued_torrents: Arc::new(DashSet::new()),
            limited_seeds: Arc::new(DashSet::new()),
            torrent_order: Arc::new(RwLock::new(Vec::new())),
            persist_lock: Arc::new(tokio::sync::Mutex::new(())),
            roster_version: Arc::new(AtomicU64::new(1)),
            queue_version: Arc::new(AtomicU64::new(1)),
            disk,
            peer_id,
            listen_port,
            session_store: None,
            lifecycle: None,
            download_bucket: Arc::new(TokenBucket::unthrottled()),
            upload_bucket: Arc::new(TokenBucket::unthrottled()),
            circuit_breaker,
            queue_manager: Arc::new(RwLock::new(QueueManager::new(QueueConfig::default()))),
            queue_order: Arc::new(Mutex::new(Vec::new())),
            ip_filter_source: Arc::new(Mutex::new((Vec::new(), None))),
            settings,
            metrics: Arc::new(GlobalEngineMetrics::default()),
            announce_scheduler: announce_scheduler.clone(),
            idle_timeout: Duration::from_secs(60),
            watch_dir: None,
            dht_state_path: None,
            nat_discovery: None,
            download_first_seen: Arc::new(
                parking_lot::Mutex::new(std::collections::HashMap::new()),
            ),
            active_mappings: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
            ip_filter,
            ban_list,
            pending_handshakes: Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_HANDSHAKES)),
            lsd_manager,
            zeroconf_manager: Arc::new(Mutex::new(crate::zeroconf::ZeroconfManager::new(peer_id))),
            zeroconf_peer_override: Arc::new(RwLock::new(None)),
            zeroconf_addr_override: Arc::new(RwLock::new(None)),
            dht: Arc::new(RwLock::new(None)),
            nat_manager,
            utp_manager: Arc::new(RwLock::new(None)),
            dht_transport: Arc::new(parking_lot::Mutex::new(None)),
            session_choker: Arc::new(RwLock::new(synapse_picker::SessionChoker::new(8, 16384))),
            alert_stream: Arc::new(crate::alert::AlertStream::default()),
            feed_manager: Arc::new(crate::feed::FeedManager::default()),
            signature_policy: Arc::new(RwLock::new(SignaturePolicy::default())),
            search_manager: Arc::new(crate::search::SearchManager::default()),
            update_manager: Arc::new(crate::update::UpdateManager::default()),
            free_disk_cache: Arc::new(parking_lot::Mutex::new(None)),
            free_disk_refreshing: Arc::new(AtomicBool::new(false)),
            dht_concurrency_notify: Arc::new(tokio::sync::Notify::new()),
            local_webseed_resolver: Arc::new(RwLock::new(None)),
            listener_required: Arc::new(AtomicBool::new(false)),
        };

        let engine_clone = engine.clone();
        announce_scheduler
            .set_peer_router(Arc::new(move |hash| engine_clone.get_or_wake_torrent(hash)));
        announce_scheduler.set_alert_sender(engine.alert_stream.sender());
        announce_scheduler.set_alert_category_mask(engine.alert_stream.category_mask_handle());

        engine
    }

    /// Persists the DHT node id and known nodes to `path` so restarts keep their position in
    /// the DHT and do not depend on the public bootstrap routers.
    pub fn with_dht_state_path(mut self, path: PathBuf) -> Self {
        self.dht_state_path = Some(path);
        self
    }

    pub fn with_watch_dir(mut self, watch_dir: PathBuf) -> Self {
        self.watch_dir = Some(watch_dir);
        self
    }

    /// Registers initial RSS/Atom syndication feeds for BEP 36 automation.
    pub fn with_rss_feeds(self, feeds: Vec<synapse_config::RssFeedConfig>) -> Self {
        for feed in feeds {
            self.feed_manager.add_configured_feed(feed);
        }
        self
    }

    /// Sets the BEP 35 trust store and whether torrents without a trusted signature are refused.
    pub fn with_signature_policy(
        self,
        trust: synapse_meta::TrustStore,
        require_trusted: bool,
    ) -> Self {
        *self.signature_policy.write() = SignaturePolicy {
            trust,
            require_trusted,
        };
        self
    }

    /// Configures local cache directories consulted by `LocalWebSeedResolver` when starting a swarm.
    pub fn with_local_webseed_dirs(self, dirs: Vec<PathBuf>) -> Self {
        self.set_local_webseed_dirs(dirs);
        self
    }

    /// Dynamically updates the local cache directories used by `LocalWebSeedResolver`.
    pub fn set_local_webseed_dirs(&self, dirs: Vec<PathBuf>) {
        *self.local_webseed_resolver.write() = if dirs.is_empty() {
            None
        } else {
            Some(Arc::new(crate::local_webseed::LocalWebSeedResolver::new(
                dirs,
            )))
        };
    }

    fn is_safe_storage_dir(dir: &std::path::Path) -> bool {
        !dir.as_os_str().is_empty()
            && dir.is_absolute()
            && !dir
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            && !std::fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink())
    }

    /// Whether a torrent may be added under the signature policy. Call before `add_torrent`.
    pub fn check_signature_policy(&self, info: &Info) -> Result<(), String> {
        let policy = self.signature_policy.read();
        if !policy.require_trusted {
            return Ok(());
        }
        if info
            .verify_signatures(&policy.trust)
            .iter()
            .any(|(_, status)| status.is_trusted())
        {
            Ok(())
        } else if info.signatures.is_empty() {
            Err("torrent is not signed and this daemon only accepts torrents signed by a trusted signer".into())
        } else {
            Err("torrent is not signed by a trusted signer".into())
        }
    }

    pub(crate) fn with_trust_store<R>(&self, f: impl FnOnce(&synapse_meta::TrustStore) -> R) -> R {
        f(&self.signature_policy.read().trust)
    }

    /// Every torrent we hold.
    pub fn list_handles(&self) -> Vec<Arc<TorrentHandle>> {
        self.torrents.iter().map(|r| r.value().clone()).collect()
    }

    /// The BEP 35 signature status of a torrent we hold, per signer.
    pub fn torrent_signatures(
        &self,
        info_hash: &[u8; 20],
    ) -> Option<Vec<(String, synapse_meta::SignatureStatus)>> {
        let handle = self.torrents.get(info_hash).map(|r| r.value().clone())?;
        Some(
            handle
                .info
                .verify_signatures(&self.signature_policy.read().trust),
        )
    }

    /// Keeps RSS state (handled items, feeds added or removed over the API) at `path`.
    pub fn with_rss_state_path(self, path: std::path::PathBuf) -> Self {
        self.feed_manager.load_state(path);
        self
    }

    /// The shared smart-ban list: addresses temporarily banned for sending corrupt data.
    pub fn ban_list(&self) -> Arc<crate::banlist::BanList> {
        self.ban_list.clone()
    }

    /// Returns the shared IP filter used to gate both inbound accepts (`start_listener`)
    /// and outbound dials (`AnnounceScheduler::dial_step`), for inspection or RPC exposure.
    pub fn ip_filter(&self) -> Arc<RwLock<IpFilter>> {
        self.ip_filter.clone()
    }

    /// Rebuilds the IP filter from config: inline CIDR strings plus an optional
    /// `ipfilter.dat`-style blocklist file. Replaces any previously loaded rules.
    /// Malformed inline entries or file-load errors are logged and skipped rather than
    /// failing startup -- a bad blocklist entry should never prevent the daemon running.
    pub fn load_ip_filter_config(
        &self,
        cidr_ranges: &[String],
        file_path: Option<&std::path::Path>,
    ) {
        *self.ip_filter_source.lock() = (cidr_ranges.to_vec(), file_path.map(PathBuf::from));
        let mut filter = IpFilter::new();
        for cidr in cidr_ranges {
            if let Err(e) = filter.add_cidr_str(cidr) {
                warn!("Skipping invalid entry in blocked_ip_ranges: {e}");
            }
        }
        if let Some(path) = file_path {
            match filter.load_file(path) {
                Ok(n) => info!("Loaded {n} rule(s) from ipfilter file {}", path.display()),
                Err(e) => warn!("Failed to load ipfilter file {}: {e}", path.display()),
            }
        }
        filter.normalize();
        info!(
            "IP filter active with {} total rule(s)",
            filter.total_rules()
        );
        *self.ip_filter.write() = filter;
    }

    /// Re-reads the IP filter from the sources it was last loaded from (the configured CIDR
    /// list and blocklist file), picking up edits made to the file since. Returns the number
    /// of rules now active.
    pub fn reload_ip_filter(&self) -> usize {
        let (cidrs, path) = self.ip_filter_source.lock().clone();
        self.load_ip_filter_config(&cidrs, path.as_deref());
        self.ip_filter.read().total_rules()
    }

    /// Attempts to recover the full `Info` struct for a swarm:
    /// 1. First from the session store's raw bencode snapshot.
    /// 2. If the snapshot was corrupted/evicted in an older version, falls back to scanning
    ///    `watch_dir`, `watch_dir/.imported/`, and `watch_dir/.failed/` for matching `.torrent` files.
    ///    Upon matching, repairs the session store so future restarts load instantly.
    pub fn try_recover_info(&self, info_hash: &[u8; 20]) -> Option<Info> {
        // 1. Try session store
        if let Some(ref store) = self.session_store {
            if let Ok(Some(bytes)) = store.load_metadata(info_hash) {
                if let Ok(reloaded) = Info::from_persisted_bencode(&bytes) {
                    if &reloaded.hash == info_hash && reloaded.has_piece_hashes() {
                        return Some(reloaded);
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
                                if let Ok(reloaded) = Info::from_persisted_bencode(&bytes) {
                                    if &reloaded.hash == info_hash && reloaded.has_piece_hashes()
                                    {
                                        tracing::info!(
                                            "Auto-healed corrupted session metadata for '{}' ({}) from {}",
                                            reloaded.name,
                                            hex::encode(info_hash),
                                            path.display()
                                        );
                                        // Repair session store so subsequent restarts don't need to rescan
                                        if let Some(ref store) = self.session_store {
                                            let _ = store.save_metadata(info_hash, &bytes);
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

    pub fn with_lifecycle(mut self, lifecycle: Arc<LifecycleDispatcher>) -> Self {
        self.lifecycle = Some(lifecycle);
        self
    }

    pub fn with_settings(self, settings: DynamicSessionSettings) -> Self {
        *self.settings.write() = settings.clone();
        *self.queue_manager.write() = QueueManager::new(settings.queue);
        self.recalculate_effective_rate_limits();
        self
    }

    pub fn with_circuit_breaker(
        self,
        enabled: bool,
        failure_threshold: u32,
        initial_backoff: Duration,
        max_backoff: Duration,
    ) -> Self {
        self.circuit_breaker
            .configure(enabled, failure_threshold, initial_backoff, max_backoff);
        self
    }

    /// Replaces the active session and queue settings dynamically and recalculates rate limits.
    pub fn update_settings(&self, settings: DynamicSessionSettings) {
        *self.settings.write() = settings.clone();
        *self.queue_manager.write() = QueueManager::new(settings.queue);
        self.dht_concurrency_notify.notify_waiters();
        self.recalculate_effective_rate_limits();
    }

    pub fn circuit_breaker(&self) -> &Arc<PeerCircuitBreaker> {
        &self.circuit_breaker
    }

    pub fn tracker_circuit_breaker(&self) -> &Arc<synapse_tracker::CanaryCircuitBreaker> {
        self.announce_scheduler.announcer().tracker_breaker()
    }

    pub fn queue_manager(&self) -> &Arc<RwLock<QueueManager>> {
        &self.queue_manager
    }

    pub fn set_queue_config(&self, config: QueueConfig) {
        self.queue_manager.write().set_config(config);
    }

    pub fn with_nat_enabled(self, enabled: bool) -> Self {
        *self.nat_manager.write() = crate::nat::NatManager::new(enabled);
        self
    }

    pub fn nat_manager(&self) -> Arc<RwLock<crate::nat::NatManager>> {
        self.nat_manager.clone()
    }

    pub fn utp_manager(&self) -> Arc<RwLock<Option<Arc<crate::utp::UtpSocketManager>>>> {
        self.utp_manager.clone()
    }

    pub fn listen_port(&self) -> u16 {
        *self.listen_port.read()
    }

    pub fn set_listener_required(&self, required: bool) {
        self.listener_required.store(required, Ordering::Relaxed);
    }

    pub fn is_listener_required(&self) -> bool {
        self.listener_required.load(Ordering::Relaxed)
    }

    pub fn is_session_store_configured(&self) -> bool {
        self.session_store.is_some()
    }

    pub async fn is_session_store_healthy(&self) -> bool {
        let Some(store) = self.session_store.clone() else {
            return true;
        };
        tokio::task::spawn_blocking(move || store.is_healthy())
            .await
            .unwrap_or(false)
    }

    pub fn mapped_external_port(
        &self,
        port: u16,
        protocol: crate::nat::PortProtocol,
    ) -> Option<u16> {
        self.nat_manager.read().mapped_external_port(port, protocol)
    }

    pub fn public_listen_port(&self) -> u16 {
        let local = *self.listen_port.read();
        self.mapped_external_port(local, crate::nat::PortProtocol::Tcp)
            .unwrap_or(local)
    }

    pub fn start_nat_mapping(
        self: Arc<Self>,
        internal_port: u16,
        protocol: crate::nat::PortProtocol,
    ) {
        if !self.nat_manager.read().is_enabled() {
            return;
        }
        let discovery = self
            .nat_discovery
            .clone()
            .unwrap_or_else(crate::portmap::Discovery::system_default);
        // The task holds only a weak reference so it ends when the engine is dropped.
        let engine = Arc::downgrade(&self);
        drop(self);
        tokio::spawn(async move {
            let description = match protocol {
                crate::nat::PortProtocol::Tcp => "Synapse BitTorrent TCP",
                crate::nat::PortProtocol::Udp => "Synapse BitTorrent UDP",
            };
            loop {
                // 1. Get a mapping: PCP, then NAT-PMP, then UPnP, against every candidate.
                let mapping =
                    match crate::portmap::acquire(&discovery, protocol, internal_port, description)
                        .await
                    {
                        Ok(m) => m,
                        Err(e) => {
                            debug!("No port mapping for {:?} {internal_port}: {e}", protocol);
                            // The router may appear later or the network may change; retry, but slowly.
                            tokio::time::sleep(Duration::from_secs(600)).await;
                            if engine.upgrade().is_none() {
                                return;
                            }
                            continue;
                        }
                    };
                {
                    let Some(engine) = engine.upgrade() else {
                        return;
                    };
                    engine.nat_manager.write().set_mapped(
                        internal_port,
                        protocol,
                        mapping.external_port,
                        mapping.gateway,
                    );
                    engine
                        .active_mappings
                        .lock()
                        .insert((internal_port, protocol), mapping.clone());
                }
                info!(
                    "{} mapped {:?} port {} -> external {} on gateway {}",
                    mapping.method.name(),
                    protocol,
                    internal_port,
                    mapping.external_port,
                    mapping.gateway
                );

                // 2. Keep it alive: renew at half the lease (a permanent mapping is refreshed
                // occasionally anyway). A failed renewal means the gateway lost the mapping or
                // went away, so start over from discovery.
                let mut current = mapping;
                loop {
                    let wait = if current.lifetime_secs == 0 {
                        1800
                    } else {
                        u64::from(current.lifetime_secs.max(120) / 2)
                    };
                    tokio::time::sleep(Duration::from_secs(wait)).await;
                    let Some(engine) = engine.upgrade() else {
                        return;
                    };
                    match crate::portmap::renew(&current, protocol, internal_port, description)
                        .await
                    {
                        Ok(next) => {
                            engine.nat_manager.write().set_mapped(
                                internal_port,
                                protocol,
                                next.external_port,
                                next.gateway,
                            );
                            engine
                                .active_mappings
                                .lock()
                                .insert((internal_port, protocol), next.clone());
                            debug!(
                                "{} renewed {:?} port {}",
                                next.method.name(),
                                protocol,
                                internal_port
                            );
                            current = next;
                        }
                        Err(e) => {
                            warn!("Port mapping renewal for {:?} {internal_port} failed ({e}); rediscovering gateway", protocol);
                            engine
                                .nat_manager
                                .write()
                                .set_failed(internal_port, protocol);
                            engine
                                .active_mappings
                                .lock()
                                .remove(&(internal_port, protocol));
                            break;
                        }
                    }
                }
            }
        });
    }

    /// Overrides where port mapping looks for a gateway (tests point it at a mock gateway).
    pub fn with_nat_discovery(mut self, discovery: crate::portmap::Discovery) -> Self {
        self.nat_discovery = Some(discovery);
        self
    }

    /// Asks the gateway to drop every mapping this engine created (called on shutdown; leases
    /// expire on their own if this is skipped or fails).
    pub async fn release_port_mappings(&self) {
        let mappings: Vec<_> = self.active_mappings.lock().drain().collect();
        for ((port, protocol), mapping) in mappings {
            crate::portmap::release(&mapping, protocol, port).await;
        }
    }

    pub fn global_metrics(&self) -> EngineMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn metrics_ref(&self) -> &Arc<GlobalEngineMetrics> {
        &self.metrics
    }

    pub fn record_event_bus_lag(&self, skipped: u64) {
        self.metrics
            .event_bus_lag_total
            .fetch_add(skipped, Ordering::Relaxed);
    }

    pub fn record_rpc_sync_duration_ms(&self, ms: u64) {
        self.metrics
            .last_sync_duration_ms
            .store(ms, Ordering::Relaxed);
    }

    pub fn subscribe_alerts(&self) -> tokio::sync::broadcast::Receiver<crate::alert::Alert> {
        self.alert_stream.subscribe()
    }

    pub fn set_alert_category_mask(&self, mask: crate::alert::AlertCategory) {
        self.alert_stream.set_category_mask(mask);
    }

    pub fn alert_category_mask(&self) -> crate::alert::AlertCategory {
        self.alert_stream.category_mask()
    }

    pub fn post_alert(&self, alert: crate::alert::Alert) {
        self.alert_stream.post(alert);
    }

    pub fn disk_write_queue_bytes(&self) -> usize {
        self.disk.in_flight_write_bytes()
    }

    pub fn utp_packet_loss_total(&self) -> u64 {
        self.utp_manager
            .read()
            .as_ref()
            .map(|u| u.packet_loss_total())
            .unwrap_or(0)
            + self.metrics.utp_packet_loss_total.load(Ordering::Relaxed)
    }

    pub fn dht_dos_blocks_total(&self) -> u64 {
        self.dht
            .read()
            .as_ref()
            .map(|d| d.dos_blocks_total())
            .unwrap_or(0)
            + self.metrics.dht_dos_blocks_total.load(Ordering::Relaxed)
    }

    pub fn announce_scheduler(&self) -> &Arc<AnnounceScheduler> {
        &self.announce_scheduler
    }

    /// Returns the live tracker status reports for the specified torrent info hash.
    ///
    /// Looks the handle up from `self.torrents`; a caller that already has the handle (e.g.
    /// while iterating it via [`SwarmEngine::for_each_torrent_handle`]) must use
    /// [`SwarmEngine::tracker_reports_for_handle`] instead, since a nested `self.torrents.get`
    /// while that same shard's iterator guard is still held on this thread can deadlock behind
    /// a concurrent writer.
    pub fn get_tracker_reports(&self, info_hash: &[u8; 20]) -> Vec<TrackerReport> {
        let reports = self.announce_scheduler.get_tracker_reports(info_hash);
        if !reports.is_empty() {
            return reports;
        }
        match self.torrents.get(info_hash).map(|r| r.value().clone()) {
            Some(handle) => self.tracker_reports_for_handle(&handle),
            None => Vec::new(),
        }
    }

    /// Same fallback as [`SwarmEngine::get_tracker_reports`], but for a handle the caller
    /// already has in hand instead of looking it up from `self.torrents`.
    pub fn tracker_reports_for_handle(&self, handle: &TorrentHandle) -> Vec<TrackerReport> {
        let reports = self
            .announce_scheduler
            .get_tracker_reports(&handle.info.hash);
        if !reports.is_empty() {
            return reports;
        }
        let candidate_urls = self
            .announce_scheduler
            .announcer()
            .trackers_for(&handle.info);
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
                cb_state: None,
                recovery_progress_pct: None,
                last_announce_time: None,
            })
            .collect()
    }

    /// Scrapes a tracker URL (HTTP or UDP) for one or more info hashes (BEP 48).
    pub async fn scrape_tracker(
        &self,
        tracker_url: &url::Url,
        info_hashes: &[[u8; 20]],
    ) -> Result<synapse_tracker::ScrapeResponse, synapse_tracker::TrackerError> {
        self.announce_scheduler
            .announcer()
            .scrape(tracker_url, info_hashes)
            .await
    }

    pub async fn announce_stopped_all(&self) {
        self.announce_scheduler.announce_stopped_all().await;
    }

    pub fn shutdown(&self) {
        self.announce_scheduler.shutdown();
        for entry in self.torrents.iter() {
            entry.value().stop_actor();
        }
        self.active_torrents.clear();
    }

    fn sync_tracking_sets(
        &self,
        hash: &[u8; 20],
        state: &SwarmState,
        tier: SwarmTier,
        handle: Option<&TorrentHandle>,
    ) {
        let has_limits = handle.is_some_and(|h| {
            let meta = h.metadata.read();
            meta.seed_ratio_limit.is_some() || meta.seed_time_limit_secs.is_some()
        });
        match state {
            SwarmState::Downloading => {
                self.downloading_torrents.insert(*hash);
                self.queued_torrents.remove(hash);
                if has_limits {
                    self.limited_seeds.insert(*hash);
                } else {
                    self.limited_seeds.remove(hash);
                }
            }
            SwarmState::Queued => {
                self.queued_torrents.insert(*hash);
                self.downloading_torrents.remove(hash);
                if has_limits {
                    self.limited_seeds.insert(*hash);
                } else {
                    self.limited_seeds.remove(hash);
                }
            }
            SwarmState::Seeding => {
                self.downloading_torrents.remove(hash);
                self.queued_torrents.remove(hash);
                if has_limits {
                    self.limited_seeds.insert(*hash);
                } else {
                    self.limited_seeds.remove(hash);
                }
            }
            _ => {
                self.downloading_torrents.remove(hash);
                self.queued_torrents.remove(hash);
                self.limited_seeds.remove(hash);
            }
        }
        if tier == SwarmTier::Hot {
            self.active_torrents.insert(*hash);
        } else {
            self.active_torrents.remove(hash);
        }
    }

    fn remove_from_tracking_sets(&self, hash: &[u8; 20]) {
        self.active_torrents.remove(hash);
        self.downloading_torrents.remove(hash);
        self.queued_torrents.remove(hash);
        self.limited_seeds.remove(hash);
    }

    fn snapshot_handle_state(
        h: &TorrentHandle,
        queue_position: Option<u32>,
    ) -> TorrentSessionState {
        let s = h.stats.read().clone();
        let bf = h.compressed_bitfield.read().clone();
        let bitfield_hex = bf
            .map(|b| hex::encode(b.to_bitfield().as_bytes()))
            .unwrap_or_default();
        let meta = h.metadata.read().clone();
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
            is_paused: s.state == SwarmState::Stopped,
            ratio: Some(s.ratio),
            magnet_uri: h.magnet_uri.read().clone(),
            raw_bencode_hex: None,
            file_priorities: h.file_priorities.read().clone(),
            sequential: h.sequential.load(Ordering::Relaxed),
            tracker_override: h.tracker_override.read().clone(),
            category: meta.category,
            tags: meta.tags,
            seed_ratio_limit: meta.seed_ratio_limit,
            seed_time_limit_secs: meta.seed_time_limit_secs,
            super_seeding: h.super_seeding.load(Ordering::Relaxed),
            first_last_piece_priority: h.first_last_piece_priority.load(Ordering::Relaxed),
            queue_position,
            download_limit_bytes: h.download_limit_bytes.load(Ordering::Relaxed),
            upload_limit_bytes: h.upload_limit_bytes.load(Ordering::Relaxed),
        }
    }

    /// Dynamically awakens a Warm torrent into the Hot tier and returns its peer event sender.
    /// Cold/stopped or queued torrents are never woken automatically.
    pub fn get_or_wake_torrent(&self, info_hash: &[u8; 20]) -> Option<mpsc::Sender<PeerEvent>> {
        let handle = self.torrents.get(info_hash).map(|r| r.value().clone())?;
        {
            let stats = handle.stats.read();
            if stats.tier == SwarmTier::Cold
                || matches!(stats.state, SwarmState::Stopped | SwarmState::Queued)
            {
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
        self.wake_torrent_internal(&handle).map(|a| a.peer_event_tx)
    }

    /// Dynamically awakens a Warm torrent into the Hot tier and returns its command sender.
    /// Cold/stopped torrents are never woken automatically.
    pub fn get_or_wake_command_tx(
        &self,
        info_hash: &[u8; 20],
    ) -> Option<mpsc::Sender<TorrentCommand>> {
        let handle = self.torrents.get(info_hash).map(|r| r.value().clone())?;
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
        self.wake_torrent_internal(&handle).map(|a| a.command_tx)
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
        let have = handle
            .compressed_bitfield
            .read()
            .as_ref()
            .map(|b| b.to_bitfield());

        let (peer_tx, peer_rx) = mpsc::channel(2048);
        let (command_tx, command_rx) = mpsc::channel(32);
        let (piece_tx, mut piece_rx) = mpsc::channel(128);
        let (pex_tx, mut pex_rx) = mpsc::channel::<Vec<SocketAddr>>(32);
        let (metadata_tx, metadata_rx) = oneshot::channel::<Info>();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

        let (complete_tx, complete_rx) = oneshot::channel();
        {
            let info_clone = info.clone();
            let handle_complete = handle.clone();
            let scheduler_complete = self.announce_scheduler.clone();
            let hash_complete = info.hash;
            let lifecycle_opt = self.lifecycle.clone();
            tokio::spawn(async move {
                if complete_rx.await.is_ok() {
                    *handle_complete.final_download_dir.write() = None;
                    let completed_dir = PathBuf::from(&handle_complete.stats.read().download_dir);
                    scheduler_complete.notify_completed(&hash_complete);
                    if let Some(lifecycle) = lifecycle_opt {
                        info!(
                            "Torrent {} completed! Triggering lifecycle dispatcher",
                            info_clone.name
                        );
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
                        let _ = lifecycle
                            .on_torrent_completed(
                                info_clone.hash,
                                &info_clone.name,
                                info_clone.total_len,
                                &completed_dir,
                                &info_clone.files,
                                &trackers,
                            )
                            .await;
                    }
                }
            });
        }

        let config = TorrentConfig {
            info: info.clone(),
            download_dir: download_dir.clone(),
            peer_id: self.peer_id,
            disk: self.disk.clone(),
            mode: if handle.sequential.load(Ordering::Relaxed) {
                synapse_picker::Mode::Sequential
            } else {
                synapse_picker::Mode::RarestFirst
            },
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
            settings: self.settings.clone(),
            on_peers_discovered: Some(pex_tx),
            on_metadata_resolved: Some(metadata_tx),
            ban_list: self.ban_list.clone(),
            ip_filter: self.ip_filter.clone(),
            super_seeding: handle.super_seeding.load(Ordering::Relaxed),
            local_webseed_resolver: self.local_webseed_resolver.read().clone(),
            alert_sender: Some(self.alert_stream.sender()),
        };

        {
            let pieces = info.pieces() as usize;
            let is_seeding = handle.stats.read().state == SwarmState::Seeding;
            let mut pa = handle.piece_availability.write();
            if pa.len() != pieces {
                pa.resize(pieces, if is_seeding { 1 } else { 0 });
            }
        }

        let mut torrent = Torrent::new(config, have.as_ref());
        torrent.set_stop_signal(stop_rx);
        torrent.set_alert_category_mask(self.alert_stream.category_mask_handle());
        torrent.set_active_torrents(self.active_torrents.clone());
        torrent.set_downloading_torrents(self.downloading_torrents.clone());
        torrent.set_dirty_flag(handle.dirty.clone());
        torrent.set_missing_wanted_bytes(handle.missing_wanted_bytes.clone());
        if let Some(dest_dir) = handle.final_download_dir.read().clone() {
            torrent.set_final_download_dir(dest_dir);
        }
        if let Some(ref store) = self.session_store {
            torrent.set_session_store(store.clone());
        }
        if handle.first_last_piece_priority.load(Ordering::Relaxed) {
            torrent.set_first_last_piece_priority(true);
        }
        let torrent_dl = handle.download_limit_bytes.load(Ordering::Relaxed);
        let torrent_ul = handle.upload_limit_bytes.load(Ordering::Relaxed);
        if torrent_dl > 0 || torrent_ul > 0 {
            torrent.set_torrent_rate_limits(torrent_dl, torrent_ul);
        }
        // Skip/priority choices live on the handle so they survive the actor being evicted and
        // woken again, and (via the session store) a daemon restart.
        let priorities = handle.file_priorities.read().clone();
        for (idx, &prio) in priorities.iter().enumerate() {
            if prio != 4 {
                torrent.apply_file_priority(idx as u32, prio);
            }
        }
        self.metrics.active_actors.fetch_add(1, Ordering::Relaxed);
        self.active_torrents.insert(info.hash);
        {
            let mut s = handle.stats.write();
            s.tier = SwarmTier::Hot;
        }

        tokio::spawn(async move {
            torrent.run(peer_rx, command_rx).await;
        });

        let scheduler_pex = self.announce_scheduler.clone();
        let hash_pex = info.hash;
        tokio::spawn(async move {
            while let Some(peers) = pex_rx.recv().await {
                scheduler_pex.add_candidate_peers_with_source(
                    &hash_pex,
                    peers,
                    crate::announcer::PeerDiscoverySource::Pex,
                );
            }
        });

        let engine_metadata = self.clone();
        let download_dir_metadata = download_dir.clone();
        let select_only = info.select_only.clone();
        // The magnet's own `tr=` trackers (see `Info::from_magnet`, which stashes them in
        // `url_list`): BEP 9 only transfers the bencoded "info" dict, which never carries
        // announce URLs, so `resolved_info` always comes back with an empty `url_list`.
        // Without carrying these over, the real download starts with zero trackers and no
        // way to get more candidate peers once DHT/PEX/LSD dry up.
        let magnet_trackers = info.url_list.clone();
        tokio::spawn(async move {
            if let Ok(mut resolved_info) = metadata_rx.await {
                if resolved_info.select_only.is_none() {
                    resolved_info.select_only = select_only;
                }
                if resolved_info.url_list.is_empty() {
                    resolved_info.url_list = magnet_trackers;
                }
                engine_metadata.resolve_magnet_metadata(download_dir_metadata, resolved_info);
            }
        });

        let bitfield_worker = handle.compressed_bitfield.clone();
        let stats_worker = handle.stats.clone();
        let total_pieces = info.pieces() as usize;
        let total_len = info.total_len;
        let hash_worker = info.hash;
        let info_worker = info.clone();
        let store_worker = self.session_store.clone();
        let name_worker = info.name.clone();
        let dl_dir_str = download_dir.to_string_lossy().to_string();
        let added_at = handle.stats.read().added_at;

        let magnet_uri_worker = handle.magnet_uri.clone();
        let priorities_worker = handle.file_priorities.clone();
        let sequential_worker = handle.sequential.clone();
        let first_last_worker = handle.first_last_piece_priority.clone();
        let super_seeding_worker = handle.super_seeding.clone();
        let download_limit_worker = handle.download_limit_bytes.clone();
        let upload_limit_worker = handle.upload_limit_bytes.clone();
        let metadata_worker = handle.metadata.clone();
        let tracker_override_worker = handle.tracker_override.clone();
        let dirty_worker = handle.dirty.clone();
        let last_flushed_dl_worker = handle.last_flushed_downloaded.clone();
        let last_flushed_ul_worker = handle.last_flushed_uploaded.clone();
        let missing_worker = handle.missing_wanted_bytes.clone();
        let dl_set_worker = self.downloading_torrents.clone();
        let limited_seeds_worker = self.limited_seeds.clone();
        let scheduler_worker = self.announce_scheduler.clone();
        let last_saved_secs = Arc::new(AtomicU64::new(0));
        const SAVE_THROTTLE: Duration = Duration::from_secs(5);

        tokio::spawn(async move {
            while let Some(piece_idx) = piece_rx.recv().await {
                let (completed_count, newly_added) = {
                    let mut bf_guard = bitfield_worker.write();
                    if let Some(ref mut bf) = *bf_guard {
                        let was_set = bf.has(piece_idx as usize);
                        bf.set(piece_idx as usize);
                        (bf.count_ones(), !was_set)
                    } else {
                        let mut bf = synapse_picker::RoaringBitfield::new(total_pieces);
                        bf.set(piece_idx as usize);
                        *bf_guard = Some(bf);
                        (1, true)
                    }
                };

                if newly_added {
                    let prios_guard = priorities_worker.read();
                    if crate::announcer::is_piece_wanted(&info_worker, &prios_guard, piece_idx) {
                        let piece_len = info_worker.piece_len(piece_idx) as u64;
                        let _ = missing_worker.fetch_update_compat(
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                            |m| Some(m.saturating_sub(piece_len)),
                        );
                    }
                }
                dirty_worker.store(true, Ordering::Release);

                let progress = if total_pieces > 0 {
                    (completed_count as f32) / (total_pieces as f32)
                } else {
                    1.0
                };
                let dl_bytes = ((progress as f64) * (total_len as f64)) as u64;

                {
                    let mut s = stats_worker.write();
                    s.progress = progress;
                    s.downloaded_bytes = dl_bytes;
                    if progress >= 1.0 {
                        s.state = SwarmState::Seeding;
                    }
                }
                if progress >= 1.0 {
                    missing_worker.store(0, Ordering::Release);
                    dl_set_worker.remove(&hash_worker);
                    scheduler_worker.mark_seeding(&hash_worker);
                    let m = metadata_worker.read();
                    if m.seed_ratio_limit.is_some() || m.seed_time_limit_secs.is_some() {
                        limited_seeds_worker.insert(hash_worker);
                    }
                }

                if let Some(ref store) = store_worker {
                    let now_secs = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let prev = last_saved_secs.load(Ordering::Relaxed);
                    let should_save =
                        progress >= 1.0 || now_secs.saturating_sub(prev) >= SAVE_THROTTLE.as_secs();

                    if should_save {
                        last_saved_secs.store(now_secs, Ordering::Relaxed);
                        let store = store.clone();
                        let bf_snapshot = bitfield_worker.read().clone();
                        let name_c = name_worker.clone();
                        let dl_dir_c = dl_dir_str.clone();
                        let magnet_c = magnet_uri_worker.read().clone();
                        let prios_c = priorities_worker.read().clone();
                        let sequential_c = sequential_worker.load(Ordering::Relaxed);
                        let first_last_c = first_last_worker.load(Ordering::Relaxed);
                        let super_seeding_c = super_seeding_worker.load(Ordering::Relaxed);
                        let download_limit_c = download_limit_worker.load(Ordering::Relaxed);
                        let upload_limit_c = upload_limit_worker.load(Ordering::Relaxed);
                        let meta_c = metadata_worker.read().clone();
                        let tracker_override_c = tracker_override_worker.read().clone();
                        let (uploaded_bytes, current_ratio) = {
                            let s = stats_worker.read();
                            (s.uploaded_bytes, s.ratio)
                        };
                        let dirty_c = dirty_worker.clone();
                        let dl_flush_c = last_flushed_dl_worker.clone();
                        let ul_flush_c = last_flushed_ul_worker.clone();
                        dirty_c.store(false, Ordering::Release);
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
                                ratio: Some(current_ratio),
                                magnet_uri: magnet_c,
                                raw_bencode_hex: None,
                                file_priorities: prios_c,
                                sequential: sequential_c,
                                tracker_override: tracker_override_c,
                                category: meta_c.category,
                                tags: meta_c.tags,
                                seed_ratio_limit: meta_c.seed_ratio_limit,
                                seed_time_limit_secs: meta_c.seed_time_limit_secs,
                                super_seeding: super_seeding_c,
                                first_last_piece_priority: first_last_c,
                                queue_position: None,
                                download_limit_bytes: download_limit_c,
                                upload_limit_bytes: upload_limit_c,
                            };
                            if store.save_states_batch(&[state]).is_ok() {
                                dl_flush_c.store(dl_bytes, Ordering::Relaxed);
                                ul_flush_c.store(uploaded_bytes, Ordering::Relaxed);
                            } else {
                                dirty_c.store(true, Ordering::Release);
                            }
                        });
                    }
                }
            }
        });

        let actor = ActiveActor {
            peer_event_tx: peer_tx,
            command_tx,
            stop_tx,
        };
        *actor_guard = Some(actor.clone());
        Some(actor)
    }

    /// Transmission-style queue reconciliation: detects stalled downloads and promotes queued torrents.
    pub fn reconcile_queue(&self) {
        let qm = self.queue_manager.read();
        let mut active_non_stalled = 0usize;
        let mut active_seeds = 0usize;
        let mut queued_hashes = Vec::new();

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let now = Instant::now();
        let mut first_seen = self.download_first_seen.lock();
        first_seen.retain(|hash, _| self.downloading_torrents.contains(hash));

        let mut stop_handles: Vec<Arc<TorrentHandle>> = Vec::new();
        let mut stopped_hashes: std::collections::HashSet<[u8; 20]> =
            std::collections::HashSet::new();
        let mut hot_active_seeds: Vec<([u8; 20], u64, i64)> = Vec::new();

        // 1. Evaluate downloading swarms in O(downloading).
        let dl_hashes: Vec<[u8; 20]> = self.downloading_torrents.iter().map(|r| *r).collect();
        for hash in dl_hashes {
            let Some(handle) = self.torrents.get(&hash).map(|r| r.value().clone()) else {
                self.downloading_torrents.remove(&hash);
                continue;
            };
            let (
                is_dl,
                peers_connected,
                download_rate,
                dl_bytes,
                total_size,
                last_tx,
                added_at,
                old_stalled,
            ) = {
                let stats = handle.stats.read();
                (
                    stats.state == SwarmState::Downloading,
                    stats.peers_connected,
                    stats.download_rate,
                    stats.downloaded_bytes,
                    stats.total_size,
                    stats.last_transfer_at,
                    stats.added_at,
                    stats.is_stalled,
                )
            };
            if !is_dl {
                self.downloading_torrents.remove(&hash);
                continue;
            }
            let last_activity = if last_tx > 0 {
                last_tx as u64
            } else {
                added_at as u64
            };
            let elapsed_secs = now_secs.saturating_sub(last_activity);
            let stalled = qm.is_stalled(
                peers_connected,
                download_rate,
                dl_bytes,
                total_size,
                Duration::from_secs(elapsed_secs),
            );
            if old_stalled != stalled {
                handle.stats.write().is_stalled = stalled;
            }
            // A freshly started torrent has no throughput yet; without a grace period it would
            // count as "slow", not use up a slot, and every queued torrent would be started.
            let started = *first_seen.entry(hash).or_insert(now);
            let in_startup_grace = now.duration_since(started) < AUTO_MANAGE_STARTUP;
            let is_slow = !in_startup_grace && qm.is_slow_downloader(download_rate);
            if !stalled && !is_slow {
                active_non_stalled += 1;
            }
        }

        // 2. Enforce seed ratio and idle seed time limits.
        let global_seed_limits =
            qm.config().seed_ratio_limited || qm.config().idle_seeding_limit_enabled;
        let check_seed_limit =
            |hash: [u8; 20],
             handle: &Arc<TorrentHandle>,
             stop_handles: &mut Vec<Arc<TorrentHandle>>,
             stopped_hashes: &mut std::collections::HashSet<[u8; 20]>| {
                let (is_seeding, ratio, last_tx, added_at) = {
                    let s = handle.stats.read();
                    (
                        s.state == SwarmState::Seeding,
                        s.ratio,
                        s.last_transfer_at,
                        s.added_at,
                    )
                };
                if !is_seeding {
                    return false;
                }
                let last_activity = if last_tx > 0 {
                    last_tx as u64
                } else {
                    added_at as u64
                };
                let elapsed_secs = now_secs.saturating_sub(last_activity);
                let meta = handle.metadata.read();
                let per_torrent_ratio_hit = meta
                    .seed_ratio_limit
                    .is_some_and(|limit| limit > 0.0 && (ratio as f64) >= limit);
                let per_torrent_time_hit = meta
                    .seed_time_limit_secs
                    .is_some_and(|limit| elapsed_secs >= limit);
                drop(meta);
                let action = qm.evaluate_seeder(0, 0, ratio as f64, elapsed_secs);
                if per_torrent_ratio_hit
                    || per_torrent_time_hit
                    || matches!(
                        action,
                        QueueAction::AutoStopRatioReached | QueueAction::AutoStopSeedTimeReached
                    )
                {
                    let mut stats = handle.stats.write();
                    if stats.state == SwarmState::Seeding {
                        stats.state = SwarmState::Stopped;
                        stats.tier = SwarmTier::Cold;
                        self.metrics
                            .record_state_transition(&SwarmState::Seeding, &SwarmState::Stopped);
                        drop(stats);
                        stopped_hashes.insert(hash);
                        stop_handles.push(handle.clone());
                    }
                    true
                } else {
                    false
                }
            };

        if global_seed_limits {
            for entry in self.torrents.iter() {
                let _ = check_seed_limit(
                    *entry.key(),
                    entry.value(),
                    &mut stop_handles,
                    &mut stopped_hashes,
                );
            }
        } else {
            let limit_hashes: Vec<[u8; 20]> = self.limited_seeds.iter().map(|r| *r).collect();
            for hash in limit_hashes {
                if let Some(handle) = self.torrents.get(&hash).map(|r| r.value().clone()) {
                    let _ = check_seed_limit(hash, &handle, &mut stop_handles, &mut stopped_hashes);
                } else {
                    self.limited_seeds.remove(&hash);
                }
            }
        }

        // 3. Count active seeds and enforce seed queue cap in O(active).
        let active_hashes: Vec<[u8; 20]> = self.active_torrents.iter().map(|r| *r).collect();
        for hash in active_hashes {
            if stopped_hashes.contains(&hash) {
                continue;
            }
            if let Some(handle) = self.torrents.get(&hash).map(|r| r.value().clone()) {
                let s = handle.stats.read();
                if s.state == SwarmState::Seeding && !qm.is_slow_seeder(s.upload_rate) {
                    active_seeds += 1;
                    if s.tier == SwarmTier::Hot {
                        hot_active_seeds.push((hash, s.upload_rate, s.last_transfer_at));
                    }
                }
            } else {
                self.active_torrents.remove(&hash);
            }
        }
        if !qm.config().dont_count_slow_torrents {
            active_seeds = self.metrics.seeding_count.load(Ordering::Relaxed);
        }

        for h in stop_handles {
            let hash = h.info.hash;
            self.active_torrents.remove(&hash);
            self.limited_seeds.remove(&hash);
            h.mark_dirty();
            h.stop_actor();
            self.announce_scheduler.unregister(&hash);
            self.lsd_manager.lock().unregister_torrent(&hash);
            self.zeroconf_manager.lock().unregister_torrent(&hash);
        }

        if qm.config().seed_queue_enabled && hot_active_seeds.len() > qm.config().max_active_seeds {
            hot_active_seeds.sort_by_key(|&(_, ul, ts)| (ul, ts));
            let excess = hot_active_seeds.len() - qm.config().max_active_seeds;
            for &(hash, _, _) in hot_active_seeds.iter().take(excess) {
                if let Some(handle) = self.torrents.get(&hash).map(|r| r.value().clone()) {
                    // Zero the live rate/peer fields synchronously here rather than leaving it
                    // to the demoted actor's own async teardown -- `stop_actor` below clears
                    // `live_peers` immediately but never touches `stats`, so without this a
                    // torrent can show a frozen nonzero upload/download rate with 0 connected
                    // peers indefinitely if the actor is slow (or never gets around) to notice
                    // its stop signal. Mirrors `transition_to_cold`'s handling below.
                    let demoted = {
                        let mut s = handle.stats.write();
                        if s.state == SwarmState::Seeding && s.tier == SwarmTier::Hot {
                            let old = (s.download_rate, s.upload_rate, s.peers_connected);
                            s.tier = SwarmTier::Warm;
                            s.download_rate = 0;
                            s.upload_rate = 0;
                            s.peers_connected = 0;
                            s.peers_sending = 0;
                            Some(old)
                        } else {
                            None
                        }
                    };
                    if let Some((old_dl, old_ul, old_peers)) = demoted {
                        self.metrics
                            .record_rate_change(old_dl, 0, old_ul, 0, old_peers, 0);
                    }
                    self.active_torrents.remove(&hash);
                    handle.stop_actor();
                }
            }
        }

        // 4. Start queued torrents in queue order (only rebuilding queue_positions when queued exist).
        for r in self.queued_torrents.iter() {
            let hash = *r;
            if self
                .torrents
                .get(&hash)
                .is_some_and(|h| h.value().stats.read().state == SwarmState::Queued)
            {
                queued_hashes.push(hash);
            }
        }
        if queued_hashes.is_empty() {
            return;
        }
        let mut active_total = active_non_stalled + active_seeds;
        let positions = self.queue_positions();
        queued_hashes.sort_by_key(|h| positions.get(h).copied().unwrap_or(u32::MAX));
        for hash in queued_hashes {
            if qm.evaluate_downloader(active_non_stalled, active_total) == QueueAction::Allow {
                if let Some(handle) = self.torrents.get(&hash).map(|r| r.value().clone()) {
                    {
                        let mut s = handle.stats.write();
                        if s.state != SwarmState::Queued {
                            continue;
                        }
                        s.state = SwarmState::Downloading;
                        s.tier = SwarmTier::Hot;
                        s.is_stalled = false;
                        s.last_transfer_at = now_secs as i64;
                        self.metrics
                            .record_state_transition(&SwarmState::Queued, &SwarmState::Downloading);
                    }
                    self.queued_torrents.remove(&hash);
                    self.downloading_torrents.insert(hash);
                    handle.mark_dirty();
                    first_seen.insert(hash, now);
                    let _ = self.wake_torrent_internal(&handle);
                    self.lsd_manager
                        .lock()
                        .register_torrent(hash, handle.info.private);
                    self.zeroconf_manager
                        .lock()
                        .register_torrent(hash, handle.info.private);
                    let peer_tx = handle.peer_event_tx().unwrap_or_else(|| mpsc::channel(1).0);
                    let initial_dl = handle.stats.read().downloaded_bytes;
                    self.announce_scheduler.register_with_details(
                        hash,
                        handle.info.clone(),
                        handle.stats.clone(),
                        peer_tx,
                        true,
                        crate::announcer::AnnounceDetails {
                            file_priorities: handle.file_priorities.clone(),
                            compressed_bitfield: handle.compressed_bitfield.clone(),
                            initial_downloaded: initial_dl,
                            missing_wanted_bytes: handle.missing_wanted_bytes.clone(),
                        },
                    );
                    active_non_stalled += 1;
                    active_total += 1;
                }
            }
        }
    }

    pub fn session_store(&self) -> Option<&Arc<SessionStore>> {
        self.session_store.as_ref()
    }

    pub fn lifecycle(&self) -> Option<&Arc<LifecycleDispatcher>> {
        self.lifecycle.as_ref()
    }

    pub fn torrent_count(&self) -> usize {
        self.torrents.len()
    }

    pub fn roster_version(&self) -> u64 {
        self.roster_version.load(Ordering::Acquire)
    }

    pub fn queue_version(&self) -> u64 {
        self.queue_version.load(Ordering::Acquire)
    }

    pub fn for_each_torrent_handle(&self, mut f: impl FnMut(&[u8; 20], &TorrentHandle)) {
        for entry in self.torrents.iter() {
            f(entry.key(), entry.value());
        }
    }

    /// Returns the number of currently active swarm actors running background tick loops.
    pub fn active_swarm_count(&self) -> usize {
        self.active_torrents
            .iter()
            .filter(|h| {
                self.torrents
                    .get(h.key())
                    .is_some_and(|t| t.value().is_active())
            })
            .count()
    }

    pub fn get_torrent(&self, info_hash: &[u8; 20]) -> Option<Arc<TorrentHandle>> {
        self.torrents.get(info_hash).map(|r| r.value().clone())
    }

    pub fn has_torrent(&self, info_hash: &[u8; 20]) -> bool {
        self.torrents.contains_key(info_hash)
    }

    pub fn search_manager(&self) -> &Arc<crate::search::SearchManager> {
        &self.search_manager
    }

    pub fn feed_manager(&self) -> &Arc<crate::feed::FeedManager> {
        &self.feed_manager
    }

    pub async fn poll_rss_feeds(&self) -> Vec<Result<usize, String>> {
        self.feed_manager.poll_all_feeds(self).await
    }

    pub fn list_torrents(&self) -> Vec<SwarmStats> {
        self.torrents
            .iter()
            .map(|r| r.value().stats.read().clone())
            .collect()
    }

    /// High-performance engine-level pagination that slices insertion order in O(limit) when
    /// unfiltered and preserves deterministic order across pages.
    pub fn list_torrents_paged(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<SwarmStateFilter>,
    ) -> (Vec<SwarmStats>, usize) {
        let order = self.torrent_order.read();
        if let Some(f) = filter {
            let mut matching_count = 0usize;
            let mut items = Vec::with_capacity(limit.min(100));
            for hash in order.iter() {
                match f {
                    SwarmStateFilter::Downloading if !self.downloading_torrents.contains(hash) => {
                        continue;
                    }
                    SwarmStateFilter::Queued if !self.queued_torrents.contains(hash) => {
                        continue;
                    }
                    _ => {}
                }
                if let Some(entry) = self.torrents.get(hash) {
                    let stats = entry.value().stats.read();
                    if f.matches(&stats.state, stats.tier) {
                        if matching_count >= offset && items.len() < limit {
                            items.push(stats.clone());
                        }
                        matching_count += 1;
                    }
                }
            }
            (items, matching_count)
        } else {
            let total = order.len();
            let start = offset.min(total);
            let end = start.saturating_add(limit).min(total);
            let items: Vec<SwarmStats> = order[start..end]
                .iter()
                .filter_map(|hash| {
                    self.torrents
                        .get(hash)
                        .map(|r| r.value().stats.read().clone())
                })
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
        let opts = SwarmResumeOptions {
            magnet_uri: Some(magnet_uri.to_string()),
            ..Default::default()
        };
        Ok(self.add_torrent_with_resume(info, download_dir, None, Some(opts)))
    }

    pub fn add_torrent(
        &self,
        info: Arc<Info>,
        download_dir: std::path::PathBuf,
        have: Option<&Bitfield>,
    ) -> Arc<TorrentHandle> {
        self.add_torrent_with_resume(info, download_dir, have, None)
    }

    /// BEP 9: called once a magnet-added torrent's metadata-only actor finishes
    /// assembling and verifying its real `Info` over the wire (see `TorrentConfig::
    /// on_metadata_resolved`). Drops the placeholder registration and re-adds the
    /// torrent under the same info_hash with the real metadata, preserving user
    /// flags/metadata/overrides and updating `metrics` cleanly.
    fn resolve_magnet_metadata(&self, download_dir: std::path::PathBuf, info: Info) {
        let info_hash = info.hash;
        tracing::info!(name = %info.name, hash = %hex::encode(info_hash), "Magnet metadata resolved; starting real download");
        self.announce_scheduler.unregister(&info_hash);
        self.lsd_manager.lock().unregister_torrent(&info_hash);
        self.zeroconf_manager.lock().unregister_torrent(&info_hash);
        self.mse_req2_index
            .remove(&synapse_wire::mse_req2(&info_hash));
        if let Some(v2) = info.info_hash_v2 {
            self.v2_torrents.remove(&v2);
        }

        self.remove_from_tracking_sets(&info_hash);
        let (prev_resume, old_final_dir) = if let Some((_, old)) = self.torrents.remove(&info_hash)
        {
            self.torrent_order.write().retain(|h| h != &info_hash);
            self.roster_version.fetch_add(1, Ordering::Release);
            self.queue_version.fetch_add(1, Ordering::Release);
            let (snap, was_paused) = {
                let mut s = old.stats.write();
                let snap = s.clone();
                let was_paused = s.state == SwarmState::Stopped;
                s.download_rate = 0;
                s.upload_rate = 0;
                s.peers_connected = 0;
                s.peers_sending = 0;
                (snap, was_paused)
            };
            self.metrics.record_remove(&snap);
            let final_dir = old.final_download_dir.read().clone();
            old.stop_actor();
            let meta = old.metadata.read().clone();
            (
                Some(SwarmResumeOptions {
                    uploaded_bytes: snap.uploaded_bytes,
                    downloaded_bytes: snap.downloaded_bytes,
                    ratio: Some(snap.ratio),
                    added_at: Some(snap.added_at),
                    is_paused: was_paused,
                    file_priorities: old.file_priorities.read().clone(),
                    sequential: old.sequential.load(Ordering::Relaxed),
                    tracker_override: old.tracker_override.read().clone(),
                    category: meta.category,
                    tags: meta.tags,
                    seed_ratio_limit: meta.seed_ratio_limit,
                    seed_time_limit_secs: meta.seed_time_limit_secs,
                    super_seeding: old.super_seeding.load(Ordering::Relaxed),
                    first_last_piece_priority: old
                        .first_last_piece_priority
                        .load(Ordering::Relaxed),
                    magnet_uri: None,
                    queue_position: None,
                    download_limit_bytes: old.download_limit_bytes.load(Ordering::Relaxed),
                    upload_limit_bytes: old.upload_limit_bytes.load(Ordering::Relaxed),
                }),
                final_dir,
            )
        } else {
            (None, None)
        };

        let target_dir = old_final_dir.unwrap_or(download_dir);
        let info_arc = Arc::new(info);
        let resolved_handle = self.add_torrent_with_resume_internal(
            info_arc.clone(),
            target_dir,
            None,
            prev_resume,
            true,
        );

        if let Some(ref store) = self.session_store {
            if info_arc.has_piece_hashes() {
                let store = store.clone();
                let hex_hash = hex::encode(info_hash);
                let raw_bytes = info_arc.to_torrent_bytes();
                let name = info_arc.name.clone();
                let total_size = info_arc.total_len;
                let total_pieces = info_arc.pieces() as usize;
                let file_count = info_arc.files.len();
                let select_only = info_arc.select_only.clone();
                let dl_dir_str = resolved_handle.stats.read().download_dir.clone();
                tokio::task::spawn_blocking(move || {
                    let _ = store.save_metadata(&info_hash, &raw_bytes);
                    if let Ok(Some(mut state)) = store.load_torrent(&hex_hash) {
                        state.name = name;
                        state.total_size = total_size;
                        state.total_pieces = total_pieces;
                        state.download_dir = dl_dir_str;
                        state.magnet_uri = None;
                        state.raw_bencode_hex = None;
                        if state.file_priorities.len() != file_count {
                            let mut prios = vec![4u8; file_count];
                            if let Some(ref sel) = select_only {
                                for (i, p) in prios.iter_mut().enumerate() {
                                    if !sel.contains(&i) {
                                        *p = 0;
                                    }
                                }
                            }
                            state.file_priorities = prios;
                        }
                        let _ = store.save_states_batch(&[state]);
                    }
                });
            }
        }
    }

    pub fn add_torrent_with_resume(
        &self,
        info: Arc<Info>,
        download_dir: std::path::PathBuf,
        have: Option<&Bitfield>,
        resume: Option<SwarmResumeOptions>,
    ) -> Arc<TorrentHandle> {
        self.add_torrent_with_resume_internal(info, download_dir, have, resume, false)
    }

    fn add_torrent_with_resume_internal(
        &self,
        info: Arc<Info>,
        download_dir: std::path::PathBuf,
        have: Option<&Bitfield>,
        resume: Option<SwarmResumeOptions>,
        treat_as_new_add: bool,
    ) -> Arc<TorrentHandle> {
        let info_hash = info.hash;

        // Re-adding a torrent that's already running (same info_hash) must be a no-op that
        // hands back the existing handle, not a teardown-and-restart: `resolve_magnet_metadata`
        // relies on this method still accepting a re-add for the same hash, but it always
        // removes the placeholder entry from `self.torrents` first, so it never hits this guard.
        if let Some(existing) = self.torrents.get(&info_hash) {
            tracing::info!(
                name = %info.name,
                hash = %hex::encode(info_hash),
                "torrent already added; ignoring duplicate add"
            );
            return existing.clone();
        }

        let total_size = info.total_len;
        let name = info.name.clone();
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let added_at = resume.as_ref().and_then(|r| r.added_at).unwrap_or(now_secs);

        let initial_progress = if let Some(h) = have {
            if h.is_complete() {
                1.0
            } else {
                (h.count_ones() as f32) / (info.pieces() as f32)
            }
        } else {
            0.0
        };
        let piece_downloaded = ((initial_progress as f64) * (total_size as f64)) as u64;
        let downloaded_bytes = resume
            .as_ref()
            .map(|r| r.downloaded_bytes.max(piece_downloaded))
            .unwrap_or(piece_downloaded);
        let uploaded_bytes = resume.as_ref().map(|r| r.uploaded_bytes).unwrap_or(0);
        let is_paused = resume.as_ref().map(|r| r.is_paused).unwrap_or(false);
        let ratio = resume.as_ref().and_then(|r| r.ratio).unwrap_or_else(|| {
            if downloaded_bytes > 0 {
                uploaded_bytes as f32 / downloaded_bytes as f32
            } else if total_size > 0 && uploaded_bytes > 0 {
                uploaded_bytes as f32 / total_size as f32
            } else {
                0.0
            }
        });

        // Seeding swarms (100% complete) initialize in the Warm tier (standby seed)
        // without spawning an idle actor ticker task until peers connect.
        let (initial_state, initial_tier) = if is_paused {
            (SwarmState::Stopped, SwarmTier::Cold)
        } else if initial_progress >= 1.0 {
            (SwarmState::Seeding, SwarmTier::Warm)
        } else {
            let qm = self.queue_manager.read();
            let mut active_dl = 0usize;
            for r in self.downloading_torrents.iter() {
                if let Some(t) = self.torrents.get(r.key()) {
                    let s = t.value().stats.read();
                    if s.state == SwarmState::Downloading && !s.is_stalled {
                        active_dl += 1;
                    }
                }
            }
            let active_seeds = if qm.config().dont_count_slow_torrents {
                let mut count = 0usize;
                for r in self.active_torrents.iter() {
                    if let Some(t) = self.torrents.get(r.key()) {
                        let s = t.value().stats.read();
                        if s.state == SwarmState::Seeding && !qm.is_slow_seeder(s.upload_rate) {
                            count += 1;
                        }
                    }
                }
                count
            } else {
                self.metrics.seeding_count.load(Ordering::Relaxed)
            };
            let active_total = active_dl + active_seeds;
            if qm.evaluate_downloader(active_dl, active_total) == QueueAction::Allow {
                (SwarmState::Downloading, SwarmTier::Hot)
            } else {
                (SwarmState::Queued, SwarmTier::Warm)
            }
        };

        let is_new_add = treat_as_new_add
            || resume.is_none()
            || resume
                .as_ref()
                .and_then(|r| r.magnet_uri.as_ref())
                .is_some();
        let (inc_enabled, inc_dir_opt, default_dl_dir) = {
            let s = self.settings.read();
            (
                s.incomplete_dir_enabled,
                s.incomplete_dir.clone(),
                s.download_dir.clone(),
            )
        };
        let (active_dir, final_dir) = if initial_progress < 1.0 && inc_enabled {
            if let Some(ref inc_dir) = inc_dir_opt {
                if Self::is_safe_storage_dir(inc_dir) {
                    if is_new_add
                        && download_dir != *inc_dir
                        && Self::is_safe_storage_dir(&download_dir)
                    {
                        (inc_dir.clone(), Some(download_dir))
                    } else if !is_new_add
                        && download_dir == *inc_dir
                        && default_dl_dir != *inc_dir
                        && Self::is_safe_storage_dir(&default_dl_dir)
                    {
                        (inc_dir.clone(), Some(default_dl_dir))
                    } else {
                        (download_dir, None)
                    }
                } else {
                    (download_dir, None)
                }
            } else {
                (download_dir, None)
            }
        } else {
            (download_dir, None)
        };
        let active_dir_str = active_dir.to_string_lossy().to_string();

        let initial_stats = SwarmStats {
            info_hash,
            name: name.clone(),
            total_size,
            progress: initial_progress,
            state: initial_state.clone(),
            tier: initial_tier,
            download_rate: 0,
            upload_rate: 0,
            downloaded_bytes,
            uploaded_bytes,
            peers_connected: 0,
            peers_sending: 0,
            eta_seconds: 0,
            ratio,
            download_dir: active_dir_str.clone(),
            added_at,
            is_private: info.private,
            is_stalled: false,
            last_transfer_at: now_secs,
            piece_count: info.pieces(),
            piece_size: info.piece_len,
        };

        self.metrics.record_add(
            &initial_state,
            initial_tier,
            downloaded_bytes,
            uploaded_bytes,
        );

        let magnet_uri_val = resume.as_ref().and_then(|r| r.magnet_uri.clone());
        let stats = Arc::new(RwLock::new(initial_stats));
        let compressed_bitfield = Arc::new(RwLock::new(
            have.map(synapse_picker::RoaringBitfield::from_bitfield),
        ));
        let saved_priorities = resume
            .as_ref()
            .map(|r| r.file_priorities.clone())
            .filter(|p| p.len() == info.files.len())
            .unwrap_or_else(|| {
                let mut prios = vec![4u8; info.files.len()];
                if let Some(ref select_only) = info.select_only {
                    for (i, p) in prios.iter_mut().enumerate() {
                        if !select_only.contains(&i) {
                            *p = 0;
                        }
                    }
                }
                prios
            });
        let initial_missing_wanted = if initial_progress >= 1.0 {
            0
        } else {
            let bf_guard = compressed_bitfield.read();
            crate::announcer::compute_missing_wanted_bytes(
                &info,
                &saved_priorities,
                bf_guard.as_ref(),
            )
        };
        let missing_wanted_bytes = Arc::new(AtomicU64::new(initial_missing_wanted));

        if resume.is_none() || magnet_uri_val.is_some() {
            if let Some(ref store) = self.session_store {
                if info.has_piece_hashes() {
                    let _ = store.save_metadata(&info_hash, &info.to_torrent_bytes());
                }
                let bitfield_hex = have.map(|h| hex::encode(h.as_bytes())).unwrap_or_default();
                let state = TorrentSessionState {
                    info_hash_hex: hex::encode(info_hash),
                    name: name.clone(),
                    download_dir: active_dir_str,
                    bitfield_hex,
                    total_pieces: info.pieces() as usize,
                    total_size,
                    uploaded_bytes,
                    downloaded_bytes,
                    added_at,
                    is_paused,
                    ratio: Some(ratio),
                    magnet_uri: magnet_uri_val.clone(),
                    raw_bencode_hex: None,
                    file_priorities: saved_priorities.clone(),
                    sequential: resume.as_ref().is_some_and(|r| r.sequential),
                    tracker_override: resume.as_ref().and_then(|r| r.tracker_override.clone()),
                    category: resume.as_ref().and_then(|r| r.category.clone()),
                    tags: resume.as_ref().map(|r| r.tags.clone()).unwrap_or_default(),
                    seed_ratio_limit: resume.as_ref().and_then(|r| r.seed_ratio_limit),
                    seed_time_limit_secs: resume.as_ref().and_then(|r| r.seed_time_limit_secs),
                    super_seeding: resume.as_ref().is_some_and(|r| r.super_seeding),
                    first_last_piece_priority: resume
                        .as_ref()
                        .is_some_and(|r| r.first_last_piece_priority),
                    queue_position: resume.as_ref().and_then(|r| r.queue_position),
                    download_limit_bytes: resume
                        .as_ref()
                        .map(|r| r.download_limit_bytes)
                        .unwrap_or(0),
                    upload_limit_bytes: resume.as_ref().map(|r| r.upload_limit_bytes).unwrap_or(0),
                };
                let _ = store.save_states_batch(&[state]);
            }
        }

        let initial_availability = if initial_tier == SwarmTier::Hot {
            if initial_state == SwarmState::Seeding {
                vec![1u32; info.pieces() as usize]
            } else {
                vec![0u32; info.pieces() as usize]
            }
        } else {
            Vec::new()
        };
        let piece_availability = Arc::new(RwLock::new(initial_availability));
        let file_priorities = Arc::new(RwLock::new(saved_priorities));

        let handle = Arc::new(TorrentHandle {
            info: info.clone(),
            stats: stats.clone(),
            compressed_bitfield,
            active_actor: Arc::new(RwLock::new(None)),
            live_peers: Arc::new(RwLock::new(Vec::new())),
            piece_availability,
            file_priorities,
            sequential: Arc::new(std::sync::atomic::AtomicBool::new(
                resume.as_ref().is_some_and(|r| r.sequential),
            )),
            first_last_piece_priority: Arc::new(std::sync::atomic::AtomicBool::new(
                resume.as_ref().is_some_and(|r| r.first_last_piece_priority),
            )),
            super_seeding: Arc::new(std::sync::atomic::AtomicBool::new(
                resume.as_ref().is_some_and(|r| r.super_seeding),
            )),
            magnet_uri: Arc::new(RwLock::new(magnet_uri_val)),
            metadata: Arc::new(RwLock::new(
                resume
                    .as_ref()
                    .map(|r| TorrentMetadata {
                        category: r.category.clone(),
                        tags: r.tags.clone(),
                        seed_ratio_limit: r.seed_ratio_limit,
                        seed_time_limit_secs: r.seed_time_limit_secs,
                    })
                    .unwrap_or_default(),
            )),
            tracker_override: Arc::new(RwLock::new(
                resume.as_ref().and_then(|r| r.tracker_override.clone()),
            )),
            download_limit_bytes: Arc::new(std::sync::atomic::AtomicU64::new(
                resume.as_ref().map(|r| r.download_limit_bytes).unwrap_or(0),
            )),
            upload_limit_bytes: Arc::new(std::sync::atomic::AtomicU64::new(
                resume.as_ref().map(|r| r.upload_limit_bytes).unwrap_or(0),
            )),
            dirty: Arc::new(AtomicBool::new(false)),
            last_flushed_downloaded: Arc::new(AtomicU64::new(downloaded_bytes)),
            last_flushed_uploaded: Arc::new(AtomicU64::new(uploaded_bytes)),
            missing_wanted_bytes,
            final_download_dir: Arc::new(RwLock::new(final_dir)),
        });
        // Always set (or clear): a re-added torrent must not inherit an override left over
        // from an earlier life under the same info hash.
        self.announce_scheduler.announcer().set_tracker_override(
            info.hash,
            handle
                .tracker_override
                .read()
                .as_ref()
                .map(|list| parse_tracker_urls(list)),
        );

        if initial_state == SwarmState::Seeding {
            info.evict_piece_hashes();
        }

        self.torrents.insert(info_hash, handle.clone());
        self.torrent_order.write().push(info_hash);
        self.sync_tracking_sets(&info_hash, &initial_state, initial_tier, Some(&handle));
        self.queue_order.lock().push(info_hash);
        self.roster_version.fetch_add(1, Ordering::Release);
        self.queue_version.fetch_add(1, Ordering::Release);
        self.mse_req2_index
            .insert(synapse_wire::mse_req2(&info_hash), info_hash);
        if let Some(v2) = info.info_hash_v2 {
            self.v2_torrents.insert(v2, handle.clone());
        }
        if !is_paused && initial_state != SwarmState::Queued {
            self.lsd_manager
                .lock()
                .register_torrent(info_hash, info.private);
            self.zeroconf_manager
                .lock()
                .register_torrent(info_hash, info.private);
        }
        self.post_alert(crate::alert::Alert::TorrentAdded { info_hash });

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

        if !is_paused && initial_state != SwarmState::Queued {
            let is_dl = initial_state == SwarmState::Downloading;
            // Trackers get only what this session downloads; bytes already on disk (cross-seed,
            // resume) are the baseline.
            let initial_dl = downloaded_bytes;
            self.announce_scheduler.register_with_details(
                info_hash,
                info,
                stats,
                peer_tx,
                is_dl,
                crate::announcer::AnnounceDetails {
                    file_priorities: handle.file_priorities.clone(),
                    compressed_bitfield: handle.compressed_bitfield.clone(),
                    initial_downloaded: initial_dl,
                    missing_wanted_bytes: handle.missing_wanted_bytes.clone(),
                },
            );
        }

        handle
    }

    /// Flushes dirty swarm session states to disk synchronously or during shutdown.
    pub async fn flush_session(&self) {
        let Some(ref store) = self.session_store else {
            return;
        };
        // Scanning/snapshotting dirty handles below only reads in-memory per-torrent state
        // (no disk I/O) and doesn't touch the session store, so it doesn't need `persist_lock`;
        // taking the lock only around the actual batched write lets `persist_torrent_option`/
        // `persist_file_priorities`'s quick single-record updates interleave with this scan
        // instead of queuing behind it.
        let dirty_handles: Vec<Arc<TorrentHandle>> = self
            .torrents
            .iter()
            .filter_map(|r| {
                let h = r.value();
                let is_dirty = h.dirty.load(Ordering::Acquire) || {
                    let s = h.stats.read();
                    s.downloaded_bytes != h.last_flushed_downloaded.load(Ordering::Relaxed)
                        || s.uploaded_bytes != h.last_flushed_uploaded.load(Ordering::Relaxed)
                };
                if is_dirty {
                    Some(h.clone())
                } else {
                    None
                }
            })
            .collect();
        if dirty_handles.is_empty() {
            return;
        }

        let positions = self.queue_positions();
        let mut snapshots = Vec::with_capacity(dirty_handles.len());
        let mut flushed_meta = Vec::with_capacity(dirty_handles.len());
        for h in dirty_handles {
            h.dirty.store(false, Ordering::Release);
            let state = Self::snapshot_handle_state(&h, positions.get(&h.info.hash).copied());
            let dl = state.downloaded_bytes;
            let ul = state.uploaded_bytes;
            snapshots.push(state);
            flushed_meta.push((h, dl, ul));
        }

        let flush_start = Instant::now();
        let store = store.clone();
        let persist_lock = self.persist_lock.clone();
        let res = tokio::task::spawn_blocking(move || {
            let _guard = persist_lock.blocking_lock();
            store.save_states_batch(&snapshots)
        })
        .await;
        self.metrics
            .last_flush_duration_ms
            .store(flush_start.elapsed().as_millis() as u64, Ordering::Relaxed);
        match res {
            Ok(Ok(())) => {
                for (h, dl, ul) in flushed_meta {
                    h.last_flushed_downloaded.store(dl, Ordering::Relaxed);
                    h.last_flushed_uploaded.store(ul, Ordering::Relaxed);
                }
            }
            _ => {
                for (h, _, _) in flushed_meta {
                    h.dirty.store(true, Ordering::Release);
                }
            }
        }
    }

    /// Rechecks torrent files on disk and verifies integrity — dispatched to the torrent's own
    /// task via `TorrentCommand::Recheck` for active torrents, or executed asynchronously in a
    /// standalone task for `Cold`/`Stopped` torrents so paused torrents never wake or resume
    /// network activity on recheck.
    pub fn recheck_torrent(&self, info_hash: &[u8; 20]) -> bool {
        let Some(handle) = self.torrents.get(info_hash).map(|r| r.value().clone()) else {
            return false;
        };

        // If hashes were evicted for memory savings during seeding, recover them on-demand
        if !handle.info.has_piece_hashes() {
            if let Some(hashes) = self.try_recover_piece_hashes(info_hash) {
                handle.info.restore_piece_hashes(hashes);
            }
        }

        let has_actor = handle.command_tx().is_some();
        let (old_state, tier, download_dir_str) = {
            let s = handle.stats.read();
            (s.state.clone(), s.tier, s.download_dir.clone())
        };

        if !has_actor
            && (tier == SwarmTier::Cold
                || matches!(old_state, SwarmState::Stopped | SwarmState::Checking))
        {
            if old_state == SwarmState::Checking {
                return true;
            }
            handle.stats.write().state = SwarmState::Checking;
            self.metrics
                .record_state_transition(&old_state, &SwarmState::Checking);
            self.downloading_torrents.remove(info_hash);
            self.queued_torrents.remove(info_hash);
            self.limited_seeds.remove(info_hash);
            handle.mark_dirty();
            self.post_alert(crate::alert::Alert::StateChanged {
                info_hash: *info_hash,
                old_state,
                new_state: SwarmState::Checking,
            });

            let engine = self.clone();
            let info_hash_copy = *info_hash;
            let info = handle.info.clone();
            let disk = self.disk.clone();
            let download_dir = PathBuf::from(download_dir_str);
            let file_priorities = handle.file_priorities.read().clone();

            tokio::spawn(async move {
                let part_file =
                    crate::part_file::PartFileManager::new(download_dir.clone(), info.hash);
                let total = info.pieces();
                let mut new_bitfield = Bitfield::new(total as usize);
                let previous_bitfield = handle.compressed_bitfield.read().clone();
                let concurrency = 8usize.min(total as usize).max(1);
                let mut join_set: tokio::task::JoinSet<(u32, bool, Option<[u8; 20]>, bool)> =
                    tokio::task::JoinSet::new();
                let mut results: Vec<(u32, bool, Option<[u8; 20]>, bool)> =
                    Vec::with_capacity(total as usize);

                for idx in 0..total {
                    while join_set.len() >= concurrency {
                        if let Some(Ok(r)) = join_set.join_next().await {
                            results.push(r);
                        }
                    }

                    let piece_len = info.piece_len(idx);
                    let locations = info.block_locations(idx, 0, piece_len);
                    let mut read_slices = Vec::with_capacity(locations.len());
                    let mut symlink_blocked = false;
                    for loc in locations {
                        if synapse_meta::is_padding_file(&info.files[loc.file].path, None) {
                            read_slices.push((None, loc.piece_range));
                        } else if crate::fs::verify_no_symlinks_under(
                            &download_dir,
                            &info.files[loc.file].path,
                        )
                        .is_err()
                        {
                            symlink_blocked = true;
                            break;
                        } else {
                            let normal_path = download_dir.join(&info.files[loc.file].path);
                            let mut piece_cursor = loc.piece_range.start;
                            for (target_path, target_offset, sub_len) in part_file
                                .resolve_read_ranges(
                                    loc.file,
                                    loc.file_offset,
                                    loc.piece_range.len(),
                                    &normal_path,
                                )
                            {
                                read_slices.push((
                                    Some(ReadJob {
                                        path: Arc::new(target_path),
                                        offset: target_offset,
                                        len: sub_len,
                                    }),
                                    piece_cursor..piece_cursor + sub_len,
                                ));
                                piece_cursor += sub_len;
                            }
                        }
                    }
                    if symlink_blocked {
                        // Treat as if a hash were available so the "no statically-known hash"
                        // fallback below never trusts a previous have-bit for a path a symlink
                        // may now be redirecting outside download_dir.
                        results.push((idx, false, None, true));
                        continue;
                    }

                    let info_c = info.clone();
                    let disk_c = disk.clone();
                    let expected_v1 = info.piece_hash(idx);
                    let is_merkle = info.is_merkle_v1();
                    let expected_v2 = info.piece_hash_v2(idx);
                    let has_expected_hash = expected_v1.is_some() || expected_v2.is_some();

                    join_set.spawn(async move {
                        let mut buf = vec![0u8; piece_len as usize];
                        let mut read_ok = true;
                        for (job_opt, range) in read_slices {
                            if let Some(job) = job_opt {
                                match disk_c.read(job).await {
                                    Ok(data) if data.len() == range.len() => {
                                        buf[range].copy_from_slice(&data);
                                    }
                                    Ok(_) | Err(_) => {
                                        read_ok = false;
                                        break;
                                    }
                                }
                            } else {
                                buf[range].fill(0);
                            }
                        }

                        let (verified, sha1) = tokio::task::spawn_blocking(move || {
                            let sha1: Option<[u8; 20]> =
                                (read_ok && is_merkle).then(|| Sha1::digest(&buf).into());
                            let verified = read_ok && {
                                if let Some(expected) = expected_v1 {
                                    let computed: [u8; 20] = Sha1::digest(&buf).into();
                                    computed == expected
                                } else if let Some(expected_v2) = expected_v2 {
                                    let computed: [u8; 32] =
                                        info_c.compute_piece_hash_v2(idx, &buf);
                                    computed == expected_v2
                                } else {
                                    false
                                }
                            };
                            (verified, sha1)
                        })
                        .await
                        .unwrap_or((false, None));

                        (idx, verified, sha1, has_expected_hash)
                    });
                }

                while let Some(res) = join_set.join_next().await {
                    if let Ok(r) = res {
                        results.push(r);
                    }
                }

                if info.is_merkle_v1() && results.iter().all(|(_, _, h, _)| h.is_some()) {
                    results.sort_by_key(|r| r.0);
                    let hashes: Vec<[u8; 20]> = results.iter().filter_map(|r| r.2).collect();
                    let expected_root = info.root_hash_v1;
                    let valid_merkle = tokio::task::spawn_blocking(move || {
                        synapse_meta::merkle_v1::MerkleTreeV1::from_piece_hashes(&hashes)
                            .is_some_and(|t| Some(t.root()) == expected_root)
                    })
                    .await
                    .unwrap_or(false);
                    if valid_merkle {
                        for r in &mut results {
                            r.1 = true;
                        }
                    }
                }

                let mut verified_count = 0usize;
                for (idx, verified, _, has_expected_hash) in results {
                    // A piece with no statically-known hash can't be re-verified cold (e.g. a
                    // BEP52 hash only ever recovered dynamically from a peer in a now-stopped
                    // live actor session); trust its previous have-bit rather than silently
                    // marking a paused/complete torrent incomplete. `Torrent::handle_recheck`
                    // (the live-actor path) can attempt this with in-memory dynamic hashes;
                    // this cold path cannot.
                    let keep = verified
                        || (!has_expected_hash
                            && previous_bitfield.as_ref().is_some_and(|b| b.has(idx as usize)));
                    if keep {
                        new_bitfield.set(idx as usize);
                        verified_count += 1;
                    }
                }

                // Ensure the handle wasn't removed, replaced, or woken into a live actor while checking.
                let Some(current) = engine
                    .torrents
                    .get(&info_hash_copy)
                    .map(|r| r.value().clone())
                else {
                    return;
                };
                if !Arc::ptr_eq(&current, &handle) || handle.command_tx().is_some() {
                    return;
                }

                let is_magnet_unresolved = handle.magnet_uri.read().is_some();
                let progress = if total > 0 {
                    verified_count as f32 / total as f32
                } else if is_magnet_unresolved {
                    0.0
                } else {
                    1.0
                };

                *handle.compressed_bitfield.write() = Some(
                    synapse_picker::RoaringBitfield::from_bitfield(&new_bitfield),
                );
                let new_missing = if total > 0 && verified_count == total as usize {
                    0
                } else {
                    crate::announcer::compute_missing_wanted_bytes(
                        &info,
                        &file_priorities,
                        handle.compressed_bitfield.read().as_ref(),
                    )
                };
                handle
                    .missing_wanted_bytes
                    .store(new_missing, Ordering::Release);

                {
                    let mut s = handle.stats.write();
                    s.progress = progress;
                    s.downloaded_bytes = ((progress as f64) * (info.total_len as f64)) as u64;
                    if s.state == SwarmState::Checking {
                        s.state = SwarmState::Stopped;
                        engine
                            .metrics
                            .record_state_transition(&SwarmState::Checking, &SwarmState::Stopped);
                    }
                }
                handle.mark_dirty();

                if let Some(ref store) = engine.session_store {
                    let queue_pos = engine.queue_positions().get(&info_hash_copy).copied();
                    let state = Self::snapshot_handle_state(&handle, queue_pos);
                    let store = store.clone();
                    let _ = tokio::task::spawn_blocking(move || store.save_states_batch(&[state]))
                        .await;
                }

                engine.post_alert(crate::alert::Alert::StateChanged {
                    info_hash: info_hash_copy,
                    old_state: SwarmState::Checking,
                    new_state: SwarmState::Stopped,
                });
            });

            return true;
        }

        if let Some(tx) = self.get_or_wake_command_tx(info_hash) {
            {
                let mut s = handle.stats.write();
                let prev_state = std::mem::replace(&mut s.state, SwarmState::Checking);
                self.metrics
                    .record_state_transition(&prev_state, &SwarmState::Checking);
            }
            self.downloading_torrents.remove(info_hash);
            self.queued_torrents.remove(info_hash);
            self.limited_seeds.remove(info_hash);
            handle.mark_dirty();
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
    /// Switches a torrent between rarest-first and sequential (in-order) piece picking.
    /// Returns false if the torrent doesn't exist.
    pub fn set_sequential_download(&self, info_hash: &[u8; 20], enabled: bool) -> bool {
        let Some(handle) = self.torrents.get(info_hash).map(|r| r.value().clone()) else {
            return false;
        };
        handle.sequential.store(enabled, Ordering::Relaxed);
        handle.mark_dirty();
        self.persist_torrent_option(info_hash, move |state| state.sequential = enabled);
        // A running actor changes mode now; a dormant one picks it up when it next starts.
        if let Some(tx) = handle.command_tx() {
            let _ = tx.try_send(TorrentCommand::SetSequential(enabled));
        }
        true
    }

    pub fn is_sequential(&self, info_hash: &[u8; 20]) -> bool {
        self.torrents
            .get(info_hash)
            .is_some_and(|h| h.sequential.load(Ordering::Relaxed))
    }

    /// Enables or disables first/last piece priority for a torrent.
    pub fn set_first_last_piece_priority(&self, info_hash: &[u8; 20], enabled: bool) -> bool {
        let Some(handle) = self.torrents.get(info_hash).map(|r| r.value().clone()) else {
            return false;
        };
        handle
            .first_last_piece_priority
            .store(enabled, Ordering::Relaxed);
        handle.mark_dirty();
        self.persist_torrent_option(info_hash, move |state| {
            state.first_last_piece_priority = enabled;
        });
        if let Some(tx) = handle.command_tx() {
            let _ = tx.try_send(TorrentCommand::SetFirstLastPiecePriority(enabled));
        }
        true
    }

    /// Enables or disables super-seeding mode for a torrent.
    pub fn set_super_seeding(&self, info_hash: &[u8; 20], enabled: bool) -> bool {
        let Some(handle) = self.torrents.get(info_hash).map(|r| r.value().clone()) else {
            return false;
        };
        handle.super_seeding.store(enabled, Ordering::Relaxed);
        handle.mark_dirty();
        self.persist_torrent_option(info_hash, move |state| {
            state.super_seeding = enabled;
        });
        if let Some(tx) = handle.command_tx() {
            let _ = tx.try_send(TorrentCommand::SetSuperSeeding(enabled));
        }
        true
    }

    /// Updates user-defined metadata (category, tags, per-torrent seed limits) and persists it.
    pub fn set_torrent_metadata(
        &self,
        info_hash: &[u8; 20],
        patch: TorrentMetadataPatch,
    ) -> Option<TorrentMetadata> {
        let handle = self.torrents.get(info_hash).map(|r| r.value().clone())?;
        let updated = {
            let mut meta = handle.metadata.write();
            if let Some(cat) = patch.category {
                meta.category = cat.and_then(|s| {
                    let t = s.trim().to_string();
                    if t.is_empty() {
                        None
                    } else {
                        Some(t)
                    }
                });
            }
            if let Some(tags) = patch.tags {
                let mut clean: Vec<String> = Vec::new();
                for t in tags {
                    let trimmed = t.trim().to_string();
                    if !trimmed.is_empty() && !clean.contains(&trimmed) {
                        clean.push(trimmed);
                    }
                }
                meta.tags = clean;
            }
            if let Some(ratio_lim) = patch.seed_ratio_limit {
                meta.seed_ratio_limit = ratio_lim.filter(|r| *r > 0.0);
            }
            if let Some(time_lim) = patch.seed_time_limit_secs {
                meta.seed_time_limit_secs = time_lim.filter(|t| *t > 0);
            }
            meta.clone()
        };
        if handle.stats.read().state != SwarmState::Stopped {
            if updated.seed_ratio_limit.is_some() || updated.seed_time_limit_secs.is_some() {
                self.limited_seeds.insert(*info_hash);
            } else {
                self.limited_seeds.remove(info_hash);
            }
        }
        let persisted = updated.clone();
        handle.mark_dirty();
        self.persist_torrent_option(info_hash, move |state| {
            state.category = persisted.category;
            state.tags = persisted.tags;
            state.seed_ratio_limit = persisted.seed_ratio_limit;
            state.seed_time_limit_secs = persisted.seed_time_limit_secs;
        });
        Some(updated)
    }

    /// Exports the `.torrent` bencode bytes and torrent name for a loaded torrent.
    pub fn export_torrent_bytes(&self, info_hash: &[u8; 20]) -> Option<(String, Vec<u8>)> {
        let handle = self.torrents.get(info_hash).map(|r| r.value().clone())?;
        let name = handle.stats.read().name.clone();
        if handle.info.has_piece_hashes() {
            return Some((name, handle.info.to_torrent_bytes()));
        }
        if let Some(ref store) = self.session_store {
            if let Ok(Some(bytes)) = store.load_metadata(info_hash) {
                return Some((name, bytes));
            }
        }
        None
    }

    /// Replaces the trackers a torrent announces to with `trackers` and announces to them
    /// straight away. An empty list restores the torrent's own trackers. Invalid URLs are
    /// dropped; returns how many usable trackers were set, or `None` if the torrent
    /// doesn't exist.
    pub fn replace_trackers(&self, info_hash: &[u8; 20], trackers: &[String]) -> Option<usize> {
        let handle = self.torrents.get(info_hash).map(|r| r.value().clone())?;
        let urls = parse_tracker_urls(trackers);
        let announcer = self.announce_scheduler.announcer();
        let (stored, count) = if trackers.is_empty() {
            announcer.set_tracker_override(handle.info.hash, None);
            (None, 0)
        } else {
            let strings: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
            let count = urls.len();
            announcer.set_tracker_override(handle.info.hash, Some(urls));
            (Some(strings), count)
        };
        *handle.tracker_override.write() = stored.clone();
        handle.mark_dirty();
        self.persist_torrent_option(info_hash, move |state| state.tracker_override = stored);
        self.announce_scheduler
            .drop_stale_tracker_reports(info_hash, &announcer.trackers_for(&handle.info));
        self.announce_scheduler.reannounce(info_hash);
        Some(count)
    }

    /// Announces to a torrent's trackers now rather than at the next scheduled time. Returns
    /// false if the torrent doesn't exist or isn't announcing (stopped or still queued).
    pub fn reannounce_torrent(&self, info_hash: &[u8; 20]) -> bool {
        self.torrents.contains_key(info_hash) && self.announce_scheduler.reannounce(info_hash)
    }

    /// Reconciles the queue order with the torrents that exist: drops the gone, and appends
    /// newcomers oldest-first so an unordered set of adds still yields a stable queue.
    fn sync_queue_order(&self, order: &mut Vec<[u8; 20]>) {
        let mut known: std::collections::HashSet<[u8; 20]> = std::collections::HashSet::new();
        order.retain(|h| self.torrents.contains_key(h) && known.insert(*h));
        let mut fresh: Vec<([u8; 20], i64)> = self
            .torrents
            .iter()
            .filter(|e| !known.contains(e.key()))
            .map(|e| (*e.key(), e.value().stats.read().added_at))
            .collect();
        fresh.sort_by_key(|(h, added)| (*added, *h));
        order.extend(fresh.into_iter().map(|(h, _)| h));
    }

    /// Every torrent's position in the download queue (0 is next in line).
    pub fn queue_positions(&self) -> std::collections::HashMap<[u8; 20], u32> {
        let mut order = self.queue_order.lock();
        self.sync_queue_order(&mut order);
        order
            .iter()
            .enumerate()
            .map(|(i, h)| (*h, i as u32))
            .collect()
    }

    /// Moves torrents within the download queue. Position decides which queued torrent starts
    /// next when a download slot frees up; it doesn't stop one that is already running.
    /// Returns how many of `hashes` exist.
    pub fn move_in_queue(&self, hashes: &[[u8; 20]], direction: QueueMove) -> usize {
        let selected: std::collections::HashSet<[u8; 20]> = hashes
            .iter()
            .copied()
            .filter(|h| self.torrents.contains_key(h))
            .collect();
        let mut order = self.queue_order.lock();
        self.sync_queue_order(&mut order);
        let old_order = order.clone();
        if apply_queue_move(&mut order, &selected, direction) {
            for (idx, hash) in order.iter().enumerate() {
                if old_order.get(idx) != Some(hash) {
                    if let Some(h) = self.torrents.get(hash) {
                        h.mark_dirty();
                    }
                }
            }
            drop(order);
            self.queue_version.fetch_add(1, Ordering::Release);
            self.reconcile_queue();
        }
        selected.len()
    }

    /// Saves one field of a torrent's session record without waiting for the next full flush.
    fn persist_torrent_option(
        &self,
        info_hash: &[u8; 20],
        apply: impl FnOnce(&mut TorrentSessionState) + Send + 'static,
    ) {
        let Some(store) = self.session_store.clone() else {
            return;
        };
        let persist_lock = self.persist_lock.clone();
        let hex = hex::encode(info_hash);
        tokio::task::spawn_blocking(move || {
            let _guard = persist_lock.blocking_lock();
            if let Ok(Some(mut state)) = store.load_torrent(&hex) {
                apply(&mut state);
                state.raw_bencode_hex = None;
                let _ = store.save_states_batch(&[state]);
            }
        });
    }

    pub fn set_file_priority(&self, info_hash: &[u8; 20], file_index: u32, priority: u8) -> bool {
        let Some(handle) = self.torrents.get(info_hash).map(|r| r.value().clone()) else {
            return false;
        };
        let priorities_snapshot = {
            let mut prios = handle.file_priorities.write();
            if let Some(p) = prios.get_mut(file_index as usize) {
                *p = priority;
            }
            prios.clone()
        };
        {
            let bf = handle.compressed_bitfield.read();
            let missing = crate::announcer::compute_missing_wanted_bytes(
                &handle.info,
                &priorities_snapshot,
                bf.as_ref(),
            );
            handle
                .missing_wanted_bytes
                .store(missing, Ordering::Release);
        }
        handle.mark_dirty();
        self.persist_file_priorities(info_hash, priorities_snapshot);
        if let Some(tx) = self.get_or_wake_command_tx(info_hash) {
            let _ = tx.try_send(TorrentCommand::SetFilePriority(file_index, priority));
        }
        true
    }

    /// Saves the current per-file priorities into the torrent's session record so they survive a
    /// restart (or crash) without waiting for the next full session flush.
    fn persist_file_priorities(&self, info_hash: &[u8; 20], priorities: Vec<u8>) {
        let Some(store) = self.session_store.clone() else {
            return;
        };
        let persist_lock = self.persist_lock.clone();
        let hex = hex::encode(info_hash);
        tokio::task::spawn_blocking(move || {
            let _guard = persist_lock.blocking_lock();
            if let Ok(Some(mut state)) = store.load_torrent(&hex) {
                state.file_priorities = priorities;
                state.raw_bencode_hex = None;
                let _ = store.save_states_batch(&[state]);
            }
        });
    }

    /// Returns the active priority for each file in the torrent (0=skip, 1=low, 4=normal, 7=high).
    pub fn get_file_priorities(&self, info_hash: &[u8; 20]) -> Option<Vec<u8>> {
        self.torrents
            .get(info_hash)
            .map(|h| h.file_priorities.read().clone())
    }

    /// Moves or updates a torrent's download directory. For active swarms this dispatches to
    /// `Torrent::handle_set_location`; for paused (`Cold`/`Stopped`) swarms this updates
    /// location (and optionally moves existing verified files) without waking the actor.
    pub fn set_location(&self, info_hash: &[u8; 20], new_download_dir: &str) -> bool {
        self.set_location_with_options(info_hash, new_download_dir, true)
    }

    pub fn set_location_with_options(
        &self,
        info_hash: &[u8; 20],
        new_download_dir: &str,
        move_existing_files: bool,
    ) -> bool {
        let Some(handle) = self.torrents.get(info_hash).map(|r| r.value().clone()) else {
            return false;
        };
        let new_dir = PathBuf::from(new_download_dir);
        if new_dir.as_os_str().is_empty()
            || !new_dir.is_absolute()
            || new_dir
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return false;
        }
        let (is_cold_or_stopped, old_dir_str, progress) = {
            let s = handle.stats.read();
            (
                s.tier == SwarmTier::Cold || s.state == SwarmState::Stopped,
                s.download_dir.clone(),
                s.progress,
            )
        };
        if !is_cold_or_stopped {
            if let Some(tx) = self.get_or_wake_command_tx(info_hash) {
                if tx
                    .try_send(TorrentCommand::SetLocation {
                        new_dir,
                        move_existing_files,
                    })
                    .is_ok()
                {
                    *handle.final_download_dir.write() = None;
                    return true;
                }
                return false;
            }
            return false;
        }

        let old_dir = PathBuf::from(&old_dir_str);
        if new_dir == old_dir {
            *handle.final_download_dir.write() = None;
            return true;
        }
        if std::fs::symlink_metadata(&new_dir).is_ok_and(|m| m.file_type().is_symlink()) {
            return false;
        }
        if move_existing_files
            && std::fs::symlink_metadata(&old_dir).is_ok_and(|m| m.file_type().is_symlink())
        {
            return false;
        }
        if std::fs::create_dir_all(&new_dir).is_err() {
            return false;
        }

        let has_verified_data = progress > 0.0
            || handle
                .compressed_bitfield
                .read()
                .as_ref()
                .is_some_and(|b| b.count_ones() > 0);

        let mut moved: Vec<(PathBuf, PathBuf)> = Vec::new();
        if move_existing_files {
            if has_verified_data {
                for file in &handle.info.files {
                    if crate::fs::verify_no_symlinks_under(&old_dir, &file.path).is_err()
                        || crate::fs::verify_no_symlinks_under(&new_dir, &file.path).is_err()
                    {
                        Self::rollback_moves_sync(&self.disk, &moved);
                        return false;
                    }
                    let src = old_dir.join(&file.path);
                    let dst = new_dir.join(&file.path);
                    match std::fs::symlink_metadata(&src) {
                        Ok(meta) if meta.file_type().is_file() => {}
                        Ok(_) => {
                            Self::rollback_moves_sync(&self.disk, &moved);
                            return false;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(_) => {
                            Self::rollback_moves_sync(&self.disk, &moved);
                            return false;
                        }
                    }
                    if !Self::move_file_with_fallback(&self.disk, &src, &dst, &mut moved) {
                        Self::rollback_moves_sync(&self.disk, &moved);
                        return false;
                    }
                }
            }

            let hex_hash = hex::encode(info_hash);
            for fname in [
                format!(".synapse_part_{hex_hash}"),
                format!(".synapse_part_{hex_hash}.map"),
            ] {
                let src = old_dir.join(&fname);
                match std::fs::symlink_metadata(&src) {
                    Ok(meta) if meta.file_type().is_file() => {}
                    Ok(_) => {
                        Self::rollback_moves_sync(&self.disk, &moved);
                        return false;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => {
                        Self::rollback_moves_sync(&self.disk, &moved);
                        return false;
                    }
                }
                let dst = new_dir.join(&fname);
                if !Self::move_file_with_fallback(&self.disk, &src, &dst, &mut moved) {
                    Self::rollback_moves_sync(&self.disk, &moved);
                    return false;
                }
            }
        }

        *handle.final_download_dir.write() = None;
        handle.stats.write().download_dir = new_dir.to_string_lossy().to_string();
        if let Some(ref store) = self.session_store {
            let hex_hash = hex::encode(info_hash);
            let new_dir_str = new_dir.to_string_lossy().to_string();
            if let Ok(Some(mut state)) = store.load_torrent(&hex_hash) {
                state.download_dir = new_dir_str;
                state.raw_bencode_hex = None;
                let _ = store.save_states_batch(&[state]);
            }
        }
        true
    }

    fn move_file_with_fallback(
        disk: &diskio::DiskEngine,
        src: &std::path::Path,
        dst: &std::path::Path,
        moved: &mut Vec<(PathBuf, PathBuf)>,
    ) -> bool {
        if let Ok(dst_meta) = std::fs::symlink_metadata(dst) {
            if dst_meta.file_type().is_symlink() || dst_meta.file_type().is_dir() {
                return false;
            }
        }
        if let Some(parent) = dst.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                return false;
            }
        }
        disk.evict(src);
        disk.evict(dst);
        if std::fs::rename(src, dst).is_err() {
            if std::fs::copy(src, dst).is_err() {
                let _ = std::fs::remove_file(dst);
                return false;
            }
            let _ = std::fs::remove_file(src);
        }
        moved.push((src.to_path_buf(), dst.to_path_buf()));
        true
    }

    fn rollback_moves_sync(disk: &diskio::DiskEngine, moved: &[(PathBuf, PathBuf)]) {
        for (src, dst) in moved.iter().rev() {
            disk.evict(dst);
            disk.evict(src);
            if std::fs::rename(dst, src).is_err() && std::fs::copy(dst, src).is_ok() {
                let _ = std::fs::remove_file(dst);
            }
        }
    }

    /// Configures global download and upload rate limits in bytes per second (0 = unlimited).
    pub fn set_rate_limits(&self, download_limit_bytes: u64, upload_limit_bytes: u64) {
        self.update_global_rate_limits(Some(download_limit_bytes), Some(upload_limit_bytes));
    }

    /// Partially updates global download and/or upload rate limits without wiping the omitted direction.
    pub fn update_global_rate_limits(
        &self,
        download_limit_bytes: Option<u64>,
        upload_limit_bytes: Option<u64>,
    ) {
        if download_limit_bytes.is_none() && upload_limit_bytes.is_none() {
            return;
        }
        {
            let mut s = self.settings.write();
            if let Some(dl) = download_limit_bytes {
                s.download_limit_bytes = dl;
                s.download_limit_enabled = dl > 0;
            }
            if let Some(ul) = upload_limit_bytes {
                s.upload_limit_bytes = ul;
                s.upload_limit_enabled = ul > 0;
            }
        }
        self.recalculate_effective_rate_limits();
    }

    /// Partially updates per-torrent download and/or upload rate limits (0 = unlimited), preserving
    /// any omitted direction across active and future woken actors.
    pub fn set_torrent_rate_limits(
        &self,
        info_hash: &[u8; 20],
        download_limit_bytes: Option<u64>,
        upload_limit_bytes: Option<u64>,
    ) -> bool {
        let Some(handle) = self.torrents.get(info_hash).map(|r| r.value().clone()) else {
            return false;
        };
        let effective_dl = match download_limit_bytes {
            Some(dl) => {
                handle.download_limit_bytes.store(dl, Ordering::Relaxed);
                dl
            }
            None => handle.download_limit_bytes.load(Ordering::Relaxed),
        };
        let effective_ul = match upload_limit_bytes {
            Some(ul) => {
                handle.upload_limit_bytes.store(ul, Ordering::Relaxed);
                ul
            }
            None => handle.upload_limit_bytes.load(Ordering::Relaxed),
        };
        if let Some(tx) = handle.command_tx() {
            let _ = tx.try_send(TorrentCommand::SetRateLimits {
                download_limit_bytes: effective_dl,
                upload_limit_bytes: effective_ul,
            });
        }
        handle.mark_dirty();
        true
    }

    pub fn settings(&self) -> Arc<RwLock<DynamicSessionSettings>> {
        self.settings.clone()
    }

    pub fn session_choker(&self) -> Arc<RwLock<synapse_picker::SessionChoker>> {
        self.session_choker.clone()
    }

    pub fn get_session_settings(&self) -> DynamicSessionSettings {
        self.settings.read().clone()
    }

    fn trigger_free_disk_refresh(&self, download_dir: PathBuf) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if self.free_disk_refreshing.swap(true, Ordering::AcqRel) {
            return;
        }
        struct ResetFlag(Arc<AtomicBool>);
        impl Drop for ResetFlag {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let cache = self.free_disk_cache.clone();
        let flag = ResetFlag(self.free_disk_refreshing.clone());
        handle.spawn_blocking(move || {
            let _guard = flag;
            let bytes = crate::fs::get_available_disk_space(&download_dir);
            *cache.lock() = Some((download_dir, Instant::now(), bytes));
        });
    }

    /// Returns the available disk space in bytes on the filesystem backing the configured `download_dir`,
    /// using a short-lived cache and background refresh when called inside a Tokio runtime.
    pub fn free_disk_space_bytes(&self) -> u64 {
        const FREE_DISK_CACHE_TTL: Duration = Duration::from_secs(5);
        let download_dir = self.settings.read().download_dir.clone();
        if let Some((ref cached_dir, cached_at, cached_bytes)) = *self.free_disk_cache.lock() {
            if cached_dir == &download_dir {
                if cached_at.elapsed() < FREE_DISK_CACHE_TTL {
                    return cached_bytes;
                }
                if tokio::runtime::Handle::try_current().is_ok() {
                    self.trigger_free_disk_refresh(download_dir);
                    return cached_bytes;
                }
            }
        }
        let bytes = crate::fs::get_available_disk_space(&download_dir);
        *self.free_disk_cache.lock() = Some((download_dir, Instant::now(), bytes));
        bytes
    }

    /// Non-blocking async variant of `free_disk_space_bytes` that offloads cache misses to `spawn_blocking`.
    pub async fn free_disk_space_bytes_async(&self) -> u64 {
        const FREE_DISK_CACHE_TTL: Duration = Duration::from_secs(5);
        let download_dir = self.settings.read().download_dir.clone();
        if let Some((ref cached_dir, cached_at, cached_bytes)) = *self.free_disk_cache.lock() {
            if cached_dir == &download_dir {
                if cached_at.elapsed() >= FREE_DISK_CACHE_TTL {
                    self.trigger_free_disk_refresh(download_dir);
                }
                return cached_bytes;
            }
        }
        let dir_for_stat = download_dir.clone();
        let bytes =
            tokio::task::spawn_blocking(move || crate::fs::get_available_disk_space(&dir_for_stat))
                .await
                .unwrap_or(0);
        *self.free_disk_cache.lock() = Some((download_dir, Instant::now(), bytes));
        bytes
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
            self.download_bucket
                .set_rate_auto_burst(s.alt_speed_down_bytes);
            self.upload_bucket.set_rate_auto_burst(s.alt_speed_up_bytes);
        } else {
            let dl = if s.download_limit_enabled {
                s.download_limit_bytes
            } else {
                0
            };
            let ul = if s.upload_limit_enabled {
                s.upload_limit_bytes
            } else {
                0
            };
            self.download_bucket.set_rate_auto_burst(dl);
            self.upload_bucket.set_rate_auto_burst(ul);
        }
    }

    /// Applies dynamic settings updates in flight. Returns a list of warning messages
    /// for any provided parameters that require a full daemon restart.
    pub fn update_session_settings(&self, update: SessionSettingsUpdate) -> Vec<String> {
        let mut warnings = Vec::new();
        if update.peer_port.is_some() {
            warnings.push("Modifying 'peer_port' dynamically is not supported; restart daemon to bind new port.".to_string());
        }
        if update.rpc_listen_addr.is_some() {
            warnings.push("Modifying 'rpc_listen_addr' dynamically is not supported; restart daemon to bind new address.".to_string());
        }
        if update.http_listen_addr.is_some() {
            warnings.push("Modifying 'http_listen_addr' dynamically is not supported; restart daemon to bind new address.".to_string());
        }

        {
            let mut s = self.settings.write();
            if let Some(v) = update.download_limit_enabled {
                s.download_limit_enabled = v;
            }
            if let Some(v) = update.download_limit_bytes {
                s.download_limit_bytes = v;
            }
            if let Some(v) = update.upload_limit_enabled {
                s.upload_limit_enabled = v;
            }
            if let Some(v) = update.upload_limit_bytes {
                s.upload_limit_bytes = v;
            }

            if let Some(v) = update.alt_speed_enabled {
                s.alt_speed_enabled = v;
            }
            if let Some(v) = update.alt_speed_down_bytes {
                s.alt_speed_down_bytes = v;
            }
            if let Some(v) = update.alt_speed_up_bytes {
                s.alt_speed_up_bytes = v;
            }
            if let Some(v) = update.alt_speed_time_enabled {
                s.alt_speed_time_enabled = v;
            }
            if let Some(v) = update.alt_speed_time_begin {
                s.alt_speed_time_begin = v;
            }
            if let Some(v) = update.alt_speed_time_end {
                s.alt_speed_time_end = v;
            }
            if let Some(v) = update.alt_speed_time_days {
                s.alt_speed_time_days = v;
            }

            if let Some(v) = update.download_queue_enabled {
                s.queue.download_queue_enabled = v;
            }
            if let Some(v) = update.download_queue_size {
                s.queue.max_active_downloads = v;
            }
            if let Some(v) = update.seed_queue_enabled {
                s.queue.seed_queue_enabled = v;
            }
            if let Some(v) = update.seed_queue_size {
                s.queue.max_active_seeds = v;
            }
            if let Some(v) = update.max_active_torrents {
                s.queue.max_active_torrents = v;
            }
            if let Some(v) = update.queue_stalled_enabled {
                s.queue.queue_stalled_enabled = v;
            }
            if let Some(v) = update.queue_stalled_minutes {
                s.queue.queue_stalled_minutes = v;
            }
            if let Some(v) = update.seed_ratio_limited {
                s.queue.seed_ratio_limited = v;
            }
            if let Some(v) = update.seed_ratio_limit {
                s.queue.share_ratio_limit = Some(v);
            }
            if let Some(v) = update.idle_seeding_limit_enabled {
                s.queue.idle_seeding_limit_enabled = v;
            }
            if let Some(v) = update.idle_seeding_limit_minutes {
                s.queue.seed_time_limit_secs = Some((v as u64) * 60);
            }

            if let Some(v) = update.max_peers_per_torrent {
                s.max_peers_per_torrent = v;
            }
            if let Some(v) = update.max_global_peers {
                s.max_global_peers = v;
            }
            if let Some(v) = update.dht_enabled {
                s.dht_enabled = v;
            }
            if let Some(v) = update.dht_read_only {
                s.dht_read_only = v;
                if let Some(h) = self.dht.read().as_ref() {
                    h.set_read_only(v);
                }
            }
            if let Some(v) = update.pex_enabled {
                s.pex_enabled = v;
            }
            if let Some(v) = update.lsd_enabled {
                s.lsd_enabled = v;
            }
            if let Some(v) = update.zeroconf_enabled {
                s.zeroconf_enabled = v;
            }
            if let Some(v) = update.announce_ip {
                let v = v.trim();
                if v.is_empty() {
                    s.announce_ip = None;
                } else {
                    match v.parse() {
                        Ok(ip) => s.announce_ip = Some(ip),
                        Err(_) => warnings
                            .push(format!("announce_ip '{v}' is not an IP address; ignored")),
                    }
                }
            }
            if let Some(v) = update.enable_utp {
                s.enable_utp = v;
            }
            if let Some(v) = update.encryption {
                s.encryption = v;
            }

            if let Some(v) = update.download_dir {
                s.download_dir = std::path::PathBuf::from(v);
            }
            if let Some(v) = update.incomplete_dir {
                s.incomplete_dir = Some(std::path::PathBuf::from(v));
            }
            if let Some(v) = update.incomplete_dir_enabled {
                s.incomplete_dir_enabled = v;
            }
            if let Some(v) = update.start_added_torrents {
                s.start_added_torrents = v;
            }
            if let Some(v) = update.trash_original_torrent_files {
                s.trash_original_torrent_files = v;
            }

            if let Some(v) = update.unchoke_slots_global {
                s.unchoke_slots_global = v;
            }
            if let Some(v) = update.seed_choking_algorithm {
                s.seed_choking_algorithm = v;
            }
            if let Some(v) = update.unchoke_slot_bandwidth {
                s.unchoke_slot_bandwidth = v;
            }
            if let Some(v) = update.limit_lan_peers {
                s.limit_lan_peers = v;
            }
            if let Some(v) = update.rate_limit_ip_overhead {
                s.rate_limit_ip_overhead = v;
            }

            if let Some(v) = update.max_concurrent_tracker_announces {
                s.max_concurrent_tracker_announces = v;
            }
            if let Some(v) = update.max_concurrent_dht_announces {
                s.max_concurrent_dht_announces = v;
            }
            if let Some(v) = update.max_concurrent_lsd_announces {
                s.max_concurrent_lsd_announces = v;
            }

            self.queue_manager.write().set_config(s.queue.clone());
        }

        self.dht_concurrency_notify.notify_waiters();
        self.recalculate_effective_rate_limits();
        self.rechoke_session();
        warnings
    }

    /// Evaluates all active swarms and distributes unchoke slots session-wide based on
    /// torrent priority, seeding state, and interested peer demand.
    pub fn rechoke_session(&self) {
        let is_alt = self.is_alt_speed_active();
        let (global_slots, slot_bw, upload_limit, seed_algo_str) = {
            let s = self.settings.read();
            let upload_lim = if is_alt {
                s.alt_speed_up_bytes
            } else if s.upload_limit_enabled {
                s.upload_limit_bytes
            } else {
                0
            };
            (
                s.unchoke_slots_global,
                s.unchoke_slot_bandwidth,
                upload_lim,
                s.seed_choking_algorithm.clone(),
            )
        };

        let seed_algo = match seed_algo_str.to_lowercase().as_str() {
            "anti_leech" => synapse_picker::SeedChokingAlgorithm::AntiLeech,
            "fastest_upload" => synapse_picker::SeedChokingAlgorithm::FastestUpload,
            _ => synapse_picker::SeedChokingAlgorithm::RoundRobin,
        };

        let mut choker = self.session_choker.write();
        choker.global_unchoke_slots = global_slots.max(1);
        choker.slot_bandwidth = slot_bw.max(1);

        let mut demands = Vec::new();
        let active_hashes: Vec<[u8; 20]> = self.active_torrents.iter().map(|r| *r).collect();
        for info_hash in active_hashes {
            let Some(handle) = self.torrents.get(&info_hash).map(|r| r.value().clone()) else {
                self.active_torrents.remove(&info_hash);
                continue;
            };
            if !handle.is_active() {
                self.active_torrents.remove(&info_hash);
                continue;
            }
            let (is_seeding, priority) = {
                let s = handle.stats.read();
                let prio = match s.tier {
                    SwarmTier::Hot => 5,
                    SwarmTier::Warm => 4,
                    SwarmTier::Cold => 2,
                };
                (s.state == SwarmState::Seeding, prio)
            };
            let interested_peers = handle
                .live_peers
                .read()
                .iter()
                .filter(|p| p.peer_interested)
                .count();
            demands.push(synapse_picker::SwarmChokerDemand {
                swarm_id: info_hash,
                priority,
                is_seeding,
                interested_peers,
            });
        }

        let allocation = choker.allocate_slots(&demands, upload_limit);

        for (info_hash, slots) in allocation {
            if let Some(handle) = self.torrents.get(&info_hash).map(|r| r.value().clone()) {
                if let Some(tx) = handle.command_tx() {
                    let _ = tx.try_send(TorrentCommand::SetUnchokeSlots(slots));
                    let _ = tx.try_send(TorrentCommand::SetSeedChokingAlgorithm(seed_algo));
                }
            }
        }
    }

    /// Spawns a background task running periodic session rechokes every 5 seconds.
    pub fn start_session_choker_loop(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                self.recalculate_effective_rate_limits();
                self.rechoke_session();
            }
        })
    }

    /// Transitions an active torrent to the Warm tier (idle seeding with compressed Roaring Bitfield).
    pub fn transition_to_warm(&self, info_hash: &[u8; 20]) -> bool {
        if let Some(handle) = self.torrents.get(info_hash).map(|r| r.value().clone()) {
            let (cur_state, old_dl, old_ul, old_peers) = {
                let mut stats = handle.stats.write();
                let old = (
                    stats.download_rate,
                    stats.upload_rate,
                    stats.peers_connected,
                );
                stats.tier = SwarmTier::Warm;
                // Zero synchronously -- see the matching comment on the seed-queue-cap
                // demotion in `reconcile_queue` for why relying solely on `stop_actor`'s async
                // teardown leaves a torrent showing a frozen nonzero rate with 0 peers.
                stats.download_rate = 0;
                stats.upload_rate = 0;
                stats.peers_connected = 0;
                stats.peers_sending = 0;
                (stats.state.clone(), old.0, old.1, old.2)
            };
            self.metrics
                .record_rate_change(old_dl, 0, old_ul, 0, old_peers, 0);
            self.sync_tracking_sets(info_hash, &cur_state, SwarmTier::Warm, Some(&handle));
            handle.stop_actor();
            true
        } else {
            false
        }
    }

    /// Transitions an active torrent to the Cold tier (paused / stopped).
    pub fn transition_to_cold(&self, info_hash: &[u8; 20]) -> bool {
        if let Some(handle) = self.torrents.get(info_hash).map(|r| r.value().clone()) {
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
            self.metrics
                .record_rate_change(old_dl, 0, old_ul, 0, old_peers, 0);
            self.metrics
                .record_state_transition(&old_state, &SwarmState::Stopped);
            self.post_alert(crate::alert::Alert::StateChanged {
                info_hash: *info_hash,
                old_state,
                new_state: SwarmState::Stopped,
            });
            drop(stats);
            self.remove_from_tracking_sets(info_hash);
            handle.stop_actor();
            self.announce_scheduler.unregister(info_hash);
            self.lsd_manager.lock().unregister_torrent(info_hash);
            self.zeroconf_manager.lock().unregister_torrent(info_hash);

            if let Some(ref store) = self.session_store {
                let hex_hash = hex::encode(info_hash);
                if let Ok(Some(mut state)) = store.load_torrent(&hex_hash) {
                    state.is_paused = true;
                    state.raw_bencode_hex = None;
                    let _ = store.save_states_batch(&[state]);
                } else {
                    handle.mark_dirty();
                }
            } else {
                handle.mark_dirty();
            }
            true
        } else {
            false
        }
    }

    /// Transitions a torrent back to the Hot tier for active transfers.
    pub fn transition_to_hot(&self, info_hash: &[u8; 20]) -> bool {
        if let Some(handle) = self.torrents.get(info_hash).map(|r| r.value().clone()) {
            let mut stats = handle.stats.write();
            let old_state = stats.state.clone();
            let target_state = if stats.progress >= 1.0 {
                SwarmState::Seeding
            } else {
                SwarmState::Downloading
            };
            stats.tier = SwarmTier::Hot;
            stats.state = target_state.clone();
            stats.is_stalled = false;
            stats.last_transfer_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            self.metrics
                .record_state_transition(&old_state, &target_state);
            self.post_alert(crate::alert::Alert::StateChanged {
                info_hash: *info_hash,
                old_state,
                new_state: target_state.clone(),
            });
            drop(stats);

            let is_dl = target_state == SwarmState::Downloading;
            self.sync_tracking_sets(info_hash, &target_state, SwarmTier::Hot, Some(&handle));
            let _ = self.wake_torrent_internal(&handle);
            let peer_tx = handle.peer_event_tx().unwrap_or_else(|| mpsc::channel(1).0);
            let initial_dl = {
                let s = handle.stats.read();
                s.downloaded_bytes
            };
            self.announce_scheduler.register_with_details(
                *info_hash,
                handle.info.clone(),
                handle.stats.clone(),
                peer_tx,
                is_dl,
                crate::announcer::AnnounceDetails {
                    file_priorities: handle.file_priorities.clone(),
                    compressed_bitfield: handle.compressed_bitfield.clone(),
                    initial_downloaded: initial_dl,
                    missing_wanted_bytes: handle.missing_wanted_bytes.clone(),
                },
            );
            self.announce_scheduler.notify_resumed(info_hash);
            self.lsd_manager
                .lock()
                .register_torrent(*info_hash, handle.info.private);
            self.zeroconf_manager
                .lock()
                .register_torrent(*info_hash, handle.info.private);

            if let Some(ref store) = self.session_store {
                let hex_hash = hex::encode(info_hash);
                if let Ok(Some(mut state)) = store.load_torrent(&hex_hash) {
                    state.is_paused = false;
                    state.raw_bencode_hex = None;
                    let _ = store.save_states_batch(&[state]);
                } else {
                    handle.mark_dirty();
                }
            } else {
                handle.mark_dirty();
            }
            true
        } else {
            false
        }
    }

    pub fn remove_torrent(&self, info_hash: &[u8; 20]) -> bool {
        self.announce_scheduler.unregister(info_hash);
        self.lsd_manager.lock().unregister_torrent(info_hash);
        self.zeroconf_manager.lock().unregister_torrent(info_hash);
        self.remove_from_tracking_sets(info_hash);
        if let Some(ref store) = self.session_store {
            let _ = store.remove_torrent(info_hash);
        }
        if let Some((_, handle)) = self.torrents.remove(info_hash) {
            self.torrent_order.write().retain(|h| h != info_hash);
            self.roster_version.fetch_add(1, Ordering::Release);
            self.queue_version.fetch_add(1, Ordering::Release);
            self.mse_req2_index
                .remove(&synapse_wire::mse_req2(info_hash));
            if let Some(v2) = handle.info.info_hash_v2 {
                self.v2_torrents.remove(&v2);
            }
            let dl_dir = {
                let mut s = handle.stats.write();
                self.metrics.record_remove(&s);
                s.download_rate = 0;
                s.upload_rate = 0;
                s.peers_connected = 0;
                s.peers_sending = 0;
                PathBuf::from(&s.download_dir)
            };
            handle.stop_actor();
            for file in &handle.info.files {
                self.disk.evict(&dl_dir.join(&file.path));
            }
            let hex_hash = hex::encode(info_hash);
            self.disk
                .evict(&dl_dir.join(format!(".synapse_part_{hex_hash}")));
            // The part file and its slice map are private scratch; nothing else can use them.
            crate::part_file::PartFileManager::remove_files(&dl_dir, info_hash);
            true
        } else {
            false
        }
    }

    /// Looks up a torrent by its 32-byte BitTorrent v2 SHA-256 info-hash (BEP 52).
    pub fn torrent_by_v2_hash(&self, hash: &[u8; 32]) -> Option<Arc<TorrentHandle>> {
        self.v2_torrents.get(hash).map(|r| r.value().clone())
    }

    fn build_watch_dir_index(watch_dir: &std::path::Path) -> WatchDirIndex {
        let mut index = std::collections::HashMap::new();
        let candidates = [
            watch_dir.to_path_buf(),
            watch_dir.join(".imported"),
            watch_dir.join(".failed"),
        ];
        for dir in &candidates {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Ok(bytes) = std::fs::read(&path) {
                            if let Ok(reloaded) = Info::from_persisted_bencode(&bytes) {
                                if reloaded.has_piece_hashes() {
                                    index.entry(reloaded.hash).or_insert((reloaded, bytes));
                                }
                            }
                        }
                    }
                }
            }
        }
        index
    }

    pub fn restore_session(&self) -> std::io::Result<usize> {
        let Some(ref store) = self.session_store else {
            return Ok(0);
        };
        let mut entries = store.load_all_entries()?;
        entries.sort_by(|a, b| {
            (
                a.0.queue_position.unwrap_or(u32::MAX),
                a.0.added_at,
                &a.0.info_hash_hex,
            )
                .cmp(&(
                    b.0.queue_position.unwrap_or(u32::MAX),
                    b.0.added_at,
                    &b.0.info_hash_hex,
                ))
        });

        enum ParsedMeta {
            Complete(Info),
            Incomplete(Info),
            Mismatch([u8; 20]),
            Missing,
        }

        let mut watch_dir_index: Option<WatchDirIndex> = None;
        let mut restored = 0;
        for (state, raw_meta) in entries {
            if let Some(info_hash) = state.info_hash() {
                if self.torrents.contains_key(&info_hash) {
                    continue;
                }
                let parsed = match raw_meta {
                    Some(bytes) => match Info::from_persisted_bencode(&bytes).ok() {
                        Some(mut info) => {
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
                                    ParsedMeta::Incomplete(info)
                                } else {
                                    ParsedMeta::Mismatch(info.hash)
                                }
                            } else if info.has_piece_hashes() {
                                ParsedMeta::Complete(info)
                            } else {
                                ParsedMeta::Incomplete(info)
                            }
                        }
                        None => ParsedMeta::Missing,
                    },
                    None => ParsedMeta::Missing,
                };

                let info_result = match parsed {
                    ParsedMeta::Complete(info) => Some(info),
                    other => {
                        let healed = if let Some(ref watch_dir) = self.watch_dir {
                            let idx = watch_dir_index
                                .get_or_insert_with(|| Self::build_watch_dir_index(watch_dir));
                            idx.get(&info_hash).map(|(reloaded, raw_bytes)| {
                                tracing::info!(
                                    "Auto-healed corrupted session metadata for '{}' ({}) from watch directory",
                                    reloaded.name,
                                    state.info_hash_hex,
                                );
                                let _ = store.save_metadata(&info_hash, raw_bytes);
                                reloaded.clone()
                            })
                        } else {
                            None
                        };
                        match (healed, other) {
                            (Some(info), _) => Some(info),
                            (None, ParsedMeta::Incomplete(info)) => Some(info),
                            (None, ParsedMeta::Mismatch(payload_hash)) => {
                                tracing::warn!(
                                    "Session file hash mismatch for '{}' (header hash: {}, payload hash: {}). Skipping without purging.",
                                    state.name,
                                    state.info_hash_hex,
                                    hex::encode(payload_hash)
                                );
                                continue;
                            }
                            (None, ParsedMeta::Missing | ParsedMeta::Complete(_)) => state
                                .magnet_uri
                                .as_deref()
                                .and_then(|uri| Info::from_magnet(uri).ok()),
                        }
                    }
                };

                if let Some(info) = info_result {
                    let mut have = state.to_bitfield();
                    let mut downloaded_bytes = state.downloaded_bytes;
                    if let Some(ref mut bf) = have {
                        let dropped = verify_resume_bitfield(
                            &info,
                            std::path::Path::new(&state.download_dir),
                            bf,
                        );
                        if dropped > 0 {
                            warn!(
                                name = %info.name,
                                dropped,
                                "Resume data claimed pieces whose files are missing or too short; they will be downloaded again"
                            );
                            downloaded_bytes = (0..info.pieces())
                                .filter(|&i| bf.has(i as usize))
                                .map(|i| u64::from(info.piece_len(i)))
                                .sum();
                        }
                    }
                    let resume_opts = SwarmResumeOptions {
                        uploaded_bytes: state.uploaded_bytes,
                        downloaded_bytes,
                        ratio: Some(state.effective_ratio()),
                        added_at: Some(state.added_at),
                        is_paused: state.is_paused,
                        file_priorities: state.file_priorities.clone(),
                        sequential: state.sequential,
                        tracker_override: state.tracker_override.clone(),
                        category: state.category.clone(),
                        tags: state.tags.clone(),
                        seed_ratio_limit: state.seed_ratio_limit,
                        seed_time_limit_secs: state.seed_time_limit_secs,
                        super_seeding: state.super_seeding,
                        first_last_piece_priority: state.first_last_piece_priority,
                        magnet_uri: if info.files.is_empty() {
                            state.magnet_uri.clone()
                        } else {
                            None
                        },
                        queue_position: state.queue_position,
                        download_limit_bytes: state.download_limit_bytes,
                        upload_limit_bytes: state.upload_limit_bytes,
                    };
                    self.add_torrent_with_resume(
                        Arc::new(info),
                        std::path::PathBuf::from(&state.download_dir),
                        have.as_ref(),
                        Some(resume_opts),
                    );
                    restored += 1;
                }
            }
        }
        // Preserve restored queue_position order; sync_queue_order only deduplicates/appends.
        if restored > 0 {
            let mut order = self.queue_order.lock();
            self.sync_queue_order(&mut order);
            self.roster_version.fetch_add(1, Ordering::Release);
            self.queue_version.fetch_add(1, Ordering::Release);
        }
        Ok(restored)
    }

    pub async fn start_listener(
        self: Arc<Self>,
        bind_addr: SocketAddr,
    ) -> Result<tokio::task::JoinHandle<()>, std::io::Error> {
        let listener = bind_tcp_listener(bind_addr)?;
        let local_addr = listener.local_addr()?;
        // The first listener started is the primary one: it owns the advertised port, the NAT
        // mapping and the UDP side (uTP + DHT). Any further listener (IPv6, or another
        // interface) only adds inbound TCP.
        let primary = *self.listen_port.read() == 0;
        if primary {
            *self.listen_port.write() = local_addr.port();
            self.nat_manager.write().request_mapping(
                local_addr.port(),
                crate::nat::PortProtocol::Tcp,
                "Synapse BitTorrent TCP",
            );
            self.clone()
                .start_nat_mapping(local_addr.port(), crate::nat::PortProtocol::Tcp);
        }
        info!("SwarmEngine inbound TCP listener active on {}", local_addr);

        if primary && self.settings.read().enable_utp {
            let utp_bind_addr = SocketAddr::new(bind_addr.ip(), local_addr.port());
            // One UDP socket serves both uTP and the DHT (see `synapse_wire::UdpMux`); the DHT
            // half is parked until `start_dht` claims it.
            let mux_result = synapse_wire::UdpMux::bind(utp_bind_addr).await;
            let utp_result = match mux_result {
                Ok(mux) => {
                    *self.dht_transport.lock() = Some((local_addr.port(), mux.dht));
                    crate::utp::UtpSocketManager::with_transport(mux.utp, 1000).await
                }
                Err(e) => Err(e),
            };
            match utp_result {
                Ok(utp_mgr) => {
                    *self.utp_manager.write() = Some(Arc::clone(&utp_mgr));
                    self.announce_scheduler
                        .set_utp_manager(Arc::clone(&utp_mgr));
                    self.nat_manager.write().request_mapping(
                        local_addr.port(),
                        crate::nat::PortProtocol::Udp,
                        "Synapse BitTorrent uTP",
                    );
                    self.clone()
                        .start_nat_mapping(local_addr.port(), crate::nat::PortProtocol::Udp);
                    info!(
                        "SwarmEngine inbound uTP listener active on {}",
                        utp_bind_addr
                    );

                    let engine = self.clone();
                    let utp_listener = Arc::clone(&utp_mgr);
                    tokio::spawn(async move {
                        while let Ok((stream, remote_addr)) = utp_listener.accept().await {
                            if engine.ip_filter.read().is_blocked(remote_addr.ip()) {
                                debug!(addr = %remote_addr, "Rejecting inbound uTP connection: IP blocklisted");
                                continue;
                            }
                            if engine.ban_list.is_banned(remote_addr.ip()) {
                                debug!(addr = %remote_addr, "Rejecting inbound uTP connection: IP banned");
                                continue;
                            }
                            let max_global = engine.settings.read().max_global_peers;
                            if engine
                                .metrics
                                .global_peers_connected
                                .load(Ordering::Relaxed)
                                >= max_global.saturating_add(CONNECTION_SLACK)
                            {
                                debug!(addr = %remote_addr, "Rejecting inbound uTP connection: global connection limit reached");
                                continue;
                            }
                            let Ok(handshake_slot) =
                                engine.pending_handshakes.clone().try_acquire_owned()
                            else {
                                debug!(addr = %remote_addr, "Rejecting inbound uTP connection: too many pending handshakes");
                                continue;
                            };
                            let engine_inner = engine.clone();
                            tokio::spawn(async move {
                                let _handshake_slot = handshake_slot;
                                let enc_mode = engine_inner.settings.read().encryption_mode();
                                let req2_index = engine_inner.mse_req2_index.clone();
                                let _ = accept_router_indexed(
                                    stream,
                                    remote_addr,
                                    engine_inner.peer_id,
                                    move |req2| req2_index.get(req2).map(|h| *h),
                                    |hash| {
                                        let tx = engine_inner.get_or_wake_torrent(&hash)?;
                                        let is_private = engine_inner
                                            .torrents
                                            .get(&hash)
                                            .map(|h| h.is_private())
                                            .unwrap_or(false);
                                        Some((tx, is_private))
                                    },
                                    enc_mode,
                                )
                                .await;
                            });
                        }
                    });
                }
                Err(e) => {
                    warn!("Failed to bind uTP UDP socket on {}: {}", utp_bind_addr, e);
                }
            }
        }

        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, remote_addr)) => {
                        if self.ip_filter.read().is_blocked(remote_addr.ip()) {
                            debug!(addr = %remote_addr, "Rejecting inbound connection: IP blocklisted");
                            continue;
                        }
                        if self.ban_list.is_banned(remote_addr.ip()) {
                            debug!(addr = %remote_addr, "Rejecting inbound connection: IP banned");
                            continue;
                        }
                        // Gate before spending any handshake work: refuse outright when the
                        // global connection limit (plus slack, as in libtorrent) is already
                        // reached, and bound the number of connections mid-handshake so a
                        // flood of half-open sockets cannot pile up tasks and buffers.
                        let max_global = self.settings.read().max_global_peers;
                        if self.metrics.global_peers_connected.load(Ordering::Relaxed)
                            >= max_global.saturating_add(CONNECTION_SLACK)
                        {
                            debug!(addr = %remote_addr, "Rejecting inbound connection: global connection limit reached");
                            continue;
                        }
                        let Ok(handshake_slot) =
                            self.pending_handshakes.clone().try_acquire_owned()
                        else {
                            debug!(addr = %remote_addr, "Rejecting inbound connection: too many pending handshakes");
                            continue;
                        };
                        let engine = self.clone();
                        tokio::spawn(async move {
                            let _handshake_slot = handshake_slot;
                            let enc_mode = engine.settings.read().encryption_mode();
                            let req2_index = engine.mse_req2_index.clone();
                            let _ = accept_router_indexed(
                                socket,
                                remote_addr,
                                engine.peer_id,
                                move |req2| req2_index.get(req2).map(|h| *h),
                                |hash| {
                                    let tx = engine.get_or_wake_torrent(&hash)?;
                                    let is_private = engine
                                        .torrents
                                        .get(&hash)
                                        .map(|h| h.is_private())
                                        .unwrap_or(false);
                                    Some((tx, is_private))
                                },
                                enc_mode,
                            )
                            .await;
                        });
                    }
                    Err(e) => {
                        warn!("Error accepting inbound peer connection: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        Ok(handle)
    }

    /// Returns the live DHT routing table size in O(1) without messaging the DHT actor.
    pub fn dht_node_count_fast(&self) -> usize {
        self.dht
            .read()
            .as_ref()
            .map(|h| h.node_count())
            .unwrap_or(0)
    }

    /// Returns the live DHT routing table size (0 if DHT isn't running), for metrics.
    pub async fn dht_node_count(&self) -> usize {
        self.dht_node_count_fast()
    }

    /// Returns the number of candidate peers queued to be dialed for this swarm.
    pub fn candidate_peers_count(&self, info_hash: &[u8; 20]) -> usize {
        self.announce_scheduler.candidate_peers_count(info_hash)
    }

    /// Returns the number of active dials currently in flight for this swarm.
    pub fn active_dials_count(&self, info_hash: &[u8; 20]) -> usize {
        self.announce_scheduler.active_dials_count(info_hash)
    }

    /// Returns comprehensive discovery metrics and flags for this swarm.
    pub fn swarm_discovery_stats(&self, info_hash: &[u8; 20]) -> SwarmDiscoveryStats {
        let (candidate_peers, active_dials, from_tracker, from_dht, from_pex, from_lsd) =
            self.announce_scheduler.discovery_breakdown(info_hash);

        let (dht_enabled, pex_enabled, lsd_enabled) = {
            let s = self.settings.read();
            (s.dht_enabled, s.pex_enabled, s.lsd_enabled)
        };

        if let Some(handle) = self.get_torrent(info_hash) {
            let pex_peers = handle
                .live_peers
                .read()
                .iter()
                .filter(|p| p.supports_pex || p.flags.contains('X'))
                .count();
            let webseeds: Vec<String> = handle
                .info
                .web_seeds
                .iter()
                .map(|u| u.to_string())
                .collect();
            let webseeds_count = webseeds.len();
            SwarmDiscoveryStats {
                candidate_peers,
                active_dials,
                dht_enabled,
                dht_allowed: handle.allows_dht(),
                pex_enabled,
                pex_allowed: handle.allows_pex(),
                pex_peers,
                lsd_enabled,
                lsd_allowed: handle.allows_lsd(),
                is_private: handle.is_private(),
                webseeds_count,
                webseeds,
                discovered_from_tracker: from_tracker,
                discovered_from_dht: from_dht,
                discovered_from_pex: from_pex,
                discovered_from_lsd: from_lsd,
            }
        } else {
            SwarmDiscoveryStats {
                candidate_peers,
                active_dials,
                dht_enabled,
                pex_enabled,
                lsd_enabled,
                discovered_from_tracker: from_tracker,
                discovered_from_dht: from_dht,
                discovered_from_pex: from_pex,
                discovered_from_lsd: from_lsd,
                ..Default::default()
            }
        }
    }

    /// Starts the BEP 5 Kademlia DHT: binds a UDP node, resolves the standard public
    /// bootstrap routers, then periodically (every `DHT_CRAWL_INTERVAL`) walks the
    /// network for peers on every registered non-private swarm and feeds discovered
    /// addresses into the same candidate pool trackers/LSD/PEX use. Also announces our
    /// own presence to the closest nodes found during each crawl, so other DHT clients
    /// can discover us. Best-effort throughout: a crawl or announce failure for one
    /// swarm is logged and skipped, never fatal to the loop or the daemon.
    pub async fn start_dht(self: Arc<Self>, bind_addr: SocketAddr) -> std::io::Result<SocketAddr> {
        const DHT_CRAWL_INTERVAL: Duration = Duration::from_secs(180);
        const BOOTSTRAP_HOSTS: &[&str] = &[
            "router.bittorrent.com:6881",
            "dht.transmissionbt.com:6881",
            "router.utorrent.com:6881",
        ];

        // Resume from the saved state if there is one: same node id, and the nodes we knew.
        let saved = match self.dht_state_path.as_ref() {
            Some(p) => tokio::fs::read(p)
                .await
                .ok()
                .and_then(|b| synapse_dht::DhtState::decode(&b)),
            None => None,
        };
        let our_id: [u8; 20] = saved
            .as_ref()
            .map(|s| s.node_id)
            .unwrap_or_else(rand::random);
        // Prefer a dual-stack node (BEP 32): an IPv4 socket on `bind_addr` plus an IPv6-only
        // socket on the same port. If IPv6 is unavailable (no v6 stack, container without
        // it), fall back to IPv4 only rather than failing to start DHT at all.
        // If the peer listener already set aside the DHT half of a shared UDP port, use it;
        // otherwise bind our own socket.
        let (shared, port_already_mapped) = {
            let mut slot = self.dht_transport.lock();
            match slot.take() {
                Some((port, t)) if port == bind_addr.port() => (Some(t), true),
                other => {
                    *slot = other;
                    (None, false)
                }
            }
        };
        let (handle, local_addr) = match bind_addr {
            SocketAddr::V4(v4) => {
                let bind_v6 = SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), v4.port());
                let v4_transport = match shared {
                    Some(t) => t,
                    None => synapse_wire::UdpTransport::Plain(
                        tokio::net::UdpSocket::bind(bind_addr).await?,
                    ),
                };
                let local_v4 = v4_transport.local_addr()?;
                let v6_transport = synapse_dht::bind_udp_v6_only(bind_v6)
                    .ok()
                    .map(synapse_wire::UdpTransport::Plain);
                match v6_transport.as_ref().map(|t| t.local_addr()) {
                    Some(Ok(local_v6)) => {
                        info!("DHT dual-stack: IPv4 on {local_v4}, IPv6 on {local_v6}")
                    }
                    _ => debug!("DHT IPv6 socket unavailable; running IPv4-only"),
                }
                let dht_options = synapse_dht::DhtOptions {
                    read_only: self.settings.read().dht_read_only,
                };
                let handle = synapse_dht::spawn_with_transports(
                    our_id,
                    Some(v4_transport),
                    v6_transport,
                    dht_options,
                );
                (handle, local_v4)
            }
            SocketAddr::V6(_) => {
                let dht_options = synapse_dht::DhtOptions {
                    read_only: self.settings.read().dht_read_only,
                };
                synapse_dht::spawn_with_options(our_id, bind_addr, dht_options).await?
            }
        };
        *self.dht.write() = Some(handle.clone());
        // A shared port was already mapped for uTP; only map a DHT-only port separately.
        if !port_already_mapped {
            self.nat_manager.write().request_mapping(
                local_addr.port(),
                crate::nat::PortProtocol::Udp,
                "Synapse BitTorrent DHT UDP",
            );
            self.clone()
                .start_nat_mapping(local_addr.port(), crate::nat::PortProtocol::Udp);
        }
        info!(
            "DHT node active on {} (id {})",
            local_addr,
            hex::encode(our_id)
        );

        // Bootstrap from the nodes we knew last time first, then the public routers. IPv4 nodes
        // seed the iterative lookups; IPv6 ones are pinged so they enter the IPv6 routing table
        // (a reply from a node is what adds it).
        let mut bootstrap_nodes: Vec<std::net::SocketAddrV4> = Vec::new();
        let mut bootstrap_v6: Vec<std::net::SocketAddrV6> = Vec::new();
        if let Some(ref state) = saved {
            info!("DHT: resuming with {} saved nodes", state.nodes.len());
            for addr in &state.nodes {
                match addr {
                    SocketAddr::V4(v4) => bootstrap_nodes.push(*v4),
                    SocketAddr::V6(v6) => bootstrap_v6.push(*v6),
                }
            }
        }
        for host in BOOTSTRAP_HOSTS {
            if let Ok(addrs) = tokio::net::lookup_host(host).await {
                for addr in addrs {
                    match addr {
                        SocketAddr::V4(v4) => bootstrap_nodes.push(v4),
                        SocketAddr::V6(v6) => bootstrap_v6.push(v6),
                    }
                }
            }
        }
        if bootstrap_nodes.is_empty() && bootstrap_v6.is_empty() {
            warn!("DHT: could not resolve any bootstrap routers (no network access?); routing table will only grow from inbound traffic");
        }
        for v6 in bootstrap_v6.into_iter().take(16) {
            let handle = handle.clone();
            tokio::spawn(async move {
                let _ = handle.ping(v6).await;
            });
        }

        let engine = self;
        tokio::spawn(async move {
            let mut sem_cap = engine.settings.read().max_concurrent_dht_announces.max(1);
            let semaphore = Arc::new(tokio::sync::Semaphore::new(sem_cap));
            let active_dht = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let done_notify = engine.dht_concurrency_notify.clone();

            struct DhtCrawlGuard {
                _permit: tokio::sync::OwnedSemaphorePermit,
                active: Arc<std::sync::atomic::AtomicUsize>,
                notify: Arc<tokio::sync::Notify>,
            }
            impl Drop for DhtCrawlGuard {
                fn drop(&mut self) {
                    self.active.fetch_sub(1, Ordering::AcqRel);
                    self.notify.notify_waiters();
                }
            }

            let mut ticker = tokio::time::interval(DHT_CRAWL_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if !engine.settings.read().dht_enabled {
                    continue;
                }
                engine.save_dht_state(&handle).await;

                let peer_port = engine.public_listen_port();
                let swarms: Vec<([u8; 20], bool)> = engine
                    .torrents
                    .iter()
                    .filter(|r| r.value().allows_dht())
                    .map(|r| {
                        let downloading = !matches!(
                            r.value().stats.read().state,
                            SwarmState::Stopped | SwarmState::Queued
                        );
                        (*r.key(), downloading)
                    })
                    .filter(|(_, active)| *active)
                    .collect();

                for (info_hash, _) in swarms {
                    let permit = loop {
                        let notified = done_notify.notified();
                        tokio::pin!(notified);
                        notified.as_mut().enable();
                        let limit = engine.settings.read().max_concurrent_dht_announces.max(1);
                        if limit > sem_cap {
                            semaphore.add_permits(limit - sem_cap);
                            sem_cap = limit;
                        }
                        if active_dht.load(Ordering::Acquire) < limit {
                            if let Ok(permit) = semaphore.clone().try_acquire_owned() {
                                break permit;
                            }
                        }
                        notified.await;
                    };
                    active_dht.fetch_add(1, Ordering::AcqRel);
                    let guard = DhtCrawlGuard {
                        _permit: permit,
                        active: active_dht.clone(),
                        notify: done_notify.clone(),
                    };
                    let handle = handle.clone();
                    let engine = engine.clone();
                    let bootstrap_nodes = bootstrap_nodes.clone();
                    tokio::spawn(async move {
                        let _guard = guard;
                        match handle
                            .iterative_get_peers(info_hash, &bootstrap_nodes)
                            .await
                        {
                            Ok(result) => {
                                if !result.peers.is_empty() {
                                    let addrs = result.peers.into_iter().map(SocketAddr::V4);
                                    engine.announce_scheduler.add_candidate_peers_with_source(
                                        &info_hash,
                                        addrs,
                                        crate::announcer::PeerDiscoverySource::Dht,
                                    );
                                }
                                if !result.peers6.is_empty() {
                                    let addrs = result.peers6.into_iter().map(SocketAddr::V6);
                                    engine.announce_scheduler.add_candidate_peers_with_source(
                                        &info_hash,
                                        addrs,
                                        crate::announcer::PeerDiscoverySource::Dht,
                                    );
                                }
                                for (node, token) in result.closest_nodes {
                                    let _ = handle
                                        .announce_peer(node.addr, info_hash, peer_port, token)
                                        .await;
                                }
                                for (node6, token) in result.closest_nodes6 {
                                    let _ = handle
                                        .announce_peer(node6.addr, info_hash, peer_port, token)
                                        .await;
                                }
                            }
                            Err(e) => {
                                debug!(hash = %hex::encode(info_hash), "DHT get_peers crawl failed: {e}");
                            }
                        }
                    });
                }
            }
        });

        Ok(local_addr)
    }

    /// Starts BEP 14/22 Local Peer Discovery: binds the LSD multicast group, periodically
    /// announces every registered public torrent, and ingests announcements from other
    /// local clients, feeding discovered peers into the same candidate pool trackers use
    /// (`AnnounceScheduler::add_candidate_peers`). Gated on `dynamic_settings.lsd_enabled`
    /// at each tick, checked live so a runtime settings change takes effect without a
    /// restart. Requires `start_listener` to have already run so the real peer port is
    /// known -- the announced port would otherwise be wrong.
    pub async fn start_lsd(self: Arc<Self>) -> Result<tokio::task::JoinHandle<()>, std::io::Error> {
        let lsd_v4: SocketAddr = synapse_wire::LSD_MULTICAST_IPV4
            .parse()
            .expect("LSD_MULTICAST_IPV4 constant must be a valid socket address");
        let lsd_v6: SocketAddr = synapse_wire::LSD_MULTICAST_IPV6
            .parse()
            .expect("LSD_MULTICAST_IPV6 constant must be a valid socket address");

        let peer_port = *self.listen_port.read();
        self.lsd_manager.lock().set_listen_port(peer_port);

        // IPv4 group (BEP 14) is required; the IPv6 group (BEP 14/22) is best effort, as many
        // hosts and containers have no IPv6.
        let socket_v4 = Arc::new(bind_lsd_socket(lsd_v4)?);
        info!("LSD (Local Peer Discovery) active on {}", lsd_v4);
        let socket_v6 = match bind_lsd_socket(lsd_v6) {
            Ok(s) => {
                info!("LSD (Local Peer Discovery) active on {}", lsd_v6);
                Some(Arc::new(s))
            }
            Err(e) => {
                debug!("LSD IPv6 group unavailable: {e}");
                None
            }
        };

        let handle = tokio::spawn(async move {
            // BEP 14 recommends announcing about every 5 minutes.
            let mut announce_ticker = tokio::time::interval(Duration::from_secs(300));
            announce_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut buf_v4 = [0u8; 2048];
            let mut buf_v6 = [0u8; 2048];

            loop {
                let from_v4 = socket_v4.recv_from(&mut buf_v4);
                let from_v6 = async {
                    match &socket_v6 {
                        Some(s) => s.recv_from(&mut buf_v6).await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    _ = announce_ticker.tick() => {
                        if !self.settings.read().lsd_enabled {
                            continue;
                        }
                        let mut sends: Vec<(Arc<tokio::net::UdpSocket>, SocketAddr, String)> =
                            Vec::new();
                        for packet in self
                            .lsd_manager
                            .lock()
                            .build_announce_packets_for_host(synapse_wire::LSD_MULTICAST_IPV4)
                        {
                            sends.push((socket_v4.clone(), lsd_v4, packet));
                        }
                        if let Some(ref s6) = socket_v6 {
                            for v6_packet in self
                                .lsd_manager
                                .lock()
                                .build_announce_packets_for_host(synapse_wire::LSD_MULTICAST_IPV6)
                            {
                                sends.push((s6.clone(), lsd_v6, v6_packet));
                            }
                        }
                        let limit = self.settings.read().max_concurrent_lsd_announces.max(1);
                        let mut in_flight = tokio::task::JoinSet::new();
                        for (sock, dest, pkt) in sends {
                            while in_flight.len() >= limit {
                                let _ = in_flight.join_next().await;
                            }
                            in_flight.spawn(async move {
                                if let Err(e) = sock.send_to(pkt.as_bytes(), dest).await {
                                    debug!("LSD announce send failed to {dest}: {e}");
                                }
                            });
                        }
                        while in_flight.join_next().await.is_some() {}
                    }
                    recv = from_v4 => {
                        match recv {
                            Ok((n, from)) => self.ingest_lsd(&buf_v4[..n], from),
                            Err(e) => warn!("LSD receive error: {e}"),
                        }
                    }
                    recv = from_v6 => {
                        match recv {
                            Ok((n, from)) => self.ingest_lsd(&buf_v6[..n], from),
                            Err(e) => warn!("LSD IPv6 receive error: {e}"),
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    /// Starts BEP 26 Zeroconf discovery on the mDNS group: announces the public torrents
    /// (and asks about them) every few minutes, answers questions about them, and queues the
    /// peers others announce into the candidate pool. Gated live on `zeroconf_enabled`.
    /// `group` is the multicast address (`synapse_wire::zeroconf::MDNS_IPV4`); tests point it
    /// at a unicast socket instead.
    pub async fn start_zeroconf(
        self: Arc<Self>,
        group: SocketAddr,
    ) -> Result<tokio::task::JoinHandle<()>, std::io::Error> {
        self.zeroconf_manager
            .lock()
            .set_listen_port(*self.listen_port.read());
        let socket = if group.ip().is_multicast() {
            bind_lsd_socket(group)?
        } else {
            tokio::net::UdpSocket::bind(group).await?
        };
        info!("Zeroconf (BEP 26) peer discovery active on {group}");
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(300));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut buf = [0u8; 2048];
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if !self.settings.read().zeroconf_enabled {
                            continue;
                        }
                        let addrs = self.zeroconf_addresses();
                        let (queries, announcements) = {
                            let mut m = self.zeroconf_manager.lock();
                            m.set_listen_port(*self.listen_port.read());
                            (m.queries(), m.announcements(&addrs))
                        };
                        for q in queries {
                            let _ = socket.send_to(&q, self.zeroconf_target(group)).await;
                        }
                        for a in announcements {
                            let _ = socket.send_to(&a, self.zeroconf_target(group)).await;
                        }
                    }
                    recv = socket.recv_from(&mut buf) => {
                        let Ok((n, from)) = recv else { continue };
                        if !self.settings.read().zeroconf_enabled {
                            continue;
                        }
                        let addrs = self.zeroconf_addresses();
                        let handled = self
                            .zeroconf_manager
                            .lock()
                            .handle_datagram(from, &buf[..n], &addrs);
                        if let Some(reply) = handled.reply {
                            let _ = socket.send_to(&reply, self.zeroconf_target(group)).await;
                        }
                        for (hash, addr) in handled.peers {
                            self.announce_scheduler.add_candidate_peers_with_source(
                                &hash,
                                [addr],
                                crate::announcer::PeerDiscoverySource::Lsd,
                            );
                        }
                    }
                }
            }
        });
        Ok(handle)
    }

    fn zeroconf_addresses(&self) -> Vec<std::net::IpAddr> {
        self.zeroconf_addr_override
            .read()
            .clone()
            .unwrap_or_else(local_addresses)
    }

    /// Test hook: the addresses zeroconf announces for this host.
    pub fn set_zeroconf_addresses(&self, addrs: Vec<std::net::IpAddr>) {
        *self.zeroconf_addr_override.write() = Some(addrs);
    }

    /// Where zeroconf messages are sent: the multicast group, or the peer socket a test set.
    fn zeroconf_target(&self, group: SocketAddr) -> SocketAddr {
        self.zeroconf_peer_override.read().unwrap_or(group)
    }

    /// Test hook: send zeroconf messages to `target` (a unicast socket) instead of the group.
    pub fn set_zeroconf_target(&self, target: SocketAddr) {
        *self.zeroconf_peer_override.write() = Some(target);
    }

    /// Feeds one received LSD datagram to the manager and queues any peers it yields.
    fn ingest_lsd(&self, datagram: &[u8], from: SocketAddr) {
        if !self.settings.read().lsd_enabled {
            return;
        }
        let Ok(text) = std::str::from_utf8(datagram) else {
            return;
        };
        let discovered = self.lsd_manager.lock().ingest_packet(from.ip(), text);
        for peer in discovered {
            self.announce_scheduler.add_candidate_peers_with_source(
                &peer.info_hash,
                [peer.addr],
                crate::announcer::PeerDiscoverySource::Lsd,
            );
        }
    }
}

impl SwarmEngine {
    /// The running DHT node's id, if a node is running.
    pub fn dht_node_id(&self) -> Option<[u8; 20]> {
        self.dht.read().as_ref().map(|h| h.our_id())
    }

    /// Saves the DHT state now (also done periodically). No-op without a state path or node.
    pub async fn persist_dht_state(&self) {
        let handle = self.dht.read().clone();
        if let Some(h) = handle {
            self.save_dht_state(&h).await;
        }
    }

    /// Writes the DHT id and good nodes to the configured state file (atomically, via a
    /// temporary file). Failures are logged and otherwise ignored: persistence is an
    /// optimisation, never a reason to disturb the running node.
    async fn save_dht_state(&self, handle: &synapse_dht::DhtHandle) {
        let Some(path) = self.dht_state_path.clone() else {
            return;
        };
        let Ok((node_id, nodes)) = handle.state().await else {
            return;
        };
        if nodes.is_empty() {
            return; // nothing worth keeping, and do not overwrite a good file with an empty one
        }
        let bytes = synapse_dht::DhtState { node_id, nodes }.encode();
        let tmp = path.with_extension("tmp");
        let write_path = path.clone();
        let result = tokio::task::spawn_blocking(move || {
            std::fs::write(&tmp, &bytes).and_then(|_| std::fs::rename(&tmp, &write_path))
        })
        .await
        .map_err(std::io::Error::other)
        .and_then(|r| r);
        if let Err(e) = result {
            debug!("DHT: could not save state to {}: {e}", path.display());
        }
    }
}

/// This host's outward-facing addresses, learned by asking the OS which local address it would
/// use to reach a public one (nothing is sent).
fn local_addresses() -> Vec<std::net::IpAddr> {
    let mut out = Vec::new();
    for (bind, probe) in [("0.0.0.0:0", "192.0.2.1:9"), ("[::]:0", "[2001:db8::1]:9")] {
        if let Ok(sock) = std::net::UdpSocket::bind(bind) {
            if sock.connect(probe).is_ok() {
                if let Ok(addr) = sock.local_addr() {
                    if !addr.ip().is_unspecified() {
                        out.push(addr.ip());
                    }
                }
            }
        }
    }
    out
}

/// Binds a UDP socket on the LSD port and joins the multicast `group`. The port is shared
/// (`SO_REUSEADDR`, and `SO_REUSEPORT` where available) because other BitTorrent clients on the
/// same host use it too; IPv6 sockets are IPv6-only.
fn bind_lsd_socket(group: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(group), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(
        unix,
        not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))
    ))]
    socket.set_reuse_port(true)?;
    let bind: SocketAddr = match group {
        SocketAddr::V4(_) => SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), group.port()),
        SocketAddr::V6(_) => {
            socket.set_only_v6(true)?;
            SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), group.port())
        }
    };
    socket.set_nonblocking(true)?;
    socket.bind(&bind.into())?;
    match group {
        SocketAddr::V4(g) => socket.join_multicast_v4(g.ip(), &std::net::Ipv4Addr::UNSPECIFIED)?,
        SocketAddr::V6(g) => socket.join_multicast_v6(g.ip(), 0)?,
    }
    tokio::net::UdpSocket::from_std(socket.into())
}

/// Binds a TCP listener. An IPv6 wildcard listener is made IPv6-only (`IPV6_V6ONLY`) so it can
/// share a port with the IPv4 listener; on Linux a plain `[::]` listener also claims the IPv4
/// side and the second bind would otherwise fail with `EADDRINUSE`.
fn bind_tcp_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

#[cfg(test)]
mod resume_verification_tests {
    use super::*;
    use std::collections::BTreeMap;
    use synapse_bencode::BEncode;

    /// Two files (a: 40 000 B, b: 25 000 B), 16 384-byte pieces -> 4 pieces; piece 2 spans both files.
    fn two_file_info() -> Info {
        let file = |name: &str, len: i64| {
            BEncode::Dict(BTreeMap::from([
                (b"length".to_vec(), BEncode::Int(len)),
                (
                    b"path".to_vec(),
                    BEncode::List(vec![BEncode::String(name.as_bytes().to_vec())]),
                ),
            ]))
        };
        let info = BEncode::Dict(BTreeMap::from([
            (b"name".to_vec(), BEncode::String(b"t".to_vec())),
            (b"piece length".to_vec(), BEncode::Int(16_384)),
            (b"pieces".to_vec(), BEncode::String(vec![0u8; 80])),
            (
                b"files".to_vec(),
                BEncode::List(vec![file("a", 40_000), file("b", 25_000)]),
            ),
        ]));
        Info::from_bencode(BEncode::Dict(BTreeMap::from([(b"info".to_vec(), info)]))).unwrap()
    }

    fn all_set(n: u32) -> Bitfield {
        let mut bf = Bitfield::new(n as usize);
        for i in 0..n {
            bf.set(i as usize);
        }
        bf
    }

    #[test]
    fn intact_files_keep_every_piece() {
        let info = two_file_info();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("t")).unwrap();
        std::fs::write(dir.path().join("t/a"), vec![0u8; 40_000]).unwrap();
        std::fs::write(dir.path().join("t/b"), vec![0u8; 25_000]).unwrap();
        let mut bf = all_set(info.pieces());
        assert_eq!(verify_resume_bitfield(&info, dir.path(), &mut bf), 0);
        assert_eq!(bf.count_ones(), 4);
    }

    #[test]
    fn pieces_kept_in_the_part_file_survive_the_resume_check() {
        let info = two_file_info();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("t")).unwrap();
        std::fs::write(dir.path().join("t/a"), vec![0u8; 40_000]).unwrap();
        // File `b` was skipped: its bytes for pieces 2 (0..9152) and 3 (9152..25000) sit in the
        // part file, and `b` itself was never created.
        let mut pfm = crate::part_file::PartFileManager::new(dir.path().to_path_buf(), info.hash);
        pfm.set_file_priority(1, 0);
        pfm.resolve_write_location(1, 0, 9_152, dir.path().join("t/b"));
        pfm.resolve_write_location(1, 9_152, 15_848, dir.path().join("t/b"));
        let mut bf = all_set(info.pieces());
        assert_eq!(verify_resume_bitfield(&info, dir.path(), &mut bf), 0);
        assert_eq!(bf.count_ones(), 4);

        // Without the saved map (e.g. the map was lost) those pieces are dropped, not trusted.
        std::fs::remove_file(
            dir.path()
                .join(format!(".synapse_part_{}.map", hex::encode(info.hash))),
        )
        .unwrap();
        let mut bf = all_set(info.pieces());
        assert_eq!(verify_resume_bitfield(&info, dir.path(), &mut bf), 2);
    }

    #[test]
    fn missing_or_truncated_files_drop_exactly_the_pieces_they_back() {
        let info = two_file_info();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("t")).unwrap();
        // `a` truncated to 20 000 B: piece 0 (0..16384) fits, piece 1 (16384..32768) does not,
        // piece 2 (32768..49152) needs a[..40000] and b[..9152] so it is gone too. `b` missing.
        std::fs::write(dir.path().join("t/a"), vec![0u8; 20_000]).unwrap();
        let mut bf = all_set(info.pieces());
        let dropped = verify_resume_bitfield(&info, dir.path(), &mut bf);
        assert_eq!(dropped, 3);
        assert!(bf.has(0));
        assert!(!bf.has(1) && !bf.has(2) && !bf.has(3));
    }

    #[test]
    fn a_wiped_download_directory_drops_everything_and_unset_pieces_stay_unset() {
        let info = two_file_info();
        let dir = tempfile::tempdir().unwrap();
        let mut bf = Bitfield::new(info.pieces() as usize);
        bf.set(1);
        assert_eq!(verify_resume_bitfield(&info, dir.path(), &mut bf), 1);
        assert_eq!(bf.count_ones(), 0);
    }
}

#[cfg(test)]
mod queue_order_tests {
    use super::*;
    use std::collections::HashSet;

    fn h(n: u8) -> [u8; 20] {
        [n; 20]
    }

    fn order(list: &[u8]) -> Vec<[u8; 20]> {
        list.iter().map(|n| h(*n)).collect()
    }

    fn sel(list: &[u8]) -> HashSet<[u8; 20]> {
        list.iter().map(|n| h(*n)).collect()
    }

    #[test]
    fn top_and_bottom_move_the_selection_as_a_group_in_its_own_order() {
        let mut o = order(&[1, 2, 3, 4, 5]);
        assert!(apply_queue_move(&mut o, &sel(&[4, 2]), QueueMove::Top));
        assert_eq!(o, order(&[2, 4, 1, 3, 5]));
        assert!(apply_queue_move(&mut o, &sel(&[2, 4]), QueueMove::Bottom));
        assert_eq!(o, order(&[1, 3, 5, 2, 4]));
    }

    #[test]
    fn up_and_down_step_one_place_and_stop_at_the_ends() {
        let mut o = order(&[1, 2, 3, 4]);
        assert!(apply_queue_move(&mut o, &sel(&[3]), QueueMove::Up));
        assert_eq!(o, order(&[1, 3, 2, 4]));
        assert!(apply_queue_move(&mut o, &sel(&[3]), QueueMove::Up));
        assert_eq!(o, order(&[3, 1, 2, 4]));
        assert!(
            !apply_queue_move(&mut o, &sel(&[3]), QueueMove::Up),
            "already first"
        );

        assert!(
            !apply_queue_move(&mut o, &sel(&[4]), QueueMove::Down),
            "already last"
        );
        assert!(apply_queue_move(&mut o, &sel(&[1]), QueueMove::Down));
        assert_eq!(o, order(&[3, 2, 1, 4]));
    }

    #[test]
    fn a_selected_block_moves_together_and_does_not_leapfrog_itself() {
        let mut o = order(&[1, 2, 3, 4, 5]);
        assert!(apply_queue_move(&mut o, &sel(&[3, 4]), QueueMove::Up));
        assert_eq!(o, order(&[1, 3, 4, 2, 5]));
        assert!(apply_queue_move(&mut o, &sel(&[3, 4]), QueueMove::Down));
        assert_eq!(o, order(&[1, 2, 3, 4, 5]));
    }

    #[test]
    fn selecting_nothing_changes_nothing() {
        let mut o = order(&[1, 2, 3]);
        for d in [
            QueueMove::Top,
            QueueMove::Up,
            QueueMove::Down,
            QueueMove::Bottom,
        ] {
            assert!(!apply_queue_move(&mut o, &sel(&[]), d));
        }
        assert_eq!(o, order(&[1, 2, 3]));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_set_file_priority_and_swarm_mutations_do_not_deadlock() {
        use std::collections::BTreeMap;
        use synapse_bencode::BEncode;

        let make_info = |name: Vec<u8>, len: i64| -> Arc<Info> {
            let mut fdict = BTreeMap::new();
            fdict.insert(b"length".to_vec(), BEncode::Int(len));
            fdict.insert(
                b"path".to_vec(),
                BEncode::List(vec![BEncode::String(b"file.bin".to_vec())]),
            );
            let mut id = BTreeMap::new();
            id.insert(b"name".to_vec(), BEncode::String(name));
            id.insert(b"piece length".to_vec(), BEncode::Int(16384));
            id.insert(
                b"pieces".to_vec(),
                BEncode::String(vec![0u8; 20 * ((len as usize) / 16384)]),
            );
            id.insert(b"files".to_vec(), BEncode::List(vec![BEncode::Dict(fdict)]));
            let mut top = BTreeMap::new();
            top.insert(b"info".to_vec(), BEncode::Dict(id));
            Arc::new(Info::from_bencode(BEncode::Dict(top)).unwrap())
        };

        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::new_blocking(64 * 1024 * 1024));
        let engine = Arc::new(SwarmEngine::new(disk, [0x42; 20]));
        let info = make_info(b"primary".to_vec(), 32768);
        let hash = info.hash;
        engine.add_torrent_with_resume(info, dir.path().to_path_buf(), None, None);

        let e1 = engine.clone();
        let h1 = tokio::spawn(async move {
            for i in 0..200u32 {
                e1.set_file_priority(&hash, 0, if i % 2 == 0 { 0 } else { 4 });
            }
        });

        let e2 = engine.clone();
        let dir2 = dir.path().to_path_buf();
        let h2 = tokio::spawn(async move {
            for idx in 0..50u8 {
                let inf = make_info(format!("t_{idx}").into_bytes(), 16384);
                let h = inf.hash;
                e2.add_torrent_with_resume(inf, dir2.clone(), None, None);
                e2.remove_torrent(&h);
            }
        });

        tokio::time::timeout(Duration::from_secs(10), async move {
            h1.await.unwrap();
            h2.await.unwrap();
        })
        .await
        .expect("concurrent set_file_priority + shard mutations deadlocked");
    }

    #[tokio::test]
    async fn queued_torrent_isolated_and_magnet_plus_queue_position_survive_restore() {
        use std::collections::BTreeMap;
        use synapse_bencode::BEncode;

        let make_info = |name: &str, len: i64| -> Arc<Info> {
            let mut fdict = BTreeMap::new();
            fdict.insert(b"length".to_vec(), BEncode::Int(len));
            fdict.insert(
                b"path".to_vec(),
                BEncode::List(vec![BEncode::String(b"file.bin".to_vec())]),
            );
            let mut id = BTreeMap::new();
            id.insert(b"name".to_vec(), BEncode::String(name.as_bytes().to_vec()));
            id.insert(b"piece length".to_vec(), BEncode::Int(16384));
            id.insert(
                b"pieces".to_vec(),
                BEncode::String(vec![0u8; 20 * ((len as usize) / 16384)]),
            );
            id.insert(b"files".to_vec(), BEncode::List(vec![BEncode::Dict(fdict)]));
            let mut top = BTreeMap::new();
            top.insert(b"info".to_vec(), BEncode::Dict(id));
            Arc::new(Info::from_bencode(BEncode::Dict(top)).unwrap())
        };

        let dir = tempfile::tempdir().unwrap();
        let sess_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(crate::session::SessionStore::new(sess_dir.path()).unwrap());
        let disk = Arc::new(diskio::DiskEngine::new_blocking(64 * 1024 * 1024));
        let engine =
            Arc::new(SwarmEngine::new(disk.clone(), [0x44; 20]).with_session_store(store.clone()));
        {
            let mut qm = engine.queue_manager.write();
            let mut cfg = qm.config().clone();
            cfg.max_active_downloads = 1;
            qm.set_config(cfg);
        }

        let i1 = make_info("dl1", 16384);
        let h1 = i1.hash;
        engine.add_torrent(i1, dir.path().to_path_buf(), None);

        let i2 = make_info("dl2", 16384);
        let h2 = i2.hash;
        let handle2 = engine.add_torrent(i2, dir.path().to_path_buf(), None);
        assert_eq!(handle2.stats.read().state, SwarmState::Queued);
        assert!(engine.get_or_wake_torrent(&h2).is_none());

        let mag = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=unresolved";
        let m_handle = engine.add_magnet(mag, dir.path().to_path_buf()).unwrap();
        let mh = m_handle.info.hash;

        engine.move_in_queue(&[h2], QueueMove::Top);
        engine.flush_session().await;

        let engine2 = Arc::new(SwarmEngine::new(disk, [0x45; 20]).with_session_store(store));
        let restored = engine2.restore_session().unwrap();
        assert_eq!(restored, 3);
        assert!(engine2.get_torrent(&mh).is_some());
        let pos = engine2.queue_positions();
        assert!(pos[&h2] < pos[&h1]);
    }

    #[tokio::test]
    async fn completing_download_triggers_tracker_event_completed() {
        use sha1::{Digest, Sha1};
        use std::collections::BTreeMap;
        use synapse_bencode::BEncode;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let events_seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let events_bg = events_seen.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tracker_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let events_inner = events_bg.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    if let Ok(n) = sock.read(&mut buf).await {
                        let req = String::from_utf8_lossy(&buf[..n]);
                        if let Some(line) = req.lines().next() {
                            events_inner.lock().push(line.to_string());
                        }
                        let body = b"d8:intervali600e5:peers0:e";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.write_all(body).await;
                    }
                });
            }
        });

        let payload = vec![0xABu8; 16_384];
        let hash = Sha1::digest(&payload).to_vec();
        let announce_url = format!("http://{tracker_addr}/announce");
        let mut info_dict = BTreeMap::new();
        info_dict.insert(b"name".to_vec(), BEncode::String(b"done-evt.bin".to_vec()));
        info_dict.insert(b"piece length".to_vec(), BEncode::Int(16_384));
        info_dict.insert(b"pieces".to_vec(), BEncode::String(hash));
        info_dict.insert(b"length".to_vec(), BEncode::Int(16_384));
        info_dict.insert(b"private".to_vec(), BEncode::Int(1));
        let mut top = BTreeMap::new();
        top.insert(
            b"announce".to_vec(),
            BEncode::String(announce_url.into_bytes()),
        );
        top.insert(b"info".to_vec(), BEncode::Dict(info_dict));
        let info = Arc::new(Info::from_bencode(BEncode::Dict(top)).unwrap());

        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::new_blocking(1024 * 1024));
        let engine = SwarmEngine::new(disk, [0x46; 20]);
        let handle = engine.add_torrent(info.clone(), dir.path().to_path_buf(), None);
        let peer_tx = handle.peer_event_tx().unwrap();

        let (out_tx, mut out_rx) = mpsc::channel(16);
        let peer_handle =
            crate::peer::PeerHandle::new_for_test(1, "127.0.0.1:6891".parse().unwrap(), out_tx);
        let pinfo = crate::peer::PeerInfo {
            info_hash: info.hash,
            peer_id: [0x77; 20],
            addr: "127.0.0.1:6891".parse().unwrap(),
            local_addr: None,
            is_outbound: true,
            is_encrypted: false,
            reserved: [0, 0, 0, 0, 0, 0x10, 0, 0x04],
            is_utp: false,
        };
        peer_tx
            .send(PeerEvent::Connected(peer_handle, pinfo))
            .await
            .unwrap();
        peer_tx
            .send(PeerEvent::Message(1, synapse_wire::Message::HaveAll))
            .await
            .unwrap();
        peer_tx
            .send(PeerEvent::Message(1, synapse_wire::Message::Unchoke))
            .await
            .unwrap();

        // Wait until the actor requests block 0, then deliver it.
        tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(msg) = out_rx.recv().await {
                if matches!(
                    msg,
                    synapse_wire::Message::Request {
                        index: 0,
                        begin: 0,
                        ..
                    }
                ) {
                    break;
                }
            }
        })
        .await
        .expect("torrent actor requested block 0");

        peer_tx
            .send(PeerEvent::Message(
                1,
                synapse_wire::Message::Piece {
                    index: 0,
                    begin: 0,
                    data: bytes::Bytes::from(payload),
                },
            ))
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if events_seen
                    .lock()
                    .iter()
                    .any(|line| line.contains("event=completed"))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("expected event=completed tracker announce on download completion");
    }

    #[tokio::test]
    async fn partial_global_and_per_torrent_rate_limits_preserve_omitted_direction() {
        let disk = Arc::new(diskio::DiskEngine::new_blocking(1024 * 1024));
        let engine = SwarmEngine::new(disk, [0x47; 20]);

        engine.set_rate_limits(200_000, 100_000);
        engine.update_global_rate_limits(Some(50_000), None);
        {
            let settings = engine.settings();
            let s = settings.read();
            assert_eq!(s.download_limit_bytes, 50_000);
            assert!(s.download_limit_enabled);
            assert_eq!(s.upload_limit_bytes, 100_000);
            assert!(s.upload_limit_enabled);
        }

        let mut info_dict = std::collections::BTreeMap::new();
        info_dict.insert(
            b"name".to_vec(),
            synapse_bencode::BEncode::String(b"rate-limit-test.bin".to_vec()),
        );
        info_dict.insert(
            b"piece length".to_vec(),
            synapse_bencode::BEncode::Int(16_384),
        );
        info_dict.insert(
            b"pieces".to_vec(),
            synapse_bencode::BEncode::String(vec![0x11; 20]),
        );
        info_dict.insert(b"length".to_vec(), synapse_bencode::BEncode::Int(16_384));
        let mut top = std::collections::BTreeMap::new();
        top.insert(b"info".to_vec(), synapse_bencode::BEncode::Dict(info_dict));
        let info = Arc::new(Info::from_bencode(synapse_bencode::BEncode::Dict(top)).unwrap());
        let dir = tempfile::tempdir().unwrap();
        let handle = engine.add_torrent(info.clone(), dir.path().to_path_buf(), None);

        assert!(engine.set_torrent_rate_limits(&info.hash, Some(75_000), Some(25_000)));
        assert!(engine.set_torrent_rate_limits(&info.hash, Some(125_000), None));
        assert_eq!(handle.download_limit_bytes.load(Ordering::Relaxed), 125_000);
        assert_eq!(handle.upload_limit_bytes.load(Ordering::Relaxed), 25_000);
    }

    #[tokio::test]
    async fn per_torrent_rate_limits_survive_a_session_restart() {
        let mut info_dict = std::collections::BTreeMap::new();
        info_dict.insert(
            b"name".to_vec(),
            synapse_bencode::BEncode::String(b"rate-limit-resume-test.bin".to_vec()),
        );
        info_dict.insert(
            b"piece length".to_vec(),
            synapse_bencode::BEncode::Int(16_384),
        );
        info_dict.insert(
            b"pieces".to_vec(),
            synapse_bencode::BEncode::String(vec![0x22; 20]),
        );
        info_dict.insert(b"length".to_vec(), synapse_bencode::BEncode::Int(16_384));
        let mut top = std::collections::BTreeMap::new();
        top.insert(b"info".to_vec(), synapse_bencode::BEncode::Dict(info_dict));
        let info = Arc::new(Info::from_bencode(synapse_bencode::BEncode::Dict(top)).unwrap());

        let dir = tempfile::tempdir().unwrap();
        let sess_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(crate::session::SessionStore::new(sess_dir.path()).unwrap());
        let disk = Arc::new(diskio::DiskEngine::new_blocking(1024 * 1024));
        let engine = SwarmEngine::new(disk.clone(), [0x49; 20]).with_session_store(store.clone());

        engine.add_torrent(info.clone(), dir.path().to_path_buf(), None);
        assert!(engine.set_torrent_rate_limits(&info.hash, Some(75_000), Some(25_000)));
        engine.flush_session().await;

        let engine2 = SwarmEngine::new(disk, [0x4a; 20]).with_session_store(store);
        assert_eq!(engine2.restore_session().unwrap(), 1);
        let restored_handle = engine2.get_torrent(&info.hash).unwrap();
        assert_eq!(
            restored_handle.download_limit_bytes.load(Ordering::Relaxed),
            75_000,
            "a per-torrent download limit must survive a daemon restart"
        );
        assert_eq!(
            restored_handle.upload_limit_bytes.load(Ordering::Relaxed),
            25_000,
            "a per-torrent upload limit must survive a daemon restart"
        );
    }

    #[tokio::test]
    async fn paused_torrent_set_location_with_options_respects_move_flag_and_stays_cold() {
        use sha1::Digest;

        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let dir_c = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::new_blocking(1024 * 1024));
        let store = Arc::new(crate::session::SessionStore::new(dir_a.path()).unwrap());
        let engine = SwarmEngine::new(disk, [0x48; 20]).with_session_store(store.clone());

        let payload = vec![0x5Au8; 16_384];
        std::fs::write(dir_a.path().join("paused-move.bin"), &payload).unwrap();

        let hash: [u8; 20] = sha1::Sha1::digest(&payload).into();
        let mut info_dict = std::collections::BTreeMap::new();
        info_dict.insert(
            b"name".to_vec(),
            synapse_bencode::BEncode::String(b"paused-move.bin".to_vec()),
        );
        info_dict.insert(
            b"piece length".to_vec(),
            synapse_bencode::BEncode::Int(16_384),
        );
        info_dict.insert(
            b"pieces".to_vec(),
            synapse_bencode::BEncode::String(hash.to_vec()),
        );
        info_dict.insert(b"length".to_vec(), synapse_bencode::BEncode::Int(16_384));
        let mut top = std::collections::BTreeMap::new();
        top.insert(b"info".to_vec(), synapse_bencode::BEncode::Dict(info_dict));
        let info = Arc::new(Info::from_bencode(synapse_bencode::BEncode::Dict(top)).unwrap());

        let mut bf = synapse_picker::Bitfield::new(1);
        bf.set(0);
        let resume = SwarmResumeOptions {
            is_paused: true,
            ..Default::default()
        };
        let handle = engine.add_torrent_with_resume(
            info.clone(),
            dir_a.path().to_path_buf(),
            Some(&bf),
            Some(resume),
        );
        engine.transition_to_cold(&info.hash);
        engine.flush_session().await;

        assert_eq!(handle.stats.read().tier, SwarmTier::Cold);
        assert!(engine.set_location_with_options(
            &info.hash,
            &dir_b.path().to_string_lossy(),
            true
        ));
        assert_eq!(handle.stats.read().tier, SwarmTier::Cold);
        assert_eq!(
            handle.stats.read().download_dir,
            dir_b.path().to_string_lossy()
        );
        assert!(dir_b.path().join("paused-move.bin").exists());
        assert!(!dir_a.path().join("paused-move.bin").exists());
        assert_eq!(
            store
                .load_torrent(&hex::encode(info.hash))
                .unwrap()
                .unwrap()
                .download_dir,
            dir_b.path().to_string_lossy()
        );

        // move_existing_files = false updates metadata without touching files on disk.
        assert!(engine.set_location_with_options(
            &info.hash,
            &dir_c.path().to_string_lossy(),
            false
        ));
        assert_eq!(handle.stats.read().tier, SwarmTier::Cold);
        assert_eq!(
            handle.stats.read().download_dir,
            dir_c.path().to_string_lossy()
        );
        assert!(dir_b.path().join("paused-move.bin").exists());
        assert!(!dir_c.path().join("paused-move.bin").exists());
    }
}

#[cfg(test)]
mod batch1_scale_tests {
    use super::*;
    use std::collections::BTreeMap;
    use synapse_bencode::BEncode;

    fn make_multi_piece_info(name: &str, pieces: usize) -> Arc<Info> {
        let len = (pieces as i64) * 16_384;
        let mut fdict = BTreeMap::new();
        fdict.insert(b"length".to_vec(), BEncode::Int(len));
        fdict.insert(
            b"path".to_vec(),
            BEncode::List(vec![BEncode::String(format!("{name}.bin").into_bytes())]),
        );
        let mut id = BTreeMap::new();
        id.insert(b"name".to_vec(), BEncode::String(name.as_bytes().to_vec()));
        id.insert(b"piece length".to_vec(), BEncode::Int(16_384));
        id.insert(b"pieces".to_vec(), BEncode::String(vec![0xAB; 20 * pieces]));
        id.insert(b"files".to_vec(), BEncode::List(vec![BEncode::Dict(fdict)]));
        let mut top = BTreeMap::new();
        top.insert(b"info".to_vec(), BEncode::Dict(id));
        Arc::new(Info::from_bencode(BEncode::Dict(top)).unwrap())
    }

    #[tokio::test]
    async fn dormant_torrent_elides_piece_availability_and_synthesizes_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let sess_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(crate::session::SessionStore::new(sess_dir.path()).unwrap());
        let disk = Arc::new(diskio::DiskEngine::new_blocking(16 * 1024 * 1024));
        let engine = Arc::new(SwarmEngine::new(disk, [0x51; 20]).with_session_store(store));

        let seed_info = make_multi_piece_info("seed-dormant", 4);
        let seed_hash = seed_info.hash;
        let mut bf = synapse_picker::Bitfield::new(4);
        for i in 0..4 {
            bf.set(i);
        }
        let seed_handle = engine.add_torrent(seed_info, dir.path().to_path_buf(), Some(&bf));
        assert_eq!(seed_handle.stats.read().state, SwarmState::Seeding);
        assert_eq!(seed_handle.stats.read().tier, SwarmTier::Warm);
        assert_eq!(seed_handle.piece_availability.read().capacity(), 0);
        assert_eq!(seed_handle.piece_availability_snapshot(), vec![1; 4]);
        assert!(!seed_handle.info.has_piece_hashes());
        let (exp_name, exp_bytes) = engine
            .export_torrent_bytes(&seed_hash)
            .expect("metadata should be recovered from session store");
        assert_eq!(exp_name, "seed-dormant");
        assert!(!exp_bytes.is_empty());

        let cold_info = make_multi_piece_info("paused-dormant", 4);
        let cold_handle = engine.add_torrent_with_resume(
            cold_info,
            dir.path().to_path_buf(),
            None,
            Some(SwarmResumeOptions {
                is_paused: true,
                ..Default::default()
            }),
        );
        assert_eq!(cold_handle.stats.read().state, SwarmState::Stopped);
        assert_eq!(cold_handle.stats.read().tier, SwarmTier::Cold);
        assert_eq!(cold_handle.piece_availability.read().capacity(), 0);
        assert_eq!(cold_handle.piece_availability_snapshot(), vec![0; 4]);
    }

    #[tokio::test]
    async fn idle_flush_session_skips_clean_torrents() {
        let dir = tempfile::tempdir().unwrap();
        let sess_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(crate::session::SessionStore::new(sess_dir.path()).unwrap());
        let disk = Arc::new(diskio::DiskEngine::new_blocking(16 * 1024 * 1024));
        let engine = Arc::new(SwarmEngine::new(disk, [0x52; 20]).with_session_store(store.clone()));

        let info1 = make_multi_piece_info("clean-one", 2);
        let h1 = info1.hash;
        let handle1 = engine.add_torrent(info1, dir.path().to_path_buf(), None);
        assert!(engine.transition_to_cold(&h1));
        let info2 = make_multi_piece_info("clean-two", 2);
        let h2 = info2.hash;
        let handle2 = engine.add_torrent(info2, dir.path().to_path_buf(), None);
        assert!(engine.transition_to_cold(&h2));

        assert!(!handle1.dirty.load(Ordering::Acquire));
        assert!(!handle2.dirty.load(Ordering::Acquire));

        // Inject a sentinel name into SessionStore without dirtying `handle1`; an idle
        // `flush_session()` must skip writing clean handles so the sentinel remains untouched.
        let mut persisted = store.load_torrent(&hex::encode(h1)).unwrap().unwrap();
        persisted.name = "sentinel-unflushed".to_string();
        persisted.raw_bencode_hex = None;
        store
            .save_states_batch(std::slice::from_ref(&persisted))
            .unwrap();

        engine.flush_session().await;
        let after_idle = store.load_torrent(&hex::encode(h1)).unwrap().unwrap();
        assert_eq!(after_idle.name, "sentinel-unflushed");

        // Reordering queue marks changed handles dirty, so flush persists and clears dirty.
        assert_eq!(engine.move_in_queue(&[h2], QueueMove::Top), 1);
        assert!(handle1.dirty.load(Ordering::Acquire));
        assert!(handle2.dirty.load(Ordering::Acquire));

        engine.flush_session().await;
        assert!(!handle1.dirty.load(Ordering::Acquire));
        assert!(!handle2.dirty.load(Ordering::Acquire));
        let after_dirty_flush = store.load_torrent(&hex::encode(h1)).unwrap().unwrap();
        assert_eq!(after_dirty_flush.name, "clean-one");
        let after_h2 = store.load_torrent(&hex::encode(h2)).unwrap().unwrap();
        assert_eq!(after_h2.queue_position, Some(0));
        assert_eq!(after_dirty_flush.queue_position, Some(1));
    }

    #[tokio::test]
    async fn list_torrents_paged_is_deterministic_across_pages_and_respects_remove() {
        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::new_blocking(16 * 1024 * 1024));
        let engine = Arc::new(SwarmEngine::new(disk, [0x53; 20]));

        let mut expected_hashes = Vec::new();
        for idx in 0..5 {
            let info = make_multi_piece_info(&format!("paged-{idx}"), 1);
            expected_hashes.push(info.hash);
            engine.add_torrent_with_resume(
                info,
                dir.path().to_path_buf(),
                None,
                Some(SwarmResumeOptions {
                    is_paused: true,
                    ..Default::default()
                }),
            );
        }

        let (p0, t0) = engine.list_torrents_paged(0, 2, None);
        let (p1, t1) = engine.list_torrents_paged(2, 2, None);
        let (p2, t2) = engine.list_torrents_paged(4, 2, None);
        assert_eq!((t0, t1, t2), (5, 5, 5));
        assert_eq!((p0.len(), p1.len(), p2.len()), (2, 2, 1));
        let combined: Vec<[u8; 20]> = p0
            .into_iter()
            .chain(p1)
            .chain(p2)
            .map(|s| s.info_hash)
            .collect();
        assert_eq!(combined, expected_hashes);

        assert!(engine.remove_torrent(&expected_hashes[2]));
        let (all_after, total_after) = engine.list_torrents_paged(0, 10, None);
        assert_eq!(total_after, 4);
        let after_hashes: Vec<[u8; 20]> = all_after.into_iter().map(|s| s.info_hash).collect();
        assert_eq!(
            after_hashes,
            vec![
                expected_hashes[0],
                expected_hashes[1],
                expected_hashes[3],
                expected_hashes[4],
            ]
        );
        let (mid_page, mid_total) = engine.list_torrents_paged(1, 2, None);
        assert_eq!(mid_total, 4);
        assert_eq!(
            mid_page.iter().map(|s| s.info_hash).collect::<Vec<_>>(),
            vec![expected_hashes[1], expected_hashes[3]]
        );
    }

    #[tokio::test]
    async fn reconcile_queue_and_rechoke_use_tracking_sets() {
        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::new_blocking(16 * 1024 * 1024));
        let engine = Arc::new(SwarmEngine::new(disk, [0x54; 20]));
        {
            let mut qm = engine.queue_manager.write();
            let mut cfg = qm.config().clone();
            cfg.max_active_downloads = 1;
            cfg.max_active_torrents = 10;
            qm.set_config(cfg);
        }

        let d1 = make_multi_piece_info("track-dl-1", 2);
        let h1 = d1.hash;
        let handle1 = engine.add_torrent(d1, dir.path().to_path_buf(), None);
        let d2 = make_multi_piece_info("track-dl-2", 2);
        let h2 = d2.hash;
        let handle2 = engine.add_torrent(d2, dir.path().to_path_buf(), None);

        assert_eq!(handle1.stats.read().state, SwarmState::Downloading);
        assert_eq!(handle2.stats.read().state, SwarmState::Queued);
        assert!(engine.downloading_torrents.contains(&h1));
        assert!(!engine.downloading_torrents.contains(&h2));
        assert!(engine.queued_torrents.contains(&h2));
        assert!(engine.active_torrents.contains(&h1));
        assert!(!engine.active_torrents.contains(&h2));

        engine.rechoke_session();
        assert!(engine.active_torrents.contains(&h1));

        assert!(engine.transition_to_cold(&h1));
        assert!(!engine.downloading_torrents.contains(&h1));
        assert!(!engine.active_torrents.contains(&h1));

        engine.reconcile_queue();
        assert_eq!(handle2.stats.read().state, SwarmState::Downloading);
        assert!(!engine.queued_torrents.contains(&h2));
        assert!(engine.downloading_torrents.contains(&h2));
        assert!(engine.active_torrents.contains(&h2));

        engine.rechoke_session();
        assert!(engine.active_torrents.contains(&h2));
    }

    #[tokio::test]
    async fn incomplete_dir_downloads_into_incomplete_and_moves_before_lifecycle() {
        use sha1::{Digest, Sha1};

        struct CapturePlugin {
            tx: parking_lot::Mutex<Option<oneshot::Sender<(String, bool, bool)>>>,
            inc_file: PathBuf,
            final_file: PathBuf,
        }

        #[async_trait::async_trait]
        impl crate::lifecycle::LifecyclePlugin for CapturePlugin {
            fn name(&self) -> &str {
                "capture"
            }

            async fn on_torrent_completed(
                &self,
                event: &crate::lifecycle::TorrentCompletedEvent,
            ) -> Result<(), crate::lifecycle::LifecycleError> {
                if let Some(tx) = self.tx.lock().take() {
                    let _ = tx.send((
                        event.download_dir.clone(),
                        self.final_file.exists(),
                        !self.inc_file.exists(),
                    ));
                }
                Ok(())
            }
        }

        let inc_dir = tempfile::tempdir().unwrap();
        let final_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let data = vec![0x5Au8; 16_384];
        let hash: [u8; 20] = Sha1::digest(&data).into();

        let mut fdict = BTreeMap::new();
        fdict.insert(b"length".to_vec(), BEncode::Int(data.len() as i64));
        fdict.insert(
            b"path".to_vec(),
            BEncode::List(vec![BEncode::String(b"payload.bin".to_vec())]),
        );
        let mut id = BTreeMap::new();
        id.insert(b"name".to_vec(), BEncode::String(b"inc_dir_test".to_vec()));
        id.insert(b"piece length".to_vec(), BEncode::Int(data.len() as i64));
        id.insert(b"pieces".to_vec(), BEncode::String(hash.to_vec()));
        id.insert(b"files".to_vec(), BEncode::List(vec![BEncode::Dict(fdict)]));
        let mut top = BTreeMap::new();
        top.insert(b"info".to_vec(), BEncode::Dict(id));
        let info = Arc::new(Info::from_bencode(BEncode::Dict(top)).unwrap());

        let cached_file = cache_dir.path().join(&info.files[0].path);
        std::fs::create_dir_all(cached_file.parent().unwrap()).unwrap();
        std::fs::write(&cached_file, &data).unwrap();

        let inc_file = inc_dir.path().join(&info.files[0].path);
        let final_file = final_dir.path().join(&info.files[0].path);
        let (cap_tx, cap_rx) = oneshot::channel();
        let lifecycle = Arc::new(
            crate::lifecycle::LifecycleDispatcher::new(crate::lifecycle::LifecycleConfig {
                staging_dir: None,
                auto_hardlink: false,
                wal_path: None,
                post_script: None,
                copy_script: None,
                script_timeout: None,
                instructions: None,
            })
            .with_plugin(Arc::new(CapturePlugin {
                tx: parking_lot::Mutex::new(Some(cap_tx)),
                inc_file: inc_file.clone(),
                final_file: final_file.clone(),
            })),
        );

        let disk = Arc::new(diskio::DiskEngine::new_blocking(4 * 1024 * 1024));
        let engine = Arc::new(SwarmEngine::new(disk, [0x54; 20]).with_lifecycle(lifecycle));
        let settings = DynamicSessionSettings {
            incomplete_dir_enabled: true,
            incomplete_dir: Some(inc_dir.path().to_path_buf()),
            ..Default::default()
        };
        engine.update_settings(settings);

        let handle = engine.add_torrent(info.clone(), final_dir.path().to_path_buf(), None);
        assert!(engine.transition_to_cold(&info.hash));

        let inc_str = inc_dir.path().to_string_lossy().to_string();
        let final_str = final_dir.path().to_string_lossy().to_string();
        assert_eq!(handle.stats.read().download_dir, inc_str);
        assert_eq!(
            handle.final_download_dir.read().as_ref(),
            Some(&final_dir.path().to_path_buf())
        );

        engine.set_local_webseed_dirs(vec![cache_dir.path().to_path_buf()]);
        assert!(engine.transition_to_hot(&info.hash));

        let (cb_dir, final_exists_at_cb, gone_from_inc_at_cb) =
            tokio::time::timeout(Duration::from_secs(5), cap_rx)
                .await
                .expect("lifecycle callback timed out")
                .expect("capture channel dropped");

        assert_eq!(cb_dir, final_str);
        assert!(
            final_exists_at_cb,
            "file must already be moved to final_dir before lifecycle callback runs"
        );
        assert!(
            gone_from_inc_at_cb,
            "file must no longer remain in incomplete_dir after completion move"
        );
        assert_eq!(handle.stats.read().download_dir, final_str);
        assert!(handle.final_download_dir.read().is_none());
        assert_eq!(std::fs::read(&final_file).unwrap(), data);
    }

    #[tokio::test]
    async fn rechoke_session_honors_turtle_mode_upload_limit() {
        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::new_blocking(4 * 1024 * 1024));
        let engine = Arc::new(SwarmEngine::new(disk, [0x54; 20]));

        {
            let mut s = engine.settings.write();
            s.upload_limit_enabled = false;
            s.unchoke_slots_global = 10;
            s.unchoke_slot_bandwidth = 16_384;
            s.alt_speed_enabled = true;
            s.alt_speed_up_bytes = 32_768;
            s.alt_speed_time_enabled = false;
        }

        let info = make_multi_piece_info("turtle-rechoke", 1);
        let handle = engine.add_torrent(info, dir.path().to_path_buf(), None);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let (ev_tx, _ev_rx) = mpsc::channel(8);
        let (stop_tx, _stop_rx) = tokio::sync::watch::channel(false);
        *handle.active_actor.write() = Some(ActiveActor {
            peer_event_tx: ev_tx,
            command_tx: cmd_tx,
            stop_tx,
        });
        {
            let mut peers = handle.live_peers.write();
            for i in 0..6u16 {
                peers.push(crate::torrent::PeerSnapshot {
                    addr: SocketAddr::from(([127, 0, 0, 1], 7000 + i)),
                    client_name: "Synapse/2.0".to_string(),
                    flags: "I".to_string(),
                    rate_to_client: 0,
                    rate_to_peer: 0,
                    progress: 0.5,
                    is_encrypted: false,
                    is_utp: false,
                    supports_pex: false,
                    peer_interested: true,
                });
            }
        }

        engine.rechoke_session();
        let mut alt_slots = None;
        while let Ok(cmd) = cmd_rx.try_recv() {
            if let TorrentCommand::SetUnchokeSlots(slots) = cmd {
                alt_slots = Some(slots);
            }
        }
        let alt_slots = alt_slots.expect("expected SetUnchokeSlots under turtle mode");
        assert_eq!(
            alt_slots, 4,
            "turtle mode upload limit (32 KiB/s) at 16 KiB/slot must cap slots at SessionChoker min 4, got {alt_slots}"
        );

        engine.settings.write().alt_speed_enabled = false;
        engine.rechoke_session();
        let mut normal_slots = None;
        while let Ok(cmd) = cmd_rx.try_recv() {
            if let TorrentCommand::SetUnchokeSlots(slots) = cmd {
                normal_slots = Some(slots);
            }
        }
        let normal_slots =
            normal_slots.expect("expected SetUnchokeSlots after disabling turtle mode");
        assert!(
            normal_slots > 4,
            "disabling turtle mode must restore > 4 slots, got {normal_slots}"
        );
    }

    #[tokio::test]
    async fn paused_torrent_recheck_verifies_disk_and_stays_cold_stopped() {
        use sha1::Digest;
        use std::collections::BTreeMap;
        use synapse_bencode::BEncode;

        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(diskio::DiskEngine::new_blocking(4 * 1024 * 1024));
        let engine = Arc::new(SwarmEngine::new(disk, [0x55; 20]));

        let payload = b"hello cold recheck world! 1234567890".to_vec();
        let hash: [u8; 20] = sha1::Sha1::digest(&payload).into();
        let mut id = BTreeMap::new();
        id.insert(
            b"name".to_vec(),
            BEncode::String(b"cold_recheck.bin".to_vec()),
        );
        id.insert(b"length".to_vec(), BEncode::Int(payload.len() as i64));
        id.insert(b"piece length".to_vec(), BEncode::Int(payload.len() as i64));
        id.insert(b"pieces".to_vec(), BEncode::String(hash.to_vec()));
        let mut top = BTreeMap::new();
        top.insert(b"info".to_vec(), BEncode::Dict(id));
        let info = Arc::new(Info::from_bencode(BEncode::Dict(top)).unwrap());
        let info_hash = info.hash;

        let handle = engine.add_torrent_with_resume(
            info,
            dir.path().to_path_buf(),
            None,
            Some(SwarmResumeOptions {
                is_paused: true,
                ..Default::default()
            }),
        );
        assert_eq!(handle.stats.read().state, SwarmState::Stopped);
        assert_eq!(handle.stats.read().tier, SwarmTier::Cold);
        assert!(handle.command_tx().is_none());
        assert_eq!(handle.stats.read().progress, 0.0);

        // Write valid data on disk and recheck without waking the actor.
        std::fs::write(dir.path().join("cold_recheck.bin"), &payload).unwrap();
        assert!(engine.recheck_torrent(&info_hash));

        let deadline = Instant::now() + Duration::from_secs(5);
        while handle.stats.read().state == SwarmState::Checking {
            assert!(Instant::now() < deadline, "cold recheck timed out");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        {
            let s = handle.stats.read();
            assert_eq!(s.state, SwarmState::Stopped);
            assert_eq!(s.tier, SwarmTier::Cold);
            assert!((s.progress - 1.0).abs() < f32::EPSILON);
        }
        assert!(handle.command_tx().is_none());

        // Corrupt the payload on disk and recheck again while staying Cold/Stopped.
        std::fs::write(
            dir.path().join("cold_recheck.bin"),
            vec![0u8; payload.len()],
        )
        .unwrap();
        assert!(engine.recheck_torrent(&info_hash));

        let deadline2 = Instant::now() + Duration::from_secs(5);
        while handle.stats.read().state == SwarmState::Checking {
            assert!(Instant::now() < deadline2, "second cold recheck timed out");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        {
            let s = handle.stats.read();
            assert_eq!(s.state, SwarmState::Stopped);
            assert_eq!(s.tier, SwarmTier::Cold);
            assert!((s.progress - 0.0).abs() < f32::EPSILON);
        }
        assert!(handle.command_tx().is_none());
    }
}
