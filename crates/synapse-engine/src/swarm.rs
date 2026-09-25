use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use diskio::DiskEngine;
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
const MAX_PENDING_HANDSHAKES: usize = 256;

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
            peers_banned: self.peers_banned.load(Ordering::Relaxed),
            chokes_total: self.chokes_total.load(Ordering::Relaxed),
            unchokes_total: self.unchokes_total.load(Ordering::Relaxed),
            piece_requests_total: self.piece_requests_total.load(Ordering::Relaxed),
            piece_rejects_total: self.piece_rejects_total.load(Ordering::Relaxed),
            hash_fails_total: self.hash_fails_total.load(Ordering::Relaxed),
            utp_packet_loss_total: self.utp_packet_loss_total.load(Ordering::Relaxed),
            dht_dos_blocks_total: self.dht_dos_blocks_total.load(Ordering::Relaxed),
        }
    }

    pub fn record_add(&self, state: &SwarmState, tier: SwarmTier, downloaded: u64, uploaded: u64) {
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
            _ => {
                if tier == SwarmTier::Cold {
                    self.paused_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    pub fn record_remove(&self, s: &SwarmStats) {
        let _ = self
            .total_torrents
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
        let _ =
            self.total_downloaded_bytes
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(s.downloaded_bytes))
                });
        let _ = self
            .total_uploaded_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(s.uploaded_bytes))
            });
        let _ = self
            .global_download_rate
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(s.download_rate))
            });
        let _ = self
            .global_upload_rate
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(s.upload_rate))
            });
        let _ =
            self.global_peers_connected
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(s.peers_connected))
                });

        match s.state {
            SwarmState::Downloading => {
                let _ = self.downloading_count.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
            }
            SwarmState::Seeding => {
                let _ =
                    self.seeding_count
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            Some(v.saturating_sub(1))
                        });
            }
            SwarmState::Queued => {
                let _ = self
                    .queued_count
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                        Some(v.saturating_sub(1))
                    });
            }
            SwarmState::Stopped => {
                let _ = self
                    .paused_count
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                        Some(v.saturating_sub(1))
                    });
            }
            _ => {
                if s.tier == SwarmTier::Cold {
                    let _ =
                        self.paused_count
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                                Some(v.saturating_sub(1))
                            });
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
                let _ = self.downloading_count.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
            }
            SwarmState::Seeding => {
                let _ =
                    self.seeding_count
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            Some(v.saturating_sub(1))
                        });
            }
            SwarmState::Queued => {
                let _ = self
                    .queued_count
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                        Some(v.saturating_sub(1))
                    });
            }
            SwarmState::Stopped => {
                let _ = self
                    .paused_count
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                        Some(v.saturating_sub(1))
                    });
            }
            _ => {}
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
            self.global_download_rate
                .fetch_add(new_dl - old_dl, Ordering::Relaxed);
        } else {
            let diff = old_dl - new_dl;
            let _ = self.global_download_rate.fetch_update(
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
            let _ =
                self.global_upload_rate
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |val| {
                        Some(val.saturating_sub(diff))
                    });
        }
        if new_peers >= old_peers {
            self.global_peers_connected
                .fetch_add(new_peers - old_peers, Ordering::Relaxed);
        } else {
            let diff = old_peers - new_peers;
            let _ = self.global_peers_connected.fetch_update(
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
    pub stop_tx: Option<Arc<oneshot::Sender<()>>>,
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
    /// API-set replacement tracker list, kept as strings so it can be saved with the session.
    pub tracker_override: Arc<RwLock<Option<Vec<String>>>>,
}

impl TorrentHandle {
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
    v2_torrents: Arc<DashMap<[u8; 32], Arc<TorrentHandle>>>,
    /// MSE `req2` hash -> info hash, for every registered torrent, so an inbound encrypted
    /// handshake resolves its torrent in O(1) instead of hashing every torrent.
    mse_req2_index: Arc<DashMap<[u8; 20], [u8; 20]>>,
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
}

/// BEP 35: which signers are trusted, and whether unsigned torrents are refused.
#[derive(Default)]
struct SignaturePolicy {
    trust: synapse_meta::TrustStore,
    require_trusted: bool,
}

impl SwarmEngine {
    pub fn new(disk: Arc<DiskEngine>, peer_id: [u8; 20]) -> Self {
        let listen_port = Arc::new(RwLock::new(0));
        let circuit_breaker = Arc::new(PeerCircuitBreaker::default());
        let nat_manager = Arc::new(RwLock::new(crate::nat::NatManager::new(true)));
        let settings = Arc::new(RwLock::new(DynamicSessionSettings::default()));
        let announcer = Arc::new(
            Announcer::new(peer_id, listen_port.clone(), circuit_breaker.clone())
                .with_nat_manager(nat_manager.clone())
                .with_settings(settings.clone()),
        );
        let announce_scheduler = AnnounceScheduler::new(
            announcer,
            32,
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
        };

        let engine_clone = engine.clone();
        announce_scheduler
            .set_peer_router(Arc::new(move |hash| engine_clone.get_or_wake_torrent(hash)));
        announce_scheduler.set_alert_sender(engine.alert_stream.sender());

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
        let handle = self.torrents.get(info_hash)?;
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
            let hex_hash = hex::encode(info_hash);
            if let Ok(Some(state)) = store.load_torrent(&hex_hash) {
                if let Some(ref raw_hex) = state.raw_bencode_hex {
                    if let Ok(bytes) = hex::decode(raw_hex) {
                        if let Ok(bencode) = synapse_bencode::decode_buf(&bytes) {
                            if let Ok(reloaded) = Info::from_persisted_bencode(bencode) {
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
                                    if let Ok(reloaded) = Info::from_persisted_bencode(bencode) {
                                        if &reloaded.hash == info_hash
                                            && reloaded.has_piece_hashes()
                                        {
                                            tracing::info!(
                                                "Auto-healed corrupted session metadata for '{}' ({}) from {}",
                                                reloaded.name,
                                                hex::encode(info_hash),
                                                path.display()
                                            );
                                            // Repair session store so subsequent restarts don't need to rescan
                                            if let Some(ref store) = self.session_store {
                                                let hex_hash = hex::encode(info_hash);
                                                if let Ok(Some(mut state)) =
                                                    store.load_torrent(&hex_hash)
                                                {
                                                    state.raw_bencode_hex =
                                                        Some(hex::encode(&bytes));
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

    pub fn subscribe_alerts(&self) -> tokio::sync::broadcast::Receiver<crate::alert::Alert> {
        self.alert_stream.subscribe()
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
    pub fn get_tracker_reports(&self, info_hash: &[u8; 20]) -> Vec<TrackerReport> {
        let reports = self.announce_scheduler.get_tracker_reports(info_hash);
        if !reports.is_empty() {
            return reports;
        }
        if let Some(handle) = self.torrents.get(info_hash) {
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
                })
                .collect()
        } else {
            Vec::new()
        }
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
    pub fn get_or_wake_command_tx(
        &self,
        info_hash: &[u8; 20],
    ) -> Option<mpsc::Sender<TorrentCommand>> {
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
        let have = handle
            .compressed_bitfield
            .read()
            .as_ref()
            .map(|b| b.to_bitfield());

        let (peer_tx, peer_rx) = mpsc::channel(256);
        let (command_tx, command_rx) = mpsc::channel(32);
        let (piece_tx, mut piece_rx) = mpsc::channel(128);
        let (pex_tx, mut pex_rx) = mpsc::channel::<Vec<SocketAddr>>(32);
        let (metadata_tx, metadata_rx) = oneshot::channel::<Info>();

        let (complete_tx, complete_rx) = oneshot::channel();
        if let Some(lifecycle) = self.lifecycle.clone() {
            let info_clone = info.clone();
            let dl_dir = download_dir.clone();
            tokio::spawn(async move {
                if complete_rx.await.is_ok() {
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
                            &dl_dir,
                            &info_clone.files,
                            &trackers,
                        )
                        .await;
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
            super_seeding: false,
            local_webseed_resolver: None,
            alert_sender: Some(self.alert_stream.sender()),
        };

        let mut torrent = Torrent::new(config, have.as_ref());
        // Skip/priority choices live on the handle so they survive the actor being evicted and
        // woken again, and (via the session store) a daemon restart.
        let priorities = handle.file_priorities.read().clone();
        for (idx, &prio) in priorities.iter().enumerate() {
            if prio != 4 {
                torrent.apply_file_priority(idx as u32, prio);
            }
        }
        self.metrics.active_actors.fetch_add(1, Ordering::Relaxed);
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
        tokio::spawn(async move {
            if let Ok(mut resolved_info) = metadata_rx.await {
                if resolved_info.select_only.is_none() {
                    resolved_info.select_only = select_only;
                }
                engine_metadata.resolve_magnet_metadata(download_dir_metadata, resolved_info);
            }
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

        let priorities_worker = handle.file_priorities.clone();
        let sequential_worker = handle.sequential.clone();
        let tracker_override_worker = handle.tracker_override.clone();
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
                    metrics_worker
                        .record_state_transition(&SwarmState::Downloading, &SwarmState::Seeding);
                    scheduler_worker.notify_completed(&hash_worker);
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
                        let raw_hex_c = raw_bencode_hex_worker.clone();
                        let prios_c = priorities_worker.read().clone();
                        let sequential_c = sequential_worker.load(Ordering::Relaxed);
                        let tracker_override_c = tracker_override_worker.read().clone();
                        let (uploaded_bytes, current_ratio) = {
                            let s = stats_worker.read();
                            (s.uploaded_bytes, s.ratio)
                        };
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
                                magnet_uri: None,
                                raw_bencode_hex: raw_hex_c,
                                file_priorities: prios_c,
                                sequential: sequential_c,
                                tracker_override: tracker_override_c,
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
        let now = Instant::now();
        let mut first_seen = self.download_first_seen.lock();
        first_seen.retain(|hash, _| {
            self.torrents
                .get(hash)
                .is_some_and(|h| h.stats.read().state == SwarmState::Downloading)
        });

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
                // A freshly started torrent has no throughput yet; without a grace period it would
                // count as "slow", not use up a slot, and every queued torrent would be started.
                let started = *first_seen.entry(stats.info_hash).or_insert(now);
                let in_startup_grace = now.duration_since(started) < AUTO_MANAGE_STARTUP;
                let is_slow = !in_startup_grace && qm.is_slow_downloader(stats.download_rate);
                stats.is_stalled = stalled;
                if !stalled && !is_slow {
                    active_non_stalled += 1;
                }
            } else if stats.state == SwarmState::Seeding {
                // "Idle seeding": time since anything last moved, not time since the torrent was
                // added (a torrent that took hours to download must not be stopped the moment it
                // finishes because it is "older" than the seed-time limit).
                let last_activity = if stats.last_transfer_at > 0 {
                    stats.last_transfer_at as u64
                } else {
                    stats.added_at as u64
                };
                let elapsed_secs = now_secs.saturating_sub(last_activity);
                let action =
                    qm.evaluate_seeder(1, self.torrents.len(), stats.ratio as f64, elapsed_secs);
                if matches!(
                    action,
                    QueueAction::AutoStopRatioReached | QueueAction::AutoStopSeedTimeReached
                ) {
                    stats.state = SwarmState::Stopped;
                    stats.tier = SwarmTier::Cold;
                    self.metrics
                        .record_state_transition(&SwarmState::Seeding, &SwarmState::Stopped);
                    drop(stats);
                    handle.stop_actor();
                }
            } else if stats.state == SwarmState::Queued {
                queued_hashes.push(stats.info_hash);
            }
        }

        // Start queued torrents in queue order, not in whatever order the map yields them.
        let positions = self.queue_positions();
        queued_hashes.sort_by_key(|h| positions.get(h).copied().unwrap_or(u32::MAX));
        for hash in queued_hashes {
            if qm.evaluate_downloader(active_non_stalled, self.torrents.len()) == QueueAction::Allow
            {
                if let Some(handle) = self.torrents.get(&hash) {
                    let mut s = handle.stats.write();
                    s.state = SwarmState::Downloading;
                    s.tier = SwarmTier::Hot;
                    self.metrics
                        .record_state_transition(&SwarmState::Queued, &SwarmState::Downloading);
                    drop(s);
                    first_seen.insert(hash, now);
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

    pub fn lifecycle(&self) -> Option<&Arc<LifecycleDispatcher>> {
        self.lifecycle.as_ref()
    }

    pub fn torrent_count(&self) -> usize {
        self.torrents.len()
    }

    /// Returns the number of currently active swarm actors running background tick loops.
    pub fn active_swarm_count(&self) -> usize {
        self.torrents
            .iter()
            .filter(|t| t.value().is_active())
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
        self.add_torrent_with_resume(info, download_dir, have, None)
    }

    /// BEP 9: called once a magnet-added torrent's metadata-only actor finishes
    /// assembling and verifying its real `Info` over the wire (see `TorrentConfig::
    /// on_metadata_resolved`). Drops the placeholder registration and re-adds the
    /// torrent under the same info_hash with the real metadata, which spawns a normal
    /// downloading actor in its place via the usual `add_torrent_with_resume` path.
    fn resolve_magnet_metadata(&self, download_dir: std::path::PathBuf, info: Info) {
        let info_hash = info.hash;
        tracing::info!(name = %info.name, hash = %hex::encode(info_hash), "Magnet metadata resolved; starting real download");
        self.announce_scheduler.unregister(&info_hash);
        self.lsd_manager.lock().unregister_torrent(&info_hash);
        self.zeroconf_manager.lock().unregister_torrent(&info_hash);
        self.torrents.remove(&info_hash);
        self.mse_req2_index
            .remove(&synapse_wire::mse_req2(&info_hash));
        if let Some(v2) = info.info_hash_v2 {
            self.v2_torrents.remove(&v2);
        }
        self.add_torrent(Arc::new(info), download_dir, None);
    }

    pub fn add_torrent_with_resume(
        &self,
        info: Arc<Info>,
        download_dir: std::path::PathBuf,
        have: Option<&Bitfield>,
        resume: Option<SwarmResumeOptions>,
    ) -> Arc<TorrentHandle> {
        let info_hash = info.hash;

        let total_size = info.total_len;
        let name = info.name.clone();
        let added_at = resume.as_ref().and_then(|r| r.added_at).unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        });

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
            let active_dl = self
                .torrents
                .iter()
                .filter(|t| {
                    let s = t.value().stats.read();
                    s.state == SwarmState::Downloading && !s.is_stalled
                })
                .count();
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
            downloaded_bytes,
            uploaded_bytes,
            peers_connected: 0,
            peers_sending: 0,
            eta_seconds: 0,
            ratio,
            download_dir: download_dir.to_string_lossy().to_string(),
            added_at,
            is_private: info.private,
            is_stalled: false,
            last_transfer_at: added_at,
            piece_count: info.pieces(),
            piece_size: info.piece_len,
        };

        self.metrics.record_add(
            &initial_state,
            initial_tier,
            downloaded_bytes,
            uploaded_bytes,
        );

        let stats = Arc::new(RwLock::new(initial_stats));
        let compressed_bitfield = Arc::new(RwLock::new(
            have.map(synapse_picker::RoaringBitfield::from_bitfield),
        ));

        if resume.is_none() {
            if let Some(ref store) = self.session_store {
                let bitfield_hex = have.map(|h| hex::encode(h.as_bytes())).unwrap_or_default();
                let state = TorrentSessionState {
                    info_hash_hex: hex::encode(info_hash),
                    name: name.clone(),
                    download_dir: download_dir.to_string_lossy().to_string(),
                    bitfield_hex,
                    total_pieces: info.pieces() as usize,
                    total_size,
                    uploaded_bytes,
                    downloaded_bytes,
                    added_at,
                    is_paused,
                    ratio: Some(ratio),
                    magnet_uri: None,
                    raw_bencode_hex: Some(hex::encode(info.to_torrent_bytes())),
                    file_priorities: Vec::new(),
                    sequential: false,
                    tracker_override: None,
                };
                let _ = store.save_torrent(&state);
            }
        }

        let initial_availability = if initial_state == SwarmState::Seeding {
            vec![1u32; info.pieces() as usize]
        } else {
            vec![0u32; info.pieces() as usize]
        };
        let piece_availability = Arc::new(RwLock::new(initial_availability));
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
            tracker_override: Arc::new(RwLock::new(
                resume.as_ref().and_then(|r| r.tracker_override.clone()),
            )),
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
        self.queue_order.lock().push(info_hash);
        self.mse_req2_index
            .insert(synapse_wire::mse_req2(&info_hash), info_hash);
        if let Some(v2) = info.info_hash_v2 {
            self.v2_torrents.insert(v2, handle.clone());
        }
        self.lsd_manager
            .lock()
            .register_torrent(info_hash, info.private);
        self.zeroconf_manager
            .lock()
            .register_torrent(info_hash, info.private);
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

        if !is_paused {
            let is_dl = initial_state == SwarmState::Downloading;
            self.announce_scheduler
                .register(info_hash, info, stats, peer_tx, is_dl);
        }

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
                        is_paused: matches!(s.tier, SwarmTier::Cold)
                            || s.state == SwarmState::Stopped,
                        ratio: Some(s.ratio),
                        magnet_uri: None,
                        raw_bencode_hex: if h.info.has_piece_hashes() {
                            Some(hex::encode(h.info.to_torrent_bytes()))
                        } else {
                            None
                        },
                        file_priorities: h.file_priorities.read().clone(),
                        sequential: h.sequential.load(Ordering::Relaxed),
                        tracker_override: h.tracker_override.read().clone(),
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
    /// Switches a torrent between rarest-first and sequential (in-order) piece picking.
    /// Returns false if the torrent doesn't exist.
    pub fn set_sequential_download(&self, info_hash: &[u8; 20], enabled: bool) -> bool {
        let Some(handle) = self.torrents.get(info_hash) else {
            return false;
        };
        handle.sequential.store(enabled, Ordering::Relaxed);
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

    /// Replaces the trackers a torrent announces to with `trackers` and announces to them
    /// straight away. An empty list restores the torrent's own trackers. Invalid URLs are
    /// dropped; returns how many usable trackers were set, or `None` if the torrent
    /// doesn't exist.
    pub fn replace_trackers(&self, info_hash: &[u8; 20], trackers: &[String]) -> Option<usize> {
        let handle = self.torrents.get(info_hash)?;
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
        if apply_queue_move(&mut order, &selected, direction) {
            drop(order);
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
        let hex = hex::encode(info_hash);
        tokio::task::spawn_blocking(move || {
            if let Ok(Some(mut state)) = store.load_torrent(&hex) {
                apply(&mut state);
                let _ = store.save_torrent(&state);
            }
        });
    }

    pub fn set_file_priority(&self, info_hash: &[u8; 20], file_index: u32, priority: u8) -> bool {
        if let Some(handle) = self.torrents.get(info_hash) {
            {
                let mut prios = handle.file_priorities.write();
                if let Some(p) = prios.get_mut(file_index as usize) {
                    *p = priority;
                }
            }
            self.persist_file_priorities(info_hash, handle.file_priorities.read().clone());
            if let Some(tx) = self.get_or_wake_command_tx(info_hash) {
                let _ = tx.try_send(TorrentCommand::SetFilePriority(file_index, priority));
            }
            true
        } else {
            false
        }
    }

    /// Saves the current per-file priorities into the torrent's session record so they survive a
    /// restart (or crash) without waiting for the next full session flush.
    fn persist_file_priorities(&self, info_hash: &[u8; 20], priorities: Vec<u8>) {
        let Some(store) = self.session_store.clone() else {
            return;
        };
        let hex = hex::encode(info_hash);
        tokio::task::spawn_blocking(move || {
            if let Ok(Some(mut state)) = store.load_torrent(&hex) {
                state.file_priorities = priorities;
                let _ = store.save_torrent(&state);
            }
        });
    }

    /// Returns the active priority for each file in the torrent (0=skip, 1=low, 4=normal, 7=high).
    pub fn get_file_priorities(&self, info_hash: &[u8; 20]) -> Option<Vec<u8>> {
        self.torrents
            .get(info_hash)
            .map(|h| h.file_priorities.read().clone())
    }

    /// Moves an active swarm's downloaded files to a new directory — dispatched to
    /// `Torrent::handle_set_location` via `TorrentCommand::SetLocation`, which does the actual
    /// file move. Previously this only relabeled `stats.download_dir` without moving anything
    /// on disk, silently diverging from where the files actually were.
    pub fn set_location(&self, info_hash: &[u8; 20], new_download_dir: &str) -> bool {
        if let Some(tx) = self.get_or_wake_command_tx(info_hash) {
            let _ = tx.try_send(TorrentCommand::SetLocation(std::path::PathBuf::from(
                new_download_dir,
            )));
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

    pub fn session_choker(&self) -> Arc<RwLock<synapse_picker::SessionChoker>> {
        self.session_choker.clone()
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

        self.recalculate_effective_rate_limits();
        self.rechoke_session();
        warnings
    }

    /// Evaluates all active swarms and distributes unchoke slots session-wide based on
    /// torrent priority, seeding state, and interested peer demand.
    pub fn rechoke_session(&self) {
        let (global_slots, slot_bw, upload_limit, seed_algo_str) = {
            let s = self.settings.read();
            let upload_lim = if s.upload_limit_enabled {
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
        for item in self.torrents.iter() {
            let info_hash = *item.key();
            let handle = item.value();
            if !handle.is_active() {
                continue;
            }
            let is_seeding = handle.stats.read().state == SwarmState::Seeding;
            let priority = match handle.stats.read().tier {
                SwarmTier::Hot => 5,
                SwarmTier::Warm => 4,
                SwarmTier::Cold => 2,
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
            if let Some(handle) = self.torrents.get(&info_hash) {
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
                self.rechoke_session();
            }
        })
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
            handle.stop_actor();
            self.announce_scheduler.unregister(info_hash);
            self.lsd_manager.lock().unregister_torrent(info_hash);
            self.zeroconf_manager.lock().unregister_torrent(info_hash);

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
            self.metrics
                .record_state_transition(&old_state, &target_state);
            self.post_alert(crate::alert::Alert::StateChanged {
                info_hash: *info_hash,
                old_state,
                new_state: target_state.clone(),
            });
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
                    let _ = store.save_torrent(&state);
                }
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
        if let Some(ref store) = self.session_store {
            let _ = store.remove_torrent(info_hash);
        }
        if let Some((_, handle)) = self.torrents.remove(info_hash) {
            self.mse_req2_index
                .remove(&synapse_wire::mse_req2(info_hash));
            if let Some(v2) = handle.info.info_hash_v2 {
                self.v2_torrents.remove(&v2);
            }
            handle.stop_actor();
            let s = handle.stats.read();
            self.metrics.record_remove(&s);
            // The part file and its slice map are private scratch; nothing else can use them.
            crate::part_file::PartFileManager::remove_files(
                std::path::Path::new(&s.download_dir),
                info_hash,
            );
            true
        } else {
            false
        }
    }

    /// Looks up a torrent by its 32-byte BitTorrent v2 SHA-256 info-hash (BEP 52).
    pub fn torrent_by_v2_hash(&self, hash: &[u8; 32]) -> Option<Arc<TorrentHandle>> {
        self.v2_torrents.get(hash).map(|r| r.value().clone())
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
                            if let Ok(mut info) = Info::from_persisted_bencode(bencode) {
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
                                    if let Some(hashes) = self.try_recover_piece_hashes(&info_hash)
                                    {
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
        // The store yields torrents in arbitrary order; start the queue oldest-first.
        if restored > 0 {
            let mut order = self.queue_order.lock();
            order.clear();
            self.sync_queue_order(&mut order);
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
                    }
                }
            }
        });

        Ok(handle)
    }

    /// Returns the live DHT routing table size (0 if DHT isn't running), for metrics.
    pub async fn dht_node_count(&self) -> usize {
        let handle = self.dht.read().clone();
        match handle {
            Some(h) => h.routing_snapshot().await.map(|v| v.len()).unwrap_or(0),
            None => 0,
        }
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
        let saved = self
            .dht_state_path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| synapse_dht::DhtState::decode(&b));
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
            let dht_concurrency = engine.settings.read().max_concurrent_dht_announces.max(1);
            let semaphore = Arc::new(tokio::sync::Semaphore::new(dht_concurrency));
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
                    let permit = semaphore.clone().acquire_owned().await;
                    let Ok(permit) = permit else { continue };
                    let handle = handle.clone();
                    let engine = engine.clone();
                    let bootstrap_nodes = bootstrap_nodes.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
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
        let socket_v4 = bind_lsd_socket(lsd_v4)?;
        info!("LSD (Local Peer Discovery) active on {}", lsd_v4);
        let socket_v6 = match bind_lsd_socket(lsd_v6) {
            Ok(s) => {
                info!("LSD (Local Peer Discovery) active on {}", lsd_v6);
                Some(s)
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
                        let packet = self.lsd_manager.lock().build_announce_packet();
                        if let Some(packet) = packet {
                            if let Err(e) = socket_v4.send_to(packet.as_bytes(), lsd_v4).await {
                                debug!("LSD IPv4 announce send failed: {e}");
                            }
                            if let Some(ref s6) = socket_v6 {
                                // The `Host:` header names the group the packet is sent to.
                                let v6_packet = packet.replace(
                                    synapse_wire::LSD_MULTICAST_IPV4,
                                    synapse_wire::LSD_MULTICAST_IPV6,
                                );
                                if let Err(e) = s6.send_to(v6_packet.as_bytes(), lsd_v6).await {
                                    debug!("LSD IPv6 announce send failed: {e}");
                                }
                            }
                        }
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
                        let (queries, announcement) = {
                            let mut m = self.zeroconf_manager.lock();
                            m.set_listen_port(*self.listen_port.read());
                            (m.queries(), m.announcement(&addrs))
                        };
                        for q in queries {
                            let _ = socket.send_to(&q, self.zeroconf_target(group)).await;
                        }
                        if let Some(a) = announcement {
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
        let result = std::fs::write(&tmp, &bytes).and_then(|_| std::fs::rename(&tmp, &path));
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
}
