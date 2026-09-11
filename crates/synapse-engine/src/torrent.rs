//! The per-torrent state machine: owns the picker/choker, tracks per-peer state, and
//! drives requesting/serving pieces. Replaces the pre-rewrite codebase's `Control`
//! struct + `CIO` trait + `amy`-based event loop (see `doc/REWRITE_ROADMAP.md` Part 1)
//! with a plain tokio task that `select!`s between peer events and a periodic tick.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use parking_lot::RwLock;
use sha1::{Digest, Sha1};
use tokio::sync::{mpsc, oneshot};

use diskio::{DiskEngine, ReadJob, WriteJob};
use synapse_meta::Info;
use synapse_picker::{Bitfield, ChokeDecisions, Choker, Mode, PeerStats, Picker, RoaringBitfield};

use crate::ratelimit::TokenBucket;
use crate::swarm::{SwarmState, SwarmStats, SwarmTier};
use synapse_wire::{ExtensionHandshake, Message};

use std::net::SocketAddr;
use crate::fast_ext::compute_allowed_fast_set;
use crate::peer::{parse_client_name, PeerEvent, PeerHandle, PeerId, PeerInfo};

/// Snapshot of an active peer's live transfer statistics and connection flags.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerSnapshot {
    pub addr: SocketAddr,
    pub client_name: String,
    pub flags: String,
    pub rate_to_client: u64,
    pub rate_to_peer: u64,
    pub progress: f32,
    pub is_encrypted: bool,
    pub is_utp: bool,
    #[serde(default)]
    pub supports_pex: bool,
}

/// Conventional BitTorrent block size. Requests are always made in blocks of this size
/// (the last block of a piece may be shorter).
const BLOCK_LEN: u32 = 16 * 1024;

/// Minimum time between BEP 19 webseed fetch attempts once a torrent has no peers --
/// see `Torrent::maybe_fetch_via_webseed`.
const WEBSEED_RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// Fixed BEP 10 extension message IDs *we* declare for ourselves in our own handshake
/// (`ExtensionHandshake::for_torrent`). An incoming `Message::Extension { id, .. }` is
/// dispatched by matching against these -- per BEP 10, the sender addresses us using
/// the IDs *we* published, not IDs from their own handshake (those instead say what
/// *we* must use when sending *to them* -- see `peer.peer_extensions`).
const EXT_ID_UT_METADATA: u8 = 1;
const EXT_ID_UT_PEX: u8 = 2;

/// Out-of-band control commands from the RPC layer (via `SwarmEngine`) to a running
/// `Torrent` task — distinct from `PeerEvent` (wire-protocol events from a peer connection)
/// since these originate from the control plane instead. Delivered on their own channel
/// rather than folded into `PeerEvent` to keep "something a peer said" and "something an
/// operator asked for" from being the same enum.
pub enum TorrentCommand {
    /// `priority` follows the proto's documented mapping (0=skip, 1=low, 4=normal, 7=high).
    /// The picker currently only supports a wanted/not-wanted mask, not the full four-level
    /// weighting — `0` deselects the file's pieces, anything else (re)selects them.
    SetFilePriority(u32, u8),
    /// Re-verifies every piece already on disk against the torrent's real hashes and
    /// rebuilds picker/bitfield state to match, rather than just flipping a state label.
    Recheck,
    /// Moves every downloaded file from the current download directory to a new one.
    SetLocation(PathBuf),
    /// Stops the torrent actor: closes all peer handles to terminate connection tasks and exits the actor loop.
    Stop,
}

pub struct TorrentConfig {
    pub info: Arc<Info>,
    pub download_dir: PathBuf,
    pub peer_id: [u8; 20],
    pub disk: Arc<DiskEngine>,
    pub mode: Mode,
    /// Outstanding block requests allowed per peer at once.
    pub max_pipeline: usize,
    pub regular_unchokes: usize,
    pub optimistic_unchoke_interval: Duration,
    pub tick_interval: Duration,
    pub on_torrent_completed: Option<oneshot::Sender<()>>,
    pub on_piece_completed: Option<mpsc::Sender<u32>>,
    /// Shared with `SwarmEngine`/the RPC layer — `tick()` writes live rate/peer/ETA/ratio
    /// stats here every tick, and `Recheck`/`SetLocation` write their results here directly,
    /// instead of those fields staying frozen at whatever they were at add-time.
    pub stats: Arc<RwLock<SwarmStats>>,
    /// Shared compressed bitfield — rewritten wholesale after a `Recheck`; incremental
    /// per-piece updates during normal downloading remain `SwarmEngine`'s piece-completion
    pub bitfield: Arc<RwLock<Option<RoaringBitfield>>>,
    pub download_bucket: Arc<TokenBucket>,
    pub upload_bucket: Arc<TokenBucket>,
    pub global_metrics: Option<Arc<crate::swarm::GlobalEngineMetrics>>,
    pub idle_timeout: Option<Duration>,
    /// Shared live active peer snapshots inspected by RPC / UI clients.
    pub live_peers: Arc<RwLock<Vec<PeerSnapshot>>>,
    /// Shared piece availability counts inspected by RPC / UI clients.
    pub piece_availability: Arc<RwLock<Vec<u32>>>,
    /// Live peer-limit settings (`max_peers_per_torrent` / `max_global_peers`), read at
    /// each connection to enforce the configured caps -- see `on_connected`.
    pub settings: Arc<RwLock<crate::settings::DynamicSessionSettings>>,
    /// BEP 11 Peer Exchange: peers discovered via `ut_pex` messages from connected peers
    /// are forwarded here so the owning `SwarmEngine` can feed them into the same
    /// candidate pool trackers use.
    pub on_peers_discovered: Option<mpsc::Sender<Vec<SocketAddr>>>,
    /// Shared HTTP client used for BEP 19 webseed range requests.
    pub http_client: reqwest::Client,
    /// BEP 9: fires once when a magnet-added torrent (constructed with a placeholder
    /// `Info` that has no files) finishes assembling and verifying its real metadata
    /// over the wire. `None` for a normal torrent that already has full metadata.
    pub on_metadata_resolved: Option<oneshot::Sender<Info>>,
}

struct PeerState {
    handle: PeerHandle,
    peer_info: PeerInfo,
    has: Bitfield,
    am_choking: bool,
    am_interested: bool,
    peer_choking: bool,
    peer_interested: bool,
    in_flight: HashMap<(u32, u32), std::time::Instant>,
    consecutive_timeouts: u32,
    is_snubbed: bool,
    downloaded_from: u64,
    uploaded_to: u64,
    /// `downloaded_from`/`uploaded_to` are cumulative totals; these are the values they held
    /// as of the previous tick, so `tick()` can compute a per-second rate from the delta
    /// instead of reporting the cumulative total as if it were instantaneous throughput.
    prev_downloaded_from: u64,
    prev_uploaded_to: u64,
    /// BEP 6: AllowedFast pieces we permit this peer to request while choked
    allowed_fast: HashSet<u32>,
    /// BEP 6: AllowedFast pieces this peer permits us to request while choked
    peer_allowed_fast: HashSet<u32>,
    /// Last instant data or an unchoke was received from this peer
    last_received_at: std::time::Instant,
    /// This peer's BEP 10 extension handshake `m` dict (extension name -> the message ID
    /// *they* will use when sending us that extension), captured once their handshake
    /// (`Message::Extension { id: 0, .. }`) arrives. Empty until then.
    peer_extensions: HashMap<String, u8>,
}

struct InProgressPiece {
    buf: Vec<u8>,
    received_blocks: HashSet<u32>,
    expected_blocks: usize,
}

impl InProgressPiece {
    fn new(piece_len: u32) -> InProgressPiece {
        let expected_blocks = (piece_len as usize).div_ceil(BLOCK_LEN as usize);
        InProgressPiece {
            buf: vec![0u8; piece_len as usize],
            received_blocks: HashSet::with_capacity(expected_blocks),
            expected_blocks,
        }
    }

    fn is_complete(&self) -> bool {
        self.received_blocks.len() == self.expected_blocks
    }
}

pub struct Torrent {
    info: Arc<Info>,
    download_dir: PathBuf,
    disk: Arc<DiskEngine>,
    picker: Picker,
    choker: Choker<PeerId>,
    peers: HashMap<PeerId, PeerState>,
    in_progress: HashMap<u32, InProgressPiece>,
    max_pipeline: usize,
    tick_interval: Duration,
    on_complete: Vec<oneshot::Sender<()>>,
    on_piece_completed: Option<mpsc::Sender<u32>>,
    completed_fired: bool,
    stats: Arc<RwLock<SwarmStats>>,
    bitfield: Arc<RwLock<Option<RoaringBitfield>>>,
    download_bucket: Arc<TokenBucket>,
    upload_bucket: Arc<TokenBucket>,
    global_metrics: Option<Arc<crate::swarm::GlobalEngineMetrics>>,
    /// Running total, independent of any single peer's `uploaded_to` — a per-peer counter is
    /// lost when that peer disconnects (`on_disconnected` drops its `PeerState`), so this is
    /// tracked separately to survive peer churn across the torrent's lifetime.
    total_uploaded: u64,
    idle_timeout: Option<Duration>,
    last_activity: std::time::Instant,
    live_peers: Arc<RwLock<Vec<PeerSnapshot>>>,
    piece_availability: Arc<RwLock<Vec<u32>>>,
    settings: Arc<RwLock<crate::settings::DynamicSessionSettings>>,
    pex: crate::pex::PexManager,
    last_pex_broadcast: std::time::Instant,
    on_peers_discovered: Option<mpsc::Sender<Vec<SocketAddr>>>,
    /// BEP 19: `None` when the torrent metadata declares no `url-list`.
    webseed: Option<crate::webseed::WebSeedManager>,
    last_webseed_attempt: std::time::Instant,
    http_client: reqwest::Client,
    metadata_fetcher: Option<crate::metadata::MetadataFetcher>,
    on_metadata_resolved: Option<oneshot::Sender<Info>>,
    metadata_resolved: bool,
}

impl Torrent {
    pub fn new(config: TorrentConfig, have: Option<&Bitfield>) -> Torrent {
        let mut picker = Picker::new(config.info.pieces() as usize, config.mode);
        if let Some(have) = have {
            picker = picker.with_completed(have);
        }
        let mut on_complete = Vec::new();
        if let Some(tx) = config.on_torrent_completed {
            on_complete.push(tx);
        }
        let starting_uploaded = config.stats.read().uploaded_bytes;
        let is_private = config.info.private;
        // NB: `Info::url_list` is (confusingly) the tracker `announce-list`; the actual
        // BEP 19 webseed URLs live in `Info::web_seeds`, parsed from the torrent's
        // `url-list` key. Unlike DHT/PEX/LSD, BEP 27 does not restrict webseeds on
        // private torrents -- a webseed entry is an HTTP mirror the torrent publisher
        // controls directly, not a peer-discovery mechanism that leaks swarm membership.
        let webseed = if config.info.web_seeds.is_empty() {
            None
        } else {
            Some(crate::webseed::WebSeedManager::new(&config.info.web_seeds))
        };
        // A magnet-added torrent is constructed with a placeholder `Info` that carries
        // an info_hash but no files (see `SwarmEngine::add_magnet` / `Info::from_magnet`).
        // Real parsed torrents always have at least one file (`Info::from_bencode`
        // rejects an empty file list), so this is a reliable "awaiting metadata" test.
        let metadata_fetcher = if config.info.files.is_empty() {
            Some(crate::metadata::MetadataFetcher::new(config.info.hash))
        } else {
            None
        };
        Torrent {
            info: config.info,
            download_dir: config.download_dir,
            disk: config.disk,
            picker,
            choker: Choker::new(config.regular_unchokes, config.optimistic_unchoke_interval),
            peers: HashMap::new(),
            in_progress: HashMap::new(),
            stats: config.stats,
            bitfield: config.bitfield,
            download_bucket: config.download_bucket,
            upload_bucket: config.upload_bucket,
            global_metrics: config.global_metrics,
            total_uploaded: starting_uploaded,
            max_pipeline: config.max_pipeline,
            tick_interval: config.tick_interval,
            on_complete,
            on_piece_completed: config.on_piece_completed,
            completed_fired: false,
            idle_timeout: config.idle_timeout,
            last_activity: std::time::Instant::now(),
            live_peers: config.live_peers,
            piece_availability: config.piece_availability,
            settings: config.settings,
            pex: crate::pex::PexManager::new(is_private),
            last_pex_broadcast: std::time::Instant::now(),
            on_peers_discovered: config.on_peers_discovered,
            webseed,
            // Set in the past so a torrent with no peers can try its webseed on the very
            // first tick, rather than waiting a full retry interval after construction.
            last_webseed_attempt: std::time::Instant::now() - WEBSEED_RETRY_INTERVAL,
            http_client: config.http_client,
            metadata_fetcher,
            on_metadata_resolved: config.on_metadata_resolved,
            metadata_resolved: false,
        }
    }

    /// Registers a channel that fires exactly once, the moment every piece is complete.
    /// If the torrent is already complete when this is called, fires immediately (on
    /// the next event loop iteration).
    pub fn notify_on_complete(&mut self, tx: oneshot::Sender<()>) {
        if self.picker.is_complete() {
            let _ = tx.send(());
        } else {
            self.on_complete.push(tx);
        }
    }

    pub fn info_hash(&self) -> [u8; 20] {
        self.info.hash
    }

    /// Runs the torrent's event loop until `events` closes (every peer task's sender
    /// has been dropped and nothing new will ever arrive). `commands` carries control-plane
    /// requests (file priority, recheck, relocate) — see `TorrentCommand`.
    pub async fn run(mut self, mut events: mpsc::Receiver<PeerEvent>, mut commands: mpsc::Receiver<TorrentCommand>) {
        let mut ticker = tokio::time::interval(self.tick_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // `command_tx` and `peer_event_tx` (behind `events`) both live in the same
        // `TorrentHandle` and are dropped together on remove, but `events` can also stay open
        // independently as long as any individual peer connection still holds its own cloned
        // sender — so `commands` can close first. A closed mpsc's `recv()` resolves to `None`
        // immediately on every poll; without this guard that would busy-spin the select loop
        // once `commands` closes but `events` hasn't yet.
        let mut commands_open = true;
        loop {
            if self.metadata_resolved {
                tracing::debug!(name = %self.info.name, "Metadata-only actor exiting after successful resolution");
                break;
            }
            tokio::select! {
                ev = events.recv() => {
                    self.last_activity = std::time::Instant::now();
                    match ev {
                        Some(PeerEvent::Connected(handle, info)) => self.on_connected(handle, info).await,
                        Some(PeerEvent::Message(id, msg)) => self.on_message(id, msg).await,
                        Some(PeerEvent::Disconnected(id)) => self.on_disconnected(id),
                        None => break,
                    }
                }
                cmd = commands.recv(), if commands_open => {
                    self.last_activity = std::time::Instant::now();
                    match cmd {
                        Some(TorrentCommand::SetFilePriority(file_idx, priority)) => self.apply_file_priority(file_idx, priority),
                        Some(TorrentCommand::Recheck) => self.handle_recheck().await,
                        Some(TorrentCommand::SetLocation(new_dir)) => self.handle_set_location(new_dir).await,
                        Some(TorrentCommand::Stop) => {
                            tracing::debug!(name = %self.info.name, "Stopping torrent actor: disconnecting peers and draining state");
                            self.peers.clear();
                            break;
                        }
                        None => { commands_open = false; }
                    }
                }
                _ = ticker.tick() => {
                    self.tick().await;
                    if self.picker.is_complete() && self.peers.is_empty() {
                        if let Some(timeout) = self.idle_timeout {
                            if self.last_activity.elapsed() >= timeout {
                                tracing::info!(
                                    name = %self.info.name,
                                    "Torrent seeding idle for {:?}, transitioning from Hot to Warm tier",
                                    timeout
                                );
                                break;
                            }
                        }
                    } else {
                        self.last_activity = std::time::Instant::now();
                    }
                }
            }
        }

        self.publish_live_stats();
        self.live_peers.write().clear();

        // On actor loop exit (due to idle timeout, unregistration, or channel close):
        // Ensure Warm tier is set if still seeding/not cold, and decrement active actor metric.
        {
            let mut s = self.stats.write();
            if s.tier == SwarmTier::Hot {
                s.tier = SwarmTier::Warm;
            }
        }
        if let Some(ref m) = self.global_metrics {
            let _ = m.active_actors.fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |v| Some(v.saturating_sub(1)),
            );
        }
    }

    async fn on_connected(&mut self, handle: PeerHandle, info: PeerInfo) {
        let (max_per_torrent, max_global) = {
            let s = self.settings.read();
            (s.max_peers_per_torrent, s.max_global_peers)
        };
        if self.peers.len() >= max_per_torrent {
            tracing::debug!(
                name = %self.info.name,
                addr = %info.addr,
                limit = max_per_torrent,
                "Rejecting peer connection: per-torrent peer cap reached"
            );
            return; // dropping `handle` closes the connection, see peer::spawn
        }
        if let Some(ref m) = self.global_metrics {
            if m.global_peers_connected.load(std::sync::atomic::Ordering::Relaxed) >= max_global {
                tracing::debug!(
                    name = %self.info.name,
                    addr = %info.addr,
                    limit = max_global,
                    "Rejecting peer connection: global peer cap reached"
                );
                return;
            }
        }

        let id = handle.id;
        let num_pieces = self.info.pieces() as usize;
        let our_bitfield = if self.picker.is_complete() {
            Bitfield::full(num_pieces)
        } else {
            let mut bf = Bitfield::new(num_pieces);
            for i in 0..num_pieces {
                if self.picker.have(i as u32) {
                    bf.set(i);
                }
            }
            bf
        };
        let is_seeding = self.picker.is_complete();
        let allowed_fast_vec = compute_allowed_fast_set(
            info.addr.ip(),
            self.info.hash,
            self.info.pieces(),
            10,
        );
        let allowed_fast_set: HashSet<u32> = allowed_fast_vec.iter().copied().collect();
        let addr = info.addr;

        self.peers.insert(
            id,
            PeerState {
                handle: handle.clone(),
                peer_info: info,
                has: Bitfield::new(num_pieces),
                am_choking: true,
                am_interested: false,
                peer_choking: true,
                peer_interested: false,
                in_flight: HashMap::new(),
                consecutive_timeouts: 0,
                is_snubbed: false,
                downloaded_from: 0,
                uploaded_to: 0,
                prev_downloaded_from: 0,
                prev_uploaded_to: 0,
                allowed_fast: allowed_fast_set,
                peer_allowed_fast: HashSet::new(),
                last_received_at: std::time::Instant::now(),
                peer_extensions: HashMap::new(),
            },
        );
        self.pex.peer_connected(addr);

        // BEP 10: Immediately send Extension Handshake message (ID 0). When we already
        // have real metadata (i.e. we're not ourselves awaiting it), advertise its size
        // so a magnet-downloading peer on the other end knows how many pieces to ask
        // for -- see `maybe_request_metadata`, which reads this same field from peers.
        let metadata_size = if self.metadata_fetcher.is_none() {
            Some(self.info.to_info_dict_bytes().len() as u32)
        } else {
            None
        };
        let ext_hs = ExtensionHandshake::for_torrent(self.info.private, metadata_size).encode();
        handle
            .send(Message::Extension {
                id: 0,
                payload: ext_hs,
            })
            .await;

        // BEP 6 Fast Extension: If seeding, send HaveAll, otherwise Bitfield
        if is_seeding {
            handle.send(Message::HaveAll).await;
        } else {
            handle
                .send(Message::Bitfield(Bytes::copy_from_slice(
                    our_bitfield.as_bytes(),
                )))
                .await;
        }

        // BEP 6 Fast Extension: Send AllowedFast piece indices
        for piece_idx in allowed_fast_vec {
            handle.send(Message::AllowedFast(piece_idx)).await;
        }
    }

    fn on_disconnected(&mut self, id: PeerId) {
        let Some(mut peer) = self.peers.remove(&id) else {
            return;
        };
        self.pex.peer_disconnected(peer.peer_info.addr);
        for i in 0..self.info.pieces() {
            if peer.has.has(i as usize) {
                self.picker.peer_lost(i);
            }
        }
        for ((idx, _), _) in peer.in_flight.drain() {
            if !self.picker.have(idx) {
                let any_in_flight = self.peers.values().any(|p| p.in_flight.keys().any(|&(i, _)| i == idx));
                if !any_in_flight {
                    self.picker.mark_missing(idx);
                }
            }
        }
    }

    async fn on_message(&mut self, id: PeerId, msg: Message) {
        tracing::trace!(peer = %id, ?msg, "Torrent actor received message");
        match msg {
            Message::Handshake { .. } | Message::KeepAlive => {}
            Message::Choke => {
                let drained: Vec<u32> = if let Some(p) = self.peers.get_mut(&id) {
                    p.peer_choking = true;
                    p.in_flight.drain().map(|((idx, _), _)| idx).collect()
                } else {
                    Vec::new()
                };
                for idx in &drained {
                    let idx = *idx;
                    if !self.picker.have(idx) {
                        let any_in_flight = self.peers.values().any(|peer| peer.in_flight.keys().any(|&(i, _)| i == idx));
                        if !any_in_flight {
                            self.picker.mark_missing(idx);
                        }
                    }
                }
                if !drained.is_empty() {
                    let other_unchoked: Vec<PeerId> = self.peers.iter()
                        .filter(|(pid, p)| **pid != id && !p.peer_choking)
                        .map(|(pid, _)| *pid)
                        .collect();
                    for other_id in other_unchoked {
                        self.try_request_more(other_id).await;
                    }
                }
            }
            Message::Unchoke => {
                if let Some(p) = self.peers.get_mut(&id) {
                    p.peer_choking = false;
                    p.consecutive_timeouts = 0;
                    p.is_snubbed = false;
                    p.last_received_at = std::time::Instant::now();
                }
                self.try_request_more(id).await;
            }
            Message::Interested => {
                if let Some(p) = self.peers.get_mut(&id) {
                    p.peer_interested = true;
                }
            }
            Message::Uninterested => {
                if let Some(p) = self.peers.get_mut(&id) {
                    p.peer_interested = false;
                }
            }
            Message::Have(index) => {
                let idx_usize = index as usize;
                let already_had = if let Some(p) = self.peers.get_mut(&id) {
                    let had = p.has.has(idx_usize);
                    p.has.set(idx_usize);
                    had
                } else {
                    false
                };
                if !already_had {
                    self.picker.peer_has(index);
                }
                self.maybe_show_interest(id).await;
                let can_request = self.peers.get(&id).map(|p| !p.peer_choking).unwrap_or(false);
                if can_request {
                    self.try_request_more(id).await;
                }
            }
            Message::Bitfield(bits) => {
                if let Some(bf) = Bitfield::from_bytes(&bits, self.info.pieces() as usize) {
                    for i in 0..bf.len() {
                        if bf.has(i) {
                            self.picker.peer_has(i as u32);
                        }
                    }
                    if let Some(p) = self.peers.get_mut(&id) {
                        p.has = bf;
                    }
                }
                self.maybe_show_interest(id).await;
                let can_request = self.peers.get(&id).map(|p| !p.peer_choking).unwrap_or(false);
                if can_request {
                    self.try_request_more(id).await;
                }
            }
            Message::Request { index, begin, length } => {
                self.serve_request(id, index, begin, length).await;
            }
            Message::Piece { index, begin, data } => {
                self.on_block(id, index, begin, data).await;
            }
            Message::HaveAll => {
                let pieces = self.info.pieces() as usize;
                let mut bf = Bitfield::new(pieces);
                for i in 0..pieces {
                    bf.set(i);
                    self.picker.peer_has(i as u32);
                }
                if let Some(p) = self.peers.get_mut(&id) {
                    p.has = bf;
                }
                self.maybe_show_interest(id).await;
                let can_request = self.peers.get(&id).map(|p| !p.peer_choking).unwrap_or(false);
                if can_request {
                    self.try_request_more(id).await;
                }
            }
            Message::HaveNone => {
                if let Some(p) = self.peers.get_mut(&id) {
                    p.has = Bitfield::new(self.info.pieces() as usize);
                }
            }
            Message::SuggestPiece(_) => {
                self.maybe_show_interest(id).await;
            }
            Message::AllowedFast(index) => {
                if let Some(p) = self.peers.get_mut(&id) {
                    p.peer_allowed_fast.insert(index);
                }
                self.maybe_show_interest(id).await;
                self.try_request_more(id).await;
            }
            Message::RejectRequest { index, .. } => {
                self.picker.mark_missing(index);
            }
            Message::Cancel { .. } => {}
            Message::Port(port) => {
                // BEP 5 / BEP 27: DHT port messages must never trigger DHT queries for private torrents.
                tracing::trace!(peer = %id, port, "Received DHT Port message; ignoring per privacy/config");
            }
            Message::Extension { id: ext_id, payload } => {
                // BEP 10 / BEP 11 / BEP 27: Extension messages (including ut_pex) are strictly discarded
                // when info.private is true.
                if self.info.private {
                    tracing::trace!(peer = %id, ext_id, "Ignoring extension message on private swarm (BEP 27)");
                } else if ext_id == 0 {
                    // BEP 10: the peer's own extension handshake. `hs.m` names the ids
                    // *we* must use when sending extension messages *to this peer* --
                    // stored for that purpose (see `maybe_broadcast_pex` and the ut_metadata
                    // request below), independent of the fixed ids we expect incoming
                    // messages addressed to *us* to use (`EXT_ID_UT_METADATA`/`EXT_ID_UT_PEX`).
                    match ExtensionHandshake::decode(&payload) {
                        Ok(hs) => {
                            let their_metadata_id = hs.m.get("ut_metadata").copied();
                            let their_metadata_size = hs.metadata_size;
                            if let Some(p) = self.peers.get_mut(&id) {
                                p.peer_extensions = hs.m;
                            }
                            self.maybe_request_metadata(id, their_metadata_id, their_metadata_size).await;
                        }
                        Err(e) => {
                            tracing::debug!(peer = %id, "Malformed extension handshake: {e}");
                        }
                    }
                } else {
                    match ext_id {
                        EXT_ID_UT_METADATA => {
                            match synapse_wire::UtMetadataMessage::decode(&payload) {
                                Ok(msg) => self.on_ut_metadata_message(id, msg).await,
                                Err(e) => {
                                    tracing::debug!(peer = %id, "Malformed ut_metadata message: {e}");
                                }
                            }
                        }
                        EXT_ID_UT_PEX => {
                            match synapse_wire::UtPexMessage::decode(&payload) {
                                Ok(pex_msg) => {
                                    let discovered = self.pex.ingest_pex_message(pex_msg);
                                    if !discovered.is_empty() {
                                        if let Some(ref tx) = self.on_peers_discovered {
                                            let _ = tx.try_send(discovered);
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(peer = %id, "Malformed ut_pex message: {e}");
                                }
                            }
                        }
                        _ => {
                            tracing::trace!(peer = %id, ext_id, len = payload.len(), "Received unhandled extension message");
                        }
                    }
                }
            }
        }
    }

    async fn maybe_show_interest(&mut self, id: PeerId) {
        let Some(peer) = self.peers.get_mut(&id) else {
            return;
        };
        let wants_something = (0..self.info.pieces())
            .any(|i| peer.has.has(i as usize) && !self.picker.have(i));
        if wants_something && !peer.am_interested {
            peer.am_interested = true;
            peer.handle.send(Message::Interested).await;
        } else if !wants_something && peer.am_interested {
            peer.am_interested = false;
            peer.handle.send(Message::Uninterested).await;
        }
    }

    async fn try_request_more(&mut self, id: PeerId) {
        loop {
            let (is_choking, in_flight_count, is_snubbed, peer_has, peer_allowed_fast) = {
                let Some(peer) = self.peers.get(&id) else {
                    return;
                };
                (
                    peer.peer_choking,
                    peer.in_flight.len(),
                    peer.is_snubbed,
                    peer.has.clone(),
                    peer.peer_allowed_fast.clone(),
                )
            };

            if is_choking {
                let has_missing_allowed_fast = peer_allowed_fast
                    .iter()
                    .any(|&idx| !self.picker.have(idx) && peer_has.has(idx as usize));
                if !has_missing_allowed_fast || in_flight_count >= 2 {
                    return;
                }
            } else {
                let max_allowed = if is_snubbed { 1 } else { self.max_pipeline };
                if in_flight_count >= max_allowed {
                    return;
                }
            }

            let is_endgame = self.picker.pick(&peer_has, false).is_none() && !self.in_progress.is_empty();
            let now = std::time::Instant::now();
            const STEAL_THRESHOLD: Duration = Duration::from_secs(3);

            // 1. Scan in-progress pieces that this peer has for missing blocks
            let mut candidate_block = None;
            for (&idx, in_prog) in &self.in_progress {
                if is_choking && !peer_allowed_fast.contains(&idx) {
                    continue;
                }
                if !self.picker.have(idx) && peer_has.has(idx as usize) {
                    let piece_len = self.info.piece_len(idx);
                    let total_blocks = (piece_len as usize).div_ceil(BLOCK_LEN as usize);
                    if in_prog.received_blocks.len() < total_blocks {
                        for b in 0..total_blocks {
                            let offset = (b * BLOCK_LEN as usize) as u32;
                            if !in_prog.received_blocks.contains(&offset) {
                                let this_peer_in_flight = {
                                    let Some(p) = self.peers.get(&id) else { return; };
                                    p.in_flight.contains_key(&(idx, offset))
                                };
                                if this_peer_in_flight {
                                    continue;
                                }

                                let other_peer_in_flight = self.peers.values().find_map(|p| {
                                    p.in_flight.get(&(idx, offset)).map(|sent_at| (p.is_snubbed, *sent_at))
                                });

                                let should_request = match other_peer_in_flight {
                                    None => true,
                                    Some((other_snubbed, sent_at)) => {
                                        other_snubbed || (now.duration_since(sent_at) >= STEAL_THRESHOLD) || is_endgame
                                    }
                                };

                                if should_request {
                                    candidate_block = Some((idx, offset));
                                    break;
                                }
                            }
                        }
                        if candidate_block.is_some() {
                            break;
                        }
                    }
                }
            }

            let (target_piece, target_offset) = if let Some(target) = candidate_block {
                target
            } else if is_choking {
                let allowed_cand = peer_allowed_fast
                    .iter()
                    .find(|&&idx| !self.picker.have(idx) && !self.in_progress.contains_key(&idx) && peer_has.has(idx as usize));
                match allowed_cand {
                    Some(&idx) => {
                        self.picker.mark_requested(idx);
                        self.in_progress
                            .entry(idx)
                            .or_insert_with(|| InProgressPiece::new(self.info.piece_len(idx)));
                        (idx, 0)
                    }
                    None => return,
                }
            } else {
                // 2. Pick a new piece using rarest-first picker
                match self.picker.pick(&peer_has, false) {
                    Some(idx) => {
                        self.picker.mark_requested(idx);
                        self.in_progress
                            .entry(idx)
                            .or_insert_with(|| InProgressPiece::new(self.info.piece_len(idx)));
                        (idx, 0)
                    }
                    None => return,
                }
            };

            let piece_len = self.info.piece_len(target_piece);
            let begin = target_offset;
            if begin >= piece_len {
                return;
            }
            let length = BLOCK_LEN.min(piece_len - begin);

            if !self.download_bucket.try_consume(length as usize) {
                return;
            }

            let Some(peer) = self.peers.get_mut(&id) else {
                return;
            };

            peer.in_flight.insert((target_piece, begin), std::time::Instant::now());
            let handle = peer.handle.clone();

            handle
                .send(Message::Request {
                    index: target_piece,
                    begin,
                    length,
                })
                .await;
        }
    }

    async fn on_block(&mut self, id: PeerId, index: u32, begin: u32, data: Bytes) {
        let Some(peer) = self.peers.get_mut(&id) else {
            return;
        };
        peer.in_flight.remove(&(index, begin));
        peer.downloaded_from += data.len() as u64;
        peer.consecutive_timeouts = 0;
        peer.is_snubbed = false;
        peer.last_received_at = std::time::Instant::now();

        // Cancel pending duplicate requests for this block from any other peers
        let other_peers_with_block: Vec<(PeerId, PeerHandle)> = self.peers
            .iter_mut()
            .filter_map(|(&p_id, p)| {
                if p_id != id && p.in_flight.remove(&(index, begin)).is_some() {
                    Some((p_id, p.handle.clone()))
                } else {
                    None
                }
            })
            .collect();
        for (other_id, handle) in other_peers_with_block {
            let length = BLOCK_LEN.min(self.info.piece_len(index) - begin);
            let _ = handle.try_send(Message::Cancel { index, begin, length });
            self.try_request_more(other_id).await;
        }

        let Some(piece) = self.in_progress.get_mut(&index) else {
            // Stale/unsolicited block (piece already completed or abandoned) - ignore.
            self.try_request_more(id).await;
            return;
        };
        let start = begin as usize;
        let end = start + data.len();
        if end > piece.buf.len() {
            tracing::warn!(peer = id, index, begin, "block extends past piece end, dropping");
            self.try_request_more(id).await;
            return;
        }
        piece.buf[start..end].copy_from_slice(&data);
        piece.received_blocks.insert(begin);

        if piece.is_complete() {
            self.finish_piece(index).await;
        }
        self.try_request_more(id).await;
    }

    async fn finish_piece(&mut self, index: u32) {
        if self.picker.have(index) {
            return;
        }
        let Some(piece) = self.in_progress.remove(&index) else {
            return;
        };

        let piece_buf = piece.buf;
        let expected_hash = match self.info.piece_hash(index) {
            Some(h) => h,
            None => {
                tracing::warn!(
                    name = %self.info.name,
                    hash = %hex::encode(self.info.hash),
                    index,
                    "missing piece hash for verification, discarding piece"
                );
                self.picker.mark_missing(index);
                return;
            }
        };
        let computed: [u8; 20] = tokio::task::spawn_blocking({
            let buf = piece_buf.clone();
            move || Sha1::digest(&buf).into()
        })
        .await
        .unwrap_or_default();

        if computed != expected_hash {
            tracing::warn!(index, "piece failed hash verification, discarding and re-requesting");
            self.picker.mark_missing(index);
            return;
        }

        let piece_bytes = Bytes::from(piece_buf);
        if let Err(e) = self.write_piece(index, piece_bytes).await {
            tracing::error!(index, "failed to write completed piece to disk: {e}");
            self.picker.mark_missing(index);
            return;
        }

        self.picker.mark_complete(index);
        let piece_len = self.info.piece_len(index) as u64;
        let was_downloading = {
            let mut s = self.stats.write();
            let was_dl = s.state == SwarmState::Downloading;
            s.downloaded_bytes = s.downloaded_bytes.saturating_add(piece_len).min(s.total_size);
            s.progress = if s.total_size > 0 {
                (s.downloaded_bytes as f32) / (s.total_size as f32)
            } else {
                1.0
            };
            if self.picker.is_complete() {
                s.state = SwarmState::Seeding;
                s.tier = SwarmTier::Hot;
            }
            was_dl
        };
        if let Some(ref m) = self.global_metrics {
            m.total_downloaded_bytes.fetch_add(piece_len, std::sync::atomic::Ordering::Relaxed);
            if was_downloading && self.picker.is_complete() {
                m.record_state_transition(&SwarmState::Downloading, &SwarmState::Seeding);
            }
        }
        if let Some(ref tx) = self.on_piece_completed {
            let _ = tx.send(index).await;
        }
        let peer_ids: Vec<PeerId> = self.peers.keys().copied().collect();
        for peer in self.peers.values_mut() {
            peer.handle.send(Message::Have(index)).await;
        }

        if self.picker.is_complete() {
            self.info.evict_piece_hashes();
            if !self.completed_fired {
                self.completed_fired = true;
                for tx in self.on_complete.drain(..) {
                    let _ = tx.send(());
                }
            }
        }

        for peer_id in peer_ids {
            self.try_request_more(peer_id).await;
        }
    }

    async fn write_piece(&self, index: u32, data: Bytes) -> diskio::Result<()> {
        let locations = self.info.block_locations(index, 0, data.len() as u32);
        let jobs = locations
            .into_iter()
            .map(|loc| WriteJob {
                path: Arc::new(self.download_dir.join(&self.info.files[loc.file].path)),
                offset: loc.file_offset,
                data: data.slice(loc.piece_range),
                file_len: self.info.files[loc.file].length,
            })
            .collect();
        self.disk.write_batch(jobs).await
    }

    async fn serve_request(&mut self, id: PeerId, index: u32, begin: u32, length: u32) {
        let Some(peer) = self.peers.get_mut(&id) else {
            return;
        };

        // BEP 6 Fast Extension: If choked and piece is not in allowed_fast, or if piece is missing, reject
        let is_allowed_fast = peer.allowed_fast.contains(&index);
        let have_piece = self.picker.have(index);
        let can_serve = (!peer.am_choking || is_allowed_fast) && have_piece;

        if !can_serve {
            let _ = peer.handle.try_send(Message::RejectRequest {
                index,
                begin,
                length,
            });
            return;
        }

        let locations = self.info.block_locations(index, begin, length);
        let disk = self.disk.clone();
        let upload_bucket = self.upload_bucket.clone();
        let handle = peer.handle.clone();
        let download_dir = self.download_dir.clone();
        let file_paths: Vec<(Arc<PathBuf>, u64, usize, std::ops::Range<usize>)> = locations
            .into_iter()
            .map(|loc| {
                (
                    Arc::new(download_dir.join(&self.info.files[loc.file].path)),
                    loc.file_offset,
                    loc.piece_range.len(),
                    loc.piece_range,
                )
            })
            .collect();

        self.total_uploaded += length as u64;
        peer.uploaded_to += length as u64;
        if let Some(ref m) = self.global_metrics {
            m.total_uploaded_bytes.fetch_add(length as u64, std::sync::atomic::Ordering::Relaxed);
        }

        // Offload disk read + throttling + piece send to non-blocking worker
        tokio::spawn(async move {
            let mut buf = vec![0u8; length as usize];
            for (path, offset, len, piece_range) in file_paths {
                match disk.read(ReadJob { path, offset, len }).await {
                    Ok(data) => buf[piece_range].copy_from_slice(&data),
                    Err(e) => {
                        tracing::error!(index, begin, "failed to read block to serve: {e}");
                        let _ = handle.try_send(Message::RejectRequest {
                            index,
                            begin,
                            length,
                        });
                        return;
                    }
                }
            }

            upload_bucket.consume(length as usize).await;
            let _ = handle
                .send(Message::Piece {
                    index,
                    begin,
                    data: Bytes::from(buf),
                })
                .await;
        });
    }

    /// BEP 9: if this torrent is still awaiting metadata (magnet-added) and the peer
    /// whose handshake we just decoded advertises `ut_metadata` with a known size,
    /// requests every metadata piece we're still missing from them. Idempotent w.r.t.
    /// `metadata_size` (set once) and safe to call again for a later peer if earlier
    /// requests went unanswered -- `missing_pieces()` reflects live fetcher state.
    async fn maybe_request_metadata(&mut self, id: PeerId, their_metadata_id: Option<u8>, their_metadata_size: Option<u32>) {
        let (Some(metadata_id), Some(size)) = (their_metadata_id, their_metadata_size) else {
            return;
        };
        let Some(fetcher) = self.metadata_fetcher.as_mut() else {
            return;
        };
        fetcher.set_metadata_size(size);
        let missing = fetcher.missing_pieces();
        if missing.is_empty() {
            return;
        }
        let Some(peer) = self.peers.get(&id) else {
            return;
        };
        for piece in missing {
            peer.handle
                .send(Message::Extension {
                    id: metadata_id,
                    payload: synapse_wire::UtMetadataMessage::Request { piece }.encode(),
                })
                .await;
        }
    }

    /// BEP 9: handles an incoming `ut_metadata` message. `Data` pieces are fed to the
    /// in-progress `MetadataFetcher`; once fully assembled and hash-verified, the
    /// resolved `Info` is handed to the owning `SwarmEngine` via `on_metadata_resolved`
    /// and this (metadata-only, zero-piece) actor marks itself for shutdown -- the
    /// engine re-adds the torrent under the same info_hash with the real metadata,
    /// spawning a normal downloading `Torrent` actor in its place. `Request`s are
    /// served from our own metadata when we have it (so we can act as a source for
    /// other magnet-downloading peers, and so our own magnet leechers can resolve
    /// metadata from a normal Synapse seeder at all), and rejected when we don't.
    async fn on_ut_metadata_message(&mut self, id: PeerId, msg: synapse_wire::UtMetadataMessage) {
        use synapse_wire::UtMetadataMessage;
        match msg {
            UtMetadataMessage::Request { piece } => {
                let Some(peer) = self.peers.get(&id) else {
                    return;
                };
                let Some(&their_id) = peer.peer_extensions.get("ut_metadata") else {
                    return;
                };
                let response = if self.metadata_fetcher.is_none() {
                    let info_bytes = self.info.to_info_dict_bytes();
                    let piece_start = piece as usize * synapse_wire::UT_METADATA_PIECE_LEN;
                    if piece_start < info_bytes.len() {
                        let piece_end = (piece_start + synapse_wire::UT_METADATA_PIECE_LEN).min(info_bytes.len());
                        UtMetadataMessage::Data {
                            piece,
                            total_size: info_bytes.len() as u32,
                            data: Bytes::copy_from_slice(&info_bytes[piece_start..piece_end]),
                        }
                    } else {
                        UtMetadataMessage::Reject { piece }
                    }
                } else {
                    UtMetadataMessage::Reject { piece }
                };
                peer.handle
                    .send(Message::Extension {
                        id: their_id,
                        payload: response.encode(),
                    })
                    .await;
            }
            UtMetadataMessage::Data { piece, data, .. } => {
                let Some(fetcher) = self.metadata_fetcher.as_mut() else {
                    return;
                };
                match fetcher.add_piece(piece, data) {
                    Ok(Some(info)) => {
                        tracing::info!(name = %info.name, hash = %hex::encode(info.hash), "Magnet metadata resolved via ut_metadata");
                        if let Some(tx) = self.on_metadata_resolved.take() {
                            let _ = tx.send(info);
                        }
                        self.metadata_resolved = true;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(peer = %id, "ut_metadata assembly failed: {e}");
                    }
                }
            }
            UtMetadataMessage::Reject { piece } => {
                tracing::debug!(peer = %id, piece, "Peer rejected ut_metadata request");
            }
        }
    }

    /// BEP 11: every 60s, broadcasts the accumulated added/dropped peer delta to every
    /// connected peer that advertised `ut_pex` support in its own extension handshake.
    /// No-ops on private swarms (`PexManager::generate_pex_message` returns `None`).
    async fn maybe_broadcast_pex(&mut self) {
        const PEX_INTERVAL: Duration = Duration::from_secs(60);
        if self.last_pex_broadcast.elapsed() < PEX_INTERVAL {
            return;
        }
        self.last_pex_broadcast = std::time::Instant::now();

        let Some(msg) = self.pex.generate_pex_message() else {
            return;
        };
        let payload = msg.encode();

        // Per BEP 10, a peer's own handshake `m` dict names the extended message ID
        // *it* wants used when messages are sent to *it* -- not necessarily the ID we
        // declared for ourselves, though most clients pick matching IDs by convention.
        let recipients: Vec<(PeerHandle, u8)> = self
            .peers
            .values()
            .filter_map(|p| p.peer_extensions.get("ut_pex").map(|&ext_id| (p.handle.clone(), ext_id)))
            .collect();

        for (handle, ext_id) in recipients {
            handle
                .send(Message::Extension {
                    id: ext_id,
                    payload: payload.clone(),
                })
                .await;
        }
    }

    /// BEP 19: when this torrent has no connected peers but a webseed is configured,
    /// periodically pulls one missing piece directly over HTTP so a "dead" swarm (or a
    /// freshly-added torrent with no peers yet) can still make progress. Deliberately
    /// scoped to the no-peers case only -- bootstrapping/last-resort, not a permanent
    /// substitute for swarm peers, so it never competes with the peer-based picker for
    /// the same piece (nothing else could be requesting it if there are no peers).
    ///
    /// Note: the HTTP fetch runs inline on the torrent actor's event loop (bounded by a
    /// request timeout) rather than as a background task, since reusing `finish_piece`'s
    /// verification/disk-write/bookkeeping requires `&mut self`. This only blocks new
    /// peer connections to this specific torrent for the duration of one piece fetch,
    /// and only while it has zero peers to service anyway.
    async fn maybe_fetch_via_webseed(&mut self) {
        if !self.peers.is_empty() || self.picker.is_complete() {
            return;
        }
        let Some(ref webseed) = self.webseed else {
            return;
        };
        if !webseed.has_webseeds() || self.last_webseed_attempt.elapsed() < WEBSEED_RETRY_INTERVAL {
            return;
        }
        self.last_webseed_attempt = std::time::Instant::now();

        let full = Bitfield::full(self.info.pieces() as usize);
        let Some(index) = self.picker.pick(&full, false) else {
            return;
        };

        self.fetch_piece_via_webseed(index).await;
    }

    async fn fetch_piece_via_webseed(&mut self, index: u32) {
        let Some((seed_idx, base_url)) = self.webseed.as_ref().and_then(|w| w.pick_active_seed()) else {
            return;
        };

        self.picker.mark_requested(index);

        let piece_len = self.info.piece_len(index);
        let locations = self.info.block_locations(index, 0, piece_len);
        let single_file = self.info.files.len() == 1;
        let mut buf = vec![0u8; piece_len as usize];

        for loc in &locations {
            let file_path_rel = if single_file {
                None
            } else {
                Some(self.info.files[loc.file].path.to_string_lossy().into_owned())
            };

            let range_request = self.webseed.as_ref().unwrap().format_range_request(
                &base_url,
                file_path_rel.as_deref(),
                loc.file_offset,
                loc.piece_range.len() as u32,
            );
            let (target_url, range_header) = match range_request {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(index, "webseed URL formatting failed: {e}");
                    self.webseed.as_mut().unwrap().on_failure(seed_idx);
                    self.picker.mark_missing(index);
                    return;
                }
            };

            let result = self
                .http_client
                .get(target_url)
                .header(reqwest::header::RANGE, range_header)
                .timeout(Duration::from_secs(20))
                .send()
                .await;

            let fetched = match result {
                Ok(resp) if resp.status().is_success() => resp.bytes().await.ok(),
                _ => None,
            };

            match fetched {
                Some(data) if data.len() == loc.piece_range.len() => {
                    buf[loc.piece_range.clone()].copy_from_slice(&data);
                }
                _ => {
                    tracing::debug!(index, url = %base_url, "webseed piece fetch failed");
                    self.webseed.as_mut().unwrap().on_failure(seed_idx);
                    self.picker.mark_missing(index);
                    return;
                }
            }
        }

        self.webseed.as_mut().unwrap().on_success(seed_idx);
        self.in_progress.insert(
            index,
            InProgressPiece {
                buf,
                received_blocks: HashSet::new(),
                expected_blocks: 0,
            },
        );
        self.finish_piece(index).await;
    }

    async fn tick(&mut self) {
        self.maybe_broadcast_pex().await;
        self.maybe_fetch_via_webseed().await;

        let we_are_seeding = self.picker.is_complete();
        let stats: Vec<PeerStats<PeerId>> = self
            .peers
            .iter()
            .map(|(id, p)| PeerStats {
                id: *id,
                download_rate: p.downloaded_from,
                upload_rate: p.uploaded_to,
                interested: p.peer_interested,
            })
            .collect();
        let ChokeDecisions { unchoke, choke } = self.choker.rechoke(&stats, we_are_seeding);

        for id in unchoke {
            if let Some(p) = self.peers.get_mut(&id) {
                if p.am_choking {
                    p.am_choking = false;
                    p.handle.send(Message::Unchoke).await;
                }
            }
        }
        for id in choke {
            if let Some(p) = self.peers.get_mut(&id) {
                if !p.am_choking {
                    p.am_choking = true;
                    p.handle.send(Message::Choke).await;
                }
            }
        }

        // Evict stalled block requests (5s timeout) and wake up unchoked peers to request more
        if !we_are_seeding {
            const BLOCK_TIMEOUT: Duration = Duration::from_secs(5);
            let now = std::time::Instant::now();
            let mut active_peers = Vec::new();
            let mut timed_out_pieces = std::collections::HashSet::new();
            let mut stalled_peers_to_disconnect = Vec::new();

            let total_peers = self.peers.len();
            for (peer_id, peer) in self.peers.iter_mut() {
                let mut timed_out_blocks = Vec::new();
                peer.in_flight.retain(|&(idx, offset), sent_at| {
                    let timed_out = now.duration_since(*sent_at) >= BLOCK_TIMEOUT;
                    if timed_out {
                        timed_out_blocks.push((idx, offset));
                        timed_out_pieces.insert(idx);
                    }
                    !timed_out
                });

                if !timed_out_blocks.is_empty() {
                    peer.consecutive_timeouts += 1;
                    if peer.consecutive_timeouts >= 2 {
                        peer.is_snubbed = true;
                    }
                    for (idx, offset) in timed_out_blocks {
                        let length = BLOCK_LEN.min(self.info.piece_len(idx) - offset);
                        let _ = peer.handle.try_send(Message::Cancel {
                            index: idx,
                            begin: offset,
                            length,
                        });
                    }
                    if peer.consecutive_timeouts >= 4 {
                        // 20s of sustained timeouts without a single block delivered: disconnect stalled peer
                        stalled_peers_to_disconnect.push(*peer_id);
                        continue;
                    }
                }

                // Evict persistently choked peers:
                // If downloading, we are interested in this peer, but the peer has kept us choked
                // with 0 blocks in-flight for >= 90 seconds, and we have >= 12 connected peers,
                // disconnect this peer to free a slot for candidate peers to be dialed.
                if peer.am_interested
                    && peer.peer_choking
                    && peer.in_flight.is_empty()
                    && now.duration_since(peer.last_received_at) >= Duration::from_secs(90)
                    && total_peers >= 12
                {
                    stalled_peers_to_disconnect.push(*peer_id);
                    continue;
                }

                let max_allowed = if peer.is_snubbed { 1 } else { self.max_pipeline };
                if !peer.peer_choking && peer.in_flight.len() < max_allowed {
                    active_peers.push(*peer_id);
                }
            }

            for peer_id in stalled_peers_to_disconnect {
                tracing::warn!(peer = peer_id, "disconnecting unresponsive/stalled peer after repeated request timeouts");
                self.on_disconnected(peer_id);
            }

            for idx in timed_out_pieces {
                let piece_still_in_flight = self.peers.values().any(|p| {
                    p.in_flight.keys().any(|&(piece_idx, _)| piece_idx == idx)
                });
                if !piece_still_in_flight && !self.picker.have(idx) {
                    self.picker.mark_missing(idx);
                }
            }

            for peer_id in active_peers {
                if self.peers.contains_key(&peer_id) {
                    self.try_request_more(peer_id).await;
                }
            }
        }

        self.publish_live_stats();
    }

    /// Recomputes and writes the rate/peer/ETA/ratio fields of the shared `SwarmStats` every
    /// tick — these used to be written once at add-time (all zero) and never touched again, so
    /// every subscriber watching a downloading/seeding torrent saw a permanently frozen 0 B/s
    /// no matter how much data was actually moving.
    fn publish_live_stats(&mut self) {
        let tick_secs = self.tick_interval.as_secs_f64().max(0.001);
        let mut rate_download = 0u64;
        let mut rate_upload = 0u64;
        let mut peers_sending = 0usize;
        let mut peer_snapshots = Vec::with_capacity(self.peers.len());
        let total_pieces = self.info.pieces().max(1) as f32;

        for peer in self.peers.values_mut() {
            let dl_delta = peer.downloaded_from.saturating_sub(peer.prev_downloaded_from);
            let ul_delta = peer.uploaded_to.saturating_sub(peer.prev_uploaded_to);
            let p_rate_dl = (dl_delta as f64 / tick_secs) as u64;
            let p_rate_ul = (ul_delta as f64 / tick_secs) as u64;
            rate_download += p_rate_dl;
            rate_upload += p_rate_ul;
            peer.prev_downloaded_from = peer.downloaded_from;
            peer.prev_uploaded_to = peer.uploaded_to;
            if dl_delta > 0 {
                peers_sending += 1;
            }

            let mut flags = String::new();
            if !peer.peer_choking && peer.am_interested {
                flags.push('D');
            } else if peer.peer_choking && peer.am_interested {
                flags.push('d');
            }
            if !peer.am_choking && peer.peer_interested {
                flags.push('U');
            } else if peer.am_choking && peer.peer_interested {
                flags.push('u');
            }
            if peer.has.is_complete() {
                flags.push('H');
            }
            let supports_pex = peer.peer_extensions.contains_key("ut_pex");
            if supports_pex {
                flags.push('X');
            }
            if flags.is_empty() {
                flags.push('?');
            }

            let peer_progress = peer.has.count_ones() as f32 / total_pieces;

            peer_snapshots.push(PeerSnapshot {
                addr: peer.handle.addr,
                client_name: parse_client_name(&peer.peer_info.peer_id),
                flags,
                rate_to_client: p_rate_dl,
                rate_to_peer: p_rate_ul,
                progress: peer_progress.min(1.0),
                is_encrypted: false,
                is_utp: false,
                supports_pex,
            });
        }

        *self.live_peers.write() = peer_snapshots;
        *self.piece_availability.write() = self.picker.availability().to_vec();

        let (prev_dl, prev_ul, prev_peers) = {
            let mut s = self.stats.write();
            let prev = (s.download_rate, s.upload_rate, s.peers_connected);
            s.download_rate = rate_download;
            s.upload_rate = rate_upload;
            s.uploaded_bytes = self.total_uploaded;
            s.peers_connected = self.peers.len();
            s.peers_sending = peers_sending;
            if rate_download > 0 || rate_upload > 0 {
                s.last_transfer_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
            }
            s.ratio = if s.downloaded_bytes > 0 {
                s.uploaded_bytes as f32 / s.downloaded_bytes as f32
            } else if s.total_size > 0 && s.uploaded_bytes > 0 {
                s.uploaded_bytes as f32 / s.total_size as f32
            } else {
                0.0
            };
            s.eta_seconds = if rate_download > 0 && s.downloaded_bytes < s.total_size {
                (s.total_size - s.downloaded_bytes) / rate_download
            } else {
                0
            };
            prev
        };

        if let Some(ref m) = self.global_metrics {
            m.record_rate_change(
                prev_dl,
                rate_download,
                prev_ul,
                rate_upload,
                prev_peers,
                self.peers.len(),
            );
        }
    }

    fn apply_file_priority(&mut self, file_idx: u32, priority: u8) {
        let Some((start, end)) = self.info.piece_range_for_file(file_idx as usize) else {
            tracing::warn!(name = %self.info.name, file_idx, "set_file_priority: no such file index");
            return;
        };
        // The picker only supports a wanted/not-wanted mask today, not the proto's full
        // four-level weighting (0=skip, 1=low, 4=normal, 7=high) — 0 deselects, anything else
        // (re)selects. Differentiating low/normal/high within "wanted" would mean teaching the
        // picker to weight candidates by priority, not just filter them; that's a real further
        // improvement but a bigger change than restoring basic file selection.
        let wanted = priority > 0;
        self.picker.set_piece_range_priority(start, end, wanted);
        tracing::info!(name = %self.info.name, file_idx, priority, wanted, "applied file priority");
    }

    /// Re-verifies every piece already on disk against the torrent's real hashes and rebuilds
    /// picker/bitfield state to match — previously `recheck` just flipped the reported state
    /// to `Checking` for cosmetic effect and never actually looked at the files on disk.
    async fn handle_recheck(&mut self) {
        tracing::info!(name = %self.info.name, "recheck starting");
        self.stats.write().state = SwarmState::Checking;

        let total = self.info.pieces();
        let mut new_bitfield = Bitfield::new(total as usize);
        for idx in 0..total {
            let piece_len = self.info.piece_len(idx);
            let locations = self.info.block_locations(idx, 0, piece_len);
            let mut buf = vec![0u8; piece_len as usize];
            let mut read_ok = true;
            for loc in &locations {
                let path = Arc::new(self.download_dir.join(&self.info.files[loc.file].path));
                match self.disk.read(ReadJob { path, offset: loc.file_offset, len: loc.piece_range.len() }).await {
                    Ok(data) => buf[loc.piece_range.clone()].copy_from_slice(&data),
                    Err(_) => read_ok = false,
                }
            }

            let verified = read_ok && {
                if let Some(expected) = self.info.piece_hash(idx) {
                    let computed: [u8; 20] = tokio::task::spawn_blocking({
                        let buf = buf.clone();
                        move || Sha1::digest(&buf).into()
                    })
                    .await
                    .unwrap_or_default();
                    computed == expected
                } else {
                    false
                }
            };

            if verified {
                self.picker.mark_complete(idx);
                new_bitfield.set(idx as usize);
            } else {
                // `mark_missing` only demotes an in-flight `Requested` piece — a previously
                // `Complete` piece that just failed re-verification (corrupted on disk since)
                // needs to be forced back regardless of its prior state.
                self.picker.force_missing(idx);
            }
        }

        // Every in-flight request/partial-piece buffer refers to pre-recheck state; discard
        // it all and let peers get fresh requests next tick.
        self.in_progress.clear();
        for peer in self.peers.values_mut() {
            peer.in_flight.clear();
            peer.consecutive_timeouts = 0;
            peer.is_snubbed = false;
        }

        let completed_count = self.picker.completed_count();
        let progress = if total > 0 { completed_count as f32 / total as f32 } else { 1.0 };
        let is_complete = self.picker.is_complete();

        *self.bitfield.write() = Some(RoaringBitfield::from_bitfield(&new_bitfield));
        {
            let mut s = self.stats.write();
            s.progress = progress;
            s.downloaded_bytes = ((progress as f64) * (self.info.total_len as f64)) as u64;
            s.state = if is_complete { SwarmState::Seeding } else { SwarmState::Downloading };
        }

        tracing::info!(name = %self.info.name, progress, is_complete, "recheck complete");

        if is_complete {
            self.info.evict_piece_hashes();
            if !self.completed_fired {
                self.completed_fired = true;
                for tx in self.on_complete.drain(..) {
                    let _ = tx.send(());
                }
            }
        }
    }

    /// Moves every already-downloaded file from the current download directory to `new_dir`.
    /// Tries a same-filesystem rename first, falling back to copy+remove across devices; if
    /// any file fails partway through, already-moved files are moved back so the torrent is
    /// left entirely at the old location rather than split across both.
    async fn handle_set_location(&mut self, new_dir: PathBuf) {
        if new_dir == self.download_dir {
            return;
        }
        tracing::info!(name = %self.info.name, from = %self.download_dir.display(), to = %new_dir.display(), "moving torrent data");

        if let Err(e) = tokio::fs::create_dir_all(&new_dir).await {
            tracing::error!(name = %self.info.name, "set_location: failed to create destination directory {}: {}", new_dir.display(), e);
            return;
        }

        let mut moved: Vec<(PathBuf, PathBuf)> = Vec::new();
        for file in &self.info.files {
            let src = self.download_dir.join(&file.path);
            let dst = new_dir.join(&file.path);

            if !tokio::fs::try_exists(&src).await.unwrap_or(false) {
                continue; // not downloaded yet (or already gone) — nothing to move
            }
            if let Some(parent) = dst.parent() {
                if let Err(e) = tokio::fs::create_dir_all(parent).await {
                    tracing::error!(name = %self.info.name, "set_location: failed to create {}: {}, rolling back", parent.display(), e);
                    Self::rollback_moves(&moved).await;
                    return;
                }
            }
            if let Err(rename_err) = tokio::fs::rename(&src, &dst).await {
                if let Err(copy_err) = tokio::fs::copy(&src, &dst).await {
                    tracing::error!(
                        name = %self.info.name,
                        "set_location: failed to move {} (rename: {}, copy: {}), rolling back",
                        src.display(), rename_err, copy_err
                    );
                    Self::rollback_moves(&moved).await;
                    return;
                }
                if let Err(e) = tokio::fs::remove_file(&src).await {
                    tracing::warn!(name = %self.info.name, "set_location: copied {} but couldn't remove original {}: {}", dst.display(), src.display(), e);
                }
            }
            moved.push((src, dst));
        }

        self.download_dir = new_dir.clone();
        self.stats.write().download_dir = new_dir.to_string_lossy().to_string();
        tracing::info!(name = %self.info.name, files_moved = moved.len(), "torrent data moved successfully");
    }

    async fn rollback_moves(moved: &[(PathBuf, PathBuf)]) {
        for (src, dst) in moved.iter().rev() {
            if tokio::fs::rename(dst, src).await.is_err() {
                let _ = tokio::fs::copy(dst, src).await;
                let _ = tokio::fs::remove_file(dst).await;
            }
        }
    }
}
