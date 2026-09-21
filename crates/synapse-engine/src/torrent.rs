//! The per-torrent state machine: owns the picker/choker, tracks per-peer state, and
//! drives requesting/serving pieces. Replaces the pre-rewrite codebase's `Control`
//! struct + `CIO` trait + `amy`-based event loop (see `doc/REWRITE_ROADMAP.md` Part 1)
//! with a plain tokio task that `select!`s between peer events and a periodic tick.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use parking_lot::RwLock;
use sha1::{Digest, Sha1};
use tokio::sync::{mpsc, oneshot};

use diskio::{DiskEngine, ReadJob, WriteJob};
use synapse_meta::Info;
use synapse_picker::{
    Bitfield, ChokeDecisions, Choker, Mode, PeerStats, Picker, RoaringBitfield, SuperSeeder,
};

use crate::ratelimit::TokenBucket;
use crate::swarm::{SwarmState, SwarmStats, SwarmTier};
use synapse_wire::{ExtensionHandshake, Message};

use crate::fast_ext::compute_allowed_fast_set;
use crate::peer::{parse_client_name, PeerEvent, PeerHandle, PeerId, PeerInfo};
use std::net::SocketAddr;

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
    #[serde(default)]
    pub peer_interested: bool,
}

/// Conventional BitTorrent block size. Requests are always made in blocks of this size
/// (the last block of a piece may be shorter).
const BLOCK_LEN: u32 = 16 * 1024;

/// Largest block we will serve for a single `Request`. Anything bigger is a protocol
/// violation (or an allocation-amplification probe) and is rejected.
const MAX_REQUEST_LEN: u32 = BLOCK_LEN;

/// Cap on requests from one peer that are simultaneously being served (disk read,
/// upload throttling, send). Matches libtorrent's `max_out_request_queue` on the
/// requesting side, so a well-behaved leecher never hits it.
const MAX_PENDING_SERVES_PER_PEER: usize = 500;

/// Cap across the whole torrent, bounding worst-case buffered upload memory
/// (`MAX_PENDING_SERVES_TOTAL * MAX_REQUEST_LEN` = 32 MiB).
const MAX_PENDING_SERVES_TOTAL: usize = 2048;

/// Trust points lost by every contributor to a piece that fails its hash check
/// (libtorrent: `peer_info::trust_points -= 2`).
const TRUST_PENALTY: i32 = 2;
/// A peer whose trust falls to this value is banned.
const TRUST_BAN_THRESHOLD: i32 = -7;
/// Ceiling on accumulated trust, so a long good history cannot buy unlimited poisoning.
const TRUST_MAX: i32 = 8;
/// Bound on remembered per-address trust entries (only misbehaving addresses are kept
/// once this is exceeded).
const MAX_TRUST_ENTRIES: usize = 10_000;

/// A connection over which no piece data has moved in either direction for this long is
/// closed to free the slot, in every torrent state including seeding (libtorrent's
/// `inactivity_timeout`).
#[cfg(not(test))]
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(600);
/// Reads a complete file from disk and builds its block-level Merkle tree, returning it only if
/// it reproduces the file's `pieces root` (a modified or truncated file yields `None`).
async fn build_block_tree(
    disk: Arc<DiskEngine>,
    path: PathBuf,
    len: u64,
    expected_root: [u8; 32],
) -> Option<synapse_meta::merkle::BlockTree> {
    const CHUNK: u64 = 64 * synapse_meta::merkle::BLOCK_SIZE as u64;
    let path = Arc::new(path);
    let mut leaves =
        Vec::with_capacity(len.div_ceil(synapse_meta::merkle::BLOCK_SIZE as u64) as usize);
    let mut offset = 0u64;
    while offset < len {
        let take = CHUNK.min(len - offset) as usize;
        let data = disk
            .read(ReadJob {
                path: path.clone(),
                offset,
                len: take,
            })
            .await
            .ok()?;
        if data.len() != take {
            return None;
        }
        leaves.extend(
            data.chunks(synapse_meta::merkle::BLOCK_SIZE)
                .map(synapse_meta::merkle::hash_block),
        );
        offset += take as u64;
    }
    let tree = synapse_meta::merkle::BlockTree::from_leaves(leaves)?;
    (tree.root() == expected_root).then_some(tree)
}

#[cfg(test)]
const INACTIVITY_TIMEOUT: Duration = Duration::from_millis(500);

/// How often connected peers are re-checked against the IP filter and ban list.
#[cfg(not(test))]
const IP_FILTER_SWEEP_INTERVAL: Duration = Duration::from_secs(5);
#[cfg(test)]
const IP_FILTER_SWEEP_INTERVAL: Duration = Duration::from_millis(100);

/// Most hashes a BEP 52 `hash request` may ask for (the limit BEP 52 sets).
const MAX_HASHES_PER_REQUEST: usize = 512;
/// Piece-layer fetches driven at once when a torrent has many files.
const MAX_CONCURRENT_LAYER_FETCHES: usize = 8;
/// Strikes for a `hashes` message that fails verification (see `invalid_requests`).
const INVALID_HASHES_STRIKES: u32 = 20;
/// Largest file whose block-level Merkle tree we will build to answer `hash request`s.
const MAX_BLOCK_TREE_FILE: u64 = 16 << 30;
/// Block trees kept in memory at once.
const MAX_CACHED_BLOCK_TREES: usize = 4;
/// Block-layer requests waiting for a tree to finish building.
const MAX_PENDING_BLOCK_REQUESTS: usize = 64;

/// A pending attempt to find which block of a failed piece is corrupt (BEP 52).
struct BlockAudit {
    piece: u32,
    /// The piece as received, without padding.
    data: Vec<u8>,
    contributors: HashMap<u32, IpAddr>,
    count: u32,
    /// Nodes on the file's leaf layer (padded), for checking the proof.
    level_size: usize,
    deadline: std::time::Instant,
}

/// Block-hash audits in flight at once, and how long one may wait for its answer.
const MAX_BLOCK_AUDITS: usize = 8;
const BLOCK_AUDIT_TIMEOUT: Duration = Duration::from_secs(30);

/// A `hash request` waiting for its file's block tree.
struct PendingHashRequest {
    peer: PeerId,
    pieces_root: [u8; 32],
    base_layer: u32,
    index: u32,
    count: u32,
    proof_layers: u32,
}

/// Minimum spacing between accepted `ut_pex` messages from one peer. BEP 11 senders
/// gossip about once a minute; a peer sending faster is flooding the candidate pool.
const MIN_PEX_INTERVAL: Duration = Duration::from_secs(10);

/// A peer whose invalid-request strike count exceeds this is disconnected.
/// Strikes decay by one for every request we serve successfully, so a legitimate peer
/// that occasionally races a choke never accumulates them.
const MAX_INVALID_REQUESTS: u32 = 300;

/// Returns true when `(index, begin, length)` describes a block that lies entirely
/// inside an existing piece and is no larger than `MAX_REQUEST_LEN`.
///
/// `piece_len` is the length of piece `index` (the last piece may be short), or `None`
/// when `index` is out of range.
fn request_in_bounds(piece_len: Option<u32>, begin: u32, length: u32) -> bool {
    let Some(piece_len) = piece_len else {
        return false;
    };
    length > 0
        && length <= MAX_REQUEST_LEN
        && u64::from(begin) + u64::from(length) <= u64::from(piece_len)
}

/// Releases a peer's and the torrent's pending-serve slots when the serving task ends,
/// including on early return or cancellation.
struct ServeSlot {
    peer: Arc<AtomicUsize>,
    total: Arc<AtomicUsize>,
}

impl Drop for ServeSlot {
    fn drop(&mut self) {
        self.peer.fetch_sub(1, Ordering::Relaxed);
        self.total.fetch_sub(1, Ordering::Relaxed);
    }
}

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
const EXT_ID_UT_HOLEPUNCH: u8 = 3;
const EXT_ID_LT_DONTHAVE: u8 = 4;
/// BEP 30 Merkle torrents: blocks (and, for the first block of a piece, its hash list).
const EXT_ID_TR_HASHPIECE: u8 = 6;

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
    /// Switches the piece picker between rarest-first and sequential.
    SetSequential(bool),
    /// Stops the torrent actor: closes all peer handles to terminate connection tasks and exits the actor loop.
    Stop,
    /// Dynamically update regular unchoke slots allocated by the session choker.
    SetUnchokeSlots(usize),
    /// Dynamically update the seed-side choking algorithm.
    SetSeedChokingAlgorithm(synapse_picker::SeedChokingAlgorithm),
    /// Dynamically update per-torrent rate limits (0 = unlimited).
    SetRateLimits {
        download_limit_bytes: u64,
        upload_limit_bytes: u64,
    },
    /// Dynamically update per-peer rate limits (0 = unlimited).
    SetPeerRateLimits {
        peer_id: PeerId,
        download_limit_bytes: u64,
        upload_limit_bytes: u64,
    },
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
    /// BEP 9: fires once when a magnet-added torrent (constructed with a placeholder
    /// `Info` that has no files) finishes assembling and verifying its real metadata
    /// over the wire. `None` for a normal torrent that already has full metadata.
    pub on_metadata_resolved: Option<oneshot::Sender<Info>>,
    /// Shared list of addresses banned for corrupt data (smart-ban); consulted on every
    /// new connection and added to when a peer is caught poisoning pieces.
    pub ban_list: Arc<crate::banlist::BanList>,
    /// Shared IP blocklist. Checked on every new connection and re-applied to existing
    /// peers whenever it may have changed, so a filter update takes effect immediately
    /// rather than only for future connections.
    pub ip_filter: Arc<RwLock<crate::ipfilter::IpFilter>>,
    /// BEP super-seeding mode. When enabled, seeder advertises pieces selectively to accelerate distribution.
    pub super_seeding: bool,
    /// BEP 38 local webseed cache resolver.
    pub local_webseed_resolver: Option<Arc<crate::local_webseed::LocalWebSeedResolver>>,
    /// Broadcaster for session alerts.
    pub alert_sender: Option<tokio::sync::broadcast::Sender<crate::alert::Alert>>,
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
    /// When piece data last moved with this peer (a block accepted from it or a request
    /// served to it); seeded with the connect time. Drives `INACTIVITY_TIMEOUT`.
    last_useful_at: std::time::Instant,
    /// When we last accepted a `ut_pex` message from this peer; see `MIN_PEX_INTERVAL`.
    last_pex_at: Option<std::time::Instant>,
    /// `metadata_size` from this peer's extension handshake (BEP 9), if it declared one.
    peer_metadata_size: Option<u32>,
    /// Requests from this peer currently being served; bounded by `MAX_PENDING_SERVES_PER_PEER`.
    pending_serves: Arc<AtomicUsize>,
    /// Strikes for malformed, over-limit, or unservable requests; see `MAX_INVALID_REQUESTS`.
    invalid_requests: u32,
    /// Whether this peer is a pure or partial seed that does not download blocks (BEP 21).
    is_upload_only: bool,
    /// BEP 6 Fast Extension suggested pieces from this peer.
    suggested_pieces: HashSet<u32>,
    /// Last piece index requested from this peer (drives extent affinity).
    last_requested_piece: Option<u32>,
}

struct InProgressPiece {
    buf: Vec<u8>,
    received_blocks: HashSet<u32>,
    expected_blocks: usize,
    /// Which address supplied each received block (keyed by block offset). If the piece
    /// then fails its hash check this is how smart-ban knows whom to blame.
    contributors: HashMap<u32, IpAddr>,
}

impl InProgressPiece {
    fn new(piece_len: u32) -> InProgressPiece {
        let expected_blocks = (piece_len as usize).div_ceil(BLOCK_LEN as usize);
        InProgressPiece {
            buf: vec![0u8; piece_len as usize],
            received_blocks: HashSet::with_capacity(expected_blocks),
            expected_blocks,
            contributors: HashMap::with_capacity(expected_blocks),
        }
    }

    fn is_complete(&self) -> bool {
        self.received_blocks.len() == self.expected_blocks
    }
}

struct BlockReadSlice {
    path: Arc<PathBuf>,
    offset: u64,
    len: usize,
    piece_range: std::ops::Range<usize>,
    is_padding: bool,
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
    global_download_bucket: Arc<TokenBucket>,
    global_upload_bucket: Arc<TokenBucket>,
    torrent_download_bucket: Arc<TokenBucket>,
    torrent_upload_bucket: Arc<TokenBucket>,
    peer_download_buckets: HashMap<PeerId, Arc<TokenBucket>>,
    peer_upload_buckets: HashMap<PeerId, Arc<TokenBucket>>,
    global_metrics: Option<Arc<crate::swarm::GlobalEngineMetrics>>,
    /// Running total, independent of any single peer's `uploaded_to` — a per-peer counter is
    /// lost when that peer disconnects (`on_disconnected` drops its `PeerState`), so this is
    /// tracked separately to survive peer churn across the torrent's lifetime.
    total_uploaded: u64,
    /// Requests being served across all peers; bounded by `MAX_PENDING_SERVES_TOTAL`.
    pending_serves_total: Arc<AtomicUsize>,
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
    metadata_fetcher: Option<crate::metadata::MetadataFetcher>,
    /// Bencoded info dict served to BEP 9 requesters, built on first use.
    info_dict_cache: Option<Bytes>,
    ban_list: Arc<crate::banlist::BanList>,
    ip_filter: Arc<RwLock<crate::ipfilter::IpFilter>>,
    last_ip_filter_sweep: std::time::Instant,
    /// Our own peer id, to recognise a connection to ourselves.
    our_peer_id: [u8; 20],
    /// Smart-ban trust per address; absent means neutral (0).
    peer_trust: HashMap<IpAddr, i32>,
    /// Addresses that contributed to a failed piece. While on parole a peer only receives
    /// pieces no one else touches, so a repeat failure is attributable to it alone.
    parole: HashSet<IpAddr>,
    /// Pieces being downloaded exclusively from one (paroled) address.
    exclusive_pieces: HashMap<u32, IpAddr>,
    on_metadata_resolved: Option<oneshot::Sender<Info>>,
    metadata_resolved: bool,
    dynamic_piece_layers: HashMap<[u8; 32], Vec<u8>>,
    /// Piece layers still being fetched from peers, one per file (pure-v2 magnet).
    layer_fetches: Vec<crate::v2_layers::LayerFetch>,
    /// Priority of each file (0 = skip), the input to per-piece priorities.
    file_priorities: Vec<u8>,
    /// Cached proof-capable Merkle trees for answering hash requests.
    layer_trees: HashMap<[u8; 32], Arc<synapse_meta::merkle::PieceLayerTree>>,
    /// Full block-level trees of complete files, built on demand for `hash request`s below the
    /// piece layer.
    block_trees: HashMap<[u8; 32], Arc<synapse_meta::merkle::BlockTree>>,
    /// The file (by pieces root) whose block tree is being built right now, if any.
    block_tree_building: Option<[u8; 32]>,
    pending_block_requests: Vec<PendingHashRequest>,
    block_tree_tx: mpsc::Sender<([u8; 32], Option<synapse_meta::merkle::BlockTree>)>,
    block_tree_rx: Option<mpsc::Receiver<([u8; 32], Option<synapse_meta::merkle::BlockTree>)>>,
    /// BEP 30: piece hashes proven against the root by a received hash list, and (for a
    /// seeder) the whole tree once built from the data on disk.
    merkle_hashes: HashMap<u32, [u8; 20]>,
    merkle_tree: Option<Arc<synapse_meta::merkle_v1::MerkleTreeV1>>,
    merkle_building: bool,
    merkle_tx: mpsc::Sender<Option<synapse_meta::merkle_v1::MerkleTreeV1>>,
    merkle_rx: Option<mpsc::Receiver<Option<synapse_meta::merkle_v1::MerkleTreeV1>>>,
    super_seeder: Option<SuperSeeder>,
    local_webseed_resolver: Option<Arc<crate::local_webseed::LocalWebSeedResolver>>,
    pub part_file: crate::part_file::PartFileManager,
    alert_sender: Option<tokio::sync::broadcast::Sender<crate::alert::Alert>>,
    /// Outstanding requests for block-level hashes to pinpoint a corrupt block, by
    /// `(peer asked, file root, first block)`. Only that peer's reply, and only if its proof
    /// checks out, is used.
    pending_block_audits: HashMap<(PeerId, [u8; 32], u32), BlockAudit>,
}

impl Torrent {
    pub fn new(config: TorrentConfig, have: Option<&Bitfield>) -> Torrent {
        let total_pieces = config.info.pieces();
        let mut picker = Picker::new(total_pieces as usize, config.mode);
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
        let layer_fetches = Self::initial_layer_fetches(&config.info);
        let mut file_priorities = vec![4u8; config.info.files.len()];
        if let Some(ref select_only) = config.info.select_only {
            for (i, p) in file_priorities.iter_mut().enumerate() {
                if !select_only.contains(&i) {
                    *p = 0;
                }
            }
        }
        let metadata_fetcher = if config.info.files.is_empty() {
            Some(
                crate::metadata::MetadataFetcher::new(config.info.hash)
                    .with_v2_hash(config.info.info_hash_v2),
            )
        } else {
            None
        };
        let part_file =
            crate::part_file::PartFileManager::new(config.download_dir.clone(), config.info.hash);
        let (block_tree_tx, block_tree_rx) = mpsc::channel(4);
        let (merkle_tx, merkle_rx) = mpsc::channel(1);
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
            global_download_bucket: config.download_bucket,
            global_upload_bucket: config.upload_bucket,
            torrent_download_bucket: Arc::new(TokenBucket::unthrottled()),
            torrent_upload_bucket: Arc::new(TokenBucket::unthrottled()),
            peer_download_buckets: HashMap::new(),
            peer_upload_buckets: HashMap::new(),
            global_metrics: config.global_metrics,
            total_uploaded: starting_uploaded,
            pending_serves_total: Arc::new(AtomicUsize::new(0)),
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
            metadata_fetcher,
            info_dict_cache: None,
            ban_list: config.ban_list,
            ip_filter: config.ip_filter,
            last_ip_filter_sweep: std::time::Instant::now(),
            our_peer_id: config.peer_id,
            peer_trust: HashMap::new(),
            parole: HashSet::new(),
            exclusive_pieces: HashMap::new(),
            on_metadata_resolved: config.on_metadata_resolved,
            metadata_resolved: false,
            dynamic_piece_layers: HashMap::new(),
            layer_fetches,
            file_priorities,
            layer_trees: HashMap::new(),
            block_trees: HashMap::new(),
            block_tree_building: None,
            pending_block_requests: Vec::new(),
            block_tree_tx,
            block_tree_rx: Some(block_tree_rx),
            merkle_hashes: HashMap::new(),
            merkle_tree: None,
            merkle_building: false,
            merkle_tx,
            merkle_rx: Some(merkle_rx),
            super_seeder: if config.super_seeding {
                Some(SuperSeeder::new(total_pieces))
            } else {
                None
            },
            local_webseed_resolver: config.local_webseed_resolver,
            part_file,
            alert_sender: config.alert_sender,
            pending_block_audits: HashMap::new(),
        }
    }

    fn emit_alert(&self, alert: crate::alert::Alert) {
        if let Some(ref tx) = self.alert_sender {
            let _ = tx.send(alert);
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

    fn can_request_block(&self, peer_id: PeerId, addr: SocketAddr, length: usize) -> bool {
        // Disk write backpressure: pause block requests when in-flight writes exceed the buffer budget
        if self.disk.in_flight_write_bytes() >= self.disk.max_write_buffer_bytes() {
            return false;
        }

        let is_lan = crate::bandwidth::is_lan_address(addr.ip());
        let (limit_lan, ip_overhead) = {
            let s = self.settings.read();
            (s.limit_lan_peers, s.rate_limit_ip_overhead)
        };
        let accounted = crate::bandwidth::calculate_overhead(length, ip_overhead);
        let peer_bucket = self.peer_download_buckets.get(&peer_id).cloned();
        let limiter = crate::bandwidth::HierarchicalRateLimiter::new(
            self.global_download_bucket.clone(),
            Some(self.torrent_download_bucket.clone()),
            peer_bucket,
        );
        limiter.try_consume(accounted, is_lan, limit_lan)
    }

    fn handle_fatal_storage_error(&mut self, err: &diskio::DiskError) {
        let err_msg = format!("Fatal storage error: {err}");
        tracing::error!(name = %self.info.name, "{err_msg}");
        {
            let mut s = self.stats.write();
            s.state = SwarmState::Error(err_msg.clone());
        }
        self.emit_alert(crate::alert::Alert::TorrentError {
            info_hash: self.info.hash,
            error: err_msg,
        });
        self.peers.clear();
    }

    fn hierarchical_upload_limiter(
        &self,
        peer_id: PeerId,
        addr: SocketAddr,
        length: usize,
    ) -> (crate::bandwidth::HierarchicalRateLimiter, usize, bool, bool) {
        let is_lan = crate::bandwidth::is_lan_address(addr.ip());
        let (limit_lan, ip_overhead) = {
            let s = self.settings.read();
            (s.limit_lan_peers, s.rate_limit_ip_overhead)
        };
        let accounted = crate::bandwidth::calculate_overhead(length, ip_overhead);
        let peer_bucket = self.peer_upload_buckets.get(&peer_id).cloned();
        let limiter = crate::bandwidth::HierarchicalRateLimiter::new(
            self.global_upload_bucket.clone(),
            Some(self.torrent_upload_bucket.clone()),
            peer_bucket,
        );
        (limiter, accounted, is_lan, limit_lan)
    }

    /// The picker priority (0 = skipped) currently applied to `piece`.
    pub fn piece_priority(&self, piece: u32) -> u8 {
        self.picker.piece_priority(piece)
    }

    pub fn info_hash(&self) -> [u8; 20] {
        self.info.hash
    }

    /// Runs the torrent's event loop until `events` closes (every peer task's sender
    /// has been dropped and nothing new will ever arrive). `commands` carries control-plane
    /// requests (file priority, recheck, relocate) — see `TorrentCommand`.
    pub async fn run(
        mut self,
        mut events: mpsc::Receiver<PeerEvent>,
        mut commands: mpsc::Receiver<TorrentCommand>,
    ) {
        let mut ticker = tokio::time::interval(self.tick_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // `command_tx` and `peer_event_tx` (behind `events`) both live in the same
        // `TorrentHandle` and are dropped together on remove, but `events` can also stay open
        // independently as long as any individual peer connection still holds its own cloned
        // sender — so `commands` can close first. A closed mpsc's `recv()` resolves to `None`
        // immediately on every poll; without this guard that would busy-spin the select loop
        // once `commands` closes but `events` hasn't yet.
        let mut commands_open = true;
        let mut block_tree_rx = self
            .block_tree_rx
            .take()
            .expect("run consumes the receiver once");
        let mut merkle_rx = self
            .merkle_rx
            .take()
            .expect("run consumes the receiver once");
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
                        Some(TorrentCommand::SetFilePriority(file_idx, priority)) => {
                            self.apply_file_priority(file_idx, priority);
                            if priority > 0 {
                                self.migrate_part_file_slices(file_idx as usize).await;
                            }
                        }
                        Some(TorrentCommand::SetSequential(on)) => {
                            self.picker.set_mode(if on {
                                synapse_picker::Mode::Sequential
                            } else {
                                synapse_picker::Mode::RarestFirst
                            });
                        }
                        Some(TorrentCommand::Recheck) => self.handle_recheck().await,
                        Some(TorrentCommand::SetLocation(new_dir)) => self.handle_set_location(new_dir).await,
                        Some(TorrentCommand::SetUnchokeSlots(slots)) => self.choker.set_regular_unchokes(slots),
                        Some(TorrentCommand::SetSeedChokingAlgorithm(algo)) => self.choker.set_seed_algorithm(algo),
                        Some(TorrentCommand::SetRateLimits { download_limit_bytes, upload_limit_bytes }) => {
                            self.torrent_download_bucket.set_rate_auto_burst(download_limit_bytes);
                            self.torrent_upload_bucket.set_rate_auto_burst(upload_limit_bytes);
                        }
                        Some(TorrentCommand::SetPeerRateLimits { peer_id, download_limit_bytes, upload_limit_bytes }) => {
                            if download_limit_bytes > 0 {
                                let b = self.peer_download_buckets.entry(peer_id).or_insert_with(|| Arc::new(TokenBucket::unthrottled()));
                                b.set_rate_auto_burst(download_limit_bytes);
                            } else {
                                self.peer_download_buckets.remove(&peer_id);
                            }
                            if upload_limit_bytes > 0 {
                                let b = self.peer_upload_buckets.entry(peer_id).or_insert_with(|| Arc::new(TokenBucket::unthrottled()));
                                b.set_rate_auto_burst(upload_limit_bytes);
                            } else {
                                self.peer_upload_buckets.remove(&peer_id);
                            }
                        }
                        Some(TorrentCommand::Stop) => {
                            tracing::debug!(name = %self.info.name, "Stopping torrent actor: disconnecting peers and draining state");
                            self.peers.clear();
                            break;
                        }
                        None => { commands_open = false; }
                    }
                }
                Some(tree) = merkle_rx.recv() => {
                    self.on_merkle_tree_built(tree);
                }
                Some((root, tree)) = block_tree_rx.recv() => {
                    self.on_block_tree_built(root, tree);
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
        if self.ban_list.is_banned(info.addr.ip()) {
            tracing::debug!(name = %self.info.name, addr = %info.addr, "Rejecting peer connection: address is banned");
            return; // dropping `handle` closes the connection, see peer::spawn
        }
        if self.ip_filter.read().is_blocked(info.addr.ip()) {
            tracing::debug!(name = %self.info.name, addr = %info.addr, "Rejecting peer connection: IP filtered");
            return;
        }
        if info.peer_id == self.our_peer_id {
            tracing::debug!(name = %self.info.name, addr = %info.addr, "Rejecting peer connection: it is ourselves");
            return;
        }
        // One connection per remote address (libtorrent's default `allow_multiple_connections_per_ip
        // = false`) and per peer id. Loopback is exempt so several local clients can share a host.
        let ip = info.addr.ip();
        let duplicate_entry = self
            .peers
            .iter()
            .find(|(_, p)| {
                p.peer_info.peer_id == info.peer_id
                    || (!ip.is_loopback() && p.peer_info.addr.ip() == ip)
            })
            .map(|(k, v)| (*k, v.peer_info));

        if let Some((existing_id, existing_info)) = duplicate_entry {
            // BEP 40 Canonical Peer Priority:
            // When two peers connect simultaneously (one outbound dial, one inbound accept),
            // both peers calculate identical priority rankings to deterministically decide which
            // connection to keep and which to close.
            let should_replace = if existing_info.is_outbound != info.is_outbound {
                if let Some(local_addr) = info.local_addr {
                    let local_wins =
                        synapse_wire::bep40::canonical_peer_priority(local_addr, info.addr)
                            == std::cmp::Ordering::Greater;
                    // If local wins, the outbound connection is kept.
                    // Otherwise, the inbound connection is kept.
                    if local_wins {
                        info.is_outbound
                    } else {
                        !info.is_outbound
                    }
                } else {
                    false
                }
            } else {
                // Same direction (e.g. duplicate inbound): never allow duplicate to replace established peer
                false
            };

            if should_replace {
                tracing::debug!(
                    name = %self.info.name,
                    addr = %info.addr,
                    existing_addr = %existing_info.addr,
                    "BEP 40: Replacing lower-priority duplicate connection in simultaneous dial race"
                );
                self.peers.remove(&existing_id);
            } else {
                tracing::debug!(name = %self.info.name, addr = %info.addr, "Rejecting peer connection: duplicate peer");
                return;
            }
        }
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
            if m.global_peers_connected
                .load(std::sync::atomic::Ordering::Relaxed)
                >= max_global
            {
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
        let allowed_fast_vec =
            compute_allowed_fast_set(info.addr.ip(), self.info.hash, self.info.pieces(), 10);
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
                peer_metadata_size: None,
                last_pex_at: None,
                last_useful_at: std::time::Instant::now(),
                pending_serves: Arc::new(AtomicUsize::new(0)),
                invalid_requests: 0,
                is_upload_only: false,
                suggested_pieces: HashSet::new(),
                last_requested_piece: None,
            },
        );
        self.pex.peer_connected(addr);
        self.emit_alert(crate::alert::Alert::PeerConnected {
            info_hash: self.info.hash,
            addr,
        });

        // BEP 10: Immediately send Extension Handshake message (ID 0). When we already
        // have real metadata (i.e. we're not ourselves awaiting it), advertise its size
        // so a magnet-downloading peer on the other end knows how many pieces to ask
        // for -- see `maybe_request_metadata`, which reads this same field from peers.
        let metadata_size = if self.metadata_fetcher.is_none() {
            let info = &self.info;
            Some(
                self.info_dict_cache
                    .get_or_insert_with(|| Bytes::from(info.to_info_dict_bytes()))
                    .len() as u32,
            )
        } else {
            None
        };
        let mut ext_hs_builder = ExtensionHandshake::for_torrent(self.info.private, metadata_size);
        if is_seeding {
            // BEP 21: Extension for Partial Seeds (upload_only)
            ext_hs_builder = ext_hs_builder.with_upload_only(true);
        }
        if self.info.is_merkle_v1() {
            ext_hs_builder
                .m
                .insert(synapse_wire::TR_HASHPIECE.to_string(), EXT_ID_TR_HASHPIECE);
        }
        let ext_hs = ext_hs_builder.encode();
        handle
            .send(Message::Extension {
                id: 0,
                payload: ext_hs,
            })
            .await;

        // BEP 6 Fast Extension / Super-Seeding: If super-seeding, offer single piece; if seeding, send HaveAll, otherwise Bitfield
        if is_seeding {
            if let Some(ref mut ss) = self.super_seeder {
                if let Some(p) = ss.assign_piece_to_peer(id) {
                    handle.send(Message::Have(p)).await;
                }
            } else {
                handle.send(Message::HaveAll).await;
            }
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

        // A pure-v2 magnet needs its piece layer from peers; ask as soon as one is here.
        self.request_piece_layers();
    }

    fn on_disconnected(&mut self, id: PeerId) {
        let Some(mut peer) = self.peers.remove(&id) else {
            return;
        };
        for fetch in &mut self.layer_fetches {
            fetch.peer_disconnected(id);
        }
        self.emit_alert(crate::alert::Alert::PeerDisconnected {
            info_hash: self.info.hash,
            addr: peer.peer_info.addr,
        });
        self.peer_download_buckets.remove(&id);
        self.peer_upload_buckets.remove(&id);
        if let Some(ref mut ss) = self.super_seeder {
            ss.on_peer_disconnected(id);
        }
        self.pex.peer_disconnected(peer.peer_info.addr);
        let ip = peer.peer_info.addr.ip();
        if !self.peers.values().any(|p| p.peer_info.addr.ip() == ip) {
            self.exclusive_pieces.retain(|_, owner| *owner != ip);
        }
        for i in 0..self.info.pieces() {
            if peer.has.has(i as usize) {
                self.picker.peer_lost(i);
            }
        }
        for ((idx, _), _) in peer.in_flight.drain() {
            if !self.picker.have(idx) {
                let any_in_flight = self
                    .peers
                    .values()
                    .any(|p| p.in_flight.keys().any(|&(i, _)| i == idx));
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
                        let any_in_flight = self
                            .peers
                            .values()
                            .any(|peer| peer.in_flight.keys().any(|&(i, _)| i == idx));
                        if !any_in_flight {
                            self.picker.mark_missing(idx);
                        }
                    }
                }
                if !drained.is_empty() {
                    let other_unchoked: Vec<PeerId> = self
                        .peers
                        .iter()
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
                if let Some(ref mut ss) = self.super_seeder {
                    if let Some(freed_peer_id) = ss.on_peer_have(id, index) {
                        if let Some(next_p) = ss.assign_piece_to_peer(freed_peer_id) {
                            if let Some(freed_peer) = self.peers.get_mut(&freed_peer_id) {
                                let _ = freed_peer.handle.try_send(Message::Have(next_p));
                            }
                        }
                    }
                }
                self.maybe_show_interest(id).await;
                let can_request = self
                    .peers
                    .get(&id)
                    .map(|p| !p.peer_choking)
                    .unwrap_or(false);
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
                let can_request = self
                    .peers
                    .get(&id)
                    .map(|p| !p.peer_choking)
                    .unwrap_or(false);
                if can_request {
                    self.try_request_more(id).await;
                }
            }
            Message::Request {
                index,
                begin,
                length,
            } => {
                if let Some(ref m) = self.global_metrics {
                    m.piece_requests_total.fetch_add(1, Ordering::Relaxed);
                }
                self.serve_request(id, index, begin, length).await;
            }
            Message::Piece { index, begin, data } => {
                // On a Merkle torrent the first block of a piece must come with its hash list
                // (Tr_hashpiece); a plain block 0 would leave the piece unverifiable.
                if self.info.is_merkle_v1()
                    && begin == 0
                    && !self.merkle_hashes.contains_key(&index)
                {
                    return;
                }
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
                let can_request = self
                    .peers
                    .get(&id)
                    .map(|p| !p.peer_choking)
                    .unwrap_or(false);
                if can_request {
                    self.try_request_more(id).await;
                }
            }
            Message::HaveNone => {
                if let Some(p) = self.peers.get_mut(&id) {
                    p.has = Bitfield::new(self.info.pieces() as usize);
                }
            }
            Message::SuggestPiece(index) => {
                if let Some(p) = self.peers.get_mut(&id) {
                    p.suggested_pieces.insert(index);
                }
                self.maybe_show_interest(id).await;
                self.try_request_more(id).await;
            }
            Message::AllowedFast(index) => {
                if let Some(p) = self.peers.get_mut(&id) {
                    p.peer_allowed_fast.insert(index);
                }
                self.maybe_show_interest(id).await;
                self.try_request_more(id).await;
            }
            Message::RejectRequest { index, .. } => {
                if let Some(ref m) = self.global_metrics {
                    m.piece_rejects_total.fetch_add(1, Ordering::Relaxed);
                }
                self.picker.mark_missing(index);
            }
            Message::Cancel { .. } => {}
            Message::Port(port) => {
                // BEP 5 / BEP 27: DHT port messages must never trigger DHT queries for private torrents.
                tracing::trace!(peer = %id, port, "Received DHT Port message; ignoring per privacy/config");
            }
            Message::Extension {
                id: ext_id,
                payload,
            } => {
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
                                p.peer_metadata_size = their_metadata_size;
                                if let Some(uo) = hs.upload_only {
                                    p.is_upload_only = uo;
                                }
                            }
                            self.maybe_request_metadata(id, their_metadata_id, their_metadata_size)
                                .await;
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
                        EXT_ID_UT_PEX => match synapse_wire::UtPexMessage::decode(&payload) {
                            Ok(pex_msg) => {
                                let Some(peer) = self.peers.get_mut(&id) else {
                                    return;
                                };
                                let now = std::time::Instant::now();
                                if peer
                                    .last_pex_at
                                    .is_some_and(|t| now.duration_since(t) < MIN_PEX_INTERVAL)
                                {
                                    tracing::debug!(peer = %id, "dropping ut_pex message sent too soon after the last");
                                    return;
                                }
                                peer.last_pex_at = Some(now);
                                let source_ip = peer.peer_info.addr.ip();
                                let discovered = self.pex.ingest_pex_message(pex_msg, source_ip);
                                if !discovered.is_empty() {
                                    if let Some(ref tx) = self.on_peers_discovered {
                                        let _ = tx.try_send(discovered);
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::debug!(peer = %id, "Malformed ut_pex message: {e}");
                            }
                        },
                        EXT_ID_UT_HOLEPUNCH => {
                            match synapse_wire::HolepunchMessage::decode(payload) {
                                Ok(hp_msg) => self.on_holepunch_message(id, hp_msg).await,
                                Err(e) => {
                                    tracing::debug!(peer = %id, "Malformed ut_holepunch message: {e}");
                                }
                            }
                        }
                        EXT_ID_TR_HASHPIECE if self.info.is_merkle_v1() => {
                            match synapse_wire::TrHashPiece::decode(&payload) {
                                Ok(m) => self.on_tr_hashpiece(id, m).await,
                                Err(e) => {
                                    tracing::debug!(peer = %id, "Malformed Tr_hashpiece message: {e}");
                                    if let Some(peer) = self.peers.get_mut(&id) {
                                        peer.invalid_requests += INVALID_HASHES_STRIKES;
                                    }
                                }
                            }
                        }
                        EXT_ID_LT_DONTHAVE => {
                            match synapse_wire::LtDontHave::decode(&payload) {
                                Ok(dont_have) => {
                                    // Only a piece the peer really had counts against availability:
                                    // otherwise repeated revocations of pieces it never advertised
                                    // would drive the rarest-first counts to zero.
                                    let had = self.peers.get_mut(&id).is_some_and(|peer| {
                                        let idx = dont_have.piece as usize;
                                        let had = peer.has.has(idx);
                                        if had {
                                            peer.has.unset(idx);
                                        }
                                        had
                                    });
                                    if had {
                                        self.picker.peer_lost(dont_have.piece);
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(peer = %id, "Malformed lt_donthave message: {e}");
                                }
                            }
                        }
                        _ => {
                            tracing::trace!(peer = %id, ext_id, len = payload.len(), "Received unhandled extension message");
                        }
                    }
                }
            }
            Message::HashRequest {
                pieces_root,
                base_layer,
                index,
                count,
                proof_layers,
            } => {
                self.serve_hash_request(id, pieces_root, base_layer, index, count, proof_layers);
            }
            Message::Hashes {
                pieces_root,
                base_layer,
                index,
                count,
                proof_layers,
                hashes,
            } => {
                self.on_piece_layer_hashes(
                    id,
                    pieces_root,
                    base_layer,
                    index,
                    count,
                    proof_layers,
                    &hashes,
                )
                .await;
            }
            Message::HashReject {
                pieces_root, index, ..
            } => {
                tracing::debug!(peer = %id, pieces_root = %hex::encode(pieces_root), "Peer rejected hash request");
                self.pending_block_audits.remove(&(id, pieces_root, index));
                if let Some(fetch) = self
                    .layer_fetches
                    .iter_mut()
                    .find(|f| *f.root() == pieces_root)
                {
                    fetch.on_reject(index, std::time::Instant::now());
                }
            }
        }
    }

    async fn maybe_show_interest(&mut self, id: PeerId) {
        let Some(peer) = self.peers.get_mut(&id) else {
            return;
        };
        let wants_something =
            (0..self.info.pieces()).any(|i| peer.has.has(i as usize) && !self.picker.have(i));
        if wants_something && !peer.am_interested {
            peer.am_interested = true;
            peer.handle.send(Message::Interested).await;
        } else if !wants_something && peer.am_interested {
            peer.am_interested = false;
            peer.handle.send(Message::Uninterested).await;
        }
    }

    async fn try_request_more(&mut self, id: PeerId) {
        // A pure-v2 torrent cannot verify a piece until its piece layer has been fetched.
        if !self.layer_fetches.is_empty() {
            return;
        }
        // A Merkle torrent's pieces can only be verified with the hash lists that come in
        // Tr_hashpiece messages, so only ask peers that speak it.
        if self.info.is_merkle_v1()
            && !self
                .peers
                .get(&id)
                .is_some_and(|p| p.peer_extensions.contains_key(synapse_wire::TR_HASHPIECE))
        {
            return;
        }
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

            let is_endgame =
                self.picker.pick(&peer_has, false).is_none() && !self.in_progress.is_empty();
            let now = std::time::Instant::now();
            const STEAL_THRESHOLD: Duration = Duration::from_secs(3);

            let (my_ip, on_parole) = {
                let Some(p) = self.peers.get(&id) else {
                    return;
                };
                let ip = p.peer_info.addr.ip();
                (ip, self.parole.contains(&ip))
            };

            // 1. Scan in-progress pieces that this peer has for missing blocks,
            // prioritizing pieces closest to completion (fewest remaining blocks).
            let mut sorted_in_progress: Vec<(u32, usize)> = self
                .in_progress
                .iter()
                .map(|(&idx, p)| {
                    let total = (self.info.piece_len(idx) as usize).div_ceil(BLOCK_LEN as usize);
                    let remaining = total.saturating_sub(p.received_blocks.len());
                    (idx, remaining)
                })
                .collect();
            sorted_in_progress.sort_by_key(|&(_, remaining)| remaining);

            let mut candidate_block = None;
            for (idx, _) in sorted_in_progress {
                let Some(in_prog) = self.in_progress.get(&idx) else {
                    continue;
                };
                if is_choking && !peer_allowed_fast.contains(&idx) {
                    continue;
                }
                // Smart-ban parole: a paroled peer only works on pieces reserved for it,
                // and nobody else touches a piece reserved for a paroled peer.
                match self.exclusive_pieces.get(&idx) {
                    Some(owner) if *owner != my_ip => continue,
                    None if on_parole => continue,
                    _ => {}
                }
                if !self.picker.have(idx) && peer_has.has(idx as usize) {
                    let piece_len = self.info.piece_len(idx);
                    let total_blocks = (piece_len as usize).div_ceil(BLOCK_LEN as usize);
                    if in_prog.received_blocks.len() < total_blocks {
                        for b in 0..total_blocks {
                            let offset = (b * BLOCK_LEN as usize) as u32;
                            if !in_prog.received_blocks.contains(&offset) {
                                let this_peer_in_flight = {
                                    let Some(p) = self.peers.get(&id) else {
                                        return;
                                    };
                                    p.in_flight.contains_key(&(idx, offset))
                                };
                                if this_peer_in_flight {
                                    continue;
                                }

                                let other_peer_in_flight = self.peers.values().find_map(|p| {
                                    p.in_flight
                                        .get(&(idx, offset))
                                        .map(|sent_at| (p.is_snubbed, *sent_at))
                                });

                                let should_request = match other_peer_in_flight {
                                    None => true,
                                    Some((other_snubbed, sent_at)) => {
                                        other_snubbed
                                            || (now.duration_since(sent_at) >= STEAL_THRESHOLD)
                                            || is_endgame
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
                let allowed_cand = peer_allowed_fast.iter().find(|&&idx| {
                    !self.picker.have(idx)
                        && !self.in_progress.contains_key(&idx)
                        && peer_has.has(idx as usize)
                });
                match allowed_cand {
                    Some(&idx) => {
                        self.picker.mark_requested(idx);
                        self.in_progress
                            .entry(idx)
                            .or_insert_with(|| InProgressPiece::new(self.info.piece_len(idx)));
                        if on_parole {
                            self.exclusive_pieces.insert(idx, my_ip);
                        }
                        (idx, 0)
                    }
                    None => return,
                }
            } else {
                // 2. Pick a new piece using suggest-pieces, extent affinity, and rarest-first picker
                let (suggested_pieces, last_piece) = {
                    let Some(p) = self.peers.get(&id) else {
                        return;
                    };
                    (p.suggested_pieces.clone(), p.last_requested_piece)
                };

                let suggested_cand = suggested_pieces
                    .iter()
                    .find(|&&idx| {
                        !self.picker.have(idx)
                            && !self.in_progress.contains_key(&idx)
                            && peer_has.has(idx as usize)
                    })
                    .copied();

                let chosen = suggested_cand.or_else(|| {
                    self.picker
                        .pick_with_extent_affinity(&peer_has, last_piece, false)
                });

                match chosen {
                    Some(idx) => {
                        if let Some(p) = self.peers.get_mut(&id) {
                            p.last_requested_piece = Some(idx);
                        }
                        self.picker.mark_requested(idx);
                        self.in_progress
                            .entry(idx)
                            .or_insert_with(|| InProgressPiece::new(self.info.piece_len(idx)));
                        if on_parole {
                            self.exclusive_pieces.insert(idx, my_ip);
                        }
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

            let Some(addr) = self.peers.get(&id).map(|p| p.peer_info.addr) else {
                return;
            };

            if !self.can_request_block(id, addr, length as usize) {
                return;
            }

            let Some(peer) = self.peers.get_mut(&id) else {
                return;
            };

            peer.in_flight
                .insert((target_piece, begin), std::time::Instant::now());
            let handle = peer.handle.clone();
            if let Some(ref m) = self.global_metrics {
                m.piece_requests_total.fetch_add(1, Ordering::Relaxed);
            }

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
        // Only accept blocks we asked this peer for, at the exact size we asked. Anything
        // else is unsolicited (or a late reply to a cancelled request) and must not be
        // credited, written into a piece buffer, or used to reset the snub/timeout state.
        let expected_len = (index < self.info.pieces())
            .then(|| self.info.piece_len(index))
            .filter(|&pl| begin < pl)
            .map(|pl| BLOCK_LEN.min(pl - begin));
        if peer.in_flight.remove(&(index, begin)).is_none()
            || expected_len != Some(data.len() as u32)
        {
            tracing::debug!(
                peer = id,
                index,
                begin,
                len = data.len(),
                "dropping unsolicited or mis-sized block"
            );
            return;
        }
        let source_ip = peer.peer_info.addr.ip();
        peer.last_useful_at = std::time::Instant::now();
        peer.downloaded_from += data.len() as u64;
        peer.consecutive_timeouts = 0;
        peer.is_snubbed = false;
        peer.last_received_at = std::time::Instant::now();

        // Cancel pending duplicate requests for this block from any other peers
        let other_peers_with_block: Vec<(PeerId, PeerHandle)> = self
            .peers
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
            let _ = handle.try_send(Message::Cancel {
                index,
                begin,
                length,
            });
            self.try_request_more(other_id).await;
        }

        let Some(piece) = self.in_progress.get_mut(&index) else {
            // Stale/unsolicited block (piece already completed or abandoned) - ignore.
            self.try_request_more(id).await;
            return;
        };
        // A second copy of a block we already hold (endgame duplicates) must not overwrite
        // it: the first copy may already be part of a verified-so-far piece, and letting a
        // later sender replace it would let one bad peer poison another peer's good block.
        if piece.received_blocks.contains(&begin) {
            self.try_request_more(id).await;
            return;
        }
        let start = begin as usize;
        let end = start + data.len();
        if end > piece.buf.len() {
            tracing::warn!(
                peer = id,
                index,
                begin,
                "block extends past piece end, dropping"
            );
            self.try_request_more(id).await;
            return;
        }
        piece.buf[start..end].copy_from_slice(&data);
        piece.received_blocks.insert(begin);
        piece.contributors.insert(begin, source_ip);

        if piece.is_complete() {
            self.finish_piece(index).await;
        }
        self.try_request_more(id).await;
    }

    /// Smart-ban: a piece failed its hash check, so somebody who supplied part of it sent
    /// bad data. A sole contributor is certainly at fault and is banned outright. When
    /// several peers contributed, each loses `TRUST_PENALTY` trust points (banned at
    /// `TRUST_BAN_THRESHOLD`) and goes on parole: from now on it only downloads pieces
    /// that no one else touches, so if it poisons one again the blame is unambiguous.
    fn on_piece_failed(&mut self, index: u32, contributors: &HashMap<u32, IpAddr>) {
        self.exclusive_pieces.remove(&index);
        let ips: HashSet<IpAddr> = contributors.values().copied().collect();
        if ips.len() == 1 {
            let ip = *ips.iter().next().expect("len checked");
            tracing::warn!(name = %self.info.name, index, %ip, "banning sole contributor to a corrupt piece");
            self.ban_address(ip);
            return;
        }
        for ip in ips {
            let trust = self.peer_trust.entry(ip).or_insert(0);
            *trust -= TRUST_PENALTY;
            let trust = *trust;
            self.parole.insert(ip);
            if trust <= TRUST_BAN_THRESHOLD {
                tracing::warn!(name = %self.info.name, index, %ip, trust, "banning peer whose trust fell below the threshold");
                self.ban_address(ip);
            }
        }
    }

    /// A piece verified: every contributor earns a trust point and leaves parole.
    fn on_piece_passed(&mut self, index: u32, contributors: &HashMap<u32, IpAddr>) {
        self.exclusive_pieces.remove(&index);
        let ips: HashSet<IpAddr> = contributors.values().copied().collect();
        for ip in ips {
            self.parole.remove(&ip);
            if let Some(trust) = self.peer_trust.get_mut(&ip) {
                *trust = (*trust + 1).min(TRUST_MAX);
            }
        }
        if self.peer_trust.len() > MAX_TRUST_ENTRIES {
            self.peer_trust.retain(|_, trust| *trust < 0);
        }
    }

    /// Bans `ip` on the shared list and drops every connection we hold to it.
    pub fn ban_address(&mut self, ip: IpAddr) {
        self.ban_list.ban(ip, crate::banlist::DEFAULT_BAN_DURATION);
        self.peer_trust.remove(&ip);
        self.parole.remove(&ip);
        let victims: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, p)| p.peer_info.addr.ip() == ip)
            .map(|(&id, _)| id)
            .collect();
        for id in victims {
            self.on_disconnected(id);
        }
        if let Some(ref m) = self.global_metrics {
            m.peers_banned.fetch_add(1, Ordering::Relaxed);
        }
        self.emit_alert(crate::alert::Alert::PeerBanned {
            info_hash: self.info.hash,
            ip,
        });
    }

    async fn finish_piece(&mut self, index: u32) {
        if self.picker.have(index) {
            return;
        }
        let Some(piece) = self.in_progress.remove(&index) else {
            return;
        };

        let piece_buf = piece.buf;
        let contributors = piece.contributors;
        let expected_hash = self
            .info
            .piece_hash(index)
            .or_else(|| self.merkle_hashes.get(&index).copied());
        let verified = if let Some(expected_v1) = expected_hash {
            let computed: [u8; 20] = tokio::task::spawn_blocking({
                let buf = piece_buf.clone();
                move || Sha1::digest(&buf).into()
            })
            .await
            .unwrap_or_default();
            computed == expected_v1
        } else if let Some(expected_v2) = self
            .info
            .piece_hash_v2(index)
            .or_else(|| self.piece_hash_v2_from_dynamic(index))
        {
            let computed: [u8; 32] = tokio::task::spawn_blocking({
                let buf = piece_buf.clone();
                let info = self.info.clone();
                move || info.compute_piece_hash_v2(index, &buf)
            })
            .await
            .unwrap_or_default();
            computed == expected_v2
        } else {
            tracing::warn!(
                name = %self.info.name,
                hash = %hex::encode(self.info.hash),
                index,
                "missing piece hash for verification, discarding piece"
            );
            false
        };

        if !verified {
            tracing::warn!(
                index,
                "piece failed hash verification, discarding and re-requesting"
            );
            if let Some(ref m) = self.global_metrics {
                m.hash_fails_total.fetch_add(1, Ordering::Relaxed);
            }
            self.emit_alert(crate::alert::Alert::HashFailed {
                info_hash: self.info.hash,
                piece_index: index,
            });
            self.picker.mark_missing(index);

            // BEP 52: ask a peer for the block-level hashes to pinpoint the corrupt block. Pure v2
            // only (a hybrid connection is a v1 connection, on which hash messages get us
            // disconnected).
            if self.info.v2_aligned && contributors.len() > 1 {
                self.request_piece_block_hashes(index, &piece_buf, &contributors);
            }

            self.on_piece_failed(index, &contributors);
            return;
        }
        self.on_piece_passed(index, &contributors);

        let piece_bytes = Bytes::from(piece_buf);
        if let Err(e) = self.write_piece(index, piece_bytes).await {
            tracing::error!(index, "failed to write completed piece to disk: {e}");
            self.emit_alert(crate::alert::Alert::TorrentError {
                info_hash: self.info.hash,
                error: e.to_string(),
            });
            self.picker.mark_missing(index);
            self.handle_fatal_storage_error(&e);
            return;
        }

        self.picker.mark_complete(index);
        self.emit_alert(crate::alert::Alert::PieceFinished {
            info_hash: self.info.hash,
            piece_index: index,
        });
        let piece_len = self.info.piece_len(index) as u64;
        let was_downloading = {
            let mut s = self.stats.write();
            let was_dl = s.state == SwarmState::Downloading;
            s.downloaded_bytes = s
                .downloaded_bytes
                .saturating_add(piece_len)
                .min(s.total_size);
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
            m.total_downloaded_bytes
                .fetch_add(piece_len, std::sync::atomic::Ordering::Relaxed);
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
            self.emit_alert(crate::alert::Alert::TorrentFinished {
                info_hash: self.info.hash,
            });
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

    pub async fn write_piece(&mut self, index: u32, data: Bytes) -> diskio::Result<()> {
        let locations = self.info.block_locations(index, 0, data.len() as u32);
        let mut jobs: Vec<WriteJob> = Vec::new();
        for loc in locations {
            if synapse_meta::is_padding_file(&self.info.files[loc.file].path, None) {
                continue;
            }
            let normal_path = self.download_dir.join(&self.info.files[loc.file].path);
            let slice_len = loc.piece_range.len();
            let (target_path, target_offset, part_len) = self.part_file.resolve_write_location(
                loc.file,
                loc.file_offset,
                slice_len,
                normal_path,
            );
            let file_len = if target_path == self.part_file.part_file_path() {
                part_len
            } else {
                self.info.files[loc.file].length
            };
            jobs.push(WriteJob {
                path: Arc::new(target_path),
                offset: target_offset,
                data: data.slice(loc.piece_range),
                file_len,
            });
        }
        if jobs.is_empty() {
            Ok(())
        } else {
            self.disk.write_batch(jobs).await
        }
    }

    /// Reads a slice of a piece across files or part-file.
    pub async fn read_piece_slice(
        &self,
        index: u32,
        begin: u32,
        length: u32,
    ) -> diskio::Result<Vec<u8>> {
        let locations = self.info.block_locations(index, begin, length);
        let mut buf = vec![0u8; length as usize];
        for loc in locations {
            let is_padding = synapse_meta::is_padding_file(&self.info.files[loc.file].path, None);
            if is_padding {
                buf[loc.piece_range].fill(0);
                continue;
            }
            let normal_path = self.download_dir.join(&self.info.files[loc.file].path);
            let (target_path, target_offset) =
                self.part_file
                    .resolve_read_location(loc.file, loc.file_offset, normal_path);
            let data = self
                .disk
                .read(diskio::ReadJob {
                    path: std::sync::Arc::new(target_path),
                    offset: target_offset,
                    len: loc.piece_range.len(),
                })
                .await?;
            buf[loc.piece_range].copy_from_slice(&data);
        }
        Ok(buf)
    }

    async fn serve_request(&mut self, id: PeerId, index: u32, begin: u32, length: u32) {
        let in_bounds = request_in_bounds(
            (index < self.info.pieces()).then(|| self.info.piece_len(index)),
            begin,
            length,
        );
        let have_piece = self.picker.have(index);
        // BEP 30: the first block of a piece of a Merkle torrent goes out as Tr_hashpiece with
        // the piece's hash list, which needs the whole tree (built from the data on disk once we
        // have everything).
        let merkle_first_block = self.info.is_merkle_v1() && begin == 0;
        let merkle_hashlist = if merkle_first_block {
            self.merkle_tree
                .as_ref()
                .and_then(|t| t.hashlist_for_piece(index as usize))
        } else {
            None
        };
        if merkle_first_block && merkle_hashlist.is_none() && have_piece {
            self.start_merkle_build().await;
        }
        let total_slots = self.pending_serves_total.clone();
        let Some(peer) = self.peers.get_mut(&id) else {
            return;
        };
        let merkle_target = peer
            .peer_extensions
            .get(synapse_wire::TR_HASHPIECE)
            .copied();
        let merkle_ok =
            !merkle_first_block || (merkle_hashlist.is_some() && merkle_target.is_some());

        // BEP 6 Fast Extension: If choked and piece is not in allowed_fast, or if piece is missing, reject
        let is_allowed_fast = peer.allowed_fast.contains(&index);
        let can_serve =
            in_bounds && (!peer.am_choking || is_allowed_fast) && have_piece && merkle_ok;
        let over_capacity = peer.pending_serves.load(Ordering::Relaxed)
            >= MAX_PENDING_SERVES_PER_PEER
            || total_slots.load(Ordering::Relaxed) >= MAX_PENDING_SERVES_TOTAL;

        if !can_serve || over_capacity {
            let _ = peer.handle.try_send(Message::RejectRequest {
                index,
                begin,
                length,
            });
            if let Some(ref m) = self.global_metrics {
                m.piece_rejects_total.fetch_add(1, Ordering::Relaxed);
            }
            peer.invalid_requests += 1;
            if peer.invalid_requests > MAX_INVALID_REQUESTS {
                tracing::warn!(
                    peer = id,
                    strikes = peer.invalid_requests,
                    "disconnecting peer for repeated invalid requests"
                );
                self.on_disconnected(id);
            }
            return;
        }
        peer.invalid_requests = peer.invalid_requests.saturating_sub(1);
        peer.last_useful_at = std::time::Instant::now();
        peer.pending_serves.fetch_add(1, Ordering::Relaxed);
        total_slots.fetch_add(1, Ordering::Relaxed);
        let slot = ServeSlot {
            peer: peer.pending_serves.clone(),
            total: total_slots,
        };

        let locations = self.info.block_locations(index, begin, length);
        let disk = self.disk.clone();
        let handle = peer.handle.clone();
        let peer_addr = peer.peer_info.addr;
        peer.uploaded_to += length as u64;

        let download_dir = self.download_dir.clone();
        let file_paths: Vec<BlockReadSlice> = locations
            .into_iter()
            .map(|loc| {
                let is_padding =
                    synapse_meta::is_padding_file(&self.info.files[loc.file].path, None);
                let normal_path = download_dir.join(&self.info.files[loc.file].path);
                let (target_path, target_offset) =
                    self.part_file
                        .resolve_read_location(loc.file, loc.file_offset, normal_path);
                BlockReadSlice {
                    path: Arc::new(target_path),
                    offset: target_offset,
                    len: loc.piece_range.len(),
                    piece_range: loc.piece_range,
                    is_padding,
                }
            })
            .collect();

        self.total_uploaded += length as u64;
        if let Some(ref m) = self.global_metrics {
            m.total_uploaded_bytes
                .fetch_add(length as u64, std::sync::atomic::Ordering::Relaxed);
        }

        let (limiter, accounted, is_lan, limit_lan) =
            self.hierarchical_upload_limiter(id, peer_addr, length as usize);

        // Offload disk read + throttling + piece send to non-blocking worker
        tokio::spawn(async move {
            let _slot = slot;
            let mut buf = vec![0u8; length as usize];
            for slice in file_paths {
                if slice.is_padding {
                    buf[slice.piece_range].fill(0);
                    continue;
                }
                match disk
                    .read(ReadJob {
                        path: slice.path,
                        offset: slice.offset,
                        len: slice.len,
                    })
                    .await
                {
                    Ok(data) => buf[slice.piece_range].copy_from_slice(&data),
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

            limiter.consume(accounted, is_lan, limit_lan).await;
            let data = Bytes::from(buf);
            let message = match (merkle_hashlist, merkle_target) {
                (Some(hashlist), Some(ext_id)) => Message::Extension {
                    id: ext_id,
                    payload: synapse_wire::TrHashPiece {
                        index,
                        begin,
                        hashlist,
                        data,
                    }
                    .encode(),
                },
                _ => Message::Piece { index, begin, data },
            };
            let _ = handle.send(message).await;
        });
    }

    /// BEP 9: if this torrent is still awaiting metadata (magnet-added) and the peer
    /// whose handshake we just decoded advertises `ut_metadata` with a known size,
    /// requests every metadata piece we're still missing from them. Idempotent w.r.t.
    /// `metadata_size` (set once) and safe to call again for a later peer if earlier
    /// requests went unanswered -- `missing_pieces()` reflects live fetcher state.
    async fn maybe_request_metadata(
        &mut self,
        id: PeerId,
        their_metadata_id: Option<u8>,
        their_metadata_size: Option<u32>,
    ) {
        let (Some(metadata_id), Some(size)) = (their_metadata_id, their_metadata_size) else {
            return;
        };
        let Some(fetcher) = self.metadata_fetcher.as_mut() else {
            return;
        };
        if !fetcher.set_metadata_size(size) {
            tracing::debug!(peer = %id, size, "ignoring unusable ut_metadata size");
            return;
        }
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
                // Serialized once: re-encoding the info dict (which embeds every piece hash)
                // per request would let a peer make us burn CPU by asking repeatedly.
                let info_bytes = if self.metadata_fetcher.is_none() && self.peers.contains_key(&id)
                {
                    Some(
                        self.info_dict_cache
                            .get_or_insert_with(|| Bytes::from(self.info.to_info_dict_bytes()))
                            .clone(),
                    )
                } else {
                    None
                };
                let Some(peer) = self.peers.get(&id) else {
                    return;
                };
                let Some(&their_id) = peer.peer_extensions.get("ut_metadata") else {
                    return;
                };
                let piece_start =
                    (piece as usize).saturating_mul(synapse_wire::UT_METADATA_PIECE_LEN);
                let response = match info_bytes {
                    Some(bytes) if piece_start < bytes.len() => {
                        let piece_end =
                            (piece_start + synapse_wire::UT_METADATA_PIECE_LEN).min(bytes.len());
                        UtMetadataMessage::Data {
                            piece,
                            total_size: bytes.len() as u32,
                            data: bytes.slice(piece_start..piece_end),
                        }
                    }
                    _ => UtMetadataMessage::Reject { piece },
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
                        // The fetcher has reset itself, so the next source starts clean. Drop
                        // this peer (it sent a bad chunk, or the completing one) and re-ask
                        // the remaining peers that advertised the metadata extension.
                        tracing::warn!(peer = %id, "ut_metadata assembly failed: {e}");
                        self.on_disconnected(id);
                        let sources: Vec<(PeerId, u8, u32)> = self
                            .peers
                            .iter()
                            .filter_map(|(&pid, p)| {
                                Some((
                                    pid,
                                    *p.peer_extensions.get("ut_metadata")?,
                                    p.peer_metadata_size?,
                                ))
                            })
                            .collect();
                        for (pid, ext, size) in sources {
                            self.maybe_request_metadata(pid, Some(ext), Some(size))
                                .await;
                        }
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
            .filter_map(|p| {
                p.peer_extensions
                    .get("ut_pex")
                    .map(|&ext_id| (p.handle.clone(), ext_id))
            })
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
        let Some((seed_idx, base_url)) = self.webseed.as_ref().and_then(|w| w.pick_active_seed())
        else {
            return;
        };

        self.picker.mark_requested(index);

        let piece_len = self.info.piece_len(index);
        let locations = self.info.block_locations(index, 0, piece_len);
        let single_file = self.info.files.len() == 1;
        let mut buf = vec![0u8; piece_len as usize];

        for loc in &locations {
            if synapse_meta::is_padding_file(&self.info.files[loc.file].path, None) {
                buf[loc.piece_range.clone()].fill(0);
                continue;
            }

            let file_path_rel = if single_file {
                None
            } else {
                Some(
                    self.info.files[loc.file]
                        .path
                        .to_string_lossy()
                        .into_owned(),
                )
            };

            let is_hoffman = base_url.query().is_some_and(|q| q.contains("info_hash"))
                || base_url.path().ends_with(".php")
                || base_url.path().ends_with(".cgi");
            let (target_url, range_header) = if is_hoffman {
                let range = Some((
                    loc.file_offset as u32,
                    (loc.file_offset + loc.piece_range.len() as u64) as u32,
                ));
                match self.webseed.as_ref().unwrap().format_hoffman_request(
                    &base_url,
                    &self.info.hash,
                    index,
                    range,
                ) {
                    Ok(u) => (u, None),
                    Err(e) => {
                        tracing::debug!(index, "Hoffman webseed URL formatting failed: {e}");
                        self.webseed.as_mut().unwrap().on_failure(seed_idx);
                        self.picker.mark_missing(index);
                        return;
                    }
                }
            } else {
                let range_request = self.webseed.as_ref().unwrap().format_range_request(
                    &base_url,
                    file_path_rel.as_deref(),
                    loc.file_offset,
                    loc.piece_range.len() as u32,
                );
                match range_request {
                    Ok((u, h)) => (u, Some(h)),
                    Err(e) => {
                        tracing::debug!(index, "webseed URL formatting failed: {e}");
                        self.webseed.as_mut().unwrap().on_failure(seed_idx);
                        self.picker.mark_missing(index);
                        return;
                    }
                }
            };

            // Web seed URLs come from the torrent, so they go through the SSRF-checked,
            // size-capped client: never a local address, at most 5 redirects, and the body
            // is abandoned once it exceeds the range we asked for (a server ignoring
            // `Range` and streaming the whole file cannot exhaust memory).
            let opts = synapse_tracker::safe_http::FetchOptions {
                timeout: Duration::from_secs(20),
                max_body: loc.piece_range.len(),
                user_agent: concat!("Synapse/", env!("CARGO_PKG_VERSION")),
                local: if self.settings.read().allow_local_web_seeds {
                    synapse_tracker::safe_http::LocalPolicy::AllowAny
                } else {
                    synapse_tracker::safe_http::LocalPolicy::Deny
                },
                range: range_header,
            };
            let expected_start = loc.file_offset;
            let expected_len = loc.piece_range.len() as u64;
            let fetched = match synapse_tracker::safe_http::fetch(&target_url, &opts).await {
                Ok(r)
                    if is_hoffman
                        && (r.status == 200 || r.status == 206)
                        && r.body.len() as u64 == expected_len =>
                {
                    Some(r.body)
                }
                Ok(r)
                    if crate::webseed::response_matches_range(
                        r.status,
                        r.content_range.as_deref(),
                        r.body.len(),
                        expected_start,
                        expected_len,
                    ) =>
                {
                    Some(r.body)
                }
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
                contributors: HashMap::new(),
            },
        );
        self.finish_piece(index).await;
    }

    async fn tick(&mut self) {
        self.maybe_broadcast_pex().await;
        self.request_piece_layers();
        if !self.pending_block_audits.is_empty() {
            let now = std::time::Instant::now();
            self.pending_block_audits.retain(|_, a| a.deadline > now);
        }
        self.maybe_fetch_via_webseed().await;

        // Re-apply the IP filter (and ban list) to peers already connected, so adding a
        // range or a ban drops matching live connections instead of only blocking new ones.
        if self.last_ip_filter_sweep.elapsed() >= IP_FILTER_SWEEP_INTERVAL {
            self.last_ip_filter_sweep = std::time::Instant::now();
            let blocked: Vec<PeerId> = {
                let filter = self.ip_filter.read();
                self.peers
                    .iter()
                    .filter(|(_, p)| {
                        let ip = p.peer_info.addr.ip();
                        filter.is_blocked(ip) || self.ban_list.is_banned(ip)
                    })
                    .map(|(&id, _)| id)
                    .collect()
            };
            for id in blocked {
                tracing::info!(
                    peer = id,
                    "disconnecting peer: address is now filtered or banned"
                );
                self.on_disconnected(id);
            }
        }

        // Inactivity applies in every state, including seeding.
        let idle: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, p)| p.last_useful_at.elapsed() >= INACTIVITY_TIMEOUT)
            .map(|(&id, _)| id)
            .collect();
        for id in idle {
            tracing::debug!(
                peer = id,
                "disconnecting peer: no piece data exchanged within the inactivity timeout"
            );
            self.on_disconnected(id);
        }

        let we_are_seeding = self.picker.is_complete();
        let total_pieces = self.info.pieces().max(1) as f32;
        let stats: Vec<PeerStats<PeerId>> = self
            .peers
            .iter()
            .map(|(id, p)| PeerStats {
                id: *id,
                download_rate: p.downloaded_from,
                upload_rate: p.uploaded_to,
                interested: p.peer_interested,
                progress: p.has.count_ones() as f32 / total_pieces,
                last_unchoked: None,
            })
            .collect();
        let ChokeDecisions { unchoke, choke } = self.choker.rechoke(&stats, we_are_seeding);

        for id in unchoke {
            if let Some(p) = self.peers.get_mut(&id) {
                if p.am_choking {
                    p.am_choking = false;
                    p.handle.send(Message::Unchoke).await;
                    if let Some(ref m) = self.global_metrics {
                        m.unchokes_total.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        for id in choke {
            if let Some(p) = self.peers.get_mut(&id) {
                if !p.am_choking {
                    p.am_choking = true;
                    p.handle.send(Message::Choke).await;
                    if let Some(ref m) = self.global_metrics {
                        m.chokes_total.fetch_add(1, Ordering::Relaxed);
                    }
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

                let max_allowed = if peer.is_snubbed {
                    1
                } else {
                    self.max_pipeline
                };
                if !peer.peer_choking && peer.in_flight.len() < max_allowed {
                    active_peers.push(*peer_id);
                }
            }

            for peer_id in stalled_peers_to_disconnect {
                tracing::warn!(
                    peer = peer_id,
                    "disconnecting unresponsive/stalled peer after repeated request timeouts"
                );
                self.on_disconnected(peer_id);
            }

            for idx in timed_out_pieces {
                let piece_still_in_flight = self
                    .peers
                    .values()
                    .any(|p| p.in_flight.keys().any(|&(piece_idx, _)| piece_idx == idx));
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
            let dl_delta = peer
                .downloaded_from
                .saturating_sub(peer.prev_downloaded_from);
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
            if peer.peer_info.is_encrypted {
                flags.push('E');
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
                is_encrypted: peer.peer_info.is_encrypted,
                is_utp: false,
                supports_pex,
                peer_interested: peer.peer_interested,
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

    /// A file that was unwanted (its boundary-piece bytes went to the part file) has become
    /// wanted: copy those bytes into the real file so it is complete on disk, then stop
    /// redirecting. Without this the pieces stay marked complete while their bytes exist only in
    /// the part file, leaving holes in the finished file.
    pub async fn migrate_part_file_slices(&mut self, file_idx: usize) {
        let slices = self.part_file.slices_for_file(file_idx);
        if slices.is_empty() {
            return;
        }
        let Some(file) = self.info.files.get(file_idx) else {
            return;
        };
        let real_path = Arc::new(self.download_dir.join(&file.path));
        let file_len = file.length;
        let part_path = Arc::new(self.part_file.part_file_path().to_path_buf());
        for (start, len, part_off) in slices {
            let data = match self
                .disk
                .read(ReadJob {
                    path: part_path.clone(),
                    offset: part_off,
                    len: len as usize,
                })
                .await
            {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(name = %self.info.name, file_idx, "part-file migration read failed: {e}");
                    return;
                }
            };
            if let Err(e) = self
                .disk
                .write_batch(vec![WriteJob {
                    path: real_path.clone(),
                    offset: start,
                    data,
                    file_len,
                }])
                .await
            {
                tracing::error!(name = %self.info.name, file_idx, "part-file migration write failed: {e}");
                return;
            }
        }
        self.part_file.forget_file(file_idx);
        tracing::info!(name = %self.info.name, file_idx, "moved part-file data into the now-wanted file");
    }

    /// Sets a piece's picker priority to the highest priority among the files it touches
    /// (padding counts as skipped).
    fn refresh_piece_priority(&mut self, piece: u32) {
        let len = self.info.piece_len(piece);
        let priority = self
            .info
            .block_locations(piece, 0, len)
            .iter()
            .map(|loc| {
                if synapse_meta::is_padding_file(&self.info.files[loc.file].path, None) {
                    0
                } else {
                    self.file_priorities.get(loc.file).copied().unwrap_or(4)
                }
            })
            .max()
            .unwrap_or(4);
        self.picker.set_piece_priority(piece, priority);
    }

    pub fn apply_file_priority(&mut self, file_idx: u32, priority: u8) {
        let Some((start, end)) = self.info.piece_range_for_file(file_idx as usize) else {
            tracing::warn!(name = %self.info.name, file_idx, "set_file_priority: no such file index");
            return;
        };
        self.part_file
            .set_file_priority(file_idx as usize, priority);
        if let Some(slot) = self.file_priorities.get_mut(file_idx as usize) {
            *slot = priority;
        }
        // Pieces wholly inside the file take its priority. The first and last piece may be shared
        // with a neighbouring file: they stay wanted as long as either file is (the skipped
        // file's bytes in them go to the part file), otherwise the neighbour could never finish.
        if end > start + 1 {
            self.picker
                .set_piece_range_priority_tier(start + 1, end - 1, priority);
        }
        self.refresh_piece_priority(start);
        self.refresh_piece_priority(end);
        tracing::info!(name = %self.info.name, file_idx, priority, "applied file priority tier");
    }

    /// Re-verifies every piece already on disk against the torrent's real hashes and rebuilds
    /// picker/bitfield state to match — previously `recheck` just flipped the reported state
    /// to `Checking` for cosmetic effect and never actually looked at the files on disk.
    pub async fn handle_recheck(&mut self) {
        tracing::info!(name = %self.info.name, "recheck starting");
        self.stats.write().state = SwarmState::Checking;

        let total = self.info.pieces();
        let mut new_bitfield = Bitfield::new(total as usize);

        // Bounded concurrency pool for pipelined parallel rechecking (buffer pool)
        let concurrency = 8usize.min(total as usize).max(1);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let (res_tx, mut res_rx) =
            tokio::sync::mpsc::channel::<(u32, bool, Option<[u8; 20]>)>(concurrency * 2);

        for idx in 0..total {
            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("recheck semaphore closed");
            let info = self.info.clone();
            let disk = self.disk.clone();
            let piece_len = info.piece_len(idx);
            let locations = info.block_locations(idx, 0, piece_len);
            let tx = res_tx.clone();

            let mut read_slices = Vec::with_capacity(locations.len());
            for loc in locations {
                if synapse_meta::is_padding_file(&info.files[loc.file].path, None) {
                    read_slices.push((None, loc.piece_range));
                } else {
                    let normal_path = self.download_dir.join(&info.files[loc.file].path);
                    let (target_path, target_offset) = self.part_file.resolve_read_location(
                        loc.file,
                        loc.file_offset,
                        normal_path,
                    );
                    read_slices.push((
                        Some(ReadJob {
                            path: Arc::new(target_path),
                            offset: target_offset,
                            len: loc.piece_range.len(),
                        }),
                        loc.piece_range,
                    ));
                }
            }

            let expected_v1 = info
                .piece_hash(idx)
                .or_else(|| self.merkle_hashes.get(&idx).copied());
            let is_merkle = info.is_merkle_v1();
            let expected_v2 = info
                .piece_hash_v2(idx)
                .or_else(|| self.piece_hash_v2_from_dynamic(idx));

            tokio::spawn(async move {
                let _permit = permit;
                let mut buf = vec![0u8; piece_len as usize];
                let mut read_ok = true;
                for (job_opt, range) in read_slices {
                    if let Some(job) = job_opt {
                        match disk.read(job).await {
                            Ok(data) => buf[range].copy_from_slice(&data),
                            Err(_) => {
                                read_ok = false;
                                break;
                            }
                        }
                    } else {
                        buf[range].fill(0);
                    }
                }

                // A Merkle torrent's pieces are checked as a whole afterwards, so hand back the hash.
                let sha1: Option<[u8; 20]> =
                    (read_ok && is_merkle).then(|| Sha1::digest(&buf).into());
                let verified = read_ok && {
                    if let Some(expected) = expected_v1 {
                        let computed: [u8; 20] = Sha1::digest(&buf).into();
                        computed == expected
                    } else if let Some(expected_v2) = expected_v2 {
                        let computed: [u8; 32] = info.compute_piece_hash_v2(idx, &buf);
                        computed == expected_v2
                    } else {
                        false
                    }
                };

                let _ = tx.send((idx, verified, sha1)).await;
            });
        }
        drop(res_tx);

        let mut results: Vec<(u32, bool, Option<[u8; 20]>)> = Vec::with_capacity(total as usize);
        while let Some(r) = res_rx.recv().await {
            results.push(r);
        }
        // BEP 30: if every piece is present and the tree of their hashes reproduces the root hash,
        // all of them are good, and the tree is what a seeder needs.
        if self.info.is_merkle_v1() && results.iter().all(|(_, _, h)| h.is_some()) {
            results.sort_by_key(|r| r.0);
            let hashes: Vec<[u8; 20]> = results.iter().filter_map(|r| r.2).collect();
            if let Some(tree) = synapse_meta::merkle_v1::MerkleTreeV1::from_piece_hashes(&hashes)
                .filter(|t| Some(t.root()) == self.info.root_hash_v1)
            {
                for r in results.iter_mut() {
                    r.1 = true;
                }
                self.merkle_tree = Some(Arc::new(tree));
            }
        }
        for (idx, verified, _) in results {
            if verified {
                self.picker.mark_complete(idx);
                new_bitfield.set(idx as usize);
            } else {
                // `mark_missing` only demotes an in-flight `Requested` piece — a previously
                // `Complete` piece that just failed re-verification (corrupted on disk since)
                // needs to be forced back regardless of its prior state.
                self.picker.force_missing(idx);
                self.broadcast_dont_have(idx);
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
        let progress = if total > 0 {
            completed_count as f32 / total as f32
        } else {
            1.0
        };
        let is_complete = self.picker.is_complete();

        *self.bitfield.write() = Some(RoaringBitfield::from_bitfield(&new_bitfield));
        {
            let mut s = self.stats.write();
            s.progress = progress;
            s.downloaded_bytes = ((progress as f64) * (self.info.total_len as f64)) as u64;
            s.state = if is_complete {
                SwarmState::Seeding
            } else {
                SwarmState::Downloading
            };
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

    async fn on_holepunch_message(&mut self, id: PeerId, msg: synapse_wire::HolepunchMessage) {
        match msg {
            synapse_wire::HolepunchMessage::Rendezvous { target } => {
                let sender_addr = self.peers.get(&id).map(|p| p.peer_info.addr);
                let target_peer = self.peers.values().find(|p| p.peer_info.addr == target);
                if let (Some(sender_addr), Some(target_peer)) = (sender_addr, target_peer) {
                    let target_hp_id = target_peer.peer_extensions.get("ut_holepunch").copied();
                    let sender_hp_id = self
                        .peers
                        .get(&id)
                        .and_then(|p| p.peer_extensions.get("ut_holepunch").copied());

                    if let Some(target_ext_id) = target_hp_id {
                        let _ = target_peer.handle.try_send(Message::Extension {
                            id: target_ext_id,
                            payload: synapse_wire::HolepunchMessage::Connect { peer: sender_addr }
                                .encode(),
                        });
                    }
                    if let (Some(sender_ext_id), Some(sender)) = (sender_hp_id, self.peers.get(&id))
                    {
                        let _ = sender.handle.try_send(Message::Extension {
                            id: sender_ext_id,
                            payload: synapse_wire::HolepunchMessage::Connect { peer: target }
                                .encode(),
                        });
                    }
                } else if let Some(sender) = self.peers.get(&id) {
                    let sender_hp_id = sender.peer_extensions.get("ut_holepunch").copied();
                    if let Some(ext_id) = sender_hp_id {
                        let _ = sender.handle.try_send(Message::Extension {
                            id: ext_id,
                            payload: synapse_wire::HolepunchMessage::Failed { err_code: 1 }
                                .encode(),
                        });
                    }
                }
            }
            synapse_wire::HolepunchMessage::Connect { peer } => {
                tracing::debug!(peer = %peer, "Received ut_holepunch Connect rendezvous directive; dialing peer via uTP");
                if let Some(ref tx) = self.on_peers_discovered {
                    let _ = tx.try_send(vec![peer]);
                }
            }
            synapse_wire::HolepunchMessage::Failed { err_code } => {
                tracing::debug!(from_peer = %id, err_code, "Received ut_holepunch Failed notification");
            }
        }
    }

    /// The piece layer for `root`, from the metainfo or already fetched and verified.
    fn piece_layer_bytes(&self, root: &[u8; 32]) -> Option<&Vec<u8>> {
        self.info
            .piece_layers
            .get(root)
            .or_else(|| self.dynamic_piece_layers.get(root))
    }

    /// Answers a BEP 52 `hash request` with the hashes *and* the uncle-hash proof the requester
    /// needs to verify them against the file root, or a `hash reject`. Only the piece layer is
    /// available (not per-block hashes), requests are capped at 512 hashes, and the range and
    /// proof must lie inside the padded tree.
    fn serve_hash_request(
        &mut self,
        id: PeerId,
        pieces_root: [u8; 32],
        base_layer: u32,
        index: u32,
        count: u32,
        proof_layers: u32,
    ) {
        if base_layer == 0
            && self.try_serve_block_hashes(id, pieces_root, index, count, proof_layers)
        {
            return;
        }
        let reply = self.build_hash_reply(pieces_root, base_layer, index, count, proof_layers);
        let Some(peer) = self.peers.get_mut(&id) else {
            return;
        };
        let msg = match reply {
            Some(hashes) => Message::Hashes {
                pieces_root,
                base_layer,
                index,
                count,
                proof_layers,
                hashes,
            },
            None => Message::HashReject {
                pieces_root,
                base_layer,
                index,
                count,
                proof_layers,
            },
        };
        let _ = peer.handle.try_send(msg);
    }

    /// Handles a request for block-level (layer 0) hashes below the piece layer. Returns `false`
    /// when the request is really for the piece layer (piece length 16 KiB) and should take the
    /// normal path. Otherwise the request is answered from a cached tree, queued while the tree
    /// is built from the file on disk (only for a complete file), or rejected.
    fn try_serve_block_hashes(
        &mut self,
        id: PeerId,
        pieces_root: [u8; 32],
        index: u32,
        count: u32,
        proof_layers: u32,
    ) -> bool {
        if self.info.piece_len as usize == synapse_meta::merkle::BLOCK_SIZE {
            return false;
        }
        let request = PendingHashRequest {
            peer: id,
            pieces_root,
            base_layer: 0,
            index,
            count,
            proof_layers,
        };
        if count as usize > MAX_HASHES_PER_REQUEST {
            self.reject_hash_request(&request);
            return true;
        }
        if let Some(tree) = self.block_trees.get(&pieces_root).cloned() {
            self.answer_from_block_tree(&tree, &request);
            return true;
        }
        let Some(file_idx) = self
            .info
            .file_roots
            .iter()
            .position(|r| *r == Some(pieces_root))
        else {
            self.reject_hash_request(&request);
            return true;
        };
        let file = &self.info.files[file_idx];
        let complete = self
            .info
            .piece_range_for_file(file_idx)
            .is_some_and(|(a, b)| (a..=b).all(|p| self.picker.have(p)));
        let busy = self.block_tree_building.is_some_and(|r| r != pieces_root);
        if !complete
            || file.length == 0
            || file.length > MAX_BLOCK_TREE_FILE
            || self.part_file.is_unwanted(file_idx)
            || busy
            || self.pending_block_requests.len() >= MAX_PENDING_BLOCK_REQUESTS
        {
            self.reject_hash_request(&request);
            return true;
        }
        self.pending_block_requests.push(request);
        if self.block_tree_building.is_none() {
            self.block_tree_building = Some(pieces_root);
            let path = self.download_dir.join(&file.path);
            let (disk, len, tx) = (self.disk.clone(), file.length, self.block_tree_tx.clone());
            tokio::spawn(async move {
                let tree = build_block_tree(disk, path, len, pieces_root).await;
                let _ = tx.send((pieces_root, tree)).await;
            });
        }
        true
    }

    fn on_block_tree_built(
        &mut self,
        root: [u8; 32],
        tree: Option<synapse_meta::merkle::BlockTree>,
    ) {
        self.block_tree_building = None;
        let tree = tree.map(Arc::new);
        if let Some(tree) = &tree {
            if self.block_trees.len() >= MAX_CACHED_BLOCK_TREES {
                if let Some(evict) = self.block_trees.keys().next().copied() {
                    self.block_trees.remove(&evict);
                }
            }
            self.block_trees.insert(root, tree.clone());
        } else {
            tracing::warn!(name = %self.info.name, "could not build a block hash tree for a file that matches its root");
        }
        let (mine, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending_block_requests)
            .into_iter()
            .partition(|r| r.pieces_root == root);
        self.pending_block_requests = rest;
        for request in mine {
            match &tree {
                Some(tree) => self.answer_from_block_tree(tree, &request),
                None => self.reject_hash_request(&request),
            }
        }
    }

    fn answer_from_block_tree(
        &mut self,
        tree: &synapse_meta::merkle::BlockTree,
        r: &PendingHashRequest,
    ) {
        let Some(peer) = self.peers.get(&r.peer) else {
            return;
        };
        let msg = match tree.respond(
            r.base_layer as usize,
            r.index as usize,
            r.count as usize,
            r.proof_layers as usize,
        ) {
            Some((hashes, proof)) => Message::Hashes {
                pieces_root: r.pieces_root,
                base_layer: r.base_layer,
                index: r.index,
                count: r.count,
                proof_layers: r.proof_layers,
                hashes: Bytes::from(
                    hashes
                        .into_iter()
                        .chain(proof)
                        .flatten()
                        .collect::<Vec<u8>>(),
                ),
            },
            None => Message::HashReject {
                pieces_root: r.pieces_root,
                base_layer: r.base_layer,
                index: r.index,
                count: r.count,
                proof_layers: r.proof_layers,
            },
        };
        let _ = peer.handle.try_send(msg);
    }

    fn reject_hash_request(&mut self, r: &PendingHashRequest) {
        if let Some(peer) = self.peers.get(&r.peer) {
            let _ = peer.handle.try_send(Message::HashReject {
                pieces_root: r.pieces_root,
                base_layer: r.base_layer,
                index: r.index,
                count: r.count,
                proof_layers: r.proof_layers,
            });
        }
    }

    fn build_hash_reply(
        &mut self,
        pieces_root: [u8; 32],
        base_layer: u32,
        index: u32,
        count: u32,
        proof_layers: u32,
    ) -> Option<Bytes> {
        let file_idx = self
            .info
            .file_roots
            .iter()
            .position(|r| *r == Some(pieces_root))?;
        let geo = crate::v2_layers::LayerGeometry::for_file(
            self.info.files.get(file_idx)?.length,
            self.info.piece_len,
        )?;
        if base_layer != geo.base || count as usize > MAX_HASHES_PER_REQUEST {
            return None;
        }
        if !self.layer_trees.contains_key(&pieces_root) {
            let tree = synapse_meta::merkle::PieceLayerTree::new(
                self.piece_layer_bytes(&pieces_root)?,
                self.info.piece_len as usize,
            )?;
            self.layer_trees.insert(pieces_root, Arc::new(tree));
        }
        let tree = self.layer_trees.get(&pieces_root)?;
        let (hashes, proof) =
            tree.respond(index as usize, count as usize, proof_layers as usize)?;
        Some(Bytes::from(
            hashes
                .into_iter()
                .chain(proof)
                .flatten()
                .collect::<Vec<u8>>(),
        ))
    }

    /// A `hashes` message: only worth anything while we are fetching this file's layer, and
    /// then only if every chunk proves out against the file's `pieces root`. A peer that sends
    /// hashes that do not verify takes a strike (the same accounting as invalid requests).
    #[allow(clippy::too_many_arguments)]
    async fn on_piece_layer_hashes(
        &mut self,
        id: PeerId,
        pieces_root: [u8; 32],
        base_layer: u32,
        index: u32,
        count: u32,
        proof_layers: u32,
        payload: &[u8],
    ) {
        if base_layer == 0 {
            // Block-level hashes are only used if we asked *this* peer for exactly this range,
            // and only after the proof ties them to the file root: a peer must not be able to
            // get someone else banned by inventing hashes.
            let Some(audit) = self.pending_block_audits.remove(&(id, pieces_root, index)) else {
                return;
            };
            let cells = payload.as_chunks::<32>().0;
            let expected_cells = audit.count as usize + proof_layers as usize;
            if count != audit.count
                || payload.len() != expected_cells * 32
                || cells.len() != expected_cells
                || !synapse_meta::merkle::verify_piece_layer_chunk(
                    &pieces_root,
                    audit.level_size,
                    index as usize,
                    &cells[..audit.count as usize],
                    &cells[audit.count as usize..],
                )
            {
                if let Some(peer) = self.peers.get_mut(&id) {
                    peer.invalid_requests += INVALID_HASHES_STRIKES;
                }
                return;
            }
            let hashes = &cells[..audit.count as usize];
            for (b_idx, chunk) in audit.data.chunks(BLOCK_LEN as usize).enumerate() {
                let Some(expected) = hashes.get(b_idx) else {
                    break;
                };
                if synapse_meta::merkle::hash_block(chunk) != *expected {
                    let block_offset = b_idx as u32 * BLOCK_LEN;
                    if let Some(bad_ip) = audit.contributors.get(&block_offset).copied() {
                        tracing::warn!(
                            %bad_ip,
                            piece = audit.piece,
                            block = b_idx,
                            "BEP 52 pinpointed a corrupt block; banning its sender"
                        );
                        self.ban_address(bad_ip);
                    }
                }
            }
            return;
        }

        let Some(pos) = self
            .layer_fetches
            .iter()
            .position(|f| *f.root() == pieces_root)
        else {
            return; // not fetching this layer (we have it, or it is not ours): ignore quietly
        };
        let fetch = &mut self.layer_fetches[pos];
        match fetch.on_hashes(base_layer, index, count, proof_layers, payload) {
            Ok(None) => {}
            Ok(Some(layer)) => {
                tracing::info!(name = %self.info.name, pieces = layer.len() / 32, "BEP 52 piece layer fetched and verified");
                self.dynamic_piece_layers.insert(pieces_root, layer);
                self.layer_fetches.remove(pos);
                if self.layer_fetches.is_empty() {
                    let peer_ids: Vec<PeerId> = self.peers.keys().copied().collect();
                    for pid in peer_ids {
                        self.try_request_more(pid).await;
                    }
                }
            }
            Err(()) => {
                tracing::debug!(peer = %id, "ignoring unverifiable BEP 52 hashes message");
                if let Some(peer) = self.peers.get_mut(&id) {
                    peer.invalid_requests += INVALID_HASHES_STRIKES;
                }
            }
        }
    }

    fn request_piece_block_hashes(
        &mut self,
        piece_index: u32,
        piece_buf: &[u8],
        contributors: &HashMap<u32, IpAddr>,
    ) {
        let now = std::time::Instant::now();
        self.pending_block_audits.retain(|_, a| a.deadline > now);
        if self.pending_block_audits.len() >= MAX_BLOCK_AUDITS {
            return;
        }
        let block = synapse_meta::merkle::BLOCK_SIZE as u64;
        let piece_len = u64::from(self.info.piece_len);
        let locs = self.info.block_locations(piece_index, 0, 1);
        let Some(loc) = locs.first() else { return };
        let Some(Some(root)) = self.info.file_roots.get(loc.file) else {
            return;
        };
        let file_len = self.info.files[loc.file].length;
        if !piece_len.is_power_of_two() || piece_len < block || loc.file_offset % piece_len != 0 {
            return;
        }
        let leaves = file_len.div_ceil(block).next_power_of_two();
        let count = (piece_len / block).min(leaves);
        if count as usize > MAX_HASHES_PER_REQUEST {
            return;
        }
        let proof_layers = leaves.trailing_zeros() - count.trailing_zeros();
        let index = (loc.file_offset / block) as u32;

        // Ask a peer that did not send any of the blocks, so the answer is not from the suspect.
        let suspects: HashSet<IpAddr> = contributors.values().copied().collect();
        let Some((&peer_id, peer)) = self
            .peers
            .iter()
            .find(|(_, p)| !suspects.contains(&p.peer_info.addr.ip()))
        else {
            return;
        };
        let real = self.info.piece_real_len(piece_index).min(piece_buf.len());
        if !peer.handle.try_send(Message::HashRequest {
            pieces_root: *root,
            base_layer: 0,
            index,
            count: count as u32,
            proof_layers,
        }) {
            return;
        }
        self.pending_block_audits.insert(
            (peer_id, *root, index),
            BlockAudit {
                piece: piece_index,
                data: piece_buf[..real].to_vec(),
                contributors: contributors.clone(),
                count: count as u32,
                level_size: leaves as usize,
                deadline: now + BLOCK_AUDIT_TIMEOUT,
            },
        );
    }

    /// Asks connected peers for the piece-layer chunks we still need (pure-v2 torrents whose
    /// metainfo carried no layer, i.e. a v2 magnet). Hybrid torrents verify with their v1
    /// hashes and never need this; a hybrid connection also is not a v2 connection, on which
    /// real clients disconnect a peer for sending hash requests.
    fn request_piece_layers(&mut self) {
        if self.layer_fetches.is_empty() {
            return;
        }
        let peers: Vec<PeerId> = self.peers.keys().copied().collect();
        let now = std::time::Instant::now();
        // Work through the files a few at a time so a many-file torrent does not ask every peer
        // for every layer at once.
        for fetch in self
            .layer_fetches
            .iter_mut()
            .take(MAX_CONCURRENT_LAYER_FETCHES)
        {
            let geo = fetch.geometry();
            let root = *fetch.root();
            for req in fetch.due_requests(now, &peers) {
                if let Some(peer) = self.peers.get(&req.peer) {
                    let _ = peer.handle.try_send(Message::HashRequest {
                        pieces_root: root,
                        base_layer: geo.base,
                        index: req.index,
                        count: req.count,
                        proof_layers: geo.proof_layers,
                    });
                }
            }
        }
    }

    /// One fetch per file whose piece layer the metainfo did not carry (files that fit in one
    /// piece need none). Pure v2 only: identified by the truncated SHA-256 (see `Info::hash`).
    fn initial_layer_fetches(info: &Info) -> Vec<crate::v2_layers::LayerFetch> {
        let Some(v2) = info.info_hash_v2 else {
            return Vec::new();
        };
        if info.hash[..] != v2[..20] {
            return Vec::new();
        }
        let mut seen = std::collections::HashSet::new();
        info.files
            .iter()
            .zip(&info.file_roots)
            .filter_map(|(file, root)| {
                let root = (*root)?;
                if file.length == 0 || info.piece_layers.contains_key(&root) || !seen.insert(root) {
                    return None;
                }
                crate::v2_layers::LayerFetch::new(root, file.length, info.piece_len)
            })
            .collect()
    }

    fn piece_hash_v2_from_dynamic(&self, index: u32) -> Option<[u8; 32]> {
        if self.info.file_roots.is_empty() || self.info.files.is_empty() {
            return None;
        }
        let locs = self.info.block_locations(index, 0, 1);
        let loc = locs.first()?;
        let file_root = self.info.file_roots.get(loc.file)?.as_ref()?;
        let file_len = self.info.files.get(loc.file)?.length;
        if file_len <= u64::from(self.info.piece_len) {
            Some(*file_root)
        } else {
            let piece_in_file = (loc.file_offset / u64::from(self.info.piece_len)) as usize;
            let layer = self.dynamic_piece_layers.get(file_root)?;
            let start = piece_in_file * 32;
            let end = start + 32;
            if end <= layer.len() {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&layer[start..end]);
                Some(hash)
            } else {
                None
            }
        }
    }

    pub async fn check_local_webseed_cache(&mut self) {
        let Some(resolver) = self.local_webseed_resolver.clone() else {
            return;
        };
        let files = self.info.files.clone();
        for (file_idx, file) in files.iter().enumerate() {
            if let Some(cached_path) = resolver.find_local_file(&file.path) {
                if let Ok(meta) = tokio::fs::metadata(&cached_path).await {
                    if meta.len() == file.length {
                        if let Some((start_p, end_p)) = self.info.piece_range_for_file(file_idx) {
                            for p in start_p..=end_p {
                                if !self.picker.have(p) {
                                    let piece_len = self.info.piece_len(p);
                                    // Only a piece lying wholly inside this file can be checked
                                    // from it alone; one that straddles a file boundary is skipped.
                                    let locs = self.info.block_locations(p, 0, piece_len);
                                    let [loc] = locs.as_slice() else {
                                        continue;
                                    };
                                    let mut buf = vec![0u8; piece_len as usize];
                                    if let Ok(mut f) = tokio::fs::File::open(&cached_path).await {
                                        use tokio::io::{AsyncReadExt, AsyncSeekExt};
                                        if f.seek(std::io::SeekFrom::Start(loc.file_offset))
                                            .await
                                            .is_ok()
                                            && f.read_exact(&mut buf).await.is_ok()
                                        {
                                            let verified =
                                                if let Some(expected) = self.info.piece_hash(p) {
                                                    let comp: [u8; 20] = Sha1::digest(&buf).into();
                                                    comp == expected
                                                } else if let Some(expected_v2) =
                                                    self.info.piece_hash_v2(p)
                                                {
                                                    let comp: [u8; 32] =
                                                        self.info.compute_piece_hash_v2(p, &buf);
                                                    comp == expected_v2
                                                } else {
                                                    false
                                                };
                                            if verified {
                                                let _ = self.write_piece(p, Bytes::from(buf)).await;
                                                self.picker.mark_complete(p);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// BEP 30: a block of a Merkle torrent. The hash list that comes with a piece's first block
    /// is checked against the torrent's root hash; only then is the piece hash it carries
    /// trusted, and the block is handled like any other.
    async fn on_tr_hashpiece(&mut self, id: PeerId, m: synapse_wire::TrHashPiece) {
        let Some(root) = self.info.root_hash_v1 else {
            return;
        };
        let strike = |this: &mut Self| {
            if let Some(peer) = this.peers.get_mut(&id) {
                peer.invalid_requests += INVALID_HASHES_STRIKES;
            }
        };
        if m.index >= self.info.pieces() {
            strike(self);
            return;
        }
        if m.begin == 0 {
            match synapse_meta::merkle_v1::verify_hashlist(
                &m.hashlist,
                m.index as usize,
                self.info.pieces() as usize,
                &root,
            ) {
                Some(hash) => {
                    self.merkle_hashes.insert(m.index, hash);
                }
                None => {
                    tracing::debug!(peer = %id, piece = m.index, "Tr_hashpiece hash list does not prove out against the root hash");
                    strike(self);
                    return;
                }
            }
        }
        self.on_block(id, m.index, m.begin, m.data).await;
    }

    /// Starts building the Merkle tree from the data on disk (a seeder needs the hashes of all
    /// pieces to send hash lists). Only possible once every piece is present.
    async fn start_merkle_build(&mut self) {
        if self.merkle_building || self.merkle_tree.is_some() || !self.picker.is_complete() {
            return;
        }
        self.merkle_building = true;
        let mut jobs = Vec::with_capacity(self.info.pieces() as usize);
        for idx in 0..self.info.pieces() {
            let len = self.info.piece_len(idx);
            let mut slices = Vec::new();
            for loc in self.info.block_locations(idx, 0, len) {
                let normal_path = self.download_dir.join(&self.info.files[loc.file].path);
                let (path, offset) =
                    self.part_file
                        .resolve_read_location(loc.file, loc.file_offset, normal_path);
                slices.push(ReadJob {
                    path: Arc::new(path),
                    offset,
                    len: loc.piece_range.len(),
                });
            }
            jobs.push(slices);
        }
        let (disk, tx, root) = (
            self.disk.clone(),
            self.merkle_tx.clone(),
            self.info.root_hash_v1,
        );
        tokio::spawn(async move {
            let mut hashes = Vec::with_capacity(jobs.len());
            for slices in jobs {
                let mut hasher = Sha1::new();
                for job in slices {
                    match disk.read(job).await {
                        Ok(data) => hasher.update(&data),
                        Err(_) => {
                            let _ = tx.send(None).await;
                            return;
                        }
                    }
                }
                hashes.push(<[u8; 20]>::from(hasher.finalize()));
            }
            let tree = synapse_meta::merkle_v1::MerkleTreeV1::from_piece_hashes(&hashes)
                .filter(|t| Some(t.root()) == root);
            let _ = tx.send(tree).await;
        });
    }

    fn on_merkle_tree_built(&mut self, tree: Option<synapse_meta::merkle_v1::MerkleTreeV1>) {
        self.merkle_building = false;
        match tree {
            Some(t) => self.merkle_tree = Some(Arc::new(t)),
            None => tracing::warn!(
                name = %self.info.name,
                "the data on disk does not match the Merkle root hash; not serving this torrent"
            ),
        }
    }

    pub fn broadcast_dont_have(&mut self, piece: u32) {
        let msg = synapse_wire::LtDontHave::new(piece);
        let payload = msg.encode();
        for peer in self.peers.values() {
            if let Some(&ext_id) = peer.peer_extensions.get("lt_donthave") {
                let _ = peer.handle.try_send(Message::Extension {
                    id: ext_id,
                    payload: payload.clone(),
                });
            }
        }
    }
}
