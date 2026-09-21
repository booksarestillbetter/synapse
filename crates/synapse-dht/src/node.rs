//! The networked DHT node: a single tokio task owns the UDP socket, routing table,
//! token secret, and announced-peer storage, driven by a `select!` over incoming
//! packets, an outbound-command channel, and a periodic maintenance tick.
//!
//! **Scope of this first cut**: this implements the KRPC wire handling, routing table
//! maintenance, BEP5 token security, and peer-announce storage/expiry correctly and
//! completely, plus *single-hop* query primitives (`ping`/`find_node`/`get_peers`/
//! `announce_peer` against one already-known address). It does **not** yet implement
//! iterative network-wide lookup (recursively following a `find_node`/`get_peers`
//! response's returned nodes to walk toward a target across the wider network) - that's
//! what actually makes DHT-only ("trackerless") peer discovery useful beyond nodes we
//! already know about, and it's a real, separate piece of complexity (parallelism,
//! termination conditions) worth its own focused pass rather than folding in here.
//! Until then, this node is fully correct and useful as a good DHT citizen (it responds
//! properly to any incoming query, which is how routing tables across the network learn
//! about it) and for direct queries to specific known nodes.

use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngCore;
use sha1::{Digest, Sha1};
use synapse_wire::UdpTransport;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use crate::dos::{DosBlocker, ReplyQuota};
use crate::ip_voter::IpVoter;
use crate::proto::{
    Body, GetItem, GetPeersResult, Message, NodeId, NodeInfo, NodeInfoV6, PutArgs, Query, Response,
};
use crate::routing::{self, Node, NodeV6, RoutingTable, RoutingTableV6};
use crate::sample::{DhtScrapeResponse, SampleInfohashesResponse};
use crate::storage::{
    compute_immutable_target, compute_mutable_target, DhtItem, DhtStorage, StorageError,
    MAX_ITEM_VALUE_LEN, MAX_SALT_LEN,
};

const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const TOKEN_ROTATION: Duration = Duration::from_secs(5 * 60);
const PEER_TTL: Duration = Duration::from_secs(30 * 60);
/// Token rotation and announced-peer TTL expiry aren't latency-sensitive, so they only
/// need to be swept occasionally.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);
/// Pending outbound queries need a much tighter sweep than `MAINTENANCE_INTERVAL` -
/// otherwise a query could sit past its actual `QUERY_TIMEOUT` for up to a whole
/// maintenance period before anyone notices and fails it.
const PENDING_SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// Large enough for a `get_peers`/`find_node` response carrying a full bucket of
/// compact nodes plus a sizeable peer list, without UDP silently truncating it - same
/// reasoning as the pre-rewrite Phase 4 fix for the equivalent buffer.
const RECV_BUF_LEN: usize = 2048;

/// Storage caps for announced peers (libtorrent's `dht_storage`): torrents tracked, peers
/// kept per torrent, and peers returned in one `get_peers` reply (which keeps the reply
/// within a single MTU). Without them any host could grow this map without bound.
const MAX_ANNOUNCED_TORRENTS: usize = 2000;
const MAX_PEERS_PER_TORRENT: usize = 500;
const MAX_PEERS_PER_REPLY: usize = 100;
/// Largest datagram we will even try to decode; real KRPC messages are far smaller.
const MAX_PACKET_LEN: usize = 1500;
/// Infohashes returned in one BEP 51 `sample_infohashes` reply, and how long a crawler is
/// told to wait before asking again.
const MAX_SAMPLES_PER_REPLY: usize = 20;
const SAMPLE_INTERVAL_SECS: i64 = 3600;

/// Behaviour switches for a DHT node.
#[derive(Debug, Clone, Copy, Default)]
pub struct DhtOptions {
    /// BEP 43: act as a read-only node. Our queries carry `ro=1` so peers do not add us to
    /// their routing tables, and we do not answer incoming queries. For nodes that cannot
    /// receive unsolicited UDP (behind NAT, no mapped port) and would only slow lookups.
    pub read_only: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum DhtError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("the DHT node task is no longer running")]
    Closed,
    #[error("query timed out")]
    Timeout,
    #[error("malformed or unexpected response")]
    Malformed,
    #[error("remote returned an error: {0}")]
    Remote(String),
}

struct AnnouncedPeer {
    addr: SocketAddr,
    announced_at: Instant,
    seed: bool,
}

struct PendingQuery {
    reply: oneshot::Sender<Result<Message, DhtError>>,
    sent_at: Instant,
    target_addr: SocketAddr,
    target_id: Option<NodeId>,
}

struct TokenSecrets {
    current: [u8; 20],
    previous: [u8; 20],
}

impl TokenSecrets {
    fn generate() -> TokenSecrets {
        TokenSecrets {
            current: random_secret(),
            previous: random_secret(),
        }
    }

    /// Tokens are bound to the requester's IP *and* the info hash they were issued for, so
    /// one obtained for a cheap swarm cannot be replayed to announce into another.
    fn make_token(&self, addr: &SocketAddr, info_hash: &[u8; 20]) -> Vec<u8> {
        token_hash(&self.current, addr, info_hash)
    }

    fn validate(&self, token: &[u8], addr: &SocketAddr, info_hash: &[u8; 20]) -> bool {
        // Both candidates are always evaluated, and compared without early exit, so the
        // check does not leak how much of a guessed token was right.
        let current = ct_eq(token, &token_hash(&self.current, addr, info_hash));
        let previous = ct_eq(token, &token_hash(&self.previous, addr, info_hash));
        current | previous
    }
}

/// Constant-time equality for equal-length byte strings; unequal lengths are simply unequal.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Bundles the routing table and per-packet-handling state together purely to keep
/// `handle_packet`/`handle_query`'s argument counts sane - they're otherwise
/// independent pieces of `run`'s local state, not a cohesive type in their own right.
struct PacketCtx<'a> {
    routing: &'a mut RoutingTable,
    routing_v6: &'a mut RoutingTableV6,
    pending: &'a mut HashMap<Vec<u8>, PendingQuery>,
    announced: &'a mut HashMap<[u8; 20], Vec<AnnouncedPeer>>,
    storage: &'a mut DhtStorage,
    read_only: bool,
    /// Set by `handle_packet` when a reply to one of our queries reports our external address:
    /// (the node that reported it, the address it saw). Consumed by `apply_vote`.
    vote: &'a mut Option<(std::net::IpAddr, std::net::IpAddr)>,
}

#[derive(Debug, Clone, Default)]
pub struct IterativePeersResult {
    pub peers: Vec<SocketAddrV4>,
    pub peers6: Vec<SocketAddrV6>,
    pub closest_nodes: Vec<(NodeInfo, Vec<u8>)>,
    pub closest_nodes6: Vec<(NodeInfoV6, Vec<u8>)>,
}

enum Command {
    Query {
        addr: SocketAddr,
        node_id: Option<NodeId>,
        query: Box<Query>,
        reply: oneshot::Sender<Result<Message, DhtError>>,
    },
    Snapshot {
        reply: oneshot::Sender<Vec<Node>>,
    },
    SnapshotV6 {
        reply: oneshot::Sender<Vec<NodeV6>>,
    },
    State {
        reply: oneshot::Sender<(NodeId, Vec<SocketAddr>)>,
    },
    ClosestNodes {
        target: NodeId,
        count: usize,
        reply: oneshot::Sender<Vec<Node>>,
    },
    ClosestNodesV6 {
        target: NodeId,
        count: usize,
        reply: oneshot::Sender<Vec<NodeV6>>,
    },
}

#[derive(Clone)]
pub struct DhtHandle {
    /// Our node id. It can change once, after enough nodes agree on our external address, when
    /// BEP 42 requires the id to be derived from it (see `ip_voter`).
    our_id: Arc<std::sync::RwLock<NodeId>>,
    cmd_tx: mpsc::Sender<Command>,
    dos_blocks: Arc<AtomicU64>,
    /// BEP 43 read-only switch, read by the node for every packet so it can be flipped live.
    read_only: Arc<std::sync::atomic::AtomicBool>,
}

/// Binds and starts a DHT node, returning a handle to it plus the address it actually
/// bound to (useful when `bind_addr`'s port is 0, i.e. "pick any free port").
pub async fn spawn(
    our_id: NodeId,
    bind_addr: SocketAddr,
) -> std::io::Result<(DhtHandle, SocketAddr)> {
    spawn_with_options(our_id, bind_addr, DhtOptions::default()).await
}

/// Like [`spawn`], with explicit [`DhtOptions`].
pub async fn spawn_with_options(
    our_id: NodeId,
    bind_addr: SocketAddr,
    options: DhtOptions,
) -> std::io::Result<(DhtHandle, SocketAddr)> {
    let socket = UdpTransport::Plain(UdpSocket::bind(bind_addr).await?);
    let local_addr = socket.local_addr()?;
    let (v4, v6) = match local_addr {
        SocketAddr::V4(_) => (Some(socket), None),
        SocketAddr::V6(_) => (None, Some(socket)),
    };
    let handle = spawn_with_transports(our_id, v4, v6, options);
    Ok((handle, local_addr))
}

/// Starts a node on already-bound transports, IPv4 and/or IPv6. This is how the DHT shares
/// a UDP port with uTP (see `synapse_wire::UdpMux`).
pub fn spawn_with_transports(
    our_id: NodeId,
    v4: Option<UdpTransport>,
    v6: Option<UdpTransport>,
    options: DhtOptions,
) -> DhtHandle {
    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let dos_blocks = Arc::new(AtomicU64::new(0));
    let id_cell = Arc::new(std::sync::RwLock::new(our_id));
    let read_only = Arc::new(std::sync::atomic::AtomicBool::new(options.read_only));
    tokio::spawn(run(
        id_cell.clone(),
        v4.map(Arc::new),
        v6.map(Arc::new),
        cmd_rx,
        options,
        dos_blocks.clone(),
        read_only.clone(),
    ));
    DhtHandle {
        our_id: id_cell,
        cmd_tx,
        dos_blocks,
        read_only,
    }
}

/// Binds an IPv6 UDP socket that carries *only* IPv6 traffic (`IPV6_V6ONLY`). Without this,
/// on Linux (where a `[::]` socket also accepts IPv4 by default) binding it on the same port
/// as the IPv4 socket fails with `EADDRINUSE`, which is exactly the layout a dual-stack node
/// wants (one port, two sockets).
pub fn bind_udp_v6_only(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

/// Binds both an IPv4 and IPv6 UDP socket for dual-stack DHT operation.
pub async fn spawn_dual(
    our_id: NodeId,
    bind_v4: SocketAddr,
    bind_v6: SocketAddr,
) -> std::io::Result<(DhtHandle, SocketAddr, SocketAddr)> {
    spawn_dual_with_options(our_id, bind_v4, bind_v6, DhtOptions::default()).await
}

/// Like [`spawn_dual`], with explicit [`DhtOptions`].
pub async fn spawn_dual_with_options(
    our_id: NodeId,
    bind_v4: SocketAddr,
    bind_v6: SocketAddr,
    options: DhtOptions,
) -> std::io::Result<(DhtHandle, SocketAddr, SocketAddr)> {
    let s_v4 = UdpTransport::Plain(UdpSocket::bind(bind_v4).await?);
    let local_v4 = s_v4.local_addr()?;
    let s_v6 = UdpTransport::Plain(bind_udp_v6_only(bind_v6)?);
    let local_v6 = s_v6.local_addr()?;
    let handle = spawn_with_transports(our_id, Some(s_v4), Some(s_v6), options);
    Ok((handle, local_v4, local_v6))
}

impl DhtHandle {
    /// Switches BEP 43 read-only mode on or off while the node runs: from the next packet on,
    /// our queries carry `ro=1` and incoming queries go unanswered (or not).
    pub fn set_read_only(&self, read_only: bool) {
        self.read_only
            .store(read_only, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn our_id(&self) -> NodeId {
        *self.our_id.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Our id and every routing-table node that has not gone bad, for persisting across
    /// restarts (see [`crate::state`]).
    pub async fn state(&self) -> Result<(NodeId, Vec<SocketAddr>), DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::State { reply: tx })
            .await
            .map_err(|_| DhtError::Closed)?;
        rx.await.map_err(|_| DhtError::Closed)
    }

    pub fn dos_blocks_total(&self) -> u64 {
        self.dos_blocks.load(Ordering::Relaxed)
    }

    async fn query(
        &self,
        addr: impl Into<SocketAddr>,
        node_id: Option<NodeId>,
        query: Query,
    ) -> Result<Message, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Query {
                addr: addr.into(),
                node_id,
                query: Box::new(query),
                reply: tx,
            })
            .await
            .map_err(|_| DhtError::Closed)?;
        rx.await.map_err(|_| DhtError::Closed)?
    }

    pub async fn ping(&self, addr: impl Into<SocketAddr>) -> Result<NodeId, DhtError> {
        let msg = self.query(addr, None, Query::Ping).await?;
        expect_response(msg, |r| matches!(r, Response::Id))
    }

    pub async fn find_node(
        &self,
        addr: impl Into<SocketAddr>,
        target: NodeId,
    ) -> Result<Vec<NodeInfo>, DhtError> {
        let (nodes, _) = self.find_node_both(addr, target, None).await?;
        Ok(nodes)
    }

    pub async fn find_node_v6(
        &self,
        addr: impl Into<SocketAddr>,
        target: NodeId,
    ) -> Result<Vec<NodeInfoV6>, DhtError> {
        let (_, nodes6) = self
            .find_node_both(addr, target, Some(vec!["n6".into()]))
            .await?;
        Ok(nodes6)
    }

    pub async fn find_node_both(
        &self,
        addr: impl Into<SocketAddr>,
        target: NodeId,
        want: Option<Vec<String>>,
    ) -> Result<(Vec<NodeInfo>, Vec<NodeInfoV6>), DhtError> {
        let msg = self
            .query(addr, None, Query::FindNode { target, want })
            .await?;
        match msg.body {
            Body::Response(Response::FindNode { nodes, nodes6 }) => Ok((nodes, nodes6)),
            Body::Response(_) => Err(DhtError::Malformed),
            Body::Error { message, .. } => Err(DhtError::Remote(message)),
            Body::Query(_) => Err(DhtError::Malformed),
        }
    }

    pub async fn get_peers(
        &self,
        addr: impl Into<SocketAddr>,
        info_hash: [u8; 20],
    ) -> Result<(Vec<u8>, GetPeersResult), DhtError> {
        self.get_peers_with_want(addr, info_hash, None).await
    }

    pub async fn get_peers_with_want(
        &self,
        addr: impl Into<SocketAddr>,
        info_hash: [u8; 20],
        want: Option<Vec<String>>,
    ) -> Result<(Vec<u8>, GetPeersResult), DhtError> {
        let msg = self
            .query(addr, None, Query::GetPeers { info_hash, want })
            .await?;
        match msg.body {
            Body::Response(Response::GetPeers { token, result }) => Ok((token, result)),
            Body::Response(_) => Err(DhtError::Malformed),
            Body::Error { message, .. } => Err(DhtError::Remote(message)),
            Body::Query(_) => Err(DhtError::Malformed),
        }
    }

    pub async fn announce_peer(
        &self,
        addr: impl Into<SocketAddr>,
        info_hash: [u8; 20],
        port: u16,
        token: Vec<u8>,
    ) -> Result<(), DhtError> {
        self.announce_peer_impl(addr, info_hash, port, token, false)
            .await
    }

    pub async fn announce_peer_implied(
        &self,
        addr: impl Into<SocketAddr>,
        info_hash: [u8; 20],
        token: Vec<u8>,
    ) -> Result<(), DhtError> {
        self.announce_peer_impl(addr, info_hash, 0, token, true)
            .await
    }

    async fn announce_peer_impl(
        &self,
        addr: impl Into<SocketAddr>,
        info_hash: [u8; 20],
        port: u16,
        token: Vec<u8>,
        implied_port: bool,
    ) -> Result<(), DhtError> {
        let msg = self
            .query(
                addr,
                None,
                Query::AnnouncePeer {
                    info_hash,
                    port,
                    token,
                    implied_port,
                },
            )
            .await?;
        expect_response(msg, |r| matches!(r, Response::Id)).map(|_| ())
    }

    /// BEP 44 `get`: asks `addr` for the item at `target`. Returns the write token (needed
    /// for a following `put`) and the item if the node holds it. `seq`, for a mutable item,
    /// means "only send it if newer than this".
    pub async fn get(
        &self,
        addr: impl Into<SocketAddr>,
        target: [u8; 20],
        seq: Option<u64>,
    ) -> Result<(Vec<u8>, Option<GetItem>), DhtError> {
        let msg = self.query(addr, None, Query::Get { target, seq }).await?;
        match msg.body {
            Body::Response(Response::Get { token, item, .. }) => Ok((token, Some(item))),
            Body::Response(Response::GetPeers { token, .. }) => Ok((token, None)),
            Body::Response(_) => Err(DhtError::Malformed),
            Body::Error { message, .. } => Err(DhtError::Remote(message)),
            Body::Query(_) => Err(DhtError::Malformed),
        }
    }

    /// BEP 44 `put` of an already-built argument set (see [`PutArgs`]); `token` comes from a
    /// preceding [`DhtHandle::get`] on the item's target.
    pub async fn put(&self, addr: impl Into<SocketAddr>, args: PutArgs) -> Result<(), DhtError> {
        let msg = self.query(addr, None, Query::Put(args)).await?;
        expect_response(msg, |r| matches!(r, Response::Id)).map(|_| ())
    }

    /// BEP 51 `sample_infohashes`: a random sample of the info hashes `addr` stores.
    pub async fn sample_infohashes(
        &self,
        addr: impl Into<SocketAddr>,
        target: NodeId,
    ) -> Result<SampleInfohashesResponse, DhtError> {
        let msg = self
            .query(addr, None, Query::SampleInfohashes { target })
            .await?;
        match msg.body {
            Body::Response(Response::SampleInfohashes(s)) => Ok(s),
            Body::Response(_) => Err(DhtError::Malformed),
            Body::Error { message, .. } => Err(DhtError::Remote(message)),
            Body::Query(_) => Err(DhtError::Malformed),
        }
    }

    /// BEP 33 `scrape`: queries `addr` for swarm stats (seeders, leechers, and Bloom filters) for `info_hash`.
    pub async fn scrape(
        &self,
        addr: impl Into<SocketAddr>,
        info_hash: [u8; 20],
    ) -> Result<DhtScrapeResponse, DhtError> {
        let msg = self.query(addr, None, Query::Scrape { info_hash }).await?;
        match msg.body {
            Body::Response(Response::Scrape(s)) => Ok(s),
            Body::Response(_) => Err(DhtError::Malformed),
            Body::Error { message, .. } => Err(DhtError::Remote(message)),
            Body::Query(_) => Err(DhtError::Malformed),
        }
    }

    /// A snapshot of the routing table's current contents, mainly for tests/inspection.
    pub async fn routing_snapshot(&self) -> Result<Vec<Node>, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Snapshot { reply: tx })
            .await
            .map_err(|_| DhtError::Closed)?;
        rx.await.map_err(|_| DhtError::Closed)
    }

    /// A snapshot of the IPv6 routing table's current contents.
    pub async fn routing_snapshot_v6(&self) -> Result<Vec<NodeV6>, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::SnapshotV6 { reply: tx })
            .await
            .map_err(|_| DhtError::Closed)?;
        rx.await.map_err(|_| DhtError::Closed)
    }

    /// Query the local routing table for the `count` closest nodes to `target`.
    pub async fn closest_nodes(&self, target: NodeId, count: usize) -> Result<Vec<Node>, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::ClosestNodes {
                target,
                count,
                reply: tx,
            })
            .await
            .map_err(|_| DhtError::Closed)?;
        rx.await.map_err(|_| DhtError::Closed)
    }

    /// Query the local IPv6 routing table for the `count` closest nodes to `target`.
    pub async fn closest_nodes_v6(
        &self,
        target: NodeId,
        count: usize,
    ) -> Result<Vec<NodeV6>, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::ClosestNodesV6 {
                target,
                count,
                reply: tx,
            })
            .await
            .map_err(|_| DhtError::Closed)?;
        rx.await.map_err(|_| DhtError::Closed)
    }

    /// Recursively queries nodes across the DHT network to find the k-closest nodes to `target`.
    pub async fn iterative_find_node(
        &self,
        target: NodeId,
        bootstrap_nodes: &[SocketAddrV4],
    ) -> Result<Vec<NodeInfo>, DhtError> {
        let mut candidates: Vec<NodeInfo> = Vec::new();
        let mut seen_addrs = std::collections::HashSet::new();
        let mut queried_addrs = std::collections::HashSet::new();

        // 1. Seed from local routing table
        let local_closest = self.closest_nodes(target, routing::K).await?;
        for n in local_closest {
            seen_addrs.insert(n.addr);
            candidates.push(NodeInfo {
                id: n.id,
                addr: n.addr,
            });
        }

        // 2. Add bootstrap nodes
        for &addr in bootstrap_nodes {
            if seen_addrs.insert(addr) {
                candidates.push(NodeInfo {
                    id: [0u8; 20],
                    addr,
                });
            }
        }

        let alpha = 3;
        let mut step = 0;
        while step < 50 {
            step += 1;
            candidates.sort_by_key(|n| routing::xor_distance(&n.id, &target));

            let unqueried: Vec<NodeInfo> = candidates
                .iter()
                .filter(|n| !queried_addrs.contains(&n.addr))
                .take(alpha)
                .cloned()
                .collect();

            if unqueried.is_empty() {
                break;
            }

            let mut query_futs = Vec::new();
            for cand in unqueried {
                queried_addrs.insert(cand.addr);
                let handle = self.clone();
                query_futs.push(tokio::spawn(async move {
                    handle.find_node(cand.addr, target).await
                }));
            }

            let mut any_progress = false;
            for fut in query_futs {
                if let Ok(Ok(nodes)) = fut.await {
                    for node in nodes {
                        if seen_addrs.insert(node.addr) {
                            candidates.push(node);
                            any_progress = true;
                        }
                    }
                }
            }

            if !any_progress
                && candidates
                    .iter()
                    .filter(|n| !queried_addrs.contains(&n.addr))
                    .count()
                    == 0
            {
                break;
            }
        }

        candidates.sort_by_key(|n| routing::xor_distance(&n.id, &target));
        candidates.truncate(routing::K);
        Ok(candidates)
    }

    /// Recursively queries nodes across the DHT network for peers associated with `info_hash`.
    pub async fn iterative_get_peers(
        &self,
        info_hash: [u8; 20],
        bootstrap_nodes: &[SocketAddrV4],
    ) -> Result<IterativePeersResult, DhtError> {
        let target = info_hash;
        let mut candidates: Vec<NodeInfo> = Vec::new();
        let mut seen_addrs = std::collections::HashSet::new();
        let mut queried_addrs = std::collections::HashSet::new();

        let mut discovered_peers = std::collections::HashSet::new();
        let mut discovered_peers6 = std::collections::HashSet::new();
        let mut closest_nodes_with_tokens = Vec::new();

        // 1. Seed from local routing table
        let local_closest = self.closest_nodes(target, routing::K).await?;
        for n in local_closest {
            seen_addrs.insert(n.addr);
            candidates.push(NodeInfo {
                id: n.id,
                addr: n.addr,
            });
        }

        // 2. Add bootstrap nodes
        for &addr in bootstrap_nodes {
            if seen_addrs.insert(addr) {
                candidates.push(NodeInfo {
                    id: [0u8; 20],
                    addr,
                });
            }
        }

        let alpha = 3;
        let mut step = 0;
        while step < 50 {
            step += 1;
            candidates.sort_by_key(|n| routing::xor_distance(&n.id, &target));

            let unqueried: Vec<NodeInfo> = candidates
                .iter()
                .filter(|n| !queried_addrs.contains(&n.addr))
                .take(alpha)
                .cloned()
                .collect();

            if unqueried.is_empty() {
                break;
            }

            let mut query_futs = Vec::new();
            for cand in unqueried {
                queried_addrs.insert(cand.addr);
                let handle = self.clone();
                let cand_clone = cand;
                query_futs.push(tokio::spawn(async move {
                    let res = handle.get_peers(cand.addr, info_hash).await;
                    (cand_clone, res)
                }));
            }

            let mut any_progress = false;
            for fut in query_futs {
                if let Ok((cand, Ok((token, result)))) = fut.await {
                    match result {
                        GetPeersResult::Peers(peers) => {
                            for peer in peers {
                                discovered_peers.insert(peer);
                            }
                            closest_nodes_with_tokens.push((cand, token));
                            any_progress = true;
                        }
                        GetPeersResult::Peers6(peers6) => {
                            for peer in peers6 {
                                discovered_peers6.insert(peer);
                            }
                            closest_nodes_with_tokens.push((cand, token));
                            any_progress = true;
                        }
                        GetPeersResult::Nodes(nodes) => {
                            closest_nodes_with_tokens.push((cand, token));
                            for node in nodes {
                                if seen_addrs.insert(node.addr) {
                                    candidates.push(node);
                                    any_progress = true;
                                }
                            }
                        }
                        GetPeersResult::Nodes6(_) => {
                            closest_nodes_with_tokens.push((cand, token));
                        }
                    }
                }
            }

            if !any_progress
                && candidates
                    .iter()
                    .filter(|n| !queried_addrs.contains(&n.addr))
                    .count()
                    == 0
            {
                break;
            }
        }

        Ok(IterativePeersResult {
            peers: discovered_peers.into_iter().collect(),
            peers6: discovered_peers6.into_iter().collect(),
            closest_nodes: closest_nodes_with_tokens,
            closest_nodes6: Vec::new(),
        })
    }
}

fn expect_response(
    msg: Message,
    matches_expected: impl Fn(&Response) -> bool,
) -> Result<NodeId, DhtError> {
    match msg.body {
        Body::Response(ref r) if matches_expected(r) => msg.sender_id.ok_or(DhtError::Malformed),
        Body::Response(_) => Err(DhtError::Malformed),
        Body::Error { message, .. } => Err(DhtError::Remote(message)),
        Body::Query(_) => Err(DhtError::Malformed),
    }
}

async fn run(
    id_cell: Arc<std::sync::RwLock<NodeId>>,
    socket_v4: Option<Arc<UdpTransport>>,
    socket_v6: Option<Arc<UdpTransport>>,
    mut cmds: mpsc::Receiver<Command>,
    options: DhtOptions,
    dos_blocks: Arc<AtomicU64>,
    read_only_flag: Arc<std::sync::atomic::AtomicBool>,
) {
    let _ = options;
    let mut our_id = *id_cell.read().unwrap_or_else(|e| e.into_inner());
    let mut routing = RoutingTable::new(our_id);
    let mut routing_v6 = RoutingTableV6::new(our_id);
    let mut voter_v4 = IpVoter::new();
    let mut voter_v6 = IpVoter::new();
    let mut vote: Option<(std::net::IpAddr, std::net::IpAddr)> = None;
    let mut pending: HashMap<Vec<u8>, PendingQuery> = HashMap::new();
    let mut announced: HashMap<[u8; 20], Vec<AnnouncedPeer>> = HashMap::new();
    let mut secrets = TokenSecrets::generate();
    let mut last_rotation = Instant::now();
    let mut next_txn: u32 = rand::random();
    let mut buf_v4 = vec![0u8; RECV_BUF_LEN];
    let mut buf_v6 = vec![0u8; RECV_BUF_LEN];
    let mut maintenance = tokio::time::interval(MAINTENANCE_INTERVAL);
    let mut pending_sweep = tokio::time::interval(PENDING_SWEEP_INTERVAL);
    let mut storage = DhtStorage::default();
    let mut dos = DosBlocker::new();
    let mut quota = ReplyQuota::new(Instant::now());

    loop {
        tokio::select! {
            recvd = async {
                if let Some(s) = &socket_v4 {
                    s.recv_from(&mut buf_v4).await
                } else {
                    std::future::pending().await
                }
            } => {
                let Ok((n, from)) = recvd else { continue };
                if n > MAX_PACKET_LEN || !dos.allow(from.ip(), Instant::now()) {
                    dos_blocks.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let mut ctx = PacketCtx {
                    routing: &mut routing,
                    routing_v6: &mut routing_v6,
                    pending: &mut pending,
                    announced: &mut announced,
                    storage: &mut storage,
                    read_only: read_only_flag.load(std::sync::atomic::Ordering::Relaxed),
                    vote: &mut vote,
                };
                let s = socket_v4.as_ref().unwrap();
                handle_packet(&buf_v4[..n], from, s, our_id, &mut ctx, &secrets, &mut quota).await;
                apply_vote(&mut vote, &mut voter_v4, &mut voter_v6, &id_cell, &mut our_id, &mut routing, &mut routing_v6);
            }
            recvd = async {
                if let Some(s) = &socket_v6 {
                    s.recv_from(&mut buf_v6).await
                } else {
                    std::future::pending().await
                }
            } => {
                let Ok((n, from)) = recvd else { continue };
                if n > MAX_PACKET_LEN || !dos.allow(from.ip(), Instant::now()) {
                    dos_blocks.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let mut ctx = PacketCtx {
                    routing: &mut routing,
                    routing_v6: &mut routing_v6,
                    pending: &mut pending,
                    announced: &mut announced,
                    storage: &mut storage,
                    read_only: read_only_flag.load(std::sync::atomic::Ordering::Relaxed),
                    vote: &mut vote,
                };
                let s = socket_v6.as_ref().unwrap();
                handle_packet(&buf_v6[..n], from, s, our_id, &mut ctx, &secrets, &mut quota).await;
                apply_vote(&mut vote, &mut voter_v4, &mut voter_v6, &id_cell, &mut our_id, &mut routing, &mut routing_v6);
            }
            cmd = cmds.recv() => {
                match cmd {
                    Some(cmd) => {
                        let mut cmd_ctx = CommandCtx {
                            our_id,
                            socket_v4: socket_v4.as_deref(),
                            socket_v6: socket_v6.as_deref(),
                            next_txn: &mut next_txn,
                            pending: &mut pending,
                            routing: &routing,
                            routing_v6: &routing_v6,
                            read_only: read_only_flag.load(std::sync::atomic::Ordering::Relaxed),
                        };
                        handle_command(cmd, &mut cmd_ctx).await;
                    }
                    None => break, // All DhtHandles dropped, exit worker gracefully
                }
            }
            _ = pending_sweep.tick() => {
                let now = Instant::now();
                let expired: Vec<Vec<u8>> = pending
                    .iter()
                    .filter(|(_, pq)| now.duration_since(pq.sent_at) >= QUERY_TIMEOUT)
                    .map(|(k, _)| k.clone())
                    .collect();
                for key in expired {
                    if let Some(pq) = pending.remove(&key) {
                        if let Some(id) = pq.target_id {
                            match pq.target_addr {
                                SocketAddr::V4(_) => routing.mark_failed(&id),
                                SocketAddr::V6(_) => routing_v6.mark_failed(&id),
                            }
                        }
                        let _ = pq.reply.send(Err(DhtError::Timeout));
                    }
                }
            }
            _ = maintenance.tick() => {
                let now = Instant::now();
                announced.retain(|_, list| {
                    list.retain(|p| now.duration_since(p.announced_at) < PEER_TTL);
                    !list.is_empty()
                });
                storage.prune_expired();
                if now.duration_since(last_rotation) >= TOKEN_ROTATION {
                    secrets.previous = std::mem::replace(&mut secrets.current, random_secret());
                    last_rotation = now;
                }
            }
        }
    }
}

/// Feeds a reported-address vote (see `PacketCtx::vote`) to the per-family voters and, when the
/// vote produces a new consensus external address that our current node id does not match
/// under BEP 42, switches to a fresh id derived from it. The routing tables are rebuilt around
/// the new id (bucket placement is relative to it) keeping every node we already know.
fn apply_vote(
    vote: &mut Option<(std::net::IpAddr, std::net::IpAddr)>,
    voter_v4: &mut IpVoter,
    voter_v6: &mut IpVoter,
    id_cell: &Arc<std::sync::RwLock<NodeId>>,
    our_id: &mut NodeId,
    routing: &mut RoutingTable,
    routing_v6: &mut RoutingTableV6,
) {
    let Some((voter, reported)) = vote.take() else {
        return;
    };
    let voter_table = if voter.is_ipv4() { voter_v4 } else { voter_v6 };
    let Some(consensus) = voter_table.vote(voter, reported) else {
        return;
    };
    if crate::bep42::is_exempt_from_node_id_check(consensus)
        || crate::bep42::verify_secure_node_id(our_id, consensus)
    {
        return;
    }
    let new_id = crate::bep42::generate_secure_node_id(consensus, rand::random());
    tracing::info!(
        "DHT: external address agreed as {consensus}; adopting BEP 42 node id derived from it"
    );
    let old4 = routing.closest(our_id, usize::MAX);
    let old6 = routing_v6.closest(our_id, usize::MAX);
    *routing = RoutingTable::new(new_id);
    *routing_v6 = RoutingTableV6::new(new_id);
    for n in old4 {
        routing.seen(n.id, n.addr, n.last_seen);
    }
    for n in old6 {
        routing_v6.seen(n.id, n.addr, n.last_seen);
    }
    *our_id = new_id;
    *id_cell.write().unwrap_or_else(|e| e.into_inner()) = new_id;
}

struct CommandCtx<'a> {
    our_id: NodeId,
    socket_v4: Option<&'a UdpTransport>,
    socket_v6: Option<&'a UdpTransport>,
    next_txn: &'a mut u32,
    pending: &'a mut HashMap<Vec<u8>, PendingQuery>,
    routing: &'a RoutingTable,
    routing_v6: &'a RoutingTableV6,
    read_only: bool,
}

async fn handle_command(cmd: Command, ctx: &mut CommandCtx<'_>) {
    match cmd {
        Command::Query {
            addr,
            node_id,
            query,
            reply,
        } => {
            let socket = match addr {
                SocketAddr::V4(_) => ctx.socket_v4.or(ctx.socket_v6),
                SocketAddr::V6(_) => ctx.socket_v6.or(ctx.socket_v4),
            };
            let Some(socket) = socket else {
                let _ = reply.send(Err(DhtError::Io(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "no socket available for destination address family",
                ))));
                return;
            };
            let txn_id = ctx.next_txn.to_be_bytes().to_vec();
            *ctx.next_txn = ctx.next_txn.wrapping_add(1);
            let msg = Message {
                transaction_id: txn_id.clone(),
                sender_id: Some(ctx.our_id),
                body: Body::Query(*query),
                read_only: ctx.read_only,
                external_addr: None,
            };
            if let Err(e) = socket.send_to(&msg.encode(), addr).await {
                let _ = reply.send(Err(e.into()));
                return;
            }
            ctx.pending.insert(
                txn_id,
                PendingQuery {
                    reply,
                    sent_at: Instant::now(),
                    target_addr: addr,
                    target_id: node_id,
                },
            );
        }
        Command::Snapshot { reply } => {
            let _ = reply.send(ctx.routing.closest(&ctx.our_id, usize::MAX));
        }
        Command::State { reply } => {
            let now = Instant::now();
            let mut nodes: Vec<SocketAddr> = ctx
                .routing
                .closest(&ctx.our_id, usize::MAX)
                .into_iter()
                .filter(|n| n.state(now) != crate::routing::NodeState::Bad)
                .map(|n| SocketAddr::V4(n.addr))
                .collect();
            nodes.extend(
                ctx.routing_v6
                    .closest(&ctx.our_id, usize::MAX)
                    .into_iter()
                    .filter(|n| n.state(now) != crate::routing::NodeState::Bad)
                    .map(|n| SocketAddr::V6(n.addr)),
            );
            let _ = reply.send((ctx.our_id, nodes));
        }
        Command::SnapshotV6 { reply } => {
            let _ = reply.send(ctx.routing_v6.closest(&ctx.our_id, usize::MAX));
        }
        Command::ClosestNodes {
            target,
            count,
            reply,
        } => {
            let _ = reply.send(ctx.routing.closest(&target, count));
        }
        Command::ClosestNodesV6 {
            target,
            count,
            reply,
        } => {
            let _ = reply.send(ctx.routing_v6.closest(&target, count));
        }
    }
}

async fn handle_packet(
    data: &[u8],
    from: SocketAddr,
    socket: &UdpTransport,
    our_id: NodeId,
    ctx: &mut PacketCtx<'_>,
    secrets: &TokenSecrets,
    quota: &mut ReplyQuota,
) {
    let Ok(msg) = Message::decode(data) else {
        return;
    };

    match &msg.body {
        Body::Query(q) => {
            // BEP 43: a read-only node does not answer queries, and a read-only *sender*
            // never enters our routing table (it will not answer ours).
            if ctx.read_only {
                return;
            }
            if let Some(sender_id) = msg.sender_id.filter(|_| !msg.read_only) {
                match from {
                    SocketAddr::V4(v4) => {
                        ctx.routing.seen(sender_id, v4, Instant::now());
                    }
                    SocketAddr::V6(v6) => {
                        ctx.routing_v6.seen(sender_id, v6, Instant::now());
                    }
                }
            }
            let response_body = handle_query(q, from, ctx, secrets);
            let resp = Message {
                transaction_id: msg.transaction_id.clone(),
                sender_id: Some(our_id),
                body: response_body,
                read_only: false,
                // BEP 42: tell the querier what address we see it at.
                external_addr: Some(from),
            };
            let encoded = resp.encode();
            // A query is tiny and its source address may be forged, so replies are what
            // make a DHT node an amplifier; cap the bytes we send per second.
            if quota.try_consume(encoded.len(), Instant::now()) {
                let _ = socket.send_to(&encoded, from).await;
            }
        }
        Body::Response(_) | Body::Error { .. } => {
            // Reject a response whose source address doesn't match the node we
            // actually sent this transaction to: unlike the UDP tracker client (which
            // gets this for free from a `connect`ed socket), the DHT shares one socket
            // across every node it ever talks to, so this has to be checked here -
            // without it, any host that can send us a UDP packet and guess a live
            // transaction id could inject a fake response.
            let Some(pq) = ctx.pending.get(&msg.transaction_id) else {
                return;
            };
            if pq.target_addr != from {
                tracing::debug!(
                    expected = %pq.target_addr, got = %from,
                    "dropping DHT response from unexpected source address"
                );
                return;
            }
            let pq = ctx.pending.remove(&msg.transaction_id).unwrap();
            if let Some(reported) = msg.external_addr {
                *ctx.vote = Some((from.ip(), reported.ip()));
            }
            if let Some(sender_id) = msg.sender_id {
                match from {
                    SocketAddr::V4(v4) => {
                        ctx.routing.seen(sender_id, v4, Instant::now());
                    }
                    SocketAddr::V6(v6) => {
                        ctx.routing_v6.seen(sender_id, v6, Instant::now());
                    }
                }
            }
            let _ = pq.reply.send(Ok(msg));
        }
    }
}

fn handle_query(
    q: &Query,
    from: SocketAddr,
    ctx: &mut PacketCtx<'_>,
    secrets: &TokenSecrets,
) -> Body {
    match q {
        Query::Ping => Body::Response(Response::Id),
        Query::FindNode { target, want } => {
            let wants_v6 = match want.as_deref() {
                Some(w) => w.iter().any(|s| s == "n6"),
                None => from.is_ipv6(),
            };
            let wants_v4 = match want.as_deref() {
                Some(w) => w.iter().any(|s| s == "n4"),
                None => from.is_ipv4(),
            };
            let nodes = if wants_v4 {
                ctx.routing.closest_nodes(target, routing::K)
            } else {
                Vec::new()
            };
            let nodes6 = if wants_v6 {
                ctx.routing_v6.closest_nodes6(target, routing::K)
            } else {
                Vec::new()
            };
            Body::Response(Response::FindNode { nodes, nodes6 })
        }
        Query::GetPeers { info_hash, want } => {
            let token = secrets.make_token(&from, info_hash);
            let now = Instant::now();
            let wants_v6 = match want.as_deref() {
                Some(w) => w.iter().any(|s| s == "n6"),
                None => from.is_ipv6(),
            };
            let wants_v4 = match want.as_deref() {
                Some(w) => w.iter().any(|s| s == "n4"),
                None => from.is_ipv4(),
            };

            if let Some(list) = ctx.announced.get(info_hash) {
                // Most recently announced first, capped so the reply fits one packet.
                let mut fresh: Vec<&AnnouncedPeer> = list
                    .iter()
                    .filter(|p| now.duration_since(p.announced_at) < PEER_TTL)
                    .collect();
                fresh.sort_by_key(|p| std::cmp::Reverse(p.announced_at));

                if wants_v6 && !wants_v4 {
                    let v6_peers: Vec<SocketAddrV6> = fresh
                        .iter()
                        .filter_map(|p| match p.addr {
                            SocketAddr::V6(v6) => Some(v6),
                            _ => None,
                        })
                        .take(MAX_PEERS_PER_REPLY)
                        .collect();
                    if !v6_peers.is_empty() {
                        return Body::Response(Response::GetPeers {
                            token,
                            result: GetPeersResult::Peers6(v6_peers),
                        });
                    }
                } else if wants_v4 && !wants_v6 {
                    let v4_peers: Vec<SocketAddrV4> = fresh
                        .iter()
                        .filter_map(|p| match p.addr {
                            SocketAddr::V4(v4) => Some(v4),
                            _ => None,
                        })
                        .take(MAX_PEERS_PER_REPLY)
                        .collect();
                    if !v4_peers.is_empty() {
                        return Body::Response(Response::GetPeers {
                            token,
                            result: GetPeersResult::Peers(v4_peers),
                        });
                    }
                } else {
                    if from.is_ipv6() {
                        let v6_peers: Vec<SocketAddrV6> = fresh
                            .iter()
                            .filter_map(|p| match p.addr {
                                SocketAddr::V6(v6) => Some(v6),
                                _ => None,
                            })
                            .take(MAX_PEERS_PER_REPLY)
                            .collect();
                        if !v6_peers.is_empty() {
                            return Body::Response(Response::GetPeers {
                                token,
                                result: GetPeersResult::Peers6(v6_peers),
                            });
                        }
                    }
                    let v4_peers: Vec<SocketAddrV4> = fresh
                        .iter()
                        .filter_map(|p| match p.addr {
                            SocketAddr::V4(v4) => Some(v4),
                            _ => None,
                        })
                        .take(MAX_PEERS_PER_REPLY)
                        .collect();
                    if !v4_peers.is_empty() {
                        return Body::Response(Response::GetPeers {
                            token,
                            result: GetPeersResult::Peers(v4_peers),
                        });
                    }
                }
            }

            if wants_v6 && !wants_v4 {
                let nodes6 = ctx.routing_v6.closest_nodes6(info_hash, routing::K);
                Body::Response(Response::GetPeers {
                    token,
                    result: GetPeersResult::Nodes6(nodes6),
                })
            } else if wants_v4 && !wants_v6 {
                let nodes = ctx.routing.closest_nodes(info_hash, routing::K);
                Body::Response(Response::GetPeers {
                    token,
                    result: GetPeersResult::Nodes(nodes),
                })
            } else if from.is_ipv6() {
                let nodes6 = ctx.routing_v6.closest_nodes6(info_hash, routing::K);
                Body::Response(Response::GetPeers {
                    token,
                    result: GetPeersResult::Nodes6(nodes6),
                })
            } else {
                let nodes = ctx.routing.closest_nodes(info_hash, routing::K);
                Body::Response(Response::GetPeers {
                    token,
                    result: GetPeersResult::Nodes(nodes),
                })
            }
        }
        Query::AnnouncePeer {
            info_hash,
            port,
            token,
            implied_port,
        } => {
            if !secrets.validate(token, &from, info_hash) {
                return Body::Error {
                    code: 203,
                    message: "Bad token".to_owned(),
                };
            }
            let announce_port = if *implied_port { from.port() } else { *port };
            if announce_port == 0 {
                return Body::Error {
                    code: 203,
                    message: "Invalid port".to_owned(),
                };
            }
            let addr = match from {
                SocketAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(*v4.ip(), announce_port)),
                SocketAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(
                    *v6.ip(),
                    announce_port,
                    v6.flowinfo(),
                    v6.scope_id(),
                )),
            };
            let now = Instant::now();
            store_announce(ctx.announced, *info_hash, addr, now, false);
            Body::Response(Response::Id)
        }
        Query::Get { target, seq } => {
            let token = secrets.make_token(&from, target);
            let nodes: Vec<NodeInfo> = ctx.routing.closest_nodes(target, routing::K);
            let item = match ctx.storage.get(target) {
                Some(DhtItem::Immutable { value, .. }) => Some(GetItem {
                    v: value.clone(),
                    k: None,
                    sig: None,
                    seq: None,
                }),
                // BEP 44: a requester that already has this sequence number (or newer) is
                // only sent the closer nodes, not the value again.
                Some(DhtItem::Mutable {
                    public_key,
                    seq: stored,
                    sig,
                    value,
                    ..
                }) if seq.is_none_or(|s| s < *stored) => Some(GetItem {
                    v: value.clone(),
                    k: Some(*public_key),
                    sig: Some(*sig),
                    seq: Some(*stored),
                }),
                _ => None,
            };
            match item {
                Some(item) => Body::Response(Response::Get { token, item, nodes }),
                None => Body::Response(Response::GetPeers {
                    token,
                    result: GetPeersResult::Nodes(nodes),
                }),
            }
        }
        Query::Put(put) => handle_put(put, from, ctx, secrets),
        Query::SampleInfohashes { target } => {
            let mut hashes: Vec<[u8; 20]> = ctx.announced.keys().copied().collect();
            let num = hashes.len() as i64;
            {
                use rand::seq::SliceRandom;
                hashes.shuffle(&mut rand::thread_rng());
            }
            hashes.truncate(MAX_SAMPLES_PER_REPLY);
            let nodes = ctx.routing.closest_nodes(target, routing::K);
            let nodes6 = ctx.routing_v6.closest_nodes6(target, routing::K);
            Body::Response(Response::SampleInfohashes(SampleInfohashesResponse {
                samples: hashes,
                num,
                interval: SAMPLE_INTERVAL_SECS,
                nodes,
                nodes6,
            }))
        }
        Query::Scrape { info_hash } => {
            let mut seeders = 0u32;
            let mut leechers = 0u32;
            let mut bfsd = crate::sample::DhtBloomFilter::new();
            let mut bfpe = crate::sample::DhtBloomFilter::new();

            let now = Instant::now();
            if let Some(list) = ctx.announced.get(info_hash) {
                for p in list
                    .iter()
                    .filter(|p| now.duration_since(p.announced_at) < PEER_TTL)
                {
                    let ip = p.addr.ip();
                    bfpe.insert_ip(ip);
                    if p.seed {
                        seeders += 1;
                        bfsd.insert_ip(ip);
                    } else {
                        leechers += 1;
                    }
                }
            }
            Body::Response(Response::Scrape(DhtScrapeResponse {
                seeders,
                leechers,
                bfsd: Some(bfsd.bytes.to_vec()),
                bfpe: Some(bfpe.bytes.to_vec()),
            }))
        }
    }
}

/// BEP 44 `put`. Error codes follow the spec: 203 protocol/bad token, 205 message too big,
/// 206 invalid signature, 207 salt too big, 301 CAS mismatch, 302 sequence number too low.
fn handle_put(
    put: &PutArgs,
    from: SocketAddr,
    ctx: &mut PacketCtx<'_>,
    secrets: &TokenSecrets,
) -> Body {
    let err = |code: i64, message: &str| Body::Error {
        code,
        message: message.to_owned(),
    };
    if put.v.len() > MAX_ITEM_VALUE_LEN {
        return err(205, "Message too big");
    }
    if put.salt.as_ref().is_some_and(|s| s.len() > MAX_SALT_LEN) {
        return err(207, "Salt too big");
    }
    let target = match put.k {
        Some(k) => compute_mutable_target(&k, put.salt.as_deref()),
        None => compute_immutable_target(&put.v),
    };
    if !secrets.validate(&put.token, &from, &target) {
        return err(203, "Bad token");
    }
    let stored = match put.k {
        Some(k) => {
            let (Some(sig), Some(seq)) = (put.sig, put.seq) else {
                return err(203, "Mutable put requires sig and seq");
            };
            ctx.storage
                .put_mutable(k, seq, sig, put.v.clone(), put.salt.clone(), put.cas)
        }
        None => ctx.storage.put_immutable(put.v.clone()),
    };
    match stored {
        Ok(_) => Body::Response(Response::Id),
        Err(StorageError::InvalidSignature | StorageError::InvalidPublicKey) => {
            err(206, "Invalid signature")
        }
        Err(StorageError::CasMismatch { .. }) => err(301, "CAS mismatch"),
        Err(StorageError::StaleSequence { .. }) => err(302, "Sequence number less than current"),
        Err(StorageError::ValueTooLarge) => err(205, "Message too big"),
        Err(StorageError::SaltTooLarge) => err(207, "Salt too big"),
    }
}

/// Records `addr` as a peer of `info_hash`, within the storage caps: at most
/// `MAX_ANNOUNCED_TORRENTS` torrents (a new one evicts the torrent with the fewest peers,
/// so popular swarms survive a flood of fake ones) and `MAX_PEERS_PER_TORRENT` peers each
/// (a new one replaces the oldest).
fn store_announce(
    announced: &mut HashMap<[u8; 20], Vec<AnnouncedPeer>>,
    info_hash: [u8; 20],
    addr: SocketAddr,
    now: Instant,
    seed: bool,
) {
    if !announced.contains_key(&info_hash) && announced.len() >= MAX_ANNOUNCED_TORRENTS {
        if let Some(&victim) = announced
            .iter()
            .min_by_key(|(_, l)| l.len())
            .map(|(h, _)| h)
        {
            announced.remove(&victim);
        }
    }
    let list = announced.entry(info_hash).or_default();
    if let Some(p) = list.iter_mut().find(|p| p.addr == addr) {
        p.announced_at = now;
        p.seed = seed;
        return;
    }
    if list.len() >= MAX_PEERS_PER_TORRENT {
        if let Some(oldest) = list
            .iter()
            .enumerate()
            .min_by_key(|(_, p)| p.announced_at)
            .map(|(i, _)| i)
        {
            list.swap_remove(oldest);
        }
    }
    list.push(AnnouncedPeer {
        addr,
        announced_at: now,
        seed,
    });
}

fn random_secret() -> [u8; 20] {
    let mut s = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

/// A short, opaque token: `sha1(secret || requester_ip || info_hash)`, truncated.
/// Rotated periodically (`TOKEN_ROTATION`) with the previous secret still accepted for
/// a grace period (`TokenSecrets::validate` checks both), so a token handed out just
/// before a rotation doesn't immediately stop working.
fn token_hash(secret: &[u8; 20], addr: &SocketAddr, info_hash: &[u8; 20]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(secret);
    match addr.ip() {
        std::net::IpAddr::V4(v4) => hasher.update(v4.octets()),
        std::net::IpAddr::V6(v6) => hasher.update(v6.octets()),
    }
    hasher.update(info_hash);
    hasher.finalize()[..8].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::new(a, b, c, d), port))
    }

    fn addr6(segments: [u16; 8], port: u16) -> SocketAddr {
        use std::net::Ipv6Addr;
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
            ),
            port,
            0,
            0,
        ))
    }

    fn test_ctx<'a>(
        routing: &'a mut RoutingTable,
        routing_v6: &'a mut RoutingTableV6,
        pending: &'a mut HashMap<Vec<u8>, PendingQuery>,
        announced: &'a mut HashMap<[u8; 20], Vec<AnnouncedPeer>>,
    ) -> PacketCtx<'a> {
        // Storage lives for the whole process in tests that use this helper.
        let storage: &'static mut DhtStorage = Box::leak(Box::new(DhtStorage::default()));
        PacketCtx {
            routing,
            routing_v6,
            pending,
            announced,
            storage,
            read_only: false,
            vote: Box::leak(Box::new(None)),
        }
    }

    fn public_v4(n: u8) -> std::net::IpAddr {
        std::net::IpAddr::from([30 + n, n, 9, 9])
    }

    #[test]
    fn agreement_on_our_external_address_switches_to_a_bep42_id_and_keeps_known_nodes() {
        let old_id = [0x11u8; 20];
        let cell = Arc::new(std::sync::RwLock::new(old_id));
        let mut our_id = old_id;
        let mut routing = RoutingTable::new(old_id);
        let mut routing_v6 = RoutingTableV6::new(old_id);
        let neighbour = SocketAddrV4::new(std::net::Ipv4Addr::new(8, 8, 4, 4), 6881);
        assert!(routing.seen([0xF0; 20], neighbour, Instant::now()));
        let (mut v4, mut v6) = (IpVoter::new(), IpVoter::new());
        let me: std::net::IpAddr = "203.0.113.77".parse().unwrap();

        for n in 0..7u8 {
            let mut vote = Some((public_v4(n), me));
            apply_vote(
                &mut vote,
                &mut v4,
                &mut v6,
                &cell,
                &mut our_id,
                &mut routing,
                &mut routing_v6,
            );
            assert_eq!(our_id, old_id, "not enough voters yet");
        }
        let mut vote = Some((public_v4(50), me));
        apply_vote(
            &mut vote,
            &mut v4,
            &mut v6,
            &cell,
            &mut our_id,
            &mut routing,
            &mut routing_v6,
        );

        assert_ne!(our_id, old_id);
        assert!(
            crate::bep42::verify_secure_node_id(&our_id, me),
            "the new id must verify for the agreed address"
        );
        assert_eq!(*cell.read().unwrap(), our_id, "handle-visible id updated");
        assert_eq!(routing.our_id(), our_id);
        assert_eq!(routing.len(), 1, "known nodes survive the re-key");
        // Agreement on an address the id already matches changes nothing further.
        let before = our_id;
        for n in 60..70u8 {
            let mut vote = Some((public_v4(n), me));
            apply_vote(
                &mut vote,
                &mut v4,
                &mut v6,
                &cell,
                &mut our_id,
                &mut routing,
                &mut routing_v6,
            );
        }
        assert_eq!(our_id, before);
    }

    #[test]
    fn a_private_consensus_address_never_changes_the_id() {
        let old_id = [0x22u8; 20];
        let cell = Arc::new(std::sync::RwLock::new(old_id));
        let mut our_id = old_id;
        let mut routing = RoutingTable::new(old_id);
        let mut routing_v6 = RoutingTableV6::new(old_id);
        let (mut v4, mut v6) = (IpVoter::new(), IpVoter::new());
        let lan: std::net::IpAddr = "192.168.1.50".parse().unwrap();
        for n in 0..12u8 {
            let mut vote = Some((public_v4(n), lan));
            apply_vote(
                &mut vote,
                &mut v4,
                &mut v6,
                &cell,
                &mut our_id,
                &mut routing,
                &mut routing_v6,
            );
        }
        assert_eq!(
            our_id, old_id,
            "BEP 42 exempts private addresses; no derived id is needed"
        );
    }

    #[test]
    fn token_validates_against_current_and_previous_secret_but_not_others() {
        let secrets = TokenSecrets::generate();
        let a = addr(1, 2, 3, 4, 100);
        let h = [7u8; 20];
        let token = secrets.make_token(&a, &h);
        assert!(secrets.validate(&token, &a, &h));

        let prev_token = token_hash(&secrets.previous, &a, &h);
        assert!(secrets.validate(&prev_token, &a, &h));

        let other = TokenSecrets::generate();
        assert!(!other.validate(&token, &a, &h));
    }

    #[test]
    fn token_is_bound_to_the_requesters_address() {
        let secrets = TokenSecrets::generate();
        let a = addr(1, 2, 3, 4, 100);
        let b = addr(5, 6, 7, 8, 100);
        let h = [7u8; 20];
        let token_for_a = secrets.make_token(&a, &h);
        assert!(secrets.validate(&token_for_a, &a, &h));
        assert!(!secrets.validate(&token_for_a, &b, &h));

        let a6 = addr6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 100);
        let b6 = addr6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2], 100);
        let token_for_a6 = secrets.make_token(&a6, &h);
        assert!(secrets.validate(&token_for_a6, &a6, &h));
        assert!(!secrets.validate(&token_for_a6, &b6, &h));
        assert!(!secrets.validate(&token_for_a6, &a, &h));
    }

    #[test]
    fn token_is_bound_to_the_info_hash_it_was_issued_for() {
        let secrets = TokenSecrets::generate();
        let a = addr(1, 2, 3, 4, 100);
        let token = secrets.make_token(&a, &[1u8; 20]);
        assert!(secrets.validate(&token, &a, &[1u8; 20]));
        assert!(
            !secrets.validate(&token, &a, &[2u8; 20]),
            "a token for one swarm must not announce into another"
        );
        assert!(
            !secrets.validate(&token[..4], &a, &[1u8; 20]),
            "truncated tokens are rejected"
        );
        assert!(!secrets.validate(&[], &a, &[1u8; 20]));
    }

    #[test]
    fn announce_with_port_zero_is_refused() {
        let secrets = TokenSecrets::generate();
        let mut routing = RoutingTable::new([0u8; 20]);
        let mut routing_v6 = RoutingTableV6::new([0u8; 20]);
        let mut pending = HashMap::new();
        let mut announced = HashMap::new();
        let from = addr(1, 1, 1, 1, 6881);
        let info_hash = [9u8; 20];
        let token = secrets.make_token(&from, &info_hash);
        let body = handle_query(
            &Query::AnnouncePeer {
                info_hash,
                port: 0,
                token,
                implied_port: false,
            },
            from,
            &mut test_ctx(&mut routing, &mut routing_v6, &mut pending, &mut announced),
            &secrets,
        );
        assert!(matches!(body, Body::Error { code: 203, .. }));
        assert!(announced.is_empty());
    }

    #[test]
    fn announce_storage_is_bounded_and_keeps_popular_swarms() {
        let mut announced: HashMap<[u8; 20], Vec<AnnouncedPeer>> = HashMap::new();
        let now = Instant::now();
        let popular = [0xFFu8; 20];
        for p in 0..50u16 {
            store_announce(
                &mut announced,
                popular,
                addr(9, 9, 9, 9, 1000 + p),
                now,
                false,
            );
        }
        // A flood of one-peer fake swarms must not grow the map past the cap or evict the popular one.
        for i in 0..(MAX_ANNOUNCED_TORRENTS as u32 * 2) {
            let mut h = [0u8; 20];
            h[..4].copy_from_slice(&i.to_be_bytes());
            store_announce(&mut announced, h, addr(8, 8, 8, 8, 1), now, false);
        }
        assert!(announced.len() <= MAX_ANNOUNCED_TORRENTS);
        assert_eq!(announced.get(&popular).map(Vec::len), Some(50));
    }

    #[test]
    fn peers_per_torrent_are_capped_replacing_the_oldest() {
        let mut announced: HashMap<[u8; 20], Vec<AnnouncedPeer>> = HashMap::new();
        let t0 = Instant::now();
        let h = [3u8; 20];
        for p in 0..(MAX_PEERS_PER_TORRENT as u16 + 100) {
            store_announce(
                &mut announced,
                h,
                addr(7, 7, (p >> 8) as u8, p as u8, 5000),
                t0 + Duration::from_millis(u64::from(p)),
                false,
            );
        }
        let list = &announced[&h];
        assert_eq!(list.len(), MAX_PEERS_PER_TORRENT);
        // The first 100 announced were the ones dropped.
        assert!(!list.iter().any(|p| p.addr == addr(7, 7, 0, 0, 5000)));
        assert!(list.iter().any(|p| p.addr
            == addr(
                7,
                7,
                ((MAX_PEERS_PER_TORRENT as u16 + 99) >> 8) as u8,
                (MAX_PEERS_PER_TORRENT as u16 + 99) as u8,
                5000
            )));
    }

    #[test]
    fn get_peers_reply_is_capped_to_one_packet_of_peers() {
        let secrets = TokenSecrets::generate();
        let mut routing = RoutingTable::new([0u8; 20]);
        let mut routing_v6 = RoutingTableV6::new([0u8; 20]);
        let mut pending = HashMap::new();
        let mut announced = HashMap::new();
        let info_hash = [4u8; 20];
        let now = Instant::now();
        for p in 0..300u16 {
            store_announce(
                &mut announced,
                info_hash,
                addr(6, 6, (p >> 8) as u8, p as u8, 4000),
                now,
                false,
            );
        }
        match handle_query(
            &Query::GetPeers {
                info_hash,
                want: None,
            },
            addr(2, 2, 2, 2, 1),
            &mut test_ctx(&mut routing, &mut routing_v6, &mut pending, &mut announced),
            &secrets,
        ) {
            Body::Response(Response::GetPeers {
                result: GetPeersResult::Peers(peers),
                ..
            }) => {
                assert_eq!(peers.len(), MAX_PEERS_PER_REPLY);
            }
            other => panic!("expected peers, got {other:?}"),
        }
    }

    #[test]
    fn announce_peer_is_rejected_without_a_valid_token() {
        let secrets = TokenSecrets::generate();
        let mut routing = RoutingTable::new([0u8; 20]);
        let mut routing_v6 = RoutingTableV6::new([0u8; 20]);
        let mut pending = HashMap::new();
        let mut announced = HashMap::new();
        let from = addr(1, 1, 1, 1, 6881);
        let body = handle_query(
            &Query::AnnouncePeer {
                info_hash: [9u8; 20],
                port: 6881,
                token: vec![0, 0, 0, 0, 0, 0, 0, 0],
                implied_port: false,
            },
            from,
            &mut test_ctx(&mut routing, &mut routing_v6, &mut pending, &mut announced),
            &secrets,
        );
        assert!(matches!(body, Body::Error { code: 203, .. }));
        assert!(announced.is_empty());
    }

    #[test]
    fn announce_peer_with_a_valid_token_is_stored_and_findable() {
        let secrets = TokenSecrets::generate();
        let mut routing = RoutingTable::new([0u8; 20]);
        let mut routing_v6 = RoutingTableV6::new([0u8; 20]);
        let mut pending = HashMap::new();
        let mut announced = HashMap::new();
        let from = addr(1, 1, 1, 1, 6881);
        let info_hash = [9u8; 20];

        let token = match handle_query(
            &Query::GetPeers {
                info_hash,
                want: None,
            },
            from,
            &mut test_ctx(&mut routing, &mut routing_v6, &mut pending, &mut announced),
            &secrets,
        ) {
            Body::Response(Response::GetPeers { token, .. }) => token,
            other => panic!("expected GetPeers response, got {other:?}"),
        };

        let body = handle_query(
            &Query::AnnouncePeer {
                info_hash,
                port: 6881,
                token,
                implied_port: true,
            },
            from,
            &mut test_ctx(&mut routing, &mut routing_v6, &mut pending, &mut announced),
            &secrets,
        );
        assert!(matches!(body, Body::Response(Response::Id)));

        // implied_port=true: the stored port should be the source port (6881), not
        // whatever `port` field the (deliberately mismatched, here) request carried.
        match handle_query(
            &Query::GetPeers {
                info_hash,
                want: None,
            },
            addr(2, 2, 2, 2, 1),
            &mut test_ctx(&mut routing, &mut routing_v6, &mut pending, &mut announced),
            &secrets,
        ) {
            Body::Response(Response::GetPeers {
                result: GetPeersResult::Peers(peers),
                ..
            }) => {
                let SocketAddr::V4(expected_v4) = from else {
                    unreachable!()
                };
                assert_eq!(peers, vec![expected_v4]);
            }
            other => panic!("expected peers, got {other:?}"),
        }
    }

    #[test]
    fn ipv6_announce_and_get_peers_with_want_n6() {
        let secrets = TokenSecrets::generate();
        let mut routing = RoutingTable::new([0u8; 20]);
        let mut routing_v6 = RoutingTableV6::new([0u8; 20]);
        let mut pending = HashMap::new();
        let mut announced = HashMap::new();
        let from6 = addr6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 6881);
        let info_hash = [0x55u8; 20];

        let token = match handle_query(
            &Query::GetPeers {
                info_hash,
                want: Some(vec!["n6".into()]),
            },
            from6,
            &mut test_ctx(&mut routing, &mut routing_v6, &mut pending, &mut announced),
            &secrets,
        ) {
            Body::Response(Response::GetPeers {
                token,
                result: GetPeersResult::Nodes6(_),
            }) => token,
            other => panic!("expected GetPeers Nodes6 response, got {other:?}"),
        };

        let body = handle_query(
            &Query::AnnouncePeer {
                info_hash,
                port: 6881,
                token,
                implied_port: false,
            },
            from6,
            &mut test_ctx(&mut routing, &mut routing_v6, &mut pending, &mut announced),
            &secrets,
        );
        assert!(matches!(body, Body::Response(Response::Id)));

        match handle_query(
            &Query::GetPeers {
                info_hash,
                want: Some(vec!["n6".into()]),
            },
            addr6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 9], 1),
            &mut test_ctx(&mut routing, &mut routing_v6, &mut pending, &mut announced),
            &secrets,
        ) {
            Body::Response(Response::GetPeers {
                result: GetPeersResult::Peers6(peers),
                ..
            }) => {
                let SocketAddr::V6(expected_v6) = from6 else {
                    unreachable!()
                };
                assert_eq!(peers, vec![expected_v6]);
            }
            other => panic!("expected peers6, got {other:?}"),
        }
    }

    #[test]
    fn find_node_with_want_returns_both_v4_and_v6() {
        let secrets = TokenSecrets::generate();
        let mut routing = RoutingTable::new([0u8; 20]);
        let mut routing_v6 = RoutingTableV6::new([0u8; 20]);
        let mut pending = HashMap::new();
        let mut announced = HashMap::new();

        let v4_id = [0x11u8; 20];
        let SocketAddr::V4(v4_addr) = addr(1, 1, 1, 1, 6881) else {
            unreachable!()
        };
        routing.seen(v4_id, v4_addr, Instant::now());

        let v6_id = [0x22u8; 20];
        let SocketAddr::V6(v6_addr) = addr6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 6881) else {
            unreachable!()
        };
        routing_v6.seen(v6_id, v6_addr, Instant::now());

        let body = handle_query(
            &Query::FindNode {
                target: [0u8; 20],
                want: Some(vec!["n4".into(), "n6".into()]),
            },
            addr(2, 2, 2, 2, 1),
            &mut test_ctx(&mut routing, &mut routing_v6, &mut pending, &mut announced),
            &secrets,
        );
        match body {
            Body::Response(Response::FindNode { nodes, nodes6 }) => {
                assert_eq!(nodes.len(), 1);
                assert_eq!(nodes[0].id, v4_id);
                assert_eq!(nodes6.len(), 1);
                assert_eq!(nodes6[0].id, v6_id);
            }
            other => panic!("expected FindNode with both, got {other:?}"),
        }
    }

    async fn spawn_pair() -> ((DhtHandle, SocketAddrV4), (DhtHandle, SocketAddrV4)) {
        let (a, a_addr) = spawn([1u8; 20], "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let (b, b_addr) = spawn([2u8; 20], "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let SocketAddr::V4(a_addr) = a_addr else {
            unreachable!()
        };
        let SocketAddr::V4(b_addr) = b_addr else {
            unreachable!()
        };
        ((a, a_addr), (b, b_addr))
    }

    #[tokio::test]
    async fn ping_between_two_live_nodes_returns_the_right_id_and_updates_routing() {
        let ((a, _a_addr), (b, b_addr)) = spawn_pair().await;
        let responder_id = a.ping(b_addr).await.unwrap();
        assert_eq!(responder_id, b.our_id());

        // `a`'s routing table should now know about `b`, learned from the response.
        let snapshot = a.routing_snapshot().await.unwrap();
        assert!(snapshot.iter().any(|n| n.id == b.our_id()));
    }

    #[tokio::test]
    async fn find_node_answers_from_the_responders_routing_table() {
        let ((a, _a_addr), (_b, b_addr)) = spawn_pair().await;
        // Seed `b`'s routing table with a third node's identity by having it ping `b`
        // first (any query updates the recipient's table).
        let (c, c_addr) = spawn([3u8; 20], "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let SocketAddr::V4(c_addr) = c_addr else {
            unreachable!()
        };
        c.ping(b_addr).await.unwrap();

        let nodes = a.find_node(b_addr, [0xFFu8; 20]).await.unwrap();
        assert!(
            nodes.iter().any(|n| n.id == c.our_id() && n.addr == c_addr),
            "expected b's find_node response to include c, got {nodes:?}"
        );
    }

    #[tokio::test]
    async fn get_peers_then_announce_then_get_peers_again_finds_the_announced_peer() {
        let ((a, _a_addr), (_b, b_addr)) = spawn_pair().await;
        let info_hash = [0x42u8; 20];

        let (token, first) = a.get_peers(b_addr, info_hash).await.unwrap();
        // Nobody has announced for this hash yet, so `b` must not claim to have peers -
        // it may legitimately return `a` itself in `nodes` (learned from `a`'s own
        // incoming query, which is correct Kademlia behavior: any query updates the
        // recipient's routing table), so this only pins down the "no peers" half.
        assert!(matches!(first, GetPeersResult::Nodes(_)));

        a.announce_peer(b_addr, info_hash, 6881, token)
            .await
            .unwrap();

        let (_token, second) = a.get_peers(b_addr, info_hash).await.unwrap();
        match second {
            GetPeersResult::Peers(peers) => {
                assert_eq!(peers.len(), 1);
                // The announcing node's source IP is 127.0.0.1 with whatever port its
                // socket actually sent from - just confirm the announced port made it
                // through, which is the part `announce_peer`'s `port` argument controls.
                assert_eq!(peers[0].port(), 6881);
            }
            other => panic!("expected the announced peer, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn announce_with_a_stale_token_from_a_different_node_is_rejected() {
        let ((a, _a_addr), (_b, b_addr)) = spawn_pair().await;
        let info_hash = [7u8; 20];
        let bogus_token = vec![1, 2, 3, 4];
        let result = a.announce_peer(b_addr, info_hash, 6881, bogus_token).await;
        assert!(matches!(result, Err(DhtError::Remote(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn querying_a_dead_address_times_out_rather_than_hanging_forever() {
        let (a, _a_addr) = spawn([1u8; 20], "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        // Nothing is listening on this address.
        let dead = addr(127, 0, 0, 1, 1);
        let result = a.ping(dead).await;
        assert!(matches!(result, Err(DhtError::Timeout)));
    }
}
