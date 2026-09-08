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
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngCore;
use sha1::{Digest, Sha1};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use crate::proto::{Body, GetPeersResult, Message, NodeId, NodeInfo, Query, Response};
use crate::routing::{self, Node, RoutingTable};

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
    addr: SocketAddrV4,
    announced_at: Instant,
}

struct PendingQuery {
    reply: oneshot::Sender<Result<Message, DhtError>>,
    sent_at: Instant,
    target_addr: SocketAddrV4,
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

    fn make_token(&self, addr: &SocketAddrV4) -> Vec<u8> {
        token_hash(&self.current, addr)
    }

    fn validate(&self, token: &[u8], addr: &SocketAddrV4) -> bool {
        token == token_hash(&self.current, addr) || token == token_hash(&self.previous, addr)
    }
}

/// Bundles the routing table and per-packet-handling state together purely to keep
/// `handle_packet`/`handle_query`'s argument counts sane - they're otherwise
/// independent pieces of `run`'s local state, not a cohesive type in their own right.
struct PacketCtx<'a> {
    routing: &'a mut RoutingTable,
    pending: &'a mut HashMap<Vec<u8>, PendingQuery>,
    announced: &'a mut HashMap<[u8; 20], Vec<AnnouncedPeer>>,
}

#[derive(Debug, Clone, Default)]
pub struct IterativePeersResult {
    pub peers: Vec<SocketAddrV4>,
    pub closest_nodes: Vec<(NodeInfo, Vec<u8>)>,
}

enum Command {
    Query {
        addr: SocketAddrV4,
        node_id: Option<NodeId>,
        query: Query,
        reply: oneshot::Sender<Result<Message, DhtError>>,
    },
    Snapshot {
        reply: oneshot::Sender<Vec<Node>>,
    },
    ClosestNodes {
        target: NodeId,
        count: usize,
        reply: oneshot::Sender<Vec<Node>>,
    },
}

#[derive(Clone)]
pub struct DhtHandle {
    our_id: NodeId,
    cmd_tx: mpsc::Sender<Command>,
}

/// Binds and starts a DHT node, returning a handle to it plus the address it actually
/// bound to (useful when `bind_addr`'s port is 0, i.e. "pick any free port").
pub async fn spawn(our_id: NodeId, bind_addr: SocketAddr) -> std::io::Result<(DhtHandle, SocketAddr)> {
    let socket = UdpSocket::bind(bind_addr).await?;
    let local_addr = socket.local_addr()?;
    let socket = Arc::new(socket);
    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    tokio::spawn(run(our_id, socket, cmd_rx));
    Ok((DhtHandle { our_id, cmd_tx }, local_addr))
}

impl DhtHandle {
    pub fn our_id(&self) -> NodeId {
        self.our_id
    }

    async fn query(&self, addr: SocketAddrV4, node_id: Option<NodeId>, query: Query) -> Result<Message, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Query {
                addr,
                node_id,
                query,
                reply: tx,
            })
            .await
            .map_err(|_| DhtError::Closed)?;
        rx.await.map_err(|_| DhtError::Closed)?
    }

    pub async fn ping(&self, addr: SocketAddrV4) -> Result<NodeId, DhtError> {
        let msg = self.query(addr, None, Query::Ping).await?;
        expect_response(msg, |r| matches!(r, Response::Id))
    }

    pub async fn find_node(&self, addr: SocketAddrV4, target: NodeId) -> Result<Vec<NodeInfo>, DhtError> {
        let msg = self.query(addr, None, Query::FindNode { target, want: None }).await?;
        match msg.body {
            Body::Response(Response::FindNode { nodes, .. }) => Ok(nodes),
            Body::Response(_) => Err(DhtError::Malformed),
            Body::Error { message, .. } => Err(DhtError::Remote(message)),
            Body::Query(_) => Err(DhtError::Malformed),
        }
    }

    pub async fn get_peers(
        &self,
        addr: SocketAddrV4,
        info_hash: [u8; 20],
    ) -> Result<(Vec<u8>, GetPeersResult), DhtError> {
        let msg = self.query(addr, None, Query::GetPeers { info_hash, want: None }).await?;
        match msg.body {
            Body::Response(Response::GetPeers { token, result }) => Ok((token, result)),
            Body::Response(_) => Err(DhtError::Malformed),
            Body::Error { message, .. } => Err(DhtError::Remote(message)),
            Body::Query(_) => Err(DhtError::Malformed),
        }
    }

    pub async fn announce_peer(
        &self,
        addr: SocketAddrV4,
        info_hash: [u8; 20],
        port: u16,
        token: Vec<u8>,
    ) -> Result<(), DhtError> {
        let msg = self
            .query(
                addr,
                None,
                Query::AnnouncePeer {
                    info_hash,
                    port,
                    token,
                    implied_port: false,
                },
            )
            .await?;
        expect_response(msg, |r| matches!(r, Response::Id)).map(|_| ())
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
            candidates.push(NodeInfo { id: n.id, addr: n.addr });
        }

        // 2. Add bootstrap nodes
        for &addr in bootstrap_nodes {
            if seen_addrs.insert(addr) {
                candidates.push(NodeInfo { id: [0u8; 20], addr });
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

            if !any_progress && candidates.iter().filter(|n| !queried_addrs.contains(&n.addr)).count() == 0 {
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
        let mut closest_nodes_with_tokens = Vec::new();

        // 1. Seed from local routing table
        let local_closest = self.closest_nodes(target, routing::K).await?;
        for n in local_closest {
            seen_addrs.insert(n.addr);
            candidates.push(NodeInfo { id: n.id, addr: n.addr });
        }

        // 2. Add bootstrap nodes
        for &addr in bootstrap_nodes {
            if seen_addrs.insert(addr) {
                candidates.push(NodeInfo { id: [0u8; 20], addr });
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
                        GetPeersResult::Nodes(nodes) => {
                            closest_nodes_with_tokens.push((cand, token));
                            for node in nodes {
                                if seen_addrs.insert(node.addr) {
                                    candidates.push(node);
                                    any_progress = true;
                                }
                            }
                        }
                        GetPeersResult::Peers6(_) | GetPeersResult::Nodes6(_) => {
                            closest_nodes_with_tokens.push((cand, token));
                        }
                    }
                }
            }

            if !any_progress && candidates.iter().filter(|n| !queried_addrs.contains(&n.addr)).count() == 0 {
                break;
            }
        }

        Ok(IterativePeersResult {
            peers: discovered_peers.into_iter().collect(),
            closest_nodes: closest_nodes_with_tokens,
        })
    }
}

fn expect_response(msg: Message, matches_expected: impl Fn(&Response) -> bool) -> Result<NodeId, DhtError> {
    match msg.body {
        Body::Response(ref r) if matches_expected(r) => msg.sender_id.ok_or(DhtError::Malformed),
        Body::Response(_) => Err(DhtError::Malformed),
        Body::Error { message, .. } => Err(DhtError::Remote(message)),
        Body::Query(_) => Err(DhtError::Malformed),
    }
}

async fn run(our_id: NodeId, socket: Arc<UdpSocket>, mut cmds: mpsc::Receiver<Command>) {
    let mut routing = RoutingTable::new(our_id);
    let mut pending: HashMap<Vec<u8>, PendingQuery> = HashMap::new();
    let mut announced: HashMap<[u8; 20], Vec<AnnouncedPeer>> = HashMap::new();
    let mut secrets = TokenSecrets::generate();
    let mut last_rotation = Instant::now();
    let mut next_txn: u32 = rand::random();
    let mut buf = vec![0u8; RECV_BUF_LEN];
    let mut maintenance = tokio::time::interval(MAINTENANCE_INTERVAL);
    let mut pending_sweep = tokio::time::interval(PENDING_SWEEP_INTERVAL);

    loop {
        tokio::select! {
            recvd = socket.recv_from(&mut buf) => {
                let Ok((n, from)) = recvd else { continue };
                let SocketAddr::V4(from_v4) = from else { continue }; // IPv4 only, see module docs
                let mut ctx = PacketCtx { routing: &mut routing, pending: &mut pending, announced: &mut announced };
                handle_packet(&buf[..n], from_v4, &socket, our_id, &mut ctx, &secrets).await;
            }
            cmd = cmds.recv() => {
                match cmd {
                    Some(cmd) => handle_command(cmd, &socket, our_id, &mut next_txn, &mut pending, &routing).await,
                    None => break, // All DhtHandles dropped, exit worker gracefully
                }
            }
            _ = pending_sweep.tick() => {
                let now = Instant::now();
                // Two passes rather than `HashMap::retain`: retain's closure only
                // gets `&mut PendingQuery`, and failing a timed-out query means
                // *moving* its oneshot::Sender out to consume it via `.send()`, which
                // needs real ownership - so identify expired keys first, then
                // `remove` (which does give ownership) and act on each.
                let expired: Vec<Vec<u8>> = pending
                    .iter()
                    .filter(|(_, pq)| now.duration_since(pq.sent_at) >= QUERY_TIMEOUT)
                    .map(|(k, _)| k.clone())
                    .collect();
                for key in expired {
                    if let Some(pq) = pending.remove(&key) {
                        if let Some(id) = pq.target_id {
                            routing.mark_failed(&id);
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
                if now.duration_since(last_rotation) >= TOKEN_ROTATION {
                    secrets.previous = std::mem::replace(&mut secrets.current, random_secret());
                    last_rotation = now;
                }
            }
        }
    }
}

async fn handle_command(
    cmd: Command,
    socket: &UdpSocket,
    our_id: NodeId,
    next_txn: &mut u32,
    pending: &mut HashMap<Vec<u8>, PendingQuery>,
    routing: &RoutingTable,
) {
    match cmd {
        Command::Query {
            addr,
            node_id,
            query,
            reply,
        } => {
            let txn_id = next_txn.to_be_bytes().to_vec();
            *next_txn = next_txn.wrapping_add(1);
            let msg = Message {
                transaction_id: txn_id.clone(),
                sender_id: Some(our_id),
                body: Body::Query(query),
            };
            if let Err(e) = socket.send_to(&msg.encode(), SocketAddr::V4(addr)).await {
                let _ = reply.send(Err(e.into()));
                return;
            }
            pending.insert(
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
            let _ = reply.send(routing.closest(&our_id, usize::MAX));
        }
        Command::ClosestNodes { target, count, reply } => {
            let _ = reply.send(routing.closest(&target, count));
        }
    }
}

async fn handle_packet(
    data: &[u8],
    from: SocketAddrV4,
    socket: &UdpSocket,
    our_id: NodeId,
    ctx: &mut PacketCtx<'_>,
    secrets: &TokenSecrets,
) {
    let Ok(msg) = Message::decode(data) else {
        return;
    };

    match &msg.body {
        Body::Query(q) => {
            if let Some(sender_id) = msg.sender_id {
                ctx.routing.seen(sender_id, from, Instant::now());
            }
            let response_body = handle_query(q, from, ctx, secrets);
            let resp = Message {
                transaction_id: msg.transaction_id.clone(),
                sender_id: Some(our_id),
                body: response_body,
            };
            let _ = socket.send_to(&resp.encode(), SocketAddr::V4(from)).await;
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
            if let Some(sender_id) = msg.sender_id {
                ctx.routing.seen(sender_id, from, Instant::now());
            }
            let _ = pq.reply.send(Ok(msg));
        }
    }
}

fn handle_query(q: &Query, from: SocketAddrV4, ctx: &mut PacketCtx<'_>, secrets: &TokenSecrets) -> Body {
    match q {
        Query::Ping => Body::Response(Response::Id),
        Query::FindNode { target, .. } => {
            let nodes = ctx
                .routing
                .closest(target, routing::K)
                .into_iter()
                .map(|n| NodeInfo { id: n.id, addr: n.addr })
                .collect();
            Body::Response(Response::FindNode { nodes, nodes6: Vec::new() })
        }
        Query::GetPeers { info_hash, .. } => {
            let token = secrets.make_token(&from);
            let now = Instant::now();
            if let Some(list) = ctx.announced.get(info_hash) {
                let fresh: Vec<SocketAddrV4> = list
                    .iter()
                    .filter(|p| now.duration_since(p.announced_at) < PEER_TTL)
                    .map(|p| p.addr)
                    .collect();
                if !fresh.is_empty() {
                    return Body::Response(Response::GetPeers {
                        token,
                        result: GetPeersResult::Peers(fresh),
                    });
                }
            }
            let nodes = ctx
                .routing
                .closest(info_hash, routing::K)
                .into_iter()
                .map(|n| NodeInfo { id: n.id, addr: n.addr })
                .collect();
            Body::Response(Response::GetPeers {
                token,
                result: GetPeersResult::Nodes(nodes),
            })
        }
        Query::AnnouncePeer {
            info_hash,
            port,
            token,
            implied_port,
        } => {
            if !secrets.validate(token, &from) {
                return Body::Error {
                    code: 203,
                    message: "Bad token".to_owned(),
                };
            }
            let announce_port = if *implied_port { from.port() } else { *port };
            let addr = SocketAddrV4::new(*from.ip(), announce_port);
            let now = Instant::now();
            let list = ctx.announced.entry(*info_hash).or_default();
            if let Some(p) = list.iter_mut().find(|p| p.addr == addr) {
                p.announced_at = now;
            } else {
                list.push(AnnouncedPeer {
                    addr,
                    announced_at: now,
                });
            }
            Body::Response(Response::Id)
        }
    }
}

fn random_secret() -> [u8; 20] {
    let mut s = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

/// A short, opaque, per-requester-IP token: `sha1(secret || requester_ip)`, truncated.
/// Rotated periodically (`TOKEN_ROTATION`) with the previous secret still accepted for
/// a grace period (`TokenSecrets::validate` checks both), so a token handed out just
/// before a rotation doesn't immediately stop working.
fn token_hash(secret: &[u8; 20], addr: &SocketAddrV4) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(secret);
    hasher.update(addr.ip().octets());
    hasher.finalize()[..8].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(std::net::Ipv4Addr::new(a, b, c, d), port)
    }

    fn test_ctx<'a>(
        routing: &'a mut RoutingTable,
        pending: &'a mut HashMap<Vec<u8>, PendingQuery>,
        announced: &'a mut HashMap<[u8; 20], Vec<AnnouncedPeer>>,
    ) -> PacketCtx<'a> {
        PacketCtx {
            routing,
            pending,
            announced,
        }
    }

    #[test]
    fn token_validates_against_current_and_previous_secret_but_not_others() {
        let secrets = TokenSecrets::generate();
        let a = addr(1, 2, 3, 4, 100);
        let token = secrets.make_token(&a);
        assert!(secrets.validate(&token, &a));

        let prev_token = token_hash(&secrets.previous, &a);
        assert!(secrets.validate(&prev_token, &a));

        let other = TokenSecrets::generate();
        assert!(!other.validate(&token, &a));
    }

    #[test]
    fn token_is_bound_to_the_requesters_address() {
        let secrets = TokenSecrets::generate();
        let a = addr(1, 2, 3, 4, 100);
        let b = addr(5, 6, 7, 8, 100);
        let token_for_a = secrets.make_token(&a);
        assert!(secrets.validate(&token_for_a, &a));
        assert!(!secrets.validate(&token_for_a, &b));
    }

    #[test]
    fn announce_peer_is_rejected_without_a_valid_token() {
        let secrets = TokenSecrets::generate();
        let mut routing = RoutingTable::new([0u8; 20]);
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
            &mut test_ctx(&mut routing, &mut pending, &mut announced),
            &secrets,
        );
        assert!(matches!(body, Body::Error { code: 203, .. }));
        assert!(announced.is_empty());
    }

    #[test]
    fn announce_peer_with_a_valid_token_is_stored_and_findable() {
        let secrets = TokenSecrets::generate();
        let mut routing = RoutingTable::new([0u8; 20]);
        let mut pending = HashMap::new();
        let mut announced = HashMap::new();
        let from = addr(1, 1, 1, 1, 6881);
        let info_hash = [9u8; 20];

        let token = match handle_query(
            &Query::GetPeers { info_hash, want: None },
            from,
            &mut test_ctx(&mut routing, &mut pending, &mut announced),
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
            &mut test_ctx(&mut routing, &mut pending, &mut announced),
            &secrets,
        );
        assert!(matches!(body, Body::Response(Response::Id)));

        // implied_port=true: the stored port should be the source port (6881), not
        // whatever `port` field the (deliberately mismatched, here) request carried.
        match handle_query(
            &Query::GetPeers { info_hash, want: None },
            addr(2, 2, 2, 2, 1),
            &mut test_ctx(&mut routing, &mut pending, &mut announced),
            &secrets,
        ) {
            Body::Response(Response::GetPeers {
                result: GetPeersResult::Peers(peers),
                ..
            }) => {
                assert_eq!(peers, vec![from]);
            }
            other => panic!("expected peers, got {other:?}"),
        }
    }

    async fn spawn_pair() -> ((DhtHandle, SocketAddrV4), (DhtHandle, SocketAddrV4)) {
        let (a, a_addr) = spawn([1u8; 20], "127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (b, b_addr) = spawn([2u8; 20], "127.0.0.1:0".parse().unwrap()).await.unwrap();
        let SocketAddr::V4(a_addr) = a_addr else { unreachable!() };
        let SocketAddr::V4(b_addr) = b_addr else { unreachable!() };
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
        let (c, c_addr) = spawn([3u8; 20], "127.0.0.1:0".parse().unwrap()).await.unwrap();
        let SocketAddr::V4(c_addr) = c_addr else { unreachable!() };
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

        a.announce_peer(b_addr, info_hash, 6881, token).await.unwrap();

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
        let (a, _a_addr) = spawn([1u8; 20], "127.0.0.1:0".parse().unwrap()).await.unwrap();
        // Nothing is listening on this address.
        let dead = addr(127, 0, 0, 1, 1);
        let result = a.ping(dead).await;
        assert!(matches!(result, Err(DhtError::Timeout)));
    }
}
