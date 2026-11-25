//! UDP tracker protocol (BEP15).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio::time::timeout;

use crate::{AnnounceRequest, AnnounceResponse, Event, TrackerError};

const PROTOCOL_ID: u64 = 0x0000_0417_2710_1980;
const ACTION_CONNECT: u32 = 0;
const ACTION_ANNOUNCE: u32 = 1;
const ACTION_SCRAPE: u32 = 2;
const ACTION_ERROR: u32 = 3;
const MAX_ATTEMPTS: u32 = 3;
/// Bounded retransmission schedule: 5 * 2^n seconds (5s, 10s, 20s = 35s max) so an unreachable
/// or stalled UDP tracker fails fast without blocking swarm announce cycles for minutes.
const BASE_TIMEOUT_SECS: u64 = 5;

/// Performs a full connect+announce exchange against a UDP tracker at `addr` (already
/// resolved - callers own DNS resolution and its own security properties, not this
/// module). `key` is BEP15's anti-spoofing/identification field: generate one randomly
/// once per daemon instance (`rand::random()`) and pass the *same* value on every call,
/// rather than a fresh one each time or a hardcoded constant - a fresh key every
/// announce defeats its purpose just as much as a constant one does.
pub async fn announce(
    addr: SocketAddr,
    req: &AnnounceRequest,
    key: u32,
) -> Result<AnnounceResponse, TrackerError> {
    let sock = UdpSocket::bind(if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    sock.connect(addr).await?;

    let connection_id = connect(&sock).await?;
    do_announce(&sock, connection_id, req, key).await
}

/// Announces to the first of `addrs` that answers, in the order given (BEP 34 failover across
/// SRV targets and the several addresses one name can resolve to).
pub async fn announce_any(
    addrs: &[SocketAddr],
    req: &AnnounceRequest,
    key: u32,
    per_attempt: std::time::Duration,
) -> Result<AnnounceResponse, TrackerError> {
    let mut last = TrackerError::Malformed("no tracker address to try");
    for addr in addrs.iter().take(4) {
        match tokio::time::timeout(per_attempt, announce(*addr, req, key)).await {
            Ok(Ok(resp)) => return Ok(resp),
            Ok(Err(e)) => last = e,
            Err(_) => last = TrackerError::Malformed("tracker timed out"),
        }
    }
    Err(last)
}

/// BEP 15 allows at most 74 info_hashes per UDP scrape request (`16 + 74 * 20 = 1496` bytes <= MTU).
const MAX_UDP_SCRAPE_HASHES: usize = 74;
const UDP_RECV_BUF_LEN: usize = 4096;
/// BEP 15 `connection_id` values remain valid for 60s; refresh slightly before expiry.
const CONNECTION_ID_TTL: Duration = Duration::from_secs(55);
const MAX_CONNECTION_IDS: usize = 4096;
const MAX_PENDING_TXNS: usize = 4096;

type PendingTxnMap = HashMap<u32, (SocketAddr, oneshot::Sender<Vec<u8>>)>;

#[derive(Default)]
struct FamilySocketState {
    socket: Option<Arc<UdpSocket>>,
    recv_task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for FamilySocketState {
    fn drop(&mut self) {
        if let Some(task) = self.recv_task.take() {
            task.abort();
        }
    }
}

struct PendingTxnGuard {
    pending: Arc<Mutex<PendingTxnMap>>,
    txn_id: u32,
}

impl Drop for PendingTxnGuard {
    fn drop(&mut self) {
        self.pending.lock().remove(&self.txn_id);
    }
}

/// Shared BEP 15 UDP tracker client with persistent per-family UDP sockets, transaction-ID
/// demultiplexing, and a 55-second per-tracker `connection_id` cache.
pub struct UdpTrackerClient {
    v4: AsyncMutex<FamilySocketState>,
    v6: AsyncMutex<FamilySocketState>,
    pending: Arc<Mutex<PendingTxnMap>>,
    conn_cache: Mutex<HashMap<SocketAddr, (u64, Instant)>>,
}

impl Default for UdpTrackerClient {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpTrackerClient {
    pub fn new() -> Self {
        Self {
            v4: AsyncMutex::new(FamilySocketState::default()),
            v6: AsyncMutex::new(FamilySocketState::default()),
            pending: Arc::new(Mutex::new(HashMap::new())),
            conn_cache: Mutex::new(HashMap::new()),
        }
    }

    async fn socket_for(&self, is_v4: bool) -> Result<Arc<UdpSocket>, TrackerError> {
        let mutex = if is_v4 { &self.v4 } else { &self.v6 };
        let mut guard = mutex.lock().await;
        if let Some(ref sock) = guard.socket {
            return Ok(sock.clone());
        }
        let bind_addr = if is_v4 { "0.0.0.0:0" } else { "[::]:0" };
        let sock = Arc::new(UdpSocket::bind(bind_addr).await?);
        let recv_sock = sock.clone();
        let pending = self.pending.clone();
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_RECV_BUF_LEN];
            loop {
                match recv_sock.recv_from(&mut buf).await {
                    Ok((n, from)) if n >= 8 => {
                        let txn_id = u32::from_be_bytes(buf[4..8].try_into().unwrap());
                        let tx = {
                            let mut map = pending.lock();
                            match map.get(&txn_id) {
                                Some((expected_addr, _)) if *expected_addr == from => {
                                    map.remove(&txn_id).map(|(_, tx)| tx)
                                }
                                _ => None,
                            }
                        };
                        if let Some(tx) = tx {
                            let _ = tx.send(buf[..n].to_vec());
                        }
                    }
                    Ok(_) => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::WouldBlock
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
        });
        guard.socket = Some(sock.clone());
        guard.recv_task = Some(task);
        Ok(sock)
    }

    fn cached_connection_id(&self, addr: SocketAddr) -> Option<u64> {
        let now = Instant::now();
        let mut cache = self.conn_cache.lock();
        match cache.get(&addr).copied() {
            Some((id, obtained_at))
                if now.saturating_duration_since(obtained_at) < CONNECTION_ID_TTL =>
            {
                Some(id)
            }
            Some(_) => {
                cache.remove(&addr);
                None
            }
            None => None,
        }
    }

    fn cache_connection_id(&self, addr: SocketAddr, connection_id: u64) {
        let now = Instant::now();
        let mut cache = self.conn_cache.lock();
        if cache.len() >= MAX_CONNECTION_IDS && !cache.contains_key(&addr) {
            cache.retain(|_, (_, ts)| now.saturating_duration_since(*ts) < CONNECTION_ID_TTL);
            if cache.len() >= MAX_CONNECTION_IDS {
                if let Some(oldest) = cache.iter().min_by_key(|(_, (_, ts))| *ts).map(|(k, _)| *k) {
                    cache.remove(&oldest);
                }
            }
        }
        cache.insert(addr, (connection_id, now));
    }

    fn invalidate_connection_id(&self, addr: SocketAddr) {
        self.conn_cache.lock().remove(&addr);
    }

    async fn send_and_recv(
        &self,
        sock: &UdpSocket,
        addr: SocketAddr,
        req: &[u8],
        txn_id: u32,
        max_attempts: u32,
    ) -> Result<Vec<u8>, TrackerError> {
        let (tx, mut rx) = oneshot::channel();
        {
            let mut map = self.pending.lock();
            if map.len() >= MAX_PENDING_TXNS {
                return Err(TrackerError::Malformed(
                    "too many pending UDP tracker transactions",
                ));
            }
            map.insert(txn_id, (addr, tx));
        }
        let _guard = PendingTxnGuard {
            pending: self.pending.clone(),
            txn_id,
        };

        for attempt in 0..max_attempts {
            sock.send_to(req, addr).await?;
            let wait = Duration::from_secs(BASE_TIMEOUT_SECS * (1u64 << attempt));
            match timeout(wait, &mut rx).await {
                Ok(Ok(buf)) => return Ok(buf),
                Ok(Err(_)) => {
                    return Err(TrackerError::Malformed(
                        "UDP tracker response channel closed",
                    ));
                }
                Err(_) => {}
            }
        }
        Err(TrackerError::Timeout)
    }

    fn allocate_txn_id(&self) -> u32 {
        let map = self.pending.lock();
        for _ in 0..8 {
            let candidate: u32 = rand::random();
            if !map.contains_key(&candidate) {
                return candidate;
            }
        }
        rand::random()
    }

    async fn connect(&self, sock: &UdpSocket, addr: SocketAddr) -> Result<u64, TrackerError> {
        let txn_id = self.allocate_txn_id();
        let mut req = [0u8; 16];
        req[0..8].copy_from_slice(&PROTOCOL_ID.to_be_bytes());
        req[8..12].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
        req[12..16].copy_from_slice(&txn_id.to_be_bytes());

        let buf = self
            .send_and_recv(sock, addr, &req, txn_id, MAX_ATTEMPTS)
            .await?;
        let cid = parse_connect_response(&buf)?;
        self.cache_connection_id(addr, cid);
        Ok(cid)
    }

    async fn do_announce(
        &self,
        sock: &UdpSocket,
        addr: SocketAddr,
        connection_id: u64,
        req: &AnnounceRequest,
        key: u32,
        max_attempts: u32,
    ) -> Result<AnnounceResponse, TrackerError> {
        let txn_id = self.allocate_txn_id();
        let pkt = encode_announce_packet(connection_id, txn_id, req, key);
        let buf = self
            .send_and_recv(sock, addr, &pkt, txn_id, max_attempts)
            .await?;
        parse_announce_response(&buf, addr.is_ipv6())
    }

    /// Performs a BEP 15 announce against `addr`, reusing a cached `connection_id` within 55s.
    pub async fn announce(
        &self,
        addr: SocketAddr,
        req: &AnnounceRequest,
        key: u32,
    ) -> Result<AnnounceResponse, TrackerError> {
        let sock = self.socket_for(addr.is_ipv4()).await?;
        if let Some(cid) = self.cached_connection_id(addr) {
            match self.do_announce(&sock, addr, cid, req, key, 1).await {
                Ok(resp) => return Ok(resp),
                Err(TrackerError::TrackerReported(_)) | Err(TrackerError::Timeout) => {
                    self.invalidate_connection_id(addr);
                }
                Err(e) => return Err(e),
            }
        }

        let cid = self.connect(&sock, addr).await?;
        match self
            .do_announce(&sock, addr, cid, req, key, MAX_ATTEMPTS)
            .await
        {
            Ok(resp) => Ok(resp),
            Err(TrackerError::TrackerReported(msg)) => {
                self.invalidate_connection_id(addr);
                Err(TrackerError::TrackerReported(msg))
            }
            Err(e) => Err(e),
        }
    }

    /// Announces to the first of `addrs` that answers within `per_attempt`.
    pub async fn announce_any(
        &self,
        addrs: &[SocketAddr],
        req: &AnnounceRequest,
        key: u32,
        per_attempt: Duration,
    ) -> Result<AnnounceResponse, TrackerError> {
        let mut last = TrackerError::Malformed("no tracker address to try");
        for addr in addrs.iter().take(4) {
            match timeout(per_attempt, self.announce(*addr, req, key)).await {
                Ok(Ok(resp)) => return Ok(resp),
                Ok(Err(e)) => last = e,
                Err(_) => last = TrackerError::Malformed("tracker timed out"),
            }
        }
        Err(last)
    }

    /// Performs a BEP 15 scrape against `addr`, reusing a cached `connection_id` within 55s.
    pub async fn scrape(
        &self,
        addr: SocketAddr,
        info_hashes: &[[u8; 20]],
    ) -> Result<crate::ScrapeResponse, TrackerError> {
        if info_hashes.is_empty() {
            return Ok(crate::ScrapeResponse {
                files: HashMap::new(),
            });
        }
        let sock = self.socket_for(addr.is_ipv4()).await?;
        let mut cid = match self.cached_connection_id(addr) {
            Some(c) => c,
            None => self.connect(&sock, addr).await?,
        };
        let mut merged = HashMap::with_capacity(info_hashes.len());
        for (idx, chunk) in info_hashes.chunks(MAX_UDP_SCRAPE_HASHES).enumerate() {
            let txn_id = self.allocate_txn_id();
            let pkt = encode_scrape_packet(cid, txn_id, chunk);
            match self
                .send_and_recv(&sock, addr, &pkt, txn_id, MAX_ATTEMPTS)
                .await
            {
                Ok(buf) => match parse_scrape_response(&buf, chunk) {
                    Ok(part) => merged.extend(part.files),
                    Err(TrackerError::TrackerReported(_msg)) if idx == 0 => {
                        self.invalidate_connection_id(addr);
                        cid = self.connect(&sock, addr).await?;
                        let retry_txn = self.allocate_txn_id();
                        let retry_pkt = encode_scrape_packet(cid, retry_txn, chunk);
                        let retry_buf = self
                            .send_and_recv(&sock, addr, &retry_pkt, retry_txn, MAX_ATTEMPTS)
                            .await?;
                        merged.extend(parse_scrape_response(&retry_buf, chunk)?.files);
                    }
                    Err(e) => return Err(e),
                },
                Err(TrackerError::Timeout) if idx == 0 => {
                    self.invalidate_connection_id(addr);
                    cid = self.connect(&sock, addr).await?;
                    let retry_txn = self.allocate_txn_id();
                    let retry_pkt = encode_scrape_packet(cid, retry_txn, chunk);
                    let retry_buf = self
                        .send_and_recv(&sock, addr, &retry_pkt, retry_txn, MAX_ATTEMPTS)
                        .await?;
                    merged.extend(parse_scrape_response(&retry_buf, chunk)?.files);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(crate::ScrapeResponse { files: merged })
    }
}

pub async fn scrape(
    addr: SocketAddr,
    info_hashes: &[[u8; 20]],
) -> Result<crate::ScrapeResponse, TrackerError> {
    if info_hashes.is_empty() {
        return Ok(crate::ScrapeResponse {
            files: std::collections::HashMap::new(),
        });
    }
    let sock = UdpSocket::bind(if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    sock.connect(addr).await?;

    let connection_id = connect(&sock).await?;
    let mut merged = std::collections::HashMap::with_capacity(info_hashes.len());
    for chunk in info_hashes.chunks(MAX_UDP_SCRAPE_HASHES) {
        let part = do_scrape(&sock, connection_id, chunk).await?;
        merged.extend(part.files);
    }
    Ok(crate::ScrapeResponse { files: merged })
}

fn encode_scrape_packet(connection_id: u64, txn_id: u32, info_hashes: &[[u8; 20]]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(16 + info_hashes.len() * 20);
    pkt.extend_from_slice(&connection_id.to_be_bytes());
    pkt.extend_from_slice(&ACTION_SCRAPE.to_be_bytes());
    pkt.extend_from_slice(&txn_id.to_be_bytes());
    for hash in info_hashes {
        pkt.extend_from_slice(hash);
    }
    pkt
}

fn encode_announce_packet(
    connection_id: u64,
    txn_id: u32,
    req: &AnnounceRequest,
    key: u32,
) -> Vec<u8> {
    let mut pkt = [0u8; 98];
    pkt[0..8].copy_from_slice(&connection_id.to_be_bytes());
    pkt[8..12].copy_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
    pkt[12..16].copy_from_slice(&txn_id.to_be_bytes());
    pkt[16..36].copy_from_slice(&req.info_hash);
    pkt[36..56].copy_from_slice(&req.peer_id);
    pkt[56..64].copy_from_slice(&req.downloaded.to_be_bytes());
    pkt[64..72].copy_from_slice(&req.left.to_be_bytes());
    pkt[72..80].copy_from_slice(&req.uploaded.to_be_bytes());
    let event: u32 = match req.event {
        Event::None => 0,
        Event::Completed => 1,
        Event::Started => 2,
        Event::Stopped => 3,
    };
    pkt[80..84].copy_from_slice(&event.to_be_bytes());
    if let Some(v4) = req.ipv4 {
        pkt[84..88].copy_from_slice(&v4.octets());
    } else {
        pkt[84..88].copy_from_slice(&0u32.to_be_bytes()); // IP: 0 = let the tracker infer it
    }
    pkt[88..92].copy_from_slice(&key.to_be_bytes());
    let num_want = req.num_want.unwrap_or(-1);
    pkt[92..96].copy_from_slice(&num_want.to_be_bytes());
    pkt[96..98].copy_from_slice(&req.port.to_be_bytes());

    let ext_bytes = crate::udp_ext::encode_udp_options(&req.udp_options);
    let mut full_pkt = Vec::with_capacity(98 + ext_bytes.len());
    full_pkt.extend_from_slice(&pkt);
    full_pkt.extend_from_slice(&ext_bytes);
    full_pkt
}

async fn do_scrape(
    sock: &UdpSocket,
    connection_id: u64,
    info_hashes: &[[u8; 20]],
) -> Result<crate::ScrapeResponse, TrackerError> {
    let txn_id: u32 = rand::random();
    let pkt = encode_scrape_packet(connection_id, txn_id, info_hashes);

    let mut buf = vec![0u8; UDP_RECV_BUF_LEN.max(8 + info_hashes.len() * 12)];
    let n = send_and_recv(sock, &pkt, txn_id, &mut buf).await?;
    parse_scrape_response(&buf[..n], info_hashes)
}

pub fn parse_scrape_response(
    buf: &[u8],
    info_hashes: &[[u8; 20]],
) -> Result<crate::ScrapeResponse, TrackerError> {
    if buf.len() < 8 {
        return Err(TrackerError::Malformed("scrape response too short"));
    }
    let action = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    match action {
        ACTION_SCRAPE => {
            let data = &buf[8..];
            if !data.len().is_multiple_of(12) {
                return Err(TrackerError::Malformed(
                    "scrape payload length not multiple of 12",
                ));
            }
            let mut files = std::collections::HashMap::new();
            for (i, chunk) in data.as_chunks::<12>().0.iter().enumerate() {
                if i < info_hashes.len() {
                    let seeders = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
                    let completed = u32::from_be_bytes(chunk[4..8].try_into().unwrap());
                    let leechers = u32::from_be_bytes(chunk[8..12].try_into().unwrap());
                    files.insert(
                        info_hashes[i],
                        crate::ScrapeStats {
                            seeders,
                            completed,
                            leechers,
                            name: None,
                        },
                    );
                }
            }
            Ok(crate::ScrapeResponse { files })
        }
        ACTION_ERROR => Err(parse_error(&buf[8..])),
        _ => Err(TrackerError::Malformed(
            "unexpected action in scrape response",
        )),
    }
}

async fn connect(sock: &UdpSocket) -> Result<u64, TrackerError> {
    let txn_id: u32 = rand::random();
    let mut req = [0u8; 16];
    req[0..8].copy_from_slice(&PROTOCOL_ID.to_be_bytes());
    req[8..12].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
    req[12..16].copy_from_slice(&txn_id.to_be_bytes());

    let mut buf = [0u8; UDP_RECV_BUF_LEN];
    let n = send_and_recv(sock, &req, txn_id, &mut buf).await?;
    parse_connect_response(&buf[..n])
}

pub fn parse_connect_response(buf: &[u8]) -> Result<u64, TrackerError> {
    if buf.len() < 8 {
        return Err(TrackerError::Malformed("connect response too short"));
    }
    let action = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    match action {
        ACTION_CONNECT => {
            if buf.len() < 16 {
                return Err(TrackerError::Malformed("connect response too short"));
            }
            Ok(u64::from_be_bytes(buf[8..16].try_into().unwrap()))
        }
        ACTION_ERROR => Err(parse_error(&buf[8..])),
        _ => Err(TrackerError::Malformed(
            "unexpected action in connect response",
        )),
    }
}

async fn do_announce(
    sock: &UdpSocket,
    connection_id: u64,
    req: &AnnounceRequest,
    key: u32,
) -> Result<AnnounceResponse, TrackerError> {
    let txn_id: u32 = rand::random();
    let full_pkt = encode_announce_packet(connection_id, txn_id, req, key);

    let mut buf = [0u8; UDP_RECV_BUF_LEN];
    let n = send_and_recv(sock, &full_pkt, txn_id, &mut buf).await?;
    parse_announce_response(&buf[..n], sock.peer_addr().is_ok_and(|a| a.is_ipv6()))
}

/// Parses an announce response. `v6` says the tracker was reached over IPv6, in which case its
/// peers are 18 bytes each (BEP 15) rather than 6.
pub fn parse_announce_response(buf: &[u8], v6: bool) -> Result<AnnounceResponse, TrackerError> {
    if buf.len() < 8 {
        return Err(TrackerError::Malformed("announce response too short"));
    }
    let action = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    match action {
        ACTION_ANNOUNCE => {
            if buf.len() < 20 {
                return Err(TrackerError::Malformed("announce response too short"));
            }
            let interval = u32::from_be_bytes(buf[8..12].try_into().unwrap());
            let leechers = u32::from_be_bytes(buf[12..16].try_into().unwrap());
            let seeders = u32::from_be_bytes(buf[16..20].try_into().unwrap());
            // `as_chunks` (not `chunks`) silently drops a ragged trailing chunk
            // instead of yielding it - the pre-rewrite fix for exactly this panic risk
            // (CHANGELOG.md) applies here too, from the start this time.
            let mut peers: Vec<SocketAddr> = if v6 {
                buf[20..]
                    .as_chunks::<18>()
                    .0
                    .iter()
                    .map(|c| {
                        let mut ip = [0u8; 16];
                        ip.copy_from_slice(&c[..16]);
                        SocketAddr::from((
                            std::net::Ipv6Addr::from(ip),
                            u16::from_be_bytes([c[16], c[17]]),
                        ))
                    })
                    .collect()
            } else {
                buf[20..]
                    .as_chunks::<6>()
                    .0
                    .iter()
                    .map(|c| {
                        let ip = std::net::Ipv4Addr::new(c[0], c[1], c[2], c[3]);
                        SocketAddr::from((ip, u16::from_be_bytes([c[4], c[5]])))
                    })
                    .collect()
            };
            peers.retain(|p| p.port() != 0);
            peers.truncate(crate::MAX_PEERS_PER_RESPONSE);
            Ok(AnnounceResponse {
                interval: interval
                    .clamp(crate::MIN_ANNOUNCE_INTERVAL, crate::MAX_ANNOUNCE_INTERVAL),
                leechers,
                seeders,
                peers,
                min_interval: None,
                tracker_id: None,
                warning: None,
                external_ip: None,
                remote_addr: None,
            })
        }
        ACTION_ERROR => Err(parse_error(&buf[8..])),
        _ => Err(TrackerError::Malformed(
            "unexpected action in announce response",
        )),
    }
}

fn parse_error(msg: &[u8]) -> TrackerError {
    TrackerError::TrackerReported(String::from_utf8_lossy(msg).into_owned())
}

/// Sends `req` and waits for a response whose transaction ID matches `txn_id`,
/// retrying with BEP15's recommended backoff schedule on timeout. A response from the
/// wrong source address can't reach us at all (the socket is `connect`ed - see
/// `announce`'s doc-comment); a response with a mismatched transaction ID (e.g. a very
/// late reply to a previous, already-abandoned attempt) is treated the same as no
/// response and we keep waiting out the current attempt's timeout rather than
/// accepting it.
async fn send_and_recv(
    sock: &UdpSocket,
    req: &[u8],
    txn_id: u32,
    buf: &mut [u8],
) -> Result<usize, TrackerError> {
    for attempt in 0..MAX_ATTEMPTS {
        sock.send(req).await?;
        let deadline = Duration::from_secs(BASE_TIMEOUT_SECS * (1u64 << attempt));
        let attempt_start = tokio::time::Instant::now();
        loop {
            let remaining = deadline.saturating_sub(attempt_start.elapsed());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, sock.recv(buf)).await {
                Ok(Ok(n)) if n >= 8 => {
                    let resp_txn = u32::from_be_bytes(buf[4..8].try_into().unwrap());
                    if resp_txn == txn_id {
                        return Ok(n);
                    }
                    // Mismatched transaction id: not for us (or a stale retry's
                    // response) - keep waiting within this attempt's deadline.
                }
                Ok(Ok(_)) => {} // too short to even have a transaction id; ignore
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break, // this attempt's deadline elapsed
            }
        }
    }
    Err(TrackerError::Timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket as TokioUdpSocket;

    fn test_request() -> AnnounceRequest {
        AnnounceRequest {
            info_hash: [1u8; 20],
            peer_id: [2u8; 20],
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: 1000,
            event: Event::Started,
            num_want: None,
            ipv4: None,
            ipv6: None,
            udp_options: Vec::new(),
            tracker_id: None,
        }
    }

    /// A minimal fake UDP tracker: replies to one connect and one announce, then stops.
    async fn run_fake_tracker(sock: TokioUdpSocket, peers: Vec<SocketAddr>) {
        let mut buf = [0u8; 512];
        let (n, from) = sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 16, "expected a connect request");
        let txn_id = &buf[12..16];
        let connection_id: u64 = 0xdead_beef_1234_5678;
        let mut resp = [0u8; 16];
        resp[0..4].copy_from_slice(&0u32.to_be_bytes()); // action = connect
        resp[4..8].copy_from_slice(txn_id);
        resp[8..16].copy_from_slice(&connection_id.to_be_bytes());
        sock.send_to(&resp, from).await.unwrap();

        let (n, from) = sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 98, "expected an announce request");
        assert_eq!(&buf[0..8], connection_id.to_be_bytes());
        let txn_id = buf[12..16].to_vec();
        let mut resp = Vec::new();
        resp.extend_from_slice(&1u32.to_be_bytes()); // action = announce
        resp.extend_from_slice(&txn_id);
        resp.extend_from_slice(&1800u32.to_be_bytes()); // interval
        resp.extend_from_slice(&3u32.to_be_bytes()); // leechers
        resp.extend_from_slice(&5u32.to_be_bytes()); // seeders
        for peer in &peers {
            let SocketAddr::V4(v4) = peer else {
                panic!("test only supports v4 peers")
            };
            resp.extend_from_slice(&v4.ip().octets());
            resp.extend_from_slice(&v4.port().to_be_bytes());
        }
        sock.send_to(&resp, from).await.unwrap();
    }

    #[tokio::test]
    async fn full_connect_and_announce_roundtrip() {
        let tracker_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tracker_addr = tracker_sock.local_addr().unwrap();
        let expected_peers = vec![
            "127.0.0.1:1000".parse().unwrap(),
            "127.0.0.1:2000".parse().unwrap(),
        ];
        let server = tokio::spawn(run_fake_tracker(tracker_sock, expected_peers.clone()));

        let resp = announce(tracker_addr, &test_request(), 0x1122_3344)
            .await
            .unwrap();
        assert_eq!(resp.interval, 1800);
        assert_eq!(resp.leechers, 3);
        assert_eq!(resp.seeders, 5);
        assert_eq!(resp.peers, expected_peers);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn tracker_error_response_is_surfaced() {
        let tracker_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tracker_addr = tracker_sock.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_n, from) = tracker_sock.recv_from(&mut buf).await.unwrap();
            let txn_id = buf[12..16].to_vec();
            let mut resp = Vec::new();
            resp.extend_from_slice(&3u32.to_be_bytes()); // action = error
            resp.extend_from_slice(&txn_id);
            resp.extend_from_slice(b"torrent not registered");
            tracker_sock.send_to(&resp, from).await.unwrap();
        });

        let err = announce(tracker_addr, &test_request(), 0)
            .await
            .unwrap_err();
        assert!(matches!(err, TrackerError::TrackerReported(_)));
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn times_out_when_the_tracker_never_responds() {
        let tracker_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tracker_addr = tracker_sock.local_addr().unwrap();
        // Nobody answers `tracker_sock` at all.
        let result = announce(tracker_addr, &test_request(), 0).await;
        assert!(matches!(result, Err(TrackerError::Timeout)));
    }

    #[tokio::test]
    async fn ignores_a_response_with_the_wrong_transaction_id_and_still_succeeds() {
        let tracker_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tracker_addr = tracker_sock.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_n, from) = tracker_sock.recv_from(&mut buf).await.unwrap();
            // Send a bogus, mismatched-transaction-id reply first - must be ignored.
            let mut bogus = [0u8; 16];
            bogus[0..4].copy_from_slice(&0u32.to_be_bytes());
            bogus[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
            tracker_sock.send_to(&bogus, from).await.unwrap();

            // Then the real one.
            let txn_id = buf[12..16].to_vec();
            let mut resp = [0u8; 16];
            resp[0..4].copy_from_slice(&0u32.to_be_bytes());
            resp[4..8].copy_from_slice(&txn_id);
            resp[8..16].copy_from_slice(&42u64.to_be_bytes());
            tracker_sock.send_to(&resp, from).await.unwrap();

            let (n, from) = tracker_sock.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 98);
            let txn_id = buf[12..16].to_vec();
            let mut resp = Vec::new();
            resp.extend_from_slice(&1u32.to_be_bytes());
            resp.extend_from_slice(&txn_id);
            resp.extend_from_slice(&1800u32.to_be_bytes());
            resp.extend_from_slice(&0u32.to_be_bytes());
            resp.extend_from_slice(&0u32.to_be_bytes());
            tracker_sock.send_to(&resp, from).await.unwrap();
        });

        let resp = announce(tracker_addr, &test_request(), 0).await.unwrap();
        assert_eq!(resp.interval, 1800);
        server.await.unwrap();
    }

    #[test]
    fn parse_short_action_error_before_min_length_and_large_announce() {
        let mut short_err = Vec::new();
        short_err.extend_from_slice(&ACTION_ERROR.to_be_bytes());
        short_err.extend_from_slice(&0x1122_3344u32.to_be_bytes());
        short_err.extend_from_slice(b"nope"); // 12 bytes < 16 and < 20
        assert!(matches!(
            parse_connect_response(&short_err),
            Err(TrackerError::TrackerReported(ref msg)) if msg == "nope"
        ));
        assert!(matches!(
            parse_announce_response(&short_err, false),
            Err(TrackerError::TrackerReported(ref msg)) if msg == "nope"
        ));

        // 200 peers = 20 + 1200 = 1220 bytes (> old 1024-byte cap).
        let mut big = Vec::new();
        big.extend_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
        big.extend_from_slice(&1u32.to_be_bytes());
        big.extend_from_slice(&1800u32.to_be_bytes());
        big.extend_from_slice(&10u32.to_be_bytes());
        big.extend_from_slice(&20u32.to_be_bytes());
        for i in 0..200u16 {
            big.extend_from_slice(&[198, 51, 100, (i % 250) as u8 + 1]);
            big.extend_from_slice(&(6881 + i).to_be_bytes());
        }
        let parsed = parse_announce_response(&big, false).unwrap();
        assert_eq!(parsed.peers.len(), 200);
    }

    #[tokio::test]
    async fn scrape_batches_over_74_info_hashes_into_multiple_bep15_packets() {
        let tracker_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tracker_addr = tracker_sock.local_addr().unwrap();

        let hashes: Vec<[u8; 20]> = (0..100u8).map(|i| [i; 20]).collect();
        let server = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (n, from) = tracker_sock.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 16);
            let mut resp = [0u8; 16];
            resp[0..4].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
            resp[4..8].copy_from_slice(&buf[12..16]);
            resp[8..16].copy_from_slice(&0x99u64.to_be_bytes());
            tracker_sock.send_to(&resp, from).await.unwrap();

            for expected_count in [74usize, 26usize] {
                let (n, from) = tracker_sock.recv_from(&mut buf).await.unwrap();
                assert_eq!(n, 16 + expected_count * 20);
                let mut scrape_resp = Vec::new();
                scrape_resp.extend_from_slice(&ACTION_SCRAPE.to_be_bytes());
                scrape_resp.extend_from_slice(&buf[12..16]);
                for idx in 0..expected_count {
                    scrape_resp.extend_from_slice(&((idx as u32) + 1).to_be_bytes());
                    scrape_resp.extend_from_slice(&10u32.to_be_bytes());
                    scrape_resp.extend_from_slice(&2u32.to_be_bytes());
                }
                tracker_sock.send_to(&scrape_resp, from).await.unwrap();
            }
        });

        let out = scrape(tracker_addr, &hashes).await.unwrap();
        assert_eq!(out.files.len(), 100);
        assert_eq!(out.files[&[0u8; 20]].seeders, 1);
        assert_eq!(out.files[&[74u8; 20]].seeders, 1);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_tracker_client_reuses_cached_connection_id_for_55s() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let tracker_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tracker_addr = tracker_sock.local_addr().unwrap();
        let connect_count = Arc::new(AtomicUsize::new(0));
        let connect_bg = connect_count.clone();

        let server = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let cid: u64 = 0xfeed_face_cafe_babe;
            // Expect 1 CONNECT + 2 ANNOUNCE packets.
            for expected in [ACTION_CONNECT, ACTION_ANNOUNCE, ACTION_ANNOUNCE] {
                let (_n, from) = tracker_sock.recv_from(&mut buf).await.unwrap();
                let action = u32::from_be_bytes(buf[8..12].try_into().unwrap());
                assert_eq!(action, expected);
                if action == ACTION_CONNECT {
                    connect_bg.fetch_add(1, Ordering::Relaxed);
                    let mut resp = [0u8; 16];
                    resp[0..4].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
                    resp[4..8].copy_from_slice(&buf[12..16]);
                    resp[8..16].copy_from_slice(&cid.to_be_bytes());
                    tracker_sock.send_to(&resp, from).await.unwrap();
                } else {
                    assert_eq!(&buf[0..8], &cid.to_be_bytes());
                    let mut resp = Vec::new();
                    resp.extend_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
                    resp.extend_from_slice(&buf[12..16]);
                    resp.extend_from_slice(&900u32.to_be_bytes());
                    resp.extend_from_slice(&1u32.to_be_bytes());
                    resp.extend_from_slice(&2u32.to_be_bytes());
                    tracker_sock.send_to(&resp, from).await.unwrap();
                }
            }
        });

        let client = UdpTrackerClient::new();
        let r1 = client
            .announce(tracker_addr, &test_request(), 0x42)
            .await
            .unwrap();
        let r2 = client
            .announce(tracker_addr, &test_request(), 0x42)
            .await
            .unwrap();
        assert_eq!(r1.interval, 900);
        assert_eq!(r2.interval, 900);
        assert_eq!(
            connect_count.load(Ordering::Relaxed),
            1,
            "second announce within 55s must reuse cached BEP 15 connection_id"
        );
        server.await.unwrap();
    }
}
