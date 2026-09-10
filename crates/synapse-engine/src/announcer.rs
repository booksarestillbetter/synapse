//! Tracker Announcer and Centralized Announce Priority Scheduler.
//!
//! Orchestrates BEP 15 UDP and HTTP tracker announces for active and seeding swarms.
//! Replaces per-torrent announce interval loops with a single centralized priority
//! min-heap scheduler that enforces tracker-specified intervals (BEP 3/15), applies
//! randomized startup jitter, bounds concurrency, and handles exponential backoff.

use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use tokio::sync::{mpsc, Notify, Semaphore};
use tracing::{debug, info, warn};

use synapse_meta::Info;
use synapse_tracker::{AnnounceRequest, CanaryCircuitBreaker, Event};

use crate::circuit_breaker::PeerCircuitBreaker;
use crate::peer::{connect, PeerEvent};
use crate::swarm::SwarmStats;

/// Transfer statistics passed to tracker announce calls.
#[derive(Debug, Clone, Copy, Default)]
pub struct AnnounceStats {
    pub downloaded: u64,
    pub left: u64,
    pub uploaded: u64,
}

/// Live status and metrics for a single tracker URL reported to RPC/UI.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrackerReport {
    pub url: String,
    pub status: String,
    pub seeders: u32,
    pub leechers: u32,
    pub next_announce_in: i64,
    pub failure_reason: Option<String>,
    pub is_circuit_broken: bool,
    /// Circuit breaker state for this tracker's host, derived from `CanaryCircuitBreaker`
    /// at report-build time (not stored on the report while it's cached in swarm metadata).
    pub cb_state: Option<synapse_tracker::CircuitState>,
    /// 0-100, only `Some` while `cb_state` is `Recovering`.
    pub recovery_progress_pct: Option<f32>,
}

pub struct Announcer {
    our_peer_id: [u8; 20],
    listen_port: Arc<RwLock<u16>>,
    tracker_key: u32,
    circuit_breaker: Arc<PeerCircuitBreaker>,
    tracker_breaker: Arc<CanaryCircuitBreaker>,
}

impl Announcer {
    pub fn new(
        our_peer_id: [u8; 20],
        listen_port: Arc<RwLock<u16>>,
        circuit_breaker: Arc<PeerCircuitBreaker>,
    ) -> Self {
        Self::with_tracker_breaker(
            our_peer_id,
            listen_port,
            circuit_breaker,
            Arc::new(CanaryCircuitBreaker::default()),
        )
    }

    pub fn with_tracker_breaker(
        our_peer_id: [u8; 20],
        listen_port: Arc<RwLock<u16>>,
        circuit_breaker: Arc<PeerCircuitBreaker>,
        tracker_breaker: Arc<CanaryCircuitBreaker>,
    ) -> Self {
        Self {
            our_peer_id,
            listen_port,
            tracker_key: rand::random(),
            circuit_breaker,
            tracker_breaker,
        }
    }

    pub fn tracker_breaker(&self) -> &Arc<CanaryCircuitBreaker> {
        &self.tracker_breaker
    }

    /// Extracts all unique announce and fallback tracker URLs for an info hash.
    pub fn candidate_trackers(info: &Info) -> Vec<url::Url> {
        let mut candidate_urls = Vec::new();
        if let Some(ref a) = info.announce {
            candidate_urls.push((**a).clone());
        }
        for tier in &info.url_list {
            for u in tier {
                let url = (**u).clone();
                if !candidate_urls.contains(&url) {
                    candidate_urls.push(url);
                }
            }
        }

        if !info.private {
            let fallback_trackers = [
                "udp://tracker.opentrackr.org:1337/announce",
                "udp://open.stealth.si:80/announce",
                "udp://tracker.openbittorrent.com:6969/announce",
                "udp://explodie.org:6969/announce",
            ];
            for fb in fallback_trackers {
                if let Ok(u) = url::Url::parse(fb) {
                    if !candidate_urls.contains(&u) {
                        candidate_urls.push(u);
                    }
                }
            }
        }
        candidate_urls
    }

    /// Announce to all trackers associated with the torrent info, returning discovered peer addresses,
    /// the minimum tracker interval, and individual tracker status reports.
    pub async fn announce_with_interval(
        &self,
        info: &Info,
        downloaded: u64,
        left: u64,
        uploaded: u64,
        event: Event,
    ) -> (Vec<SocketAddr>, u32, Vec<TrackerReport>) {
        let candidate_urls = Self::candidate_trackers(info);
        let bound_port = *self.listen_port.read();
        let port = if bound_port == 0 { 54345 } else { bound_port };
        let req = AnnounceRequest {
            info_hash: info.hash,
            peer_id: self.our_peer_id,
            port,
            uploaded,
            downloaded,
            left,
            event,
            num_want: Some(50),
        };

        let mut discovered_peers = HashSet::new();
        let mut tasks = Vec::new();
        let tracker_key = self.tracker_key;

        let torrent_label = format!("{} ({})", info.name, &hex::encode(info.hash)[..8]);
        for tracker_url in candidate_urls {
            let req_clone = req.clone();
            let label_c = torrent_label.clone();
            let circuit_breaker = self.circuit_breaker.clone();
            let tracker_breaker = self.tracker_breaker.clone();
            tasks.push(async move {
                let mut peers = Vec::new();
                let mut interval = None;
                let url_str = tracker_url.to_string();
                // Logged in place of `tracker_url` everywhere below: private trackers
                // commonly embed a passkey in the announce URL's query string, and
                // docs/TRUST_AND_SAFETY.md promises it never appears in logs.
                let safe_url = synapse_tracker::sanitize_tracker_url(&tracker_url);

                if !tracker_breaker.can_announce(&url_str) {
                    let rep = TrackerReport {
                        url: url_str,
                        status: "CircuitBroken".into(),
                        seeders: 0,
                        leechers: 0,
                        next_announce_in: 30,
                        failure_reason: Some("Tracker circuit broken or cooling down in recovery ramp-up".into()),
                        is_circuit_broken: true,
                        cb_state: None,
                        recovery_progress_pct: None,
                    };
                    return (peers, interval, rep);
                }

                let (peers_res, interval_res, report) = match tracker_url.scheme() {
                    "udp" => {
                        let host = match tracker_url.host_str() {
                            Some(h) => h.to_string(),
                            None => {
                                tracker_breaker.record_failure(&url_str);
                                let rep = TrackerReport {
                                    url: url_str,
                                    status: "Error".into(),
                                    seeders: 0,
                                    leechers: 0,
                                    next_announce_in: 300,
                                    failure_reason: Some("Missing host in tracker URL".into()),
                                    is_circuit_broken: false,
                                    cb_state: None,
                                    recovery_progress_pct: None,
                                };
                                return (peers, interval, rep);
                            }
                        };
                        let port = tracker_url.port().unwrap_or(6969);
                        let host_port = format!("{}:{}", host, port);

                        match tokio::time::timeout(
                            Duration::from_secs(2),
                            tokio::net::lookup_host(host_port),
                        )
                        .await
                        {
                            Ok(Ok(addrs)) => {
                                let addrs_vec: Vec<SocketAddr> = addrs.collect();
                                if let Some(&resolved_addr) = addrs_vec.first() {
                                    let is_cb = !circuit_breaker.can_connect(&resolved_addr);
                                    debug!(
                                        "[{}] Announcing to UDP tracker {} ({})",
                                        label_c, safe_url, resolved_addr
                                    );
                                    match tokio::time::timeout(
                                        Duration::from_secs(5),
                                        synapse_tracker::udp::announce(
                                            resolved_addr,
                                            &req_clone,
                                            tracker_key,
                                        ),
                                    )
                                    .await
                                    {
                                        Ok(Ok(resp)) => {
                                            tracker_breaker.record_success(&url_str);
                                            info!(
                                                "[{}] UDP tracker {} returned {} seeders, {} leechers, {} peers (interval: {}s)",
                                                label_c,
                                                safe_url,
                                                resp.seeders,
                                                resp.leechers,
                                                resp.peers.len(),
                                                resp.interval
                                            );
                                            interval = Some(resp.interval);
                                            for p in resp.peers {
                                                if p.port() != 0 {
                                                    peers.push(p);
                                                }
                                            }
                                            let rep = TrackerReport {
                                                url: tracker_url.to_string(),
                                                status: "Announced".into(),
                                                seeders: resp.seeders,
                                                leechers: resp.leechers,
                                                next_announce_in: resp.interval as i64,
                                                failure_reason: None,
                                                is_circuit_broken: is_cb,
                                                cb_state: None,
                                                recovery_progress_pct: None,
                                            };
                                            (peers, interval, rep)
                                        }
                                        Ok(Err(e)) => {
                                            tracker_breaker.record_failure(&url_str);
                                            warn!(
                                                "[{}] UDP tracker {} announce failed: {}",
                                                label_c, safe_url, e
                                            );
                                            let rep = TrackerReport {
                                                url: tracker_url.to_string(),
                                                status: "Error".into(),
                                                seeders: 0,
                                                leechers: 0,
                                                next_announce_in: 300,
                                                failure_reason: Some(e.to_string()),
                                                is_circuit_broken: is_cb,
                                                cb_state: None,
                                                recovery_progress_pct: None,
                                            };
                                            (peers, interval, rep)
                                        }
                                        Err(_) => {
                                            tracker_breaker.record_failure(&url_str);
                                            warn!(
                                                "[{}] UDP tracker {} announce timed out",
                                                label_c, safe_url
                                            );
                                            let rep = TrackerReport {
                                                url: tracker_url.to_string(),
                                                status: "Timeout".into(),
                                                seeders: 0,
                                                leechers: 0,
                                                next_announce_in: 300,
                                                failure_reason: Some("Tracker timed out after 5s".into()),
                                                is_circuit_broken: is_cb,
                                                cb_state: None,
                                                recovery_progress_pct: None,
                                            };
                                            (peers, interval, rep)
                                        }
                                    }
                                } else {
                                    tracker_breaker.record_failure(&url_str);
                                    let rep = TrackerReport {
                                        url: tracker_url.to_string(),
                                        status: "Error".into(),
                                        seeders: 0,
                                        leechers: 0,
                                        next_announce_in: 300,
                                        failure_reason: Some("No address found for host".into()),
                                        is_circuit_broken: false,
                                        cb_state: None,
                                        recovery_progress_pct: None,
                                    };
                                    (peers, interval, rep)
                                }
                            }
                            Ok(Err(e)) => {
                                tracker_breaker.record_failure(&url_str);
                                let rep = TrackerReport {
                                    url: tracker_url.to_string(),
                                    status: "Error".into(),
                                    seeders: 0,
                                    leechers: 0,
                                    next_announce_in: 300,
                                    failure_reason: Some(format!("DNS lookup failed: {}", e)),
                                    is_circuit_broken: false,
                                    cb_state: None,
                                    recovery_progress_pct: None,
                                };
                                (peers, interval, rep)
                            }
                            Err(_) => {
                                tracker_breaker.record_failure(&url_str);
                                let rep = TrackerReport {
                                    url: tracker_url.to_string(),
                                    status: "Timeout".into(),
                                    seeders: 0,
                                    leechers: 0,
                                    next_announce_in: 300,
                                    failure_reason: Some("DNS lookup timed out".into()),
                                    is_circuit_broken: false,
                                    cb_state: None,
                                    recovery_progress_pct: None,
                                };
                                (peers, interval, rep)
                            }
                        }
                    }
                    "http" | "https" => {
                        match tokio::time::timeout(
                            Duration::from_secs(10),
                            synapse_tracker::http::announce(&tracker_url, &req_clone),
                        )
                        .await
                        {
                            Ok(Ok(resp)) => {
                                tracker_breaker.record_success(&url_str);
                                info!(
                                    "[{}] HTTP/HTTPS tracker {} returned {} seeders, {} leechers, {} peers (interval: {}s)",
                                    label_c,
                                    safe_url,
                                    resp.seeders,
                                    resp.leechers,
                                    resp.peers.len(),
                                    resp.interval
                                );
                                interval = Some(resp.interval);
                                for p in resp.peers {
                                    if p.port() != 0 {
                                        peers.push(p);
                                    }
                                }
                                let rep = TrackerReport {
                                    url: tracker_url.to_string(),
                                    status: "Announced".into(),
                                    seeders: resp.seeders,
                                    leechers: resp.leechers,
                                    next_announce_in: resp.interval as i64,
                                    failure_reason: None,
                                    is_circuit_broken: false,
                                    cb_state: None,
                                    recovery_progress_pct: None,
                                };
                                (peers, interval, rep)
                            }
                            Ok(Err(e)) => {
                                tracker_breaker.record_failure(&url_str);
                                warn!(
                                    "[{}] HTTP/HTTPS tracker {} error: {}",
                                    label_c, safe_url, e
                                );
                                let rep = TrackerReport {
                                    url: tracker_url.to_string(),
                                    status: "Error".into(),
                                    seeders: 0,
                                    leechers: 0,
                                    next_announce_in: 300,
                                    failure_reason: Some(e.to_string()),
                                    is_circuit_broken: false,
                                    cb_state: None,
                                    recovery_progress_pct: None,
                                };
                                (peers, interval, rep)
                            }
                            Err(_) => {
                                tracker_breaker.record_failure(&url_str);
                                warn!(
                                    "[{}] HTTP/HTTPS tracker {} timed out after 10s",
                                    label_c, safe_url
                                );
                                let rep = TrackerReport {
                                    url: tracker_url.to_string(),
                                    status: "Timeout".into(),
                                    seeders: 0,
                                    leechers: 0,
                                    next_announce_in: 300,
                                    failure_reason: Some("HTTP announce timed out after 10s".into()),
                                    is_circuit_broken: false,
                                    cb_state: None,
                                    recovery_progress_pct: None,
                                };
                                (peers, interval, rep)
                            }
                        }
                    }
                    _ => {
                        let rep = TrackerReport {
                            url: tracker_url.to_string(),
                            status: "Unsupported".into(),
                            seeders: 0,
                            leechers: 0,
                            next_announce_in: 3600,
                            failure_reason: Some(format!("Unsupported tracker scheme: {}", tracker_url.scheme())),
                            is_circuit_broken: false,
                            cb_state: None,
                            recovery_progress_pct: None,
                        };
                        (peers, interval, rep)
                    }
                };
                (peers_res, interval_res, report)
            });
        }

        let results = futures::future::join_all(tasks).await;
        let mut min_interval = None;
        let mut reports = Vec::with_capacity(results.len());
        for (peer_list, intv, rep) in results {
            for p in peer_list {
                discovered_peers.insert(p);
            }
            if let Some(i) = intv {
                if i > 0 {
                    min_interval = Some(min_interval.map_or(i, |curr: u32| curr.min(i)));
                }
            }
            reports.push(rep);
        }

        let interval = min_interval.unwrap_or(1800).clamp(300, 3600);
        (discovered_peers.into_iter().collect(), interval, reports)
    }

    /// Announce to all trackers associated with the torrent info, returning all discovered peer addresses.
    pub async fn announce(
        &self,
        info: &Info,
        downloaded: u64,
        left: u64,
        uploaded: u64,
        event: Event,
    ) -> Vec<SocketAddr> {
        self.announce_with_interval(info, downloaded, left, uploaded, event)
            .await
            .0
    }

    /// Discovers peers from trackers and dials outbound connections for the torrent actor.
    pub async fn discover_and_connect_peers(
        &self,
        info: Arc<Info>,
        downloaded: u64,
        left: u64,
        uploaded: u64,
        events_tx: mpsc::Sender<PeerEvent>,
        max_peers: usize,
    ) -> usize {
        self.discover_and_connect_peers_with_event(
            info,
            AnnounceStats {
                downloaded,
                left,
                uploaded,
            },
            events_tx,
            max_peers,
            Event::Started,
        )
        .await
        .0
    }

    /// Discovers peers with an explicit event and returns (dialed_count, tracker_interval, tracker_reports).
    pub async fn discover_and_connect_peers_with_event(
        &self,
        info: Arc<Info>,
        stats: AnnounceStats,
        events_tx: mpsc::Sender<PeerEvent>,
        max_peers: usize,
        event: Event,
    ) -> (usize, u32, Vec<TrackerReport>) {
        let (peers, interval, reports) = self
            .announce_with_interval(&info, stats.downloaded, stats.left, stats.uploaded, event)
            .await;
        let mut connected_count = 0;

        for peer_addr in peers {
            if peer_addr.port() == 0 {
                continue;
            }
            if connected_count >= max_peers {
                break;
            }

            if !self.circuit_breaker.can_connect(&peer_addr) {
                continue;
            }

            let our_id = self.our_peer_id;
            let info_hash = info.hash;
            let is_private = info.private;
            let tx = events_tx.clone();
            let cb = self.circuit_breaker.clone();

            tokio::spawn(async move {
                match tokio::time::timeout(
                    Duration::from_secs(12),
                    connect(peer_addr, our_id, info_hash, is_private, tx),
                )
                .await
                {
                    Ok(Ok(())) => {
                        cb.record_success(&peer_addr);
                        debug!("Successfully initiated peer connection to {}", peer_addr);
                    }
                    Ok(Err(e)) => {
                        cb.record_failure(&peer_addr);
                        debug!("Failed to connect to peer {}: {}", peer_addr, e);
                    }
                    Err(_) => {
                        cb.record_failure(&peer_addr);
                        debug!("Connection attempt timed out for peer {}", peer_addr);
                    }
                }
            });

            connected_count += 1;
        }

        (connected_count, interval, reports)
    }
}

/// Represents a scheduled announce job in the priority min-heap.
#[derive(Debug, Clone)]
struct ScheduledJob {
    info_hash: [u8; 20],
    next_announce_at: Instant,
    is_downloading: bool,
    event: Event,
}

impl PartialEq for ScheduledJob {
    fn eq(&self, other: &Self) -> bool {
        self.next_announce_at == other.next_announce_at
            && self.is_downloading == other.is_downloading
    }
}

impl Eq for ScheduledJob {}

impl Ord for ScheduledJob {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Min-heap ordering: earliest next_announce_at is popped first.
        // For matching times, downloading swarms take priority over seeding.
        other
            .next_announce_at
            .cmp(&self.next_announce_at)
            .then_with(|| self.is_downloading.cmp(&other.is_downloading))
    }
}

impl PartialOrd for ScheduledJob {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

struct SwarmMeta {
    info: Arc<Info>,
    stats: Arc<RwLock<SwarmStats>>,
    events_tx: mpsc::Sender<PeerEvent>,
    consecutive_failures: u32,
    next_announce_at: Instant,
    tracker_reports: Vec<TrackerReport>,
    candidate_peers: VecDeque<SocketAddr>,
    active_dials: HashSet<SocketAddr>,
}

/// Callback type for dynamically waking dormant swarms and obtaining their peer event channel.
pub type PeerEventRouter = Arc<dyn Fn(&[u8; 20]) -> Option<mpsc::Sender<PeerEvent>> + Send + Sync>;

/// Centralized Announce Scheduler for high-scale swarm management (10,000–50,000+ torrents).
///
/// Replaces individual per-torrent ticker loops with a single unified event scheduler
/// that enforces tracker intervals, bounds concurrent announces, applies BEP-compliant jitter,
/// and executes exponential backoff on tracker failures.
pub struct AnnounceScheduler {
    announcer: Arc<Announcer>,
    queue: Mutex<BinaryHeap<ScheduledJob>>,
    swarms: RwLock<HashMap<[u8; 20], SwarmMeta>>,
    wake_notify: Arc<Notify>,
    shutdown: AtomicBool,
    concurrency_limit: Arc<Semaphore>,
    default_interval: Duration,
    max_startup_jitter: Duration,
    peer_router: RwLock<Option<PeerEventRouter>>,
    settings: RwLock<Option<Arc<RwLock<crate::settings::DynamicSessionSettings>>>>,
    ip_filter: RwLock<Option<Arc<RwLock<crate::ipfilter::IpFilter>>>>,
}

impl AnnounceScheduler {
    pub fn new(
        announcer: Arc<Announcer>,
        max_concurrent_announces: usize,
        default_interval: Duration,
        max_startup_jitter: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            announcer,
            queue: Mutex::new(BinaryHeap::new()),
            swarms: RwLock::new(HashMap::new()),
            wake_notify: Arc::new(Notify::new()),
            shutdown: AtomicBool::new(false),
            concurrency_limit: Arc::new(Semaphore::new(max_concurrent_announces.max(1))),
            default_interval,
            max_startup_jitter,
            peer_router: RwLock::new(None),
            settings: RwLock::new(None),
            ip_filter: RwLock::new(None),
        })
    }

    /// Sets the dynamic peer event router used to awaken dormant Warm/Cold swarms when tracker peers are found.
    pub fn set_peer_router(&self, router: PeerEventRouter) {
        *self.peer_router.write() = Some(router);
    }

    /// Sets the live session settings used to bound outbound dial targets by the
    /// configured `max_peers_per_torrent` / `max_global_peers` caps -- see `dial_step`.
    pub fn set_settings(&self, settings: Arc<RwLock<crate::settings::DynamicSessionSettings>>) {
        *self.settings.write() = Some(settings);
    }

    /// Sets the shared IP filter used to skip blocklisted candidate peers before ever
    /// dialing them -- see `dial_step`.
    pub fn set_ip_filter(&self, ip_filter: Arc<RwLock<crate::ipfilter::IpFilter>>) {
        *self.ip_filter.write() = Some(ip_filter);
    }

    /// Returns a reference to the inner Announcer instance.
    pub fn announcer(&self) -> &Arc<Announcer> {
        &self.announcer
    }

    /// Registers a new or restored torrent in the centralized announce queue.
    /// Downloading swarms announce immediately; seeding swarms apply startup jitter.
    pub fn register(
        &self,
        info_hash: [u8; 20],
        info: Arc<Info>,
        stats: Arc<RwLock<SwarmStats>>,
        events_tx: mpsc::Sender<PeerEvent>,
        is_downloading: bool,
    ) {
        let next_announce_at = if is_downloading {
            Instant::now()
        } else {
            let jitter_secs = if self.max_startup_jitter.as_secs() > 0 {
                rand::Rng::gen_range(&mut rand::thread_rng(), 1..=self.max_startup_jitter.as_secs())
            } else {
                0
            };
            Instant::now() + Duration::from_secs(jitter_secs)
        };

        let candidate_urls = Announcer::candidate_trackers(&info);
        let now = Instant::now();
        let initial_remaining = if next_announce_at > now {
            (next_announce_at - now).as_secs() as i64
        } else {
            0
        };
        let initial_reports: Vec<TrackerReport> = candidate_urls
            .into_iter()
            .map(|u| TrackerReport {
                url: u.to_string(),
                status: if is_downloading { "Updating".into() } else { "Ready".into() },
                seeders: 0,
                leechers: 0,
                next_announce_in: initial_remaining,
                failure_reason: None,
                is_circuit_broken: false,
                cb_state: None,
                recovery_progress_pct: None,
            })
            .collect();

        {
            let mut swarms = self.swarms.write();
            swarms.insert(
                info_hash,
                SwarmMeta {
                    info,
                    stats,
                    events_tx,
                    consecutive_failures: 0,
                    next_announce_at,
                    tracker_reports: initial_reports,
                    candidate_peers: VecDeque::new(),
                    active_dials: HashSet::new(),
                },
            );
        }

        {
            let mut q = self.queue.lock();
            q.push(ScheduledJob {
                info_hash,
                next_announce_at,
                is_downloading,
                event: Event::Started,
            });
        }

        if is_downloading {
            self.wake_notify.notify_one();
        }
    }

    /// Enqueues newly discovered peers from trackers or PEX into the swarm's candidate pool.
    pub fn add_candidate_peers(&self, info_hash: &[u8; 20], peers: impl IntoIterator<Item = SocketAddr>) {
        let mut swarms = self.swarms.write();
        if let Some(meta) = swarms.get_mut(info_hash) {
            let mut existing: HashSet<SocketAddr> = meta.candidate_peers.iter().copied().collect();
            for addr in peers {
                if addr.port() != 0
                    && !existing.contains(&addr)
                    && !meta.active_dials.contains(&addr)
                    && self.announcer.circuit_breaker.can_connect(&addr)
                    && meta.candidate_peers.len() < 2000
                {
                    existing.insert(addr);
                    meta.candidate_peers.push_back(addr);
                }
            }
        }
    }

    /// Returns the number of candidate peers currently queued for dialing.
    pub fn candidate_peers_count(&self, info_hash: &[u8; 20]) -> usize {
        let swarms = self.swarms.read();
        swarms.get(info_hash).map(|m| m.candidate_peers.len()).unwrap_or(0)
    }

    /// Unregisters a removed torrent from future announces.
    pub fn unregister(&self, info_hash: &[u8; 20]) {
        let mut swarms = self.swarms.write();
        swarms.remove(info_hash);
    }

    /// Wakes the scheduler to send an immediate `Event::Completed` announce for a finished download.
    pub fn notify_completed(&self, info_hash: &[u8; 20]) {
        let mut q = self.queue.lock();
        q.push(ScheduledJob {
            info_hash: *info_hash,
            next_announce_at: Instant::now(),
            is_downloading: false,
            event: Event::Completed,
        });
        self.wake_notify.notify_one();
    }

    /// Wakes the scheduler to immediately announce a resumed torrent.
    pub fn notify_resumed(&self, info_hash: &[u8; 20]) {
        let mut q = self.queue.lock();
        q.push(ScheduledJob {
            info_hash: *info_hash,
            next_announce_at: Instant::now(),
            is_downloading: true,
            event: Event::Started,
        });
        self.wake_notify.notify_one();
    }

    pub fn active_swarms_count(&self) -> usize {
        self.swarms.read().len()
    }

    pub fn pending_announces(&self) -> usize {
        self.queue.lock().len()
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.wake_notify.notify_one();
    }

    /// Spawns the background scheduler actor loop and continuous candidate peer dialer.
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let dialer_self = self.clone();
        tokio::spawn(async move {
            dialer_self.run_dialer().await;
        });

        tokio::spawn(async move {
            loop {
                if self.shutdown.load(Ordering::Relaxed) {
                    break;
                }

                let next_due = {
                    let q = self.queue.lock();
                    q.peek().map(|j| j.next_announce_at)
                };

                let wait_duration = match next_due {
                    Some(t) => {
                        let now = Instant::now();
                        if t <= now {
                            Duration::from_millis(0)
                        } else {
                            t - now
                        }
                    }
                    None => Duration::from_secs(30),
                };

                if wait_duration.as_millis() > 0 {
                    tokio::select! {
                        _ = tokio::time::sleep(wait_duration) => {}
                        _ = self.wake_notify.notified() => {}
                    }
                }

                self.dispatch_batch().await;
            }
        })
    }

    async fn run_dialer(self: Arc<Self>) {
        let mut ticker = tokio::time::interval(Duration::from_millis(500));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }

            tokio::select! {
                _ = ticker.tick() => {}
                _ = self.wake_notify.notified() => {}
            }

            self.dial_step().await;
        }
    }

    async fn dial_step(self: &Arc<Self>) {
        // Bound outbound dial targets by the configured per-torrent cap -- without this,
        // the dialer would keep opening connections up to a hardcoded target regardless
        // of what the user has configured (or lowered) `max_peers_per_torrent` to.
        let max_per_torrent = self
            .settings
            .read()
            .as_ref()
            .map(|s| s.read().max_peers_per_torrent)
            .unwrap_or(crate::settings::DynamicSessionSettings::default().max_peers_per_torrent);

        let ip_filter = self.ip_filter.read().clone();

        let dials_to_start = {
            let mut swarms = self.swarms.write();
            let mut to_dial = Vec::new();
            let mut starved_swarms = Vec::new();

            for (info_hash, meta) in swarms.iter_mut() {
                let (state, connected) = {
                    let s = meta.stats.read();
                    (s.state.clone(), s.peers_connected)
                };

                let target_peers = match state {
                    crate::swarm::SwarmState::Downloading => max_per_torrent.min(40),
                    crate::swarm::SwarmState::Seeding => max_per_torrent.min(30),
                    _ => 0,
                };

                if target_peers == 0 {
                    continue;
                }

                // Fast re-announce on peer starvation:
                // If downloading and fewer than 8 peers connected (or connected < target_peers and 0 peers sending),
                // with empty candidate pool and no active dials,
                // trigger an accelerated announce if the next scheduled announce is more than 20s away.
                let peers_sending = meta.stats.read().peers_sending;
                let is_starved = state == crate::swarm::SwarmState::Downloading
                    && meta.candidate_peers.is_empty()
                    && meta.active_dials.is_empty()
                    && (connected < 8 || (connected < target_peers && peers_sending == 0));

                if is_starved {
                    let now = Instant::now();
                    if meta.next_announce_at > now + Duration::from_secs(20) {
                        meta.next_announce_at = now + Duration::from_secs(15);
                        starved_swarms.push((*info_hash, meta.next_announce_at));
                    }
                }

                if connected >= target_peers {
                    continue;
                }

                const MAX_CONCURRENT_DIALS_PER_SWARM: usize = 16;
                let active_count = meta.active_dials.len();
                if active_count >= MAX_CONCURRENT_DIALS_PER_SWARM {
                    continue;
                }

                let remaining_needed = target_peers.saturating_sub(connected + active_count);
                let dial_budget = remaining_needed.min(MAX_CONCURRENT_DIALS_PER_SWARM - active_count);
                if dial_budget == 0 {
                    continue;
                }

                let mut count = 0;
                while count < dial_budget {
                    if let Some(addr) = meta.candidate_peers.pop_front() {
                        if meta.active_dials.contains(&addr) || !self.announcer.circuit_breaker.can_connect(&addr) {
                            continue;
                        }
                        if let Some(ref filter) = ip_filter {
                            if filter.read().is_blocked(addr.ip()) {
                                continue;
                            }
                        }
                        meta.active_dials.insert(addr);
                        to_dial.push((*info_hash, meta.info.clone(), addr, meta.events_tx.clone()));
                        count += 1;
                    } else {
                        break;
                    }
                }
            }

            if !starved_swarms.is_empty() {
                let mut q = self.queue.lock();
                for (info_hash, next_at) in starved_swarms {
                    debug!(
                        info_hash = %hex::encode(info_hash),
                        "Swarm starved of peers; accelerating next tracker announce"
                    );
                    q.push(ScheduledJob {
                        info_hash,
                        next_announce_at: next_at,
                        is_downloading: true,
                        event: Event::None,
                    });
                }
            }

            to_dial
        };

        for (info_hash, info, addr, fallback_tx) in dials_to_start {
            let scheduler = self.clone();
            let our_id = self.announcer.our_peer_id;
            let cb = self.announcer.circuit_breaker.clone();
            let events_tx = if let Some(ref router) = *self.peer_router.read() {
                router(&info_hash).unwrap_or(fallback_tx)
            } else {
                fallback_tx
            };

            tokio::spawn(async move {
                match tokio::time::timeout(
                    Duration::from_secs(12),
                    connect(addr, our_id, info.hash, info.private, events_tx),
                )
                .await
                {
                    Ok(Ok(())) => {
                        cb.record_success(&addr);
                        debug!(peer = %addr, "Successfully connected to candidate peer");
                    }
                    Ok(Err(e)) => {
                        cb.record_failure(&addr);
                        debug!(peer = %addr, "Failed to connect to candidate peer: {e}");
                    }
                    Err(_) => {
                        cb.record_failure(&addr);
                        debug!(peer = %addr, "Candidate peer connect timed out");
                    }
                }

                let mut swarms = scheduler.swarms.write();
                if let Some(m) = swarms.get_mut(&info_hash) {
                    m.active_dials.remove(&addr);
                }
            });
        }
    }

    async fn dispatch_batch(self: &Arc<Self>) {
        let now = Instant::now();
        let mut due_jobs = Vec::new();

        {
            let mut q = self.queue.lock();
            while let Some(job) = q.peek() {
                if job.next_announce_at <= now && due_jobs.len() < 32 {
                    due_jobs.push(q.pop().unwrap());
                } else {
                    break;
                }
            }
        }

        for job in due_jobs {
            let meta_opt = {
                let swarms = self.swarms.read();
                swarms.get(&job.info_hash).map(|m| {
                    (
                        m.info.clone(),
                        m.stats.clone(),
                        m.consecutive_failures,
                    )
                })
            };

            let Some((info, stats, failures)) = meta_opt else {
                continue; // Unregistered torrent
            };

            let (state, dl, left, ul) = {
                let s = stats.read();
                (
                    s.state.clone(),
                    s.downloaded_bytes,
                    s.total_size.saturating_sub(s.downloaded_bytes),
                    s.uploaded_bytes,
                )
            };

            if matches!(
                state,
                crate::swarm::SwarmState::Stopped | crate::swarm::SwarmState::Error(_)
            ) {
                // Torrent paused or errored: defer next announce attempt
                let mut q = self.queue.lock();
                q.push(ScheduledJob {
                    info_hash: job.info_hash,
                    next_announce_at: Instant::now() + Duration::from_secs(300),
                    is_downloading: false,
                    event: Event::None,
                });
                continue;
            }

            let permit = match self.concurrency_limit.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    // Maximum concurrent announces reached; requeue with short backpressure delay
                    let mut q = self.queue.lock();
                    q.push(ScheduledJob {
                        info_hash: job.info_hash,
                        next_announce_at: Instant::now() + Duration::from_millis(500),
                        is_downloading: job.is_downloading,
                        event: job.event,
                    });
                    continue;
                }
            };

            let scheduler = self.clone();
            let announcer = self.announcer.clone();
            let is_dl = state == crate::swarm::SwarmState::Downloading;

            tokio::spawn(async move {
                let _permit = permit;
                let (peers, tracker_interval, reports) = announcer
                    .announce_with_interval(&info, dl, left, ul, job.event)
                    .await;

                let peer_count = peers.len();
                scheduler.add_candidate_peers(&job.info_hash, peers);

                let (current_connected, current_sending) = {
                    let swarms = scheduler.swarms.read();
                    swarms
                        .get(&job.info_hash)
                        .map(|m| {
                            let s = m.stats.read();
                            (s.peers_connected, s.peers_sending)
                        })
                        .unwrap_or((0, 0))
                };

                let is_starved = is_dl && (current_connected < 8 || current_sending == 0);

                let all_cb = !reports.is_empty() && reports.iter().all(|r| r.is_circuit_broken);
                let (delay_secs, new_failures) = if all_cb && peer_count == 0 {
                    // Stagger retry during circuit breaker cooling/ramp-up: 5 to 15 seconds randomized jitter
                    let stagger = rand::Rng::gen_range(&mut rand::thread_rng(), 5..=15);
                    (stagger as u64, failures)
                } else if (peer_count > 0 || tracker_interval > 0) && !reports.is_empty() {
                    let base = if is_starved {
                        if peer_count == 0 { 30 } else { 60 }
                    } else if tracker_interval > 0 {
                        tracker_interval
                    } else {
                        scheduler.default_interval.as_secs() as u32
                    }
                    .clamp(15, 3600);

                    // BEP 3 recommended +/- 10% randomized jitter
                    let jitter_range = (base as f64 * 0.1) as i64;
                    let jitter = if jitter_range > 0 {
                        rand::Rng::gen_range(&mut rand::thread_rng(), -jitter_range..=jitter_range)
                    } else {
                        0
                    };
                    ((base as i64 + jitter).max(15) as u64, 0)
                } else {
                    // Exponential backoff on failed or unreachable tracker: 30s, 60s, 120s...
                    let backoff = (30 * (1 << failures.min(5))).min(1800);
                    (backoff as u64, failures + 1)
                };

                let next_announce_at = Instant::now() + Duration::from_secs(delay_secs);

                {
                    let mut swarms = scheduler.swarms.write();
                    if let Some(m) = swarms.get_mut(&job.info_hash) {
                        m.consecutive_failures = new_failures;
                        m.next_announce_at = next_announce_at;
                        for mut rep in reports {
                            rep.next_announce_in = delay_secs as i64;
                            if let Some(existing) = m.tracker_reports.iter_mut().find(|t| t.url == rep.url) {
                                *existing = rep;
                            } else {
                                m.tracker_reports.push(rep);
                            }
                        }
                    }
                }

                {
                    let mut q = scheduler.queue.lock();
                    q.push(ScheduledJob {
                        info_hash: job.info_hash,
                        next_announce_at,
                        is_downloading: is_dl,
                        event: Event::None,
                    });
                }

                scheduler.wake_notify.notify_one();
            });
        }
    }

    /// Returns the latest live tracker status reports for the given info hash,
    /// with dynamically computed countdown seconds until the next announce.
    pub fn get_tracker_reports(&self, info_hash: &[u8; 20]) -> Vec<TrackerReport> {
        let swarms = self.swarms.read();
        if let Some(meta) = swarms.get(info_hash) {
            let now = Instant::now();
            let remaining_secs = if meta.next_announce_at > now {
                (meta.next_announce_at - now).as_secs() as i64
            } else {
                0
            };
            let tracker_breaker = self.announcer.tracker_breaker();
            meta.tracker_reports
                .iter()
                .cloned()
                .map(|mut r| {
                    r.next_announce_in = remaining_secs;
                    let status = tracker_breaker.get_host_status(&r.url);
                    r.cb_state = Some(status.state);
                    r.recovery_progress_pct = tracker_breaker.recovery_progress_pct(&status);
                    r
                })
                .collect()
        } else {
            Vec::new()
        }
    }
}
