//! Tracker Announcer and Centralized Announce Priority Scheduler.
//!
//! Orchestrates BEP 15 UDP and HTTP tracker announces for active and seeding swarms.
//! Replaces per-torrent announce interval loops with a single centralized priority
//! min-heap scheduler that enforces tracker-specified intervals (BEP 3/15), applies
//! randomized startup jitter, bounds concurrency, and handles exponential backoff.

use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::{DashMap, DashSet};
use parking_lot::{Mutex, RwLock};
use tokio::sync::{mpsc, Notify, Semaphore};
use tracing::{debug, info, warn};

use synapse_meta::Info;
use synapse_tracker::{AnnounceRequest, CanaryCircuitBreaker, Event};

use crate::circuit_breaker::PeerCircuitBreaker;
use crate::peer::{connect_with_options, PeerEvent, HANDSHAKE_TIMEOUT};
use crate::pex;
use crate::swarm::SwarmStats;

fn udp_tracker_target_allowed(tracker_url: &url::Url, target: IpAddr) -> bool {
    if synapse_tracker::safe_http::is_public_ip(target) {
        return true;
    }
    let Some(host) = tracker_url.host_str() else {
        return false;
    };
    if !synapse_tracker::safe_http::is_internal_hostname(host) {
        return false;
    }
    tracker_url
        .path_segments()
        .and_then(|mut segs| segs.rfind(|s| !s.is_empty()))
        .is_some_and(|last| matches!(last, "announce" | "scrape"))
}

/// Drops peer addresses a tracker response must never be allowed to steer us toward
/// dialling: loopback/link-local/private-range targets, unless the tracker we asked is
/// itself on that kind of network (a genuine private/self-hosted tracker). A malicious
/// or compromised public tracker returning `127.0.0.1:<port>` or `192.168.x.x:<port>`
/// peer entries cannot otherwise make us probe our own internal network on its behalf.
fn filter_tracker_peers(peers: Vec<SocketAddr>, tracker_source: Option<IpAddr>) -> Vec<SocketAddr> {
    let source = tracker_source.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    peers
        .into_iter()
        .filter(|addr| pex::pex_address_allowed(*addr, source))
        .collect()
}

/// Most tracker URLs taken from a torrent's own announce list.
const MAX_TRACKERS_PER_TORRENT: usize = 50;

/// Whether public (non-private) torrents also announce to the built-in list of well-known
/// public trackers. Off by default: announcing hands each torrent's info hash to third
/// parties the user never chose. Set once at startup from `network.enable_fallback_trackers`.
static FALLBACK_TRACKERS_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enables or disables the built-in public fallback trackers (see above).
pub fn set_fallback_trackers_enabled(enabled: bool) {
    FALLBACK_TRACKERS_ENABLED.store(enabled, Ordering::Relaxed);
}

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
    /// Unix epoch seconds of the most recent completed/attempted announce.
    #[serde(default)]
    pub last_announce_time: Option<i64>,
}

/// `(info hash, tracker URL)` -> the tracker id it gave.
type TrackerIds = HashMap<([u8; 20], String), String>;

pub struct Announcer {
    our_peer_id: [u8; 20],
    listen_port: Arc<RwLock<u16>>,
    tracker_key: u32,
    circuit_breaker: Arc<PeerCircuitBreaker>,
    tracker_breaker: Arc<CanaryCircuitBreaker>,
    udp_client: Arc<synapse_tracker::UdpTrackerClient>,
    nat_manager: Option<Arc<RwLock<crate::nat::NatManager>>>,
    settings: Option<Arc<RwLock<crate::settings::DynamicSessionSettings>>>,
    utp_manager: Arc<RwLock<Option<Arc<crate::utp::UtpSocketManager>>>>,
    alert_sender: Arc<RwLock<Option<tokio::sync::broadcast::Sender<crate::alert::Alert>>>>,
    alert_category_mask: Arc<RwLock<Option<Arc<AtomicU32>>>>,
    /// The `tracker id` each tracker gave us for each torrent, sent back on later announces.
    tracker_ids: Arc<parking_lot::Mutex<TrackerIds>>,
    /// The external address each tracker reported (BEP 24), by tracker URL.
    external_ip_votes: Arc<parking_lot::Mutex<HashMap<String, std::net::IpAddr>>>,
    /// Per-torrent tracker lists set through the API. A torrent's own `announce`/`announce-list`
    /// lives in an immutable `Info`, so a replacement is held here and consulted instead.
    tracker_overrides: Arc<RwLock<HashMap<[u8; 20], Vec<url::Url>>>>,
}

impl Announcer {
    /// Replaces the tracker list used for a torrent (`None` restores the torrent's own).
    pub fn set_tracker_override(&self, info_hash: [u8; 20], trackers: Option<Vec<url::Url>>) {
        let mut map = self.tracker_overrides.write();
        match trackers {
            Some(list) => {
                map.insert(info_hash, list);
            }
            None => {
                map.remove(&info_hash);
            }
        }
    }

    /// Structured tracker tiers for BEP 12 failover: tracker override (if set) in tier 0,
    /// otherwise metainfo `announce-list` tiers + `announce`, plus optional public fallback tier.
    pub fn tracker_tiers_for(&self, info: &Info) -> Vec<Vec<url::Url>> {
        match self.tracker_overrides.read().get(&info.hash) {
            Some(list) => {
                let mut seen = HashSet::new();
                let mut primary = Vec::new();
                for u in list {
                    if primary.len() >= MAX_TRACKERS_PER_TORRENT {
                        break;
                    }
                    if seen.insert(u.clone()) {
                        primary.push(u.clone());
                    }
                }
                let mut tiers = Vec::new();
                if !primary.is_empty() {
                    tiers.push(primary);
                }
                Self::append_fallback_tier(&mut tiers, &mut seen, info.private);
                tiers
            }
            None => Self::candidate_tracker_tiers(info),
        }
    }

    /// The trackers a torrent announces to: its API-set replacement if there is one,
    /// otherwise the ones in its metainfo (plus the public fallbacks, for public torrents).
    pub fn trackers_for(&self, info: &Info) -> Vec<url::Url> {
        self.tracker_tiers_for(info).into_iter().flatten().collect()
    }

    /// Our external address if at least two different trackers agree on it (BEP 24).
    pub fn external_ip(&self) -> Option<std::net::IpAddr> {
        let votes = self.external_ip_votes.lock();
        let mut counts: HashMap<std::net::IpAddr, usize> = HashMap::new();
        for ip in votes.values() {
            *counts.entry(*ip).or_default() += 1;
        }
        counts
            .into_iter()
            .filter(|(_, n)| *n >= 2)
            .max_by_key(|(_, n)| *n)
            .map(|(ip, _)| ip)
    }

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
            udp_client: Arc::new(synapse_tracker::UdpTrackerClient::new()),
            nat_manager: None,
            settings: None,
            utp_manager: Arc::new(RwLock::new(None)),
            alert_sender: Arc::new(RwLock::new(None)),
            alert_category_mask: Arc::new(RwLock::new(None)),
            tracker_ids: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            external_ip_votes: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            tracker_overrides: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_alert_sender(
        self,
        sender: tokio::sync::broadcast::Sender<crate::alert::Alert>,
    ) -> Self {
        *self.alert_sender.write() = Some(sender);
        self
    }

    pub fn set_alert_sender(&self, sender: tokio::sync::broadcast::Sender<crate::alert::Alert>) {
        *self.alert_sender.write() = Some(sender);
    }

    pub fn set_alert_category_mask(&self, mask: Arc<AtomicU32>) {
        *self.alert_category_mask.write() = Some(mask);
    }

    pub fn with_nat_manager(mut self, nat_manager: Arc<RwLock<crate::nat::NatManager>>) -> Self {
        self.nat_manager = Some(nat_manager);
        self
    }

    pub fn with_settings(
        mut self,
        settings: Arc<RwLock<crate::settings::DynamicSessionSettings>>,
    ) -> Self {
        self.settings = Some(settings);
        self
    }

    pub fn with_utp_manager(self, utp_manager: Arc<crate::utp::UtpSocketManager>) -> Self {
        *self.utp_manager.write() = Some(utp_manager);
        self
    }

    pub fn set_utp_manager(&self, utp_manager: Arc<crate::utp::UtpSocketManager>) {
        *self.utp_manager.write() = Some(utp_manager);
    }

    pub fn tracker_breaker(&self) -> &Arc<CanaryCircuitBreaker> {
        &self.tracker_breaker
    }

    /// Scrapes a tracker (HTTP/HTTPS or UDP) for swarm statistics across info hashes (BEP 48).
    pub async fn scrape(
        &self,
        tracker_url: &url::Url,
        info_hashes: &[[u8; 20]],
    ) -> Result<synapse_tracker::ScrapeResponse, synapse_tracker::TrackerError> {
        match tracker_url.scheme() {
            "http" | "https" => synapse_tracker::http::scrape(tracker_url, info_hashes).await,
            "udp" if crate::proxy::global().is_some_and(|p| p.proxy_http || p.force_proxy) => {
                Err(synapse_tracker::TrackerError::InvalidUrl(
                    "UDP trackers are not used while a proxy is configured",
                ))
            }
            "udp" => {
                let host = tracker_url
                    .host_str()
                    .ok_or(synapse_tracker::TrackerError::InvalidUrl("missing host"))?;
                let port = tracker_url.port().unwrap_or(6969);
                let target = tokio::net::lookup_host((host, port)).await?.next().ok_or(
                    synapse_tracker::TrackerError::InvalidUrl("failed to resolve tracker host"),
                )?;
                if !udp_tracker_target_allowed(tracker_url, target.ip()) {
                    return Err(synapse_tracker::TrackerError::InvalidUrl(
                        "non-public UDP tracker address is not permitted",
                    ));
                }
                self.udp_client.scrape(target, info_hashes).await
            }
            _ => Err(synapse_tracker::TrackerError::InvalidUrl(
                "unsupported tracker scheme for scrape",
            )),
        }
    }

    /// Extracts tracker tiers in BEP 12 order plus an optional public fallback tier.
    pub fn candidate_tracker_tiers(info: &Info) -> Vec<Vec<url::Url>> {
        let mut seen = HashSet::new();
        let mut tiers: Vec<Vec<url::Url>> = Vec::new();
        let mut total = 0usize;

        for tier in &info.url_list {
            let mut out_tier = Vec::new();
            for u in tier {
                if total >= MAX_TRACKERS_PER_TORRENT {
                    break;
                }
                let url = (**u).clone();
                if seen.insert(url.clone()) {
                    out_tier.push(url);
                    total += 1;
                }
            }
            if !out_tier.is_empty() {
                tiers.push(out_tier);
            }
            if total >= MAX_TRACKERS_PER_TORRENT {
                break;
            }
        }

        if let Some(ref a) = info.announce {
            if total < MAX_TRACKERS_PER_TORRENT {
                let url = (**a).clone();
                if seen.insert(url.clone()) {
                    tiers.push(vec![url]);
                }
            }
        }

        Self::append_fallback_tier(&mut tiers, &mut seen, info.private);
        tiers
    }

    /// Extracts all unique announce and fallback tracker URLs for an info hash.
    pub fn candidate_trackers(info: &Info) -> Vec<url::Url> {
        Self::candidate_tracker_tiers(info)
            .into_iter()
            .flatten()
            .collect()
    }

    fn append_fallback_tier(
        tiers: &mut Vec<Vec<url::Url>>,
        seen: &mut HashSet<url::Url>,
        private: bool,
    ) {
        if !private && FALLBACK_TRACKERS_ENABLED.load(Ordering::Relaxed) {
            let fallback_trackers = [
                "udp://tracker.opentrackr.org:1337/announce",
                "udp://open.stealth.si:80/announce",
                "udp://tracker.openbittorrent.com:6969/announce",
                "udp://explodie.org:6969/announce",
            ];
            let mut fallback_tier = Vec::new();
            for fb in fallback_trackers {
                if let Ok(u) = url::Url::parse(fb) {
                    if seen.insert(u.clone()) {
                        fallback_tier.push(u);
                    }
                }
            }
            if !fallback_tier.is_empty() {
                tiers.push(fallback_tier);
            }
        }
    }

    /// Announce to trackers using BEP 12 per-tier failover, returning discovered peer addresses,
    /// the minimum tracker interval, and individual tracker status reports.
    pub async fn announce_with_interval(
        &self,
        info: &Info,
        downloaded: u64,
        left: u64,
        uploaded: u64,
        event: Event,
    ) -> (Vec<SocketAddr>, u32, Vec<TrackerReport>) {
        let tiers = self.tracker_tiers_for(info);
        let announce_ip = self.settings.as_ref().and_then(|s| s.read().announce_ip);
        let bound_port = *self.listen_port.read();
        let port = self
            .nat_manager
            .as_ref()
            .and_then(|nm| {
                nm.read()
                    .mapped_external_port(bound_port, crate::nat::PortProtocol::Tcp)
            })
            .unwrap_or(if bound_port == 0 { 54345 } else { bound_port });
        let req = AnnounceRequest {
            info_hash: info.hash,
            peer_id: self.our_peer_id,
            port,
            uploaded,
            downloaded,
            left,
            event,
            num_want: Some(50),
            ipv4: announce_ip.and_then(|ip| match ip {
                std::net::IpAddr::V4(v4) => Some(v4),
                _ => None,
            }),
            ipv6: announce_ip.and_then(|ip| match ip {
                std::net::IpAddr::V6(v6) => Some(v6),
                _ => None,
            }),
            udp_options: Vec::new(),
            tracker_id: None,
        };

        let mut discovered_peers = HashSet::new();
        let mut min_interval = None;
        let mut reports = Vec::new();
        let tracker_key = self.tracker_key;

        let torrent_label = format!("{} ({})", info.name, &hex::encode(info.hash)[..8]);
        let announce_one = |tracker_url: url::Url| {
            let mut req_clone = req.clone();
            let label_c = torrent_label.clone();
            let circuit_breaker = self.circuit_breaker.clone();
            let tracker_breaker = self.tracker_breaker.clone();
            let alert_sender = self.alert_sender.clone();
            let alert_category_mask = self.alert_category_mask.clone();
            let tracker_ids = self.tracker_ids.clone();
            let external_ip_votes = self.external_ip_votes.clone();
            let udp_client = self.udp_client.clone();
            req_clone.tracker_id = tracker_ids
                .lock()
                .get(&(info.hash, tracker_url.to_string()))
                .cloned();
            async move {
                let mut peers = Vec::new();
                let mut interval = None;
                let url_str = tracker_url.to_string();
                // Logged and emitted in place of `tracker_url` everywhere below: private
                // trackers commonly embed a passkey in the query string or path.
                let safe_url = synapse_tracker::sanitize_tracker_url(&tracker_url);
                let tx_opt = alert_sender.read().clone();
                if let Some(tx) = tx_opt {
                    if tx.receiver_count() > 0 {
                        let allow_cat = alert_category_mask.read().as_ref().is_none_or(|m| {
                            (m.load(Ordering::Relaxed)
                                & crate::alert::AlertCategory::TRACKER.bits())
                                != 0
                        });
                        if allow_cat {
                            let _ = tx.send(crate::alert::Alert::TrackerAnnounce {
                                info_hash: req_clone.info_hash,
                                tracker_url: safe_url.clone(),
                                event: format!("{:?}", req_clone.event),
                            });
                        }
                    }
                }

                if !tracker_breaker.can_announce(&url_str) {
                    let rep = TrackerReport {
                        url: url_str,
                        status: "CircuitBroken".into(),
                        seeders: 0,
                        leechers: 0,
                        next_announce_in: 30,
                        failure_reason: Some(
                            "Tracker circuit broken or cooling down in recovery ramp-up".into(),
                        ),
                        is_circuit_broken: true,
                        cb_state: None,
                        last_announce_time: None,
                        recovery_progress_pct: None,
                    };
                    return (peers, interval, rep);
                }

                let (peers_res, interval_res, report) = match tracker_url.scheme() {
                    "udp"
                        if crate::proxy::global()
                            .is_some_and(|p| p.proxy_http || p.force_proxy) =>
                    {
                        // UDP cannot go through the proxy, and sending it directly would give
                        // away our address.
                        let rep = TrackerReport {
                            url: tracker_url.to_string(),
                            status: "Unsupported".into(),
                            seeders: 0,
                            leechers: 0,
                            next_announce_in: 3600,
                            failure_reason: Some(
                                "UDP trackers are not used while a proxy is configured".into(),
                            ),
                            is_circuit_broken: false,
                            cb_state: None,
                            last_announce_time: None,
                            recovery_progress_pct: None,
                        };
                        (peers, interval, rep)
                    }
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
                                    last_announce_time: None,
                                    recovery_progress_pct: None,
                                };
                                return (peers, interval, rep);
                            }
                        };
                        let port = tracker_url.port().unwrap_or(6969);

                        // BEP 41: If the UDP URL carries a path or query, attach UrlData option
                        let mut req_clone = req_clone;
                        let path = tracker_url.path();
                        let query = tracker_url.query();
                        let full_path = match (path, query) {
                            (p, Some(q)) if p.len() > 1 => format!("{p}?{q}"),
                            (p, None) if p.len() > 1 => p.to_string(),
                            (_, Some(q)) => format!("/?{q}"),
                            _ => String::new(),
                        };
                        if !full_path.is_empty() {
                            req_clone
                                .udp_options
                                .push(synapse_tracker::UdpOption::UrlData(full_path));
                        }

                        // BEP 34: a tracker URL without an explicit port may have DNS TXT preferences/opt-out
                        // or DNS SRV records naming where (and in what order) to announce. Targets must be
                        // public addresses, so DNS cannot aim us at the local network.
                        let mut srv_candidates: Vec<SocketAddr> = Vec::new();
                        if tracker_url.port().is_none() && host.parse::<std::net::IpAddr>().is_err()
                        {
                            match synapse_tracker::resolve_bep34_txt(&host, None).await {
                                synapse_tracker::Bep34TxtResult::OptOut => {
                                    let rep = TrackerReport {
                                        url: tracker_url.to_string(),
                                        status: "Blocked".into(),
                                        seeders: 0,
                                        leechers: 0,
                                        next_announce_in: 3600,
                                        failure_reason: Some(
                                            "Tracker domain opted out via BEP 34 DNS TXT record"
                                                .into(),
                                        ),
                                        is_circuit_broken: false,
                                        cb_state: None,
                                        last_announce_time: None,
                                        recovery_progress_pct: None,
                                    };
                                    return (peers, interval, rep);
                                }
                                synapse_tracker::Bep34TxtResult::Preferences(prefs) => {
                                    for pref in prefs
                                        .into_iter()
                                        .filter(|p| p.proto == synapse_tracker::TrackerProto::Udp)
                                        .take(3)
                                    {
                                        if let Ok(Ok(addrs)) = tokio::time::timeout(
                                            Duration::from_secs(2),
                                            tokio::net::lookup_host((host.as_str(), pref.port)),
                                        )
                                        .await
                                        {
                                            for a in addrs
                                                .filter(|a| {
                                                    synapse_tracker::safe_http::is_public_ip(a.ip())
                                                })
                                                .take(2)
                                            {
                                                if !srv_candidates.contains(&a) {
                                                    srv_candidates.push(a);
                                                }
                                            }
                                        }
                                    }
                                }
                                synapse_tracker::Bep34TxtResult::None => {}
                            }
                            for srv in synapse_tracker::resolve_tracker_srv(&host, "udp", None)
                                .await
                                .into_iter()
                                .take(3)
                            {
                                if let Ok(Ok(addrs)) = tokio::time::timeout(
                                    Duration::from_secs(2),
                                    tokio::net::lookup_host((srv.target.as_str(), srv.port)),
                                )
                                .await
                                {
                                    for a in addrs
                                        .filter(|a| {
                                            synapse_tracker::safe_http::is_public_ip(a.ip())
                                        })
                                        .take(2)
                                    {
                                        if !srv_candidates.contains(&a) {
                                            srv_candidates.push(a);
                                        }
                                    }
                                }
                            }
                        }
                        let host_port = format!("{}:{}", host, port);

                        match tokio::time::timeout(
                            Duration::from_secs(2),
                            tokio::net::lookup_host(host_port),
                        )
                        .await
                        {
                            Ok(Ok(addrs)) => {
                                let mut addrs_vec = srv_candidates;
                                for a in addrs {
                                    if !addrs_vec.contains(&a) {
                                        addrs_vec.push(a);
                                    }
                                }
                                addrs_vec
                                    .retain(|a| udp_tracker_target_allowed(&tracker_url, a.ip()));
                                if let Some(&resolved_addr) = addrs_vec.first() {
                                    let is_cb = !circuit_breaker.can_connect(&resolved_addr);
                                    debug!(
                                        "[{}] Announcing to UDP tracker {} ({})",
                                        label_c, safe_url, resolved_addr
                                    );
                                    match tokio::time::timeout(
                                        Duration::from_secs(20),
                                        udp_client.announce_any(
                                            &addrs_vec,
                                            &req_clone,
                                            tracker_key,
                                            Duration::from_secs(5),
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
                                            peers.extend(filter_tracker_peers(
                                                resp.peers,
                                                Some(resolved_addr.ip()),
                                            ));
                                            let rep = TrackerReport {
                                                url: tracker_url.to_string(),
                                                status: "Announced".into(),
                                                seeders: resp.seeders,
                                                leechers: resp.leechers,
                                                next_announce_in: resp.interval as i64,
                                                failure_reason: None,
                                                is_circuit_broken: is_cb,
                                                cb_state: None,
                                                last_announce_time: None,
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
                                                last_announce_time: None,
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
                                                failure_reason: Some("Tracker timed out".into()),
                                                is_circuit_broken: is_cb,
                                                cb_state: None,
                                                last_announce_time: None,
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
                                        failure_reason: Some(
                                            "No allowed public address found for host".into(),
                                        ),
                                        is_circuit_broken: false,
                                        cb_state: None,
                                        last_announce_time: None,
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
                                    last_announce_time: None,
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
                                    last_announce_time: None,
                                    recovery_progress_pct: None,
                                };
                                (peers, interval, rep)
                            }
                        }
                    }
                    "http" | "https" => {
                        let mut target_url = tracker_url.clone();
                        if tracker_url.port().is_none() {
                            if let Some(host) = tracker_url.host_str() {
                                if host.parse::<std::net::IpAddr>().is_err() {
                                    match synapse_tracker::resolve_bep34_txt(host, None).await {
                                        synapse_tracker::Bep34TxtResult::OptOut => {
                                            let rep = TrackerReport {
                                                url: tracker_url.to_string(),
                                                status: "Blocked".into(),
                                                seeders: 0,
                                                leechers: 0,
                                                next_announce_in: 3600,
                                                failure_reason: Some(
                                                    "Tracker domain opted out via BEP 34 DNS TXT record"
                                                        .into(),
                                                ),
                                                is_circuit_broken: false,
                                                cb_state: None,
                                                last_announce_time: None,
                                                recovery_progress_pct: None,
                                            };
                                            return (peers, interval, rep);
                                        }
                                        synapse_tracker::Bep34TxtResult::Preferences(prefs) => {
                                            if let Some(pref) = prefs.into_iter().find(|p| {
                                                p.proto == synapse_tracker::TrackerProto::Tcp
                                            }) {
                                                let _ = target_url.set_port(Some(pref.port));
                                            }
                                        }
                                        synapse_tracker::Bep34TxtResult::None => {}
                                    }
                                }
                            }
                        }
                        let announce_fut = synapse_tracker::http::announce(&target_url, &req_clone);
                        match tokio::time::timeout(Duration::from_secs(10), announce_fut).await {
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
                                interval = Some(resp.interval.max(resp.min_interval.unwrap_or(0)));
                                if let Some(ref w) = resp.warning {
                                    warn!("[{}] tracker {} warning: {}", label_c, safe_url, w);
                                }
                                if let Some(ref id) = resp.tracker_id {
                                    let mut ids = tracker_ids.lock();
                                    if ids.len() < 4096 {
                                        ids.insert(
                                            (req_clone.info_hash, url_str.clone()),
                                            id.clone(),
                                        );
                                    }
                                }
                                if let Some(ip) = resp.external_ip {
                                    let mut votes = external_ip_votes.lock();
                                    if votes.len() < 64 || votes.contains_key(&url_str) {
                                        votes.insert(url_str.clone(), ip);
                                    }
                                }
                                let tracker_source =
                                    resp.remote_addr.map(|a| a.ip()).or_else(|| {
                                        tracker_url.host_str().and_then(|h| {
                                            h.trim_start_matches('[')
                                                .trim_end_matches(']')
                                                .parse::<IpAddr>()
                                                .ok()
                                        })
                                    });
                                peers.extend(filter_tracker_peers(resp.peers, tracker_source));
                                let rep = TrackerReport {
                                    url: tracker_url.to_string(),
                                    status: "Announced".into(),
                                    seeders: resp.seeders,
                                    leechers: resp.leechers,
                                    next_announce_in: resp.interval as i64,
                                    failure_reason: None,
                                    is_circuit_broken: false,
                                    cb_state: None,
                                    last_announce_time: None,
                                    recovery_progress_pct: None,
                                };
                                (peers, interval, rep)
                            }
                            Ok(Err(e)) => {
                                tracker_breaker.record_failure(&url_str);
                                warn!("[{}] HTTP/HTTPS tracker {} error: {}", label_c, safe_url, e);
                                let rep = TrackerReport {
                                    url: tracker_url.to_string(),
                                    status: "Error".into(),
                                    seeders: 0,
                                    leechers: 0,
                                    next_announce_in: 300,
                                    failure_reason: Some(e.to_string()),
                                    is_circuit_broken: false,
                                    cb_state: None,
                                    last_announce_time: None,
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
                                    failure_reason: Some(
                                        "HTTP announce timed out after 10s".into(),
                                    ),
                                    is_circuit_broken: false,
                                    cb_state: None,
                                    last_announce_time: None,
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
                            failure_reason: Some(format!(
                                "Unsupported tracker scheme: {}",
                                tracker_url.scheme()
                            )),
                            is_circuit_broken: false,
                            cb_state: None,
                            last_announce_time: None,
                            recovery_progress_pct: None,
                        };
                        (peers, interval, rep)
                    }
                };
                (peers_res, interval_res, report)
            }
        };

        // BEP 12: trackers within a tier are interchangeable, so they're raced concurrently;
        // the next tier is only tried if every tracker in this one failed, preserving tier
        // failover semantics without serializing the (common) case of several trackers in
        // the same tier.
        for tier in tiers {
            let results = futures::future::join_all(tier.into_iter().map(&announce_one)).await;
            let mut tier_succeeded = false;
            for (peer_list, intv, rep) in results {
                let ok = rep.status == "Announced";
                for p in peer_list {
                    discovered_peers.insert(p);
                }
                if let Some(i) = intv {
                    if i > 0 {
                        min_interval = Some(min_interval.map_or(i, |curr: u32| curr.min(i)));
                    }
                }
                reports.push(rep);
                if ok {
                    tier_succeeded = true;
                }
            }
            if tier_succeeded {
                break;
            }
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
            let enc_mode = self
                .settings
                .as_ref()
                .map(|s| s.read().encryption_mode())
                .unwrap_or(synapse_wire::EncryptionMode::PreferEncrypted);
            let utp_mgr = self.utp_manager.read().clone();

            // See the matching comment in `dial_step` below: this must comfortably outlast
            // both the `PreferEncrypted` MSE attempt AND its plaintext fallback (each up to
            // `HANDSHAKE_TIMEOUT`), or the fallback never gets a chance to run.
            let dial_timeout = 2 * HANDSHAKE_TIMEOUT + Duration::from_secs(5);

            tokio::spawn(async move {
                match tokio::time::timeout(
                    dial_timeout,
                    connect_with_options(
                        peer_addr, our_id, info_hash, is_private, tx, enc_mode, utp_mgr,
                    ),
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

/// Peer discovery origin for candidate peer telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PeerDiscoverySource {
    Tracker,
    Dht,
    Pex,
    Lsd,
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
    discovered_from_tracker: u64,
    discovered_from_dht: u64,
    discovered_from_pex: u64,
    discovered_from_lsd: u64,
    initial_downloaded: u64,
    missing_wanted_bytes: Arc<AtomicU64>,
}

/// Returns true when any file covered by `piece` has priority > 0 (ignoring BEP 47 padding).
pub fn is_piece_wanted(info: &Info, file_priorities: &[u8], piece: u32) -> bool {
    if file_priorities.iter().all(|&p| p > 0) {
        return true;
    }
    info.block_locations(piece, 0, info.piece_len(piece))
        .iter()
        .any(|loc| {
            if synapse_meta::is_padding_file(&info.files[loc.file].path, None) {
                false
            } else {
                file_priorities.get(loc.file).copied().unwrap_or(4) > 0
            }
        })
}

/// Computes the total missing bytes across all wanted files/pieces.
/// A piece is considered wanted if any file it covers has priority > 0.
pub fn compute_missing_wanted_bytes(
    info: &Info,
    file_priorities: &[u8],
    have: Option<&synapse_picker::RoaringBitfield>,
) -> u64 {
    // Nothing skipped: every missing piece counts, no per-piece file lookup needed.
    let all_wanted = file_priorities.iter().all(|&p| p > 0);
    let mut missing = 0u64;
    for piece in 0..info.pieces() {
        if let Some(bf) = have {
            if bf.has(piece as usize) {
                continue;
            }
        }
        if all_wanted || is_piece_wanted(info, file_priorities, piece) {
            missing += info.piece_len(piece) as u64;
        }
    }
    missing
}

/// Per-torrent state the scheduler needs to compute the `downloaded`/`left` counters it announces.
pub struct AnnounceDetails {
    pub file_priorities: Arc<RwLock<Vec<u8>>>,
    pub compressed_bitfield: Arc<RwLock<Option<synapse_picker::RoaringBitfield>>>,
    /// `downloaded_bytes` already present when the torrent was registered (the session baseline).
    pub initial_downloaded: u64,
    /// Incrementally maintained missing bytes across wanted files for O(1) announce `left` lookup.
    pub missing_wanted_bytes: Arc<AtomicU64>,
}

/// The `(downloaded, left)` pair sent to trackers.
///
/// `downloaded` is only what this session pulled from the swarm: bytes already on disk when the
/// torrent was added (cross-seeding, resume) are the baseline and are never reported. `left` is 0
/// for a seeding/complete torrent, otherwise the bytes still missing from *wanted* files.
pub fn announce_transfer_counters(
    stats: &SwarmStats,
    initial_downloaded: u64,
    info: &Info,
    file_priorities: &[u8],
    have: Option<&synapse_picker::RoaringBitfield>,
) -> (u64, u64) {
    let downloaded = stats.downloaded_bytes.saturating_sub(initial_downloaded);
    let left = if stats.state == crate::swarm::SwarmState::Seeding || stats.progress >= 1.0 {
        0
    } else {
        compute_missing_wanted_bytes(info, file_priorities, have)
    };
    (downloaded, left)
}

/// Callback type for dynamically waking dormant swarms and obtaining their peer event channel.
pub type PeerEventRouter = Arc<dyn Fn(&[u8; 20]) -> Option<mpsc::Sender<PeerEvent>> + Send + Sync>;

struct ActiveAnnouncePermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    active: Arc<AtomicUsize>,
    notify: Arc<Notify>,
}

impl Drop for ActiveAnnouncePermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
        self.notify.notify_one();
    }
}

/// Centralized Announce Scheduler for high-scale swarm management (10,000–50,000+ torrents).
///
/// Replaces individual per-torrent ticker loops with a single unified event scheduler
/// that enforces tracker intervals, bounds concurrent announces, applies BEP-compliant jitter,
/// and executes exponential backoff on tracker failures.
pub struct AnnounceScheduler {
    announcer: Arc<Announcer>,
    queue: Mutex<BinaryHeap<ScheduledJob>>,
    swarms: DashMap<[u8; 20], SwarmMeta>,
    dial_ready: Mutex<VecDeque<[u8; 20]>>,
    in_dial_ready: DashSet<[u8; 20]>,
    downloading_swarms: DashSet<[u8; 20]>,
    global_active_dials: Arc<AtomicUsize>,
    announce_notify: Arc<Notify>,
    dialer_notify: Arc<Notify>,
    shutdown: AtomicBool,
    concurrency_limit: Arc<Semaphore>,
    semaphore_capacity: AtomicUsize,
    active_announces: Arc<AtomicUsize>,
    default_interval: Duration,
    max_startup_jitter: Duration,
    peer_router: RwLock<Option<PeerEventRouter>>,
    settings: RwLock<Option<Arc<RwLock<crate::settings::DynamicSessionSettings>>>>,
    ip_filter: RwLock<Option<Arc<RwLock<crate::ipfilter::IpFilter>>>>,
    ban_list: RwLock<Option<Arc<crate::banlist::BanList>>>,
    utp_manager: RwLock<Option<Arc<crate::utp::UtpSocketManager>>>,
}

impl AnnounceScheduler {
    pub fn new(
        announcer: Arc<Announcer>,
        max_concurrent_announces: usize,
        default_interval: Duration,
        max_startup_jitter: Duration,
    ) -> Arc<Self> {
        let initial_cap = max_concurrent_announces.max(1);
        Arc::new(Self {
            announcer,
            queue: Mutex::new(BinaryHeap::new()),
            swarms: DashMap::new(),
            dial_ready: Mutex::new(VecDeque::new()),
            in_dial_ready: DashSet::new(),
            downloading_swarms: DashSet::new(),
            global_active_dials: Arc::new(AtomicUsize::new(0)),
            announce_notify: Arc::new(Notify::new()),
            dialer_notify: Arc::new(Notify::new()),
            shutdown: AtomicBool::new(false),
            concurrency_limit: Arc::new(Semaphore::new(initial_cap)),
            semaphore_capacity: AtomicUsize::new(initial_cap),
            active_announces: Arc::new(AtomicUsize::new(0)),
            default_interval,
            max_startup_jitter,
            peer_router: RwLock::new(None),
            settings: RwLock::new(None),
            ip_filter: RwLock::new(None),
            ban_list: RwLock::new(None),
            utp_manager: RwLock::new(None),
        })
    }

    /// Sets the dynamic peer event router used to awaken dormant Warm/Cold swarms when tracker peers are found.
    pub fn set_peer_router(&self, router: PeerEventRouter) {
        *self.peer_router.write() = Some(router);
    }

    pub fn set_utp_manager(&self, utp_manager: Arc<crate::utp::UtpSocketManager>) {
        *self.utp_manager.write() = Some(utp_manager.clone());
        self.announcer.set_utp_manager(utp_manager);
    }

    pub fn set_alert_sender(&self, sender: tokio::sync::broadcast::Sender<crate::alert::Alert>) {
        self.announcer.set_alert_sender(sender);
    }

    pub fn set_alert_category_mask(&self, mask: Arc<AtomicU32>) {
        self.announcer.set_alert_category_mask(mask);
    }

    /// Sets the live session settings used to bound outbound dial targets by the
    /// configured `max_peers_per_torrent` / `max_global_peers` caps -- see `dial_step`.
    pub fn set_settings(&self, settings: Arc<RwLock<crate::settings::DynamicSessionSettings>>) {
        *self.settings.write() = Some(settings);
    }

    /// Sets the shared IP filter used to skip blocklisted candidate peers before ever
    /// dialing them -- see `dial_step`.
    pub fn set_ban_list(&self, ban_list: Arc<crate::banlist::BanList>) {
        *self.ban_list.write() = Some(ban_list);
    }

    pub fn set_ip_filter(&self, ip_filter: Arc<RwLock<crate::ipfilter::IpFilter>>) {
        *self.ip_filter.write() = Some(ip_filter);
    }

    /// Returns a reference to the inner Announcer instance.
    pub fn announcer(&self) -> &Arc<Announcer> {
        &self.announcer
    }

    /// Registers a new or restored torrent in the centralized announce queue with priority and bitfield details.
    /// Downloading swarms announce immediately; seeding swarms apply startup jitter.
    pub fn register_with_details(
        &self,
        info_hash: [u8; 20],
        info: Arc<Info>,
        stats: Arc<RwLock<SwarmStats>>,
        events_tx: mpsc::Sender<PeerEvent>,
        is_downloading: bool,
        details: AnnounceDetails,
    ) {
        let AnnounceDetails {
            file_priorities: _,
            compressed_bitfield: _,
            initial_downloaded,
            missing_wanted_bytes,
        } = details;
        let next_announce_at = if is_downloading {
            Instant::now()
        } else {
            let jitter_secs = if self.max_startup_jitter.as_secs() > 0 {
                rand::Rng::gen_range(
                    &mut rand::thread_rng(),
                    1..=self.max_startup_jitter.as_secs(),
                )
            } else {
                0
            };
            Instant::now() + Duration::from_secs(jitter_secs)
        };

        let candidate_urls = self.announcer.trackers_for(&info);
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
                status: if is_downloading {
                    "Updating".into()
                } else {
                    "Ready".into()
                },
                seeders: 0,
                leechers: 0,
                next_announce_in: initial_remaining,
                failure_reason: None,
                is_circuit_broken: false,
                cb_state: None,
                recovery_progress_pct: None,
                last_announce_time: None,
            })
            .collect();

        self.swarms.insert(
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
                discovered_from_tracker: 0,
                discovered_from_dht: 0,
                discovered_from_pex: 0,
                discovered_from_lsd: 0,
                initial_downloaded,
                missing_wanted_bytes,
            },
        );
        if is_downloading {
            self.downloading_swarms.insert(info_hash);
        } else {
            self.downloading_swarms.remove(&info_hash);
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
            self.announce_notify.notify_one();
        }
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
        let initial_downloaded = stats.read().downloaded_bytes;
        let initial_missing = compute_missing_wanted_bytes(&info, &[], None);
        self.register_with_details(
            info_hash,
            info,
            stats,
            events_tx,
            is_downloading,
            AnnounceDetails {
                file_priorities: Arc::new(RwLock::new(Vec::new())),
                compressed_bitfield: Arc::new(RwLock::new(None)),
                initial_downloaded,
                missing_wanted_bytes: Arc::new(AtomicU64::new(initial_missing)),
            },
        );
    }

    fn enqueue_dial_ready(&self, info_hash: [u8; 20]) {
        if self.in_dial_ready.insert(info_hash) {
            self.dial_ready.lock().push_back(info_hash);
        }
    }

    /// Enqueues newly discovered peers from Trackers, DHT, PEX, or LSD into the swarm's candidate pool,
    /// tracking discovery metrics by origin subsystem.
    pub fn add_candidate_peers_with_source(
        &self,
        info_hash: &[u8; 20],
        peers: impl IntoIterator<Item = SocketAddr>,
        source: PeerDiscoverySource,
    ) {
        let local_addr = self
            .announcer
            .external_ip()
            .or_else(|| {
                self.announcer
                    .settings
                    .as_ref()
                    .and_then(|s| s.read().announce_ip)
            })
            .map(|ip| SocketAddr::new(ip, *self.announcer.listen_port.read()));

        let has_candidates = if let Some(mut meta) = self.swarms.get_mut(info_hash) {
            let mut existing: HashSet<SocketAddr> = meta.candidate_peers.iter().copied().collect();
            let mut new_peers = Vec::new();
            for addr in peers {
                let ip = addr.ip();
                let invalid_ip = ip.is_unspecified()
                    || ip.is_multicast()
                    || match ip {
                        std::net::IpAddr::V4(v4) => v4.is_broadcast() || v4.octets()[0] == 0,
                        std::net::IpAddr::V6(_) => false,
                    };
                if addr.port() != 0
                    && !invalid_ip
                    && !existing.contains(&addr)
                    && !meta.active_dials.contains(&addr)
                    && self.announcer.circuit_breaker.can_connect(&addr)
                    && meta.candidate_peers.len() + new_peers.len() < 2000
                {
                    existing.insert(addr);
                    new_peers.push(addr);
                    match source {
                        PeerDiscoverySource::Tracker => meta.discovered_from_tracker += 1,
                        PeerDiscoverySource::Dht => meta.discovered_from_dht += 1,
                        PeerDiscoverySource::Pex => meta.discovered_from_pex += 1,
                        PeerDiscoverySource::Lsd => meta.discovered_from_lsd += 1,
                    }
                }
            }
            // BEP 40: Order dial queue by Canonical Peer Priority score
            if let Some(local) = local_addr {
                new_peers.sort_by_key(|&a| {
                    std::cmp::Reverse(synapse_wire::bep40::bep40_peer_priority(local, a))
                });
            } else {
                new_peers.sort_by_key(|&a| {
                    std::cmp::Reverse(synapse_wire::bep40::canonical_peer_score(a))
                });
            }
            for addr in new_peers {
                meta.candidate_peers.push_back(addr);
            }
            !meta.candidate_peers.is_empty()
        } else {
            false
        };
        if has_candidates {
            self.enqueue_dial_ready(*info_hash);
        }
    }

    /// Enqueues newly discovered peers into the swarm's candidate pool, attributing them to Tracker announces.
    pub fn add_candidate_peers(
        &self,
        info_hash: &[u8; 20],
        peers: impl IntoIterator<Item = SocketAddr>,
    ) {
        self.add_candidate_peers_with_source(info_hash, peers, PeerDiscoverySource::Tracker);
    }

    /// Returns the number of candidate peers currently queued for dialing.
    pub fn candidate_peers_count(&self, info_hash: &[u8; 20]) -> usize {
        self.swarms
            .get(info_hash)
            .map(|m| m.candidate_peers.len())
            .unwrap_or(0)
    }

    /// Returns the number of active dials currently in flight for this swarm.
    pub fn active_dials_count(&self, info_hash: &[u8; 20]) -> usize {
        self.swarms
            .get(info_hash)
            .map(|m| m.active_dials.len())
            .unwrap_or(0)
    }

    /// Returns the candidate pool size, active dials count, and discovery attribution counters
    /// (candidate_peers, active_dials, from_tracker, from_dht, from_pex, from_lsd).
    pub fn discovery_breakdown(&self, info_hash: &[u8; 20]) -> (usize, usize, u64, u64, u64, u64) {
        self.swarms
            .get(info_hash)
            .map(|m| {
                (
                    m.candidate_peers.len(),
                    m.active_dials.len(),
                    m.discovered_from_tracker,
                    m.discovered_from_dht,
                    m.discovered_from_pex,
                    m.discovered_from_lsd,
                )
            })
            .unwrap_or((0, 0, 0, 0, 0, 0))
    }

    /// Unregisters a removed torrent from future announces.
    pub fn unregister(&self, info_hash: &[u8; 20]) {
        self.swarms.remove(info_hash);
        self.downloading_swarms.remove(info_hash);
        self.in_dial_ready.remove(info_hash);
    }

    /// Marks an already-registered swarm as downloading for O(downloading) starvation checks.
    pub fn mark_downloading(&self, info_hash: &[u8; 20]) {
        if self.swarms.contains_key(info_hash) {
            self.downloading_swarms.insert(*info_hash);
        }
    }

    /// Marks a swarm as no longer downloading for O(downloading) starvation checks.
    pub fn mark_seeding(&self, info_hash: &[u8; 20]) {
        self.downloading_swarms.remove(info_hash);
    }

    /// Wakes the scheduler to send an immediate `Event::Completed` announce for a finished download.
    pub fn notify_completed(&self, info_hash: &[u8; 20]) {
        self.downloading_swarms.remove(info_hash);
        self.schedule_now(info_hash, false, Event::Completed);
    }

    /// Announces to the torrent's trackers right away, outside the normal schedule.
    /// Returns false if the torrent isn't registered with the scheduler (stopped, or not
    /// started yet), in which case there is nothing to announce.
    pub fn reannounce(&self, info_hash: &[u8; 20]) -> bool {
        let is_downloading = match self.swarms.get(info_hash) {
            Some(m) => m.stats.read().state == crate::swarm::SwarmState::Downloading,
            None => return false,
        };
        self.schedule_now(info_hash, is_downloading, Event::None)
    }

    /// Queues an immediate announce and marks it as the swarm's current schedule, so the
    /// regular job that was already queued for later is recognised as superseded (see
    /// `dispatch_batch`) instead of running a second announce chain.
    fn schedule_now(&self, info_hash: &[u8; 20], is_downloading: bool, event: Event) -> bool {
        let now = Instant::now();
        {
            match self.swarms.get_mut(info_hash) {
                Some(mut m) => m.next_announce_at = now,
                None => return false,
            }
        }
        if is_downloading {
            self.downloading_swarms.insert(*info_hash);
        } else {
            self.downloading_swarms.remove(info_hash);
        }
        self.queue.lock().push(ScheduledJob {
            info_hash: *info_hash,
            next_announce_at: now,
            is_downloading,
            event,
        });
        self.announce_notify.notify_one();
        true
    }

    /// Wakes the scheduler to immediately announce a resumed torrent.
    pub fn notify_resumed(&self, info_hash: &[u8; 20]) {
        self.schedule_now(info_hash, true, Event::Started);
    }

    /// Forgets the status reports of trackers a torrent no longer uses, so a replaced tracker
    /// doesn't linger in the tracker list.
    pub fn drop_stale_tracker_reports(&self, info_hash: &[u8; 20], keep: &[url::Url]) {
        if let Some(mut m) = self.swarms.get_mut(info_hash) {
            m.tracker_reports
                .retain(|r| keep.iter().any(|u| u.as_str() == r.url));
        }
    }

    pub fn active_swarms_count(&self) -> usize {
        self.swarms.len()
    }

    pub fn pending_announces(&self) -> usize {
        self.queue.lock().len()
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.announce_notify.notify_waiters();
        self.dialer_notify.notify_waiters();
    }

    /// Best-effort `event=stopped` announce for all active swarms during graceful shutdown.
    pub async fn announce_stopped_all(&self) {
        let targets: Vec<(Arc<Info>, u64, u64, u64)> = self
            .swarms
            .iter()
            .filter_map(|entry| {
                let m = entry.value();
                let s = m.stats.read();
                if s.state == crate::SwarmState::Stopped {
                    return None;
                }
                let dl = s.downloaded_bytes.saturating_sub(m.initial_downloaded);
                let left = if s.state == crate::SwarmState::Seeding || s.progress >= 1.0 {
                    0
                } else {
                    m.missing_wanted_bytes.load(Ordering::Relaxed)
                };
                Some((m.info.clone(), dl, left, s.uploaded_bytes))
            })
            .collect();
        if targets.is_empty() {
            return;
        }
        let sem = Arc::new(Semaphore::new(16));
        let mut futs = Vec::with_capacity(targets.len());
        for (info, downloaded, left, uploaded) in targets {
            let announcer = self.announcer.clone();
            let sem = sem.clone();
            futs.push(async move {
                let Ok(_permit) = sem.acquire().await else {
                    return;
                };
                let _ = announcer
                    .announce(&info, downloaded, left, uploaded, Event::Stopped)
                    .await;
            });
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), futures::future::join_all(futs)).await;
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

                let now = Instant::now();
                let wait_duration = match next_due {
                    Some(t) => {
                        if t <= now {
                            if self.concurrency_limit.available_permits() == 0
                                || self.active_announces.load(Ordering::Acquire)
                                    >= self.effective_concurrency_limit()
                            {
                                // Concurrency cap saturated: wait for a permit release notification
                                // instead of busy-spinning on due queue items.
                                Duration::from_millis(50)
                            } else {
                                Duration::from_millis(0)
                            }
                        } else {
                            t - now
                        }
                    }
                    None => Duration::from_secs(30),
                };

                if !wait_duration.is_zero() {
                    tokio::select! {
                        _ = tokio::time::sleep(wait_duration) => {}
                        _ = self.announce_notify.notified() => {}
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
                _ = self.dialer_notify.notified() => {}
            }
            if self.shutdown.load(Ordering::Relaxed) {
                break;
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
        let ban_list = self.ban_list.read().clone();

        const MAX_GLOBAL_CONCURRENT_DIALS: usize = 128;
        const MAX_NEW_DIALS_PER_STEP: usize = 30;
        const MAX_CONCURRENT_DIALS_PER_SWARM: usize = 16;

        let mut to_dial = Vec::new();
        let mut global_active = self.global_active_dials.load(Ordering::Relaxed);
        let mut deferred_ready = Vec::new();

        loop {
            if global_active >= MAX_GLOBAL_CONCURRENT_DIALS
                || to_dial.len() >= MAX_NEW_DIALS_PER_STEP
            {
                break;
            }
            let next_hash = { self.dial_ready.lock().pop_front() };
            let Some(info_hash) = next_hash else {
                break;
            };
            self.in_dial_ready.remove(&info_hash);

            let Some(mut meta) = self.swarms.get_mut(&info_hash) else {
                continue;
            };
            let (state, connected) = {
                let s = meta.stats.read();
                (s.state.clone(), s.peers_connected)
            };
            let target_peers = match state {
                crate::swarm::SwarmState::Downloading => max_per_torrent.min(40),
                crate::swarm::SwarmState::Seeding => max_per_torrent.min(30),
                _ => 0,
            };
            if target_peers == 0 || connected >= target_peers {
                continue;
            }
            let active_count = meta.active_dials.len();
            if active_count >= MAX_CONCURRENT_DIALS_PER_SWARM {
                if !meta.candidate_peers.is_empty() {
                    deferred_ready.push(info_hash);
                }
                continue;
            }

            let remaining_needed = target_peers.saturating_sub(connected + active_count);
            let dial_budget = remaining_needed.min(MAX_CONCURRENT_DIALS_PER_SWARM - active_count);
            let mut count = 0;
            while count < dial_budget
                && global_active < MAX_GLOBAL_CONCURRENT_DIALS
                && to_dial.len() < MAX_NEW_DIALS_PER_STEP
            {
                let Some(addr) = meta.candidate_peers.pop_front() else {
                    break;
                };
                if meta.active_dials.contains(&addr)
                    || !self.announcer.circuit_breaker.can_connect(&addr)
                {
                    continue;
                }
                if let Some(ref filter) = ip_filter {
                    if filter.read().is_blocked(addr.ip()) {
                        continue;
                    }
                }
                if ban_list.as_ref().is_some_and(|b| b.is_banned(addr.ip())) {
                    continue;
                }
                if addr.port() == 0 {
                    continue;
                }
                meta.active_dials.insert(addr);
                to_dial.push((info_hash, meta.info.clone(), addr, meta.events_tx.clone()));
                count += 1;
                global_active += 1;
            }
            if !meta.candidate_peers.is_empty() && connected + count < target_peers {
                deferred_ready.push(info_hash);
            }
        }
        for hash in deferred_ready {
            if self.in_dial_ready.insert(hash) {
                self.dial_ready.lock().push_back(hash);
            }
        }

        // Fast re-announce on peer starvation (O(downloading) rather than scanning all swarms).
        let dl_hashes: Vec<[u8; 20]> = self.downloading_swarms.iter().map(|h| *h).collect();
        let mut starved_swarms = Vec::new();
        let mut ready_dl = Vec::new();
        let mut stale_dl = Vec::new();
        let now = Instant::now();
        for info_hash in dl_hashes {
            let Some(mut meta) = self.swarms.get_mut(&info_hash) else {
                stale_dl.push(info_hash);
                continue;
            };
            let (state, connected, peers_sending) = {
                let s = meta.stats.read();
                (s.state.clone(), s.peers_connected, s.peers_sending)
            };
            if state != crate::swarm::SwarmState::Downloading {
                stale_dl.push(info_hash);
                continue;
            }
            let target_peers = max_per_torrent.min(40);
            let is_starved = meta.candidate_peers.is_empty()
                && meta.active_dials.is_empty()
                && (connected < 8 || (connected < target_peers && peers_sending == 0));
            if is_starved && meta.next_announce_at > now + Duration::from_secs(20) {
                meta.next_announce_at = now + Duration::from_secs(15);
                starved_swarms.push((info_hash, meta.next_announce_at));
            } else if !meta.candidate_peers.is_empty() && connected < target_peers {
                ready_dl.push(info_hash);
            }
        }
        for hash in ready_dl {
            self.enqueue_dial_ready(hash);
        }
        for h in stale_dl {
            self.downloading_swarms.remove(&h);
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

        struct ActiveDialGuard {
            scheduler: Arc<AnnounceScheduler>,
            info_hash: [u8; 20],
            addr: SocketAddr,
        }
        impl Drop for ActiveDialGuard {
            fn drop(&mut self) {
                self.scheduler
                    .global_active_dials
                    .fetch_sub(1, Ordering::Relaxed);
                if let Some(mut m) = self.scheduler.swarms.get_mut(&self.info_hash) {
                    m.active_dials.remove(&self.addr);
                }
            }
        }

        for (info_hash, info, addr, fallback_tx) in to_dial {
            let scheduler = self.clone();
            let our_id = self.announcer.our_peer_id;
            let cb = self.announcer.circuit_breaker.clone();
            let events_tx = if let Some(ref router) = *self.peer_router.read() {
                router(&info_hash).unwrap_or(fallback_tx)
            } else {
                fallback_tx
            };
            let enc_mode = self
                .settings
                .read()
                .as_ref()
                .map(|s| s.read().encryption_mode())
                .unwrap_or(synapse_wire::EncryptionMode::PreferEncrypted);
            let utp_mgr = self.utp_manager.read().clone();

            // `PreferEncrypted` can run the full MSE negotiation (up to `HANDSHAKE_TIMEOUT`)
            // against a peer that never answers it (many real peers go silent rather than
            // reset on unrecognized bytes), THEN fall back to a fresh plaintext connection
            // and handshake (up to another `HANDSHAKE_TIMEOUT`). This outer timeout must
            // comfortably outlast both phases plus the fallback's own TCP connect, or it
            // fires first and kills the task before the plaintext fallback ever gets to run
            // - silently turning every slow-to-reject non-MSE peer into a lost connection
            // (and, at scale, most of a swarm's effective throughput) instead of a fallback.
            let dial_timeout = 2 * HANDSHAKE_TIMEOUT + Duration::from_secs(5);
            self.global_active_dials.fetch_add(1, Ordering::Relaxed);

            tokio::spawn(async move {
                let _dial_guard = ActiveDialGuard {
                    scheduler,
                    info_hash,
                    addr,
                };
                match tokio::time::timeout(
                    dial_timeout,
                    connect_with_options(
                        addr,
                        our_id,
                        info.hash,
                        info.private,
                        events_tx,
                        enc_mode,
                        utp_mgr,
                    ),
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
            });
        }
    }

    fn effective_concurrency_limit(&self) -> usize {
        self.settings
            .read()
            .as_ref()
            .map(|s| s.read().max_concurrent_tracker_announces.max(1))
            .unwrap_or_else(|| self.semaphore_capacity.load(Ordering::Acquire))
    }

    async fn dispatch_batch(self: &Arc<Self>) {
        let now = Instant::now();
        let mut due_jobs = Vec::new();

        let effective_limit = self.effective_concurrency_limit();

        let mut cur_cap = self.semaphore_capacity.load(Ordering::Acquire);
        while effective_limit > cur_cap {
            match self.semaphore_capacity.compare_exchange_weak(
                cur_cap,
                effective_limit,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.concurrency_limit
                        .add_permits(effective_limit - cur_cap);
                    break;
                }
                Err(actual) => cur_cap = actual,
            }
        }

        let batch_limit = effective_limit.min(32);
        {
            let mut q = self.queue.lock();
            while due_jobs.len() < batch_limit {
                if q.peek().is_none_or(|job| job.next_announce_at > now) {
                    break;
                }
                if self.active_announces.load(Ordering::Acquire) >= effective_limit {
                    break;
                }
                let Ok(permit) = self.concurrency_limit.clone().try_acquire_owned() else {
                    break;
                };
                self.active_announces.fetch_add(1, Ordering::AcqRel);
                due_jobs.push((
                    q.pop().unwrap(),
                    ActiveAnnouncePermit {
                        _permit: permit,
                        active: self.active_announces.clone(),
                        notify: self.announce_notify.clone(),
                    },
                ));
            }
        }

        for (job, permit) in due_jobs {
            let meta_opt = self.swarms.get(&job.info_hash).map(|m| {
                (
                    m.info.clone(),
                    m.stats.clone(),
                    m.consecutive_failures,
                    m.next_announce_at,
                    m.initial_downloaded,
                    m.missing_wanted_bytes.clone(),
                )
            });

            let Some((
                info,
                stats,
                failures,
                scheduled_for,
                initial_downloaded,
                missing_wanted_bytes,
            )) = meta_opt
            else {
                drop(permit);
                continue; // Unregistered torrent
            };

            // A regular periodic job whose time is well before the swarm's current schedule was
            // superseded (an announce already ran after it was queued); running it would start a
            // second, parallel announce chain for the same torrent. Explicit lifecycle events
            // (`Started`, `Completed`, `Stopped`) must never be dropped as superseded.
            if job.event == Event::None
                && scheduled_for > job.next_announce_at + Duration::from_secs(1)
            {
                drop(permit);
                continue;
            }

            let (state, dl, left, ul) = {
                let s = stats.read();
                let dl = s.downloaded_bytes.saturating_sub(initial_downloaded);
                let left = if s.state == crate::swarm::SwarmState::Seeding || s.progress >= 1.0 {
                    0
                } else {
                    missing_wanted_bytes.load(Ordering::Relaxed)
                };
                (s.state.clone(), dl, left, s.uploaded_bytes)
            };

            if matches!(
                state,
                crate::swarm::SwarmState::Stopped | crate::swarm::SwarmState::Error(_)
            ) {
                self.downloading_swarms.remove(&job.info_hash);
                drop(permit);
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

            let scheduler = self.clone();
            let announcer = self.announcer.clone();
            let is_dl = state == crate::swarm::SwarmState::Downloading;
            if is_dl {
                self.downloading_swarms.insert(job.info_hash);
            } else {
                self.downloading_swarms.remove(&job.info_hash);
            }

            tokio::spawn(async move {
                let (peers, tracker_interval, reports) = announcer
                    .announce_with_interval(&info, dl, left, ul, job.event)
                    .await;
                drop(permit);

                let peer_count = peers.len();
                scheduler.add_candidate_peers(&job.info_hash, peers);

                let all_cb = !reports.is_empty() && reports.iter().all(|r| r.is_circuit_broken);
                let any_succeeded = reports.iter().any(|r| r.status == "Announced");
                let (delay_secs, new_failures) = if all_cb && peer_count == 0 {
                    // Stagger retry during circuit breaker cooling/ramp-up: 5 to 15 seconds randomized jitter
                    let stagger = rand::Rng::gen_range(&mut rand::thread_rng(), 5..=15);
                    (stagger as u64, failures)
                } else if any_succeeded {
                    let base = if tracker_interval > 0 {
                        tracker_interval
                    } else {
                        scheduler.default_interval.as_secs() as u32
                    }
                    .clamp(60, 3600);

                    // BEP 3 recommended +/- 10% randomized jitter
                    let jitter_range = (base as f64 * 0.1) as i64;
                    let jitter = if jitter_range > 0 {
                        rand::Rng::gen_range(&mut rand::thread_rng(), -jitter_range..=jitter_range)
                    } else {
                        0
                    };
                    ((base as i64 + jitter).max(60) as u64, 0)
                } else {
                    // Exponential backoff on failed or unreachable tracker: 30s, 60s, 120s...
                    let backoff = (30 * (1 << failures.min(5))).min(1800);
                    (backoff as u64, failures + 1)
                };

                let finished_at = Instant::now();
                let next_announce_at = finished_at + Duration::from_secs(delay_secs);

                let preempted = {
                    if let Some(mut m) = scheduler.swarms.get_mut(&job.info_hash) {
                        m.consecutive_failures = new_failures;
                        let preempted = m.next_announce_at > job.next_announce_at
                            && m.next_announce_at <= finished_at;
                        if !preempted {
                            m.next_announce_at = next_announce_at;
                        }
                        let announced_at = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .ok();
                        for mut rep in reports {
                            rep.next_announce_in = delay_secs as i64;
                            if rep.last_announce_time.is_none() {
                                rep.last_announce_time = announced_at;
                            }
                            if let Some(existing) =
                                m.tracker_reports.iter_mut().find(|t| t.url == rep.url)
                            {
                                *existing = rep;
                            } else {
                                m.tracker_reports.push(rep);
                            }
                        }
                        preempted
                    } else {
                        false
                    }
                };

                if !preempted {
                    let mut q = scheduler.queue.lock();
                    q.push(ScheduledJob {
                        info_hash: job.info_hash,
                        next_announce_at,
                        is_downloading: is_dl,
                        event: Event::None,
                    });
                }

                scheduler.announce_notify.notify_one();
            });
        }
    }

    /// Returns the latest live tracker status reports for the given info hash,
    /// with dynamically computed countdown seconds until the next announce.
    pub fn get_tracker_reports(&self, info_hash: &[u8; 20]) -> Vec<TrackerReport> {
        if let Some(meta) = self.swarms.get(info_hash) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn bep12_tier_failover_stops_once_tier_succeeds() {
        use std::collections::BTreeMap;
        use synapse_bencode::BEncode;

        // Bind then drop to obtain an unused closed local port for Tier 0 failure.
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = closed.local_addr().unwrap();
        drop(closed);

        // Tier 1 live mock HTTP tracker returning a valid bencoded announce reply.
        let tier1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tier1_addr = tier1.local_addr().unwrap();
        let tier1_hits = Arc::new(AtomicUsize::new(0));
        let t1_hits_bg = tier1_hits.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = tier1.accept().await {
                t1_hits_bg.fetch_add(1, Ordering::Relaxed);
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body = b"d8:intervali600e5:peers6:\xcb\x00\x71\x05\x1a\xe1e";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.write_all(body).await;
            }
        });

        // Tier 2 backup tracker must NOT be contacted after Tier 1 succeeds.
        let tier2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tier2_addr = tier2.local_addr().unwrap();
        let tier2_hits = Arc::new(AtomicUsize::new(0));
        let t2_hits_bg = tier2_hits.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = tier2.accept().await {
                t2_hits_bg.fetch_add(1, Ordering::Relaxed);
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 19\r\n\r\nd8:intervali600e5:peers0:e",
                    )
                    .await;
            }
        });

        let u0 = format!("http://{dead_addr}/announce");
        let u1 = format!("http://{tier1_addr}/announce");
        let u2 = format!("http://{tier2_addr}/announce");

        let mut info_dict = BTreeMap::new();
        info_dict.insert(
            b"name".to_vec(),
            BEncode::String(b"bep12-failover".to_vec()),
        );
        info_dict.insert(b"piece length".to_vec(), BEncode::Int(16384));
        info_dict.insert(b"pieces".to_vec(), BEncode::String(vec![0u8; 20]));
        info_dict.insert(b"length".to_vec(), BEncode::Int(16384));
        info_dict.insert(b"private".to_vec(), BEncode::Int(1));

        let mut top = BTreeMap::new();
        top.insert(
            b"announce".to_vec(),
            BEncode::String(u0.as_bytes().to_vec()),
        );
        top.insert(
            b"announce-list".to_vec(),
            BEncode::List(vec![
                BEncode::List(vec![BEncode::String(u0.into_bytes())]),
                BEncode::List(vec![BEncode::String(u1.into_bytes())]),
                BEncode::List(vec![BEncode::String(u2.into_bytes())]),
            ]),
        );
        top.insert(b"info".to_vec(), BEncode::Dict(info_dict));
        let info = Info::from_bencode(BEncode::Dict(top)).unwrap();

        let announcer = Announcer::new(
            [0x12; 20],
            Arc::new(RwLock::new(0)),
            Arc::new(crate::circuit_breaker::PeerCircuitBreaker::default()),
        );
        let (peers, interval, reports) = announcer
            .announce_with_interval(&info, 0, 16384, 0, Event::Started)
            .await;

        assert_eq!(tier1_hits.load(Ordering::Relaxed), 1);
        assert_eq!(tier2_hits.load(Ordering::Relaxed), 0);
        assert_eq!(interval, 600);
        assert!(peers.contains(&"203.0.113.5:6881".parse().unwrap()));
        assert_eq!(reports.len(), 2);
        assert_ne!(reports[0].status, "Announced");
        assert_eq!(reports[1].status, "Announced");
    }

    #[tokio::test]
    async fn dial_ready_dispatches_candidates_and_pre_pop_semaphore_backpressure_holds_due_jobs() {
        let cb = Arc::new(PeerCircuitBreaker::default());
        let announcer = Arc::new(Announcer::new([0x13; 20], Arc::new(RwLock::new(6881)), cb));
        // Concurrency limit = 1 so holding the single permit exercises pre-pop backpressure.
        let scheduler = AnnounceScheduler::new(
            announcer,
            1,
            Duration::from_secs(1800),
            Duration::from_secs(0),
        );

        let build_info = |name: &str| -> Arc<Info> {
            let mut info_dict = std::collections::BTreeMap::new();
            info_dict.insert(
                b"name".to_vec(),
                synapse_bencode::BEncode::String(name.as_bytes().to_vec()),
            );
            info_dict.insert(
                b"piece length".to_vec(),
                synapse_bencode::BEncode::Int(16384),
            );
            info_dict.insert(
                b"pieces".to_vec(),
                synapse_bencode::BEncode::String(vec![0u8; 40]),
            );
            info_dict.insert(b"length".to_vec(), synapse_bencode::BEncode::Int(32768));
            info_dict.insert(b"private".to_vec(), synapse_bencode::BEncode::Int(1));
            let mut top = std::collections::BTreeMap::new();
            top.insert(b"info".to_vec(), synapse_bencode::BEncode::Dict(info_dict));
            Arc::new(Info::from_bencode(synapse_bencode::BEncode::Dict(top)).unwrap())
        };

        let make_stats = |info: &Info| {
            Arc::new(RwLock::new(SwarmStats {
                info_hash: info.hash,
                name: info.name.clone(),
                total_size: info.total_len,
                progress: 0.0,
                state: crate::swarm::SwarmState::Downloading,
                tier: crate::swarm::SwarmTier::Hot,
                download_rate: 0,
                upload_rate: 0,
                downloaded_bytes: 0,
                uploaded_bytes: 0,
                peers_connected: 0,
                peers_sending: 0,
                eta_seconds: 0,
                ratio: 0.0,
                download_dir: String::new(),
                added_at: 0,
                is_private: info.private,
                is_stalled: false,
                last_transfer_at: 0,
                piece_count: info.pieces(),
                piece_size: info.piece_len,
            }))
        };

        // Hold the sole semaphore permit; dispatch_batch must leave due job queued without dropping it.
        let held_permit = scheduler
            .concurrency_limit
            .clone()
            .try_acquire_owned()
            .unwrap();
        let info_a = build_info("swarm-a");
        let (tx_a, _rx_a) = mpsc::channel(8);
        scheduler.register(info_a.hash, info_a.clone(), make_stats(&info_a), tx_a, true);
        assert_eq!(scheduler.pending_announces(), 1);
        scheduler.dispatch_batch().await;
        assert_eq!(
            scheduler.pending_announces(),
            1,
            "due job must stay in heap when semaphore permit is unavailable"
        );
        drop(held_permit);
        scheduler.dispatch_batch().await;
        assert_eq!(
            scheduler.pending_announces(),
            0,
            "due job dispatches once semaphore permit becomes available"
        );

        // Candidate addition populates dial_ready, and dial_step pops only from dial_ready.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let info_b = build_info("swarm-b");
        let (tx_b, _rx_b) = mpsc::channel(8);
        scheduler.register(info_b.hash, info_b.clone(), make_stats(&info_b), tx_b, true);
        scheduler.add_candidate_peers(&info_b.hash, [peer_addr]);
        assert!(scheduler.in_dial_ready.contains(&info_b.hash));

        scheduler.dial_step().await;
        assert!(!scheduler.in_dial_ready.contains(&info_b.hash));
        assert_eq!(scheduler.candidate_peers_count(&info_b.hash), 0);

        let expected = compute_missing_wanted_bytes(&info_b, &[4], None);
        let decremented = expected
            - if is_piece_wanted(&info_b, &[4], 0) {
                info_b.piece_len(0) as u64
            } else {
                0
            };
        let mut bf = synapse_picker::RoaringBitfield::new(2);
        bf.set(0);
        assert_eq!(
            decremented,
            compute_missing_wanted_bytes(&info_b, &[4], Some(&bf))
        );
    }

    #[tokio::test]
    async fn dynamic_max_concurrent_tracker_announces_throttles_and_expands() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tracker_url = format!("http://{addr}/announce");

        let release_notify = Arc::new(Notify::new());
        let hold_requests = Arc::new(AtomicBool::new(true));
        let in_flight_http = Arc::new(AtomicUsize::new(0));
        let release_srv = release_notify.clone();
        let hold_srv = hold_requests.clone();
        let in_flight_srv = in_flight_http.clone();

        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let rel = release_srv.clone();
                let hold = hold_srv.clone();
                let in_flight = in_flight_srv.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = stream.read(&mut buf).await;
                    in_flight.fetch_add(1, Ordering::AcqRel);
                    while hold.load(Ordering::Acquire) {
                        let notified = rel.notified();
                        tokio::pin!(notified);
                        notified.as_mut().enable();
                        if !hold.load(Ordering::Acquire) {
                            break;
                        }
                        notified.await;
                    }
                    let body = b"d8:intervali60e5:peers0:e";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        let make_tracker_info = |name: &str| -> Arc<Info> {
            let mut info_dict = std::collections::BTreeMap::new();
            info_dict.insert(
                b"name".to_vec(),
                synapse_bencode::BEncode::String(name.as_bytes().to_vec()),
            );
            info_dict.insert(
                b"piece length".to_vec(),
                synapse_bencode::BEncode::Int(16384),
            );
            info_dict.insert(
                b"pieces".to_vec(),
                synapse_bencode::BEncode::String(vec![0u8; 20]),
            );
            info_dict.insert(b"length".to_vec(), synapse_bencode::BEncode::Int(16384));
            info_dict.insert(b"private".to_vec(), synapse_bencode::BEncode::Int(1));
            let mut top = std::collections::BTreeMap::new();
            top.insert(
                b"announce".to_vec(),
                synapse_bencode::BEncode::String(tracker_url.as_bytes().to_vec()),
            );
            top.insert(b"info".to_vec(), synapse_bencode::BEncode::Dict(info_dict));
            Arc::new(Info::from_bencode(synapse_bencode::BEncode::Dict(top)).unwrap())
        };

        let make_stats = |info: &Info| {
            Arc::new(RwLock::new(SwarmStats {
                info_hash: info.hash,
                name: info.name.clone(),
                total_size: info.total_len,
                progress: 0.0,
                state: crate::swarm::SwarmState::Downloading,
                tier: crate::swarm::SwarmTier::Hot,
                download_rate: 0,
                upload_rate: 0,
                downloaded_bytes: 0,
                uploaded_bytes: 0,
                peers_connected: 0,
                peers_sending: 0,
                eta_seconds: 0,
                ratio: 0.0,
                download_dir: String::new(),
                added_at: 0,
                is_private: true,
                is_stalled: false,
                last_transfer_at: 0,
                piece_count: info.pieces(),
                piece_size: info.piece_len,
            }))
        };

        let settings = Arc::new(RwLock::new(crate::settings::DynamicSessionSettings {
            max_concurrent_tracker_announces: 1,
            ..Default::default()
        }));
        let announcer = Arc::new(Announcer::new(
            [0x53; 20],
            Arc::new(RwLock::new(6881)),
            Arc::new(crate::circuit_breaker::PeerCircuitBreaker::default()),
        ));
        // Start with initial semaphore capacity = 2 so we exercise both throttling below initial (1 < 2)
        // and dynamic permit expansion above initial (4 > 2).
        let scheduler =
            AnnounceScheduler::new(announcer, 2, Duration::from_secs(1800), Duration::ZERO);
        scheduler.set_settings(settings.clone());

        let i1 = make_tracker_info("dyn-1");
        let i2 = make_tracker_info("dyn-2");
        let (tx1, _rx1) = mpsc::channel(8);
        let (tx2, _rx2) = mpsc::channel(8);
        scheduler.register(i1.hash, i1.clone(), make_stats(&i1), tx1, true);
        scheduler.register(i2.hash, i2.clone(), make_stats(&i2), tx2, true);

        scheduler.dispatch_batch().await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while in_flight_http.load(Ordering::Acquire) < 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("first tracker announce did not hit mock server");
        assert_eq!(scheduler.active_announces.load(Ordering::Acquire), 1);
        assert_eq!(
            scheduler.pending_announces(),
            1,
            "limit=1 must keep second due announce queued even though initial semaphore_capacity=2"
        );

        // Raise limit above initial semaphore capacity (2 -> 4) and register 3 more swarms (4 queued total).
        settings.write().max_concurrent_tracker_announces = 4;
        for name in ["dyn-3", "dyn-4", "dyn-5"] {
            let info = make_tracker_info(name);
            let (tx, _rx) = mpsc::channel(8);
            scheduler.register(info.hash, info.clone(), make_stats(&info), tx, true);
        }

        scheduler.dispatch_batch().await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while in_flight_http.load(Ordering::Acquire) < 4 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("raised limit=4 did not expand concurrent announces");

        assert_eq!(scheduler.semaphore_capacity.load(Ordering::Acquire), 4);
        assert_eq!(scheduler.active_announces.load(Ordering::Acquire), 4);
        assert_eq!(scheduler.pending_announces(), 1);

        // Release all held tracker HTTP requests and verify active count drains cleanly.
        hold_requests.store(false, Ordering::Release);
        release_notify.notify_waiters();
        tokio::time::timeout(Duration::from_secs(2), async {
            while scheduler.active_announces.load(Ordering::Acquire) > 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("active_announces did not drain after releasing responses");

        scheduler.dispatch_batch().await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while in_flight_http.load(Ordering::Acquire) < 5
                || scheduler.active_announces.load(Ordering::Acquire) > 0
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("final queued announce did not complete");
        assert_eq!(in_flight_http.load(Ordering::Acquire), 5);
        assert_eq!(scheduler.active_announces.load(Ordering::Acquire), 0);

        scheduler.shutdown();
        server_task.abort();
    }
}
