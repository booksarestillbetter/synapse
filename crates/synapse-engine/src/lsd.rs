//! Local Peer Discovery (LSD - BEP 14 / BEP 22) Swarm Manager.
//!
//! Handles local network multicast peer announcements and incoming discovery.
//!
//! STRICT SECURITY / PRIVACY INVARIANT:
//! If a torrent has `info.private = true` (BEP 27), LSD is completely disabled
//! for that info_hash and will never announce or ingest local peers.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use synapse_wire::{format_lsd_announce, parse_lsd_announce};
use tracing::debug;

/// Announcements accepted from one source address per `SOURCE_WINDOW`. Honest clients
/// announce every few minutes, so this only ever affects a flooder.
const MAX_PACKETS_PER_SOURCE: u32 = 20;
const SOURCE_WINDOW: Duration = Duration::from_secs(60);
/// Sources tracked for rate limiting at once.
const MAX_TRACKED_SOURCES: usize = 1024;
/// Distinct local peers remembered per torrent (also what bounds spoofed-port floods).
const MAX_PEERS_PER_TORRENT: usize = 256;

#[derive(Debug, Clone)]
pub struct DiscoveredLocalPeer {
    pub addr: SocketAddr,
    pub info_hash: [u8; 20],
}

/// Swarm-level LSD Coordinator.
pub struct LsdManager {
    listen_port: u16,
    cookie: String,
    public_torrents: HashSet<[u8; 20]>,
    private_torrents: HashSet<[u8; 20]>,
    known_peers: HashMap<[u8; 20], HashSet<SocketAddr>>,
    /// Per-source (window start, packets in window) for rate limiting.
    sources: HashMap<IpAddr, (Instant, u32)>,
}

impl LsdManager {
    pub fn new(listen_port: u16, cookie: String) -> Self {
        Self {
            listen_port,
            cookie,
            public_torrents: HashSet::new(),
            private_torrents: HashSet::new(),
            known_peers: HashMap::new(),
            sources: HashMap::new(),
        }
    }

    /// Whether another packet from `ip` is within its budget; counts it.
    fn source_allowed(&mut self, ip: IpAddr, now: Instant) -> bool {
        if self.sources.len() >= MAX_TRACKED_SOURCES && !self.sources.contains_key(&ip) {
            self.sources
                .retain(|_, (start, _)| now.duration_since(*start) < SOURCE_WINDOW);
            if self.sources.len() >= MAX_TRACKED_SOURCES {
                return false;
            }
        }
        let entry = self.sources.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= SOURCE_WINDOW {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= MAX_PACKETS_PER_SOURCE
    }

    /// Updates the peer listen port advertised in outgoing announcements (e.g. once the
    /// daemon's inbound TCP listener has actually bound and the real port is known).
    pub fn set_listen_port(&mut self, port: u16) {
        self.listen_port = port;
    }

    /// Registers a torrent in the LSD manager with its privacy flag.
    pub fn register_torrent(&mut self, info_hash: [u8; 20], is_private: bool) {
        if is_private {
            self.private_torrents.insert(info_hash);
            self.public_torrents.remove(&info_hash);
        } else {
            self.public_torrents.insert(info_hash);
            self.private_torrents.remove(&info_hash);
        }
    }

    /// Unregisters a torrent from the LSD manager.
    pub fn unregister_torrent(&mut self, info_hash: &[u8; 20]) {
        self.public_torrents.remove(info_hash);
        self.private_torrents.remove(info_hash);
        self.known_peers.remove(info_hash);
    }

    /// Builds a multicast announcement packet string containing all active public torrents.
    /// Returns None if there are no public torrents to announce.
    pub fn build_announce_packet(&self) -> Option<String> {
        if self.public_torrents.is_empty() {
            return None;
        }

        let hashes: Vec<[u8; 20]> = self.public_torrents.iter().copied().collect();
        Some(format_lsd_announce(
            self.listen_port,
            &hashes,
            Some(&self.cookie),
        ))
    }

    /// Ingests a received raw multicast packet from `sender_ip` and returns newly discovered peers.
    pub fn ingest_packet(
        &mut self,
        sender_ip: IpAddr,
        packet_raw: &str,
    ) -> Vec<DiscoveredLocalPeer> {
        // LSD is link-local multicast: a genuine announcement comes from a host on our own
        // network. A packet claiming a public source address is spoofed (or misrouted) and
        // must not be able to inject peers.
        // (IPv6 hosts on a LAN commonly hold global addresses, so the public-source test only
        // applies to IPv4, where multicast senders are on private space. The per-source rate
        // limit and per-torrent peer cap below bound what a spoofed IPv6 source could inject.)
        if sender_ip.is_ipv4() && synapse_tracker::safe_http::is_public_ip(sender_ip) {
            return Vec::new();
        }
        if !self.source_allowed(sender_ip, Instant::now()) {
            return Vec::new();
        }
        let announce = match parse_lsd_announce(packet_raw) {
            Ok(a) => a,
            Err(_) => return Vec::new(),
        };

        // Ignore our own announcements
        if let Some(ref c) = announce.cookie {
            if c == &self.cookie {
                return Vec::new();
            }
        }

        if announce.port == 0 {
            return Vec::new();
        }
        let peer_addr = SocketAddr::new(sender_ip, announce.port);
        let mut discovered = Vec::new();

        for hash in announce.info_hashes {
            // Strict BEP 27 invariant: Private torrents NEVER accept LSD peers
            if self.private_torrents.contains(&hash) {
                debug!(
                    "LSD peer ignored for private torrent info_hash={}",
                    hex::encode(hash)
                );
                continue;
            }

            if self.public_torrents.contains(&hash) {
                let peer_set = self.known_peers.entry(hash).or_default();
                if peer_set.len() >= MAX_PEERS_PER_TORRENT {
                    continue;
                }
                if peer_set.insert(peer_addr) {
                    discovered.push(DiscoveredLocalPeer {
                        addr: peer_addr,
                        info_hash: hash,
                    });
                }
            }
        }

        discovered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_lsd_manager_public_announces_and_ingestion() {
        let mut mgr1 = LsdManager::new(6881, "cookie_mgr1".into());
        let mut mgr2 = LsdManager::new(6882, "cookie_mgr2".into());

        let public_hash = [0x11; 20];
        mgr1.register_torrent(public_hash, false);
        mgr2.register_torrent(public_hash, false);

        // Mgr1 builds announcement packet
        let pkt = mgr1.build_announce_packet().unwrap();

        // Mgr2 ingests packet from Mgr1
        let sender = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let discovered = mgr2.ingest_packet(sender, &pkt);

        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].addr, SocketAddr::new(sender, 6881));
        assert_eq!(discovered[0].info_hash, public_hash);

        // Deduplication: second ingestion from same peer returns empty
        let re_discovered = mgr2.ingest_packet(sender, &pkt);
        assert!(re_discovered.is_empty());
    }

    #[test]
    fn test_lsd_manager_strictly_ignores_private_swarms() {
        let mut mgr = LsdManager::new(6881, "cookie_test".into());
        let private_hash = [0x99; 20];
        mgr.register_torrent(private_hash, true); // Private torrent

        // Announcement builder should not include private torrent
        assert!(mgr.build_announce_packet().is_none());

        // Ingesting remote announcement for private hash must be rejected
        let fake_pkt = format_lsd_announce(51413, &[private_hash], Some("remote_cookie"));
        let sender = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
        let discovered = mgr.ingest_packet(sender, &fake_pkt);
        assert!(discovered.is_empty());
    }

    fn announce_for(port: u16, hash: [u8; 20]) -> String {
        let mut m = LsdManager::new(port, format!("cookie{port}"));
        m.register_torrent(hash, false);
        m.build_announce_packet().unwrap()
    }

    #[test]
    fn packets_from_public_source_addresses_are_ignored() {
        let hash = [0x22; 20];
        let mut rx = LsdManager::new(6881, "rx".into());
        rx.register_torrent(hash, false);
        let pkt = announce_for(6882, hash);
        assert!(
            rx.ingest_packet(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), &pkt)
                .is_empty(),
            "spoofed public source"
        );
        assert_eq!(
            rx.ingest_packet(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7)), &pkt)
                .len(),
            1
        );
    }

    #[test]
    fn a_flooding_source_is_rate_limited_but_others_are_unaffected() {
        let hash = [0x33; 20];
        let mut rx = LsdManager::new(6881, "rx".into());
        rx.register_torrent(hash, false);
        let flooder = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let mut accepted = 0;
        for port in 1..=200u16 {
            accepted += rx
                .ingest_packet(flooder, &announce_for(port + 1000, hash))
                .len();
        }
        assert_eq!(
            accepted, MAX_PACKETS_PER_SOURCE as usize,
            "only the per-window budget is honoured"
        );
        assert_eq!(
            rx.ingest_packet(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)),
                &announce_for(7000, hash)
            )
            .len(),
            1
        );
    }
}
