//! Local Peer Discovery (LSD - BEP 14 / BEP 22) Swarm Manager.
//!
//! Handles local network multicast peer announcements and incoming discovery.
//!
//! STRICT SECURITY / PRIVACY INVARIANT:
//! If a torrent has `info.private = true` (BEP 27), LSD is completely disabled
//! for that info_hash and will never announce or ingest local peers.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use synapse_wire::{format_lsd_announce, parse_lsd_announce};
use tracing::debug;

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
}

impl LsdManager {
    pub fn new(listen_port: u16, cookie: String) -> Self {
        Self {
            listen_port,
            cookie,
            public_torrents: HashSet::new(),
            private_torrents: HashSet::new(),
            known_peers: HashMap::new(),
        }
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

        let peer_addr = SocketAddr::new(sender_ip, announce.port);
        let mut discovered = Vec::new();

        for hash in announce.info_hashes {
            // Strict BEP 27 invariant: Private torrents NEVER accept LSD peers
            if self.private_torrents.contains(&hash) {
                debug!("LSD peer ignored for private torrent info_hash={}", hex::encode(hash));
                continue;
            }

            if self.public_torrents.contains(&hash) {
                let peer_set = self.known_peers.entry(hash).or_default();
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
}
