//! Swarm Peer Exchange (PEX) Manager.
//!
//! Orchestrates delta tracking of connected swarm peers and handles incoming/outgoing
//! `ut_pex` messages.
//!
//! STRICT SECURITY / PRIVACY INVARIANT:
//! If `is_private` is `true` (BEP 27), PEX is permanently disabled and will never
//! export or ingest peers.

use std::collections::HashSet;
use std::net::SocketAddr;
use synapse_wire::UtPexMessage;

pub struct PexManager {
    is_private: bool,
    known_peers: HashSet<SocketAddr>,
    recently_added: Vec<SocketAddr>,
    recently_dropped: Vec<SocketAddr>,
}

impl PexManager {
    pub fn new(is_private: bool) -> Self {
        Self {
            is_private,
            known_peers: HashSet::new(),
            recently_added: Vec::new(),
            recently_dropped: Vec::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.is_private
    }

    /// Records a new peer connection in the swarm.
    pub fn peer_connected(&mut self, addr: SocketAddr) {
        if self.is_private {
            return;
        }
        if self.known_peers.insert(addr) {
            self.recently_added.push(addr);
        }
    }

    /// Records a disconnected peer from the swarm.
    pub fn peer_disconnected(&mut self, addr: SocketAddr) {
        if self.is_private {
            return;
        }
        if self.known_peers.remove(&addr) {
            self.recently_dropped.push(addr);
        }
    }

    /// Generates a `UtPexMessage` with recently joined and dropped peers, then clears delta buffers.
    pub fn generate_pex_message(&mut self) -> Option<UtPexMessage> {
        if self.is_private || (self.recently_added.is_empty() && self.recently_dropped.is_empty()) {
            return None;
        }

        let mut msg = UtPexMessage::new();

        for addr in self.recently_added.drain(..) {
            match addr {
                SocketAddr::V4(v4) => {
                    msg.added_v4.push(v4);
                    msg.added_v4_flags.push(0); // 0 or PEX_FLAG_SEEDER
                }
                SocketAddr::V6(v6) => {
                    msg.added_v6.push(v6);
                    msg.added_v6_flags.push(0);
                }
            }
        }

        for addr in self.recently_dropped.drain(..) {
            match addr {
                SocketAddr::V4(v4) => msg.dropped_v4.push(v4),
                SocketAddr::V6(v6) => msg.dropped_v6.push(v6),
            }
        }

        Some(msg)
    }

    /// Ingests a `UtPexMessage` from a remote peer and returns discovered peer addresses.
    pub fn ingest_pex_message(&mut self, msg: UtPexMessage) -> Vec<SocketAddr> {
        if self.is_private {
            return Vec::new();
        }

        let mut discovered = Vec::new();

        for v4 in msg.added_v4 {
            let addr = SocketAddr::V4(v4);
            if !self.known_peers.contains(&addr) {
                discovered.push(addr);
            }
        }

        for v6 in msg.added_v6 {
            let addr = SocketAddr::V6(v6);
            if !self.known_peers.contains(&addr) {
                discovered.push(addr);
            }
        }

        discovered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_pex_manager_public_swarm_delta_flow() {
        let mut pex = PexManager::new(false);
        assert!(pex.is_enabled());

        let peer1 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 6881));
        let peer2 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 51413, 0, 0));

        pex.peer_connected(peer1);
        pex.peer_connected(peer2);

        let msg = pex.generate_pex_message().unwrap();
        assert_eq!(msg.added_v4.len(), 1);
        assert_eq!(msg.added_v6.len(), 1);

        // Next generation has no new changes
        assert!(pex.generate_pex_message().is_none());

        pex.peer_disconnected(peer1);
        let drop_msg = pex.generate_pex_message().unwrap();
        assert_eq!(drop_msg.dropped_v4.len(), 1);
        assert_eq!(drop_msg.dropped_v4[0], SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 6881));
    }

    #[test]
    fn test_pex_manager_strictly_disabled_for_private_swarms() {
        let mut pex = PexManager::new(true); // Private torrent
        assert!(!pex.is_enabled());

        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 6881));
        pex.peer_connected(peer);

        assert!(pex.generate_pex_message().is_none());

        let incoming_msg = UtPexMessage {
            added_v4: vec![SocketAddrV4::new(Ipv4Addr::new(99, 99, 99, 99), 6881)],
            ..Default::default()
        };
        let discovered = pex.ingest_pex_message(incoming_msg);
        assert!(discovered.is_empty()); // Dropped completely for private
    }
}
