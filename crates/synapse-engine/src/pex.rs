//! Swarm Peer Exchange (PEX) Manager.
//!
//! Orchestrates delta tracking of connected swarm peers and handles incoming/outgoing
//! `ut_pex` messages.
//!
//! STRICT SECURITY / PRIVACY INVARIANT:
//! If `is_private` is `true` (BEP 27), PEX is permanently disabled and will never
//! export or ingest peers.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use synapse_wire::UtPexMessage;

/// Most peers accepted from (or sent in) one `ut_pex` message, per address family. BEP 11
/// recommends at most 50 added entries per message; a hostile peer can otherwise flood
/// the candidate pool with junk addresses in a single frame.
pub const MAX_PEX_PEERS_PER_MESSAGE: usize = 50;

/// Whether `ip` is an address that must never be dialled on the word of an untrusted
/// peer: unspecified, loopback, multicast and link-local ranges, plus IPv4 broadcast.
fn is_never_dialable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Whether `ip` is in a private/unique-local range (RFC 1918, fc00::/7).
fn is_private_range(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Decides whether a peer address learned via PEX from `source` may become a candidate.
/// Public addresses are always fine; private ranges only when the sender is itself on a
/// private/loopback network (a genuine LAN swarm), so a remote peer cannot steer us into
/// dialling addresses on our own internal network.
fn pex_address_allowed(addr: SocketAddr, source: IpAddr) -> bool {
    if addr.port() == 0 || is_never_dialable(addr.ip()) {
        return false;
    }
    !is_private_range(addr.ip()) || is_private_range(source) || source.is_loopback()
}

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

        // Send at most MAX_PEX_PEERS_PER_MESSAGE per family and keep the remainder for the
        // next interval, never leaking loopback/link-local addresses to other peers.
        let (mut n4, mut n6) = (0usize, 0usize);
        let mut deferred = Vec::new();
        for addr in std::mem::take(&mut self.recently_added) {
            if addr.port() == 0 || is_never_dialable(addr.ip()) {
                continue;
            }
            let count = if addr.is_ipv4() { &mut n4 } else { &mut n6 };
            if *count >= MAX_PEX_PEERS_PER_MESSAGE {
                deferred.push(addr);
                continue;
            }
            *count += 1;
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
        self.recently_added = deferred;

        let dropped = std::mem::take(&mut self.recently_dropped);
        let (mut d4, mut d6) = (0usize, 0usize);
        for addr in dropped {
            match addr {
                SocketAddr::V4(v4) if d4 < MAX_PEX_PEERS_PER_MESSAGE => {
                    d4 += 1;
                    msg.dropped_v4.push(v4);
                }
                SocketAddr::V6(v6) if d6 < MAX_PEX_PEERS_PER_MESSAGE => {
                    d6 += 1;
                    msg.dropped_v6.push(v6);
                }
                other => self.recently_dropped.push(other),
            }
        }

        Some(msg)
    }

    /// Ingests a `UtPexMessage` from a remote peer and returns discovered peer addresses.
    ///
    /// `source` is the sender's address. Entries beyond `MAX_PEX_PEERS_PER_MESSAGE` per
    /// family, port-0 entries, and non-dialable or (for non-LAN senders) private addresses
    /// are dropped.
    pub fn ingest_pex_message(&mut self, msg: UtPexMessage, source: IpAddr) -> Vec<SocketAddr> {
        if self.is_private {
            return Vec::new();
        }

        let v4 = msg
            .added_v4
            .into_iter()
            .take(MAX_PEX_PEERS_PER_MESSAGE)
            .map(SocketAddr::V4);
        let v6 = msg
            .added_v6
            .into_iter()
            .take(MAX_PEX_PEERS_PER_MESSAGE)
            .map(SocketAddr::V6);
        v4.chain(v6)
            .filter(|addr| pex_address_allowed(*addr, source) && !self.known_peers.contains(addr))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    const PUBLIC_SRC: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)
    }

    #[test]
    fn ingest_caps_entries_per_message() {
        let mut pex = PexManager::new(false);
        let msg = UtPexMessage {
            added_v4: (0..500u16)
                .map(|i| v4(8, 8, (i / 250) as u8, (i % 250) as u8 + 1, 6881))
                .collect(),
            ..Default::default()
        };
        assert_eq!(
            pex.ingest_pex_message(msg, PUBLIC_SRC).len(),
            MAX_PEX_PEERS_PER_MESSAGE
        );
    }

    #[test]
    fn ingest_drops_undialable_and_port_zero_entries() {
        let mut pex = PexManager::new(false);
        let msg = UtPexMessage {
            added_v4: vec![
                v4(127, 0, 0, 1, 6881),
                v4(0, 0, 0, 0, 6881),
                v4(169, 254, 1, 1, 6881),
                v4(224, 0, 0, 1, 6881),
                v4(255, 255, 255, 255, 6881),
                v4(8, 8, 8, 8, 0),
                v4(10, 0, 0, 5, 6881),
                v4(192, 168, 1, 5, 6881),
                v4(8, 8, 4, 4, 6881),
            ],
            added_v6: vec![
                SocketAddrV6::new(Ipv6Addr::LOCALHOST, 6881, 0, 0),
                SocketAddrV6::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 6881, 0, 0),
                SocketAddrV6::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), 6881, 0, 0),
            ],
            ..Default::default()
        };
        let got = pex.ingest_pex_message(msg, PUBLIC_SRC);
        assert_eq!(got, vec![SocketAddr::V4(v4(8, 8, 4, 4, 6881))]);
    }

    #[test]
    fn private_addresses_are_accepted_only_from_lan_senders() {
        let lan_peer = SocketAddr::V4(v4(192, 168, 1, 20, 6881));
        let mk = || UtPexMessage {
            added_v4: vec![v4(192, 168, 1, 20, 6881)],
            ..Default::default()
        };
        let mut pex = PexManager::new(false);
        assert!(pex.ingest_pex_message(mk(), PUBLIC_SRC).is_empty());
        assert_eq!(
            pex.ingest_pex_message(mk(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            vec![lan_peer]
        );
        assert_eq!(
            pex.ingest_pex_message(mk(), IpAddr::V4(Ipv4Addr::LOCALHOST)),
            vec![lan_peer]
        );
    }

    #[test]
    fn generate_caps_message_and_carries_remainder_forward() {
        let mut pex = PexManager::new(false);
        for i in 0..120u8 {
            pex.peer_connected(SocketAddr::V4(v4(8, 8, 8, i + 1, 6881)));
        }
        pex.peer_connected(SocketAddr::V4(v4(127, 0, 0, 1, 6881)));
        let first = pex.generate_pex_message().unwrap();
        assert_eq!(first.added_v4.len(), MAX_PEX_PEERS_PER_MESSAGE);
        let second = pex.generate_pex_message().unwrap();
        assert_eq!(second.added_v4.len(), MAX_PEX_PEERS_PER_MESSAGE);
        let third = pex.generate_pex_message().unwrap();
        assert_eq!(third.added_v4.len(), 20);
        assert!(pex.generate_pex_message().is_none());
    }

    #[test]
    fn test_pex_manager_public_swarm_delta_flow() {
        let mut pex = PexManager::new(false);
        assert!(pex.is_enabled());

        let peer1 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 6881));
        let peer2 = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            51413,
            0,
            0,
        ));

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
        assert_eq!(
            drop_msg.dropped_v4[0],
            SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 6881)
        );
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
        let discovered = pex.ingest_pex_message(incoming_msg, PUBLIC_SRC);
        assert!(discovered.is_empty()); // Dropped completely for private
    }
}
