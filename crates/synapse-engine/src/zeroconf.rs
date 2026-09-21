//! BEP 26 Zeroconf peer discovery: state and message handling. The multicast sockets and timers
//! live in `SwarmEngine::start_zeroconf`.
//!
//! Like LSD, this is for the local network only and never involves a private torrent (BEP 27):
//! a private torrent's info hash is not announced, asked about, or answered.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use synapse_wire::zeroconf as dns;
pub use synapse_wire::zeroconf::MDNS_IPV4;

/// Messages accepted from one source per window, sources tracked, and peers kept per torrent.
const MAX_PACKETS_PER_SOURCE: u32 = 30;
const SOURCE_WINDOW: Duration = Duration::from_secs(60);
const MAX_TRACKED_SOURCES: usize = 1024;
const MAX_PEERS_PER_TORRENT: usize = 256;
/// Subtypes asked about in one query message.
const NAMES_PER_QUERY: usize = 8;

pub struct ZeroconfManager {
    peer_id: [u8; 20],
    port: u16,
    public: HashSet<[u8; 20]>,
    private: HashSet<[u8; 20]>,
    known: HashMap<[u8; 20], HashSet<SocketAddr>>,
    sources: HashMap<IpAddr, (Instant, u32)>,
}

/// What to do with a received datagram.
#[derive(Debug, Default)]
pub struct Handled {
    /// A response to multicast, when we were asked about a torrent we share.
    pub reply: Option<Vec<u8>>,
    /// Newly learned peers.
    pub peers: Vec<([u8; 20], SocketAddr)>,
}

impl ZeroconfManager {
    pub fn new(peer_id: [u8; 20]) -> Self {
        Self {
            peer_id,
            port: 0,
            public: HashSet::new(),
            private: HashSet::new(),
            known: HashMap::new(),
            sources: HashMap::new(),
        }
    }

    pub fn set_listen_port(&mut self, port: u16) {
        self.port = port;
    }

    pub fn register_torrent(&mut self, info_hash: [u8; 20], is_private: bool) {
        if is_private {
            self.private.insert(info_hash);
            self.public.remove(&info_hash);
        } else {
            self.public.insert(info_hash);
            self.private.remove(&info_hash);
        }
    }

    pub fn unregister_torrent(&mut self, info_hash: &[u8; 20]) {
        self.public.remove(info_hash);
        self.private.remove(info_hash);
        self.known.remove(info_hash);
    }

    /// Queries (PTR questions for each public torrent's subtype), split into datagram-sized
    /// messages. Empty when nothing is shared.
    pub fn queries(&self) -> Vec<Vec<u8>> {
        let names: Vec<String> = self.public.iter().map(dns::sub_service_name).collect();
        names
            .chunks(NAMES_PER_QUERY)
            .map(dns::build_query)
            .collect()
    }

    /// Our announcement of every public torrent. `None` when nothing is shared, or the port
    /// is not known yet.
    pub fn announcement(&self, local_addrs: &[IpAddr]) -> Option<Vec<u8>> {
        if self.public.is_empty() || self.port == 0 || local_addrs.is_empty() {
            return None;
        }
        let hashes: Vec<[u8; 20]> = self.public.iter().copied().collect();
        Some(dns::build_response(
            &self.peer_id,
            &hashes,
            self.port,
            local_addrs,
        ))
    }

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

    /// Handles one datagram from `from`: answers questions about torrents we share and learns
    /// the peers an answer lists.
    pub fn handle_datagram(
        &mut self,
        from: SocketAddr,
        datagram: &[u8],
        local_addrs: &[IpAddr],
    ) -> Handled {
        // Link-local multicast: a genuine sender is on our own network, so an IPv4 datagram
        // claiming a public source is spoofed or misrouted.
        if from.ip().is_ipv4() && synapse_tracker::safe_http::is_public_ip(from.ip()) {
            return Handled::default();
        }
        if !self.source_allowed(from.ip(), Instant::now()) {
            return Handled::default();
        }
        let Some(msg) = dns::parse_message(datagram) else {
            return Handled::default();
        };
        let mut handled = Handled::default();

        if !msg.is_response {
            let asked_about_us = msg.questions.iter().any(|q| {
                dns::info_hash_of_sub_service(q).is_some_and(|h| self.public.contains(&h))
                    || q == dns::SERVICE
            });
            if asked_about_us {
                handled.reply = self.announcement(local_addrs);
            }
            return handled;
        }

        let our_instance = dns::instance_name(&self.peer_id);
        if msg.ptr.iter().any(|(_, target)| *target == our_instance) {
            return handled; // our own announcement coming back
        }
        for (hash, addr) in dns::discovered_peers(&msg) {
            // Only torrents we share, and only a host vouching for its own address: otherwise
            // any machine on the LAN could point us at arbitrary third parties.
            if !self.public.contains(&hash) || addr.ip() != from.ip() {
                continue;
            }
            let peers = self.known.entry(hash).or_default();
            if peers.len() < MAX_PEERS_PER_TORRENT && peers.insert(addr) {
                handled.peers.push((hash, addr));
            }
        }
        handled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const HASH: [u8; 20] = [7; 20];
    const LAN: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

    fn manager(peer_id: u8, port: u16) -> ZeroconfManager {
        let mut m = ZeroconfManager::new([peer_id; 20]);
        m.set_listen_port(port);
        m.register_torrent(HASH, false);
        m
    }

    #[test]
    fn a_peer_answers_a_query_and_the_asker_learns_its_address() {
        let mut alice = manager(1, 6881);
        let mut bob = manager(2, 7000);
        let alice_ip: IpAddr = "192.168.1.10".parse().unwrap();

        // Bob asks who is on the torrent; Alice answers; Bob turns the answer into a peer.
        let query = bob.queries().remove(0);
        let handled = alice.handle_datagram(SocketAddr::new(LAN, 5353), &query, &[alice_ip]);
        let reply = handled
            .reply
            .expect("alice shares the torrent, so she answers");
        let learned = bob.handle_datagram(SocketAddr::new(alice_ip, 5353), &reply, &[LAN]);
        assert_eq!(learned.peers, vec![(HASH, SocketAddr::new(alice_ip, 6881))]);
        // Hearing it again is not news.
        assert!(bob
            .handle_datagram(SocketAddr::new(alice_ip, 5353), &reply, &[LAN])
            .peers
            .is_empty());
    }

    #[test]
    fn private_torrents_and_unrelated_torrents_are_never_answered_or_learned() {
        let mut m = ZeroconfManager::new([1; 20]);
        m.set_listen_port(6881);
        m.register_torrent(HASH, true);
        assert!(
            m.queries().is_empty(),
            "a private torrent is not asked about"
        );
        assert!(m.announcement(&[LAN]).is_none());
        let ask = dns::build_query(&[dns::sub_service_name(&HASH)]);
        assert!(m
            .handle_datagram(SocketAddr::new(LAN, 5353), &ask, &[LAN])
            .reply
            .is_none());
        // An answer about a torrent we do not share teaches us nothing.
        let other = ZeroconfManager::new([9; 20]);
        let _ = other;
        let answer = dns::build_response(&[3; 20], &[HASH], 6881, &[LAN]);
        assert!(m
            .handle_datagram(SocketAddr::new(LAN, 5353), &answer, &[LAN])
            .peers
            .is_empty());
    }

    #[test]
    fn spoofed_sources_and_third_party_addresses_are_ignored() {
        let mut m = manager(1, 6881);
        // A host may only vouch for its own address.
        let other_host: IpAddr = "192.168.1.99".parse().unwrap();
        let answer = dns::build_response(&[3; 20], &[HASH], 6881, &[other_host]);
        assert!(m
            .handle_datagram(SocketAddr::new(LAN, 5353), &answer, &[LAN])
            .peers
            .is_empty());
        // A public IPv4 source is not on our LAN.
        let public: IpAddr = "8.8.8.8".parse().unwrap();
        let own = dns::build_response(&[3; 20], &[HASH], 6881, &[public]);
        assert!(m
            .handle_datagram(SocketAddr::new(public, 5353), &own, &[LAN])
            .peers
            .is_empty());
        // Our own announcement is ignored.
        let ours = dns::build_response(&[1; 20], &[HASH], 6881, &[LAN]);
        assert!(m
            .handle_datagram(SocketAddr::new(LAN, 5353), &ours, &[LAN])
            .peers
            .is_empty());
    }

    #[test]
    fn a_flooding_source_is_rate_limited() {
        let mut m = manager(1, 6881);
        let junk = [0u8; 12];
        for _ in 0..MAX_PACKETS_PER_SOURCE {
            let _ = m.handle_datagram(SocketAddr::new(LAN, 5353), &junk, &[LAN]);
        }
        let answer = dns::build_response(&[3; 20], &[HASH], 6881, &[LAN]);
        assert!(m
            .handle_datagram(SocketAddr::new(LAN, 5353), &answer, &[LAN])
            .peers
            .is_empty());
    }
}
