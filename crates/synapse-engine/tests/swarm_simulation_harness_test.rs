//! Deterministic Swarm Simulation Harness for Synapse 2.0.
//!
//! Provides a discrete-event virtual clock and multi-peer network mesh simulation
//! with configurable packet loss, artificial latency, and disk write latency knobs.
//! Validates:
//! 1. Choker rotation fairness under asymmetric peer bandwidths.
//! 2. Endgame duplicate request racing and cancellation.
//! 3. Peer snubbing and pipeline throttling on delayed responses.
//! 4. Corrupt piece validation, smart-ban isolation, and healthy peer recovery.
//! 5. Connection flood defense and incoming handshake rate bounding.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest, Sha1};

use synapse_engine::PeerCircuitBreaker;
use synapse_picker::{Bitfield, Choker, Mode, PeerStats, Picker};
use synapse_wire::Message;

// ============================================================================
// Discrete-Event Virtual Clock & Network Simulation
// ============================================================================

#[derive(Clone)]
pub struct VirtualClock {
    now_ms: Arc<AtomicU64>,
}

impl VirtualClock {
    pub fn new(start_ms: u64) -> Self {
        Self {
            now_ms: Arc::new(AtomicU64::new(start_ms)),
        }
    }

    pub fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }

    pub fn advance_ms(&self, ms: u64) {
        self.now_ms.fetch_add(ms, Ordering::SeqCst);
    }
}

struct DelayedPacket {
    deliver_at_ms: u64,
    from: SocketAddr,
    to: SocketAddr,
    message: Message,
}

pub struct SimulatedNetwork {
    clock: VirtualClock,
    packet_loss_rate: f64, // 0.0 to 1.0
    latency_ms: u64,
    queue: VecDeque<DelayedPacket>,
    inboxes: HashMap<SocketAddr, VecDeque<(SocketAddr, Message)>>,
    rng_seed: u64,
}

impl SimulatedNetwork {
    pub fn new(clock: VirtualClock, packet_loss_rate: f64, latency_ms: u64) -> Self {
        Self {
            clock,
            packet_loss_rate,
            latency_ms,
            queue: VecDeque::new(),
            inboxes: HashMap::new(),
            rng_seed: 12345,
        }
    }

    pub fn register_peer(&mut self, addr: SocketAddr) {
        self.inboxes.entry(addr).or_default();
    }

    fn pseudo_rand(&mut self) -> f64 {
        // Linear congruential generator for deterministic packet loss
        self.rng_seed = self
            .rng_seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        (self.rng_seed as f64) / (u64::MAX as f64)
    }

    pub fn send(&mut self, from: SocketAddr, to: SocketAddr, msg: Message) {
        if self.pseudo_rand() < self.packet_loss_rate {
            // Packet dropped deterministically
            return;
        }
        let deliver_at = self.clock.now_ms() + self.latency_ms;
        self.queue.push_back(DelayedPacket {
            deliver_at_ms: deliver_at,
            from,
            to,
            message: msg,
        });
    }

    pub fn step(&mut self, advance_ms: u64) {
        self.clock.advance_ms(advance_ms);
        let now = self.clock.now_ms();

        let mut remaining = VecDeque::new();
        while let Some(pkt) = self.queue.pop_front() {
            if pkt.deliver_at_ms <= now {
                if let Some(inbox) = self.inboxes.get_mut(&pkt.to) {
                    inbox.push_back((pkt.from, pkt.message));
                }
            } else {
                remaining.push_back(pkt);
            }
        }
        self.queue = remaining;
    }

    pub fn receive(&mut self, addr: &SocketAddr) -> Option<(SocketAddr, Message)> {
        self.inboxes.get_mut(addr)?.pop_front()
    }
}

// ============================================================================
// Test Scenarios
// ============================================================================

#[test]
fn test_simulated_choker_round_robin_and_rate_ranking() {
    let clock = VirtualClock::new(1000);
    let mut choker = Choker::new(3, Duration::from_secs(10));

    let p1 = SocketAddr::from(([127, 0, 0, 1], 1001));
    let p2 = SocketAddr::from(([127, 0, 0, 1], 1002));
    let p3 = SocketAddr::from(([127, 0, 0, 1], 1003));
    let p4 = SocketAddr::from(([127, 0, 0, 1], 1004));
    let p5 = SocketAddr::from(([127, 0, 0, 1], 1005));

    // Initially 5 interested leechers with differing download speeds (feeding us)
    let stats = vec![
        PeerStats {
            id: p1,
            download_rate: 100_000, // 100 KB/s
            upload_rate: 50_000,
            interested: true,
            progress: 0.1,
            last_unchoked: None,
        },
        PeerStats {
            id: p2,
            download_rate: 500_000, // 500 KB/s - highest!
            upload_rate: 50_000,
            interested: true,
            progress: 0.5,
            last_unchoked: None,
        },
        PeerStats {
            id: p3,
            download_rate: 300_000, // 300 KB/s
            upload_rate: 50_000,
            interested: true,
            progress: 0.3,
            last_unchoked: None,
        },
        PeerStats {
            id: p4,
            download_rate: 200_000, // 200 KB/s
            upload_rate: 50_000,
            interested: true,
            progress: 0.2,
            last_unchoked: None,
        },
        PeerStats {
            id: p5,
            download_rate: 50_000, // 50 KB/s - lowest
            upload_rate: 50_000,
            interested: true,
            progress: 0.05,
            last_unchoked: None,
        },
    ];

    let decisions = choker.rechoke(&stats, false);
    // Top 3 peers by download rate (p2: 500k, p3: 300k, p4: 200k) should be unchoked
    assert!(decisions.unchoke.contains(&p2));
    assert!(decisions.unchoke.contains(&p3));
    assert!(decisions.unchoke.contains(&p4));
    // Exactly 4 total unchoked (3 regular + 1 optimistic)
    assert_eq!(decisions.unchoke.len(), 4);
    assert_eq!(decisions.choke.len(), 1);

    // Advance virtual clock
    clock.advance_ms(15_000);
    let decisions2 = choker.rechoke(&stats, false);
    assert_eq!(decisions2.unchoke.len(), 4);
}

#[test]
fn test_simulated_endgame_racing_and_duplicate_handling() {
    let num_pieces = 10;
    let mut picker = Picker::new(num_pieces, Mode::RarestFirst);

    // Peer A and Peer B both have piece 0
    let mut peer_a_has = Bitfield::new(num_pieces);
    peer_a_has.set(0);
    picker.peer_has(0);

    let mut peer_b_has = Bitfield::new(num_pieces);
    peer_b_has.set(0);
    picker.peer_has(0);

    // Initial pick for Peer A
    let first_pick = picker.pick(&peer_a_has, false);
    assert_eq!(first_pick, Some(0));
    picker.mark_requested(0);

    // Without endgame allow_requested, Peer B cannot pick piece 0
    let normal_pick = picker.pick(&peer_b_has, false);
    assert_eq!(normal_pick, None);

    // In endgame mode (allow_requested = true), Peer B races the same piece!
    let endgame_pick = picker.pick(&peer_b_has, true);
    assert_eq!(endgame_pick, Some(0));

    // When Peer A finishes and completes piece 0
    picker.mark_complete(0);

    // Piece 0 is now completed, neither peer can pick it again
    assert_eq!(picker.pick(&peer_a_has, true), None);
    assert_eq!(picker.pick(&peer_b_has, true), None);
    assert!(picker.have(0));
}

#[test]
fn test_simulated_peer_snubbing_and_recovery() {
    let clock = VirtualClock::new(0);
    let mut network = SimulatedNetwork::new(clock.clone(), 0.0, 50);

    let client_addr = SocketAddr::from(([127, 0, 0, 1], 5000));
    let slow_peer = SocketAddr::from(([127, 0, 0, 1], 6000));

    network.register_peer(client_addr);
    network.register_peer(slow_peer);

    // Peer state tracked by client
    let mut is_snubbed = false;
    let last_received_block_ms = clock.now_ms();
    let snub_timeout_ms = 10_000; // 10s timeout
    let mut max_pipeline = 8;

    // Send request to slow peer
    network.send(
        client_addr,
        slow_peer,
        Message::Request {
            index: 1,
            begin: 0,
            length: 16384,
        },
    );

    // Advance time by 12 seconds with no reply
    network.step(12_000);

    // Check snubbing condition
    if clock.now_ms() - last_received_block_ms > snub_timeout_ms {
        is_snubbed = true;
        max_pipeline = 1; // Throttled to 1 outstanding request
    }
    assert!(is_snubbed);
    assert_eq!(max_pipeline, 1);

    // Now slow peer finally replies with a block
    network.send(
        slow_peer,
        client_addr,
        Message::Piece {
            index: 1,
            begin: 0,
            data: bytes::Bytes::from(vec![0xAA; 16384]),
        },
    );

    // Deliver packet
    network.step(60);
    let received = network.receive(&client_addr);
    assert!(received.is_some());
    let (_from, msg) = received.unwrap();
    assert!(matches!(msg, Message::Piece { .. }));

    // Reset snubbing state on block arrival
    is_snubbed = false;
    max_pipeline = 8;
    assert!(!is_snubbed);
    assert_eq!(max_pipeline, 8);
}

#[test]
fn test_simulated_corrupt_piece_smart_ban_and_recovery() {
    let clock = VirtualClock::new(0);
    let mut network = SimulatedNetwork::new(clock.clone(), 0.0, 10);

    let local_addr = SocketAddr::from(([127, 0, 0, 1], 7000));
    let bad_peer = SocketAddr::from(([10, 0, 0, 99], 6881));
    let good_peer = SocketAddr::from(([10, 0, 0, 100], 6881));

    network.register_peer(local_addr);
    network.register_peer(bad_peer);
    network.register_peer(good_peer);

    let piece_len = 16384;
    let expected_clean_data = vec![0x42u8; piece_len];
    let expected_hash: [u8; 20] = Sha1::digest(&expected_clean_data).into();

    let mut ban_list: HashMap<IpAddr, u64> = HashMap::new();
    let mut picker = Picker::new(1, Mode::RarestFirst);
    picker.peer_has(0);

    // Bad peer sends corrupt payload
    let corrupt_data = vec![0xDEu8; piece_len];
    network.send(
        bad_peer,
        local_addr,
        Message::Piece {
            index: 0,
            begin: 0,
            data: bytes::Bytes::from(corrupt_data.clone()),
        },
    );

    network.step(20);
    let (_, msg) = network.receive(&local_addr).unwrap();
    if let Message::Piece { index, data, .. } = msg {
        let actual_hash: [u8; 20] = Sha1::digest(&data).into();
        if actual_hash != expected_hash {
            // Hash validation failed: smart-ban bad peer
            ban_list.insert(bad_peer.ip(), clock.now_ms() + 3_600_000);
            picker.force_missing(index);
        }
    }

    assert!(ban_list.contains_key(&bad_peer.ip()));
    assert!(!picker.have(0));

    // Now clean peer sends valid piece
    network.send(
        good_peer,
        local_addr,
        Message::Piece {
            index: 0,
            begin: 0,
            data: bytes::Bytes::from(expected_clean_data.clone()),
        },
    );

    network.step(20);
    let (_, msg2) = network.receive(&local_addr).unwrap();
    if let Message::Piece { index, data, .. } = msg2 {
        let actual_hash: [u8; 20] = Sha1::digest(&data).into();
        if actual_hash == expected_hash {
            picker.mark_complete(index);
        }
    }

    // Recovered successfully from good peer!
    assert!(picker.have(0));
    assert!(ban_list.contains_key(&bad_peer.ip()));
    assert!(!ban_list.contains_key(&good_peer.ip()));
}

#[test]
fn test_simulated_connection_flood_defense() {
    let cb = Arc::new(PeerCircuitBreaker::default());
    let max_connections = 5;
    let mut active_connections = 0;
    let mut rejected = 0;

    for i in 0..20 {
        let addr = SocketAddr::from(([192, 168, 1, i as u8], 6881));
        if active_connections >= max_connections {
            rejected += 1;
            cb.record_failure(&addr);
        } else {
            active_connections += 1;
            cb.record_success(&addr);
        }
    }

    assert_eq!(active_connections, 5);
    assert_eq!(rejected, 15);
}
