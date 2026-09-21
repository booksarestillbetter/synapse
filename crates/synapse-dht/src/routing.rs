//! Kademlia routing table.
//!
//! Uses the "bucket index = length of the shared ID prefix with our own id" scheme
//! (160 fixed buckets, one per possible prefix length) rather than literal dynamic
//! bucket splitting/merging - a standard, widely-used simplification (several
//! production Kademlia DHT implementations do the same) that's simpler to implement
//! correctly than a real binary trie with runtime splitting, at the cost of not
//! specially subdividing the region of the ID space nearest to our own id. Good enough
//! for a first cut; revisit only if measurement shows it actually matters.

use std::net::{IpAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};

use crate::proto::{NodeId, NodeInfo, NodeInfoV6};

/// Standard Kademlia bucket size.
pub const K: usize = 8;
/// BEP5: a node that's neither responded to a query nor sent us one in this long is
/// "questionable" rather than "good".
const GOOD_DURATION: Duration = Duration::from_secs(15 * 60);
/// BEP5: a node is "bad" once it fails to respond to this many consecutive queries.
const BAD_AFTER_FAILURES: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Good,
    Questionable,
    Bad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node {
    pub id: NodeId,
    pub addr: SocketAddrV4,
    pub last_seen: Instant,
    pub failed_queries: u32,
    /// Whether `id` is consistent with `addr` under BEP 42 (or the address is exempt).
    /// Verified nodes are preferred when a bucket is full.
    pub verified: bool,
}

impl Node {
    pub fn state(&self, now: Instant) -> NodeState {
        if self.failed_queries >= BAD_AFTER_FAILURES {
            NodeState::Bad
        } else if now.saturating_duration_since(self.last_seen) < GOOD_DURATION {
            NodeState::Good
        } else {
            NodeState::Questionable
        }
    }
}

pub fn xor_distance(a: &NodeId, b: &NodeId) -> [u8; 20] {
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Index of the bucket a node with id `other` belongs in, relative to `ours`: the
/// number of leading bits `other` shares with `ours` (0 = differs in the very first
/// bit - "far" - up to 159 = differs only in the last bit - "close"). Returns 160 for
/// `other == ours` (shouldn't come up in practice - callers should never route our own
/// id into the table).
fn bucket_index(ours: &NodeId, other: &NodeId) -> usize {
    for i in 0..20 {
        let x = ours[i] ^ other[i];
        if x != 0 {
            return i * 8 + x.leading_zeros() as usize;
        }
    }
    160
}

pub struct RoutingTable {
    our_id: NodeId,
    buckets: Vec<Vec<Node>>,
    /// Refuse nodes whose id does not match their address (BEP 42). Off by default: much of
    /// the network predates BEP 42, so enforcing it shrinks the reachable DHT; verified
    /// nodes are merely preferred (as libtorrent's `prefer_verified_node_ids`).
    enforce_node_id: bool,
}

/// The /24 (IPv4) network of `addr`, as a comparable value.
fn slash24(addr: &SocketAddrV4) -> [u8; 3] {
    let o = addr.ip().octets();
    [o[0], o[1], o[2]]
}

impl RoutingTable {
    pub fn new(our_id: NodeId) -> RoutingTable {
        RoutingTable {
            our_id,
            buckets: (0..=160).map(|_| Vec::new()).collect(),
            enforce_node_id: false,
        }
    }

    /// Enables strict BEP 42 enforcement: nodes whose id does not match their (non-exempt)
    /// address are refused outright rather than merely ranked below verified ones.
    pub fn set_enforce_node_id(&mut self, enforce: bool) {
        self.enforce_node_id = enforce;
    }

    pub fn our_id(&self) -> NodeId {
        self.our_id
    }

    /// Records activity from `id`/`addr` (a query or response we just received), either
    /// refreshing an existing entry or inserting a new one if its bucket has room or has
    /// a node it can evict. Returns `true` if the node is now in the table.
    ///
    /// Sybil/eclipse defences (libtorrent's `restrict_routing_ips`, BEP 42), applied to
    /// non-local addresses only so LAN and loopback swarms keep working:
    /// * at most one node per IP address across the whole table, and at most one node per
    ///   /24 within a bucket, so one machine or subnet cannot fill the buckets nearest a
    ///   target with ids it chose;
    /// * an id we already hold cannot be moved to a different IP while the existing entry is
    ///   still good, so a node cannot be hijacked by replaying its id from elsewhere;
    /// * nodes whose id matches their IP under BEP 42 are preferred over those that don't.
    pub fn seen(&mut self, id: NodeId, addr: SocketAddrV4, now: Instant) -> bool {
        if id == self.our_id {
            return false;
        }
        let ip = IpAddr::V4(*addr.ip());
        let exempt = crate::bep42::is_exempt_from_node_id_check(ip);
        let verified = exempt || crate::bep42::verify_secure_node_id(&id, ip);
        if self.enforce_node_id && !verified {
            return false;
        }
        let idx = bucket_index(&self.our_id, &id);

        if let Some(n) = self.buckets[idx].iter_mut().find(|n| n.id == id) {
            if n.addr.ip() != addr.ip() && n.state(now) == NodeState::Good && !exempt {
                return false;
            }
            n.addr = addr;
            n.last_seen = now;
            n.failed_queries = 0;
            n.verified = verified;
            return true;
        }

        if !exempt {
            // One node per IP across the table: a different id from an IP we already have
            // only replaces the old entry if the old one has stopped being good.
            let mut stale_same_ip: Option<(usize, NodeId)> = None;
            for (bi, bucket) in self.buckets.iter().enumerate() {
                for n in bucket {
                    if n.addr.ip() == addr.ip() {
                        if n.state(now) == NodeState::Good {
                            return false;
                        }
                        stale_same_ip = Some((bi, n.id));
                    }
                }
            }
            if let Some((bi, old)) = stale_same_ip {
                self.buckets[bi].retain(|n| n.id != old);
            }
            // One node per /24 within the destination bucket.
            if self.buckets[idx].iter().any(|n| {
                !crate::bep42::is_exempt_from_node_id_check(IpAddr::V4(*n.addr.ip()))
                    && slash24(&n.addr) == slash24(&addr)
            }) {
                return false;
            }
        }

        let new_node = Node {
            id,
            addr,
            last_seen: now,
            failed_queries: 0,
            verified,
        };
        let bucket = &mut self.buckets[idx];
        if bucket.len() < K {
            bucket.push(new_node);
            return true;
        }
        if let Some(pos) = bucket.iter().position(|n| n.state(now) == NodeState::Bad) {
            bucket[pos] = new_node;
            return true;
        }
        // Full of live nodes: a verified newcomer may displace an unverified one that is
        // not currently good, but never a good verified node.
        if verified {
            if let Some(pos) = bucket
                .iter()
                .position(|n| !n.verified && n.state(now) != NodeState::Good)
            {
                bucket[pos] = new_node;
                return true;
            }
        }
        false
    }

    /// Records that a query to `id` went unanswered - after enough of these the node
    /// becomes `Bad` and is eligible for eviction on the next `seen` for its bucket.
    pub fn mark_failed(&mut self, id: &NodeId) {
        let idx = bucket_index(&self.our_id, id);
        if let Some(n) = self.buckets[idx].iter_mut().find(|n| &n.id == id) {
            n.failed_queries += 1;
        }
    }

    pub fn remove(&mut self, id: &NodeId) {
        let idx = bucket_index(&self.our_id, id);
        self.buckets[idx].retain(|n| &n.id != id);
    }

    /// The `count` nodes closest to `target` by XOR distance, across the whole table.
    pub fn closest(&self, target: &NodeId, count: usize) -> Vec<Node> {
        let mut all: Vec<&Node> = self.buckets.iter().flatten().collect();
        all.sort_by_key(|n| xor_distance(&n.id, target));
        all.into_iter().take(count).copied().collect()
    }

    pub fn closest_nodes(&self, target: &NodeId, count: usize) -> Vec<NodeInfo> {
        self.closest(target, count)
            .into_iter()
            .map(|n| NodeInfo {
                id: n.id,
                addr: n.addr,
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Nodes not seen as `Good` recently - candidates for a refresh ping, per BEP5.
    pub fn questionable(&self, now: Instant) -> Vec<Node> {
        self.buckets
            .iter()
            .flatten()
            .filter(|n| n.state(now) == NodeState::Questionable)
            .copied()
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeV6 {
    pub id: NodeId,
    pub addr: SocketAddrV6,
    pub last_seen: Instant,
    pub failed_queries: u32,
    /// Whether `id` is consistent with `addr` under BEP 42 (or the address is exempt).
    pub verified: bool,
}

impl NodeV6 {
    pub fn state(&self, now: Instant) -> NodeState {
        if self.failed_queries >= BAD_AFTER_FAILURES {
            NodeState::Bad
        } else if now.saturating_duration_since(self.last_seen) < GOOD_DURATION {
            NodeState::Good
        } else {
            NodeState::Questionable
        }
    }
}

/// The /64 (IPv6) network of `addr`, as an 8-byte prefix array.
fn slash64(addr: &SocketAddrV6) -> [u8; 8] {
    let o = addr.ip().octets();
    [o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]]
}

pub struct RoutingTableV6 {
    our_id: NodeId,
    buckets: Vec<Vec<NodeV6>>,
    enforce_node_id: bool,
}

impl RoutingTableV6 {
    pub fn new(our_id: NodeId) -> RoutingTableV6 {
        RoutingTableV6 {
            our_id,
            buckets: (0..=160).map(|_| Vec::new()).collect(),
            enforce_node_id: false,
        }
    }

    pub fn set_enforce_node_id(&mut self, enforce: bool) {
        self.enforce_node_id = enforce;
    }

    pub fn our_id(&self) -> NodeId {
        self.our_id
    }

    pub fn seen(&mut self, id: NodeId, addr: SocketAddrV6, now: Instant) -> bool {
        if id == self.our_id {
            return false;
        }
        let ip = IpAddr::V6(*addr.ip());
        let exempt = crate::bep42::is_exempt_from_node_id_check(ip);
        let verified = exempt || crate::bep42::verify_secure_node_id(&id, ip);
        if self.enforce_node_id && !verified {
            return false;
        }
        let idx = bucket_index(&self.our_id, &id);

        if let Some(n) = self.buckets[idx].iter_mut().find(|n| n.id == id) {
            if n.addr.ip() != addr.ip() && n.state(now) == NodeState::Good && !exempt {
                return false;
            }
            n.addr = addr;
            n.last_seen = now;
            n.failed_queries = 0;
            n.verified = verified;
            return true;
        }

        if !exempt {
            let mut stale_same_ip: Option<(usize, NodeId)> = None;
            for (bi, bucket) in self.buckets.iter().enumerate() {
                for n in bucket {
                    if n.addr.ip() == addr.ip() {
                        if n.state(now) == NodeState::Good {
                            return false;
                        }
                        stale_same_ip = Some((bi, n.id));
                    }
                }
            }
            if let Some((bi, old)) = stale_same_ip {
                self.buckets[bi].retain(|n| n.id != old);
            }
            // One node per /64 within the destination bucket.
            if self.buckets[idx].iter().any(|n| {
                !crate::bep42::is_exempt_from_node_id_check(IpAddr::V6(*n.addr.ip()))
                    && slash64(&n.addr) == slash64(&addr)
            }) {
                return false;
            }
        }

        let new_node = NodeV6 {
            id,
            addr,
            last_seen: now,
            failed_queries: 0,
            verified,
        };
        let bucket = &mut self.buckets[idx];
        if bucket.len() < K {
            bucket.push(new_node);
            return true;
        }
        if let Some(pos) = bucket.iter().position(|n| n.state(now) == NodeState::Bad) {
            bucket[pos] = new_node;
            return true;
        }
        if verified {
            if let Some(pos) = bucket
                .iter()
                .position(|n| !n.verified && n.state(now) != NodeState::Good)
            {
                bucket[pos] = new_node;
                return true;
            }
        }
        false
    }

    pub fn mark_failed(&mut self, id: &NodeId) {
        let idx = bucket_index(&self.our_id, id);
        if let Some(n) = self.buckets[idx].iter_mut().find(|n| &n.id == id) {
            n.failed_queries += 1;
        }
    }

    pub fn remove(&mut self, id: &NodeId) {
        let idx = bucket_index(&self.our_id, id);
        self.buckets[idx].retain(|n| &n.id != id);
    }

    pub fn closest(&self, target: &NodeId, count: usize) -> Vec<NodeV6> {
        let mut all: Vec<&NodeV6> = self.buckets.iter().flatten().collect();
        all.sort_by_key(|n| xor_distance(&n.id, target));
        all.into_iter().take(count).copied().collect()
    }

    pub fn closest_nodes6(&self, target: &NodeId, count: usize) -> Vec<NodeInfoV6> {
        self.closest(target, count)
            .into_iter()
            .map(|n| NodeInfoV6 {
                id: n.id,
                addr: n.addr,
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn questionable(&self, now: Instant) -> Vec<NodeV6> {
        self.buckets
            .iter()
            .flatten()
            .filter(|n| n.state(now) == NodeState::Questionable)
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn id_all(b: u8) -> NodeId {
        [b; 20]
    }

    fn addr(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port)
    }

    #[test]
    fn bucket_index_is_0_for_maximally_different_ids() {
        let ours = [0u8; 20];
        let other = [0xFFu8; 20]; // every bit differs, starting from the very first
        assert_eq!(bucket_index(&ours, &other), 0);
    }

    #[test]
    fn bucket_index_is_159_for_ids_differing_only_in_the_last_bit() {
        let ours = [0u8; 20];
        let mut other = [0u8; 20];
        other[19] = 0x01;
        assert_eq!(bucket_index(&ours, &other), 159);
    }

    #[test]
    fn seen_inserts_a_new_node() {
        let mut rt = RoutingTable::new(id_all(0));
        assert!(rt.seen(id_all(1), addr(1), Instant::now()));
        assert_eq!(rt.len(), 1);
    }

    #[test]
    fn seen_refuses_to_insert_our_own_id() {
        let mut rt = RoutingTable::new(id_all(0));
        assert!(!rt.seen(id_all(0), addr(1), Instant::now()));
        assert_eq!(rt.len(), 0);
    }

    #[test]
    fn seen_updates_an_existing_node_in_place() {
        let mut rt = RoutingTable::new(id_all(0));
        let now = Instant::now();
        rt.seen(id_all(1), addr(1), now);
        rt.mark_failed(&id_all(1));
        rt.seen(id_all(1), addr(2), now); // re-seen: should reset failure count + addr
        assert_eq!(rt.len(), 1);
        let closest = rt.closest(&id_all(1), 1);
        assert_eq!(closest[0].addr, addr(2));
        assert_eq!(closest[0].failed_queries, 0);
    }

    #[test]
    fn bucket_full_of_good_nodes_rejects_new_insertions() {
        let mut rt = RoutingTable::new(id_all(0));
        let now = Instant::now();
        // All of these share the same bucket_index (0) since they differ from `ours`
        // in the very first bit but are otherwise varied - fill it to capacity.
        for i in 0..K as u8 {
            let mut node_id = id_all(0);
            node_id[0] = 0x80 | i; // first bit set -> bucket 0, distinct per-node
            assert!(rt.seen(node_id, addr(i as u16), now));
        }
        assert_eq!(rt.len(), K);

        let mut overflow_id = id_all(0);
        overflow_id[0] = 0x80 | (K as u8);
        assert!(
            !rt.seen(overflow_id, addr(99), now),
            "full bucket of good nodes should reject"
        );
        assert_eq!(rt.len(), K);
    }

    #[test]
    fn a_bad_node_is_evicted_to_make_room() {
        let mut rt = RoutingTable::new(id_all(0));
        let now = Instant::now();
        let mut ids = Vec::new();
        for i in 0..K as u8 {
            let mut node_id = id_all(0);
            node_id[0] = 0x80 | i;
            ids.push(node_id);
            rt.seen(node_id, addr(i as u16), now);
        }
        // Fail the first node enough times to make it Bad.
        rt.mark_failed(&ids[0]);
        rt.mark_failed(&ids[0]);

        let mut new_id = id_all(0);
        new_id[0] = 0x80 | (K as u8);
        assert!(rt.seen(new_id, addr(123), now), "should evict the Bad node");
        assert_eq!(rt.len(), K);
        assert!(rt.closest(&new_id, K).iter().any(|n| n.id == new_id));
        assert!(!rt.closest(&ids[0], K).iter().any(|n| n.id == ids[0]));
    }

    #[test]
    fn closest_orders_by_xor_distance() {
        let mut rt = RoutingTable::new(id_all(0));
        let now = Instant::now();
        let near = {
            let mut i = id_all(0);
            i[19] = 0x01;
            i
        };
        let far = id_all(0xFF);
        rt.seen(far, addr(1), now);
        rt.seen(near, addr(2), now);

        let target = id_all(0);
        let closest = rt.closest(&target, 2);
        assert_eq!(closest[0].id, near);
        assert_eq!(closest[1].id, far);
    }

    #[test]
    fn node_state_transitions() {
        let now = Instant::now();
        let fresh = Node {
            id: id_all(1),
            addr: addr(1),
            last_seen: now,
            failed_queries: 0,
            verified: false,
        };
        assert_eq!(fresh.state(now), NodeState::Good);

        let stale = Node {
            last_seen: now - Duration::from_secs(20 * 60),
            ..fresh
        };
        assert_eq!(stale.state(now), NodeState::Questionable);

        let failed = Node {
            failed_queries: 2,
            ..fresh
        };
        assert_eq!(failed.state(now), NodeState::Bad);
    }

    #[test]
    fn questionable_lists_only_stale_nodes() {
        let mut rt = RoutingTable::new(id_all(0));
        let now = Instant::now();
        rt.seen(id_all(1), addr(1), now - Duration::from_secs(20 * 60));
        rt.seen(id_all(2), addr(2), now);
        let stale = rt.questionable(now);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].id, id_all(1));
    }

    #[test]
    fn remove_drops_a_node() {
        let mut rt = RoutingTable::new(id_all(0));
        rt.seen(id_all(1), addr(1), Instant::now());
        assert_eq!(rt.len(), 1);
        rt.remove(&id_all(1));
        assert_eq!(rt.len(), 0);
    }

    // --- Sybil / eclipse defences, exercised with public (non-exempt) addresses ---

    fn pub_addr(a: u8, b: u8, c: u8, d: u8) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), 6881)
    }

    fn id_in_bucket0(n: u8) -> NodeId {
        let mut id = [0u8; 20];
        id[0] = 0x80;
        id[19] = n;
        id
    }

    #[test]
    fn one_node_per_ip_across_the_table() {
        let mut rt = RoutingTable::new(id_all(0));
        let now = Instant::now();
        assert!(rt.seen(id_in_bucket0(1), pub_addr(8, 8, 8, 8), now));
        // Same IP, different id (a second identity from one machine) is refused.
        assert!(!rt.seen(id_in_bucket0(2), pub_addr(8, 8, 8, 8), now));
        assert_eq!(rt.len(), 1);
        // Once the first stops being good, the new identity may take its place.
        let later = now + Duration::from_secs(20 * 60);
        assert!(rt.seen(id_in_bucket0(2), pub_addr(8, 8, 8, 8), later));
        assert_eq!(rt.len(), 1);
        assert_eq!(rt.closest(&id_all(0), 1)[0].id, id_in_bucket0(2));
    }

    #[test]
    fn one_node_per_slash24_within_a_bucket() {
        let mut rt = RoutingTable::new(id_all(0));
        let now = Instant::now();
        assert!(rt.seen(id_in_bucket0(1), pub_addr(9, 9, 9, 1), now));
        assert!(
            !rt.seen(id_in_bucket0(2), pub_addr(9, 9, 9, 2), now),
            "same /24, same bucket"
        );
        assert!(
            rt.seen(id_in_bucket0(3), pub_addr(9, 9, 10, 2), now),
            "different /24 is fine"
        );
        // Same /24 in a *different* bucket is allowed.
        let mut other_bucket = [0u8; 20];
        other_bucket[0] = 0x40;
        assert!(rt.seen(other_bucket, pub_addr(9, 9, 9, 3), now));
    }

    #[test]
    fn an_id_cannot_be_moved_to_another_ip_while_the_existing_entry_is_good() {
        let mut rt = RoutingTable::new(id_all(0));
        let now = Instant::now();
        assert!(rt.seen(id_in_bucket0(1), pub_addr(8, 8, 4, 4), now));
        assert!(
            !rt.seen(id_in_bucket0(1), pub_addr(1, 2, 3, 4), now),
            "hijack attempt"
        );
        assert_eq!(rt.closest(&id_all(0), 1)[0].addr, pub_addr(8, 8, 4, 4));
        // But the node may move once it has gone quiet.
        assert!(rt.seen(
            id_in_bucket0(1),
            pub_addr(1, 2, 3, 4),
            now + Duration::from_secs(20 * 60)
        ));
    }

    #[test]
    fn local_addresses_are_exempt_from_the_ip_restrictions() {
        let mut rt = RoutingTable::new(id_all(0));
        let now = Instant::now();
        assert!(rt.seen(
            id_in_bucket0(1),
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 5), 1),
            now
        ));
        assert!(rt.seen(
            id_in_bucket0(2),
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 5), 2),
            now
        ));
        assert_eq!(rt.len(), 2);
    }

    #[test]
    fn enforcement_refuses_unverified_ids_and_accepts_verified_ones() {
        let ip = Ipv4Addr::new(124, 31, 75, 21);
        let good = crate::bep42::generate_secure_node_id(IpAddr::V4(ip), 1);
        let bad = [0x33u8; 20];
        let mut rt = RoutingTable::new(id_all(0xAA));
        rt.set_enforce_node_id(true);
        let now = Instant::now();
        assert!(!rt.seen(bad, SocketAddrV4::new(ip, 1), now));
        assert!(rt.seen(good, SocketAddrV4::new(ip, 1), now));
        // Without enforcement an unverified id is still accepted.
        let mut lax = RoutingTable::new(id_all(0xAA));
        assert!(lax.seen(bad, SocketAddrV4::new(ip, 1), now));
    }

    #[test]
    fn a_verified_node_displaces_a_stale_unverified_one_in_a_full_bucket() {
        let newcomer_ip = Ipv4Addr::new(124, 31, 75, 21);
        let verified_id = crate::bep42::generate_secure_node_id(IpAddr::V4(newcomer_ip), 1);
        // Choose our id so the verified id falls in bucket 0 (differs in the first bit).
        let mut ours = [0u8; 20];
        ours[0] = verified_id[0] ^ 0x80;
        let mut rt = RoutingTable::new(ours);
        let t0 = Instant::now();
        let first_bit = verified_id[0] & 0x80;

        // Fill bucket 0 with unverified public nodes from distinct /24s.
        for i in 0..K as u8 {
            let mut id = [0u8; 20];
            id[0] = first_bit | 0x01;
            id[19] = i;
            assert!(rt.seen(id, pub_addr(20 + i, 1, 1, 1), t0));
        }
        // While they are all good, even a verified newcomer is refused...
        assert!(!rt.seen(verified_id, SocketAddrV4::new(newcomer_ip, 6881), t0));
        // ...but once they have gone stale it takes one of their places.
        let later = t0 + Duration::from_secs(20 * 60);
        assert!(rt.seen(verified_id, SocketAddrV4::new(newcomer_ip, 6881), later));
        assert!(rt.closest(&verified_id, 1)[0].verified);
        assert_eq!(rt.len(), K);
    }

    #[test]
    fn test_routing_table_v6_basic_and_slash64_limit() {
        use std::net::Ipv6Addr;
        let ours = [0u8; 20];
        let mut rt = RoutingTableV6::new(ours);
        let now = Instant::now();

        let id1 = {
            let mut id = [0u8; 20];
            id[0] = 0x80;
            id[19] = 1;
            id
        };
        let addr1 = SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 1, 1, 0, 0, 0, 1), 6881, 0, 0);
        assert!(rt.seen(id1, addr1, now));
        assert_eq!(rt.len(), 1);

        // Same /64 prefix (first 4 segments: 2001:db8:1:1):
        let id2 = {
            let mut id = [0u8; 20];
            id[0] = 0x80;
            id[19] = 2;
            id
        };
        let addr2 = SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 1, 1, 0, 0, 0, 2), 6881, 0, 0);
        assert!(
            !rt.seen(id2, addr2, now),
            "Second node from same /64 in same bucket should be rejected"
        );

        // Different /64 prefix (2001:db8:1:2):
        let addr3 = SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1), 6881, 0, 0);
        assert!(
            rt.seen(id2, addr3, now),
            "Node from different /64 should be accepted"
        );
        assert_eq!(rt.len(), 2);

        let closest = rt.closest_nodes6(&ours, 10);
        assert_eq!(closest.len(), 2);
    }
}
