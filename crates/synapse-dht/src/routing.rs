//! Kademlia routing table.
//!
//! Uses the "bucket index = length of the shared ID prefix with our own id" scheme
//! (160 fixed buckets, one per possible prefix length) rather than literal dynamic
//! bucket splitting/merging - a standard, widely-used simplification (several
//! production Kademlia DHT implementations do the same) that's simpler to implement
//! correctly than a real binary trie with runtime splitting, at the cost of not
//! specially subdividing the region of the ID space nearest to our own id. Good enough
//! for a first cut; revisit only if measurement shows it actually matters.

use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use crate::proto::NodeId;

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
}

impl RoutingTable {
    pub fn new(our_id: NodeId) -> RoutingTable {
        RoutingTable {
            our_id,
            buckets: (0..=160).map(|_| Vec::new()).collect(),
        }
    }

    pub fn our_id(&self) -> NodeId {
        self.our_id
    }

    /// Records activity from `id`/`addr` (a query or response we just received), either
    /// refreshing an existing entry or inserting a new one if its bucket has room or has
    /// a `Bad` node to evict. Returns `true` if the node is now in the table.
    pub fn seen(&mut self, id: NodeId, addr: SocketAddrV4, now: Instant) -> bool {
        if id == self.our_id {
            return false;
        }
        let idx = bucket_index(&self.our_id, &id);
        let bucket = &mut self.buckets[idx];

        if let Some(n) = bucket.iter_mut().find(|n| n.id == id) {
            n.addr = addr;
            n.last_seen = now;
            n.failed_queries = 0;
            return true;
        }
        if bucket.len() < K {
            bucket.push(Node {
                id,
                addr,
                last_seen: now,
                failed_queries: 0,
            });
            return true;
        }
        if let Some(pos) = bucket.iter().position(|n| n.state(now) == NodeState::Bad) {
            bucket[pos] = Node {
                id,
                addr,
                last_seen: now,
                failed_queries: 0,
            };
            return true;
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
        assert!(!rt.seen(overflow_id, addr(99), now), "full bucket of good nodes should reject");
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
}
