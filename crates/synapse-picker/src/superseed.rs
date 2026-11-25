//! Super-Seeding (Initial Seeding) Mode.
//!
//! Minimizes the upload bandwidth required by the initial seeder of a torrent by
//! assigning unique piece hints (`HAVE`) to distinct peers only after they have
//! uploaded their previously assigned pieces to the rest of the swarm.

use std::collections::{HashMap, HashSet};

pub struct SuperSeeder {
    total_pieces: u32,
    assigned_pieces: HashMap<u64, u32>, // peer_id -> assigned_piece
    confirmed_distributed: HashSet<u32>,
    next_piece_cursor: u32,
}

impl SuperSeeder {
    pub fn new(total_pieces: u32) -> Self {
        Self {
            total_pieces,
            assigned_pieces: HashMap::new(),
            confirmed_distributed: HashSet::new(),
            next_piece_cursor: 0,
        }
    }

    /// Selects the next unique piece to offer to a peer.
    pub fn assign_piece_to_peer(&mut self, peer_id: u64) -> Option<u32> {
        self.assign_piece_to_peer_filtered(peer_id, |_| false)
    }

    /// Selects the next unique unconfirmed and unassigned piece that `peer_already_has` does not hold.
    pub fn assign_piece_to_peer_filtered<F>(
        &mut self,
        peer_id: u64,
        peer_already_has: F,
    ) -> Option<u32>
    where
        F: Fn(u32) -> bool,
    {
        if self.total_pieces == 0 || self.confirmed_distributed.len() == self.total_pieces as usize
        {
            return None;
        }

        if let Some(&already_assigned) = self.assigned_pieces.get(&peer_id) {
            if !self.confirmed_distributed.contains(&already_assigned)
                && !peer_already_has(already_assigned)
            {
                return Some(already_assigned);
            }
            self.assigned_pieces.remove(&peer_id);
        }

        // Find a piece that is neither confirmed nor currently assigned to another peer.
        for _ in 0..self.total_pieces {
            let candidate = self.next_piece_cursor;
            self.next_piece_cursor = (self.next_piece_cursor + 1) % self.total_pieces;

            if !self.confirmed_distributed.contains(&candidate)
                && !peer_already_has(candidate)
                && !self.assigned_pieces.values().any(|&p| p == candidate)
            {
                self.assigned_pieces.insert(peer_id, candidate);
                return Some(candidate);
            }
        }

        None
    }

    /// Records when a peer advertises that it has `piece_idx`.
    ///
    /// If another peer reports having `piece_idx`, that means the peer previously
    /// assigned to upload `piece_idx` has successfully propagated it. Returns
    /// `Some(freed_peer_id)` of the peer that is now eligible for a new piece assignment.
    pub fn on_peer_have(&mut self, reporting_peer: u64, piece_idx: u32) -> Option<u64> {
        // If someone other than the assigned peer now has the piece, it was successfully distributed
        let assigned_peer = self
            .assigned_pieces
            .iter()
            .find(|(_, &p)| p == piece_idx)
            .map(|(&k, _)| k)?;
        if reporting_peer != assigned_peer {
            self.confirmed_distributed.insert(piece_idx);
            self.assigned_pieces.remove(&assigned_peer);
            Some(assigned_peer)
        } else {
            None
        }
    }

    /// Removes a disconnected peer from assignments.
    pub fn on_peer_disconnected(&mut self, peer_id: u64) {
        self.assigned_pieces.remove(&peer_id);
    }

    pub fn is_fully_distributed(&self) -> bool {
        self.confirmed_distributed.len() == self.total_pieces as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_super_seeding_piece_assignment_and_swarm_propagation() {
        let mut ss = SuperSeeder::new(3);

        // Peer 1 connects, gets piece 0
        let p0 = ss.assign_piece_to_peer(1).unwrap();
        assert_eq!(p0, 0);

        // Peer 2 connects, gets piece 1
        let p1 = ss.assign_piece_to_peer(2).unwrap();
        assert_eq!(p1, 1);

        // Peer 2 tells us it got piece 0 from Peer 1!
        let freed = ss.on_peer_have(2, 0);
        assert_eq!(freed, Some(1));
        assert!(ss.confirmed_distributed.contains(&0));

        // Now Peer 1 can be assigned a new piece (piece 2)
        let p2 = ss.assign_piece_to_peer(1).unwrap();
        assert_eq!(p2, 2);
    }

    #[test]
    fn super_seeder_avoids_double_assignment_and_skips_held_pieces_and_empty_torrents() {
        let mut empty = SuperSeeder::new(0);
        assert_eq!(empty.assign_piece_to_peer(1), None);

        let mut ss = SuperSeeder::new(3);
        let p1 = ss.assign_piece_to_peer(1).unwrap();
        assert_eq!(p1, 0);
        // Peer 2 already holds piece 1, so skip to unassigned piece 2.
        let p2 = ss.assign_piece_to_peer_filtered(2, |idx| idx == 1).unwrap();
        assert_eq!(p2, 2);
        // Peer 3 cannot get 0 or 2 (already assigned to peers 1 and 2); only piece 1 is free.
        let p3 = ss.assign_piece_to_peer(3).unwrap();
        assert_eq!(p3, 1);
        // Peer 4 gets None while all unconfirmed pieces are actively assigned.
        assert_eq!(ss.assign_piece_to_peer(4), None);
    }
}
