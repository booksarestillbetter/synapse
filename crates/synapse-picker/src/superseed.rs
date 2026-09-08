//! Super-Seeding (Initial Seeding) Mode.
//!
//! Minimizes the upload bandwidth required by the initial seeder of a torrent by
//! assigning unique piece hints (`HAVE`) to distinct peers only after they have
//! uploaded their previously assigned pieces to the rest of the swarm.

use std::collections::{HashMap, HashSet};

pub struct SuperSeeder {
    total_pieces: u32,
    assigned_pieces: HashMap<u32, u32>, // peer_id_num -> assigned_piece
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
    pub fn assign_piece_to_peer(&mut self, peer_id_num: u32) -> Option<u32> {
        if self.confirmed_distributed.len() == self.total_pieces as usize {
            // All pieces are distributed to the swarm, normal seeding can resume
            return None;
        }

        if let Some(&already_assigned) = self.assigned_pieces.get(&peer_id_num) {
            return Some(already_assigned);
        }

        // Find a piece that hasn't been confirmed yet
        for _ in 0..self.total_pieces {
            let candidate = self.next_piece_cursor;
            self.next_piece_cursor = (self.next_piece_cursor + 1) % self.total_pieces;

            if !self.confirmed_distributed.contains(&candidate) {
                self.assigned_pieces.insert(peer_id_num, candidate);
                return Some(candidate);
            }
        }

        None
    }

    /// Records when a peer advertises that it has `piece_idx`.
    pub fn on_peer_have(&mut self, reporting_peer: u32, piece_idx: u32) {
        // If someone other than the assigned peer now has the piece, it was successfully distributed
        if let Some(&assigned_peer) = self.assigned_pieces.iter().find(|(_, &p)| p == piece_idx).map(|(k, _)| k) {
            if reporting_peer != assigned_peer {
                self.confirmed_distributed.insert(piece_idx);
                self.assigned_pieces.remove(&assigned_peer);
            }
        }
    }

    /// Removes a disconnected peer from assignments.
    pub fn on_peer_disconnected(&mut self, peer_id_num: u32) {
        self.assigned_pieces.remove(&peer_id_num);
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
        ss.on_peer_have(2, 0);
        assert!(ss.confirmed_distributed.contains(&0));

        // Now Peer 1 can be assigned a new piece (piece 2)
        let p2 = ss.assign_piece_to_peer(1).unwrap();
        assert_eq!(p2, 2);
    }
}
