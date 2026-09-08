//! File and Piece Priority Manager.
//!
//! Provides granular priority weighting (`DoNotDownload`, `Low`, `Normal`, `High`)
//! across files and piece ranges within a torrent swarm.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum FilePriority {
    DoNotDownload = 0,
    Low = 1,
    Normal = 4,
    High = 7,
}

#[derive(Debug, Clone)]
pub struct PriorityMap {
    total_pieces: u32,
    file_priorities: Vec<FilePriority>,
    piece_priorities: Vec<FilePriority>,
}

impl PriorityMap {
    pub fn new(total_pieces: u32, num_files: usize) -> Self {
        Self {
            total_pieces,
            file_priorities: vec![FilePriority::Normal; num_files],
            piece_priorities: vec![FilePriority::Normal; total_pieces as usize],
        }
    }

    pub fn total_pieces(&self) -> u32 {
        self.total_pieces
    }

    /// Sets the priority for a specific file index, updating overlapping piece priorities.
    pub fn set_file_priority<F>(&mut self, file_idx: usize, priority: FilePriority, piece_mapper: F)
    where
        F: Fn(usize) -> Option<(u32, u32)>,
    {
        if file_idx >= self.file_priorities.len() {
            return;
        }
        self.file_priorities[file_idx] = priority;

        if let Some((start, end)) = piece_mapper(file_idx) {
            for p in start..=end {
                if (p as usize) < self.piece_priorities.len() {
                    self.piece_priorities[p as usize] = priority;
                }
            }
        }
    }

    /// Returns whether a piece is actively wanted (not `DoNotDownload`).
    pub fn is_piece_wanted(&self, piece_idx: u32) -> bool {
        if let Some(&prio) = self.piece_priorities.get(piece_idx as usize) {
            prio > FilePriority::DoNotDownload
        } else {
            false
        }
    }

    /// Returns the priority of a piece.
    pub fn piece_priority(&self, piece_idx: u32) -> FilePriority {
        self.piece_priorities
            .get(piece_idx as usize)
            .copied()
            .unwrap_or(FilePriority::Normal)
    }

    /// Returns all deselected (`DoNotDownload`) piece indices (for BEP 21 Partial Seeds).
    pub fn deselected_pieces(&self) -> Vec<u32> {
        self.piece_priorities
            .iter()
            .enumerate()
            .filter(|(_, &p)| p == FilePriority::DoNotDownload)
            .map(|(idx, _)| idx as u32)
            .collect()
    }

    pub fn file_priorities(&self) -> &[FilePriority] {
        &self.file_priorities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_map_file_and_piece_masking() {
        let mut pmap = PriorityMap::new(10, 2);

        // File 0 maps to pieces 0..=4, File 1 maps to pieces 5..=9
        let mapper = |f| match f {
            0 => Some((0, 4)),
            1 => Some((5, 9)),
            _ => None,
        };

        // Mark file 0 as DoNotDownload
        pmap.set_file_priority(0, FilePriority::DoNotDownload, mapper);
        assert!(!pmap.is_piece_wanted(0));
        assert!(!pmap.is_piece_wanted(4));
        assert!(pmap.is_piece_wanted(5));
        assert!(pmap.is_piece_wanted(9));

        assert_eq!(pmap.deselected_pieces().len(), 5);

        // Mark file 1 as High
        pmap.set_file_priority(1, FilePriority::High, mapper);
        assert_eq!(pmap.piece_priority(5), FilePriority::High);
    }
}
