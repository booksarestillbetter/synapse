//! Part-File storage for boundary pieces overlapping unselected (priority 0) files.
//!
//! Libtorrent parity: When some files in a multi-file torrent are unselected (priority 0),
//! piece boundaries frequently cross file edges. Writing to unselected files would allocate
//! or touch them on disk. The `PartFileManager` redirects slices belonging to priority-0
//! files into a single compact `.synapse_part` file.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// `(file index, offset in file)` -> `(length, offset in the part file)`.
type SliceMap = BTreeMap<(usize, u64), (u64, u64)>;

/// Manages boundary piece redirection for unselected files into a single `.synapse_part` file.
#[derive(Debug, Clone)]
pub struct PartFileManager {
    download_dir: PathBuf,
    part_file_path: PathBuf,
    map_path: PathBuf,
    unwanted_files: HashSet<usize>,
    /// (file_idx, slice start within the file) -> (slice length, offset in the part file).
    /// Ordered so a read of *any* byte inside a slice (a block is smaller than the piece slice
    /// that was written) can find the slice that contains it.
    slices: SliceMap,
    next_part_offset: u64,
}

impl PartFileManager {
    pub fn new(download_dir: PathBuf, info_hash: [u8; 20]) -> Self {
        let hex_hash = hex::encode(info_hash);
        let part_file_path = download_dir.join(format!(".synapse_part_{hex_hash}"));
        let map_path = download_dir.join(format!(".synapse_part_{hex_hash}.map"));
        let (slices, next_part_offset) = Self::load_map(&map_path);
        Self {
            download_dir,
            part_file_path,
            map_path,
            unwanted_files: HashSet::new(),
            slices,
            next_part_offset,
        }
    }

    /// Reads the saved slice map, if any. A missing or unreadable map is treated as empty (the
    /// pieces it described are then re-downloaded), never as an error.
    fn load_map(path: &Path) -> (SliceMap, u64) {
        let Ok(bytes) = std::fs::read(path) else {
            return (BTreeMap::new(), 0);
        };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return (BTreeMap::new(), 0);
        };
        let next = v["next"].as_u64().unwrap_or(0);
        let mut slices = BTreeMap::new();
        for e in v["slices"].as_array().into_iter().flatten() {
            if let (Some(f), Some(start), Some(len), Some(off)) =
                (e[0].as_u64(), e[1].as_u64(), e[2].as_u64(), e[3].as_u64())
            {
                slices.insert((f as usize, start), (len, off));
            }
        }
        (slices, next)
    }

    /// Saves the slice map (atomically) so a restart can find the data in the part file again.
    /// Removes the map and the part file when nothing is left in them.
    fn persist(&self) {
        if self.slices.is_empty() {
            let _ = std::fs::remove_file(&self.map_path);
            let _ = std::fs::remove_file(&self.part_file_path);
            return;
        }
        let entries: Vec<serde_json::Value> = self
            .slices
            .iter()
            .map(|(&(f, start), &(len, off))| serde_json::json!([f, start, len, off]))
            .collect();
        let doc = serde_json::json!({ "next": self.next_part_offset, "slices": entries });
        let tmp = self.map_path.with_extension("map.tmp");
        if std::fs::write(&tmp, doc.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, &self.map_path);
        }
    }

    /// Deletes the part file and slice map a torrent left in `download_dir`, if any.
    pub fn remove_files(download_dir: &Path, info_hash: &[u8; 20]) {
        let hex_hash = hex::encode(info_hash);
        let _ = std::fs::remove_file(download_dir.join(format!(".synapse_part_{hex_hash}")));
        let _ = std::fs::remove_file(download_dir.join(format!(".synapse_part_{hex_hash}.map")));
    }

    /// Whether the part file holds every byte of `[offset, offset + len)` of `file_idx`.
    pub fn covers(&self, file_idx: usize, offset: u64, len: u64) -> bool {
        let end = offset + len;
        let mut cursor = offset;
        // Blocks are stored one slice each, so a piece's bytes usually span several adjacent ones.
        while cursor < end {
            match self.slices.range(..=(file_idx, cursor)).next_back() {
                Some((&(idx, start), &(slen, _))) if idx == file_idx && cursor < start + slen => {
                    cursor = start + slen;
                }
                _ => return false,
            }
        }
        true
    }

    /// File indices that have data stored in the part file.
    pub fn files_with_slices(&self) -> Vec<usize> {
        let mut v: Vec<usize> = self.slices.keys().map(|&(f, _)| f).collect();
        v.dedup();
        v
    }

    /// Sets or updates the priority of a file.
    /// Priority 0 indicates unwanted/skipped.
    pub fn set_file_priority(&mut self, file_idx: usize, priority: u8) {
        if priority == 0 {
            self.unwanted_files.insert(file_idx);
        } else {
            self.unwanted_files.remove(&file_idx);
        }
    }

    pub fn is_unwanted(&self, file_idx: usize) -> bool {
        self.unwanted_files.contains(&file_idx)
    }

    pub fn has_unwanted_files(&self) -> bool {
        !self.unwanted_files.is_empty()
    }

    pub fn download_dir(&self) -> &Path {
        &self.download_dir
    }

    pub fn part_file_path(&self) -> &Path {
        &self.part_file_path
    }

    /// Resolves target path and offset for writing a slice.
    /// If the target file is unselected, redirects to the part file.
    pub fn resolve_write_location(
        &mut self,
        file_idx: usize,
        file_offset: u64,
        slice_len: usize,
        normal_path: PathBuf,
    ) -> (PathBuf, u64, u64) {
        if self.is_unwanted(file_idx) {
            let before = self.slices.len();
            let part_offset = self
                .slices
                .entry((file_idx, file_offset))
                .and_modify(|(len, _)| *len = (*len).max(slice_len as u64))
                .or_insert_with(|| {
                    let off = self.next_part_offset;
                    self.next_part_offset += slice_len as u64;
                    (slice_len as u64, off)
                })
                .1;
            if self.slices.len() != before {
                self.persist();
            }
            (
                self.part_file_path.clone(),
                part_offset,
                self.next_part_offset,
            )
        } else {
            (normal_path, file_offset, 0)
        }
    }

    /// Resolves target path and offset for reading `file_offset` of a file. If that byte was
    /// redirected to the part file, returns the part-file coordinates; a block read from the
    /// middle of a stored slice maps to the same relative position inside it.
    pub fn resolve_read_location(
        &self,
        file_idx: usize,
        file_offset: u64,
        normal_path: PathBuf,
    ) -> (PathBuf, u64) {
        // Not gated on `is_unwanted`: a stored slice is the only copy of its bytes until the file
        // is migrated, so it must stay readable whatever the file's priority is right now.
        if let Some((&(idx, start), &(len, part_off))) =
            self.slices.range(..=(file_idx, file_offset)).next_back()
        {
            if idx == file_idx && file_offset < start + len {
                return (
                    self.part_file_path.clone(),
                    part_off + (file_offset - start),
                );
            }
        }
        (normal_path, file_offset)
    }

    /// Every stored slice of `file_idx` as `(offset in the file, length, offset in the part file)`.
    pub fn slices_for_file(&self, file_idx: usize) -> Vec<(u64, u64, u64)> {
        self.slices
            .range((file_idx, 0)..=(file_idx, u64::MAX))
            .map(|(&(_, start), &(len, part_off))| (start, len, part_off))
            .collect()
    }

    /// Forgets the part-file mapping of `file_idx` once its data has been moved into the real
    /// file (the part-file bytes are simply left behind, unreferenced).
    pub fn forget_file(&mut self, file_idx: usize) {
        self.slices.retain(|&(idx, _), _| idx != file_idx);
        self.persist();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_part_file_redirection_and_isolation() {
        let temp = tempfile::tempdir().unwrap();
        let hash = [0xab; 20];
        let mut pfm = PartFileManager::new(temp.path().to_path_buf(), hash);

        // File 0 is wanted, File 1 is unwanted
        pfm.set_file_priority(0, 4);
        pfm.set_file_priority(1, 0);

        assert!(!pfm.is_unwanted(0));
        assert!(pfm.is_unwanted(1));

        let normal_path0 = temp.path().join("file0.bin");
        let normal_path1 = temp.path().join("file1.bin");

        // Wanted file routes to normal path
        let (path0, off0, _) = pfm.resolve_write_location(0, 1024, 4096, normal_path0.clone());
        assert_eq!(path0, normal_path0);
        assert_eq!(off0, 1024);

        // Unwanted file routes to part file
        let (path1, off1, part_len) = pfm.resolve_write_location(1, 0, 4096, normal_path1.clone());
        assert_eq!(path1, pfm.part_file_path());
        assert_eq!(off1, 0);
        assert_eq!(part_len, 4096);

        // Subsequent read routes to part file
        let (read_path, read_off) = pfm.resolve_read_location(1, 0, normal_path1.clone());
        assert_eq!(read_path, pfm.part_file_path());
        assert_eq!(read_off, 0);
    }

    #[test]
    fn a_block_read_from_inside_a_stored_slice_finds_its_bytes_and_neighbours_do_not_leak() {
        let temp = tempfile::tempdir().unwrap();
        let mut pfm = PartFileManager::new(temp.path().to_path_buf(), [1; 20]);
        pfm.set_file_priority(1, 0);
        let normal = temp.path().join("f1");
        // Two pieces' worth of slices for file 1: bytes 32768..49152 and 49152..53248.
        let (_, a, _) = pfm.resolve_write_location(1, 32768, 16384, normal.clone());
        let (_, b, _) = pfm.resolve_write_location(1, 49152, 4096, normal.clone());
        assert_eq!((a, b), (0, 16384));

        // A 4 KiB block in the middle of the first slice.
        assert_eq!(
            pfm.resolve_read_location(1, 32768 + 8192, normal.clone()),
            (pfm.part_file_path().to_path_buf(), 8192)
        );
        // The very last byte of the first slice, and the first byte of the second.
        assert_eq!(pfm.resolve_read_location(1, 49151, normal.clone()).1, 16383);
        assert_eq!(pfm.resolve_read_location(1, 49152, normal.clone()).1, 16384);
        // Outside any slice, or in another file: the normal path.
        assert_eq!(
            pfm.resolve_read_location(1, 53248, normal.clone()).0,
            normal
        );
        assert_eq!(pfm.resolve_read_location(1, 100, normal.clone()).0, normal);
        assert_eq!(
            pfm.resolve_read_location(2, 32768, temp.path().join("f2"))
                .0,
            temp.path().join("f2")
        );
    }

    #[test]
    fn slices_can_be_listed_for_migration_and_then_forgotten() {
        let temp = tempfile::tempdir().unwrap();
        let mut pfm = PartFileManager::new(temp.path().to_path_buf(), [2; 20]);
        pfm.set_file_priority(3, 0);
        pfm.resolve_write_location(3, 0, 100, temp.path().join("f3"));
        pfm.resolve_write_location(3, 100, 50, temp.path().join("f3"));
        assert_eq!(pfm.slices_for_file(3), vec![(0, 100, 0), (100, 50, 100)]);
        assert!(pfm.slices_for_file(4).is_empty());
        pfm.forget_file(3);
        assert!(pfm.slices_for_file(3).is_empty());
    }

    #[test]
    fn the_slice_map_survives_a_restart_and_covers_adjacent_blocks() {
        let temp = tempfile::tempdir().unwrap();
        let hash = [7; 20];
        {
            let mut pfm = PartFileManager::new(temp.path().to_path_buf(), hash);
            pfm.set_file_priority(1, 0);
            let f = temp.path().join("f1");
            pfm.resolve_write_location(1, 0, 16384, f.clone());
            pfm.resolve_write_location(1, 16384, 4000, f);
        }
        let mut pfm = PartFileManager::new(temp.path().to_path_buf(), hash);
        assert_eq!(
            pfm.slices_for_file(1),
            vec![(0, 16384, 0), (16384, 4000, 16384)]
        );
        // Reads find the data even before the file's priority is re-applied.
        assert_eq!(
            pfm.resolve_read_location(1, 100, temp.path().join("f1")).1,
            100
        );
        assert!(pfm.covers(1, 0, 20384));
        assert!(pfm.covers(1, 10_000, 8_000));
        assert!(!pfm.covers(1, 0, 20385));
        assert!(!pfm.covers(2, 0, 1));
        // New slices continue after the old ones instead of overwriting them.
        pfm.set_file_priority(1, 0);
        let (_, off, _) = pfm.resolve_write_location(1, 50_000, 10, temp.path().join("f1"));
        assert_eq!(off, 20384);
        // Migrating everything out removes the map and the part file.
        std::fs::write(pfm.part_file_path(), b"x").unwrap();
        pfm.forget_file(1);
        let map = temp
            .path()
            .join(format!(".synapse_part_{}.map", hex::encode(hash)));
        assert!(!map.exists() && !pfm.part_file_path().exists());
        assert!(PartFileManager::new(temp.path().to_path_buf(), hash)
            .slices_for_file(1)
            .is_empty());
    }
}
