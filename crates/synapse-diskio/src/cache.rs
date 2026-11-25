use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenMode {
    ReadOnly,
    Write { file_len: u64 },
}

struct Entry {
    path: PathBuf,
    file: Arc<File>,
    writable: bool,
    preallocated_len: u64,
    used: bool,
}

struct CacheInner {
    max_open: usize,
    slots: Vec<Option<Entry>>,
    index: HashMap<PathBuf, usize>,
    clock_hand: usize,
    evict_gen: u64,
}

impl CacheInner {
    fn new(max_open: usize) -> Self {
        Self {
            max_open,
            slots: Vec::with_capacity(max_open.min(1024)),
            index: HashMap::with_capacity(max_open.min(1024)),
            clock_hand: 0,
            evict_gen: 0,
        }
    }

    fn get_mut(&mut self, path: &Path) -> Option<&mut Entry> {
        let idx = *self.index.get(path)?;
        self.slots.get_mut(idx)?.as_mut()
    }

    fn insert_or_replace(&mut self, path: PathBuf, entry: Entry) {
        if self.max_open == 0 {
            return;
        }
        if let Some(&idx) = self.index.get(&path) {
            self.slots[idx] = Some(entry);
            return;
        }
        if self.slots.len() < self.max_open {
            let idx = self.slots.len();
            self.slots.push(Some(entry));
            self.index.insert(path, idx);
            return;
        }
        // Check if an evicted hole exists first (bounded scan), otherwise sweep with clock_hand.
        let len = self.slots.len();
        for _ in 0..len {
            let idx = self.clock_hand % len;
            self.clock_hand = (idx + 1) % len;
            match &mut self.slots[idx] {
                None => {
                    self.slots[idx] = Some(entry);
                    self.index.insert(path, idx);
                    return;
                }
                Some(existing) if !existing.used => {
                    self.index.remove(&existing.path);
                    self.slots[idx] = Some(entry);
                    self.index.insert(path, idx);
                    return;
                }
                Some(existing) => {
                    existing.used = false;
                }
            }
        }
        // Second hand after all entries had `used = true`: evict at current clock_hand.
        let idx = self.clock_hand % len;
        self.clock_hand = (idx + 1) % len;
        if let Some(existing) = self.slots[idx].take() {
            self.index.remove(&existing.path);
        }
        self.slots[idx] = Some(entry);
        self.index.insert(path, idx);
    }

    fn remove(&mut self, path: &Path) {
        self.evict_gen = self.evict_gen.wrapping_add(1);
        if let Some(idx) = self.index.remove(path) {
            if let Some(slot) = self.slots.get_mut(idx) {
                *slot = None;
            }
        }
    }
}

/// An open-file-descriptor cache with O(1) amortized clock-hand ("second chance")
/// eviction, capped at `max_open` entries.
///
/// `File`s are held behind `Arc` so callers can clone a handle out while holding the
/// lock only briefly, then do the actual positioned I/O (`pwrite`/`pread`) without
/// holding the cache lock for the duration.
pub struct FileCache {
    inner: Mutex<CacheInner>,
}

impl FileCache {
    pub fn new(max_open: usize) -> FileCache {
        FileCache {
            inner: Mutex::new(CacheInner::new(max_open)),
        }
    }

    /// Returns a handle to `path`'s open file under the requested [`OpenMode`].
    ///
    /// - [`OpenMode::ReadOnly`]: opens read-only without creating missing parent directories
    ///   or files (allows seeding read-only files/mounts and avoids creating empty ghost files
    ///   when rechecking absent data).
    /// - [`OpenMode::Write { file_len }`]: creates missing parents/file, upgrades a cached
    ///   read-only handle if needed, and ensures real disk space is preallocated up to
    ///   `file_len` if not already reserved through this handle.
    pub fn get_or_open(&self, path: &Path, mode: OpenMode) -> io::Result<Arc<File>> {
        // Fast path: cached handle lookup under brief mutex hold.
        let (existing_upgrade, gen_before) = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let gen_before = inner.evict_gen;
            if let Some(entry) = inner.get_mut(path) {
                match mode {
                    OpenMode::ReadOnly => {
                        entry.used = true;
                        return Ok(entry.file.clone());
                    }
                    OpenMode::Write { file_len }
                        if entry.writable && entry.preallocated_len >= file_len =>
                    {
                        entry.used = true;
                        return Ok(entry.file.clone());
                    }
                    OpenMode::Write { .. } if entry.writable => {
                        entry.used = true;
                        (Some(entry.file.clone()), gen_before)
                    }
                    OpenMode::Write { .. } => (None, gen_before),
                }
            } else {
                (None, gen_before)
            }
        };

        // Fast upgrade when the file is already open read-write, just needs preallocation.
        if let (Some(existing_file), OpenMode::Write { file_len }) = (existing_upgrade, mode) {
            preallocate(&existing_file, file_len)?;
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.evict_gen == gen_before {
                if let Some(entry) = inner.get_mut(path) {
                    entry.preallocated_len = entry.preallocated_len.max(file_len);
                    entry.used = true;
                }
            }
            return Ok(existing_file);
        }

        // Slow path: perform directory creation, file opening, and disk preallocation
        // WITHOUT holding the cache mutex so concurrent cache hits and file accesses
        // across other swarms/threads are not blocked or serialized.
        let mut open_opts = OpenOptions::new();
        let (writable, preallocated_len) = match mode {
            OpenMode::ReadOnly => {
                open_opts.read(true);
                #[cfg(unix)]
                open_opts.custom_flags(libc::O_NOFOLLOW);
                (false, 0)
            }
            OpenMode::Write { file_len } => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                // `.truncate(false)` is explicit: this file may already hold partially-downloaded
                // piece data from a previous run, and silently truncating it would lose data.
                open_opts
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false);
                #[cfg(unix)]
                open_opts.custom_flags(libc::O_NOFOLLOW);
                (true, file_len)
            }
        };

        let file = open_opts.open(path)?;
        if let OpenMode::Write { file_len } = mode {
            preallocate(&file, file_len)?;
        }

        let file = Arc::new(file);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.evict_gen != gen_before || inner.max_open == 0 {
            return Ok(file);
        }

        // Check if another worker thread raced and cached an equal-or-stronger handle.
        if let Some(entry) = inner.get_mut(path) {
            let sufficient = match mode {
                OpenMode::ReadOnly => true,
                OpenMode::Write { file_len } => {
                    entry.writable && entry.preallocated_len >= file_len
                }
            };
            if sufficient {
                entry.used = true;
                return Ok(entry.file.clone());
            }
        }

        let owned_path = path.to_path_buf();
        inner.insert_or_replace(
            owned_path.clone(),
            Entry {
                path: owned_path,
                file: file.clone(),
                writable,
                preallocated_len,
                used: true,
            },
        );
        Ok(file)
    }

    /// Drops the cached handle for `path`, if any (used on explicit file deletion or move).
    pub fn evict(&self, path: &Path) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(path);
    }
}

/// Reserves `len` bytes of real disk space for `file` (rather than `File::set_len`
/// alone, which can leave a sparse file with no space actually guaranteed - risking a
/// mid-write `ENOSPC` and worse fragmentation under concurrent writers). Falls back to
/// `set_len` on platforms/filesystems where `fallocate` isn't supported.
#[cfg(target_os = "linux")]
fn preallocate(file: &File, len: u64) -> io::Result<()> {
    if file.metadata()?.len() >= len {
        return Ok(());
    }
    match rustix::fs::fallocate(file, rustix::fs::FallocateFlags::empty(), 0, len) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::OPNOTSUPP) | Err(rustix::io::Errno::NOSYS) => file.set_len(len),
        Err(e) => Err(e.into()),
    }
}

#[cfg(not(target_os = "linux"))]
fn preallocate(file: &File, len: u64) -> io::Result<()> {
    if file.metadata()?.len() < len {
        file.set_len(len)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn readonly_miss_does_not_create_empty_file_or_dirs() {
        let dir = tempdir().unwrap();
        let cache = FileCache::new(4);
        let missing = dir.path().join("nonexistent_sub/file.bin");
        let res = cache.get_or_open(&missing, OpenMode::ReadOnly);
        assert!(res.is_err());
        assert!(!missing.exists());
        assert!(!dir.path().join("nonexistent_sub").exists());
    }

    #[cfg(unix)]
    #[test]
    fn readonly_file_can_be_opened_then_upgraded_on_write() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("ro.bin");
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(b"abcd").unwrap();
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();

        let cache = FileCache::new(4);
        let ro_handle = cache.get_or_open(&path, OpenMode::ReadOnly).unwrap();
        assert_eq!(ro_handle.metadata().unwrap().len(), 4);

        // Make writable and upgrade via Write mode; verify preallocation runs too.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let rw_handle = cache
            .get_or_open(&path, OpenMode::Write { file_len: 128 })
            .unwrap();
        assert_eq!(rw_handle.metadata().unwrap().len(), 128);
    }

    #[test]
    fn max_open_zero_does_not_cache() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        let cache = FileCache::new(0);
        let _ = cache
            .get_or_open(&path, OpenMode::Write { file_len: 4 })
            .unwrap();
        let inner = cache.inner.lock().unwrap();
        assert!(inner.index.is_empty());
        assert!(inner.slots.is_empty());
    }
}
