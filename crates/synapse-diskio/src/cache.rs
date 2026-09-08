use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

struct Entry {
    file: Arc<File>,
    used: bool,
}

/// An open-file-descriptor cache with clock-hand ("second chance") eviction, capped at
/// `max_open` entries.
///
/// Ports the fix landed in the pre-rewrite codebase's `src/disk/cache.rs::ensure_exists`
/// (see `CHANGELOG.md`): the *first* unreferenced entry found while sweeping is evicted,
/// not an arbitrary one found by scanning the whole map.
///
/// `File`s are held behind `Arc` so callers can clone a handle out while holding the
/// lock only briefly, then do the actual (blocking) I/O against their own `Arc<File>`
/// clone without holding the cache lock for the duration - `File::write_at`/`read_at`
/// (positioned I/O, `pwrite`/`pread` under the hood) are safe to call concurrently from
/// multiple threads on a shared handle, so this doesn't need to serialize actual disk
/// I/O through the cache's lock, only the "find or open the handle" step.
pub struct FileCache {
    max_open: usize,
    files: Mutex<HashMap<PathBuf, Entry>>,
}

impl FileCache {
    pub fn new(max_open: usize) -> FileCache {
        FileCache {
            max_open,
            files: Mutex::new(HashMap::new()),
        }
    }

    /// Returns a handle to `path`'s open file, opening (and creating/preallocating to
    /// `file_len`, if given and the file doesn't already reach that length) it first if
    /// necessary.
    pub fn get_or_open(&self, path: &Path, file_len: Option<u64>) -> io::Result<Arc<File>> {
        // Fast path: cached handle lookup under brief mutex hold
        {
            let mut files = self.files.lock().unwrap();
            if let Some(entry) = files.get_mut(path) {
                entry.used = true;
                return Ok(entry.file.clone());
            }
        }

        // Slow path: perform directory creation, file opening, and disk preallocation
        // WITHOUT holding the cache mutex so concurrent cache hits and file accesses
        // across other swarms/threads are not blocked or serialized.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // `.truncate(false)` is explicit: this file may already hold partially-downloaded
        // piece data from a previous run, and silently truncating it would lose data.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        if let Some(len) = file_len {
            preallocate(&file, len)?;
        }

        let file = Arc::new(file);
        let mut files = self.files.lock().unwrap();
        // Check if another worker thread raced and cached this file handle while we opened it
        if let Some(entry) = files.get_mut(path) {
            entry.used = true;
            return Ok(entry.file.clone());
        }

        if files.len() >= self.max_open {
            evict_one(&mut files);
        }

        files.insert(
            path.to_path_buf(),
            Entry {
                file: file.clone(),
                used: true,
            },
        );
        Ok(file)
    }

    /// Drops the cached handle for `path`, if any (used on explicit file deletion).
    pub fn evict(&self, path: &Path) {
        self.files.lock().unwrap().remove(path);
    }
}

fn evict_one(files: &mut HashMap<PathBuf, Entry>) {
    if files.is_empty() {
        return;
    }
    // Pass 1: find an entry whose used bit is false
    for (path, entry) in files.iter_mut() {
        if !entry.used {
            let p = path.clone();
            files.remove(&p);
            return;
        }
        entry.used = false;
    }
    // Pass 2: all entries had used=true and are now reset to false; evict the first entry
    if let Some(p) = files.keys().next().cloned() {
        files.remove(&p);
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
