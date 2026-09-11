//! Disk I/O engine for the synapse rewrite.
//!
//! Two backends behind one API: [`BlockingDiskEngine`] (portable, always available) and
//! [`IoUringDiskEngine`] (Linux-only, the fast path). See `doc/REWRITE_ROADMAP.md` Part 3
//! for the design this implements, and its "note on this development environment" -
//! anything under the `io_uring` backend is written and type-checked but **not**
//! runtime-verified outside a real Linux machine.

mod blocking;
mod cache;
#[cfg(target_os = "linux")]
mod uring;

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;

pub use blocking::{BlockingDiskEngine, BlockingDiskEngineConfig};
#[cfg(target_os = "linux")]
pub use uring::{IoUringDiskEngine, IoUringDiskEngineConfig};

/// A single write: `data` written to `path` at `offset`. `file_len` is the file's final
/// expected size, used to preallocate real disk space the first time this path is
/// touched (see `cache::preallocate`) rather than leaving a sparse file.
#[derive(Clone)]
pub struct WriteJob {
    pub path: Arc<PathBuf>,
    pub offset: u64,
    pub data: Bytes,
    pub file_len: u64,
}

/// A single read: `len` bytes from `path` starting at `offset`.
#[derive(Clone)]
pub struct ReadJob {
    pub path: Arc<PathBuf>,
    pub offset: u64,
    pub len: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum DiskError {
    #[error("disk I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

pub type Result<T> = std::result::Result<T, DiskError>;

/// The disk I/O backend a running daemon uses.
///
/// An enum rather than a trait object: exactly two implementations are ever chosen
/// between, at startup (see [`DiskEngine::auto`]), so static dispatch avoids both the
/// object-safety complications of `async fn` in traits and any dynamic-dispatch
/// overhead on what is meant to be the daemon's hottest path.
pub enum DiskEngine {
    Blocking(BlockingDiskEngine),
    #[cfg(target_os = "linux")]
    IoUring(IoUringDiskEngine),
}

impl DiskEngine {
    /// Picks the best backend available: `io_uring` on Linux if the running kernel
    /// supports the operations this engine needs, the portable blocking-thread-pool
    /// backend otherwise (including on every non-Linux platform), bounded by default max open files.
    pub async fn auto() -> DiskEngine {
        Self::auto_with_max_open_files(500).await
    }

    /// Picks the best backend available with a configured maximum open files limit for
    /// LRU file descriptor caching.
    pub async fn auto_with_max_open_files(max_open_files: usize) -> DiskEngine {
        #[cfg(target_os = "linux")]
        {
            let cfg = IoUringDiskEngineConfig {
                max_open_files,
                ..Default::default()
            };
            match IoUringDiskEngine::new(cfg).await {
                Ok(engine) => {
                    tracing::info!("disk engine: io_uring (max_open_files={})", max_open_files);
                    return DiskEngine::IoUring(engine);
                }
                Err(e) => {
                    tracing::warn!("io_uring disk engine unavailable ({e}), falling back to the blocking engine");
                }
            }
        }
        tracing::info!("disk engine: blocking thread pool (max_open_files={})", max_open_files);
        DiskEngine::Blocking(BlockingDiskEngine::new(BlockingDiskEngineConfig { max_open_files }))
    }

    /// Submits a batch of writes (e.g. every file location one piece touches, when a
    /// piece spans multiple files) and waits for all of them to land. The `io_uring`
    /// backend submits these as one batch of SQEs; the blocking backend runs them as
    /// concurrent `spawn_blocking` tasks - either way, callers never wait on file
    /// locations sequentially.
    pub async fn write_batch(&self, jobs: Vec<WriteJob>) -> Result<()> {
        match self {
            DiskEngine::Blocking(e) => e.write_batch(jobs).await,
            #[cfg(target_os = "linux")]
            DiskEngine::IoUring(e) => e.write_batch(jobs).await,
        }
    }

    pub async fn read(&self, job: ReadJob) -> Result<Bytes> {
        match self {
            DiskEngine::Blocking(e) => e.read(job).await,
            #[cfg(target_os = "linux")]
            DiskEngine::IoUring(e) => e.read(job).await,
        }
    }

    /// Flushes `path` to durable storage. Callers should only call this once a file has
    /// actually reached its final size (see the pre-rewrite Phase 6 fix in
    /// `CHANGELOG.md` for why "every non-block-aligned write" was the wrong trigger) -
    /// this engine doesn't second-guess when it's called, just performs the sync.
    pub async fn sync(&self, path: Arc<PathBuf>) -> Result<()> {
        match self {
            DiskEngine::Blocking(e) => e.sync(path).await,
            #[cfg(target_os = "linux")]
            DiskEngine::IoUring(e) => e.sync(path).await,
        }
    }
}
