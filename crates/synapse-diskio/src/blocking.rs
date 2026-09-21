use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};

use crate::cache::FileCache;
use crate::{DiskError, ReadJob, Result, WriteJob};

pub(crate) const DEFAULT_MAX_WRITE_BUFFER_BYTES: usize = 100 * 1024 * 1024; // 100 MiB

/// Portable disk engine: a `spawn_blocking` pool doing positioned reads/writes
/// (`pread`/`pwrite` via `std::os::unix::fs::FileExt`). No `io_uring`, so no Linux
/// dependency and no unsafe FFI - this is the always-available fallback, and what runs
/// on any machine without (or with restricted access to) `io_uring`: dev machines, CI,
/// sandboxed containers. See `crate::uring::IoUringDiskEngine` for the fast path.
///
/// A batch of writes (e.g. every file location a single piece touches) is submitted as
/// concurrent `spawn_blocking` tasks and awaited together, so a piece spanning multiple
/// files doesn't serialize on them one at a time - real parallelism via tokio's blocking
/// thread pool, just not literally one batched syscall the way the `io_uring` engine
/// submits a whole batch of SQEs at once.
pub struct BlockingDiskEngine {
    cache: Arc<FileCache>,
    budget: Arc<crate::WriteBudget>,
}

#[derive(Clone, Copy)]
pub struct BlockingDiskEngineConfig {
    pub max_open_files: usize,
    pub max_write_buffer_bytes: usize,
}

impl Default for BlockingDiskEngineConfig {
    fn default() -> Self {
        BlockingDiskEngineConfig {
            max_open_files: 500,
            max_write_buffer_bytes: DEFAULT_MAX_WRITE_BUFFER_BYTES,
        }
    }
}

impl BlockingDiskEngine {
    pub fn new(config: BlockingDiskEngineConfig) -> BlockingDiskEngine {
        let max_buf = config.max_write_buffer_bytes;
        BlockingDiskEngine {
            cache: Arc::new(FileCache::new(config.max_open_files)),
            budget: crate::WriteBudget::new(max_buf),
        }
    }

    pub async fn write_batch(&self, jobs: Vec<WriteJob>) -> Result<()> {
        let jobs = crate::coalesce_write_jobs(jobs);
        let total_bytes: usize = jobs.iter().map(|j| j.data.len()).sum();
        if total_bytes == 0 {
            return Ok(());
        }

        let _reservation = self
            .budget
            .reserve(total_bytes)
            .await
            .map_err(|e| DiskError::Io {
                path: PathBuf::from("<buffer>"),
                source: std::io::Error::new(std::io::ErrorKind::BrokenPipe, e),
            })?;

        let mut tasks = Vec::with_capacity(jobs.len());
        for job in jobs {
            let cache = self.cache.clone();
            tasks.push(tokio::task::spawn_blocking(move || write_one(&cache, job)));
        }
        for task in tasks {
            task.await.expect("blocking disk write task panicked")?;
        }
        Ok(())
    }

    pub fn in_flight_write_bytes(&self) -> usize {
        self.budget.in_flight()
    }

    pub fn max_write_buffer_bytes(&self) -> usize {
        self.budget.threshold()
    }

    pub fn set_max_write_buffer_bytes(&self, bytes: usize) {
        self.budget.set_threshold(bytes);
    }

    pub async fn read(&self, job: ReadJob) -> Result<Bytes> {
        let cache = self.cache.clone();
        tokio::task::spawn_blocking(move || read_one(&cache, job))
            .await
            .expect("blocking disk read task panicked")
    }

    pub async fn sync(&self, path: Arc<PathBuf>) -> Result<()> {
        let cache = self.cache.clone();
        tokio::task::spawn_blocking(move || {
            let file = cache
                .get_or_open(&path, None)
                .map_err(|source| DiskError::Io {
                    path: (*path).clone(),
                    source,
                })?;
            file.sync_data().map_err(|source| DiskError::Io {
                path: (*path).clone(),
                source,
            })
        })
        .await
        .expect("blocking disk sync task panicked")
    }

    pub fn evict(&self, path: &std::path::Path) {
        self.cache.evict(path);
    }
}

fn write_one(cache: &FileCache, job: WriteJob) -> Result<()> {
    let file = cache
        .get_or_open(&job.path, Some(job.file_len))
        .map_err(|source| DiskError::Io {
            path: (*job.path).clone(),
            source,
        })?;
    file.write_all_at(&job.data, job.offset)
        .map_err(|source| DiskError::Io {
            path: (*job.path).clone(),
            source,
        })
}

fn read_one(cache: &FileCache, job: ReadJob) -> Result<Bytes> {
    let file = cache
        .get_or_open(&job.path, None)
        .map_err(|source| DiskError::Io {
            path: (*job.path).clone(),
            source,
        })?;
    let mut buf = BytesMut::zeroed(job.len);
    file.read_exact_at(&mut buf, job.offset)
        .map_err(|source| DiskError::Io {
            path: (*job.path).clone(),
            source,
        })?;
    Ok(buf.freeze())
}

#[cfg(test)]
fn assert_send_sync<T: Send + Sync>() {}

#[cfg(test)]
const _: fn() = || assert_send_sync::<BlockingDiskEngine>();

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn job(path: Arc<PathBuf>, offset: u64, data: &[u8], file_len: u64) -> WriteJob {
        WriteJob {
            path,
            offset,
            data: Bytes::copy_from_slice(data),
            file_len,
        }
    }

    #[tokio::test]
    async fn write_then_read_back() {
        let dir = tempdir().unwrap();
        let path = Arc::new(dir.path().join("a.dat"));
        let engine = BlockingDiskEngine::new(Default::default());

        engine
            .write_batch(vec![job(path.clone(), 0, b"hello world", 11)])
            .await
            .unwrap();

        let data = engine
            .read(ReadJob {
                path: path.clone(),
                offset: 0,
                len: 11,
            })
            .await
            .unwrap();
        assert_eq!(&data[..], b"hello world");
    }

    #[tokio::test]
    async fn batch_write_spans_multiple_files() {
        let dir = tempdir().unwrap();
        let a = Arc::new(dir.path().join("a.dat"));
        let b = Arc::new(dir.path().join("b.dat"));
        let engine = BlockingDiskEngine::new(Default::default());

        engine
            .write_batch(vec![
                job(a.clone(), 0, b"first-file", 10),
                job(b.clone(), 0, b"second-file", 11),
            ])
            .await
            .unwrap();

        let a_data = engine
            .read(ReadJob {
                path: a,
                offset: 0,
                len: 10,
            })
            .await
            .unwrap();
        let b_data = engine
            .read(ReadJob {
                path: b,
                offset: 0,
                len: 11,
            })
            .await
            .unwrap();
        assert_eq!(&a_data[..], b"first-file");
        assert_eq!(&b_data[..], b"second-file");
    }

    #[tokio::test]
    async fn write_at_offset_within_preallocated_file() {
        let dir = tempdir().unwrap();
        let path = Arc::new(dir.path().join("c.dat"));
        let engine = BlockingDiskEngine::new(Default::default());

        engine
            .write_batch(vec![job(path.clone(), 100, b"tail", 104)])
            .await
            .unwrap();

        let data = engine
            .read(ReadJob {
                path: path.clone(),
                offset: 100,
                len: 4,
            })
            .await
            .unwrap();
        assert_eq!(&data[..], b"tail");

        let meta = std::fs::metadata(&*path).unwrap();
        assert_eq!(meta.len(), 104);
    }

    #[tokio::test]
    async fn sync_on_written_file_succeeds() {
        let dir = tempdir().unwrap();
        let path = Arc::new(dir.path().join("d.dat"));
        let engine = BlockingDiskEngine::new(Default::default());

        engine
            .write_batch(vec![job(path.clone(), 0, b"data", 4)])
            .await
            .unwrap();
        engine.sync(path).await.unwrap();
    }

    #[tokio::test]
    async fn eviction_reopens_transparently_under_a_tiny_cache() {
        let dir = tempdir().unwrap();
        let engine = BlockingDiskEngine::new(BlockingDiskEngineConfig {
            max_open_files: 1,
            ..Default::default()
        });

        let a = Arc::new(dir.path().join("a.dat"));
        let b = Arc::new(dir.path().join("b.dat"));

        engine
            .write_batch(vec![job(a.clone(), 0, b"aaaa", 4)])
            .await
            .unwrap();
        // With max_open_files=1, opening b's handle evicts a's cached entry.
        engine
            .write_batch(vec![job(b.clone(), 0, b"bbbb", 4)])
            .await
            .unwrap();
        // Reading a again must transparently reopen it, not fail.
        let data = engine
            .read(ReadJob {
                path: a,
                offset: 0,
                len: 4,
            })
            .await
            .unwrap();
        assert_eq!(&data[..], b"aaaa");
    }

    #[test]
    fn test_coalesce_write_jobs() {
        let dir = tempdir().unwrap();
        let file = Arc::new(dir.path().join("coalesce.dat"));
        let jobs = vec![
            job(file.clone(), 16384, b"second_block", 32768),
            job(file.clone(), 0, b"first_block", 32768),
        ];
        let coalesced = crate::coalesce_write_jobs(jobs);
        assert_eq!(
            coalesced.len(),
            2,
            "Non-adjacent in length (11 vs 16384) remain separate"
        );

        let contiguous = vec![
            job(file.clone(), 0, b"1234", 10),
            job(file.clone(), 4, b"5678", 10),
        ];
        let merged = crate::coalesce_write_jobs(contiguous);
        assert_eq!(merged.len(), 1, "Adjacent offsets must be merged");
        assert_eq!(merged[0].offset, 0);
        assert_eq!(&merged[0].data[..], b"12345678");
    }

    #[tokio::test]
    async fn test_write_backpressure_accounting() {
        let engine = BlockingDiskEngine::new(BlockingDiskEngineConfig {
            max_open_files: 10,
            max_write_buffer_bytes: 1024,
        });
        assert_eq!(engine.max_write_buffer_bytes(), 1024);
        assert_eq!(engine.in_flight_write_bytes(), 0);
    }
}
