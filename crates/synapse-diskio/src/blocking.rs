use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};

use crate::cache::FileCache;
use crate::{DiskError, ReadJob, Result, WriteJob};

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
}

#[derive(Clone, Copy)]
pub struct BlockingDiskEngineConfig {
    pub max_open_files: usize,
}

impl Default for BlockingDiskEngineConfig {
    fn default() -> Self {
        BlockingDiskEngineConfig {
            max_open_files: 500,
        }
    }
}

impl BlockingDiskEngine {
    pub fn new(config: BlockingDiskEngineConfig) -> BlockingDiskEngine {
        BlockingDiskEngine {
            cache: Arc::new(FileCache::new(config.max_open_files)),
        }
    }

    pub async fn write_batch(&self, jobs: Vec<WriteJob>) -> Result<()> {
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
        let engine = BlockingDiskEngine::new(BlockingDiskEngineConfig { max_open_files: 1 });

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
}
