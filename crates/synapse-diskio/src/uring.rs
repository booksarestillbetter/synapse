//! `io_uring`-backed disk engine. Linux only.
//!
//! **Not runtime-verified in this repo** - this was written and cross-checked with
//! `cargo check --target x86_64-unknown-linux-gnu` from a macOS development machine,
//! which catches type errors but proves nothing about runtime correctness. Treat this
//! module as an unreviewed-by-execution first draft until it has actually run on Linux.
//! See `doc/REWRITE_ROADMAP.md`'s note on the development environment.
//!
//! ## Design
//!
//! One dedicated OS thread owns the `IoUring` instance and its submission/completion
//! queues for its whole lifetime - `io_uring` isn't meant to be shared/moved between
//! threads, so this is a thread, not a tokio task. The async-facing [`IoUringDiskEngine`]
//! handle just sends `(Job, OpResponder)` pairs to that thread over a channel and awaits
//! a `oneshot` for the result; the thread submits SQEs (batching everything queued up
//! before it next blocks on completions) and dispatches results back as CQEs arrive.
//!
//! ## What this does *not* yet do
//!
//! The design doc (`doc/REWRITE_ROADMAP.md` Part 3) calls for registered fixed buffers
//! and registered file descriptors for the fastest path. This first implementation uses
//! plain (unregistered) `Write`/`Read`/`Fsync` opcodes against plain (unregistered) fds
//! instead: registering buffers only pays off when the buffers being registered are the
//! *same* ones the network read path fills in the first place (otherwise you're just
//! adding a registration step around a buffer you're about to throw away), and that
//! integration doesn't exist until Stage 3 wires up the peer wire protocol's buffer
//! pool. Building registered-buffer support now, against a buffer pool that doesn't
//! exist yet, isn't worth the added unsafe surface and risk of getting the lifetime
//! rules wrong in code nobody can run yet. This still gets the core `io_uring` wins
//! (batched submission, no blocking-thread-per-op, async completion) - registered
//! buffers/fds are a follow-up optimization once there's a real pool to register.
//!
//! ## Safety
//!
//! `io_uring` requires that any buffer (or file descriptor) referenced by a submitted
//! SQE remain valid and untouched by anything else until its CQE is reaped - the kernel
//! holds a raw pointer to it in the meantime. This module upholds that by moving the
//! `Bytes`/`BytesMut` buffer (for writes/reads) and an `Arc<File>` (keeping the fd open
//! regardless of cache eviction) into a `PendingOp` keyed by the SQE's `user_data`,
//! which is only dropped *after* the matching CQE has been reaped in [`complete_op`].
//! Nothing in this module drops or moves a buffer/file while an operation referencing
//! it is still in flight.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::thread;

use bytes::{Bytes, BytesMut};
use io_uring::{opcode, types, IoUring};
use tokio::sync::oneshot;

use crate::cache::FileCache;
use crate::{DiskError, ReadJob, Result, WriteJob};

#[derive(Clone, Copy)]
pub struct IoUringDiskEngineConfig {
    pub queue_depth: u32,
    pub max_open_files: usize,
}

impl Default for IoUringDiskEngineConfig {
    fn default() -> Self {
        IoUringDiskEngineConfig {
            queue_depth: 256,
            max_open_files: 500,
        }
    }
}

enum Job {
    Write {
        path: Arc<PathBuf>,
        offset: u64,
        data: Bytes,
        file_len: u64,
    },
    Read {
        path: Arc<PathBuf>,
        offset: u64,
        len: usize,
    },
    Sync {
        path: Arc<PathBuf>,
    },
}

enum OpResponder {
    Write(oneshot::Sender<Result<()>>),
    Read(oneshot::Sender<Result<Bytes>>),
    Sync(oneshot::Sender<Result<()>>),
}

/// Everything that must stay alive, unmoved, until this operation's CQE arrives.
struct PendingOp {
    _file: Arc<File>,
    /// Absolute file offset for the *next* SQE this op submits -- advanced on each
    /// short completion so a retry resumes exactly where the last one left off.
    offset: u64,
    _write_buf: Option<Bytes>,
    read_buf: Option<BytesMut>,
    /// Bytes already completed for this op across however many short completions
    /// preceded this one (0 on first submission).
    progress: usize,
    expected_len: usize,
    path: PathBuf,
    responder: OpResponder,
}

pub struct IoUringDiskEngine {
    tx: std_mpsc::Sender<(Job, OpResponder)>,
}

impl IoUringDiskEngine {
    /// Attempts to create a real `io_uring` instance up front, so [`crate::DiskEngine::auto`]
    /// can fall back to the blocking engine cleanly (old kernel, a seccomp profile
    /// blocking `io_uring_setup`, etc.) instead of failing on first use.
    pub async fn new(config: IoUringDiskEngineConfig) -> io::Result<IoUringDiskEngine> {
        let ring = IoUring::new(config.queue_depth)?;
        let (tx, rx) = std_mpsc::channel();
        let max_open_files = config.max_open_files;
        thread::Builder::new()
            .name("diskio-uring".into())
            .spawn(move || run_ring(ring, rx, max_open_files))
            .map_err(io::Error::other)?;
        Ok(IoUringDiskEngine { tx })
    }

    fn send_gone_err(path: &std::path::Path) -> DiskError {
        DiskError::Io {
            path: path.to_path_buf(),
            source: io::Error::other("io_uring worker thread is gone"),
        }
    }

    pub async fn write_batch(&self, jobs: Vec<WriteJob>) -> Result<()> {
        let mut receivers = Vec::with_capacity(jobs.len());
        for job in jobs {
            let (otx, orx) = oneshot::channel();
            let path = job.path.clone();
            self.tx
                .send((
                    Job::Write {
                        path: job.path,
                        offset: job.offset,
                        data: job.data,
                        file_len: job.file_len,
                    },
                    OpResponder::Write(otx),
                ))
                .map_err(|_| Self::send_gone_err(&path))?;
            receivers.push(orx);
        }
        // Every SQE above is already queued for the worker thread to batch-submit; we
        // just wait for each to complete. Order of completion doesn't need to match
        // submission order, so this doesn't force artificial serialization.
        for rx in receivers {
            rx.await
                .expect("io_uring worker dropped a pending write response")?;
        }
        Ok(())
    }

    pub async fn read(&self, job: ReadJob) -> Result<Bytes> {
        let (otx, orx) = oneshot::channel();
        let path = job.path.clone();
        self.tx
            .send((
                Job::Read {
                    path: job.path,
                    offset: job.offset,
                    len: job.len,
                },
                OpResponder::Read(otx),
            ))
            .map_err(|_| Self::send_gone_err(&path))?;
        orx.await
            .expect("io_uring worker dropped a pending read response")
    }

    pub async fn sync(&self, path: Arc<PathBuf>) -> Result<()> {
        let (otx, orx) = oneshot::channel();
        self.tx
            .send((Job::Sync { path: path.clone() }, OpResponder::Sync(otx)))
            .map_err(|_| Self::send_gone_err(&path))?;
        orx.await
            .expect("io_uring worker dropped a pending sync response")
    }
}

fn run_ring(mut ring: IoUring, rx: std_mpsc::Receiver<(Job, OpResponder)>, max_open_files: usize) {
    let cache = FileCache::new(max_open_files);
    let mut pending: HashMap<u64, PendingOp> = HashMap::new();
    let mut next_id: u64 = 0;

    loop {
        // Drain and submit everything currently queued without blocking.
        loop {
            match rx.try_recv() {
                Ok((job, responder)) => {
                    submit_job(&mut ring, &cache, &mut pending, &mut next_id, job, responder);
                }
                Err(std_mpsc::TryRecvError::Empty) => break,
                Err(std_mpsc::TryRecvError::Disconnected) => return,
            }
        }

        if pending.is_empty() {
            // Nothing in flight: block for the next job rather than busy-polling.
            match rx.recv() {
                Ok((job, responder)) => {
                    submit_job(&mut ring, &cache, &mut pending, &mut next_id, job, responder);
                }
                Err(_) => return,
            }
            continue;
        }

        if let Err(e) = ring.submit_and_wait(1) {
            tracing::error!("io_uring submit_and_wait failed: {e}");
            continue;
        }
        let completed: Vec<(u64, i32)> = ring
            .completion()
            .map(|cqe| (cqe.user_data(), cqe.result()))
            .collect();
        for (user_data, result) in completed {
            if let Some(op) = pending.remove(&user_data) {
                let fd = types::Fd(op._file.as_raw_fd());
                if let Some((entry, retry_op)) = process_completion(fd, op, result) {
                    let retry_id = next_id;
                    next_id += 1;
                    let entry = entry.user_data(retry_id);
                    // SAFETY: same invariant as the initial submission in `submit_job` --
                    // `retry_op` (and its buffer/file) is inserted into `pending` before
                    // this SQE is pushed, and is only dropped after the matching CQE is
                    // reaped in a future pass through this same loop.
                    let push_result = unsafe { ring.submission().push(&entry) };
                    if push_result.is_err() {
                        fail_responder(
                            retry_op.responder,
                            retry_op.path,
                            io::Error::other("io_uring submission queue full (short-completion retry)"),
                        );
                    } else {
                        pending.insert(retry_id, retry_op);
                    }
                }
            }
        }
    }
}

fn submit_job(
    ring: &mut IoUring,
    cache: &FileCache,
    pending: &mut HashMap<u64, PendingOp>,
    next_id: &mut u64,
    job: Job,
    responder: OpResponder,
) {
    let id = *next_id;
    *next_id += 1;

    let (path, file_len_hint): (&PathBuf, Option<u64>) = match &job {
        Job::Write { path, file_len, .. } => (path, Some(*file_len)),
        Job::Read { path, .. } => (path, None),
        Job::Sync { path } => (path, None),
    };
    let file = match cache.get_or_open(path, file_len_hint) {
        Ok(file) => file,
        Err(e) => {
            fail_responder(responder, path.clone(), e);
            return;
        }
    };
    let fd = types::Fd(file.as_raw_fd());

    let (entry, op) = match job {
        Job::Write {
            path,
            offset,
            data,
            ..
        } => {
            let entry = opcode::Write::new(fd, data.as_ptr(), data.len() as u32)
                .offset(offset)
                .build()
                .user_data(id);
            let op = PendingOp {
                _file: file,
                offset,
                expected_len: data.len(),
                progress: 0,
                _write_buf: Some(data),
                read_buf: None,
                path: (*path).clone(),
                responder,
            };
            (entry, op)
        }
        Job::Read { path, offset, len } => {
            let mut buf = BytesMut::zeroed(len);
            let entry = opcode::Read::new(fd, buf.as_mut_ptr(), len as u32)
                .offset(offset)
                .build()
                .user_data(id);
            let op = PendingOp {
                _file: file,
                offset,
                expected_len: len,
                progress: 0,
                _write_buf: None,
                read_buf: Some(buf),
                path: (*path).clone(),
                responder,
            };
            (entry, op)
        }
        Job::Sync { path } => {
            let entry = opcode::Fsync::new(fd).build().user_data(id);
            let op = PendingOp {
                _file: file,
                offset: 0,
                expected_len: 0,
                progress: 0,
                _write_buf: None,
                read_buf: None,
                path: (*path).clone(),
                responder,
            };
            (entry, op)
        }
    };

    // SAFETY: `op` (and the `Arc<File>`/buffer it owns) is inserted into `pending`
    // before submission and is only removed - dropping the file handle and buffer -
    // after this SQE's CQE has been reaped in `complete_op`. The pointers this entry
    // carries (into `op`'s buffer) therefore stay valid for as long as the kernel might
    // hold them.
    let push_result = unsafe { ring.submission().push(&entry) };
    if push_result.is_err() {
        fail_responder(
            op.responder,
            op.path,
            io::Error::other("io_uring submission queue full"),
        );
        return;
    }
    pending.insert(id, op);
}

fn fail_responder(responder: OpResponder, path: PathBuf, source: io::Error) {
    let err = DiskError::Io { path, source };
    match responder {
        OpResponder::Write(tx) => {
            let _ = tx.send(Err(err));
        }
        OpResponder::Read(tx) => {
            let _ = tx.send(Err(err));
        }
        OpResponder::Sync(tx) => {
            let _ = tx.send(Err(err));
        }
    }
}

/// Handles one CQE. Returns `Some((entry, op))` when the completion was short and a
/// retry SQE for the remaining bytes must be submitted (the op stays in `pending`
/// under a freshly minted id); returns `None` once the op is fully done (error or
/// success already delivered to its responder).
///
/// `io_uring`'s plain (unregistered) Read/Write opcodes can complete with a short
/// count, exactly like a raw `read(2)`/`write(2)` syscall can -- this resubmits an SQE
/// covering just the unfinished remainder, exactly as a caller of `read(2)`/`write(2)`
/// directly would be expected to loop and retry, rather than silently accepting
/// truncated data or an incomplete write as success.
fn process_completion(fd: types::Fd, mut op: PendingOp, result: i32) -> Option<(io_uring::squeue::Entry, PendingOp)> {
    if result < 0 {
        fail_responder(op.responder, op.path, io::Error::from_raw_os_error(-result));
        return None;
    }

    let n = result as usize;
    op.progress += n;

    // A zero-length completion that still leaves bytes unaccounted for means the
    // kernel can make no further progress at this offset (e.g. EOF on a short file) --
    // looping again would spin forever, so this is treated as an error rather than a
    // retry, exactly like a bare `read(2)`/`write(2)` loop must.
    if op.progress < op.expected_len && n == 0 {
        fail_responder(
            op.responder,
            op.path,
            io::Error::other(format!(
                "io_uring op made no progress: {} of {} bytes completed",
                op.progress, op.expected_len
            )),
        );
        return None;
    }

    if op.progress < op.expected_len {
        // Short completion: resubmit an SQE for exactly the remaining bytes, resuming
        // at the advanced file offset.
        op.offset += n as u64;
        let remaining = op.expected_len - op.progress;
        let entry = match (&mut op._write_buf, &mut op.read_buf) {
            (Some(write_buf), None) => {
                *write_buf = write_buf.slice(n..);
                opcode::Write::new(fd, write_buf.as_ptr(), remaining as u32).offset(op.offset).build()
            }
            (None, Some(read_buf)) => {
                let ptr = unsafe { read_buf.as_mut_ptr().add(op.progress) };
                opcode::Read::new(fd, ptr, remaining as u32).offset(op.offset).build()
            }
            _ => unreachable!("a pending op has exactly one of write_buf/read_buf set"),
        };
        return Some((entry, op));
    }

    match op.responder {
        OpResponder::Write(tx) => {
            let _ = tx.send(Ok(()));
        }
        OpResponder::Read(tx) => {
            let buf = op
                .read_buf
                .expect("read completion missing its buffer")
                .freeze();
            let _ = tx.send(Ok(buf));
        }
        OpResponder::Sync(tx) => {
            let _ = tx.send(Ok(()));
        }
    }
    None
}
