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
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::thread;

use bytes::{Bytes, BytesMut};
use io_uring::{opcode, types, IoUring};
use tokio::sync::oneshot;

use crate::cache::{FileCache, OpenMode};
use crate::{DiskError, ReadJob, Result, WriteJob, WriteReservation};

/// Linux caps a single read/write syscall (and io_uring RW CQE result) at 2 GiB - 4 KiB.
const MAX_RW_COUNT: usize = 0x7fff_f000;
/// Cap concurrent un-reaped ops in the ring to avoid overflowing the default 2*SQ completion queue
/// while reserving room for the `eventfd` wakeup `PollAdd`.
const MAX_IN_FLIGHT_OPS: usize = 510;
/// Sentinel `user_data` reserved for the persistent `eventfd` wakeup `PollAdd` SQE.
const WAKEUP_USER_DATA: u64 = u64::MAX;
/// Bound CQE reaping per iteration so newly queued jobs and retries get fair progress.
const REAP_BATCH_LIMIT: usize = 128;

#[derive(Clone, Copy)]
pub struct IoUringDiskEngineConfig {
    pub queue_depth: u32,
    pub max_open_files: usize,
    /// Bytes of write data that may be in flight at once (see `WriteBudget`).
    pub max_write_buffer_bytes: usize,
}

impl Default for IoUringDiskEngineConfig {
    fn default() -> Self {
        IoUringDiskEngineConfig {
            queue_depth: 256,
            max_open_files: 500,
            max_write_buffer_bytes: crate::blocking::DEFAULT_MAX_WRITE_BUFFER_BYTES,
        }
    }
}

enum Job {
    Write {
        path: Arc<PathBuf>,
        offset: u64,
        data: Bytes,
        file_len: u64,
        reservation: Option<Arc<WriteReservation>>,
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

struct EventFd {
    fd: OwnedFd,
    signaled: AtomicBool,
}

impl EventFd {
    fn new() -> io::Result<Self> {
        // SAFETY: `eventfd` creates a new non-blocking close-on-exec fd; `-1` is checked before wrapping.
        let raw = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw >= 0` is an open owned file descriptor returned by `eventfd(2)`.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self {
            fd,
            signaled: AtomicBool::new(false),
        })
    }

    fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    fn write_one(&self) {
        let buf = 1u64.to_ne_bytes();
        loop {
            // SAFETY: `self.fd` is a valid open eventfd and `buf` points to 8 stack bytes.
            let n = unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    buf.as_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n >= 0 {
                return;
            }
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
    }

    fn notify(&self) {
        if !self.signaled.swap(true, Ordering::SeqCst) {
            self.write_one();
        }
    }

    fn force_notify(&self) {
        self.signaled.store(true, Ordering::SeqCst);
        self.write_one();
    }

    fn drain(&self) {
        let mut buf = [0u8; 8];
        loop {
            // SAFETY: `self.fd` is a valid open eventfd and `buf` points to 8 writable stack bytes.
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n >= 0 {
                return;
            }
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
    }
}

/// Everything that must stay alive, unmoved, until this operation's CQE arrives.
struct PendingOp {
    _file: Arc<std::fs::File>,
    /// Absolute file offset for the *next* SQE this op submits -- advanced on each
    /// short completion so a retry resumes exactly where the last one left off.
    offset: u64,
    _write_buf: Option<Bytes>,
    _write_reservation: Option<Arc<WriteReservation>>,
    read_buf: Option<BytesMut>,
    /// Bytes already completed for this op across however many short completions
    /// preceded this one (0 on first submission).
    progress: usize,
    expected_len: usize,
    path: Arc<PathBuf>,
    responder: OpResponder,
}

/// Declaration order guarantees `ring` drops *first* (closing the kernel ring FD)
/// before `pending` buffers/file handles, `cache`, and `eventfd` are released, even on unwind.
struct RingLoopState {
    ring: IoUring,
    pending: HashMap<u64, PendingOp>,
    cqe_buf: Vec<(u64, i32)>,
    cache: Arc<FileCache>,
    eventfd: Arc<EventFd>,
    eventfd_poll_armed: bool,
    next_id: u64,
}

pub struct IoUringDiskEngine {
    tx: Option<std_mpsc::Sender<(Job, OpResponder)>>,
    eventfd: Arc<EventFd>,
    cache: Arc<FileCache>,
    budget: Arc<crate::WriteBudget>,
}

impl Drop for IoUringDiskEngine {
    fn drop(&mut self) {
        drop(self.tx.take());
        self.eventfd.force_notify();
    }
}

impl IoUringDiskEngine {
    /// Attempts to create a real `io_uring` instance up front, so [`crate::DiskEngine::auto`]
    /// can fall back to the blocking engine cleanly (old kernel, a seccomp profile
    /// blocking `io_uring_setup`, etc.) instead of failing on first use.
    pub async fn new(config: IoUringDiskEngineConfig) -> io::Result<IoUringDiskEngine> {
        let ring = IoUring::new(config.queue_depth)?;
        let eventfd = Arc::new(EventFd::new()?);
        let (tx, rx) = std_mpsc::channel();
        let cache = Arc::new(FileCache::new(config.max_open_files));
        let worker_cache = cache.clone();
        let worker_eventfd = eventfd.clone();
        thread::Builder::new()
            .name("diskio-uring".into())
            .spawn(move || run_ring(ring, rx, worker_cache, worker_eventfd))
            .map_err(io::Error::other)?;
        Ok(IoUringDiskEngine {
            tx: Some(tx),
            eventfd,
            cache,
            budget: crate::WriteBudget::new(config.max_write_buffer_bytes),
        })
    }

    fn send_gone_err(path: &std::path::Path) -> DiskError {
        DiskError::Io {
            path: path.to_path_buf(),
            source: io::Error::other("io_uring worker thread is gone"),
        }
    }

    pub fn evict(&self, path: &std::path::Path) {
        self.cache.evict(path);
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

    pub async fn write_batch(&self, jobs: Vec<WriteJob>) -> Result<()> {
        // Same behaviour as the blocking engine: merge contiguous blocks into single writes
        // and hold at most `max_write_buffer_bytes` of data in flight.
        let jobs = crate::coalesce_write_jobs(jobs);
        if jobs.is_empty() {
            return Ok(());
        }
        let total_bytes: usize = jobs.iter().map(|j| j.data.len()).sum();
        let reservation = if total_bytes > 0 {
            Some(Arc::new(self.budget.reserve(total_bytes).await.map_err(
                |e| DiskError::Io {
                    path: PathBuf::from("<buffer>"),
                    source: io::Error::new(io::ErrorKind::BrokenPipe, e),
                },
            )?))
        } else {
            None
        };
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| Self::send_gone_err(&jobs[0].path))?;
        let mut receivers = Vec::with_capacity(jobs.len());
        for job in jobs {
            let (otx, orx) = oneshot::channel();
            let path = job.path.clone();
            tx.send((
                Job::Write {
                    path: job.path,
                    offset: job.offset,
                    data: job.data,
                    file_len: job.file_len,
                    reservation: reservation.clone(),
                },
                OpResponder::Write(otx),
            ))
            .map_err(|_| Self::send_gone_err(&path))?;
            receivers.push((path, orx));
        }
        self.eventfd.notify();
        // Drop the local Arc so `budget` is released once the last PendingOp in the worker drops.
        drop(reservation);
        // Every SQE above is already queued for the worker thread to batch-submit; we
        // just wait for each to complete. Order of completion doesn't need to match
        // submission order, so this doesn't force artificial serialization.
        for (path, rx) in receivers {
            rx.await.map_err(|_| Self::send_gone_err(&path))??;
        }
        Ok(())
    }

    pub async fn read(&self, job: ReadJob) -> Result<Bytes> {
        let (otx, orx) = oneshot::channel();
        let path = job.path.clone();
        let tx = self.tx.as_ref().ok_or_else(|| Self::send_gone_err(&path))?;
        tx.send((
            Job::Read {
                path: job.path,
                offset: job.offset,
                len: job.len,
            },
            OpResponder::Read(otx),
        ))
        .map_err(|_| Self::send_gone_err(&path))?;
        self.eventfd.notify();
        orx.await.map_err(|_| Self::send_gone_err(&path))?
    }

    pub async fn sync(&self, path: Arc<PathBuf>) -> Result<()> {
        let (otx, orx) = oneshot::channel();
        let tx = self.tx.as_ref().ok_or_else(|| Self::send_gone_err(&path))?;
        tx.send((Job::Sync { path: path.clone() }, OpResponder::Sync(otx)))
            .map_err(|_| Self::send_gone_err(&path))?;
        self.eventfd.notify();
        orx.await.map_err(|_| Self::send_gone_err(&path))?
    }
}

fn next_op_id(state: &mut RingLoopState) -> u64 {
    let mut id = state.next_id;
    if id == WAKEUP_USER_DATA {
        id = 0;
    }
    state.next_id = id.wrapping_add(1);
    if state.next_id == WAKEUP_USER_DATA {
        state.next_id = 0;
    }
    id
}

fn arm_eventfd_poll(state: &mut RingLoopState) -> io::Result<()> {
    if state.eventfd_poll_armed {
        return Ok(());
    }
    let entry = opcode::PollAdd::new(types::Fd(state.eventfd.raw_fd()), libc::POLLIN as u32)
        .build()
        .user_data(WAKEUP_USER_DATA);
    // SAFETY: `state.eventfd` outlives `state.ring` by `RingLoopState` field declaration order,
    // and the poll targets `POLLIN` on an owned `eventfd` until its `WAKEUP_USER_DATA` CQE arrives.
    unsafe { push_entry(&mut state.ring, &entry)? };
    state.eventfd_poll_armed = true;
    Ok(())
}

fn run_ring(
    ring: IoUring,
    rx: std_mpsc::Receiver<(Job, OpResponder)>,
    cache: Arc<FileCache>,
    eventfd: Arc<EventFd>,
) {
    let mut state = RingLoopState {
        ring,
        pending: HashMap::new(),
        cqe_buf: Vec::with_capacity(REAP_BATCH_LIMIT),
        cache,
        eventfd,
        eventfd_poll_armed: false,
        next_id: 0,
    };
    let mut disconnected = false;

    loop {
        reap_completions(&mut state);

        if !disconnected {
            // Clear signaled BEFORE draining `rx` (paired with SeqCst swap+write on producers)
            // so no submitted job can slip in after `try_recv()` without waking `eventfd`.
            state.eventfd.signaled.store(false, Ordering::SeqCst);
            while state.pending.len() < MAX_IN_FLIGHT_OPS {
                match rx.try_recv() {
                    Ok((job, responder)) => submit_job(&mut state, job, responder),
                    Err(std_mpsc::TryRecvError::Empty) => break,
                    Err(std_mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }

        if disconnected && state.pending.is_empty() {
            return;
        }

        if !state.ring.completion().is_empty() {
            let _ = state.ring.submit();
            continue;
        }

        if !disconnected && state.pending.len() < MAX_IN_FLIGHT_OPS {
            if let Err(e) = arm_eventfd_poll(&mut state) {
                tracing::error!("io_uring eventfd PollAdd failed: {e}");
                let msg = e.to_string();
                for (_, op) in state.pending.drain() {
                    fail_responder(op.responder, &op.path, io::Error::other(msg.clone()));
                }
                return;
            }
        }

        match state.ring.submit_and_wait(1) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {}
            Err(e) => {
                tracing::error!("io_uring submit_and_wait failed: {e}");
                let msg = e.to_string();
                for (_, op) in state.pending.drain() {
                    fail_responder(op.responder, &op.path, io::Error::other(msg.clone()));
                }
                return;
            }
        }

        reap_completions(&mut state);

        if disconnected && state.pending.is_empty() {
            return;
        }
    }
}

fn reap_completions(state: &mut RingLoopState) -> usize {
    state.cqe_buf.clear();
    {
        let mut cq = state.ring.completion();
        for cqe in (&mut cq).take(REAP_BATCH_LIMIT) {
            state.cqe_buf.push((cqe.user_data(), cqe.result()));
        }
    }
    let reaped = state.cqe_buf.len();
    let mut completed = std::mem::take(&mut state.cqe_buf);

    for &(user_data, result) in &completed {
        if user_data == WAKEUP_USER_DATA {
            state.eventfd_poll_armed = false;
            state.eventfd.drain();
            continue;
        }
        if let Some(op) = state.pending.remove(&user_data) {
            let fd = types::Fd(op._file.as_raw_fd());
            if let Some((entry, retry_op)) = process_completion(fd, op, result) {
                let retry_id = next_op_id(state);
                let entry = entry.user_data(retry_id);
                // SAFETY: `retry_op` (and its buffer/file) is inserted into `state.pending`
                // before any future wait and `state.ring` drops before `state.pending`.
                let push_result = unsafe { push_entry(&mut state.ring, &entry) };
                match push_result {
                    Ok(()) => {
                        state.pending.insert(retry_id, retry_op);
                    }
                    Err(e) => {
                        fail_responder(retry_op.responder, &retry_op.path, e);
                    }
                }
            }
        }
    }

    completed.clear();
    state.cqe_buf = completed;
    reaped
}

fn submit_job(state: &mut RingLoopState, job: Job, responder: OpResponder) {
    let id = next_op_id(state);

    let (path, mode): (&PathBuf, OpenMode) = match &job {
        Job::Write { path, file_len, .. } => (
            path,
            OpenMode::Write {
                file_len: *file_len,
            },
        ),
        Job::Read { path, .. } | Job::Sync { path } => (path, OpenMode::ReadOnly),
    };
    let file = match state.cache.get_or_open(path, mode) {
        Ok(file) => file,
        Err(e) => {
            fail_responder(responder, path.as_path(), e);
            return;
        }
    };
    let fd = types::Fd(file.as_raw_fd());

    let (entry, op) = match job {
        Job::Write {
            path,
            offset,
            data,
            reservation,
            ..
        } => {
            if offset > i64::MAX as u64 {
                fail_responder(
                    responder,
                    &path,
                    io::Error::new(io::ErrorKind::InvalidInput, "write offset exceeds i64::MAX"),
                );
                return;
            }
            if data.is_empty() {
                if let OpResponder::Write(tx) = responder {
                    let _ = tx.send(Ok(()));
                }
                return;
            }
            let chunk_len = data.len().min(MAX_RW_COUNT) as u32;
            let entry = opcode::Write::new(fd, data.as_ptr(), chunk_len)
                .offset(offset)
                .build()
                .user_data(id);
            let op = PendingOp {
                _file: file,
                offset,
                expected_len: data.len(),
                progress: 0,
                _write_buf: Some(data),
                _write_reservation: reservation,
                read_buf: None,
                path,
                responder,
            };
            (entry, op)
        }
        Job::Read { path, offset, len } => {
            if offset > i64::MAX as u64 {
                fail_responder(
                    responder,
                    &path,
                    io::Error::new(io::ErrorKind::InvalidInput, "read offset exceeds i64::MAX"),
                );
                return;
            }
            if len == 0 {
                if let OpResponder::Read(tx) = responder {
                    let _ = tx.send(Ok(Bytes::new()));
                }
                return;
            }
            let mut buf = BytesMut::zeroed(len);
            let chunk_len = len.min(MAX_RW_COUNT) as u32;
            let entry = opcode::Read::new(fd, buf.as_mut_ptr(), chunk_len)
                .offset(offset)
                .build()
                .user_data(id);
            let op = PendingOp {
                _file: file,
                offset,
                expected_len: len,
                progress: 0,
                _write_buf: None,
                _write_reservation: None,
                read_buf: Some(buf),
                path,
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
                _write_reservation: None,
                read_buf: None,
                path,
                responder,
            };
            (entry, op)
        }
    };

    // SAFETY: `op` (and the `Arc<File>`/buffer it owns) is inserted into `state.pending`
    // before submission and `state.ring` drops before `state.pending`, ensuring pointers
    // remain valid for as long as the kernel holds them.
    if let Err(e) = unsafe { push_entry(&mut state.ring, &entry) } {
        fail_responder(op.responder, &op.path, e);
        return;
    }
    state.pending.insert(id, op);
}

/// Pushes `entry` onto `ring`'s submission queue, flushing first (`ring.submit()`) if
/// the queue is already at its fixed `queue_depth` capacity.
///
/// Draining a burst of more than `queue_depth` queued jobs in one pass (see
/// `run_ring`) would otherwise fail every push past the limit with `QueueFull`,
/// since the userspace SQ ring is a fixed-size buffer. `submit()` hands every queued
/// SQE to the kernel via `io_uring_enter` and frees their slots for reuse immediately
/// -- independent of whether the kernel has *completed* them yet -- so retrying the
/// push right after is expected to succeed.
///
/// # Safety
/// Same invariant as a direct `ring.submission().push()`: any buffer or file
/// descriptor `entry` references must remain valid and untouched until its CQE is
/// reaped.
unsafe fn push_entry(ring: &mut IoUring, entry: &io_uring::squeue::Entry) -> io::Result<()> {
    if ring.submission().is_full() {
        ring.submit()?;
    }
    ring.submission()
        .push(entry)
        .map_err(|_| io::Error::other("io_uring submission queue full"))
}

fn fail_responder(responder: OpResponder, path: &std::path::Path, source: io::Error) {
    let err = DiskError::Io {
        path: path.to_path_buf(),
        source,
    };
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
fn process_completion(
    fd: types::Fd,
    mut op: PendingOp,
    result: i32,
) -> Option<(io_uring::squeue::Entry, PendingOp)> {
    if result == -libc::EINTR {
        let remaining = op.expected_len.saturating_sub(op.progress);
        let entry = match (&mut op._write_buf, &mut op.read_buf) {
            (Some(write_buf), None) => {
                let chunk = remaining.min(MAX_RW_COUNT) as u32;
                opcode::Write::new(fd, write_buf.as_ptr(), chunk)
                    .offset(op.offset)
                    .build()
            }
            (None, Some(read_buf)) => {
                let chunk = remaining.min(MAX_RW_COUNT) as u32;
                let ptr = unsafe { read_buf.as_mut_ptr().add(op.progress) };
                opcode::Read::new(fd, ptr, chunk).offset(op.offset).build()
            }
            (None, None) => opcode::Fsync::new(fd).build(),
            _ => unreachable!("a pending op has at most one of write_buf/read_buf set"),
        };
        return Some((entry, op));
    }

    if result < 0 {
        fail_responder(
            op.responder,
            &op.path,
            io::Error::from_raw_os_error(-result),
        );
        return None;
    }

    let remaining_before = op.expected_len.saturating_sub(op.progress);
    let advance = (result as usize).min(remaining_before);
    op.progress += advance;

    // A zero-length completion that still leaves bytes unaccounted for means the
    // kernel can make no further progress at this offset (e.g. EOF on a short file) --
    // looping again would spin forever, so this is treated as an error rather than a
    // retry, exactly like a bare `read(2)`/`write(2)` loop must.
    if op.progress < op.expected_len && advance == 0 {
        fail_responder(
            op.responder,
            &op.path,
            io::Error::other(format!(
                "io_uring op made no progress: {} of {} bytes completed",
                op.progress, op.expected_len
            )),
        );
        return None;
    }

    if op.progress < op.expected_len {
        // Short completion: resubmit an SQE for the remaining bytes, resuming
        // at the advanced file offset and capped at `MAX_RW_COUNT`.
        op.offset += advance as u64;
        let remaining = op.expected_len - op.progress;
        let chunk = remaining.min(MAX_RW_COUNT) as u32;
        let entry = match (&mut op._write_buf, &mut op.read_buf) {
            (Some(write_buf), None) => {
                *write_buf = write_buf.slice(advance..);
                opcode::Write::new(fd, write_buf.as_ptr(), chunk)
                    .offset(op.offset)
                    .build()
            }
            (None, Some(read_buf)) => {
                let ptr = unsafe { read_buf.as_mut_ptr().add(op.progress) };
                opcode::Read::new(fd, ptr, chunk).offset(op.offset).build()
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
