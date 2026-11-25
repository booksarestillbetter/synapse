//! BEP 29 Micro Transport Protocol (uTP) Connection Engine & LEDBAT Congestion Control.
//!
//! Provides delay-based congestion control (LEDBAT) over UDP to prevent saturating
//! user internet links while maintaining high-speed BitTorrent throughput, along with
//! asynchronous stream multiplexing (`UtpStream`, `UtpSocketManager`), retransmission,
//! RTT estimation (RFC 6298), SACK processing, and SYN-flood protection.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use parking_lot::{Mutex, RwLock};
use rand::Rng;
use synapse_wire::UdpTransport;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(test)]
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tracing::{debug, trace, warn};

use synapse_wire::{build_sack_bitmask_iter, UtpHeader, UtpPacket, UtpType};

/// Target queuing delay in microseconds (100ms per BEP 29).
pub const LEDBAT_TARGET_DELAY_US: u32 = 100_000;
/// Minimum window size in bytes (2 packets ~ 3000 bytes).
pub const MIN_CWND_BYTES: u32 = 3_000;
/// Maximum default window size in bytes (10MB).
pub const MAX_CWND_BYTES: u32 = 10 * 1024 * 1024;
/// Default payload size for uTP packets.
pub const DEFAULT_MTU_PAYLOAD: usize = 1400;
/// Scaled gain factor for LEDBAT window adaptation.
pub const LEDBAT_GAIN: f64 = 3000.0;

/// Compares two 16-bit sequence numbers handling wrapping. Returns true if `a <= b`.
pub fn seq_less_equal(a: u16, b: u16) -> bool {
    (b.wrapping_sub(a) as i16) >= 0
}

/// Returns distance from `a` to `b` (`b - a`) handling 16-bit sequence wrapping.
pub fn seq_distance(a: u16, b: u16) -> i16 {
    b.wrapping_sub(a) as i16
}

/// Returns monotonic process-relative timestamp in microseconds (per BEP 29).
pub fn now_micros() -> u32 {
    static MONOTONIC_EPOCH: OnceLock<Instant> = OnceLock::new();
    MONOTONIC_EPOCH
        .get_or_init(Instant::now)
        .elapsed()
        .as_micros() as u32
}

const LEDBAT_BASE_WINDOW: Duration = Duration::from_secs(120);
const LEDBAT_BUCKET_INTERVAL: Duration = Duration::from_secs(30);

/// LEDBAT (Low Extra Delay Background Transport) Delay-Based Congestion Controller.
#[derive(Debug, Clone)]
pub struct LedbatCongestionController {
    pub target_delay_us: u32,
    pub max_window_bytes: u32,
    pub base_delay_us: u32,
    pub cur_delay_us: u32,
    pub bytes_in_flight: u32,
    pub base_delay_history: VecDeque<(Instant, u32)>,
}

impl LedbatCongestionController {
    pub fn new() -> Self {
        Self {
            target_delay_us: LEDBAT_TARGET_DELAY_US,
            max_window_bytes: MIN_CWND_BYTES,
            base_delay_us: u32::MAX,
            cur_delay_us: 0,
            bytes_in_flight: 0,
            base_delay_history: VecDeque::with_capacity(6),
        }
    }

    #[inline]
    fn wrapping_delay_less(a: u32, b: u32) -> bool {
        (a.wrapping_sub(b) as i32) < 0
    }

    /// Records an ACK with its one-way delay sample and adapts the congestion window using
    /// a 2-minute rolling minimum base-delay window with wrapping 32-bit timestamp math.
    pub fn on_ack(&mut self, bytes_acked: u32, delay_sample_us: u32) {
        if delay_sample_us == 0 || bytes_acked == 0 {
            return;
        }

        let now = Instant::now();
        while let Some(&(ts, _)) = self.base_delay_history.front() {
            if now.saturating_duration_since(ts) > LEDBAT_BASE_WINDOW {
                self.base_delay_history.pop_front();
            } else {
                break;
            }
        }
        match self.base_delay_history.back_mut() {
            Some((ts, bucket_min))
                if now.saturating_duration_since(*ts) < LEDBAT_BUCKET_INTERVAL =>
            {
                if Self::wrapping_delay_less(delay_sample_us, *bucket_min) {
                    *bucket_min = delay_sample_us;
                }
            }
            _ => {
                self.base_delay_history.push_back((now, delay_sample_us));
            }
        }
        let mut rolling_min = delay_sample_us;
        for &(_, sample) in &self.base_delay_history {
            if Self::wrapping_delay_less(sample, rolling_min) {
                rolling_min = sample;
            }
        }
        self.base_delay_us = rolling_min;
        self.cur_delay_us = delay_sample_us;

        let queue_delay = delay_sample_us.wrapping_sub(self.base_delay_us);
        let off_target =
            (self.target_delay_us as f64 - queue_delay as f64) / (self.target_delay_us as f64);

        // Standard LEDBAT window adaptation formula:
        // window_delta = GAIN * off_target * (bytes_acked / max_window)
        let window_factor = (bytes_acked as f64) / (self.max_window_bytes.max(1) as f64);
        let delta = (LEDBAT_GAIN * off_target * window_factor) as i32;

        if delta >= 0 {
            self.max_window_bytes = self
                .max_window_bytes
                .saturating_add(delta as u32)
                .min(MAX_CWND_BYTES);
        } else {
            let decrease = (-delta) as u32;
            self.max_window_bytes = self
                .max_window_bytes
                .saturating_sub(decrease)
                .max(MIN_CWND_BYTES);
        }
    }

    /// Checks if a packet of `payload_len` bytes can be transmitted under congestion & flow control.
    pub fn can_send(&self, payload_len: usize, remote_wnd: u32) -> bool {
        let effective_wnd = self.max_window_bytes.min(remote_wnd);
        (self.bytes_in_flight.saturating_add(payload_len as u32)) <= effective_wnd
    }

    /// Notifies the controller that a packet was sent.
    pub fn on_packet_sent(&mut self, payload_len: usize) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(payload_len as u32);
    }

    /// Notifies the controller that packets were acknowledged.
    pub fn on_bytes_acknowledged(&mut self, bytes: u32) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
    }

    /// Drops congestion window to minimum on timeout or severe packet loss.
    pub fn on_loss(&mut self) {
        self.max_window_bytes = MIN_CWND_BYTES;
    }
}

impl Default for LedbatCongestionController {
    fn default() -> Self {
        Self::new()
    }
}

/// RTT and Retransmission Timeout (RTO) estimator implementing RFC 6298.
#[derive(Debug, Clone)]
pub struct RttEstimator {
    pub srtt_us: u32,
    pub rttvar_us: u32,
    pub rto_ms: u32,
    has_sample: bool,
}

impl RttEstimator {
    pub fn new() -> Self {
        Self {
            srtt_us: 500_000,   // 500ms initial
            rttvar_us: 250_000, // 250ms initial
            rto_ms: 1000,       // 1000ms initial RTO
            has_sample: false,
        }
    }

    pub fn on_rtt_sample(&mut self, sample_us: u32) {
        let sample = u64::from(sample_us.min(10_000_000));
        if !self.has_sample {
            self.has_sample = true;
            self.srtt_us = sample as u32;
            self.rttvar_us = (sample / 2) as u32;
        } else {
            let srtt = u64::from(self.srtt_us);
            let rttvar = u64::from(self.rttvar_us);
            let diff = srtt.abs_diff(sample);
            self.rttvar_us = ((3 * rttvar + diff) / 4) as u32;
            self.srtt_us = ((7 * srtt + sample) / 8) as u32;
        }
        let rto_us =
            u64::from(self.srtt_us) + 4u64.saturating_mul(u64::from(self.rttvar_us)).max(100_000);
        self.rto_ms = (rto_us / 1000).clamp(500, 10_000) as u32;
    }

    pub fn on_timeout(&mut self) {
        self.rto_ms = (self.rto_ms.saturating_mul(2)).min(10_000);
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtpConnectionState {
    SynSent,
    Connected,
    FinSent,
    Closed,
    Reset,
}

/// Packet currently tracked in flight for acknowledgement and retransmission.
#[derive(Debug, Clone)]
struct InFlightPacket {
    seq_nr: u16,
    send_time: Instant,
    payload: Bytes,
    transmits: u32,
    sacked: bool,
}

/// Shared read state for `UtpStream`.
#[derive(Debug, Default)]
struct StreamReadState {
    buffer: VecDeque<u8>,
    eof: bool,
    error: Option<String>,
    waker: Option<Waker>,
}

/// Shared write state for `UtpStream`.
#[derive(Debug, Default)]
struct StreamWriteState {
    is_closed: bool,
    error: Option<String>,
    queued_channel_chunks: usize,
    inflight_count: usize,
    write_waker: Option<Waker>,
    flush_waker: Option<Waker>,
}

/// uTP Connection instance tracking sequence numbers, connection IDs, and LEDBAT state.
#[derive(Debug, Clone)]
pub struct UtpConnection {
    pub recv_conn_id: u16,
    pub send_conn_id: u16,
    pub seq_nr: u16,
    pub ack_nr: u16,
    pub state: UtpConnectionState,
    pub congestion: LedbatCongestionController,
    pub last_remote_timestamp_us: u32,
    pub last_timestamp_diff_us: u32,
    /// Free space in our receive buffer, sent as `wnd_size` in every packet: the header field is
    /// the *receiver's* window (how much the peer may still send us), not our congestion window.
    pub recv_wnd: u32,
}

/// Bytes of received-but-unread data buffered per connection. Data beyond this is not
/// acknowledged (the sender retransmits it later), which is what makes the advertised window a
/// real limit instead of an honour system.
pub const RECV_BUFFER_CAP: usize = 1024 * 1024;

/// How far ahead of the next expected sequence number a packet may arrive and still be held for
/// reordering. Bounds the reorder buffer at roughly 256 packets instead of the 32 767 the
/// sequence space would otherwise allow a peer to make us store.
pub const MAX_OUT_OF_ORDER_PACKETS: i16 = 256;

impl UtpConnection {
    /// Creates a new outgoing uTP connection with a given base `recv_conn_id`.
    pub fn new_outgoing(conn_id: u16) -> Self {
        Self {
            recv_conn_id: conn_id,
            send_conn_id: conn_id.wrapping_add(1),
            seq_nr: 1,
            ack_nr: 0,
            state: UtpConnectionState::SynSent,
            congestion: LedbatCongestionController::new(),
            recv_wnd: RECV_BUFFER_CAP as u32,
            last_remote_timestamp_us: 0,
            last_timestamp_diff_us: 0,
        }
    }

    /// Creates a new incoming uTP connection from a received `Syn` packet.
    pub fn new_incoming(syn_packet: &UtpPacket) -> Self {
        let send_id = syn_packet.header.connection_id;
        let recv_id = send_id.wrapping_add(1);
        let remote_ts = syn_packet.header.timestamp_us;
        let diff = if remote_ts != 0 {
            now_micros().wrapping_sub(remote_ts)
        } else {
            0
        };
        Self {
            recv_conn_id: recv_id,
            send_conn_id: send_id,
            seq_nr: 100, // Initial sequence number
            ack_nr: syn_packet.header.seq_nr,
            state: UtpConnectionState::Connected,
            congestion: LedbatCongestionController::new(),
            recv_wnd: RECV_BUFFER_CAP as u32,
            last_remote_timestamp_us: remote_ts,
            last_timestamp_diff_us: diff,
        }
    }

    #[inline]
    pub fn record_remote_timestamp(&mut self, remote_ts_us: u32, recv_now_us: u32) {
        self.last_remote_timestamp_us = remote_ts_us;
        self.last_timestamp_diff_us = if remote_ts_us != 0 {
            recv_now_us.wrapping_sub(remote_ts_us)
        } else {
            0
        };
    }

    /// Builds a SYN packet to initiate a connection.
    pub fn build_syn_packet(&mut self) -> UtpPacket {
        let mut header = UtpHeader::new(
            UtpType::Syn,
            self.recv_conn_id,
            self.seq_nr,
            0,
            self.recv_wnd,
        );
        header.timestamp_us = now_micros();
        self.seq_nr = self.seq_nr.wrapping_add(1);
        UtpPacket::new(header, Bytes::new())
    }

    /// Builds a STATE (ACK) packet.
    pub fn build_state_packet(&self) -> UtpPacket {
        let mut header = UtpHeader::new(
            UtpType::State,
            self.send_conn_id,
            self.seq_nr,
            self.ack_nr,
            self.recv_wnd,
        );
        header.timestamp_us = now_micros();
        header.timestamp_diff_us = self.last_timestamp_diff_us;
        UtpPacket::new(header, Bytes::new())
    }

    /// Builds a STATE (ACK) packet with a SACK extension.
    pub fn build_state_packet_with_sack(&self, sack_bitmask: Vec<u8>) -> UtpPacket {
        let mut pkt = self.build_state_packet();
        pkt = pkt.with_sack(sack_bitmask);
        pkt
    }

    /// Builds a DATA packet with an explicit sequence number (used for retransmissions).
    pub fn build_data_packet_with_seq(&self, seq_nr: u16, payload: Bytes) -> UtpPacket {
        let mut header = UtpHeader::new(
            UtpType::Data,
            self.send_conn_id,
            seq_nr,
            self.ack_nr,
            self.recv_wnd,
        );
        header.timestamp_us = now_micros();
        header.timestamp_diff_us = self.last_timestamp_diff_us;
        UtpPacket::new(header, payload)
    }

    /// Builds a DATA packet carrying payload bytes.
    pub fn build_data_packet(&mut self, payload: Bytes) -> UtpPacket {
        let seq = self.seq_nr;
        self.seq_nr = self.seq_nr.wrapping_add(1);
        self.build_data_packet_with_seq(seq, payload)
    }

    /// Builds a FIN packet to gracefully close the connection.
    pub fn build_fin_packet(&mut self) -> UtpPacket {
        self.state = UtpConnectionState::FinSent;
        let mut header = UtpHeader::new(
            UtpType::Fin,
            self.send_conn_id,
            self.seq_nr,
            self.ack_nr,
            self.recv_wnd,
        );
        header.timestamp_us = now_micros();
        header.timestamp_diff_us = self.last_timestamp_diff_us;

        self.seq_nr = self.seq_nr.wrapping_add(1);
        UtpPacket::new(header, Bytes::new())
    }

    /// Builds a RESET packet.
    pub fn build_reset_packet(&self) -> UtpPacket {
        let mut header = UtpHeader::new(
            UtpType::Reset,
            self.send_conn_id,
            self.seq_nr,
            self.ack_nr,
            0,
        );
        header.timestamp_us = now_micros();
        UtpPacket::new(header, Bytes::new())
    }

    /// Ingests a received packet, updates internal state, sequence numbers, LEDBAT delay,
    /// and returns received payload data if applicable.
    pub fn on_packet_recv(&mut self, packet: &UtpPacket) -> Result<Option<Bytes>, &'static str> {
        self.record_remote_timestamp(packet.header.timestamp_us, now_micros());

        // Feed LEDBAT delay sample
        if packet.header.timestamp_diff_us > 0 {
            self.congestion
                .on_ack(1400, packet.header.timestamp_diff_us);
        }

        match packet.header.ptype {
            UtpType::State => {
                if self.state == UtpConnectionState::SynSent
                    && packet.header.ack_nr == self.seq_nr.wrapping_sub(1)
                {
                    self.state = UtpConnectionState::Connected;
                    self.ack_nr = packet.header.seq_nr.wrapping_sub(1);
                }
                Ok(None)
            }
            UtpType::Data => {
                self.ack_nr = packet.header.seq_nr;
                Ok(Some(packet.payload.clone()))
            }
            UtpType::Fin => {
                self.ack_nr = packet.header.seq_nr;
                self.state = UtpConnectionState::Closed;
                Ok(None)
            }
            UtpType::Reset => {
                self.state = UtpConnectionState::Reset;
                Err("uTP connection reset by peer")
            }
            UtpType::Syn => {
                self.state = UtpConnectionState::Connected;
                self.ack_nr = packet.header.seq_nr;
                Ok(None)
            }
        }
    }
}

/// An asynchronous duplex stream carrying BitTorrent peer wire traffic over BEP 29 uTP.
/// Implements `tokio::io::AsyncRead` and `tokio::io::AsyncWrite`.
pub struct UtpStream {
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    read_state: Arc<Mutex<StreamReadState>>,
    write_state: Arc<Mutex<StreamWriteState>>,
    outbound_tx: mpsc::Sender<Bytes>,
    flush_notify: Arc<Notify>,
    shutdown_notify: Arc<Notify>,
    read_window_notify: Arc<Notify>,
    closed: Arc<AtomicBool>,
}

impl std::fmt::Debug for UtpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UtpStream")
            .field("peer_addr", &self.peer_addr)
            .field("local_addr", &self.local_addr)
            .finish()
    }
}

impl UtpStream {
    /// Bytes received but not yet read (bounded by [`RECV_BUFFER_CAP`]).
    pub fn buffered_bytes(&self) -> usize {
        self.read_state.lock().buffer.len()
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl AsyncRead for UtpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        let mut notify_window = false;
        let res = {
            let mut state = self.read_state.lock();

            if let Some(ref err) = state.error {
                return Poll::Ready(Err(Error::new(ErrorKind::ConnectionReset, err.clone())));
            }

            if !state.buffer.is_empty() {
                let prev_free = RECV_BUFFER_CAP.saturating_sub(state.buffer.len());
                let to_read = state.buffer.len().min(buf.remaining());
                let (part1, part2) = state.buffer.as_slices();
                if to_read <= part1.len() {
                    buf.put_slice(&part1[..to_read]);
                } else {
                    buf.put_slice(part1);
                    buf.put_slice(&part2[..(to_read - part1.len())]);
                }
                state.buffer.drain(..to_read);
                let new_free = RECV_BUFFER_CAP.saturating_sub(state.buffer.len());
                if prev_free < DEFAULT_MTU_PAYLOAD * 4 && new_free >= DEFAULT_MTU_PAYLOAD * 4 {
                    notify_window = true;
                }
                Poll::Ready(Ok(()))
            } else if state.eof {
                Poll::Ready(Ok(()))
            } else {
                state.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        };
        if notify_window {
            self.read_window_notify.notify_one();
        }
        res
    }
}

impl AsyncWrite for UtpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "uTP stream closed")));
        }

        let mut w_state = self.write_state.lock();
        if let Some(ref err) = w_state.error {
            return Poll::Ready(Err(Error::new(ErrorKind::ConnectionReset, err.clone())));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let bytes = Bytes::copy_from_slice(buf);
        let len = bytes.len();
        match self.outbound_tx.try_send(bytes) {
            Ok(()) => {
                w_state.queued_channel_chunks += 1;
                w_state.inflight_count += 1;
                self.flush_notify.notify_one();
                Poll::Ready(Ok(len))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                w_state.write_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "uTP outbound channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let mut w_state = self.write_state.lock();
        if let Some(ref err) = w_state.error {
            return Poll::Ready(Err(Error::new(ErrorKind::ConnectionReset, err.clone())));
        }
        if w_state.inflight_count == 0 {
            Poll::Ready(Ok(()))
        } else {
            w_state.flush_waker = Some(cx.waker().clone());
            self.flush_notify.notify_one();
            Poll::Pending
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.closed.store(true, Ordering::SeqCst);
        self.shutdown_notify.notify_one();
        let mut w_state = self.write_state.lock();
        if w_state.is_closed {
            Poll::Ready(Ok(()))
        } else {
            w_state.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// Type alias for connection table mapping (peer address, connection id) -> packet sender
type UtpConnectionTable = Arc<RwLock<HashMap<(SocketAddr, u16), mpsc::Sender<UtpPacket>>>>;

/// UDP Socket Manager for multiplexing uTP connections on a single UDP port.
pub struct UtpSocketManager {
    socket: Arc<UdpTransport>,
    local_addr: SocketAddr,
    connections: UtpConnectionTable,
    pending_syn_count: Arc<AtomicUsize>,
    syn_flood_limit: usize,
    accept_tx: mpsc::Sender<(UtpStream, SocketAddr)>,
    accept_rx: tokio::sync::Mutex<mpsc::Receiver<(UtpStream, SocketAddr)>>,
    shutdown: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
    packet_loss_counter: Arc<AtomicU64>,
}

impl UtpSocketManager {
    /// Binds a UDP socket for uTP on `bind_addr` with a default SYN-flood limit of 1000.
    pub async fn bind(bind_addr: SocketAddr) -> IoResult<Arc<Self>> {
        Self::bind_with_syn_limit(bind_addr, 1000).await
    }

    /// Binds a UDP socket for uTP on `bind_addr` with a specified SYN-flood limit.
    pub async fn bind_with_syn_limit(
        bind_addr: SocketAddr,
        syn_flood_limit: usize,
    ) -> IoResult<Arc<Self>> {
        let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
        Self::with_transport(UdpTransport::Plain(socket), syn_flood_limit).await
    }

    /// Runs uTP over an already-bound transport, e.g. the uTP half of a `UdpMux` that shares
    /// its port with the DHT.
    pub async fn with_transport(
        transport: UdpTransport,
        syn_flood_limit: usize,
    ) -> IoResult<Arc<Self>> {
        let socket = Arc::new(transport);
        let local_addr = socket.local_addr()?;
        let (accept_tx, accept_rx) = mpsc::channel(256);
        let shutdown = Arc::new(AtomicBool::new(false));
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let manager = Arc::new(Self {
            socket: socket.clone(),
            local_addr,
            connections: Arc::new(RwLock::new(HashMap::new())),
            pending_syn_count: Arc::new(AtomicUsize::new(0)),
            syn_flood_limit,
            accept_tx,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
            shutdown: shutdown.clone(),
            shutdown_tx,
            packet_loss_counter: Arc::new(AtomicU64::new(0)),
        });

        // Hold only `Weak<UtpSocketManager>` so dropping all external `Arc`s runs `Drop`
        // and immediately wakes the demultiplexer loop via `watch` without missed wakeups.
        let weak_mgr = Arc::downgrade(&manager);
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while !shutdown.load(Ordering::Relaxed) && !*shutdown_rx.borrow() {
                let recv_result = tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => break,
                    res = socket.recv_bytes(&mut buf) => res,
                };
                match recv_result {
                    Ok((raw, remote_addr)) => {
                        let Some(mgr) = weak_mgr.upgrade() else {
                            break;
                        };
                        let Ok(packet) = UtpPacket::decode(raw) else {
                            trace!("Dropped malformed uTP packet from {}", remote_addr);
                            continue;
                        };

                        // A SYN names the id the *initiator* receives on (R); the connection we
                        // registered for it is keyed by the id we receive on (R + 1). So a repeated
                        // SYN (the initiator retransmitting because our STATE was lost, or a
                        // duplicated datagram) must be looked up under R + 1, or it would be taken
                        // for a new connection that replaces, and so kills, the established one.
                        let conn_id = if packet.header.ptype == UtpType::Syn {
                            packet.header.connection_id.wrapping_add(1)
                        } else {
                            packet.header.connection_id
                        };
                        let sender_opt = {
                            let table = mgr.connections.read();
                            table.get(&(remote_addr, conn_id)).cloned()
                        };

                        if let Some(tx) = sender_opt {
                            let _ = tx.try_send(packet);
                        } else if packet.header.ptype == UtpType::Syn {
                            // Inbound SYN
                            if mgr.pending_syn_count.load(Ordering::Relaxed) >= mgr.syn_flood_limit
                            {
                                debug!(addr = %remote_addr, "Rejecting inbound uTP SYN: SYN flood limit reached");
                                let mut reset_hdr = UtpHeader::new(
                                    UtpType::Reset,
                                    packet.header.connection_id,
                                    0,
                                    0,
                                    0,
                                );
                                reset_hdr.timestamp_us = now_micros();
                                let reset_pkt = UtpPacket::new(reset_hdr, Bytes::new());
                                let _ = mgr.socket.send_to(&reset_pkt.encode(), remote_addr).await;
                                continue;
                            }

                            mgr.handle_inbound_syn(packet, remote_addr).await;
                        }
                    }
                    Err(e) => {
                        if shutdown.load(Ordering::Relaxed) || *shutdown_rx.borrow() {
                            break;
                        }
                        if matches!(
                            e.kind(),
                            ErrorKind::ConnectionReset
                                | ErrorKind::ConnectionRefused
                                | ErrorKind::ConnectionAborted
                                | ErrorKind::Interrupted
                                | ErrorKind::WouldBlock
                        ) {
                            continue;
                        }
                        if matches!(e.kind(), ErrorKind::BrokenPipe | ErrorKind::NotConnected) {
                            debug!("uTP socket closed, stopping demultiplexer: {}", e);
                            break;
                        }
                        warn!("uTP socket recv_from error, backing off: {}", e);
                        tokio::select! {
                            _ = shutdown_rx.changed() => break,
                            _ = tokio::time::sleep(Duration::from_millis(25)) => {}
                        }
                    }
                }
            }
        });

        Ok(manager)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn packet_loss_total(&self) -> u64 {
        self.packet_loss_counter.load(Ordering::Relaxed)
    }

    pub fn record_loss(&self) {
        self.packet_loss_counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn packet_loss_counter(&self) -> Arc<AtomicU64> {
        self.packet_loss_counter.clone()
    }

    /// Accepts an incoming uTP connection.
    pub async fn accept(&self) -> IoResult<(UtpStream, SocketAddr)> {
        let mut rx = self.accept_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| Error::new(ErrorKind::BrokenPipe, "uTP socket manager stopped"))
    }

    /// Initiates an outbound uTP connection to `remote_addr`.
    pub async fn connect(&self, remote_addr: SocketAddr) -> IoResult<UtpStream> {
        let recv_id: u16 = rand::thread_rng().gen();
        let (pkt_tx, pkt_rx) = mpsc::channel(256);
        let (outbound_tx, outbound_rx) = mpsc::channel(64);

        let mut conn = UtpConnection::new_outgoing(recv_id);
        let syn_pkt = conn.build_syn_packet();

        // Register in connection table (we receive packets addressed to our recv_conn_id)
        {
            let mut table = self.connections.write();
            table.insert((remote_addr, conn.recv_conn_id), pkt_tx);
        }

        // Send initial SYN
        self.socket.send_to(&syn_pkt.encode(), remote_addr).await?;

        let read_state = Arc::new(Mutex::new(StreamReadState::default()));
        let write_state = Arc::new(Mutex::new(StreamWriteState::default()));
        let flush_notify = Arc::new(Notify::new());
        let shutdown_notify = Arc::new(Notify::new());
        let read_window_notify = Arc::new(Notify::new());
        let closed = Arc::new(AtomicBool::new(false));

        let stream = UtpStream {
            peer_addr: remote_addr,
            local_addr: self.local_addr,
            read_state: read_state.clone(),
            write_state: write_state.clone(),
            outbound_tx,
            flush_notify: flush_notify.clone(),
            shutdown_notify: shutdown_notify.clone(),
            read_window_notify: read_window_notify.clone(),
            closed: closed.clone(),
        };

        let (connect_tx, connect_rx) = oneshot::channel();
        let initial_syn_pkt = Some(syn_pkt);

        // Spawn connection driver task
        let socket = self.socket.clone();
        let connections = self.connections.clone();
        let packet_loss = self.packet_loss_counter.clone();
        tokio::spawn(async move {
            drive_utp_connection(
                socket,
                remote_addr,
                conn,
                pkt_rx,
                outbound_rx,
                read_state,
                write_state,
                flush_notify,
                shutdown_notify,
                read_window_notify,
                closed,
                connections,
                None,
                Some(connect_tx),
                initial_syn_pkt,
                packet_loss,
            )
            .await;
        });

        connect_rx.await.map_err(|_| {
            Error::new(
                ErrorKind::ConnectionReset,
                "uTP driver exited before connecting",
            )
        })??;

        Ok(stream)
    }

    async fn handle_inbound_syn(&self, syn_pkt: UtpPacket, remote_addr: SocketAddr) {
        if self.connections.read().len() >= self.syn_flood_limit.max(512) {
            debug!(addr = %remote_addr, "Dropping inbound uTP SYN: connection table limit reached");
            return;
        }
        let conn = UtpConnection::new_incoming(&syn_pkt);
        let (pkt_tx, pkt_rx) = mpsc::channel(256);
        let (outbound_tx, outbound_rx) = mpsc::channel(64);

        let read_state = Arc::new(Mutex::new(StreamReadState::default()));
        let write_state = Arc::new(Mutex::new(StreamWriteState::default()));
        let flush_notify = Arc::new(Notify::new());
        let shutdown_notify = Arc::new(Notify::new());
        let read_window_notify = Arc::new(Notify::new());
        let closed = Arc::new(AtomicBool::new(false));

        let stream = UtpStream {
            peer_addr: remote_addr,
            local_addr: self.local_addr,
            read_state: read_state.clone(),
            write_state: write_state.clone(),
            outbound_tx,
            flush_notify: flush_notify.clone(),
            shutdown_notify: shutdown_notify.clone(),
            read_window_notify: read_window_notify.clone(),
            closed: closed.clone(),
        };

        if self.accept_tx.try_send((stream, remote_addr)).is_err() {
            debug!(
                addr = %remote_addr,
                "Dropping inbound uTP SYN: accept backlog channel is full or closed"
            );
            return;
        }

        self.pending_syn_count.fetch_add(1, Ordering::Relaxed);

        // Register in connection table
        {
            let mut table = self.connections.write();
            table.insert((remote_addr, conn.recv_conn_id), pkt_tx);
        }

        // Immediately send STATE (ACK) to complete handshake
        let state_pkt = conn.build_state_packet();
        let _ = self.socket.send_to(&state_pkt.encode(), remote_addr).await;

        let pending_syn = self.pending_syn_count.clone();
        let socket = self.socket.clone();
        let connections = self.connections.clone();
        let packet_loss = self.packet_loss_counter.clone();

        tokio::spawn(async move {
            drive_utp_connection(
                socket,
                remote_addr,
                conn,
                pkt_rx,
                outbound_rx,
                read_state,
                write_state,
                flush_notify,
                shutdown_notify,
                read_window_notify,
                closed,
                connections,
                Some(pending_syn),
                None,
                None,
                packet_loss,
            )
            .await;
        });
    }
}

impl Drop for UtpSocketManager {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = self.shutdown_tx.send(true);
    }
}

/// Data accepted from the stream but not yet put on the wire because the congestion or flow
/// control window was full. Kept per connection so nothing the application wrote is ever
/// dropped when the window is closed; it is sent as ACKs open the window again.
struct PendingOut {
    chunks: VecDeque<Bytes>,
    bytes: usize,
}

/// Most unsent bytes held per connection; past this the loop stops taking new writes from the
/// stream, which is what pushes back on the writer.
const PENDING_OUT_CAP: usize = 512 * 1024;

struct PendingSynGuard(Option<Arc<AtomicUsize>>);

impl PendingSynGuard {
    fn release(&mut self) {
        if let Some(counter) = self.0.take() {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn is_pending(&self) -> bool {
        self.0.is_some()
    }
}

impl Drop for PendingSynGuard {
    fn drop(&mut self) {
        self.release();
    }
}

async fn send_packet(
    socket: &UdpTransport,
    remote_addr: SocketAddr,
    pkt: &UtpPacket,
    send_buf: &mut BytesMut,
) {
    send_buf.clear();
    pkt.encode_into(send_buf);
    let _ = socket.send_to(send_buf, remote_addr).await;
}

async fn send_state_packet(
    socket: &UdpTransport,
    remote_addr: SocketAddr,
    conn: &UtpConnection,
    out_of_order: &BTreeMap<u16, Bytes>,
    send_buf: &mut BytesMut,
) {
    let state_pkt = if out_of_order.is_empty() {
        conn.build_state_packet()
    } else if let Some(mask) = build_sack_bitmask_iter(conn.ack_nr, out_of_order.keys().copied()) {
        conn.build_state_packet_with_sack(mask)
    } else {
        conn.build_state_packet()
    };
    send_packet(socket, remote_addr, &state_pkt, send_buf).await;
}

/// Applies a BEP 29 SACK bitmask in O(sacked_bits + in_flight_gap) using direct offset
/// indexing from `in_flight.front().seq_nr`, and returns `(newly_sacked_bytes, fast_retransmit_idx)`.
fn apply_sack_and_find_fast_retransmit(
    in_flight: &mut VecDeque<InFlightPacket>,
    ack_nr: u16,
    bitmask: &[u8],
    total_sacked_in_flight: &mut usize,
    congestion: &mut LedbatCongestionController,
) -> (u32, Option<usize>) {
    let Some(base_seq) = in_flight.front().map(|p| p.seq_nr) else {
        return (0, None);
    };

    let mut newly_sacked_bytes = 0u32;
    for (byte_idx, &byte) in bitmask.iter().enumerate() {
        let mut b = byte;
        while b != 0 {
            let bit_idx = b.trailing_zeros() as usize;
            b &= b - 1;
            let seq = ack_nr
                .wrapping_add(2)
                .wrapping_add((byte_idx * 8 + bit_idx) as u16);
            let dist = seq_distance(base_seq, seq);
            if dist >= 0 {
                if let Some(pkt) = in_flight.get_mut(dist as usize) {
                    if pkt.seq_nr == seq && !pkt.sacked {
                        pkt.sacked = true;
                        *total_sacked_in_flight += 1;
                        let len = pkt.payload.len() as u32;
                        congestion.on_bytes_acknowledged(len);
                        newly_sacked_bytes = newly_sacked_bytes.saturating_add(len);
                    }
                }
            }
        }
    }

    if *total_sacked_in_flight < 3 {
        return (newly_sacked_bytes, None);
    }

    let mut sacked_so_far = 0usize;
    let mut fast_retransmit_idx = None;
    for (idx, pkt) in in_flight.iter().enumerate() {
        if pkt.sacked {
            sacked_so_far += 1;
        } else {
            let sacked_ahead = total_sacked_in_flight.saturating_sub(sacked_so_far);
            if sacked_ahead < 3 {
                break;
            }
            if seq_distance(ack_nr, pkt.seq_nr) > 0 && pkt.transmits <= 3 {
                fast_retransmit_idx = Some(idx);
                break;
            }
        }
    }

    (newly_sacked_bytes, fast_retransmit_idx)
}

/// Sends queued data while the congestion & flow-control windows allow (`can_send`). When the
/// receiver advertises a non-zero window smaller than a full MTU and nothing is in flight, sends
/// a smaller slice bounded by `remote_wnd` so forward progress cannot stall; zero-window probing is
/// handled explicitly on a periodic timer in `drive_utp_connection`.
///
/// Returns `true` if at least one packet was transmitted.
#[allow(clippy::too_many_arguments)]
async fn pump_outbound(
    conn: &mut UtpConnection,
    in_flight: &mut VecDeque<InFlightPacket>,
    pending: &mut PendingOut,
    socket: &UdpTransport,
    remote_addr: SocketAddr,
    mtu: usize,
    remote_wnd: u32,
    send_buf: &mut BytesMut,
) -> bool {
    let mut sent_any = false;
    while let Some(front) = pending.chunks.front_mut() {
        let mut chunk_size = front.len().min(mtu);
        if !conn.congestion.can_send(chunk_size, remote_wnd) {
            if remote_wnd > 0 && in_flight.is_empty() {
                chunk_size = chunk_size.min(remote_wnd as usize).max(1);
            } else {
                break;
            }
        }
        let payload = front.split_to(chunk_size);
        if front.is_empty() {
            pending.chunks.pop_front();
        }
        pending.bytes -= chunk_size;

        let pkt = conn.build_data_packet(payload.clone());
        send_packet(socket, remote_addr, &pkt, send_buf).await;
        conn.congestion.on_packet_sent(payload.len());
        in_flight.push_back(InFlightPacket {
            seq_nr: pkt.header.seq_nr,
            send_time: Instant::now(),
            payload,
            transmits: 1,
            sacked: false,
        });
        sent_any = true;
    }
    sent_any
}

fn drain_ooo_and_check_fin(
    conn: &mut UtpConnection,
    read_state: &Mutex<StreamReadState>,
    out_of_order: &mut BTreeMap<u16, Bytes>,
    expected_seq: &mut u16,
    remote_fin_seq: Option<u16>,
    remote_fin_delivered: &mut bool,
    mut woke_data: bool,
) {
    let mut rs = read_state.lock();
    while out_of_order
        .get(expected_seq)
        .is_some_and(|p| rs.buffer.len() + p.len() <= RECV_BUFFER_CAP)
    {
        let payload = out_of_order.remove(expected_seq).expect("checked");
        rs.buffer.extend(&payload);
        *expected_seq = expected_seq.wrapping_add(1);
        woke_data = true;
    }
    conn.ack_nr = expected_seq.wrapping_sub(1);

    if !*remote_fin_delivered && remote_fin_seq == Some(*expected_seq) {
        *remote_fin_delivered = true;
        conn.ack_nr = *expected_seq;
        conn.state = UtpConnectionState::Closed;
        rs.eof = true;
        woke_data = true;
    }
    if woke_data {
        if let Some(w) = rs.waker.take() {
            w.wake();
        }
    }
    conn.recv_wnd = RECV_BUFFER_CAP.saturating_sub(rs.buffer.len()) as u32;
}

fn fail_stream(
    read_state: &Mutex<StreamReadState>,
    write_state: &Mutex<StreamWriteState>,
    err_msg: String,
) {
    {
        let mut rs = read_state.lock();
        rs.error = Some(err_msg.clone());
        if let Some(w) = rs.waker.take() {
            w.wake();
        }
    }
    {
        let mut ws = write_state.lock();
        ws.error = Some(err_msg);
        if let Some(w) = ws.write_waker.take() {
            w.wake();
        }
        if let Some(w) = ws.flush_waker.take() {
            w.wake();
        }
    }
}

/// Drives a single uTP connection: manages packet transmission, in-flight queue,
/// LEDBAT congestion control, RTT estimation, SACK, and retransmissions.
#[allow(clippy::too_many_arguments)]
async fn drive_utp_connection(
    socket: Arc<UdpTransport>,
    remote_addr: SocketAddr,
    mut conn: UtpConnection,
    mut inbound_pkt_rx: mpsc::Receiver<UtpPacket>,
    mut outbound_data_rx: mpsc::Receiver<Bytes>,
    read_state: Arc<Mutex<StreamReadState>>,
    write_state: Arc<Mutex<StreamWriteState>>,
    flush_notify: Arc<Notify>,
    shutdown_notify: Arc<Notify>,
    read_window_notify: Arc<Notify>,
    closed: Arc<AtomicBool>,
    connections: UtpConnectionTable,
    pending_syn_guard: Option<Arc<AtomicUsize>>,
    mut connect_tx: Option<oneshot::Sender<IoResult<()>>>,
    initial_syn_pkt: Option<UtpPacket>,
    packet_loss: Arc<AtomicU64>,
) {
    let mut syn_guard = PendingSynGuard(pending_syn_guard);
    let mut in_flight: VecDeque<InFlightPacket> = VecDeque::new();
    let mut pending = PendingOut {
        chunks: VecDeque::new(),
        bytes: 0,
    };
    let mut out_of_order: BTreeMap<u16, Bytes> = BTreeMap::new();
    let mut expected_seq = conn.ack_nr.wrapping_add(1);
    let mut rtt_est = RttEstimator::new();
    let mut remote_wnd = MAX_CWND_BYTES;
    let mut last_ack_received = 0u16;
    let mut dup_ack_count = 0u32;
    let mut current_mtu = DEFAULT_MTU_PAYLOAD;

    let mut syn_sent_time = Instant::now();
    let mut syn_transmits = 1u32;
    let mut syn_rto_ms = 250u64;
    let mut last_recv_at = Instant::now();
    let mut last_zwp_at = Instant::now() - Duration::from_secs(1);

    let mut remote_fin_seq: Option<u16> = None;
    let mut remote_fin_delivered = false;
    let mut local_shutdown = false;
    let mut shutdown_started: Option<Instant> = None;
    let mut outbound_closed = false;

    let mut tick_timer = tokio::time::interval(Duration::from_millis(50));
    tick_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    const DELAYED_ACK_TIMEOUT: Duration = Duration::from_millis(25);
    let delayed_ack_sleep = tokio::time::sleep(Duration::from_secs(3600));
    tokio::pin!(delayed_ack_sleep);
    let mut delayed_ack_armed = false;
    let mut unacked_in_order_pkts: u32 = 0;
    let mut total_sacked_in_flight: usize = 0;
    let mut send_buf = BytesMut::with_capacity(2048);

    loop {
        if local_shutdown {
            while let Ok(data) = outbound_data_rx.try_recv() {
                if !data.is_empty() {
                    pending.bytes += data.len();
                    pending.chunks.push_back(data);
                }
                let mut ws = write_state.lock();
                ws.queued_channel_chunks = ws.queued_channel_chunks.saturating_sub(1);
            }
            let drained = pending.chunks.is_empty() && in_flight.is_empty();
            let timed_out = shutdown_started.is_some_and(|t| t.elapsed() >= Duration::from_secs(2));
            if drained || timed_out {
                let fin_pkt = conn.build_fin_packet();
                send_packet(&socket, remote_addr, &fin_pkt, &mut send_buf).await;
                let mut ws = write_state.lock();
                ws.is_closed = true;
                if let Some(w) = ws.write_waker.take() {
                    w.wake();
                }
                if let Some(w) = ws.flush_waker.take() {
                    w.wake();
                }
                break;
            }
        } else if remote_fin_delivered && pending.chunks.is_empty() && in_flight.is_empty() {
            if delayed_ack_armed {
                send_state_packet(&socket, remote_addr, &conn, &out_of_order, &mut send_buf).await;
            }
            break;
        }

        tokio::select! {
            // 1. Incoming packets from demuxer
            pkt_opt = inbound_pkt_rx.recv() => {
                let Some(pkt) = pkt_opt else {
                    break;
                };

                let recv_now_us = now_micros();
                last_recv_at = Instant::now();
                conn.record_remote_timestamp(pkt.header.timestamp_us, recv_now_us);
                remote_wnd = pkt.header.wnd_size;

                // Validate ack_nr is within the active unacknowledged window when packets are in flight.
                let ack_nr = pkt.header.ack_nr;
                let ack_in_window = if let (Some(front), Some(back)) = (in_flight.front(), in_flight.back()) {
                    let lo = front.seq_nr.wrapping_sub(1);
                    let hi = back.seq_nr;
                    seq_less_equal(lo, ack_nr) && seq_less_equal(ack_nr, hi)
                } else {
                    true
                };

                let mut total_acked_for_ledbat = 0u32;
                if !in_flight.is_empty() && ack_in_window {
                    let mut acked_bytes = 0u32;
                    while let Some(front) = in_flight.front() {
                        if seq_less_equal(front.seq_nr, ack_nr) {
                            let removed = in_flight.pop_front().unwrap();
                            // A packet already selectively acknowledged was counted then.
                            if removed.sacked {
                                total_sacked_in_flight = total_sacked_in_flight.saturating_sub(1);
                            } else {
                                acked_bytes += removed.payload.len() as u32;
                            }
                            if removed.transmits == 1 {
                                let sample_us = removed.send_time.elapsed().as_micros() as u32;
                                rtt_est.on_rtt_sample(sample_us);
                            }
                        } else {
                            break;
                        }
                    }

                    if acked_bytes > 0 {
                        conn.congestion.on_bytes_acknowledged(acked_bytes);
                        total_acked_for_ledbat = total_acked_for_ledbat.saturating_add(acked_bytes);
                    }

                    // SACK processing
                    if let Some(ref bitmask) = pkt.sack_bitmask {
                        let (newly_sacked_bytes, fast_retransmit_idx) =
                            apply_sack_and_find_fast_retransmit(
                                &mut in_flight,
                                ack_nr,
                                bitmask,
                                &mut total_sacked_in_flight,
                                &mut conn.congestion,
                            );
                        total_acked_for_ledbat =
                            total_acked_for_ledbat.saturating_add(newly_sacked_bytes);
                        if let Some(idx) = fast_retransmit_idx {
                            let pkt = &mut in_flight[idx];
                            let data_pkt = conn.build_data_packet_with_seq(pkt.seq_nr, pkt.payload.clone());
                            send_packet(&socket, remote_addr, &data_pkt, &mut send_buf).await;
                            pkt.transmits += 1;
                            pkt.send_time = Instant::now();
                            packet_loss.fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    // Duplicate ACK detection
                    if ack_nr == last_ack_received && pkt.payload.is_empty() && !in_flight.is_empty() {
                        dup_ack_count += 1;
                        if dup_ack_count == 3 {
                            if let Some(front) = in_flight.front_mut() {
                                let data_pkt = conn.build_data_packet_with_seq(front.seq_nr, front.payload.clone());
                                send_packet(&socket, remote_addr, &data_pkt, &mut send_buf).await;
                                front.transmits += 1;
                                front.send_time = Instant::now();
                                packet_loss.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    } else {
                        last_ack_received = ack_nr;
                        dup_ack_count = 0;
                    }
                }

                // Update LEDBAT delay sample using real newly-acknowledged bytes.
                if total_acked_for_ledbat > 0 && pkt.header.timestamp_diff_us > 0 {
                    conn.congestion
                        .on_ack(total_acked_for_ledbat, pkt.header.timestamp_diff_us);
                }

                // The window may have opened: send what was waiting, then update stream write state.
                if pump_outbound(&mut conn, &mut in_flight, &mut pending, &socket, remote_addr, current_mtu, remote_wnd, &mut send_buf).await
                    && out_of_order.is_empty()
                {
                    unacked_in_order_pkts = 0;
                    delayed_ack_armed = false;
                }
                {
                    let mut ws = write_state.lock();
                    ws.inflight_count = ws.queued_channel_chunks + in_flight.len() + pending.chunks.len();
                    if let Some(w) = ws.write_waker.take() {
                        w.wake();
                    }
                    if ws.inflight_count == 0 {
                        if let Some(w) = ws.flush_waker.take() {
                            w.wake();
                        }
                    }
                }

                match pkt.header.ptype {
                    UtpType::Data => {
                        syn_guard.release();
                        conn.state = UtpConnectionState::Connected;
                        let seq = pkt.header.seq_nr;
                        let had_ooo = !out_of_order.is_empty();
                        let mut accepted_in_order = false;
                        let mut fin_just_delivered = false;

                        if seq == expected_seq {
                            let mut pushed = false;
                            {
                                let mut rs = read_state.lock();
                                if rs.buffer.len() + pkt.payload.len() <= RECV_BUFFER_CAP {
                                    rs.buffer.extend(&pkt.payload);
                                    expected_seq = expected_seq.wrapping_add(1);
                                    pushed = !pkt.payload.is_empty();
                                    accepted_in_order = true;
                                }
                            }
                            let fin_before = remote_fin_delivered;
                            drain_ooo_and_check_fin(
                                &mut conn,
                                &read_state,
                                &mut out_of_order,
                                &mut expected_seq,
                                remote_fin_seq,
                                &mut remote_fin_delivered,
                                pushed,
                            );
                            fin_just_delivered = !fin_before && remote_fin_delivered;
                        } else if (1..=MAX_OUT_OF_ORDER_PACKETS).contains(&seq_distance(expected_seq, seq)) {
                            out_of_order.insert(seq, pkt.payload);
                            conn.recv_wnd = RECV_BUFFER_CAP.saturating_sub(read_state.lock().buffer.len()) as u32;
                        } else {
                            conn.recv_wnd = RECV_BUFFER_CAP.saturating_sub(read_state.lock().buffer.len()) as u32;
                        }

                        // Coalesce clean in-order ACKs (every 2 packets or 25ms); ACK immediately on
                        // gaps, filled gaps, FIN delivery, low receive window, or unaccepted data.
                        let send_ack_now = !accepted_in_order
                            || had_ooo
                            || !out_of_order.is_empty()
                            || fin_just_delivered
                            || conn.recv_wnd < (DEFAULT_MTU_PAYLOAD * 4) as u32
                            || unacked_in_order_pkts + 1 >= 2;
                        if send_ack_now {
                            unacked_in_order_pkts = 0;
                            delayed_ack_armed = false;
                            send_state_packet(&socket, remote_addr, &conn, &out_of_order, &mut send_buf).await;
                        } else {
                            unacked_in_order_pkts += 1;
                            if !delayed_ack_armed {
                                delayed_ack_sleep
                                    .as_mut()
                                    .reset(tokio::time::Instant::now() + DELAYED_ACK_TIMEOUT);
                                delayed_ack_armed = true;
                            }
                        }
                    }
                    UtpType::Fin => {
                        syn_guard.release();
                        remote_fin_seq = Some(pkt.header.seq_nr);
                        drain_ooo_and_check_fin(
                            &mut conn,
                            &read_state,
                            &mut out_of_order,
                            &mut expected_seq,
                            remote_fin_seq,
                            &mut remote_fin_delivered,
                            false,
                        );
                        unacked_in_order_pkts = 0;
                        delayed_ack_armed = false;
                        send_state_packet(&socket, remote_addr, &conn, &out_of_order, &mut send_buf).await;
                    }
                    UtpType::Reset => {
                        syn_guard.release();
                        if let Some(tx) = connect_tx.take() {
                            let _ = tx.send(Err(Error::new(ErrorKind::ConnectionRefused, "uTP connection reset by peer")));
                        }
                        conn.state = UtpConnectionState::Reset;
                        fail_stream(&read_state, &write_state, "uTP connection reset by peer".to_string());
                        break;
                    }
                    UtpType::State => {
                        syn_guard.release();
                        if conn.state == UtpConnectionState::SynSent
                            && pkt.header.ack_nr == conn.seq_nr.wrapping_sub(1)
                        {
                            conn.state = UtpConnectionState::Connected;
                            conn.ack_nr = pkt.header.seq_nr.wrapping_sub(1);
                            expected_seq = pkt.header.seq_nr;
                            if let Some(tx) = connect_tx.take() {
                                let _ = tx.send(Ok(()));
                            }
                        }
                    }
                    UtpType::Syn => {
                        // A repeated SYN: the initiator has not seen our STATE yet. Say it again.
                        conn.state = UtpConnectionState::Connected;
                        unacked_in_order_pkts = 0;
                        delayed_ack_armed = false;
                        send_state_packet(&socket, remote_addr, &conn, &out_of_order, &mut send_buf).await;
                    }
                }
            }

            // 2. Outbound data from UtpStream.
            data_opt = outbound_data_rx.recv(), if !outbound_closed && pending.bytes < PENDING_OUT_CAP => {
                match data_opt {
                    None => {
                        outbound_closed = true;
                        local_shutdown = true;
                        shutdown_started.get_or_insert_with(Instant::now);
                    }
                    Some(data) => {
                        if !data.is_empty() {
                            pending.bytes += data.len();
                            pending.chunks.push_back(data);
                        }
                        if pump_outbound(&mut conn, &mut in_flight, &mut pending, &socket, remote_addr, current_mtu, remote_wnd, &mut send_buf).await
                            && out_of_order.is_empty()
                        {
                            unacked_in_order_pkts = 0;
                            delayed_ack_armed = false;
                        }

                        let mut ws = write_state.lock();
                        ws.queued_channel_chunks = ws.queued_channel_chunks.saturating_sub(1);
                        ws.inflight_count = ws.queued_channel_chunks + in_flight.len() + pending.chunks.len();
                        if let Some(w) = ws.write_waker.take() {
                            w.wake();
                        }
                        if ws.inflight_count == 0 {
                            if let Some(w) = ws.flush_waker.take() {
                                w.wake();
                            }
                        }
                    }
                }
            }

            // 3. Periodic timer for retransmission, zero-window probes & idle timeouts
            _ = tick_timer.tick() => {
                if pump_outbound(&mut conn, &mut in_flight, &mut pending, &socket, remote_addr, current_mtu, remote_wnd, &mut send_buf).await
                    && out_of_order.is_empty()
                {
                    unacked_in_order_pkts = 0;
                    delayed_ack_armed = false;
                }

                // Zero-window probe: avoid permanent stall if peer's window-opening STATE packet was lost.
                if remote_wnd == 0
                    && !pending.chunks.is_empty()
                    && in_flight.is_empty()
                    && last_zwp_at.elapsed() >= Duration::from_millis(500)
                {
                    if let Some(front) = pending.chunks.front_mut() {
                        let probe = front.split_to(1);
                        if front.is_empty() {
                            pending.chunks.pop_front();
                        }
                        pending.bytes -= 1;
                        let pkt = conn.build_data_packet(probe.clone());
                        send_packet(&socket, remote_addr, &pkt, &mut send_buf).await;
                        conn.congestion.on_packet_sent(1);
                        in_flight.push_back(InFlightPacket {
                            seq_nr: pkt.header.seq_nr,
                            send_time: Instant::now(),
                            payload: probe,
                            transmits: 1,
                            sacked: false,
                        });
                        last_zwp_at = Instant::now();
                    }
                }

                // Periodically advertise freed receive buffer space even without incoming packets.
                let actual_free = RECV_BUFFER_CAP.saturating_sub(read_state.lock().buffer.len()) as u32;
                if conn.recv_wnd < DEFAULT_MTU_PAYLOAD as u32
                    && actual_free >= (DEFAULT_MTU_PAYLOAD * 4) as u32
                {
                    drain_ooo_and_check_fin(
                        &mut conn,
                        &read_state,
                        &mut out_of_order,
                        &mut expected_seq,
                        remote_fin_seq,
                        &mut remote_fin_delivered,
                        false,
                    );
                    unacked_in_order_pkts = 0;
                    delayed_ack_armed = false;
                    send_state_packet(&socket, remote_addr, &conn, &out_of_order, &mut send_buf).await;
                }

                if conn.state == UtpConnectionState::SynSent
                    && syn_sent_time.elapsed().as_millis() as u64 >= syn_rto_ms
                {
                    if syn_transmits >= 3 {
                        if let Some(tx) = connect_tx.take() {
                            let _ = tx.send(Err(Error::new(ErrorKind::TimedOut, "uTP connection timed out")));
                        }
                        break;
                    } else if let Some(ref syn) = initial_syn_pkt {
                        send_packet(&socket, remote_addr, syn, &mut send_buf).await;
                        syn_transmits += 1;
                        syn_sent_time = Instant::now();
                        syn_rto_ms = (syn_rto_ms * 2).min(2000);
                    }
                }

                let idle_limit = if syn_guard.is_pending() {
                    Duration::from_secs(15)
                } else {
                    Duration::from_secs(120)
                };
                if conn.state != UtpConnectionState::SynSent && last_recv_at.elapsed() >= idle_limit {
                    fail_stream(&read_state, &write_state, "uTP connection idle timeout".to_string());
                    break;
                }

                if let Some(front) = in_flight.front_mut() {
                    if front.send_time.elapsed().as_millis() as u32 >= rtt_est.rto_ms {
                        // Timeout: retransmit oldest unacked packet
                        let pkt = conn.build_data_packet_with_seq(front.seq_nr, front.payload.clone());
                        send_packet(&socket, remote_addr, &pkt, &mut send_buf).await;

                        front.transmits += 1;
                        front.send_time = Instant::now();
                        packet_loss.fetch_add(1, Ordering::Relaxed);

                        // Exponential backoff and congestion window collapse
                        rtt_est.on_timeout();
                        conn.congestion.on_loss();
                        current_mtu = (current_mtu / 2).max(576);

                        if front.transmits > 10 {
                            fail_stream(&read_state, &write_state, "uTP connection timed out".to_string());
                            break;
                        }
                    }
                }

                let mut ws = write_state.lock();
                ws.inflight_count = ws.queued_channel_chunks + in_flight.len() + pending.chunks.len();
                if ws.inflight_count == 0 {
                    if let Some(w) = ws.flush_waker.take() {
                        w.wake();
                    }
                }
            }

            // 4. Reader drained buffer from near-full -> send window update immediately.
            _ = read_window_notify.notified() => {
                drain_ooo_and_check_fin(
                    &mut conn,
                    &read_state,
                    &mut out_of_order,
                    &mut expected_seq,
                    remote_fin_seq,
                    &mut remote_fin_delivered,
                    false,
                );
                unacked_in_order_pkts = 0;
                delayed_ack_armed = false;
                send_state_packet(&socket, remote_addr, &conn, &out_of_order, &mut send_buf).await;
            }

            // 5. Delayed ACK timer expired for a lone in-order packet.
            _ = &mut delayed_ack_sleep, if delayed_ack_armed => {
                delayed_ack_armed = false;
                unacked_in_order_pkts = 0;
                send_state_packet(&socket, remote_addr, &conn, &out_of_order, &mut send_buf).await;
            }

            // 6. Shutdown notification: flush remaining queued data before sending FIN.
            _ = shutdown_notify.notified(), if !local_shutdown => {
                local_shutdown = true;
                shutdown_started.get_or_insert_with(Instant::now);
            }

            // 7. Explicit flush notification
            _ = flush_notify.notified() => {
                let mut ws = write_state.lock();
                ws.inflight_count = ws.queued_channel_chunks + in_flight.len() + pending.chunks.len();
                if ws.inflight_count == 0 {
                    if let Some(ref w) = ws.flush_waker {
                        w.wake_by_ref();
                    }
                }
            }
        }
    }

    if let Some(tx) = connect_tx.take() {
        let _ = tx.send(Err(Error::new(
            ErrorKind::ConnectionReset,
            "uTP connection aborted",
        )));
    }

    // Cleanup connection from manager's table
    connections
        .write()
        .remove(&(remote_addr, conn.recv_conn_id));
    drop(syn_guard);
    closed.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_ledbat_congestion_window_adaptation() {
        let mut ledbat = LedbatCongestionController::new();
        assert_eq!(ledbat.max_window_bytes, MIN_CWND_BYTES);

        // Low queue delay (< 100ms) -> Congestion window expands
        ledbat.on_ack(1400, 20_000); // 20ms base
        let initial_base = ledbat.base_delay_us;
        assert_eq!(initial_base, 20_000);

        ledbat.on_ack(1400, 30_000); // 10ms queue delay -> well under target 100ms
        assert!(ledbat.max_window_bytes > MIN_CWND_BYTES);

        // High queue delay (> 100ms) -> Congestion window contracts
        let expanded_cwnd = ledbat.max_window_bytes;
        ledbat.on_ack(1400, 150_000); // 130ms queue delay -> exceeds target 100ms
        assert!(ledbat.max_window_bytes < expanded_cwnd);
    }

    #[test]
    fn test_rtt_estimator_and_backoff() {
        let mut rtt = RttEstimator::new();
        assert_eq!(rtt.rto_ms, 1000);

        rtt.on_rtt_sample(100_000); // 100ms sample
        assert!(rtt.rto_ms >= 500);

        rtt.on_timeout();
        assert!(rtt.rto_ms >= 1000);
    }

    #[test]
    fn test_utp_connection_handshake_and_data_exchange() {
        // 1. Client creates outgoing connection and sends SYN
        let mut client = UtpConnection::new_outgoing(0x8888);
        assert_eq!(client.state, UtpConnectionState::SynSent);
        let syn_pkt = client.build_syn_packet();

        // 2. Server creates incoming connection from SYN and replies with STATE
        let mut server = UtpConnection::new_incoming(&syn_pkt);
        assert_eq!(server.state, UtpConnectionState::Connected);
        let state_pkt = server.build_state_packet();

        // 3. Client receives STATE -> enters Connected
        let data = client.on_packet_recv(&state_pkt).unwrap();
        assert!(data.is_none());
        assert_eq!(client.state, UtpConnectionState::Connected);

        // 4. Client sends DATA packet
        let payload = Bytes::from_static(b"synapse utp block chunk 0");
        let data_pkt = client.build_data_packet(payload.clone());

        // 5. Server receives DATA packet
        let received = server.on_packet_recv(&data_pkt).unwrap().unwrap();
        assert_eq!(received, payload);

        // 6. Client sends FIN to close
        let fin_pkt = client.build_fin_packet();
        assert_eq!(client.state, UtpConnectionState::FinSent);

        server.on_packet_recv(&fin_pkt).unwrap();
        assert_eq!(server.state, UtpConnectionState::Closed);
    }

    #[tokio::test]
    async fn test_utp_socket_manager_duplex_stream_transfer() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let server_mgr = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let server_addr = server_mgr.local_addr();

            let client_mgr = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();

            let server_handle = tokio::spawn(async move {
                let (mut stream, _) = server_mgr.accept().await.unwrap();
                let mut buf = vec![0u8; 100];
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"client payload over utp stream");

                stream.write_all(b"server response payload").await.unwrap();
                stream.flush().await.unwrap();
            });

            let mut client_stream = client_mgr.connect(server_addr).await.unwrap();
            client_stream
                .write_all(b"client payload over utp stream")
                .await
                .unwrap();
            client_stream.flush().await.unwrap();

            let mut resp = vec![0u8; 100];
            let n = client_stream.read(&mut resp).await.unwrap();
            assert_eq!(&resp[..n], b"server response payload");

            server_handle.await.unwrap();
        })
        .await
        .expect("test timed out after 60s");
    }

    #[tokio::test]
    async fn test_utp_syn_flood_guard() {
        // Manager with syn_flood_limit = 2
        let mgr = UtpSocketManager::bind_with_syn_limit("127.0.0.1:0".parse().unwrap(), 2)
            .await
            .unwrap();
        let addr = mgr.local_addr();

        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Send 2 SYNs -> accepted
        for id in [0x1111, 0x2222] {
            let hdr = UtpHeader::new(UtpType::Syn, id, 1, 0, 3000);
            let pkt = UtpPacket::new(hdr, Bytes::new());
            client_sock.send_to(&pkt.encode(), addr).await.unwrap();
            let mut buf = [0u8; 1024];
            let (len, _) =
                tokio::time::timeout(Duration::from_secs(20), client_sock.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            let resp = UtpPacket::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
            assert_eq!(resp.header.ptype, UtpType::State);
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(mgr.pending_syn_count.load(Ordering::Relaxed), 2);

        // 3rd SYN should trigger SYN flood guard and receive ST_RESET
        let hdr = UtpHeader::new(UtpType::Syn, 0x3333, 1, 0, 3000);
        let pkt = UtpPacket::new(hdr, Bytes::new());
        client_sock.send_to(&pkt.encode(), addr).await.unwrap();

        let mut buf = [0u8; 1024];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(20), client_sock.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        let resp = UtpPacket::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
        assert_eq!(resp.header.ptype, UtpType::Reset);
    }

    #[tokio::test]
    async fn dropping_utp_socket_manager_stops_demux_loop_and_releases_port() {
        let mgr = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = mgr.local_addr();
        let weak = Arc::downgrade(&mgr);
        drop(mgr);
        assert!(
            weak.upgrade().is_none(),
            "demux task must not hold a strong Arc reference cycle"
        );

        let mut rebound = false;
        for _ in 0..50 {
            if UdpSocket::bind(addr).await.is_ok() {
                rebound = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            rebound,
            "UDP socket should be closed promptly when UtpSocketManager drops"
        );
    }

    #[test]
    fn ledbat_wraps_u32_delay_cleanly_and_rtt_handles_huge_samples() {
        let mut ledbat = LedbatCongestionController::new();
        let before_wrap = u32::MAX - 5_000;
        let after_wrap = 15_000; // +20_001 us across wraparound
        ledbat.on_ack(1400, before_wrap);
        assert_eq!(ledbat.base_delay_us, before_wrap);

        let w_before = ledbat.max_window_bytes;
        ledbat.on_ack(1400, after_wrap);
        // Must recognize before_wrap as still the smaller base delay and see ~20ms queue delay (< 100ms target).
        assert_eq!(ledbat.base_delay_us, before_wrap);
        assert!(ledbat.max_window_bytes > w_before);

        let mut rtt = RttEstimator::new();
        rtt.on_rtt_sample(u32::MAX);
        assert!(rtt.rto_ms <= 10_000 && rtt.rto_ms >= 500);
        rtt.on_rtt_sample(u32::MAX / 2);
        assert!(rtt.rto_ms <= 10_000 && rtt.rto_ms >= 500);
    }

    #[test]
    fn syn_sent_ignores_wrong_ack_nr_and_sets_ack_nr_to_seq_minus_one() {
        let mut client = UtpConnection::new_outgoing(0x2200);
        let syn = client.build_syn_packet();
        assert_eq!(syn.header.seq_nr, 1);

        // Wrong ack_nr must leave client in SynSent.
        let wrong_state = UtpPacket::new(
            UtpHeader::new(UtpType::State, client.send_conn_id, 500, 999, 65535),
            Bytes::new(),
        );
        client.on_packet_recv(&wrong_state).unwrap();
        assert_eq!(client.state, UtpConnectionState::SynSent);

        // Correct ack_nr = syn.seq_nr sets Connected with ack_nr = remote.seq_nr - 1.
        let right_state = UtpPacket::new(
            UtpHeader::new(
                UtpType::State,
                client.send_conn_id,
                500,
                syn.header.seq_nr,
                65535,
            ),
            Bytes::new(),
        );
        client.on_packet_recv(&right_state).unwrap();
        assert_eq!(client.state, UtpConnectionState::Connected);
        assert_eq!(client.ack_nr, 499);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn graceful_shutdown_flushes_pending_writes_and_out_of_order_fin_waits_for_gap() {
        let server_mgr = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let server_addr = server_mgr.local_addr();
        let client_mgr = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let accept_task = tokio::spawn({
            let mgr = server_mgr.clone();
            async move { mgr.accept().await.unwrap().0 }
        });
        let mut client = client_mgr.connect(server_addr).await.unwrap();
        let mut server = accept_task.await.unwrap();

        let payload = vec![0x5Au8; 64 * 1024];
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();

        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), server.read_to_end(&mut received))
            .await
            .expect("read_to_end timed out")
            .unwrap();
        assert_eq!(received, payload);

        // Also verify out-of-order FIN: server receives Data(2) & Fin(3) before Data(1),
        // and delivers full payload before EOF.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let srv2 = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let srv2_addr = srv2.local_addr();
        let mut raw = UtpConnection::new_outgoing(0x4444);
        let syn = raw.build_syn_packet();
        sock.send_to(&syn.encode(), srv2_addr).await.unwrap();
        let mut buf = [0u8; 2048];
        let (n, _) = sock.recv_from(&mut buf).await.unwrap();
        let st = UtpPacket::decode(Bytes::copy_from_slice(&buf[..n])).unwrap();
        raw.on_packet_recv(&st).unwrap();
        let mut s2 = srv2.accept().await.unwrap().0;

        let p1 = raw.build_data_packet(Bytes::from_static(b"first-"));
        let p2 = raw.build_data_packet(Bytes::from_static(b"second"));
        let pfin = raw.build_fin_packet();
        sock.send_to(&p2.encode(), srv2_addr).await.unwrap();
        sock.send_to(&pfin.encode(), srv2_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        sock.send_to(&p1.encode(), srv2_addr).await.unwrap();

        let mut all = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), s2.read_to_end(&mut all))
            .await
            .expect("out-of-order FIN stalled")
            .unwrap();
        assert_eq!(&all, b"first-second");
    }

    #[test]
    fn test_indexed_sack_and_fast_retransmit_wraparound() {
        // Test across u16::MAX -> 0 wraparound: ack_nr = u16::MAX - 2 (65533),
        // in_flight starts at 65534, 65535, 0, 1, 2, 3.
        let ack_nr = u16::MAX - 2; // 65533
        let seqs = [
            ack_nr.wrapping_add(1), // idx 0: 65534 (gap 0, transmits = 4 -> skip!)
            ack_nr.wrapping_add(2), // idx 1: 65535 (gap 1, transmits = 1 -> pick!)
            ack_nr.wrapping_add(3), // idx 2: 0 (sacked via SACK)
            ack_nr.wrapping_add(4), // idx 3: 1 (already sacked previously)
            ack_nr.wrapping_add(5), // idx 4: 2 (sacked via SACK)
            ack_nr.wrapping_add(6), // idx 5: 3 (sacked via SACK)
        ];
        let payload = Bytes::from_static(b"1234567890");
        let mut in_flight: VecDeque<InFlightPacket> = seqs
            .iter()
            .enumerate()
            .map(|(i, &seq_nr)| InFlightPacket {
                seq_nr,
                send_time: Instant::now(),
                payload: payload.clone(),
                transmits: if i == 0 { 4 } else { 1 },
                sacked: i == 3,
            })
            .collect();
        let mut congestion = LedbatCongestionController::new();
        congestion.on_packet_sent(60);
        let mut total_sacked = 1; // idx 3 already sacked

        // SACK bits cover ack_nr + 2 + offset:
        // seq 0 -> diff=3 -> offset 1 (bit 1)
        // seq 1 -> diff=4 -> offset 2 (bit 2, duplicate SACK!)
        // seq 2 -> diff=5 -> offset 3 (bit 3)
        // seq 3 -> diff=6 -> offset 4 (bit 4)
        // Also include an out-of-range high offset beyond in_flight (bit 7 of byte 3 -> +31)
        // to ensure it is safely ignored without panicking.
        let bitmask = [0b0001_1110u8, 0, 0, 0x80u8];

        let (newly_sacked_bytes, fast_retransmit_idx) = apply_sack_and_find_fast_retransmit(
            &mut in_flight,
            ack_nr,
            &bitmask,
            &mut total_sacked,
            &mut congestion,
        );

        // Only 3 packets were newly sacked (idx 2, 4, 5); idx 3 was not double-counted.
        assert_eq!(newly_sacked_bytes, 30);
        assert_eq!(total_sacked, 4);
        assert_eq!(congestion.bytes_in_flight, 30);
        // idx 0 had 4 sacked packets ahead but transmits == 4 (> 3), so idx 1 is picked.
        assert_eq!(fast_retransmit_idx, Some(1));

        // Now test stale/before-window SACK with base_seq > ack_nr + 2.
        in_flight.pop_front(); // base_seq = 65535
        total_sacked = 4;
        // SACK relative to older ack_nr - 10 so bit 0 is way before base_seq
        let (stale_bytes, _) = apply_sack_and_find_fast_retransmit(
            &mut in_flight,
            ack_nr.wrapping_sub(10),
            &[0x01, 0, 0, 0],
            &mut total_sacked,
            &mut congestion,
        );
        assert_eq!(stale_bytes, 0);
        assert_eq!(total_sacked, 4);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_delayed_ack_coalesces_two_in_order_and_fires_on_timer_and_ooo() {
        let srv = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let srv_addr = srv.local_addr();
        let cli_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut client = UtpConnection::new_outgoing(0x6100);
        let syn = client.build_syn_packet();
        cli_sock.send_to(&syn.encode(), srv_addr).await.unwrap();

        let mut buf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), cli_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let st = UtpPacket::decode(Bytes::copy_from_slice(&buf[..n])).unwrap();
        assert_eq!(st.header.ptype, UtpType::State);
        client.on_packet_recv(&st).unwrap();
        let _server_stream = tokio::time::timeout(Duration::from_secs(2), srv.accept())
            .await
            .unwrap()
            .unwrap()
            .0;

        // 1. Send 1 in-order DATA packet -> delayed ACK timer fires within ~25ms (well before 500ms RTO).
        let d1 = client.build_data_packet(Bytes::from_static(b"packet-1"));
        cli_sock.send_to(&d1.encode(), srv_addr).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_millis(500), cli_sock.recv_from(&mut buf))
            .await
            .expect("delayed ACK did not fire")
            .unwrap();
        let ack1 = UtpPacket::decode(Bytes::copy_from_slice(&buf[..n])).unwrap();
        assert_eq!(ack1.header.ptype, UtpType::State);
        assert_eq!(ack1.header.ack_nr, d1.header.seq_nr);
        assert!(ack1.sack_bitmask.is_none());

        // 2. Send 2 back-to-back in-order DATA packets -> single coalesced ACK covering d3, no extra ACK.
        let d2 = client.build_data_packet(Bytes::from_static(b"packet-2"));
        let d3 = client.build_data_packet(Bytes::from_static(b"packet-3"));
        cli_sock.send_to(&d2.encode(), srv_addr).await.unwrap();
        cli_sock.send_to(&d3.encode(), srv_addr).await.unwrap();

        let (n, _) = tokio::time::timeout(Duration::from_millis(500), cli_sock.recv_from(&mut buf))
            .await
            .expect("coalesced ACK did not arrive")
            .unwrap();
        let ack23 = UtpPacket::decode(Bytes::copy_from_slice(&buf[..n])).unwrap();
        assert_eq!(ack23.header.ptype, UtpType::State);
        assert_eq!(ack23.header.ack_nr, d3.header.seq_nr);
        assert!(
            tokio::time::timeout(Duration::from_millis(60), cli_sock.recv_from(&mut buf))
                .await
                .is_err(),
            "expected single coalesced ACK without a second STATE packet"
        );

        // 3. Skip d4 and send out-of-order d5 -> immediate STATE packet with SACK bitmask.
        let _skipped_d4 = client.build_data_packet(Bytes::from_static(b"packet-4-lost"));
        let d5 = client.build_data_packet(Bytes::from_static(b"packet-5-ooo"));
        cli_sock.send_to(&d5.encode(), srv_addr).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_millis(500), cli_sock.recv_from(&mut buf))
            .await
            .expect("immediate SACK ACK did not arrive for OOO packet")
            .unwrap();
        let sack_pkt = UtpPacket::decode(Bytes::copy_from_slice(&buf[..n])).unwrap();
        assert_eq!(sack_pkt.header.ptype, UtpType::State);
        assert_eq!(sack_pkt.header.ack_nr, d3.header.seq_nr);
        assert!(
            sack_pkt.sack_bitmask.is_some(),
            "out-of-order packet should immediately emit SACK bitmask"
        );
    }
}
