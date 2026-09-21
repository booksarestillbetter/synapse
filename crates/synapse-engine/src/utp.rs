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
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use rand::Rng;
use synapse_wire::UdpTransport;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(test)]
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Notify};
use tracing::{debug, trace, warn};

use synapse_wire::{build_sack_bitmask, parse_sack_bitmask, UtpHeader, UtpPacket, UtpType};

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

/// Returns current UNIX timestamp in microseconds.
pub fn now_micros() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u32
}

/// LEDBAT (Low Extra Delay Background Transport) Delay-Based Congestion Controller.
#[derive(Debug, Clone)]
pub struct LedbatCongestionController {
    pub target_delay_us: u32,
    pub max_window_bytes: u32,
    pub base_delay_us: u32,
    pub cur_delay_us: u32,
    pub bytes_in_flight: u32,
}

impl LedbatCongestionController {
    pub fn new() -> Self {
        Self {
            target_delay_us: LEDBAT_TARGET_DELAY_US,
            max_window_bytes: MIN_CWND_BYTES,
            base_delay_us: u32::MAX,
            cur_delay_us: 0,
            bytes_in_flight: 0,
        }
    }

    /// Records an ACK with its one-way delay sample and adapts the congestion window.
    pub fn on_ack(&mut self, bytes_acked: u32, delay_sample_us: u32) {
        if delay_sample_us == 0 {
            return;
        }

        if delay_sample_us < self.base_delay_us {
            self.base_delay_us = delay_sample_us;
        }
        self.cur_delay_us = delay_sample_us;

        let queue_delay = delay_sample_us.saturating_sub(self.base_delay_us);
        let off_target =
            (self.target_delay_us as f64 - queue_delay as f64) / (self.target_delay_us as f64);

        // Standard LEDBAT window adaptation formula:
        // window_delta = GAIN * off_target * (bytes_acked / max_window)
        let window_factor = (bytes_acked as f64) / (self.max_window_bytes.max(1) as f64);
        let delta = (LEDBAT_GAIN * off_target * window_factor) as i32;

        if delta >= 0 {
            self.max_window_bytes = (self.max_window_bytes + delta as u32).min(MAX_CWND_BYTES);
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
        let effective_wnd = self.max_window_bytes.min(remote_wnd.max(MIN_CWND_BYTES));
        (self.bytes_in_flight + payload_len as u32) <= effective_wnd
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
        if !self.has_sample {
            self.has_sample = true;
            self.srtt_us = sample_us;
            self.rttvar_us = sample_us / 2;
        } else {
            let diff = (self.srtt_us as i64 - sample_us as i64).unsigned_abs() as u32;
            self.rttvar_us = (3 * self.rttvar_us + diff) / 4;
            self.srtt_us = (7 * self.srtt_us + sample_us) / 8;
        }
        let rto_us = self.srtt_us + (4 * self.rttvar_us).max(100_000);
        self.rto_ms = (rto_us / 1000).clamp(500, 10_000);
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
        }
    }

    /// Creates a new incoming uTP connection from a received `Syn` packet.
    pub fn new_incoming(syn_packet: &UtpPacket) -> Self {
        let send_id = syn_packet.header.connection_id;
        let recv_id = send_id.wrapping_add(1);
        Self {
            recv_conn_id: recv_id,
            send_conn_id: send_id,
            seq_nr: 100, // Initial sequence number
            ack_nr: syn_packet.header.seq_nr,
            state: UtpConnectionState::Connected,
            congestion: LedbatCongestionController::new(),
            recv_wnd: RECV_BUFFER_CAP as u32,
            last_remote_timestamp_us: syn_packet.header.timestamp_us,
        }
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
        header.timestamp_diff_us = header
            .timestamp_us
            .wrapping_sub(self.last_remote_timestamp_us);
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
        header.timestamp_diff_us = header
            .timestamp_us
            .wrapping_sub(self.last_remote_timestamp_us);
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
        header.timestamp_diff_us = header
            .timestamp_us
            .wrapping_sub(self.last_remote_timestamp_us);

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
        self.last_remote_timestamp_us = packet.header.timestamp_us;

        // Feed LEDBAT delay sample
        if packet.header.timestamp_diff_us > 0 {
            self.congestion
                .on_ack(1400, packet.header.timestamp_diff_us);
        }

        match packet.header.ptype {
            UtpType::State => {
                if self.state == UtpConnectionState::SynSent {
                    self.state = UtpConnectionState::Connected;
                    self.ack_nr = packet.header.seq_nr;
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
        let mut state = self.read_state.lock();

        if let Some(ref err) = state.error {
            return Poll::Ready(Err(Error::new(ErrorKind::ConnectionReset, err.clone())));
        }

        if !state.buffer.is_empty() {
            let to_read = state.buffer.len().min(buf.remaining());
            let (part1, part2) = state.buffer.as_slices();
            if to_read <= part1.len() {
                buf.put_slice(&part1[..to_read]);
            } else {
                buf.put_slice(part1);
                buf.put_slice(&part2[..(to_read - part1.len())]);
            }
            state.buffer.drain(..to_read);
            return Poll::Ready(Ok(()));
        }

        if state.eof {
            return Poll::Ready(Ok(()));
        }

        state.waker = Some(cx.waker().clone());
        Poll::Pending
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

        let bytes = Bytes::copy_from_slice(buf);
        let len = bytes.len();
        match self.outbound_tx.try_send(bytes) {
            Ok(()) => {
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

        let manager = Arc::new(Self {
            socket: socket.clone(),
            local_addr,
            connections: Arc::new(RwLock::new(HashMap::new())),
            pending_syn_count: Arc::new(AtomicUsize::new(0)),
            syn_flood_limit,
            accept_tx,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
            shutdown: Arc::new(AtomicBool::new(false)),
            packet_loss_counter: Arc::new(AtomicU64::new(0)),
        });

        // Spawn packet demultiplexer
        let mgr = manager.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while !mgr.shutdown.load(Ordering::Relaxed) {
                match mgr.socket.recv_from(&mut buf).await {
                    Ok((len, remote_addr)) => {
                        let raw = Bytes::copy_from_slice(&buf[..len]);
                        let Ok(packet) = UtpPacket::decode(raw) else {
                            trace!("Dropped malformed uTP packet from {}", remote_addr);
                            continue;
                        };

                        let conn_id = packet.header.connection_id;
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
                        if mgr.shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                        warn!("uTP socket recv_from error: {}", e);
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
        let closed = Arc::new(AtomicBool::new(false));

        let stream = UtpStream {
            peer_addr: remote_addr,
            local_addr: self.local_addr,
            read_state: read_state.clone(),
            write_state: write_state.clone(),
            outbound_tx,
            flush_notify: flush_notify.clone(),
            shutdown_notify: shutdown_notify.clone(),
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
        self.pending_syn_count.fetch_add(1, Ordering::Relaxed);
        let conn = UtpConnection::new_incoming(&syn_pkt);
        let (pkt_tx, pkt_rx) = mpsc::channel(256);
        let (outbound_tx, outbound_rx) = mpsc::channel(64);

        // Register in connection table
        {
            let mut table = self.connections.write();
            table.insert((remote_addr, conn.recv_conn_id), pkt_tx);
        }

        // Immediately send STATE (ACK) to complete handshake
        let state_pkt = conn.build_state_packet();
        let _ = self.socket.send_to(&state_pkt.encode(), remote_addr).await;

        let read_state = Arc::new(Mutex::new(StreamReadState::default()));
        let write_state = Arc::new(Mutex::new(StreamWriteState::default()));
        let flush_notify = Arc::new(Notify::new());
        let shutdown_notify = Arc::new(Notify::new());
        let closed = Arc::new(AtomicBool::new(false));

        let stream = UtpStream {
            peer_addr: remote_addr,
            local_addr: self.local_addr,
            read_state: read_state.clone(),
            write_state: write_state.clone(),
            outbound_tx,
            flush_notify: flush_notify.clone(),
            shutdown_notify: shutdown_notify.clone(),
            closed: closed.clone(),
        };

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
                closed,
                connections,
                Some(pending_syn),
                None,
                None,
                packet_loss,
            )
            .await;
        });

        let _ = self.accept_tx.send((stream, remote_addr)).await;
    }
}

impl Drop for UtpSocketManager {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
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

/// Sends queued data while the window allows (`can_send`). Always sends at least one packet
/// when nothing is in flight, so a closed window can never deadlock the connection.
#[allow(clippy::too_many_arguments)]
async fn pump_outbound(
    conn: &mut UtpConnection,
    in_flight: &mut VecDeque<InFlightPacket>,
    pending: &mut PendingOut,
    socket: &UdpTransport,
    remote_addr: SocketAddr,
    mtu: usize,
    remote_wnd: u32,
) {
    while let Some(front) = pending.chunks.front_mut() {
        let chunk_size = front.len().min(mtu);
        if !conn.congestion.can_send(chunk_size, remote_wnd) && !in_flight.is_empty() {
            break;
        }
        let payload = front.split_to(chunk_size);
        if front.is_empty() {
            pending.chunks.pop_front();
        }
        pending.bytes -= chunk_size;

        let pkt = conn.build_data_packet(payload.clone());
        let _ = socket.send_to(&pkt.encode(), remote_addr).await;
        conn.congestion.on_packet_sent(payload.len());
        in_flight.push_back(InFlightPacket {
            seq_nr: pkt.header.seq_nr,
            send_time: Instant::now(),
            payload,
            transmits: 1,
            sacked: false,
        });
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
    closed: Arc<AtomicBool>,
    connections: UtpConnectionTable,
    pending_syn_guard: Option<Arc<AtomicUsize>>,
    mut connect_tx: Option<oneshot::Sender<IoResult<()>>>,
    initial_syn_pkt: Option<UtpPacket>,
    packet_loss: Arc<AtomicU64>,
) {
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

    let mut tick_timer = tokio::time::interval(Duration::from_millis(50));
    tick_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // 1. Incoming packets from demuxer
            pkt_opt = inbound_pkt_rx.recv() => {
                let Some(pkt) = pkt_opt else {
                    break;
                };

                conn.last_remote_timestamp_us = pkt.header.timestamp_us;
                remote_wnd = pkt.header.wnd_size;

                // Update LEDBAT delay sample
                if pkt.header.timestamp_diff_us > 0 {
                    conn.congestion.on_ack(1400, pkt.header.timestamp_diff_us);
                }

                // Process ACK number
                let ack_nr = pkt.header.ack_nr;
                let mut acked_bytes = 0u32;

                // Remove acknowledged packets from in_flight
                while let Some(front) = in_flight.front() {
                    if seq_less_equal(front.seq_nr, ack_nr) {
                        let removed = in_flight.pop_front().unwrap();
                        // A packet already selectively acknowledged was counted then.
                        if !removed.sacked {
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
                }

                // SACK processing
                if let Some(ref bitmask) = pkt.sack_bitmask {
                    let sacked_seqs = parse_sack_bitmask(ack_nr, bitmask);
                    for pkt in in_flight.iter_mut() {
                        if sacked_seqs.contains(&pkt.seq_nr) && !pkt.sacked {
                            pkt.sacked = true;
                            conn.congestion.on_bytes_acknowledged(pkt.payload.len() as u32);
                        }
                    }

                    // Fast retransmit check for gaps
                    let fast_retransmit_idx = in_flight.iter().position(|pkt| {
                        if !pkt.sacked && seq_distance(ack_nr, pkt.seq_nr) > 0 {
                            let sacked_ahead = in_flight
                                .iter()
                                .filter(|p| p.sacked && seq_distance(pkt.seq_nr, p.seq_nr) > 0)
                                .count();
                            sacked_ahead >= 3 && pkt.transmits <= 3
                        } else {
                            false
                        }
                    });
                    if let Some(idx) = fast_retransmit_idx {
                        let pkt = &mut in_flight[idx];
                        let data_pkt = conn.build_data_packet_with_seq(pkt.seq_nr, pkt.payload.clone());
                        let _ = socket.send_to(&data_pkt.encode(), remote_addr).await;
                        pkt.transmits += 1;
                        pkt.send_time = Instant::now();
                        packet_loss.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // Duplicate ACK detection
                if ack_nr == last_ack_received && pkt.payload.is_empty() {
                    dup_ack_count += 1;
                    if dup_ack_count == 3 {
                        // Fast Retransmit on 3 dup ACKs
                        if let Some(front) = in_flight.front_mut() {
                            let data_pkt = conn.build_data_packet_with_seq(front.seq_nr, front.payload.clone());
                            let _ = socket.send_to(&data_pkt.encode(), remote_addr).await;
                            front.transmits += 1;
                            front.send_time = Instant::now();
                            packet_loss.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                } else {
                    last_ack_received = ack_nr;
                    dup_ack_count = 0;
                }

                // The window may have opened: send what was waiting, then tell the stream how much
                // is still outstanding (flush completes only when nothing is queued or in flight).
                pump_outbound(&mut conn, &mut in_flight, &mut pending, &socket, remote_addr, current_mtu, remote_wnd).await;
                {
                    let mut ws = write_state.lock();
                    ws.inflight_count = in_flight.len() + pending.chunks.len();
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
                        conn.state = UtpConnectionState::Connected;
                        let seq = pkt.header.seq_nr;

                        if seq == expected_seq {
                            // In-order packet. If the reader has fallen too far behind, do not
                            // take it: leaving it unacknowledged makes the sender retransmit
                            // once there is room, so our memory use stays bounded.
                            {
                                let mut rs = read_state.lock();
                                if rs.buffer.len() + pkt.payload.len() <= RECV_BUFFER_CAP {
                                    rs.buffer.extend(&pkt.payload);
                                    expected_seq = expected_seq.wrapping_add(1);

                                    // Drain contiguous out-of-order packets
                                    while out_of_order
                                        .get(&expected_seq)
                                        .is_some_and(|p| rs.buffer.len() + p.len() <= RECV_BUFFER_CAP)
                                    {
                                        let payload = out_of_order.remove(&expected_seq).expect("checked");
                                        rs.buffer.extend(&payload);
                                        expected_seq = expected_seq.wrapping_add(1);
                                    }
                                    if let Some(w) = rs.waker.take() {
                                        w.wake();
                                    }
                                }
                            }
                            conn.ack_nr = expected_seq.wrapping_sub(1);
                        } else if (1..=MAX_OUT_OF_ORDER_PACKETS).contains(&seq_distance(expected_seq, seq)) {
                            // Out-of-order packet within the reordering window
                            out_of_order.insert(seq, pkt.payload);
                        }
                        conn.recv_wnd = RECV_BUFFER_CAP.saturating_sub(read_state.lock().buffer.len()) as u32;

                        // Send STATE (ACK) back with optional SACK
                        let sack_seqs: Vec<u16> = out_of_order.keys().copied().collect();
                        let state_pkt = if let Some(mask) = build_sack_bitmask(conn.ack_nr, &sack_seqs) {
                            conn.build_state_packet_with_sack(mask)
                        } else {
                            conn.build_state_packet()
                        };
                        let _ = socket.send_to(&state_pkt.encode(), remote_addr).await;
                    }
                    UtpType::Fin => {
                        conn.state = UtpConnectionState::Closed;
                        conn.ack_nr = pkt.header.seq_nr;
                        let state_pkt = conn.build_state_packet();
                        let _ = socket.send_to(&state_pkt.encode(), remote_addr).await;
                        {
                            let mut rs = read_state.lock();
                            rs.eof = true;
                            if let Some(w) = rs.waker.take() {
                                w.wake();
                            }
                        }
                        break;
                    }
                    UtpType::Reset => {
                        if let Some(tx) = connect_tx.take() {
                            let _ = tx.send(Err(Error::new(ErrorKind::ConnectionRefused, "uTP connection reset by peer")));
                        }
                        conn.state = UtpConnectionState::Reset;
                        let err_msg = "uTP connection reset by peer".to_string();
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
                        break;
                    }
                    UtpType::State => {
                        if conn.state == UtpConnectionState::SynSent {
                            conn.state = UtpConnectionState::Connected;
                            conn.ack_nr = pkt.header.seq_nr;
                            expected_seq = pkt.header.seq_nr;
                            if let Some(tx) = connect_tx.take() {
                                let _ = tx.send(Ok(()));
                            }
                        }
                    }
                    UtpType::Syn => {
                        conn.state = UtpConnectionState::Connected;
                    }
                }
            }

            // 2. Outbound data from UtpStream. Only taken while the unsent backlog is small, so a
            // writer that outruns the window is held back instead of buffered without bound.
            data_opt = outbound_data_rx.recv(), if pending.bytes < PENDING_OUT_CAP => {
                let Some(data) = data_opt else {
                    break;
                };
                if !data.is_empty() {
                    pending.bytes += data.len();
                    pending.chunks.push_back(data);
                }
                pump_outbound(&mut conn, &mut in_flight, &mut pending, &socket, remote_addr, current_mtu, remote_wnd).await;

                let mut ws = write_state.lock();
                ws.inflight_count = in_flight.len() + pending.chunks.len();
            }

            // 3. Periodic timer for retransmission & timeouts
            _ = tick_timer.tick() => {
                pump_outbound(&mut conn, &mut in_flight, &mut pending, &socket, remote_addr, current_mtu, remote_wnd).await;
                if conn.state == UtpConnectionState::SynSent
                    && syn_sent_time.elapsed().as_millis() as u64 >= syn_rto_ms
                {
                    if syn_transmits >= 3 {
                        if let Some(tx) = connect_tx.take() {
                            let _ = tx.send(Err(Error::new(ErrorKind::TimedOut, "uTP connection timed out")));
                        }
                        break;
                    } else if let Some(ref syn) = initial_syn_pkt {
                        let _ = socket.send_to(&syn.encode(), remote_addr).await;
                        syn_transmits += 1;
                        syn_sent_time = Instant::now();
                        syn_rto_ms = (syn_rto_ms * 2).min(2000);
                    }
                }

                if let Some(front) = in_flight.front_mut() {
                    if front.send_time.elapsed().as_millis() as u32 >= rtt_est.rto_ms {
                        // Timeout: retransmit oldest unacked packet
                        let pkt = conn.build_data_packet_with_seq(front.seq_nr, front.payload.clone());
                        let _ = socket.send_to(&pkt.encode(), remote_addr).await;

                        front.transmits += 1;
                        front.send_time = Instant::now();
                        packet_loss.fetch_add(1, Ordering::Relaxed);

                        // Exponential backoff and congestion window collapse
                        rtt_est.on_timeout();
                        conn.congestion.on_loss();
                        current_mtu = (current_mtu / 2).max(576);

                        if front.transmits > 10 {
                            // Abandon stalled connection
                            let err_msg = "uTP connection timed out".to_string();
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
                            break;
                        }
                    }
                }
            }

            // 4. Shutdown notification
            _ = shutdown_notify.notified() => {
                let fin_pkt = conn.build_fin_packet();
                let _ = socket.send_to(&fin_pkt.encode(), remote_addr).await;
                conn.state = UtpConnectionState::FinSent;
                let mut ws = write_state.lock();
                ws.is_closed = true;
                if let Some(w) = ws.flush_waker.take() {
                    w.wake();
                }
                break;
            }

            // 5. Explicit flush notification
            _ = flush_notify.notified() => {
                let ws = write_state.lock();
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
    if let Some(guard) = pending_syn_guard {
        guard.fetch_sub(1, Ordering::Relaxed);
    }
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
        tokio::time::timeout(Duration::from_secs(5), async {
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
        .expect("test timed out after 5s");
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
                tokio::time::timeout(Duration::from_secs(1), client_sock.recv_from(&mut buf))
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
            tokio::time::timeout(Duration::from_secs(1), client_sock.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        let resp = UtpPacket::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
        assert_eq!(resp.header.ptype, UtpType::Reset);
    }
}
