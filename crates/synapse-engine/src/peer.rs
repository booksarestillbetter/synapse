//! Peer connection handling: the BEP3 handshake exchange and the per-connection task
//! that drives a `Framed<TcpStream, PeerCodec>`, replacing the pre-rewrite codebase's
//! `torrent/peer/{reader,writer}.rs` hand-rolled state machines with a plain tokio task.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::codec::{Encoder, Framed};
use tracing::debug;

use crate::utp::{UtpSocketManager, UtpStream};
use synapse_wire::{EncryptedStream, EncryptionMode, Message, PeerCodec, WireError};

pub type PeerId = u64;

/// Underlying transport stream for a BitTorrent peer connection (TCP or BEP 29 uTP).
#[derive(Debug)]
pub enum PeerStream {
    Tcp(TcpStream),
    Utp(UtpStream),
}

impl PeerStream {
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            PeerStream::Tcp(s) => s.peer_addr().ok(),
            PeerStream::Utp(s) => Some(s.peer_addr()),
        }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            PeerStream::Tcp(s) => s.local_addr().ok(),
            PeerStream::Utp(s) => Some(s.local_addr()),
        }
    }

    pub fn is_utp(&self) -> bool {
        matches!(self, PeerStream::Utp(_))
    }

    pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        match self {
            PeerStream::Tcp(s) => s.set_nodelay(nodelay),
            PeerStream::Utp(_) => Ok(()),
        }
    }
}

impl From<TcpStream> for PeerStream {
    fn from(s: TcpStream) -> Self {
        PeerStream::Tcp(s)
    }
}

impl From<UtpStream> for PeerStream {
    fn from(s: UtpStream) -> Self {
        PeerStream::Utp(s)
    }
}

impl AsyncRead for PeerStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            PeerStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            PeerStream::Utp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for PeerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            PeerStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            PeerStream::Utp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            PeerStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            PeerStream::Utp(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            PeerStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            PeerStream::Utp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Maximum time a peer has to complete the BEP3 handshake before the connection is
/// dropped. Applies to both inbound and outbound connections. Without this, a peer
/// that opens a TCP connection and never sends (or slowly trickles) a handshake would
/// otherwise tie up a tokio task indefinitely -- a trivial resource-exhaustion vector
/// against an internet-facing listener.
#[cfg(not(test))]
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(test)]
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(300);

/// We send a keep-alive if nothing has been written to a peer for this long, so idle but
/// healthy connections are not dropped by the other side's inactivity timer.
#[cfg(not(test))]
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);
#[cfg(test)]
const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(100);

/// A connection that delivers nothing at all (not even a keep-alive) for this long is
/// dead or hostile and is closed. BitTorrent's traditional keep-alive period is two
/// minutes, so this leaves one full period of slack; libtorrent's `peer_timeout` is 120 s.
/// Without it a peer could hold a connection slot forever by never sending a byte.
#[cfg(not(test))]
const PEER_RECEIVE_TIMEOUT: Duration = Duration::from_secs(180);
#[cfg(test)]
const PEER_RECEIVE_TIMEOUT: Duration = Duration::from_millis(600);

#[cfg(not(test))]
const PEER_SEND_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(test)]
const PEER_SEND_TIMEOUT: Duration = Duration::from_millis(600);

static NEXT_PEER_ID: AtomicU64 = AtomicU64::new(1);

fn next_peer_id() -> PeerId {
    NEXT_PEER_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("wire protocol error: {0}")]
    Wire(#[from] WireError),
    #[error("connection closed during handshake")]
    HandshakeClosed,
    #[error("handshake timed out")]
    HandshakeTimeout,
    #[error("peer sent something other than a handshake first")]
    NotAHandshake,
    #[error("info hash mismatch")]
    InfoHashMismatch,
}

/// Events a peer task reports up to whatever owns it (the `Torrent` actor).
#[derive(Debug)]
pub enum PeerEvent {
    Connected(PeerHandle, PeerInfo),
    Message(PeerId, Message),
    Disconnected(PeerId),
}

#[derive(Debug, Clone, Copy)]
pub struct PeerInfo {
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
    pub addr: SocketAddr,
    pub local_addr: Option<SocketAddr>,
    pub is_outbound: bool,
    pub is_encrypted: bool,
    pub reserved: [u8; 8],
    pub is_utp: bool,
}

impl PeerInfo {
    pub fn supports_extensions(&self) -> bool {
        (self.reserved[5] & 0x10) != 0
    }

    pub fn supports_fast(&self) -> bool {
        (self.reserved[7] & 0x04) != 0
    }

    pub fn supports_dht(&self) -> bool {
        (self.reserved[7] & 0x01) != 0
    }
}

/// What the owner of a peer connection uses to send it outbound messages. Dropping
/// `outbound` (or the task's `PeerEvent` receiver going away) cleanly ends the task.
#[derive(Debug, Clone)]
pub struct PeerHandle {
    pub id: PeerId,
    pub addr: SocketAddr,
    outbound: mpsc::Sender<Message>,
}

impl PeerHandle {
    #[cfg(test)]
    pub(crate) fn new_for_test(
        id: PeerId,
        addr: SocketAddr,
        outbound: mpsc::Sender<Message>,
    ) -> Self {
        Self { id, addr, outbound }
    }

    /// Best-effort send: attempts an immediate non-blocking send, falling back to a bounded
    /// timeout (200ms) if the outbound buffer is congested. If the peer is completely stalled,
    /// the message is dropped rather than stalling the torrent actor event loop and choking all
    /// other peers in the swarm.
    pub async fn send(&self, msg: Message) {
        if let Err(tokio::sync::mpsc::error::TrySendError::Full(msg)) = self.outbound.try_send(msg)
        {
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                self.outbound.send(msg),
            )
            .await;
        }
    }

    /// Immediate non-blocking send. Returns true if queued, false if buffer is full or channel closed.
    pub fn try_send(&self, msg: Message) -> bool {
        self.outbound.try_send(msg).is_ok()
    }
}

/// Dials `addr`, sends our handshake immediately (we already know which torrent we
/// want), and validates the peer's handshake matches `info_hash` before treating the
/// connection as live.
///
/// Per BEP 27, when connecting to peers in a private torrent (`is_private == true`),
/// the DHT bit (`reserved[7] & 0x01`) MUST remain cleared.
pub async fn connect(
    addr: SocketAddr,
    our_peer_id: [u8; 20],
    info_hash: [u8; 20],
    is_private: bool,
    events: mpsc::Sender<PeerEvent>,
) -> Result<(), PeerError> {
    connect_with_mode(
        addr,
        our_peer_id,
        info_hash,
        is_private,
        events,
        EncryptionMode::PreferEncrypted,
    )
    .await
}

pub async fn connect_with_mode(
    addr: SocketAddr,
    our_peer_id: [u8; 20],
    info_hash: [u8; 20],
    is_private: bool,
    events: mpsc::Sender<PeerEvent>,
    mode: EncryptionMode,
) -> Result<(), PeerError> {
    connect_with_options(addr, our_peer_id, info_hash, is_private, events, mode, None).await
}

/// Dials `addr` attempting BEP 29 uTP first (if `utp_manager` is provided), falling back
/// seamlessly to TCP, then completes MSE negotiation and BitTorrent handshakes.
pub async fn connect_with_options(
    addr: SocketAddr,
    our_peer_id: [u8; 20],
    info_hash: [u8; 20],
    is_private: bool,
    events: mpsc::Sender<PeerEvent>,
    mode: EncryptionMode,
    utp_manager: Option<Arc<UtpSocketManager>>,
) -> Result<(), PeerError> {
    // uTP is UDP and would bypass a proxy that carries our peer connections.
    let utp_manager = utp_manager.filter(|_| !crate::proxy::peers_use_proxy());
    if let Some(ref utp) = utp_manager {
        #[cfg(not(test))]
        let utp_timeout = Duration::from_millis(2500);
        #[cfg(test)]
        let utp_timeout = Duration::from_millis(200);

        match tokio::time::timeout(utp_timeout, utp.connect(addr)).await {
            Ok(Ok(utp_stream)) => {
                debug!(peer = %addr, "Connected via BEP 29 uTP, proceeding to handshake");
                return connect_stream(
                    PeerStream::Utp(utp_stream),
                    addr,
                    our_peer_id,
                    info_hash,
                    is_private,
                    events,
                    mode,
                )
                .await;
            }
            Ok(Err(e)) => {
                debug!(peer = %addr, "uTP connect failed: {e}, falling back to TCP");
            }
            Err(_) => {
                debug!(peer = %addr, "uTP connect timed out, falling back to TCP");
            }
        }
    }

    let tcp_stream = crate::proxy::connect_peer(addr).await?;
    let _ = tcp_stream.set_nodelay(true);
    connect_stream(
        PeerStream::Tcp(tcp_stream),
        addr,
        our_peer_id,
        info_hash,
        is_private,
        events,
        mode,
    )
    .await
}

async fn connect_stream(
    stream: PeerStream,
    addr: SocketAddr,
    our_peer_id: [u8; 20],
    info_hash: [u8; 20],
    is_private: bool,
    events: mpsc::Sender<PeerEvent>,
    mode: EncryptionMode,
) -> Result<(), PeerError> {
    let mut reserved = [0u8; 8];
    reserved[5] |= 0x10; // BEP 10 Extension Protocol
    reserved[7] |= 0x04; // BEP 6 Fast Extension
    if !is_private {
        reserved[7] |= 0x01; // BEP 5 DHT (Strict BEP 27: MUST clear DHT bit on private torrents)
    }

    let our_handshake = Message::Handshake {
        reserved,
        info_hash,
        peer_id: our_peer_id,
    };

    let mut handshake_bytes = bytes::BytesMut::new();
    PeerCodec::new().encode(our_handshake.clone(), &mut handshake_bytes)?;

    let enc_stream = match mode {
        EncryptionMode::PlaintextOnly => {
            let mut framed = Framed::new(EncryptedStream::new_plain(stream), PeerCodec::new());
            framed.send(our_handshake).await?;
            let (their_id, their_reserved) =
                read_and_verify_handshake(&mut framed, info_hash).await?;
            spawn(
                framed,
                addr,
                info_hash,
                their_id,
                their_reserved,
                events,
                true,
            );
            return Ok(());
        }
        EncryptionMode::PreferEncrypted => {
            match tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                synapse_wire::mse_handshake_initiator(stream, info_hash, mode, &handshake_bytes),
            )
            .await
            {
                Ok(Ok(s)) => s,
                _ => {
                    // Fallback to plain connection if remote does not speak MSE
                    let stream2 = crate::proxy::connect_peer(addr).await?;
                    let _ = stream2.set_nodelay(true);
                    let mut framed = Framed::new(
                        EncryptedStream::new_plain(PeerStream::Tcp(stream2)),
                        PeerCodec::new(),
                    );
                    framed.send(our_handshake).await?;
                    let (their_id, their_reserved) =
                        read_and_verify_handshake(&mut framed, info_hash).await?;
                    spawn(
                        framed,
                        addr,
                        info_hash,
                        their_id,
                        their_reserved,
                        events,
                        true,
                    );
                    return Ok(());
                }
            }
        }
        EncryptionMode::ForcedEncrypted => tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            synapse_wire::mse_handshake_initiator(stream, info_hash, mode, &handshake_bytes),
        )
        .await
        .map_err(|_| PeerError::HandshakeTimeout)?
        .map_err(PeerError::Io)?,
    };

    let mut framed = Framed::new(enc_stream, PeerCodec::new());
    let (their_id, their_reserved) = read_and_verify_handshake(&mut framed, info_hash).await?;
    spawn(
        framed,
        addr,
        info_hash,
        their_id,
        their_reserved,
        events,
        true,
    );
    Ok(())
}

/// Accepts an inbound stream, decodes its handshake to discover its requested info hash,
/// and dispatches the connection to the corresponding torrent actor.
pub async fn accept_router<F>(
    stream: impl Into<PeerStream>,
    addr: SocketAddr,
    our_peer_id: [u8; 20],
    lookup_events: F,
) -> Result<(), PeerError>
where
    F: FnOnce([u8; 20]) -> Option<(mpsc::Sender<PeerEvent>, bool)>,
{
    accept_router_with_candidates(
        stream,
        addr,
        our_peer_id,
        Vec::new(),
        lookup_events,
        EncryptionMode::PreferEncrypted,
    )
    .await
}

pub async fn accept_router_with_candidates<F>(
    stream: impl Into<PeerStream>,
    addr: SocketAddr,
    our_peer_id: [u8; 20],
    candidate_hashes: Vec<[u8; 20]>,
    lookup_events: F,
    mode: EncryptionMode,
) -> Result<(), PeerError>
where
    F: FnOnce([u8; 20]) -> Option<(mpsc::Sender<PeerEvent>, bool)>,
{
    accept_router_indexed(
        stream,
        addr,
        our_peer_id,
        |target_req2| {
            candidate_hashes
                .iter()
                .find(|h| &synapse_wire::mse_req2(h) == target_req2)
                .copied()
        },
        lookup_events,
        mode,
    )
    .await
}

/// Like [`accept_router_with_candidates`], but takes a lookup from an MSE `req2` hash to the
/// info hash it identifies instead of a list of candidates. A daemon holding tens of
/// thousands of torrents keeps that as an index (see `SwarmEngine`): scanning a candidate
/// list would hash every torrent per inbound handshake, which an attacker could turn into
/// a CPU-exhaustion lever.
pub async fn accept_router_indexed<F, L>(
    stream: impl Into<PeerStream>,
    addr: SocketAddr,
    our_peer_id: [u8; 20],
    find_by_req2: L,
    lookup_events: F,
    mode: EncryptionMode,
) -> Result<(), PeerError>
where
    F: FnOnce([u8; 20]) -> Option<(mpsc::Sender<PeerEvent>, bool)>,
    L: Fn(&[u8; 20]) -> Option<[u8; 20]>,
{
    let stream = stream.into();
    let _ = stream.set_nodelay(true);
    let rx_res = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        synapse_wire::mse_handshake_receiver(stream, mode, find_by_req2),
    )
    .await
    .map_err(|_| PeerError::HandshakeTimeout)?
    .map_err(PeerError::Io)?;

    let (enc_stream, mse_info_hash) = match rx_res {
        synapse_wire::ReceiverHandshakeResult::Plaintext { stream } => (stream, None),
        synapse_wire::ReceiverHandshakeResult::Encrypted {
            stream, info_hash, ..
        } => (stream, Some(info_hash)),
    };

    let mut framed = Framed::new(enc_stream, PeerCodec::new());
    let msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, framed.next())
        .await
        .map_err(|_| PeerError::HandshakeTimeout)?
        .ok_or(PeerError::HandshakeClosed)??;
    let (their_reserved, info_hash, their_id) = match msg {
        Message::Handshake {
            reserved,
            info_hash,
            peer_id,
        } => (reserved, info_hash, peer_id),
        _ => return Err(PeerError::NotAHandshake),
    };
    if mse_info_hash.is_some_and(|mse_hash| mse_hash != info_hash) {
        return Err(PeerError::InfoHashMismatch);
    }
    let Some((events, is_private)) = lookup_events(info_hash) else {
        return Err(PeerError::InfoHashMismatch);
    };

    let mut reserved = [0u8; 8];
    reserved[5] |= 0x10; // BEP 10 Extension Protocol
    reserved[7] |= 0x04; // BEP 6 Fast Extension
    if !is_private {
        reserved[7] |= 0x01; // BEP 5 DHT (Strict BEP 27: MUST clear DHT bit on private torrents)
    }

    framed
        .send(Message::Handshake {
            reserved,
            info_hash,
            peer_id: our_peer_id,
        })
        .await?;
    spawn(
        framed,
        addr,
        info_hash,
        their_id,
        their_reserved,
        events,
        false,
    );
    Ok(())
}

pub async fn accept(
    stream: impl Into<PeerStream>,
    addr: SocketAddr,
    our_peer_id: [u8; 20],
    expected_hash: [u8; 20],
    is_private: bool,
    events: mpsc::Sender<PeerEvent>,
) -> Result<(), PeerError> {
    accept_with_mode(
        stream,
        addr,
        our_peer_id,
        expected_hash,
        is_private,
        events,
        EncryptionMode::PreferEncrypted,
    )
    .await
}

pub async fn accept_with_mode(
    stream: impl Into<PeerStream>,
    addr: SocketAddr,
    our_peer_id: [u8; 20],
    expected_hash: [u8; 20],
    is_private: bool,
    events: mpsc::Sender<PeerEvent>,
    mode: EncryptionMode,
) -> Result<(), PeerError> {
    let stream = stream.into();
    let _ = stream.set_nodelay(true);
    let rx_res = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        synapse_wire::mse_handshake_receiver(stream, mode, |target_req2| {
            if &synapse_wire::mse_req2(&expected_hash) == target_req2 {
                Some(expected_hash)
            } else {
                None
            }
        }),
    )
    .await
    .map_err(|_| PeerError::HandshakeTimeout)?
    .map_err(PeerError::Io)?;

    let (enc_stream, mse_info_hash) = match rx_res {
        synapse_wire::ReceiverHandshakeResult::Plaintext { stream } => (stream, None),
        synapse_wire::ReceiverHandshakeResult::Encrypted {
            stream, info_hash, ..
        } => (stream, Some(info_hash)),
    };

    let mut framed = Framed::new(enc_stream, PeerCodec::new());
    let msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, framed.next())
        .await
        .map_err(|_| PeerError::HandshakeTimeout)?
        .ok_or(PeerError::HandshakeClosed)??;
    let (their_reserved, info_hash, their_id) = match msg {
        Message::Handshake {
            reserved,
            info_hash,
            peer_id,
        } => (reserved, info_hash, peer_id),
        _ => return Err(PeerError::NotAHandshake),
    };
    if info_hash != expected_hash || mse_info_hash.is_some_and(|mse_hash| mse_hash != info_hash) {
        return Err(PeerError::InfoHashMismatch);
    }

    let mut reserved = [0u8; 8];
    reserved[5] |= 0x10; // BEP 10 Extension Protocol
    reserved[7] |= 0x04; // BEP 6 Fast Extension
    if !is_private {
        reserved[7] |= 0x01; // BEP 5 DHT (Strict BEP 27: MUST clear DHT bit on private torrents)
    }

    framed
        .send(Message::Handshake {
            reserved,
            info_hash,
            peer_id: our_peer_id,
        })
        .await?;
    spawn(
        framed,
        addr,
        info_hash,
        their_id,
        their_reserved,
        events,
        false,
    );
    Ok(())
}

async fn read_and_verify_handshake(
    framed: &mut Framed<EncryptedStream<PeerStream>, PeerCodec>,
    expected_hash: [u8; 20],
) -> Result<([u8; 20], [u8; 8]), PeerError> {
    let msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, framed.next())
        .await
        .map_err(|_| PeerError::HandshakeTimeout)?
        .ok_or(PeerError::HandshakeClosed)??;
    match msg {
        Message::Handshake {
            reserved,
            info_hash,
            peer_id,
        } if info_hash == expected_hash => Ok((peer_id, reserved)),
        Message::Handshake { .. } => Err(PeerError::InfoHashMismatch),
        _ => Err(PeerError::NotAHandshake),
    }
}

async fn send_messages_bounded<S>(
    framed: &mut Framed<S, PeerCodec>,
    first: Message,
    out_rx: Option<&mut mpsc::Receiver<Message>>,
    receive_deadline: &mut std::pin::Pin<&mut tokio::time::Sleep>,
) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let send_fut = async {
        framed.feed(first).await.map_err(|_| ())?;
        if let Some(rx) = out_rx {
            for _ in 0..31 {
                match rx.try_recv() {
                    Ok(next_msg) => framed.feed(next_msg).await.map_err(|_| ())?,
                    Err(_) => break,
                }
            }
        }
        framed.flush().await.map_err(|_| ())
    };
    let send_timeout = tokio::time::sleep(PEER_SEND_TIMEOUT);
    tokio::pin!(send_timeout);
    tokio::select! {
        res = send_fut => res.is_ok(),
        _ = &mut send_timeout => false,
        _ = &mut *receive_deadline => false,
    }
}

fn spawn(
    mut framed: Framed<EncryptedStream<PeerStream>, PeerCodec>,
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    reserved: [u8; 8],
    events: mpsc::Sender<PeerEvent>,
    is_outbound: bool,
) {
    let id = next_peer_id();
    let (out_tx, mut out_rx) = mpsc::channel(64);
    let handle = PeerHandle {
        id,
        addr,
        outbound: out_tx,
    };

    let local_addr = framed.get_ref().get_ref().local_addr();
    let is_encrypted = framed.get_ref().is_encrypted();
    let is_utp = framed.get_ref().get_ref().is_utp();
    tokio::spawn(async move {
        if events
            .send(PeerEvent::Connected(
                handle,
                PeerInfo {
                    info_hash,
                    peer_id,
                    addr,
                    local_addr,
                    is_outbound,
                    is_encrypted,
                    reserved,
                    is_utp,
                },
            ))
            .await
            .is_err()
        {
            return; // owner already gone
        }

        let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        keepalive.reset();
        let receive_deadline = tokio::time::sleep(PEER_RECEIVE_TIMEOUT);
        tokio::pin!(receive_deadline);

        loop {
            tokio::select! {
                _ = &mut receive_deadline => {
                    tracing::debug!(peer = id, "no data received within the peer timeout, closing");
                    break;
                }
                _ = keepalive.tick() => {
                    if !send_messages_bounded(&mut framed, Message::KeepAlive, None, &mut receive_deadline).await {
                        break;
                    }
                }
                incoming = framed.next() => {
                    match incoming {
                        Some(Ok(msg)) => {
                            receive_deadline.as_mut().reset(tokio::time::Instant::now() + PEER_RECEIVE_TIMEOUT);
                            if events.send(PeerEvent::Message(id, msg)).await.is_err() {
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            tracing::debug!(peer = id, "wire error, closing: {e}");
                            break;
                        }
                        None => break, // EOF
                    }
                }
                outgoing = out_rx.recv() => {
                    match outgoing {
                        Some(msg) => {
                            if !send_messages_bounded(&mut framed, msg, Some(&mut out_rx), &mut receive_deadline).await {
                                tracing::debug!(peer = id, "write error or slow-reader timeout, closing");
                                break;
                            }
                            keepalive.reset();
                        }
                        None => break, // owner dropped the handle: close the connection
                    }
                }
            }
        }
        let close_budget = if cfg!(test) {
            Duration::from_millis(200)
        } else {
            Duration::from_secs(2)
        };
        let _ = tokio::time::timeout(close_budget, framed.close()).await;
        drop(framed);
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            events.send(PeerEvent::Disconnected(id)),
        )
        .await;
    });
}

/// Parses standard Azureus/Shadow/Mainline style peer IDs into readable client names.
pub fn parse_client_name(peer_id: &[u8; 20]) -> String {
    if peer_id[0] == b'-' && peer_id[7] == b'-' {
        let client = match &peer_id[1..3] {
            b"SY" => "Synapse",
            b"qB" => "qBittorrent",
            b"TR" => "Transmission",
            b"UT" => "uTorrent",
            b"LT" => "libtorrent",
            b"lt" => "libtorrent (Rasterbar)",
            b"DE" => "Deluge",
            b"AZ" => "Azureus",
            b"KT" => "KTorrent",
            b"BT" => "BitTorrent",
            b"WD" => "WebTorrent",
            b"BI" => "BiglyBT",
            b"FC" => "FileCroc",
            b"PI" => "PicoTorrent",
            b"TX" => "Tox",
            b"FD" => "Free Download Manager",
            b"SD" | b"XL" => "Xunlei",
            other => {
                let id_str = String::from_utf8_lossy(other);
                return format!("{}-unknown", id_str);
            }
        };
        let ver = &peer_id[3..7];
        if ver.iter().all(|b| b.is_ascii_alphanumeric()) {
            let v_str = String::from_utf8_lossy(ver);
            let chars: Vec<char> = v_str.chars().collect();
            if chars.len() == 4 {
                if chars[3] == '0' {
                    return format!("{} {}.{}.{}", client, chars[0], chars[1], chars[2]);
                } else {
                    return format!(
                        "{} {}.{}.{}.{}",
                        client, chars[0], chars[1], chars[2], chars[3]
                    );
                }
            }
        }
        format!("{} {}", client, String::from_utf8_lossy(ver))
    } else if let Ok(s) = std::str::from_utf8(&peer_id[..8]) {
        if s.chars().all(|c| c.is_ascii_graphic()) {
            s.to_string()
        } else {
            format!("Peer-{}", &hex::encode(peer_id)[..8])
        }
    } else {
        format!("Peer-{}", &hex::encode(peer_id)[..8])
    }
}

/// Standard BEP 20 Azureus-style peer ID prefix for Synapse 2.2 (`-SY2200-`).
///
/// NOTE: Peer ID is intentionally invariant and strictly non-customizable by users
/// or runtime configuration. This ensures consistent tracker protocol compatibility,
/// proper swarm identification, and prevents tracker spoofing or fingerprint distortion.
/// Any change to this prefix must only occur across official major/minor version bumps.
pub const SYNAPSE_PEER_ID_PREFIX: &[u8; 8] = b"-SY2200-";

/// Generates a local peer ID using the fixed BEP 20 Synapse prefix (`-SY2200-`)
/// followed by 12 random bytes.
pub fn generate_peer_id() -> [u8; 20] {
    let mut peer_id = [0u8; 20];
    peer_id[0..8].copy_from_slice(SYNAPSE_PEER_ID_PREFIX);
    for byte in &mut peer_id[8..20] {
        *byte = rand::random::<u8>();
    }
    peer_id
}

/// Forces the Synapse prefix onto `peer_id`, keeping the caller's last 12 bytes.
///
/// `SwarmEngine::new` runs every peer ID through this, so nothing built on the engine (daemon,
/// benchmarks, tests, embedders) can ever announce or handshake as another client.
pub fn with_synapse_prefix(mut peer_id: [u8; 20]) -> [u8; 20] {
    peer_id[0..8].copy_from_slice(SYNAPSE_PEER_ID_PREFIX);
    peer_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_synapse_prefix_overrides_any_other_client_prefix() {
        for other in [
            b"-TR4050-",
            b"-qB4430-",
            b"-UT3550-",
            b"-DE1360-",
            b"\0\0\0\0\0\0\0\0",
        ] {
            let mut id = [7u8; 20];
            id[..8].copy_from_slice(other);
            let fixed = with_synapse_prefix(id);
            assert_eq!(&fixed[..8], SYNAPSE_PEER_ID_PREFIX);
            assert_eq!(&fixed[8..], &id[8..]);
        }
    }

    #[test]
    fn test_generate_peer_id() {
        let peer_id = generate_peer_id();
        assert_eq!(&peer_id[0..8], SYNAPSE_PEER_ID_PREFIX);
        assert_eq!(parse_client_name(&peer_id), "Synapse 2.2.0");
    }

    #[test]
    fn test_parse_client_name() {
        let mut id = [0u8; 20];
        id[..8].copy_from_slice(SYNAPSE_PEER_ID_PREFIX);
        assert_eq!(parse_client_name(&id), "Synapse 2.2.0");

        id[..8].copy_from_slice(b"-qB4430-");
        assert_eq!(parse_client_name(&id), "qBittorrent 4.4.3");

        id[..8].copy_from_slice(b"-TR3000-");
        assert_eq!(parse_client_name(&id), "Transmission 3.0.0");

        id[..8].copy_from_slice(b"-UT3550-");
        assert_eq!(parse_client_name(&id), "uTorrent 3.5.5");

        id[..8].copy_from_slice(b"-DE1360-");
        assert_eq!(parse_client_name(&id), "Deluge 1.3.6");
    }
}

#[cfg(test)]
mod liveness_tests {
    use super::*;
    use futures::StreamExt;
    use tokio::net::TcpListener;

    /// Returns (our framed end, events receiver, the owner's handle) for a real, handshaken
    /// inbound connection, so both codecs are in their post-handshake state.
    async fn spawn_pair() -> (
        Framed<TcpStream, PeerCodec>,
        mpsc::Receiver<PeerEvent>,
        PeerHandle,
    ) {
        use futures::SinkExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(16);
        tokio::spawn(async move {
            let (stream, remote) = listener.accept().await.unwrap();
            accept(stream, remote, [9; 20], [7; 20], false, tx)
                .await
                .unwrap();
        });
        let mut them = Framed::new(TcpStream::connect(addr).await.unwrap(), PeerCodec::new());
        them.send(Message::Handshake {
            reserved: [0; 8],
            info_hash: [7; 20],
            peer_id: [1; 20],
        })
        .await
        .unwrap();
        assert!(matches!(
            them.next().await,
            Some(Ok(Message::Handshake { .. }))
        ));
        // Keep the handle alive: dropping it is how the owner closes a connection.
        let Some(PeerEvent::Connected(handle, _)) = rx.recv().await else {
            panic!("expected Connected");
        };
        (them, rx, handle)
    }

    #[tokio::test]
    async fn slow_loris_handshake_is_cut_off_at_the_handshake_timeout() {
        use tokio::io::AsyncWriteExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, _rx) = mpsc::channel(4);
        let server = tokio::spawn(async move {
            let (stream, remote) = listener.accept().await.unwrap();
            accept(stream, remote, [9; 20], [7; 20], false, tx).await
        });
        // Trickle the start of a handshake one byte at a time, never finishing it.
        let mut c = TcpStream::connect(addr).await.unwrap();
        let trickle = tokio::spawn(async move {
            for b in [
                19u8, b'B', b'i', b't', b'T', b'o', b'r', b'r', b'e', b'n', b't',
            ] {
                if c.write_all(&[b]).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        let res = tokio::time::timeout(Duration::from_secs(30), server).await;
        assert!(
            matches!(res, Ok(Ok(Err(PeerError::HandshakeTimeout)))),
            "trickled handshake must fail with HandshakeTimeout, got {res:?}"
        );
        trickle.abort();
    }

    // Unit tests run with shrunk timers (100 ms keep-alive, 600 ms receive timeout) so the
    // real production behaviour is exercised over a real socket without waiting minutes.

    #[tokio::test]
    async fn silent_peer_gets_keepalives_then_is_dropped() {
        let (mut them, mut rx, _handle) = spawn_pair().await;
        let first = tokio::time::timeout(Duration::from_secs(20), them.next()).await;
        assert!(
            matches!(first, Ok(Some(Ok(Message::KeepAlive)))),
            "expected a keepalive, got {first:?}"
        );
        let closed = tokio::time::timeout(Duration::from_secs(30), async {
            while let Some(m) = rx.recv().await {
                if matches!(m, PeerEvent::Disconnected(_)) {
                    return true;
                }
            }
            false
        })
        .await;
        assert_eq!(closed, Ok(true), "silent peer must be disconnected");
    }

    #[tokio::test]
    async fn peer_that_keeps_sending_is_not_timed_out() {
        use futures::SinkExt;
        let (mut them, mut rx, _handle) = spawn_pair().await;
        // 10 x 200 ms = 2 s, more than three receive timeouts.
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            them.send(Message::KeepAlive).await.unwrap();
        }
        while let Ok(ev) = rx.try_recv() {
            assert!(
                !matches!(ev, PeerEvent::Disconnected(_)),
                "live peer was disconnected"
            );
        }
    }

    /// Regression for a production bug: callers of `connect_with_options` (in
    /// `synapse-engine::announcer`) wrapped it in an outer timeout shorter than
    /// `HANDSHAKE_TIMEOUT`, so a `PreferEncrypted` peer that never answers the MSE probe at
    /// all (silence, not a reset - common for genuinely non-MSE peers) got killed by the
    /// outer timeout before `connect_stream`'s own plaintext fallback ever got to run. This
    /// reproduces exactly that shape - a first connection that never speaks, forcing the MSE
    /// probe to run out its own full timeout, then a second (fallback) connection that
    /// completes a plain handshake - wrapped in the combined budget callers must now use
    /// (`2 * HANDSHAKE_TIMEOUT + slack`), and asserts it actually succeeds.
    #[tokio::test]
    async fn prefer_encrypted_falls_back_to_plaintext_within_the_combined_dial_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(4);

        tokio::spawn(async move {
            // First connection: a peer that doesn't speak MSE and never answers the DH
            // probe - held open and silent for longer than one `HANDSHAKE_TIMEOUT`, so the
            // initiator's encrypted attempt has to run out its own timeout rather than fail
            // fast on a reset.
            let (first, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                tokio::time::sleep(HANDSHAKE_TIMEOUT * 4).await;
                drop(first);
            });

            // Second connection: the fallback's fresh plaintext attempt - answer it like any
            // other inbound peer.
            let (second, remote) = listener.accept().await.unwrap();
            accept(second, remote, [9; 20], [7; 20], false, tx)
                .await
                .unwrap();
        });

        // The budget every real caller (`announcer::dial_step` and its sibling) must give
        // `connect_with_options` - see the comment there for why it's derived this way.
        let dial_timeout = 2 * HANDSHAKE_TIMEOUT + Duration::from_secs(5);
        let (events_tx, _events_rx) = mpsc::channel(4);
        let result = tokio::time::timeout(
            dial_timeout,
            connect_with_mode(
                addr,
                [1; 20],
                [7; 20],
                false,
                events_tx,
                EncryptionMode::PreferEncrypted,
            ),
        )
        .await;
        assert!(
            matches!(result, Ok(Ok(()))),
            "expected the plaintext fallback to succeed within the combined dial budget, got {result:?}"
        );
        assert!(
            rx.recv().await.is_some(),
            "fallback connection never reached the accept() side"
        );
    }

    #[tokio::test]
    async fn peer_info_exposes_reserved_bits_and_slow_reader_times_out_promptly() {
        let info = PeerInfo {
            info_hash: [0; 20],
            peer_id: [1; 20],
            addr: "127.0.0.1:6881".parse().unwrap(),
            local_addr: None,
            is_outbound: false,
            is_encrypted: false,
            reserved: [0, 0, 0, 0, 0, 0x10, 0, 0x05],
            is_utp: false,
        };
        assert!(info.supports_extensions());
        assert!(info.supports_fast());
        assert!(info.supports_dht());

        let (them, mut rx, handle) = spawn_pair().await;
        // Drop or stop draining `them`'s read side while flooding large Piece messages;
        // even if writes stall on a full socket buffer, the task must disconnect within ~2x PEER_RECEIVE_TIMEOUT.
        let chunk = bytes::Bytes::from(vec![0xAA; 16_384]);
        let _keep_them_open = them;
        let disconnected = tokio::time::timeout(PEER_RECEIVE_TIMEOUT * 3, async move {
            loop {
                let _ = handle.try_send(Message::Piece {
                    index: 0,
                    begin: 0,
                    data: chunk.clone(),
                });
                match tokio::time::timeout(Duration::from_millis(20), rx.recv()).await {
                    Ok(Some(PeerEvent::Disconnected(_))) => break true,
                    Ok(None) => break true,
                    _ => {}
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(
            disconnected,
            "stalled slow-reading peer must still be timed out within PEER_RECEIVE_TIMEOUT"
        );
    }
}
