//! Peer connection handling: the BEP3 handshake exchange and the per-connection task
//! that drives a `Framed<TcpStream, PeerCodec>`, replacing the pre-rewrite codebase's
//! `torrent/peer/{reader,writer}.rs` hand-rolled state machines with a plain tokio task.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::codec::Framed;

use synapse_wire::{Message, PeerCodec, WireError};

pub type PeerId = u64;

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
    #[error("peer sent something other than a handshake first")]
    NotAHandshake,
    #[error("info hash mismatch")]
    InfoHashMismatch,
}

/// Events a peer task reports up to whatever owns it (the `Torrent` actor).
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
}

/// What the owner of a peer connection uses to send it outbound messages. Dropping
/// `outbound` (or the task's `PeerEvent` receiver going away) cleanly ends the task.
#[derive(Clone)]
pub struct PeerHandle {
    pub id: PeerId,
    pub addr: SocketAddr,
    outbound: mpsc::Sender<Message>,
}

impl PeerHandle {
    /// Best-effort send: attempts an immediate non-blocking send, falling back to a bounded
    /// timeout (200ms) if the outbound buffer is congested. If the peer is completely stalled,
    /// the message is dropped rather than stalling the torrent actor event loop and choking all
    /// other peers in the swarm.
    pub async fn send(&self, msg: Message) {
        if let Err(tokio::sync::mpsc::error::TrySendError::Full(msg)) = self.outbound.try_send(msg) {
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
    let stream = TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    let mut framed = Framed::new(stream, PeerCodec::new());

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
    let their_id = read_and_verify_handshake(&mut framed, info_hash).await?;
    spawn(framed, addr, info_hash, their_id, events);
    Ok(())
}

/// Accepts an inbound stream, decodes its handshake to discover its requested info hash,
/// and dispatches the connection to the corresponding torrent actor.
pub async fn accept_router<F>(
    stream: TcpStream,
    addr: SocketAddr,
    our_peer_id: [u8; 20],
    lookup_events: F,
) -> Result<(), PeerError>
where
    F: FnOnce([u8; 20]) -> Option<(mpsc::Sender<PeerEvent>, bool)>,
{
    let _ = stream.set_nodelay(true);
    let mut framed = Framed::new(stream, PeerCodec::new());
    let msg = framed.next().await.ok_or(PeerError::HandshakeClosed)??;
    let (info_hash, their_id) = match msg {
        Message::Handshake { info_hash, peer_id, .. } => (info_hash, peer_id),
        _ => return Err(PeerError::NotAHandshake),
    };
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
    spawn(framed, addr, info_hash, their_id, events);
    Ok(())
}

pub async fn accept(
    stream: TcpStream,
    addr: SocketAddr,
    our_peer_id: [u8; 20],
    is_known: impl FnOnce([u8; 20]) -> bool,
    is_private: bool,
    events: mpsc::Sender<PeerEvent>,
) -> Result<(), PeerError> {
    let mut framed = Framed::new(stream, PeerCodec::new());
    let msg = framed.next().await.ok_or(PeerError::HandshakeClosed)??;
    let (info_hash, their_id) = match msg {
        Message::Handshake { info_hash, peer_id, .. } => (info_hash, peer_id),
        _ => return Err(PeerError::NotAHandshake),
    };
    if !is_known(info_hash) {
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
    spawn(framed, addr, info_hash, their_id, events);
    Ok(())
}

async fn read_and_verify_handshake(
    framed: &mut Framed<TcpStream, PeerCodec>,
    expected_hash: [u8; 20],
) -> Result<[u8; 20], PeerError> {
    let msg = framed.next().await.ok_or(PeerError::HandshakeClosed)??;
    match msg {
        Message::Handshake { info_hash, peer_id, .. } if info_hash == expected_hash => Ok(peer_id),
        Message::Handshake { .. } => Err(PeerError::InfoHashMismatch),
        _ => Err(PeerError::NotAHandshake),
    }
}

fn spawn(
    mut framed: Framed<TcpStream, PeerCodec>,
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    events: mpsc::Sender<PeerEvent>,
) {
    let id = next_peer_id();
    let (out_tx, mut out_rx) = mpsc::channel(64);
    let handle = PeerHandle {
        id,
        addr,
        outbound: out_tx,
    };

    tokio::spawn(async move {
        if events
            .send(PeerEvent::Connected(
                handle,
                PeerInfo {
                    info_hash,
                    peer_id,
                    addr,
                },
            ))
            .await
            .is_err()
        {
            return; // owner already gone
        }

        loop {
            tokio::select! {
                incoming = framed.next() => {
                    match incoming {
                        Some(Ok(msg)) => {
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
                            if let Err(e) = framed.send(msg).await {
                                tracing::debug!(peer = id, "write error, closing: {e}");
                                break;
                            }
                        }
                        None => break, // owner dropped the handle: close the connection
                    }
                }
            }
        }
        let _ = framed.close().await;
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
                    return format!("{} {}.{}.{}.{}", client, chars[0], chars[1], chars[2], chars[3]);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_client_name() {
        let mut id = [0u8; 20];
        id[..8].copy_from_slice(b"-SY2000-");
        assert_eq!(parse_client_name(&id), "Synapse 2.0.0");

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
