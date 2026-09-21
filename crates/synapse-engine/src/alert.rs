//! Structured session alert stream for Synapse 2.0.
//!
//! Exposes typed, high-fidelity lifecycle, integrity, network, and error events
//! dispatched across torrent swarms, consumed by local and remote API clients.

use crate::swarm::SwarmState;
use std::net::{IpAddr, SocketAddr};
use tokio::sync::broadcast;

/// Types of alerts emitted by the Synapse engine.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Alert {
    /// A new torrent was added to the session.
    TorrentAdded { info_hash: [u8; 20] },
    /// A torrent completed downloading all non-padding pieces and entered seeding state.
    TorrentFinished { info_hash: [u8; 20] },
    /// A fatal storage or network error halted torrent operation.
    TorrentError { info_hash: [u8; 20], error: String },
    /// A single piece passed cryptographic verification and was flushed to disk.
    PieceFinished {
        info_hash: [u8; 20],
        piece_index: u32,
    },
    /// A completed piece failed cryptographic hash verification and was discarded.
    HashFailed {
        info_hash: [u8; 20],
        piece_index: u32,
    },
    /// A peer handshake succeeded and connection established.
    PeerConnected {
        info_hash: [u8; 20],
        addr: SocketAddr,
    },
    /// A peer connection was terminated or dropped.
    PeerDisconnected {
        info_hash: [u8; 20],
        addr: SocketAddr,
    },
    /// A peer address was banned for sending corrupted or invalid piece blocks.
    PeerBanned { info_hash: [u8; 20], ip: IpAddr },
    /// A swarm transitioned between execution states (e.g. Downloading -> Seeding).
    StateChanged {
        info_hash: [u8; 20],
        old_state: SwarmState,
        new_state: SwarmState,
    },
    /// An announce request was dispatched to a tracker.
    TrackerAnnounce {
        info_hash: [u8; 20],
        tracker_url: String,
        event: String,
    },
}

impl Alert {
    /// Returns the 20-byte info hash of the torrent associated with this alert.
    pub fn info_hash(&self) -> [u8; 20] {
        match self {
            Alert::TorrentAdded { info_hash, .. }
            | Alert::TorrentFinished { info_hash, .. }
            | Alert::TorrentError { info_hash, .. }
            | Alert::PieceFinished { info_hash, .. }
            | Alert::HashFailed { info_hash, .. }
            | Alert::PeerConnected { info_hash, .. }
            | Alert::PeerDisconnected { info_hash, .. }
            | Alert::PeerBanned { info_hash, .. }
            | Alert::StateChanged { info_hash, .. }
            | Alert::TrackerAnnounce { info_hash, .. } => *info_hash,
        }
    }

    /// Returns the hex-encoded 40-character string representation of the info hash.
    pub fn info_hash_hex(&self) -> String {
        hex::encode(self.info_hash())
    }
}

/// Broadcast stream for session-wide alerts.
#[derive(Debug)]
pub struct AlertStream {
    sender: broadcast::Sender<Alert>,
}

impl Default for AlertStream {
    fn default() -> Self {
        Self::new(2048)
    }
}

impl AlertStream {
    /// Creates a new alert broadcast channel with the specified circular buffer capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Returns a clone of the internal broadcast sender.
    pub fn sender(&self) -> broadcast::Sender<Alert> {
        self.sender.clone()
    }

    /// Dispatches an alert into the broadcast stream.
    /// Returns the number of active subscribers that received the alert.
    pub fn post(&self, alert: Alert) -> usize {
        self.sender.send(alert).unwrap_or(0)
    }

    /// Subscribes a new receiver to the alert stream.
    pub fn subscribe(&self) -> broadcast::Receiver<Alert> {
        self.sender.subscribe()
    }
}
