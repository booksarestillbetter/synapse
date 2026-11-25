//! Structured session alert stream for Synapse 2.0.
//!
//! Exposes typed, high-fidelity lifecycle, integrity, network, and error events
//! dispatched across torrent swarms, consumed by local and remote API clients.

use crate::swarm::SwarmState;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;

/// Bitflags identifying alert categories for lightweight alert filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlertCategory(u32);

impl AlertCategory {
    pub const NONE: Self = Self(0);
    pub const LIFECYCLE: Self = Self(1 << 0);
    pub const ERROR: Self = Self(1 << 1);
    pub const PIECE: Self = Self(1 << 2);
    pub const PEER: Self = Self(1 << 3);
    pub const TRACKER: Self = Self(1 << 4);
    pub const ALL: Self =
        Self(Self::LIFECYCLE.0 | Self::ERROR.0 | Self::PIECE.0 | Self::PEER.0 | Self::TRACKER.0);

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn from_bits_truncate(bits: u32) -> Self {
        Self(bits & Self::ALL.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl std::ops::BitOr for AlertCategory {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for AlertCategory {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

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
    /// Returns the category flag corresponding to this alert variant.
    pub fn category(&self) -> AlertCategory {
        match self {
            Alert::TorrentAdded { .. }
            | Alert::TorrentFinished { .. }
            | Alert::StateChanged { .. } => AlertCategory::LIFECYCLE,
            Alert::TorrentError { .. } => AlertCategory::ERROR,
            Alert::PieceFinished { .. } | Alert::HashFailed { .. } => AlertCategory::PIECE,
            Alert::PeerConnected { .. }
            | Alert::PeerDisconnected { .. }
            | Alert::PeerBanned { .. } => AlertCategory::PEER,
            Alert::TrackerAnnounce { .. } => AlertCategory::TRACKER,
        }
    }

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
    category_mask: Arc<AtomicU32>,
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
        Self {
            sender,
            category_mask: Arc::new(AtomicU32::new(AlertCategory::ALL.bits())),
        }
    }

    /// Updates the enabled alert category bitmask.
    pub fn set_category_mask(&self, mask: AlertCategory) {
        self.category_mask.store(mask.bits(), Ordering::Relaxed);
    }

    /// Returns the currently active alert category bitmask.
    pub fn category_mask(&self) -> AlertCategory {
        AlertCategory::from_bits_truncate(self.category_mask.load(Ordering::Relaxed))
    }

    /// Returns a shared handle to the category bitmask atomic for fast actor-side checks.
    pub fn category_mask_handle(&self) -> Arc<AtomicU32> {
        self.category_mask.clone()
    }

    /// Returns the number of active subscribers attached to the stream.
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }

    /// Returns true if at least one subscriber is connected AND `category` is enabled.
    pub fn has_listeners_for(&self, category: AlertCategory) -> bool {
        self.sender.receiver_count() > 0
            && (self.category_mask.load(Ordering::Relaxed) & category.bits()) != 0
    }

    /// Returns a clone of the internal broadcast sender.
    pub fn sender(&self) -> broadcast::Sender<Alert> {
        self.sender.clone()
    }

    /// Dispatches an alert into the broadcast stream if listeners for its category exist.
    /// Returns the number of active subscribers that received the alert.
    pub fn post(&self, alert: Alert) -> usize {
        if !self.has_listeners_for(alert.category()) {
            return 0;
        }
        self.sender.send(alert).unwrap_or(0)
    }

    /// Lazily constructs and dispatches an alert only if listeners for `category` are active.
    pub fn post_lazy<F: FnOnce() -> Alert>(&self, category: AlertCategory, f: F) -> usize {
        if !self.has_listeners_for(category) {
            return 0;
        }
        self.sender.send(f()).unwrap_or(0)
    }

    /// Subscribes a new receiver to the alert stream.
    pub fn subscribe(&self) -> broadcast::Receiver<Alert> {
        self.sender.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn alert_stream_zero_subscriber_skips_lazy_closure_and_respects_category_mask() {
        let stream = AlertStream::new(16);
        assert_eq!(stream.subscriber_count(), 0);

        let called = AtomicBool::new(false);
        let delivered = stream.post_lazy(AlertCategory::PIECE, || {
            called.store(true, Ordering::SeqCst);
            Alert::PieceFinished {
                info_hash: [1u8; 20],
                piece_index: 0,
            }
        });
        assert_eq!(delivered, 0);
        assert!(!called.load(Ordering::SeqCst));

        // Subscribe, but mask out PIECE category.
        let mut rx = stream.subscribe();
        assert_eq!(stream.subscriber_count(), 1);
        stream.set_category_mask(AlertCategory::LIFECYCLE | AlertCategory::ERROR);

        let delivered_masked = stream.post_lazy(AlertCategory::PIECE, || {
            called.store(true, Ordering::SeqCst);
            Alert::PieceFinished {
                info_hash: [1u8; 20],
                piece_index: 1,
            }
        });
        assert_eq!(delivered_masked, 0);
        assert!(!called.load(Ordering::SeqCst));
        assert!(rx.try_recv().is_err());

        // LIFECYCLE passes through when enabled.
        assert_eq!(
            stream.post(Alert::TorrentAdded {
                info_hash: [2u8; 20]
            }),
            1
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            Alert::TorrentAdded {
                info_hash: [2u8; 20]
            }
        );

        // Re-enable PIECE and verify lazy construction invokes closure and delivers.
        stream.set_category_mask(AlertCategory::ALL);
        let delivered_ok = stream.post_lazy(AlertCategory::PIECE, || {
            called.store(true, Ordering::SeqCst);
            Alert::PieceFinished {
                info_hash: [1u8; 20],
                piece_index: 2,
            }
        });
        assert_eq!(delivered_ok, 1);
        assert!(called.load(Ordering::SeqCst));
        assert_eq!(
            rx.try_recv().unwrap(),
            Alert::PieceFinished {
                info_hash: [1u8; 20],
                piece_index: 2,
            }
        );
    }
}
