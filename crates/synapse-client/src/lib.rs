//! Synapse 2.0 Official Client SDK.
//!
//! Provides a high-performance, asynchronous Rust client for the Synapse 2.0
//! BitTorrent Daemon control plane, including:
//!
//! - Type-safe gRPC commands (add/remove torrents, file priorities, rate limits).
//! - Transmission-parity dynamic session settings & scheduled Turtle Mode (Alt-Speed).
//! - Automatic reconnection with exponential backoff.
//! - In-memory live replica caching backed by 100ms sparse delta coalesced streams (`SynapseLiveCache`).

pub mod client;
pub mod error;
pub mod live_cache;

pub use client::SynapseClient;
pub use error::{Result, SynapseClientError};
pub use live_cache::SynapseLiveCache;
pub use synapse_proto::v2 as proto;
pub use tonic;
