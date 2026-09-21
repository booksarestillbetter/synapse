//! Tracker clients (HTTP and UDP/BEP15) for the synapse rewrite. See
//! `doc/REWRITE_ROADMAP.md` Part 2.
//!
//! Security posture carried forward from this branch's pre-rewrite Phase 2 fixes (see
//! `CHANGELOG.md`), and in the UDP client's case strengthened further: `udp::announce`
//! uses `UdpSocket::connect`, which - despite the name, this is still UDP - makes the
//! kernel filter `recv` to only the address we dialed. That gets us source-address
//! validation against off-path response spoofing for free, at the OS level, rather than
//! needing to check it ourselves in application code the way the pre-rewrite fix did.
//! Transaction IDs are still randomized per request (`rand`, not a counter) and checked
//! against what we sent, and the BEP15 anti-spoofing "key" field is caller-supplied
//! (generate it once randomly per daemon instance and reuse it - see `udp::announce`'s
//! doc-comment) rather than hardcoded.

pub mod breaker;
pub mod http;
pub mod safe_http;
pub mod srv;
pub mod udp;
pub mod udp_ext;

pub use breaker::{CanaryCircuitBreaker, CircuitState, HostCircuitInfo};
pub use srv::{resolve_tracker_srv, SrvRecord};
pub use udp_ext::{decode_udp_options, encode_udp_options, UdpOption};

use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    None,
    Started,
    Stopped,
    Completed,
}

#[derive(Debug, Clone)]
pub struct AnnounceRequest {
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
    pub port: u16,
    pub uploaded: u64,
    pub downloaded: u64,
    pub left: u64,
    pub event: Event,
    /// `None` lets the tracker pick a default.
    pub num_want: Option<i32>,
    /// BEP 7 cross-family address overrides.
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
    /// BEP 41 UDP tracker extensions.
    pub udp_options: Vec<crate::udp_ext::UdpOption>,
    /// The `tracker id` an earlier response gave, sent back as `trackerid` (BEP 3).
    pub tracker_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceResponse {
    pub interval: u32,
    pub leechers: u32,
    pub seeders: u32,
    pub peers: Vec<SocketAddr>,
    /// BEP 3 `min interval`: the tracker asks not to be announced to more often than this.
    pub min_interval: Option<u32>,
    /// BEP 3 `tracker id`, to be sent back on later announces.
    pub tracker_id: Option<String>,
    /// BEP 3 `warning message`.
    pub warning: Option<String>,
    /// BEP 24 `external ip`: the address the tracker sees us at.
    pub external_ip: Option<std::net::IpAddr>,
}

/// Announces we accept at most this many peers from one tracker response.
pub const MAX_PEERS_PER_RESPONSE: usize = 2000;
/// Longest and shortest re-announce interval honoured, in seconds.
pub const MIN_ANNOUNCE_INTERVAL: u32 = 60;
pub const MAX_ANNOUNCE_INTERVAL: u32 = 86_400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrapeStats {
    pub seeders: u32,
    pub completed: u32,
    pub leechers: u32,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrapeResponse {
    pub files: std::collections::HashMap<[u8; 20], ScrapeStats>,
}

#[derive(Debug, thiserror::Error)]
pub enum TrackerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("http/network error: {0}")]
    Network(String),
    #[error("tracker did not respond in time")]
    Timeout,
    #[error("malformed tracker response: {0}")]
    Malformed(&'static str),
    #[error("tracker returned an error: {0}")]
    TrackerReported(String),
    #[error("invalid tracker URL: {0}")]
    InvalidUrl(&'static str),
}

/// Sanitizes tracker URLs for safe logging, masking passkeys and authentication tokens.
pub fn sanitize_tracker_url(url: &url::Url) -> String {
    let mut safe = url.clone();
    if let Some(query) = safe.query() {
        let sanitized_query = query
            .split('&')
            .map(|pair| {
                if let Some((k, _)) = pair.split_once('=') {
                    let k_lower = k.to_lowercase();
                    if k_lower.contains("pass")
                        || k_lower.contains("auth")
                        || k_lower.contains("key")
                        || k_lower.contains("token")
                        || k_lower.contains("secret")
                    {
                        format!("{k}=[REDACTED]")
                    } else {
                        pair.to_string()
                    }
                } else {
                    pair.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("&");
        safe.set_query(Some(&sanitized_query));
    }
    safe.to_string()
}

#[cfg(test)]
mod privacy_tests {
    use super::*;
    use url::Url;

    #[test]
    fn test_sanitize_tracker_url_masks_passkeys() {
        let u = Url::parse(
            "http://tracker.private-site.org/announce?passkey=secret1234567890abcdef&info_hash=123",
        )
        .unwrap();
        let sanitized = sanitize_tracker_url(&u);
        assert!(!sanitized.contains("secret1234567890abcdef"));
        assert!(sanitized.contains("passkey=[REDACTED]"));
        assert!(sanitized.contains("info_hash=123"));
    }
}
