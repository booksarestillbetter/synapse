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

fn percent_decode_ascii(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push(((hi << 4) | lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_sensitive_query_key(raw_key: &str) -> bool {
    let decoded = percent_decode_ascii(raw_key).to_ascii_lowercase();
    decoded.contains("pass")
        || decoded.contains("auth")
        || decoded.contains("key")
        || decoded.contains("token")
        || decoded.contains("secret")
        || decoded.contains("session")
        || decoded.contains("signature")
        || matches!(
            decoded.as_str(),
            "pid" | "pk" | "uid" | "hash" | "sig" | "ak" | "id"
        )
}

fn is_passkey_path_segment(seg: &str) -> bool {
    let decoded = percent_decode_ascii(seg);
    let lower = decoded.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "" | "announce"
            | "announce.php"
            | "scrape"
            | "scrape.php"
            | "tracker"
            | "torrents"
            | "download"
    ) {
        return false;
    }
    decoded.len() >= 16
        && decoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Sanitizes tracker URLs for safe logging, masking passkeys, path tokens, userinfo, and authentication tokens.
pub fn sanitize_tracker_url(url: &url::Url) -> String {
    let mut safe = url.clone();
    let had_userinfo = !safe.username().is_empty() || safe.password().is_some();
    if had_userinfo {
        let _ = safe.set_username("REDACTED");
        let _ = safe.set_password(None);
    }

    let path = safe.path().to_string();
    if path.contains('/') {
        let sanitized_segments: Vec<String> = path
            .split('/')
            .map(|seg| {
                if is_passkey_path_segment(seg) {
                    "[REDACTED]".to_string()
                } else {
                    seg.to_string()
                }
            })
            .collect();
        safe.set_path(&sanitized_segments.join("/"));
    }

    if let Some(query) = safe.query() {
        let sanitized_query = query
            .split('&')
            .map(|pair| {
                if let Some((k, _)) = pair.split_once('=') {
                    if is_sensitive_query_key(k) {
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

    let mut out = safe.to_string();
    if had_userinfo {
        out = out.replacen("://REDACTED@", "://[REDACTED]@", 1);
    }
    out
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

    #[test]
    fn test_sanitize_tracker_url_masks_path_passkeys_userinfo_and_encoded_params() {
        // 1. Path-based passkeys (/<passkey>/announce and /announce/<passkey>)
        let u1 = Url::parse(
            "https://tracker.example.org/0123456789abcdef0123456789abcdef/announce?info_hash=123",
        )
        .unwrap();
        let s1 = sanitize_tracker_url(&u1);
        assert!(!s1.contains("0123456789abcdef0123456789abcdef"), "{s1}");
        assert!(s1.contains("/[REDACTED]/announce"), "{s1}");
        assert!(s1.contains("info_hash=123"), "{s1}");

        let u2 =
            Url::parse("https://tracker.example.org/announce/fedcba9876543210fedcba9876543210")
                .unwrap();
        let s2 = sanitize_tracker_url(&u2);
        assert!(!s2.contains("fedcba9876543210fedcba9876543210"), "{s2}");
        assert!(s2.contains("/announce/[REDACTED]"), "{s2}");

        // 2. URL userinfo
        let u3 = Url::parse("http://alice:supersecret@tracker.example.org/announce").unwrap();
        let s3 = sanitize_tracker_url(&u3);
        assert!(!s3.contains("alice"), "{s3}");
        assert!(!s3.contains("supersecret"), "{s3}");
        assert!(s3.contains("[REDACTED]@tracker.example.org"), "{s3}");

        // 3. Percent-encoded query parameter names and short param names (pid, pk, uid, sig, session)
        let u4 = Url::parse(
            "http://tracker.example.org/announce?p%61sskey=mysecret1&pid=mysecret2&pk=mysecret3&session_id=mysecret4&sig=mysecret5",
        )
        .unwrap();
        let s4 = sanitize_tracker_url(&u4);
        for secret in [
            "mysecret1",
            "mysecret2",
            "mysecret3",
            "mysecret4",
            "mysecret5",
        ] {
            assert!(!s4.contains(secret), "leaked {secret} in {s4}");
        }
    }
}
