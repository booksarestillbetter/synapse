//! BEP 19 WebSeed (HTTP/FTP Seeding - GetRight style) Client.
//!
//! Allows leechers to fetch missing piece blocks directly from HTTP/HTTPS web mirrors
//! when swarm peer availability is low or when bootstrap seeding a new torrent.

use std::sync::Arc;
use url::Url;

/// Whether a web seed's response really is the byte range we asked for.
///
/// A `206` must carry a `Content-Range: bytes A-B/T` naming exactly `[start, start+len)`;
/// otherwise the bytes belong to some other part of the file and would corrupt the piece
/// (or, hash-checked, just get the piece discarded and the seed penalised). A `200` means
/// the server ignored `Range` and sent the whole resource, which is only usable when the
/// request started at offset 0 and the whole resource is exactly `len` bytes.
pub fn response_matches_range(
    status: u16,
    content_range: Option<&str>,
    body_len: usize,
    start: u64,
    len: u64,
) -> bool {
    if body_len as u64 != len {
        return false;
    }
    match status {
        206 => {
            let Some(rest) = content_range.and_then(|h| h.trim().strip_prefix("bytes ")) else {
                return false;
            };
            let Some((range, _total)) = rest.split_once('/') else {
                return false;
            };
            let Some((a, b)) = range.split_once('-') else {
                return false;
            };
            matches!((a.trim().parse::<u64>(), b.trim().parse::<u64>()), (Ok(a), Ok(b)) if a == start && b == start + len - 1)
        }
        200 => start == 0,
        _ => false,
    }
}

#[derive(Debug, Clone)]
pub struct WebSeedTarget {
    pub base_url: Arc<Url>,
    pub failed_attempts: u32,
    pub is_active: bool,
}

impl WebSeedTarget {
    pub fn new(url: Arc<Url>) -> Self {
        Self {
            base_url: url,
            failed_attempts: 0,
            is_active: true,
        }
    }
}

pub struct WebSeedManager {
    seeds: Vec<WebSeedTarget>,
}

impl WebSeedManager {
    pub fn new(url_list: &[Arc<Url>]) -> Self {
        let seeds = url_list.iter().cloned().map(WebSeedTarget::new).collect();

        Self { seeds }
    }

    pub fn has_webseeds(&self) -> bool {
        !self.seeds.is_empty()
    }

    /// Formats the HTTP request URL and `Range` header for a requested piece block.
    pub fn format_range_request(
        &self,
        base_url: &Url,
        file_path_rel: Option<&str>,
        start_byte: u64,
        length: u32,
    ) -> Result<(Url, String), url::ParseError> {
        let target_url = if let Some(path) = file_path_rel {
            if base_url.as_str().ends_with('/') {
                base_url.join(path)?
            } else {
                base_url.clone()
            }
        } else {
            base_url.clone()
        };

        let end_byte = start_byte + u64::from(length).saturating_sub(1);
        let range_header = format!("bytes={}-{}", start_byte, end_byte);

        Ok((target_url, range_header))
    }

    /// Formats a BEP 17 Hoffman-style HTTP seeding request URL for a piece and byte range.
    pub fn format_hoffman_request(
        &self,
        base_url: &Url,
        info_hash: &[u8; 20],
        piece_idx: u32,
        range: Option<(u32, u32)>,
    ) -> Result<Url, url::ParseError> {
        let hoffman = crate::hoffman::HoffmanWebSeed::new(base_url.as_str().to_string());
        let formatted = hoffman.format_request_url(info_hash, piece_idx, range);
        Url::parse(&formatted)
    }

    /// Records a successful block response from a webseed.
    pub fn on_success(&mut self, url_idx: usize) {
        if let Some(seed) = self.seeds.get_mut(url_idx) {
            seed.failed_attempts = 0;
            seed.is_active = true;
        }
    }

    /// Records a failed response from a webseed (tripping to inactive on 5 consecutive failures).
    pub fn on_failure(&mut self, url_idx: usize) {
        if let Some(seed) = self.seeds.get_mut(url_idx) {
            seed.failed_attempts += 1;
            if seed.failed_attempts >= 5 {
                seed.is_active = false;
            }
        }
    }

    pub fn active_seeds(&self) -> Vec<&WebSeedTarget> {
        self.seeds.iter().filter(|s| s.is_active).collect()
    }

    /// Picks the first active webseed target, returning its index (for `on_success`/
    /// `on_failure`) and base URL.
    pub fn pick_active_seed(&self) -> Option<(usize, Arc<Url>)> {
        self.seeds
            .iter()
            .enumerate()
            .find(|(_, s)| s.is_active)
            .map(|(i, s)| (i, s.base_url.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webseed_range_request_formatting() {
        let base_url = Arc::new(Url::parse("https://cdn.example.org/torrents/").unwrap());
        let mgr = WebSeedManager::new(std::slice::from_ref(&base_url));
        assert!(mgr.has_webseeds());

        // Single file / direct offset
        let (url, range) = mgr
            .format_range_request(&base_url, None, 16384, 16384)
            .unwrap();
        assert_eq!(url.as_str(), "https://cdn.example.org/torrents/");
        assert_eq!(range, "bytes=16384-32767");

        // Multi-file subpath
        let (url2, range2) = mgr
            .format_range_request(&base_url, Some("ubuntu.iso"), 0, 16384)
            .unwrap();
        assert_eq!(url2.as_str(), "https://cdn.example.org/torrents/ubuntu.iso");
        assert_eq!(range2, "bytes=0-16383");
    }

    #[test]
    fn test_webseed_failure_tripping() {
        let base_url = Arc::new(Url::parse("https://mirror.example.com/data.bin").unwrap());
        let mut mgr = WebSeedManager::new(&[base_url]);
        assert_eq!(mgr.active_seeds().len(), 1);

        for _ in 0..4 {
            mgr.on_failure(0);
            assert_eq!(mgr.active_seeds().len(), 1);
        }

        mgr.on_failure(0); // 5th failure trips
        assert_eq!(mgr.active_seeds().len(), 0);

        mgr.on_success(0);
        assert_eq!(mgr.active_seeds().len(), 1);
    }
}

#[cfg(test)]
mod range_tests {
    use super::response_matches_range;

    #[test]
    fn accepts_only_the_exact_requested_range() {
        assert!(response_matches_range(
            206,
            Some("bytes 100-199/1000"),
            100,
            100,
            100
        ));
        assert!(
            !response_matches_range(206, Some("bytes 0-99/1000"), 100, 100, 100),
            "wrong offset"
        );
        assert!(
            !response_matches_range(206, Some("bytes 100-198/1000"), 100, 100, 100),
            "wrong end"
        );
        assert!(
            !response_matches_range(206, None, 100, 100, 100),
            "missing Content-Range"
        );
        assert!(
            !response_matches_range(206, Some("items 100-199/1000"), 100, 100, 100),
            "wrong unit"
        );
        assert!(
            !response_matches_range(206, Some("bytes 100-199/1000"), 99, 100, 100),
            "short body"
        );
        assert!(!response_matches_range(404, None, 100, 100, 100));
    }

    #[test]
    fn a_200_is_usable_only_for_a_whole_small_resource_at_offset_zero() {
        assert!(response_matches_range(200, None, 100, 0, 100));
        assert!(
            !response_matches_range(200, None, 100, 100, 100),
            "server ignored Range for a mid-file request"
        );
    }
}
