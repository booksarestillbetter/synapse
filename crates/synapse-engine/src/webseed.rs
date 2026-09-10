//! BEP 19 WebSeed (HTTP/FTP Seeding - GetRight style) Client.
//!
//! Allows leechers to fetch missing piece blocks directly from HTTP/HTTPS web mirrors
//! when swarm peer availability is low or when bootstrap seeding a new torrent.

use std::sync::Arc;
use url::Url;

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
        let seeds = url_list
            .iter()
            .cloned()
            .map(WebSeedTarget::new)
            .collect();

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
