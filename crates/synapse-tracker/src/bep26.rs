//! BEP 26 HTTP/REST Tracker Protocol.
//!
//! Provides RESTful URL formatting for HTTP trackers that expose REST-compliant
//! paths rather than classic URL query parameters.

#[derive(Debug, Clone)]
pub struct RestTrackerClient {
    pub base_url: String,
}

impl RestTrackerClient {
    pub fn new(base_url: String) -> Self {
        let trimmed = base_url.trim_end_matches('/').to_string();
        Self { base_url: trimmed }
    }

    /// Formats a RESTful announce URL: `/announce/{info_hash_hex}`.
    pub fn format_announce_url(&self, info_hash: &[u8; 20], peer_id: &[u8; 20], port: u16) -> String {
        let hex_hash = hex_encode(info_hash);
        let hex_peer = hex_encode(peer_id);
        format!(
            "{}/announce/{}?peer_id={}&port={}",
            self.base_url, hex_hash, hex_peer, port
        )
    }

    /// Formats a RESTful scrape URL: `/scrape/{info_hash_hex}`.
    pub fn format_scrape_url(&self, info_hash: &[u8; 20]) -> String {
        let hex_hash = hex_encode(info_hash);
        format!("{}/scrape/{}", self.base_url, hex_hash)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bep26_rest_urls() {
        let client = RestTrackerClient::new("http://tracker.example.com/api/v1".to_string());
        let hash = [0xAB; 20];
        let peer = [0xCD; 20];

        let announce = client.format_announce_url(&hash, &peer, 6881);
        assert!(announce.starts_with("http://tracker.example.com/api/v1/announce/ababab"));
        assert!(announce.contains("port=6881"));

        let scrape = client.format_scrape_url(&hash);
        assert_eq!(
            scrape,
            format!("http://tracker.example.com/api/v1/scrape/{}", hex_encode(&hash))
        );
    }
}
