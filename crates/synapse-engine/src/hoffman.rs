//! BEP 17 HTTP Seeding (Hoffman Style).
//!
//! Formats HTTP GET requests with `info_hash`, `piece`, and `ranges` URL query
//! parameters per the original Hoffman HTTP seeding specification.

pub struct HoffmanWebSeed {
    pub base_url: String,
}

impl HoffmanWebSeed {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }

    /// Formats a BEP 17 HTTP seeding request URL for a specific piece and optional byte range.
    pub fn format_request_url(&self, info_hash: &[u8; 20], piece_idx: u32, range: Option<(u32, u32)>) -> String {
        let hex_hash = hex::encode(info_hash);
        let mut url = if self.base_url.contains('?') {
            format!("{}&info_hash={}&piece={}", self.base_url, hex_hash, piece_idx)
        } else {
            format!("{}?info_hash={}&piece={}", self.base_url, hex_hash, piece_idx)
        };

        if let Some((start, end)) = range {
            url.push_str(&format!("&ranges={}-{}", start, end));
        }

        url
    }
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bep17_hoffman_request_formatting() {
        let seed = HoffmanWebSeed::new("http://mirror.example.com/seed".to_string());
        let hash = [0x55; 20];
        let url = seed.format_request_url(&hash, 3, Some((0, 16384)));

        assert!(url.starts_with("http://mirror.example.com/seed?info_hash="));
        assert!(url.contains("&piece=3"));
        assert!(url.contains("&ranges=0-16384"));
    }
}
