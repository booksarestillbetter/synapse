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
    pub fn format_request_url(
        &self,
        info_hash: &[u8; 20],
        piece_idx: u32,
        range: Option<(u32, u32)>,
    ) -> String {
        let encoded_hash = url_encode_info_hash(info_hash);
        let mut url = if self.base_url.contains('?') {
            format!(
                "{}&info_hash={}&piece={}",
                self.base_url, encoded_hash, piece_idx
            )
        } else {
            format!(
                "{}?info_hash={}&piece={}",
                self.base_url, encoded_hash, piece_idx
            )
        };

        if let Some((start, end)) = range {
            url.push_str(&format!("&ranges={}-{}", start, end));
        }

        url
    }
}

fn url_encode_info_hash(bytes: &[u8; 20]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(&mut out, "%{:02X}", b);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bep17_hoffman_request_formatting() {
        let seed = HoffmanWebSeed::new("http://mirror.example.com/seed".to_string());
        let hash = [0x55; 20];
        let url = seed.format_request_url(&hash, 3, Some((0, 16384)));

        assert_eq!(
            url,
            "http://mirror.example.com/seed?info_hash=UUUUUUUUUUUUUUUUUUUU&piece=3&ranges=0-16384"
        );
    }

    #[test]
    fn bep17_percent_encodes_raw_binary_info_hash() {
        let seed = HoffmanWebSeed::new("http://mirror.example.com/seed?k=v".to_string());
        let hash = [
            0x00, 0xFF, 0x20, b'A', b'~', b'-', b'_', b'.', 0xAB, 0x12, 0x34, 0x56, 0x78, 0x9A,
            0xBC, 0xDE, 0xF0, 0x01, 0x02, 0x03,
        ];
        let url = seed.format_request_url(&hash, 7, None);
        assert_eq!(
            url,
            "http://mirror.example.com/seed?k=v&info_hash=%00%FF%20A~-_.".to_owned()
                + "%AB%124Vx%9A%BC%DE%F0%01%02%03&piece=7"
        );
    }
}
