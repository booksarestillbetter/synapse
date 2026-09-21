use std::time::Duration;
use synapse_meta::Info;
use synapse_tracker::safe_http::{FetchError, FetchOptions, LocalPolicy};
use url::Url;

use synapse_meta::MAX_TORRENT_FILE_BYTES;
const FETCH_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, thiserror::Error)]
pub enum FetchTorrentError {
    #[error("Insecure or invalid URL: {0}")]
    InvalidUrl(String),
    #[error("HTTP network request failed: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Response body exceeded 10 MB size limit")]
    PayloadTooLarge,
    #[error("Failed to decode bencode structure: {0}")]
    BencodeDecode(String),
    #[error("Invalid .torrent metadata: {0}")]
    Metadata(String),
}

/// Reads a local `.torrent` file, never buffering more than `MAX_TORRENT_FILE_BYTES`
/// (a regular file's reported size can lie, and a path may name `/dev/zero` or a FIFO, so
/// the cap is applied to the bytes actually read rather than to `metadata().len()`).
pub async fn read_torrent_file(path: &std::path::Path) -> Result<Vec<u8>, FetchTorrentError> {
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(path).await.map_err(|e| {
        FetchTorrentError::Metadata(format!("Failed to read local torrent file: {e}"))
    })?;
    let mut buf = Vec::new();
    file.take(MAX_TORRENT_FILE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .await
        .map_err(|e| {
            FetchTorrentError::Metadata(format!("Failed to read local torrent file: {e}"))
        })?;
    if buf.len() > MAX_TORRENT_FILE_BYTES {
        return Err(FetchTorrentError::PayloadTooLarge);
    }
    Ok(buf)
}

/// Securely fetches and parses a `.torrent` file or `magnet:` link from a remote URL or URI.
///
/// Implements comprehensive security hardening:
/// 1. Only `http://`, `https://`, and `magnet:?` schemes are permitted (strictly rejects `file://`, `ftp://`, `javascript:`, etc.).
/// 2. Protection against newline and null-byte injection.
/// 3. Memory exhaustion / zip bomb prevention (bounded 10 MB payload stream).
/// 4. Strict connection and total request timeouts (8s).
/// 5. Complete bencode AST validation and path-traversal sanitization via `synapse_meta::Info`.
pub async fn fetch_or_parse_torrent(url_or_magnet: &str) -> Result<Info, FetchTorrentError> {
    let trimmed = url_or_magnet.trim();

    // Check for control characters or null-byte injection
    if trimmed.chars().any(|c| c.is_control() || c == '\0') {
        return Err(FetchTorrentError::InvalidUrl(
            "URL contains illegal control or null characters".into(),
        ));
    }

    // 1. Direct Magnet Link Fast-Path
    if trimmed.starts_with("magnet:?") {
        return Info::from_magnet(trimmed)
            .map_err(|e| FetchTorrentError::Metadata(format!("Invalid magnet URI: {e}")));
    }

    // 2. Local File Path Fast-Path
    let resolved_path = if let Some(subpath) = trimmed.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            let mut p = std::path::PathBuf::from(home);
            p.push(subpath);
            p
        } else {
            std::path::PathBuf::from(trimmed)
        }
    } else {
        std::path::PathBuf::from(trimmed)
    };

    if resolved_path.is_file() {
        let bytes = read_torrent_file(&resolved_path).await?;
        let bencode = synapse_bencode::decode(&mut bytes.as_slice())
            .map_err(|e| FetchTorrentError::BencodeDecode(format!("Invalid local bencode: {e}")))?;
        return Info::from_bencode(bencode).map_err(|e| {
            FetchTorrentError::Metadata(format!("Failed to parse local torrent metadata: {e}"))
        });
    }

    // 2. HTTP/HTTPS URL Validation
    let parsed_url = Url::parse(trimmed)
        .map_err(|e| FetchTorrentError::InvalidUrl(format!("Malformed URL: {e}")))?;

    match parsed_url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(FetchTorrentError::InvalidUrl(format!(
                "Insecure scheme '{}' rejected (only http://, https://, and magnet:? are permitted)",
                other
            )));
        }
    }

    if parsed_url.host_str().is_none() {
        return Err(FetchTorrentError::InvalidUrl(
            "URL is missing a valid hostname".into(),
        ));
    }

    // 3. SSRF-checked, size-capped fetch: at most 5 redirects, none from a public host to
    // a local address, and the body is abandoned at the cap. The URL comes from the API
    // caller, so a LAN indexer is allowed as the starting point.
    let opts = FetchOptions {
        timeout: FETCH_TIMEOUT,
        max_body: MAX_TORRENT_FILE_BYTES,
        user_agent: concat!("Synapse/", env!("CARGO_PKG_VERSION")),
        local: LocalPolicy::AllowAny,
        range: None,
    };
    let fetched = synapse_tracker::safe_http::fetch(&parsed_url, &opts)
        .await
        .map_err(|e| match e {
            FetchError::TooLarge(_) => FetchTorrentError::PayloadTooLarge,
            FetchError::Http(err) => FetchTorrentError::Network(err),
            other => FetchTorrentError::InvalidUrl(other.to_string()),
        })?;
    if !(200..300).contains(&fetched.status) {
        return Err(FetchTorrentError::InvalidUrl(format!(
            "Remote server returned HTTP {}",
            fetched.status
        )));
    }
    let bytes = fetched.body;

    // 4. Bencode & Torrent Metadata Verification
    let bencode = synapse_bencode::decode_buf(&bytes)
        .map_err(|e| FetchTorrentError::BencodeDecode(format!("Invalid bencode format: {e}")))?;

    Info::from_bencode(bencode)
        .map_err(|e| FetchTorrentError::Metadata(format!("Invalid .torrent metadata: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_reject_insecure_schemes() {
        let err = fetch_or_parse_torrent("file:///etc/passwd")
            .await
            .unwrap_err();
        assert!(matches!(err, FetchTorrentError::InvalidUrl(_)));

        let err = fetch_or_parse_torrent("ftp://example.com/test.torrent")
            .await
            .unwrap_err();
        assert!(matches!(err, FetchTorrentError::InvalidUrl(_)));

        let err = fetch_or_parse_torrent("javascript:alert(1)")
            .await
            .unwrap_err();
        assert!(matches!(err, FetchTorrentError::InvalidUrl(_)));
    }

    #[tokio::test]
    async fn read_torrent_file_enforces_the_size_cap_and_never_reads_endless_files() {
        let dir = std::env::temp_dir().join(format!("synapse-torrent-cap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let big = dir.join("big.torrent");
        std::fs::write(&big, vec![0u8; MAX_TORRENT_FILE_BYTES + 1]).unwrap();
        assert!(matches!(
            read_torrent_file(&big).await,
            Err(FetchTorrentError::PayloadTooLarge)
        ));

        let ok = dir.join("ok.torrent");
        std::fs::write(&ok, b"d1:ai1ee").unwrap();
        assert_eq!(read_torrent_file(&ok).await.unwrap(), b"d1:ai1ee");

        // An endless device must be cut off at the cap rather than exhausting memory.
        #[cfg(unix)]
        assert!(matches!(
            read_torrent_file(std::path::Path::new("/dev/zero")).await,
            Err(FetchTorrentError::PayloadTooLarge)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_reject_control_characters() {
        let err = fetch_or_parse_torrent("http://example.com/test\0.torrent")
            .await
            .unwrap_err();
        assert!(matches!(err, FetchTorrentError::InvalidUrl(_)));

        let err = fetch_or_parse_torrent("http://example.com/test\r\nHost: evil.com")
            .await
            .unwrap_err();
        assert!(matches!(err, FetchTorrentError::InvalidUrl(_)));
    }

    #[tokio::test]
    async fn test_parse_valid_magnet() {
        let magnet = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=Ubuntu-24.04";
        let info = fetch_or_parse_torrent(magnet).await.expect("valid magnet");
        assert_eq!(info.name, "Ubuntu-24.04");
        assert_eq!(info.total_len, 0);
    }
}
