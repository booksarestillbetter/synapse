//! HTTP and HTTPS tracker client implementation using reqwest.
//!
//! Supports both plain HTTP and TLS-secured HTTPS tracker announces and scrapes,
//! with chunked transfer encoding and HTTP keep-alive.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;

use synapse_bencode::BEncode;
use url::Url;

use crate::{AnnounceRequest, AnnounceResponse, Event, TrackerError};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// A compact tracker-announce peer list is 6 bytes/peer; this bounds how much
/// a tracker response can buffer.
const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn get_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(CONNECT_TIMEOUT)
            .user_agent("Synapse/2.0.0")
            .build()
            .unwrap_or_default()
    })
}

pub async fn announce(url: &Url, req: &AnnounceRequest) -> Result<AnnounceResponse, TrackerError> {
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(TrackerError::InvalidUrl(
            "only http:// and https:// tracker URLs are supported",
        ));
    }

    let target_url = build_announce_url(url, req)?;
    let client = get_client();
    let resp = client
        .get(target_url)
        .send()
        .await
        .map_err(map_reqwest_error)?;

    if !resp.status().is_success() {
        return Err(TrackerError::Malformed("tracker did not return HTTP 200"));
    }

    let bytes = resp.bytes().await.map_err(map_reqwest_error)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(TrackerError::Malformed("tracker response too large"));
    }

    parse_response(&bytes)
}

pub async fn scrape(url: &Url, info_hashes: &[[u8; 20]]) -> Result<crate::ScrapeResponse, TrackerError> {
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(TrackerError::InvalidUrl(
            "only http:// and https:// tracker URLs are supported",
        ));
    }

    let target_url = build_scrape_url(url, info_hashes)?;
    let client = get_client();
    let resp = client
        .get(target_url)
        .send()
        .await
        .map_err(map_reqwest_error)?;

    if !resp.status().is_success() {
        return Err(TrackerError::Malformed("tracker did not return HTTP 200"));
    }

    let bytes = resp.bytes().await.map_err(map_reqwest_error)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(TrackerError::Malformed("tracker response too large"));
    }

    parse_scrape_response(&bytes)
}

fn build_announce_url(url: &Url, req: &AnnounceRequest) -> Result<reqwest::Url, TrackerError> {
    let mut query = format!(
        "info_hash={}&peer_id={}&port={}&uploaded={}&downloaded={}&left={}&compact=1",
        percent_encode(&req.info_hash),
        percent_encode(&req.peer_id),
        req.port,
        req.uploaded,
        req.downloaded,
        req.left,
    );
    match req.event {
        Event::Started => query.push_str("&event=started"),
        Event::Stopped => query.push_str("&event=stopped"),
        Event::Completed => query.push_str("&event=completed"),
        Event::None => {}
    }
    if let Some(num_want) = req.num_want {
        query.push_str(&format!("&numwant={num_want}"));
    }

    let url_str = url.as_str();
    let base_no_frag = match url_str.split_once('#') {
        Some((base, _)) => base,
        None => url_str,
    };

    let full = if url.query().is_some() {
        format!("{base_no_frag}&{query}")
    } else {
        format!("{base_no_frag}?{query}")
    };

    reqwest::Url::parse(&full).map_err(|_| TrackerError::InvalidUrl("failed to construct tracker request URL"))
}

fn build_scrape_url(url: &Url, info_hashes: &[[u8; 20]]) -> Result<reqwest::Url, TrackerError> {
    let url_str = url.as_str();
    let base_no_frag = match url_str.split_once('#') {
        Some((base, _)) => base,
        None => url_str,
    };
    let scrape_base = base_no_frag.replace("/announce", "/scrape");
    let mut query = String::new();
    for (i, hash) in info_hashes.iter().enumerate() {
        if i > 0 {
            query.push('&');
        }
        query.push_str(&format!("info_hash={}", percent_encode(hash)));
    }

    let full = if url.query().is_some() {
        if query.is_empty() {
            scrape_base
        } else {
            format!("{scrape_base}&{query}")
        }
    } else if query.is_empty() {
        scrape_base
    } else {
        format!("{scrape_base}?{query}")
    };

    reqwest::Url::parse(&full).map_err(|_| TrackerError::InvalidUrl("failed to construct tracker scrape URL"))
}

fn map_reqwest_error(e: reqwest::Error) -> TrackerError {
    if e.is_timeout() {
        TrackerError::Timeout
    } else {
        TrackerError::Network(e.to_string())
    }
}

fn parse_scrape_response(body: &[u8]) -> Result<crate::ScrapeResponse, TrackerError> {
    let bencode = synapse_bencode::decode_buf(body).map_err(|_| TrackerError::Malformed("not valid bencode"))?;
    let mut dict = bencode.into_dict().ok_or(TrackerError::Malformed("scrape response must be a dictionary"))?;

    if let Some(reason) = dict.remove(b"failure reason".as_ref()).and_then(BEncode::into_string) {
        return Err(TrackerError::TrackerReported(reason));
    }

    let files_dict = dict.remove(b"files".as_ref()).and_then(BEncode::into_dict).ok_or(TrackerError::Malformed("missing files dict in scrape"))?;
    let mut files = std::collections::HashMap::new();

    for (hash_bytes, val) in files_dict {
        if hash_bytes.len() != 20 {
            continue;
        }
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&hash_bytes);

        if let Some(mut file_info) = val.into_dict() {
            let complete = file_info.remove(b"complete".as_ref()).and_then(BEncode::into_int).unwrap_or(0) as u32;
            let downloaded = file_info.remove(b"downloaded".as_ref()).and_then(BEncode::into_int).unwrap_or(0) as u32;
            let incomplete = file_info.remove(b"incomplete".as_ref()).and_then(BEncode::into_int).unwrap_or(0) as u32;
            let name = file_info.remove(b"name".as_ref()).and_then(BEncode::into_string);

            files.insert(hash, crate::ScrapeStats {
                seeders: complete,
                completed: downloaded,
                leechers: incomplete,
                name,
            });
        }
    }

    Ok(crate::ScrapeResponse { files })
}

/// BitTorrent's tracker query-string convention percent-encodes raw bytes directly
/// (`info_hash`/`peer_id` are arbitrary 20-byte binary, not necessarily valid UTF-8).
fn percent_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                s.push(b as char)
            }
            _ => s.push_str(&format!("%{b:02X}")),
        }
    }
    s
}

fn parse_response(data: &[u8]) -> Result<AnnounceResponse, TrackerError> {
    let value = synapse_bencode::decode_buf(data)
        .map_err(|_| TrackerError::Malformed("tracker response is not valid bencode"))?;
    let mut dict = value
        .into_dict()
        .ok_or(TrackerError::Malformed("tracker response is not a dict"))?;

    if let Some(reason) = dict
        .remove(b"failure reason".as_ref())
        .and_then(BEncode::into_string)
    {
        return Err(TrackerError::TrackerReported(reason));
    }

    let interval = dict
        .remove(b"interval".as_ref())
        .and_then(BEncode::into_int)
        .unwrap_or(1800) as u32;
    let leechers = dict
        .remove(b"incomplete".as_ref())
        .and_then(BEncode::into_int)
        .unwrap_or(0) as u32;
    let seeders = dict
        .remove(b"complete".as_ref())
        .and_then(BEncode::into_int)
        .unwrap_or(0) as u32;

    let peers = match dict.remove(b"peers".as_ref()) {
        // Compact format (BEP23): 6 bytes/peer, 4-byte IPv4 + 2-byte port.
        Some(BEncode::String(bytes)) => bytes
            .as_chunks::<6>()
            .0
            .iter()
            .map(|c| {
                let ip = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
                SocketAddr::from((ip, u16::from_be_bytes([c[4], c[5]])))
            })
            .collect(),
        // Legacy dictionary-model peer list: a list of {"ip": ..., "port": ...} dicts.
        Some(BEncode::List(list)) => list
            .into_iter()
            .filter_map(|p| {
                let mut d = p.into_dict()?;
                let ip = d.remove(b"ip".as_ref())?.into_string()?;
                let port = d.remove(b"port".as_ref())?.into_int()? as u16;
                format!("{ip}:{port}").parse().ok()
            })
            .collect(),
        _ => Vec::new(),
    };

    Ok(AnnounceResponse {
        interval,
        leechers,
        seeders,
        peers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn test_request() -> AnnounceRequest {
        AnnounceRequest {
            info_hash: [0xAAu8; 20],
            peer_id: [0xBBu8; 20],
            port: 6881,
            uploaded: 10,
            downloaded: 20,
            left: 30,
            event: Event::Started,
            num_want: Some(50),
        }
    }

    fn compact_response_body(interval: u32, seeders: u32, leechers: u32, peers: &[SocketAddr]) -> Vec<u8> {
        let mut dict = BTreeMap::new();
        dict.insert(b"interval".to_vec(), BEncode::Int(interval as i64));
        dict.insert(b"complete".to_vec(), BEncode::Int(seeders as i64));
        dict.insert(b"incomplete".to_vec(), BEncode::Int(leechers as i64));
        let mut compact = Vec::new();
        for p in peers {
            let SocketAddr::V4(v4) = p else { panic!("v4 only in test") };
            compact.extend_from_slice(&v4.ip().octets());
            compact.extend_from_slice(&v4.port().to_be_bytes());
        }
        dict.insert(b"peers".to_vec(), BEncode::String(compact));
        BEncode::Dict(dict).encode_to_buf()
    }

    async fn serve_once(listener: TcpListener, body: Vec<u8>) -> Vec<u8> {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") || n == 0 {
                break;
            }
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        stream.shutdown().await.unwrap();
        request
    }

    #[tokio::test]
    async fn announce_parses_a_compact_peer_list() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peers = vec![
            "127.0.0.1:1111".parse().unwrap(),
            "127.0.0.1:2222".parse().unwrap(),
        ];
        let body = compact_response_body(1800, 5, 2, &peers);
        let server = tokio::spawn(serve_once(listener, body));

        let url = Url::parse(&format!("http://{addr}/announce")).unwrap();
        let resp = announce(&url, &test_request()).await.unwrap();
        assert_eq!(resp.interval, 1800);
        assert_eq!(resp.seeders, 5);
        assert_eq!(resp.leechers, 2);
        assert_eq!(resp.peers, peers);

        let request = server.await.unwrap();
        let request = String::from_utf8_lossy(&request);
        assert!(request.starts_with("GET /announce?"));
        assert!(request.contains("port=6881"));
        assert!(request.contains("event=started"));
        assert!(request.contains("numwant=50"));
    }

    #[tokio::test]
    async fn announce_surfaces_a_failure_reason() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut dict = BTreeMap::new();
        dict.insert(
            b"failure reason".to_vec(),
            BEncode::String(b"torrent banned".to_vec()),
        );
        let body = BEncode::Dict(dict).encode_to_buf();
        tokio::spawn(serve_once(listener, body));

        let url = Url::parse(&format!("http://{addr}/announce")).unwrap();
        let err = announce(&url, &test_request()).await.unwrap_err();
        assert!(matches!(err, TrackerError::TrackerReported(ref s) if s == "torrent banned"));
    }

    #[tokio::test]
    async fn unsupported_schemes_are_rejected() {
        let url = Url::parse("ftp://tracker.example/announce").unwrap();
        let err = announce(&url, &test_request()).await.unwrap_err();
        assert!(matches!(err, TrackerError::InvalidUrl(_)));
    }

    #[tokio::test]
    async fn http_scrape_parses_files_dictionary() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut file_dict = BTreeMap::new();
        file_dict.insert(b"complete".to_vec(), BEncode::Int(10));
        file_dict.insert(b"downloaded".to_vec(), BEncode::Int(100));
        file_dict.insert(b"incomplete".to_vec(), BEncode::Int(3));
        file_dict.insert(b"name".to_vec(), BEncode::String(b"Ubuntu".to_vec()));

        let mut files = BTreeMap::new();
        let hash = [0x55u8; 20];
        files.insert(hash.to_vec(), BEncode::Dict(file_dict));

        let mut root = BTreeMap::new();
        root.insert(b"files".to_vec(), BEncode::Dict(files));
        let body = BEncode::Dict(root).encode_to_buf();

        let server = tokio::spawn(serve_once(listener, body));

        let url = Url::parse(&format!("http://{addr}/announce")).unwrap();
        let resp = scrape(&url, &[hash]).await.unwrap();
        assert_eq!(resp.files.len(), 1);
        let stats = resp.files.get(&hash).unwrap();
        assert_eq!(stats.seeders, 10);
        assert_eq!(stats.completed, 100);
        assert_eq!(stats.leechers, 3);
        assert_eq!(stats.name.as_deref(), Some("Ubuntu"));

        let req = server.await.unwrap();
        let req_str = String::from_utf8_lossy(&req);
        assert!(req_str.starts_with("GET /scrape?info_hash="));
    }

    #[test]
    fn percent_encode_matches_bittorrent_convention() {
        assert_eq!(percent_encode(b"abcABC012-_.~"), "abcABC012-_.~");
        assert_eq!(percent_encode(&[0x00, 0xFF, 0x20]), "%00%FF%20");
    }
}
