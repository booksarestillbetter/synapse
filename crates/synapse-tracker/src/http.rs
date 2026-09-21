//! HTTP and HTTPS tracker client implementation using reqwest.
//!
//! Supports both plain HTTP and TLS-secured HTTPS tracker announces and scrapes,
//! with chunked transfer encoding and HTTP keep-alive.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use synapse_bencode::BEncode;
use url::Url;

use crate::safe_http::{self, FetchError, FetchOptions, LocalPolicy};
use crate::{
    AnnounceRequest, AnnounceResponse, Event, TrackerError, MAX_ANNOUNCE_INTERVAL,
    MAX_PEERS_PER_RESPONSE, MIN_ANNOUNCE_INTERVAL,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest tracker response we will buffer (libtorrent's `tracker_maximum_response_length`).
/// A compact peer list is 6 bytes per peer, so this is generous.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Path segments a tracker URL must contain when it points at a non-public address, so a
/// torrent's announce URL cannot be aimed at an arbitrary local service.
const TRACKER_PATH_SEGMENTS: &[&str] = &["announce", "scrape"];

/// GETs `url` through the SSRF-checked, size-capped client and returns the body of a 200.
pub(crate) async fn fetch_tracker_body(url: reqwest::Url) -> Result<Vec<u8>, TrackerError> {
    let opts = FetchOptions {
        timeout: REQUEST_TIMEOUT,
        max_body: MAX_RESPONSE_BYTES,
        user_agent: concat!("Synapse/", env!("CARGO_PKG_VERSION")),
        local: LocalPolicy::AllowPathSegments(TRACKER_PATH_SEGMENTS),
        range: None,
    };
    let fetched = safe_http::fetch(&url, &opts)
        .await
        .map_err(map_fetch_error)?;
    if fetched.status != 200 {
        return Err(TrackerError::Malformed("tracker did not return HTTP 200"));
    }
    Ok(fetched.body)
}

fn map_fetch_error(e: FetchError) -> TrackerError {
    match e {
        FetchError::Http(err) => map_reqwest_error(err),
        FetchError::TooLarge(_) => TrackerError::Malformed("tracker response too large"),
        FetchError::Blocked(why) => TrackerError::InvalidUrl(why),
        FetchError::InvalidUrl(why) => TrackerError::InvalidUrl(why),
        FetchError::TooManyRedirects => TrackerError::Malformed("too many redirects"),
        FetchError::Resolve => TrackerError::Network("could not resolve tracker host".into()),
    }
}

pub async fn announce(url: &Url, req: &AnnounceRequest) -> Result<AnnounceResponse, TrackerError> {
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(TrackerError::InvalidUrl(
            "only http:// and https:// tracker URLs are supported",
        ));
    }

    let target_url = build_announce_url(url, req)?;
    let bytes = fetch_tracker_body(target_url).await?;

    parse_response(&bytes)
}

pub async fn scrape(
    url: &Url,
    info_hashes: &[[u8; 20]],
) -> Result<crate::ScrapeResponse, TrackerError> {
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(TrackerError::InvalidUrl(
            "only http:// and https:// tracker URLs are supported",
        ));
    }

    let target_url = build_scrape_url(url, info_hashes)?;
    let bytes = fetch_tracker_body(target_url).await?;

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
    if let Some(ref v6) = req.ipv6 {
        query.push_str(&format!(
            "&ipv6={}",
            percent_encode(v6.to_string().as_bytes())
        ));
    }
    if let Some(ref v4) = req.ipv4 {
        // `ip` is the classic BEP 3 parameter most trackers honour; `ipv4` is BEP 7's.
        query.push_str(&format!("&ip={v4}&ipv4={v4}"));
    }
    if let Some(ref id) = req.tracker_id {
        query.push_str(&format!("&trackerid={}", percent_encode(id.as_bytes())));
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

    reqwest::Url::parse(&full)
        .map_err(|_| TrackerError::InvalidUrl("failed to construct tracker request URL"))
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

    reqwest::Url::parse(&full)
        .map_err(|_| TrackerError::InvalidUrl("failed to construct tracker scrape URL"))
}

fn map_reqwest_error(e: reqwest::Error) -> TrackerError {
    if e.is_timeout() {
        TrackerError::Timeout
    } else {
        TrackerError::Network(e.to_string())
    }
}

pub fn parse_scrape_response(body: &[u8]) -> Result<crate::ScrapeResponse, TrackerError> {
    let bencode = synapse_bencode::decode_buf(body)
        .map_err(|_| TrackerError::Malformed("not valid bencode"))?;
    let mut dict = bencode.into_dict().ok_or(TrackerError::Malformed(
        "scrape response must be a dictionary",
    ))?;

    if let Some(reason) = dict
        .remove(b"failure reason".as_ref())
        .and_then(BEncode::into_string)
    {
        return Err(TrackerError::TrackerReported(reason));
    }

    let files_dict = dict
        .remove(b"files".as_ref())
        .and_then(BEncode::into_dict)
        .ok_or(TrackerError::Malformed("missing files dict in scrape"))?;
    let mut files = std::collections::HashMap::new();

    for (hash_bytes, val) in files_dict {
        if hash_bytes.len() != 20 {
            continue;
        }
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&hash_bytes);

        if let Some(mut file_info) = val.into_dict() {
            let complete = file_info
                .remove(b"complete".as_ref())
                .and_then(BEncode::into_int)
                .unwrap_or(0) as u32;
            let downloaded = file_info
                .remove(b"downloaded".as_ref())
                .and_then(BEncode::into_int)
                .unwrap_or(0) as u32;
            let incomplete = file_info
                .remove(b"incomplete".as_ref())
                .and_then(BEncode::into_int)
                .unwrap_or(0) as u32;
            let name = file_info
                .remove(b"name".as_ref())
                .and_then(BEncode::into_string);

            files.insert(
                hash,
                crate::ScrapeStats {
                    seeders: complete,
                    completed: downloaded,
                    leechers: incomplete,
                    name,
                },
            );
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

pub fn parse_response(data: &[u8]) -> Result<AnnounceResponse, TrackerError> {
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

    // Intervals are attacker-influenced numbers: bound them so a tracker cannot make us hammer it
    // (0) or go silent for years (huge), and reject negative values instead of wrapping.
    let bounded = |v: i64| {
        (v.clamp(0, i64::from(u32::MAX)) as u32).clamp(MIN_ANNOUNCE_INTERVAL, MAX_ANNOUNCE_INTERVAL)
    };
    let interval = dict
        .remove(b"interval".as_ref())
        .and_then(BEncode::into_int)
        .map(bounded)
        .unwrap_or(1800);
    let min_interval = dict
        .remove(b"min interval".as_ref())
        .and_then(BEncode::into_int)
        .map(bounded);
    let count = |v: Option<BEncode>| {
        v.and_then(BEncode::into_int)
            .map(|n| n.clamp(0, i64::from(u32::MAX)) as u32)
            .unwrap_or(0)
    };
    let leechers = count(dict.remove(b"incomplete".as_ref()));
    let seeders = count(dict.remove(b"complete".as_ref()));
    let tracker_id = dict
        .remove(b"tracker id".as_ref())
        .and_then(BEncode::into_string)
        .filter(|id| id.len() <= 256);
    let warning = dict
        .remove(b"warning message".as_ref())
        .and_then(BEncode::into_string);
    // BEP 24: our address as the tracker sees it, 4 or 16 raw bytes (some send it as text).
    let external_ip = dict
        .remove(b"external ip".as_ref())
        .and_then(BEncode::into_bytes)
        .and_then(|b| match b.len() {
            4 => Some(std::net::IpAddr::from(<[u8; 4]>::try_from(&b[..]).ok()?)),
            16 => Some(std::net::IpAddr::from(<[u8; 16]>::try_from(&b[..]).ok()?)),
            _ => std::str::from_utf8(&b).ok()?.parse().ok(),
        });

    let mut peers: Vec<SocketAddr> = match dict.remove(b"peers".as_ref()) {
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
                let port = u16::try_from(d.remove(b"port".as_ref())?.into_int()?).ok()?;
                let ip: std::net::IpAddr = ip.parse().ok()?;
                Some(SocketAddr::new(ip, port))
            })
            .collect(),
        _ => Vec::new(),
    };
    // BEP 7: IPv6 peers, 18 bytes each (16-byte address + 2-byte port).
    if let Some(BEncode::String(bytes)) = dict.remove(b"peers6".as_ref()) {
        peers.extend(bytes.as_chunks::<18>().0.iter().map(|c| {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&c[..16]);
            SocketAddr::from((
                std::net::Ipv6Addr::from(ip),
                u16::from_be_bytes([c[16], c[17]]),
            ))
        }));
    }
    peers.retain(|p| p.port() != 0);
    peers.truncate(MAX_PEERS_PER_RESPONSE);

    Ok(AnnounceResponse {
        interval,
        leechers,
        seeders,
        peers,
        min_interval,
        tracker_id,
        warning,
        external_ip,
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
            ipv4: None,
            ipv6: None,
            udp_options: Vec::new(),
            tracker_id: None,
        }
    }

    fn compact_response_body(
        interval: u32,
        seeders: u32,
        leechers: u32,
        peers: &[SocketAddr],
    ) -> Vec<u8> {
        let mut dict = BTreeMap::new();
        dict.insert(b"interval".to_vec(), BEncode::Int(interval as i64));
        dict.insert(b"complete".to_vec(), BEncode::Int(seeders as i64));
        dict.insert(b"incomplete".to_vec(), BEncode::Int(leechers as i64));
        let mut compact = Vec::new();
        for p in peers {
            let SocketAddr::V4(v4) = p else {
                panic!("v4 only in test")
            };
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

    fn bencode(entries: Vec<(&str, BEncode)>) -> Vec<u8> {
        let dict = entries
            .into_iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), v))
            .collect();
        let mut out = Vec::new();
        BEncode::Dict(dict).encode(&mut out).unwrap();
        out
    }

    #[test]
    fn response_carries_ipv6_peers_external_ip_tracker_id_and_min_interval() {
        let mut v4 = vec![10, 0, 0, 1, 0x1A, 0xE1]; // 10.0.0.1:6881
        v4.extend_from_slice(&[10, 0, 0, 2, 0, 0]); // port 0: dropped
        let mut v6 = Vec::new();
        v6.extend_from_slice(
            &"2001:db8::7"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        v6.extend_from_slice(&6882u16.to_be_bytes());
        let body = bencode(vec![
            ("interval", BEncode::Int(1800)),
            ("min interval", BEncode::Int(900)),
            ("complete", BEncode::Int(5)),
            ("incomplete", BEncode::Int(-3)),
            ("peers", BEncode::String(v4)),
            ("peers6", BEncode::String(v6)),
            ("external ip", BEncode::String(vec![203, 0, 113, 9])),
            ("tracker id", BEncode::String(b"abc".to_vec())),
            ("warning message", BEncode::String(b"slow down".to_vec())),
        ]);
        let r = parse_response(&body).unwrap();
        assert_eq!(r.interval, 1800);
        assert_eq!(r.min_interval, Some(900));
        assert_eq!(r.seeders, 5);
        assert_eq!(r.leechers, 0, "a negative count must not wrap");
        assert_eq!(
            r.peers,
            vec![
                "10.0.0.1:6881".parse::<SocketAddr>().unwrap(),
                "[2001:db8::7]:6882".parse::<SocketAddr>().unwrap()
            ]
        );
        assert_eq!(r.external_ip, Some("203.0.113.9".parse().unwrap()));
        assert_eq!(r.tracker_id.as_deref(), Some("abc"));
        assert_eq!(r.warning.as_deref(), Some("slow down"));
    }

    #[test]
    fn hostile_intervals_and_ports_are_bounded() {
        let zero = parse_response(&bencode(vec![("interval", BEncode::Int(0))])).unwrap();
        assert_eq!(zero.interval, MIN_ANNOUNCE_INTERVAL);
        let huge = parse_response(&bencode(vec![("interval", BEncode::Int(i64::MAX))])).unwrap();
        assert_eq!(huge.interval, MAX_ANNOUNCE_INTERVAL);
        let neg = parse_response(&bencode(vec![("interval", BEncode::Int(-5))])).unwrap();
        assert_eq!(neg.interval, MIN_ANNOUNCE_INTERVAL);
        // Dictionary-model peer with an out-of-range port is skipped, not truncated.
        let peer = |ip: &str, port: i64| {
            BEncode::Dict(
                [
                    (b"ip".to_vec(), BEncode::String(ip.as_bytes().to_vec())),
                    (b"port".to_vec(), BEncode::Int(port)),
                ]
                .into_iter()
                .collect(),
            )
        };
        let r = parse_response(&bencode(vec![(
            "peers",
            BEncode::List(vec![peer("1.2.3.4", 65536 + 80), peer("::1", 7000)]),
        )]))
        .unwrap();
        assert_eq!(r.peers, vec!["[::1]:7000".parse::<SocketAddr>().unwrap()]);
        // A flood of peers is capped.
        let many = vec![1u8; 6 * (MAX_PEERS_PER_RESPONSE + 500)];
        let r = parse_response(&bencode(vec![("peers", BEncode::String(many))])).unwrap();
        assert_eq!(r.peers.len(), MAX_PEERS_PER_RESPONSE);
    }

    #[test]
    fn a_configured_announce_address_is_sent_as_ip_ipv4_and_ipv6() {
        let url = Url::parse("http://tracker.example/announce").unwrap();
        let mut req = test_request();
        req.ipv4 = Some("203.0.113.5".parse().unwrap());
        req.ipv6 = Some("2001:db8::5".parse().unwrap());
        let built = build_announce_url(&url, &req).unwrap();
        let q = built.query().unwrap();
        assert!(q.contains("&ip=203.0.113.5&ipv4=203.0.113.5"), "{q}");
        assert!(
            q.contains("&ipv6=2001%3Adb8%3A%3A5") || q.contains("&ipv6=2001:db8::5"),
            "{q}"
        );
    }
}
