//! BEP 34 DNS Tracker Preferences (TXT & SRV Records).
//!
//! Queries BEP 34 DNS TXT records (`BITTORRENT [UDP:<port>|TCP:<port>]`) and DNS SRV
//! records (`_bittorrent-tracker._tcp.<domain>` for HTTP/HTTPS trackers,
//! `_bittorrent-tracker._udp.<domain>` for UDP trackers) to discover tracker endpoints,
//! opt-out directives, priorities, weights, and failover targets.

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackerProto {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtTrackerPreference {
    pub proto: TrackerProto,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bep34TxtResult {
    None,
    OptOut,
    Preferences(Vec<TxtTrackerPreference>),
}

fn build_dns_query(name: &str, qtype: u16, tx_id: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    // Transaction ID
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    // Flags: standard query, recursion desired (0x0100)
    pkt.extend_from_slice(&[0x01, 0x00]);
    // QDCOUNT = 1
    pkt.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Encode QNAME: labels length-prefixed
    for label in name.split('.') {
        let bytes = label.as_bytes();
        if !bytes.is_empty() && bytes.len() <= 63 {
            pkt.push(bytes.len() as u8);
            pkt.extend_from_slice(bytes);
        }
    }
    pkt.push(0x00); // Root label

    pkt.extend_from_slice(&qtype.to_be_bytes());
    // QCLASS = 1 (IN)
    pkt.extend_from_slice(&1u16.to_be_bytes());

    pkt
}

/// Formats a DNS query packet for an SRV record (Type 33, Class IN).
pub fn build_srv_query(name: &str, tx_id: u16) -> Vec<u8> {
    build_dns_query(name, 33, tx_id)
}

/// Formats a DNS query packet for a TXT record (Type 16, Class IN).
pub fn build_txt_query(name: &str, tx_id: u16) -> Vec<u8> {
    build_dns_query(name, 16, tx_id)
}

/// Parses a DNS response packet for SRV records, also returning the minimum answer TTL in seconds.
pub fn parse_srv_response_with_ttl(
    buf: &[u8],
    tx_id: u16,
) -> Result<(Vec<SrvRecord>, Option<u32>), &'static str> {
    if buf.len() < 12 {
        return Err("response packet too short");
    }
    let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
    if resp_id != tx_id {
        return Err("transaction ID mismatch");
    }

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Ok((Vec::new(), None)); // Non-zero return code (NXDOMAIN or error)
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut cursor = 12;

    // Skip question section
    for _ in 0..qdcount {
        cursor = skip_name(buf, cursor)?;
        cursor += 4; // QTYPE (2) + QCLASS (2)
        if cursor > buf.len() {
            return Err("truncated question section");
        }
    }

    // Parse answers
    let mut records = Vec::new();
    let mut min_ttl: Option<u32> = None;
    for _ in 0..ancount.min(64) {
        if cursor >= buf.len() {
            break;
        }
        cursor = skip_name(buf, cursor)?;
        if cursor + 10 > buf.len() {
            return Err("truncated answer header");
        }
        let rtype = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
        let ttl = u32::from_be_bytes([
            buf[cursor + 4],
            buf[cursor + 5],
            buf[cursor + 6],
            buf[cursor + 7],
        ]);
        let rdlength = u16::from_be_bytes([buf[cursor + 8], buf[cursor + 9]]) as usize;
        cursor += 10;

        if cursor + rdlength > buf.len() {
            return Err("truncated answer RDATA");
        }

        if rtype == 33 && rdlength >= 6 {
            let priority = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
            let weight = u16::from_be_bytes([buf[cursor + 2], buf[cursor + 3]]);
            let port = u16::from_be_bytes([buf[cursor + 4], buf[cursor + 5]]);
            let (target, _) = parse_name(buf, cursor + 6)?;

            records.push(SrvRecord {
                priority,
                weight,
                port,
                target,
            });
            min_ttl = Some(min_ttl.map_or(ttl, |cur| cur.min(ttl)));
        }
        cursor += rdlength;
    }

    Ok((records, min_ttl))
}

/// Parses a DNS response packet for SRV records.
pub fn parse_srv_response(buf: &[u8], tx_id: u16) -> Result<Vec<SrvRecord>, &'static str> {
    parse_srv_response_with_ttl(buf, tx_id).map(|(records, _)| records)
}

/// Parses a DNS response packet for TXT records (Type 16), also returning the minimum answer TTL.
pub fn parse_txt_response_with_ttl(
    buf: &[u8],
    tx_id: u16,
) -> Result<(Vec<String>, Option<u32>), &'static str> {
    if buf.len() < 12 {
        return Err("response packet too short");
    }
    let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
    if resp_id != tx_id {
        return Err("transaction ID mismatch");
    }

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Ok((Vec::new(), None));
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut cursor = 12;
    for _ in 0..qdcount {
        cursor = skip_name(buf, cursor)?;
        cursor += 4;
        if cursor > buf.len() {
            return Err("truncated question section");
        }
    }

    let mut texts = Vec::new();
    let mut min_ttl: Option<u32> = None;
    for _ in 0..ancount.min(64) {
        if cursor >= buf.len() {
            break;
        }
        cursor = skip_name(buf, cursor)?;
        if cursor + 10 > buf.len() {
            return Err("truncated answer header");
        }
        let rtype = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
        let ttl = u32::from_be_bytes([
            buf[cursor + 4],
            buf[cursor + 5],
            buf[cursor + 6],
            buf[cursor + 7],
        ]);
        let rdlength = u16::from_be_bytes([buf[cursor + 8], buf[cursor + 9]]) as usize;
        cursor += 10;

        if cursor + rdlength > buf.len() {
            return Err("truncated answer RDATA");
        }

        if rtype == 16 {
            let rdata = &buf[cursor..cursor + rdlength];
            let mut pos = 0usize;
            let mut joined = String::new();
            while pos < rdata.len() {
                let seg_len = usize::from(rdata[pos]);
                pos += 1;
                if pos + seg_len > rdata.len() {
                    return Err("truncated TXT string");
                }
                joined.push_str(&String::from_utf8_lossy(&rdata[pos..pos + seg_len]));
                pos += seg_len;
            }
            texts.push(joined);
            min_ttl = Some(min_ttl.map_or(ttl, |cur| cur.min(ttl)));
        }
        cursor += rdlength;
    }

    Ok((texts, min_ttl))
}

/// Parses BEP 34 `"BITTORRENT ..."` TXT strings into tracker preferences or an opt-out directive.
pub fn parse_bep34_txt_strings(records: &[String]) -> Bep34TxtResult {
    let mut saw_bittorrent = false;
    let mut prefs = Vec::new();

    for rec in records {
        let mut tokens = rec.split_whitespace();
        let Some(first) = tokens.next() else {
            continue;
        };
        if !first.eq_ignore_ascii_case("BITTORRENT") {
            continue;
        }
        saw_bittorrent = true;
        for tok in tokens {
            let Some((proto_raw, port_raw)) = tok.split_once(':') else {
                continue;
            };
            let proto = if proto_raw.eq_ignore_ascii_case("UDP") {
                TrackerProto::Udp
            } else if proto_raw.eq_ignore_ascii_case("TCP") {
                TrackerProto::Tcp
            } else {
                continue;
            };
            if let Ok(port) = port_raw.parse::<u16>() {
                if port > 0 {
                    prefs.push(TxtTrackerPreference { proto, port });
                }
            }
        }
    }

    if !saw_bittorrent {
        Bep34TxtResult::None
    } else if prefs.is_empty() {
        Bep34TxtResult::OptOut
    } else {
        Bep34TxtResult::Preferences(prefs)
    }
}

fn skip_name(buf: &[u8], mut cursor: usize) -> Result<usize, &'static str> {
    while cursor < buf.len() {
        let len = buf[cursor] as usize;
        if len == 0 {
            return Ok(cursor + 1);
        }
        if len >= 0xC0 {
            // Pointer
            return Ok(cursor + 2);
        }
        cursor += 1 + len;
    }
    Err("unterminated name")
}

fn parse_name(buf: &[u8], mut cursor: usize) -> Result<(String, usize), &'static str> {
    let mut labels = Vec::new();
    let mut bytes_read = 0;
    let mut jumped = false;
    let mut loop_count = 0;

    while cursor < buf.len() && loop_count < 100 {
        loop_count += 1;
        let len = buf[cursor] as usize;
        if len == 0 {
            if !jumped {
                bytes_read += 1;
            }
            break;
        }
        if len >= 0xC0 {
            if cursor + 1 >= buf.len() {
                return Err("truncated pointer");
            }
            let ptr = ((len & 0x3F) << 8) | usize::from(buf[cursor + 1]);
            if !jumped {
                bytes_read += 2;
                jumped = true;
            }
            cursor = ptr;
            continue;
        }
        cursor += 1;
        if cursor + len > buf.len() {
            return Err("truncated label");
        }
        labels.push(String::from_utf8_lossy(&buf[cursor..cursor + len]).to_string());
        cursor += len;
        if !jumped {
            bytes_read += 1 + len;
        }
    }

    Ok((labels.join("."), bytes_read))
}

/// The nameservers the system is configured with (`/etc/resolv.conf`). Empty where there is no
/// such file: SRV lookups are then skipped rather than sent to a public resolver, which would
/// leak the name of every tracker to a third party in the clear.
pub fn system_nameservers() -> Vec<SocketAddr> {
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            (it.next()? == "nameserver").then_some(())?;
            let ip: std::net::IpAddr = it.next()?.split('%').next()?.parse().ok()?;
            Some(SocketAddr::new(ip, 53))
        })
        .take(3)
        .collect()
}

const MIN_CACHE_TTL: Duration = Duration::from_secs(30);
const MAX_CACHE_TTL: Duration = Duration::from_secs(3600);
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60);
const CACHE_MAX: usize = 1024;

fn clamp_ttl(ttl_secs: Option<u32>, has_records: bool) -> Duration {
    if has_records {
        Duration::from_secs(u64::from(ttl_secs.unwrap_or(600))).clamp(MIN_CACHE_TTL, MAX_CACHE_TTL)
    } else {
        NEGATIVE_CACHE_TTL
    }
}

type SrvCache = std::collections::HashMap<String, (Instant, Vec<SrvRecord>)>;
type TxtCache = std::collections::HashMap<String, (Instant, Bep34TxtResult)>;

fn cache() -> &'static parking_lot::Mutex<SrvCache> {
    static CACHE: std::sync::OnceLock<parking_lot::Mutex<SrvCache>> = std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
}

fn txt_cache() -> &'static parking_lot::Mutex<TxtCache> {
    static TXT_CACHE: std::sync::OnceLock<parking_lot::Mutex<TxtCache>> =
        std::sync::OnceLock::new();
    TXT_CACHE.get_or_init(Default::default)
}

/// Orders records per RFC 2782: by priority, and within a priority by weighted random choice
/// (a record with weight 0 is only chosen when it must be).
pub fn order_records(mut records: Vec<SrvRecord>) -> Vec<SrvRecord> {
    use rand::Rng;
    records.sort_by_key(|r| r.priority);
    let mut out = Vec::with_capacity(records.len());
    let mut rng = rand::thread_rng();
    while !records.is_empty() {
        let prio = records[0].priority;
        let group_len = records.iter().take_while(|r| r.priority == prio).count();
        let total: u32 = records[..group_len]
            .iter()
            .map(|r| u32::from(r.weight))
            .sum();
        let pick = if total == 0 {
            0
        } else {
            let mut n = rng.gen_range(0..total);
            records[..group_len]
                .iter()
                .position(|r| {
                    let w = u32::from(r.weight);
                    if n < w {
                        true
                    } else {
                        n -= w;
                        false
                    }
                })
                .unwrap_or(0)
        };
        out.push(records.remove(pick));
    }
    out
}

async fn query_udp(server: SocketAddr, query: &[u8], tx_id: u16) -> Option<Result<Vec<u8>, ()>> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().ok()?
    } else {
        "[::]:0".parse().ok()?
    };
    let sock = UdpSocket::bind(bind).await.ok()?;
    // Connected: datagrams from anyone but the server are discarded by the kernel.
    sock.connect(server).await.ok()?;
    sock.send(query).await.ok()?;
    // Keep listening until the deadline: a forged or stray datagram (wrong id, not a response)
    // must not end the lookup, or anyone who can spray packets could make it fail.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(800);
    let mut buf = vec![0u8; 4096];
    loop {
        let n = tokio::time::timeout_at(deadline, sock.recv(&mut buf))
            .await
            .ok()?
            .ok()?;
        let resp = &buf[..n];
        if resp.len() < 12 || u16::from_be_bytes([resp[0], resp[1]]) != tx_id || resp[2] & 0x80 == 0
        {
            continue;
        }
        // TC bit: the answer did not fit; retry over TCP.
        if resp[2] & 0x02 != 0 {
            return Some(Err(()));
        }
        return Some(Ok(resp.to_vec()));
    }
}

async fn query_tcp(server: SocketAddr, query: &[u8], tx_id: u16) -> Option<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::time::timeout(
        Duration::from_millis(1500),
        tokio::net::TcpStream::connect(server),
    )
    .await
    .ok()?
    .ok()?;
    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(query);
    stream.write_all(&framed).await.ok()?;
    let mut len = [0u8; 2];
    tokio::time::timeout(Duration::from_millis(1500), stream.read_exact(&mut len))
        .await
        .ok()?
        .ok()?;
    let len = usize::from(u16::from_be_bytes(len));
    let mut buf = vec![0u8; len];
    tokio::time::timeout(Duration::from_millis(1500), stream.read_exact(&mut buf))
        .await
        .ok()?
        .ok()?;
    (buf.len() >= 12 && u16::from_be_bytes([buf[0], buf[1]]) == tx_id).then_some(buf)
}

/// Resolves DNS SRV records for a tracker host (BEP 34), in the order they should be tried.
///
/// Uses the system's nameservers unless `dns_server` is given, caches answers according to
/// the parsed DNS record TTL (clamped `30..=3600s`, or `60s` for negative answers), and returns
/// nothing when there is no nameserver or no answer.
/// BEP 34 applies only to a tracker URL without an explicit port: the caller checks that.
pub async fn resolve_tracker_srv(
    host: &str,
    scheme: &str,
    dns_server: Option<SocketAddr>,
) -> Vec<SrvRecord> {
    let service_proto = if scheme == "udp" {
        "_bittorrent-tracker._udp"
    } else {
        "_bittorrent-tracker._tcp"
    };
    let query_name = format!("{service_proto}.{host}");
    if dns_server.is_none() {
        let now = Instant::now();
        if let Some((expires_at, records)) = cache().lock().get(&query_name) {
            if now < *expires_at {
                return order_records(records.clone());
            }
        }
    }
    let servers: Vec<SocketAddr> = dns_server
        .map(|s| vec![s])
        .unwrap_or_else(system_nameservers);
    let mut records = Vec::new();
    let mut parsed_ttl = None;
    for server in servers {
        let tx_id: u16 = rand::random();
        let query = build_srv_query(&query_name, tx_id);
        let answer = match query_udp(server, &query, tx_id).await {
            Some(Ok(buf)) => Some(buf),
            Some(Err(())) => query_tcp(server, &query, tx_id).await,
            None => None,
        };
        if let Some(buf) = answer {
            let (recs, ttl) = parse_srv_response_with_ttl(&buf, tx_id).unwrap_or_default();
            records = recs;
            parsed_ttl = ttl;
            break;
        }
    }
    if dns_server.is_none() {
        let ttl = clamp_ttl(parsed_ttl, !records.is_empty());
        let mut c = cache().lock();
        if c.len() >= CACHE_MAX {
            c.clear();
        }
        c.insert(query_name, (Instant::now() + ttl, records.clone()));
    }
    order_records(records)
}

/// Resolves BEP 34 DNS TXT preferences or opt-out directives for a tracker hostname.
///
/// Queries DNS TXT (`QTYPE = 16`) on `host` directly over UDP with TCP fallback, caching
/// results using the parsed record TTL (clamped `30..=3600s`, or `60s` for `None`).
pub async fn resolve_bep34_txt(host: &str, dns_server: Option<SocketAddr>) -> Bep34TxtResult {
    if dns_server.is_none() {
        let now = Instant::now();
        if let Some((expires_at, cached)) = txt_cache().lock().get(host) {
            if now < *expires_at {
                return cached.clone();
            }
        }
    }
    let servers: Vec<SocketAddr> = dns_server
        .map(|s| vec![s])
        .unwrap_or_else(system_nameservers);
    let mut result = Bep34TxtResult::None;
    let mut parsed_ttl = None;
    for server in servers {
        let tx_id: u16 = rand::random();
        let query = build_txt_query(host, tx_id);
        let answer = match query_udp(server, &query, tx_id).await {
            Some(Ok(buf)) => Some(buf),
            Some(Err(())) => query_tcp(server, &query, tx_id).await,
            None => None,
        };
        if let Some(buf) = answer {
            if let Ok((strings, ttl)) = parse_txt_response_with_ttl(&buf, tx_id) {
                result = parse_bep34_txt_strings(&strings);
                parsed_ttl = ttl;
            }
            break;
        }
    }
    if dns_server.is_none() {
        let ttl = clamp_ttl(parsed_ttl, result != Bep34TxtResult::None);
        let mut c = txt_cache().lock();
        if c.len() >= CACHE_MAX {
            c.clear();
        }
        c.insert(host.to_string(), (Instant::now() + ttl, result.clone()));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_srv_query() {
        let name = "_bittorrent-tracker._tcp.tracker.example.com";
        let pkt = build_srv_query(name, 0x1234);
        assert_eq!(&pkt[0..2], &[0x12, 0x34]); // TX ID
        assert_eq!(&pkt[2..4], &[0x01, 0x00]); // Flags
        assert_eq!(&pkt[4..6], &[0x00, 0x01]); // 1 question

        // Verify trailing query type is 33 (SRV)
        let qtype = u16::from_be_bytes([pkt[pkt.len() - 4], pkt[pkt.len() - 3]]);
        assert_eq!(qtype, 33);
    }

    #[test]
    fn test_parse_srv_response_synthetic() {
        let mut resp = Vec::new();
        // Header: ID=0x5678, Flags=0x8180 (response, no error), QD=1, AN=1
        resp.extend_from_slice(&0x5678u16.to_be_bytes());
        resp.extend_from_slice(&0x8180u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes()); // QD
        resp.extend_from_slice(&1u16.to_be_bytes()); // AN
        resp.extend_from_slice(&0u32.to_be_bytes()); // NS, AR

        // Question: \x03foo\x00 QTYPE=33 QCLASS=1
        resp.extend_from_slice(&[3, b'f', b'o', b'o', 0]);
        resp.extend_from_slice(&33u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());

        // Answer: pointer to question (0xC00C), TYPE=33, CLASS=1, TTL=300, RDLENGTH=11
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&33u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&300u32.to_be_bytes());
        resp.extend_from_slice(&11u16.to_be_bytes()); // RDLENGTH

        // RDATA: Priority=10, Weight=20, Port=6969, Target=\x03bar\x00
        resp.extend_from_slice(&10u16.to_be_bytes());
        resp.extend_from_slice(&20u16.to_be_bytes());
        resp.extend_from_slice(&6969u16.to_be_bytes());
        resp.extend_from_slice(&[3, b'b', b'a', b'r', 0]);

        let parsed = parse_srv_response(&resp, 0x5678).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].priority, 10);
        assert_eq!(parsed[0].weight, 20);
        assert_eq!(parsed[0].port, 6969);
        assert_eq!(parsed[0].target, "bar");
    }

    fn rec(priority: u16, weight: u16, port: u16, target: &str) -> SrvRecord {
        SrvRecord {
            priority,
            weight,
            port,
            target: target.into(),
        }
    }

    #[test]
    fn records_are_ordered_by_priority_then_weighted_random() {
        let input = vec![rec(20, 5, 1, "c"), rec(10, 0, 2, "b"), rec(10, 100, 3, "a")];
        let mut first_is_a = 0;
        for _ in 0..200 {
            let out = order_records(input.clone());
            assert_eq!(out.len(), 3);
            assert_eq!(out[2].target, "c", "lower priority always last");
            if out[0].target == "a" {
                first_is_a += 1;
            }
        }
        // weight 100 vs 0: 'a' is always first within the priority-10 group.
        assert_eq!(first_is_a, 200);
    }

    /// A DNS server that answers every query with one SRV record.
    #[tokio::test]
    async fn resolves_over_udp_and_ignores_answers_with_a_wrong_id() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            let query = &buf[..n];
            let id = [query[0], query[1]];
            // Question section is everything after the 12-byte header.
            let question = &query[12..];
            let build = |id: [u8; 2]| {
                let mut r = Vec::new();
                r.extend_from_slice(&id);
                r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
                r.extend_from_slice(question);
                r.extend_from_slice(&[0xC0, 0x0C]);
                r.extend_from_slice(&33u16.to_be_bytes());
                r.extend_from_slice(&1u16.to_be_bytes());
                r.extend_from_slice(&60u32.to_be_bytes());
                r.extend_from_slice(&15u16.to_be_bytes());
                r.extend_from_slice(&[0, 5, 0, 7, 0x1B, 0x39]); // prio 5, weight 7, port 6969
                r.extend_from_slice(&[3, b't', b'r', b'k', 3, b'e', b'g', b'z', 0]);
                r
            };
            // First a forged answer with the wrong transaction id, then the real one.
            let _ = server.send_to(&build([id[0] ^ 0xFF, id[1]]), from).await;
            let _ = server.send_to(&build(id), from).await;
        });
        let records = resolve_tracker_srv("example.test", "udp", Some(addr)).await;
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].target, "trk.egz");
        assert_eq!(records[0].port, 6969);
    }

    #[test]
    fn parse_bep34_txt_preferences_and_opt_out() {
        assert_eq!(
            parse_bep34_txt_strings(&[
                "v=spf1 -all".to_string(),
                "BITTORRENT UDP:6969 TCP:80".to_string(),
            ]),
            Bep34TxtResult::Preferences(vec![
                TxtTrackerPreference {
                    proto: TrackerProto::Udp,
                    port: 6969,
                },
                TxtTrackerPreference {
                    proto: TrackerProto::Tcp,
                    port: 80,
                },
            ])
        );
        assert_eq!(
            parse_bep34_txt_strings(&["BITTORRENT".to_string()]),
            Bep34TxtResult::OptOut
        );
        assert_eq!(
            parse_bep34_txt_strings(&["BITTORRENT UDP:0 TCP:notaport".to_string()]),
            Bep34TxtResult::OptOut
        );
        assert_eq!(
            parse_bep34_txt_strings(&["v=spf1 -all".to_string()]),
            Bep34TxtResult::None
        );
    }

    #[test]
    fn parse_srv_and_txt_responses_extract_real_ttl() {
        // SRV packet TTL=123
        let mut srv_resp = Vec::new();
        srv_resp.extend_from_slice(&0x5678u16.to_be_bytes());
        srv_resp.extend_from_slice(&0x8180u16.to_be_bytes());
        srv_resp.extend_from_slice(&1u16.to_be_bytes());
        srv_resp.extend_from_slice(&1u16.to_be_bytes());
        srv_resp.extend_from_slice(&0u32.to_be_bytes());
        srv_resp.extend_from_slice(&[3, b'f', b'o', b'o', 0]);
        srv_resp.extend_from_slice(&33u16.to_be_bytes());
        srv_resp.extend_from_slice(&1u16.to_be_bytes());
        srv_resp.extend_from_slice(&[0xC0, 0x0C]);
        srv_resp.extend_from_slice(&33u16.to_be_bytes());
        srv_resp.extend_from_slice(&1u16.to_be_bytes());
        srv_resp.extend_from_slice(&123u32.to_be_bytes());
        srv_resp.extend_from_slice(&11u16.to_be_bytes());
        srv_resp.extend_from_slice(&10u16.to_be_bytes());
        srv_resp.extend_from_slice(&20u16.to_be_bytes());
        srv_resp.extend_from_slice(&6969u16.to_be_bytes());
        srv_resp.extend_from_slice(&[3, b'b', b'a', b'r', 0]);
        let (recs, ttl) = parse_srv_response_with_ttl(&srv_resp, 0x5678).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(ttl, Some(123));

        // TXT packet split across two RFC 1035 <character-string> chunks, TTL=45
        let seg1 = b"BITTORRENT ";
        let seg2 = b"UDP:6969 TCP:443";
        let rdlen = 1 + seg1.len() + 1 + seg2.len();
        let mut txt_resp = Vec::new();
        txt_resp.extend_from_slice(&0x9ABCu16.to_be_bytes());
        txt_resp.extend_from_slice(&0x8180u16.to_be_bytes());
        txt_resp.extend_from_slice(&1u16.to_be_bytes());
        txt_resp.extend_from_slice(&1u16.to_be_bytes());
        txt_resp.extend_from_slice(&0u32.to_be_bytes());
        txt_resp.extend_from_slice(&[3, b'f', b'o', b'o', 0]);
        txt_resp.extend_from_slice(&16u16.to_be_bytes());
        txt_resp.extend_from_slice(&1u16.to_be_bytes());
        txt_resp.extend_from_slice(&[0xC0, 0x0C]);
        txt_resp.extend_from_slice(&16u16.to_be_bytes());
        txt_resp.extend_from_slice(&1u16.to_be_bytes());
        txt_resp.extend_from_slice(&45u32.to_be_bytes());
        txt_resp.extend_from_slice(&(rdlen as u16).to_be_bytes());
        txt_resp.push(seg1.len() as u8);
        txt_resp.extend_from_slice(seg1);
        txt_resp.push(seg2.len() as u8);
        txt_resp.extend_from_slice(seg2);

        let (txts, txt_ttl) = parse_txt_response_with_ttl(&txt_resp, 0x9ABC).unwrap();
        assert_eq!(txts, vec!["BITTORRENT UDP:6969 TCP:443".to_string()]);
        assert_eq!(txt_ttl, Some(45));

        assert_eq!(clamp_ttl(Some(5), true), Duration::from_secs(30));
        assert_eq!(clamp_ttl(Some(86_400), true), Duration::from_secs(3600));
        assert_eq!(clamp_ttl(Some(300), true), Duration::from_secs(300));
        assert_eq!(clamp_ttl(None, false), Duration::from_secs(60));
    }

    #[tokio::test]
    async fn resolves_bep34_txt_over_loopback_udp() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            let query = &buf[..n];
            let id = [query[0], query[1]];
            let question = &query[12..];
            let txt = b"BITTORRENT UDP:6969 TCP:8080";
            let mut r = Vec::new();
            r.extend_from_slice(&id);
            r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            r.extend_from_slice(question);
            r.extend_from_slice(&[0xC0, 0x0C]);
            r.extend_from_slice(&16u16.to_be_bytes());
            r.extend_from_slice(&1u16.to_be_bytes());
            r.extend_from_slice(&120u32.to_be_bytes());
            r.extend_from_slice(&((1 + txt.len()) as u16).to_be_bytes());
            r.push(txt.len() as u8);
            r.extend_from_slice(txt);
            let _ = server.send_to(&r, from).await;
        });
        let res = resolve_bep34_txt("tracker.test", Some(addr)).await;
        assert_eq!(
            res,
            Bep34TxtResult::Preferences(vec![
                TxtTrackerPreference {
                    proto: TrackerProto::Udp,
                    port: 6969,
                },
                TxtTrackerPreference {
                    proto: TrackerProto::Tcp,
                    port: 8080,
                },
            ])
        );
    }
}
