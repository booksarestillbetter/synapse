//! UDP tracker protocol (BEP15).

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::{AnnounceRequest, AnnounceResponse, Event, TrackerError};

const PROTOCOL_ID: u64 = 0x0000_0417_2710_1980;
const ACTION_CONNECT: u32 = 0;
const ACTION_ANNOUNCE: u32 = 1;
const ACTION_ERROR: u32 = 3;
const MAX_ATTEMPTS: u32 = 3;
/// Bounded retransmission schedule: 5 * 2^n seconds (5s, 10s, 20s = 35s max) so an unreachable
/// or stalled UDP tracker fails fast without blocking swarm announce cycles for minutes.
const BASE_TIMEOUT_SECS: u64 = 5;

/// Performs a full connect+announce exchange against a UDP tracker at `addr` (already
/// resolved - callers own DNS resolution and its own security properties, not this
/// module). `key` is BEP15's anti-spoofing/identification field: generate one randomly
/// once per daemon instance (`rand::random()`) and pass the *same* value on every call,
/// rather than a fresh one each time or a hardcoded constant - a fresh key every
/// announce defeats its purpose just as much as a constant one does.
pub async fn announce(
    addr: SocketAddr,
    req: &AnnounceRequest,
    key: u32,
) -> Result<AnnounceResponse, TrackerError> {
    let sock = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
    sock.connect(addr).await?;

    let connection_id = connect(&sock).await?;
    do_announce(&sock, connection_id, req, key).await
}

pub async fn scrape(
    addr: SocketAddr,
    info_hashes: &[[u8; 20]],
) -> Result<crate::ScrapeResponse, TrackerError> {
    let sock = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
    sock.connect(addr).await?;

    let connection_id = connect(&sock).await?;
    do_scrape(&sock, connection_id, info_hashes).await
}

async fn do_scrape(
    sock: &UdpSocket,
    connection_id: u64,
    info_hashes: &[[u8; 20]],
) -> Result<crate::ScrapeResponse, TrackerError> {
    const ACTION_SCRAPE: u32 = 2;
    let txn_id: u32 = rand::random();
    let mut pkt = Vec::with_capacity(16 + info_hashes.len() * 20);
    pkt.extend_from_slice(&connection_id.to_be_bytes());
    pkt.extend_from_slice(&ACTION_SCRAPE.to_be_bytes());
    pkt.extend_from_slice(&txn_id.to_be_bytes());
    for hash in info_hashes {
        pkt.extend_from_slice(hash);
    }

    let mut buf = vec![0u8; 8 + info_hashes.len() * 12];
    let n = send_and_recv(sock, &pkt, txn_id, &mut buf).await?;
    if n < 8 {
        return Err(TrackerError::Malformed("scrape response too short"));
    }
    let action = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    match action {
        ACTION_SCRAPE => {
            let data = &buf[8..n];
            if !data.len().is_multiple_of(12) {
                return Err(TrackerError::Malformed("scrape payload length not multiple of 12"));
            }
            let mut files = std::collections::HashMap::new();
            for (i, chunk) in data.chunks_exact(12).enumerate() {
                if i < info_hashes.len() {
                    let seeders = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
                    let completed = u32::from_be_bytes(chunk[4..8].try_into().unwrap());
                    let leechers = u32::from_be_bytes(chunk[8..12].try_into().unwrap());
                    files.insert(info_hashes[i], crate::ScrapeStats {
                        seeders,
                        completed,
                        leechers,
                        name: None,
                    });
                }
            }
            Ok(crate::ScrapeResponse { files })
        }
        ACTION_ERROR => Err(parse_error(&buf[8..n])),
        _ => Err(TrackerError::Malformed("unexpected action in scrape response")),
    }
}

async fn connect(sock: &UdpSocket) -> Result<u64, TrackerError> {
    let txn_id: u32 = rand::random();
    let mut req = [0u8; 16];
    req[0..8].copy_from_slice(&PROTOCOL_ID.to_be_bytes());
    req[8..12].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
    req[12..16].copy_from_slice(&txn_id.to_be_bytes());

    let mut buf = [0u8; 16];
    let n = send_and_recv(sock, &req, txn_id, &mut buf).await?;
    if n < 16 {
        return Err(TrackerError::Malformed("connect response too short"));
    }
    let action = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    match action {
        ACTION_CONNECT => Ok(u64::from_be_bytes(buf[8..16].try_into().unwrap())),
        ACTION_ERROR => Err(parse_error(&buf[8..n])),
        _ => Err(TrackerError::Malformed("unexpected action in connect response")),
    }
}

async fn do_announce(
    sock: &UdpSocket,
    connection_id: u64,
    req: &AnnounceRequest,
    key: u32,
) -> Result<AnnounceResponse, TrackerError> {
    let txn_id: u32 = rand::random();
    let mut pkt = [0u8; 98];
    pkt[0..8].copy_from_slice(&connection_id.to_be_bytes());
    pkt[8..12].copy_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
    pkt[12..16].copy_from_slice(&txn_id.to_be_bytes());
    pkt[16..36].copy_from_slice(&req.info_hash);
    pkt[36..56].copy_from_slice(&req.peer_id);
    pkt[56..64].copy_from_slice(&req.downloaded.to_be_bytes());
    pkt[64..72].copy_from_slice(&req.left.to_be_bytes());
    pkt[72..80].copy_from_slice(&req.uploaded.to_be_bytes());
    let event: u32 = match req.event {
        Event::None => 0,
        Event::Completed => 1,
        Event::Started => 2,
        Event::Stopped => 3,
    };
    pkt[80..84].copy_from_slice(&event.to_be_bytes());
    pkt[84..88].copy_from_slice(&0u32.to_be_bytes()); // IP: 0 = let the tracker infer it
    pkt[88..92].copy_from_slice(&key.to_be_bytes());
    let num_want = req.num_want.unwrap_or(-1);
    pkt[92..96].copy_from_slice(&num_want.to_be_bytes());
    pkt[96..98].copy_from_slice(&req.port.to_be_bytes());

    // Compact peer list: up to ~74 * 6-byte entries in a 500-byte buffer, generous for
    // a single announce response.
    let mut buf = [0u8; 500];
    let n = send_and_recv(sock, &pkt, txn_id, &mut buf).await?;
    if n < 20 {
        return Err(TrackerError::Malformed("announce response too short"));
    }
    let action = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    match action {
        ACTION_ANNOUNCE => {
            let interval = u32::from_be_bytes(buf[8..12].try_into().unwrap());
            let leechers = u32::from_be_bytes(buf[12..16].try_into().unwrap());
            let seeders = u32::from_be_bytes(buf[16..20].try_into().unwrap());
            // `chunks_exact` (not `chunks`) silently drops a ragged trailing chunk
            // instead of yielding it - the pre-rewrite fix for exactly this panic risk
            // (CHANGELOG.md) applies here too, from the start this time.
            let peers = buf[20..n]
                .chunks_exact(6)
                .map(|c| {
                    let ip = std::net::Ipv4Addr::new(c[0], c[1], c[2], c[3]);
                    SocketAddr::from((ip, u16::from_be_bytes([c[4], c[5]])))
                })
                .collect();
            Ok(AnnounceResponse {
                interval,
                leechers,
                seeders,
                peers,
            })
        }
        ACTION_ERROR => Err(parse_error(&buf[8..n])),
        _ => Err(TrackerError::Malformed("unexpected action in announce response")),
    }
}

fn parse_error(msg: &[u8]) -> TrackerError {
    TrackerError::TrackerReported(String::from_utf8_lossy(msg).into_owned())
}

/// Sends `req` and waits for a response whose transaction ID matches `txn_id`,
/// retrying with BEP15's recommended backoff schedule on timeout. A response from the
/// wrong source address can't reach us at all (the socket is `connect`ed - see
/// `announce`'s doc-comment); a response with a mismatched transaction ID (e.g. a very
/// late reply to a previous, already-abandoned attempt) is treated the same as no
/// response and we keep waiting out the current attempt's timeout rather than
/// accepting it.
async fn send_and_recv(
    sock: &UdpSocket,
    req: &[u8],
    txn_id: u32,
    buf: &mut [u8],
) -> Result<usize, TrackerError> {
    for attempt in 0..MAX_ATTEMPTS {
        sock.send(req).await?;
        let deadline = Duration::from_secs(BASE_TIMEOUT_SECS * (1u64 << attempt));
        let attempt_start = tokio::time::Instant::now();
        loop {
            let remaining = deadline.saturating_sub(attempt_start.elapsed());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, sock.recv(buf)).await {
                Ok(Ok(n)) if n >= 8 => {
                    let resp_txn = u32::from_be_bytes(buf[4..8].try_into().unwrap());
                    if resp_txn == txn_id {
                        return Ok(n);
                    }
                    // Mismatched transaction id: not for us (or a stale retry's
                    // response) - keep waiting within this attempt's deadline.
                }
                Ok(Ok(_)) => {} // too short to even have a transaction id; ignore
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break, // this attempt's deadline elapsed
            }
        }
    }
    Err(TrackerError::Timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket as TokioUdpSocket;

    fn test_request() -> AnnounceRequest {
        AnnounceRequest {
            info_hash: [1u8; 20],
            peer_id: [2u8; 20],
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: 1000,
            event: Event::Started,
            num_want: None,
        }
    }

    /// A minimal fake UDP tracker: replies to one connect and one announce, then stops.
    async fn run_fake_tracker(sock: TokioUdpSocket, peers: Vec<SocketAddr>) {
        let mut buf = [0u8; 512];
        let (n, from) = sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 16, "expected a connect request");
        let txn_id = &buf[12..16];
        let connection_id: u64 = 0xdead_beef_1234_5678;
        let mut resp = [0u8; 16];
        resp[0..4].copy_from_slice(&0u32.to_be_bytes()); // action = connect
        resp[4..8].copy_from_slice(txn_id);
        resp[8..16].copy_from_slice(&connection_id.to_be_bytes());
        sock.send_to(&resp, from).await.unwrap();

        let (n, from) = sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 98, "expected an announce request");
        assert_eq!(&buf[0..8], connection_id.to_be_bytes());
        let txn_id = buf[12..16].to_vec();
        let mut resp = Vec::new();
        resp.extend_from_slice(&1u32.to_be_bytes()); // action = announce
        resp.extend_from_slice(&txn_id);
        resp.extend_from_slice(&1800u32.to_be_bytes()); // interval
        resp.extend_from_slice(&3u32.to_be_bytes()); // leechers
        resp.extend_from_slice(&5u32.to_be_bytes()); // seeders
        for peer in &peers {
            let SocketAddr::V4(v4) = peer else {
                panic!("test only supports v4 peers")
            };
            resp.extend_from_slice(&v4.ip().octets());
            resp.extend_from_slice(&v4.port().to_be_bytes());
        }
        sock.send_to(&resp, from).await.unwrap();
    }

    #[tokio::test]
    async fn full_connect_and_announce_roundtrip() {
        let tracker_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tracker_addr = tracker_sock.local_addr().unwrap();
        let expected_peers = vec![
            "127.0.0.1:1000".parse().unwrap(),
            "127.0.0.1:2000".parse().unwrap(),
        ];
        let server = tokio::spawn(run_fake_tracker(tracker_sock, expected_peers.clone()));

        let resp = announce(tracker_addr, &test_request(), 0x1122_3344)
            .await
            .unwrap();
        assert_eq!(resp.interval, 1800);
        assert_eq!(resp.leechers, 3);
        assert_eq!(resp.seeders, 5);
        assert_eq!(resp.peers, expected_peers);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn tracker_error_response_is_surfaced() {
        let tracker_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tracker_addr = tracker_sock.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_n, from) = tracker_sock.recv_from(&mut buf).await.unwrap();
            let txn_id = buf[12..16].to_vec();
            let mut resp = Vec::new();
            resp.extend_from_slice(&3u32.to_be_bytes()); // action = error
            resp.extend_from_slice(&txn_id);
            resp.extend_from_slice(b"torrent not registered");
            tracker_sock.send_to(&resp, from).await.unwrap();
        });

        let err = announce(tracker_addr, &test_request(), 0)
            .await
            .unwrap_err();
        assert!(matches!(err, TrackerError::TrackerReported(_)));
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn times_out_when_the_tracker_never_responds() {
        let tracker_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tracker_addr = tracker_sock.local_addr().unwrap();
        // Nobody answers `tracker_sock` at all.
        let result = announce(tracker_addr, &test_request(), 0).await;
        assert!(matches!(result, Err(TrackerError::Timeout)));
    }

    #[tokio::test]
    async fn ignores_a_response_with_the_wrong_transaction_id_and_still_succeeds() {
        let tracker_sock = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tracker_addr = tracker_sock.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_n, from) = tracker_sock.recv_from(&mut buf).await.unwrap();
            // Send a bogus, mismatched-transaction-id reply first - must be ignored.
            let mut bogus = [0u8; 16];
            bogus[0..4].copy_from_slice(&0u32.to_be_bytes());
            bogus[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
            tracker_sock.send_to(&bogus, from).await.unwrap();

            // Then the real one.
            let txn_id = buf[12..16].to_vec();
            let mut resp = [0u8; 16];
            resp[0..4].copy_from_slice(&0u32.to_be_bytes());
            resp[4..8].copy_from_slice(&txn_id);
            resp[8..16].copy_from_slice(&42u64.to_be_bytes());
            tracker_sock.send_to(&resp, from).await.unwrap();

            let (n, from) = tracker_sock.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 98);
            let txn_id = buf[12..16].to_vec();
            let mut resp = Vec::new();
            resp.extend_from_slice(&1u32.to_be_bytes());
            resp.extend_from_slice(&txn_id);
            resp.extend_from_slice(&1800u32.to_be_bytes());
            resp.extend_from_slice(&0u32.to_be_bytes());
            resp.extend_from_slice(&0u32.to_be_bytes());
            tracker_sock.send_to(&resp, from).await.unwrap();
        });

        let resp = announce(tracker_addr, &test_request(), 0).await.unwrap();
        assert_eq!(resp.interval, 1800);
        server.await.unwrap();
    }
}
