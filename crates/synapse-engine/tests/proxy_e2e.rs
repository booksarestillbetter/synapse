//! A configured SOCKS5 proxy carries the peer connections we open, and HTTP requests (with host
//! names left to the proxy) go through the proxy too. The proxy is process-wide, so this is a
//! single test that runs both checks in turn.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use diskio::DiskEngine;
use synapse_engine::proxy::{self, ProxyKind, ProxySettings};
use synapse_engine::{
    PeerEvent, SwarmState, SwarmStats, SwarmTier, TokenBucket, Torrent, TorrentConfig,
};
use synapse_meta::create::{create_torrent, CreateOptions};
use synapse_meta::Info;
use synapse_picker::{Bitfield, Mode, RoaringBitfield};

fn stats(info: &Info, dir: &Path) -> Arc<parking_lot::RwLock<SwarmStats>> {
    Arc::new(parking_lot::RwLock::new(SwarmStats {
        info_hash: info.hash,
        name: info.name.clone(),
        total_size: info.total_len,
        progress: 0.0,
        state: SwarmState::Downloading,
        tier: SwarmTier::Hot,
        download_rate: 0,
        upload_rate: 0,
        downloaded_bytes: 0,
        uploaded_bytes: 0,
        peers_connected: 0,
        peers_sending: 0,
        eta_seconds: 0,
        ratio: 0.0,
        download_dir: dir.to_string_lossy().to_string(),
        added_at: 0,
        is_private: false,
        is_stalled: false,
        last_transfer_at: 0,
        piece_count: info.pieces(),
        piece_size: info.piece_len,
    }))
}

fn config(
    info: &Arc<Info>,
    dir: &Path,
    peer_id: u8,
    disk: Arc<DiskEngine>,
    have: Option<&Bitfield>,
) -> TorrentConfig {
    TorrentConfig {
        info: info.clone(),
        download_dir: dir.to_path_buf(),
        peer_id: [peer_id; 20],
        disk,
        mode: Mode::RarestFirst,
        max_pipeline: 8,
        regular_unchokes: 4,
        optimistic_unchoke_interval: Duration::from_secs(600),
        tick_interval: Duration::from_millis(50),
        on_torrent_completed: None,
        on_piece_completed: None,
        stats: stats(info, dir),
        bitfield: Arc::new(parking_lot::RwLock::new(
            have.map(RoaringBitfield::from_bitfield),
        )),
        download_bucket: Arc::new(TokenBucket::unthrottled()),
        upload_bucket: Arc::new(TokenBucket::unthrottled()),
        global_metrics: None,
        idle_timeout: None,
        live_peers: Arc::new(parking_lot::RwLock::new(Vec::new())),
        piece_availability: Arc::new(parking_lot::RwLock::new(vec![0; info.pieces() as usize])),
        settings: Arc::new(parking_lot::RwLock::new(Default::default())),
        on_peers_discovered: None,
        on_metadata_resolved: None,
        ban_list: Default::default(),
        ip_filter: Default::default(),
        super_seeding: false,
        local_webseed_resolver: None,
        alert_sender: None,
    }
}

/// A minimal SOCKS5 proxy (no authentication) that relays to whatever address it is asked for and
/// counts how many tunnels it opened.
async fn socks5_relay() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let tunnels = Arc::new(AtomicUsize::new(0));
    let count = tunnels.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            let count = count.clone();
            tokio::spawn(async move {
                let mut hello = [0u8; 2];
                client.read_exact(&mut hello).await.unwrap();
                let mut methods = vec![0u8; hello[1] as usize];
                client.read_exact(&mut methods).await.unwrap();
                client.write_all(&[5, 0]).await.unwrap();
                let mut req = [0u8; 10];
                client.read_exact(&mut req).await.unwrap();
                assert_eq!(&req[..4], &[5, 1, 0, 1], "peers are dialled by address");
                let target = std::net::SocketAddr::from((
                    [req[4], req[5], req[6], req[7]],
                    u16::from_be_bytes([req[8], req[9]]),
                ));
                let Ok(mut upstream) = TcpStream::connect(target).await else {
                    let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                    return;
                };
                client
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    (port, tunnels)
}

/// An HTTP proxy that answers any request with a fixed body and records the request line.
async fn http_proxy() -> (u16, Arc<parking_lot::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut c, _)) = listener.accept().await else {
                return;
            };
            let log = log.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = c.read(&mut buf).await.unwrap_or(0);
                log.lock().push(
                    String::from_utf8_lossy(&buf[..n])
                        .lines()
                        .next()
                        .unwrap_or("")
                        .to_string(),
                );
                let body = "via-proxy";
                let _ = c
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                            .as_bytes(),
                    )
                    .await;
            });
        }
    });
    (port, seen)
}

fn settings(kind: ProxyKind, port: u16) -> ProxySettings {
    ProxySettings {
        kind,
        host: "127.0.0.1".into(),
        port,
        auth: None,
        proxy_peer_connections: true,
        proxy_http: true,
        proxy_hostnames: true,
        force_proxy: false,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn peers_and_http_requests_go_through_the_proxy() {
    // --- Peer connections through SOCKS5 -------------------------------------------------
    let data: Vec<u8> = (0..100_000u32).map(|i| (i * 13 % 251) as u8).collect();
    let seeder_dir = tempfile::tempdir().unwrap();
    let leecher_dir = tempfile::tempdir().unwrap();
    let file = seeder_dir.path().join("p.bin");
    std::fs::write(&file, &data).unwrap();
    let torrent = create_torrent(&file, &CreateOptions::default(), |_, _| {}).unwrap();
    let info = Arc::new(Info::from_torrent_bytes(&torrent).unwrap());

    let (socks_port, tunnels) = socks5_relay().await;
    proxy::set_global(Some(settings(ProxyKind::Socks5, socks_port)));
    assert!(proxy::peers_use_proxy());

    let mut have = Bitfield::new(info.pieces() as usize);
    for i in 0..info.pieces() {
        have.set(i as usize);
    }
    let disk = Arc::new(DiskEngine::auto().await);
    let (seeder_tx, seeder_rx) = mpsc::channel::<PeerEvent>(64);
    let (_c1, seeder_cmd) = mpsc::channel(1);
    let seeder = Torrent::new(
        config(&info, seeder_dir.path(), 1, disk.clone(), Some(&have)),
        Some(&have),
    );
    tokio::spawn(seeder.run(seeder_rx, seeder_cmd));
    let (leecher_tx, leecher_rx) = mpsc::channel::<PeerEvent>(64);
    let (_c2, leecher_cmd) = mpsc::channel(1);
    let mut leecher = Torrent::new(config(&info, leecher_dir.path(), 2, disk, None), None);
    let (done_tx, done_rx) = oneshot::channel();
    leecher.notify_on_complete(done_tx);
    tokio::spawn(leecher.run(leecher_rx, leecher_cmd));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hash = info.hash;
    tokio::spawn(async move {
        let (s, a) = listener.accept().await.unwrap();
        synapse_engine::accept(s, a, [1u8; 20], hash, false, seeder_tx)
            .await
            .unwrap();
    });
    synapse_engine::connect(addr, [2u8; 20], hash, false, leecher_tx)
        .await
        .expect("the connection through the proxy failed");
    tokio::time::timeout(Duration::from_secs(20), done_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        std::fs::read(leecher_dir.path().join("p.bin")).unwrap(),
        data
    );
    assert!(
        tunnels.load(Ordering::SeqCst) >= 1,
        "the peer connection did not use the proxy"
    );

    // A proxy that is down means the peer is unreachable, never a silent direct connection.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    proxy::set_global(Some(settings(ProxyKind::Socks5, dead_port)));
    let (tx, _rx) = mpsc::channel::<PeerEvent>(4);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reachable = listener.local_addr().unwrap();
    assert!(
        synapse_engine::connect(reachable, [2u8; 20], hash, false, tx)
            .await
            .is_err()
    );

    // --- HTTP requests through an HTTP proxy, host name left to the proxy -----------------
    let (http_port, seen) = http_proxy().await;
    proxy::set_global(Some(settings(ProxyKind::Http, http_port)));
    let url = url::Url::parse("http://tracker.invalid/announce?x=1").unwrap();
    let opts = synapse_tracker::safe_http::FetchOptions {
        timeout: Duration::from_secs(10),
        max_body: 1024,
        user_agent: "test",
        local: synapse_tracker::safe_http::LocalPolicy::Deny,
        range: None,
    };
    let fetched = synapse_tracker::safe_http::fetch(&url, &opts)
        .await
        .expect("fetch through the proxy");
    assert_eq!(fetched.body, b"via-proxy");
    let line = seen.lock().last().cloned().unwrap();
    assert!(
        line.contains("tracker.invalid"),
        "the proxy is told the host name: {line}"
    );
    // Literal local addresses are still refused: the proxy does not open the local network.
    let local = url::Url::parse("http://127.0.0.1:9/announce").unwrap();
    assert!(synapse_tracker::safe_http::fetch(&local, &opts)
        .await
        .is_err());

    proxy::set_global(None);
    assert!(!proxy::peers_use_proxy());
}
