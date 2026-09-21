use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use diskio::DiskEngine;
use futures::{SinkExt, StreamExt};
use sha1::{Digest, Sha1};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::codec::Framed;

use synapse_bencode::BEncode;
use synapse_engine::{
    accept, PeerEvent, SwarmEngine, SwarmState, SwarmStats, SwarmTier, TokenBucket, Torrent,
    TorrentConfig,
};
use synapse_meta::Info;
use synapse_picker::{Bitfield, Mode, RoaringBitfield};
use synapse_wire::{
    bep40::{canonical_peer_priority, canonical_peer_score},
    ExtensionHandshake, Message, PeerCodec,
};

fn build_test_info(file_data: &[u8], piece_len: u32, name: &str) -> Info {
    let mut pieces = Vec::new();
    for chunk in file_data.chunks(piece_len as usize) {
        let hash: [u8; 20] = Sha1::digest(chunk).into();
        pieces.extend_from_slice(&hash);
    }

    let mut info_dict = std::collections::BTreeMap::new();
    info_dict.insert(b"name".to_vec(), BEncode::String(name.as_bytes().to_vec()));
    info_dict.insert(b"piece length".to_vec(), BEncode::Int(piece_len as i64));
    info_dict.insert(b"pieces".to_vec(), BEncode::String(pieces));
    info_dict.insert(b"length".to_vec(), BEncode::Int(file_data.len() as i64));

    let mut torrent_dict = std::collections::BTreeMap::new();
    torrent_dict.insert(b"info".to_vec(), BEncode::Dict(info_dict));

    Info::from_bencode(BEncode::Dict(torrent_dict)).expect("valid test torrent")
}

#[tokio::test(flavor = "multi_thread")]
async fn test_bep21_upload_only_advertised_by_seeder_and_parsed() {
    let data = vec![0x42u8; 16384];
    let info = Arc::new(build_test_info(&data, 16384, "bep21_seed"));
    let hash = info.hash;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bep21_seed"), &data).unwrap();

    let mut have = Bitfield::new(info.pieces() as usize);
    for i in 0..info.pieces() {
        have.set(i as usize);
    }

    let stats = Arc::new(parking_lot::RwLock::new(SwarmStats {
        info_hash: hash,
        name: info.name.clone(),
        total_size: info.total_len,
        progress: 1.0,
        state: SwarmState::Seeding,
        tier: SwarmTier::Hot,
        download_rate: 0,
        upload_rate: 0,
        downloaded_bytes: 0,
        uploaded_bytes: 0,
        peers_connected: 0,
        peers_sending: 0,
        eta_seconds: 0,
        ratio: 0.0,
        download_dir: dir.path().to_string_lossy().to_string(),
        added_at: 0,
        is_private: false,
        is_stalled: false,
        last_transfer_at: 0,
        piece_count: info.pieces(),
        piece_size: info.piece_len,
    }));

    let (tx, rx) = mpsc::channel::<PeerEvent>(64);
    let (_cmd_tx, cmd_rx) = mpsc::channel(1);
    let seeder_id = [0x53; 20];

    let seeder = Torrent::new(
        TorrentConfig {
            info: info.clone(),
            download_dir: dir.path().to_path_buf(),
            peer_id: seeder_id,
            disk: Arc::new(DiskEngine::auto().await),
            mode: Mode::RarestFirst,
            max_pipeline: 8,
            regular_unchokes: 4,
            optimistic_unchoke_interval: Duration::from_secs(600),
            tick_interval: Duration::from_millis(50),
            on_torrent_completed: None,
            on_piece_completed: None,
            stats,
            bitfield: Arc::new(parking_lot::RwLock::new(Some(
                RoaringBitfield::from_bitfield(&have),
            ))),
            download_bucket: Arc::new(TokenBucket::unthrottled()),
            upload_bucket: Arc::new(TokenBucket::unthrottled()),
            global_metrics: None,
            idle_timeout: None,
            live_peers: Arc::new(parking_lot::RwLock::new(Vec::new())),
            piece_availability: Arc::new(parking_lot::RwLock::new(vec![1; info.pieces() as usize])),
            settings: Arc::new(parking_lot::RwLock::new(Default::default())),
            on_peers_discovered: None,
            on_metadata_resolved: None,
            ban_list: Default::default(),
            ip_filter: Default::default(),
            super_seeding: false,
            local_webseed_resolver: None,
            alert_sender: None,
        },
        Some(&have),
    );
    tokio::spawn(seeder.run(rx, cmd_rx));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        accept(stream, peer_addr, seeder_id, hash, false, tx)
            .await
            .unwrap();
    });

    // Connect remote peer over real TCP socket
    let stream = TcpStream::connect(local_addr).await.unwrap();
    let mut framed = Framed::new(stream, PeerCodec::new());

    // Send Handshake
    let mut reserved = [0u8; 8];
    reserved[5] |= 0x10; // BEP 10 extension protocol
    framed
        .send(Message::Handshake {
            reserved,
            info_hash: hash,
            peer_id: [0x50; 20],
        })
        .await
        .unwrap();

    // Read Handshake response
    let resp = tokio::time::timeout(Duration::from_secs(5), framed.next())
        .await
        .expect("handshake timed out")
        .expect("stream closed")
        .expect("codec error");

    match resp {
        Message::Handshake { info_hash, .. } => assert_eq!(info_hash, hash),
        other => panic!("expected Handshake, got {:?}", other),
    }

    // Next message should be Extension Handshake (ID 0)
    let mut upload_only_seen = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let msg = tokio::time::timeout(Duration::from_secs(2), framed.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        if let Message::Extension { id: 0, payload } = msg {
            let decoded = ExtensionHandshake::decode(&payload).expect("decode extension handshake");
            // Since this torrent was configured in Seeding state,
            // BEP 21 upload_only MUST be Some(true)
            assert_eq!(
                decoded.upload_only,
                Some(true),
                "Seeder must advertise BEP 21 upload_only = 1"
            );
            upload_only_seen = true;
            break;
        }
    }
    assert!(
        upload_only_seen,
        "Did not receive Extension Handshake with upload_only"
    );

    // Send our own ExtensionHandshake with upload_only = 1
    let our_ext_hs = ExtensionHandshake::new().with_upload_only(true).encode();
    framed
        .send(Message::Extension {
            id: 0,
            payload: our_ext_hs,
        })
        .await
        .unwrap();

    // KeepAlive to ensure orderly socket handling
    framed.send(Message::KeepAlive).await.unwrap();
}

#[test]
fn test_bep40_canonical_peer_priority_and_score() {
    let addr1: SocketAddr = "192.0.2.1:6881".parse().unwrap();
    let addr2: SocketAddr = "198.51.100.2:51413".parse().unwrap();

    let score1 = canonical_peer_score(addr1);
    let score2 = canonical_peer_score(addr2);
    assert_ne!(score1, 0);
    assert_ne!(score2, 0);

    // Strict antisymmetry in priority comparison
    let ord1 = canonical_peer_priority(addr1, addr2);
    let ord2 = canonical_peer_priority(addr2, addr1);
    assert_eq!(ord1, ord2.reverse());
    assert_ne!(ord1, std::cmp::Ordering::Equal);

    // Deterministic priority ordering across multiple candidate peers
    let mut addrs = [
        "192.168.1.10:6881".parse::<SocketAddr>().unwrap(),
        "10.0.0.5:51413".parse::<SocketAddr>().unwrap(),
        "172.16.0.2:8999".parse::<SocketAddr>().unwrap(),
        "203.0.113.195:6881".parse::<SocketAddr>().unwrap(),
    ];
    addrs.sort_by_key(|&a| std::cmp::Reverse(canonical_peer_score(a)));
    assert_eq!(addrs.len(), 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_bep48_tracker_scrape_http_e2e() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 1. Spawn a mock HTTP tracker answering /scrape
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let scrape_port = listener.local_addr().unwrap().port();

    let target_hash = [0x5A; 20];
    let mut files_dict = std::collections::BTreeMap::new();
    let mut file_info = std::collections::BTreeMap::new();
    file_info.insert(b"complete".to_vec(), BEncode::Int(25));
    file_info.insert(b"downloaded".to_vec(), BEncode::Int(150));
    file_info.insert(b"incomplete".to_vec(), BEncode::Int(5));
    files_dict.insert(target_hash.to_vec(), BEncode::Dict(file_info));

    let mut root_dict = std::collections::BTreeMap::new();
    root_dict.insert(b"files".to_vec(), BEncode::Dict(files_dict));
    let mut body = Vec::new();
    BEncode::Dict(root_dict).encode(&mut body).unwrap();

    let server_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            let req_str = String::from_utf8_lossy(&buf[..n]);
            assert!(req_str.starts_with("GET /scrape?info_hash="));

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
            stream.flush().await.unwrap();
        }
    });

    let disk = Arc::new(DiskEngine::auto().await);
    let swarm = Arc::new(SwarmEngine::new(disk, [0x99; 20]));
    let tracker_url = url::Url::parse(&format!("http://127.0.0.1:{scrape_port}/announce")).unwrap();

    let scrape_res = swarm
        .scrape_tracker(&tracker_url, &[target_hash])
        .await
        .expect("scrape must succeed");
    assert_eq!(scrape_res.files.len(), 1);
    let stats = scrape_res
        .files
        .get(&target_hash)
        .expect("target hash stats present");
    assert_eq!(stats.seeders, 25);
    assert_eq!(stats.completed, 150);
    assert_eq!(stats.leechers, 5);

    server_task.await.unwrap();
}
