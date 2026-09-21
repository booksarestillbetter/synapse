//! End-to-end proof that BEP 19 webseed fetching actually pulls a piece over HTTP and
//! lands it on disk: a `Torrent` actor with zero connected peers and a single-file
//! `url-list` entry pointing at a minimal local HTTP server that answers one ranged
//! GET with the whole file.

use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use diskio::DiskEngine;
use synapse_engine::{
    PeerEvent, SwarmState, SwarmStats, SwarmTier, TokenBucket, Torrent, TorrentConfig,
};
use synapse_meta::Info;
use synapse_picker::Mode;

fn fresh_stats(
    info: &Info,
    download_dir: &std::path::Path,
) -> Arc<parking_lot::RwLock<SwarmStats>> {
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
        download_dir: download_dir.to_string_lossy().to_string(),
        added_at: 0,
        is_private: info.private,
        is_stalled: false,
        last_transfer_at: 0,
        piece_count: info.pieces(),
        piece_size: info.piece_len,
    }))
}

fn build_single_file_info_with_webseed(
    file_data: &[u8],
    piece_len: u32,
    name: &str,
    webseed_url: &str,
) -> Info {
    let mut pieces = Vec::new();
    for chunk in file_data.chunks(piece_len as usize) {
        let hash: [u8; 20] = Sha1::digest(chunk).into();
        pieces.extend_from_slice(&hash);
    }

    let mut info_dict = std::collections::BTreeMap::new();
    info_dict.insert(
        b"name".to_vec(),
        synapse_bencode::BEncode::String(name.as_bytes().to_vec()),
    );
    info_dict.insert(
        b"piece length".to_vec(),
        synapse_bencode::BEncode::Int(piece_len as i64),
    );
    info_dict.insert(b"pieces".to_vec(), synapse_bencode::BEncode::String(pieces));
    info_dict.insert(
        b"length".to_vec(),
        synapse_bencode::BEncode::Int(file_data.len() as i64),
    );

    let mut torrent_dict = std::collections::BTreeMap::new();
    torrent_dict.insert(b"info".to_vec(), synapse_bencode::BEncode::Dict(info_dict));
    torrent_dict.insert(
        b"url-list".to_vec(),
        synapse_bencode::BEncode::List(vec![synapse_bencode::BEncode::String(
            webseed_url.as_bytes().to_vec(),
        )]),
    );

    Info::from_bencode(synapse_bencode::BEncode::Dict(torrent_dict)).expect("valid test torrent")
}

/// A minimal single-request HTTP/1.1 server: accepts one connection, ignores the
/// request beyond finding the blank line that ends the headers, and always responds
/// with the full `body` as a 206 Partial Content (real webseed clients request the
/// exact byte range, but a test server serving one small file can just return it all).
async fn serve_one_http_request(listener: TcpListener, body: Vec<u8>) {
    if let Ok((mut stream, _)) = listener.accept().await {
        let mut buf = [0u8; 4096];
        let mut received = Vec::new();
        loop {
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
            if received.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        let response = format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-{}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len() - 1,
            body.len(),
            body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(&body).await;
        let _ = stream.shutdown().await;
    }
}

/// Runs a peerless torrent against a loopback web seed. Returns the receiver that fires on
/// completion, plus the download dir and payload for assertions.
async fn run_webseed_torrent(
    allow_local_web_seeds: bool,
) -> (
    oneshot::Receiver<()>,
    tempfile::TempDir,
    Vec<u8>,
    mpsc::Sender<PeerEvent>,
) {
    let file_data = b"webseed round-trip test payload, byte-for-byte".to_vec();
    let piece_len = file_data.len() as u32; // single piece

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let webseed_url = format!("http://{addr}/testfile.bin");

    let info = Arc::new(build_single_file_info_with_webseed(
        &file_data,
        piece_len,
        "testfile.bin",
        &webseed_url,
    ));

    tokio::spawn(serve_one_http_request(listener, file_data.clone()));

    let download_dir = tempfile::tempdir().unwrap();
    let disk = Arc::new(DiskEngine::auto().await);

    let (peer_tx, peer_rx) = mpsc::channel::<PeerEvent>(1);
    let (_cmd_tx, cmd_rx) = mpsc::channel(1);

    let mut torrent = Torrent::new(
        TorrentConfig {
            info: info.clone(),
            download_dir: download_dir.path().to_path_buf(),
            peer_id: [3u8; 20],
            disk,
            mode: Mode::RarestFirst,
            max_pipeline: 8,
            regular_unchokes: 4,
            optimistic_unchoke_interval: Duration::from_secs(600),
            tick_interval: Duration::from_millis(20),
            on_torrent_completed: None,
            on_piece_completed: None,
            stats: fresh_stats(&info, download_dir.path()),
            bitfield: Arc::new(parking_lot::RwLock::new(None)),
            download_bucket: Arc::new(TokenBucket::unthrottled()),
            upload_bucket: Arc::new(TokenBucket::unthrottled()),
            global_metrics: None,
            idle_timeout: None,
            live_peers: Arc::new(parking_lot::RwLock::new(Vec::new())),
            piece_availability: Arc::new(parking_lot::RwLock::new(vec![0; info.pieces() as usize])),
            settings: Arc::new(parking_lot::RwLock::new(
                synapse_engine::settings::DynamicSessionSettings {
                    allow_local_web_seeds,
                    ..Default::default()
                },
            )),
            on_peers_discovered: None,
            on_metadata_resolved: None,
            ban_list: Default::default(),
            ip_filter: Default::default(),
            super_seeding: false,
            local_webseed_resolver: None,
            alert_sender: None,
        },
        None,
    );
    let (done_tx, done_rx) = oneshot::channel();
    torrent.notify_on_complete(done_tx);
    tokio::spawn(torrent.run(peer_rx, cmd_rx));
    (done_rx, download_dir, file_data, peer_tx)
}

#[tokio::test]
async fn torrent_with_no_peers_fetches_its_only_piece_from_a_webseed() {
    // Keep `peer_tx` alive so `events.recv()` doesn't close the actor loop while we wait.
    let (done_rx, download_dir, file_data, _peer_tx) = run_webseed_torrent(true).await;

    tokio::time::timeout(Duration::from_secs(10), done_rx)
        .await
        .expect("torrent did not complete via webseed within timeout")
        .expect("completion channel dropped");

    let on_disk = tokio::fs::read(download_dir.path().join("testfile.bin"))
        .await
        .unwrap();
    assert_eq!(on_disk, file_data, "webseed-fetched file content mismatch");
}

#[tokio::test]
async fn a_loopback_webseed_is_refused_unless_explicitly_allowed() {
    let (done_rx, download_dir, _file_data, _peer_tx) = run_webseed_torrent(false).await;
    let outcome = tokio::time::timeout(Duration::from_secs(2), done_rx).await;
    assert!(
        outcome.is_err(),
        "a torrent must not be able to point the daemon at a local address"
    );
    assert!(!download_dir.path().join("testfile.bin").exists());
}
