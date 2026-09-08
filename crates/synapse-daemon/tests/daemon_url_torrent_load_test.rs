use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use diskio::DiskEngine;
use reqwest::StatusCode;
use std::sync::Arc;
use synapse_engine::SwarmEngine;
use tempfile::tempdir;

/// Generates a valid minimal .torrent bencoded file payload for testing.
fn create_test_torrent_bytes(name: &str, length: usize) -> Vec<u8> {
    let pieces_hash = vec![0x42u8; 20]; // 1 piece of 20 bytes SHA-1
    let torrent_dict = synapse_bencode::BEncode::Dict(std::collections::BTreeMap::from([
        (
            b"info".to_vec(),
            synapse_bencode::BEncode::Dict(std::collections::BTreeMap::from([
                (b"name".to_vec(), synapse_bencode::BEncode::String(name.as_bytes().to_vec())),
                (b"piece length".to_vec(), synapse_bencode::BEncode::Int(262144)),
                (b"pieces".to_vec(), synapse_bencode::BEncode::String(pieces_hash)),
                (b"length".to_vec(), synapse_bencode::BEncode::Int(length as i64)),
            ])),
        ),
        (
            b"announce".to_vec(),
            synapse_bencode::BEncode::String(b"http://tracker.example.com:80/announce".to_vec()),
        ),
    ]));
    let mut buf = Vec::new();
    torrent_dict.encode(&mut buf).unwrap();
    buf
}

#[tokio::test]
async fn test_daemon_secure_url_torrent_ingestion_and_injection_defense() {
    // 1. Stand up a local mock HTTP server hosting test .torrent files
    let mock_torrent_payload = create_test_torrent_bytes("Debian-12.torrent", 5242880);
    let mock_payload_clone = mock_torrent_payload.clone();

    let mock_app = Router::new()
        .route(
            "/debian.torrent",
            get(move || {
                let p = mock_payload_clone.clone();
                async move { ([(axum::http::header::CONTENT_TYPE, "application/x-bittorrent")], p).into_response() }
            }),
        )
        .route(
            "/not-a-torrent.torrent",
            get(|| async { "This is plain text, not bencode torrent" }),
        );

    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(mock_listener, mock_app).await.unwrap();
    });

    // 2. Start Synapse Daemon Engine and REST Control Plane
    let tmp = tempdir().unwrap();
    let disk = Arc::new(DiskEngine::auto().await);
    let swarm = Arc::new(SwarmEngine::new(disk, [0xEE; 20]));

    let daemon_app = synapse_rpc::create_http_router_with_auth(swarm.clone(), None);
    let daemon_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let daemon_addr = daemon_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(daemon_listener, daemon_app).await.unwrap();
    });

    let client = reqwest::Client::new();
    let api_url = format!("http://{}/api/v1/torrents", daemon_addr);

    // =========================================================================
    // 3. Valid Torrent Load 1: Pass HTTP URL pointing to remote .torrent file
    // =========================================================================
    let remote_url = format!("http://{}/debian.torrent", mock_addr);
    let res = client
        .post(&api_url)
        .json(&serde_json::json!({
            "url": remote_url,
            "download_dir": tmp.path().to_string_lossy().to_string(),
        }))
        .send()
        .await
        .expect("send add torrent request");

    assert_eq!(res.status(), StatusCode::OK);
    let json: serde_json::Value = res.json().await.unwrap();
    assert_eq!(json["success"], true);
    assert!(json["message"].as_str().unwrap().contains("Torrent added successfully"));

    // Verify torrent is active in SwarmEngine
    let torrents = swarm.list_torrents();
    assert_eq!(torrents.len(), 1);
    assert_eq!(torrents[0].name, "Debian-12.torrent");
    assert_eq!(torrents[0].total_size, 5242880);

    // =========================================================================
    // 4. Valid Torrent Load 2: Pass Magnet URI
    // =========================================================================
    let magnet = "magnet:?xt=urn:btih:3333444455556666777788889999000011112222&dn=Ubuntu-24.04-LTS&xl=2147483648";
    let res = client
        .post(&api_url)
        .json(&serde_json::json!({
            "url": magnet,
            "download_dir": tmp.path().to_string_lossy().to_string(),
        }))
        .send()
        .await
        .expect("send add magnet request");

    assert_eq!(res.status(), StatusCode::OK);
    let json: serde_json::Value = res.json().await.unwrap();
    assert_eq!(json["success"], true);

    let torrents = swarm.list_torrents();
    assert_eq!(torrents.len(), 2);

    // =========================================================================
    // 5. Valid Torrent Load 3: Pass Base64 Encoded .torrent payload
    // =========================================================================
    let fedora_bytes = create_test_torrent_bytes("Fedora-40.torrent", 1048576);
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&fedora_bytes);

    let res = client
        .post(&api_url)
        .json(&serde_json::json!({
            "torrent_base64": b64,
            "download_dir": tmp.path().to_string_lossy().to_string(),
        }))
        .send()
        .await
        .expect("send base64 torrent request");

    assert_eq!(res.status(), StatusCode::OK);
    let torrents = swarm.list_torrents();
    assert_eq!(torrents.len(), 3);

    // =========================================================================
    // 6. Security Defense: Reject Insecure URI Scheme (file://, ftp://, javascript:)
    // =========================================================================
    let res = client
        .post(&api_url)
        .json(&serde_json::json!({ "url": "file:///etc/passwd" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let res = client
        .post(&api_url)
        .json(&serde_json::json!({ "url": "ftp://ftp.example.com/payload.torrent" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let res = client
        .post(&api_url)
        .json(&serde_json::json!({ "url": "javascript:alert(document.cookie)" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // =========================================================================
    // 7. Security Defense: Reject Null-Byte and CRLF Injection Attacks
    // =========================================================================
    let res = client
        .post(&api_url)
        .json(&serde_json::json!({ "url": format!("http://{}/debian.torrent\0evil", mock_addr) }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let res = client
        .post(&api_url)
        .json(&serde_json::json!({ "url": format!("http://{}/debian.torrent\r\nHost: evil.com", mock_addr) }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // =========================================================================
    // 8. Security Defense: Reject Malformed / Non-Torrent Payloads
    // =========================================================================
    let res = client
        .post(&api_url)
        .json(&serde_json::json!({ "url": format!("http://{}/not-a-torrent.torrent", mock_addr) }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Ensure no corrupted swarms were added to the engine
    assert_eq!(swarm.list_torrents().len(), 3);
}
