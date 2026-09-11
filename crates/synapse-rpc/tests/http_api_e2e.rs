use std::sync::Arc;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use synapse_engine::SwarmEngine;
use synapse_rpc::create_http_router;
use tower::ServiceExt;

#[tokio::test]
async fn test_rest_api_full_crud_and_metrics_lifecycle() {
    let disk = Arc::new(diskio::DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
    let app = create_http_router(engine.clone());

    // 1. Health check
    let req = Request::builder()
        .uri("/api/v1/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Add Magnet Torrent
    let magnet_req = Request::builder()
        .method("POST")
        .uri("/api/v1/torrents")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"magnet": "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=Ubuntu+ISO"}"#,
        ))
        .unwrap();
    let resp = app.clone().oneshot(magnet_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. List Torrents
    let list_req = Request::builder()
        .uri("/api/v1/torrents")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(list_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["torrents"].as_array().unwrap().len(), 1);
    assert_eq!(
        val["torrents"][0]["info_hash"],
        "0123456789abcdef0123456789abcdef01234567"
    );

    // 4. Pause Torrent
    let pause_req = Request::builder()
        .method("POST")
        .uri("/api/v1/torrents/0123456789abcdef0123456789abcdef01234567/pause")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(pause_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. Inspect Torrent
    let inspect_req = Request::builder()
        .uri("/api/v1/torrents/0123456789abcdef0123456789abcdef01234567")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(inspect_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["tier"], "Cold");

    // 6. Resume Torrent
    let resume_req = Request::builder()
        .method("POST")
        .uri("/api/v1/torrents/0123456789abcdef0123456789abcdef01234567/resume")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(resume_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 7. Verify Prometheus Metrics
    let metrics_req = Request::builder()
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(metrics_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("synapse_torrents_total{state=\"total\"} 1"));

    // 8. Delete Torrent
    let delete_req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/torrents/0123456789abcdef0123456789abcdef01234567")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(delete_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify list is now empty
    let list_req2 = Request::builder()
        .uri("/api/v1/torrents")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(list_req2).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["torrents"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_web_interface_enabled_and_disabled_modes() {
    let disk = Arc::new(diskio::DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));

    // 1. Test with Web UI ENABLED
    let web_cfg = synapse_config::WebConfig {
        enabled: true,
        ..Default::default()
    };
    let app_enabled = synapse_rpc::create_http_router_all(engine.clone(), None, true, web_cfg);

    // Root /
    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let resp = app_enabled.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 100_000).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("Synapse 2.0 Web Client"));
    assert!(html.contains("Turtle Mode"));

    // Style CSS
    let req_css = Request::builder().uri("/style.css").body(Body::empty()).unwrap();
    let resp_css = app_enabled.clone().oneshot(req_css).await.unwrap();
    assert_eq!(resp_css.status(), StatusCode::OK);
    assert_eq!(resp_css.headers().get("content-type").unwrap(), "text/css; charset=utf-8");

    // App JS
    let req_js = Request::builder().uri("/app.js").body(Body::empty()).unwrap();
    let resp_js = app_enabled.clone().oneshot(req_js).await.unwrap();
    assert_eq!(resp_js.status(), StatusCode::OK);
    assert_eq!(resp_js.headers().get("content-type").unwrap(), "application/javascript; charset=utf-8");

    // Favicon
    let req_fav = Request::builder().uri("/favicon.ico").body(Body::empty()).unwrap();
    let resp_fav = app_enabled.clone().oneshot(req_fav).await.unwrap();
    assert_eq!(resp_fav.status(), StatusCode::OK);

    // 2. Test with Web UI DISABLED
    let web_cfg_disabled = synapse_config::WebConfig {
        enabled: false,
        ..Default::default()
    };
    let app_disabled = synapse_rpc::create_http_router_all(engine.clone(), None, true, web_cfg_disabled);

    let req_root_disabled = Request::builder().uri("/").body(Body::empty()).unwrap();
    let resp_root_disabled = app_disabled.clone().oneshot(req_root_disabled).await.unwrap();
    assert_eq!(resp_root_disabled.status(), StatusCode::NOT_FOUND);

    let req_js_disabled = Request::builder().uri("/app.js").body(Body::empty()).unwrap();
    let resp_js_disabled = app_disabled.clone().oneshot(req_js_disabled).await.unwrap();
    assert_eq!(resp_js_disabled.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_rest_api_detail_upload_and_settings_patch() {
    let disk = Arc::new(diskio::DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
    let app = synapse_rpc::create_http_router(engine.clone());

    // 1. Add Magnet Torrent
    let magnet_req = Request::builder()
        .method("POST")
        .uri("/api/v1/torrents")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"magnet": "magnet:?xt=urn:btih:aabbccddeeff00112233aabbccddeeff00112233&dn=Debian+Netinst"}"#,
        ))
        .unwrap();
    let resp = app.clone().oneshot(magnet_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Query Detail endpoint
    let detail_req = Request::builder()
        .uri("/api/v1/torrents/aabbccddeeff00112233aabbccddeeff00112233/detail")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(detail_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 50_000).await.unwrap();
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["name"], "Debian Netinst");
    assert_eq!(val["info_hash"], "aabbccddeeff00112233aabbccddeeff00112233");
    assert!(val.get("piece_bitfield").is_some());
    assert!(val.get("files").is_some());
    assert!(val.get("trackers").is_some());
    assert!(val.get("active_peers").is_some());
    assert!(val.get("candidate_peers").is_some());
    assert!(val.get("active_dials").is_some());
    assert!(val.get("discovery").is_some());
    let disc = &val["discovery"];
    assert_eq!(disc["dht_allowed"], true);
    assert_eq!(disc["pex_allowed"], true);
    assert_eq!(disc["lsd_allowed"], true);
    assert_eq!(disc["is_private"], false);

    // Verify Session Stats exposes DHT nodes and discovery subsystem states
    let session_stats_req = Request::builder()
        .uri("/api/v1/session/stats")
        .body(Body::empty())
        .unwrap();
    let resp_stats = app.clone().oneshot(session_stats_req).await.unwrap();
    assert_eq!(resp_stats.status(), StatusCode::OK);
    let stats_body = axum::body::to_bytes(resp_stats.into_body(), 10_000).await.unwrap();
    let stats_json: serde_json::Value = serde_json::from_slice(&stats_body).unwrap();
    assert!(stats_json.get("dht_nodes").is_some());
    assert_eq!(stats_json["dht_enabled"], true);
    assert_eq!(stats_json["pex_enabled"], true);
    assert_eq!(stats_json["lsd_enabled"], true);

    // 3. Test In-flight Session Settings PATCH
    let patch_req = Request::builder()
        .method("PATCH")
        .uri("/api/v1/session")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{
                "download_limit_enabled": true,
                "download_limit_bytes": 10485760,
                "alt_speed_enabled": true
            }"#,
        ))
        .unwrap();
    let resp = app.clone().oneshot(patch_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify settings updated
    let get_settings_req = Request::builder()
        .uri("/api/v1/session")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(get_settings_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 10_000).await.unwrap();
    let s: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(s["download_limit_enabled"], true);
    assert_eq!(s["download_limit_bytes"], 10485760);
    assert_eq!(s["alt_speed_enabled"], true);

    // 4. Delete with delete_data query parameter
    let del_req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/torrents/aabbccddeeff00112233aabbccddeeff00112233?delete_data=true")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(del_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_http_api_and_web_token_authentication() {
    let disk = Arc::new(diskio::DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
    let web_cfg = synapse_config::WebConfig {
        enabled: true,
        ..Default::default()
    };
    let app = synapse_rpc::create_http_router_all(
        engine.clone(),
        Some("super-secret-token".to_string()),
        true,
        web_cfg,
    );

    // 1. Health check is public
    let health_req = Request::builder().uri("/api/v1/health").body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(health_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Web UI static assets are public (so client can load and prompt for token)
    let root_req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(root_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 100_000).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("Security"));
    assert!(html.contains("cfg-auth-token"));

    let js_req = Request::builder().uri("/app.js").body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(js_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 100_000).await.unwrap();
    let js = String::from_utf8_lossy(&body);
    assert!(js.contains("synapse_auth_token"));

    // 3. Protected API route without token returns 401
    let unauth_req = Request::builder().uri("/api/v1/session").body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(unauth_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 4. Protected API route with invalid token returns 401
    let bad_auth_req = Request::builder()
        .uri("/api/v1/torrents")
        .header("Authorization", "Bearer wrong-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(bad_auth_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 5. Protected API route with correct Bearer token returns 200
    let auth_req = Request::builder()
        .uri("/api/v1/session")
        .header("Authorization", "Bearer super-secret-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(auth_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

fn build_test_torrent(name: &str) -> synapse_meta::Info {
    let piece_len = 16384u32;
    let file_len = 32768usize;
    let pieces = vec![0x33u8; 40]; // 2 pieces * 20 bytes
    let mut info_dict = std::collections::BTreeMap::new();
    info_dict.insert(b"name".to_vec(), synapse_bencode::BEncode::String(name.as_bytes().to_vec()));
    info_dict.insert(b"piece length".to_vec(), synapse_bencode::BEncode::Int(piece_len as i64));
    info_dict.insert(b"pieces".to_vec(), synapse_bencode::BEncode::String(pieces));
    info_dict.insert(b"length".to_vec(), synapse_bencode::BEncode::Int(file_len as i64));
    let mut torrent_dict = std::collections::BTreeMap::new();
    torrent_dict.insert(b"info".to_vec(), synapse_bencode::BEncode::Dict(info_dict));
    synapse_meta::Info::from_bencode(synapse_bencode::BEncode::Dict(torrent_dict)).unwrap()
}

#[tokio::test]
async fn test_file_priority_and_default_download_dir() {
    let disk = Arc::new(diskio::DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
    engine.settings().write().download_dir = std::path::PathBuf::from("/custom/download/path");
    let app = synapse_rpc::create_http_router(engine.clone());

    let test_info = Arc::new(build_test_torrent("MultiFileTest"));
    let hash_hex = hex::encode(test_info.hash);
    engine.add_torrent(test_info, std::path::PathBuf::from("/custom/download/path"), None);

    // 1. Verify initial file priority is 4 (Normal)
    let detail_req = Request::builder()
        .uri(format!("/api/v1/torrents/{hash_hex}/detail"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(detail_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 50_000).await.unwrap();
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["files"][0]["priority"], 4);

    // 2. Update file priority to 7 (High)
    let prio_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/torrents/{hash_hex}/files/0/priority"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"priority": 7}"#))
        .unwrap();
    let prio_resp = app.clone().oneshot(prio_req).await.unwrap();
    assert_eq!(prio_resp.status(), StatusCode::OK);

    // 3. Verify file priority updated in detail response
    let detail_req2 = Request::builder()
        .uri(format!("/api/v1/torrents/{hash_hex}/detail"))
        .body(Body::empty())
        .unwrap();
    let resp2 = app.clone().oneshot(detail_req2).await.unwrap();
    let body2 = axum::body::to_bytes(resp2.into_body(), 50_000).await.unwrap();
    let val2: serde_json::Value = serde_json::from_slice(&body2).unwrap();
    assert_eq!(val2["files"][0]["priority"], 7);
}


