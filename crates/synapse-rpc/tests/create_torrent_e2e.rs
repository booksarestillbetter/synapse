//! `POST /api/v1/torrents/create` makes torrents from content in the download directory only.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use synapse_engine::SwarmEngine;
use tower::ServiceExt;

async fn post(
    app: &axum::Router,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn torrents_are_created_from_download_dir_content_and_can_be_added_back() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret.txt"), b"not for you").unwrap();
    let content = dir.path().join("release");
    std::fs::create_dir_all(content.join("sub")).unwrap();
    std::fs::write(content.join("a.bin"), vec![7u8; 50_000]).unwrap();
    std::fs::write(content.join("sub/b.bin"), vec![9u8; 20_000]).unwrap();

    let disk = Arc::new(diskio::DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
    let mut settings = engine.settings().read().clone();
    settings.download_dir = dir.path().to_path_buf();
    engine.update_settings(settings);
    let app = synapse_rpc::create_http_router(engine.clone());

    let (status, body) = post(
        &app,
        "/api/v1/torrents/create",
        serde_json::json!({
            "path": "release", "trackers": ["http://t.example/announce"], "comment": "hi",
            "piece_size_kib": 32, "version": "hybrid"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], "release");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(body["torrent_base64"].as_str().unwrap())
        .unwrap();
    let info = synapse_meta::Info::from_torrent_bytes(&bytes).unwrap();
    assert!(info.is_hybrid());
    assert_eq!(hex::encode(info.hash), body["info_hash"].as_str().unwrap());

    // The result is accepted by the add endpoint.
    let (status, _) = post(
        &app,
        "/api/v1/torrents",
        serde_json::json!({ "torrent_base64": body["torrent_base64"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(engine.has_torrent(&info.hash));

    // Outside the download directory, by absolute path or by climbing out of it: refused.
    let outside_file = outside.path().join("secret.txt");
    for path in [
        outside_file.to_string_lossy().into_owned(),
        "../".to_string() + &outside.path().file_name().unwrap().to_string_lossy() + "/secret.txt",
        "..".to_string(),
    ] {
        let (status, body) = post(
            &app,
            "/api/v1/torrents/create",
            serde_json::json!({ "path": path }),
        )
        .await;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
            "{path}: {status} {body}"
        );
    }
    // Bad version and missing path.
    let (status, _) = post(
        &app,
        "/api/v1/torrents/create",
        serde_json::json!({ "path": "release", "version": "v3" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(
        &app,
        "/api/v1/torrents/create",
        serde_json::json!({ "path": "nothing-here" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
