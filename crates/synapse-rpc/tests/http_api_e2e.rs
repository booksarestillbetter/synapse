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
