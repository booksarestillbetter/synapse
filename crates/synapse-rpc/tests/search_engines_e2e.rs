//! BEP 18: search engines described by `.btsearch` files are queried over HTTP and their RSS
//! results returned through the REST API.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use synapse_engine::SwarmEngine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::ServiceExt;

const RSS: &str = r#"<?xml version="1.0"?>
<rss version="2.0" xmlns:torrent="http://xmlns.ezrss.it/0.1/"><channel>
<item><title>Ubuntu 24.04 ISO</title>
<enclosure url="http://indexer.example/u.torrent" length="1234" type="application/x-bittorrent"/>
<torrent:infoHash>0123456789abcdef0123456789abcdef01234567</torrent:infoHash>
<torrent:seeds>42</torrent:seeds><torrent:peers>7</torrent:peers></item>
</channel></rss>"#;

/// A one-shot-per-connection HTTP server that records the request line and serves `RSS`.
async fn indexer() -> (u16, Arc<parking_lot::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let log = log.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]);
                log.lock()
                    .push(head.lines().next().unwrap_or("").to_string());
                let body = RSS;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/rss+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    (port, seen)
}

async fn json_of(app: &axum::Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn configured_engines_are_queried_and_their_results_returned() {
    let (port, seen) = indexer().await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("example.btsearch");
    std::fs::write(
        &file,
        format!(
            r#"<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">
<ShortName>Example</ShortName><Description>d</Description>
<Url type="application/rss+xml" template="http://127.0.0.1:{port}/rss?q={{searchTerms}}"/></OpenSearchDescription>"#
        ),
    )
    .unwrap();

    let disk = Arc::new(diskio::DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0u8; 20]));
    let app = synapse_rpc::create_http_router(engine);

    // Nothing configured yet.
    let search = |q: &str| {
        Request::builder()
            .uri(format!("/api/v1/search?q={q}"))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        json_of(&app, search("ubuntu")).await.0,
        StatusCode::NOT_FOUND
    );

    // Register the engine from its .btsearch file.
    let add = Request::builder()
        .method("POST")
        .uri("/api/v1/search/engines")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::json!({ "source": file.to_string_lossy() }).to_string(),
        ))
        .unwrap();
    let (status, body) = json_of(&app, add).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["engine"]["short_name"], "Example");

    // A search goes to the engine with the query percent-encoded, and its RSS comes back parsed.
    let (status, body) = json_of(&app, search("ubuntu%20iso%26x")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let result = &body["engines"][0];
    assert_eq!(result["engine"], "Example");
    assert!(result["error"].is_null(), "{result}");
    let item = &result["results"][0];
    assert_eq!(item["name"], "Ubuntu 24.04 ISO");
    assert_eq!(item["size"], 1234);
    assert_eq!(item["seeds"], 42);
    assert_eq!(item["leechers"], 7);
    assert_eq!(item["download_url"], "http://indexer.example/u.torrent");
    assert_eq!(item["info_hash"].as_array().unwrap().len(), 20);
    assert_eq!(
        seen.lock().last().unwrap(),
        "GET /rss?q=ubuntu%20iso%26x HTTP/1.1"
    );

    // A missing query is refused; an unknown engine name yields no results; local scope works.
    assert_eq!(
        json_of(
            &app,
            Request::builder()
                .uri("/api/v1/search")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (_, body) = json_of(
        &app,
        Request::builder()
            .uri("/api/v1/search?q=x&engine=Nope")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert!(body["engines"].as_array().unwrap().is_empty());
    let (status, body) = json_of(
        &app,
        Request::builder()
            .uri("/api/v1/search?scope=local&q=zzz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total_results"], 0);

    // Engines can be listed and removed; a bad description is refused.
    let (_, listed) = json_of(
        &app,
        Request::builder()
            .uri("/api/v1/search/engines")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(listed["count"], 1);
    let bad = dir.path().join("bad.btsearch");
    std::fs::write(&bad, "<rss/>").unwrap();
    let add_bad = Request::builder()
        .method("POST")
        .uri("/api/v1/search/engines")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::json!({ "source": bad.to_string_lossy() }).to_string(),
        ))
        .unwrap();
    assert_eq!(json_of(&app, add_bad).await.0, StatusCode::BAD_REQUEST);
    let del = Request::builder()
        .method("DELETE")
        .uri("/api/v1/search/engines/Example")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(del).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
}
