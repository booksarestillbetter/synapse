//! Drives `safe_http::fetch` against a real loopback HTTP server: size caps, redirect
//! handling, and the local-address policy.

use std::time::Duration;

use synapse_tracker::safe_http::{fetch, FetchError, FetchOptions, LocalPolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

/// Serves every connection with `respond(request_path) -> raw HTTP response bytes`.
async fn serve(respond: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let respond = std::sync::Arc::new(respond);
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let respond = respond.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let _ = sock.write_all(&respond(&path)).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

fn opts(local: LocalPolicy, max_body: usize) -> FetchOptions {
    FetchOptions {
        timeout: Duration::from_secs(5),
        max_body,
        user_agent: "test",
        local,
        range: None,
    }
}

fn ok(body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

#[tokio::test]
async fn returns_a_body_within_the_cap() {
    let addr = serve(|_| ok(b"hello")).await;
    let url = Url::parse(&format!("http://{addr}/announce")).unwrap();
    let got = fetch(&url, &opts(LocalPolicy::AllowAny, 1024))
        .await
        .unwrap();
    assert_eq!((got.status, got.body.as_slice()), (200, &b"hello"[..]));
}

#[tokio::test]
async fn an_honest_content_length_over_the_cap_is_refused_up_front() {
    let addr = serve(|_| ok(&vec![b'x'; 5000])).await;
    let url = Url::parse(&format!("http://{addr}/announce")).unwrap();
    let err = fetch(&url, &opts(LocalPolicy::AllowAny, 1000))
        .await
        .err()
        .unwrap();
    assert!(matches!(err, FetchError::TooLarge(1000)), "{err:?}");
}

#[tokio::test]
async fn a_chunked_body_with_no_content_length_is_cut_off_at_the_cap() {
    // 200 chunks of 100 bytes = 20 000 bytes streamed with no Content-Length.
    let addr = serve(|_| {
        let mut r =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
        for _ in 0..200 {
            r.extend_from_slice(b"64\r\n");
            r.extend_from_slice(&[b'y'; 100]);
            r.extend_from_slice(b"\r\n");
        }
        r.extend_from_slice(b"0\r\n\r\n");
        r
    })
    .await;
    let url = Url::parse(&format!("http://{addr}/announce")).unwrap();
    let err = fetch(&url, &opts(LocalPolicy::AllowAny, 1000))
        .await
        .err()
        .unwrap();
    assert!(matches!(err, FetchError::TooLarge(1000)), "{err:?}");
}

#[tokio::test]
async fn redirect_loops_stop_after_five_hops() {
    let addr = serve(|_| {
        b"HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_vec()
    })
    .await;
    let url = Url::parse(&format!("http://{addr}/announce")).unwrap();
    let err = fetch(&url, &opts(LocalPolicy::AllowAny, 1024))
        .await
        .err()
        .unwrap();
    assert!(matches!(err, FetchError::TooManyRedirects), "{err:?}");
}

#[tokio::test]
async fn redirects_are_followed_to_the_final_body() {
    let addr = serve(|p| {
        if p == "/final" {
            ok(b"done")
        } else {
            b"HTTP/1.1 301 Moved\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
        }
    })
    .await;
    let url = Url::parse(&format!("http://{addr}/announce")).unwrap();
    let got = fetch(&url, &opts(LocalPolicy::AllowAny, 1024))
        .await
        .unwrap();
    assert_eq!(got.body, b"done");
}

#[tokio::test]
async fn loopback_origin_obeys_the_local_policy() {
    let addr = serve(|_| ok(b"secret admin page")).await;
    let base = format!("http://{addr}");

    // Denied outright (web seeds).
    let e = fetch(
        &Url::parse(&format!("{base}/x")).unwrap(),
        &opts(LocalPolicy::Deny, 1024),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(e, FetchError::Blocked(_)), "{e:?}");

    // Tracker rule: only announce/scrape paths.
    let tracker = LocalPolicy::AllowPathSegments(&["announce", "scrape"]);
    let e = fetch(
        &Url::parse(&format!("{base}/admin/reboot")).unwrap(),
        &opts(tracker, 1024),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(e, FetchError::Blocked(_)), "{e:?}");
    assert!(fetch(
        &Url::parse(&format!("{base}/passkey123/announce?x=1")).unwrap(),
        &opts(tracker, 1024)
    )
    .await
    .is_ok());
}

#[tokio::test]
async fn non_http_schemes_are_refused() {
    let e = fetch(
        &Url::parse("file:///etc/passwd").unwrap(),
        &opts(LocalPolicy::AllowAny, 1024),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(e, FetchError::InvalidUrl(_)), "{e:?}");
}
