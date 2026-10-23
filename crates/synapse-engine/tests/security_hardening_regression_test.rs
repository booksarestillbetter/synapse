use std::net::IpAddr;
use std::path::{Path, PathBuf};

use synapse_engine::announcer::Announcer;
use synapse_engine::feed::FeedManager;
use synapse_engine::fs::verify_no_symlinks_under;
use synapse_engine::lifecycle::StagingPlugin;
use synapse_engine::pex::{holepunch_address_allowed, pex_address_allowed};
use synapse_engine::proxy::{self, ProxyKind, ProxySettings};
use synapse_engine::search::SearchManager;
use synapse_engine::SessionStore;
use synapse_meta::File as MetaFile;
use tempfile::tempdir;

#[cfg(unix)]
#[test]
fn test_verify_no_symlinks_and_staging_single_file_path() {
    let src_dir = tempdir().unwrap();
    let staging_dir = tempdir().unwrap();
    let secret_dir = tempdir().unwrap();

    let secret_file = secret_dir.path().join("secret.txt");
    std::fs::write(&secret_file, b"classified").unwrap();

    // Symlink inside source_dir must be rejected
    let symlink_in_src = src_dir.path().join("evil.txt");
    std::os::unix::fs::symlink(&secret_file, &symlink_in_src).unwrap();
    assert!(verify_no_symlinks_under(src_dir.path(), Path::new("evil.txt")).is_err());
    assert!(verify_no_symlinks_under(src_dir.path(), Path::new("../secret.txt")).is_err());

    let plugin = StagingPlugin::new(Some(staging_dir.path().to_path_buf()), true, None);
    let err = plugin.perform_hardlinks(
        src_dir.path(),
        "evil.txt",
        &[MetaFile {
            path: PathBuf::from("evil.txt"),
            length: 10,
        }],
    );
    assert!(
        err.is_err(),
        "StagingPlugin must refuse symlinked source files"
    );

    // Single-file torrent with nested relative path in files[0].path must use files[0].path
    let sub = src_dir.path().join("nested");
    std::fs::create_dir_all(&sub).unwrap();
    let real_file = sub.join("movie.mkv");
    std::fs::write(&real_file, b"video-bytes").unwrap();

    let staged = plugin
        .perform_hardlinks(
            src_dir.path(),
            "display-name-only",
            &[MetaFile {
                path: PathBuf::from("nested/movie.mkv"),
                length: 11,
            }],
        )
        .unwrap()
        .expect("staged path returned");
    assert_eq!(staged, staging_dir.path().join("nested/movie.mkv"));
    assert_eq!(std::fs::read(&staged).unwrap(), b"video-bytes");
}

#[tokio::test]
async fn test_proxy_force_proxy_and_udp_scrape_blocked() {
    // Save current global proxy to restore at end of test
    let prev = proxy::global();

    proxy::set_global(Some(ProxySettings {
        kind: ProxyKind::Socks5,
        host: "127.0.0.1".into(),
        port: 1, // unreachable local port
        auth: None,
        proxy_http: false,
        proxy_peer_connections: false,
        proxy_hostnames: true,
        force_proxy: true,
    }));

    assert!(
        proxy::peers_use_proxy(),
        "force_proxy must force peer connections to use the proxy"
    );

    // Announcer::scrape must refuse UDP trackers when force_proxy is enabled
    let listen_port = std::sync::Arc::new(parking_lot::RwLock::new(6881));
    let circuit_breaker =
        std::sync::Arc::new(synapse_engine::circuit_breaker::PeerCircuitBreaker::default());
    let announcer = Announcer::new([0x11; 20], listen_port, circuit_breaker);
    let udp_url = url::Url::parse("udp://127.0.0.1:6969/announce").unwrap();
    let res = announcer.scrape(&udp_url, &[[0x22; 20]]).await;
    assert!(
        res.is_err(),
        "UDP tracker scrape must be rejected when proxy/force_proxy is active"
    );

    // Empty proxy host with force_proxy must fail closed on connect_peer
    proxy::set_global(Some(ProxySettings {
        kind: ProxyKind::Socks5,
        host: "".into(),
        port: 0,
        auth: None,
        proxy_http: false,
        proxy_peer_connections: false,
        proxy_hostnames: true,
        force_proxy: true,
    }));
    let dial_res = proxy::connect_peer("127.0.0.1:6881".parse().unwrap()).await;
    assert!(
        dial_res.is_err(),
        "connect_peer must fail closed when force_proxy is set without a valid proxy"
    );

    proxy::set_global(prev);
}

#[tokio::test]
async fn test_search_and_feed_ssrf_and_special_file_protection() {
    let search = SearchManager::default();

    #[cfg(unix)]
    {
        // /dev/zero must be rejected immediately as a non-regular file (no OOM)
        let err = search.add_source("/dev/zero").await.unwrap_err();
        assert!(
            err.contains("not a regular file"),
            "Expected non-regular file error for /dev/zero, got: {err}"
        );
    }

    // Loopback HTTP URLs must be rejected by LocalPolicy::Deny in SearchManager and FeedManager
    let search_err = search
        .add_source("http://127.0.0.1:65530/btsearch.xml")
        .await
        .unwrap_err();
    assert!(
        search_err.contains("could not fetch"),
        "SearchManager must block loopback SSRF URLs: {search_err}"
    );

    let feed_err = FeedManager::fetch_and_parse_feed("http://127.0.0.1:65530/rss.xml")
        .await
        .unwrap_err();
    assert!(
        feed_err.contains("Network request failed"),
        "FeedManager must block loopback SSRF URLs: {feed_err}"
    );
}

#[test]
fn test_holepunch_and_pex_address_validation() {
    let public_source: IpAddr = "198.51.100.10".parse().unwrap();
    let lan_source: IpAddr = "192.168.1.50".parse().unwrap();
    let loopback_source: IpAddr = "127.0.0.1".parse().unwrap();

    // Public peer must not steer us into dialling loopback, RFC1918, unspecified, multicast, or port 0
    assert!(!holepunch_address_allowed(
        "127.0.0.1:6881".parse().unwrap(),
        public_source
    ));
    assert!(!holepunch_address_allowed(
        "10.0.0.1:6881".parse().unwrap(),
        public_source
    ));
    assert!(!holepunch_address_allowed(
        "192.168.1.1:6881".parse().unwrap(),
        public_source
    ));
    assert!(!holepunch_address_allowed(
        "0.0.0.0:6881".parse().unwrap(),
        public_source
    ));
    assert!(!holepunch_address_allowed(
        "224.0.0.1:6881".parse().unwrap(),
        public_source
    ));
    assert!(!holepunch_address_allowed(
        "203.0.113.5:0".parse().unwrap(),
        public_source
    ));
    assert!(holepunch_address_allowed(
        "203.0.113.5:6881".parse().unwrap(),
        public_source
    ));

    // Loopback peer is allowed to reference loopback (for local E2E tests), LAN peer allowed LAN
    assert!(holepunch_address_allowed(
        "127.0.0.1:54321".parse().unwrap(),
        loopback_source
    ));
    assert!(pex_address_allowed(
        "192.168.1.99:6881".parse().unwrap(),
        lan_source
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn test_session_key_created_with_0600_and_rejects_symlink() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempdir().unwrap();
    let _store = SessionStore::new(tmp.path()).unwrap();
    let key_path = tmp.path().join("session.key");
    let mode = std::fs::symlink_metadata(&key_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "session.key must be created with 0600 permissions"
    );

    // Symlinked session.key must be rejected
    let tmp2 = tempdir().unwrap();
    let symlink_key = tmp2.path().join("session.key");
    std::os::unix::fs::symlink(&key_path, &symlink_key).unwrap();
    assert!(
        SessionStore::new(tmp2.path()).is_err(),
        "SessionStore::new must refuse a symlinked session.key"
    );
}
