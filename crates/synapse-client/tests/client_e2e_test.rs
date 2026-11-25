//! End-to-end integration test for SynapseClient and SynapseLiveCache against SynapseService.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use diskio::DiskEngine;
use synapse_client::{SynapseClient, SynapseLiveCache};
use synapse_engine::SwarmEngine;
use synapse_rpc::proto_v2::synapse_control_server::SynapseControlServer;
use synapse_rpc::{EventBus, SynapseService};

#[tokio::test]
#[allow(clippy::result_large_err)]
async fn test_synapse_client_crud_and_settings() {
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0x55; 20]));
    let event_bus = Arc::new(EventBus::new(1024));

    let service = SynapseService::new(event_bus.clone())
        .with_swarm_engine(engine.clone())
        .with_auth_token(Some("test-secret".to_string()));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    let auth_service = service.clone();
    let interceptor = move |req: tonic::Request<()>| -> Result<tonic::Request<()>, tonic::Status> {
        auth_service.verify_auth(&req)?;
        Ok(req)
    };

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(SynapseControlServer::with_interceptor(service, interceptor))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. Connect Client with Auth Token
    let client = SynapseClient::connect(format!("http://{addr}"))
        .await
        .expect("connect to test server")
        .with_auth_token("test-secret");

    // 2. Query Initial Session Stats
    let stats = client.get_session_stats().await.expect("get session stats");
    assert_eq!(stats.torrent_count, 0);

    // 3. Query Session Settings
    let settings = client
        .get_session_settings()
        .await
        .expect("get session settings");
    assert!(!settings.alt_speed_enabled);

    // 4. In-Flight Setting Updates: Turtle Mode & Concurrency
    let warnings = client.set_turtle_mode(true).await.expect("set turtle mode");
    assert!(warnings.is_empty());

    let updated_settings = client
        .get_session_settings()
        .await
        .expect("get updated session settings");
    assert!(updated_settings.alt_speed_enabled);
    assert!(updated_settings.is_alt_speed_active);

    let queue_warnings = client
        .set_queue_concurrency(Some(8), Some(12), Some(25))
        .await
        .expect("update queue concurrency");
    assert!(queue_warnings.is_empty());

    let final_settings = client
        .get_session_settings()
        .await
        .expect("get final settings");
    assert_eq!(final_settings.download_queue_size, 8);
    assert_eq!(final_settings.seed_queue_size, 12);
    assert_eq!(final_settings.max_active_torrents, 25);

    // 5. Add Torrent via Magnet
    let magnet = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=Ubuntu";
    let add_resp = client
        .add_magnet(magnet, None, true)
        .await
        .expect("add magnet");
    assert!(add_resp.success);
    assert_eq!(add_resp.hash, "0123456789abcdef0123456789abcdef01234567");

    // 6. Test Live Cache Synchronization
    let cache = SynapseLiveCache::spawn(client.clone());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(cache.is_connected());
}

fn minimal_torrent_bytes(name: &str, tracker_url: &str) -> Vec<u8> {
    format!(
        "d8:announce{}:{}4:infod6:lengthi16384e4:name{}:{}12:piece lengthi16384e6:pieces20:aaaaaaaaaaaaaaaaaaaaee",
        tracker_url.len(),
        tracker_url,
        name.len(),
        name
    )
    .into_bytes()
}

#[tokio::test]
#[allow(clippy::result_large_err)]
async fn test_synapse_client_builder_and_full_rpc_coverage() {
    use futures::StreamExt;
    use synapse_client::proto::move_in_queue_request::Direction;
    use synapse_client::proto::{
        OptionalDouble, OptionalUint64, TagsPatch, UpdateTorrentMetadataRequest,
    };

    let tmp = tempfile::tempdir().unwrap();
    let dl_dir = tmp.path().join("downloads");
    std::fs::create_dir_all(&dl_dir).unwrap();

    let disk = Arc::new(DiskEngine::auto().await);
    let engine = Arc::new(SwarmEngine::new(disk, [0x56; 20]));
    engine.settings().write().download_dir = dl_dir.clone();
    let event_bus = Arc::new(EventBus::new(1024));

    let service = SynapseService::new(event_bus.clone())
        .with_swarm_engine(engine.clone())
        .with_auth_token(Some("builder-secret".to_string()));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    let auth_service = service.clone();
    let interceptor = move |req: tonic::Request<()>| -> Result<tonic::Request<()>, tonic::Status> {
        auth_service.verify_auth(&req)?;
        Ok(req)
    };

    tokio::spawn(async move {
        let server_svc = SynapseControlServer::new(service)
            .max_decoding_message_size(synapse_rpc::MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(synapse_rpc::MAX_GRPC_MESSAGE_BYTES);
        tonic::transport::Server::builder()
            .add_service(tonic::service::interceptor::InterceptedService::new(
                server_svc,
                interceptor,
            ))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = SynapseClient::builder(format!("http://{addr}"))
        .auth_token("builder-secret")
        .connect_timeout(Duration::from_secs(5))
        .request_timeout(Duration::from_secs(15))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .http2_keep_alive_interval(Some(Duration::from_secs(15)))
        .keep_alive_timeout(Some(Duration::from_secs(5)))
        .keep_alive_while_idle(true)
        .max_decoding_message_size(synapse_rpc::MAX_GRPC_MESSAGE_BYTES)
        .max_encoding_message_size(synapse_rpc::MAX_GRPC_MESSAGE_BYTES)
        .connect()
        .await
        .expect("builder connect");

    let mut alert_stream = client
        .subscribe_alerts(None)
        .await
        .expect("subscribe_alerts");

    let bytes_a = minimal_torrent_bytes("sdk-alpha.bin", "http://127.0.0.1:9/announce");
    let bytes_b = minimal_torrent_bytes("sdk-beta.bin", "http://127.0.0.1:9/announce");
    let add_a = client
        .add_torrent_bytes(bytes_a, Some(dl_dir.to_string_lossy().into_owned()), false)
        .await
        .expect("add_torrent_bytes a");
    let add_b = client
        .add_torrent_bytes(bytes_b, Some(dl_dir.to_string_lossy().into_owned()), false)
        .await
        .expect("add_torrent_bytes b");
    assert!(add_a.success && add_b.success);

    let first_alert = tokio::time::timeout(Duration::from_secs(2), alert_stream.next())
        .await
        .expect("alert stream timed out")
        .expect("alert stream closed")
        .expect("alert ok");
    assert_eq!(first_alert.event_type, "TorrentAdded");

    // 10 previously-unwrapped RPCs
    let hashes = vec![add_a.hash.clone(), add_b.hash.clone()];
    assert!(
        client
            .move_in_queue(vec![add_b.hash.clone()], Direction::Top)
            .await
            .expect("move_in_queue")
            .success
    );
    assert!(
        client
            .set_sequential_download(hashes.clone(), true)
            .await
            .expect("set_sequential_download")
            .success
    );
    assert!(
        client
            .set_super_seeding(hashes.clone(), true)
            .await
            .expect("set_super_seeding")
            .success
    );
    assert!(
        client
            .set_first_last_piece_priority(hashes.clone(), true)
            .await
            .expect("set_first_last_piece_priority")
            .success
    );
    assert!(
        client
            .replace_trackers(&add_a.hash, vec!["http://127.0.0.1:18080/announce".into()])
            .await
            .expect("replace_trackers")
            .success
    );
    assert!(
        client
            .reannounce_torrents(hashes.clone())
            .await
            .expect("reannounce_torrents")
            .success
    );
    let reload_resp = client.reload_ip_filter().await.expect("reload_ip_filter");
    assert_eq!(reload_resp.rules, 0);

    let meta_resp = client
        .update_torrent_metadata(UpdateTorrentMetadataRequest {
            hash: add_a.hash.clone(),
            category: Some("linux".into()),
            tags: Some(TagsPatch {
                tags: vec!["iso".into(), "verified".into()],
            }),
            seed_ratio_limit: Some(OptionalDouble { value: Some(2.5) }),
            seed_time_limit_secs: Some(OptionalUint64 { value: Some(3600) }),
        })
        .await
        .expect("update_torrent_metadata");
    assert!(meta_resp.success);
    assert_eq!(meta_resp.category.as_deref(), Some("linux"));
    assert_eq!(meta_resp.tags, vec!["iso", "verified"]);
    assert_eq!(meta_resp.seed_ratio_limit, Some(2.5));
    assert_eq!(meta_resp.seed_time_limit_secs, Some(3600));

    let exported = client
        .export_torrent(&add_a.hash)
        .await
        .expect("export_torrent");
    assert!(exported.success);
    assert!(!exported.torrent_bytes.is_empty());

    // 4 bulk batch RPCs + failed_hashes + delete_data
    let missing_hash = "ff".repeat(20);
    let batch_with_missing = vec![add_a.hash.clone(), add_b.hash.clone(), missing_hash.clone()];

    let pause_resp = client
        .pause_torrents(batch_with_missing.clone())
        .await
        .expect("pause_torrents");
    assert!(!pause_resp.success);
    assert_eq!(pause_resp.succeeded, 2);
    assert_eq!(pause_resp.failed_hashes, vec![missing_hash.clone()]);

    let resume_resp = client
        .resume_torrents(hashes.clone())
        .await
        .expect("resume_torrents");
    assert!(resume_resp.success);
    assert_eq!(resume_resp.succeeded, 2);

    let recheck_resp = client
        .recheck_torrents(hashes.clone())
        .await
        .expect("recheck_torrents");
    assert!(recheck_resp.success);
    assert_eq!(recheck_resp.succeeded, 2);

    let payload_path_a = dl_dir.join("sdk-alpha.bin");
    std::fs::write(&payload_path_a, vec![0x55u8; 16]).unwrap();

    let remove_resp = client
        .remove_torrents(batch_with_missing, true)
        .await
        .expect("remove_torrents");
    assert!(!remove_resp.success);
    assert_eq!(remove_resp.succeeded, 2);
    assert_eq!(remove_resp.failed_hashes, vec![missing_hash]);
    assert!(
        !payload_path_a.exists(),
        "delete_data should remove payload"
    );
}
