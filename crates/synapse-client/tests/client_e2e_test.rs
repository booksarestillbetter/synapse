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
