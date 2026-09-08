use std::sync::Arc;
use std::time::Duration;
use diskio::DiskEngine;
use synapse_engine::SwarmEngine;
use synapse_rpc::proto_v2::synapse_control_client::SynapseControlClient;
use synapse_rpc::proto_v2::synapse_control_server::SynapseControlServer;
use synapse_rpc::proto_v2::*;
use synapse_rpc::{EventBus, SynapseService};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;

#[tokio::test]
async fn test_grpc_add_and_remove_torrent_with_swarm_engine() {
    let disk = Arc::new(DiskEngine::auto().await);
    let swarm = Arc::new(SwarmEngine::new(disk, [0x01; 20]));
    let event_bus = Arc::new(EventBus::new(256));
    let service = SynapseService::new(event_bus.clone()).with_swarm_engine(swarm.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(SynapseControlServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = SynapseControlClient::connect(format!("http://{}", addr))
        .await
        .unwrap();

    // 1. Add Torrent via Magnet URI
    let hex_hash = "0123456789abcdef0123456789abcdef01234567";
    let magnet = format!("magnet:?xt=urn:btih:{}&dn=Test+Movie&tr=http://tracker.example.com:80/announce", hex_hash);

    let add_resp = client
        .add_torrent(AddTorrentRequest {
            source: Some(add_torrent_request::Source::MagnetUri(magnet)),
            download_dir: Some("/tmp/downloads".into()),
            start_paused: Some(false),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(add_resp.success);
    assert_eq!(add_resp.hash, hex_hash);
    assert_eq!(add_resp.name, "Test Movie");
    assert_eq!(swarm.torrent_count(), 1);

    // 2. Subscribe Torrent Detail
    let mut detail_stream = client
        .subscribe_torrent_detail(TorrentDetailRequest {
            hash: hex_hash.into(),
            refresh_interval_ms: 50,
        })
        .await
        .unwrap()
        .into_inner();

    if let Some(detail) = detail_stream.next().await {
        let detail = detail.unwrap();
        assert_eq!(detail.hash, hex_hash);
        assert!(!detail.trackers.is_empty());
        assert_eq!(detail.trackers[0].url, "http://tracker.example.com/announce");
        assert!(detail.trackers[0].status == "Ready" || detail.trackers[0].status == "Updating");
        assert_eq!(detail.active_peers.len(), 0);
    }

    // 3. Remove Torrent
    let remove_resp = client
        .remove_torrent(RemoveTorrentRequest {
            hash: hex_hash.into(),
            delete_data: false,
        })
        .await
        .unwrap()
        .into_inner();

    assert!(remove_resp.success);
    assert_eq!(swarm.torrent_count(), 0);
}
