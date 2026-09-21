use std::sync::Arc;
use std::time::Duration;
use synapse_rpc::proto_v2::synapse_control_client::SynapseControlClient;
use synapse_rpc::proto_v2::synapse_control_server::SynapseControlServer;
use synapse_rpc::proto_v2::{SubscribeTorrentsRequest, TorrentState, TorrentSummary};
use synapse_rpc::{EventBus, SynapseService};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;

#[tokio::test]
async fn test_grpc_subscribe_torrents_and_delta_streaming() {
    let event_bus = Arc::new(EventBus::new(1024));
    let flusher_bus = event_bus.clone();
    let _flusher_handle = flusher_bus.start_flusher(Duration::from_millis(50));

    let service = SynapseService::new(event_bus.clone());

    // Pre-populate with 2 torrents
    for i in 0..2 {
        let summary = TorrentSummary {
            hash: format!("hash_{:04}", i),
            name: format!("Torrent_{}", i),
            total_size: 1_000_000,
            progress: 0.5,
            state: TorrentState::StateDownloading as i32,
            rate_download: 500_000,
            rate_upload: 100_000,
            peers_connected: 12,
            peers_sending: 4,
            eta_seconds: 120,
            ratio: 0.2,
            error_message: None,
            download_dir: "/downloads".into(),
            added_at: 1700000000,
            piece_count: 100,
            piece_size: 10000,
        };
        service.upsert_torrent(summary);
    }

    // Start in-memory tonic server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(SynapseControlServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = SynapseControlClient::connect(format!("http://{}", addr))
        .await
        .unwrap();

    let mut stream = client
        .subscribe_torrents(SubscribeTorrentsRequest {
            chunk_size: 1,
            flush_window_ms: 50,
        })
        .await
        .unwrap()
        .into_inner();

    // First chunk of snapshot
    let chunk1 = stream.next().await.unwrap().unwrap();
    if let Some(synapse_rpc::proto_v2::torrent_list_event::Event::Snapshot(snap)) = chunk1.event {
        assert_eq!(snap.items.len(), 1);
        assert_eq!(snap.chunk_index, 0);
        assert_eq!(snap.total_chunks, 2);
        assert!(!snap.is_last_chunk);
    } else {
        panic!("Expected snapshot chunk 1");
    }

    // Second chunk of snapshot
    let chunk2 = stream.next().await.unwrap().unwrap();
    if let Some(synapse_rpc::proto_v2::torrent_list_event::Event::Snapshot(snap)) = chunk2.event {
        assert_eq!(snap.items.len(), 1);
        assert_eq!(snap.chunk_index, 1);
        assert!(snap.is_last_chunk);
    } else {
        panic!("Expected snapshot chunk 2");
    }

    // Now emit a live delta
    event_bus.record_delta(synapse_rpc::proto_v2::TorrentDelta {
        hash: "hash_0000".into(),
        progress: Some(0.75),
        rate_download: Some(1_200_000),
        ..Default::default()
    });

    // Receive live delta after 50ms flush
    let delta_event = stream.next().await.unwrap().unwrap();
    if let Some(synapse_rpc::proto_v2::torrent_list_event::Event::Updated(delta)) =
        delta_event.event
    {
        assert_eq!(delta.hash, "hash_0000");
        assert_eq!(delta.progress, Some(0.75));
        assert_eq!(delta.rate_download, Some(1_200_000));
    } else {
        panic!("Expected updated delta");
    }
}
