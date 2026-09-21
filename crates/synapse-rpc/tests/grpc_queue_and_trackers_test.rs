//! The queue / sequential / reannounce / tracker-replacement / blocklist RPCs, over a real
//! gRPC connection to a real engine.

use diskio::DiskEngine;
use std::sync::Arc;
use std::time::Duration;
use synapse_engine::SwarmEngine;
use synapse_rpc::proto_v2::synapse_control_client::SynapseControlClient;
use synapse_rpc::proto_v2::synapse_control_server::SynapseControlServer;
use synapse_rpc::proto_v2::*;
use synapse_rpc::{EventBus, SynapseService};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const C: &str = "cccccccccccccccccccccccccccccccccccccccc";

async fn start() -> (
    SynapseControlClient<tonic::transport::Channel>,
    Arc<SwarmEngine>,
) {
    let disk = Arc::new(DiskEngine::auto().await);
    let swarm = Arc::new(SwarmEngine::new(disk, [0x07; 20]));
    let service =
        SynapseService::new(Arc::new(EventBus::new(256))).with_swarm_engine(swarm.clone());
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
    let client = SynapseControlClient::connect(format!("http://{addr}"))
        .await
        .unwrap();
    (client, swarm)
}

async fn add(client: &mut SynapseControlClient<tonic::transport::Channel>, hash: &str) {
    let magnet =
        format!("magnet:?xt=urn:btih:{hash}&dn=T&tr=http://tracker.example.com:80/announce");
    let r = client
        .add_torrent(AddTorrentRequest {
            source: Some(add_torrent_request::Source::MagnetUri(magnet)),
            download_dir: Some("/tmp/downloads".into()),
            start_paused: Some(false),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(r.success);
}

fn hex(h: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&::hex::decode(h).unwrap());
    out
}

#[tokio::test]
async fn capabilities_advertise_the_new_operations() {
    let (mut client, _swarm) = start().await;
    let caps = client
        .get_capabilities(Empty {})
        .await
        .unwrap()
        .into_inner();
    for f in [
        "queue_move_v1",
        "sequential_download_v1",
        "reannounce_v1",
        "replace_trackers_v1",
        "ip_filter_reload_v1",
    ] {
        assert!(caps.features.iter().any(|x| x == f), "missing {f}");
    }
}

#[tokio::test]
async fn queue_moves_reorder_positions_and_the_torrent_list_reports_them() {
    let (mut client, swarm) = start().await;
    for h in [A, B, C] {
        add(&mut client, h).await;
    }
    let pos = swarm.queue_positions();
    assert_eq!(
        (pos[&hex(A)], pos[&hex(B)], pos[&hex(C)]),
        (0, 1, 2),
        "adds queue in the order they were made, even within the same second"
    );

    let r = client
        .move_in_queue(MoveInQueueRequest {
            hashes: vec![C.into()],
            direction: move_in_queue_request::Direction::Top as i32,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(r.success);
    let pos = swarm.queue_positions();
    assert_eq!((pos[&hex(C)], pos[&hex(A)], pos[&hex(B)]), (0, 1, 2));

    // The list a client subscribes to carries the same positions.
    let mut stream = client
        .subscribe_torrents(SubscribeTorrentsRequest {
            chunk_size: 10,
            flush_window_ms: 50,
        })
        .await
        .unwrap()
        .into_inner();
    let mut seen = std::collections::HashMap::new();
    while seen.len() < 3 {
        let ev = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("snapshot arrives")
            .unwrap()
            .unwrap();
        if let Some(torrent_list_event::Event::Snapshot(chunk)) = ev.event {
            for t in chunk.items {
                seen.insert(t.hash, t.queue_position);
            }
        }
    }
    assert_eq!((seen[C], seen[A], seen[B]), (0, 1, 2));

    let r = client
        .move_in_queue(MoveInQueueRequest {
            hashes: vec!["dddddddddddddddddddddddddddddddddddddddd".into()],
            direction: move_in_queue_request::Direction::Down as i32,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(
        !r.success,
        "unknown torrent is reported, not silently accepted"
    );
}

#[tokio::test]
async fn sequential_download_toggles_per_torrent() {
    let (mut client, swarm) = start().await;
    add(&mut client, A).await;
    add(&mut client, B).await;

    let r = client
        .set_sequential_download(SequentialDownloadRequest {
            hashes: vec![A.into()],
            enabled: true,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(r.success);
    assert!(swarm.is_sequential(&hex(A)));
    assert!(!swarm.is_sequential(&hex(B)));

    client
        .set_sequential_download(SequentialDownloadRequest {
            hashes: vec![A.into()],
            enabled: false,
        })
        .await
        .unwrap();
    assert!(!swarm.is_sequential(&hex(A)));

    let r = client
        .set_sequential_download(SequentialDownloadRequest {
            hashes: vec!["dddddddddddddddddddddddddddddddddddddddd".into()],
            enabled: true,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!r.success);
}

#[tokio::test]
async fn replacing_trackers_changes_what_the_torrent_announces_to() {
    let (mut client, swarm) = start().await;
    add(&mut client, A).await;

    let urls = |swarm: &SwarmEngine| -> Vec<String> {
        let mut v: Vec<String> = swarm
            .get_tracker_reports(&hex(A))
            .into_iter()
            .map(|r| r.url)
            .filter(|u| u.contains("example"))
            .collect();
        v.sort();
        v
    };
    assert_eq!(urls(&swarm), ["http://tracker.example.com/announce"]);

    let r = client
        .replace_trackers(ReplaceTrackersRequest {
            hash: A.into(),
            trackers: vec![
                "http://new.example.org:8080/announce".into(),
                "not a url".into(),
                "http://new.example.org:8080/announce".into(),
            ],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(r.success);
    assert_eq!(urls(&swarm), ["http://new.example.org:8080/announce"]);

    // Nothing usable in the list is an error, and leaves the current trackers alone.
    let r = client
        .replace_trackers(ReplaceTrackersRequest {
            hash: A.into(),
            trackers: vec!["nope".into()],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!r.success);

    // An empty list puts the torrent's own trackers back.
    let r = client
        .replace_trackers(ReplaceTrackersRequest {
            hash: A.into(),
            trackers: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(r.success);
    assert_eq!(urls(&swarm), ["http://tracker.example.com/announce"]);
}

#[tokio::test]
async fn reannounce_targets_announcing_torrents_only() {
    let (mut client, _swarm) = start().await;
    add(&mut client, A).await;

    let r = client
        .reannounce_torrents(TorrentHashesRequest {
            hashes: vec![A.into()],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(r.success, "{:?}", r.error);

    let r = client
        .reannounce_torrents(TorrentHashesRequest {
            hashes: vec!["dddddddddddddddddddddddddddddddddddddddd".into()],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!r.success);
}

#[tokio::test]
async fn reloading_the_ip_filter_rereads_the_blocklist_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ipfilter.dat");
    std::fs::write(&path, "001.002.003.000 - 001.002.003.255 , 000 , test\n").unwrap();

    let (mut client, swarm) = start().await;
    swarm.load_ip_filter_config(&["10.0.0.0/8".to_string()], Some(&path));
    let base = swarm.ip_filter().read().total_rules();
    assert!(base >= 2);

    std::fs::write(
        &path,
        "001.002.003.000 - 001.002.003.255 , 000 , test\n\
         004.005.006.000 - 004.005.006.255 , 000 , test\n",
    )
    .unwrap();
    let r = client
        .reload_ip_filter(Empty {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r.rules as usize, base + 1);
    assert!(swarm
        .ip_filter()
        .read()
        .is_blocked("4.5.6.7".parse().unwrap()));
}
