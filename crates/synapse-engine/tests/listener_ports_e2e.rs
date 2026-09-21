//! The daemon starts the peer listener (TCP + uTP on UDP) and the DHT on the same port
//! number; both UDP users must be able to coexist.

use std::net::SocketAddr;
use std::sync::Arc;

use diskio::DiskEngine;
use synapse_engine::SwarmEngine;

#[tokio::test(flavor = "multi_thread")]
async fn utp_and_dht_can_share_the_listen_port_number() {
    let engine = Arc::new(SwarmEngine::new(
        Arc::new(DiskEngine::auto().await),
        [8u8; 20],
    ));
    // A port free for TCP and UDP both.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let bind: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    engine.clone().start_listener(bind).await.unwrap();
    let dht = engine.clone().start_dht(bind).await;
    assert!(
        dht.is_ok(),
        "DHT could not start next to the uTP socket: {dht:?}"
    );

    // Both protocols must actually work on that one port, not merely bind.
    let SocketAddr::V4(v4) = bind else {
        unreachable!()
    };
    let (client, _) = synapse_dht::spawn([1u8; 20], "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let answered = tokio::time::timeout(std::time::Duration::from_secs(5), client.ping(v4)).await;
    assert!(
        matches!(answered, Ok(Ok(_))),
        "DHT ping over the shared port failed: {answered:?}"
    );

    let utp = synapse_engine::UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let connected =
        tokio::time::timeout(std::time::Duration::from_secs(5), utp.connect(bind)).await;
    assert!(
        matches!(connected, Ok(Ok(_))),
        "uTP connect over the shared port failed: {connected:?}"
    );
}

/// The daemon listens on IPv4 and IPv6 wildcards on one port number. That requires the IPv6
/// socket to be IPv6-only; a plain `[::]` listener collides with `0.0.0.0` on Linux.
#[tokio::test(flavor = "multi_thread")]
async fn ipv4_and_ipv6_wildcard_listeners_coexist_on_one_port() {
    let engine = Arc::new(SwarmEngine::new(
        Arc::new(DiskEngine::auto().await),
        [8u8; 20],
    ));
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    engine
        .clone()
        .start_listener(format!("0.0.0.0:{port}").parse().unwrap())
        .await
        .unwrap();
    match engine
        .clone()
        .start_listener(format!("[::]:{port}").parse().unwrap())
        .await
    {
        Ok(_) => {
            // Both families accept connections on the shared port.
            assert!(tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok());
            assert!(tokio::net::TcpStream::connect(("::1", port)).await.is_ok());
        }
        // Hosts without an IPv6 stack cannot run the v6 half.
        Err(e)
            if e.kind() == std::io::ErrorKind::AddrNotAvailable || e.raw_os_error() == Some(97) => {
        }
        Err(e) => panic!("IPv6 listener could not share the port: {e}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn dht_node_id_and_known_nodes_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("dht_state.bencode");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let bind: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    // First run: fresh id, learn one node, persist.
    let first = Arc::new(
        SwarmEngine::new(Arc::new(DiskEngine::auto().await), [8u8; 20])
            .with_dht_state_path(state_path.clone()),
    );
    first.clone().start_dht(bind).await.unwrap();
    let id = first.dht_node_id().expect("node running");
    let (peer, peer_addr) = synapse_dht::spawn([9u8; 20], "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let SocketAddr::V4(peer_v4) = peer_addr else {
        unreachable!()
    };
    // The peer queries us, so we learn it (and it is a "good" node).
    let dht_v4 = match bind {
        SocketAddr::V4(v) => v,
        _ => unreachable!(),
    };
    peer.ping(dht_v4).await.unwrap();
    first.persist_dht_state().await;
    assert!(state_path.exists(), "state file was not written");
    drop(first);

    // Second run resumes with the same id.
    let saved = synapse_dht::DhtState::decode(&std::fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(saved.node_id, id);
    assert!(
        saved.nodes.contains(&SocketAddr::V4(peer_v4)),
        "known node not saved: {:?}",
        saved.nodes
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_saved_dht_node_id_is_reused_on_start() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.bencode");
    let id = [0x5Au8; 20];
    std::fs::write(
        &path,
        synapse_dht::DhtState {
            node_id: id,
            nodes: vec![],
        }
        .encode(),
    )
    .unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let engine = Arc::new(
        SwarmEngine::new(Arc::new(DiskEngine::auto().await), [8u8; 20]).with_dht_state_path(path),
    );
    engine
        .clone()
        .start_dht(format!("127.0.0.1:{port}").parse().unwrap())
        .await
        .unwrap();
    assert_eq!(engine.dht_node_id(), Some(id));
}
