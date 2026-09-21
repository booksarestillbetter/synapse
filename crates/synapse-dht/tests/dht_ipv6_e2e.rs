//! BEP 32 IPv6 DHT end-to-end integration tests over real UDP sockets.

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use synapse_dht::{spawn, spawn_dual, GetPeersResult, NodeId};

/// CI containers often have no IPv6 loopback; the tests below have nothing to check there.
fn ipv6_loopback_available() -> bool {
    std::net::UdpSocket::bind("[::1]:0").is_ok()
}

macro_rules! require_ipv6 {
    () => {
        if !ipv6_loopback_available() {
            eprintln!("skipping: no IPv6 loopback on this host");
            return;
        }
    };
}

fn addr6(port: u16) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0))
}

#[tokio::test]
async fn test_ipv6_ping_and_routing_table() {
    require_ipv6!();
    let id_a: NodeId = [1u8; 20];
    let id_b: NodeId = [2u8; 20];

    let (node_a, addr_a) = spawn(id_a, addr6(0))
        .await
        .expect("bind node A on IPv6 loopback");
    let (_node_b, addr_b) = spawn(id_b, addr6(0))
        .await
        .expect("bind node B on IPv6 loopback");

    assert!(addr_a.is_ipv6());
    assert!(addr_b.is_ipv6());

    // A pings B over IPv6
    let pong_id = node_a.ping(addr_b).await.expect("ping over IPv6");
    assert_eq!(pong_id, id_b);

    // Node A's IPv6 routing table should now contain Node B
    let v6_nodes = node_a.routing_snapshot_v6().await.expect("snapshot v6");
    assert!(v6_nodes.iter().any(|n| n.id == id_b));
}

#[tokio::test]
async fn test_ipv6_find_node_want_n6() {
    require_ipv6!();
    let id_a: NodeId = [0x10; 20];
    let id_b: NodeId = [0x20; 20];
    let id_c: NodeId = [0x30; 20];

    let (node_a, _) = spawn(id_a, addr6(0)).await.unwrap();
    let (_node_b, addr_b) = spawn(id_b, addr6(0)).await.unwrap();
    let (node_c, addr_c) = spawn(id_c, addr6(0)).await.unwrap();

    // Node C pings Node B so B learns about C in its IPv6 routing table
    node_c.ping(addr_b).await.unwrap();

    // Node A queries Node B with find_node_v6
    let nodes6 = node_a.find_node_v6(addr_b, id_c).await.unwrap();
    assert!(!nodes6.is_empty(), "expected nodes6 in response");
    assert!(
        nodes6
            .iter()
            .any(|n| n.id == id_c && SocketAddr::V6(n.addr) == addr_c),
        "expected Node C in nodes6 result, got {nodes6:?}"
    );
}

#[tokio::test]
async fn test_ipv6_announce_and_get_peers() {
    require_ipv6!();
    let id_a: NodeId = [0x41; 20];
    let id_b: NodeId = [0x42; 20];

    let (node_a, _) = spawn(id_a, addr6(0)).await.unwrap();
    let (_node_b, addr_b) = spawn(id_b, addr6(0)).await.unwrap();

    let info_hash = [0x99u8; 20];

    // Node A queries get_peers on Node B
    let (token, first_res) = node_a.get_peers(addr_b, info_hash).await.unwrap();
    assert!(matches!(first_res, GetPeersResult::Nodes6(_)));

    // Node A announces peer on Node B for port 6882
    node_a
        .announce_peer(addr_b, info_hash, 6882, token)
        .await
        .unwrap();

    // Node A queries get_peers with want n6 again
    let (_token, second_res) = node_a
        .get_peers_with_want(addr_b, info_hash, Some(vec!["n6".into()]))
        .await
        .unwrap();
    match second_res {
        GetPeersResult::Peers6(peers) => {
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].port(), 6882);
            assert_eq!(peers[0].ip(), &Ipv6Addr::LOCALHOST);
        }
        other => panic!("expected Peers6 result, got {other:?}"),
    }
}

#[tokio::test]
async fn test_dual_stack_node_find_node_both() {
    require_ipv6!();
    let id_dual: NodeId = [0xdd; 20];
    let id_v4: NodeId = [0x44; 20];
    let id_v6: NodeId = [0x66; 20];

    let (_dual_node, local_v4, local_v6) = spawn_dual(
        id_dual,
        "127.0.0.1:0".parse().unwrap(),
        "[::1]:0".parse().unwrap(),
    )
    .await
    .expect("spawn dual stack DHT node");

    assert!(local_v4.is_ipv4());
    assert!(local_v6.is_ipv6());

    // Peer on IPv4 pings dual node
    let (v4_node, addr_v4) = spawn(id_v4, "127.0.0.1:0".parse().unwrap()).await.unwrap();
    v4_node.ping(local_v4).await.unwrap();

    // Peer on IPv6 pings dual node
    let (v6_node, addr_v6) = spawn(id_v6, "[::1]:0".parse().unwrap()).await.unwrap();
    v6_node.ping(local_v6).await.unwrap();

    // Query dual node asking for both ["n4", "n6"]
    let (nodes4, nodes6) = v4_node
        .find_node_both(local_v4, [0; 20], Some(vec!["n4".into(), "n6".into()]))
        .await
        .unwrap();

    assert!(nodes4
        .iter()
        .any(|n| n.id == id_v4 && SocketAddr::V4(n.addr) == addr_v4));
    assert!(nodes6
        .iter()
        .any(|n| n.id == id_v6 && SocketAddr::V6(n.addr) == addr_v6));
}

/// A dual-stack node wants one port for both families. That only works if the IPv6 socket is
/// IPv6-only; a plain `[::]` socket also claims the IPv4 side on Linux and collides.
#[tokio::test]
async fn dual_stack_node_binds_v4_and_v6_sockets_on_the_same_port() {
    let port = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let bind_v4: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let bind_v6: std::net::SocketAddr = format!("[::]:{port}").parse().unwrap();
    match spawn_dual([5u8; 20], bind_v4, bind_v6).await {
        Ok((_h, v4, v6)) => {
            assert_eq!(v4.port(), port);
            assert_eq!(v6.port(), port);
        }
        // Hosts without an IPv6 stack cannot run this test.
        Err(e)
            if e.kind() == std::io::ErrorKind::AddrNotAvailable || e.raw_os_error() == Some(97) => {
        }
        Err(e) => panic!("dual-stack bind on one port failed: {e}"),
    }
}
