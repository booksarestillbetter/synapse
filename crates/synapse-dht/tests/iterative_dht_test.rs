use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use synapse_dht::{spawn, IterativePeersResult};

fn to_v4(addr: SocketAddr) -> SocketAddrV4 {
    match addr {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => unreachable!(),
    }
}

#[tokio::test]
async fn test_iterative_dht_find_node_and_get_peers() {
    let bind_any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

    // Node A (Originator): id all 0x01
    let id_a = [0x01; 20];
    let (node_a, _addr_a) = spawn(id_a, bind_any).await.unwrap();

    // Node B (Bridge): id all 0x02
    let id_b = [0x02; 20];
    let (node_b, addr_b) = spawn(id_b, bind_any).await.unwrap();

    // Node C (Target holder): id all 0x03
    let id_c = [0x03; 20];
    let (_node_c, addr_c) = spawn(id_c, bind_any).await.unwrap();

    // Node B learns about Node C by pinging it
    node_b.ping(to_v4(addr_c)).await.unwrap();

    // On Node C, announce a peer for info_hash
    let info_hash = [0x42; 20];
    let (token, _) = node_b.get_peers(to_v4(addr_c), info_hash).await.unwrap();
    node_b.announce_peer(to_v4(addr_c), info_hash, 6881, token).await.unwrap();

    // Node A does not know Node C directly. It only has Node B as a bootstrap node.
    let bootstrap = vec![to_v4(addr_b)];

    // 1. Test iterative find_node
    let found_nodes = node_a.iterative_find_node(id_c, &bootstrap).await.unwrap();
    assert!(found_nodes.iter().any(|n| n.id == id_c && n.addr == to_v4(addr_c)));

    // 2. Test iterative get_peers
    let IterativePeersResult { peers, closest_nodes } = node_a.iterative_get_peers(info_hash, &bootstrap).await.unwrap();
    assert!(peers.iter().any(|p| p.port() == 6881));
    assert!(!closest_nodes.is_empty());
}
