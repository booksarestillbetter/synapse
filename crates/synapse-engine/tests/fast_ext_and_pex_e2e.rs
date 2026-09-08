use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use synapse_engine::{compute_allowed_fast_set, PexManager};
use synapse_wire::{Message, UtPexMessage};

#[test]
fn test_bep6_fast_extension_negotiation_and_allowed_fast() {
    let peer_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    let info_hash = [0xAB; 20];
    let total_pieces = 500;

    let allowed_fast = compute_allowed_fast_set(peer_ip, info_hash, total_pieces, 10);
    assert_eq!(allowed_fast.len(), 10);

    for &piece in &allowed_fast {
        assert!(piece < total_pieces);
        let msg = Message::AllowedFast(piece);
        assert_eq!(msg, Message::AllowedFast(piece));
    }

    // Verify RejectRequest structure
    let reject = Message::RejectRequest {
        index: allowed_fast[0],
        begin: 0,
        length: 16384,
    };
    assert_eq!(
        reject,
        Message::RejectRequest {
            index: allowed_fast[0],
            begin: 0,
            length: 16384,
        }
    );
}

#[test]
fn test_bep11_pex_and_bep27_privacy_isolation() {
    // 1. Public Swarm PEX flow
    let mut public_pex = PexManager::new(false);
    assert!(public_pex.is_enabled());

    let peer_v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 6881));
    let peer_v6 = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 99),
        51413,
        0,
        0,
    ));

    public_pex.peer_connected(peer_v4);
    public_pex.peer_connected(peer_v6);

    let outgoing_pex = public_pex.generate_pex_message().unwrap();
    let encoded = outgoing_pex.encode();
    let decoded = UtPexMessage::decode(&encoded).unwrap();

    let mut remote_pex = PexManager::new(false);
    let discovered = remote_pex.ingest_pex_message(decoded);
    assert_eq!(discovered.len(), 2);
    assert!(discovered.contains(&peer_v4));
    assert!(discovered.contains(&peer_v6));

    // 2. Private Swarm PEX Isolation (BEP 27)
    let mut private_pex = PexManager::new(true);
    assert!(!private_pex.is_enabled());

    private_pex.peer_connected(peer_v4);
    assert!(private_pex.generate_pex_message().is_none());

    // Ingesting PEX on private swarm must return empty list (rejecting external gossip)
    let dropped_discovery = private_pex.ingest_pex_message(outgoing_pex);
    assert!(dropped_discovery.is_empty());
}
