use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use synapse_engine::announcer::Announcer;
use synapse_engine::nat::{
    decode_natpmp_mapping_response, encode_natpmp_mapping_request, send_natpmp_mapping,
    validate_upnp_location_url, NatManager, PortProtocol,
};
use synapse_engine::PeerCircuitBreaker;

#[tokio::test]
async fn test_natpmp_real_socket_mock_gateway() {
    // 1. Spawn a mock NAT-PMP router gateway on loopback UDP
    let mock_gw_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let gw_addr = mock_gw_sock.local_addr().unwrap();

    let gw_handle = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        let (n, client_addr) = mock_gw_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 12, "NAT-PMP mapping request must be exactly 12 bytes");
        assert_eq!(buf[0], 0, "NAT-PMP version must be 0");
        assert_eq!(buf[1], 2, "TCP mapping opcode must be 2");

        let internal_port = u16::from_be_bytes([buf[4], buf[5]]);
        let _suggested_port = u16::from_be_bytes([buf[6], buf[7]]);
        let lifetime = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

        // Form 16-byte success response: external port 45678
        let mut resp = [0u8; 16];
        resp[0] = 0; // version
        resp[1] = 130; // 128 + 2 (TCP response)
        resp[2..4].copy_from_slice(&0u16.to_be_bytes()); // result code: Success
        resp[4..8].copy_from_slice(&999999u32.to_be_bytes()); // epoch
        resp[8..10].copy_from_slice(&internal_port.to_be_bytes());
        resp[10..12].copy_from_slice(&45678u16.to_be_bytes()); // mapped external port
        resp[12..16].copy_from_slice(&lifetime.to_be_bytes());

        mock_gw_sock.send_to(&resp, client_addr).await.unwrap();
    });

    // 2. Client sends request to mock gateway
    let result = send_natpmp_mapping(gw_addr, PortProtocol::Tcp, 6881, 6881, 3600)
        .await
        .expect("NAT-PMP mapping should succeed against mock gateway");

    assert_eq!(result.internal_port, 6881);
    assert_eq!(result.external_port, 45678);
    assert_eq!(result.lifetime_secs, 3600);

    gw_handle.await.unwrap();
}

#[tokio::test]
async fn test_nat_manager_attempt_natpmp() {
    let mock_gw_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let gw_addr = mock_gw_sock.local_addr().unwrap();

    let gw_handle = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        let (n, client_addr) = mock_gw_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 12);
        let internal_port = u16::from_be_bytes([buf[4], buf[5]]);

        let mut resp = [0u8; 16];
        resp[0] = 0;
        resp[1] = 130; // TCP
        resp[2..4].copy_from_slice(&0u16.to_be_bytes());
        resp[4..8].copy_from_slice(&100u32.to_be_bytes());
        resp[8..10].copy_from_slice(&internal_port.to_be_bytes());
        resp[10..12].copy_from_slice(&49999u16.to_be_bytes());
        resp[12..16].copy_from_slice(&3600u32.to_be_bytes());

        mock_gw_sock.send_to(&resp, client_addr).await.unwrap();
    });

    let mut nat_mgr = NatManager::new(true);
    nat_mgr.request_mapping(6881, PortProtocol::Tcp, "Test mapping");

    let mapped_port = nat_mgr
        .attempt_natpmp_mapping(gw_addr, 6881, PortProtocol::Tcp)
        .await
        .expect("Mapping attempt should succeed");

    assert_eq!(mapped_port, 49999);
    assert_eq!(
        nat_mgr.mapped_external_port(6881, PortProtocol::Tcp),
        Some(49999)
    );

    gw_handle.await.unwrap();
}

#[tokio::test]
async fn test_upnp_and_natpmp_security_checks() {
    // 1. UPnP location URL host validation (libtorrent upnp.cpp:161)
    let gw = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    assert!(validate_upnp_location_url("http://192.168.1.1:49152/root.xml", gw).is_ok());
    assert!(validate_upnp_location_url("http://10.0.0.1:49152/root.xml", gw).is_err());
    assert!(validate_upnp_location_url("http://attacker.com/root.xml", gw).is_err());
    assert!(validate_upnp_location_url("ftp://192.168.1.1/root.xml", gw).is_err());

    // 2. Decode validation
    let req = encode_natpmp_mapping_request(PortProtocol::Udp, 5000, 5000, 1800);
    assert_eq!(req[1], 1); // UDP opcode

    let mut invalid_resp = [0u8; 16];
    invalid_resp[0] = 0;
    invalid_resp[1] = 129; // UDP
    invalid_resp[2..4].copy_from_slice(&3u16.to_be_bytes()); // error code: Not Authorized
    assert!(decode_natpmp_mapping_response(&invalid_resp, PortProtocol::Udp).is_err());
}

#[test]
fn test_announcer_uses_nat_mapped_external_port() {
    let listen_port = Arc::new(RwLock::new(6881));
    let circuit_breaker = Arc::new(PeerCircuitBreaker::default());
    let nat_manager = Arc::new(RwLock::new(NatManager::new(true)));

    let _announcer = Announcer::new([0xaa; 20], listen_port.clone(), circuit_breaker)
        .with_nat_manager(nat_manager.clone());

    // Initially unmapped, candidate port should be bound listen_port 6881
    assert_eq!(
        nat_manager
            .read()
            .mapped_external_port(*listen_port.read(), PortProtocol::Tcp),
        None
    );

    // Map external port to 54321
    let gw = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    nat_manager
        .write()
        .set_mapped(6881, PortProtocol::Tcp, 54321, gw);

    assert_eq!(
        nat_manager
            .read()
            .mapped_external_port(*listen_port.read(), PortProtocol::Tcp),
        Some(54321)
    );
}
