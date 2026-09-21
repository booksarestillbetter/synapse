//! Integration test for BEP 26 REST tracker announce, BEP 41 UDP options, and BEP 7 IPv6 parameters.

use std::net::SocketAddr;
use tokio::net::UdpSocket;

use synapse_tracker::{AnnounceRequest, Event, UdpOption};

#[tokio::test]
async fn test_bep41_and_bep7_udp_announce_e2e() {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tracker_addr = sock.local_addr().unwrap();

    let tracker_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        // 1. Connect request
        let (n, client_addr) = sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 16);
        let tx_id = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);

        // Connect response: action 0, tx_id, connection_id = 0x0102030405060708
        let mut resp = [0u8; 16];
        resp[0..4].copy_from_slice(&0u32.to_be_bytes());
        resp[4..8].copy_from_slice(&tx_id.to_be_bytes());
        resp[8..16].copy_from_slice(&0x0102030405060708u64.to_be_bytes());
        sock.send_to(&resp, client_addr).await.unwrap();

        // 2. Announce request with BEP 41 options and BEP 7 IPv4
        let (n, client_addr) = sock.recv_from(&mut buf).await.unwrap();
        assert!(n > 98, "packet should contain trailing BEP 41 options");

        // Verify BEP 7 IPv4 was populated in bytes 84..88
        assert_eq!(&buf[84..88], &[192, 168, 1, 99]);

        // Verify BEP 41 options trailing
        let opts = synapse_tracker::decode_udp_options(&buf[98..n]).unwrap();
        assert_eq!(opts.len(), 1);
        match &opts[0] {
            UdpOption::UrlData(path) => assert_eq!(path, "/passkey123"),
            _ => panic!("Expected UrlData option"),
        }

        let announce_tx = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let mut ann_resp = vec![0u8; 26];
        ann_resp[0..4].copy_from_slice(&1u32.to_be_bytes()); // action 1
        ann_resp[4..8].copy_from_slice(&announce_tx.to_be_bytes());
        ann_resp[8..12].copy_from_slice(&900u32.to_be_bytes()); // interval
        ann_resp[12..16].copy_from_slice(&1u32.to_be_bytes()); // leechers
        ann_resp[16..20].copy_from_slice(&10u32.to_be_bytes()); // seeders
        ann_resp[20..26].copy_from_slice(&[10, 0, 0, 1, 0x1A, 0xE1]); // 10.0.0.1:6881

        sock.send_to(&ann_resp, client_addr).await.unwrap();
    });

    let req = AnnounceRequest {
        info_hash: [0x42; 20],
        peer_id: *b"-SY2200-testbep41001",
        port: 6881,
        uploaded: 0,
        downloaded: 0,
        left: 1000,
        event: Event::Started,
        num_want: Some(20),
        ipv4: Some(std::net::Ipv4Addr::new(192, 168, 1, 99)),
        ipv6: None,
        udp_options: vec![UdpOption::UrlData("/passkey123".to_string())],
        tracker_id: None,
    };

    let resp = synapse_tracker::udp::announce(tracker_addr, &req, 0x12345678)
        .await
        .unwrap();
    assert_eq!(resp.interval, 900);
    assert_eq!(resp.seeders, 10);
    assert_eq!(resp.peers.len(), 1);
    assert_eq!(
        resp.peers[0],
        "10.0.0.1:6881".parse::<SocketAddr>().unwrap()
    );

    tracker_task.await.unwrap();
}
