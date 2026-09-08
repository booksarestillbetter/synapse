use bytes::Bytes;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

use synapse_engine::{UtpConnection, UtpConnectionState};
use synapse_wire::{UtpPacket, UtpType};

#[tokio::test]
async fn test_utp_socket_handshake_data_and_teardown_over_udp() {
    let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let server_addr = server_sock.local_addr().unwrap();
    let client_addr = client_sock.local_addr().unwrap();

    // 1. Client initiates SYN
    let mut client = UtpConnection::new_outgoing(0x9999);
    let syn_pkt = client.build_syn_packet();
    client_sock.send_to(&syn_pkt.encode(), server_addr).await.unwrap();

    // 2. Server receives SYN
    let mut buf = vec![0u8; 2048];
    let (len, src) = timeout(Duration::from_secs(2), server_sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(src, client_addr);

    let syn_received = UtpPacket::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
    assert_eq!(syn_received.header.ptype, UtpType::Syn);

    let mut server = UtpConnection::new_incoming(&syn_received);
    assert_eq!(server.state, UtpConnectionState::Connected);

    let state_pkt = server.build_state_packet();
    server_sock.send_to(&state_pkt.encode(), client_addr).await.unwrap();

    // 3. Client receives STATE (ACK) -> enters Connected
    let (len, _) = timeout(Duration::from_secs(2), client_sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let state_received = UtpPacket::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
    client.on_packet_recv(&state_received).unwrap();
    assert_eq!(client.state, UtpConnectionState::Connected);

    // 4. Client sends DATA packet
    let payload = Bytes::from_static(b"streaming bittorrent payload via uTP LEDBAT");
    let data_pkt = client.build_data_packet(payload.clone());
    client_sock.send_to(&data_pkt.encode(), server_addr).await.unwrap();

    // 5. Server receives DATA
    let (len, _) = timeout(Duration::from_secs(2), server_sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let data_received = UtpPacket::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
    let extracted = server.on_packet_recv(&data_received).unwrap().unwrap();
    assert_eq!(extracted, payload);

    // 6. Server sends ACK back
    let ack_pkt = server.build_state_packet();
    server_sock.send_to(&ack_pkt.encode(), client_addr).await.unwrap();

    let (len, _) = timeout(Duration::from_secs(2), client_sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let ack_received = UtpPacket::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
    client.on_packet_recv(&ack_received).unwrap();

    // 7. Client sends FIN
    let fin_pkt = client.build_fin_packet();
    client_sock.send_to(&fin_pkt.encode(), server_addr).await.unwrap();

    let (len, _) = timeout(Duration::from_secs(2), server_sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let fin_received = UtpPacket::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
    server.on_packet_recv(&fin_received).unwrap();
    assert_eq!(server.state, UtpConnectionState::Closed);
}
