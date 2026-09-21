use bytes::Bytes;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use synapse_engine::{
    accept_router_with_candidates, connect_with_options, PeerEvent, UtpConnection,
    UtpConnectionState, UtpSocketManager,
};
use synapse_wire::{EncryptionMode, Message, UtpPacket, UtpType};

#[tokio::test]
async fn test_utp_socket_handshake_data_and_teardown_over_udp() {
    let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let server_addr = server_sock.local_addr().unwrap();
    let client_addr = client_sock.local_addr().unwrap();

    // 1. Client initiates SYN
    let mut client = UtpConnection::new_outgoing(0x9999);
    let syn_pkt = client.build_syn_packet();
    client_sock
        .send_to(&syn_pkt.encode(), server_addr)
        .await
        .unwrap();

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
    server_sock
        .send_to(&state_pkt.encode(), client_addr)
        .await
        .unwrap();

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
    client_sock
        .send_to(&data_pkt.encode(), server_addr)
        .await
        .unwrap();

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
    server_sock
        .send_to(&ack_pkt.encode(), client_addr)
        .await
        .unwrap();

    let (len, _) = timeout(Duration::from_secs(2), client_sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let ack_received = UtpPacket::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
    client.on_packet_recv(&ack_received).unwrap();

    // 7. Client sends FIN
    let fin_pkt = client.build_fin_packet();
    client_sock
        .send_to(&fin_pkt.encode(), server_addr)
        .await
        .unwrap();

    let (len, _) = timeout(Duration::from_secs(2), server_sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let fin_received = UtpPacket::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
    server.on_packet_recv(&fin_received).unwrap();
    assert_eq!(server.state, UtpConnectionState::Closed);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_utp_bittorrent_handshake_and_messages_over_utp() {
    let server_mgr = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let client_mgr = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let server_addr = server_mgr.local_addr();
    let info_hash = [0x55u8; 20];
    let server_peer_id = [0x11u8; 20];
    let client_peer_id = [0x22u8; 20];

    let (server_tx, mut server_rx) = mpsc::channel(16);
    let (client_tx, mut client_rx) = mpsc::channel(16);

    let server_ih = info_hash;
    let s_mgr = server_mgr.clone();
    let server_task = tokio::spawn(async move {
        let (stream, remote_addr) = timeout(Duration::from_secs(5), s_mgr.accept())
            .await
            .unwrap()
            .unwrap();
        accept_router_with_candidates(
            stream,
            remote_addr,
            server_peer_id,
            vec![server_ih],
            move |ih| {
                if ih == server_ih {
                    Some((server_tx, false))
                } else {
                    None
                }
            },
            EncryptionMode::PlaintextOnly,
        )
        .await
        .unwrap();
    });

    let c_mgr = client_mgr.clone();
    let client_task = tokio::spawn(async move {
        connect_with_options(
            server_addr,
            client_peer_id,
            info_hash,
            false,
            client_tx,
            EncryptionMode::PlaintextOnly,
            Some(c_mgr),
        )
        .await
        .unwrap();
    });

    client_task.await.unwrap();
    server_task.await.unwrap();

    let server_connected = timeout(Duration::from_secs(2), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let client_connected = timeout(Duration::from_secs(2), client_rx.recv())
        .await
        .unwrap()
        .unwrap();

    let server_handle = match server_connected {
        PeerEvent::Connected(handle, info) => {
            assert_eq!(info.peer_id, client_peer_id);
            handle
        }
        _ => panic!("Expected Connected event on server"),
    };

    let client_handle = match client_connected {
        PeerEvent::Connected(handle, info) => {
            assert_eq!(info.peer_id, server_peer_id);
            handle
        }
        _ => panic!("Expected Connected event on client"),
    };

    // Client sends Have message over uTP
    client_handle.send(Message::Have(42)).await;

    // Server receives Have message over uTP
    let msg_on_server = timeout(Duration::from_secs(2), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match msg_on_server {
        PeerEvent::Message(_peer_id, Message::Have(piece_index)) => {
            assert_eq!(piece_index, 42);
        }
        other => panic!("Unexpected peer event on server: {:?}", other),
    }

    // Server sends Bitfield message over uTP
    let bitfield = Bytes::from_static(&[0b10101010, 0b11110000]);
    server_handle
        .send(Message::Bitfield(bitfield.clone()))
        .await;

    // Client receives Bitfield over uTP
    let msg_on_client = timeout(Duration::from_secs(2), client_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match msg_on_client {
        PeerEvent::Message(_peer_id, Message::Bitfield(bf)) => {
            assert_eq!(&bf[..], &bitfield[..]);
        }
        other => panic!("Unexpected peer event on client: {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_utp_mse_encrypted_stream_over_utp() {
    let server_mgr = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let client_mgr = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let server_addr = server_mgr.local_addr();
    let info_hash = [0x77u8; 20];
    let server_peer_id = [0x33u8; 20];
    let client_peer_id = [0x44u8; 20];

    let (server_tx, mut server_rx) = mpsc::channel(16);
    let (client_tx, mut client_rx) = mpsc::channel(16);

    let server_ih = info_hash;
    let s_mgr = server_mgr.clone();
    let server_task = tokio::spawn(async move {
        let (stream, remote_addr) = timeout(Duration::from_secs(5), s_mgr.accept())
            .await
            .unwrap()
            .unwrap();
        accept_router_with_candidates(
            stream,
            remote_addr,
            server_peer_id,
            vec![server_ih],
            move |ih| {
                if ih == server_ih {
                    Some((server_tx, false))
                } else {
                    None
                }
            },
            EncryptionMode::ForcedEncrypted,
        )
        .await
        .unwrap();
    });

    let c_mgr = client_mgr.clone();
    let client_task = tokio::spawn(async move {
        connect_with_options(
            server_addr,
            client_peer_id,
            info_hash,
            false,
            client_tx,
            EncryptionMode::ForcedEncrypted,
            Some(c_mgr),
        )
        .await
        .unwrap();
    });

    client_task.await.unwrap();
    server_task.await.unwrap();

    let server_connected = timeout(Duration::from_secs(2), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let client_connected = timeout(Duration::from_secs(2), client_rx.recv())
        .await
        .unwrap()
        .unwrap();

    let server_handle = match server_connected {
        PeerEvent::Connected(h, _) => h,
        _ => panic!("Expected Connected event on server"),
    };
    let client_handle = match client_connected {
        PeerEvent::Connected(h, _) => h,
        _ => panic!("Expected Connected event on client"),
    };

    client_handle.send(Message::Have(999)).await;
    let event = timeout(Duration::from_secs(2), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match event {
        PeerEvent::Message(_peer_id, Message::Have(piece_index)) => assert_eq!(piece_index, 999),
        other => panic!("Unexpected event: {:?}", other),
    }

    server_handle.send(Message::Unchoke).await;
    let event = timeout(Duration::from_secs(2), client_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match event {
        PeerEvent::Message(_peer_id, Message::Unchoke) => {}
        other => panic!("Unexpected event: {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_utp_dial_fallback_to_tcp_when_udp_unreachable() {
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();

    let client_mgr = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let info_hash = [0x88u8; 20];
    let server_peer_id = [0x55u8; 20];
    let client_peer_id = [0x66u8; 20];

    let (server_tx, mut server_rx) = mpsc::channel(16);
    let (client_tx, mut client_rx) = mpsc::channel(16);

    let server_ih = info_hash;
    let server_task = tokio::spawn(async move {
        let (tcp_stream, remote_addr) = timeout(Duration::from_secs(5), tcp_listener.accept())
            .await
            .unwrap()
            .unwrap();
        accept_router_with_candidates(
            tcp_stream,
            remote_addr,
            server_peer_id,
            vec![server_ih],
            move |ih| {
                if ih == server_ih {
                    Some((server_tx, false))
                } else {
                    None
                }
            },
            EncryptionMode::PlaintextOnly,
        )
        .await
        .unwrap();
    });

    let client_task = tokio::spawn(async move {
        connect_with_options(
            tcp_addr,
            client_peer_id,
            info_hash,
            false,
            client_tx,
            EncryptionMode::PlaintextOnly,
            Some(client_mgr),
        )
        .await
        .unwrap();
    });

    client_task.await.unwrap();
    server_task.await.unwrap();

    let server_connected = timeout(Duration::from_secs(2), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let client_connected = timeout(Duration::from_secs(2), client_rx.recv())
        .await
        .unwrap()
        .unwrap();

    match server_connected {
        PeerEvent::Connected(_, info) => assert_eq!(info.peer_id, client_peer_id),
        _ => panic!("Expected Connected on server"),
    }
    match client_connected {
        PeerEvent::Connected(_, info) => assert_eq!(info.peer_id, server_peer_id),
        _ => panic!("Expected Connected on client"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reader_that_falls_behind_cannot_make_the_receiver_buffer_without_bound() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let client = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let server_addr = server.local_addr();

    let accepted = tokio::spawn({
        let server = server.clone();
        async move { server.accept().await.unwrap().0 }
    });
    let mut c = client.connect(server_addr).await.unwrap();
    let mut s = accepted.await.unwrap();

    let data: Vec<u8> = (0..3 * 1024 * 1024usize).map(|i| (i % 253) as u8).collect();
    let to_send = data.clone();
    let writer = tokio::spawn(async move {
        c.write_all(&to_send).await.unwrap();
        c.flush().await.unwrap();
        c
    });

    // The receiver does not read for a while: its buffer fills to the cap and stops there.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let buffered = s.buffered_bytes();
    assert!(buffered > 0, "nothing arrived");
    assert!(
        buffered <= synapse_engine::utp::RECV_BUFFER_CAP,
        "receive buffer grew to {buffered} bytes, past the {} byte cap",
        synapse_engine::utp::RECV_BUFFER_CAP
    );

    // Once it reads, the rest is retransmitted and arrives intact.
    let mut got = vec![0u8; data.len()];
    timeout(Duration::from_secs(90), s.read_exact(&mut got))
        .await
        .expect("transfer did not finish after the reader caught up")
        .unwrap();
    assert!(got == data, "data corrupted or reordered");
    let _ = writer.await;
}

/// Bulk data through a real uTP connection. Until the send queue was fixed, anything larger than
/// the initial congestion window was silently truncated and the transfer stalled forever; the
/// other uTP tests only ever sent a few bytes.
#[tokio::test(flavor = "multi_thread")]
async fn multi_megabyte_transfers_arrive_complete_and_in_order_in_both_directions() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let client = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let server_addr = server.local_addr();
    let accepted = tokio::spawn({
        let server = server.clone();
        async move { server.accept().await.unwrap().0 }
    });
    let mut c = client.connect(server_addr).await.unwrap();
    let mut s = accepted.await.unwrap();

    let up: Vec<u8> = (0..4 * 1024 * 1024usize).map(|i| (i % 251) as u8).collect();
    let down: Vec<u8> = (0..2 * 1024 * 1024usize)
        .map(|i| (i * 7 % 253) as u8)
        .collect();
    let (up_c, down_s) = (up.clone(), down.clone());

    let (mut c_read, mut c_write) = tokio::io::split(&mut c);
    let (mut s_read, mut s_write) = tokio::io::split(&mut s);
    let run = async {
        tokio::join!(
            async {
                c_write.write_all(&up_c).await.unwrap();
                c_write.flush().await.unwrap();
            },
            async {
                s_write.write_all(&down_s).await.unwrap();
                s_write.flush().await.unwrap();
            },
            async {
                let mut got = vec![0u8; up.len()];
                s_read.read_exact(&mut got).await.unwrap();
                assert!(got == up, "client->server data corrupted");
            },
            async {
                let mut got = vec![0u8; down.len()];
                c_read.read_exact(&mut got).await.unwrap();
                assert!(got == down, "server->client data corrupted");
            },
        )
    };
    timeout(Duration::from_secs(60), run)
        .await
        .expect("bulk transfer did not complete");
}

/// A UDP relay that drops, delays (so reorders) and duplicates datagrams between one client and
/// one server, to exercise retransmission, SACK and reassembly.
async fn lossy_relay(
    server: std::net::SocketAddr,
    drop_pct: u32,
    max_delay_ms: u64,
) -> std::net::SocketAddr {
    use rand::Rng;
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let mut client: Option<std::net::SocketAddr> = None;
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let to = if from == server {
                match client {
                    Some(c) => c,
                    None => continue,
                }
            } else {
                client = Some(from);
                server
            };
            let (drop, delay, dup) = {
                let mut r = rand::thread_rng();
                (
                    r.gen_range(0..100) < drop_pct,
                    r.gen_range(0..=max_delay_ms),
                    r.gen_range(0..100) < 2,
                )
            };
            if drop {
                continue;
            }
            let data = buf[..n].to_vec();
            let sock = sock.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                let _ = sock.send_to(&data, to).await;
                if dup {
                    let _ = sock.send_to(&data, to).await;
                }
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn a_transfer_over_a_lossy_reordering_path_still_arrives_intact() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let relay = lossy_relay(server.local_addr(), 5, 15).await;
    let client = UtpSocketManager::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let accepted = tokio::spawn({
        let server = server.clone();
        async move { server.accept().await.unwrap().0 }
    });
    let mut c = client.connect(relay).await.unwrap();
    let mut s = accepted.await.unwrap();

    let data: Vec<u8> = (0..1024 * 1024usize)
        .map(|i| (i * 31 % 251) as u8)
        .collect();
    let to_send = data.clone();
    let writer = tokio::spawn(async move {
        c.write_all(&to_send).await.unwrap();
        c.flush().await.unwrap();
        c
    });
    let mut got = vec![0u8; data.len()];
    timeout(Duration::from_secs(120), s.read_exact(&mut got))
        .await
        .expect("transfer stalled on a lossy path")
        .unwrap();
    assert!(got == data, "data corrupted or reordered on a lossy path");
    let _ = writer.await;
}
