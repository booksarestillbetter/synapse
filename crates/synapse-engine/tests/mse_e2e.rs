//! End-to-end integration tests for Message Stream Encryption (MSE / RC4 - BEP 8).
//!
//! Validates encrypted Diffie-Hellman handshake, plaintext backward-compatibility fallback,
//! forced encryption gating, and transmission of encrypted wire messages over real TCP sockets.

use std::time::Duration;
use synapse_engine::{accept_router_with_candidates, connect_with_mode, PeerEvent};
use synapse_wire::{EncryptionMode, Message};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

#[tokio::test(flavor = "multi_thread")]
async fn test_mse_e2e_both_prefer_encrypted() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let info_hash = [0x42u8; 20];
    let server_peer_id = [0x11u8; 20];
    let client_peer_id = [0x22u8; 20];

    let (server_tx, mut server_rx) = mpsc::channel(16);
    let (client_tx, mut client_rx) = mpsc::channel(16);

    let server_ih = info_hash;
    let server_task = tokio::spawn(async move {
        let (socket, remote_addr) = listener.accept().await.unwrap();
        let res = accept_router_with_candidates(
            socket,
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
            EncryptionMode::PreferEncrypted,
        )
        .await;
        res.unwrap();
    });

    let client_task = tokio::spawn(async move {
        connect_with_mode(
            addr,
            client_peer_id,
            info_hash,
            false,
            client_tx,
            EncryptionMode::PreferEncrypted,
        )
        .await
        .unwrap();
    });

    client_task.await.unwrap();
    server_task.await.unwrap();

    // Verify both sides received PeerEvent::Connected with is_encrypted == true
    let server_conn = tokio::time::timeout(Duration::from_secs(3), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let client_conn = tokio::time::timeout(Duration::from_secs(3), client_rx.recv())
        .await
        .unwrap()
        .unwrap();

    let (server_handle, server_info) = match server_conn {
        PeerEvent::Connected(h, info) => (h, info),
        other => panic!("Expected Connected event on server, got {:?}", other),
    };

    let (client_handle, client_info) = match client_conn {
        PeerEvent::Connected(h, info) => (h, info),
        other => panic!("Expected Connected event on client, got {:?}", other),
    };

    assert!(
        server_info.is_encrypted,
        "Server peer connection should be flagged as encrypted"
    );
    assert!(
        client_info.is_encrypted,
        "Client peer connection should be flagged as encrypted"
    );
    assert_eq!(server_info.peer_id, client_peer_id);
    assert_eq!(client_info.peer_id, server_peer_id);

    // Verify bidirectional encrypted data transmission
    client_handle.send(Message::Have(99)).await;
    let received_on_server = tokio::time::timeout(Duration::from_secs(3), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match received_on_server {
        PeerEvent::Message(peer_id, Message::Have(piece_index)) => {
            assert_eq!(peer_id, server_handle.id);
            assert_eq!(piece_index, 99);
        }
        other => panic!("Expected Have message on server, got {:?}", other),
    }

    server_handle.send(Message::Have(100)).await;
    let received_on_client = tokio::time::timeout(Duration::from_secs(3), client_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match received_on_client {
        PeerEvent::Message(peer_id, Message::Have(piece_index)) => {
            assert_eq!(peer_id, client_handle.id);
            assert_eq!(piece_index, 100);
        }
        other => panic!("Expected Have message on client, got {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mse_e2e_forced_encryption_rejects_plaintext_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let info_hash = [0x55u8; 20];
    let server_peer_id = [0x33u8; 20];
    let client_peer_id = [0x44u8; 20];

    let (server_tx, _server_rx) = mpsc::channel(16);
    let (client_tx, _client_rx) = mpsc::channel(16);

    let server_ih = info_hash;
    let server_task = tokio::spawn(async move {
        let (socket, remote_addr) = listener.accept().await.unwrap();
        accept_router_with_candidates(
            socket,
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
    });

    let client_task = tokio::spawn(async move {
        connect_with_mode(
            addr,
            client_peer_id,
            info_hash,
            false,
            client_tx,
            EncryptionMode::PlaintextOnly,
        )
        .await
    });

    let client_res = client_task.await.unwrap();
    let server_res = server_task.await.unwrap();

    assert!(
        server_res.is_err(),
        "ForcedEncrypted server must reject plaintext peer"
    );
    assert!(
        client_res.is_err(),
        "Plaintext client must fail when connecting to ForcedEncrypted server"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mse_e2e_prefer_encrypted_accepts_plaintext_fallback() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let info_hash = [0x66u8; 20];
    let server_peer_id = [0x55u8; 20];
    let client_peer_id = [0x66u8; 20];

    let (server_tx, mut server_rx) = mpsc::channel(16);
    let (client_tx, mut client_rx) = mpsc::channel(16);

    let server_ih = info_hash;
    let server_task = tokio::spawn(async move {
        let (socket, remote_addr) = listener.accept().await.unwrap();
        let res = accept_router_with_candidates(
            socket,
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
            EncryptionMode::PreferEncrypted,
        )
        .await;
        res.unwrap();
    });

    let client_task = tokio::spawn(async move {
        connect_with_mode(
            addr,
            client_peer_id,
            info_hash,
            false,
            client_tx,
            EncryptionMode::PlaintextOnly,
        )
        .await
        .unwrap();
    });

    client_task.await.unwrap();
    server_task.await.unwrap();

    let server_conn = tokio::time::timeout(Duration::from_secs(3), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let client_conn = tokio::time::timeout(Duration::from_secs(3), client_rx.recv())
        .await
        .unwrap()
        .unwrap();

    let (server_handle, server_info) = match server_conn {
        PeerEvent::Connected(h, info) => (h, info),
        other => panic!("Expected Connected event on server, got {:?}", other),
    };

    let (client_handle, client_info) = match client_conn {
        PeerEvent::Connected(h, info) => (h, info),
        other => panic!("Expected Connected event on client, got {:?}", other),
    };

    // Plaintext fallback -> is_encrypted is false
    assert!(
        !server_info.is_encrypted,
        "Server should identify connection as plaintext"
    );
    assert!(
        !client_info.is_encrypted,
        "Client should identify connection as plaintext"
    );

    // Communication works
    client_handle.send(Message::KeepAlive).await;
    let received_on_server = tokio::time::timeout(Duration::from_secs(3), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match received_on_server {
        PeerEvent::Message(peer_id, Message::KeepAlive) => {
            assert_eq!(peer_id, server_handle.id);
        }
        other => panic!("Expected KeepAlive on server, got {:?}", other),
    }

    server_handle.send(Message::KeepAlive).await;
    let received_on_client = tokio::time::timeout(Duration::from_secs(3), client_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match received_on_client {
        PeerEvent::Message(peer_id, Message::KeepAlive) => {
            assert_eq!(peer_id, client_handle.id);
        }
        other => panic!("Expected KeepAlive on client, got {:?}", other),
    }
}
