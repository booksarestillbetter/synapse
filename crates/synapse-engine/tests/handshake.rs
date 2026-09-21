//! Handshake-level tests that don't need a full `Torrent` - just the connect/accept
//! handshake exchange in `synapse_engine::{connect, accept}`.

use tokio::net::TcpListener;
use tokio::sync::mpsc;

#[tokio::test(flavor = "multi_thread")]
async fn accept_rejects_an_unrecognized_info_hash() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let known_hash = [7u8; 20];
    let wrong_hash = [9u8; 20];

    let accept_task = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        let (tx, _rx) = mpsc::channel(1);
        synapse_engine::accept(stream, peer_addr, [1u8; 20], known_hash, false, tx).await
    });

    let (tx, _rx) = mpsc::channel(1);
    let connect_result = synapse_engine::connect(addr, [2u8; 20], wrong_hash, false, tx).await;

    let accept_result = accept_task.await.unwrap();
    assert!(
        accept_result.is_err(),
        "accept should reject an unknown info hash"
    );
    // The connecting side's handshake read then fails too, since the acceptor closes
    // the connection instead of replying (see `synapse_engine::accept`).
    assert!(connect_result.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_rejects_a_mismatched_response_hash() {
    // A "peer" that replies with a different info hash than the one we asked for -
    // simulates a buggy or malicious remote, not exercised by `accept` (which only
    // ever echoes back the hash it was given, so it can't produce this case itself).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requested_hash = [3u8; 20];
    let replied_hash = [4u8; 20];

    let server = tokio::spawn(async move {
        use futures::{SinkExt, StreamExt};
        use tokio_util::codec::Framed;
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut framed = Framed::new(stream, synapse_wire::PeerCodec::new());
        let _their_handshake = framed.next().await.unwrap().unwrap();
        framed
            .send(synapse_wire::Message::Handshake {
                reserved: [0; 8],
                info_hash: replied_hash,
                peer_id: [5u8; 20],
            })
            .await
            .unwrap();
    });

    let (tx, _rx) = mpsc::channel(1);
    let result = synapse_engine::connect_with_mode(
        addr,
        [6u8; 20],
        requested_hash,
        false,
        tx,
        synapse_wire::EncryptionMode::PlaintextOnly,
    )
    .await;
    assert!(
        result.is_err(),
        "connect must reject a reply for the wrong info hash"
    );
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_clears_dht_bit_for_private_swarm() {
    use futures::{SinkExt, StreamExt};
    use tokio_util::codec::Framed;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let info_hash = [0x55; 20];

    // 1. Outbound connect() with is_private = true
    let server = tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut framed = Framed::new(stream, synapse_wire::PeerCodec::new());
        let msg = framed.next().await.unwrap().unwrap();
        if let synapse_wire::Message::Handshake { reserved, .. } = msg {
            // BEP 27 invariant: DHT bit MUST be 0
            assert_eq!(
                reserved[7] & 0x01,
                0,
                "DHT bit must be cleared for private swarm"
            );
            // BEP 10 extension bit
            assert_eq!(
                reserved[5] & 0x10,
                0x10,
                "BEP 10 extension protocol must be set"
            );
            // BEP 6 fast extension bit
            assert_eq!(reserved[7] & 0x04, 0x04, "BEP 6 fast extension must be set");
        } else {
            panic!("Expected Handshake message");
        }

        // Echo valid handshake back so connect() succeeds
        framed
            .send(synapse_wire::Message::Handshake {
                reserved: [0; 8],
                info_hash,
                peer_id: [0x99; 20],
            })
            .await
            .unwrap();
    });

    let (tx, _rx) = mpsc::channel(1);
    let res = synapse_engine::connect_with_mode(
        addr,
        [0x11; 20],
        info_hash,
        true,
        tx,
        synapse_wire::EncryptionMode::PlaintextOnly,
    )
    .await;
    assert!(res.is_ok());
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_sets_dht_bit_for_public_swarm() {
    use futures::{SinkExt, StreamExt};
    use tokio_util::codec::Framed;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let info_hash = [0x77; 20];

    // Outbound connect() with is_private = false
    let server = tokio::spawn(async move {
        let (stream, _addr) = listener.accept().await.unwrap();
        let mut framed = Framed::new(stream, synapse_wire::PeerCodec::new());
        let msg = framed.next().await.unwrap().unwrap();
        if let synapse_wire::Message::Handshake { reserved, .. } = msg {
            // Public swarm: DHT bit is 1
            assert_eq!(
                reserved[7] & 0x01,
                0x01,
                "DHT bit must be set for public swarm"
            );
            assert_eq!(reserved[5] & 0x10, 0x10);
            assert_eq!(reserved[7] & 0x04, 0x04);
        } else {
            panic!("Expected Handshake message");
        }

        framed
            .send(synapse_wire::Message::Handshake {
                reserved: [0; 8],
                info_hash,
                peer_id: [0x88; 20],
            })
            .await
            .unwrap();
    });

    let (tx, _rx) = mpsc::channel(1);
    let res = synapse_engine::connect_with_mode(
        addr,
        [0x22; 20],
        info_hash,
        false,
        tx,
        synapse_wire::EncryptionMode::PlaintextOnly,
    )
    .await;
    assert!(res.is_ok());
    server.await.unwrap();
}
