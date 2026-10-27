use synapse_wire::{mse_handshake_receiver, EncryptionMode};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn forced_encrypted_rejects_plaintext_handshake_fast() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let start = std::time::Instant::now();
        let res = mse_handshake_receiver(stream, EncryptionMode::ForcedEncrypted, |_h| None).await;
        (res.is_err(), start.elapsed())
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut handshake = vec![19u8];
    handshake.extend_from_slice(b"BitTorrent protocol");
    handshake.extend_from_slice(&[0u8; 8]); // reserved
    handshake.extend_from_slice(&[0xAA; 20]); // info_hash
    handshake.extend_from_slice(&[0xBB; 20]); // peer_id
    assert_eq!(handshake.len(), 68);
    client.write_all(&handshake).await.unwrap();
    client.flush().await.unwrap();

    let (was_err, elapsed) = server.await.unwrap();
    eprintln!("was_err={was_err} elapsed={elapsed:?}");
    assert!(was_err, "ForcedEncrypted must reject a plaintext handshake");
    assert!(
        elapsed.as_secs() < 2,
        "rejection took {elapsed:?}, expected near-instant (fast prefix check, no timeout needed)"
    );
}
