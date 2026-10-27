//! Validates that two peers both configured for `ForcedEncrypted` can actually complete
//! a real MSE handshake end-to-end (not just that plaintext gets rejected).

use synapse_wire::{
    mse_handshake_initiator, mse_handshake_receiver, EncryptionMode, ReceiverHandshakeResult,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn forced_encrypted_to_forced_encrypted_completes_over_real_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let info_hash = [0x42u8; 20];

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let target_req2 = synapse_wire::mse_req2(&info_hash);
        let res = mse_handshake_receiver(stream, EncryptionMode::ForcedEncrypted, |r2| {
            (*r2 == target_req2).then_some(info_hash)
        })
        .await;
        match res {
            Ok(ReceiverHandshakeResult::Encrypted {
                mut stream,
                initial_payload,
                ..
            }) => {
                let mut rest = vec![0u8; initial_payload.len()];
                stream.read_exact(&mut rest).await.unwrap();
                stream.write_all(b"server_reply").await.unwrap();
                stream.flush().await.unwrap();
                Ok(())
            }
            Ok(ReceiverHandshakeResult::Plaintext { .. }) => {
                Err("got plaintext, not encrypted".to_string())
            }
            Err(e) => Err(format!("receiver error: {e}")),
        }
    });

    let client = TcpStream::connect(addr).await.unwrap();
    let client_res = mse_handshake_initiator(
        client,
        info_hash,
        EncryptionMode::ForcedEncrypted,
        b"client_payload_68_bytes_padded_to_match_a_real_bt_handshake!!",
    )
    .await;

    let server_res = server.await.unwrap();
    assert!(server_res.is_ok(), "server side failed: {server_res:?}");

    let mut stream = client_res.expect("initiator must complete a ForcedEncrypted handshake");
    assert!(stream.is_encrypted());
    let mut reply = [0u8; 12];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"server_reply");
}
