//! The inbound listener must bound work done for connections that never complete a
//! handshake: a flood of silent sockets must not pile up unbounded handshake tasks.

use std::sync::Arc;
use std::time::Duration;

use diskio::DiskEngine;
use synapse_engine::SwarmEngine;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

#[tokio::test(flavor = "multi_thread")]
async fn flood_of_silent_connections_is_capped_at_the_pending_handshake_limit() {
    let swarm = Arc::new(SwarmEngine::new(
        Arc::new(DiskEngine::auto().await),
        [3u8; 20],
    ));
    // Reserve a free port, release it, and have the engine listen there.
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let _listener = swarm.clone().start_listener(addr).await.unwrap();

    // Open well over the limit without ever sending a handshake.
    let mut socks = Vec::new();
    for _ in 0..400 {
        socks.push(TcpStream::connect(addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Connections refused at accept are closed by the server almost immediately (EOF/reset),
    // while those holding a handshake slot stay open waiting for our handshake.
    let mut closed = 0;
    for s in socks.iter_mut() {
        let mut b = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(50), s.read(&mut b)).await {
            Ok(Ok(0)) | Ok(Err(_)) => closed += 1,
            _ => {}
        }
    }
    assert!(
        closed >= 400 - 256 - 5,
        "expected the excess connections to be refused, only {closed} were"
    );
    assert!(
        closed < 400,
        "connections within the limit must be allowed to wait for a handshake"
    );
}
