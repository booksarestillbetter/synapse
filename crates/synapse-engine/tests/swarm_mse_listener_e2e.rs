//! The engine's real inbound listener (`SwarmEngine::start_listener`) must complete MSE
//! handshakes, resolve the torrent through its req2 index, and enforce the configured
//! encryption policy. Earlier MSE tests only drove `accept_router_*` directly.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest, Sha1};
use tokio::sync::mpsc;

use diskio::DiskEngine;
use synapse_bencode::BEncode;
use synapse_engine::{connect_with_mode, PeerEvent, SessionSettingsUpdate, SwarmEngine};
use synapse_meta::Info;
use synapse_wire::EncryptionMode;

fn info() -> Info {
    let data = vec![3u8; 32 * 1024];
    let pieces: Vec<u8> = data
        .chunks(16 * 1024)
        .flat_map(|c| Sha1::digest(c).to_vec())
        .collect();
    let d = BTreeMap::from([
        (b"name".to_vec(), BEncode::String(b"t.bin".to_vec())),
        (b"piece length".to_vec(), BEncode::Int(16 * 1024)),
        (b"pieces".to_vec(), BEncode::String(pieces)),
        (b"length".to_vec(), BEncode::Int(data.len() as i64)),
    ]);
    Info::from_bencode(BEncode::Dict(BTreeMap::from([(
        b"info".to_vec(),
        BEncode::Dict(d),
    )])))
    .unwrap()
}

async fn engine_with_listener(
    policy: &str,
) -> (
    Arc<SwarmEngine>,
    std::net::SocketAddr,
    [u8; 20],
    tempfile::TempDir,
) {
    let engine = Arc::new(SwarmEngine::new(
        Arc::new(DiskEngine::auto().await),
        [4u8; 20],
    ));
    engine.update_session_settings(SessionSettingsUpdate {
        encryption: Some(policy.to_string()),
        ..Default::default()
    });
    let dir = tempfile::tempdir().unwrap();
    let info = info();
    let hash = info.hash;
    engine.add_torrent(Arc::new(info), dir.path().to_path_buf(), None);
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    engine.clone().start_listener(addr).await.unwrap();
    (engine, addr, hash, dir)
}

async fn dial(addr: std::net::SocketAddr, hash: [u8; 20], mode: EncryptionMode) -> bool {
    let (tx, mut rx) = mpsc::channel::<PeerEvent>(16);
    let res = tokio::time::timeout(
        Duration::from_secs(8),
        connect_with_mode(addr, [7u8; 20], hash, false, tx, mode),
    )
    .await;
    // Keep any Connected handle alive until the handshake result is known.
    let _ = rx.try_recv();
    matches!(res, Ok(Ok(())))
}

#[tokio::test(flavor = "multi_thread")]
async fn listener_completes_forced_mse_for_a_registered_torrent() {
    let (_e, addr, hash, _d) = engine_with_listener("prefer_encrypted").await;
    assert!(
        dial(addr, hash, EncryptionMode::ForcedEncrypted).await,
        "MSE handshake with the real listener failed"
    );
    assert!(
        dial(addr, hash, EncryptionMode::PlaintextOnly).await,
        "prefer_encrypted must still accept plaintext peers"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn listener_rejects_mse_for_an_unknown_torrent() {
    let (_e, addr, _hash, _d) = engine_with_listener("prefer_encrypted").await;
    assert!(!dial(addr, [0x55; 20], EncryptionMode::ForcedEncrypted).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn encryption_policy_is_enforced_by_the_listener() {
    let (_e, addr, hash, _d) = engine_with_listener("require_encrypted").await;
    assert!(dial(addr, hash, EncryptionMode::ForcedEncrypted).await);
    assert!(
        !dial(addr, hash, EncryptionMode::PlaintextOnly).await,
        "require_encrypted must refuse a plaintext peer"
    );

    let (_e2, addr2, hash2, _d2) = engine_with_listener("plaintext_only").await;
    assert!(dial(addr2, hash2, EncryptionMode::PlaintextOnly).await);
    assert!(
        !dial(addr2, hash2, EncryptionMode::ForcedEncrypted).await,
        "plaintext_only must refuse an encrypted peer"
    );
}
