//! End-to-end integration test verifying BEP 55 `ut_holepunch` extension relay and rendezvous coordination.
//!
//! Validates:
//! 1. Extension handshake exchange negotiating `ut_holepunch`.
//! 2. Relay coordination: Peer A requests Rendezvous for Peer B; Relay sends Connect to both peers.
//! 3. Error reporting: Relay returns `Failed { err_code: 1 }` (NoSuchPeer) when the requested target is not connected.
//! 4. Inbound Connect message triggers peer discovery channel for uTP dialing.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

use diskio::DiskEngine;
use synapse_bencode::BEncode;
use synapse_engine::{SwarmState, SwarmStats, SwarmTier, TokenBucket, Torrent, TorrentConfig};
use synapse_meta::Info;
use synapse_picker::{Mode, RoaringBitfield};
use synapse_wire::{ExtensionHandshake, HolepunchMessage, Message, PeerCodec};

fn fresh_stats(info: &Info, download_dir: &Path) -> Arc<parking_lot::RwLock<SwarmStats>> {
    Arc::new(parking_lot::RwLock::new(SwarmStats {
        name: info.name.clone(),
        info_hash: info.hash,
        total_size: info.total_len,
        progress: 1.0,
        state: SwarmState::Seeding,
        tier: SwarmTier::Hot,
        download_rate: 0,
        upload_rate: 0,
        downloaded_bytes: info.total_len,
        uploaded_bytes: 0,
        peers_connected: 0,
        peers_sending: 0,
        eta_seconds: 0,
        ratio: 0.0,
        download_dir: download_dir.to_string_lossy().to_string(),
        added_at: 0,
        is_private: info.private,
        is_stalled: false,
        last_transfer_at: 0,
        piece_count: info.pieces(),
        piece_size: info.piece_len,
    }))
}

fn build_test_info() -> Info {
    let mut info_dict = BTreeMap::new();
    info_dict.insert(b"name".to_vec(), BEncode::String(b"hp_test".to_vec()));
    info_dict.insert(b"piece length".to_vec(), BEncode::Int(16384));
    info_dict.insert(b"pieces".to_vec(), BEncode::String(vec![0x42; 20]));
    info_dict.insert(b"length".to_vec(), BEncode::Int(16384));

    let mut top_dict = BTreeMap::new();
    top_dict.insert(b"info".to_vec(), BEncode::Dict(info_dict));

    Info::from_bencode(BEncode::Dict(top_dict)).expect("valid test info")
}

#[tokio::test]
async fn test_bep55_holepunch_rendezvous_relay_and_discovery() {
    let temp_dir = tempfile::tempdir().unwrap();
    let info = build_test_info();
    let relay_peer_id = [0x11; 20];
    let (peer_tx, peer_rx) = tokio::sync::mpsc::channel(64);
    let (_cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(1);
    let (disco_tx, mut disco_rx) = tokio::sync::mpsc::channel(16);

    let stats = fresh_stats(&info, temp_dir.path());
    let mut have = synapse_picker::Bitfield::new(info.pieces() as usize);
    have.set(0);

    let disk = Arc::new(DiskEngine::auto().await);
    let config = TorrentConfig {
        info: Arc::new(info.clone()),
        download_dir: temp_dir.path().to_path_buf(),
        peer_id: relay_peer_id,
        disk,
        mode: Mode::RarestFirst,
        max_pipeline: 8,
        regular_unchokes: 4,
        optimistic_unchoke_interval: Duration::from_secs(60),
        tick_interval: Duration::from_millis(50),
        on_torrent_completed: None,
        on_piece_completed: None,
        stats,
        bitfield: Arc::new(parking_lot::RwLock::new(Some(
            RoaringBitfield::from_bitfield(&have),
        ))),
        download_bucket: Arc::new(TokenBucket::unthrottled()),
        upload_bucket: Arc::new(TokenBucket::unthrottled()),
        global_metrics: None,
        idle_timeout: None,
        live_peers: Arc::new(parking_lot::RwLock::new(Vec::new())),
        piece_availability: Arc::new(parking_lot::RwLock::new(vec![1; info.pieces() as usize])),
        settings: Arc::new(parking_lot::RwLock::new(Default::default())),
        on_peers_discovered: Some(disco_tx),
        on_metadata_resolved: None,
        ban_list: Default::default(),
        ip_filter: Default::default(),
        super_seeding: false,
        local_webseed_resolver: None,
        alert_sender: None,
    };

    let torrent = Torrent::new(config, Some(&have));
    tokio::spawn(torrent.run(peer_rx, cmd_rx));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    let relay_info_hash = info.hash;

    let peer_tx_clone = peer_tx.clone();
    tokio::spawn(async move {
        while let Ok((stream, addr)) = listener.accept().await {
            let tx = peer_tx_clone.clone();
            tokio::spawn(async move {
                let _ =
                    synapse_engine::accept(stream, addr, relay_peer_id, relay_info_hash, false, tx)
                        .await;
            });
        }
    });

    // Helper to connect and do BitTorrent + Extension handshake
    async fn connect_peer(
        relay_addr: SocketAddr,
        info_hash: [u8; 20],
        peer_id: [u8; 20],
    ) -> (Framed<TcpStream, PeerCodec>, SocketAddr) {
        let stream = TcpStream::connect(relay_addr).await.unwrap();
        let local_addr = stream.local_addr().unwrap();
        let mut framed = Framed::new(stream, PeerCodec::new());

        let mut reserved = [0u8; 8];
        reserved[5] |= 0x10; // BEP 10 Extension protocol support

        framed
            .send(Message::Handshake {
                reserved,
                info_hash,
                peer_id,
            })
            .await
            .unwrap();

        // Read handshake
        let hs = framed.next().await.unwrap().unwrap();
        assert!(matches!(hs, Message::Handshake { .. }));

        // Read extension handshake and HaveAll/Bitfield from relay
        let mut ext_hs_seen = false;
        while !ext_hs_seen {
            if let Message::Extension { id: 0, payload } = framed.next().await.unwrap().unwrap() {
                let parsed = ExtensionHandshake::decode(&payload).expect("valid ext hs");
                assert_eq!(parsed.m.get("ut_holepunch"), Some(&3));
                ext_hs_seen = true;
            }
        }

        // Send our extension handshake advertising ut_holepunch = 3
        let our_ext_hs = ExtensionHandshake::new().with_ut_holepunch(3);
        framed
            .send(Message::Extension {
                id: 0,
                payload: our_ext_hs.encode(),
            })
            .await
            .unwrap();

        (framed, local_addr)
    }

    let (mut peer_a, addr_a) = connect_peer(relay_addr, relay_info_hash, [0x22; 20]).await;
    let (mut peer_b, addr_b) = connect_peer(relay_addr, relay_info_hash, [0x33; 20]).await;

    // Small yield so engine registers both peer connections
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. Peer A sends Rendezvous targeting Peer B
    let rendezvous = HolepunchMessage::Rendezvous { target: addr_b };
    peer_a
        .send(Message::Extension {
            id: 3,
            payload: rendezvous.encode(),
        })
        .await
        .unwrap();

    // Peer B should receive Connect { peer: addr_a }
    let msg_b = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(Ok(Message::Extension { id: 3, payload })) = peer_b.next().await {
                if let Ok(hp) = HolepunchMessage::decode(payload) {
                    return hp;
                }
            }
        }
    })
    .await
    .expect("Peer B received holepunch message");
    assert_eq!(msg_b, HolepunchMessage::Connect { peer: addr_a });

    // Peer A should receive Connect { peer: addr_b }
    let msg_a = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(Ok(Message::Extension { id: 3, payload })) = peer_a.next().await {
                if let Ok(hp) = HolepunchMessage::decode(payload) {
                    return hp;
                }
            }
        }
    })
    .await
    .expect("Peer A received holepunch message");
    assert_eq!(msg_a, HolepunchMessage::Connect { peer: addr_b });

    // 2. Peer A sends Rendezvous targeting an unknown address -> Relay responds Failed { err_code: 1 }
    let unknown_target: SocketAddr = "127.0.0.1:59999".parse().unwrap();
    peer_a
        .send(Message::Extension {
            id: 3,
            payload: HolepunchMessage::Rendezvous {
                target: unknown_target,
            }
            .encode(),
        })
        .await
        .unwrap();

    let fail_msg = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(Ok(Message::Extension { id: 3, payload })) = peer_a.next().await {
                if let Ok(hp) = HolepunchMessage::decode(payload) {
                    return hp;
                }
            }
        }
    })
    .await
    .expect("Peer A received fail response");
    assert_eq!(fail_msg, HolepunchMessage::Failed { err_code: 1 });

    // 3. Peer A sends Connect { peer: target } directly to relay -> Relay notifies on_peers_discovered
    let target_to_discover: SocketAddr = "127.0.0.1:54321".parse().unwrap();
    peer_a
        .send(Message::Extension {
            id: 3,
            payload: HolepunchMessage::Connect {
                peer: target_to_discover,
            }
            .encode(),
        })
        .await
        .unwrap();

    let discovered = tokio::time::timeout(Duration::from_secs(2), disco_rx.recv())
        .await
        .expect("on_peers_discovered received")
        .expect("discovered peers list");
    assert!(discovered.contains(&target_to_discover));
}
