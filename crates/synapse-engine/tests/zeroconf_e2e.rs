//! BEP 26 Zeroconf: two engines find each other through mDNS messages. The multicast group is
//! replaced by each other's unicast socket so the test needs no multicast networking; the
//! messages, parsing, and candidate-peer wiring are the real ones.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest, Sha1};

use diskio::DiskEngine;
use synapse_engine::SwarmEngine;
use synapse_meta::Info;

fn info(private: bool) -> Info {
    let data = vec![3u8; 32 * 1024];
    let pieces: Vec<u8> = data
        .chunks(16 * 1024)
        .flat_map(|c| Sha1::digest(c).to_vec())
        .collect();
    let mut d = std::collections::BTreeMap::from([
        (
            b"name".to_vec(),
            synapse_bencode::BEncode::String(b"zc.bin".to_vec()),
        ),
        (
            b"piece length".to_vec(),
            synapse_bencode::BEncode::Int(16 * 1024),
        ),
        (b"pieces".to_vec(), synapse_bencode::BEncode::String(pieces)),
        (
            b"length".to_vec(),
            synapse_bencode::BEncode::Int(data.len() as i64),
        ),
    ]);
    if private {
        d.insert(b"private".to_vec(), synapse_bencode::BEncode::Int(1));
    }
    Info::from_bencode(synapse_bencode::BEncode::Dict(
        std::collections::BTreeMap::from([(b"info".to_vec(), synapse_bencode::BEncode::Dict(d))]),
    ))
    .unwrap()
}

async fn engine(peer_id: u8, info: Info, dir: &std::path::Path) -> (Arc<SwarmEngine>, [u8; 20]) {
    let e = Arc::new(SwarmEngine::new(
        Arc::new(DiskEngine::auto().await),
        [peer_id; 20],
    ));
    let mut settings = e.settings().read().clone();
    settings.zeroconf_enabled = true;
    e.update_settings(settings);
    let hash = info.hash;
    e.add_torrent(Arc::new(info), dir.to_path_buf(), None);
    (e, hash)
}

fn free_udp_addr() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn two_engines_sharing_a_torrent_discover_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let (a, hash) = engine(1, info(false), dir.path()).await;
    let (b, _) = engine(2, info(false), dir.path()).await;
    let (addr_a, addr_b) = (free_udp_addr(), free_udp_addr());
    a.set_zeroconf_target(addr_b);
    b.set_zeroconf_target(addr_a);
    a.set_zeroconf_addresses(vec!["127.0.0.1".parse().unwrap()]);
    b.set_zeroconf_addresses(vec!["127.0.0.1".parse().unwrap()]);
    // The peer ports they advertise.
    let la = a
        .clone()
        .start_listener("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let lb = b
        .clone()
        .start_listener("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let _ = (la, lb);
    let _ta = a.clone().start_zeroconf(addr_a).await.unwrap();
    let _tb = b.clone().start_zeroconf(addr_b).await.unwrap();

    let mut found = false;
    for _ in 0..100 {
        if a.candidate_peers_count(&hash) > 0 && b.candidate_peers_count(&hash) > 0 {
            found = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        found,
        "the engines never learned each other's address through mDNS"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_private_torrent_is_neither_advertised_nor_learned() {
    let dir = tempfile::tempdir().unwrap();
    let (a, hash) = engine(1, info(true), dir.path()).await;
    let (b, _) = engine(2, info(true), dir.path()).await;
    let (addr_a, addr_b) = (free_udp_addr(), free_udp_addr());
    a.set_zeroconf_target(addr_b);
    b.set_zeroconf_target(addr_a);
    a.set_zeroconf_addresses(vec!["127.0.0.1".parse().unwrap()]);
    b.set_zeroconf_addresses(vec!["127.0.0.1".parse().unwrap()]);
    let _la = a
        .clone()
        .start_listener("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let _lb = b
        .clone()
        .start_listener("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let _ta = a.clone().start_zeroconf(addr_a).await.unwrap();
    let _tb = b.clone().start_zeroconf(addr_b).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(a.candidate_peers_count(&hash), 0);
    assert_eq!(b.candidate_peers_count(&hash), 0);
}
