//! LSD over IPv6: the engine's LSD sockets must ingest announcements arriving on the IPv6
//! group's port and turn them into candidate peers.

use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest, Sha1};

use diskio::DiskEngine;
use synapse_engine::SwarmEngine;
use synapse_meta::Info;

fn info() -> Info {
    let data = vec![9u8; 32 * 1024];
    let pieces: Vec<u8> = data
        .chunks(16 * 1024)
        .flat_map(|c| Sha1::digest(c).to_vec())
        .collect();
    let d = std::collections::BTreeMap::from([
        (
            b"name".to_vec(),
            synapse_bencode::BEncode::String(b"lsd6.bin".to_vec()),
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
    Info::from_bencode(synapse_bencode::BEncode::Dict(
        std::collections::BTreeMap::from([(b"info".to_vec(), synapse_bencode::BEncode::Dict(d))]),
    ))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ipv6_lsd_announcement_yields_a_candidate_peer() {
    let engine = Arc::new(SwarmEngine::new(
        Arc::new(DiskEngine::auto().await),
        [6u8; 20],
    ));
    let dir = tempfile::tempdir().unwrap();
    let info = info();
    let hash = info.hash;
    engine.add_torrent(Arc::new(info), dir.path().to_path_buf(), None);
    if engine.clone().start_lsd().await.is_err() {
        return; // no multicast in this environment
    }
    // Deliver an announcement to the IPv6 LSD socket (unicast to loopback: same socket, same
    // parser; the multicast group join itself is exercised by the bind succeeding).
    let sock = match tokio::net::UdpSocket::bind("[::1]:0").await {
        Ok(s) => s,
        Err(_) => return, // no IPv6 loopback
    };
    let packet = synapse_wire::format_lsd_announce(45678, &[hash], Some("someone-else"));
    if sock.send_to(packet.as_bytes(), "[::1]:6771").await.is_err() {
        return;
    }
    // Port 6771 is a well-known shared port (SO_REUSEPORT), so another process on the host may
    // occasionally receive a datagram instead; resend a few times.
    let mut found = false;
    for _ in 0..10 {
        let _ = sock.send_to(packet.as_bytes(), "[::1]:6771").await;
        for _ in 0..10 {
            if engine.candidate_peers_count(&hash) > 0 {
                found = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        if found {
            break;
        }
    }
    // If the engine had no IPv6 LSD socket (host without IPv6 multicast), there is nothing to check.
    // Is an IPv6 socket bound to the LSD port? The probe must be IPv6-only: a plain `[::]` bind
    // is dual-stack on Linux and collides with the engine's *IPv4* LSD socket, which would make
    // a host without IPv6 multicast (a CI container, say) look as if the engine had one.
    let v6_bound = {
        use socket2::{Domain, Protocol, Socket, Type};
        let probe = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        probe.set_only_v6(true).unwrap();
        probe
            .bind(&"[::]:6771".parse::<std::net::SocketAddr>().unwrap().into())
            .is_err()
    };
    assert!(
        found || !v6_bound,
        "IPv6 LSD announcement was not turned into a candidate peer"
    );
}
