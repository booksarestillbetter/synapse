//! BEP 43 / 44 / 51 over real UDP sockets between two DHT nodes.

use std::net::{SocketAddr, SocketAddrV4};

use ed25519_dalek::{Signer, SigningKey};
use synapse_dht::storage::{compute_immutable_target, compute_mutable_target, format_sign_payload};
use synapse_dht::{spawn, spawn_with_options, DhtError, DhtHandle, DhtOptions, PutArgs};

async fn node(id: u8, opts: DhtOptions) -> (DhtHandle, SocketAddrV4) {
    let (h, addr) = spawn_with_options([id; 20], "127.0.0.1:0".parse().unwrap(), opts)
        .await
        .unwrap();
    let SocketAddr::V4(addr) = addr else {
        unreachable!()
    };
    (h, addr)
}

fn put_args(token: Vec<u8>, v: &[u8]) -> PutArgs {
    PutArgs {
        token,
        v: v.to_vec(),
        k: None,
        sig: None,
        seq: None,
        cas: None,
        salt: None,
    }
}

#[tokio::test]
async fn immutable_item_round_trips_through_put_and_get() {
    let (a, _) = node(1, DhtOptions::default()).await;
    let (_b, b_addr) = node(2, DhtOptions::default()).await;
    let v = b"12:hello, dht!!".to_vec();
    let target = compute_immutable_target(&v);

    let (token, item) = a.get(b_addr, target, None).await.unwrap();
    assert!(item.is_none(), "nothing stored yet");
    a.put(b_addr, put_args(token.clone(), &v)).await.unwrap();

    let (_, item) = a.get(b_addr, target, None).await.unwrap();
    assert_eq!(item.expect("stored item").v, v);

    // A token issued for a different target must not authorise this put.
    let other_target = [0x55; 20];
    let (wrong_token, _) = a.get(b_addr, other_target, None).await.unwrap();
    let err = a
        .put(b_addr, put_args(wrong_token, b"3:new"))
        .await
        .unwrap_err();
    assert!(matches!(err, DhtError::Remote(_)), "{err:?}");
}

#[tokio::test]
async fn mutable_item_needs_a_valid_signature_and_a_higher_sequence_number() {
    let (a, _) = node(1, DhtOptions::default()).await;
    let (_b, b_addr) = node(2, DhtOptions::default()).await;
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let pk = sk.verifying_key().to_bytes();
    let salt = b"feed".to_vec();
    let target = compute_mutable_target(&pk, Some(&salt));

    let mk = |token: Vec<u8>, seq: u64, v: &[u8], cas: Option<u64>| {
        let sig = sk
            .sign(&format_sign_payload(Some(&salt), seq, v))
            .to_bytes();
        PutArgs {
            token,
            v: v.to_vec(),
            k: Some(pk),
            sig: Some(sig),
            seq: Some(seq),
            cas,
            salt: Some(salt.clone()),
        }
    };

    let (token, _) = a.get(b_addr, target, None).await.unwrap();
    a.put(b_addr, mk(token.clone(), 1, b"2:v1", None))
        .await
        .unwrap();

    // Forged signature (sequence number changed after signing) is refused with 206.
    let mut forged = mk(token.clone(), 2, b"2:v2", None);
    forged.seq = Some(3);
    match a.put(b_addr, forged).await.unwrap_err() {
        DhtError::Remote(m) => assert!(m.contains("signature"), "{m}"),
        e => panic!("{e:?}"),
    }
    // Replaying seq 1 is refused (302), a CAS mismatch is refused (301).
    assert!(matches!(
        a.put(b_addr, mk(token.clone(), 1, b"2:v1", None)).await,
        Err(DhtError::Remote(_))
    ));
    assert!(matches!(
        a.put(b_addr, mk(token.clone(), 2, b"2:v2", Some(9))).await,
        Err(DhtError::Remote(_))
    ));
    // A proper update with the right CAS succeeds and is what `get` returns, signed, with seq.
    a.put(b_addr, mk(token, 2, b"2:v2", Some(1))).await.unwrap();
    let (_, item) = a.get(b_addr, target, None).await.unwrap();
    let item = item.unwrap();
    assert_eq!(
        (item.v.as_slice(), item.seq, item.k),
        (&b"2:v2"[..], Some(2), Some(pk))
    );
    // A requester that already has seq 2 is not sent the value again.
    let (_, item) = a.get(b_addr, target, Some(2)).await.unwrap();
    assert!(item.is_none());
}

#[tokio::test]
async fn sample_infohashes_returns_a_sample_of_announced_torrents() {
    let (a, _) = node(1, DhtOptions::default()).await;
    let (_b, b_addr) = node(2, DhtOptions::default()).await;
    for n in 0..30u8 {
        let hash = [n; 20];
        let (token, _) = a.get_peers(b_addr, hash).await.unwrap();
        a.announce_peer(b_addr, hash, 6881, token).await.unwrap();
    }
    let sample = a.sample_infohashes(b_addr, [0; 20]).await.unwrap();
    assert_eq!(sample.num, 30);
    assert_eq!(sample.samples.len(), 20, "capped at 20 per reply");
    assert!(sample
        .samples
        .iter()
        .all(|h| h.iter().all(|&b| b == h[0]) && h[0] < 30));
    assert!(sample.interval > 0);
}

#[tokio::test]
async fn read_only_nodes_query_without_being_routed_and_never_answer() {
    let (ro, ro_addr) = node(9, DhtOptions { read_only: true }).await;
    let (full, full_addr) = node(2, DhtOptions::default()).await;

    // A read-only node can query a normal one and gets an answer...
    assert_eq!(ro.ping(full_addr).await.unwrap(), full.our_id());
    // ...but is not added to that node's routing table (BEP 43)...
    assert!(!full
        .routing_snapshot()
        .await
        .unwrap()
        .iter()
        .any(|n| n.id == ro.our_id()));
    // ...and does not answer queries itself.
    let plain = spawn([3u8; 20], "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap()
        .0;
    let res = tokio::time::timeout(std::time::Duration::from_secs(12), plain.ping(ro_addr)).await;
    assert!(
        matches!(res, Ok(Err(DhtError::Timeout))),
        "read-only node must stay silent, got {res:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn replies_tell_the_querier_its_external_address_and_state_lists_known_nodes() {
    use std::net::UdpSocket;
    let (h, addr) = node(2, DhtOptions::default()).await;
    // Raw KRPC ping from a plain socket: the reply must carry `ip`, the address we appear at.
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    sock.send_to(
        b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q4:ping1:t2:xx1:y1:qe",
        addr,
    )
    .unwrap();
    let mut buf = [0u8; 512];
    let (n, _) = sock.recv_from(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    let mine = sock.local_addr().unwrap();
    let mut compact = match mine.ip() {
        std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
        _ => unreachable!(),
    };
    compact.extend_from_slice(&mine.port().to_be_bytes());
    let needle = [b"2:ip6:".as_slice(), &compact].concat();
    assert!(
        buf[..n]
            .windows(needle.len())
            .any(|w| w == needle.as_slice()),
        "reply lacks our address in `ip`: {text:?}"
    );

    // The node's state (id + good nodes) is available for persistence.
    let (id, nodes) = h.state().await.unwrap();
    assert_eq!(id, h.our_id());
    assert!(nodes.contains(&SocketAddr::V4(SocketAddrV4::new(
        *mine_v4(mine).ip(),
        mine.port()
    ))));
}

fn mine_v4(a: std::net::SocketAddr) -> SocketAddrV4 {
    match a {
        SocketAddr::V4(v) => v,
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn read_only_mode_can_be_switched_while_the_node_runs() {
    let (node_a, addr_a) = node(4, DhtOptions::default()).await;
    let (peer, _) = node(5, DhtOptions::default()).await;
    let plain = |t: u8| async move {
        spawn([t; 20], "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap()
            .0
    };
    // A normal node answers.
    assert_eq!(peer.ping(addr_a).await.unwrap(), node_a.our_id());
    // Switched to read-only it goes silent, and its own queries carry ro=1 so it is not routed.
    node_a.set_read_only(true);
    assert!(node_a.is_read_only());
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(12),
        plain(6).await.ping(addr_a),
    )
    .await;
    assert!(matches!(res, Ok(Err(DhtError::Timeout))), "{res:?}");
    // And back: it answers again.
    node_a.set_read_only(false);
    assert_eq!(plain(7).await.ping(addr_a).await.unwrap(), node_a.our_id());
}
