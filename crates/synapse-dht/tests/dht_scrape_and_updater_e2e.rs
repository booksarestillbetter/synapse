//! BEP 33 (DHT Scrape) and BEP 46 (Torrent Updates via DHT Mutable Items) over real UDP sockets.

use ed25519_dalek::{Signer, SigningKey};
use std::net::{SocketAddr, SocketAddrV4};
use synapse_dht::sample::DhtBloomFilter;
use synapse_dht::storage::{compute_mutable_target, format_sign_payload};
use synapse_dht::{spawn_with_options, DhtOptions, PutArgs, TorrentUpdatePointer};

async fn test_node(id: u8) -> (synapse_dht::DhtHandle, SocketAddrV4) {
    let (h, addr) = spawn_with_options(
        [id; 20],
        "127.0.0.1:0".parse().unwrap(),
        DhtOptions::default(),
    )
    .await
    .unwrap();
    let SocketAddr::V4(addr) = addr else {
        unreachable!()
    };
    (h, addr)
}

#[tokio::test]
async fn bep33_dht_scrape_over_udp() {
    let (client, _) = test_node(1).await;
    let (_server, server_addr) = test_node(2).await;

    let info_hash = [0x42; 20];

    // Query empty swarm
    let scrape_empty = client.scrape(server_addr, info_hash).await.unwrap();
    assert_eq!(scrape_empty.seeders, 0);
    assert_eq!(scrape_empty.leechers, 0);

    // Announce a peer
    let (token, _) = client.get_peers(server_addr, info_hash).await.unwrap();
    client
        .announce_peer(server_addr, info_hash, 6881, token)
        .await
        .unwrap();

    // Query again: now 1 leecher/peer
    let scrape = client.scrape(server_addr, info_hash).await.unwrap();
    assert_eq!(scrape.seeders, 0);
    assert_eq!(scrape.leechers, 1);

    // Check Bloom filter
    assert!(scrape.bfpe.is_some());
    let bfpe_bytes: [u8; 256] = scrape.bfpe.unwrap().try_into().unwrap();
    let bfpe = DhtBloomFilter::from_bytes(bfpe_bytes);
    assert!(bfpe.count_zero_bits() < DhtBloomFilter::M);
    assert!(bfpe.estimate_cardinality() >= 0.5);
}

#[tokio::test]
async fn bep46_torrent_update_over_udp() {
    let (client, _) = test_node(10).await;
    let (_server, server_addr) = test_node(20).await;

    let sk = SigningKey::from_bytes(&[0x88; 32]);
    let pk = sk.verifying_key().to_bytes();
    let salt: Option<Vec<u8>> = Some(b"torrent_channel".to_vec());
    let target = compute_mutable_target(&pk, salt.as_deref());

    let mut updater = TorrentUpdatePointer::new(pk, salt.clone());
    assert_eq!(updater.target_hash(), target);

    // Initial poll should see nothing
    let updated = updater.poll_node(&client, server_addr).await.unwrap();
    assert!(!updated);
    assert_eq!(updater.current_info_hash, None);

    // Publish v1 infohash in a BEP 46 dictionary
    let info_hash_v1 = [0x11; 20];
    let mut dict1 = std::collections::BTreeMap::new();
    dict1.insert(
        b"ih".to_vec(),
        synapse_bencode::BEncode::String(info_hash_v1.to_vec()),
    );
    let v1 = synapse_bencode::BEncode::Dict(dict1).encode_to_buf();

    let (token, _) = client.get(server_addr, target, None).await.unwrap();
    let sig1 = sk
        .sign(&format_sign_payload(salt.as_deref(), 1, &v1))
        .to_bytes();
    let put_v1 = PutArgs {
        token: token.clone(),
        v: v1,
        k: Some(pk),
        sig: Some(sig1),
        seq: Some(1),
        cas: None,
        salt: salt.clone(),
    };
    client.put(server_addr, put_v1).await.unwrap();

    // Poll node: should discover v1
    let updated = updater.poll_node(&client, server_addr).await.unwrap();
    assert!(updated);
    assert_eq!(updater.latest_seq, 1);
    assert_eq!(updater.current_info_hash, Some(info_hash_v1));

    // Polling again without new seq returns false
    let updated_stale = updater.poll_node(&client, server_addr).await.unwrap();
    assert!(!updated_stale);

    // Publish v2 infohash
    let info_hash_v2 = [0x22; 20];
    let mut dict2 = std::collections::BTreeMap::new();
    dict2.insert(
        b"ih".to_vec(),
        synapse_bencode::BEncode::String(info_hash_v2.to_vec()),
    );
    let v2 = synapse_bencode::BEncode::Dict(dict2).encode_to_buf();

    let (token2, _) = client.get(server_addr, target, None).await.unwrap();
    let sig2 = sk
        .sign(&format_sign_payload(salt.as_deref(), 2, &v2))
        .to_bytes();
    let put_v2 = PutArgs {
        token: token2,
        v: v2,
        k: Some(pk),
        sig: Some(sig2),
        seq: Some(2),
        cas: Some(1),
        salt: salt.clone(),
    };
    client.put(server_addr, put_v2).await.unwrap();

    // Poll node: should advance to v2
    let updated_v2 = updater.poll_node(&client, server_addr).await.unwrap();
    assert!(updated_v2);
    assert_eq!(updater.latest_seq, 2);
    assert_eq!(updater.current_info_hash, Some(info_hash_v2));
}
