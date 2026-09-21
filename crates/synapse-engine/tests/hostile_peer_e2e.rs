//! A malicious peer speaks raw wire messages to a real seeder over a loopback socket.
//! The seeder must reject malformed/oversized requests without allocating for them,
//! disconnect a peer that keeps sending them, and keep serving well-behaved peers.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use sha1::{Digest, Sha1};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::codec::Framed;

use diskio::DiskEngine;
use synapse_bencode::BEncode;
use synapse_engine::{
    PeerEvent, SwarmState, SwarmStats, SwarmTier, TokenBucket, Torrent, TorrentConfig,
};
use synapse_meta::Info;
use synapse_picker::{Bitfield, Mode, RoaringBitfield};
use synapse_wire::{Message, PeerCodec};

const PIECE_LEN: u32 = 32 * 1024;
const SEEDER_ID: [u8; 20] = [1u8; 20];
const EVIL_ID: [u8; 20] = [9u8; 20];

fn build_info(data: &[u8]) -> Info {
    let mut pieces = Vec::new();
    for chunk in data.chunks(PIECE_LEN as usize) {
        pieces.extend_from_slice(&Sha1::digest(chunk));
    }
    let mut d = BTreeMap::new();
    d.insert(b"name".to_vec(), BEncode::String(b"f.bin".to_vec()));
    d.insert(b"piece length".to_vec(), BEncode::Int(PIECE_LEN as i64));
    d.insert(b"pieces".to_vec(), BEncode::String(pieces));
    d.insert(b"length".to_vec(), BEncode::Int(data.len() as i64));
    let mut t = BTreeMap::new();
    t.insert(b"info".to_vec(), BEncode::Dict(d));
    Info::from_bencode(BEncode::Dict(t)).unwrap()
}

/// Starts a seeder for `data` and returns a raw, already-handshaken framed connection to it.
async fn connect_evil(data: &[u8]) -> (Framed<TcpStream, PeerCodec>, tempfile::TempDir) {
    let info = Arc::new(build_info(data));
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("f.bin"), data).unwrap();

    let mut have = Bitfield::new(info.pieces() as usize);
    for i in 0..info.pieces() {
        have.set(i as usize);
    }
    let stats = Arc::new(parking_lot::RwLock::new(SwarmStats {
        info_hash: info.hash,
        name: info.name.clone(),
        total_size: info.total_len,
        progress: 1.0,
        state: SwarmState::Seeding,
        tier: SwarmTier::Hot,
        download_rate: 0,
        upload_rate: 0,
        downloaded_bytes: 0,
        uploaded_bytes: 0,
        peers_connected: 0,
        peers_sending: 0,
        eta_seconds: 0,
        ratio: 0.0,
        download_dir: dir.path().to_string_lossy().to_string(),
        added_at: 0,
        is_private: false,
        is_stalled: false,
        last_transfer_at: 0,
        piece_count: info.pieces(),
        piece_size: info.piece_len,
    }));
    let (tx, rx) = mpsc::channel::<PeerEvent>(64);
    let (_cmd_tx, cmd_rx) = mpsc::channel(1);
    let seeder = Torrent::new(
        TorrentConfig {
            info: info.clone(),
            download_dir: dir.path().to_path_buf(),
            peer_id: SEEDER_ID,
            disk: Arc::new(DiskEngine::auto().await),
            mode: Mode::RarestFirst,
            max_pipeline: 8,
            regular_unchokes: 4,
            optimistic_unchoke_interval: Duration::from_secs(600),
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
            on_peers_discovered: None,
            on_metadata_resolved: None,
            ban_list: Default::default(),
            ip_filter: Default::default(),
            super_seeding: false,
            local_webseed_resolver: None,
            alert_sender: None,
        },
        Some(&have),
    );
    tokio::spawn(seeder.run(rx, cmd_rx));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hash = info.hash;
    tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        synapse_engine::accept(stream, peer_addr, SEEDER_ID, hash, false, tx)
            .await
            .unwrap();
    });

    let mut framed = Framed::new(TcpStream::connect(addr).await.unwrap(), PeerCodec::new());
    framed
        .send(Message::Handshake {
            reserved: [0; 8],
            info_hash: info.hash,
            peer_id: EVIL_ID,
        })
        .await
        .unwrap();
    assert!(matches!(
        framed.next().await,
        Some(Ok(Message::Handshake { .. }))
    ));
    (framed, dir)
}

/// Reads messages until `pred` matches or the deadline passes. Returns `None` if the
/// connection closed first.
async fn wait_for(
    framed: &mut Framed<TcpStream, PeerCodec>,
    secs: u64,
    mut pred: impl FnMut(&Message) -> bool,
) -> Option<Message> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        match tokio::time::timeout_at(deadline, framed.next()).await {
            Ok(Some(Ok(m))) if pred(&m) => return Some(m),
            Ok(Some(Ok(_))) => continue,
            _ => return None,
        }
    }
}

async fn unchoke(framed: &mut Framed<TcpStream, PeerCodec>) {
    framed.send(Message::Interested).await.unwrap();
    wait_for(framed, 5, |m| matches!(m, Message::Unchoke))
        .await
        .expect("seeder never unchoked an interested peer");
}

fn data() -> Vec<u8> {
    (0..3 * PIECE_LEN as usize)
        .map(|i| (i % 251) as u8)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_and_out_of_range_requests_are_rejected_and_seeder_keeps_serving() {
    let data = data();
    let (mut c, _dir) = connect_evil(&data).await;
    unchoke(&mut c).await;

    let bad = [
        (0u32, 0u32, u32::MAX),        // ~4 GiB read
        (0, 0, 1 << 30),               // 1 GiB
        (0, 0, 16 * 1024 + 1),         // one byte over the block cap
        (0, 0, 0),                     // zero length
        (0, PIECE_LEN, 16 * 1024),     // begins past the piece
        (0, PIECE_LEN - 1, 16 * 1024), // straddles the piece end
        (0, u32::MAX, 16 * 1024),      // begin + length overflows u32
        (3, 0, 16 * 1024),             // piece index == piece count
        (u32::MAX, 0, 16 * 1024),      // index far out of range
    ];
    for (index, begin, length) in bad {
        c.send(Message::Request {
            index,
            begin,
            length,
        })
        .await
        .unwrap();
        let got = wait_for(&mut c, 5, |m| {
            matches!(m, Message::RejectRequest { .. } | Message::Piece { .. })
        })
        .await
        .unwrap_or_else(|| panic!("no reply to bad request {index}/{begin}/{length}"));
        assert!(
            matches!(got, Message::RejectRequest { index: i, begin: b, length: l } if (i, b, l) == (index, begin, length)),
            "bad request {index}/{begin}/{length} must be rejected, got {got:?}"
        );
    }

    // Seeder is still alive and still serves a valid request byte-for-byte.
    c.send(Message::Request {
        index: 1,
        begin: 16 * 1024,
        length: 16 * 1024,
    })
    .await
    .unwrap();
    let got = wait_for(&mut c, 5, |m| matches!(m, Message::Piece { .. }))
        .await
        .expect("valid request not served");
    let Message::Piece {
        index,
        begin,
        data: block,
    } = got
    else {
        unreachable!()
    };
    assert_eq!((index, begin), (1, 16 * 1024));
    let start = PIECE_LEN as usize + 16 * 1024;
    assert_eq!(&block[..], &data[start..start + 16 * 1024]);
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_that_keeps_sending_invalid_requests_is_disconnected() {
    let (mut c, _dir) = connect_evil(&data()).await;
    unchoke(&mut c).await;

    for _ in 0..400 {
        if c.send(Message::Request {
            index: 0,
            begin: 0,
            length: u32::MAX,
        })
        .await
        .is_err()
        {
            break;
        }
    }
    // Drain replies until the seeder hangs up.
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(Ok(_)) = c.next().await {}
    })
    .await;
    assert!(closed.is_ok(), "seeder never disconnected the abusive peer");
}

#[tokio::test(flavor = "multi_thread")]
async fn unsolicited_blocks_are_ignored() {
    let (mut c, _dir) = connect_evil(&data()).await;
    unchoke(&mut c).await;

    // A seeder never asked for these; they must not crash it or corrupt anything.
    for (index, begin, len) in [
        (0u32, 0u32, 16 * 1024usize),
        (0, 7, 16 * 1024),
        (99, 0, 16),
        (0, u32::MAX, 1),
    ] {
        c.send(Message::Piece {
            index,
            begin,
            data: vec![0xAA; len].into(),
        })
        .await
        .unwrap();
    }
    c.send(Message::Request {
        index: 0,
        begin: 0,
        length: 16 * 1024,
    })
    .await
    .unwrap();
    assert!(wait_for(&mut c, 5, |m| matches!(m, Message::Piece { .. }))
        .await
        .is_some());
}

// ---------------------------------------------------------------------------------------
// Smart-ban: a peer that supplies a piece that fails its hash check is banned.
// ---------------------------------------------------------------------------------------

/// A leecher `Torrent` (empty) listening for one raw "seeder" connection at a time.
/// Returns the listener address plus the shared ban list.
async fn start_leecher(
    data: &[u8],
) -> (
    std::net::SocketAddr,
    Arc<synapse_engine::BanList>,
    tempfile::TempDir,
    [u8; 20],
) {
    start_leecher_with_filter(data, Default::default()).await
}

async fn start_leecher_with_filter(
    data: &[u8],
    ip_filter: Arc<parking_lot::RwLock<synapse_engine::ipfilter::IpFilter>>,
) -> (
    std::net::SocketAddr,
    Arc<synapse_engine::BanList>,
    tempfile::TempDir,
    [u8; 20],
) {
    let info = Arc::new(build_info(data));
    let dir = tempfile::tempdir().unwrap();
    let hash = info.hash;
    let stats = Arc::new(parking_lot::RwLock::new(SwarmStats {
        info_hash: info.hash,
        name: info.name.clone(),
        total_size: info.total_len,
        progress: 0.0,
        state: SwarmState::Downloading,
        tier: SwarmTier::Hot,
        download_rate: 0,
        upload_rate: 0,
        downloaded_bytes: 0,
        uploaded_bytes: 0,
        peers_connected: 0,
        peers_sending: 0,
        eta_seconds: 0,
        ratio: 0.0,
        download_dir: dir.path().to_string_lossy().to_string(),
        added_at: 0,
        is_private: false,
        is_stalled: false,
        last_transfer_at: 0,
        piece_count: info.pieces(),
        piece_size: info.piece_len,
    }));
    let ban_list = Arc::new(synapse_engine::BanList::new());
    let (tx, rx) = mpsc::channel::<PeerEvent>(64);
    let (_cmd_tx, cmd_rx) = mpsc::channel(1);
    let leecher = Torrent::new(
        TorrentConfig {
            info: info.clone(),
            download_dir: dir.path().to_path_buf(),
            peer_id: [2u8; 20],
            disk: Arc::new(DiskEngine::auto().await),
            mode: Mode::RarestFirst,
            max_pipeline: 8,
            regular_unchokes: 4,
            optimistic_unchoke_interval: Duration::from_secs(600),
            tick_interval: Duration::from_millis(50),
            on_torrent_completed: None,
            on_piece_completed: None,
            stats,
            bitfield: Arc::new(parking_lot::RwLock::new(None)),
            download_bucket: Arc::new(TokenBucket::unthrottled()),
            upload_bucket: Arc::new(TokenBucket::unthrottled()),
            global_metrics: None,
            idle_timeout: None,
            live_peers: Arc::new(parking_lot::RwLock::new(Vec::new())),
            piece_availability: Arc::new(parking_lot::RwLock::new(vec![0; info.pieces() as usize])),
            settings: Arc::new(parking_lot::RwLock::new(Default::default())),
            on_peers_discovered: None,
            on_metadata_resolved: None,
            ban_list: ban_list.clone(),
            ip_filter,
            super_seeding: false,
            local_webseed_resolver: None,
            alert_sender: None,
        },
        None,
    );
    tokio::spawn(leecher.run(rx, cmd_rx));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, peer_addr) = listener.accept().await.unwrap();
            let tx = tx.clone();
            let _ = synapse_engine::accept(stream, peer_addr, [2u8; 20], hash, false, tx).await;
        }
    });
    (addr, ban_list, dir, hash)
}

async fn connect_as_seeder(
    addr: std::net::SocketAddr,
    hash: [u8; 20],
) -> Framed<TcpStream, PeerCodec> {
    let mut framed = Framed::new(TcpStream::connect(addr).await.unwrap(), PeerCodec::new());
    framed
        .send(Message::Handshake {
            reserved: [0; 8],
            info_hash: hash,
            peer_id: EVIL_ID,
        })
        .await
        .unwrap();
    assert!(matches!(
        framed.next().await,
        Some(Ok(Message::Handshake { .. }))
    ));
    framed
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_that_supplies_a_corrupt_piece_is_banned_and_disconnected() {
    // Two pieces so the leecher has something left to want after the first fails.
    let data: Vec<u8> = (0..2 * PIECE_LEN as usize)
        .map(|i| (i % 249) as u8)
        .collect();
    let (addr, bans, _dir, hash) = start_leecher(&data).await;

    let mut c = connect_as_seeder(addr, hash).await;
    // Claim every piece, then unchoke so the leecher starts requesting.
    c.send(Message::Bitfield(vec![0b1100_0000].into()))
        .await
        .unwrap();
    c.send(Message::Unchoke).await.unwrap();

    // Answer every request with garbage of the right size, until the leecher hangs up.
    let hung_up = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(Ok(msg)) = c.next().await {
            if let Message::Request {
                index,
                begin,
                length,
            } = msg
            {
                let _ = c
                    .send(Message::Piece {
                        index,
                        begin,
                        data: vec![0xEE; length as usize].into(),
                    })
                    .await;
            }
        }
    })
    .await;
    assert!(
        hung_up.is_ok(),
        "leecher never disconnected the poisoning peer"
    );
    assert!(
        bans.is_banned("127.0.0.1".parse().unwrap()),
        "poisoner's address must be on the ban list"
    );

    // And a reconnect from the banned address is dropped instead of being served/requested from.
    let mut again = connect_as_seeder(addr, hash).await;
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        again.send(Message::Unchoke).await.ok();
        while let Some(Ok(_)) = again.next().await {}
    })
    .await;
    assert!(
        closed.is_ok(),
        "banned address was allowed to stay connected"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn honest_seeder_is_not_banned_and_completes_the_download() {
    let data: Vec<u8> = (0..2 * PIECE_LEN as usize)
        .map(|i| (i % 249) as u8)
        .collect();
    let (addr, bans, dir, hash) = start_leecher(&data).await;

    let mut c = connect_as_seeder(addr, hash).await;
    c.send(Message::Bitfield(vec![0b1100_0000].into()))
        .await
        .unwrap();
    c.send(Message::Unchoke).await.unwrap();

    let path = dir.path().join("f.bin");
    let done = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                msg = c.next() => match msg {
                    Some(Ok(Message::Request { index, begin, length })) => {
                        let start = index as usize * PIECE_LEN as usize + begin as usize;
                        let block = data[start..start + length as usize].to_vec();
                        c.send(Message::Piece { index, begin, data: block.into() }).await.unwrap();
                    }
                    Some(Ok(_)) => {}
                    _ => panic!("honest seeder was disconnected"),
                },
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    if std::fs::read(&path).map(|d| d == data).unwrap_or(false) { break; }
                }
            }
        }
    })
    .await;
    assert!(done.is_ok(), "download never completed");
    assert!(!bans.is_banned("127.0.0.1".parse().unwrap()));
}

async fn connect_with_id(
    addr: std::net::SocketAddr,
    hash: [u8; 20],
    peer_id: [u8; 20],
) -> Framed<TcpStream, PeerCodec> {
    let mut framed = Framed::new(TcpStream::connect(addr).await.unwrap(), PeerCodec::new());
    framed
        .send(Message::Handshake {
            reserved: [0; 8],
            info_hash: hash,
            peer_id,
        })
        .await
        .unwrap();
    assert!(matches!(
        framed.next().await,
        Some(Ok(Message::Handshake { .. }))
    ));
    framed
}

/// True if the leecher closes the connection within a few seconds.
async fn gets_closed(c: &mut Framed<TcpStream, PeerCodec>) -> bool {
    tokio::time::timeout(Duration::from_secs(3), async {
        c.send(Message::Unchoke).await.ok();
        while let Some(Ok(_)) = c.next().await {}
    })
    .await
    .is_ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn connection_to_ourselves_is_refused() {
    let data: Vec<u8> = vec![7; PIECE_LEN as usize];
    let (addr, _bans, _dir, hash) = start_leecher(&data).await;
    // start_leecher's Torrent uses peer id [2; 20]; a peer presenting the same id is us.
    let mut me = connect_with_id(addr, hash, [2u8; 20]).await;
    assert!(
        gets_closed(&mut me).await,
        "self-connection must be dropped"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_peer_id_is_refused_but_first_connection_stays() {
    let data: Vec<u8> = vec![7; PIECE_LEN as usize];
    let (addr, _bans, _dir, hash) = start_leecher(&data).await;
    let mut first = connect_with_id(addr, hash, [5u8; 20]).await;
    first.send(Message::Unchoke).await.unwrap();
    // Wait until the leecher has registered this peer (it greets every accepted peer), so the
    // duplicate below is unambiguously the second connection rather than racing the first.
    let greeted = tokio::time::timeout(Duration::from_secs(5), first.next()).await;
    assert!(
        matches!(greeted, Ok(Some(Ok(_)))),
        "leecher never greeted the first peer"
    );
    let mut second = connect_with_id(addr, hash, [5u8; 20]).await;
    assert!(
        gets_closed(&mut second).await,
        "duplicate peer id must be dropped"
    );
    // The original connection is still writable (not torn down by the duplicate).
    assert!(first.send(Message::KeepAlive).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn adding_an_ip_filter_rule_drops_already_connected_peers() {
    let data: Vec<u8> = vec![7; PIECE_LEN as usize];
    let filter = Arc::new(parking_lot::RwLock::new(
        synapse_engine::ipfilter::IpFilter::new(),
    ));
    let (addr, _bans, _dir, hash) = start_leecher_with_filter(&data, filter.clone()).await;

    let mut c = connect_with_id(addr, hash, [5u8; 20]).await;
    c.send(Message::Unchoke).await.unwrap();
    assert!(
        c.send(Message::KeepAlive).await.is_ok(),
        "peer should be connected before the rule exists"
    );

    filter.write().add_cidr_str("127.0.0.0/8").unwrap();

    // The periodic sweep (5 s) notices and closes the live connection.
    let closed = tokio::time::timeout(Duration::from_secs(12), async {
        while let Some(Ok(_)) = c.next().await {}
    })
    .await;
    assert!(
        closed.is_ok(),
        "already-connected peer survived an IP filter update"
    );
}
