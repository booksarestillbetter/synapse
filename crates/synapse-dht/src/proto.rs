//! KRPC message encoding/decoding (the bencoded protocol BEP5 DHT messages use). Pure
//! parsing/building, no networking - see `node.rs` for the actual UDP-socket-driven
//! client. IPv4 only for this first cut, matching the pre-rewrite codebase's scope
//! (BEP32 IPv6 DHT support is a documented gap there too, not a regression here).

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use synapse_bencode::BEncode;

use crate::sample::SampleInfohashesResponse;

pub type NodeId = [u8; 20];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeInfo {
    pub id: NodeId,
    pub addr: SocketAddrV4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeInfoV6 {
    pub id: NodeId,
    pub addr: SocketAddrV6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    Ping,
    FindNode {
        target: NodeId,
        want: Option<Vec<String>>,
    },
    GetPeers {
        info_hash: [u8; 20],
        want: Option<Vec<String>>,
    },
    AnnouncePeer {
        info_hash: [u8; 20],
        port: u16,
        token: Vec<u8>,
        implied_port: bool,
    },
    /// BEP 44 `get`: fetch the item stored at `target`. For a mutable item, `seq` lets the
    /// requester say "only send it if newer than this".
    Get {
        target: [u8; 20],
        seq: Option<u64>,
    },
    /// BEP 44 `put`.
    Put(PutArgs),
    /// BEP 51 `sample_infohashes`.
    SampleInfohashes {
        target: NodeId,
    },
    /// BEP 33 `scrape`.
    Scrape {
        info_hash: [u8; 20],
    },
}

/// Arguments of a BEP 44 `put`. `v` is the *bencoded* value exactly as it is signed and
/// hashed, not a decoded structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutArgs {
    pub token: Vec<u8>,
    pub v: Vec<u8>,
    /// Ed25519 public key (mutable items only).
    pub k: Option<[u8; 32]>,
    pub sig: Option<[u8; 64]>,
    pub seq: Option<u64>,
    /// Compare-and-swap: only store if the current sequence number equals this.
    pub cas: Option<u64>,
    pub salt: Option<Vec<u8>>,
}

/// The item part of a BEP 44 `get` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetItem {
    pub v: Vec<u8>,
    pub k: Option<[u8; 32]>,
    pub sig: Option<[u8; 64]>,
    pub seq: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetPeersResult {
    Peers(Vec<SocketAddrV4>),
    Peers6(Vec<SocketAddrV6>),
    Nodes(Vec<NodeInfo>),
    Nodes6(Vec<NodeInfoV6>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// `ping` and `announce_peer` both reply with just the sender's id.
    Id,
    FindNode {
        nodes: Vec<NodeInfo>,
        nodes6: Vec<NodeInfoV6>,
    },
    GetPeers {
        token: Vec<u8>,
        result: GetPeersResult,
    },
    /// BEP 44 `get` response carrying an item. (A `get` for an item the node does not have
    /// is answered with `token` + `nodes` and so decodes as [`Response::GetPeers`] with
    /// `Nodes`, exactly like a `get_peers` miss.)
    Get {
        token: Vec<u8>,
        item: GetItem,
        nodes: Vec<NodeInfo>,
    },
    SampleInfohashes(SampleInfohashesResponse),
    /// BEP 33 `scrape` response.
    Scrape(crate::sample::DhtScrapeResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Query(Query),
    Response(Response),
    Error { code: i64, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub transaction_id: Vec<u8>,
    /// The sender's own node id. Absent on well-formed error messages (BEP5 doesn't
    /// require one there), so callers that need it for e.g. routing-table bookkeeping
    /// should treat `Body::Error` as having no associated id.
    pub sender_id: Option<NodeId>,
    pub body: Body,
    /// BEP 43: the sender is a read-only node (`ro: 1`). Such nodes send queries but do not
    /// answer them, so they must not be added to a routing table.
    pub read_only: bool,
    /// BEP 42: the address the *recipient* of this message appears to have (the `ip` key of a
    /// reply), so a node can learn its own public address. Present on replies we send, and
    /// read from replies we receive.
    pub external_addr: Option<std::net::SocketAddr>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtoError {
    #[error("malformed bencode")]
    Bencode,
    #[error("malformed KRPC message: {0}")]
    Malformed(&'static str),
    #[error("unknown query method: {0}")]
    UnknownQuery(String),
}

/// Compact `ip` field of BEP 42: 4 (or 16) address bytes followed by the 2-byte port.
fn compact_socket_addr(addr: std::net::SocketAddr) -> Vec<u8> {
    let mut out = match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
        std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

fn parse_compact_socket_addr(b: &[u8]) -> Option<std::net::SocketAddr> {
    match b.len() {
        6 => Some(std::net::SocketAddr::new(
            std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).into(),
            u16::from_be_bytes([b[4], b[5]]),
        )),
        18 => {
            let ip: [u8; 16] = b[..16].try_into().ok()?;
            Some(std::net::SocketAddr::new(
                ip.into(),
                u16::from_be_bytes([b[16], b[17]]),
            ))
        }
        _ => None,
    }
}

fn node_id_from(v: Option<BEncode>) -> Option<NodeId> {
    v.and_then(BEncode::into_bytes)?.try_into().ok()
}

pub fn compact_nodes_encode(nodes: &[NodeInfo]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nodes.len() * 26);
    for n in nodes {
        out.extend_from_slice(&n.id);
        out.extend_from_slice(&n.addr.ip().octets());
        out.extend_from_slice(&n.addr.port().to_be_bytes());
    }
    out
}

pub fn compact_nodes_decode(data: &[u8]) -> Result<Vec<NodeInfo>, ProtoError> {
    if !data.len().is_multiple_of(26) {
        return Err(ProtoError::Malformed(
            "compact node list length not a multiple of 26",
        ));
    }
    Ok(data
        .as_chunks::<26>()
        .0
        .iter()
        .map(|c| NodeInfo {
            id: c[0..20].try_into().unwrap(),
            addr: SocketAddrV4::new(
                Ipv4Addr::new(c[20], c[21], c[22], c[23]),
                u16::from_be_bytes([c[24], c[25]]),
            ),
        })
        .collect())
}

pub fn compact_nodes6_encode(nodes: &[NodeInfoV6]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nodes.len() * 38);
    for n in nodes {
        out.extend_from_slice(&n.id);
        out.extend_from_slice(&n.addr.ip().octets());
        out.extend_from_slice(&n.addr.port().to_be_bytes());
    }
    out
}

pub fn compact_nodes6_decode(data: &[u8]) -> Result<Vec<NodeInfoV6>, ProtoError> {
    if !data.len().is_multiple_of(38) {
        return Err(ProtoError::Malformed(
            "compact IPv6 node list length not a multiple of 38",
        ));
    }
    Ok(data
        .as_chunks::<38>()
        .0
        .iter()
        .map(|c| NodeInfoV6 {
            id: c[0..20].try_into().unwrap(),
            addr: SocketAddrV6::new(
                Ipv6Addr::from(TryInto::<[u8; 16]>::try_into(&c[20..36]).unwrap()),
                u16::from_be_bytes([c[36], c[37]]),
                0,
                0,
            ),
        })
        .collect())
}

pub fn compact_peer_encode(addr: &SocketAddrV4) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&addr.ip().octets());
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

pub fn compact_peer_decode(data: &[u8]) -> Option<SocketAddrV4> {
    if data.len() != 6 {
        return None;
    }
    Some(SocketAddrV4::new(
        Ipv4Addr::new(data[0], data[1], data[2], data[3]),
        u16::from_be_bytes([data[4], data[5]]),
    ))
}

pub fn compact_peer6_encode(addr: &SocketAddrV6) -> Vec<u8> {
    let mut out = Vec::with_capacity(18);
    out.extend_from_slice(&addr.ip().octets());
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

pub fn compact_peer6_decode(data: &[u8]) -> Option<SocketAddrV6> {
    if data.len() != 18 {
        return None;
    }
    let ip_bytes: [u8; 16] = data[0..16].try_into().ok()?;
    let port = u16::from_be_bytes([data[16], data[17]]);
    Some(SocketAddrV6::new(Ipv6Addr::from(ip_bytes), port, 0, 0))
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut top = BTreeMap::new();
        top.insert(b"t".to_vec(), BEncode::String(self.transaction_id.clone()));
        top.insert(b"v".to_vec(), BEncode::String(b"sy01".to_vec()));
        if let Some(addr) = self.external_addr {
            top.insert(b"ip".to_vec(), BEncode::String(compact_socket_addr(addr)));
        }

        match &self.body {
            Body::Query(q) => {
                top.insert(b"y".to_vec(), BEncode::String(b"q".to_vec()));
                if self.read_only {
                    top.insert(b"ro".to_vec(), BEncode::Int(1));
                }
                let mut a = BTreeMap::new();
                a.insert(
                    b"id".to_vec(),
                    BEncode::String(
                        self.sender_id
                            .expect("a query always carries our id")
                            .to_vec(),
                    ),
                );
                let method: &[u8] = match q {
                    Query::Ping => b"ping",
                    Query::FindNode { target, want } => {
                        a.insert(b"target".to_vec(), BEncode::String(target.to_vec()));
                        if let Some(w) = want {
                            a.insert(
                                b"want".to_vec(),
                                BEncode::List(
                                    w.iter()
                                        .map(|s| BEncode::String(s.as_bytes().to_vec()))
                                        .collect(),
                                ),
                            );
                        }
                        b"find_node"
                    }
                    Query::GetPeers { info_hash, want } => {
                        a.insert(b"info_hash".to_vec(), BEncode::String(info_hash.to_vec()));
                        if let Some(w) = want {
                            a.insert(
                                b"want".to_vec(),
                                BEncode::List(
                                    w.iter()
                                        .map(|s| BEncode::String(s.as_bytes().to_vec()))
                                        .collect(),
                                ),
                            );
                        }
                        b"get_peers"
                    }
                    Query::AnnouncePeer {
                        info_hash,
                        port,
                        token,
                        implied_port,
                    } => {
                        a.insert(b"info_hash".to_vec(), BEncode::String(info_hash.to_vec()));
                        a.insert(b"port".to_vec(), BEncode::Int(*port as i64));
                        a.insert(b"token".to_vec(), BEncode::String(token.clone()));
                        a.insert(
                            b"implied_port".to_vec(),
                            BEncode::Int(if *implied_port { 1 } else { 0 }),
                        );
                        b"announce_peer"
                    }
                    Query::Get { target, seq } => {
                        a.insert(b"target".to_vec(), BEncode::String(target.to_vec()));
                        if let Some(seq) = seq {
                            a.insert(b"seq".to_vec(), BEncode::Int(*seq as i64));
                        }
                        b"get"
                    }
                    Query::Put(put) => {
                        a.insert(b"token".to_vec(), BEncode::String(put.token.clone()));
                        if let Ok(v) = synapse_bencode::decode_buf(&put.v) {
                            a.insert(b"v".to_vec(), v);
                        }
                        if let Some(k) = put.k {
                            a.insert(b"k".to_vec(), BEncode::String(k.to_vec()));
                        }
                        if let Some(sig) = put.sig {
                            a.insert(b"sig".to_vec(), BEncode::String(sig.to_vec()));
                        }
                        if let Some(seq) = put.seq {
                            a.insert(b"seq".to_vec(), BEncode::Int(seq as i64));
                        }
                        if let Some(cas) = put.cas {
                            a.insert(b"cas".to_vec(), BEncode::Int(cas as i64));
                        }
                        if let Some(ref salt) = put.salt {
                            a.insert(b"salt".to_vec(), BEncode::String(salt.clone()));
                        }
                        b"put"
                    }
                    Query::SampleInfohashes { target } => {
                        a.insert(b"target".to_vec(), BEncode::String(target.to_vec()));
                        b"sample_infohashes"
                    }
                    Query::Scrape { info_hash } => {
                        a.insert(b"info_hash".to_vec(), BEncode::String(info_hash.to_vec()));
                        b"scrape"
                    }
                };
                top.insert(b"q".to_vec(), BEncode::String(method.to_vec()));
                top.insert(b"a".to_vec(), BEncode::Dict(a));
            }
            Body::Response(r) => {
                top.insert(b"y".to_vec(), BEncode::String(b"r".to_vec()));
                let mut rd = BTreeMap::new();
                rd.insert(
                    b"id".to_vec(),
                    BEncode::String(
                        self.sender_id
                            .expect("a response always carries our id")
                            .to_vec(),
                    ),
                );
                match r {
                    Response::Id => {}
                    Response::FindNode { nodes, nodes6 } => {
                        if !nodes.is_empty() || nodes6.is_empty() {
                            rd.insert(
                                b"nodes".to_vec(),
                                BEncode::String(compact_nodes_encode(nodes)),
                            );
                        }
                        if !nodes6.is_empty() {
                            rd.insert(
                                b"nodes6".to_vec(),
                                BEncode::String(compact_nodes6_encode(nodes6)),
                            );
                        }
                    }
                    Response::Get { token, item, nodes } => {
                        rd.insert(b"token".to_vec(), BEncode::String(token.clone()));
                        if let Ok(v) = synapse_bencode::decode_buf(&item.v) {
                            rd.insert(b"v".to_vec(), v);
                        }
                        if let Some(k) = item.k {
                            rd.insert(b"k".to_vec(), BEncode::String(k.to_vec()));
                        }
                        if let Some(sig) = item.sig {
                            rd.insert(b"sig".to_vec(), BEncode::String(sig.to_vec()));
                        }
                        if let Some(seq) = item.seq {
                            rd.insert(b"seq".to_vec(), BEncode::Int(seq as i64));
                        }
                        if !nodes.is_empty() {
                            rd.insert(
                                b"nodes".to_vec(),
                                BEncode::String(compact_nodes_encode(nodes)),
                            );
                        }
                    }
                    Response::SampleInfohashes(sample) => {
                        if let BEncode::Dict(d) =
                            crate::sample::encode_sample_infohashes_response(&[0u8; 20], sample)
                        {
                            for (k, v) in d {
                                if k != b"id" {
                                    rd.insert(k, v);
                                }
                            }
                        }
                    }
                    Response::Scrape(scrape) => {
                        if let BEncode::Dict(d) =
                            crate::sample::encode_dht_scrape_response(&[0u8; 20], scrape)
                        {
                            for (k, v) in d {
                                if k != b"id" {
                                    rd.insert(k, v);
                                }
                            }
                        }
                    }
                    Response::GetPeers { token, result } => {
                        rd.insert(b"token".to_vec(), BEncode::String(token.clone()));
                        match result {
                            GetPeersResult::Peers(peers) => {
                                rd.insert(
                                    b"values".to_vec(),
                                    BEncode::List(
                                        peers
                                            .iter()
                                            .map(|p| BEncode::String(compact_peer_encode(p)))
                                            .collect(),
                                    ),
                                );
                            }
                            GetPeersResult::Peers6(peers) => {
                                rd.insert(
                                    b"values6".to_vec(),
                                    BEncode::List(
                                        peers
                                            .iter()
                                            .map(|p| BEncode::String(compact_peer6_encode(p)))
                                            .collect(),
                                    ),
                                );
                            }
                            GetPeersResult::Nodes(nodes) => {
                                rd.insert(
                                    b"nodes".to_vec(),
                                    BEncode::String(compact_nodes_encode(nodes)),
                                );
                            }
                            GetPeersResult::Nodes6(nodes) => {
                                rd.insert(
                                    b"nodes6".to_vec(),
                                    BEncode::String(compact_nodes6_encode(nodes)),
                                );
                            }
                        }
                    }
                }
                top.insert(b"r".to_vec(), BEncode::Dict(rd));
            }
            Body::Error { code, message } => {
                top.insert(b"y".to_vec(), BEncode::String(b"e".to_vec()));
                top.insert(
                    b"e".to_vec(),
                    BEncode::List(vec![
                        BEncode::Int(*code),
                        BEncode::String(message.clone().into_bytes()),
                    ]),
                );
            }
        }

        BEncode::Dict(top).encode_to_buf()
    }

    pub fn decode(data: &[u8]) -> Result<Message, ProtoError> {
        // KRPC messages are tiny and shallow; refuse anything deeper than 10 levels or with
        // more than 500 values before building it (libtorrent applies the same budget).
        let value =
            synapse_bencode::decode_buf_limited(data, 10, 500).map_err(|_| ProtoError::Bencode)?;
        let mut top = value
            .into_dict()
            .ok_or(ProtoError::Malformed("top level is not a dict"))?;

        let external_addr = top
            .remove(b"ip".as_ref())
            .and_then(BEncode::into_bytes)
            .and_then(|b| parse_compact_socket_addr(&b));
        let transaction_id = top
            .remove(b"t".as_ref())
            .and_then(BEncode::into_bytes)
            .ok_or(ProtoError::Malformed("missing transaction id"))?;
        let y = top
            .remove(b"y".as_ref())
            .and_then(BEncode::into_bytes)
            .ok_or(ProtoError::Malformed("missing message type"))?;

        match y.as_slice() {
            b"q" => {
                let read_only = top.remove(b"ro".as_ref()).and_then(BEncode::into_int) == Some(1);
                let mut a = top
                    .remove(b"a".as_ref())
                    .and_then(BEncode::into_dict)
                    .ok_or(ProtoError::Malformed("query missing arguments"))?;
                let sender_id = node_id_from(a.remove(b"id".as_ref()))
                    .ok_or(ProtoError::Malformed("query missing id"))?;
                let method = top
                    .remove(b"q".as_ref())
                    .and_then(BEncode::into_bytes)
                    .ok_or(ProtoError::Malformed("missing query method"))?;
                let want = a
                    .remove(b"want".as_ref())
                    .and_then(BEncode::into_list)
                    .map(|list| list.into_iter().filter_map(BEncode::into_string).collect());
                let query = match method.as_slice() {
                    b"ping" => Query::Ping,
                    b"find_node" => {
                        let target = node_id_from(a.remove(b"target".as_ref()))
                            .ok_or(ProtoError::Malformed("find_node missing target"))?;
                        Query::FindNode { target, want }
                    }
                    b"get_peers" => {
                        let info_hash = node_id_from(a.remove(b"info_hash".as_ref()))
                            .ok_or(ProtoError::Malformed("get_peers missing info_hash"))?;
                        Query::GetPeers { info_hash, want }
                    }
                    b"announce_peer" => {
                        let info_hash = node_id_from(a.remove(b"info_hash".as_ref()))
                            .ok_or(ProtoError::Malformed("announce_peer missing info_hash"))?;
                        let port = a
                            .remove(b"port".as_ref())
                            .and_then(BEncode::into_int)
                            .and_then(|p| u16::try_from(p).ok())
                            .ok_or(ProtoError::Malformed(
                                "announce_peer missing or out-of-range port",
                            ))?;
                        let token = a
                            .remove(b"token".as_ref())
                            .and_then(BEncode::into_bytes)
                            .ok_or(ProtoError::Malformed("announce_peer missing token"))?;
                        let implied_port = a
                            .remove(b"implied_port".as_ref())
                            .and_then(BEncode::into_int)
                            .map(|v| v != 0)
                            .unwrap_or(false);
                        Query::AnnouncePeer {
                            info_hash,
                            port,
                            token,
                            implied_port,
                        }
                    }
                    b"get" => {
                        let target = node_id_from(a.remove(b"target".as_ref()))
                            .ok_or(ProtoError::Malformed("get missing target"))?;
                        let seq = a
                            .remove(b"seq".as_ref())
                            .and_then(BEncode::into_int)
                            .and_then(|s| u64::try_from(s).ok());
                        Query::Get { target, seq }
                    }
                    b"put" => {
                        let token = a
                            .remove(b"token".as_ref())
                            .and_then(BEncode::into_bytes)
                            .ok_or(ProtoError::Malformed("put missing token"))?;
                        let v = a
                            .remove(b"v".as_ref())
                            .map(|v| v.encode_to_buf())
                            .ok_or(ProtoError::Malformed("put missing v"))?;
                        let k = a
                            .remove(b"k".as_ref())
                            .and_then(BEncode::into_bytes)
                            .and_then(|b| b.try_into().ok());
                        let sig = a
                            .remove(b"sig".as_ref())
                            .and_then(BEncode::into_bytes)
                            .and_then(|b| b.try_into().ok());
                        let seq = a
                            .remove(b"seq".as_ref())
                            .and_then(BEncode::into_int)
                            .and_then(|s| u64::try_from(s).ok());
                        let cas = a
                            .remove(b"cas".as_ref())
                            .and_then(BEncode::into_int)
                            .and_then(|s| u64::try_from(s).ok());
                        let salt = a.remove(b"salt".as_ref()).and_then(BEncode::into_bytes);
                        Query::Put(PutArgs {
                            token,
                            v,
                            k,
                            sig,
                            seq,
                            cas,
                            salt,
                        })
                    }
                    b"sample_infohashes" => {
                        let target = node_id_from(a.remove(b"target".as_ref()))
                            .ok_or(ProtoError::Malformed("sample_infohashes missing target"))?;
                        Query::SampleInfohashes { target }
                    }
                    b"scrape" => {
                        let info_hash = node_id_from(a.remove(b"info_hash".as_ref()))
                            .ok_or(ProtoError::Malformed("scrape missing info_hash"))?;
                        Query::Scrape { info_hash }
                    }
                    other => {
                        return Err(ProtoError::UnknownQuery(
                            String::from_utf8_lossy(other).into_owned(),
                        ))
                    }
                };
                Ok(Message {
                    transaction_id,
                    sender_id: Some(sender_id),
                    body: Body::Query(query),
                    read_only,
                    external_addr: None,
                })
            }
            b"r" => {
                let mut r = top
                    .remove(b"r".as_ref())
                    .and_then(BEncode::into_dict)
                    .ok_or(ProtoError::Malformed("response missing return values"))?;
                let sender_id = node_id_from(r.remove(b"id".as_ref()))
                    .ok_or(ProtoError::Malformed("response missing id"))?;
                let response = if r.contains_key(b"samples".as_ref()) {
                    Response::SampleInfohashes(
                        crate::sample::decode_sample_infohashes_response(&mut r)
                            .map_err(|_| ProtoError::Malformed("bad sample_infohashes response"))?,
                    )
                } else if r.contains_key(b"sn".as_ref())
                    || r.contains_key(b"ln".as_ref())
                    || r.contains_key(b"BFsd".as_ref())
                    || r.contains_key(b"BFpe".as_ref())
                {
                    Response::Scrape(
                        crate::sample::decode_dht_scrape_response(&mut r)
                            .map_err(|_| ProtoError::Malformed("bad scrape response"))?,
                    )
                } else if let (true, Some(token)) = (
                    r.contains_key(b"v".as_ref()),
                    r.get(b"token".as_ref())
                        .cloned()
                        .and_then(BEncode::into_bytes),
                ) {
                    let v = r
                        .remove(b"v".as_ref())
                        .map(|v| v.encode_to_buf())
                        .unwrap_or_default();
                    let k = r
                        .remove(b"k".as_ref())
                        .and_then(BEncode::into_bytes)
                        .and_then(|b| b.try_into().ok());
                    let sig = r
                        .remove(b"sig".as_ref())
                        .and_then(BEncode::into_bytes)
                        .and_then(|b| b.try_into().ok());
                    let seq = r
                        .remove(b"seq".as_ref())
                        .and_then(BEncode::into_int)
                        .and_then(|s| u64::try_from(s).ok());
                    let nodes = match r.remove(b"nodes".as_ref()).and_then(BEncode::into_bytes) {
                        Some(n) => compact_nodes_decode(&n)?,
                        None => Vec::new(),
                    };
                    Response::Get {
                        token,
                        item: GetItem { v, k, sig, seq },
                        nodes,
                    }
                } else if let Some(token) =
                    r.remove(b"token".as_ref()).and_then(BEncode::into_bytes)
                {
                    let result = if let Some(values) =
                        r.remove(b"values".as_ref()).and_then(BEncode::into_list)
                    {
                        GetPeersResult::Peers(
                            values
                                .into_iter()
                                .filter_map(|v| v.into_bytes())
                                .filter_map(|b| compact_peer_decode(&b))
                                .collect(),
                        )
                    } else if let Some(values6) =
                        r.remove(b"values6".as_ref()).and_then(BEncode::into_list)
                    {
                        GetPeersResult::Peers6(
                            values6
                                .into_iter()
                                .filter_map(|v| v.into_bytes())
                                .filter_map(|b| compact_peer6_decode(&b))
                                .collect(),
                        )
                    } else if let Some(nodes6) =
                        r.remove(b"nodes6".as_ref()).and_then(BEncode::into_bytes)
                    {
                        GetPeersResult::Nodes6(compact_nodes6_decode(&nodes6)?)
                    } else if let Some(nodes) =
                        r.remove(b"nodes".as_ref()).and_then(BEncode::into_bytes)
                    {
                        GetPeersResult::Nodes(compact_nodes_decode(&nodes)?)
                    } else {
                        return Err(ProtoError::Malformed(
                            "get_peers response missing values/nodes",
                        ));
                    };
                    Response::GetPeers { token, result }
                } else if r.contains_key(b"nodes".as_ref()) || r.contains_key(b"nodes6".as_ref()) {
                    let nodes = if let Some(n) =
                        r.remove(b"nodes".as_ref()).and_then(BEncode::into_bytes)
                    {
                        compact_nodes_decode(&n)?
                    } else {
                        Vec::new()
                    };
                    let nodes6 = if let Some(n6) =
                        r.remove(b"nodes6".as_ref()).and_then(BEncode::into_bytes)
                    {
                        compact_nodes6_decode(&n6)?
                    } else {
                        Vec::new()
                    };
                    Response::FindNode { nodes, nodes6 }
                } else {
                    Response::Id
                };
                Ok(Message {
                    transaction_id,
                    sender_id: Some(sender_id),
                    body: Body::Response(response),
                    read_only: false,
                    external_addr,
                })
            }
            b"e" => {
                let mut e = top
                    .remove(b"e".as_ref())
                    .and_then(BEncode::into_list)
                    .ok_or(ProtoError::Malformed("error missing details"))?;
                if e.len() != 2 {
                    return Err(ProtoError::Malformed(
                        "error details must be [code, message]",
                    ));
                }
                let message = e
                    .pop()
                    .and_then(BEncode::into_string)
                    .ok_or(ProtoError::Malformed("error message not a string"))?;
                let code = e
                    .pop()
                    .and_then(BEncode::into_int)
                    .ok_or(ProtoError::Malformed("error code not an int"))?;
                Ok(Message {
                    transaction_id,
                    sender_id: None,
                    body: Body::Error { code, message },
                    read_only: false,
                    external_addr: None,
                })
            }
            _ => Err(ProtoError::Malformed("unknown message type")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> NodeId {
        [b; 20]
    }

    fn roundtrip(msg: Message) -> Message {
        let encoded = msg.encode();
        Message::decode(&encoded).unwrap()
    }

    #[test]
    fn ping_query_roundtrip() {
        let msg = Message {
            transaction_id: vec![1, 2],
            sender_id: Some(id(9)),
            body: Body::Query(Query::Ping),
            read_only: false,
            external_addr: None,
        };
        assert_eq!(roundtrip(msg.clone()), msg);
    }

    #[test]
    fn find_node_query_and_response_roundtrip() {
        let query = Message {
            transaction_id: vec![0xAB],
            sender_id: Some(id(1)),
            body: Body::Query(Query::FindNode {
                target: id(2),
                want: Some(vec!["n4".into(), "n6".into()]),
            }),
            read_only: false,
            external_addr: None,
        };
        assert_eq!(roundtrip(query.clone()), query);

        let nodes = vec![
            NodeInfo {
                id: id(3),
                addr: SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 6881),
            },
            NodeInfo {
                id: id(4),
                addr: SocketAddrV4::new(Ipv4Addr::new(5, 6, 7, 8), 6882),
            },
        ];
        let nodes6 = vec![NodeInfoV6 {
            id: id(5),
            addr: SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 6881, 0, 0),
        }];
        let resp = Message {
            transaction_id: vec![0xAB],
            sender_id: Some(id(1)),
            body: Body::Response(Response::FindNode {
                nodes: nodes.clone(),
                nodes6: nodes6.clone(),
            }),
            read_only: false,
            external_addr: None,
        };
        assert_eq!(roundtrip(resp.clone()), resp);
    }

    #[test]
    fn get_peers_query_and_both_response_shapes_roundtrip() {
        let query = Message {
            transaction_id: vec![7, 7],
            sender_id: Some(id(1)),
            body: Body::Query(Query::GetPeers {
                info_hash: id(5),
                want: None,
            }),
            read_only: false,
            external_addr: None,
        };
        assert_eq!(roundtrip(query.clone()), query);

        let peers_resp = Message {
            transaction_id: vec![7, 7],
            sender_id: Some(id(1)),
            body: Body::Response(Response::GetPeers {
                token: vec![0xCA, 0xFE],
                result: GetPeersResult::Peers(vec![SocketAddrV4::new(
                    Ipv4Addr::new(9, 9, 9, 9),
                    1234,
                )]),
            }),
            read_only: false,
            external_addr: None,
        };
        assert_eq!(roundtrip(peers_resp.clone()), peers_resp);

        let peers6_resp = Message {
            transaction_id: vec![7, 7],
            sender_id: Some(id(1)),
            body: Body::Response(Response::GetPeers {
                token: vec![0xCA, 0xFE],
                result: GetPeersResult::Peers6(vec![SocketAddrV6::new(
                    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
                    51413,
                    0,
                    0,
                )]),
            }),
            read_only: false,
            external_addr: None,
        };
        assert_eq!(roundtrip(peers6_resp.clone()), peers6_resp);

        let nodes_resp = Message {
            transaction_id: vec![7, 7],
            sender_id: Some(id(1)),
            body: Body::Response(Response::GetPeers {
                token: vec![0xCA, 0xFE],
                result: GetPeersResult::Nodes(vec![NodeInfo {
                    id: id(2),
                    addr: SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 1),
                }]),
            }),
            read_only: false,
            external_addr: None,
        };
        assert_eq!(roundtrip(nodes_resp.clone()), nodes_resp);
    }

    #[test]
    fn announce_peer_query_roundtrip() {
        let msg = Message {
            transaction_id: vec![1],
            sender_id: Some(id(1)),
            body: Body::Query(Query::AnnouncePeer {
                info_hash: id(6),
                port: 6881,
                token: vec![1, 2, 3],
                implied_port: true,
            }),
            read_only: false,
            external_addr: None,
        };
        assert_eq!(roundtrip(msg.clone()), msg);
    }

    #[test]
    fn id_only_response_roundtrip() {
        let msg = Message {
            transaction_id: vec![1],
            sender_id: Some(id(1)),
            body: Body::Response(Response::Id),
            read_only: false,
            external_addr: None,
        };
        assert_eq!(roundtrip(msg.clone()), msg);
    }

    #[test]
    fn error_message_roundtrip() {
        let msg = Message {
            transaction_id: vec![1],
            sender_id: None,
            body: Body::Error {
                code: 201,
                message: "A Generic Error Ocurred".to_owned(),
            },
            read_only: false,
            external_addr: None,
        };
        assert_eq!(roundtrip(msg.clone()), msg);
    }

    #[test]
    fn decode_rejects_ragged_compact_node_list() {
        let mut top = BTreeMap::new();
        top.insert(b"t".to_vec(), BEncode::String(vec![1]));
        top.insert(b"y".to_vec(), BEncode::String(b"r".to_vec()));
        let mut r = BTreeMap::new();
        r.insert(b"id".to_vec(), BEncode::String(id(1).to_vec()));
        r.insert(b"nodes".to_vec(), BEncode::String(vec![0u8; 25])); // not a multiple of 26
        top.insert(b"r".to_vec(), BEncode::Dict(r));
        let encoded = BEncode::Dict(top).encode_to_buf();
        assert!(matches!(
            Message::decode(&encoded),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn decode_rejects_unknown_query_method() {
        let mut top = BTreeMap::new();
        top.insert(b"t".to_vec(), BEncode::String(vec![1]));
        top.insert(b"y".to_vec(), BEncode::String(b"q".to_vec()));
        top.insert(
            b"q".to_vec(),
            BEncode::String(b"not_a_real_method".to_vec()),
        );
        let mut a = BTreeMap::new();
        a.insert(b"id".to_vec(), BEncode::String(id(1).to_vec()));
        top.insert(b"a".to_vec(), BEncode::Dict(a));
        let encoded = BEncode::Dict(top).encode_to_buf();
        assert!(matches!(
            Message::decode(&encoded),
            Err(ProtoError::UnknownQuery(_))
        ));
    }

    #[test]
    fn bep44_and_bep51_messages_roundtrip_including_the_ro_flag() {
        let put = Message {
            transaction_id: vec![9],
            sender_id: Some(id(1)),
            body: Body::Query(Query::Put(PutArgs {
                token: vec![1, 2],
                v: b"5:hello".to_vec(),
                k: Some([3u8; 32]),
                sig: Some([4u8; 64]),
                seq: Some(7),
                cas: Some(6),
                salt: Some(b"salt".to_vec()),
            })),
            read_only: true,
            external_addr: None,
        };
        assert_eq!(roundtrip(put.clone()), put);

        let get = Message {
            transaction_id: vec![9],
            sender_id: Some(id(1)),
            body: Body::Query(Query::Get {
                target: id(5),
                seq: Some(3),
            }),
            read_only: false,
            external_addr: None,
        };
        assert_eq!(roundtrip(get.clone()), get);

        let get_resp = Message {
            transaction_id: vec![9],
            sender_id: Some(id(2)),
            body: Body::Response(Response::Get {
                token: vec![8],
                item: GetItem {
                    v: b"i5e".to_vec(),
                    k: Some([3u8; 32]),
                    sig: Some([4u8; 64]),
                    seq: Some(2),
                },
                nodes: vec![NodeInfo {
                    id: id(4),
                    addr: SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 5),
                }],
            }),
            read_only: false,
            external_addr: None,
        };
        assert_eq!(roundtrip(get_resp.clone()), get_resp);

        let sample = Message {
            transaction_id: vec![9],
            sender_id: Some(id(2)),
            body: Body::Response(Response::SampleInfohashes(SampleInfohashesResponse {
                samples: vec![[1u8; 20], [2u8; 20]],
                num: 2,
                interval: 3600,
                nodes: vec![],
                nodes6: vec![],
            })),
            read_only: false,
            external_addr: None,
        };
        assert_eq!(roundtrip(sample.clone()), sample);
        let q = Message {
            transaction_id: vec![9],
            sender_id: Some(id(1)),
            body: Body::Query(Query::SampleInfohashes { target: id(3) }),
            read_only: false,
            external_addr: None,
        };
        assert_eq!(roundtrip(q.clone()), q);

        let scrape_q = Message {
            transaction_id: vec![10],
            sender_id: Some(id(1)),
            body: Body::Query(Query::Scrape { info_hash: id(7) }),
            read_only: false,
            external_addr: None,
        };
        assert_eq!(roundtrip(scrape_q.clone()), scrape_q);

        let scrape_r = Message {
            transaction_id: vec![10],
            sender_id: Some(id(2)),
            body: Body::Response(Response::Scrape(crate::sample::DhtScrapeResponse {
                seeders: 5,
                leechers: 12,
                bfsd: Some(vec![1, 2, 3]),
                bfpe: Some(vec![4, 5, 6]),
            })),
            read_only: false,
            external_addr: None,
        };
        assert_eq!(roundtrip(scrape_r.clone()), scrape_r);
    }

    #[test]
    fn announce_peer_with_an_out_of_range_port_is_rejected_not_truncated() {
        // Port 70000 used to wrap to 4464 via `as u16`.
        let raw = b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaa9:info_hash20:bbbbbbbbbbbbbbbbbbbb4:porti70000e5:token1:xe1:q13:announce_peer1:t1:a1:y1:qe";
        assert!(Message::decode(raw).is_err());
    }
}
