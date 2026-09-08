//! KRPC message encoding/decoding (the bencoded protocol BEP5 DHT messages use). Pure
//! parsing/building, no networking - see `node.rs` for the actual UDP-socket-driven
//! client. IPv4 only for this first cut, matching the pre-rewrite codebase's scope
//! (BEP32 IPv6 DHT support is a documented gap there too, not a regression here).

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use synapse_bencode::BEncode;

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
        return Err(ProtoError::Malformed("compact node list length not a multiple of 26"));
    }
    Ok(data
        .chunks_exact(26)
        .map(|c| NodeInfo {
            id: c[0..20].try_into().unwrap(),
            addr: SocketAddrV4::new(Ipv4Addr::new(c[20], c[21], c[22], c[23]), u16::from_be_bytes([c[24], c[25]])),
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
        return Err(ProtoError::Malformed("compact IPv6 node list length not a multiple of 38"));
    }
    Ok(data
        .chunks_exact(38)
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

        match &self.body {
            Body::Query(q) => {
                top.insert(b"y".to_vec(), BEncode::String(b"q".to_vec()));
                let mut a = BTreeMap::new();
                a.insert(
                    b"id".to_vec(),
                    BEncode::String(self.sender_id.expect("a query always carries our id").to_vec()),
                );
                let method: &[u8] = match q {
                    Query::Ping => b"ping",
                    Query::FindNode { target, want } => {
                        a.insert(b"target".to_vec(), BEncode::String(target.to_vec()));
                        if let Some(w) = want {
                            a.insert(
                                b"want".to_vec(),
                                BEncode::List(w.iter().map(|s| BEncode::String(s.as_bytes().to_vec())).collect()),
                            );
                        }
                        b"find_node"
                    }
                    Query::GetPeers { info_hash, want } => {
                        a.insert(b"info_hash".to_vec(), BEncode::String(info_hash.to_vec()));
                        if let Some(w) = want {
                            a.insert(
                                b"want".to_vec(),
                                BEncode::List(w.iter().map(|s| BEncode::String(s.as_bytes().to_vec())).collect()),
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
                };
                top.insert(b"q".to_vec(), BEncode::String(method.to_vec()));
                top.insert(b"a".to_vec(), BEncode::Dict(a));
            }
            Body::Response(r) => {
                top.insert(b"y".to_vec(), BEncode::String(b"r".to_vec()));
                let mut rd = BTreeMap::new();
                rd.insert(
                    b"id".to_vec(),
                    BEncode::String(self.sender_id.expect("a response always carries our id").to_vec()),
                );
                match r {
                    Response::Id => {}
                    Response::FindNode { nodes, nodes6 } => {
                        if !nodes.is_empty() || nodes6.is_empty() {
                            rd.insert(b"nodes".to_vec(), BEncode::String(compact_nodes_encode(nodes)));
                        }
                        if !nodes6.is_empty() {
                            rd.insert(b"nodes6".to_vec(), BEncode::String(compact_nodes6_encode(nodes6)));
                        }
                    }
                    Response::GetPeers { token, result } => {
                        rd.insert(b"token".to_vec(), BEncode::String(token.clone()));
                        match result {
                            GetPeersResult::Peers(peers) => {
                                rd.insert(
                                    b"values".to_vec(),
                                    BEncode::List(
                                        peers.iter().map(|p| BEncode::String(compact_peer_encode(p))).collect(),
                                    ),
                                );
                            }
                            GetPeersResult::Peers6(peers) => {
                                rd.insert(
                                    b"values6".to_vec(),
                                    BEncode::List(
                                        peers.iter().map(|p| BEncode::String(compact_peer6_encode(p))).collect(),
                                    ),
                                );
                            }
                            GetPeersResult::Nodes(nodes) => {
                                rd.insert(b"nodes".to_vec(), BEncode::String(compact_nodes_encode(nodes)));
                            }
                            GetPeersResult::Nodes6(nodes) => {
                                rd.insert(b"nodes6".to_vec(), BEncode::String(compact_nodes6_encode(nodes)));
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
        let value = synapse_bencode::decode_buf(data).map_err(|_| ProtoError::Bencode)?;
        let mut top = value.into_dict().ok_or(ProtoError::Malformed("top level is not a dict"))?;

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
                let mut a = top
                    .remove(b"a".as_ref())
                    .and_then(BEncode::into_dict)
                    .ok_or(ProtoError::Malformed("query missing arguments"))?;
                let sender_id = node_id_from(a.remove(b"id".as_ref())).ok_or(ProtoError::Malformed("query missing id"))?;
                let method = top
                    .remove(b"q".as_ref())
                    .and_then(BEncode::into_bytes)
                    .ok_or(ProtoError::Malformed("missing query method"))?;
                let want = a.remove(b"want".as_ref()).and_then(BEncode::into_list).map(|list| {
                    list.into_iter().filter_map(BEncode::into_string).collect()
                });
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
                            .ok_or(ProtoError::Malformed("announce_peer missing port"))? as u16;
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
                    other => {
                        return Err(ProtoError::UnknownQuery(String::from_utf8_lossy(other).into_owned()))
                    }
                };
                Ok(Message {
                    transaction_id,
                    sender_id: Some(sender_id),
                    body: Body::Query(query),
                })
            }
            b"r" => {
                let mut r = top
                    .remove(b"r".as_ref())
                    .and_then(BEncode::into_dict)
                    .ok_or(ProtoError::Malformed("response missing return values"))?;
                let sender_id =
                    node_id_from(r.remove(b"id".as_ref())).ok_or(ProtoError::Malformed("response missing id"))?;
                let response = if let Some(token) = r.remove(b"token".as_ref()).and_then(BEncode::into_bytes) {
                    let result = if let Some(values) = r.remove(b"values".as_ref()).and_then(BEncode::into_list) {
                        GetPeersResult::Peers(
                            values
                                .into_iter()
                                .filter_map(|v| v.into_bytes())
                                .filter_map(|b| compact_peer_decode(&b))
                                .collect(),
                        )
                    } else if let Some(values6) = r.remove(b"values6".as_ref()).and_then(BEncode::into_list) {
                        GetPeersResult::Peers6(
                            values6
                                .into_iter()
                                .filter_map(|v| v.into_bytes())
                                .filter_map(|b| compact_peer6_decode(&b))
                                .collect(),
                        )
                    } else if let Some(nodes6) = r.remove(b"nodes6".as_ref()).and_then(BEncode::into_bytes) {
                        GetPeersResult::Nodes6(compact_nodes6_decode(&nodes6)?)
                    } else if let Some(nodes) = r.remove(b"nodes".as_ref()).and_then(BEncode::into_bytes) {
                        GetPeersResult::Nodes(compact_nodes_decode(&nodes)?)
                    } else {
                        return Err(ProtoError::Malformed("get_peers response missing values/nodes"));
                    };
                    Response::GetPeers { token, result }
                } else if r.contains_key(b"nodes".as_ref()) || r.contains_key(b"nodes6".as_ref()) {
                    let nodes = if let Some(n) = r.remove(b"nodes".as_ref()).and_then(BEncode::into_bytes) {
                        compact_nodes_decode(&n)?
                    } else {
                        Vec::new()
                    };
                    let nodes6 = if let Some(n6) = r.remove(b"nodes6".as_ref()).and_then(BEncode::into_bytes) {
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
                })
            }
            b"e" => {
                let mut e = top
                    .remove(b"e".as_ref())
                    .and_then(BEncode::into_list)
                    .ok_or(ProtoError::Malformed("error missing details"))?;
                if e.len() != 2 {
                    return Err(ProtoError::Malformed("error details must be [code, message]"));
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
        };
        assert_eq!(roundtrip(msg.clone()), msg);
    }

    #[test]
    fn find_node_query_and_response_roundtrip() {
        let query = Message {
            transaction_id: vec![0xAB],
            sender_id: Some(id(1)),
            body: Body::Query(Query::FindNode { target: id(2), want: Some(vec!["n4".into(), "n6".into()]) }),
        };
        assert_eq!(roundtrip(query.clone()), query);

        let nodes = vec![
            NodeInfo { id: id(3), addr: SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 6881) },
            NodeInfo { id: id(4), addr: SocketAddrV4::new(Ipv4Addr::new(5, 6, 7, 8), 6882) },
        ];
        let nodes6 = vec![
            NodeInfoV6 { id: id(5), addr: SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 6881, 0, 0) },
        ];
        let resp = Message {
            transaction_id: vec![0xAB],
            sender_id: Some(id(1)),
            body: Body::Response(Response::FindNode { nodes: nodes.clone(), nodes6: nodes6.clone() }),
        };
        assert_eq!(roundtrip(resp.clone()), resp);
    }

    #[test]
    fn get_peers_query_and_both_response_shapes_roundtrip() {
        let query = Message {
            transaction_id: vec![7, 7],
            sender_id: Some(id(1)),
            body: Body::Query(Query::GetPeers { info_hash: id(5), want: None }),
        };
        assert_eq!(roundtrip(query.clone()), query);

        let peers_resp = Message {
            transaction_id: vec![7, 7],
            sender_id: Some(id(1)),
            body: Body::Response(Response::GetPeers {
                token: vec![0xCA, 0xFE],
                result: GetPeersResult::Peers(vec![SocketAddrV4::new(Ipv4Addr::new(9, 9, 9, 9), 1234)]),
            }),
        };
        assert_eq!(roundtrip(peers_resp.clone()), peers_resp);

        let peers6_resp = Message {
            transaction_id: vec![7, 7],
            sender_id: Some(id(1)),
            body: Body::Response(Response::GetPeers {
                token: vec![0xCA, 0xFE],
                result: GetPeersResult::Peers6(vec![SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2), 51413, 0, 0)]),
            }),
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
        };
        assert_eq!(roundtrip(msg.clone()), msg);
    }

    #[test]
    fn id_only_response_roundtrip() {
        let msg = Message {
            transaction_id: vec![1],
            sender_id: Some(id(1)),
            body: Body::Response(Response::Id),
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
        assert!(matches!(Message::decode(&encoded), Err(ProtoError::Malformed(_))));
    }

    #[test]
    fn decode_rejects_unknown_query_method() {
        let mut top = BTreeMap::new();
        top.insert(b"t".to_vec(), BEncode::String(vec![1]));
        top.insert(b"y".to_vec(), BEncode::String(b"q".to_vec()));
        top.insert(b"q".to_vec(), BEncode::String(b"not_a_real_method".to_vec()));
        let mut a = BTreeMap::new();
        a.insert(b"id".to_vec(), BEncode::String(id(1).to_vec()));
        top.insert(b"a".to_vec(), BEncode::Dict(a));
        let encoded = BEncode::Dict(top).encode_to_buf();
        assert!(matches!(Message::decode(&encoded), Err(ProtoError::UnknownQuery(_))));
    }
}
