//! Persisting DHT state across restarts: our node id (so we keep the routing-table position
//! other nodes have learned, and a BEP 42-derived id is not thrown away) and the good nodes we
//! know, which seed the next start so it does not depend on the public bootstrap routers.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use synapse_bencode::BEncode;

use crate::proto::NodeId;

/// Most nodes written to (and accepted from) a state file.
pub const MAX_STATE_NODES: usize = 400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtState {
    pub node_id: NodeId,
    pub nodes: Vec<SocketAddr>,
}

impl DhtState {
    pub fn encode(&self) -> Vec<u8> {
        let mut n4 = Vec::new();
        let mut n6 = Vec::new();
        for addr in self.nodes.iter().take(MAX_STATE_NODES) {
            match addr {
                SocketAddr::V4(a) => {
                    n4.extend_from_slice(&a.ip().octets());
                    n4.extend_from_slice(&a.port().to_be_bytes());
                }
                SocketAddr::V6(a) => {
                    n6.extend_from_slice(&a.ip().octets());
                    n6.extend_from_slice(&a.port().to_be_bytes());
                }
            }
        }
        let dict = BTreeMap::from([
            (b"id".to_vec(), BEncode::String(self.node_id.to_vec())),
            (b"nodes".to_vec(), BEncode::String(n4)),
            (b"nodes6".to_vec(), BEncode::String(n6)),
        ]);
        BEncode::Dict(dict).encode_to_buf()
    }

    /// Parses a state file. Anything malformed yields `None` (a bad file just means a cold
    /// start, never a failure).
    pub fn decode(data: &[u8]) -> Option<DhtState> {
        let mut d = synapse_bencode::decode_buf_limited(data, 4, 100)
            .ok()?
            .into_dict()?;
        let node_id: NodeId = d.remove(b"id".as_ref())?.into_bytes()?.try_into().ok()?;
        let mut nodes = Vec::new();
        if let Some(n4) = d.remove(b"nodes".as_ref()).and_then(BEncode::into_bytes) {
            for c in n4.as_chunks::<6>().0.iter().take(MAX_STATE_NODES) {
                let port = u16::from_be_bytes([c[4], c[5]]);
                if port != 0 {
                    nodes.push(SocketAddr::new(
                        Ipv4Addr::new(c[0], c[1], c[2], c[3]).into(),
                        port,
                    ));
                }
            }
        }
        if let Some(n6) = d.remove(b"nodes6".as_ref()).and_then(BEncode::into_bytes) {
            for c in n6.as_chunks::<18>().0.iter().take(MAX_STATE_NODES) {
                let ip: [u8; 16] = c[..16].try_into().ok()?;
                let port = u16::from_be_bytes([c[16], c[17]]);
                if port != 0 {
                    nodes.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port));
                }
            }
        }
        nodes.truncate(MAX_STATE_NODES);
        Some(DhtState { node_id, nodes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_v4_and_v6_nodes() {
        let s = DhtState {
            node_id: [7u8; 20],
            nodes: vec![
                "1.2.3.4:6881".parse().unwrap(),
                "[2001:db8::5]:51413".parse().unwrap(),
                "8.8.8.8:1".parse().unwrap(),
            ],
        };
        let back = DhtState::decode(&s.encode()).unwrap();
        assert_eq!(back.node_id, s.node_id);
        let mut a = back.nodes.clone();
        let mut b = s.nodes.clone();
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }

    #[test]
    fn garbage_and_port_zero_entries_are_rejected_not_fatal() {
        assert_eq!(DhtState::decode(b"not bencode"), None);
        assert_eq!(DhtState::decode(b"d2:id3:abce"), None, "wrong id length");
        let s = DhtState {
            node_id: [1; 20],
            nodes: vec!["9.9.9.9:0".parse().unwrap()],
        };
        assert!(DhtState::decode(&s.encode()).unwrap().nodes.is_empty());
    }

    #[test]
    fn node_count_is_capped() {
        let nodes: Vec<SocketAddr> = (0..1000u32)
            .map(|i| SocketAddr::new(Ipv4Addr::from(0x0808_0000 + i).into(), 6881))
            .collect();
        let s = DhtState {
            node_id: [2; 20],
            nodes,
        };
        assert_eq!(
            DhtState::decode(&s.encode()).unwrap().nodes.len(),
            MAX_STATE_NODES
        );
    }
}
