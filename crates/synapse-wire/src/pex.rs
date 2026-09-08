//! BEP 11 Peer Exchange (`ut_pex`).
//!
//! Enables high-efficiency peer sharing directly between swarm participants
//! without contacting trackers or the DHT.
//!
//! STRICT SECURITY / PRIVACY NOTE:
//! Per BEP 27, `ut_pex` MUST NEVER be enabled or sent on private torrents (`info.private == true`).

use bytes::Bytes;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use synapse_bencode::{decode_buf_first, BEncode};
use crate::WireError;

/// Peer flags advertised in `added.f` / `added6.f`.
pub const PEX_FLAG_ENCRYPTION_PREFERRED: u8 = 0x01;
pub const PEX_FLAG_SEEDER: u8 = 0x02;
pub const PEX_FLAG_UTP_SUPPORTED: u8 = 0x04;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UtPexMessage {
    pub added_v4: Vec<SocketAddrV4>,
    pub added_v4_flags: Vec<u8>,
    pub dropped_v4: Vec<SocketAddrV4>,
    pub added_v6: Vec<SocketAddrV6>,
    pub added_v6_flags: Vec<u8>,
    pub dropped_v6: Vec<SocketAddrV6>,
}

impl UtPexMessage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn encode(&self) -> Bytes {
        let mut dict = BTreeMap::new();

        if !self.added_v4.is_empty() {
            let mut added = Vec::with_capacity(self.added_v4.len() * 6);
            for addr in &self.added_v4 {
                added.extend_from_slice(&addr.ip().octets());
                added.extend_from_slice(&addr.port().to_be_bytes());
            }
            dict.insert(b"added".to_vec(), BEncode::String(added));

            if !self.added_v4_flags.is_empty() {
                dict.insert(b"added.f".to_vec(), BEncode::String(self.added_v4_flags.clone()));
            }
        }

        if !self.dropped_v4.is_empty() {
            let mut dropped = Vec::with_capacity(self.dropped_v4.len() * 6);
            for addr in &self.dropped_v4 {
                dropped.extend_from_slice(&addr.ip().octets());
                dropped.extend_from_slice(&addr.port().to_be_bytes());
            }
            dict.insert(b"dropped".to_vec(), BEncode::String(dropped));
        }

        if !self.added_v6.is_empty() {
            let mut added6 = Vec::with_capacity(self.added_v6.len() * 18);
            for addr in &self.added_v6 {
                added6.extend_from_slice(&addr.ip().octets());
                added6.extend_from_slice(&addr.port().to_be_bytes());
            }
            dict.insert(b"added6".to_vec(), BEncode::String(added6));

            if !self.added_v6_flags.is_empty() {
                dict.insert(b"added6.f".to_vec(), BEncode::String(self.added_v6_flags.clone()));
            }
        }

        if !self.dropped_v6.is_empty() {
            let mut dropped6 = Vec::with_capacity(self.dropped_v6.len() * 18);
            for addr in &self.dropped_v6 {
                dropped6.extend_from_slice(&addr.ip().octets());
                dropped6.extend_from_slice(&addr.port().to_be_bytes());
            }
            dict.insert(b"dropped6".to_vec(), BEncode::String(dropped6));
        }

        let mut buf = Vec::new();
        BEncode::Dict(dict).encode(&mut buf).unwrap();
        Bytes::from(buf)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, WireError> {
        let bencode = decode_buf_first(payload)
            .map_err(|_| WireError::Protocol("malformed ut_pex message bencode"))?;

        let mut dict = bencode.into_dict()
            .ok_or(WireError::Protocol("ut_pex message must be a dictionary"))?;

        let mut added_v4 = Vec::new();
        let mut added_v4_flags = Vec::new();
        let mut dropped_v4 = Vec::new();
        let mut added_v6 = Vec::new();
        let mut added_v6_flags = Vec::new();
        let mut dropped_v6 = Vec::new();

        if let Some(added) = dict.remove(b"added".as_ref()).and_then(|v| v.into_bytes()) {
            for chunk in added.chunks_exact(6) {
                let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                added_v4.push(SocketAddrV4::new(ip, port));
            }
        }

        if let Some(flags) = dict.remove(b"added.f".as_ref()).and_then(|v| v.into_bytes()) {
            added_v4_flags = flags;
        }

        if let Some(dropped) = dict.remove(b"dropped".as_ref()).and_then(|v| v.into_bytes()) {
            for chunk in dropped.chunks_exact(6) {
                let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                dropped_v4.push(SocketAddrV4::new(ip, port));
            }
        }

        if let Some(added6) = dict.remove(b"added6".as_ref()).and_then(|v| v.into_bytes()) {
            for chunk in added6.chunks_exact(18) {
                let ip_bytes: [u8; 16] = chunk[0..16].try_into().unwrap();
                let ip = Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes([chunk[16], chunk[17]]);
                added_v6.push(SocketAddrV6::new(ip, port, 0, 0));
            }
        }

        if let Some(flags6) = dict.remove(b"added6.f".as_ref()).and_then(|v| v.into_bytes()) {
            added_v6_flags = flags6;
        }

        if let Some(dropped6) = dict.remove(b"dropped6".as_ref()).and_then(|v| v.into_bytes()) {
            for chunk in dropped6.chunks_exact(18) {
                let ip_bytes: [u8; 16] = chunk[0..16].try_into().unwrap();
                let ip = Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes([chunk[16], chunk[17]]);
                dropped_v6.push(SocketAddrV6::new(ip, port, 0, 0));
            }
        }

        Ok(Self {
            added_v4,
            added_v4_flags,
            dropped_v4,
            added_v6,
            added_v6_flags,
            dropped_v6,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ut_pex_dual_stack_roundtrip() {
        let v4_1 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 50), 6881);
        let v4_2 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 51413);
        let v6_1 = SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 6881, 0, 0);

        let pex = UtPexMessage {
            added_v4: vec![v4_1, v4_2],
            added_v4_flags: vec![PEX_FLAG_SEEDER, PEX_FLAG_ENCRYPTION_PREFERRED],
            dropped_v4: vec![SocketAddrV4::new(Ipv4Addr::new(172, 16, 0, 1), 8080)],
            added_v6: vec![v6_1],
            added_v6_flags: vec![PEX_FLAG_UTP_SUPPORTED],
            dropped_v6: Vec::new(),
        };

        let encoded = pex.encode();
        let decoded = UtPexMessage::decode(&encoded).unwrap();

        assert_eq!(decoded.added_v4.len(), 2);
        assert_eq!(decoded.added_v4[0], v4_1);
        assert_eq!(decoded.added_v4[1], v4_2);
        assert_eq!(decoded.added_v4_flags, vec![PEX_FLAG_SEEDER, PEX_FLAG_ENCRYPTION_PREFERRED]);
        assert_eq!(decoded.dropped_v4.len(), 1);
        assert_eq!(decoded.added_v6.len(), 1);
        assert_eq!(decoded.added_v6[0], v6_1);
        assert_eq!(decoded.added_v6_flags, vec![PEX_FLAG_UTP_SUPPORTED]);
    }
}
