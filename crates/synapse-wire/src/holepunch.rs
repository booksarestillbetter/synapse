//! BEP 55 Holepunch Extension Protocol.
//!
//! Provides rendezvous coordination allowing two NATed/firewalled peers to establish
//! a direct UDP/uTP connection via a mutually connected relay peer.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use crate::WireError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolepunchType {
    Rendezvous = 0,
    Connect = 1,
    Failed = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HolepunchMessage {
    Rendezvous { target: SocketAddr },
    Connect { peer: SocketAddr },
    Failed { err_code: u32 },
}

impl HolepunchMessage {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        match self {
            HolepunchMessage::Rendezvous { target } => {
                buf.put_u8(HolepunchType::Rendezvous as u8);
                Self::encode_sock_addr(*target, &mut buf);
            }
            HolepunchMessage::Connect { peer } => {
                buf.put_u8(HolepunchType::Connect as u8);
                Self::encode_sock_addr(*peer, &mut buf);
            }
            HolepunchMessage::Failed { err_code } => {
                buf.put_u8(HolepunchType::Failed as u8);
                buf.put_u32(*err_code);
            }
        }
        buf.freeze()
    }

    fn encode_sock_addr(addr: SocketAddr, dst: &mut BytesMut) {
        match addr {
            SocketAddr::V4(v4) => {
                dst.put_u8(4);
                dst.put_slice(&v4.ip().octets());
                dst.put_u16(v4.port());
            }
            SocketAddr::V6(v6) => {
                dst.put_u8(16);
                dst.put_slice(&v6.ip().octets());
                dst.put_u16(v6.port());
            }
        }
    }

    pub fn decode(mut src: Bytes) -> Result<Self, WireError> {
        if src.is_empty() {
            return Err(WireError::Protocol("empty holepunch message"));
        }

        let ptype = src.get_u8();
        match ptype {
            0 => {
                let target = Self::decode_sock_addr(&mut src)?;
                Ok(HolepunchMessage::Rendezvous { target })
            }
            1 => {
                let peer = Self::decode_sock_addr(&mut src)?;
                Ok(HolepunchMessage::Connect { peer })
            }
            2 => {
                if src.len() < 4 {
                    return Err(WireError::Protocol("truncated holepunch failed packet"));
                }
                let err_code = src.get_u32();
                Ok(HolepunchMessage::Failed { err_code })
            }
            _ => Err(WireError::Protocol("unknown holepunch message type")),
        }
    }

    fn decode_sock_addr(src: &mut Bytes) -> Result<SocketAddr, WireError> {
        if src.is_empty() {
            return Err(WireError::Protocol("missing holepunch address length"));
        }
        let addr_len = src.get_u8();
        match addr_len {
            4 => {
                if src.len() < 6 {
                    return Err(WireError::Protocol("truncated holepunch ipv4 address"));
                }
                let mut octets = [0u8; 4];
                src.copy_to_slice(&mut octets);
                let port = src.get_u16();
                Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
            }
            16 => {
                if src.len() < 18 {
                    return Err(WireError::Protocol("truncated holepunch ipv6 address"));
                }
                let mut octets = [0u8; 16];
                src.copy_to_slice(&mut octets);
                let port = src.get_u16();
                Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
            }
            _ => Err(WireError::Protocol("unsupported holepunch IP address length")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_holepunch_rendezvous_and_connect_roundtrip() {
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)), 51413);
        let msg = HolepunchMessage::Rendezvous { target };
        let encoded = msg.encode();
        let decoded = HolepunchMessage::decode(encoded).unwrap();
        assert_eq!(decoded, msg);

        let peer = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 6881);
        let msg_v6 = HolepunchMessage::Connect { peer };
        let encoded_v6 = msg_v6.encode();
        let decoded_v6 = HolepunchMessage::decode(encoded_v6).unwrap();
        assert_eq!(decoded_v6, msg_v6);
    }
}
