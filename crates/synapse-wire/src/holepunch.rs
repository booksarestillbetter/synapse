//! BEP 55 Holepunch Extension Protocol.
//!
//! Provides rendezvous coordination allowing two NATed/firewalled peers to establish
//! a direct UDP/uTP connection via a mutually connected relay peer.

use crate::WireError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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
    Failed { target: SocketAddr, err_code: u32 },
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
            HolepunchMessage::Failed { target, err_code } => {
                buf.put_u8(HolepunchType::Failed as u8);
                Self::encode_sock_addr(*target, &mut buf);
                buf.put_u32(*err_code);
            }
        }
        buf.freeze()
    }

    fn encode_sock_addr(addr: SocketAddr, dst: &mut BytesMut) {
        match addr {
            SocketAddr::V4(v4) => {
                dst.put_u8(0);
                dst.put_slice(&v4.ip().octets());
                dst.put_u16(v4.port());
            }
            SocketAddr::V6(v6) => {
                dst.put_u8(1);
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
                let target = Self::decode_sock_addr(&mut src)?;
                if src.len() < 4 {
                    return Err(WireError::Protocol("truncated holepunch failed packet"));
                }
                let err_code = src.get_u32();
                Ok(HolepunchMessage::Failed { target, err_code })
            }
            _ => Err(WireError::Protocol("unknown holepunch message type")),
        }
    }

    fn decode_sock_addr(src: &mut Bytes) -> Result<SocketAddr, WireError> {
        if src.is_empty() {
            return Err(WireError::Protocol("missing holepunch address type"));
        }
        let addr_type = src.get_u8();
        match addr_type {
            0 => {
                if src.len() < 6 {
                    return Err(WireError::Protocol("truncated holepunch ipv4 address"));
                }
                let mut octets = [0u8; 4];
                src.copy_to_slice(&mut octets);
                let port = src.get_u16();
                Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
            }
            1 => {
                if src.len() < 18 {
                    return Err(WireError::Protocol("truncated holepunch ipv6 address"));
                }
                let mut octets = [0u8; 16];
                src.copy_to_slice(&mut octets);
                let port = src.get_u16();
                Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
            }
            _ => Err(WireError::Protocol("unsupported holepunch address type")),
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
        // BEP 55: msg_type(0) | addr_type(0=v4) | 4-byte IP | 2-byte port
        assert_eq!(encoded.as_ref(), &[0, 0, 198, 51, 100, 42, 0xC8, 0xD5]);
        let decoded = HolepunchMessage::decode(encoded).unwrap();
        assert_eq!(decoded, msg);

        let peer = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 6881);
        let msg_v6 = HolepunchMessage::Connect { peer };
        let encoded_v6 = msg_v6.encode();
        // BEP 55: msg_type(1) | addr_type(1=v6) | 16-byte IP | 2-byte port
        assert_eq!(&encoded_v6[..2], &[1, 1]);
        assert_eq!(encoded_v6.len(), 20);
        let decoded_v6 = HolepunchMessage::decode(encoded_v6).unwrap();
        assert_eq!(decoded_v6, msg_v6);
    }

    #[test]
    fn bep55_failed_carries_target_and_error_code() {
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 6881);
        let msg = HolepunchMessage::Failed {
            target,
            err_code: 3,
        };
        let encoded = msg.encode();
        // BEP 55: msg_type(2) | addr_type(0=v4) | 4-byte IP | 2-byte port | 4-byte err_code
        assert_eq!(
            encoded.as_ref(),
            &[2, 0, 203, 0, 113, 9, 0x1A, 0xE1, 0, 0, 0, 3]
        );
        assert_eq!(HolepunchMessage::decode(encoded).unwrap(), msg);
    }
}
