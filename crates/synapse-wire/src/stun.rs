//! BEP 54 / RFC 5389 STUN Discovery for UDP / uTP Sockets.
//!
//! Provides STUN Binding Request formatting and XOR-MAPPED-ADDRESS response parsing
//! to discover external public IP addresses and NAT port mappings over UDP.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_RESPONSE: u16 = 0x0101;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Encodes a 20-byte STUN Binding Request.
pub fn encode_stun_binding_request(transaction_id: &[u8; 12]) -> [u8; 20] {
    let mut pkt = [0u8; 20];
    pkt[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    pkt[2..4].copy_from_slice(&0u16.to_be_bytes()); // Message length = 0 (no attributes in request)
    pkt[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    pkt[8..20].copy_from_slice(transaction_id);
    pkt
}

/// Parses a STUN Binding Success Response to extract the external `SocketAddr`.
pub fn parse_stun_binding_response(packet: &[u8]) -> Result<SocketAddr, &'static str> {
    if packet.len() < 20 {
        return Err("STUN packet too short");
    }

    let msg_type = u16::from_be_bytes([packet[0], packet[1]]);
    if msg_type != BINDING_RESPONSE {
        return Err("not a STUN Binding Response");
    }

    let msg_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let cookie = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return Err("invalid STUN magic cookie");
    }

    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&packet[8..20]);

    if packet.len() < 20 + msg_len {
        return Err("truncated STUN packet attributes");
    }

    let mut cursor = 20;
    while cursor + 4 <= 20 + msg_len {
        let attr_type = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
        let attr_len = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]) as usize;
        cursor += 4;

        if cursor + attr_len > packet.len() {
            return Err("truncated STUN attribute");
        }

        if attr_type == ATTR_XOR_MAPPED_ADDRESS && attr_len >= 8 {
            let family = packet[cursor + 1];
            let x_port = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
            let port = x_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

            if family == 0x01 && attr_len >= 8 {
                // IPv4
                let x_ip = u32::from_be_bytes([
                    packet[cursor + 4],
                    packet[cursor + 5],
                    packet[cursor + 6],
                    packet[cursor + 7],
                ]);
                let ip_int = x_ip ^ STUN_MAGIC_COOKIE;
                let ip = IpAddr::V4(Ipv4Addr::from(ip_int));
                return Ok(SocketAddr::new(ip, port));
            } else if family == 0x02 && attr_len >= 20 {
                // IPv6
                let mut x_ip = [0u8; 16];
                x_ip.copy_from_slice(&packet[cursor + 4..cursor + 20]);
                let mut key = [0u8; 16];
                key[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                key[4..16].copy_from_slice(&transaction_id);

                let mut ip_bytes = [0u8; 16];
                for i in 0..16 {
                    ip_bytes[i] = x_ip[i] ^ key[i];
                }
                let ip = IpAddr::V6(Ipv6Addr::from(ip_bytes));
                return Ok(SocketAddr::new(ip, port));
            }
        }

        // STUN attributes are padded to 4-byte boundaries
        let padded_len = (attr_len + 3) & !3;
        cursor += padded_len;
    }

    Err("XOR-MAPPED-ADDRESS attribute not found")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_binding_request_and_response_v4() {
        let txn_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44];
        let req = encode_stun_binding_request(&txn_id);
        assert_eq!(req.len(), 20);

        // Build mock Binding Success Response with XOR-MAPPED-ADDRESS
        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&12u16.to_be_bytes()); // attr length = 12
        resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txn_id);

        // Attribute: XOR-MAPPED-ADDRESS
        resp.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        resp.extend_from_slice(&8u16.to_be_bytes()); // attr value len = 8
        resp.push(0x00); // reserved
        resp.push(0x01); // IPv4 family
        
        let test_port = 51413u16;
        let x_port = test_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        resp.extend_from_slice(&x_port.to_be_bytes());

        let test_ip = Ipv4Addr::new(203, 0, 113, 195);
        let x_ip = u32::from(test_ip) ^ STUN_MAGIC_COOKIE;
        resp.extend_from_slice(&x_ip.to_be_bytes());

        let parsed_addr = parse_stun_binding_response(&resp).unwrap();
        assert_eq!(parsed_addr, SocketAddr::new(IpAddr::V4(test_ip), test_port));
    }
}
