//! BEP 14 / BEP 22 Local Peer Discovery (LSD) Protocol.
//!
//! Provides multicast SSDP-formatted packet generation and parsing over UDP
//! for local area network peer discovery (`239.192.152.143:6771` for IPv4 and
//! `[ff15::efc0:988f]:6771` for IPv6).

pub const LSD_MULTICAST_IPV4: &str = "239.192.152.143:6771";
pub const LSD_MULTICAST_IPV6: &str = "[ff15::efc0:988f]:6771";
pub const LSD_PORT: u16 = 6771;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsdAnnounce {
    pub port: u16,
    pub info_hashes: Vec<[u8; 20]>,
    pub cookie: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LsdError {
    #[error("invalid LSD packet header")]
    InvalidHeader,
    #[error("missing port in LSD message")]
    MissingPort,
    #[error("missing infohash in LSD message")]
    MissingInfoHash,
    #[error("invalid infohash encoding")]
    InvalidInfoHash,
}

/// Formats a BEP 14/22 LSD multicast announcement string.
pub fn format_lsd_announce(port: u16, info_hashes: &[[u8; 20]], cookie: Option<&str>) -> String {
    let mut msg = String::with_capacity(256);
    msg.push_str("BT-SEARCH * HTTP/1.1\r\n");
    msg.push_str("Host: 239.192.152.143:6771\r\n");
    msg.push_str(&format!("Port: {}\r\n", port));

    for hash in info_hashes {
        msg.push_str(&format!("Infohash: {}\r\n", hex::encode(hash)));
    }

    if let Some(c) = cookie {
        msg.push_str(&format!("cookie: {}\r\n", c));
    }

    msg.push_str("\r\n\r\n");
    msg
}

/// Parses an incoming BEP 14/22 LSD multicast announcement packet.
pub fn parse_lsd_announce(packet: &str) -> Result<LsdAnnounce, LsdError> {
    let lines: Vec<&str> = packet.lines().map(|l| l.trim()).collect();
    if lines.is_empty() || !lines[0].starts_with("BT-SEARCH * HTTP/1.1") {
        return Err(LsdError::InvalidHeader);
    }

    let mut port = None;
    let mut info_hashes = Vec::new();
    let mut cookie = None;

    for line in &lines[1..] {
        if line.is_empty() {
            continue;
        }
        if let Some((key, val)) = line.split_once(':') {
            let key_norm = key.trim().to_ascii_lowercase();
            let val_norm = val.trim();

            match key_norm.as_str() {
                "port" => {
                    if let Ok(p) = val_norm.parse::<u16>() {
                        port = Some(p);
                    }
                }
                "infohash" => {
                    // Try decoding 40-char hex
                    if val_norm.len() == 40 {
                        if let Ok(bytes) = hex::decode(val_norm) as Result<Vec<u8>, _> {
                            if bytes.len() == 20 {
                                let mut arr = [0u8; 20];
                                arr.copy_from_slice(&bytes);
                                info_hashes.push(arr);
                            }
                        }
                    }
                }
                "cookie" => {
                    cookie = Some(val_norm.to_string());
                }
                _ => {}
            }
        }
    }

    let port = port.ok_or(LsdError::MissingPort)?;
    if info_hashes.is_empty() {
        return Err(LsdError::MissingInfoHash);
    }

    Ok(LsdAnnounce {
        port,
        info_hashes,
        cookie,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_and_parse_lsd_announce() {
        let hash1 = [0xAA; 20];
        let hash2 = [0xBB; 20];
        let cookie = "synapse_lsd_test_cookie";
        let formatted = format_lsd_announce(6881, &[hash1, hash2], Some(cookie));

        let parsed = parse_lsd_announce(&formatted).unwrap();
        assert_eq!(parsed.port, 6881);
        assert_eq!(parsed.info_hashes.len(), 2);
        assert_eq!(parsed.info_hashes[0], hash1);
        assert_eq!(parsed.info_hashes[1], hash2);
        assert_eq!(parsed.cookie.as_deref(), Some(cookie));
    }

    #[test]
    fn test_parse_invalid_lsd_packets() {
        assert_eq!(parse_lsd_announce("GET / HTTP/1.1\r\n"), Err(LsdError::InvalidHeader));
        assert_eq!(
            parse_lsd_announce("BT-SEARCH * HTTP/1.1\r\nPort: 6881\r\n\r\n"),
            Err(LsdError::MissingInfoHash)
        );
        assert_eq!(
            parse_lsd_announce("BT-SEARCH * HTTP/1.1\r\nInfohash: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n"),
            Err(LsdError::MissingPort)
        );
    }
}
