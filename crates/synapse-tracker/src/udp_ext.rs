//! BEP 41 UDP Tracker Protocol Extensions.
//!
//! Provides Type-Length-Value (TLV) extension option frames appended to BEP 15
//! UDP tracker announce requests. Used for URLData (passkeys/auth tokens) and custom parameters.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpOption {
    /// Option 1: URLData (arbitrary query string / passkey data)
    UrlData(String),
    /// Option 2: Authentication token or credentials
    Authentication(Vec<u8>),
    /// Generic or custom option
    Custom { option_type: u8, data: Vec<u8> },
}

pub const OPTION_URL_DATA: u8 = 1;
pub const OPTION_AUTHENTICATION: u8 = 2;

/// Encodes a slice of BEP 41 options into a byte vector with the `0xBEFE` extension header.
pub fn encode_udp_options(options: &[UdpOption]) -> Vec<u8> {
    if options.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    // BEP 41 magic header
    out.extend_from_slice(&0xBEFEu16.to_be_bytes());

    for opt in options {
        match opt {
            UdpOption::UrlData(ref s) => {
                let bytes = s.as_bytes();
                out.push(OPTION_URL_DATA);
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
            }
            UdpOption::Authentication(ref b) => {
                out.push(OPTION_AUTHENTICATION);
                out.push(b.len() as u8);
                out.extend_from_slice(b);
            }
            UdpOption::Custom { option_type, ref data } => {
                out.push(*option_type);
                out.push(data.len() as u8);
                out.extend_from_slice(data);
            }
        }
    }

    // Trailing 0x00 option to indicate end of extension options
    out.push(0x00);
    out
}

/// Decodes BEP 41 options from raw trailing bytes.
pub fn decode_udp_options(data: &[u8]) -> Result<Vec<UdpOption>, &'static str> {
    if data.len() < 2 {
        return Ok(Vec::new());
    }

    let magic = u16::from_be_bytes([data[0], data[1]]);
    if magic != 0xBEFE {
        return Ok(Vec::new()); // No extension header
    }

    let mut options = Vec::new();
    let mut cursor = 2;

    while cursor < data.len() {
        let opt_type = data[cursor];
        if opt_type == 0x00 {
            break; // End of options
        }
        cursor += 1;

        if cursor >= data.len() {
            return Err("unexpected EOF reading option length");
        }
        let opt_len = data[cursor] as usize;
        cursor += 1;

        if cursor + opt_len > data.len() {
            return Err("unexpected EOF reading option value");
        }
        let val_bytes = &data[cursor..cursor + opt_len];
        cursor += opt_len;

        match opt_type {
            OPTION_URL_DATA => {
                let s = String::from_utf8_lossy(val_bytes).to_string();
                options.push(UdpOption::UrlData(s));
            }
            OPTION_AUTHENTICATION => {
                options.push(UdpOption::Authentication(val_bytes.to_vec()));
            }
            other => {
                options.push(UdpOption::Custom {
                    option_type: other,
                    data: val_bytes.to_vec(),
                });
            }
        }
    }

    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bep41_udp_options_roundtrip() {
        let options = vec![
            UdpOption::UrlData("passkey=abc123xyz".to_string()),
            UdpOption::Authentication(vec![0x01, 0x02, 0x03, 0x04]),
            UdpOption::Custom {
                option_type: 0x42,
                data: vec![0x99, 0x88],
            },
        ];

        let encoded = encode_udp_options(&options);
        assert!(encoded.starts_with(&0xBEFEu16.to_be_bytes()));

        let decoded = decode_udp_options(&encoded).unwrap();
        assert_eq!(decoded, options);
    }
}
