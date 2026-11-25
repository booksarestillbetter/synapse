//! BEP 41 UDP Tracker Protocol Extensions.
//!
//! Provides Type-Length-Value (TLV) extension option frames appended directly after
//! byte 98 of BEP 15 UDP tracker announce requests:
//! - `0`: End of options (0 bytes, no length field)
//! - `1`: NOP (1 byte, no length field)
//! - `2`: URLData (`[type=2, len, ...bytes]`, consecutive segments concatenated)
//! - `3`: Authentication (`[type=3, len, ...bytes]`)

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpOption {
    /// Option 2: URLData (arbitrary query string / passkey data)
    UrlData(String),
    /// Option 3: Authentication token or credentials
    Authentication(Vec<u8>),
    /// Generic or custom option
    Custom { option_type: u8, data: Vec<u8> },
}

pub const OPTION_END: u8 = 0;
pub const OPTION_NOP: u8 = 1;
pub const OPTION_URL_DATA: u8 = 2;
pub const OPTION_AUTHENTICATION: u8 = 3;

fn push_chunked_tlv(out: &mut Vec<u8>, option_type: u8, data: &[u8]) {
    if data.is_empty() {
        out.push(option_type);
        out.push(0);
        return;
    }
    for chunk in data.chunks(255) {
        out.push(option_type);
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
}

/// Encodes a slice of BEP 41 options into a raw TLV byte vector (no magic prefix).
pub fn encode_udp_options(options: &[UdpOption]) -> Vec<u8> {
    if options.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();

    for opt in options {
        match opt {
            UdpOption::UrlData(ref s) => {
                push_chunked_tlv(&mut out, OPTION_URL_DATA, s.as_bytes());
            }
            UdpOption::Authentication(ref b) => {
                push_chunked_tlv(&mut out, OPTION_AUTHENTICATION, b);
            }
            UdpOption::Custom {
                option_type,
                ref data,
            } => match *option_type {
                OPTION_END => out.push(OPTION_END),
                OPTION_NOP => out.push(OPTION_NOP),
                other => push_chunked_tlv(&mut out, other, data),
            },
        }
    }

    // Trailing 0x00 option to indicate end of extension options
    out.push(OPTION_END);
    out
}

/// Decodes BEP 41 options from raw trailing bytes (after the 98-byte BEP 15 header).
pub fn decode_udp_options(data: &[u8]) -> Result<Vec<UdpOption>, &'static str> {
    let mut options = Vec::new();
    let mut pending_url: Option<Vec<u8>> = None;
    let mut cursor = 0;

    while cursor < data.len() {
        let opt_type = data[cursor];
        cursor += 1;

        if opt_type == OPTION_END {
            break;
        }
        if opt_type == OPTION_NOP {
            continue;
        }

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

        if opt_type == OPTION_URL_DATA {
            pending_url
                .get_or_insert_with(Vec::new)
                .extend_from_slice(val_bytes);
            continue;
        }

        if let Some(url_bytes) = pending_url.take() {
            options.push(UdpOption::UrlData(
                String::from_utf8_lossy(&url_bytes).to_string(),
            ));
        }

        match opt_type {
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

    if let Some(url_bytes) = pending_url.take() {
        options.push(UdpOption::UrlData(
            String::from_utf8_lossy(&url_bytes).to_string(),
        ));
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
        assert_eq!(encoded[0], OPTION_URL_DATA);
        assert_eq!(encoded[1] as usize, "passkey=abc123xyz".len());
        assert_eq!(encoded.last().copied(), Some(OPTION_END));

        let decoded = decode_udp_options(&encoded).unwrap();
        assert_eq!(decoded, options);
    }

    #[test]
    fn bep41_url_data_over_255_bytes_chunks_and_reassembles() {
        let long_path = format!("/announce?token={}", "x".repeat(300));
        let encoded = encode_udp_options(&[UdpOption::UrlData(long_path.clone())]);

        // Must start directly with option type 2 and max first segment length 255.
        assert_eq!(encoded[0], OPTION_URL_DATA);
        assert_eq!(encoded[1], 255);
        assert_eq!(encoded[2 + 255], OPTION_URL_DATA);

        let decoded = decode_udp_options(&encoded).unwrap();
        assert_eq!(decoded, vec![UdpOption::UrlData(long_path)]);
    }

    #[test]
    fn bep41_skips_nop_and_stops_at_end_or_eof() {
        let mut wire = vec![
            OPTION_NOP,
            OPTION_URL_DATA,
            5,
            b'h',
            b'e',
            b'l',
            b'l',
            b'o',
            OPTION_NOP,
            OPTION_END,
            0x99, // trailing garbage after End must be ignored
            0x01,
        ];
        assert_eq!(
            decode_udp_options(&wire).unwrap(),
            vec![UdpOption::UrlData("hello".to_string())]
        );

        // Without explicit End marker, EOF ends cleanly.
        wire.truncate(9);
        assert_eq!(
            decode_udp_options(&wire).unwrap(),
            vec![UdpOption::UrlData("hello".to_string())]
        );
    }
}
