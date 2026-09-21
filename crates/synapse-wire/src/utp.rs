//! BEP 29 Micro Transport Protocol (uTP) Packet Codec.
//!
//! Provides binary serialization, deserialization, and header parsing for uTP
//! over UDP with LEDBAT congestion control metadata and Selective ACK (SACK) extensions.

use crate::WireError;
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const UTP_VERSION: u8 = 1;
pub const UTP_HEADER_LEN: usize = 20;
pub const UTP_EXT_NONE: u8 = 0;
pub const UTP_EXT_SACK: u8 = 1;

/// uTP Packet Type (4 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UtpType {
    /// Regular data payload.
    Data = 0,
    /// Finalize and close connection.
    Fin = 1,
    /// State packet (ACK only, no data).
    State = 2,
    /// Reset / terminate connection abruptly.
    Reset = 3,
    /// Connect / initiate new connection.
    Syn = 4,
}

impl UtpType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(UtpType::Data),
            1 => Some(UtpType::Fin),
            2 => Some(UtpType::State),
            3 => Some(UtpType::Reset),
            4 => Some(UtpType::Syn),
            _ => None,
        }
    }
}

/// uTP 20-byte base packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtpHeader {
    pub ptype: UtpType,
    pub version: u8,
    pub extension: u8,
    pub connection_id: u16,
    pub timestamp_us: u32,
    pub timestamp_diff_us: u32,
    pub wnd_size: u32,
    pub seq_nr: u16,
    pub ack_nr: u16,
}

impl UtpHeader {
    pub fn new(
        ptype: UtpType,
        connection_id: u16,
        seq_nr: u16,
        ack_nr: u16,
        wnd_size: u32,
    ) -> Self {
        Self {
            ptype,
            version: UTP_VERSION,
            extension: UTP_EXT_NONE,
            connection_id,
            timestamp_us: 0,
            timestamp_diff_us: 0,
            wnd_size,
            seq_nr,
            ack_nr,
        }
    }

    pub fn encode(&self, dst: &mut BytesMut) {
        dst.reserve(UTP_HEADER_LEN);
        let type_and_ver = ((self.ptype as u8) << 4) | (self.version & 0x0F);
        dst.put_u8(type_and_ver);
        dst.put_u8(self.extension);
        dst.put_u16(self.connection_id);
        dst.put_u32(self.timestamp_us);
        dst.put_u32(self.timestamp_diff_us);
        dst.put_u32(self.wnd_size);
        dst.put_u16(self.seq_nr);
        dst.put_u16(self.ack_nr);
    }

    pub fn decode(src: &mut Bytes) -> Result<Self, WireError> {
        if src.len() < UTP_HEADER_LEN {
            return Err(WireError::Protocol(
                "uTP packet too short for 20-byte header",
            ));
        }

        let type_and_ver = src.get_u8();
        let ptype_raw = type_and_ver >> 4;
        let version = type_and_ver & 0x0F;

        if version != UTP_VERSION {
            return Err(WireError::Protocol("unsupported uTP version"));
        }

        let ptype =
            UtpType::from_u8(ptype_raw).ok_or(WireError::Protocol("unknown uTP packet type"))?;

        let extension = src.get_u8();
        let connection_id = src.get_u16();
        let timestamp_us = src.get_u32();
        let timestamp_diff_us = src.get_u32();
        let wnd_size = src.get_u32();
        let seq_nr = src.get_u16();
        let ack_nr = src.get_u16();

        Ok(Self {
            ptype,
            version,
            extension,
            connection_id,
            timestamp_us,
            timestamp_diff_us,
            wnd_size,
            seq_nr,
            ack_nr,
        })
    }
}

/// A complete uTP packet containing header, optional extensions, and payload data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtpPacket {
    pub header: UtpHeader,
    pub sack_bitmask: Option<Vec<u8>>,
    pub payload: Bytes,
}

impl UtpPacket {
    pub fn new(header: UtpHeader, payload: Bytes) -> Self {
        Self {
            header,
            sack_bitmask: None,
            payload,
        }
    }

    pub fn with_sack(mut self, bitmask: Vec<u8>) -> Self {
        self.header.extension = UTP_EXT_SACK;
        self.sack_bitmask = Some(bitmask);
        self
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(
            UTP_HEADER_LEN
                + self.sack_bitmask.as_ref().map(|s| 2 + s.len()).unwrap_or(0)
                + self.payload.len(),
        );

        self.header.encode(&mut buf);

        if let Some(ref sack) = self.sack_bitmask {
            buf.put_u8(UTP_EXT_NONE); // next extension: none
            buf.put_u8(sack.len() as u8);
            buf.put_slice(sack);
        }

        buf.put_slice(&self.payload);
        buf.freeze()
    }

    pub fn decode(mut raw: Bytes) -> Result<Self, WireError> {
        let header = UtpHeader::decode(&mut raw)?;
        let mut sack_bitmask = None;

        let mut next_ext = header.extension;
        while next_ext != UTP_EXT_NONE {
            if raw.len() < 2 {
                return Err(WireError::Protocol("malformed uTP extension header"));
            }
            let ext_type = next_ext;
            next_ext = raw.get_u8();
            let ext_len = raw.get_u8() as usize;

            if raw.len() < ext_len {
                return Err(WireError::Protocol("truncated uTP extension payload"));
            }

            if ext_type == UTP_EXT_SACK {
                let bitmask = raw.copy_to_bytes(ext_len);
                sack_bitmask = Some(bitmask.to_vec());
            } else {
                raw.advance(ext_len);
            }
        }

        Ok(Self {
            header,
            sack_bitmask,
            payload: raw,
        })
    }
}

/// Builds a BEP 29 Selective ACK (SACK) bitmask.
///
/// The bitmask length is at least 4 bytes and padded to a multiple of 4 bytes.
/// Bit 0 of byte 0 corresponds to `ack_nr + 2`. Bit `i` corresponds to `ack_nr + 2 + i`.
pub fn build_sack_bitmask(ack_nr: u16, received_seqs: &[u16]) -> Option<Vec<u8>> {
    if received_seqs.is_empty() {
        return None;
    }

    // Find highest received sequence beyond ack_nr + 1
    let mut max_offset: i32 = -1;
    for &seq in received_seqs {
        let diff = (seq.wrapping_sub(ack_nr) as i16) as i32;
        if diff >= 2 {
            let offset = diff - 2;
            if offset > max_offset && offset < 256 {
                max_offset = offset;
            }
        }
    }

    if max_offset < 0 {
        return None;
    }

    let num_bytes = ((max_offset as usize / 8) + 1).max(4);
    // Pad to multiple of 4
    let num_bytes = (num_bytes + 3) & !3;
    let mut bitmask = vec![0u8; num_bytes];

    for &seq in received_seqs {
        let diff = (seq.wrapping_sub(ack_nr) as i16) as i32;
        if diff >= 2 {
            let offset = (diff - 2) as usize;
            let byte_idx = offset / 8;
            let bit_idx = offset % 8;
            if byte_idx < bitmask.len() {
                bitmask[byte_idx] |= 1 << bit_idx;
            }
        }
    }

    Some(bitmask)
}

/// Parses a BEP 29 Selective ACK (SACK) bitmask into a list of acknowledged sequence numbers.
pub fn parse_sack_bitmask(ack_nr: u16, bitmask: &[u8]) -> Vec<u16> {
    let mut acked = Vec::new();
    for (byte_idx, &byte) in bitmask.iter().enumerate() {
        if byte == 0 {
            continue;
        }
        for bit_idx in 0..8 {
            if (byte & (1 << bit_idx)) != 0 {
                let offset = (byte_idx * 8 + bit_idx) as u16;
                let seq = ack_nr.wrapping_add(2).wrapping_add(offset);
                acked.push(seq);
            }
        }
    }
    acked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utp_header_encode_decode() {
        let header = UtpHeader {
            ptype: UtpType::Syn,
            version: UTP_VERSION,
            extension: UTP_EXT_NONE,
            connection_id: 0x4321,
            timestamp_us: 12345678,
            timestamp_diff_us: 54321,
            wnd_size: 1048576,
            seq_nr: 1,
            ack_nr: 0,
        };

        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        assert_eq!(buf.len(), UTP_HEADER_LEN);

        let mut bytes = buf.freeze();
        let decoded = UtpHeader::decode(&mut bytes).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_utp_packet_with_payload_and_sack_roundtrip() {
        let header = UtpHeader {
            ptype: UtpType::Data,
            version: UTP_VERSION,
            extension: UTP_EXT_SACK,
            connection_id: 0x1234,
            timestamp_us: 99999,
            timestamp_diff_us: 1200,
            wnd_size: 65535,
            seq_nr: 42,
            ack_nr: 41,
        };

        let payload = Bytes::from_static(b"hello utp fast stream transmission");
        let sack = vec![0b10101010, 0b11001100, 0b11110000, 0b00001111];

        let packet = UtpPacket::new(header, payload.clone()).with_sack(sack.clone());
        let encoded = packet.encode();

        let decoded = UtpPacket::decode(encoded).unwrap();
        assert_eq!(decoded.header.ptype, UtpType::Data);
        assert_eq!(decoded.header.seq_nr, 42);
        assert_eq!(decoded.header.ack_nr, 41);
        assert_eq!(decoded.sack_bitmask, Some(sack));
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_sack_build_and_parse_roundtrip() {
        let ack_nr = 100;
        // ack_nr + 2 = 102, ack_nr + 4 = 104, ack_nr + 12 = 112
        let received = vec![102, 104, 112];
        let bitmask = build_sack_bitmask(ack_nr, &received).unwrap();
        assert!(bitmask.len() >= 4);
        assert_eq!(bitmask.len() % 4, 0);

        let parsed = parse_sack_bitmask(ack_nr, &bitmask);
        assert_eq!(parsed, received);
    }
}
