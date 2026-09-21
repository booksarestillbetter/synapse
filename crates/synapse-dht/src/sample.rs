//! BEP 33 (DHT Scrape) and BEP 51 (DHT Infohash Indexing / sample_infohashes).
//!
//! Provides sampling and scraping capabilities over the Kademlia DHT.
//! BEP 51 allows DHT crawlers and indexers to efficiently sample swarms,
//! while BEP 33 allows querying estimated seeder and leecher counts.

use crate::proto::{
    compact_nodes6_decode, compact_nodes6_encode, compact_nodes_decode, compact_nodes_encode,
    NodeInfo, NodeInfoV6,
};
use std::collections::BTreeMap;
use synapse_bencode::BEncode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleInfohashesQuery {
    pub target: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleInfohashesResponse {
    pub samples: Vec<[u8; 20]>,
    pub num: i64,
    pub interval: i64,
    pub nodes: Vec<NodeInfo>,
    pub nodes6: Vec<NodeInfoV6>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtScrapeQuery {
    pub info_hash: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtScrapeResponse {
    pub seeders: u32,
    pub leechers: u32,
    pub bfsd: Option<Vec<u8>>,
    pub bfpe: Option<Vec<u8>>,
}

/// Encodes a BEP 51 `sample_infohashes` response dictionary.
pub fn encode_sample_infohashes_response(
    id: &[u8; 20],
    resp: &SampleInfohashesResponse,
) -> BEncode {
    let mut dict = BTreeMap::new();
    dict.insert(b"id".to_vec(), BEncode::String(id.to_vec()));
    dict.insert(b"interval".to_vec(), BEncode::Int(resp.interval));
    dict.insert(b"num".to_vec(), BEncode::Int(resp.num));

    let mut samples_bytes = Vec::with_capacity(resp.samples.len() * 20);
    for s in &resp.samples {
        samples_bytes.extend_from_slice(s);
    }
    dict.insert(b"samples".to_vec(), BEncode::String(samples_bytes));

    if !resp.nodes.is_empty() {
        dict.insert(
            b"nodes".to_vec(),
            BEncode::String(compact_nodes_encode(&resp.nodes)),
        );
    }
    if !resp.nodes6.is_empty() {
        dict.insert(
            b"nodes6".to_vec(),
            BEncode::String(compact_nodes6_encode(&resp.nodes6)),
        );
    }

    BEncode::Dict(dict)
}

/// Decodes a BEP 51 `sample_infohashes` response dictionary.
pub fn decode_sample_infohashes_response(
    dict: &mut BTreeMap<Vec<u8>, BEncode>,
) -> Result<SampleInfohashesResponse, &'static str> {
    let interval = dict
        .remove(b"interval".as_ref())
        .and_then(BEncode::into_int)
        .unwrap_or(3600);
    let num = dict
        .remove(b"num".as_ref())
        .and_then(BEncode::into_int)
        .unwrap_or(0);

    let samples_bytes = dict
        .remove(b"samples".as_ref())
        .and_then(BEncode::into_bytes)
        .unwrap_or_default();

    let mut samples = Vec::new();
    for chunk in samples_bytes.as_chunks::<20>().0 {
        samples.push(*chunk);
    }

    let nodes = match dict.remove(b"nodes".as_ref()).and_then(BEncode::into_bytes) {
        Some(b) => compact_nodes_decode(&b).unwrap_or_default(),
        None => Vec::new(),
    };

    let nodes6 = match dict
        .remove(b"nodes6".as_ref())
        .and_then(BEncode::into_bytes)
    {
        Some(b) => compact_nodes6_decode(&b).unwrap_or_default(),
        None => Vec::new(),
    };

    Ok(SampleInfohashesResponse {
        samples,
        num,
        interval,
        nodes,
        nodes6,
    })
}

/// Encodes a BEP 33 DHT scrape response dictionary.
pub fn encode_dht_scrape_response(id: &[u8; 20], resp: &DhtScrapeResponse) -> BEncode {
    let mut dict = BTreeMap::new();
    dict.insert(b"id".to_vec(), BEncode::String(id.to_vec()));
    dict.insert(b"sn".to_vec(), BEncode::Int(i64::from(resp.seeders)));
    dict.insert(b"ln".to_vec(), BEncode::Int(i64::from(resp.leechers)));

    if let Some(ref bfsd) = resp.bfsd {
        dict.insert(b"BFsd".to_vec(), BEncode::String(bfsd.clone()));
    }
    if let Some(ref bfpe) = resp.bfpe {
        dict.insert(b"BFpe".to_vec(), BEncode::String(bfpe.clone()));
    }

    BEncode::Dict(dict)
}

/// Decodes a BEP 33 DHT scrape response dictionary.
pub fn decode_dht_scrape_response(
    dict: &mut BTreeMap<Vec<u8>, BEncode>,
) -> Result<DhtScrapeResponse, &'static str> {
    let seeders = dict
        .remove(b"sn".as_ref())
        .and_then(BEncode::into_int)
        .unwrap_or(0) as u32;
    let leechers = dict
        .remove(b"ln".as_ref())
        .and_then(BEncode::into_int)
        .unwrap_or(0) as u32;
    let bfsd = dict.remove(b"BFsd".as_ref()).and_then(BEncode::into_bytes);
    let bfpe = dict.remove(b"BFpe".as_ref()).and_then(BEncode::into_bytes);

    Ok(DhtScrapeResponse {
        seeders,
        leechers,
        bfsd,
        bfpe,
    })
}

/// A 256-byte (2048-bit) Bloom Filter for BEP 33 DHT scrapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtBloomFilter {
    pub bytes: [u8; 256],
}

impl Default for DhtBloomFilter {
    fn default() -> Self {
        Self { bytes: [0u8; 256] }
    }
}

impl DhtBloomFilter {
    pub const M: usize = 256 * 8; // 2048 bits

    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_bytes(bytes: [u8; 256]) -> Self {
        Self { bytes }
    }

    /// Inserts an IP address into the Bloom filter using SHA-1 as specified in BEP 33.
    pub fn insert_ip(&mut self, ip: std::net::IpAddr) {
        use sha1::{Digest, Sha1};
        let ip_bytes: Vec<u8> = match ip {
            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        let hash: [u8; 20] = Sha1::digest(&ip_bytes).into();
        let index1 = ((hash[0] as usize) | ((hash[1] as usize) << 8)) % Self::M;
        let index2 = ((hash[2] as usize) | ((hash[3] as usize) << 8)) % Self::M;

        self.bytes[index1 / 8] |= 1 << (index1 % 8);
        self.bytes[index2 / 8] |= 1 << (index2 % 8);
    }

    /// Returns the number of zero bits remaining in the filter.
    pub fn count_zero_bits(&self) -> usize {
        let ones: u32 = self.bytes.iter().map(|b| b.count_ones()).sum();
        Self::M.saturating_sub(ones as usize)
    }

    /// Calculates the estimated cardinality (count of unique items) based on the BEP 33 formula:
    /// `size = ln(c / m) / (k * ln(1 - 1/m))` where `k = 2`, `m = 2048`, and `c = min(m-1, countZeroBits)`.
    pub fn estimate_cardinality(&self) -> f64 {
        let c = self.count_zero_bits().clamp(1, Self::M - 1);
        let m = Self::M as f64;
        let c_f64 = c as f64;
        (c_f64 / m).ln() / (2.0 * (1.0 - 1.0 / m).ln())
    }

    /// Unions another Bloom filter into this one by bitwise-ORing.
    pub fn union_with(&mut self, other: &DhtBloomFilter) {
        for (a, b) in self.bytes.iter_mut().zip(other.bytes.iter()) {
            *a |= *b;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bep51_sample_infohashes_roundtrip() {
        let id = [0x11; 20];
        let hash1 = [0xAA; 20];
        let hash2 = [0xBB; 20];
        let resp = SampleInfohashesResponse {
            samples: vec![hash1, hash2],
            num: 42,
            interval: 1800,
            nodes: Vec::new(),
            nodes6: Vec::new(),
        };

        let bencode = encode_sample_infohashes_response(&id, &resp);
        let mut dict = bencode.into_dict().unwrap();
        let decoded = decode_sample_infohashes_response(&mut dict).unwrap();

        assert_eq!(decoded.samples.len(), 2);
        assert_eq!(decoded.samples[0], hash1);
        assert_eq!(decoded.samples[1], hash2);
        assert_eq!(decoded.num, 42);
        assert_eq!(decoded.interval, 1800);
    }

    #[test]
    fn test_bep33_dht_scrape_roundtrip() {
        let id = [0x22; 20];
        let resp = DhtScrapeResponse {
            seeders: 15,
            leechers: 3,
            bfsd: Some(vec![0x01, 0x02, 0x03]),
            bfpe: None,
        };

        let bencode = encode_dht_scrape_response(&id, &resp);
        let mut dict = bencode.into_dict().unwrap();
        let decoded = decode_dht_scrape_response(&mut dict).unwrap();

        assert_eq!(decoded.seeders, 15);
        assert_eq!(decoded.leechers, 3);
        assert_eq!(decoded.bfsd, Some(vec![0x01, 0x02, 0x03]));
        assert_eq!(decoded.bfpe, None);
    }

    #[test]
    fn test_bep33_bloom_filter_official_test_vector() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let mut bloom = DhtBloomFilter::new();

        // 192.0.2.0 - 192.0.2.255 inclusive (256 addresses)
        for last in 0..=255 {
            bloom.insert_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)));
        }

        // 2001:DB8:: - 2001:DB8::3E7 inclusive (1000 addresses)
        for i in 0..=0x3E7 {
            bloom.insert_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, i)));
        }

        let expected_hex = concat!(
            "F6C3F5EAA07FFD91BDE89F777F26FB2BFF37BDB8FB2BBAA2FD3DDDE7BACFFF75EE7CCBAE",
            "FE5EEDB1FBFAFF67F6ABFF5E43DDBCA3FD9B9FFDF4FFD3E9DFF12D1BDF59DB53DBE9FA5B",
            "7FF3B8FDFCDE1AFB8BEDD7BE2F3EE71EBBBFE93BCDEEFE148246C2BC5DBFF7E7EFDCF24F",
            "D8DC7ADFFD8FFFDFDDFFF7A4BBEEDF5CB95CE81FC7FCFF1FF4FFFFDFE5F7FDCBB7FD79B3",
            "FA1FC77BFE07FFF905B7B7FFC7FEFEFFE0B8370BB0CD3F5B7F2BD93FEB4386CFDD6F7FD5",
            "BFAF2E9EBFFFFEECD67ADBF7C67F17EFD5D75EBA6FFEBA7FFF47A91EB1BFBB53E8ABFB57",
            "62ABE8FF237279BFEFBFEEF5FFC5FEBFDFE5ADFFADFEE1FB737FFFFBFD9F6AEFFEEE76B6",
            "FD8F72EF"
        );

        let expected_bytes: Vec<u8> = (0..expected_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&expected_hex[i..i + 2], 16).unwrap())
            .collect();

        assert_eq!(&bloom.bytes[..], &expected_bytes[..]);

        let estimate = bloom.estimate_cardinality();
        // Expected ~1224.9308
        assert!(
            (estimate - 1224.9308).abs() < 0.01,
            "estimate was {}",
            estimate
        );
    }
}
