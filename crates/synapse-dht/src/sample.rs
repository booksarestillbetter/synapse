//! BEP 33 (DHT Scrape) and BEP 51 (DHT Infohash Indexing / sample_infohashes).
//!
//! Provides sampling and scraping capabilities over the Kademlia DHT.
//! BEP 51 allows DHT crawlers and indexers to efficiently sample swarms,
//! while BEP 33 allows querying estimated seeder and leecher counts.

use std::collections::BTreeMap;
use synapse_bencode::BEncode;
use crate::proto::{compact_nodes_decode, compact_nodes_encode, compact_nodes6_decode, compact_nodes6_encode, NodeInfo, NodeInfoV6};

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
        dict.insert(b"nodes".to_vec(), BEncode::String(compact_nodes_encode(&resp.nodes)));
    }
    if !resp.nodes6.is_empty() {
        dict.insert(b"nodes6".to_vec(), BEncode::String(compact_nodes6_encode(&resp.nodes6)));
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
    for chunk in samples_bytes.chunks_exact(20) {
        let mut arr = [0u8; 20];
        arr.copy_from_slice(chunk);
        samples.push(arr);
    }

    let nodes = match dict.remove(b"nodes".as_ref()).and_then(BEncode::into_bytes) {
        Some(b) => compact_nodes_decode(&b).unwrap_or_default(),
        None => Vec::new(),
    };

    let nodes6 = match dict.remove(b"nodes6".as_ref()).and_then(BEncode::into_bytes) {
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
pub fn encode_dht_scrape_response(
    id: &[u8; 20],
    resp: &DhtScrapeResponse,
) -> BEncode {
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
}
