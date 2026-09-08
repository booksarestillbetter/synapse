//! BEP 18 Search Engine Specification.
//!
//! Provides data models and parsers for search engine queries and result sets.

use std::collections::BTreeMap;
use synapse_bencode::BEncode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchItem {
    pub name: String,
    pub size: u64,
    pub seeds: u32,
    pub leechers: u32,
    pub info_hash: Option<[u8; 20]>,
    pub download_url: Option<String>,
    pub category: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResponse {
    pub total_results: u32,
    pub items: Vec<SearchItem>,
}

impl SearchResponse {
    /// Encodes a search response into a bencoded dictionary.
    pub fn encode_bencode(&self) -> Vec<u8> {
        let mut dict = BTreeMap::new();
        dict.insert(b"total".to_vec(), BEncode::Int(i64::from(self.total_results)));

        let mut item_list = Vec::with_capacity(self.items.len());
        for item in &self.items {
            let mut item_dict = BTreeMap::new();
            item_dict.insert(b"name".to_vec(), BEncode::String(item.name.as_bytes().to_vec()));
            item_dict.insert(b"size".to_vec(), BEncode::Int(item.size as i64));
            item_dict.insert(b"seeds".to_vec(), BEncode::Int(i64::from(item.seeds)));
            item_dict.insert(b"leechers".to_vec(), BEncode::Int(i64::from(item.leechers)));

            if let Some(ref ih) = item.info_hash {
                item_dict.insert(b"info_hash".to_vec(), BEncode::String(ih.to_vec()));
            }
            if let Some(ref url) = item.download_url {
                item_dict.insert(b"url".to_vec(), BEncode::String(url.as_bytes().to_vec()));
            }
            if let Some(ref cat) = item.category {
                item_dict.insert(b"category".to_vec(), BEncode::String(cat.as_bytes().to_vec()));
            }

            item_list.push(BEncode::Dict(item_dict));
        }

        dict.insert(b"results".to_vec(), BEncode::List(item_list));
        BEncode::Dict(dict).encode_to_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bep18_search_response_encode() {
        let resp = SearchResponse {
            total_results: 1,
            items: vec![SearchItem {
                name: "Arch Linux ISO".to_string(),
                size: 900_000_000,
                seeds: 150,
                leechers: 12,
                info_hash: Some([0x88; 20]),
                download_url: Some("https://archlinux.org/rel.torrent".to_string()),
                category: Some("OS".to_string()),
            }],
        };

        let encoded = resp.encode_bencode();
        let decoded = synapse_bencode::decode_buf(&encoded).unwrap();
        assert!(decoded.as_dict().unwrap().contains_key(b"results".as_ref()));
    }
}
