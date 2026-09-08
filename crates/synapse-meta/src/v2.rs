//! BEP 52 BitTorrent v2 File Tree and Hybrid Torrent Metadata.
//!
//! Parses the hierarchical `file tree` bencode dictionary format, per-file
//! SHA-256 Merkle roots, and handles v1/v2 hybrid metadata structures.

use std::collections::BTreeMap;
use std::path::PathBuf;
use synapse_bencode::BEncode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2FileEntry {
    pub path: PathBuf,
    pub length: u64,
    pub pieces_root: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2TorrentInfo {
    pub meta_version: u32,
    pub piece_length: u32,
    pub files: Vec<V2FileEntry>,
    pub piece_layers: BTreeMap<[u8; 32], Vec<u8>>,
}

/// Recursively parses a BEP 52 `file tree` dictionary into a flat list of `V2FileEntry` records.
pub fn parse_file_tree(
    tree_dict: &BTreeMap<Vec<u8>, BEncode>,
    current_path: PathBuf,
    out_files: &mut Vec<V2FileEntry>,
) -> Result<(), &'static str> {
    for (key, val) in tree_dict {
        let key_str = String::from_utf8_lossy(key).to_string();

        if key.is_empty() {
            // Leaf file metadata dictionary
            let file_dict = val
                .as_dict()
                .ok_or("leaf file entry in file tree must be a dict")?;

            let length = *file_dict
                .get(b"length".as_ref())
                .and_then(|v| v.as_int())
                .ok_or("file entry must contain integer length")? as u64;

            let pieces_root = file_dict
                .get(b"pieces root".as_ref())
                .and_then(|v| v.as_bytes())
                .and_then(|b| {
                    if b.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(b);
                        Some(arr)
                    } else {
                        None
                    }
                });

            out_files.push(V2FileEntry {
                path: current_path.clone(),
                length,
                pieces_root,
            });
        } else {
            // Sub-directory or file node
            if let Some(sub_dict) = val.as_dict() {
                let next_path = current_path.join(key_str);
                parse_file_tree(sub_dict, next_path, out_files)?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_v2_file_tree_nested() {
        let mut leaf = BTreeMap::new();
        leaf.insert(b"length".to_vec(), BEncode::Int(65536));
        let root_hash = [0x42u8; 32];
        leaf.insert(b"pieces root".to_vec(), BEncode::String(root_hash.to_vec()));

        let mut file_node = BTreeMap::new();
        file_node.insert(b"".to_vec(), BEncode::Dict(leaf));

        let mut dir_node = BTreeMap::new();
        dir_node.insert(b"test.iso".to_vec(), BEncode::Dict(file_node));

        let mut root_tree = BTreeMap::new();
        root_tree.insert(b"ubuntu".to_vec(), BEncode::Dict(dir_node));

        let mut files = Vec::new();
        parse_file_tree(&root_tree, PathBuf::new(), &mut files).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, PathBuf::from("ubuntu/test.iso"));
        assert_eq!(files[0].length, 65536);
        assert_eq!(files[0].pieces_root, Some(root_hash));
    }
}
