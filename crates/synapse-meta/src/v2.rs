//! BEP 52 BitTorrent v2 File Tree and Hybrid Torrent Metadata.
//!
//! Parses the hierarchical `file tree` bencode dictionary format, per-file
//! SHA-256 Merkle roots, and handles v1/v2 hybrid metadata structures.

use crate::MetaError;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use synapse_bencode::BEncode;

pub const MAX_V2_PATH_COMPONENTS: usize = 32;
pub const MAX_V2_FILES: usize = 100_000;

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
) -> Result<(), MetaError> {
    let mut total_len = 0u64;
    parse_file_tree_inner(tree_dict, current_path, 0, &mut total_len, out_files)
}

fn parse_file_tree_inner(
    tree_dict: &BTreeMap<Vec<u8>, BEncode>,
    current_path: PathBuf,
    depth: usize,
    total_len: &mut u64,
    out_files: &mut Vec<V2FileEntry>,
) -> Result<(), MetaError> {
    if depth > MAX_V2_PATH_COMPONENTS {
        return Err(MetaError::PathTooDeep);
    }

    for (key, val) in tree_dict {
        if key.is_empty() {
            if depth == 0 || tree_dict.len() != 1 {
                return Err(MetaError::InvalidFileDict);
            }
            // Leaf file metadata dictionary
            let file_dict = val.as_dict().ok_or(MetaError::InvalidFileDict)?;

            let len_i64 = *file_dict
                .get(b"length".as_ref())
                .and_then(|v| v.as_int())
                .ok_or(MetaError::InvalidFileDict)?;
            if len_i64 < 0 {
                return Err(MetaError::InvalidFileLength);
            }
            let length = len_i64 as u64;
            *total_len = total_len
                .checked_add(length)
                .ok_or(MetaError::InvalidFileLength)?;

            let pieces_root = match file_dict.get(b"pieces root".as_ref()) {
                Some(v) => {
                    let b = v.as_bytes().ok_or(MetaError::InvalidFileDict)?;
                    if b.len() != 32 {
                        return Err(MetaError::InvalidFileDict);
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(b);
                    Some(arr)
                }
                None => {
                    if length > 0 {
                        return Err(MetaError::InvalidFileDict);
                    }
                    None
                }
            };

            if out_files.len() >= MAX_V2_FILES {
                return Err(MetaError::TooManyFiles);
            }

            out_files.push(V2FileEntry {
                path: current_path.clone(),
                length,
                pieces_root,
            });
        } else {
            let key_str = std::str::from_utf8(key).map_err(|_| MetaError::InvalidFilePath)?;
            if key_str == "."
                || key_str == ".."
                || key_str.contains('/')
                || key_str.contains('\\')
                || key_str.contains('\0')
                || !crate::component_is_safe(OsStr::new(key_str))
            {
                return Err(MetaError::UnsafeFilePath);
            }
            if depth + 1 > MAX_V2_PATH_COMPONENTS {
                return Err(MetaError::PathTooDeep);
            }
            let sub_dict = val.as_dict().ok_or(MetaError::InvalidFileDict)?;
            let next_path = current_path.join(key_str);
            parse_file_tree_inner(sub_dict, next_path, depth + 1, total_len, out_files)?;
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

    #[test]
    fn test_parse_v2_file_tree_rejects_negative_len_invalid_utf8_bad_root_and_deep_paths() {
        // 1. Negative file length
        let mut bad_leaf = BTreeMap::new();
        bad_leaf.insert(b"length".to_vec(), BEncode::Int(-1));
        bad_leaf.insert(b"pieces root".to_vec(), BEncode::String(vec![0x11; 32]));
        let tree_neg = BTreeMap::from([(
            b"file.bin".to_vec(),
            BEncode::Dict(BTreeMap::from([(b"".to_vec(), BEncode::Dict(bad_leaf))])),
        )]);
        assert_eq!(
            parse_file_tree(&tree_neg, PathBuf::new(), &mut Vec::new()),
            Err(MetaError::InvalidFileLength)
        );

        // 2. Non-UTF8 path component
        let mut good_leaf = BTreeMap::new();
        good_leaf.insert(b"length".to_vec(), BEncode::Int(100));
        good_leaf.insert(b"pieces root".to_vec(), BEncode::String(vec![0x11; 32]));
        let tree_non_utf8 = BTreeMap::from([(
            vec![0xff, 0xfe],
            BEncode::Dict(BTreeMap::from([(
                b"".to_vec(),
                BEncode::Dict(good_leaf.clone()),
            )])),
        )]);
        assert_eq!(
            parse_file_tree(&tree_non_utf8, PathBuf::new(), &mut Vec::new()),
            Err(MetaError::InvalidFilePath)
        );

        // 3. Path traversal / slash / dot components
        for bad_comp in [&b".."[..], b".", b"a/b", b"a\\b", b"a\0b"] {
            let tree_bad = BTreeMap::from([(
                bad_comp.to_vec(),
                BEncode::Dict(BTreeMap::from([(
                    b"".to_vec(),
                    BEncode::Dict(good_leaf.clone()),
                )])),
            )]);
            assert_eq!(
                parse_file_tree(&tree_bad, PathBuf::new(), &mut Vec::new()),
                Err(MetaError::UnsafeFilePath)
            );
        }

        // 4. Non-empty file missing 32-byte pieces root
        let mut leaf_short_root = BTreeMap::new();
        leaf_short_root.insert(b"length".to_vec(), BEncode::Int(100));
        leaf_short_root.insert(b"pieces root".to_vec(), BEncode::String(vec![0x11; 20]));
        let tree_short_root = BTreeMap::from([(
            b"file.bin".to_vec(),
            BEncode::Dict(BTreeMap::from([(
                b"".to_vec(),
                BEncode::Dict(leaf_short_root),
            )])),
        )]);
        assert_eq!(
            parse_file_tree(&tree_short_root, PathBuf::new(), &mut Vec::new()),
            Err(MetaError::InvalidFileDict)
        );

        // 5. Exceeding MAX_V2_PATH_COMPONENTS (32)
        let mut node = BTreeMap::from([(b"".to_vec(), BEncode::Dict(good_leaf))]);
        for _ in 0..=MAX_V2_PATH_COMPONENTS {
            node = BTreeMap::from([(b"d".to_vec(), BEncode::Dict(node))]);
        }
        assert_eq!(
            parse_file_tree(&node, PathBuf::new(), &mut Vec::new()),
            Err(MetaError::PathTooDeep)
        );
    }
}
