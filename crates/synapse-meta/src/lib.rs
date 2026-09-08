//! Torrent metadata (`.torrent` file / magnet link) parsing and piece-to-file layout.
//!
//! Ports the pre-rewrite codebase's `src/torrent/info.rs`, including this session's own
//! `1.5`-branch security fix for it (see `CHANGELOG.md`/`doc/AUDIT_1.5.md` item 3): file
//! paths from bencode metadata are attacker-controlled (a `.torrent` file, magnet-derived
//! `ut_metadata`, or an RPC-uploaded torrent) and are validated to contain only normal
//! path components - no `..`, no absolute/root paths - before this crate ever hands them
//! back to a caller that might join them onto a real download directory. That fix is not
//! optional scope creep here; it's carried forward deliberately; do not weaken
//! [`path_is_safe`] without a very good reason.
//!
//! Reuses the existing `synapse-bencode` crate rather than reimplementing bencode
//! parsing - it's already iterative (not recursive, so immune to the classic
//! deeply-nested-bencode stack-overflow DoS) and has its own test/fuzz coverage; there's
//! no reason to duplicate it for the rewrite.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use rand::seq::SliceRandom;
use sha1::{Digest, Sha1};
use synapse_bencode::BEncode;
use url::Url;

pub mod bep18;
pub mod feed;
pub mod merkle;
pub mod merkle_v1;
pub mod padding;
pub mod signature;
pub mod v2;

pub use bep18::{SearchItem, SearchResponse};
pub use feed::{parse_torrent_feed, FeedItem};
pub use merkle::{compute_file_merkle_root, compute_file_piece_layer, hash_block, hash_parent};
pub use merkle_v1::compute_file_merkle_root_v1;
pub use padding::{is_padding_file, separate_padding_files};
pub use signature::{parse_signatures, TorrentSignature};
pub use v2::{parse_file_tree, V2FileEntry, V2TorrentInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum FilePriority {
    DoNotDownload = 0,
    Low = 1,
    Normal = 4,
    High = 7,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    /// Path relative to the torrent's download directory - callers join this onto
    /// their configured download directory, this crate never does I/O itself.
    pub path: PathBuf,
    pub length: u64,
}

#[derive(Debug)]
pub struct Info {
    pub name: String,
    pub announce: Option<Arc<Url>>,
    pub creator: Option<String>,
    pub comment: Option<String>,
    pub piece_len: u32,
    pub total_len: u64,
    pub pieces: u32,
    pub hashes: parking_lot::RwLock<Option<Arc<Vec<[u8; 20]>>>>,
    pub hash: [u8; 20],
    pub files: Vec<File>,
    pub private: bool,
    /// Cumulative starting offsets of each file across the concatenated torrent layout.
    pub file_offsets: Vec<u64>,
    pub url_list: Vec<Vec<Arc<Url>>>,
    pub web_seeds: Vec<Arc<Url>>,
}

impl Clone for Info {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            announce: self.announce.clone(),
            creator: self.creator.clone(),
            comment: self.comment.clone(),
            piece_len: self.piece_len,
            total_len: self.total_len,
            pieces: self.pieces,
            hashes: parking_lot::RwLock::new(self.hashes.read().clone()),
            hash: self.hash,
            files: self.files.clone(),
            private: self.private,
            file_offsets: self.file_offsets.clone(),
            url_list: self.url_list.clone(),
            web_seeds: self.web_seeds.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MetaError {
    #[error("invalid or missing info dict")]
    InvalidInfo,
    #[error("info must specify a valid piece length")]
    InvalidPieceLength,
    #[error("info must provide valid, 20-byte-aligned piece hashes")]
    InvalidHashes,
    #[error("private key must be an integer equal to 0 or 1 if present")]
    InvalidPrivateFlag,
    #[error("name field must be a valid UTF8 string")]
    InvalidName,
    #[error("file dict must contain length and name or path")]
    InvalidFileDict,
    #[error("file path must be a valid UTF8 string")]
    InvalidFilePath,
    #[error("file length must be a valid integer")]
    InvalidFileLength,
    #[error("file path is not safe (absolute path or `..` component)")]
    UnsafeFilePath,
    #[error("torrent must contain at least one file")]
    NoFiles,
    #[error("magnet URL must use the magnet:// scheme")]
    InvalidMagnetScheme,
    #[error("magnet URL is malformed")]
    MalformedMagnetUrl,
    #[error("no info hash (xt=urn:btih:...) found in magnet URL")]
    NoMagnetHash,
}

pub type Result<T> = std::result::Result<T, MetaError>;

/// Rejects paths that could escape the torrent's download directory: absolute paths
/// (including a Windows-style prefix) and any `.`/`..` component. Bencode path segments
/// are attacker-controlled, so this must run before any segment is joined onto a real
/// filesystem path anywhere downstream.
pub fn path_is_safe(path: &Path) -> bool {
    let mut components = path.components().peekable();
    components.peek().is_some() && components.all(|c| matches!(c, Component::Normal(_)))
}

pub fn bencode_to_string_lossy(b: BEncode) -> Option<String> {
    match b {
        BEncode::String(v) => Some(String::from_utf8(v.clone()).unwrap_or_else(|_| String::from_utf8_lossy(&v).into_owned())),
        _ => None,
    }
}

impl File {
    fn from_bencode(data: BEncode) -> Result<File> {
        let mut d = data.into_dict().ok_or(MetaError::InvalidFileDict)?;
        let name_val = d.remove(b"name.utf-8".as_ref()).or_else(|| d.remove(b"name".as_ref()));
        let path_val = d.remove(b"path.utf-8".as_ref()).or_else(|| d.remove(b"path".as_ref()));
        let length_val = d.remove(b"length".as_ref()).or_else(|| d.remove(b"length.utf-8".as_ref()));
        match (name_val, path_val, length_val) {
            (Some(v), None, Some(l)) => {
                let path_str = bencode_to_string_lossy(v).ok_or(MetaError::InvalidFilePath)?;
                let path = PathBuf::from(path_str);
                if !path_is_safe(&path) {
                    return Err(MetaError::UnsafeFilePath);
                }
                Ok(File {
                    path,
                    length: l.into_int().ok_or(MetaError::InvalidFileLength)? as u64,
                })
            }
            (None, Some(path), Some(l)) => {
                let mut p = PathBuf::new();
                for dir in path.into_list().ok_or(MetaError::InvalidFilePath)? {
                    let seg = bencode_to_string_lossy(dir).ok_or(MetaError::InvalidFilePath)?;
                    p.push(seg);
                }
                if !path_is_safe(&p) {
                    return Err(MetaError::UnsafeFilePath);
                }
                Ok(File {
                    path: p,
                    length: l.into_int().ok_or(MetaError::InvalidFileLength)? as u64,
                })
            }
            _ => Err(MetaError::InvalidFileDict),
        }
    }
}

fn parse_bencode_files(mut data: BTreeMap<Vec<u8>, BEncode>) -> Result<Vec<File>> {
    match data.remove(b"files".as_ref()).and_then(|l| l.into_list()) {
        Some(fs) => {
            let mut path = PathBuf::new();
            let name_str = data
                .remove(b"name.utf-8".as_ref())
                .or_else(|| data.remove(b"name".as_ref()))
                .and_then(bencode_to_string_lossy)
                .ok_or(MetaError::InvalidFileDict)?;
            path.push(name_str);
            if !path_is_safe(&path) {
                return Err(MetaError::UnsafeFilePath);
            }
            let mut files = Vec::with_capacity(fs.len());
            for f in fs {
                let mut file = File::from_bencode(f)?;
                file.path = path.join(file.path);
                files.push(file);
            }
            Ok(files)
        }
        None => File::from_bencode(BEncode::Dict(data)).map(|f| vec![f]),
    }
}

fn generate_file_offsets(files: &[File]) -> Vec<u64> {
    let mut offsets = Vec::with_capacity(files.len());
    let mut current = 0u64;
    for f in files {
        offsets.push(current);
        current += f.length;
    }
    offsets
}

/// One contiguous range of a piece's data that lands in a single file, yielded by
/// [`Info::block_locations`]. `piece_range` is the slice of the *block's own* buffer
/// that belongs in this file, at `file_offset` within `file` (an index into
/// [`Info::files`]) - callers slice their downloaded block `Bytes` by `piece_range` and
/// write it to `files[file].path` (joined onto their download directory) at
/// `file_offset`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRange {
    pub file: usize,
    pub file_offset: u64,
    pub piece_range: std::ops::Range<usize>,
}

impl Info {
    #[inline]
    pub fn pieces(&self) -> u32 {
        self.pieces
    }

    /// Looks up the expected SHA-1 hash for piece `index` if hashes have not been evicted.
    pub fn piece_hash(&self, index: u32) -> Option<[u8; 20]> {
        self.hashes.read().as_ref().and_then(|h| h.get(index as usize).copied())
    }

    /// Returns a shared reference to the full piece hashes vector if not evicted.
    pub fn piece_hashes(&self) -> Option<Arc<Vec<[u8; 20]>>> {
        self.hashes.read().as_ref().and_then(|h| {
            if h.is_empty() {
                None
            } else {
                Some(Arc::clone(h))
            }
        })
    }

    /// Returns true if the torrent's piece hashes are currently held in memory.
    pub fn has_piece_hashes(&self) -> bool {
        self.hashes.read().as_ref().is_some_and(|h| !h.is_empty())
    }

    /// Evicts piece hashes from memory to reclaim heap space on 100% complete swarms.
    pub fn evict_piece_hashes(&self) {
        *self.hashes.write() = None;
    }

    /// Restores piece hashes into memory (e.g. for re-verification / recheck).
    pub fn restore_piece_hashes(&self, hashes: Vec<[u8; 20]>) {
        if hashes.is_empty() {
            *self.hashes.write() = None;
        } else {
            *self.hashes.write() = Some(Arc::new(hashes));
        }
    }

    pub fn piece_len(&self, index: u32) -> u32 {
        if index != self.pieces.saturating_sub(1) {
            self.piece_len
        } else {
            (self.total_len - u64::from(self.piece_len) * u64::from(self.pieces.saturating_sub(1))) as u32
        }
    }

    /// Splits the byte range `[begin, begin+len)` of piece `index` across whichever
    /// file(s) it lands in. A piece commonly spans multiple files near a file boundary.
    pub fn block_locations(&self, index: u32, begin: u32, len: u32) -> Vec<FileRange> {
        if self.files.is_empty() {
            return Vec::new();
        }
        let global_offset = u64::from(index) * u64::from(self.piece_len) + u64::from(begin);
        let mut file = if self.files.len() == 1 {
            0
        } else {
            match self.file_offsets.binary_search(&global_offset) {
                Ok(f) => f,
                Err(f) => f.saturating_sub(1),
            }
        };
        let mut file_offset = global_offset - self.file_offsets[file];

        let mut out = Vec::new();
        let mut remaining = len as usize;
        let mut piece_pos = 0usize;
        while remaining > 0 && file < self.files.len() {
            let file_len = self.files[file].length;
            if file_offset >= file_len {
                file += 1;
                file_offset = 0;
                continue;
            }
            let space_in_file = (file_len - file_offset) as usize;
            let take = remaining.min(space_in_file);
            out.push(FileRange {
                file,
                file_offset,
                piece_range: piece_pos..piece_pos + take,
            });
            remaining -= take;
            piece_pos += take;
            file += 1;
            file_offset = 0;
        }
        out
    }

    /// Returns the inclusive `(start_piece, end_piece)` index range spanning a given file.
    pub fn piece_range_for_file(&self, file_idx: usize) -> Option<(u32, u32)> {
        if file_idx >= self.files.len() || self.piece_len == 0 {
            return None;
        }

        let start_offset = self.file_offsets[file_idx];
        let file_len = self.files[file_idx].length;
        if file_len == 0 {
            return None;
        }

        let end_offset = start_offset + file_len;
        let start_piece = (start_offset / u64::from(self.piece_len)) as u32;
        let end_piece = ((end_offset.saturating_sub(1)) / u64::from(self.piece_len)) as u32;

        Some((start_piece, end_piece.min(self.pieces.saturating_sub(1))))
    }

    /// Returns all file indices that overlap with a given piece index.
    pub fn files_for_piece(&self, piece_idx: u32) -> Vec<usize> {
        let mut files = Vec::new();
        for (idx, _) in self.files.iter().enumerate() {
            if let Some((start, end)) = self.piece_range_for_file(idx) {
                if piece_idx >= start && piece_idx <= end {
                    files.push(idx);
                }
            }
        }
        files
    }

    pub fn from_bencode(data: BEncode) -> Result<Info> {
        let mut d = data.into_dict().ok_or(MetaError::InvalidInfo)?;
        let mut i = d
            .remove(b"info".as_ref())
            .and_then(|i| i.into_dict())
            .ok_or(MetaError::InvalidInfo)?;

        let mut info_bytes = Vec::new();
        BEncode::Dict(i.clone())
            .encode(&mut info_bytes)
            .expect("encoding an in-memory BEncode value cannot fail");
        let hash: [u8; 20] = Sha1::digest(&info_bytes).into();

        let announce = d
            .remove(b"announce".as_ref())
            .and_then(BEncode::into_string)
            .and_then(|a| Url::parse(&a).ok().map(Arc::new));
        let comment = d.remove(b"comment.utf-8".as_ref())
            .or_else(|| d.remove(b"comment".as_ref()))
            .and_then(bencode_to_string_lossy);
        let creator = d.remove(b"created by.utf-8".as_ref())
            .or_else(|| d.remove(b"created by".as_ref()))
            .and_then(bencode_to_string_lossy);
        let piece_len = i
            .remove(b"piece length".as_ref())
            .and_then(|i| i.into_int())
            .ok_or(MetaError::InvalidPieceLength)? as u64;
        let hashes: Vec<[u8; 20]> = i
            .remove(b"pieces".as_ref())
            .and_then(|p| p.into_bytes())
            .and_then(|p| {
                if p.len() % 20 != 0 {
                    return None;
                }
                Some(p.chunks_exact(20).map(|c| c.try_into().unwrap()).collect())
            })
            .ok_or(MetaError::InvalidHashes)?;

        let private = match i.remove(b"private".as_ref()) {
            Some(BEncode::Int(0)) => false,
            Some(BEncode::Int(n)) if n > 0 => true,
            Some(BEncode::String(ref s)) if s == b"0" => false,
            Some(BEncode::String(ref s)) if s == b"1" => true,
            Some(v) => match v.into_int() {
                Some(0) => false,
                Some(1) => true,
                _ => return Err(MetaError::InvalidPrivateFlag),
            },
            None => false,
        };

        let files = parse_bencode_files(i)?;
        if files.is_empty() {
            return Err(MetaError::NoFiles);
        }
        let name = if !files[0].path.has_root() {
            files[0]
                .path
                .components()
                .next()
                .expect("non-empty path has at least one component")
                .as_os_str()
                .to_os_string()
                .into_string()
                .map_err(|_| MetaError::InvalidName)?
        } else {
            // Unreachable: `path_is_safe` (enforced in `File::from_bencode` and
            // `parse_bencode_files`) already rejects any path with a root component.
            unreachable!("path_is_safe should have rejected any rooted path already")
        };

        let total_len = files.iter().map(|f| f.length).sum();
        let pieces = hashes.len() as u32;
        let file_offsets = generate_file_offsets(&files);

        let url_list: Vec<_> = d
            .remove(b"announce-list".as_ref())
            .and_then(BEncode::into_list)
            .unwrap_or_default()
            .into_iter()
            .map(|l| {
                let mut l: Vec<_> = l
                    .into_list()
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(bencode_to_string_lossy)
                    .filter_map(|s| Url::parse(&s).ok().map(Arc::new))
                    .collect();
                l.shuffle(&mut rand::thread_rng());
                l
            })
            .collect();

        let mut web_seeds = Vec::new();
        if let Some(urls) = d.remove(b"url-list".as_ref()) {
            match urls {
                BEncode::String(s) => {
                    if let Ok(str_val) = String::from_utf8(s) {
                        if let Ok(u) = Url::parse(&str_val) {
                            web_seeds.push(Arc::new(u));
                        }
                    }
                }
                BEncode::List(list) => {
                    for item in list {
                        if let Some(s) = bencode_to_string_lossy(item) {
                            if let Ok(u) = Url::parse(&s) {
                                web_seeds.push(Arc::new(u));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(BEncode::List(list)) = d.remove(b"httpseeds".as_ref()) {
            for item in list {
                if let Some(s) = bencode_to_string_lossy(item) {
                    if let Ok(u) = Url::parse(&s) {
                        web_seeds.push(Arc::new(u));
                    }
                }
            }
        }

        Ok(Info {
            name,
            comment,
            creator,
            announce,
            piece_len: piece_len as u32,
            total_len,
            pieces,
            hashes: parking_lot::RwLock::new(if hashes.is_empty() { None } else { Some(Arc::new(hashes)) }),
            hash,
            files,
            private,
            file_offsets,
            url_list,
            web_seeds,
        })
    }

    /// Parses an `Info` directly from the raw bencoded `info` dictionary bytes received
    /// via BEP 9 `ut_metadata`.
    pub fn from_info_dict_bytes(info_bytes: &[u8]) -> Result<Info> {
        let bencode = synapse_bencode::decode_buf(info_bytes).map_err(|_| MetaError::InvalidInfo)?;
        let mut i = bencode.into_dict().ok_or(MetaError::InvalidInfo)?;
        let hash: [u8; 20] = Sha1::digest(info_bytes).into();

        let piece_len = i
            .remove(b"piece length".as_ref())
            .and_then(|i| i.into_int())
            .ok_or(MetaError::InvalidPieceLength)? as u64;
        let hashes: Vec<[u8; 20]> = i
            .remove(b"pieces".as_ref())
            .and_then(|p| p.into_bytes())
            .and_then(|p| {
                if p.len() % 20 != 0 {
                    return None;
                }
                Some(p.chunks_exact(20).map(|c| c.try_into().unwrap()).collect())
            })
            .ok_or(MetaError::InvalidHashes)?;

        let private = match i.remove(b"private".as_ref()) {
            Some(BEncode::Int(0)) => false,
            Some(BEncode::Int(n)) if n > 0 => true,
            Some(BEncode::String(ref s)) if s == b"0" => false,
            Some(BEncode::String(ref s)) if s == b"1" => true,
            Some(v) => match v.into_int() {
                Some(0) => false,
                Some(1) => true,
                _ => return Err(MetaError::InvalidPrivateFlag),
            },
            None => false,
        };

        let files = parse_bencode_files(i)?;
        if files.is_empty() {
            return Err(MetaError::NoFiles);
        }
        let name = if !files[0].path.has_root() {
            files[0]
                .path
                .components()
                .next()
                .expect("non-empty path has at least one component")
                .as_os_str()
                .to_os_string()
                .into_string()
                .map_err(|_| MetaError::InvalidName)?
        } else {
            unreachable!("path_is_safe should have rejected any rooted path already")
        };

        let total_len = files.iter().map(|f| f.length).sum();
        let pieces = hashes.len() as u32;
        let file_offsets = generate_file_offsets(&files);

        Ok(Info {
            name,
            comment: None,
            creator: None,
            announce: None,
            piece_len: piece_len as u32,
            total_len,
            pieces,
            hashes: parking_lot::RwLock::new(if hashes.is_empty() { None } else { Some(Arc::new(hashes)) }),
            hash,
            files,
            private,
            file_offsets,
            url_list: Vec::new(),
            web_seeds: Vec::new(),
        })
    }

    /// Serializes this `Info` struct back into a canonical BEncode dictionary.
    pub fn to_bencode(&self) -> BEncode {
        let mut d = BTreeMap::new();
        if let Some(ref a) = self.announce {
            d.insert(b"announce".to_vec(), BEncode::String(a.to_string().into_bytes()));
        }
        if !self.url_list.is_empty() {
            let mut list = Vec::new();
            for tier in &self.url_list {
                let tier_list: Vec<BEncode> = tier
                    .iter()
                    .map(|u| BEncode::String(u.to_string().into_bytes()))
                    .collect();
                list.push(BEncode::List(tier_list));
            }
            d.insert(b"announce-list".to_vec(), BEncode::List(list));
        }
        if let Some(ref c) = self.comment {
            d.insert(b"comment".to_vec(), BEncode::String(c.clone().into_bytes()));
        }
        if let Some(ref cr) = self.creator {
            d.insert(b"created by".to_vec(), BEncode::String(cr.clone().into_bytes()));
        }

        let mut i = BTreeMap::new();
        i.insert(b"name".to_vec(), BEncode::String(self.name.clone().into_bytes()));
        i.insert(b"piece length".to_vec(), BEncode::Int(self.piece_len as i64));

        let mut pieces_bytes = Vec::new();
        if let Some(ref hashes) = *self.hashes.read() {
            pieces_bytes.reserve(hashes.len() * 20);
            for h in hashes.iter() {
                pieces_bytes.extend_from_slice(h);
            }
        }
        i.insert(b"pieces".to_vec(), BEncode::String(pieces_bytes));

        if self.private {
            i.insert(b"private".to_vec(), BEncode::Int(1));
        }

        if self.files.len() == 1 && self.files[0].path == Path::new(&self.name) {
            i.insert(b"length".to_vec(), BEncode::Int(self.files[0].length as i64));
        } else {
            let mut files_list = Vec::new();
            for f in &self.files {
                let mut fd = BTreeMap::new();
                fd.insert(b"length".to_vec(), BEncode::Int(f.length as i64));
                let rel_path = f.path.strip_prefix(&self.name).unwrap_or(&f.path);
                let path_components: Vec<BEncode> = rel_path.iter()
                    .map(|c| BEncode::String(c.to_string_lossy().as_bytes().to_vec()))
                    .collect();
                fd.insert(b"path".to_vec(), BEncode::List(path_components));
                files_list.push(BEncode::Dict(fd));
            }
            i.insert(b"files".to_vec(), BEncode::List(files_list));
        }

        d.insert(b"info".to_vec(), BEncode::Dict(i));
        BEncode::Dict(d)
    }

    /// Encodes this `Info` struct into raw `.torrent` bencoded bytes.
    pub fn to_torrent_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.to_bencode().encode(&mut buf).expect("in-memory encoding cannot fail");
        buf
    }

    pub fn from_magnet(data: &str) -> Result<Info> {
        let url = Url::parse(data).map_err(|_| MetaError::MalformedMagnetUrl)?;
        if url.scheme() != "magnet" {
            return Err(MetaError::InvalidMagnetScheme);
        }

        let hash = url
            .query_pairs()
            .find(|(k, v)| k == "xt" && v.starts_with("urn:btih:"))
            .and_then(|(_, v)| decode_btih(&v[9..]))
            .ok_or(MetaError::NoMagnetHash)?;

        let mut trackers: Vec<_> = url
            .query_pairs()
            .filter(|(k, _)| k == "tr")
            .filter_map(|(_, v)| Url::parse(&v).ok())
            .map(Arc::new)
            .collect();
        trackers.shuffle(&mut rand::thread_rng());

        let name = url
            .query_pairs()
            .find(|(k, _)| k == "dn")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();

        Ok(Info {
            name,
            comment: None,
            creator: None,
            announce: None,
            piece_len: 0,
            total_len: 0,
            pieces: 0,
            hashes: parking_lot::RwLock::new(None),
            hash,
            files: Vec::new(),
            private: false,
            file_offsets: Vec::new(),
            url_list: vec![trackers],
            web_seeds: Vec::new(),
        })
    }
}

/// Decodes a BEP9 `xt=urn:btih:` value, which is either 40 hex chars or a base32-encoded
/// 20-byte hash.
fn decode_btih(s: &str) -> Option<[u8; 20]> {
    if s.len() == 40 {
        let mut out = [0u8; 20];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        return Some(out);
    }
    let bytes = base32_decode(s)?;
    bytes.try_into().ok()
}

/// Minimal RFC 4648 base32 decoder (no external dependency for something this small).
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u32;
    let mut bit_count = 0u32;
    let mut out = Vec::new();
    for c in s.trim_end_matches('=').chars() {
        let val = ALPHABET.iter().position(|&b| b as char == c.to_ascii_uppercase())?;
        bits = (bits << 5) | val as u32;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dict(pairs: Vec<(&[u8], BEncode)>) -> BTreeMap<Vec<u8>, BEncode> {
        pairs.into_iter().map(|(k, v)| (k.to_vec(), v)).collect()
    }

    fn base_info_fields() -> BTreeMap<Vec<u8>, BEncode> {
        dict(vec![
            (b"piece length", BEncode::Int(16_384)),
            (b"pieces", BEncode::String(vec![0u8; 20])),
        ])
    }

    fn wrap(info: BTreeMap<Vec<u8>, BEncode>) -> BEncode {
        BEncode::Dict(dict(vec![(b"info", BEncode::Dict(info))]))
    }

    #[test]
    fn path_is_safe_rejects_unsafe_paths() {
        assert!(!path_is_safe(Path::new("..")));
        assert!(!path_is_safe(Path::new("../evil")));
        assert!(!path_is_safe(Path::new("a/../../evil")));
        assert!(!path_is_safe(Path::new("/etc/passwd")));
        assert!(!path_is_safe(Path::new("")));
    }

    #[test]
    fn path_is_safe_accepts_normal_paths() {
        assert!(path_is_safe(Path::new("file.txt")));
        assert!(path_is_safe(Path::new("dir/sub/file.txt")));
    }

    #[test]
    fn rejects_empty_files_list_instead_of_panicking() {
        let mut info = base_info_fields();
        info.insert(b"name".to_vec(), BEncode::String(b"root".to_vec()));
        info.insert(b"files".to_vec(), BEncode::List(vec![]));
        assert_eq!(Info::from_bencode(wrap(info)).unwrap_err(), MetaError::NoFiles);
    }

    #[test]
    fn rejects_path_traversal_in_multi_file_path() {
        let mut info = base_info_fields();
        info.insert(b"name".to_vec(), BEncode::String(b"root".to_vec()));
        let mut file = BTreeMap::new();
        file.insert(b"length".to_vec(), BEncode::Int(1));
        file.insert(
            b"path".to_vec(),
            BEncode::List(vec![
                BEncode::String(b"..".to_vec()),
                BEncode::String(b"evil".to_vec()),
            ]),
        );
        info.insert(b"files".to_vec(), BEncode::List(vec![BEncode::Dict(file)]));
        assert_eq!(
            Info::from_bencode(wrap(info)).unwrap_err(),
            MetaError::UnsafeFilePath
        );
    }

    #[test]
    fn accepts_normal_multi_file_torrent() {
        let mut info = base_info_fields();
        info.insert(b"name".to_vec(), BEncode::String(b"root".to_vec()));
        let mut file = BTreeMap::new();
        file.insert(b"length".to_vec(), BEncode::Int(1));
        file.insert(
            b"path".to_vec(),
            BEncode::List(vec![
                BEncode::String(b"sub".to_vec()),
                BEncode::String(b"file.txt".to_vec()),
            ]),
        );
        info.insert(b"files".to_vec(), BEncode::List(vec![BEncode::Dict(file)]));
        let res = Info::from_bencode(wrap(info)).unwrap();
        assert_eq!(res.name, "root");
        assert_eq!(res.files[0].path, PathBuf::from("root/sub/file.txt"));
    }

    #[test]
    fn block_locations_within_a_single_file() {
        let files = vec![File {
            path: PathBuf::from("a"),
            length: 100,
        }];
        let file_offsets = generate_file_offsets(&files);
        let info = Info {
            name: "t".into(),
            announce: None,
            creator: None,
            comment: None,
            piece_len: 50,
            total_len: 100,
            pieces: 2,
            hashes: parking_lot::RwLock::new(Some(Arc::new(vec![[0u8; 20]; 2]))),
            hash: [0u8; 20],
            file_offsets,
            files,
            private: false,
            url_list: vec![],
            web_seeds: vec![],
        };
        let locs = info.block_locations(0, 0, 50);
        assert_eq!(
            locs,
            vec![FileRange {
                file: 0,
                file_offset: 0,
                piece_range: 0..50,
            }]
        );
    }

    #[test]
    fn block_locations_spans_a_file_boundary() {
        let files = vec![
            File {
                path: PathBuf::from("a"),
                length: 40_000,
            },
            File {
                path: PathBuf::from("b"),
                length: 10_000,
            },
        ];
        let file_offsets = generate_file_offsets(&files);
        let info = Info {
            name: "t".into(),
            announce: None,
            creator: None,
            comment: None,
            piece_len: 16_384,
            total_len: 50_000,
            pieces: 4,
            hashes: parking_lot::RwLock::new(Some(Arc::new(vec![[0u8; 20]; 4]))),
            hash: [0u8; 20],
            file_offsets,
            files,
            private: false,
            url_list: vec![],
            web_seeds: vec![],
        };
        // Piece 2 covers bytes [32768, 49152) - crosses the 40000-byte file boundary.
        let locs = info.block_locations(2, 0, 16_384);
        assert_eq!(locs.len(), 2);
        assert_eq!(locs[0].file, 0);
        assert_eq!(locs[0].file_offset, 32_768);
        assert_eq!(locs[0].piece_range, 0..7_232);
        assert_eq!(locs[1].file, 1);
        assert_eq!(locs[1].file_offset, 0);
        assert_eq!(locs[1].piece_range, 7_232..16_384);
    }

    #[test]
    fn magnet_parses_hex_btih() {
        let hash_hex = "0123456789abcdef0123456789abcdef01234567";
        let hash_hex = &hash_hex[..40];
        let url = format!("magnet:?xt=urn:btih:{hash_hex}&dn=test");
        let info = Info::from_magnet(&url).unwrap();
        assert_eq!(info.name, "test");
        assert_eq!(hex(&info.hash), hash_hex.to_lowercase());
    }

    #[test]
    fn magnet_rejects_non_magnet_scheme() {
        assert_eq!(
            Info::from_magnet("http://example.com").unwrap_err(),
            MetaError::InvalidMagnetScheme
        );
    }

    #[test]
    fn test_info_to_bencode_preserves_info_hash() {
        let mut info = base_info_fields();
        info.insert(b"name".to_vec(), BEncode::String(b"root".to_vec()));
        let mut file = BTreeMap::new();
        file.insert(b"length".to_vec(), BEncode::Int(100));
        file.insert(
            b"path".to_vec(),
            BEncode::List(vec![
                BEncode::String(b"sub".to_vec()),
                BEncode::String(b"file.txt".to_vec()),
            ]),
        );
        info.insert(b"files".to_vec(), BEncode::List(vec![BEncode::Dict(file)]));
        let orig = Info::from_bencode(wrap(info)).unwrap();
        let bytes = orig.to_torrent_bytes();
        let reconstructed = Info::from_bencode(synapse_bencode::decode_buf(&bytes).unwrap()).unwrap();
        assert_eq!(orig.hash, reconstructed.hash);
        assert_eq!(orig.name, reconstructed.name);
        assert_eq!(orig.files, reconstructed.files);
    }

    #[test]
    fn test_piece_hash_eviction_and_restoration() {
        let mut info_fields = base_info_fields();
        info_fields.insert(b"name".to_vec(), BEncode::String(b"test".to_vec()));
        info_fields.insert(b"length".to_vec(), BEncode::Int(200));
        info_fields.insert(b"pieces".to_vec(), BEncode::String(vec![0u8; 40]));
        let info = Info::from_bencode(wrap(info_fields)).unwrap();

        assert_eq!(info.pieces(), 2);
        assert!(info.has_piece_hashes());
        assert_eq!(info.piece_hash(0), Some([0u8; 20]));
        assert_eq!(info.piece_hash(1), Some([0u8; 20]));
        assert_eq!(info.piece_hash(2), None);

        // Evict piece hashes
        info.evict_piece_hashes();
        assert!(!info.has_piece_hashes());
        assert_eq!(info.piece_hash(0), None);
        assert_eq!(info.piece_hash(1), None);
        // pieces() still works with zero hashes in memory!
        assert_eq!(info.pieces(), 2);

        // Restore piece hashes
        info.restore_piece_hashes(vec![[1u8; 20], [2u8; 20]]);
        assert!(info.has_piece_hashes());
        assert_eq!(info.piece_hash(0), Some([1u8; 20]));
        assert_eq!(info.piece_hash(1), Some([2u8; 20]));

        // Restoring empty hashes must behave like eviction
        info.restore_piece_hashes(vec![]);
        assert!(!info.has_piece_hashes());
        assert_eq!(info.piece_hashes(), None);
    }

    #[test]
    fn test_private_flag_parsing_variants() {
        // 1. private = 1 (Int)
        let mut info1 = base_info_fields();
        info1.insert(b"name".to_vec(), BEncode::String(b"test1".to_vec()));
        info1.insert(b"length".to_vec(), BEncode::Int(100));
        info1.insert(b"pieces".to_vec(), BEncode::String(vec![0u8; 20]));
        info1.insert(b"private".to_vec(), BEncode::Int(1));
        let meta1 = Info::from_bencode(wrap(info1)).unwrap();
        assert!(meta1.private);

        // 2. private = 0 (Int)
        let mut info2 = base_info_fields();
        info2.insert(b"name".to_vec(), BEncode::String(b"test2".to_vec()));
        info2.insert(b"length".to_vec(), BEncode::Int(100));
        info2.insert(b"pieces".to_vec(), BEncode::String(vec![0u8; 20]));
        info2.insert(b"private".to_vec(), BEncode::Int(0));
        let meta2 = Info::from_bencode(wrap(info2)).unwrap();
        assert!(!meta2.private);

        // 3. private = "1" (String)
        let mut info3 = base_info_fields();
        info3.insert(b"name".to_vec(), BEncode::String(b"test3".to_vec()));
        info3.insert(b"length".to_vec(), BEncode::Int(100));
        info3.insert(b"pieces".to_vec(), BEncode::String(vec![0u8; 20]));
        info3.insert(b"private".to_vec(), BEncode::String(b"1".to_vec()));
        let meta3 = Info::from_bencode(wrap(info3)).unwrap();
        assert!(meta3.private);

        // 4. private = "0" (String)
        let mut info4 = base_info_fields();
        info4.insert(b"name".to_vec(), BEncode::String(b"test4".to_vec()));
        info4.insert(b"length".to_vec(), BEncode::Int(100));
        info4.insert(b"pieces".to_vec(), BEncode::String(vec![0u8; 20]));
        info4.insert(b"private".to_vec(), BEncode::String(b"0".to_vec()));
        let meta4 = Info::from_bencode(wrap(info4)).unwrap();
        assert!(!meta4.private);

        // 5. absent private
        let mut info5 = base_info_fields();
        info5.insert(b"name".to_vec(), BEncode::String(b"test5".to_vec()));
        info5.insert(b"length".to_vec(), BEncode::Int(100));
        info5.insert(b"pieces".to_vec(), BEncode::String(vec![0u8; 20]));
        let meta5 = Info::from_bencode(wrap(info5)).unwrap();
        assert!(!meta5.private);
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|b| format!("{b:02x}")).collect()
    }
}
