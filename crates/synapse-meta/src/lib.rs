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
pub use signature::{SignatureStatus, TrustStore};
use synapse_bencode::BEncode;
use url::Url;

pub mod bep18;
pub mod create;
pub mod feed;
pub mod merkle;
pub mod merkle_v1;
pub mod padding;
pub mod signature;
pub mod v2;

pub use bep18::{SearchItem, SearchResponse};
pub use feed::{parse_torrent_feed, FeedItem};
pub use merkle::{
    compute_file_merkle_root, compute_file_piece_layer, hash_block, hash_parent,
    root_from_piece_layer,
};
pub use padding::{is_padding_file, separate_padding_files};
pub use signature::{parse_signatures, TorrentSignature};
pub use v2::{parse_file_tree, V2FileEntry, V2TorrentInfo};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
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
    /// BEP 52 metainfo version (1 = pure v1, 2 = pure v2 or hybrid).
    pub meta_version: u8,
    /// BEP 52 SHA-256 info hash for v2 or hybrid torrents.
    pub info_hash_v2: Option<[u8; 32]>,
    /// BEP 52 piece layers mapping file pieces root -> concatenated 32-byte piece layer hashes.
    pub piece_layers: BTreeMap<[u8; 32], Vec<u8>>,
    /// BEP 52 per-file pieces root (Merkle root) for each file in `files`.
    pub file_roots: Vec<Option<[u8; 32]>>,
    /// The exact info dictionary bytes of a v2 or hybrid torrent. Its identity is the SHA-256 of
    /// these bytes, and a pure-v2 `files` list carries synthesized padding, so the dictionary
    /// cannot be rebuilt from the parsed fields; it is kept and reused when the torrent is
    /// persisted or served over `ut_metadata`.
    pub raw_info: Option<Arc<Vec<u8>>>,
    /// True for a pure-v2 torrent, whose files each start on a piece boundary (with padding
    /// entries synthesized between them). A piece then ends where its file's data ends, so
    /// `piece_len(i)` is shorter than `piece_len` at the end of every file.
    pub v2_aligned: bool,
    /// BEP 53 Select-Only file indices parsed from magnet URIs (`so=` parameter).
    pub select_only: Option<Vec<usize>>,
    /// BEP 35 BitTorrent Digital Signatures parsed from `.torrent` files.
    pub signatures: Vec<TorrentSignature>,
    /// BEP 30 SHA-1 Merkle root for v1 Merkle tree torrents.
    pub root_hash_v1: Option<[u8; 20]>,
    /// BEP 39 `update-url`: where a newer version of this torrent may be found.
    pub update_url: Option<String>,
    /// BEP 39 `originator`: the publisher's DER X.509 certificate.
    pub originator: Option<Vec<u8>>,
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
            meta_version: self.meta_version,
            info_hash_v2: self.info_hash_v2,
            piece_layers: self.piece_layers.clone(),
            file_roots: self.file_roots.clone(),
            raw_info: self.raw_info.clone(),
            v2_aligned: self.v2_aligned,
            select_only: self.select_only.clone(),
            signatures: self.signatures.clone(),
            root_hash_v1: self.root_hash_v1,
            update_url: self.update_url.clone(),
            originator: self.originator.clone(),
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
    #[error("torrent declares too many pieces")]
    TooManyPieces,
    #[error("piece hash count does not match total length / piece length")]
    PieceCountMismatch,
    #[error("torrent file exceeds the maximum accepted size")]
    TooLarge,
    #[error("torrent lists the same file path more than once")]
    DuplicatePath,
    #[error("torrent declares too many files")]
    TooManyFiles,
    #[error("file path has too many components")]
    PathTooDeep,
    #[error("magnet URL must use the magnet:// scheme")]
    InvalidMagnetScheme,
    #[error("magnet URL is malformed")]
    MalformedMagnetUrl,
    #[error("no info hash (xt=urn:btih:...) found in magnet URL")]
    NoMagnetHash,
    #[error("invalid bencoded data")]
    InvalidBEncode,
}

pub type Result<T> = std::result::Result<T, MetaError>;

/// Largest `.torrent` file (or `torrent_base64` payload) accepted from any source. Matches
/// libtorrent's default `load_torrent_limits::max_buffer_size`.
pub const MAX_TORRENT_FILE_BYTES: usize = 10 * 1024 * 1024;

/// Largest accepted `piece length` (matches libtorrent's `max_piece_size`, 128 MiB).
pub const MAX_PIECE_LEN: u64 = 128 * 1024 * 1024;
/// Most pieces a torrent may declare (libtorrent's default `max_pieces`).
pub const MAX_PIECES: u64 = 0x20_0000;
/// Most files a torrent may declare; bounds allocation from a hostile metainfo.
pub const MAX_FILES: usize = 1_000_000;
/// Deepest path (directory levels + file name) accepted for a single file.
pub const MAX_PATH_COMPONENTS: usize = 128;

/// Checks the piece/file layout a metainfo declares is self-consistent and bounded, and
/// returns the validated `(piece_len, total_len)`. `allow_evicted` accepts an empty
/// `pieces` string and is only for records this daemon persisted itself. Every later size computation
/// (`piece_len()`, block offsets, hash lookups) relies on these invariants holding.
/// Most `so=` terms of a magnet link that are looked at.
const MAX_SELECT_TERMS: usize = 1024;

fn validate_layout(
    piece_len: i64,
    hash_count: usize,
    files: &[File],
    allow_evicted: bool,
) -> Result<(u32, u64)> {
    let piece_len = u64::try_from(piece_len)
        .ok()
        .filter(|&p| p > 0 && p <= MAX_PIECE_LEN)
        .ok_or(MetaError::InvalidPieceLength)?;
    if files.len() > MAX_FILES {
        return Err(MetaError::TooManyFiles);
    }
    let mut seen = std::collections::HashSet::with_capacity(files.len());
    if !files.iter().all(|f| seen.insert(&f.path)) {
        return Err(MetaError::DuplicatePath);
    }
    let mut total_len = 0u64;
    for f in files {
        total_len = total_len
            .checked_add(f.length)
            .ok_or(MetaError::InvalidFileLength)?;
    }
    let expected = total_len.div_ceil(piece_len);
    if expected > MAX_PIECES {
        return Err(MetaError::TooManyPieces);
    }
    // A locally persisted record may have had its piece hashes evicted (see
    // `Info::evict_piece_hashes`); untrusted input never gets that exemption.
    let evicted = allow_evicted && hash_count == 0;
    if expected != hash_count as u64 && !evicted {
        return Err(MetaError::PieceCountMismatch);
    }
    Ok((piece_len as u32, total_len))
}

/// Rejects paths that could escape the torrent's download directory: absolute paths
/// (including a Windows-style prefix) and any `.`/`..` component. Bencode path segments
/// are attacker-controlled, so this must run before any segment is joined onto a real
/// filesystem path anywhere downstream.
pub fn path_is_safe(path: &Path) -> bool {
    let mut components = path.components().peekable();
    components.peek().is_some()
        && components.all(|c| match c {
            Component::Normal(seg) => component_is_safe(seg),
            _ => false,
        })
}

/// Longest single path component accepted (the common filesystem limit).
pub const MAX_COMPONENT_BYTES: usize = 255;

/// Rejects components that would be dangerous or confusing to display or create: control
/// characters (including NUL and terminal escape sequences), Unicode bidirectional
/// overrides that let a name masquerade as another (`invoice\u{202E}fdp.exe`), and names
/// longer than any filesystem accepts. Non-UTF-8 components are rejected too.
fn component_is_safe(seg: &std::ffi::OsStr) -> bool {
    let Some(s) = seg.to_str() else {
        return false;
    };
    s.len() <= MAX_COMPONENT_BYTES
        && !s.chars().any(|c| {
            c.is_control()
                || matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        })
}

pub fn bencode_to_string_lossy(b: BEncode) -> Option<String> {
    match b {
        BEncode::String(v) => Some(
            String::from_utf8(v.clone())
                .unwrap_or_else(|_| String::from_utf8_lossy(&v).into_owned()),
        ),
        _ => None,
    }
}

impl File {
    fn from_bencode(data: BEncode) -> Result<File> {
        let mut d = data.into_dict().ok_or(MetaError::InvalidFileDict)?;
        let name_val = d
            .remove(b"name.utf-8".as_ref())
            .or_else(|| d.remove(b"name".as_ref()));
        let path_val = d
            .remove(b"path.utf-8".as_ref())
            .or_else(|| d.remove(b"path".as_ref()));
        let length_val = d
            .remove(b"length".as_ref())
            .or_else(|| d.remove(b"length.utf-8".as_ref()));
        match (name_val, path_val, length_val) {
            (Some(v), None, Some(l)) => {
                let path_str = bencode_to_string_lossy(v).ok_or(MetaError::InvalidFilePath)?;
                let path = PathBuf::from(path_str);
                if !path_is_safe(&path) {
                    return Err(MetaError::UnsafeFilePath);
                }
                Ok(File {
                    path,
                    length: l
                        .into_int()
                        .and_then(|n| u64::try_from(n).ok())
                        .ok_or(MetaError::InvalidFileLength)?,
                })
            }
            (None, Some(path), Some(l)) => {
                let mut p = PathBuf::new();
                let segments = path.into_list().ok_or(MetaError::InvalidFilePath)?;
                if segments.len() > MAX_PATH_COMPONENTS {
                    return Err(MetaError::PathTooDeep);
                }
                for dir in segments {
                    let seg = bencode_to_string_lossy(dir).ok_or(MetaError::InvalidFilePath)?;
                    p.push(seg);
                }
                if !path_is_safe(&p) {
                    return Err(MetaError::UnsafeFilePath);
                }
                Ok(File {
                    path: p,
                    length: l
                        .into_int()
                        .and_then(|n| u64::try_from(n).ok())
                        .ok_or(MetaError::InvalidFileLength)?,
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

/// Inserts BEP 47 style padding entries after every file that does not end on a piece boundary
/// (except when no data follows), giving a pure-v2 torrent the piece-aligned layout BEP 52
/// defines. `file_roots` stays parallel to `files`; padding has no root.
fn align_v2_files(
    files: &mut Vec<File>,
    file_roots: &mut Vec<Option<[u8; 32]>>,
    piece_len: u32,
    name: &str,
) {
    let piece_len = u64::from(piece_len);
    let last_data = files.iter().rposition(|f| f.length > 0);
    let mut out_files = Vec::with_capacity(files.len() * 2);
    let mut out_roots = Vec::with_capacity(files.len() * 2);
    for (i, (f, root)) in files.drain(..).zip(file_roots.drain(..)).enumerate() {
        let pad = (piece_len - f.length % piece_len) % piece_len;
        let needs_pad = f.length > 0 && pad > 0 && last_data.is_some_and(|l| i < l);
        out_files.push(f);
        out_roots.push(root);
        if needs_pad {
            out_files.push(File {
                path: PathBuf::from(name).join(".pad").join(format!("{i}_{pad}")),
                length: pad,
            });
            out_roots.push(None);
        }
    }
    *files = out_files;
    *file_roots = out_roots;
}

/// A hybrid torrent's files (padding included) and each one's Merkle root.
type HybridLayout = (Vec<File>, Vec<Option<[u8; 32]>>);

/// The file list and per-file roots of a hybrid torrent: the v1 `files` list (padding included)
/// with each real file's `pieces root` looked up in the v2 file tree by path.
fn hybrid_layout(
    info: &BTreeMap<Vec<u8>, BEncode>,
    name: &str,
    v2_files: &[v2::V2FileEntry],
) -> Result<HybridLayout> {
    let mut v1 = info.clone();
    v1.insert(b"name".to_vec(), BEncode::String(name.as_bytes().to_vec()));
    let files = parse_bencode_files(v1)?;
    let roots: std::collections::HashMap<&Path, (&v2::V2FileEntry, Option<[u8; 32]>)> = v2_files
        .iter()
        .map(|f| (f.path.as_path(), (f, f.pieces_root)))
        .collect();
    let mut file_roots = Vec::with_capacity(files.len());
    let mut matched = 0usize;
    for f in &files {
        if is_padding_file(&f.path, None) {
            file_roots.push(None);
            continue;
        }
        match roots.get(f.path.as_path()) {
            Some((entry, root)) if entry.length == f.length => {
                if f.length > 0 {
                    matched += 1;
                }
                file_roots.push(*root);
            }
            // A real file that the two views disagree about is a malformed hybrid.
            _ if f.length > 0 => return Err(MetaError::InvalidFileDict),
            _ => file_roots.push(None),
        }
    }
    let real_v2 = v2_files.iter().filter(|f| f.length > 0).count();
    if matched != real_v2 {
        return Err(MetaError::InvalidFileDict);
    }
    Ok((files, file_roots))
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
        self.hashes
            .read()
            .as_ref()
            .and_then(|h| h.get(index as usize).copied())
    }

    /// Looks up the expected BEP 52 SHA-256 Merkle root hash for piece `index` in v2 / hybrid torrents.
    pub fn piece_hash_v2(&self, index: u32) -> Option<[u8; 32]> {
        if self.file_roots.is_empty() || self.files.is_empty() {
            return None;
        }
        let locs = self.block_locations(index, 0, 1);
        let loc = locs.first()?;
        let file_idx = loc.file;
        let file_root = self.file_roots.get(file_idx)?.as_ref()?;
        let file_len = self.files.get(file_idx)?.length;

        if file_len <= u64::from(self.piece_len) {
            Some(*file_root)
        } else {
            let piece_in_file = (loc.file_offset / u64::from(self.piece_len)) as usize;
            let layer = self.piece_layers.get(file_root)?;
            let start = piece_in_file * 32;
            let end = start + 32;
            if end <= layer.len() {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&layer[start..end]);
                Some(hash)
            } else {
                None
            }
        }
    }

    /// Computes the BEP 52 hash of piece `index` from its bytes (`piece_bytes` is the whole
    /// piece as laid out in the torrent, zero padding included). Only the file's real bytes are
    /// hashed: trailing padding is not part of the file, and a short final piece of a file is
    /// zero-padded at the *hash* level to the piece width, not with zero bytes.
    pub fn compute_piece_hash_v2(&self, index: u32, piece_bytes: &[u8]) -> [u8; 32] {
        let (real, file_len) = self.piece_real_extent(index);
        let width = if file_len <= u64::from(self.piece_len) {
            real
        } else {
            self.piece_len as usize
        };
        merkle::compute_piece_hash(&piece_bytes[..real.min(piece_bytes.len())], width)
    }

    /// Bytes of piece `index` that belong to a file (trailing padding excluded).
    pub fn piece_real_len(&self, index: u32) -> usize {
        self.piece_real_extent(index).0
    }

    /// `(real bytes in the piece, length of the file they belong to)`.
    fn piece_real_extent(&self, index: u32) -> (usize, u64) {
        let locs = self.block_locations(index, 0, self.piece_len(index));
        let mut real = 0usize;
        let mut file_len = 0u64;
        for loc in &locs {
            if !is_padding_file(&self.files[loc.file].path, None) {
                real = real.max(loc.piece_range.end);
                file_len = self.files[loc.file].length;
            }
        }
        (real, file_len)
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

    /// Length of piece `index`: `piece_len` for every piece but the last, which holds the
    /// remainder. Never panics, even if `pieces`/`total_len` disagree (a hand-edited or
    /// legacy session record): the last piece then reports the remainder saturated to
    /// `[0, piece_len]` rather than underflowing (release builds abort on panic).
    pub fn piece_len(&self, index: u32) -> u32 {
        let len = if index != self.pieces.saturating_sub(1) {
            self.piece_len
        } else {
            let before = u64::from(self.piece_len) * u64::from(self.pieces.saturating_sub(1));
            self.total_len
                .saturating_sub(before)
                .min(u64::from(self.piece_len)) as u32
        };
        if !self.v2_aligned {
            return len;
        }
        // Pure v2: the piece stops where its file's data does (the padding after it is not
        // part of the piece on the wire).
        let start = u64::from(index) * u64::from(self.piece_len);
        let file = self
            .file_offsets
            .partition_point(|&o| o <= start)
            .saturating_sub(1);
        match (self.file_offsets.get(file), self.files.get(file)) {
            (Some(&offset), Some(f)) => {
                let end = offset + f.length;
                len.min(end.saturating_sub(start).min(u64::from(u32::MAX)) as u32)
            }
            _ => len,
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

    /// Decodes and parses the raw bytes of an untrusted `.torrent` file, rejecting anything
    /// over [`MAX_TORRENT_FILE_BYTES`] before it is decoded.
    pub fn from_torrent_bytes(bytes: &[u8]) -> Result<Info> {
        if bytes.len() > MAX_TORRENT_FILE_BYTES {
            return Err(MetaError::TooLarge);
        }
        let bencode = synapse_bencode::decode_buf(bytes).map_err(|_| MetaError::InvalidInfo)?;
        Self::from_bencode(bencode)
    }

    /// Parses an untrusted metainfo: the piece hash count must match the declared length.
    pub fn from_bencode(data: BEncode) -> Result<Info> {
        Self::parse_bencode(data, false)
    }

    /// Parses a metainfo this daemon persisted to its own session store. Identical to
    /// [`Info::from_bencode`] except that a record saved after piece-hash eviction (empty
    /// `pieces`) is accepted; the caller restores the hashes from elsewhere.
    pub fn from_persisted_bencode(data: BEncode) -> Result<Info> {
        Self::parse_bencode(data, true)
    }

    fn parse_bencode(data: BEncode, allow_evicted: bool) -> Result<Info> {
        let mut d = data.into_dict().ok_or(MetaError::InvalidInfo)?;
        let signatures = parse_signatures(&d);
        let mut i = d
            .remove(b"info".as_ref())
            .and_then(|i| i.into_dict())
            .ok_or(MetaError::InvalidInfo)?;

        let mut info_bytes = Vec::new();
        BEncode::Dict(i.clone())
            .encode(&mut info_bytes)
            .expect("encoding an in-memory BEncode value cannot fail");
        let hash: [u8; 20] = Sha1::digest(&info_bytes).into();

        let mut piece_layers: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
        if let Some(layers_dict) = d
            .remove(b"piece layers".as_ref())
            .and_then(|l| l.into_dict())
        {
            for (k, v) in layers_dict {
                if k.len() == 32 {
                    let mut root = [0u8; 32];
                    root.copy_from_slice(&k);
                    if let Some(hashes_bytes) = v.into_bytes() {
                        piece_layers.insert(root, hashes_bytes);
                    }
                }
            }
        }

        let announce = d
            .remove(b"announce".as_ref())
            .and_then(BEncode::into_string)
            .and_then(|a| Url::parse(&a).ok().map(Arc::new));
        let comment = d
            .remove(b"comment.utf-8".as_ref())
            .or_else(|| d.remove(b"comment".as_ref()))
            .and_then(bencode_to_string_lossy);
        let creator = d
            .remove(b"created by.utf-8".as_ref())
            .or_else(|| d.remove(b"created by".as_ref()))
            .and_then(bencode_to_string_lossy);

        let file_tree_opt = i
            .remove(b"file tree".as_ref())
            .and_then(|ft| ft.into_dict());

        let piece_len = i
            .remove(b"piece length".as_ref())
            .and_then(|i| i.into_int())
            .ok_or(MetaError::InvalidPieceLength)?;

        let root_hash_v1: Option<[u8; 20]> = i
            .remove(b"root hash".as_ref())
            .and_then(|h| h.into_bytes())
            .and_then(|b| {
                if b.len() == 20 {
                    let mut arr = [0u8; 20];
                    arr.copy_from_slice(&b);
                    Some(arr)
                } else {
                    None
                }
            });

        let update_url = i
            .remove(b"update-url".as_ref())
            .and_then(BEncode::into_string)
            .filter(|u| u.len() <= 2048 && (u.starts_with("http://") || u.starts_with("https://")));
        let originator = i
            .remove(b"originator".as_ref())
            .and_then(BEncode::into_bytes)
            .filter(|c| !c.is_empty() && c.len() <= 16 * 1024);

        let hashes_opt: Option<Vec<[u8; 20]>> = i
            .remove(b"pieces".as_ref())
            .and_then(|p| p.into_bytes())
            .and_then(|p| {
                if p.len() % 20 != 0 {
                    return None;
                }
                Some(p.as_chunks::<20>().0.to_vec())
            });

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

        let (
            files,
            file_roots,
            name,
            piece_len,
            total_len,
            pieces,
            hashes,
            info_hash_v2,
            meta_version,
        ) = if let Some(file_tree) = file_tree_opt {
            let mut v2_files = Vec::new();
            let name_str = i
                .remove(b"name.utf-8".as_ref())
                .or_else(|| i.remove(b"name".as_ref()))
                .and_then(bencode_to_string_lossy)
                .unwrap_or_else(|| "torrent".to_string());
            let root_dir = PathBuf::from(&name_str);
            v2::parse_file_tree(&file_tree, root_dir, &mut v2_files)
                .map_err(|_| MetaError::InvalidFileDict)?;
            if v2_files.is_empty() {
                return Err(MetaError::NoFiles);
            }
            for f in &v2_files {
                if !path_is_safe(&f.path) {
                    return Err(MetaError::UnsafeFilePath);
                }
            }
            let mut files: Vec<File> = v2_files
                .iter()
                .map(|f| File {
                    path: f.path.clone(),
                    length: f.length,
                })
                .collect();
            let mut file_roots: Vec<Option<[u8; 32]>> =
                v2_files.iter().map(|f| f.pieces_root).collect();
            let v2_hash: [u8; 32] = sha2::Sha256::digest(&info_bytes).into();

            // A hybrid torrent's v1 `files` list carries the padding that makes v1 pieces line up
            // with the piece-aligned v2 files (BEP 47); the file tree does not. The v1 list is the
            // layout, and the tree supplies each real file's Merkle root.
            if hashes_opt.is_some() && i.contains_key(b"files".as_ref()) {
                let (f, r) = hybrid_layout(&i, &name_str, &v2_files)?;
                files = f;
                file_roots = r;
            }
            let (piece_len, total_len, pieces, hashes) = if let Some(h) = hashes_opt {
                let (plen, tlen) = validate_layout(piece_len, h.len(), &files, allow_evicted)?;
                let count = h.len() as u32;
                (plen, tlen, count, h)
            } else {
                // BEP 52 aligns every file to a piece boundary, so a pure-v2 torrent's piece
                // numbering is per file. Padding entries are synthesized between files so the
                // concatenated layout used everywhere else gives the same numbering.
                let plen32 = u32::try_from(piece_len)
                    .ok()
                    .filter(|&p| p > 0 && u64::from(p) <= MAX_PIECE_LEN)
                    .ok_or(MetaError::InvalidPieceLength)?;
                align_v2_files(&mut files, &mut file_roots, plen32, &name_str);
                let plen = u64::try_from(piece_len)
                    .ok()
                    .filter(|&p| p > 0 && p <= MAX_PIECE_LEN)
                    .ok_or(MetaError::InvalidPieceLength)?;
                let mut tlen = 0u64;
                for f in &files {
                    tlen = tlen
                        .checked_add(f.length)
                        .ok_or(MetaError::InvalidFileLength)?;
                }
                let count = (tlen.div_ceil(plen)) as u32;
                if (count as u64) > MAX_PIECES {
                    return Err(MetaError::TooManyPieces);
                }
                (plen as u32, tlen, count, Vec::new())
            };
            (
                files,
                file_roots,
                name_str,
                piece_len,
                total_len,
                pieces,
                hashes,
                Some(v2_hash),
                2,
            )
        } else if let Some(_root_v1) = root_hash_v1 {
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
            // Same bounds as any v1 layout: the piece count is derived (a Merkle torrent has no
            // `pieces` string), then checked like one, including overflow and duplicate paths.
            let mut total = 0u64;
            for f in &files {
                total = total
                    .checked_add(f.length)
                    .ok_or(MetaError::InvalidFileLength)?;
            }
            let plen = u64::try_from(piece_len)
                .ok()
                .filter(|&p| p > 0 && p <= MAX_PIECE_LEN)
                .ok_or(MetaError::InvalidPieceLength)?;
            let count =
                usize::try_from(total.div_ceil(plen)).map_err(|_| MetaError::TooManyPieces)?;
            let (piece_len_u64, total_len) = validate_layout(piece_len, count, &files, false)?;
            let piece_len_u64 = u64::from(piece_len_u64);
            let pieces = count as u32;
            let file_roots = vec![None; files.len()];
            (
                files,
                file_roots,
                name,
                piece_len_u64 as u32,
                total_len,
                pieces,
                Vec::new(),
                None,
                1,
            )
        } else {
            let hashes = hashes_opt.ok_or(MetaError::InvalidHashes)?;
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
            let (piece_len, total_len) =
                validate_layout(piece_len, hashes.len(), &files, allow_evicted)?;
            let pieces = hashes.len() as u32;
            let file_roots = vec![None; files.len()];
            (
                files, file_roots, name, piece_len, total_len, pieces, hashes, None, 1,
            )
        };
        // A pure v2 torrent is identified by the SHA-256 of its info dict truncated to 20 bytes
        // (BEP 52), in handshakes, tracker announces and the DHT. Only v1 and hybrid torrents
        // are keyed by the SHA-1.
        let has_v1_hashes = !hashes.is_empty();
        let hash = match (meta_version, hashes.is_empty(), info_hash_v2) {
            (2, true, Some(v2)) => {
                let mut truncated = [0u8; 20];
                truncated.copy_from_slice(&v2[..20]);
                truncated
            }
            _ => hash,
        };
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

        let mut info = Info {
            name,
            comment,
            creator,
            announce,
            piece_len,
            total_len,
            pieces,
            hashes: parking_lot::RwLock::new(if hashes.is_empty() {
                None
            } else {
                Some(Arc::new(hashes))
            }),
            hash,
            files,
            private,
            file_offsets,
            url_list,
            web_seeds,
            meta_version,
            info_hash_v2,
            piece_layers,
            file_roots,
            raw_info: (meta_version == 2 || !signatures.is_empty() || root_hash_v1.is_some())
                .then(|| Arc::new(info_bytes.clone())),
            v2_aligned: meta_version == 2 && !has_v1_hashes,
            select_only: None,
            signatures,
            root_hash_v1,
            update_url,
            originator,
        };
        // A record persisted after its piece hashes were evicted cannot be compared.
        if !(allow_evicted && info.pieces > 0 && !info.has_piece_hashes()) {
            info.keep_raw_info_if_lossy(&info_bytes);
        }
        Ok(info)
    }

    /// The info dictionary is re-encoded from the parsed fields when a torrent is persisted or
    /// served over `ut_metadata`. A torrent with keys this crate does not model (`source`,
    /// `x_cross_seed`, `md5sum`, ...) would re-encode to a different dictionary, and so a
    /// different info hash; keep the exact bytes for those.
    fn keep_raw_info_if_lossy(&mut self, info_bytes: &[u8]) {
        if self.raw_info.is_some() {
            return;
        }
        let rebuilt = self.to_info_dict_bytes();
        if Sha1::digest(&rebuilt)[..] != self.hash[..] {
            self.raw_info = Some(Arc::new(info_bytes.to_vec()));
        }
    }

    /// Parses an `Info` directly from the raw bencoded `info` dictionary bytes received
    /// via BEP 9 `ut_metadata`.
    pub fn from_info_dict_bytes(info_bytes: &[u8]) -> Result<Info> {
        let bencode =
            synapse_bencode::decode_buf(info_bytes).map_err(|_| MetaError::InvalidInfo)?;
        let mut i = bencode.into_dict().ok_or(MetaError::InvalidInfo)?;
        let hash: [u8; 20] = Sha1::digest(info_bytes).into();

        let file_tree_opt = i
            .remove(b"file tree".as_ref())
            .and_then(|ft| ft.into_dict());

        let piece_len = i
            .remove(b"piece length".as_ref())
            .and_then(|i| i.into_int())
            .ok_or(MetaError::InvalidPieceLength)?;
        let update_url = i
            .remove(b"update-url".as_ref())
            .and_then(BEncode::into_string)
            .filter(|u| u.len() <= 2048 && (u.starts_with("http://") || u.starts_with("https://")));
        let originator = i
            .remove(b"originator".as_ref())
            .and_then(BEncode::into_bytes)
            .filter(|c| !c.is_empty() && c.len() <= 16 * 1024);

        let hashes_opt: Option<Vec<[u8; 20]>> = i
            .remove(b"pieces".as_ref())
            .and_then(|p| p.into_bytes())
            .and_then(|p| {
                if p.len() % 20 != 0 {
                    return None;
                }
                Some(p.as_chunks::<20>().0.to_vec())
            });

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

        let (
            files,
            file_roots,
            name,
            piece_len,
            total_len,
            pieces,
            hashes,
            info_hash_v2,
            meta_version,
        ) = if let Some(file_tree) = file_tree_opt {
            let mut v2_files = Vec::new();
            let name_str = i
                .remove(b"name.utf-8".as_ref())
                .or_else(|| i.remove(b"name".as_ref()))
                .and_then(bencode_to_string_lossy)
                .unwrap_or_else(|| "torrent".to_string());
            let root_dir = PathBuf::from(&name_str);
            v2::parse_file_tree(&file_tree, root_dir, &mut v2_files)
                .map_err(|_| MetaError::InvalidFileDict)?;
            if v2_files.is_empty() {
                return Err(MetaError::NoFiles);
            }
            for f in &v2_files {
                if !path_is_safe(&f.path) {
                    return Err(MetaError::UnsafeFilePath);
                }
            }
            let mut files: Vec<File> = v2_files
                .iter()
                .map(|f| File {
                    path: f.path.clone(),
                    length: f.length,
                })
                .collect();
            let mut file_roots: Vec<Option<[u8; 32]>> =
                v2_files.iter().map(|f| f.pieces_root).collect();
            let v2_hash: [u8; 32] = sha2::Sha256::digest(info_bytes).into();

            // A hybrid torrent's v1 `files` list carries the padding that makes v1 pieces line up
            // with the piece-aligned v2 files (BEP 47); the file tree does not. The v1 list is the
            // layout, and the tree supplies each real file's Merkle root.
            if hashes_opt.is_some() && i.contains_key(b"files".as_ref()) {
                let (f, r) = hybrid_layout(&i, &name_str, &v2_files)?;
                files = f;
                file_roots = r;
            }
            let (piece_len, total_len, pieces, hashes) = if let Some(h) = hashes_opt {
                let (plen, tlen) = validate_layout(piece_len, h.len(), &files, false)?;
                let count = h.len() as u32;
                (plen, tlen, count, h)
            } else {
                // BEP 52 aligns every file to a piece boundary, so a pure-v2 torrent's piece
                // numbering is per file. Padding entries are synthesized between files so the
                // concatenated layout used everywhere else gives the same numbering.
                let plen32 = u32::try_from(piece_len)
                    .ok()
                    .filter(|&p| p > 0 && u64::from(p) <= MAX_PIECE_LEN)
                    .ok_or(MetaError::InvalidPieceLength)?;
                align_v2_files(&mut files, &mut file_roots, plen32, &name_str);
                let plen = u64::try_from(piece_len)
                    .ok()
                    .filter(|&p| p > 0 && p <= MAX_PIECE_LEN)
                    .ok_or(MetaError::InvalidPieceLength)?;
                let mut tlen = 0u64;
                for f in &files {
                    tlen = tlen
                        .checked_add(f.length)
                        .ok_or(MetaError::InvalidFileLength)?;
                }
                let count = (tlen.div_ceil(plen)) as u32;
                if (count as u64) > MAX_PIECES {
                    return Err(MetaError::TooManyPieces);
                }
                (plen as u32, tlen, count, Vec::new())
            };
            (
                files,
                file_roots,
                name_str,
                piece_len,
                total_len,
                pieces,
                hashes,
                Some(v2_hash),
                2,
            )
        } else {
            let hashes = hashes_opt.ok_or(MetaError::InvalidHashes)?;
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
            let (piece_len, total_len) = validate_layout(piece_len, hashes.len(), &files, false)?;
            let pieces = hashes.len() as u32;
            let file_roots = vec![None; files.len()];
            (
                files, file_roots, name, piece_len, total_len, pieces, hashes, None, 1,
            )
        };

        // A pure v2 torrent is identified by the SHA-256 of its info dict truncated to 20 bytes
        // (BEP 52), in handshakes, tracker announces and the DHT. Only v1 and hybrid torrents
        // are keyed by the SHA-1.
        let has_v1_hashes = !hashes.is_empty();
        let hash = match (meta_version, hashes.is_empty(), info_hash_v2) {
            (2, true, Some(v2)) => {
                let mut truncated = [0u8; 20];
                truncated.copy_from_slice(&v2[..20]);
                truncated
            }
            _ => hash,
        };
        let file_offsets = generate_file_offsets(&files);

        let mut info = Info {
            name,
            comment: None,
            creator: None,
            announce: None,
            piece_len,
            total_len,
            pieces,
            hashes: parking_lot::RwLock::new(if hashes.is_empty() {
                None
            } else {
                Some(Arc::new(hashes))
            }),
            hash,
            files,
            private,
            file_offsets,
            url_list: Vec::new(),
            web_seeds: Vec::new(),
            meta_version,
            info_hash_v2,
            piece_layers: BTreeMap::new(),
            file_roots,
            raw_info: (meta_version == 2).then(|| Arc::new(info_bytes.to_vec())),
            v2_aligned: meta_version == 2 && !has_v1_hashes,
            select_only: None,
            signatures: Vec::new(),
            root_hash_v1: None,
            update_url,
            originator,
        };
        info.keep_raw_info_if_lossy(info_bytes);
        Ok(info)
    }

    /// Serializes this `Info` struct back into a canonical BEncode dictionary.
    pub fn to_bencode(&self) -> BEncode {
        let mut d = BTreeMap::new();
        if let Some(ref a) = self.announce {
            d.insert(
                b"announce".to_vec(),
                BEncode::String(a.to_string().into_bytes()),
            );
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
            d.insert(
                b"created by".to_vec(),
                BEncode::String(cr.clone().into_bytes()),
            );
        }

        let info_dict = self
            .raw_info
            .as_deref()
            .and_then(|raw| synapse_bencode::decode_buf(raw).ok())
            .and_then(BEncode::into_dict)
            .unwrap_or_else(|| self.build_info_dict());
        d.insert(b"info".to_vec(), BEncode::Dict(info_dict));
        if let Some(sigs) = signature::encode_signatures(&self.signatures) {
            d.insert(b"signatures".to_vec(), sigs);
        }
        if !self.piece_layers.is_empty() {
            let layers = self
                .piece_layers
                .iter()
                .map(|(root, hashes)| (root.to_vec(), BEncode::String(hashes.clone())))
                .collect();
            d.insert(b"piece layers".to_vec(), BEncode::Dict(layers));
        }
        BEncode::Dict(d)
    }

    fn build_info_dict(&self) -> BTreeMap<Vec<u8>, BEncode> {
        let mut i = BTreeMap::new();
        i.insert(
            b"name".to_vec(),
            BEncode::String(self.name.clone().into_bytes()),
        );
        i.insert(
            b"piece length".to_vec(),
            BEncode::Int(self.piece_len as i64),
        );

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
            i.insert(
                b"length".to_vec(),
                BEncode::Int(self.files[0].length as i64),
            );
        } else {
            let mut files_list = Vec::new();
            for f in &self.files {
                let mut fd = BTreeMap::new();
                fd.insert(b"length".to_vec(), BEncode::Int(f.length as i64));
                let rel_path = f.path.strip_prefix(&self.name).unwrap_or(&f.path);
                let path_components: Vec<BEncode> = rel_path
                    .iter()
                    .map(|c| BEncode::String(c.to_string_lossy().as_bytes().to_vec()))
                    .collect();
                fd.insert(b"path".to_vec(), BEncode::List(path_components));
                files_list.push(BEncode::Dict(fd));
            }
            i.insert(b"files".to_vec(), BEncode::List(files_list));
        }

        i
    }

    /// Encodes just the inner `info` dictionary -- the bytes a BEP 9 `ut_metadata`
    /// exchange transfers and hashes to produce the info_hash, as opposed to
    /// `to_torrent_bytes()`'s full `.torrent` file (announce/comment/info/...).
    ///
    /// Reconstructs these bytes from the parsed `Info` fields rather than retaining the
    /// original wire bytes, so for a source torrent whose info dict used non-canonical
    /// key ordering or carried extra/unrecognized keys this crate doesn't model, the
    /// re-encoded bytes -- and therefore their SHA-1 -- may not exactly match the
    /// original `info_hash`. A peer we serve metadata to always independently verifies
    /// the hash on their end, so this fails safely (they reject it and try elsewhere)
    /// rather than silently corrupting anything.
    pub fn to_info_dict_bytes(&self) -> Vec<u8> {
        if let Some(raw) = &self.raw_info {
            return raw.as_ref().clone();
        }
        let mut buf = Vec::new();
        BEncode::Dict(self.build_info_dict())
            .encode(&mut buf)
            .expect("in-memory encoding cannot fail");
        buf
    }

    /// Encodes this `Info` struct into raw `.torrent` bencoded bytes.
    pub fn to_torrent_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.to_bencode()
            .encode(&mut buf)
            .expect("in-memory encoding cannot fail");
        buf
    }

    /// Returns true if this is a BEP 52 v2 or hybrid torrent.
    pub fn is_v2(&self) -> bool {
        self.meta_version == 2
    }

    /// Returns true if this is a BEP 52 hybrid torrent (has both v1 piece hashes and v2 Merkle roots).
    pub fn is_hybrid(&self) -> bool {
        self.meta_version == 2 && self.hashes.read().as_ref().is_some_and(|h| !h.is_empty())
    }

    /// Checks every BEP 35 signature against `trust`. Empty when the torrent is unsigned. A
    /// signature can only be checked against the exact `info` bytes, which a locally built
    /// `Info` may not have kept; those report as invalid.
    pub fn verify_signatures(&self, trust: &TrustStore) -> Vec<(String, SignatureStatus)> {
        self.signatures
            .iter()
            .map(|sig| {
                let status = match &self.raw_info {
                    Some(raw) => sig.verify(raw, trust),
                    None => SignatureStatus::Invalid {
                        reason: "the original info dictionary is not available".into(),
                    },
                };
                (sig.name.clone(), status)
            })
            .collect()
    }

    /// Returns true if this is a BEP 30 v1 Merkle tree torrent (has a root hash).
    pub fn is_merkle_v1(&self) -> bool {
        self.root_hash_v1.is_some()
    }

    pub fn from_magnet(data: &str) -> Result<Info> {
        let url = Url::parse(data).map_err(|_| MetaError::MalformedMagnetUrl)?;
        if url.scheme() != "magnet" {
            return Err(MetaError::InvalidMagnetScheme);
        }

        let mut btih_hash: Option<[u8; 20]> = None;
        let mut info_hash_v2: Option<[u8; 32]> = None;

        for (k, v) in url.query_pairs() {
            if k == "xt" {
                if let Some(rest) = v.strip_prefix("urn:btih:") {
                    if let Some(h) = decode_btih(rest) {
                        btih_hash = Some(h);
                    }
                } else if let Some(rest) = v.strip_prefix("urn:btmh:1220") {
                    if let Some(h) = decode_hex_32(rest) {
                        info_hash_v2 = Some(h);
                    }
                }
            }
        }

        let (hash, meta_version) = match (btih_hash, info_hash_v2) {
            (Some(h), Some(_)) => (h, 2),
            (Some(h), None) => (h, 1),
            (None, Some(v2)) => {
                let mut h = [0u8; 20];
                h.copy_from_slice(&v2[..20]);
                (h, 2)
            }
            (None, None) => return Err(MetaError::NoMagnetHash),
        };

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

        // BEP 53. A magnet is untrusted input: bound both the number of terms and the size of
        // the indices they can name, so `so=0-4294967295` cannot allocate without limit.
        let mut select_indices = Vec::new();
        for (k, v) in url.query_pairs() {
            if k != "so" {
                continue;
            }
            for part in v.split(',').take(MAX_SELECT_TERMS) {
                let part = part.trim();
                if let Some((start_str, end_str)) = part.split_once('-') {
                    if let (Ok(start), Ok(end)) =
                        (start_str.parse::<usize>(), end_str.parse::<usize>())
                    {
                        if start <= end && start < MAX_FILES {
                            select_indices.extend(start..=end.min(MAX_FILES - 1));
                        }
                    }
                } else if let Ok(idx) = part.parse::<usize>() {
                    if idx < MAX_FILES {
                        select_indices.push(idx);
                    }
                }
            }
        }
        select_indices.sort_unstable();
        select_indices.dedup();
        let select_only = if select_indices.is_empty() {
            None
        } else {
            Some(select_indices)
        };

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
            meta_version,
            info_hash_v2,
            piece_layers: BTreeMap::new(),
            file_roots: Vec::new(),
            raw_info: None,
            v2_aligned: false,
            select_only,
            signatures: Vec::new(),
            root_hash_v1: None,
            update_url: None,
            originator: None,
        })
    }
}

/// Decodes a BEP 52 64-hex-character SHA-256 multihash into a 32-byte array.
fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() == 64 && s.is_ascii() {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        return Some(out);
    }
    None
}

/// Decodes a BEP9 `xt=urn:btih:` value, which is either 40 hex chars or a base32-encoded
/// 20-byte hash.
fn decode_btih(s: &str) -> Option<[u8; 20]> {
    if s.len() == 40 && s.is_ascii() {
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
        let val = ALPHABET
            .iter()
            .position(|&b| b as char == c.to_ascii_uppercase())?;
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
        assert_eq!(
            Info::from_bencode(wrap(info)).unwrap_err(),
            MetaError::NoFiles
        );
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
            meta_version: 1,
            info_hash_v2: None,
            piece_layers: BTreeMap::new(),
            file_roots: vec![None],
            raw_info: None,
            v2_aligned: false,
            select_only: None,
            signatures: Vec::new(),
            root_hash_v1: None,
            update_url: None,
            originator: None,
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
            meta_version: 1,
            info_hash_v2: None,
            piece_layers: BTreeMap::new(),
            file_roots: vec![None, None],
            raw_info: None,
            v2_aligned: false,
            select_only: None,
            signatures: Vec::new(),
            root_hash_v1: None,
            update_url: None,
            originator: None,
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
        let reconstructed =
            Info::from_bencode(synapse_bencode::decode_buf(&bytes).unwrap()).unwrap();
        assert_eq!(orig.hash, reconstructed.hash);
        assert_eq!(orig.name, reconstructed.name);
        assert_eq!(orig.files, reconstructed.files);
    }

    #[test]
    fn test_piece_hash_eviction_and_restoration() {
        let mut info_fields = base_info_fields();
        info_fields.insert(b"name".to_vec(), BEncode::String(b"test".to_vec()));
        info_fields.insert(b"piece length".to_vec(), BEncode::Int(100));
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

    fn single_file(piece_len: i64, length: i64, hashes: usize) -> BEncode {
        let mut info = base_info_fields();
        info.insert(b"name".to_vec(), BEncode::String(b"t".to_vec()));
        info.insert(b"piece length".to_vec(), BEncode::Int(piece_len));
        info.insert(b"length".to_vec(), BEncode::Int(length));
        info.insert(b"pieces".to_vec(), BEncode::String(vec![0u8; hashes * 20]));
        wrap(info)
    }

    #[test]
    fn layout_accepts_consistent_torrents() {
        assert!(Info::from_bencode(single_file(16_384, 16_384, 1)).is_ok());
        assert!(Info::from_bencode(single_file(16_384, 16_385, 2)).is_ok());
        assert!(Info::from_bencode(single_file(MAX_PIECE_LEN as i64, 1, 1)).is_ok());
    }

    #[test]
    fn layout_rejects_bad_piece_length() {
        for pl in [0, -1, i64::MIN, MAX_PIECE_LEN as i64 + 1, i64::MAX, 1 << 32] {
            assert_eq!(
                Info::from_bencode(single_file(pl, 1, 1)).unwrap_err(),
                MetaError::InvalidPieceLength,
                "piece length {pl}"
            );
        }
    }

    #[test]
    fn layout_rejects_negative_or_overflowing_file_lengths() {
        assert_eq!(
            Info::from_bencode(single_file(16_384, -1, 0)).unwrap_err(),
            MetaError::InvalidFileLength
        );
        // Two files that overflow u64 when summed.
        let mut info = base_info_fields();
        info.insert(b"name".to_vec(), BEncode::String(b"t".to_vec()));
        let mk = |n: &str| {
            BEncode::Dict(dict(vec![
                (b"length", BEncode::Int(i64::MAX)),
                (
                    b"path",
                    BEncode::List(vec![BEncode::String(n.as_bytes().to_vec())]),
                ),
            ]))
        };
        let files: Vec<BEncode> = (0..3).map(|i| mk(&format!("f{i}"))).collect();
        info.insert(b"files".to_vec(), BEncode::List(files));
        // 3 * i64::MAX fits in u64 (~2.8e19 > u64::MAX 1.8e19? no: 2.7e19 > 1.8e19 -> overflow)
        assert_eq!(
            Info::from_bencode(wrap(info)).unwrap_err(),
            MetaError::InvalidFileLength
        );
    }

    #[test]
    fn layout_rejects_hash_count_mismatch() {
        assert_eq!(
            Info::from_bencode(single_file(16_384, 100_000, 1)).unwrap_err(),
            MetaError::PieceCountMismatch
        );
        assert_eq!(
            Info::from_bencode(single_file(16_384, 16_384, 2)).unwrap_err(),
            MetaError::PieceCountMismatch
        );
    }

    #[test]
    fn layout_rejects_too_many_pieces_without_allocating_hashes() {
        // A tiny piece length over a huge file would demand billions of piece slots.
        assert_eq!(
            Info::from_bencode(single_file(1, i64::MAX, 0)).unwrap_err(),
            MetaError::TooManyPieces
        );
    }

    #[test]
    fn layout_rejects_absurdly_deep_paths() {
        let mut info = base_info_fields();
        info.insert(b"name".to_vec(), BEncode::String(b"t".to_vec()));
        let path: Vec<BEncode> = (0..=MAX_PATH_COMPONENTS)
            .map(|_| BEncode::String(b"d".to_vec()))
            .collect();
        let file = dict(vec![
            (b"length", BEncode::Int(1)),
            (b"path", BEncode::List(path)),
        ]);
        info.insert(b"files".to_vec(), BEncode::List(vec![BEncode::Dict(file)]));
        assert_eq!(
            Info::from_bencode(wrap(info)).unwrap_err(),
            MetaError::PathTooDeep
        );
    }

    #[test]
    fn info_dict_bytes_path_applies_the_same_layout_checks() {
        let mut bad = Vec::new();
        if let BEncode::Dict(mut d) = single_file(16_384, 100_000, 1) {
            d.remove(b"info".as_ref())
                .unwrap()
                .encode(&mut bad)
                .unwrap();
        }
        assert_eq!(
            Info::from_info_dict_bytes(&bad).unwrap_err(),
            MetaError::PieceCountMismatch
        );
    }

    #[test]
    fn persisted_records_may_have_evicted_hashes_but_untrusted_input_may_not() {
        assert_eq!(
            Info::from_bencode(single_file(16_384, 32_768, 0)).unwrap_err(),
            MetaError::PieceCountMismatch
        );
        let evicted = Info::from_persisted_bencode(single_file(16_384, 32_768, 0)).unwrap();
        assert_eq!(evicted.pieces(), 0);
        assert_eq!(evicted.total_len, 32_768);
        // A wrong non-zero count is still rejected, and size bounds still apply.
        assert!(Info::from_persisted_bencode(single_file(16_384, 32_768, 1)).is_err());
        assert!(Info::from_persisted_bencode(single_file(0, 32_768, 0)).is_err());
    }

    #[test]
    fn from_torrent_bytes_rejects_oversized_input_before_decoding() {
        let big = vec![b'l'; MAX_TORRENT_FILE_BYTES + 1];
        assert_eq!(
            Info::from_torrent_bytes(&big).unwrap_err(),
            MetaError::TooLarge
        );
    }

    #[test]
    fn path_is_safe_rejects_control_bidi_and_overlong_components() {
        assert!(!path_is_safe(Path::new("a\nb")));
        assert!(!path_is_safe(Path::new("esc\u{1b}[31m")));
        assert!(!path_is_safe(Path::new("invoice\u{202E}fdp.exe")));
        assert!(!path_is_safe(Path::new("dir/\u{2066}x")));
        assert!(!path_is_safe(Path::new(
            &"a".repeat(MAX_COMPONENT_BYTES + 1)
        )));
        assert!(path_is_safe(Path::new(&"a".repeat(MAX_COMPONENT_BYTES))));
        assert!(path_is_safe(Path::new("Ünïcödé/файл 日本語.txt")));
    }

    #[test]
    fn layout_rejects_duplicate_file_paths() {
        let mut info = base_info_fields();
        info.insert(b"name".to_vec(), BEncode::String(b"t".to_vec()));
        info.insert(b"pieces".to_vec(), BEncode::String(vec![0u8; 20]));
        let mk = || {
            BEncode::Dict(dict(vec![
                (b"length", BEncode::Int(1)),
                (
                    b"path",
                    BEncode::List(vec![BEncode::String(b"same".to_vec())]),
                ),
            ]))
        };
        info.insert(b"files".to_vec(), BEncode::List(vec![mk(), mk()]));
        assert_eq!(
            Info::from_bencode(wrap(info)).unwrap_err(),
            MetaError::DuplicatePath
        );
    }

    #[test]
    fn piece_len_never_panics_when_piece_count_disagrees_with_total_length() {
        let mut info = Info::from_bencode(single_file(16_384, 40_000, 3)).unwrap();
        assert_eq!(info.piece_len(2), 40_000 - 2 * 16_384);
        // A persisted record can claim more pieces than the length supports.
        info.pieces = 16;
        assert_eq!(info.piece_len(15), 0);
        assert_eq!(info.piece_len(0), 16_384);
        assert_eq!(info.piece_len(u32::MAX), 16_384);
        info.pieces = 1;
        assert_eq!(info.piece_len(0), 16_384);
        info.pieces = 0;
        assert_eq!(info.piece_len(0), 16_384);
    }

    #[test]
    fn test_v2_torrent_metadata_parsing() {
        let mut leaf = BTreeMap::new();
        leaf.insert(b"length".to_vec(), BEncode::Int(32_768));
        let root_hash = [0x55u8; 32];
        leaf.insert(b"pieces root".to_vec(), BEncode::String(root_hash.to_vec()));

        let mut file_dict = BTreeMap::new();
        file_dict.insert(b"".to_vec(), BEncode::Dict(leaf));

        let mut file_tree = BTreeMap::new();
        file_tree.insert(b"test.bin".to_vec(), BEncode::Dict(file_dict));

        let mut info_dict = BTreeMap::new();
        info_dict.insert(b"meta version".to_vec(), BEncode::Int(2));
        info_dict.insert(b"name".to_vec(), BEncode::String(b"test_v2".to_vec()));
        info_dict.insert(b"piece length".to_vec(), BEncode::Int(16_384));
        info_dict.insert(b"file tree".to_vec(), BEncode::Dict(file_tree));

        let mut top_dict = BTreeMap::new();
        top_dict.insert(b"info".to_vec(), BEncode::Dict(info_dict));

        let parsed = Info::from_bencode(BEncode::Dict(top_dict)).unwrap();
        assert_eq!(parsed.meta_version, 2);
        assert!(parsed.is_v2());
        assert!(!parsed.is_hybrid());
        assert!(parsed.info_hash_v2.is_some());
        assert_eq!(parsed.pieces, 2);
        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.files[0].path, PathBuf::from("test_v2/test.bin"));
        assert_eq!(parsed.files[0].length, 32_768);
        assert_eq!(parsed.file_roots, vec![Some(root_hash)]);
    }

    #[test]
    fn test_bep52_magnet_v2_and_hybrid() {
        // Pure v2 magnet
        let v2_hex = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
        let magnet_v2 = format!("magnet:?xt=urn:btmh:1220{}&dn=test_v2", v2_hex);
        let info = Info::from_magnet(&magnet_v2).unwrap();
        assert_eq!(info.meta_version, 2);
        assert!(info.is_v2());
        assert_eq!(info.info_hash_v2, decode_hex_32(v2_hex));

        // Hybrid magnet with both btih and btmh
        let v1_hex = "0123456789abcdef0123456789abcdef01234567";
        let magnet_hybrid = format!(
            "magnet:?xt=urn:btih:{}&xt=urn:btmh:1220{}&dn=test_hybrid",
            v1_hex, v2_hex
        );
        let hybrid_info = Info::from_magnet(&magnet_hybrid).unwrap();
        assert_eq!(hybrid_info.meta_version, 2);
        assert_eq!(hybrid_info.hash, decode_btih(v1_hex).unwrap());
        assert_eq!(hybrid_info.info_hash_v2, decode_hex_32(v2_hex));
    }

    #[test]
    fn test_piece_hash_v2_lookup() {
        let root_hash = [0x55u8; 32];
        let p0_hash = [0x11u8; 32];
        let p1_hash = [0x22u8; 32];

        let mut leaf = BTreeMap::new();
        leaf.insert(b"length".to_vec(), BEncode::Int(32_768));
        leaf.insert(b"pieces root".to_vec(), BEncode::String(root_hash.to_vec()));

        let mut file_dict = BTreeMap::new();
        file_dict.insert(b"".to_vec(), BEncode::Dict(leaf));

        let mut file_tree = BTreeMap::new();
        file_tree.insert(b"test.bin".to_vec(), BEncode::Dict(file_dict));

        let mut info_dict = BTreeMap::new();
        info_dict.insert(b"meta version".to_vec(), BEncode::Int(2));
        info_dict.insert(b"name".to_vec(), BEncode::String(b"test_v2".to_vec()));
        info_dict.insert(b"piece length".to_vec(), BEncode::Int(16_384));
        info_dict.insert(b"file tree".to_vec(), BEncode::Dict(file_tree));

        let mut layers_dict = BTreeMap::new();
        let mut layers_bytes = Vec::new();
        layers_bytes.extend_from_slice(&p0_hash);
        layers_bytes.extend_from_slice(&p1_hash);
        layers_dict.insert(root_hash.to_vec(), BEncode::String(layers_bytes));

        let mut top_dict = BTreeMap::new();
        top_dict.insert(b"info".to_vec(), BEncode::Dict(info_dict));
        top_dict.insert(b"piece layers".to_vec(), BEncode::Dict(layers_dict));

        let parsed = Info::from_bencode(BEncode::Dict(top_dict)).unwrap();
        assert_eq!(parsed.piece_hash_v2(0), Some(p0_hash));
        assert_eq!(parsed.piece_hash_v2(1), Some(p1_hash));
        assert_eq!(parsed.piece_hash_v2(2), None);
    }

    fn v2_torrent(files: &[(&str, i64)]) -> BEncode {
        let mut tree = BTreeMap::new();
        for (name, len) in files {
            let leaf = BTreeMap::from([
                (b"length".to_vec(), BEncode::Int(*len)),
                (b"pieces root".to_vec(), BEncode::String(vec![0x42; 32])),
            ]);
            tree.insert(
                name.as_bytes().to_vec(),
                BEncode::Dict(BTreeMap::from([(b"".to_vec(), BEncode::Dict(leaf))])),
            );
        }
        let info = BTreeMap::from([
            (b"meta version".to_vec(), BEncode::Int(2)),
            (b"name".to_vec(), BEncode::String(b"t".to_vec())),
            (b"piece length".to_vec(), BEncode::Int(16_384)),
            (b"file tree".to_vec(), BEncode::Dict(tree)),
        ]);
        BEncode::Dict(BTreeMap::from([(b"info".to_vec(), BEncode::Dict(info))]))
    }

    #[test]
    fn multi_file_v2_only_torrents_get_piece_aligned_padding() {
        let info =
            Info::from_bencode(v2_torrent(&[("a", 100_000), ("b", 5), ("c", 20_000)])).unwrap();
        // a = 6.1 pieces -> 7, then padding; b = 1 piece, then padding; c = 2 pieces.
        let names: Vec<_> = info
            .files
            .iter()
            .map(|f| is_padding_file(&f.path, None))
            .collect();
        assert_eq!(names, [false, true, false, true, false]);
        assert_eq!(info.files[1].length, 7 * 16_384 - 100_000);
        assert_eq!(info.file_offsets, [0, 100_000, 114_688, 114_693, 131_072]);
        assert_eq!(info.total_len, 131_072 + 20_000);
        assert_eq!(info.pieces(), 7 + 1 + 2);
        assert_eq!(info.file_roots.len(), info.files.len());
        assert_eq!(info.file_roots[1], None);
        // Piece 7 is exactly file b (plus its padding); piece 8 starts file c.
        let loc = &info.block_locations(7, 0, 16_384)[0];
        assert_eq!((loc.file, loc.file_offset), (2, 0));
        let loc = &info.block_locations(8, 0, 16_384)[0];
        assert_eq!((loc.file, loc.file_offset), (4, 0));
        assert_eq!(info.piece_range_for_file(4), Some((8, 9)));
        // Pieces end where their file's data ends: a's last piece, all of b, c's last piece.
        assert_eq!(info.piece_len(6), 100_000 - 6 * 16_384);
        assert_eq!(info.piece_len(7), 5);
        assert_eq!(info.piece_len(8), 16_384);
        assert_eq!(info.piece_len(9), 20_000 - 16_384);
        assert!(
            info.piece_hash_v2(7).is_some(),
            "b fits in one piece: its root is the piece hash"
        );
        // Zero-length files carry no data and trailing ones need no padding.
        let with_empty = Info::from_bencode(v2_torrent(&[("a", 100_000), ("empty", 0)])).unwrap();
        assert_eq!(with_empty.files.len(), 2);
        assert_eq!(with_empty.total_len, 100_000);
    }

    #[test]
    fn v2_piece_hashes_ignore_padding_and_pad_a_short_last_piece_at_hash_level() {
        // Two real files with real Merkle roots and layers; piece length 32 KiB.
        let piece_len = 32_768usize;
        let a: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect(); // 2 full + 1 short piece
        let b: Vec<u8> = (0..1_000u32).map(|i| (i % 13) as u8).collect(); // fits one piece
        let mut tree = BTreeMap::new();
        let mut layers = BTreeMap::new();
        for (name, data) in [("a", &a), ("b", &b)] {
            let root = merkle::compute_file_merkle_root(data);
            let leaf = BTreeMap::from([
                (b"length".to_vec(), BEncode::Int(data.len() as i64)),
                (b"pieces root".to_vec(), BEncode::String(root.to_vec())),
            ]);
            if data.len() > piece_len {
                let layer: Vec<u8> = merkle::compute_file_piece_layer(data, piece_len).concat();
                layers.insert(root.to_vec(), BEncode::String(layer));
            }
            tree.insert(
                name.as_bytes().to_vec(),
                BEncode::Dict(BTreeMap::from([(b"".to_vec(), BEncode::Dict(leaf))])),
            );
        }
        let info = BTreeMap::from([
            (b"meta version".to_vec(), BEncode::Int(2)),
            (b"name".to_vec(), BEncode::String(b"t".to_vec())),
            (b"piece length".to_vec(), BEncode::Int(piece_len as i64)),
            (b"file tree".to_vec(), BEncode::Dict(tree)),
        ]);
        let torrent = BEncode::Dict(BTreeMap::from([
            (b"info".to_vec(), BEncode::Dict(info)),
            (b"piece layers".to_vec(), BEncode::Dict(layers)),
        ]));
        let info = Info::from_bencode(torrent).unwrap();
        assert_eq!(info.pieces(), 3 + 1);

        // Reassemble each piece exactly as the engine does (padding as zero bytes) and check the
        // computed hash equals the one the torrent declares.
        let payload = |idx: u32| -> Vec<u8> {
            let mut buf = vec![0u8; info.piece_len(idx) as usize];
            for loc in info.block_locations(idx, 0, info.piece_len(idx)) {
                let data = match loc.file {
                    0 => &a,
                    2 => &b,
                    _ => continue, // padding
                };
                let start = loc.file_offset as usize;
                buf[loc.piece_range.clone()]
                    .copy_from_slice(&data[start..start + loc.piece_range.len()]);
            }
            buf
        };
        for idx in 0..info.pieces() {
            assert_eq!(
                Some(info.compute_piece_hash_v2(idx, &payload(idx))),
                info.piece_hash_v2(idx),
                "piece {idx}"
            );
        }
    }

    #[test]
    fn a_v2_torrent_round_trips_through_its_persisted_form() {
        let torrent = v2_torrent(&[("a", 100_000)]);
        let info = Info::from_bencode(torrent).unwrap();
        let bytes = info.to_torrent_bytes();
        let back = Info::from_persisted_bencode(synapse_bencode::decode_buf(&bytes).unwrap())
            .expect("a persisted v2 torrent must load again");
        assert_eq!(back.hash, info.hash);
        assert_eq!(back.info_hash_v2, info.info_hash_v2);
        assert_eq!(back.file_roots, info.file_roots);
        assert_eq!(back.to_info_dict_bytes(), info.to_info_dict_bytes());
        assert_eq!(back.files.len(), info.files.len());
    }

    #[test]
    fn a_pure_v2_torrent_is_identified_by_its_truncated_sha256() {
        use sha2::{Digest as _, Sha256};
        let torrent = v2_torrent(&[("a", 100_000)]);
        let info = Info::from_bencode(torrent.clone()).unwrap();
        let v2 = info.info_hash_v2.expect("v2 hash");
        assert_eq!(
            &info.hash[..],
            &v2[..20],
            "pure v2 must use the truncated SHA-256"
        );

        // The same holds when the info dict arrives over ut_metadata.
        let mut info_bytes = Vec::new();
        if let BEncode::Dict(d) = &torrent {
            d[b"info".as_ref()].encode(&mut info_bytes).unwrap();
        }
        let via_metadata = Info::from_info_dict_bytes(&info_bytes).unwrap();
        assert_eq!(via_metadata.hash, info.hash);
        assert_eq!(
            via_metadata.info_hash_v2,
            Some(Sha256::digest(&info_bytes).into())
        );
    }

    #[test]
    fn test_bep53_magnet_select_only() {
        let uri =
            "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=test&so=0,2,4-6&so=8";
        let info = Info::from_magnet(uri).unwrap();
        assert_eq!(info.select_only, Some(vec![0, 2, 4, 5, 6, 8]));

        let uri_no_so = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=test";
        let info2 = Info::from_magnet(uri_no_so).unwrap();
        assert_eq!(info2.select_only, None);
    }

    #[test]
    fn test_bep30_merkle_v1_parsing() {
        let mut info_dict = BTreeMap::new();
        info_dict.insert(
            b"name".to_vec(),
            BEncode::String(b"merkle_file.iso".to_vec()),
        );
        info_dict.insert(b"length".to_vec(), BEncode::Int(65536));
        info_dict.insert(b"piece length".to_vec(), BEncode::Int(16384));
        info_dict.insert(b"root hash".to_vec(), BEncode::String(vec![0x77; 20]));

        let mut root = BTreeMap::new();
        root.insert(b"info".to_vec(), BEncode::Dict(info_dict));

        let info = Info::from_bencode(BEncode::Dict(root)).unwrap();
        assert!(info.is_merkle_v1());
        assert_eq!(info.root_hash_v1, Some([0x77; 20]));
        assert_eq!(info.pieces, 4);
        assert_eq!(info.total_len, 65536);
    }

    #[test]
    fn test_bep35_signature_parsing_in_torrent() {
        let mut info_dict = BTreeMap::new();
        info_dict.insert(b"name".to_vec(), BEncode::String(b"signed.bin".to_vec()));
        info_dict.insert(b"length".to_vec(), BEncode::Int(100));
        info_dict.insert(b"piece length".to_vec(), BEncode::Int(100));
        info_dict.insert(b"pieces".to_vec(), BEncode::String(vec![0x11; 20]));

        let sig_dict = BTreeMap::from([
            (b"signature".to_vec(), BEncode::String(vec![0xAA; 256])),
            (b"certificate".to_vec(), BEncode::String(vec![0xBB; 32])),
        ]);
        let signatures =
            BTreeMap::from([(b"com.example.signer".to_vec(), BEncode::Dict(sig_dict))]);

        let mut root = BTreeMap::new();
        root.insert(b"info".to_vec(), BEncode::Dict(info_dict));
        root.insert(b"signatures".to_vec(), BEncode::Dict(signatures));

        let info = Info::from_bencode(BEncode::Dict(root)).unwrap();
        assert_eq!(info.signatures.len(), 1);
        assert_eq!(info.signatures[0].name, "com.example.signer");
        assert_eq!(info.signatures[0].signature, vec![0xAA; 256]);
        // The exact info bytes are kept so the signature can be checked, and the signatures
        // survive being persisted and loaded again.
        assert!(info.raw_info.is_some());
        let back = Info::from_persisted_bencode(
            synapse_bencode::decode_buf(&info.to_torrent_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(back.signatures, info.signatures);
        assert_eq!(back.hash, info.hash);
        // Junk signature bytes never verify as trusted.
        let statuses = info.verify_signatures(&TrustStore::new());
        assert_eq!(statuses.len(), 1);
        assert!(!statuses[0].1.is_trusted());
    }

    #[test]
    fn multibyte_hashes_in_a_magnet_are_rejected_not_a_panic() {
        // 40 and 64 *bytes* long, but not ASCII: slicing them in pairs used to split a character.
        let btih = "é".repeat(20);
        assert_eq!(btih.len(), 40);
        let magnet = format!("magnet:?xt=urn:btih:{btih}");
        assert_eq!(
            Info::from_magnet(&magnet).unwrap_err(),
            MetaError::NoMagnetHash
        );
        let btmh = "é".repeat(32);
        let magnet = format!(
            "magnet:?xt=urn:btmh:1220{btmh}&xt=urn:btih:{}",
            "a".repeat(40)
        );
        assert!(
            Info::from_magnet(&magnet).is_ok(),
            "the bad btmh is ignored"
        );
    }

    #[test]
    fn a_torrent_with_extra_info_keys_keeps_its_identity_when_persisted() {
        // Private trackers add keys like `source`; cross-seed tools add `x_cross_seed`.
        let mut info_dict = BTreeMap::new();
        info_dict.insert(b"name".to_vec(), BEncode::String(b"x.bin".to_vec()));
        info_dict.insert(b"length".to_vec(), BEncode::Int(100));
        info_dict.insert(b"piece length".to_vec(), BEncode::Int(100));
        info_dict.insert(b"pieces".to_vec(), BEncode::String(vec![0x11; 20]));
        info_dict.insert(b"source".to_vec(), BEncode::String(b"TRACKER".to_vec()));
        info_dict.insert(b"x_cross_seed".to_vec(), BEncode::String(b"abc".to_vec()));
        info_dict.insert(b"private".to_vec(), BEncode::Int(1));
        let root = BTreeMap::from([(b"info".to_vec(), BEncode::Dict(info_dict))]);
        let info = Info::from_bencode(BEncode::Dict(root)).unwrap();
        let back = Info::from_persisted_bencode(
            synapse_bencode::decode_buf(&info.to_torrent_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            back.hash, info.hash,
            "the info hash must survive persistence"
        );
        assert_eq!(back.to_info_dict_bytes(), info.to_info_dict_bytes());
    }
}
