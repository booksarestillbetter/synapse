//! Creating `.torrent` files from a file or directory: BitTorrent v1, v2, or hybrid.
//!
//! Files are read as streams (one block at a time), so the size of the content is not limited by
//! memory. Symbolic links and anything that is not a regular file or directory are skipped, files
//! are ordered by path so the same content always gives the same torrent, and hybrid torrents
//! are padded per BEP 47 so v1 and v2 agree on piece boundaries.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha1::{Digest as _, Sha1};
use synapse_bencode::BEncode;

use crate::merkle::{hash_block, root_and_piece_layer, BLOCK_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TorrentVersion {
    #[default]
    V1,
    V2,
    Hybrid,
}

#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    /// Bytes per piece; a power of two of at least 16 KiB. `None` picks one for the size.
    pub piece_length: Option<u32>,
    /// Announce URLs, one inner list per tier.
    pub trackers: Vec<Vec<String>>,
    pub web_seeds: Vec<String>,
    pub comment: Option<String>,
    pub created_by: Option<String>,
    pub private: bool,
    /// The `source` tag some private trackers require.
    pub source: Option<String>,
    /// Overrides the torrent's name (default: the file or directory name).
    pub name: Option<String>,
    pub version: TorrentVersion,
    /// Seconds since the epoch for `creation date`; `None` leaves it out.
    pub creation_date: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("{0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("nothing to put in the torrent (no regular files)")]
    Empty,
    #[error("piece length must be a power of two of at least 16 KiB")]
    BadPieceLength,
    #[error("a file name is not valid UTF-8: {0}")]
    BadName(PathBuf),
}

struct SourceFile {
    /// Path components relative to the torrent's root.
    components: Vec<String>,
    path: PathBuf,
    length: u64,
}

/// The piece length to use for `total` bytes: pieces of about 1000-2000, between 32 KiB and 16 MiB.
pub fn auto_piece_length(total: u64) -> u32 {
    let mut len = 32 * 1024u64;
    while len < 16 * 1024 * 1024 && total / len > 2000 {
        len *= 2;
    }
    len as u32
}

fn collect_files(root: &Path) -> Result<(String, bool, Vec<SourceFile>), CreateError> {
    let io = |p: &Path, e| CreateError::Io(p.to_path_buf(), e);
    let meta = std::fs::symlink_metadata(root).map_err(|e| io(root, e))?;
    let name = root
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| CreateError::BadName(root.to_path_buf()))?
        .to_string();
    if meta.is_file() {
        return Ok((
            name.clone(),
            false,
            vec![SourceFile {
                components: vec![name],
                path: root.to_path_buf(),
                length: meta.len(),
            }],
        ));
    }
    let mut files = Vec::new();
    let mut stack = vec![(root.to_path_buf(), Vec::<String>::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| io(&dir, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io(&dir, e))?;
            let file_type = entry.file_type().map_err(|e| io(&dir, e))?;
            let file_name = entry
                .file_name()
                .into_string()
                .map_err(|_| CreateError::BadName(entry.path()))?;
            let mut components = prefix.clone();
            components.push(file_name);
            if file_type.is_dir() {
                stack.push((entry.path(), components));
            } else if file_type.is_file() {
                let length = entry.metadata().map_err(|e| io(&entry.path(), e))?.len();
                files.push(SourceFile {
                    components,
                    path: entry.path(),
                    length,
                });
            }
        }
    }
    files.sort_by(|a, b| a.components.cmp(&b.components));
    Ok((name, true, files))
}

/// Streams a file in 16 KiB blocks, calling `on_block` for each.
fn for_each_block(path: &Path, mut on_block: impl FnMut(&[u8])) -> Result<(), CreateError> {
    let mut file = std::fs::File::open(path).map_err(|e| CreateError::Io(path.to_path_buf(), e))?;
    let mut buf = vec![0u8; BLOCK_SIZE];
    loop {
        let mut filled = 0;
        while filled < BLOCK_SIZE {
            let n = file
                .read(&mut buf[filled..])
                .map_err(|e| CreateError::Io(path.to_path_buf(), e))?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            return Ok(());
        }
        on_block(&buf[..filled]);
        if filled < BLOCK_SIZE {
            return Ok(());
        }
    }
}

/// Feeds a byte stream into SHA-1 pieces of `piece_len`.
struct PieceHasher {
    piece_len: usize,
    hasher: Sha1,
    filled: usize,
    pieces: Vec<u8>,
}

impl PieceHasher {
    fn new(piece_len: usize) -> Self {
        Self {
            piece_len,
            hasher: Sha1::new(),
            filled: 0,
            pieces: Vec::new(),
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (self.piece_len - self.filled).min(data.len());
            self.hasher.update(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled == self.piece_len {
                self.finish_piece();
            }
        }
    }

    fn finish_piece(&mut self) {
        let done = std::mem::replace(&mut self.hasher, Sha1::new());
        self.pieces.extend_from_slice(&done.finalize());
        self.filled = 0;
    }

    /// Zero bytes up to the next piece boundary (BEP 47 padding).
    fn pad_to_boundary(&mut self) -> u64 {
        if self.filled == 0 {
            return 0;
        }
        let pad = self.piece_len - self.filled;
        let zeros = vec![0u8; pad.min(1 << 20)];
        let mut left = pad;
        while left > 0 {
            let n = left.min(zeros.len());
            self.update(&zeros[..n]);
            left -= n;
        }
        pad as u64
    }

    fn finish(mut self) -> Vec<u8> {
        if self.filled > 0 {
            self.finish_piece();
        }
        self.pieces
    }
}

fn string(s: &str) -> BEncode {
    BEncode::String(s.as_bytes().to_vec())
}

fn path_list(components: &[String]) -> BEncode {
    BEncode::List(components.iter().map(|c| string(c)).collect())
}

/// Builds the bencoded `.torrent` for `path`. `progress` is called with (bytes hashed, total).
pub fn create_torrent(
    path: &Path,
    opts: &CreateOptions,
    mut progress: impl FnMut(u64, u64),
) -> Result<Vec<u8>, CreateError> {
    let (root_name, is_dir, files) = collect_files(path)?;
    if files.is_empty()
        || (files.iter().all(|f| f.length == 0) && opts.version != TorrentVersion::V1)
    {
        return Err(CreateError::Empty);
    }
    let total: u64 = files.iter().map(|f| f.length).sum();
    let piece_len = opts
        .piece_length
        .unwrap_or_else(|| auto_piece_length(total));
    if !piece_len.is_power_of_two() || (piece_len as usize) < BLOCK_SIZE {
        return Err(CreateError::BadPieceLength);
    }
    let plen = piece_len as usize;
    let name = opts.name.clone().unwrap_or(root_name);
    let want_v1 = opts.version != TorrentVersion::V2;
    let want_v2 = opts.version != TorrentVersion::V1;
    let hybrid = opts.version == TorrentVersion::Hybrid;

    let mut v1 = PieceHasher::new(plen);
    let mut v1_files: Vec<BEncode> = Vec::new();
    let mut tree: BTreeMap<Vec<u8>, BEncode> = BTreeMap::new();
    let mut layers: BTreeMap<Vec<u8>, BEncode> = BTreeMap::new();
    let mut done = 0u64;

    for (idx, file) in files.iter().enumerate() {
        let mut leaves: Vec<[u8; 32]> = Vec::new();
        for_each_block(&file.path, |block| {
            if want_v1 {
                v1.update(block);
            }
            if want_v2 {
                leaves.push(hash_block(block));
            }
            done += block.len() as u64;
        })?;
        progress(done, total);

        if want_v1 {
            let mut d = BTreeMap::new();
            d.insert(b"length".to_vec(), BEncode::Int(file.length as i64));
            d.insert(b"path".to_vec(), path_list(&file.components));
            v1_files.push(BEncode::Dict(d));
            // Hybrid torrents pad each file out to a piece boundary so that v1 pieces never
            // straddle files (BEP 47), except after the last one.
            if hybrid && idx + 1 < files.len() && file.length % piece_len as u64 != 0 {
                let pad = v1.pad_to_boundary();
                if pad > 0 {
                    let mut p = BTreeMap::new();
                    p.insert(b"attr".to_vec(), string("p"));
                    p.insert(b"length".to_vec(), BEncode::Int(pad as i64));
                    p.insert(
                        b"path".to_vec(),
                        path_list(&[".pad".to_string(), pad.to_string()]),
                    );
                    v1_files.push(BEncode::Dict(p));
                }
            }
        }
        if want_v2 {
            let mut leaf = BTreeMap::new();
            leaf.insert(b"length".to_vec(), BEncode::Int(file.length as i64));
            if file.length > 0 {
                let (root, layer) = root_and_piece_layer(&leaves, plen);
                leaf.insert(b"pieces root".to_vec(), BEncode::String(root.to_vec()));
                if !layer.is_empty() {
                    layers.insert(root.to_vec(), BEncode::String(layer.concat()));
                }
            }
            // Insert into the nested file tree, one directory per path component.
            let mut node = &mut tree;
            let (last, dirs) = file.components.split_last().expect("a file has a name");
            for dir in dirs {
                let entry = node
                    .entry(dir.as_bytes().to_vec())
                    .or_insert_with(|| BEncode::Dict(BTreeMap::new()));
                let BEncode::Dict(d) = entry else {
                    unreachable!("directories are dictionaries")
                };
                node = d;
            }
            node.insert(
                last.as_bytes().to_vec(),
                BEncode::Dict(BTreeMap::from([(b"".to_vec(), BEncode::Dict(leaf))])),
            );
        }
    }

    let mut info = BTreeMap::new();
    info.insert(b"name".to_vec(), string(&name));
    info.insert(b"piece length".to_vec(), BEncode::Int(i64::from(piece_len)));
    if want_v1 {
        info.insert(b"pieces".to_vec(), BEncode::String(v1.finish()));
        if is_dir {
            info.insert(b"files".to_vec(), BEncode::List(v1_files));
        } else {
            info.insert(b"length".to_vec(), BEncode::Int(total as i64));
        }
    }
    if want_v2 {
        info.insert(b"meta version".to_vec(), BEncode::Int(2));
        info.insert(b"file tree".to_vec(), BEncode::Dict(tree));
    }
    if opts.private {
        info.insert(b"private".to_vec(), BEncode::Int(1));
    }
    if let Some(source) = &opts.source {
        info.insert(b"source".to_vec(), string(source));
    }

    let mut top = BTreeMap::new();
    top.insert(b"info".to_vec(), BEncode::Dict(info));
    let tiers: Vec<&Vec<String>> = opts.trackers.iter().filter(|t| !t.is_empty()).collect();
    if let Some(first) = tiers.first().and_then(|t| t.first()) {
        top.insert(b"announce".to_vec(), string(first));
    }
    if tiers.len() > 1 || tiers.first().is_some_and(|t| t.len() > 1) {
        top.insert(
            b"announce-list".to_vec(),
            BEncode::List(
                tiers
                    .iter()
                    .map(|t| BEncode::List(t.iter().map(|u| string(u)).collect()))
                    .collect(),
            ),
        );
    }
    if !opts.web_seeds.is_empty() {
        top.insert(
            b"url-list".to_vec(),
            BEncode::List(opts.web_seeds.iter().map(|u| string(u)).collect()),
        );
    }
    if let Some(c) = &opts.comment {
        top.insert(b"comment".to_vec(), string(c));
    }
    if let Some(c) = &opts.created_by {
        top.insert(b"created by".to_vec(), string(c));
    }
    if let Some(d) = opts.creation_date {
        top.insert(b"creation date".to_vec(), BEncode::Int(d));
    }
    if want_v2 && !layers.is_empty() {
        top.insert(b"piece layers".to_vec(), BEncode::Dict(layers));
    }
    let mut out = Vec::new();
    BEncode::Dict(top)
        .encode(&mut out)
        .expect("in-memory encoding cannot fail");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Info;

    fn payload(len: usize, salt: u8) -> Vec<u8> {
        (0..len)
            .map(|i| ((i * 31 + usize::from(salt)) % 253) as u8)
            .collect()
    }

    fn make_tree(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let files = vec![
            ("a.bin".to_string(), payload(40_000, 1)),
            ("sub/b.bin".to_string(), payload(5, 2)),
            ("sub/deeper/c.bin".to_string(), payload(70_000, 3)),
            ("z_empty".to_string(), Vec::new()),
        ];
        for (name, data) in &files {
            let p = dir.join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, data).unwrap();
        }
        files
    }

    fn opts(version: TorrentVersion) -> CreateOptions {
        CreateOptions {
            piece_length: Some(32768),
            version,
            trackers: vec![
                vec![
                    "http://t1.example/announce".into(),
                    "http://t1b.example/announce".into(),
                ],
                vec!["udp://t2.example:80".into()],
            ],
            web_seeds: vec!["https://mirror.example/data/".into()],
            comment: Some("hello".into()),
            created_by: Some("synapse-test".into()),
            creation_date: Some(1_700_000_000),
            ..Default::default()
        }
    }

    #[test]
    fn a_v1_torrent_has_hashes_that_match_the_data_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("payload");
        let files = make_tree(&root);
        let bytes = create_torrent(&root, &opts(TorrentVersion::V1), |_, _| {}).unwrap();
        let info = Info::from_torrent_bytes(&bytes).unwrap();
        assert_eq!(info.name, "payload");
        assert_eq!(info.files.len(), 4);
        assert_eq!(info.total_len, 110_005);
        assert_eq!(
            info.announce.as_deref().map(|u| u.as_str()),
            Some("http://t1.example/announce")
        );
        assert_eq!(info.url_list.len(), 2);
        assert_eq!(info.web_seeds.len(), 1);
        // Every piece hash equals the SHA-1 of the concatenated data (files in path order).
        let mut ordered = files.clone();
        ordered.sort_by(|a, b| {
            a.0.split('/')
                .collect::<Vec<_>>()
                .cmp(&b.0.split('/').collect::<Vec<_>>())
        });
        let stream: Vec<u8> = ordered.iter().flat_map(|(_, d)| d.clone()).collect();
        for (i, chunk) in stream.chunks(32768).enumerate() {
            let expected: [u8; 20] = Sha1::digest(chunk).into();
            assert_eq!(info.piece_hash(i as u32), Some(expected), "piece {i}");
        }
        assert_eq!(info.pieces() as usize, stream.len().div_ceil(32768));
        // Same content, same torrent.
        assert_eq!(
            bytes,
            create_torrent(&root, &opts(TorrentVersion::V1), |_, _| {}).unwrap()
        );
    }

    #[test]
    fn a_v2_torrent_verifies_every_piece_against_its_layers() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("payload");
        let files = make_tree(&root);
        let bytes = create_torrent(&root, &opts(TorrentVersion::V2), |_, _| {}).unwrap();
        let info = Info::from_torrent_bytes(&bytes).unwrap();
        assert!(info.is_v2() && !info.is_hybrid());
        // Reassemble each piece the way a downloader does and check it against the metainfo.
        let mut checked = 0;
        for idx in 0..info.pieces() {
            let mut buf = vec![0u8; info.piece_len(idx) as usize];
            for loc in info.block_locations(idx, 0, info.piece_len(idx)) {
                let rel = info.files[loc.file]
                    .path
                    .strip_prefix("payload")
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if let Some((_, data)) = files.iter().find(|(n, _)| *n == rel) {
                    let start = loc.file_offset as usize;
                    buf[loc.piece_range.clone()]
                        .copy_from_slice(&data[start..start + loc.piece_range.len()]);
                }
            }
            assert_eq!(
                Some(info.compute_piece_hash_v2(idx, &buf)),
                info.piece_hash_v2(idx),
                "piece {idx}"
            );
            checked += 1;
        }
        assert!(checked >= 4);
    }

    #[test]
    fn a_hybrid_torrent_is_consistent_between_v1_and_v2() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("single.bin");
        let data = payload(100_000, 9);
        std::fs::write(&file, &data).unwrap();
        let bytes = create_torrent(&file, &opts(TorrentVersion::Hybrid), |_, _| {}).unwrap();
        let info = Info::from_torrent_bytes(&bytes).unwrap();
        assert!(info.is_hybrid());
        assert_eq!(info.name, "single.bin");
        for (i, chunk) in data.chunks(32768).enumerate() {
            let sha1: [u8; 20] = Sha1::digest(chunk).into();
            assert_eq!(info.piece_hash(i as u32), Some(sha1));
            assert_eq!(
                info.compute_piece_hash_v2(i as u32, chunk),
                info.piece_hash_v2(i as u32).unwrap()
            );
        }
        // A multi-file hybrid pads between files so no v1 piece straddles two files.
        let root = dir.path().join("multi");
        make_tree(&root);
        let multi = Info::from_torrent_bytes(
            &create_torrent(&root, &opts(TorrentVersion::Hybrid), |_, _| {}).unwrap(),
        )
        .unwrap();
        assert!(multi.is_hybrid());
        assert!(multi
            .files
            .iter()
            .any(|f| crate::is_padding_file(&f.path, None)));
        let real_offsets: Vec<u64> = multi
            .files
            .iter()
            .zip(&multi.file_offsets)
            .filter(|(f, _)| !crate::is_padding_file(&f.path, None) && f.length > 0)
            .map(|(_, o)| *o)
            .collect();
        assert!(
            real_offsets.iter().all(|o| o % 32768 == 0),
            "files start on piece boundaries: {real_offsets:?}"
        );
    }

    #[test]
    fn options_are_validated_and_special_files_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("p");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/hosts", root.join("link")).unwrap();
        let mut o = CreateOptions {
            piece_length: Some(1000),
            ..Default::default()
        };
        assert!(matches!(
            create_torrent(&root, &o, |_, _| {}),
            Err(CreateError::BadPieceLength)
        ));
        o.piece_length = None;
        o.private = true;
        o.source = Some("SRC".into());
        let info =
            Info::from_torrent_bytes(&create_torrent(&root, &o, |_, _| {}).unwrap()).unwrap();
        assert!(info.private);
        assert_eq!(info.files.len(), 1, "the symlink is not followed");
        let empty = dir.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        assert!(matches!(
            create_torrent(&empty, &CreateOptions::default(), |_, _| {}),
            Err(CreateError::Empty)
        ));
        assert!(create_torrent(
            &dir.path().join("missing"),
            &CreateOptions::default(),
            |_, _| {}
        )
        .is_err());
        assert_eq!(auto_piece_length(1), 32 * 1024);
        assert_eq!(auto_piece_length(10 * 1024 * 1024 * 1024), 8 * 1024 * 1024);
        assert_eq!(auto_piece_length(u64::MAX), 16 * 1024 * 1024);
    }
}
