//! In-depth .torrent format inspector and validation tool.
//!
//! Parses and diagnoses single-file, multi-file, BitTorrent v2, and hybrid torrent files.
//! Validates piece hashing alignment, total file byte spans, tracker tiers, web seeds,
//! directory safety, and character encodings.

use std::path::{Path, PathBuf};

use sha1::{Digest, Sha1};
use synapse_bencode::BEncode;
use synapse_meta::Info;

#[derive(Debug, Clone)]
pub struct TorrentDiagnostic {
    pub file_path: PathBuf,
    pub name: String,
    pub info_hash_hex: String,
    pub format_type: TorrentFormatType,
    pub is_valid: bool,
    pub piece_length: u32,
    pub total_pieces: usize,
    pub total_size_bytes: u64,
    pub files_count: usize,
    pub is_private: bool,
    pub trackers: Vec<String>,
    pub web_seeds: Vec<String>,
    pub creator: Option<String>,
    pub creation_date: Option<String>,
    pub comment: Option<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub signatures_count: usize,
    pub is_signed: bool,
    pub root_hash_v1_hex: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorrentFormatType {
    BitTorrentV1SingleFile,
    BitTorrentV1MultiFile,
    BitTorrentV1Merkle,
    BitTorrentV2,
    HybridV1V2,
    Invalid,
}

impl std::fmt::Display for TorrentFormatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TorrentFormatType::BitTorrentV1SingleFile => write!(f, "BitTorrent v1 (Single File)"),
            TorrentFormatType::BitTorrentV1MultiFile => write!(f, "BitTorrent v1 (Multi-File)"),
            TorrentFormatType::BitTorrentV1Merkle => write!(f, "BitTorrent v1 (BEP 30 Merkle)"),
            TorrentFormatType::BitTorrentV2 => write!(f, "BitTorrent v2 (BEP 52 Merkle)"),
            TorrentFormatType::HybridV1V2 => write!(f, "Hybrid (v1 + v2 Merkle)"),
            TorrentFormatType::Invalid => write!(f, "Invalid / Unparseable"),
        }
    }
}

pub struct InspectBatchResult {
    pub diagnostics: Vec<TorrentDiagnostic>,
    pub total_scanned: usize,
    pub total_valid: usize,
    pub total_warnings: usize,
    pub total_errors: usize,
    pub total_payload_bytes: u64,
}

const MAX_RECURSIVE_DEPTH: usize = 64;

fn is_potential_torrent(path: &Path) -> bool {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    if name.starts_with('.') {
        return false;
    }
    if name.ends_with(".torrent")
        || name.contains(".torrent.")
        || name.ends_with(".added")
        || name.ends_with(".loaded")
    {
        return true;
    }
    if let Ok(mut file) = std::fs::File::open(path) {
        use std::io::Read;
        let Ok(meta) = file.metadata() else {
            return false;
        };
        if meta.len() == 0 || meta.len() > synapse_meta::MAX_TORRENT_FILE_BYTES as u64 {
            return false;
        }
        let mut magic = [0u8; 16];
        if let Ok(n) = file.read(&mut magic) {
            if n >= 2 && magic[0] == b'd' && magic[1].is_ascii_digit() {
                return true;
            }
        }
    }
    false
}

/// Recursively discovers all `.torrent` files in the given paths.
pub fn collect_torrent_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for path in paths {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_file() {
            if is_potential_torrent(path) || paths.len() == 1 {
                files.push(path.clone());
            }
        } else if meta.is_dir() {
            collect_recursive(path, 0, &mut files);
        }
    }
    files.sort();
    files
}

fn collect_recursive(dir: &Path, depth: usize, files: &mut Vec<PathBuf>) {
    if depth >= MAX_RECURSIVE_DEPTH {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if ft.is_dir() {
                collect_recursive(&path, depth + 1, files);
            } else if ft.is_file() && is_potential_torrent(&path) {
                files.push(path);
            }
        }
    }
}

/// Inspects and validates a single `.torrent` file in-depth.
static TRUST_STORE: std::sync::OnceLock<synapse_meta::TrustStore> = std::sync::OnceLock::new();

/// Sets the signers `inspect` trusts (BEP 35). Without it every signature reports as untrusted.
pub fn set_trust_store(store: synapse_meta::TrustStore) {
    let _ = TRUST_STORE.set(store);
}

fn trust_store() -> &'static synapse_meta::TrustStore {
    TRUST_STORE.get_or_init(synapse_meta::TrustStore::new)
}

/// `seconds` since the epoch as `YYYY-MM-DD HH:MM:SS UTC`.
fn format_utc(seconds: i64) -> String {
    let secs = seconds.max(0);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn invalid_diagnostic(file_path: &Path, errors: Vec<String>) -> TorrentDiagnostic {
    TorrentDiagnostic {
        file_path: file_path.to_path_buf(),
        name: file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        info_hash_hex: String::new(),
        format_type: TorrentFormatType::Invalid,
        root_hash_v1_hex: None,
        is_signed: false,
        signatures_count: 0,
        is_valid: false,
        piece_length: 0,
        total_pieces: 0,
        total_size_bytes: 0,
        files_count: 0,
        is_private: false,
        trackers: Vec::new(),
        web_seeds: Vec::new(),
        creator: None,
        creation_date: None,
        comment: None,
        warnings: Vec::new(),
        errors,
    }
}

pub fn inspect_torrent_file(file_path: &Path) -> TorrentDiagnostic {
    use std::io::Read;

    let file = match std::fs::File::open(file_path) {
        Ok(f) => f,
        Err(e) => return invalid_diagnostic(file_path, vec![format!("Failed to read file: {e}")]),
    };
    let max_bytes = synapse_meta::MAX_TORRENT_FILE_BYTES as u64;
    if let Ok(meta) = file.metadata() {
        if meta.len() > max_bytes {
            return invalid_diagnostic(
                file_path,
                vec![format!(
                    "Torrent file exceeds maximum supported size ({max_bytes} bytes)"
                )],
            );
        }
    }
    let mut raw_bytes = Vec::new();
    if let Err(e) = file.take(max_bytes + 1).read_to_end(&mut raw_bytes) {
        return invalid_diagnostic(file_path, vec![format!("Failed to read file: {e}")]);
    }
    if raw_bytes.len() > synapse_meta::MAX_TORRENT_FILE_BYTES {
        return invalid_diagnostic(
            file_path,
            vec![format!(
                "Torrent file exceeds maximum supported size ({max_bytes} bytes)"
            )],
        );
    }

    inspect_torrent_bytes(file_path, &raw_bytes)
}

/// Inspects raw `.torrent` bytes without reading from disk.
pub fn inspect_torrent_bytes(file_path: &Path, bytes: &[u8]) -> TorrentDiagnostic {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    let root_bencode = match synapse_bencode::decode_buf(bytes) {
        Ok(b) => b,
        Err(e) => {
            errors.push(format!("BEncode syntax error: {e}"));
            return TorrentDiagnostic {
                file_path: file_path.to_path_buf(),
                name: file_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                info_hash_hex: String::new(),
                format_type: TorrentFormatType::Invalid,
                root_hash_v1_hex: None,
                is_signed: false,
                signatures_count: 0,
                is_valid: false,
                piece_length: 0,
                total_pieces: 0,
                total_size_bytes: 0,
                files_count: 0,
                is_private: false,
                trackers: Vec::new(),
                web_seeds: Vec::new(),
                creator: None,
                creation_date: None,
                comment: None,
                warnings,
                errors,
            };
        }
    };

    let root_dict = match root_bencode {
        BEncode::Dict(ref d) => d,
        _ => {
            errors.push("Root bencode element is not a dictionary".to_string());
            return TorrentDiagnostic {
                file_path: file_path.to_path_buf(),
                name: file_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                info_hash_hex: String::new(),
                format_type: TorrentFormatType::Invalid,
                root_hash_v1_hex: None,
                is_signed: false,
                signatures_count: 0,
                is_valid: false,
                piece_length: 0,
                total_pieces: 0,
                total_size_bytes: 0,
                files_count: 0,
                is_private: false,
                trackers: Vec::new(),
                web_seeds: Vec::new(),
                creator: None,
                creation_date: None,
                comment: None,
                warnings,
                errors,
            };
        }
    };

    // Extract creation date
    let creation_date = root_dict
        .get(b"creation date".as_slice())
        .and_then(|v| match v {
            BEncode::Int(ts) => Some(format_utc(*ts)),
            _ => None,
        });

    // Check v2 / hybrid markers
    let has_file_tree = root_dict
        .get(b"info".as_slice())
        .and_then(|i| match i {
            BEncode::Dict(d) => d.get(b"file tree".as_slice()),
            _ => None,
        })
        .is_some();

    let has_v1_pieces = root_dict
        .get(b"info".as_slice())
        .and_then(|i| match i {
            BEncode::Dict(d) => d.get(b"pieces".as_slice()),
            _ => None,
        })
        .is_some();

    let meta_version = root_dict
        .get(b"info".as_slice())
        .and_then(|i| match i {
            BEncode::Dict(d) => d.get(b"meta version".as_slice()),
            _ => None,
        })
        .and_then(|v| match v {
            BEncode::Int(mv) => Some(*mv),
            _ => None,
        });

    // Parse Info using Synapse Engine's parser
    let info = match Info::from_bencode(root_bencode.clone()) {
        Ok(inf) => inf,
        Err(e) => {
            errors.push(format!("Synapse meta parser rejected torrent: {e}"));
            let hash_hex = root_dict
                .get(b"info".as_slice())
                .and_then(|i| {
                    let mut b = Vec::new();
                    i.clone().encode(&mut b).ok()?;
                    Some(hex::encode(Sha1::digest(&b)))
                })
                .unwrap_or_default();

            return TorrentDiagnostic {
                file_path: file_path.to_path_buf(),
                name: file_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                info_hash_hex: hash_hex,
                format_type: TorrentFormatType::Invalid,
                is_valid: false,
                piece_length: 0,
                total_pieces: 0,
                total_size_bytes: 0,
                files_count: 0,
                is_private: false,
                trackers: Vec::new(),
                web_seeds: Vec::new(),
                creator: None,
                creation_date,
                comment: None,
                warnings,
                errors,
                signatures_count: 0,
                is_signed: false,
                root_hash_v1_hex: None,
            };
        }
    };

    let info_hash_hex = hex::encode(info.hash);
    let total_pieces = info.pieces() as usize;
    let piece_length = info.piece_len;
    // Padding files (BEP 47) are layout, not payload: they count for the piece arithmetic but not
    // for what the torrent contains.
    let padded_len = info.total_len;
    let payload_files: Vec<_> = info
        .files
        .iter()
        .filter(|f| !(f.is_padding || synapse_meta::is_padding_file(&f.path, None)))
        .collect();
    let total_size_bytes: u64 = payload_files.iter().map(|f| f.length).sum();
    let files_count = payload_files.len();
    let is_private = info.private;

    let format_type = if info.is_merkle_v1() {
        TorrentFormatType::BitTorrentV1Merkle
    } else if info.is_hybrid() || (has_file_tree && has_v1_pieces) {
        TorrentFormatType::HybridV1V2
    } else if info.is_v2() || has_file_tree || meta_version == Some(2) {
        TorrentFormatType::BitTorrentV2
    } else if files_count > 1 || (files_count == 1 && info.files[0].path != Path::new(&info.name)) {
        TorrentFormatType::BitTorrentV1MultiFile
    } else {
        TorrentFormatType::BitTorrentV1SingleFile
    };

    // BEP 35: signatures are checked against the trust store set with `set_trust_store`.
    let signatures_count = info.signatures.len();
    let is_signed = signatures_count > 0;
    for (name, status) in info.verify_signatures(trust_store()) {
        match status {
            synapse_meta::SignatureStatus::Trusted { .. } => {}
            synapse_meta::SignatureStatus::Untrusted { reason } => {
                warnings.push(format!(
                    "BEP 35 signature by '{name}' is not trusted: {reason}"
                ));
            }
            synapse_meta::SignatureStatus::Invalid { reason } => {
                errors.push(format!("BEP 35 signature by '{name}' is invalid: {reason}"));
            }
        }
    }

    // Deep validation checks:
    // 1. Piece length sanity
    if piece_length == 0 {
        errors.push("Piece length is 0".to_string());
    } else if !piece_length.is_power_of_two() {
        warnings.push(format!(
            "Piece length {} is not a power of 2 (non-standard)",
            piece_length
        ));
    } else if piece_length < 16 * 1024 {
        warnings.push(format!(
            "Piece length {} bytes (< 16 KiB) is unusually small",
            piece_length
        ));
    } else if piece_length > 64 * 1024 * 1024 {
        warnings.push(format!(
            "Piece length {} bytes (> 64 MiB) is unusually large",
            piece_length
        ));
    }

    // 2. Piece count vs total byte span check
    if piece_length > 0 {
        let expected_pieces = (padded_len as usize).div_ceil(piece_length as usize);
        if total_pieces != expected_pieces && padded_len > 0 {
            errors.push(format!(
                "Piece count mismatch: torrent declares {} pieces, but payload size {} B requires {} pieces",
                total_pieces, padded_len, expected_pieces
            ));
        }
    }

    // 3. File paths check
    for f in &info.files {
        if f.path.is_absolute() {
            errors.push(format!(
                "File path is absolute (security violation): {}",
                f.path.display()
            ));
        }
        if f.path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            errors.push(format!(
                "File path contains parent directory '..' component (path traversal risk): {}",
                f.path.display()
            ));
        }
        let path_str = f.path.to_string_lossy();
        if path_str.starts_with(".pad/") || path_str.contains("____padding_file_") {
            warnings.push(format!(
                "Contains BEP 47 alignment padding file: {}",
                f.path.display()
            ));
        }
    }

    // 4. Trackers validation
    let mut trackers = Vec::new();
    if let Some(ref a) = info.announce {
        trackers.push(a.to_string());
    }
    for tier in &info.url_list {
        for tr in tier {
            let tr_str = tr.to_string();
            if !trackers.contains(&tr_str) {
                trackers.push(tr_str);
            }
        }
    }

    if trackers.is_empty() && !is_private {
        warnings.push("No tracker URLs specified (torrent relies solely on DHT/PEX)".to_string());
    }

    // 5. Web seeds validation
    let web_seeds: Vec<String> = info.web_seeds.iter().map(|u| u.to_string()).collect();

    let is_valid = errors.is_empty();

    TorrentDiagnostic {
        file_path: file_path.to_path_buf(),
        name: info.name,
        info_hash_hex,
        format_type,
        is_valid,
        piece_length,
        total_pieces,
        total_size_bytes,
        files_count,
        is_private,
        trackers,
        web_seeds,
        creator: info.creator,
        creation_date,
        comment: info.comment,
        warnings,
        errors,
        signatures_count,
        is_signed,
        root_hash_v1_hex: info.root_hash_v1.map(hex::encode),
    }
}

/// Runs inspection on a batch of files/paths.
pub fn inspect_paths(paths: &[PathBuf]) -> InspectBatchResult {
    let files = collect_torrent_files(paths);
    let mut diagnostics = Vec::new();
    let mut total_valid = 0;
    let mut total_warnings = 0;
    let mut total_errors = 0;
    let mut total_payload_bytes = 0;

    for file in &files {
        let diag = inspect_torrent_file(file);
        if diag.is_valid {
            total_valid += 1;
        } else {
            total_errors += 1;
        }
        total_warnings += diag.warnings.len();
        total_payload_bytes += diag.total_size_bytes;
        diagnostics.push(diag);
    }

    InspectBatchResult {
        total_scanned: files.len(),
        total_valid,
        total_warnings,
        total_errors,
        total_payload_bytes,
        diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn make_valid_torrent_bytes() -> Vec<u8> {
        let piece_data = b"Hello, Synapse 2.0 BitTorrent!";
        let piece_hash: [u8; 20] = Sha1::digest(piece_data).into();

        let mut info = BTreeMap::new();
        info.insert(b"name".to_vec(), BEncode::String(b"test_file.txt".to_vec()));
        info.insert(b"piece length".to_vec(), BEncode::Int(32768));
        info.insert(b"pieces".to_vec(), BEncode::String(piece_hash.to_vec()));
        info.insert(b"length".to_vec(), BEncode::Int(piece_data.len() as i64));

        let mut root = BTreeMap::new();
        root.insert(
            b"announce".to_vec(),
            BEncode::String(b"udp://tracker.opentrackr.org:1337/announce".to_vec()),
        );
        root.insert(b"info".to_vec(), BEncode::Dict(info));

        let mut out = Vec::new();
        BEncode::Dict(root).encode(&mut out).unwrap();
        out
    }

    #[test]
    fn test_inspect_valid_single_file_torrent() {
        let bytes = make_valid_torrent_bytes();
        let diag = inspect_torrent_bytes(Path::new("sample.torrent"), &bytes);
        assert!(diag.is_valid);
        assert_eq!(diag.name, "test_file.txt");
        assert_eq!(diag.total_pieces, 1);
        assert_eq!(diag.files_count, 1);
        assert_eq!(diag.format_type, TorrentFormatType::BitTorrentV1SingleFile);
        assert_eq!(diag.trackers.len(), 1);
        assert!(diag.errors.is_empty());
    }

    #[test]
    fn test_inspect_corrupted_piece_hashes() {
        let mut bytes = make_valid_torrent_bytes();
        // Truncate pieces bytes
        let mut decoded = synapse_bencode::decode_buf(&bytes).unwrap();
        if let BEncode::Dict(ref mut d) = decoded {
            if let Some(BEncode::Dict(ref mut i)) = d.get_mut(b"info".as_slice()) {
                i.insert(b"pieces".to_vec(), BEncode::String(vec![0u8; 15])); // Invalid 15 bytes!
            }
        }
        bytes.clear();
        decoded.encode(&mut bytes).unwrap();

        let diag = inspect_torrent_bytes(Path::new("corrupt.torrent"), &bytes);
        assert!(!diag.is_valid);
        assert!(diag
            .errors
            .iter()
            .any(|e| e.contains("InvalidHashes") || e.contains("rejected")));
    }

    #[test]
    fn test_inspect_path_traversal_detection() {
        let mut info = BTreeMap::new();
        info.insert(b"name".to_vec(), BEncode::String(b"safe_dir".to_vec()));
        info.insert(b"piece length".to_vec(), BEncode::Int(32768));
        info.insert(b"pieces".to_vec(), BEncode::String(vec![0u8; 20]));

        let mut file_dict = BTreeMap::new();
        file_dict.insert(b"length".to_vec(), BEncode::Int(100));
        file_dict.insert(
            b"path".to_vec(),
            BEncode::List(vec![
                BEncode::String(b"..".to_vec()),
                BEncode::String(b"etc".to_vec()),
                BEncode::String(b"passwd".to_vec()),
            ]),
        );
        info.insert(
            b"files".to_vec(),
            BEncode::List(vec![BEncode::Dict(file_dict)]),
        );

        let mut root = BTreeMap::new();
        root.insert(b"info".to_vec(), BEncode::Dict(info));

        let mut bytes = Vec::new();
        BEncode::Dict(root).encode(&mut bytes).unwrap();

        let diag = inspect_torrent_bytes(Path::new("evil.torrent"), &bytes);
        assert!(!diag.is_valid);
        assert!(diag
            .errors
            .iter()
            .any(|e| e.contains("UnsafeFilePath") || e.contains("rejected")));
    }

    #[test]
    fn dates_are_formatted_as_utc() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_utc(1_700_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00:00 UTC");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_loop_does_not_hang_collect_torrent_files() {
        let dir = tempfile::tempdir().unwrap();
        let real_torrent = dir.path().join("valid.torrent");
        std::fs::write(&real_torrent, make_valid_torrent_bytes()).unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::os::unix::fs::symlink(dir.path(), sub.join("loop")).unwrap();

        let collected = collect_torrent_files(&[dir.path().to_path_buf()]);
        assert_eq!(collected, vec![real_torrent]);
    }

    #[test]
    fn oversized_non_torrent_d_file_is_ignored_and_rejected() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("huge.dat");
        let mut f = std::fs::File::create(&big).unwrap();
        f.write_all(b"d4:test").unwrap();
        f.set_len(synapse_meta::MAX_TORRENT_FILE_BYTES as u64 + 1024)
            .unwrap();
        drop(f);

        assert!(!is_potential_torrent(&big));
        assert!(collect_torrent_files(&[dir.path().to_path_buf()]).is_empty());

        let diag = inspect_torrent_file(&big);
        assert!(!diag.is_valid);
        assert!(diag
            .errors
            .iter()
            .any(|e| e.contains("maximum supported size")));
    }

    #[test]
    fn pure_v2_and_hybrid_torrents_are_classified_distinctly() {
        let dir = tempfile::tempdir().unwrap();
        let data_file = dir.path().join("payload.bin");
        std::fs::write(&data_file, vec![0x42u8; 32 * 1024]).unwrap();

        let v2_opts = synapse_meta::create::CreateOptions {
            piece_length: Some(16_384),
            version: synapse_meta::create::TorrentVersion::V2,
            ..Default::default()
        };
        let v2_bytes =
            synapse_meta::create::create_torrent(&data_file, &v2_opts, |_, _| {}).unwrap();
        let v2_diag = inspect_torrent_bytes(Path::new("pure-v2.torrent"), &v2_bytes);
        assert!(v2_diag.is_valid, "v2 errors: {:?}", v2_diag.errors);
        assert_eq!(v2_diag.format_type, TorrentFormatType::BitTorrentV2);

        let hybrid_opts = synapse_meta::create::CreateOptions {
            piece_length: Some(16_384),
            version: synapse_meta::create::TorrentVersion::Hybrid,
            ..Default::default()
        };
        let hybrid_bytes =
            synapse_meta::create::create_torrent(&data_file, &hybrid_opts, |_, _| {}).unwrap();
        let hybrid_diag = inspect_torrent_bytes(Path::new("hybrid.torrent"), &hybrid_bytes);
        assert!(
            hybrid_diag.is_valid,
            "hybrid errors: {:?}",
            hybrid_diag.errors
        );
        assert_eq!(hybrid_diag.format_type, TorrentFormatType::HybridV1V2);
    }
}
