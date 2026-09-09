//! Migration tool to import torrents and resume states from Transmission to Synapse.
//!
//! Parses Transmission's `.torrent` files and `.resume` bencoded state dictionaries,
//! translates piece bitfields and download destinations, and emits native Synapse
//! session files (`<info_hash>.json`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use synapse_bencode::BEncode;
use synapse_engine::{SessionStore, TorrentSessionState};
use synapse_meta::Info;
use synapse_picker::Bitfield;

#[derive(Debug, Clone)]
pub struct TransmissionTorrentEntry {
    pub name: String,
    pub info_hash_hex: String,
    pub download_dir: PathBuf,
    pub total_size: u64,
    pub total_pieces: usize,
    pub completed_pieces: usize,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub is_paused: bool,
    pub added_at: i64,
    pub raw_bencode: Vec<u8>,
    pub bitfield_hex: String,
}

pub struct MigrationResult {
    pub found: Vec<TransmissionTorrentEntry>,
    pub migrated: usize,
    pub errors: Vec<String>,
}

/// Automatically discovers Transmission data directory based on standard OS locations.
pub fn default_transmission_dir() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(home);
        // macOS standard path
        let mac_dir = home_path.join("Library/Application Support/Transmission");
        if mac_dir.exists() {
            return Some(mac_dir);
        }
        // Linux XDG standard paths
        let linux_config = home_path.join(".config/transmission");
        if linux_config.exists() {
            return Some(linux_config);
        }
        let linux_data = home_path.join(".local/share/transmission");
        if linux_data.exists() {
            return Some(linux_data);
        }
    }
    // Linux daemon system path
    let daemon_dir = PathBuf::from("/var/lib/transmission-daemon/info");
    if daemon_dir.exists() {
        return Some(daemon_dir);
    }
    None
}

/// Automatically discovers Synapse session torrents directory.
pub fn default_synapse_session_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(home);
        #[cfg(target_os = "macos")]
        return home_path.join("Library/Application Support/synapse/torrents");
        #[cfg(not(target_os = "macos"))]
        return home_path.join(".local/share/synapse/torrents");
    }
    PathBuf::from("./torrents")
}

/// Parses a Transmission `.resume` file and extracts download path, bitfield, and stats.
pub fn parse_transmission_resume(
    resume_bytes: &[u8],
    total_pieces: usize,
) -> Result<(PathBuf, Bitfield, u64, u64, bool, i64), String> {
    let bencode = synapse_bencode::decode_buf(resume_bytes)
        .map_err(|e| format!("Failed to parse resume bencode: {e}"))?;

    let dict = match bencode {
        BEncode::Dict(d) => d,
        _ => return Err("Resume file is not a bencoded dictionary".into()),
    };

    let get_str = |key: &[u8]| -> Option<String> {
        dict.get(key).and_then(|v| match v {
            BEncode::String(s) => String::from_utf8(s.clone()).ok(),
            _ => None,
        })
    };

    let get_int = |key: &[u8]| -> Option<i64> {
        dict.get(key).and_then(|v| match v {
            BEncode::Int(i) => Some(*i),
            _ => None,
        })
    };

    let dest = get_str(b"destination")
        .or_else(|| get_str(b"downloadDir"))
        .or_else(|| get_str(b"download-dir"))
        .unwrap_or_else(|| ".".to_string());
    let download_dir = PathBuf::from(dest);

    let uploaded = get_int(b"uploaded").unwrap_or(0).max(0) as u64;
    let downloaded = get_int(b"downloaded").unwrap_or(0).max(0) as u64;
    let is_paused = get_int(b"paused").unwrap_or(0) != 0;
    let added_at = get_int(b"added-date").unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    });

    let mut bitfield = Bitfield::new(total_pieces);
    if let Some(BEncode::String(bytes)) = dict.get(b"pieces".as_slice()).or_else(|| dict.get(b"bitfield".as_slice())) {
        if let Some(bf) = Bitfield::from_bytes(bytes, total_pieces) {
            bitfield = bf;
        } else {
            // If byte length doesn't exactly match total_pieces div_ceil(8), set valid bits up to available len
            for (byte_idx, &b) in bytes.iter().enumerate() {
                for bit in 0..8 {
                    let piece_idx = byte_idx * 8 + bit;
                    if piece_idx < total_pieces && (b & (0x80 >> bit)) != 0 {
                        bitfield.set(piece_idx);
                    }
                }
            }
        }
    }

    Ok((download_dir, bitfield, uploaded, downloaded, is_paused, added_at))
}

/// Scans the given Transmission directory, parses all torrents and resume states, and migrates them to Synapse.
pub fn migrate_transmission(
    transmission_dir: &Path,
    synapse_torrents_dir: &Path,
    dry_run: bool,
) -> Result<MigrationResult, String> {
    if !transmission_dir.exists() {
        return Err(format!(
            "Transmission directory not found: {}",
            transmission_dir.display()
        ));
    }

    let torrents_dir = if transmission_dir.join("Torrents").exists() {
        transmission_dir.join("Torrents")
    } else if transmission_dir.join("torrents").exists() {
        transmission_dir.join("torrents")
    } else {
        transmission_dir.to_path_buf()
    };

    let resume_dir = if transmission_dir.join("Resume").exists() {
        transmission_dir.join("Resume")
    } else if transmission_dir.join("resume").exists() {
        transmission_dir.join("resume")
    } else {
        transmission_dir.to_path_buf()
    };

    let mut torrent_files: HashMap<String, (PathBuf, Info, Vec<u8>)> = HashMap::new();
    let mut resume_files: HashMap<String, PathBuf> = HashMap::new();
    let mut errors = Vec::new();

    // 1. Scan and parse all .torrent files
    if let Ok(entries) = std::fs::read_dir(&torrents_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("torrent") {
                if let Ok(bytes) = std::fs::read(&path) {
                    if let Ok(bencode) = synapse_bencode::decode_buf(&bytes) {
                        if let Ok(info) = Info::from_bencode(bencode) {
                            let hash_hex = hex::encode(info.hash);
                            let stem = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
                            torrent_files.insert(hash_hex.clone(), (path.clone(), info.clone(), bytes.clone()));
                            torrent_files.insert(stem, (path, info, bytes));
                        }
                    }
                }
            }
        }
    }

    // 2. Scan all .resume files
    if let Ok(entries) = std::fs::read_dir(&resume_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("resume") {
                let stem = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
                resume_files.insert(stem, path);
            }
        }
    }

    let mut found_entries = Vec::new();
    let mut processed_hashes = std::collections::HashSet::new();

    // 3. Match .torrent with .resume and construct Synapse session states
    for (key, (torrent_path, info, raw_bytes)) in &torrent_files {
        let hash_hex = hex::encode(info.hash);
        if processed_hashes.contains(&hash_hex) {
            continue;
        }
        processed_hashes.insert(hash_hex.clone());

        let total_pieces = info.pieces() as usize;
        let mut download_dir = PathBuf::from(".");
        let mut bitfield = Bitfield::new(total_pieces);
        let mut uploaded = 0u64;
        let mut downloaded = 0u64;
        let mut is_paused = false;
        let mut added_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Check if there is a matching .resume file
        let resume_path = resume_files.get(key)
            .or_else(|| resume_files.get(&hash_hex))
            .or_else(|| {
                let stem = torrent_path.file_stem().unwrap_or_default().to_string_lossy().to_string();
                resume_files.get(&stem)
            });

        if let Some(r_path) = resume_path {
            if let Ok(r_bytes) = std::fs::read(r_path) {
                if let Ok((d_dir, bf, ul, dl, paused, added)) = parse_transmission_resume(&r_bytes, total_pieces) {
                    download_dir = d_dir;
                    bitfield = bf;
                    uploaded = ul;
                    downloaded = dl;
                    is_paused = paused;
                    added_at = added;
                }
            }
        }

        let completed_pieces = bitfield.count_ones();
        let bitfield_hex = hex::encode(bitfield.as_bytes());

        found_entries.push(TransmissionTorrentEntry {
            name: info.name.clone(),
            info_hash_hex: hash_hex,
            download_dir,
            total_size: info.total_len,
            total_pieces,
            completed_pieces,
            uploaded_bytes: uploaded,
            downloaded_bytes: downloaded,
            is_paused,
            added_at,
            raw_bencode: raw_bytes.clone(),
            bitfield_hex,
        });
    }

    let mut migrated_count = 0;
    if !dry_run {
        let store = match SessionStore::new(synapse_torrents_dir) {
            Ok(s) => Some(s),
            Err(e) => {
                errors.push(format!(
                    "Failed to initialize encrypted session store at {}: {e}",
                    synapse_torrents_dir.display()
                ));
                None
            }
        };

        for entry in &found_entries {
            let ratio = if entry.downloaded_bytes > 0 {
                Some(entry.uploaded_bytes as f32 / entry.downloaded_bytes as f32)
            } else if entry.total_size > 0 && entry.uploaded_bytes > 0 {
                Some(entry.uploaded_bytes as f32 / entry.total_size as f32)
            } else {
                Some(0.0)
            };

            let session_state = TorrentSessionState {
                info_hash_hex: entry.info_hash_hex.clone(),
                name: entry.name.clone(),
                download_dir: entry.download_dir.to_string_lossy().to_string(),
                bitfield_hex: entry.bitfield_hex.clone(),
                total_pieces: entry.total_pieces,
                total_size: entry.total_size,
                uploaded_bytes: entry.uploaded_bytes,
                downloaded_bytes: entry.downloaded_bytes,
                added_at: entry.added_at,
                is_paused: entry.is_paused,
                ratio,
                magnet_uri: None,
                raw_bencode_hex: Some(hex::encode(&entry.raw_bencode)),
            };

            if let Some(ref s) = store {
                match s.save_torrent(&session_state) {
                    Ok(()) => migrated_count += 1,
                    Err(e) => errors.push(format!("Failed to save encrypted state for {}: {e}", entry.name)),
                }
            }
        }
    }

    Ok(MigrationResult {
        found: found_entries,
        migrated: migrated_count,
        errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    #[test]
    fn test_parse_transmission_resume_dictionary() {
        let mut dict = BTreeMap::new();
        dict.insert(b"destination".to_vec(), BEncode::String(b"/Users/test/Downloads".to_vec()));
        dict.insert(b"uploaded".to_vec(), BEncode::Int(2048000));
        dict.insert(b"downloaded".to_vec(), BEncode::Int(10485760));
        dict.insert(b"paused".to_vec(), BEncode::Int(1));
        dict.insert(b"added-date".to_vec(), BEncode::Int(1690000000));

        // 8 pieces: 11110000 (0xF0)
        dict.insert(b"pieces".to_vec(), BEncode::String(vec![0xF0]));

        let mut buf = Vec::new();
        BEncode::Dict(dict).encode(&mut buf).unwrap();

        let (dest, bf, ul, dl, paused, added) = parse_transmission_resume(&buf, 8).unwrap();
        assert_eq!(dest, PathBuf::from("/Users/test/Downloads"));
        assert_eq!(ul, 2048000);
        assert_eq!(dl, 10485760);
        assert!(paused);
        assert_eq!(added, 1690000000);
        assert_eq!(bf.count_ones(), 4);
        assert!(bf.has(0));
        assert!(bf.has(1));
        assert!(bf.has(2));
        assert!(bf.has(3));
        assert!(!bf.has(4));
    }

    #[test]
    fn test_migrate_transmission_end_to_end() {
        let trans_dir = TempDir::new().unwrap();
        let synapse_dir = TempDir::new().unwrap();

        let torrents_subdir = trans_dir.path().join("Torrents");
        let resume_subdir = trans_dir.path().join("Resume");
        std::fs::create_dir_all(&torrents_subdir).unwrap();
        std::fs::create_dir_all(&resume_subdir).unwrap();

        // Create a fake .torrent file
        let mut info_dict = BTreeMap::new();
        info_dict.insert(b"name".to_vec(), BEncode::String(b"sample_torrent".to_vec()));
        info_dict.insert(b"piece length".to_vec(), BEncode::Int(16384));
        info_dict.insert(b"pieces".to_vec(), BEncode::String(vec![0u8; 20])); // 1 piece
        info_dict.insert(b"length".to_vec(), BEncode::Int(16384));

        let mut root_dict = BTreeMap::new();
        root_dict.insert(b"info".to_vec(), BEncode::Dict(info_dict));

        let mut torrent_bytes = Vec::new();
        BEncode::Dict(root_dict).encode(&mut torrent_bytes).unwrap();

        let info = Info::from_bencode(synapse_bencode::decode_buf(&torrent_bytes).unwrap()).unwrap();
        let hash_hex = hex::encode(info.hash);

        std::fs::write(torrents_subdir.join(format!("{hash_hex}.torrent")), &torrent_bytes).unwrap();

        // Create fake .resume file
        let mut resume_dict = BTreeMap::new();
        resume_dict.insert(b"destination".to_vec(), BEncode::String(b"/media/torrents".to_vec()));
        resume_dict.insert(b"uploaded".to_vec(), BEncode::Int(5000));
        resume_dict.insert(b"downloaded".to_vec(), BEncode::Int(16384));
        resume_dict.insert(b"pieces".to_vec(), BEncode::String(vec![0x80])); // 1 piece complete

        let mut resume_bytes = Vec::new();
        BEncode::Dict(resume_dict).encode(&mut resume_bytes).unwrap();
        std::fs::write(resume_subdir.join(format!("{hash_hex}.resume")), &resume_bytes).unwrap();

        // Run dry-run migration
        let dry_res = migrate_transmission(trans_dir.path(), synapse_dir.path(), true).unwrap();
        assert_eq!(dry_res.found.len(), 1);
        assert_eq!(dry_res.migrated, 0);

        // Run real migration
        let res = migrate_transmission(trans_dir.path(), synapse_dir.path(), false).unwrap();
        assert_eq!(res.found.len(), 1);
        assert_eq!(res.migrated, 1);

        let store = SessionStore::new(synapse_dir.path()).unwrap();
        let loaded = store.load_torrent(&hash_hex).unwrap().unwrap();
        assert_eq!(loaded.name, "sample_torrent");
        assert_eq!(loaded.download_dir, "/media/torrents");
        assert_eq!(loaded.total_pieces, 1);
        assert_eq!(loaded.downloaded_bytes, 16384);
    }
}
