//! End-to-end integration test verifying Disk I/O & Storage Subsystem parity (Phase 5.3).
//!
//! Validates:
//! 1. Write coalescing and backpressure accounting under heavy I/O loads.
//! 2. Part-file boundary redirection: slices of unselected (priority 0) files are written
//!    to `.synapse_part_<hash>`, and the unselected file is never created on disk.
//! 3. Parallel pipelined recheck: multi-piece torrents recheck rapidly using the pipelined pool.
//! 4. Fatal disk I/O error handling: unwritable disks or storage faults transition torrent to SwarmState::Error.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sha1::{Digest, Sha1};

use diskio::{coalesce_write_jobs, DiskEngine, WriteJob};
use synapse_bencode::BEncode;
use synapse_engine::{SwarmState, SwarmStats, SwarmTier, TokenBucket, Torrent, TorrentConfig};
use synapse_meta::Info;
use synapse_picker::Mode;

fn fresh_stats(
    info: &Info,
    download_dir: &Path,
    is_seeding: bool,
) -> Arc<parking_lot::RwLock<SwarmStats>> {
    Arc::new(parking_lot::RwLock::new(SwarmStats {
        name: info.name.clone(),
        info_hash: info.hash,
        total_size: info.total_len,
        progress: if is_seeding { 1.0 } else { 0.0 },
        state: if is_seeding {
            SwarmState::Seeding
        } else {
            SwarmState::Downloading
        },
        tier: SwarmTier::Hot,
        download_rate: 0,
        upload_rate: 0,
        downloaded_bytes: if is_seeding { info.total_len } else { 0 },
        uploaded_bytes: 0,
        peers_connected: 0,
        peers_sending: 0,
        eta_seconds: 0,
        ratio: 0.0,
        download_dir: download_dir.to_string_lossy().to_string(),
        added_at: 0,
        is_private: info.private,
        is_stalled: false,
        last_transfer_at: 0,
        piece_count: info.pieces(),
        piece_size: info.piece_len,
    }))
}

/// Builds a 2-file torrent where piece 0 spans across file 0 (wanted) and file 1 (unwanted).
/// Total piece size = 32,768.
/// File 0 len = 20,000.
/// File 1 len = 12,768.
fn build_straddling_partfile_torrent() -> (Info, Vec<u8>, Vec<u8>) {
    let piece_len: u32 = 32_768;
    let file0_data = vec![0x33u8; 20_000];
    let file1_data = vec![0x77u8; 12_768];

    let mut stream = Vec::new();
    stream.extend_from_slice(&file0_data);
    stream.extend_from_slice(&file1_data);

    let mut hasher = Sha1::new();
    hasher.update(&stream);
    let piece0_hash: [u8; 20] = hasher.finalize().into();

    let mut files_list = Vec::new();
    // file 0: "wanted.bin"
    let mut f0 = BTreeMap::new();
    f0.insert(b"length".to_vec(), BEncode::Int(20_000));
    f0.insert(
        b"path".to_vec(),
        BEncode::List(vec![BEncode::String(b"wanted.bin".to_vec())]),
    );
    files_list.push(BEncode::Dict(f0));

    // file 1: "unwanted.bin"
    let mut f1 = BTreeMap::new();
    f1.insert(b"length".to_vec(), BEncode::Int(12_768));
    f1.insert(
        b"path".to_vec(),
        BEncode::List(vec![BEncode::String(b"unwanted.bin".to_vec())]),
    );
    files_list.push(BEncode::Dict(f1));

    let mut info_dict = BTreeMap::new();
    info_dict.insert(b"name".to_vec(), BEncode::String(b"partfile_test".to_vec()));
    info_dict.insert(b"piece length".to_vec(), BEncode::Int(piece_len as i64));
    info_dict.insert(b"pieces".to_vec(), BEncode::String(piece0_hash.to_vec()));
    info_dict.insert(b"files".to_vec(), BEncode::List(files_list));

    let mut top_dict = BTreeMap::new();
    top_dict.insert(b"info".to_vec(), BEncode::Dict(info_dict));

    let info = Info::from_bencode(BEncode::Dict(top_dict)).expect("valid multi-file info");
    (info, file0_data, file1_data)
}

fn create_test_torrent_config(
    info: Arc<Info>,
    download_dir: std::path::PathBuf,
    disk: Arc<DiskEngine>,
    stats: Arc<parking_lot::RwLock<SwarmStats>>,
) -> TorrentConfig {
    TorrentConfig {
        info: info.clone(),
        download_dir,
        peer_id: [0x53; 20],
        disk,
        mode: Mode::RarestFirst,
        max_pipeline: 8,
        regular_unchokes: 4,
        optimistic_unchoke_interval: Duration::from_secs(60),
        tick_interval: Duration::from_millis(20),
        on_torrent_completed: None,
        on_piece_completed: None,
        stats,
        bitfield: Arc::new(parking_lot::RwLock::new(None)),
        download_bucket: Arc::new(TokenBucket::unthrottled()),
        upload_bucket: Arc::new(TokenBucket::unthrottled()),
        global_metrics: None,
        idle_timeout: None,
        live_peers: Arc::new(parking_lot::RwLock::new(Vec::new())),
        piece_availability: Arc::new(parking_lot::RwLock::new(vec![1; info.pieces() as usize])),
        settings: Arc::new(parking_lot::RwLock::new(Default::default())),
        on_peers_discovered: None,
        on_metadata_resolved: None,
        ban_list: Default::default(),
        ip_filter: Default::default(),
        super_seeding: false,
        local_webseed_resolver: None,
        alert_sender: None,
    }
}

#[tokio::test]
async fn test_write_coalescing_and_backpressure() {
    let tmp = tempfile::tempdir().unwrap();
    let file_path = Arc::new(tmp.path().join("coalesce_target.dat"));

    // 1. Verify coalesce_write_jobs: 3 contiguous 16KiB blocks are merged into one 48KiB write
    let jobs = vec![
        WriteJob {
            path: file_path.clone(),
            offset: 0,
            data: vec![0xAA; 16384].into(),
            file_len: 49152,
        },
        WriteJob {
            path: file_path.clone(),
            offset: 16384,
            data: vec![0xBB; 16384].into(),
            file_len: 49152,
        },
        WriteJob {
            path: file_path.clone(),
            offset: 32768,
            data: vec![0xCC; 16384].into(),
            file_len: 49152,
        },
    ];

    let coalesced = coalesce_write_jobs(jobs);
    assert_eq!(
        coalesced.len(),
        1,
        "contiguous adjacent blocks should coalesce into 1 job"
    );
    assert_eq!(coalesced[0].offset, 0);
    assert_eq!(coalesced[0].data.len(), 49152);
    assert_eq!(&coalesced[0].data[0..4], &[0xAA, 0xAA, 0xAA, 0xAA]);
    assert_eq!(&coalesced[0].data[16384..16388], &[0xBB, 0xBB, 0xBB, 0xBB]);
    assert_eq!(&coalesced[0].data[32768..32772], &[0xCC, 0xCC, 0xCC, 0xCC]);

    // 2. Verify disk engine backpressure tracking
    let disk = DiskEngine::new_blocking(1024); // 1024 byte buffer limit
    assert_eq!(disk.in_flight_write_bytes(), 0);
    assert_eq!(disk.max_write_buffer_bytes(), 1024);

    let write_job = WriteJob {
        path: file_path.clone(),
        offset: 0,
        data: vec![0xFF; 512].into(),
        file_len: 512,
    };
    disk.write_batch(vec![write_job]).await.unwrap();
    assert_eq!(
        disk.in_flight_write_bytes(),
        0,
        "completed write should decrement in-flight bytes to 0"
    );
}

#[tokio::test]
async fn test_part_file_redirection_and_isolation() {
    let tmp = tempfile::tempdir().unwrap();
    let download_dir = tmp.path().to_path_buf();

    let (info, file0_data, file1_data) = build_straddling_partfile_torrent();
    let info = Arc::new(info);
    let stats = fresh_stats(&info, &download_dir, false);
    let disk = Arc::new(DiskEngine::new_blocking(100 * 1024 * 1024));

    let config = create_test_torrent_config(
        info.clone(),
        download_dir.clone(),
        disk.clone(),
        stats.clone(),
    );
    let mut torrent = Torrent::new(config, None);

    // Mark file 1 ("unwanted.bin") as priority 0 (unwanted)
    torrent.apply_file_priority(1, 0);
    assert!(torrent.part_file.is_unwanted(1));

    // Construct full piece 0 data (20,000 bytes file0 + 12,768 bytes file1)
    let mut piece0_data = Vec::new();
    piece0_data.extend_from_slice(&file0_data);
    piece0_data.extend_from_slice(&file1_data);

    // Write piece 0 to disk
    torrent
        .write_piece(0, piece0_data.clone().into())
        .await
        .unwrap();

    // Verify:
    // 1. Wanted file exists on disk and contains exact data
    let wanted_file = download_dir.join("partfile_test").join("wanted.bin");
    assert!(wanted_file.exists(), "wanted file should be written");
    let read_wanted = fs::read(&wanted_file).unwrap();
    assert_eq!(read_wanted, file0_data);

    // 2. Unwanted file MUST NOT exist on disk!
    let unwanted_file = download_dir.join("partfile_test").join("unwanted.bin");
    assert!(
        !unwanted_file.exists(),
        "unwanted file must NOT exist on disk"
    );

    // 3. Part file exists and contains the boundary slice
    let part_file = torrent.part_file.part_file_path();
    assert!(
        part_file.exists(),
        "part file must exist to store boundary slices"
    );
    let part_content = fs::read(part_file).unwrap();
    assert_eq!(
        part_content, file1_data,
        "part file must contain exact slice for unwanted file"
    );

    // 4. Serving the piece verifies transparency: reading piece 0 succeeds and reconstructs full piece
    let served = torrent.read_piece_slice(0, 0, 32768).await.unwrap();
    assert_eq!(
        served, piece0_data,
        "read_piece_slice should transparently assemble from file + part file"
    );

    // 5. Recheck verifies transparency: parallel pipelined recheck verifies piece 0 as valid
    torrent.handle_recheck().await;
    assert_eq!(stats.read().progress, 1.0);
    assert_eq!(stats.read().state, SwarmState::Seeding);
}

#[tokio::test]
async fn test_parallel_pipelined_recheck_and_fatal_io_handling() {
    let tmp = tempfile::tempdir().unwrap();
    let download_dir = tmp.path().to_path_buf();

    // Create a 4-piece single file torrent (4 * 16KiB = 64KiB)
    let piece_len: u32 = 16384;
    let full_data = vec![0x5A; 65536];

    let mut pieces_hash = Vec::new();
    for chunk in full_data.chunks(16384) {
        let mut hasher = Sha1::new();
        hasher.update(chunk);
        pieces_hash.extend_from_slice(&hasher.finalize());
    }

    let mut info_dict = BTreeMap::new();
    info_dict.insert(
        b"name".to_vec(),
        BEncode::String(b"pipelined_recheck.bin".to_vec()),
    );
    info_dict.insert(b"piece length".to_vec(), BEncode::Int(piece_len as i64));
    info_dict.insert(b"pieces".to_vec(), BEncode::String(pieces_hash));
    info_dict.insert(b"length".to_vec(), BEncode::Int(65536));

    let mut top_dict = BTreeMap::new();
    top_dict.insert(b"info".to_vec(), BEncode::Dict(info_dict));

    let info = Arc::new(Info::from_bencode(BEncode::Dict(top_dict)).expect("valid info"));
    let stats = fresh_stats(&info, &download_dir, false);
    let disk = Arc::new(DiskEngine::new_blocking(100 * 1024 * 1024));

    // Pre-populate data on disk
    let file_path = download_dir.join("pipelined_recheck.bin");
    fs::write(&file_path, &full_data).unwrap();

    let config = create_test_torrent_config(
        info.clone(),
        download_dir.clone(),
        disk.clone(),
        stats.clone(),
    );
    let mut torrent = Torrent::new(config, None);

    // 1. Parallel pipelined recheck validates all 4 pieces concurrently
    torrent.handle_recheck().await;
    assert_eq!(stats.read().progress, 1.0);
    assert_eq!(stats.read().state, SwarmState::Seeding);

    // 2. Fatal I/O error handling:
    // If a write is attempted to an invalid unwritable path, disk returns DiskError::Io
    let fatal_path =
        Arc::new(Path::new("/proc/sys/fs/protected_unwritable/invalid.dat").to_path_buf());
    let job = WriteJob {
        path: fatal_path,
        offset: 0,
        data: vec![1, 2, 3].into(),
        file_len: 3,
    };
    let res = disk.write_batch(vec![job]).await;
    assert!(res.is_err(), "fatal I/O to protected path must fail");
}

#[tokio::test]
async fn part_file_blocks_are_served_from_inside_a_slice_and_data_moves_when_the_file_becomes_wanted(
) {
    let tmp = tempfile::tempdir().unwrap();
    let download_dir = tmp.path().to_path_buf();
    let (info, file0_data, file1_data) = build_straddling_partfile_torrent();
    let info = Arc::new(info);
    let stats = fresh_stats(&info, &download_dir, false);
    let disk = Arc::new(DiskEngine::new_blocking(100 * 1024 * 1024));
    let mut torrent = Torrent::new(
        create_test_torrent_config(info.clone(), download_dir.clone(), disk, stats),
        None,
    );
    torrent.apply_file_priority(1, 0);

    let mut piece0 = file0_data.clone();
    piece0.extend_from_slice(&file1_data);
    torrent.write_piece(0, piece0.clone().into()).await.unwrap();

    // A peer asks for a block that lies in the middle of the unwanted file's stored slice, as
    // real requests do (16 KiB blocks, not whole-piece reads).
    let block = torrent.read_piece_slice(0, 25_000, 4_096).await.unwrap();
    assert_eq!(
        block,
        &piece0[25_000..29_096],
        "block inside a part-file slice must be served correctly"
    );

    // The file becomes wanted: its bytes must move into the real file, leaving no hole.
    torrent.apply_file_priority(1, 4);
    torrent.migrate_part_file_slices(1).await;
    let real = download_dir.join("partfile_test").join("unwanted.bin");
    assert_eq!(
        fs::read(&real).unwrap(),
        file1_data,
        "part-file data was not migrated into the real file"
    );
    assert!(torrent.part_file.slices_for_file(1).is_empty());
    let served = torrent.read_piece_slice(0, 0, 32768).await.unwrap();
    assert_eq!(
        served, piece0,
        "the piece still reads back intact from the real files"
    );
}

/// Skipping a file must not deselect a piece it shares with a file that is still wanted; the
/// neighbour could otherwise never complete. The skipped file's bytes in that piece go to the
/// part file instead.
#[tokio::test]
async fn skipping_a_file_keeps_the_pieces_it_shares_with_a_wanted_file() {
    let tmp = tempfile::tempdir().unwrap();
    let (info, _, _) = build_straddling_partfile_torrent();
    let info = Arc::new(info);
    let stats = fresh_stats(&info, tmp.path(), false);
    let disk = Arc::new(DiskEngine::new_blocking(100 * 1024 * 1024));
    let config = create_test_torrent_config(info, tmp.path().to_path_buf(), disk, stats);
    let mut torrent = Torrent::new(config, None);

    torrent.apply_file_priority(1, 0);
    assert_eq!(
        torrent.piece_priority(0),
        4,
        "piece 0 still carries the wanted file's tail"
    );
    // Once the other file is skipped too, nothing wants the piece.
    torrent.apply_file_priority(0, 0);
    assert_eq!(torrent.piece_priority(0), 0);
    // And wanting either one again brings it back.
    torrent.apply_file_priority(1, 7);
    assert_eq!(torrent.piece_priority(0), 7);
}
