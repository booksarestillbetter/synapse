use diskio::DiskEngine;
use std::path::PathBuf;
use std::sync::Arc;
use synapse_engine::SwarmEngine;
use synapse_meta::{File, Info};
use tempfile::tempdir;

#[tokio::test]
async fn test_bep53_select_only_file_priorities() {
    let tmp = tempdir().unwrap();
    let disk = Arc::new(DiskEngine::auto().await);
    let swarm = SwarmEngine::new(disk, [0x01; 20]);

    // Create a mock multi-file torrent with 5 files
    let files = vec![
        File {
            path: PathBuf::from("multifile/file0.txt"),
            length: 1024,
        },
        File {
            path: PathBuf::from("multifile/file1.txt"),
            length: 1024,
        },
        File {
            path: PathBuf::from("multifile/file2.txt"),
            length: 1024,
        },
        File {
            path: PathBuf::from("multifile/file3.txt"),
            length: 1024,
        },
        File {
            path: PathBuf::from("multifile/file4.txt"),
            length: 1024,
        },
    ];

    let info = Info {
        name: "multifile".to_string(),
        announce: None,
        creator: None,
        comment: None,
        piece_len: 1024,
        total_len: 5120,
        pieces: 5,
        hashes: parking_lot::RwLock::new(Some(Arc::new(vec![[0x55; 20]; 5]))),
        hash: [0x77; 20],
        file_offsets: vec![0, 1024, 2048, 3072, 4096],
        files,
        private: false,
        url_list: vec![],
        web_seeds: vec![],
        meta_version: 1,
        info_hash_v2: None,
        piece_layers: std::collections::BTreeMap::new(),
        file_roots: vec![None; 5],
        raw_info: None,
        v2_aligned: false,
        // BEP 53: only files 1 and 3 are selected!
        select_only: Some(vec![1, 3]),
        signatures: Vec::new(),
        root_hash_v1: None,
        update_url: None,
        originator: None,
    };

    let handle = swarm.add_torrent(Arc::new(info), tmp.path().to_path_buf(), None);

    let prios = handle.file_priorities.read().clone();
    assert_eq!(prios.len(), 5);
    // File 0: 0 (DoNotDownload)
    // File 1: 4 (Normal)
    // File 2: 0 (DoNotDownload)
    // File 3: 4 (Normal)
    // File 4: 0 (DoNotDownload)
    assert_eq!(prios, vec![0, 4, 0, 4, 0]);
}
