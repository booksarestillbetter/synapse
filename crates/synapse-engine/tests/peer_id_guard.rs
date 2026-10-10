//! Guard: Synapse must never present another client's peer ID.
//!
//! Fails if any Rust source in the workspace contains an Azureus-style (Azureus-style) peer-ID
//! literal other than Synapse's own (`-SY`). The only exception is `peer.rs`, whose unit tests
//! feed other clients' IDs *into* `parse_client_name` (IDs of remote peers, never ours).

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every `-XX####-` window (two letters, four digits) in `src`.
fn azureus_prefixes(src: &str) -> Vec<&str> {
    let b = src.as_bytes();
    let mut hits = Vec::new();
    for i in 0..b.len().saturating_sub(7) {
        let w = &b[i..i + 8];
        if w[0] == b'-'
            && w[7] == b'-'
            && w[1].is_ascii_alphabetic()
            && w[2].is_ascii_alphabetic()
            && w[3..7].iter().all(|c| c.is_ascii_digit())
        {
            hits.push(&src[i..i + 8]);
        }
    }
    hits
}

#[test]
fn no_other_client_peer_id_prefix_in_the_workspace() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    rust_files(&crates, &mut files);
    assert!(
        files.len() > 50,
        "scan found too few files: {}",
        files.len()
    );

    let mut offenders = Vec::new();
    for f in files {
        // Remote-peer fixtures for the client-name parser.
        if f.ends_with("synapse-engine/src/peer.rs") {
            continue;
        }
        let src = std::fs::read_to_string(&f).unwrap_or_default();
        for hit in azureus_prefixes(&src) {
            if !hit.starts_with("-SY") {
                offenders.push(format!("{}: {hit}", f.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "other clients' peer-ID prefixes found (use synapse_engine::generate_peer_id):\n{}",
        offenders.join("\n")
    );
}
