//! Guard: integration tests must never reach the public internet — no remote `.torrent`
//! downloads, no external trackers, no live swarms. Tests use loopback, private ranges or
//! reserved example/invalid names only. This catches an external URL being added to a test.

use std::path::{Path, PathBuf};

/// Hosts a test may mention: loopback/private literals, reserved names, and pure-validation
/// fixtures that are parsed but never connected to.
const ALLOWED: &[&str] = &[
    "127.",
    "localhost",
    "[::1]",
    "0.0.0.0",
    "10.",
    "192.168.",
    "172.16.",
    "169.254.",
    "[",
    "example.com",
    "example.org",
    "example.net",
    ".example",
    ".invalid",
    ".test",
    ".local",
    "attacker.com", // upnp URL validation fixture, never fetched
    "xmlns.ezrss.it",
    "a9.com", // XML namespace URIs
    "www.w3.org",
];

fn test_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            test_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs")
            && path.components().any(|c| c.as_os_str() == "tests")
        {
            out.push(path);
        }
    }
}

fn hosts(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for scheme in ["http://", "https://", "udp://", "ws://", "wss://"] {
        let mut rest = src;
        while let Some(i) = rest.find(scheme) {
            rest = &rest[i + scheme.len()..];
            let end = rest
                .find(['/', ':', '"', '\'', '?', '#', ' ', '\\', '{'])
                .unwrap_or(rest.len());
            if end > 0 {
                out.push(rest[..end].to_ascii_lowercase());
            }
        }
    }
    out
}

#[test]
fn integration_tests_never_name_an_external_host() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    test_files(&crates, &mut files);
    assert!(
        files.len() > 20,
        "scan found too few test files: {}",
        files.len()
    );

    let mut offenders = Vec::new();
    for f in files {
        if f.ends_with("synapse-engine/tests/no_external_network_guard.rs") {
            continue;
        }
        let src = std::fs::read_to_string(&f).unwrap_or_default();
        for h in hosts(&src) {
            let ok = ALLOWED
                .iter()
                .any(|a| h == *a || h.starts_with(a) || h.ends_with(a));
            if !ok {
                offenders.push(format!("{}: {h}", f.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "tests must not reference external hosts:\n{}",
        offenders.join("\n")
    );
}
