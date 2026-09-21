//! BEP 35: a daemon configured to require trusted signatures accepts only torrents whose
//! signature verifies against a trusted signer. The certificates and signatures are produced
//! by OpenSSL (see `synapse-meta/tests/data/bep35`), not by our own code.

use std::collections::BTreeMap;
use std::sync::Arc;

use diskio::DiskEngine;
use synapse_bencode::BEncode;
use synapse_engine::SwarmEngine;
use synapse_meta::{Info, TrustStore};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../synapse-meta/tests/data/bep35"
);

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}/{name}")).unwrap()
}

fn torrent(info: &[u8], signature_file: Option<&str>) -> Info {
    let mut root = BTreeMap::from([(b"info".to_vec(), synapse_bencode::decode_buf(info).unwrap())]);
    if let Some(sig) = signature_file {
        let entry = BTreeMap::from([
            (b"certificate".to_vec(), BEncode::String(read("leaf.der"))),
            (b"signature".to_vec(), BEncode::String(read(sig))),
            (
                b"info".to_vec(),
                synapse_bencode::decode_buf(&read("siginfo.bin")).unwrap(),
            ),
        ]);
        root.insert(
            b"signatures".to_vec(),
            BEncode::Dict(BTreeMap::from([(
                b"com.example.signer".to_vec(),
                BEncode::Dict(entry),
            )])),
        );
    }
    Info::from_bencode(BEncode::Dict(root)).unwrap()
}

fn trust_ca() -> TrustStore {
    let mut t = TrustStore::new();
    t.add_certificate_der(Some("root".into()), &read("ca.der"))
        .unwrap();
    t
}

#[tokio::test]
async fn only_torrents_signed_by_a_trusted_signer_are_accepted() {
    let disk = Arc::new(DiskEngine::auto().await);
    let strict = SwarmEngine::new(disk.clone(), [1; 20]).with_signature_policy(trust_ca(), true);
    let info = read("info.bin");

    assert!(strict
        .check_signature_policy(&torrent(&info, Some("sig_sha256.bin")))
        .is_ok());
    assert!(strict
        .check_signature_policy(&torrent(&info, None))
        .unwrap_err()
        .contains("not signed"));
    // Signed by a key that is not the certificate's.
    assert!(strict
        .check_signature_policy(&torrent(&info, Some("sig_other.bin")))
        .is_err());
    // A different torrent carrying a genuine signature made for another one.
    let mut other_info = info.clone();
    let name_at = other_info.windows(4).position(|w| w == b"test").unwrap();
    other_info[name_at..name_at + 4].copy_from_slice(b"evil");
    assert!(strict
        .check_signature_policy(&torrent(&other_info, Some("sig_sha256.bin")))
        .is_err());
    // A correct signature, but the daemon trusts nobody.
    let nobody =
        SwarmEngine::new(disk.clone(), [2; 20]).with_signature_policy(TrustStore::new(), true);
    assert!(nobody
        .check_signature_policy(&torrent(&info, Some("sig_sha256.bin")))
        .is_err());
    // Without the requirement, everything is accepted (signatures are informational).
    let lax = SwarmEngine::new(disk, [3; 20]);
    assert!(lax.check_signature_policy(&torrent(&info, None)).is_ok());
}

#[tokio::test]
async fn a_held_torrents_signature_status_is_reported() {
    let disk = Arc::new(DiskEngine::auto().await);
    let engine = SwarmEngine::new(disk, [4; 20]).with_signature_policy(trust_ca(), false);
    let dir = tempfile::tempdir().unwrap();
    let signed = torrent(&read("info.bin"), Some("sig_sha256.bin"));
    let hash = signed.hash;
    engine.add_torrent(Arc::new(signed), dir.path().to_path_buf(), None);
    let statuses = engine.torrent_signatures(&hash).unwrap();
    assert_eq!(statuses.len(), 1);
    assert!(statuses[0].1.is_trusted());
}
