//! BEP 35 BitTorrent Digital Signatures.
//!
//! Parses cryptographic signatures embedded in `.torrent` files for provenance validation.
//! Supports Ed25519 signature structures as well as standard X.509 certificate metadata.

use std::collections::BTreeMap;
use synapse_bencode::BEncode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorrentSignature {
    pub signature_type: String,
    pub signature: Vec<u8>,
    pub certificate: Option<Vec<u8>>,
}

/// Parses any BEP 35 signatures present in a top-level `.torrent` bencode dictionary.
pub fn parse_signatures(root_dict: &BTreeMap<Vec<u8>, BEncode>) -> Vec<TorrentSignature> {
    let mut signatures = Vec::new();

    // Check for "signatures" list
    if let Some(list) = root_dict.get(b"signatures".as_ref()).and_then(BEncode::as_list) {
        for item in list {
            if let Some(sig_dict) = item.as_dict() {
                if let Some(sig_bytes) = sig_dict.get(b"signature".as_ref()).and_then(BEncode::as_bytes) {
                    let sig_type = sig_dict
                        .get(b"signature-type".as_ref())
                        .and_then(BEncode::as_str)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "ed25519".to_string());
                    let cert = sig_dict
                        .get(b"certificate".as_ref())
                        .and_then(BEncode::as_bytes)
                        .cloned();

                    signatures.push(TorrentSignature {
                        signature_type: sig_type,
                        signature: sig_bytes.clone(),
                        certificate: cert,
                    });
                }
            }
        }
    }

    // Check for single "signature" field
    if let Some(sig_bytes) = root_dict.get(b"signature".as_ref()).and_then(BEncode::as_bytes) {
        signatures.push(TorrentSignature {
            signature_type: "ed25519".to_string(),
            signature: sig_bytes.clone(),
            certificate: None,
        });
    }

    signatures
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bep35_signatures_list() {
        let mut sig_dict = BTreeMap::new();
        sig_dict.insert(b"signature".to_vec(), BEncode::String(vec![0xAA; 64]));
        sig_dict.insert(b"signature-type".to_vec(), BEncode::String(b"ed25519".to_vec()));
        sig_dict.insert(b"certificate".to_vec(), BEncode::String(vec![0xCC; 32]));

        let mut root = BTreeMap::new();
        root.insert(b"signatures".to_vec(), BEncode::List(vec![BEncode::Dict(sig_dict)]));

        let parsed = parse_signatures(&root);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].signature_type, "ed25519");
        assert_eq!(parsed[0].signature, vec![0xAA; 64]);
        assert_eq!(parsed[0].certificate, Some(vec![0xCC; 32]));
    }
}
