//! BEP 35 signed torrents.
//!
//! A signed `.torrent` has a top-level `signatures` dictionary. Each key names a signer in
//! reverse-DNS form (`com.example.releases`) and maps to a dictionary with
//!
//! * `certificate`: an optional DER X.509 certificate (omitted when the signer is a root the
//!   client already trusts),
//! * `info`: an optional dictionary that is signed along with the torrent's `info`,
//! * `signature`: the RSA signature.
//!
//! What is signed is the bencoded torrent `info` dictionary followed by the bencoded signature
//! `info` dictionary, when there is one. A certificate is trusted only if it is one of the
//! client's trust anchors or is directly signed by one (chains of more than one level are not
//! permitted). BEP 35 does not name the hash; SHA-256 and SHA-1 (RSASSA-PKCS1-v1_5) are tried.
//!
//! A signature made with a key that arrives inside the same torrent proves nothing about who
//! made it, so verification always reports whether the signer is *trusted*, separately from
//! whether the signature is mathematically valid.

use std::collections::BTreeMap;
use std::path::Path;

use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use synapse_bencode::BEncode;
use x509_cert::der::{AnyRef, Decode, DecodePem, Encode, Tag, Tagged};
use x509_cert::Certificate;

/// Signatures looked at per torrent, and the largest certificate / signature accepted.
const MAX_SIGNATURES: usize = 16;
const MAX_CERT_BYTES: usize = 16 * 1024;
const MAX_SIGNATURE_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorrentSignature {
    /// The signer's reverse-DNS name (the key in the `signatures` dictionary).
    pub name: String,
    pub certificate: Option<Vec<u8>>,
    /// The bencoded signature `info` dictionary, if any (it is part of the signed message).
    pub info: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}

/// Parses the `signatures` dictionary of a top-level `.torrent` dictionary. Malformed or
/// oversized entries are skipped.
pub fn parse_signatures(root_dict: &BTreeMap<Vec<u8>, BEncode>) -> Vec<TorrentSignature> {
    let Some(dict) = root_dict
        .get(b"signatures".as_ref())
        .and_then(BEncode::as_dict)
    else {
        return Vec::new();
    };
    dict.iter()
        .filter_map(|(name, entry)| {
            let entry = entry.as_dict()?;
            let signature = entry.get(b"signature".as_ref())?.as_bytes()?.clone();
            let certificate = entry
                .get(b"certificate".as_ref())
                .and_then(BEncode::as_bytes)
                .cloned();
            if signature.is_empty()
                || signature.len() > MAX_SIGNATURE_BYTES
                || certificate
                    .as_ref()
                    .is_some_and(|c| c.len() > MAX_CERT_BYTES)
            {
                return None;
            }
            let info = entry.get(b"info".as_ref()).map(|i| {
                let mut buf = Vec::new();
                let _ = i.encode(&mut buf);
                buf
            });
            Some(TorrentSignature {
                name: String::from_utf8_lossy(name).into_owned(),
                certificate,
                info,
                signature,
            })
        })
        .take(MAX_SIGNATURES)
        .collect()
}

/// Encodes signatures back into a top-level dictionary entry (for persisting a torrent).
pub fn encode_signatures(signatures: &[TorrentSignature]) -> Option<BEncode> {
    if signatures.is_empty() {
        return None;
    }
    let mut dict = BTreeMap::new();
    for s in signatures {
        let mut e = BTreeMap::new();
        e.insert(b"signature".to_vec(), BEncode::String(s.signature.clone()));
        if let Some(c) = &s.certificate {
            e.insert(b"certificate".to_vec(), BEncode::String(c.clone()));
        }
        if let Some(i) = s
            .info
            .as_deref()
            .and_then(|b| synapse_bencode::decode_buf(b).ok())
        {
            e.insert(b"info".to_vec(), i);
        }
        dict.insert(s.name.clone().into_bytes(), BEncode::Dict(e));
    }
    Some(BEncode::Dict(dict))
}

/// The outcome of checking one signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// The signature is valid and the signer is trusted.
    Trusted { signer: String },
    /// The signature is valid, but nothing ties the key to a signer we trust.
    Untrusted { reason: String },
    /// The signature does not verify (tampered torrent, wrong key, bad or expired certificate).
    Invalid { reason: String },
}

impl SignatureStatus {
    pub fn is_trusted(&self) -> bool {
        matches!(self, SignatureStatus::Trusted { .. })
    }
}

struct Anchor {
    name: Option<String>,
    key: RsaPublicKey,
    /// Present when the anchor is a certificate: it can vouch for certificates it issued.
    certificate: Option<Certificate>,
}

/// The signers a client trusts: certificates (or bare RSA public keys) it was given.
#[derive(Default)]
pub struct TrustStore {
    anchors: Vec<Anchor>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Trusts an X.509 certificate (DER). Its RSA key becomes a trust anchor, and certificates it
    /// signed are trusted too. `name` is the reverse-DNS name a certificate-less signature uses.
    pub fn add_certificate_der(&mut self, name: Option<String>, der: &[u8]) -> Result<(), String> {
        let cert =
            Certificate::from_der(der).map_err(|e| format!("not an X.509 certificate: {e}"))?;
        let key = certificate_key(&cert)?;
        self.anchors.push(Anchor {
            name,
            key,
            certificate: Some(cert),
        });
        Ok(())
    }

    /// Trusts a bare RSA public key (SPKI PEM), used by name for certificate-less signatures.
    pub fn add_public_key_pem(&mut self, name: String, pem: &str) -> Result<(), String> {
        let key = RsaPublicKey::from_public_key_pem(pem)
            .map_err(|e| format!("not an RSA public key: {e}"))?;
        self.anchors.push(Anchor {
            name: Some(name),
            key,
            certificate: None,
        });
        Ok(())
    }

    /// Loads every `.pem` / `.crt` / `.cer` / `.der` certificate (and `.pub` public key) in
    /// `dir`; the file stem is the signer name. Returns the store and a message per file that
    /// could not be used.
    pub fn load_dir(dir: &Path) -> (TrustStore, Vec<String>) {
        let mut store = TrustStore::new();
        let mut problems = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            problems.push(format!("cannot read trust directory {}", dir.display()));
            return (store, problems);
        };
        for entry in entries.flatten().take(1024) {
            let path = entry.path();
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase)
                .unwrap_or_default();
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_string);
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if bytes.len() > 64 * 1024 {
                continue;
            }
            let result = match ext.as_str() {
                "der" | "cer" => store.add_certificate_der(stem, &bytes),
                "pem" | "crt" => match Certificate::from_pem(&bytes) {
                    Ok(cert) => cert
                        .to_der()
                        .map_err(|e| e.to_string())
                        .and_then(|der| store.add_certificate_der(stem, &der)),
                    Err(e) => Err(format!("bad PEM certificate: {e}")),
                },
                "pub" => match (stem, std::str::from_utf8(&bytes)) {
                    (Some(name), Ok(pem)) => store.add_public_key_pem(name, pem),
                    _ => Err("unreadable public key".into()),
                },
                _ => continue,
            };
            if let Err(e) = result {
                problems.push(format!("{}: {e}", path.display()));
            }
        }
        (store, problems)
    }
}

fn certificate_key(cert: &Certificate) -> Result<RsaPublicKey, String> {
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| format!("bad public key info: {e}"))?;
    RsaPublicKey::from_public_key_der(&spki).map_err(|_| "certificate key is not RSA".to_string())
}

/// Verifies `signature` over `message` with `key` using SHA-256, SHA-384, or SHA-512 (SHA-1 is rejected).
fn rsa_verify(key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> bool {
    key.verify(
        Pkcs1v15Sign::new::<Sha256>(),
        &Sha256::digest(message),
        signature,
    )
    .is_ok()
        || key
            .verify(
                Pkcs1v15Sign::new::<Sha384>(),
                &Sha384::digest(message),
                signature,
            )
            .is_ok()
        || key
            .verify(
                Pkcs1v15Sign::new::<Sha512>(),
                &Sha512::digest(message),
                signature,
            )
            .is_ok()
}

/// Checks whether `cert` has `BasicConstraints` (`2.5.29.19`) with `cA == true` and, if
/// `KeyUsage` (`2.5.29.15`) is present, has the `keyCertSign` bit set.
fn is_ca_certificate(cert: &Certificate) -> bool {
    let Some(exts) = &cert.tbs_certificate.extensions else {
        return false;
    };
    let mut has_ca_basic_constraints = false;
    for ext in exts {
        match ext.extn_id.to_string().as_str() {
            // id-ce-basicConstraints (2.5.29.19): SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
            "2.5.29.19" => {
                let bytes = ext.extn_value.as_bytes();
                let Ok(any) = AnyRef::from_der(bytes) else {
                    return false;
                };
                if any.tag() != Tag::Sequence {
                    return false;
                }
                // SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
                // In DER, if cA is present and true, the inner value starts with 0x01 (Tag::Boolean), 0x01 (len), non-zero (0xFF in DER).
                let inner = any.value();
                if inner.len() < 3 || inner[0] != 0x01 || inner[1] != 0x01 || inner[2] == 0x00 {
                    return false;
                }
                has_ca_basic_constraints = true;
            }
            // id-ce-keyUsage (2.5.29.15): BIT STRING where bit 5 (0x04 in first content byte) is keyCertSign
            "2.5.29.15" => {
                let bytes = ext.extn_value.as_bytes();
                let Ok(any) = AnyRef::from_der(bytes) else {
                    return false;
                };
                if any.tag() != Tag::BitString {
                    return false;
                }
                let raw = any.value();
                // First byte is unused_bits count, second byte holds bits 0..7 (MSB first).
                // Bit 5 is mask 0x04 (`0b0000_0100`).
                if raw.len() < 2 || (raw[1] & 0x04) == 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    has_ca_basic_constraints
}

/// Extracts all Common Name (`2.5.4.3`) values and SubjectAltName (`2.5.29.17`) dNSName values from `cert`.
fn certificate_names(cert: &Certificate) -> Vec<String> {
    let mut names = Vec::new();
    for rdn in &cert.tbs_certificate.subject.0 {
        for atv in rdn.0.iter() {
            if atv.oid.to_string() == "2.5.4.3" {
                if let Ok(s) = std::str::from_utf8(atv.value.value()) {
                    names.push(s.to_string());
                }
            }
        }
    }
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.extn_id.to_string() == "2.5.29.17" {
                let bytes = ext.extn_value.as_bytes();
                if let Ok(any) = AnyRef::from_der(bytes) {
                    if any.tag() == Tag::Sequence {
                        let mut slice = any.value();
                        while !slice.is_empty() {
                            if let Ok(item) = AnyRef::from_der(slice) {
                                let item_len = item.to_der().map(|v| v.len()).unwrap_or(0);
                                if item_len == 0 || item_len > slice.len() {
                                    break;
                                }
                                slice = &slice[item_len..];
                                // dNSName is [2] IMPLICIT IA5String (context-specific tag 2 = 0x82)
                                if u8::from(item.tag()) == 0x82 {
                                    if let Ok(s) = std::str::from_utf8(item.value()) {
                                        names.push(s.to_string());
                                    }
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    names
}

fn certificate_matches_signer_name(cert: &Certificate, signer_name: &str) -> bool {
    certificate_names(cert).iter().any(|n| n == signer_name)
}

/// Whether `cert` is signed by `anchor`'s key, going by the certificate's own signature
/// algorithm (RSA with SHA-256, SHA-384 or SHA-512; SHA-1 is rejected), and `anchor` is a valid CA.
fn issued_by(cert: &Certificate, anchor: &Anchor) -> bool {
    let Some(anchor_cert) = &anchor.certificate else {
        return false;
    };
    if !is_ca_certificate(anchor_cert) {
        return false;
    }
    if cert.tbs_certificate.subject == cert.tbs_certificate.issuer {
        return false;
    }
    if cert.tbs_certificate.issuer != anchor_cert.tbs_certificate.subject {
        return false;
    }
    let Ok(tbs) = cert.tbs_certificate.to_der() else {
        return false;
    };
    let Some(sig) = cert.signature.as_bytes() else {
        return false;
    };
    match cert.signature_algorithm.oid.to_string().as_str() {
        "1.2.840.113549.1.1.11" => {
            anchor
                .key
                .verify(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&tbs), sig)
        }
        "1.2.840.113549.1.1.12" => {
            anchor
                .key
                .verify(Pkcs1v15Sign::new::<Sha384>(), &Sha384::digest(&tbs), sig)
        }
        "1.2.840.113549.1.1.13" => {
            anchor
                .key
                .verify(Pkcs1v15Sign::new::<Sha512>(), &Sha512::digest(&tbs), sig)
        }
        _ => return false,
    }
    .is_ok()
}

fn is_current(cert: &Certificate) -> bool {
    let validity = &cert.tbs_certificate.validity;
    let now = std::time::SystemTime::now();
    validity.not_before.to_system_time() <= now && now <= validity.not_after.to_system_time()
}

impl TorrentSignature {
    /// Checks this signature against the torrent's bencoded `info` dictionary (exactly as it
    /// appears in the file) and reports whether the signer is trusted.
    pub fn verify(&self, info_bytes: &[u8], trust: &TrustStore) -> SignatureStatus {
        let mut message = info_bytes.to_vec();
        if let Some(extra) = &self.info {
            message.extend_from_slice(extra);
        }
        let invalid = |reason: &str| SignatureStatus::Invalid {
            reason: reason.to_string(),
        };

        match &self.certificate {
            Some(der) => {
                let Ok(cert) = Certificate::from_der(der) else {
                    return invalid("the embedded certificate is not valid X.509");
                };
                let Ok(key) = certificate_key(&cert) else {
                    return invalid("the embedded certificate does not hold an RSA key");
                };
                if !is_current(&cert) {
                    return invalid("the signing certificate is expired or not yet valid");
                }
                if !rsa_verify(&key, &message, &self.signature) {
                    return invalid("the signature does not match the torrent");
                }
                let name_matches_cert = certificate_matches_signer_name(&cert, &self.name);
                // The signature is genuine for this key; now: is the key one we trust, and does the
                // signer identity match the certificate?
                let trusted = trust.anchors.iter().any(|a| {
                    let same = a
                        .certificate
                        .as_ref()
                        .is_some_and(|c| c.to_der().ok().as_deref() == Some(der.as_slice()))
                        && (name_matches_cert || a.name.as_deref().is_some_and(|n| n == self.name));
                    let issued = name_matches_cert && is_anchor_current(a) && issued_by(&cert, a);
                    same || issued
                });
                if trusted {
                    SignatureStatus::Trusted {
                        signer: self.name.clone(),
                    }
                } else if !name_matches_cert {
                    SignatureStatus::Untrusted {
                        reason: "valid signature, but the certificate subject does not match the signer name"
                            .into(),
                    }
                } else {
                    SignatureStatus::Untrusted {
                        reason: "valid signature, but the certificate is not signed by a trusted authority"
                            .into(),
                    }
                }
            }
            None => {
                // No certificate: the signer must be a root we already trust, found by name.
                let Some(anchor) = trust
                    .anchors
                    .iter()
                    .find(|a| a.name.as_deref() == Some(self.name.as_str()))
                else {
                    return SignatureStatus::Untrusted {
                        reason: format!("no certificate and no trusted key named '{}'", self.name),
                    };
                };
                if !is_anchor_current(anchor) {
                    return invalid("the trusted certificate has expired");
                }
                if rsa_verify(&anchor.key, &message, &self.signature) {
                    SignatureStatus::Trusted {
                        signer: self.name.clone(),
                    }
                } else {
                    invalid("the signature does not match the torrent")
                }
            }
        }
    }
}

fn is_anchor_current(a: &Anchor) -> bool {
    a.certificate.as_ref().is_none_or(is_current)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/bep35");

    fn read(name: &str) -> Vec<u8> {
        std::fs::read(format!("{DIR}/{name}")).unwrap()
    }

    fn signature(cert: Option<&str>, sig: &str, with_info: bool) -> TorrentSignature {
        TorrentSignature {
            name: "com.example.signer".into(),
            certificate: cert.map(read),
            info: with_info.then(|| read("siginfo.bin")),
            signature: read(sig),
        }
    }

    fn store_with_ca() -> TrustStore {
        let mut t = TrustStore::new();
        t.add_certificate_der(Some("test-root".into()), &read("ca.der"))
            .unwrap();
        t
    }

    #[test]
    fn a_leaf_signed_by_a_trusted_authority_verifies_as_trusted() {
        let s = signature(Some("leaf.der"), "sig_sha256.bin", true);
        assert_eq!(
            s.verify(&read("info.bin"), &store_with_ca()),
            SignatureStatus::Trusted {
                signer: "com.example.signer".into()
            }
        );
        // The SHA-1 variant is rejected.
        let s1 = signature(Some("leaf.der"), "sig_sha1.bin", true);
        assert!(matches!(
            s1.verify(&read("info.bin"), &store_with_ca()),
            SignatureStatus::Invalid { .. }
        ));
    }

    #[test]
    fn leaf_certificate_cannot_act_as_ca_and_cn_mismatch_is_rejected() {
        let leaf_cert = Certificate::from_der(&read("leaf.der")).unwrap();
        let ca_cert = Certificate::from_der(&read("ca.der")).unwrap();
        assert!(is_ca_certificate(&ca_cert));
        assert!(!is_ca_certificate(&leaf_cert));

        let mut leaf_store = TrustStore::new();
        leaf_store
            .add_certificate_der(Some("leaf-anchor".into()), &read("leaf.der"))
            .unwrap();
        assert!(!issued_by(&leaf_cert, &leaf_store.anchors[0]));
        assert!(!issued_by(&ca_cert, &leaf_store.anchors[0]));

        let mut wrong_name = signature(Some("leaf.der"), "sig_sha256.bin", true);
        wrong_name.name = "com.evil.impersonator".into();
        let status = wrong_name.verify(&read("info.bin"), &store_with_ca());
        assert!(
            !status.is_trusted(),
            "expected untrusted/invalid, got {status:?}"
        );
        assert!(matches!(
            status,
            SignatureStatus::Untrusted { .. } | SignatureStatus::Invalid { .. }
        ));
    }

    #[test]
    fn a_valid_signature_from_an_unknown_authority_is_untrusted_not_trusted() {
        let s = signature(Some("leaf.der"), "sig_sha256.bin", true);
        // Empty store, and a store holding an unrelated authority.
        assert!(matches!(
            s.verify(&read("info.bin"), &TrustStore::new()),
            SignatureStatus::Untrusted { .. }
        ));
        let mut other = TrustStore::new();
        other.add_certificate_der(None, &read("other.der")).unwrap();
        assert!(matches!(
            s.verify(&read("info.bin"), &other),
            SignatureStatus::Untrusted { .. }
        ));
    }

    #[test]
    fn tampering_and_wrong_keys_are_invalid() {
        let trust = store_with_ca();
        // The torrent's info changed after signing.
        let s = signature(Some("leaf.der"), "sig_sha256.bin", true);
        assert!(matches!(
            s.verify(b"d4:name5:otheree", &trust),
            SignatureStatus::Invalid { .. }
        ));
        // The extra signed dictionary is part of the message.
        let mut no_extra = signature(Some("leaf.der"), "sig_sha256.bin", true);
        no_extra.info = None;
        assert!(matches!(
            no_extra.verify(&read("info.bin"), &trust),
            SignatureStatus::Invalid { .. }
        ));
        // A signature by a key that is not the certificate's.
        let forged = signature(Some("leaf.der"), "sig_other.bin", true);
        assert!(matches!(
            forged.verify(&read("info.bin"), &trust),
            SignatureStatus::Invalid { .. }
        ));
        // Garbage certificate.
        let mut bad = signature(Some("leaf.der"), "sig_sha256.bin", true);
        bad.certificate = Some(vec![1, 2, 3]);
        assert!(matches!(
            bad.verify(&read("info.bin"), &trust),
            SignatureStatus::Invalid { .. }
        ));
    }

    #[test]
    fn a_signer_can_be_a_trusted_root_named_instead_of_embedded() {
        // The CA itself signs (no certificate in the torrent): trusted by name.
        let mut trust = TrustStore::new();
        trust
            .add_public_key_pem(
                "com.example.signer".into(),
                &String::from_utf8(read("ca_pub.pem")).unwrap(),
            )
            .unwrap();
        // sig_sha256.bin was made by the *leaf* key, not the CA's, so it must not verify as the CA.
        let s = signature(None, "sig_sha256.bin", true);
        assert!(matches!(
            s.verify(&read("info.bin"), &trust),
            SignatureStatus::Invalid { .. }
        ));
        // With nothing named, it is untrusted rather than invalid.
        assert!(matches!(
            s.verify(&read("info.bin"), &TrustStore::new()),
            SignatureStatus::Untrusted { .. }
        ));
    }

    #[test]
    fn signatures_parse_from_the_signatures_dictionary_and_round_trip() {
        let sig_entry = BTreeMap::from([
            (b"signature".to_vec(), BEncode::String(vec![7; 256])),
            (b"certificate".to_vec(), BEncode::String(read("leaf.der"))),
            (
                b"info".to_vec(),
                BEncode::Dict(BTreeMap::from([(b"foo".to_vec(), BEncode::Int(1))])),
            ),
        ]);
        let root = BTreeMap::from([(
            b"signatures".to_vec(),
            BEncode::Dict(BTreeMap::from([
                (b"com.example.signer".to_vec(), BEncode::Dict(sig_entry)),
                (b"broken".to_vec(), BEncode::Int(3)),
                (
                    b"oversized".to_vec(),
                    BEncode::Dict(BTreeMap::from([(
                        b"signature".to_vec(),
                        BEncode::String(vec![0; MAX_SIGNATURE_BYTES + 1]),
                    )])),
                ),
            ])),
        )]);
        let parsed = parse_signatures(&root);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "com.example.signer");
        assert_eq!(parsed[0].info.as_deref(), Some(&b"d3:fooi1ee"[..]));
        let encoded = encode_signatures(&parsed).unwrap();
        let back = parse_signatures(&BTreeMap::from([(b"signatures".to_vec(), encoded)]));
        assert_eq!(back, parsed);
    }

    #[test]
    fn a_trust_directory_loads_certificates_by_file_stem() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(
            format!("{DIR}/ca.pem"),
            dir.path().join("com.example.root.pem"),
        )
        .unwrap();
        std::fs::copy(format!("{DIR}/other.der"), dir.path().join("other.der")).unwrap();
        std::fs::write(dir.path().join("junk.pem"), b"not a certificate").unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"ignored").unwrap();
        let (store, problems) = TrustStore::load_dir(dir.path());
        assert_eq!(store.len(), 2);
        assert_eq!(problems.len(), 1, "{problems:?}");
        let s = signature(Some("leaf.der"), "sig_sha256.bin", true);
        assert!(s.verify(&read("info.bin"), &store).is_trusted());
    }
}
