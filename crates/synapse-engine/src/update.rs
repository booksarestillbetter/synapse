//! BEP 39: updating torrents via the feed URL in their info dictionary.
//!
//! A torrent may carry an `update-url`. Asking it (with an `info_hash` parameter naming the torrent
//! we hold) yields a newer `.torrent`, or not; a valid torrent with a different info hash means
//! there is an update. The URL comes from the torrent, so it is untrusted: it is fetched with the
//! local network off limits, and the answer is size-bounded and parsed like any torrent.
//!
//! An update is added automatically only when the new torrent is signed (BEP 35) with the
//! certificate the old one names as its `originator`; otherwise it waits for the operator to
//! apply it. Once a torrent has an update its feed is not asked again.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use synapse_meta::Info;
use synapse_tracker::safe_http::{fetch, FetchOptions, LocalPolicy};

const UPDATE_TIMEOUT: Duration = Duration::from_secs(20);
/// Feeds asked per pass, so a daemon with thousands of torrents does not stampede.
const MAX_CHECKS_PER_PASS: usize = 200;

/// An update found for a torrent we hold.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PendingUpdate {
    pub old_info_hash: String,
    pub new_info_hash: String,
    pub new_name: String,
    /// Signed by the originator the old torrent names, so it may be applied automatically.
    pub signed_by_originator: bool,
    #[serde(skip)]
    pub new_info: Option<Arc<Info>>,
}

#[derive(Default)]
pub struct UpdateManager {
    pending: RwLock<HashMap<[u8; 20], PendingUpdate>>,
    /// Old torrents whose feed is no longer asked (an update was found and handled).
    settled: RwLock<HashSet<[u8; 20]>>,
}

impl UpdateManager {
    pub fn pending(&self) -> Vec<PendingUpdate> {
        self.pending.read().values().cloned().collect()
    }

    pub fn take_pending(&self, old: &[u8; 20]) -> Option<PendingUpdate> {
        self.pending.write().remove(old)
    }

    pub(crate) fn is_settled(&self, hash: &[u8; 20]) -> bool {
        self.settled.read().contains(hash) || self.pending.read().contains_key(hash)
    }

    pub fn settle(&self, old: [u8; 20]) {
        self.settled.write().insert(old);
    }

    pub(crate) fn record(&self, old: [u8; 20], update: PendingUpdate) {
        self.pending.write().insert(old, update);
    }
}

/// The URL to ask: the torrent's `update-url` with our `info_hash` added as a query parameter.
pub fn update_request_url(update_url: &str, info_hash: &[u8; 20]) -> Option<url::Url> {
    let mut url = url::Url::parse(update_url).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    url.query_pairs_mut()
        .append_pair("info_hash", &hex::encode(info_hash));
    Some(url)
}

/// Asks one torrent's update feed. `Ok(None)`: no update. `Ok(Some(info))`: a valid torrent
/// with a different info hash.
pub async fn fetch_update(update_url: &str, current: &[u8; 20]) -> Result<Option<Info>, String> {
    let url = update_request_url(update_url, current).ok_or("unusable update-url")?;
    let opts = FetchOptions {
        timeout: UPDATE_TIMEOUT,
        max_body: synapse_meta::MAX_TORRENT_FILE_BYTES,
        user_agent: concat!("Synapse/", env!("CARGO_PKG_VERSION")),
        local: LocalPolicy::Deny,
        range: None,
    };
    let fetched = fetch(&url, &opts).await.map_err(|e| e.to_string())?;
    if fetched.status != 200 {
        return Ok(None);
    }
    let Ok(bencode) = synapse_bencode::decode_buf(&fetched.body) else {
        return Ok(None);
    };
    let Ok(info) = Info::from_bencode(bencode) else {
        return Ok(None);
    };
    Ok((info.hash != *current).then_some(info))
}

/// Whether `new` carries a valid signature made with the certificate `old` names as its
/// originator (BEP 39). The certificate is trusted because the operator chose to add `old`.
pub fn signed_by_originator(old: &Info, new: &Info, trust: &synapse_meta::TrustStore) -> bool {
    let Some(originator) = old.originator.as_deref() else {
        return false;
    };
    let Some(raw) = new.raw_info.as_deref() else {
        return false;
    };
    new.signatures.iter().any(|sig| {
        sig.certificate.as_deref() == Some(originator)
            && !matches!(
                sig.verify(raw, trust),
                synapse_meta::SignatureStatus::Invalid { .. }
            )
    })
}

impl crate::swarm::SwarmEngine {
    pub fn update_manager(&self) -> &Arc<UpdateManager> {
        &self.update_manager
    }

    /// One pass over the torrents that have an `update-url`: ask each feed, add updates signed
    /// by the originator, and remember the rest for the operator. Returns how many updates
    /// were found.
    pub async fn check_for_updates(&self) -> usize {
        let candidates: Vec<Arc<Info>> = self
            .list_handles()
            .into_iter()
            .map(|h| h.info.clone())
            .filter(|i| i.update_url.is_some())
            .filter(|i| !self.update_manager.is_settled(&i.hash))
            .take(MAX_CHECKS_PER_PASS)
            .collect();
        let mut found = 0;
        for old in candidates {
            let Some(url) = old.update_url.as_deref() else {
                continue;
            };
            match fetch_update(url, &old.hash).await {
                Ok(Some(new)) => {
                    found += 1;
                    let trust_signed = {
                        let policy_ok = self.check_signature_policy(&new).is_ok();
                        policy_ok && self.signed_by_originator(&old, &new)
                    };
                    tracing::info!(
                        name = %old.name,
                        new = %hex::encode(new.hash),
                        auto = trust_signed,
                        "BEP 39: an update is available"
                    );
                    let new = Arc::new(new);
                    let update = PendingUpdate {
                        old_info_hash: hex::encode(old.hash),
                        new_info_hash: hex::encode(new.hash),
                        new_name: new.name.clone(),
                        signed_by_originator: trust_signed,
                        new_info: Some(new.clone()),
                    };
                    if trust_signed {
                        self.apply_update_info(&old.hash, new);
                    } else {
                        self.update_manager.record(old.hash, update);
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::debug!(name = %old.name, "BEP 39: update check failed: {e}"),
            }
        }
        found
    }

    /// Adds the new torrent next to the old one (in the same directory) and stops asking the
    /// old one's feed. The old torrent is left alone: its data is what the new one reuses.
    fn apply_update_info(&self, old: &[u8; 20], new: Arc<Info>) {
        let dir = self
            .get_torrent(old)
            .map(|h| std::path::PathBuf::from(&h.stats.read().download_dir))
            .unwrap_or_else(|| self.settings().read().download_dir.clone());
        if !self.has_torrent(&new.hash) {
            self.add_torrent(new, dir, None);
        }
        self.update_manager.settle(*old);
    }

    /// Applies an update the operator approved. `false` if there is none pending for `old`.
    pub fn apply_pending_update(&self, old: &[u8; 20]) -> bool {
        let Some(update) = self.update_manager.take_pending(old) else {
            return false;
        };
        match update.new_info {
            Some(info) => {
                self.apply_update_info(old, info);
                true
            }
            None => false,
        }
    }

    fn signed_by_originator(&self, old: &Info, new: &Info) -> bool {
        self.with_trust_store(|trust| signed_by_originator(old, new, trust))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_adds_the_info_hash_to_the_update_url() {
        let url = update_request_url("https://feed.example/u?channel=stable", &[0xAB; 20]).unwrap();
        assert_eq!(
            url.as_str(),
            format!(
                "https://feed.example/u?channel=stable&info_hash={}",
                "ab".repeat(20)
            )
        );
        assert!(update_request_url("ftp://x/y", &[0; 20]).is_none());
        assert!(update_request_url("not a url", &[0; 20]).is_none());
    }

    const DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../synapse-meta/tests/data/bep35"
    );

    fn read(name: &str) -> Vec<u8> {
        std::fs::read(format!("{DIR}/{name}")).unwrap()
    }

    /// A torrent whose info dict is `info.bin` (as signed by the fixtures), optionally with the
    /// signature made with the certificate `leaf.der`.
    fn torrent(signed: bool, extra_info: Option<(&[u8], synapse_bencode::BEncode)>) -> Info {
        use synapse_bencode::BEncode;
        let mut info = match synapse_bencode::decode_buf(&read("info.bin")).unwrap() {
            BEncode::Dict(d) => d,
            _ => unreachable!(),
        };
        if let Some((k, v)) = extra_info {
            info.insert(k.to_vec(), v);
        }
        let mut root = std::collections::BTreeMap::from([(b"info".to_vec(), BEncode::Dict(info))]);
        if signed {
            let entry = std::collections::BTreeMap::from([
                (b"certificate".to_vec(), BEncode::String(read("leaf.der"))),
                (
                    b"signature".to_vec(),
                    BEncode::String(read("sig_sha256.bin")),
                ),
                (
                    b"info".to_vec(),
                    synapse_bencode::decode_buf(&read("siginfo.bin")).unwrap(),
                ),
            ]);
            root.insert(
                b"signatures".to_vec(),
                BEncode::Dict(std::collections::BTreeMap::from([(
                    b"com.example.signer".to_vec(),
                    BEncode::Dict(entry),
                )])),
            );
        }
        Info::from_bencode(BEncode::Dict(root)).unwrap()
    }

    #[test]
    fn update_url_and_originator_are_read_from_the_info_dict() {
        use synapse_bencode::BEncode;
        let old = torrent(
            false,
            Some((
                b"update-url",
                BEncode::String(b"https://feed.example/u".to_vec()),
            )),
        );
        assert_eq!(old.update_url.as_deref(), Some("https://feed.example/u"));
        // Only http(s) URLs are kept.
        let bad = torrent(
            false,
            Some((
                b"update-url",
                BEncode::String(b"file:///etc/passwd".to_vec()),
            )),
        );
        assert_eq!(bad.update_url, None);
        // The extra keys are part of the identity, and survive persistence.
        assert_ne!(old.hash, torrent(false, None).hash);
        let back = Info::from_persisted_bencode(
            synapse_bencode::decode_buf(&old.to_torrent_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(back.hash, old.hash);
        assert_eq!(back.update_url, old.update_url);
    }

    #[test]
    fn only_a_signature_by_the_named_originator_allows_automatic_updates() {
        use synapse_bencode::BEncode;
        let trust = synapse_meta::TrustStore::new();
        // The originator of the old torrent is the certificate that signs the new one.
        let old = torrent(
            false,
            Some((b"originator", BEncode::String(read("leaf.der")))),
        );
        // `torrent(true, ..)`'s signature covers info.bin exactly, so build it without extras.
        let signed_new = torrent(true, None);
        assert!(signed_by_originator(&old, &signed_new, &trust));
        // Unsigned update, or an old torrent that names no / another originator: not automatic.
        assert!(!signed_by_originator(&old, &torrent(false, None), &trust));
        let other = torrent(
            false,
            Some((b"originator", BEncode::String(read("other.der")))),
        );
        assert!(!signed_by_originator(&other, &signed_new, &trust));
        assert!(!signed_by_originator(
            &torrent(false, None),
            &signed_new,
            &trust
        ));
        // A signature that does not verify for the torrent is not accepted even with the right cert.
        let mut tampered = torrent(true, None);
        tampered.raw_info = Some(Arc::new(b"d4:name5:otheree".to_vec()));
        assert!(!signed_by_originator(&old, &tampered, &trust));
    }

    #[tokio::test]
    async fn an_update_feed_on_the_local_network_is_never_asked() {
        // The URL comes from the torrent, so the loopback address must be refused outright.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/feed", listener.local_addr().unwrap());
        let accepted = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(500), listener.accept())
                .await
                .is_ok()
        });
        let result = fetch_update(&url, &[1; 20]).await;
        assert!(result.is_err(), "{result:?}");
        assert!(
            !accepted.await.unwrap(),
            "the local server must not have been contacted"
        );
    }

    #[tokio::test]
    async fn an_approved_update_is_added_and_the_old_feed_is_settled() {
        use synapse_bencode::BEncode;
        let disk = Arc::new(diskio::DiskEngine::auto().await);
        let engine = crate::swarm::SwarmEngine::new(disk, [1; 20]);
        let dir = tempfile::tempdir().unwrap();
        let old = Arc::new(torrent(
            false,
            Some((
                b"update-url",
                BEncode::String(b"https://feed.example/u".to_vec()),
            )),
        ));
        let new = Arc::new(torrent(true, None));
        engine.add_torrent(old.clone(), dir.path().to_path_buf(), None);
        engine.update_manager().record(
            old.hash,
            PendingUpdate {
                old_info_hash: hex::encode(old.hash),
                new_info_hash: hex::encode(new.hash),
                new_name: new.name.clone(),
                signed_by_originator: false,
                new_info: Some(new.clone()),
            },
        );
        assert_eq!(engine.update_manager().pending().len(), 1);
        assert!(!engine.apply_pending_update(&[9; 20]));
        assert!(engine.apply_pending_update(&old.hash));
        assert!(engine.has_torrent(&new.hash));
        assert!(engine.update_manager().pending().is_empty());
        assert!(
            engine.update_manager().is_settled(&old.hash),
            "its feed is no longer asked"
        );
    }
}
