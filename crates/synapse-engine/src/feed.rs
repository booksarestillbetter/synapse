//! BEP 36 Torrent RSS and Atom Feed Automation Manager.
//!
//! Provides scheduled and on-demand polling of RSS/Atom syndication feeds,
//! title pattern filtering, item deduplication, and automatic dispatch into the SwarmEngine.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use synapse_config::RssFeedConfig;
use synapse_meta::feed::{parse_torrent_feed, FeedItem};
use synapse_meta::Info;
use synapse_tracker::safe_http::{fetch, FetchOptions, LocalPolicy};
use url::Url;

const FEED_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_FEED_XML_BYTES: usize = 10 * 1024 * 1024; // 10 MiB
/// Torrents added from one feed in one poll; the rest wait for the next poll.
const MAX_ADDS_PER_POLL: usize = 50;
/// Failed downloads of one item before it is given up on.
const MAX_ITEM_ATTEMPTS: u32 = 5;
/// Items remembered as already handled (oldest forgotten first).
const MAX_SEEN_ITEMS: usize = 20_000;

/// Status snapshot of a configured RSS/Atom syndication feed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FeedStatus {
    pub url: String,
    pub name: Option<String>,
    pub auto_download: bool,
    pub filter: Option<String>,
    pub last_polled_at: Option<u64>,
    pub last_error: Option<String>,
    pub items_count: usize,
}

/// Manages syndicated torrent release feeds, periodic background polling, and auto-downloading.
#[derive(Debug)]
pub struct FeedManager {
    feeds: RwLock<Vec<RssFeedConfig>>,
    seen_items: RwLock<SeenItems>,
    /// Failed download attempts per item key.
    attempts: RwLock<HashMap<String, u32>>,
    status: RwLock<HashMap<String, FeedStatus>>,
    /// Feeds the operator removed over the API; configured feeds with these URLs stay removed.
    removed: RwLock<HashSet<String>>,
    state_path: RwLock<Option<PathBuf>>,
}

/// The items already handled, in insertion order so the oldest can be forgotten.
#[derive(Debug, Default)]
struct SeenItems {
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl SeenItems {
    fn contains(&self, key: &str) -> bool {
        self.set.contains(key)
    }

    fn insert(&mut self, key: String) {
        if self.set.insert(key.clone()) {
            self.order.push_back(key);
            while self.order.len() > MAX_SEEN_ITEMS {
                if let Some(old) = self.order.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }
}

/// What is saved between runs: handled items and the operator's feed changes.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct PersistedFeedState {
    #[serde(default)]
    seen: Vec<String>,
    #[serde(default)]
    feeds: Vec<RssFeedConfig>,
    #[serde(default)]
    removed: Vec<String>,
}

impl Default for FeedManager {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl FeedManager {
    /// Creates a new `FeedManager` with the specified initial feed configurations.
    pub fn new(feeds: Vec<RssFeedConfig>) -> Self {
        let mut status_map = HashMap::new();
        for f in &feeds {
            status_map.insert(
                f.url.clone(),
                FeedStatus {
                    url: f.url.clone(),
                    name: f.name.clone(),
                    auto_download: f.auto_download,
                    filter: f.filter.clone(),
                    last_polled_at: None,
                    last_error: None,
                    items_count: 0,
                },
            );
        }

        Self {
            feeds: RwLock::new(feeds),
            seen_items: RwLock::new(SeenItems::default()),
            attempts: RwLock::new(HashMap::new()),
            status: RwLock::new(status_map),
            removed: RwLock::new(HashSet::new()),
            state_path: RwLock::new(None),
        }
    }

    /// Keeps handled items and feed changes in `path`, loading what is already there. Feeds
    /// saved there (added over the API) are merged over the configured ones; configured feeds
    /// the operator removed stay removed.
    pub fn load_state(&self, path: PathBuf) {
        if let Some(state) = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<PersistedFeedState>(&b).ok())
        {
            {
                let mut seen = self.seen_items.write();
                for key in state.seen {
                    seen.insert(key);
                }
            }
            for url in &state.removed {
                self.remove_feed_internal(url);
            }
            *self.removed.write() = state.removed.into_iter().collect();
            for feed in state.feeds {
                self.add_feed_internal(feed);
            }
        }
        *self.state_path.write() = Some(path);
    }

    fn save_state(&self) {
        let Some(path) = self.state_path.read().clone() else {
            return;
        };
        let state = PersistedFeedState {
            seen: self.seen_items.read().order.iter().cloned().collect(),
            feeds: self.feeds.read().clone(),
            removed: self.removed.read().iter().cloned().collect(),
        };
        let Ok(bytes) = serde_json::to_vec(&state) else {
            return;
        };
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, bytes).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }

    /// Registers a new syndication feed. Replaces existing feed if matching URL is found.
    pub fn add_feed(&self, feed: RssFeedConfig) {
        // A feed the operator removed stays removed when the same URL is configured again at
        // startup; adding it explicitly clears that.
        self.removed.write().remove(&feed.url);
        self.add_feed_internal(feed);
        self.save_state();
    }

    /// Configuration-time registration: does not override an operator's removal.
    pub fn add_configured_feed(&self, feed: RssFeedConfig) {
        if !self.removed.read().contains(&feed.url) {
            self.add_feed_internal(feed);
        }
    }

    fn add_feed_internal(&self, feed: RssFeedConfig) {
        let mut feeds = self.feeds.write();
        if let Some(idx) = feeds.iter().position(|f| f.url == feed.url) {
            feeds[idx] = feed.clone();
        } else {
            feeds.push(feed.clone());
        }

        let mut status = self.status.write();
        status.insert(
            feed.url.clone(),
            FeedStatus {
                url: feed.url.clone(),
                name: feed.name.clone(),
                auto_download: feed.auto_download,
                filter: feed.filter.clone(),
                last_polled_at: None,
                last_error: None,
                items_count: 0,
            },
        );
    }

    /// Removes a syndication feed by its target URL. Returns true if found and removed.
    pub fn remove_feed(&self, url: &str) -> bool {
        let removed = self.remove_feed_internal(url);
        if removed {
            self.removed.write().insert(url.to_string());
            self.save_state();
        }
        removed
    }

    fn remove_feed_internal(&self, url: &str) -> bool {
        let mut feeds = self.feeds.write();
        let initial_len = feeds.len();
        feeds.retain(|f| f.url != url);
        self.status.write().remove(url);
        feeds.len() < initial_len
    }

    /// Returns a list of all current feed statuses.
    pub fn list_feeds(&self) -> Vec<FeedStatus> {
        self.status.read().values().cloned().collect()
    }

    /// Returns the active feed configurations.
    pub fn feed_configs(&self) -> Vec<RssFeedConfig> {
        self.feeds.read().clone()
    }

    /// Fetches and parses an RSS 2.0 or Atom XML feed from a remote URL.
    pub async fn fetch_and_parse_feed(url_str: &str) -> Result<Vec<FeedItem>, String> {
        let parsed_url =
            Url::parse(url_str).map_err(|e| format!("Invalid feed URL '{url_str}': {e}"))?;
        let opts = FetchOptions {
            timeout: FEED_TIMEOUT,
            max_body: MAX_FEED_XML_BYTES,
            user_agent: concat!("Synapse/", env!("CARGO_PKG_VERSION")),
            local: LocalPolicy::AllowAny,
            range: None,
        };

        let fetched = fetch(&parsed_url, &opts)
            .await
            .map_err(|e| format!("Network request failed: {e}"))?;

        if !(200..300).contains(&fetched.status) {
            return Err(format!(
                "Remote feed server returned HTTP {}",
                fetched.status
            ));
        }

        let xml_str = String::from_utf8_lossy(&fetched.body);
        let items = parse_torrent_feed(&xml_str);
        Ok(items)
    }

    /// Polls a single configured feed by URL, optionally auto-downloading matching releases.
    pub async fn poll_single_feed(
        &self,
        feed_url: &str,
        engine: &crate::swarm::SwarmEngine,
    ) -> Result<Vec<FeedItem>, String> {
        let feed = {
            let feeds = self.feeds.read();
            feeds
                .iter()
                .find(|f| f.url == feed_url)
                .cloned()
                .ok_or_else(|| format!("Feed with URL '{feed_url}' not found"))?
        };

        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match Self::fetch_and_parse_feed(&feed.url).await {
            Ok(items) => {
                let items_len = items.len();
                if let Some(st) = self.status.write().get_mut(&feed.url) {
                    st.last_polled_at = Some(now_sec);
                    st.last_error = None;
                    st.items_count = items_len;
                }

                self.process_feed_items(&feed, &items, engine).await;
                Ok(items)
            }
            Err(e) => {
                if let Some(st) = self.status.write().get_mut(&feed.url) {
                    st.last_polled_at = Some(now_sec);
                    st.last_error = Some(e.clone());
                }
                Err(e)
            }
        }
    }

    /// Polls all configured feeds, auto-adding new torrents matching configured filter criteria.
    pub async fn poll_all_feeds(
        &self,
        engine: &crate::swarm::SwarmEngine,
    ) -> Vec<Result<usize, String>> {
        let active_feeds = self.feeds.read().clone();
        let mut results = Vec::new();

        for feed in active_feeds {
            let res = self.poll_single_feed(&feed.url, engine).await;
            results.push(res.map(|items| items.len()));
        }

        results
    }

    /// Processes items from a feed: applies the filter and adds new releases (when the feed
    /// auto-downloads). An item is only remembered as handled once it was added or failed for
    /// good, so a transient failure is retried on the next poll; at most [`MAX_ADDS_PER_POLL`]
    /// torrents are added per poll.
    pub async fn process_feed_items(
        &self,
        feed: &RssFeedConfig,
        items: &[FeedItem],
        engine: &crate::swarm::SwarmEngine,
    ) -> usize {
        let mut added_count = 0;
        let mut changed = false;

        for item in items {
            if !feed.auto_download {
                break; // nothing is handled, so nothing is marked seen
            }
            if !matches_filter(&item.title, feed.filter.as_deref()) {
                continue;
            }
            let dedup_key = item_dedup_key(item);
            if self.seen_items.read().contains(&dedup_key) {
                continue;
            }
            if added_count >= MAX_ADDS_PER_POLL {
                break;
            }

            match resolve_torrent_from_item(item).await {
                Ok(info) => {
                    let info_hash = info.hash;
                    if let Err(e) = engine.check_signature_policy(&info) {
                        tracing::warn!(feed = %feed.url, title = %item.title, "BEP 36: not adding: {e}");
                        self.seen_items.write().insert(dedup_key);
                        changed = true;
                        continue;
                    }
                    if !engine.has_torrent(&info_hash) {
                        let download_dir = engine.settings().read().download_dir.clone();
                        tracing::info!(
                            feed = %feed.url,
                            title = %item.title,
                            hash = %hex::encode(info_hash),
                            "BEP 36: Automatically adding torrent from feed"
                        );
                        engine.add_torrent(Arc::new(info), download_dir, None);
                        added_count += 1;
                    }
                    self.seen_items.write().insert(dedup_key);
                    changed = true;
                }
                Err(e) => {
                    let attempts = {
                        let mut a = self.attempts.write();
                        let n = a.entry(dedup_key.clone()).or_insert(0);
                        *n += 1;
                        *n
                    };
                    tracing::warn!(
                        feed = %feed.url,
                        title = %item.title,
                        attempts,
                        "BEP 36: Failed to resolve torrent release from feed item: {e}"
                    );
                    if attempts >= MAX_ITEM_ATTEMPTS {
                        self.attempts.write().remove(&dedup_key);
                        self.seen_items.write().insert(dedup_key);
                        changed = true;
                    }
                }
            }
        }

        if changed {
            self.save_state();
        }
        added_count
    }
}

/// Checks whether an item's title matches the optional filter pattern (case-insensitive substring).
pub fn matches_filter(title: &str, filter: Option<&str>) -> bool {
    let Some(pat) = filter else {
        return true;
    };
    let trimmed = pat.trim();
    if trimmed.is_empty() {
        return true;
    }
    title.to_lowercase().contains(&trimmed.to_lowercase())
}

/// Generates a stable deduplication key for an RSS/Atom feed item.
pub fn item_dedup_key(item: &FeedItem) -> String {
    if let Some(ih) = item.info_hash {
        hex::encode(ih)
    } else if let Some(ref turl) = item.torrent_url {
        turl.clone()
    } else {
        item.link.clone()
    }
}

/// Resolves `synapse_meta::Info` metadata from a `FeedItem` link, torrent URL, or info_hash.
pub async fn resolve_torrent_from_item(item: &FeedItem) -> Result<Info, String> {
    // 1. Direct magnet fast-path
    if let Some(ref turl) = item.torrent_url {
        if turl.starts_with("magnet:?") {
            return Info::from_magnet(turl).map_err(|e| format!("Invalid magnet URI: {e}"));
        }
    }
    if item.link.starts_with("magnet:?") {
        return Info::from_magnet(&item.link).map_err(|e| format!("Invalid magnet URI: {e}"));
    }

    // 2. Info-hash fast-path
    if let Some(ih) = item.info_hash {
        let encoded_title: String =
            url::form_urlencoded::byte_serialize(item.title.as_bytes()).collect();
        let magnet = format!(
            "magnet:?xt=urn:btih:{}&dn={}",
            hex::encode(ih),
            encoded_title
        );
        return Info::from_magnet(&magnet).map_err(|e| format!("Invalid magnet URI: {e}"));
    }

    // 3. HTTP / HTTPS .torrent download
    let download_url = item.torrent_url.as_deref().unwrap_or(&item.link);
    if download_url.starts_with("http://") || download_url.starts_with("https://") {
        let parsed_url = Url::parse(download_url).map_err(|e| format!("Malformed URL: {e}"))?;
        let opts = FetchOptions {
            timeout: FEED_TIMEOUT,
            max_body: synapse_meta::MAX_TORRENT_FILE_BYTES,
            user_agent: concat!("Synapse/", env!("CARGO_PKG_VERSION")),
            // The URL comes from a remote feed, not from the operator: it must not be able to
            // aim the daemon at the local network.
            local: LocalPolicy::Deny,
            range: None,
        };

        let fetched = fetch(&parsed_url, &opts)
            .await
            .map_err(|e| format!("Failed to download torrent file: {e}"))?;

        if !(200..300).contains(&fetched.status) {
            return Err(format!("Remote server returned HTTP {}", fetched.status));
        }

        let bencode = synapse_bencode::decode_buf(&fetched.body)
            .map_err(|e| format!("Invalid bencode format: {e}"))?;
        return Info::from_bencode(bencode).map_err(|e| format!("Invalid .torrent metadata: {e}"));
    }

    Err("No valid download link, torrent URL, or info hash found in feed item".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feed_filter_matching() {
        assert!(matches_filter("Debian 12 Bookworm x86_64", None));
        assert!(matches_filter("Debian 12 Bookworm x86_64", Some("")));
        assert!(matches_filter("Debian 12 Bookworm x86_64", Some("debian")));
        assert!(matches_filter(
            "Debian 12 Bookworm x86_64",
            Some("BOOKWORM")
        ));
        assert!(!matches_filter("Ubuntu 24.04 LTS", Some("Debian")));
    }

    #[test]
    fn test_item_dedup_key() {
        let item1 = FeedItem {
            title: "Test 1".into(),
            link: "https://example.com/view/1".into(),
            torrent_url: Some("https://example.com/download/1.torrent".into()),
            enclosure_len: None,
            info_hash: Some([0xab; 20]),
            pub_date: None,
            ..Default::default()
        };
        assert_eq!(item_dedup_key(&item1), hex::encode([0xab; 20]));

        let item2 = FeedItem {
            title: "Test 2".into(),
            link: "https://example.com/view/2".into(),
            torrent_url: Some("https://example.com/download/2.torrent".into()),
            enclosure_len: None,
            info_hash: None,
            pub_date: None,
            ..Default::default()
        };
        assert_eq!(
            item_dedup_key(&item2),
            "https://example.com/download/2.torrent"
        );
    }

    #[test]
    fn test_feed_manager_crud() {
        let mgr = FeedManager::default();
        assert_eq!(mgr.list_feeds().len(), 0);

        mgr.add_feed(RssFeedConfig {
            url: "https://example.com/rss".into(),
            name: Some("Example Releases".into()),
            auto_download: true,
            filter: Some("1080p".into()),
        });

        assert_eq!(mgr.list_feeds().len(), 1);
        let status = &mgr.list_feeds()[0];
        assert_eq!(status.url, "https://example.com/rss");
        assert_eq!(status.name.as_deref(), Some("Example Releases"));
        assert!(status.auto_download);

        assert!(mgr.remove_feed("https://example.com/rss"));
        assert_eq!(mgr.list_feeds().len(), 0);
    }
}
