//! BEP 18 search: the engines the operator configured (`.btsearch` files) and queries to them.
//!
//! An engine's URL template comes from a file or URL the operator supplied, so it may point at
//! a LAN indexer; redirects from a public origin to a private one are still refused by
//! [`synapse_tracker::safe_http`]. Results are RSS/Atom feeds, read with the BEP 36 parser.

use std::time::Duration;

use parking_lot::RwLock;
use synapse_meta::bep18::{SearchEngine, MAX_DESCRIPTION_BYTES};
use synapse_meta::feed::{parse_torrent_feed, FeedItem};
use synapse_meta::SearchItem;
use synapse_tracker::safe_http::{fetch, FetchOptions, LocalPolicy};

/// Engines kept, results read per engine, and how long a search may take.
const MAX_ENGINES: usize = 16;
const MAX_RESULTS_PER_ENGINE: usize = 200;
const MAX_RESULT_BYTES: usize = 2 * 1024 * 1024;
const SEARCH_TIMEOUT: Duration = Duration::from_secs(15);

fn options(max_body: usize) -> FetchOptions {
    FetchOptions {
        timeout: SEARCH_TIMEOUT,
        max_body,
        user_agent: concat!("Synapse/", env!("CARGO_PKG_VERSION")),
        local: LocalPolicy::AllowAny,
        range: None,
    }
}

/// One engine's answer to a query.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EngineResults {
    pub engine: String,
    pub error: Option<String>,
    pub results: Vec<SearchItem>,
}

#[derive(Debug, Default)]
pub struct SearchManager {
    /// `(where it was loaded from, the engine)`.
    engines: RwLock<Vec<(String, SearchEngine)>>,
}

impl SearchManager {
    /// Loads a `.btsearch` description from a file path or an http(s) URL and registers it,
    /// replacing an engine of the same name.
    pub async fn add_source(&self, source: &str) -> Result<SearchEngine, String> {
        let text = if source.starts_with("http://") || source.starts_with("https://") {
            let url = url::Url::parse(source).map_err(|e| format!("bad URL: {e}"))?;
            let fetched = fetch(&url, &options(MAX_DESCRIPTION_BYTES))
                .await
                .map_err(|e| format!("could not fetch the description: {e}"))?;
            if !(200..300).contains(&fetched.status) {
                return Err(format!("the server answered HTTP {}", fetched.status));
            }
            String::from_utf8_lossy(&fetched.body).into_owned()
        } else {
            let bytes = tokio::fs::read(source)
                .await
                .map_err(|e| format!("could not read {source}: {e}"))?;
            if bytes.len() > MAX_DESCRIPTION_BYTES {
                return Err("description is too large".into());
            }
            String::from_utf8_lossy(&bytes).into_owned()
        };
        let engine = SearchEngine::from_xml(&text).map_err(|e| e.to_string())?;
        let mut engines = self.engines.write();
        engines.retain(|(_, e)| e.short_name != engine.short_name);
        if engines.len() >= MAX_ENGINES {
            return Err(format!(
                "at most {MAX_ENGINES} search engines can be configured"
            ));
        }
        engines.push((source.to_string(), engine.clone()));
        Ok(engine)
    }

    pub fn remove(&self, name: &str) -> bool {
        let mut engines = self.engines.write();
        let before = engines.len();
        engines.retain(|(_, e)| e.short_name != name);
        engines.len() < before
    }

    pub fn list(&self) -> Vec<SearchEngine> {
        self.engines.read().iter().map(|(_, e)| e.clone()).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.engines.read().is_empty()
    }

    /// Queries every engine (or just `only`, by name) at once.
    pub async fn search(&self, query: &str, only: Option<&str>) -> Vec<EngineResults> {
        let engines: Vec<SearchEngine> = self
            .engines
            .read()
            .iter()
            .map(|(_, e)| e.clone())
            .filter(|e| only.is_none_or(|n| e.short_name == n))
            .collect();
        let searches = engines.into_iter().map(|engine| async move {
            let name = engine.short_name.clone();
            match query_engine(&engine, query).await {
                Ok(results) => EngineResults {
                    engine: name,
                    error: None,
                    results,
                },
                Err(error) => EngineResults {
                    engine: name,
                    error: Some(error),
                    results: Vec::new(),
                },
            }
        });
        futures::future::join_all(searches).await
    }
}

async fn query_engine(engine: &SearchEngine, query: &str) -> Result<Vec<SearchItem>, String> {
    let url = engine.search_url(query).map_err(|e| e.to_string())?;
    let fetched = fetch(&url, &options(MAX_RESULT_BYTES))
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if !(200..300).contains(&fetched.status) {
        return Err(format!("the engine answered HTTP {}", fetched.status));
    }
    let xml = String::from_utf8_lossy(&fetched.body);
    Ok(parse_torrent_feed(&xml)
        .into_iter()
        .take(MAX_RESULTS_PER_ENGINE)
        .map(item_to_result)
        .collect())
}

fn item_to_result(item: FeedItem) -> SearchItem {
    SearchItem {
        name: item.title,
        size: item.enclosure_len.unwrap_or(0),
        seeds: item.seeds.unwrap_or(0),
        leechers: item.peers.unwrap_or(0),
        info_hash: item.info_hash,
        download_url: item.torrent_url.or(item.magnet),
        category: None,
    }
}
