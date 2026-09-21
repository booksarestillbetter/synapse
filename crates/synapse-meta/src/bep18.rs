//! BEP 18 search engine descriptions (`.btsearch` files).
//!
//! A `.btsearch` file is an OpenSearch description document: it names a search engine and gives
//! a URL template in which `{searchTerms}` stands for the URL-encoded query. The BEP says
//! nothing about the format of the results; torrent search engines return an RSS feed, which
//! [`crate::feed::parse_torrent_feed`] reads.

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

/// Longest description file accepted, and longest query built into a URL.
pub const MAX_DESCRIPTION_BYTES: usize = 64 * 1024;
pub const MAX_QUERY_CHARS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SearchItem {
    pub name: String,
    pub size: u64,
    pub seeds: u32,
    pub leechers: u32,
    pub info_hash: Option<[u8; 20]>,
    pub download_url: Option<String>,
    pub category: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SearchResponse {
    pub total_results: u32,
    pub items: Vec<SearchItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SearchEngineError {
    #[error("not an OpenSearch description document")]
    NotOpenSearch,
    #[error("the description is missing {0}")]
    Missing(&'static str),
    #[error("the URL template must be http or https and contain {{searchTerms}}")]
    BadTemplate,
    #[error("description is too large")]
    TooLarge,
}

/// A search engine described by a `.btsearch` file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SearchEngine {
    pub short_name: String,
    pub description: String,
    pub url_template: String,
}

impl SearchEngine {
    /// Parses a `.btsearch` (OpenSearch description) document.
    pub fn from_xml(xml: &str) -> Result<SearchEngine, SearchEngineError> {
        if xml.len() > MAX_DESCRIPTION_BYTES {
            return Err(SearchEngineError::TooLarge);
        }
        let mut reader = Reader::from_str(xml);
        let mut in_root = false;
        let mut field: Option<&'static str> = None;
        let (mut short_name, mut description, mut template) = (None, None, None);
        let mut text = String::new();
        loop {
            match reader.read_event() {
                Ok(Event::Start(e)) => {
                    let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                    if !in_root {
                        if name != "OpenSearchDescription" {
                            return Err(SearchEngineError::NotOpenSearch);
                        }
                        in_root = true;
                    } else {
                        field = match name.as_str() {
                            "ShortName" => Some("ShortName"),
                            "Description" => Some("Description"),
                            "Url" => {
                                take_template(&e, &mut template);
                                None
                            }
                            _ => None,
                        };
                        text.clear();
                    }
                }
                Ok(Event::Empty(e)) => {
                    if in_root && e.local_name().as_ref() == b"Url" {
                        take_template(&e, &mut template);
                    }
                }
                Ok(Event::Text(t)) => {
                    if field.is_some() {
                        if let Ok(s) = t.unescape() {
                            text.push_str(&s);
                        }
                    }
                }
                Ok(Event::End(_)) => {
                    match field.take() {
                        Some("ShortName") if short_name.is_none() => {
                            short_name = Some(text.trim().to_string())
                        }
                        Some("Description") if description.is_none() => {
                            description = Some(text.trim().to_string())
                        }
                        _ => {}
                    }
                    text.clear();
                }
                Ok(Event::Eof) | Err(_) => break,
                _ => {}
            }
        }
        if !in_root {
            return Err(SearchEngineError::NotOpenSearch);
        }
        let short_name = short_name
            .filter(|s| !s.is_empty())
            .ok_or(SearchEngineError::Missing("ShortName"))?;
        let template = template.ok_or(SearchEngineError::Missing("Url"))?;
        let parsed = url::Url::parse(&template.replace("{searchTerms}", "x"))
            .map_err(|_| SearchEngineError::BadTemplate)?;
        if !template.contains("{searchTerms}") || !matches!(parsed.scheme(), "http" | "https") {
            return Err(SearchEngineError::BadTemplate);
        }
        Ok(SearchEngine {
            short_name,
            description: description.unwrap_or_default(),
            url_template: template,
        })
    }

    /// The URL to fetch for `query`: the template with `{searchTerms}` replaced by the
    /// percent-encoded query.
    pub fn search_url(&self, query: &str) -> Result<url::Url, SearchEngineError> {
        let query: String = query.trim().chars().take(MAX_QUERY_CHARS).collect();
        let mut encoded = String::with_capacity(query.len() * 3);
        for b in query.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    encoded.push(b as char)
                }
                _ => encoded.push_str(&format!("%{b:02X}")),
            }
        }
        url::Url::parse(&self.url_template.replace("{searchTerms}", &encoded))
            .map_err(|_| SearchEngineError::BadTemplate)
    }
}

/// Records the `template` of a `<Url>` element, preferring one that returns RSS/Atom (the first
/// otherwise).
fn take_template(e: &BytesStart<'_>, slot: &mut Option<String>) {
    let attr = |name: &str| {
        e.attributes().flatten().find_map(|a| {
            (a.key.as_ref() == name.as_bytes())
                .then(|| a.unescape_value().ok().map(|v| v.into_owned()))
                .flatten()
        })
    };
    let Some(template) = attr("template") else {
        return;
    };
    let is_feed = attr("type").is_some_and(|t| t.contains("rss") || t.contains("atom"));
    if slot.is_none() || is_feed {
        *slot = Some(template);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BTSEARCH: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">
  <ShortName>Example Torrents</ShortName>
  <Description>Search the example tracker</Description>
  <Url type="text/html" template="https://example.org/html?q={searchTerms}"/>
  <Url type="application/rss+xml" template="https://example.org/rss?q={searchTerms}&amp;sort=seeds"/>
</OpenSearchDescription>"#;

    #[test]
    fn parses_a_btsearch_description_and_prefers_the_feed_url() {
        let engine = SearchEngine::from_xml(BTSEARCH).unwrap();
        assert_eq!(engine.short_name, "Example Torrents");
        assert_eq!(engine.description, "Search the example tracker");
        assert_eq!(
            engine.url_template,
            "https://example.org/rss?q={searchTerms}&sort=seeds"
        );
    }

    #[test]
    fn the_query_is_percent_encoded_into_the_template() {
        let engine = SearchEngine::from_xml(BTSEARCH).unwrap();
        let url = engine.search_url("ubuntu 24.04 & más").unwrap();
        assert_eq!(
            url.as_str(),
            "https://example.org/rss?q=ubuntu%2024.04%20%26%20m%C3%A1s&sort=seeds"
        );
        // A query cannot smuggle in extra parameters or a different host.
        let sneaky = engine.search_url("x&admin=1#@evil.example/").unwrap();
        assert_eq!(sneaky.host_str(), Some("example.org"));
        assert!(!sneaky.as_str().contains("admin=1&"));
        // And it is bounded.
        let long = engine.search_url(&"a".repeat(10_000)).unwrap();
        assert!(long.as_str().len() < 400);
    }

    #[test]
    fn descriptions_that_are_not_usable_are_rejected() {
        assert_eq!(
            SearchEngine::from_xml("<rss/>").unwrap_err(),
            SearchEngineError::NotOpenSearch
        );
        assert_eq!(
            SearchEngine::from_xml("not xml").unwrap_err(),
            SearchEngineError::NotOpenSearch
        );
        let no_url = "<OpenSearchDescription><ShortName>x</ShortName></OpenSearchDescription>";
        assert_eq!(
            SearchEngine::from_xml(no_url).unwrap_err(),
            SearchEngineError::Missing("Url")
        );
        let no_name = r#"<OpenSearchDescription><Url template="http://a/{searchTerms}"/></OpenSearchDescription>"#;
        assert_eq!(
            SearchEngine::from_xml(no_name).unwrap_err(),
            SearchEngineError::Missing("ShortName")
        );
        for bad in [
            "ftp://a/{searchTerms}",
            "http://a/nothing",
            "file:///{searchTerms}",
        ] {
            let xml = format!(
                r#"<OpenSearchDescription><ShortName>x</ShortName><Url template="{bad}"/></OpenSearchDescription>"#
            );
            assert_eq!(
                SearchEngine::from_xml(&xml).unwrap_err(),
                SearchEngineError::BadTemplate,
                "{bad}"
            );
        }
        assert_eq!(
            SearchEngine::from_xml(&" ".repeat(MAX_DESCRIPTION_BYTES + 1)).unwrap_err(),
            SearchEngineError::TooLarge
        );
    }
}
