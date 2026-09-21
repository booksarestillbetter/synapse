//! BEP 36 Torrent RSS and Atom feed parser.
//!
//! Parses syndicated torrent release feeds (RSS 2.0 and Atom) with a real XML parser, so
//! entities (`&amp;` in a URL) and CDATA are decoded, comments and namespaces are handled, and
//! nothing depends on how the publisher formatted the markup. Feeds are untrusted input:
//! the number of items and the length of every field are bounded.
//!
//! Besides `title`, `link`, `enclosure` and the publication date, BEP 36's torrent-namespace
//! elements are read: `infoHash`, `magnetURI`, `contentLength`, `seeds` and `peers`.

use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::Reader;

/// Items read from one feed, and the longest text kept for any field.
const MAX_ITEMS: usize = 5000;
const MAX_FIELD_BYTES: usize = 8 * 1024;
/// Element nesting deeper than this is not a feed.
const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FeedItem {
    pub title: String,
    pub link: String,
    pub torrent_url: Option<String>,
    pub enclosure_len: Option<u64>,
    pub info_hash: Option<[u8; 20]>,
    pub pub_date: Option<String>,
    /// `torrent:magnetURI`.
    pub magnet: Option<String>,
    /// `torrent:seeds` / `torrent:peers`.
    pub seeds: Option<u32>,
    pub peers: Option<u32>,
}

/// Parses an RSS 2.0 or Atom document into its items. A document that is not well-formed XML
/// yields the items read before the error.
pub fn parse_torrent_feed(xml: &str) -> Vec<FeedItem> {
    let mut reader = Reader::from_str(xml);
    let mut items = Vec::new();
    let mut current: Option<FeedItem> = None;
    let mut field: Option<String> = None;
    let mut text = String::new();
    let mut depth = 0usize;

    while let Ok(event) = reader.read_event() {
        match event {
            Event::Start(e) => {
                depth += 1;
                if depth > MAX_DEPTH {
                    break;
                }
                let name = local_name(&e);
                if current.is_none() {
                    if name == "item" || name == "entry" {
                        current = Some(FeedItem::default());
                    }
                } else {
                    if let Some(item) = current.as_mut() {
                        read_attributes(&name, &e, item);
                    }
                    field = Some(name);
                    text.clear();
                }
            }
            Event::Empty(e) => {
                if let Some(item) = current.as_mut() {
                    let name = local_name(&e);
                    read_attributes(&name, &e, item);
                }
            }
            Event::Text(t) => {
                if field.is_some() && text.len() < MAX_FIELD_BYTES {
                    text.push_str(&t.xml10_content());
                }
            }
            // `&amp;`, `&#x26;` and friends arrive as their own events.
            Event::GeneralRef(r) => {
                if field.is_some() && text.len() < MAX_FIELD_BYTES {
                    append_entity(&mut text, &r);
                }
            }
            Event::CData(c) => {
                if field.is_some() && text.len() < MAX_FIELD_BYTES {
                    text.push_str(&c.xml10_content());
                }
            }
            Event::End(e) => {
                depth = depth.saturating_sub(1);
                let name = e.local_name().as_ref().to_string();
                if let Some(item) = current.as_mut() {
                    if field.as_deref() == Some(name.as_str()) {
                        let value = text
                            .trim()
                            .chars()
                            .take(MAX_FIELD_BYTES)
                            .collect::<String>();
                        assign(&name, value, item);
                        field = None;
                        text.clear();
                    } else if name == "item" || name == "entry" {
                        let mut finished = current.take().unwrap_or_default();
                        // A link that is itself a torrent or magnet stands in for a missing enclosure.
                        if finished.torrent_url.is_none()
                            && (finished.link.ends_with(".torrent")
                                || finished.link.starts_with("magnet:?"))
                        {
                            finished.torrent_url = Some(finished.link.clone());
                        }
                        if finished.torrent_url.is_none() {
                            finished.torrent_url = finished.magnet.clone();
                        }
                        if !(finished.title.is_empty()
                            && finished.link.is_empty()
                            && finished.torrent_url.is_none()
                            && finished.info_hash.is_none())
                        {
                            items.push(finished);
                            if items.len() >= MAX_ITEMS {
                                break;
                            }
                        }
                        field = None;
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    items
}

/// The element name without its namespace prefix (`torrent:infoHash` -> `infoHash`).
fn local_name(e: &BytesStart<'_>) -> String {
    e.local_name().as_ref().to_string()
}

/// Appends what an entity reference stands for: the five predefined entities and numeric
/// character references. Anything else (a custom entity from a DTD, which is never defined here)
/// is dropped, so a document cannot expand into more than it says.
pub(crate) fn append_entity(text: &mut String, entity: &BytesRef<'_>) {
    if let Ok(Some(ch)) = entity.resolve_char_ref() {
        text.push(ch);
    } else if let Some(s) = quick_xml::escape::resolve_predefined_entity(&entity.xml10_content()) {
        text.push_str(s);
    }
}

fn attribute(e: &BytesStart<'_>, name: &str) -> Option<String> {
    e.attributes().flatten().find_map(|a| {
        (a.key.local_name().as_ref() == name)
            .then(|| {
                a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                    .ok()
                    .map(|v| v.into_owned())
            })
            .flatten()
    })
}

/// Attribute-carrying elements: RSS `<enclosure url= length=>` and Atom `<link href= rel=>`.
fn read_attributes(name: &str, e: &BytesStart<'_>, item: &mut FeedItem) {
    match name {
        "enclosure" => {
            if let Some(url) = attribute(e, "url") {
                item.torrent_url = Some(url.chars().take(MAX_FIELD_BYTES).collect());
            }
            item.enclosure_len = attribute(e, "length").and_then(|l| l.trim().parse().ok());
        }
        "link" => {
            if let Some(href) = attribute(e, "href") {
                let href: String = href.chars().take(MAX_FIELD_BYTES).collect();
                match attribute(e, "rel").as_deref() {
                    Some("enclosure") => {
                        item.torrent_url = Some(href);
                        item.enclosure_len =
                            attribute(e, "length").and_then(|l| l.trim().parse().ok());
                    }
                    None | Some("alternate") if item.link.is_empty() => item.link = href,
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

fn assign(name: &str, value: String, item: &mut FeedItem) {
    if value.is_empty() {
        return;
    }
    match name {
        "title" if item.title.is_empty() => item.title = value,
        "link" if item.link.is_empty() => item.link = value,
        "pubDate" | "updated" | "published" if item.pub_date.is_none() => {
            item.pub_date = Some(value)
        }
        "infoHash" => item.info_hash = parse_info_hash(&value),
        "magnetURI" => item.magnet = Some(value),
        "contentLength" if item.enclosure_len.is_none() => item.enclosure_len = value.parse().ok(),
        "seeds" => item.seeds = value.parse().ok(),
        "peers" => item.peers = value.parse().ok(),
        _ => {}
    }
}

/// 40 hex characters or 32 base32 characters (as in `btih`), nothing else.
fn parse_info_hash(s: &str) -> Option<[u8; 20]> {
    let s = s.trim();
    if !s.is_ascii() {
        return None;
    }
    match s.len() {
        40 => {
            let mut out = [0u8; 20];
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
            }
            Some(out)
        }
        32 => {
            const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let (mut bits, mut count) = (0u32, 0u32);
            let mut out = Vec::with_capacity(20);
            for c in s.bytes() {
                let v = ALPHABET.iter().position(|&b| b == c.to_ascii_uppercase())?;
                bits = (bits << 5) | v as u32;
                count += 5;
                if count >= 8 {
                    count -= 8;
                    out.push((bits >> count) as u8);
                    bits &= (1 << count) - 1;
                }
            }
            out.try_into().ok()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn rss_items_with_enclosure_and_torrent_namespace() {
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:torrent="http://xmlns.ezrss.it/0.1/">
  <channel>
    <title>Synapse Linux ISOs</title>
    <item>
      <title><![CDATA[Ubuntu 24.04 <Desktop> ISO]]></title>
      <link>https://releases.example/view?id=1&amp;lang=en</link>
      <enclosure url="https://releases.example/dl?id=1&amp;t=x.torrent" length="5000000000" type="application/x-bittorrent" />
      <pubDate>Mon, 31 Aug 2026 12:00:00 GMT</pubDate>
      <torrent:infoHash>{HASH}</torrent:infoHash>
      <torrent:contentLength>4999</torrent:contentLength>
      <torrent:seeds>12</torrent:seeds>
      <torrent:peers>3</torrent:peers>
      <torrent:magnetURI><![CDATA[magnet:?xt=urn:btih:{HASH}&dn=x]]></torrent:magnetURI>
    </item>
  </channel>
</rss>"#
        );
        let items = parse_torrent_feed(&xml);
        assert_eq!(items.len(), 1);
        let i = &items[0];
        assert_eq!(i.title, "Ubuntu 24.04 <Desktop> ISO");
        assert_eq!(
            i.link, "https://releases.example/view?id=1&lang=en",
            "entities are decoded"
        );
        assert_eq!(
            i.torrent_url.as_deref(),
            Some("https://releases.example/dl?id=1&t=x.torrent")
        );
        assert_eq!(i.enclosure_len, Some(5_000_000_000));
        assert_eq!(i.pub_date.as_deref(), Some("Mon, 31 Aug 2026 12:00:00 GMT"));
        assert_eq!(i.info_hash, parse_info_hash(HASH));
        assert_eq!((i.seeds, i.peers), (Some(12), Some(3)));
        assert_eq!(
            i.magnet.as_deref(),
            Some(format!("magnet:?xt=urn:btih:{HASH}&dn=x").as_str())
        );
    }

    #[test]
    fn atom_entries_use_href_attributes() {
        let xml = r#"<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Releases</title>
  <entry>
    <title>Debian 12</title>
    <link rel="alternate" href="https://d.example/debian"/>
    <link rel="enclosure" type="application/x-bittorrent" href="https://d.example/debian.torrent" length="123"/>
    <updated>2026-08-31T12:00:00Z</updated>
  </entry>
  <entry><title>Only a magnet</title><link href="magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567"/></entry>
</feed>"#;
        let items = parse_torrent_feed(xml);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].link, "https://d.example/debian");
        assert_eq!(
            items[0].torrent_url.as_deref(),
            Some("https://d.example/debian.torrent")
        );
        assert_eq!(items[0].enclosure_len, Some(123));
        assert_eq!(items[0].pub_date.as_deref(), Some("2026-08-31T12:00:00Z"));
        assert!(items[1]
            .torrent_url
            .as_deref()
            .unwrap()
            .starts_with("magnet:?"));
    }

    #[test]
    fn markup_that_only_looks_like_an_item_is_not_one() {
        // `<items>` is not `<item>`, and an `<item>` inside CDATA is text, not markup.
        let xml = r#"<rss><channel><items><x/></items><description><![CDATA[<item><title>fake</title></item>]]></description>
<item><title>real</title><link>https://x.example/a.torrent</link></item></channel></rss>"#;
        let items = parse_torrent_feed(xml);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "real");
        assert_eq!(
            items[0].torrent_url.as_deref(),
            Some("https://x.example/a.torrent")
        );
    }

    #[test]
    fn hostile_input_neither_panics_nor_grows_without_bound() {
        // 40 bytes that are not 40 ASCII characters: slicing them in pairs would panic.
        let bad = "é".repeat(20);
        let xml = format!("<rss><item><title>t</title><infoHash>{bad}</infoHash></item></rss>");
        let items = parse_torrent_feed(&xml);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].info_hash, None);
        // Deep nesting stops the parse; truncated and unbalanced documents return what was read.
        assert!(parse_torrent_feed(&"<a>".repeat(10_000)).is_empty());
        let unfinished = "<rss><item><title>a</title></item><item><title>b";
        assert_eq!(parse_torrent_feed(unfinished).len(), 1);
        // Item count and field length are capped.
        let many = "<item><title>x</title></item>".repeat(MAX_ITEMS + 100);
        assert_eq!(parse_torrent_feed(&many).len(), MAX_ITEMS);
        let long = format!(
            "<item><title>{}</title></item>",
            "a".repeat(MAX_FIELD_BYTES * 4)
        );
        assert!(parse_torrent_feed(&long)[0].title.len() <= MAX_FIELD_BYTES);
    }

    #[test]
    fn info_hash_accepts_hex_and_base32() {
        let hex = parse_info_hash(HASH).unwrap();
        assert_eq!(hex[0], 0x01);
        assert!(parse_info_hash("0123").is_none());
        assert!(parse_info_hash(&"g".repeat(40)).is_none());
        // base32 of 20 zero bytes is 32 'A's.
        assert_eq!(parse_info_hash(&"A".repeat(32)), Some([0u8; 20]));
    }

    #[test]
    fn numeric_references_resolve_and_undefined_entities_are_dropped() {
        let xml = "<rss><item><title>A&#x26;B &#65; &lt;x&gt; &undefined; end</title></item></rss>";
        let items = parse_torrent_feed(xml);
        assert_eq!(items[0].title, "A&B A <x>  end");
    }
}
