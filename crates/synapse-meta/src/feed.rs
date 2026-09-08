//! BEP 36 Torrent RSS and Atom Feed Parser.
//!
//! Parses syndicated torrent release feeds (RSS 2.0 and Atom), extracting
//! download links, enclosure metadata, sizes, publication dates, and infohashes.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedItem {
    pub title: String,
    pub link: String,
    pub torrent_url: Option<String>,
    pub enclosure_len: Option<u64>,
    pub info_hash: Option<[u8; 20]>,
    pub pub_date: Option<String>,
}

/// Parses an RSS 2.0 or Atom XML feed string into a list of `FeedItem` records.
pub fn parse_torrent_feed(xml: &str) -> Vec<FeedItem> {
    let mut items = Vec::new();

    // Scan for <item> (RSS) or <entry> (Atom) blocks
    let mut cursor = xml;
    while let Some(start_idx) = cursor.find("<item").or_else(|| cursor.find("<entry")) {
        let after_start = &cursor[start_idx..];
        let end_tag = if after_start.starts_with("<item") { "</item>" } else { "</entry>" };

        if let Some(end_idx) = after_start.find(end_tag) {
            let block = &after_start[..end_idx + end_tag.len()];
            if let Some(item) = parse_single_item(block) {
                items.push(item);
            }
            cursor = &after_start[end_idx + end_tag.len()..];
        } else {
            break;
        }
    }

    items
}

fn parse_single_item(block: &str) -> Option<FeedItem> {
    let title = extract_tag_content(block, "title").unwrap_or_default();
    let link = extract_tag_content(block, "link").unwrap_or_default();
    let pub_date = extract_tag_content(block, "pubDate")
        .or_else(|| extract_tag_content(block, "updated"))
        .or_else(|| extract_tag_content(block, "published"));

    let mut torrent_url = None;
    let mut enclosure_len = None;

    // Check for <enclosure url="..." length="..." ...>
    if let Some(enc_idx) = block.find("<enclosure") {
        let enc_str = &block[enc_idx..];
        if let Some(close_idx) = enc_str.find('>') {
            let tag = &enc_str[..close_idx];
            if let Some(url) = extract_attribute(tag, "url") {
                torrent_url = Some(url);
            }
            if let Some(len_str) = extract_attribute(tag, "length") {
                enclosure_len = len_str.parse::<u64>().ok();
            }
        }
    }

    // If no enclosure, fall back to link if it points to a torrent or magnet
    if torrent_url.is_none() && (link.ends_with(".torrent") || link.starts_with("magnet:?")) {
        torrent_url = Some(link.clone());
    }

    let info_hash = extract_tag_content(block, "torrent:infoHash")
        .or_else(|| extract_tag_content(block, "infoHash"))
        .and_then(|s| hex_to_hash(&s));

    if title.is_empty() && link.is_empty() && torrent_url.is_none() {
        None
    } else {
        Some(FeedItem {
            title,
            link,
            torrent_url,
            enclosure_len,
            info_hash,
            pub_date,
        })
    }
}

fn extract_tag_content(block: &str, tag: &str) -> Option<String> {
    let open_tag = format!("<{tag}>");
    let close_tag = format!("</{tag}>");

    if let Some(start) = block.find(&open_tag) {
        let content_start = start + open_tag.len();
        if let Some(end) = block[content_start..].find(&close_tag) {
            let content = &block[content_start..content_start + end];
            // Strip CDATA wrapper if present
            let trimmed = content.trim();
            if trimmed.starts_with("<![CDATA[") && trimmed.ends_with("]]>") {
                return Some(trimmed[9..trimmed.len() - 3].trim().to_string());
            }
            return Some(trimmed.to_string());
        }
    }
    None
}

fn extract_attribute(tag: &str, attr: &str) -> Option<String> {
    let pattern = format!("{attr}=\"");
    if let Some(start) = tag.find(&pattern) {
        let val_start = start + pattern.len();
        if let Some(end) = tag[val_start..].find('"') {
            return Some(tag[val_start..val_start + end].to_string());
        }
    }
    None
}

fn hex_to_hash(hex: &str) -> Option<[u8; 20]> {
    let clean = hex.trim();
    if clean.len() != 40 {
        return None;
    }
    let mut arr = [0u8; 20];
    for i in 0..20 {
        arr[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rss_2_feed() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:torrent="http://xmlns.ezrss.it/0.1/">
  <channel>
    <title>Synapse Linux ISOs</title>
    <item>
      <title>Ubuntu 24.04 Desktop ISO</title>
      <link>https://releases.ubuntu.com/noble/ubuntu-24.04-desktop-amd64.iso</link>
      <enclosure url="https://releases.ubuntu.com/noble/ubuntu-24.04-desktop-amd64.iso.torrent" length="5000000000" type="application/x-bittorrent" />
      <pubDate>Mon, 31 Aug 2026 12:00:00 GMT</pubDate>
      <torrent:infoHash>0123456789abcdef0123456789abcdef01234567</torrent:infoHash>
    </item>
  </channel>
</rss>"#;

        let items = parse_torrent_feed(xml);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Ubuntu 24.04 Desktop ISO");
        assert_eq!(items[0].torrent_url.as_deref(), Some("https://releases.ubuntu.com/noble/ubuntu-24.04-desktop-amd64.iso.torrent"));
        assert_eq!(items[0].enclosure_len, Some(5000000000));
        assert_eq!(items[0].pub_date.as_deref(), Some("Mon, 31 Aug 2026 12:00:00 GMT"));
        assert_eq!(items[0].info_hash, hex_to_hash("0123456789abcdef0123456789abcdef01234567"));
    }
}
