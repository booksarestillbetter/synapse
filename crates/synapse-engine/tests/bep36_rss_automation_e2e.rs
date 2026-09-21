use std::sync::Arc;
use tempfile::tempdir;

use diskio::DiskEngine;
use synapse_config::RssFeedConfig;
use synapse_engine::feed::{matches_filter, FeedManager};
use synapse_engine::SwarmEngine;
use synapse_meta::feed::parse_torrent_feed;

const TEST_RSS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Linux Releases RSS</title>
    <link>https://example.org</link>
    <description>Latest Linux ISO torrents</description>
    <item>
      <title>Arch Linux 2026.09.01 x86_64</title>
      <link>magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&amp;dn=archlinux</link>
      <enclosure url="magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&amp;dn=archlinux" length="1048576000" type="application/x-bittorrent" />
      <pubDate>Mon, 01 Sep 2026 00:00:00 GMT</pubDate>
    </item>
    <item>
      <title>Ubuntu 26.04 Desktop</title>
      <link>magnet:?xt=urn:btih:abcdef0123456789abcdef0123456789abcdef01&amp;dn=ubuntu</link>
      <pubDate>Mon, 01 Sep 2026 01:00:00 GMT</pubDate>
    </item>
    <item>
      <title>BSD Free 15.0</title>
      <link>magnet:?xt=urn:btih:9999999999999999999999999999999999999999&amp;dn=bsd</link>
      <pubDate>Mon, 01 Sep 2026 02:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>"#;

#[tokio::test]
async fn test_bep36_rss_automation_and_filtering() {
    let _tmp = tempdir().expect("tempdir");
    let disk = Arc::new(DiskEngine::auto().await);
    let peer_id = [0x59; 20];
    let engine = Arc::new(SwarmEngine::new(disk, peer_id));
    let mut alert_rx = engine.subscribe_alerts();

    let feed_mgr = FeedManager::new(vec![RssFeedConfig {
        url: "https://example.org/rss.xml".to_string(),
        name: Some("Linux Tracker".to_string()),
        auto_download: true,
        filter: Some("Linux".to_string()), // Should match Arch Linux, reject Ubuntu and BSD
    }]);

    // 1. Verify Feed Status
    let statuses = feed_mgr.list_feeds();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].name.as_deref(), Some("Linux Tracker"));
    assert_eq!(statuses[0].filter.as_deref(), Some("Linux"));
    assert!(statuses[0].auto_download);

    // 2. Parse feed items from XML
    let items = parse_torrent_feed(TEST_RSS_XML);
    assert_eq!(items.len(), 3);

    assert!(matches_filter(&items[0].title, Some("Linux")));
    assert!(!matches_filter(&items[1].title, Some("Linux")));
    assert!(!matches_filter(&items[2].title, Some("Linux")));

    // 3. Process items with auto-downloading enabled
    let feed_cfg = &feed_mgr.feed_configs()[0];
    let added = feed_mgr.process_feed_items(feed_cfg, &items, &engine).await;
    assert_eq!(added, 1, "Only 1 matching torrent should be auto-added");

    // 4. Verify SwarmEngine has the torrent
    let expected_hash = hex::decode("0123456789abcdef0123456789abcdef01234567").unwrap();
    let mut expected_arr = [0u8; 20];
    expected_arr.copy_from_slice(&expected_hash);
    assert!(engine.has_torrent(&expected_arr));

    // 5. Verify TorrentAdded alert was emitted
    let alert = alert_rx.try_recv().expect("Expected TorrentAdded alert");
    match alert {
        synapse_engine::Alert::TorrentAdded { info_hash } => {
            assert_eq!(info_hash, expected_arr);
        }
        other => panic!("Unexpected alert: {:?}", other),
    }

    // 6. Test Deduplication: second run of process_feed_items should add 0 new torrents
    let added_second = feed_mgr.process_feed_items(feed_cfg, &items, &engine).await;
    assert_eq!(
        added_second, 0,
        "Deduplication must prevent re-adding seen items"
    );

    // 7. Verify removing feed
    assert!(feed_mgr.remove_feed("https://example.org/rss.xml"));
    assert_eq!(feed_mgr.list_feeds().len(), 0);
}
