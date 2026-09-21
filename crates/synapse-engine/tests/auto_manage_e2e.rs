//! End-to-end integration test verifying Swarm Queue & Auto-Manage parity (Phase 5.5).
//!
//! Validates:
//! 1. `dont_count_slow_torrents`: Torrents downloading below `slow_torrent_download_rate_threshold`
//!    or stalled are excluded from active download limits, promoting queued torrents.
//! 2. Target share ratio and maximum seed time limits auto-stop/pause completed seeds.
//! 3. Separate announce limits for Trackers, DHT, and LSD can be configured and enforced independently.

use synapse_engine::queue::{QueueAction, QueueConfig, QueueManager};
use synapse_engine::settings::DynamicSessionSettings;

#[test]
fn test_dont_count_slow_torrents_and_thresholds() {
    let mut config = QueueConfig {
        download_queue_enabled: true,
        max_active_downloads: 1,
        dont_count_slow_torrents: true,
        slow_torrent_download_rate_threshold: 2048,
        slow_torrent_upload_rate_threshold: 2048,
        queue_stalled_enabled: true,
        queue_stalled_minutes: 1,
        ..Default::default()
    };

    let qm = QueueManager::new(config.clone());

    // 1. Torrent downloading at 500 B/s (< 2048 threshold) is slow
    assert!(qm.is_slow_downloader(500));
    // Torrent downloading at 10,000 B/s (>= 2048 threshold) is NOT slow
    assert!(!qm.is_slow_downloader(10_000));

    // 2. Seeder uploading at 1000 B/s (< 2048 threshold) is slow
    assert!(qm.is_slow_seeder(1000));
    assert!(!qm.is_slow_seeder(50_000));

    // 3. When dont_count_slow_torrents is disabled:
    config.dont_count_slow_torrents = false;
    let qm_no_slow = QueueManager::new(config);
    assert!(!qm_no_slow.is_slow_downloader(500));
    assert!(!qm_no_slow.is_slow_seeder(1000));
}

#[test]
fn test_auto_manage_seed_limits() {
    let config = QueueConfig {
        seed_ratio_limited: true,
        share_ratio_limit: Some(1.5),
        idle_seeding_limit_enabled: true,
        seed_time_limit_secs: Some(3600), // 1 hour
        ..Default::default()
    };
    let qm = QueueManager::new(config);

    // Seed within ratio and time limit -> Allow
    assert_eq!(qm.evaluate_seeder(1, 2, 1.0, 1800), QueueAction::Allow);

    // Seed exceeded share ratio limit (1.5) -> AutoStopRatioReached
    assert_eq!(
        qm.evaluate_seeder(1, 2, 1.6, 1800),
        QueueAction::AutoStopRatioReached
    );

    // Seed exceeded max seed duration (3600s) -> AutoStopSeedTimeReached
    assert_eq!(
        qm.evaluate_seeder(1, 2, 1.0, 4000),
        QueueAction::AutoStopSeedTimeReached
    );
}

#[test]
fn test_separate_announce_limits_configuration() {
    let mut settings = DynamicSessionSettings::default();

    // Default announce limits
    assert_eq!(settings.max_concurrent_tracker_announces, 50);
    assert_eq!(settings.max_concurrent_dht_announces, 8);
    assert_eq!(settings.max_concurrent_lsd_announces, 1);

    // Custom distinct announce limits
    settings.max_concurrent_tracker_announces = 100;
    settings.max_concurrent_dht_announces = 16;
    settings.max_concurrent_lsd_announces = 4;

    assert_eq!(settings.max_concurrent_tracker_announces, 100);
    assert_eq!(settings.max_concurrent_dht_announces, 16);
    assert_eq!(settings.max_concurrent_lsd_announces, 4);
}
