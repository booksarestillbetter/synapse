use std::sync::Arc;
use diskio::DiskEngine;
use synapse_engine::{SessionSettingsUpdate, SwarmEngine};

#[tokio::test]
async fn test_dynamic_session_settings_and_turtle_mode() {
    let disk = Arc::new(DiskEngine::auto().await);
    let peer_id = [7u8; 20];
    let engine = SwarmEngine::new(disk, peer_id);

    // Initial settings: unthrottled
    let initial = engine.get_session_settings();
    assert!(!initial.alt_speed_enabled);
    assert!(!initial.download_limit_enabled);
    assert!(!engine.is_alt_speed_active());

    // 1. Set normal rate limit
    let warnings = engine.update_session_settings(SessionSettingsUpdate {
        download_limit_enabled: Some(true),
        download_limit_bytes: Some(2_000_000), // 2 MB/s
        upload_limit_enabled: Some(true),
        upload_limit_bytes: Some(1_000_000),   // 1 MB/s
        ..Default::default()
    });
    assert!(warnings.is_empty());

    let s1 = engine.get_session_settings();
    assert!(s1.download_limit_enabled);
    assert_eq!(s1.download_limit_bytes, 2_000_000);
    assert!(!engine.is_alt_speed_active());

    // 2. Enable Turtle Mode (alt-speed)
    let warnings = engine.update_session_settings(SessionSettingsUpdate {
        alt_speed_enabled: Some(true),
        alt_speed_down_bytes: Some(250_000), // 250 KB/s
        alt_speed_up_bytes: Some(50_000),    // 50 KB/s
        ..Default::default()
    });
    assert!(warnings.is_empty());
    assert!(engine.is_alt_speed_active());

    let s2 = engine.get_session_settings();
    assert!(s2.alt_speed_enabled);
    assert_eq!(s2.alt_speed_down_bytes, 250_000);
    assert_eq!(s2.alt_speed_up_bytes, 50_000);

    // 3. Disable Turtle Mode -> reverts to normal limits
    engine.update_session_settings(SessionSettingsUpdate {
        alt_speed_enabled: Some(false),
        ..Default::default()
    });
    assert!(!engine.is_alt_speed_active());

    // 4. Update Queue settings in flight
    engine.update_session_settings(SessionSettingsUpdate {
        download_queue_size: Some(15),
        seed_queue_size: Some(25),
        queue_stalled_minutes: Some(3),
        ..Default::default()
    });

    let s3 = engine.get_session_settings();
    assert_eq!(s3.queue.download_queue_size(), 15);
    assert_eq!(s3.queue.seed_queue_size(), 25);
    assert_eq!(s3.queue.queue_stalled_minutes, 3);

    // 5. Test static setting warning
    let warnings = engine.update_session_settings(SessionSettingsUpdate {
        peer_port: Some(54321),
        ..Default::default()
    });
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("restart"));
}
