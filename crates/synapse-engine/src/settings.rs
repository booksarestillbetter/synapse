//! Dynamic Session Settings and Transmission-Parity Configuration.
//!
//! Provides thread-safe, in-flight adjustable settings for bandwidth throttling,
//! turtle mode (alt-speed), queue limits, stalled torrent detection, ratio limits,
//! peer limits, and storage directories.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::queue::QueueConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicSessionSettings {
    // Normal Bandwidth Limits
    pub download_limit_enabled: bool,
    pub download_limit_bytes: u64,
    pub upload_limit_enabled: bool,
    pub upload_limit_bytes: u64,

    // Turtle Mode (Alt Speed)
    pub alt_speed_enabled: bool,
    pub alt_speed_down_bytes: u64,
    pub alt_speed_up_bytes: u64,
    pub alt_speed_time_enabled: bool,
    pub alt_speed_time_begin: u32,
    pub alt_speed_time_end: u32,
    pub alt_speed_time_days: u32,

    // Queue & Stalled Torrents
    pub queue: QueueConfig,

    // Peer limits
    pub max_peers_per_torrent: usize,
    pub max_global_peers: usize,

    // Protocol flags
    pub dht_enabled: bool,
    pub pex_enabled: bool,
    pub lsd_enabled: bool,
    pub encryption: String,

    // Paths & Behavior
    pub download_dir: PathBuf,
    pub incomplete_dir: Option<PathBuf>,
    pub incomplete_dir_enabled: bool,
    pub start_added_torrents: bool,
    pub trash_original_torrent_files: bool,
}

impl Default for DynamicSessionSettings {
    fn default() -> Self {
        Self {
            download_limit_enabled: false,
            download_limit_bytes: 0,
            upload_limit_enabled: false,
            upload_limit_bytes: 0,

            alt_speed_enabled: false,
            alt_speed_down_bytes: 500_000, // 500 KB/s
            alt_speed_up_bytes: 100_000,   // 100 KB/s
            alt_speed_time_enabled: false,
            alt_speed_time_begin: 540,       // 09:00 AM
            alt_speed_time_end: 1020,        // 05:00 PM
            alt_speed_time_days: 127,        // All days

            queue: QueueConfig::default(),

            max_peers_per_torrent: 80,
            max_global_peers: 2000,

            dht_enabled: true,
            pex_enabled: true,
            lsd_enabled: true,
            encryption: "prefer_encrypted".to_string(),

            download_dir: PathBuf::from("."),
            incomplete_dir: None,
            incomplete_dir_enabled: false,
            start_added_torrents: true,
            trash_original_torrent_files: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionSettingsUpdate {
    pub download_limit_enabled: Option<bool>,
    #[serde(
        default,
        deserialize_with = "synapse_config::deserialize_opt_bandwidth_limit",
        alias = "download_limit",
        alias = "download_limit_bits",
        alias = "download_rate_limit"
    )]
    pub download_limit_bytes: Option<u64>,
    pub upload_limit_enabled: Option<bool>,
    #[serde(
        default,
        deserialize_with = "synapse_config::deserialize_opt_bandwidth_limit",
        alias = "upload_limit",
        alias = "upload_limit_bits",
        alias = "upload_rate_limit"
    )]
    pub upload_limit_bytes: Option<u64>,

    pub alt_speed_enabled: Option<bool>,
    #[serde(
        default,
        deserialize_with = "synapse_config::deserialize_opt_bandwidth_limit",
        alias = "alt_speed_down",
        alias = "alt_speed_down_bits",
        alias = "alt_speed_download_limit"
    )]
    pub alt_speed_down_bytes: Option<u64>,
    #[serde(
        default,
        deserialize_with = "synapse_config::deserialize_opt_bandwidth_limit",
        alias = "alt_speed_up",
        alias = "alt_speed_up_bits",
        alias = "alt_speed_upload_limit"
    )]
    pub alt_speed_up_bytes: Option<u64>,
    pub alt_speed_time_enabled: Option<bool>,
    pub alt_speed_time_begin: Option<u32>,
    pub alt_speed_time_end: Option<u32>,
    pub alt_speed_time_days: Option<u32>,

    pub download_queue_enabled: Option<bool>,
    pub download_queue_size: Option<usize>,
    pub seed_queue_enabled: Option<bool>,
    pub seed_queue_size: Option<usize>,
    pub max_active_torrents: Option<usize>,
    pub queue_stalled_enabled: Option<bool>,
    pub queue_stalled_minutes: Option<u32>,
    pub seed_ratio_limited: Option<bool>,
    pub seed_ratio_limit: Option<f64>,
    pub idle_seeding_limit_enabled: Option<bool>,
    pub idle_seeding_limit_minutes: Option<u32>,

    pub max_peers_per_torrent: Option<usize>,
    pub max_global_peers: Option<usize>,
    pub dht_enabled: Option<bool>,
    pub pex_enabled: Option<bool>,
    pub lsd_enabled: Option<bool>,
    pub encryption: Option<String>,

    pub download_dir: Option<String>,
    pub incomplete_dir: Option<String>,
    pub incomplete_dir_enabled: Option<bool>,
    pub start_added_torrents: Option<bool>,
    pub trash_original_torrent_files: Option<bool>,

    // Static parameters requiring daemon restart (warn if supplied)
    pub peer_port: Option<u16>,
    pub rpc_listen_addr: Option<String>,
    pub http_listen_addr: Option<String>,
}

/// Computes current UTC minute of day and day-of-week bitmask without external dependencies.
pub fn current_time_mins_and_day() -> (u32, u32) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let day_secs = secs % 86400;
    let mins = (day_secs / 60) as u32;

    let days_since_epoch = secs / 86400;
    // 1970-01-01 was Thursday. 0=Thu, 1=Fri, 2=Sat, 3=Sun, 4=Mon, 5=Tue, 6=Wed
    let weekday_idx = (days_since_epoch + 4) % 7;
    let day_mask = match weekday_idx {
        3 => 1,  // Sun
        4 => 2,  // Mon
        5 => 4,  // Tue
        6 => 8,  // Wed
        0 => 16, // Thu
        1 => 32, // Fri
        2 => 64, // Sat
        _ => 1,
    };

    (mins, day_mask)
}

/// Checks if the given minute of day and day mask fall within the scheduled turtle mode window.
pub fn is_in_alt_speed_schedule(
    current_mins: u32,
    current_day_mask: u32,
    begin_mins: u32,
    end_mins: u32,
    days_mask: u32,
) -> bool {
    if (days_mask & current_day_mask) == 0 {
        return false;
    }

    if begin_mins <= end_mins {
        current_mins >= begin_mins && current_mins < end_mins
    } else {
        // Wraps around midnight (e.g. 22:00 to 06:00)
        current_mins >= begin_mins || current_mins < end_mins
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alt_speed_schedule_checks() {
        // Schedule: 09:00 (540) to 17:00 (1020) every day (127)
        assert!(is_in_alt_speed_schedule(600, 2, 540, 1020, 127)); // 10:00 -> in
        assert!(!is_in_alt_speed_schedule(300, 2, 540, 1020, 127)); // 05:00 -> out
        assert!(!is_in_alt_speed_schedule(1100, 2, 540, 1020, 127)); // 18:20 -> out

        // Wraparound midnight: 22:00 (1320) to 06:00 (360)
        assert!(is_in_alt_speed_schedule(1350, 4, 1320, 360, 127)); // 22:30 -> in
        assert!(is_in_alt_speed_schedule(100, 4, 1320, 360, 127));  // 01:40 -> in
        assert!(!is_in_alt_speed_schedule(700, 4, 1320, 360, 127)); // 11:40 -> out

        // Day of week mask: weekdays only (62 = Mon..Fri)
        assert!(is_in_alt_speed_schedule(600, 2, 540, 1020, 62));  // Monday (2) -> in
        assert!(!is_in_alt_speed_schedule(600, 1, 540, 1020, 62)); // Sunday (1) -> out
    }

    #[test]
    fn test_session_settings_update_deserialization() {
        let json_str = r#"{
            "download_limit": "50m",
            "upload_limit": "1g",
            "alt_speed_down": "1000m",
            "alt_speed_up": "5g"
        }"#;

        let update: SessionSettingsUpdate = serde_json::from_str(json_str).unwrap();
        assert_eq!(update.download_limit_bytes, Some(6_250_000));
        assert_eq!(update.upload_limit_bytes, Some(125_000_000));
        assert_eq!(update.alt_speed_down_bytes, Some(125_000_000));
        assert_eq!(update.alt_speed_up_bytes, Some(625_000_000));

        let json_bytes = r#"{
            "download_limit_bytes": 1048576,
            "upload_limit_bytes": 524288
        }"#;
        let update2: SessionSettingsUpdate = serde_json::from_str(json_bytes).unwrap();
        assert_eq!(update2.download_limit_bytes, Some(1048576));
        assert_eq!(update2.upload_limit_bytes, Some(524288));
    }
}
