//! Torrent Swarm Queue and Auto-Stop Manager.
//!
//! Enforces concurrency limits (max active downloads, max active seeds) and auto-pause
//! rules on reaching target share ratios or maximum seeding durations.

use serde::{Deserialize, Serialize};

use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueConfig {
    pub download_queue_enabled: bool,
    pub max_active_downloads: usize,
    pub seed_queue_enabled: bool,
    pub max_active_seeds: usize,
    pub max_active_torrents: usize,
    pub queue_stalled_enabled: bool,
    pub queue_stalled_minutes: u32,
    pub seed_ratio_limited: bool,
    pub share_ratio_limit: Option<f64>,
    pub idle_seeding_limit_enabled: bool,
    pub seed_time_limit_secs: Option<u64>,
    /// Libtorrent parity: when true, torrents downloading/uploading below threshold or stalled
    /// do not count toward active download/seed limits.
    #[serde(default = "default_true")]
    pub dont_count_slow_torrents: bool,
    /// Threshold (bytes/sec) below which a downloading torrent is considered slow (default 2048).
    #[serde(default = "default_slow_threshold")]
    pub slow_torrent_download_rate_threshold: u64,
    /// Threshold (bytes/sec) below which a seeding torrent is considered slow (default 2048).
    #[serde(default = "default_slow_threshold")]
    pub slow_torrent_upload_rate_threshold: u64,
}

fn default_true() -> bool {
    true
}

fn default_slow_threshold() -> u64 {
    2048
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            download_queue_enabled: true,
            max_active_downloads: 5,
            seed_queue_enabled: true,
            max_active_seeds: 10,
            max_active_torrents: 20,
            queue_stalled_enabled: true,
            queue_stalled_minutes: 1,
            seed_ratio_limited: false,
            share_ratio_limit: Some(2.0),
            idle_seeding_limit_enabled: false,
            seed_time_limit_secs: Some(1800), // 30 mins
            dont_count_slow_torrents: true,
            slow_torrent_download_rate_threshold: 2048,
            slow_torrent_upload_rate_threshold: 2048,
        }
    }
}

impl QueueConfig {
    pub fn download_queue_size(&self) -> usize {
        self.max_active_downloads
    }

    pub fn seed_queue_size(&self) -> usize {
        self.max_active_seeds
    }

    pub fn idle_seeding_limit_minutes(&self) -> Option<u32> {
        self.seed_time_limit_secs.map(|s| (s / 60) as u32)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueAction {
    Allow,
    Queue,
    AutoStopRatioReached,
    AutoStopSeedTimeReached,
}

pub struct QueueManager {
    config: QueueConfig,
}

impl QueueManager {
    pub fn new(config: QueueConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &QueueConfig {
        &self.config
    }

    pub fn set_config(&mut self, config: QueueConfig) {
        self.config = config;
    }

    /// Determines whether a downloading torrent is considered stalled (idle / no throughput / no seeds).
    pub fn is_stalled(
        &self,
        peers_connected: usize,
        download_rate: u64,
        downloaded_bytes: u64,
        total_size: u64,
        time_since_last_activity: Duration,
    ) -> bool {
        if !self.config.queue_stalled_enabled {
            return false;
        }

        if downloaded_bytes >= total_size && total_size > 0 {
            return false;
        }

        let stall_threshold = Duration::from_secs((self.config.queue_stalled_minutes as u64) * 60);

        time_since_last_activity >= stall_threshold && (peers_connected == 0 || download_rate == 0)
    }

    /// Returns true if `dont_count_slow_torrents` is active and the download rate is below threshold.
    pub fn is_slow_downloader(&self, download_rate: u64) -> bool {
        self.config.dont_count_slow_torrents
            && download_rate < self.config.slow_torrent_download_rate_threshold
    }

    /// Returns true if `dont_count_slow_torrents` is active and the upload rate is below threshold.
    pub fn is_slow_seeder(&self, upload_rate: u64) -> bool {
        self.config.dont_count_slow_torrents
            && upload_rate < self.config.slow_torrent_upload_rate_threshold
    }

    /// Evaluates if a downloading torrent should proceed or be queued.
    /// In Transmission and libtorrent's model, `active_non_stalled_downloads` excludes stalled/slow torrents so they don't block the queue.
    pub fn evaluate_downloader(
        &self,
        active_non_stalled_downloads: usize,
        active_total: usize,
    ) -> QueueAction {
        if (self.config.download_queue_enabled
            && active_non_stalled_downloads >= self.config.max_active_downloads)
            || active_total >= self.config.max_active_torrents
        {
            QueueAction::Queue
        } else {
            QueueAction::Allow
        }
    }

    /// Evaluates a seeder for share ratio and seeding time limits.
    pub fn evaluate_seeder(
        &self,
        active_seeds: usize,
        active_total: usize,
        ratio: f64,
        seed_time_secs: u64,
    ) -> QueueAction {
        if self.config.seed_ratio_limited {
            if let Some(target_ratio) = self.config.share_ratio_limit {
                if ratio >= target_ratio {
                    return QueueAction::AutoStopRatioReached;
                }
            }
        }

        if self.config.idle_seeding_limit_enabled {
            if let Some(max_time) = self.config.seed_time_limit_secs {
                if seed_time_secs >= max_time {
                    return QueueAction::AutoStopSeedTimeReached;
                }
            }
        }

        if (self.config.seed_queue_enabled && active_seeds >= self.config.max_active_seeds)
            || active_total >= self.config.max_active_torrents
        {
            QueueAction::Queue
        } else {
            QueueAction::Allow
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queue_manager_evaluation_and_stalled_handling() {
        let config = QueueConfig {
            download_queue_enabled: true,
            max_active_downloads: 2,
            seed_queue_enabled: true,
            max_active_seeds: 5,
            max_active_torrents: 6,
            queue_stalled_enabled: true,
            queue_stalled_minutes: 1,
            seed_ratio_limited: true,
            share_ratio_limit: Some(2.0),
            idle_seeding_limit_enabled: true,
            seed_time_limit_secs: Some(3600),
            ..Default::default()
        };
        let qm = QueueManager::new(config);

        assert_eq!(qm.evaluate_downloader(1, 1), QueueAction::Allow);
        assert_eq!(qm.evaluate_downloader(2, 2), QueueAction::Queue);

        // Stalled detection (grace period vs threshold)
        assert!(!qm.is_stalled(0, 0, 0, 1000, Duration::from_secs(15)));
        assert!(qm.is_stalled(0, 0, 0, 1000, Duration::from_secs(65)));
        assert!(!qm.is_stalled(5, 1024, 500, 1000, Duration::from_secs(5)));
        assert!(qm.is_stalled(5, 0, 500, 1000, Duration::from_secs(65)));

        // Seeder evaluations
        assert_eq!(qm.evaluate_seeder(1, 2, 1.5, 1000), QueueAction::Allow);
        assert_eq!(
            qm.evaluate_seeder(1, 2, 2.1, 1000),
            QueueAction::AutoStopRatioReached
        );
        assert_eq!(
            qm.evaluate_seeder(1, 2, 0.5, 4000),
            QueueAction::AutoStopSeedTimeReached
        );
    }
}
