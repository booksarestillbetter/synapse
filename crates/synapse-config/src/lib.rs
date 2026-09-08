//! Config loading for the rewritten synapse daemon.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub log_level: LogLevel,
    pub logging: LoggingConfig,
    pub disk: DiskConfig,
    pub network: NetworkConfig,
    pub rpc: RpcConfig,
    pub lifecycle: LifecycleConfig,
    pub privacy: PrivacyConfig,
    pub http_api: HttpApiConfig,
    pub metrics: MetricsConfig,
    pub queue: QueueConfig,
    pub bandwidth: BandwidthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct QueueConfig {
    pub download_queue_enabled: bool,
    pub download_queue_size: usize,
    pub seed_queue_enabled: bool,
    pub seed_queue_size: usize,
    pub max_active_torrents: usize,
    pub queue_stalled_enabled: bool,
    pub queue_stalled_minutes: u32,
    pub seed_ratio_limited: bool,
    pub seed_ratio_limit: Option<f64>,
    pub idle_seeding_limit_enabled: bool,
    pub idle_seeding_limit_minutes: Option<u32>,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            download_queue_enabled: true,
            download_queue_size: 5,
            seed_queue_enabled: true,
            seed_queue_size: 10,
            max_active_torrents: 20,
            queue_stalled_enabled: true,
            queue_stalled_minutes: 1,
            seed_ratio_limited: false,
            seed_ratio_limit: Some(2.0),
            idle_seeding_limit_enabled: false,
            idle_seeding_limit_minutes: Some(30),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BandwidthConfig {
    pub download_limit_enabled: bool,
    #[serde(
        default,
        deserialize_with = "deserialize_bandwidth_limit",
        alias = "download_limit",
        alias = "download_limit_bits",
        alias = "download_rate_limit"
    )]
    pub download_limit_bytes: u64,
    pub upload_limit_enabled: bool,
    #[serde(
        default,
        deserialize_with = "deserialize_bandwidth_limit",
        alias = "upload_limit",
        alias = "upload_limit_bits",
        alias = "upload_rate_limit"
    )]
    pub upload_limit_bytes: u64,
    pub alt_speed: AltSpeedConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AltSpeedConfig {
    pub enabled: bool,
    #[serde(
        default,
        deserialize_with = "deserialize_bandwidth_limit",
        alias = "download_limit",
        alias = "download_limit_bits",
        alias = "alt_speed_down",
        alias = "alt_speed_down_bits"
    )]
    pub download_limit_bytes: u64,
    #[serde(
        default,
        deserialize_with = "deserialize_bandwidth_limit",
        alias = "upload_limit",
        alias = "upload_limit_bits",
        alias = "alt_speed_up",
        alias = "alt_speed_up_bits"
    )]
    pub upload_limit_bytes: u64,
    pub time_enabled: bool,
    pub time_begin_minutes: u32,
    pub time_end_minutes: u32,
    pub time_days: u32,
}


impl Default for AltSpeedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            download_limit_bytes: 500_000, // 500 KB/s
            upload_limit_bytes: 100_000,   // 100 KB/s
            time_enabled: false,
            time_begin_minutes: 540,       // 09:00 AM (minutes from midnight)
            time_end_minutes: 1020,        // 05:00 PM (minutes from midnight)
            time_days: 127,                // All days (bitmask)
        }
    }
}

/// Parses a human-readable network bandwidth string (e.g., "50m", "1000m", "1g", "5g", "100kbps", "10485760")
/// into bytes per second.
///
/// Bitrate units (decimal SI prefixes matching networking and ISP standards):
/// - "k", "kb", "kbps", "kbit", "kbits": 10^3 bits/s (125 B/s per kbit)
/// - "m", "mb", "mbps", "mbit", "mbits": 10^6 bits/s (125,000 B/s per Mbit, e.g. "50m" = 6,250,000 B/s)
/// - "g", "gb", "gbps", "gbit", "gbits": 10^9 bits/s (125,000,000 B/s per Gbit, e.g. "1g" = 125,000,000 B/s)
/// - "t", "tb", "tbps", "tbit", "tbits": 10^12 bits/s
///
/// Byte units:
/// - "kib", "kibps": 1024 bytes/s
/// - "mib", "mibps": 1024^2 bytes/s
/// - "gib", "gibps": 1024^3 bytes/s
/// - "tib", "tibps": 1024^4 bytes/s
/// - "b", "byte", "bytes": bytes/s
///
/// Plain numbers without units (e.g. "10485760") are parsed as raw bytes/s for backwards compatibility.
/// "0", "unlimited", "off", "none" return 0 (unlimited/disabled).
pub fn parse_bandwidth_to_bytes(input: &str) -> Result<u64, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty bandwidth value".to_string());
    }

    let lower = s.to_lowercase();
    if lower == "0" || lower == "unlimited" || lower == "off" || lower == "none" {
        return Ok(0);
    }

    // Check if it is a pure integer string -> backwards-compatible raw bytes
    if let Ok(raw_bytes) = s.parse::<u64>() {
        return Ok(raw_bytes);
    }

    // Split at the first non-digit, non-dot, non-whitespace character
    let split_pos = lower
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .ok_or_else(|| format!("invalid bandwidth value '{input}'"))?;

    let (num_part, unit_part) = lower.split_at(split_pos);
    let num: f64 = num_part
        .trim()
        .parse()
        .map_err(|_| format!("invalid numeric part in bandwidth value '{input}'"))?;

    if num < 0.0 {
        return Ok(0);
    }

    let unit = unit_part.trim().trim_end_matches("/s");

    let bytes_per_sec = match unit {
        // Networking bitrates (decimal SI, divided by 8 for bytes)
        "k" | "kb" | "kbps" | "kbit" | "kbits" => (num * 1_000.0) / 8.0,
        "m" | "mb" | "mbps" | "mbit" | "mbits" => (num * 1_000_000.0) / 8.0,
        "g" | "gb" | "gbps" | "gbit" | "gbits" => (num * 1_000_000_000.0) / 8.0,
        "t" | "tb" | "tbps" | "tbit" | "tbits" => (num * 1_000_000_000_000.0) / 8.0,
        "bps" | "bit" | "bits" => num / 8.0,

        // Binary byte units
        "kib" | "kibps" => num * 1024.0,
        "mib" | "mibps" => num * 1024.0 * 1024.0,
        "gib" | "gibps" => num * 1024.0 * 1024.0 * 1024.0,
        "tib" | "tibps" => num * 1024.0 * 1024.0 * 1024.0 * 1024.0,

        // Explicit bytes
        "b" | "byte" | "bytes" => num,

        _ => return Err(format!("unknown bandwidth unit '{unit}' in '{input}'")),
    };

    Ok(bytes_per_sec.round() as u64)
}

/// Formats a byte-per-second rate into a human-readable network bitrate string.
///
/// For example:
/// - 0 -> "unlimited"
/// - 6,250,000 -> "50 Mbps"
/// - 125,000,000 -> "1 Gbps"
/// - 625,000,000 -> "5 Gbps"
pub fn format_bytes_as_bitrate(bytes_per_sec: u64) -> String {
    if bytes_per_sec == 0 {
        return "unlimited".to_string();
    }

    let bits = (bytes_per_sec as f64) * 8.0;

    if bits >= 1_000_000_000_000.0 {
        let tbps = bits / 1_000_000_000_000.0;
        format_rate(tbps, "Tbps")
    } else if bits >= 1_000_000_000.0 {
        let gbps = bits / 1_000_000_000.0;
        format_rate(gbps, "Gbps")
    } else if bits >= 1_000_000.0 {
        let mbps = bits / 1_000_000.0;
        format_rate(mbps, "Mbps")
    } else if bits >= 1_000.0 {
        let kbps = bits / 1_000.0;
        format_rate(kbps, "Kbps")
    } else {
        format!("{bytes_per_sec} B/s")
    }
}

fn format_rate(val: f64, unit: &str) -> String {
    if (val.round() - val).abs() < 0.001 {
        format!("{:.0} {}", val.round(), unit)
    } else {
        format!("{:.1} {}", val, unit)
    }
}

/// Deserializer helper for serde supporting both integer bytes and pretty bitrate strings like "50m", "1g".
pub fn deserialize_bandwidth_limit<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct BandwidthVisitor;

    impl<'de> serde::de::Visitor<'de> for BandwidthVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a bandwidth bitrate string like '50m', '1g', or integer bytes")
        }

        fn visit_u64<E>(self, value: u64) -> Result<u64, E>
        where
            E: serde::de::Error,
        {
            Ok(value)
        }

        fn visit_i64<E>(self, value: i64) -> Result<u64, E>
        where
            E: serde::de::Error,
        {
            if value < 0 {
                Ok(0)
            } else {
                Ok(value as u64)
            }
        }

        fn visit_f64<E>(self, value: f64) -> Result<u64, E>
        where
            E: serde::de::Error,
        {
            if value < 0.0 {
                Ok(0)
            } else {
                Ok(value.round() as u64)
            }
        }

        fn visit_str<E>(self, value: &str) -> Result<u64, E>
        where
            E: serde::de::Error,
        {
            parse_bandwidth_to_bytes(value).map_err(serde::de::Error::custom)
        }
    }

    deserializer.deserialize_any(BandwidthVisitor)
}

/// Deserializer helper for serde supporting optional bandwidth values (None, integer bytes, or pretty bitrate strings).
pub fn deserialize_opt_bandwidth_limit<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct OptBandwidthVisitor;

    impl<'de> serde::de::Visitor<'de> for OptBandwidthVisitor {
        type Value = Option<u64>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("optional bandwidth bitrate string like '50m', '1g', or integer bytes")
        }

        fn visit_none<E>(self) -> Result<Option<u64>, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Option<u64>, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_some<D2>(self, deserializer: D2) -> Result<Option<u64>, D2::Error>
        where
            D2: serde::Deserializer<'de>,
        {
            deserialize_bandwidth_limit(deserializer).map(Some)
        }

        fn visit_u64<E>(self, value: u64) -> Result<Option<u64>, E>
        where
            E: serde::de::Error,
        {
            Ok(Some(value))
        }

        fn visit_i64<E>(self, value: i64) -> Result<Option<u64>, E>
        where
            E: serde::de::Error,
        {
            if value < 0 {
                Ok(Some(0))
            } else {
                Ok(Some(value as u64))
            }
        }

        fn visit_f64<E>(self, value: f64) -> Result<Option<u64>, E>
        where
            E: serde::de::Error,
        {
            if value < 0.0 {
                Ok(Some(0))
            } else {
                Ok(Some(value.round() as u64))
            }
        }

        fn visit_str<E>(self, value: &str) -> Result<Option<u64>, E>
        where
            E: serde::de::Error,
        {
            parse_bandwidth_to_bytes(value).map(Some).map_err(serde::de::Error::custom)
        }
    }

    deserializer.deserialize_option(OptBandwidthVisitor)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpApiConfig {
    pub enabled: bool,
    pub listen_addr: SocketAddr,
    pub cors_enabled: bool,
}

impl Default for HttpApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addr: SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 8080),
            cors_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub path: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: "/metrics".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrivacyConfig {
    pub prefer_private_safe_defaults: bool,
    pub mask_passkeys_in_logs: bool,
    pub disable_dht_globally: bool,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            prefer_private_safe_defaults: true,
            mask_passkeys_in_logs: true,
            disable_dht_globally: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LifecycleConfig {
    pub staging_dir: Option<PathBuf>,
    pub auto_hardlink: bool,
    pub wal_path: Option<PathBuf>,
    pub post_script: Option<PathBuf>,
    pub copy_script: Option<PathBuf>,
    pub start_added_torrents: bool,
    pub trash_original_torrent_files: bool,
    pub instructions: InstructionsWebhookConfig,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            staging_dir: None,
            auto_hardlink: false,
            wal_path: None,
            post_script: None,
            copy_script: None,
            start_added_torrents: true,
            trash_original_torrent_files: false,
            instructions: InstructionsWebhookConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InstructionsWebhookConfig {
    pub enabled: bool,
    pub url: Option<String>,
    pub token: Option<String>,
    pub node_name: String,
    pub timeout_secs: u64,
    pub fallback_dir: Option<PathBuf>,
}

impl Default for InstructionsWebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: None,
            token: None,
            node_name: "synapse".to_string(),
            timeout_secs: 10,
            fallback_dir: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub listen_port: u16,
    pub bind_interfaces: Vec<String>,
    pub enable_ipv6: bool,
    pub enable_dht: bool,
    pub enable_pex: bool,
    pub enable_lsd: bool,
    pub encryption: String,
    pub max_peers_per_torrent: usize,
    pub max_global_peers: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_port: 54345,
            bind_interfaces: Vec::new(),
            enable_ipv6: true,
            enable_dht: true,
            enable_pex: true,
            enable_lsd: true,
            encryption: "prefer_encrypted".to_string(),
            max_peers_per_torrent: 80,
            max_global_peers: 2000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RpcConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub auth_token: Option<String>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addr: "0.0.0.0:50051".to_string(),
            auth_token: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_filter(&self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Pretty,
    Json,
    Compact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    pub file: Option<PathBuf>,
    pub syslog_addr: Option<SocketAddr>,
    pub syslog_tcp: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Pretty,
            file: None,
            syslog_addr: None,
            syslog_tcp: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DiskConfig {
    pub root_dir: Option<PathBuf>,
    pub session_dir: PathBuf,
    pub download_dir: PathBuf,
    pub incomplete_dir: Option<PathBuf>,
    pub incomplete_dir_enabled: bool,
    pub watch_dir: Option<PathBuf>,
    pub max_open_files: usize,
}

impl Default for DiskConfig {
    fn default() -> Self {
        DiskConfig {
            root_dir: None,
            session_dir: default_session_dir(),
            download_dir: PathBuf::from("."),
            incomplete_dir: None,
            incomplete_dir_enabled: false,
            watch_dir: None,
            max_open_files: 500,
        }
    }
}

fn default_session_dir() -> PathBuf {
    directories::ProjectDirs::from("", "", "synapse")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".synapse"))
}

/// Expands top-level template variables and environment variables of the form `${VAR}` or `${VAR:-default}`.
pub fn expand_vars(raw: &str) -> String {
    use std::collections::HashMap;
    let mut local_vars: HashMap<String, String> = HashMap::new();

    // Parse top-level key = "value" assignments before any [table] header
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            break; // First table reached
        }
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim();
            let mut val = v.trim();
            // strip inline comments from value if any
            if let Some((clean_val, _)) = val.split_once('#') {
                val = clean_val.trim();
            }
            // strip surrounding quotes
            if ((val.starts_with('"') && val.ends_with('"'))
                || (val.starts_with('\'') && val.ends_with('\'')))
                && val.len() >= 2
            {
                let unquoted = &val[1..val.len() - 1];
                local_vars.insert(key.to_string(), unquoted.to_string());
            }
        }
    }

    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.char_indices().peekable();
    let mut cursor = 0;

    while let Some((i, c)) = chars.next() {
        if c == '$' {
            if let Some(&(_, '{')) = chars.peek() {
                chars.next(); // consume '{'
                out.push_str(&raw[cursor..i]);
                let var_start = i + 2;
                let mut var_end = None;
                for (j, inner_c) in chars.by_ref() {
                    if inner_c == '}' {
                        var_end = Some(j);
                        break;
                    }
                }
                if let Some(end) = var_end {
                    let content = &raw[var_start..end];
                    let (var_name, default_val) = match content.split_once(":-") {
                        Some((k, d)) => (k.trim(), Some(d.trim())),
                        None => (content.trim(), None),
                    };

                    let resolved = local_vars
                        .get(var_name)
                        .cloned()
                        .or_else(|| std::env::var(var_name).ok())
                        .or_else(|| default_val.map(|d| d.to_string()))
                        .unwrap_or_default();

                    out.push_str(&resolved);
                    cursor = end + 1;
                } else {
                    cursor = i;
                    break;
                }
            }
        }
    }
    out.push_str(&raw[cursor..]);
    out
}

impl Config {
    /// Loads config from `path` if given, else the platform config directory's
    /// `synapse.toml`, else built-in defaults. Overlaid with environment variables.
    pub fn load(path: Option<&Path>) -> Result<Config, ConfigError> {
        let candidate = match path {
            Some(p) => Some(p.to_path_buf()),
            None => {
                if let Ok(env_path) = std::env::var("SYNAPSE_CONFIG") {
                    Some(PathBuf::from(env_path))
                } else if Path::new("synapse.toml").exists() {
                    Some(PathBuf::from("synapse.toml"))
                } else {
                    directories::ProjectDirs::from("", "", "synapse")
                        .map(|d| d.config_dir().join("synapse.toml"))
                }
            }
        };

        let mut cfg = if let Some(candidate) = candidate {
            match fs::read_to_string(&candidate) {
                Ok(data) => {
                    let expanded = expand_vars(&data);
                    toml::from_str(&expanded).map_err(|source| ConfigError::Parse {
                        path: candidate,
                        source,
                    })?
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && path.is_none() => {
                    Config::default()
                }
                Err(source) => {
                    return Err(ConfigError::Io {
                        path: candidate,
                        source,
                    })
                }
            }
        } else {
            Config::default()
        };

        cfg.apply_env_overrides();
        cfg.resolve_paths();
        Ok(cfg)
    }

    /// Resolves relative disk paths against `[disk].root_dir` if configured.
    pub fn resolve_paths(&mut self) {
        if let Some(ref root) = self.disk.root_dir.clone() {
            if self.disk.download_dir == Path::new(".") {
                self.disk.download_dir = root.join("downloads");
            } else if self.disk.download_dir.is_relative() {
                self.disk.download_dir = root.join(&self.disk.download_dir);
            }

            if self.disk.session_dir.is_relative() {
                self.disk.session_dir = root.join(&self.disk.session_dir);
            }

            if let Some(ref inc) = self.disk.incomplete_dir {
                if inc.is_relative() {
                    self.disk.incomplete_dir = Some(root.join(inc));
                }
            }

            if let Some(ref watch) = self.disk.watch_dir {
                if watch.is_relative() {
                    self.disk.watch_dir = Some(root.join(watch));
                }
            }
        }
    }

    /// Overlays settings from `SYNAPSE_*` environment variables onto this configuration.
    pub fn apply_env_overrides(&mut self) {
        // Disk
        if let Ok(val) = std::env::var("SYNAPSE_ROOT_DIR").or_else(|_| std::env::var("SYNAPSE_DATA_DIR")) {
            self.disk.root_dir = Some(PathBuf::from(val));
        }
        if let Ok(val) = std::env::var("SYNAPSE_DOWNLOAD_DIR") {
            self.disk.download_dir = PathBuf::from(val);
        }
        if let Ok(val) = std::env::var("SYNAPSE_SESSION_DIR") {
            self.disk.session_dir = PathBuf::from(val);
        }
        if let Ok(val) = std::env::var("SYNAPSE_INCOMPLETE_DIR") {
            self.disk.incomplete_dir = Some(PathBuf::from(val));
        }
        if let Ok(val) = std::env::var("SYNAPSE_INCOMPLETE_DIR_ENABLED") {
            if let Ok(b) = val.parse::<bool>() {
                self.disk.incomplete_dir_enabled = b;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_WATCH_DIR") {
            self.disk.watch_dir = Some(PathBuf::from(val));
        }
        if let Ok(val) = std::env::var("SYNAPSE_MAX_OPEN_FILES") {
            if let Ok(n) = val.parse::<usize>() {
                self.disk.max_open_files = n;
            }
        }

        // Network
        if let Ok(val) = std::env::var("SYNAPSE_PEER_PORT")
            .or_else(|_| std::env::var("SYNAPSE_LISTEN_PORT"))
        {
            if let Ok(port) = val.parse::<u16>() {
                self.network.listen_port = port;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_ENABLE_IPV6") {
            if let Ok(b) = val.parse::<bool>() {
                self.network.enable_ipv6 = b;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_ENABLE_DHT") {
            if let Ok(b) = val.parse::<bool>() {
                self.network.enable_dht = b;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_ENABLE_PEX") {
            if let Ok(b) = val.parse::<bool>() {
                self.network.enable_pex = b;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_ENABLE_LSD") {
            if let Ok(b) = val.parse::<bool>() {
                self.network.enable_lsd = b;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_ENCRYPTION") {
            self.network.encryption = val;
        }
        if let Ok(val) = std::env::var("SYNAPSE_MAX_PEERS_PER_TORRENT") {
            if let Ok(n) = val.parse::<usize>() {
                self.network.max_peers_per_torrent = n;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_MAX_GLOBAL_PEERS") {
            if let Ok(n) = val.parse::<usize>() {
                self.network.max_global_peers = n;
            }
        }

        // RPC & HTTP
        if let Ok(val) = std::env::var("SYNAPSE_RPC_LISTEN_ADDR") {
            self.rpc.listen_addr = val;
        }
        if let Ok(val) = std::env::var("SYNAPSE_RPC_AUTH_TOKEN") {
            self.rpc.auth_token = Some(val);
        }
        if let Ok(val) = std::env::var("SYNAPSE_HTTP_LISTEN_ADDR") {
            if let Ok(addr) = val.parse::<SocketAddr>() {
                self.http_api.listen_addr = addr;
            }
        }

        // Bandwidth
        if let Ok(val) = std::env::var("SYNAPSE_DOWNLOAD_LIMIT_ENABLED") {
            if let Ok(b) = val.parse::<bool>() {
                self.bandwidth.download_limit_enabled = b;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_DOWNLOAD_LIMIT") {
            if let Ok(n) = parse_bandwidth_to_bytes(&val) {
                self.bandwidth.download_limit_bytes = n;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_UPLOAD_LIMIT_ENABLED") {
            if let Ok(b) = val.parse::<bool>() {
                self.bandwidth.upload_limit_enabled = b;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_UPLOAD_LIMIT") {
            if let Ok(n) = parse_bandwidth_to_bytes(&val) {
                self.bandwidth.upload_limit_bytes = n;
            }
        }

        // Turtle Mode (Alt Speed)
        if let Ok(val) = std::env::var("SYNAPSE_ALT_SPEED_ENABLED") {
            if let Ok(b) = val.parse::<bool>() {
                self.bandwidth.alt_speed.enabled = b;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_ALT_SPEED_DOWN") {
            if let Ok(n) = parse_bandwidth_to_bytes(&val) {
                self.bandwidth.alt_speed.download_limit_bytes = n;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_ALT_SPEED_UP") {
            if let Ok(n) = parse_bandwidth_to_bytes(&val) {
                self.bandwidth.alt_speed.upload_limit_bytes = n;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_ALT_SPEED_TIME_ENABLED") {
            if let Ok(b) = val.parse::<bool>() {
                self.bandwidth.alt_speed.time_enabled = b;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_ALT_SPEED_TIME_BEGIN") {
            if let Ok(n) = val.parse::<u32>() {
                self.bandwidth.alt_speed.time_begin_minutes = n;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_ALT_SPEED_TIME_END") {
            if let Ok(n) = val.parse::<u32>() {
                self.bandwidth.alt_speed.time_end_minutes = n;
            }
        }

        // Queue
        if let Ok(val) = std::env::var("SYNAPSE_DOWNLOAD_QUEUE_ENABLED") {
            if let Ok(b) = val.parse::<bool>() {
                self.queue.download_queue_enabled = b;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_DOWNLOAD_QUEUE_SIZE")
            .or_else(|_| std::env::var("SYNAPSE_MAX_ACTIVE_DOWNLOADS"))
        {
            if let Ok(n) = val.parse::<usize>() {
                self.queue.download_queue_size = n;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_SEED_QUEUE_ENABLED") {
            if let Ok(b) = val.parse::<bool>() {
                self.queue.seed_queue_enabled = b;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_SEED_QUEUE_SIZE")
            .or_else(|_| std::env::var("SYNAPSE_MAX_ACTIVE_SEEDS"))
        {
            if let Ok(n) = val.parse::<usize>() {
                self.queue.seed_queue_size = n;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_MAX_ACTIVE_TORRENTS") {
            if let Ok(n) = val.parse::<usize>() {
                self.queue.max_active_torrents = n;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_QUEUE_STALLED_ENABLED") {
            if let Ok(b) = val.parse::<bool>() {
                self.queue.queue_stalled_enabled = b;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_QUEUE_STALLED_MINUTES") {
            if let Ok(n) = val.parse::<u32>() {
                self.queue.queue_stalled_minutes = n;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_SEED_RATIO_LIMITED") {
            if let Ok(b) = val.parse::<bool>() {
                self.queue.seed_ratio_limited = b;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_SEED_RATIO_LIMIT") {
            if let Ok(n) = val.parse::<f64>() {
                self.queue.seed_ratio_limit = Some(n);
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_IDLE_SEEDING_LIMIT_ENABLED") {
            if let Ok(b) = val.parse::<bool>() {
                self.queue.idle_seeding_limit_enabled = b;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_IDLE_SEEDING_LIMIT_MINUTES") {
            if let Ok(n) = val.parse::<u32>() {
                self.queue.idle_seeding_limit_minutes = Some(n);
            }
        }

        // Privacy
        if let Ok(val) = std::env::var("SYNAPSE_MASK_PASSKEYS") {
            if let Ok(b) = val.parse::<bool>() {
                self.privacy.mask_passkeys_in_logs = b;
            }
        }
        if let Ok(val) = std::env::var("SYNAPSE_DISABLE_DHT_GLOBALLY") {
            if let Ok(b) = val.parse::<bool>() {
                self.privacy.disable_dht_globally = b;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_default_config_falls_back_to_defaults() {
        let cfg = Config::load(None);
        assert!(cfg.is_ok());
    }

    #[test]
    fn explicit_missing_path_is_an_error() {
        let err = Config::load(Some(Path::new("/nonexistent/does-not-exist.toml")));
        assert!(matches!(err, Err(ConfigError::Io { .. })));
    }

    #[test]
    fn parses_a_real_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synapse.toml");
        fs::write(
            &path,
            r#"
            log_level = "debug"

            [disk]
            session_dir = "/tmp/synapse-session"
            download_dir = "/tmp/synapse-downloads"
            incomplete_dir = "/tmp/synapse-incomplete"
            incomplete_dir_enabled = true
            max_open_files = 100

            [queue]
            download_queue_size = 8
            seed_queue_size = 15
            queue_stalled_minutes = 2

            [bandwidth]
            download_limit_bytes = 10485760
            download_limit_enabled = true

            [bandwidth.alt_speed]
            enabled = true
            download_limit_bytes = 524288
            "#,
        )
        .unwrap();

        let cfg = Config::load(Some(&path)).unwrap();
        assert_eq!(cfg.log_level, LogLevel::Debug);
        assert_eq!(cfg.disk.max_open_files, 100);
        assert_eq!(cfg.disk.download_dir, PathBuf::from("/tmp/synapse-downloads"));
        assert_eq!(cfg.disk.incomplete_dir, Some(PathBuf::from("/tmp/synapse-incomplete")));
        assert!(cfg.disk.incomplete_dir_enabled);
        assert_eq!(cfg.queue.download_queue_size, 8);
        assert_eq!(cfg.queue.seed_queue_size, 15);
        assert_eq!(cfg.queue.queue_stalled_minutes, 2);
        assert!(cfg.bandwidth.download_limit_enabled);
        assert_eq!(cfg.bandwidth.download_limit_bytes, 10485760);
        assert!(cfg.bandwidth.alt_speed.enabled);
        assert_eq!(cfg.bandwidth.alt_speed.download_limit_bytes, 524288);
    }

    #[test]
    fn test_env_overrides() {
        let mut cfg = Config::default();
        std::env::set_var("SYNAPSE_PEER_PORT", "59999");
        std::env::set_var("SYNAPSE_DOWNLOAD_QUEUE_SIZE", "12");
        std::env::set_var("SYNAPSE_ALT_SPEED_ENABLED", "true");
        std::env::set_var("SYNAPSE_ALT_SPEED_DOWN", "250000");

        cfg.apply_env_overrides();

        assert_eq!(cfg.network.listen_port, 59999);
        assert_eq!(cfg.queue.download_queue_size, 12);
        assert!(cfg.bandwidth.alt_speed.enabled);
        assert_eq!(cfg.bandwidth.alt_speed.download_limit_bytes, 250000);

        std::env::remove_var("SYNAPSE_PEER_PORT");
        std::env::remove_var("SYNAPSE_DOWNLOAD_QUEUE_SIZE");
        std::env::remove_var("SYNAPSE_ALT_SPEED_ENABLED");
        std::env::remove_var("SYNAPSE_ALT_SPEED_DOWN");
    }

    #[test]
    fn malformed_config_file_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synapse.toml");
        fs::write(&path, "this is not valid toml {{{").unwrap();

        let err = Config::load(Some(&path));
        assert!(matches!(err, Err(ConfigError::Parse { .. })));
    }

    #[test]
    fn test_variable_interpolation_and_root_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synapse.toml");
        fs::write(
            &path,
            r#"
            data_root = "/mnt/shared/media"

            [disk]
            root_dir = "${data_root}"
            download_dir = "downloads"
            incomplete_dir = "incomplete"
            incomplete_dir_enabled = true
            watch_dir = "${data_root}/watch"
            session_dir = "session"
            "#,
        )
        .unwrap();

        let cfg = Config::load(Some(&path)).unwrap();
        assert_eq!(cfg.disk.root_dir, Some(PathBuf::from("/mnt/shared/media")));
        assert_eq!(cfg.disk.download_dir, PathBuf::from("/mnt/shared/media/downloads"));
        assert_eq!(cfg.disk.incomplete_dir, Some(PathBuf::from("/mnt/shared/media/incomplete")));
        assert_eq!(cfg.disk.watch_dir, Some(PathBuf::from("/mnt/shared/media/watch")));
        assert_eq!(cfg.disk.session_dir, PathBuf::from("/mnt/shared/media/session"));
    }

    #[test]
    fn test_parse_bandwidth_to_bytes() {
        // User requested examples: 50m, 1000m, 1g, 5g
        assert_eq!(parse_bandwidth_to_bytes("50m").unwrap(), 6_250_000);
        assert_eq!(parse_bandwidth_to_bytes("1000m").unwrap(), 125_000_000);
        assert_eq!(parse_bandwidth_to_bytes("1g").unwrap(), 125_000_000);
        assert_eq!(parse_bandwidth_to_bytes("5g").unwrap(), 625_000_000);

        // Case insensitivity and whitespace
        assert_eq!(parse_bandwidth_to_bytes("50M").unwrap(), 6_250_000);
        assert_eq!(parse_bandwidth_to_bytes("  1G  ").unwrap(), 125_000_000);
        assert_eq!(parse_bandwidth_to_bytes("50 mbps").unwrap(), 6_250_000);
        assert_eq!(parse_bandwidth_to_bytes("1000 mbit/s").unwrap(), 125_000_000);
        assert_eq!(parse_bandwidth_to_bytes("100k").unwrap(), 12_500);

        // Floats
        assert_eq!(parse_bandwidth_to_bytes("2.5g").unwrap(), 312_500_000);
        assert_eq!(parse_bandwidth_to_bytes("0.5m").unwrap(), 62_500);

        // Raw bytes backwards compatibility
        assert_eq!(parse_bandwidth_to_bytes("10485760").unwrap(), 10_485_760);

        // Unlimited / 0
        assert_eq!(parse_bandwidth_to_bytes("0").unwrap(), 0);
        assert_eq!(parse_bandwidth_to_bytes("unlimited").unwrap(), 0);
        assert_eq!(parse_bandwidth_to_bytes("off").unwrap(), 0);
    }

    #[test]
    fn test_format_bytes_as_bitrate() {
        assert_eq!(format_bytes_as_bitrate(0), "unlimited");
        assert_eq!(format_bytes_as_bitrate(6_250_000), "50 Mbps");
        assert_eq!(format_bytes_as_bitrate(125_000_000), "1 Gbps");
        assert_eq!(format_bytes_as_bitrate(625_000_000), "5 Gbps");
        assert_eq!(format_bytes_as_bitrate(312_500_000), "2.5 Gbps");
        assert_eq!(format_bytes_as_bitrate(12_500), "100 Kbps");
    }

    #[test]
    fn test_bandwidth_toml_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synapse.toml");
        fs::write(
            &path,
            r#"
            [bandwidth]
            download_limit_enabled = true
            download_limit = "50m"
            upload_limit_enabled = true
            upload_limit = "1g"

            [bandwidth.alt_speed]
            enabled = true
            download_limit = "1000m"
            upload_limit = "5g"
            "#,
        )
        .unwrap();

        let cfg = Config::load(Some(&path)).unwrap();
        assert_eq!(cfg.bandwidth.download_limit_bytes, 6_250_000);
        assert_eq!(cfg.bandwidth.upload_limit_bytes, 125_000_000);
        assert_eq!(cfg.bandwidth.alt_speed.download_limit_bytes, 125_000_000);
        assert_eq!(cfg.bandwidth.alt_speed.upload_limit_bytes, 625_000_000);
    }

    #[test]
    fn test_load_example_config_file() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let example_path = manifest_dir.join("../../example_config.toml");
        if example_path.exists() {
            let cfg = Config::load(Some(&example_path)).expect("example_config.toml must be valid syntax and parse cleanly");
            assert!(cfg.queue.download_queue_enabled);
            assert!(cfg.network.enable_pex);
            assert!(cfg.network.enable_lsd);
            assert!(cfg.lifecycle.start_added_torrents);
            assert!(!cfg.lifecycle.trash_original_torrent_files);
            assert_eq!(cfg.bandwidth.download_limit_bytes, 6_250_000);
            assert_eq!(cfg.bandwidth.upload_limit_bytes, 125_000_000);
            assert_eq!(cfg.bandwidth.alt_speed.download_limit_bytes, 625_000);
            assert_eq!(cfg.bandwidth.alt_speed.upload_limit_bytes, 125_000);
        }
    }
}

