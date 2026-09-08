//! Conduit Dynamic Ingest & Lifecycle Execution Engine for Synapse 2.0.
//!
//! Provides a pluggable post-processing pipeline (`LifecyclePlugin` trait):
//! - `ConduitPlugin`: instant piece/torrent completion event dispatch, automatic payload
//!   hardlinking into staging directories, and offline Write-Ahead Log (WAL) recording for reliable
//!   event replay with Conduit.
//! - `PostScriptPlugin`: non-blocking execution of external post-processing scripts or copy-scripts
//!   with rich environment variable and argument passing.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("staging error: {0}")]
    Staging(String),
    #[error("plugin error from {plugin}: {message}")]
    Plugin { plugin: String, message: String },
}

/// One file within a completed torrent, relative to `TorrentCompletedEvent::download_dir` —
/// matches `synapse_meta::File`'s shape but with its own `Serialize`/`Deserialize` (needed for
/// the WAL's JSON persistence; adding that to `synapse_meta::File` itself would be a
/// synapse-meta change for something only this crate's completion-event plumbing needs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedFileInfo {
    pub path: String,
    pub length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorrentCompletedEvent {
    pub info_hash_hex: String,
    pub name: String,
    pub total_bytes: u64,
    /// The raw configured download directory (not joined with `name`) — for a multi-file
    /// torrent, `files[].path` is already relative to this, matching the convention
    /// `Torrent::write_piece`/`serve_request` use (`download_dir.join(&info.files[i].path)`,
    /// no separate `.join(name)` step).
    pub download_dir: String,
    pub source_path: String,
    pub staged_path: Option<String>,
    pub timestamp_ms: i64,
    /// Announce URL(s) this torrent's tracker tier(s) list, host-and-scheme included — for
    /// plugins that route by tracker (see `instructions::ConduitInstructionsPlugin`, which
    /// mirrors conduit's own tracker-domain/regex media-type matching).
    #[serde(default)]
    pub trackers: Vec<String>,
    #[serde(default)]
    pub files: Vec<CompletedFileInfo>,
}

/// Pluggable lifecycle handler for post-download processing and external integrations.
#[async_trait]
pub trait LifecyclePlugin: Send + Sync {
    fn name(&self) -> &str;
    async fn on_torrent_completed(&self, event: &TorrentCompletedEvent) -> Result<(), LifecycleError>;
}

/// Conduit Plugin: automates payload hardlinking and offline WAL persistence.
pub struct ConduitPlugin {
    staging_dir: Option<PathBuf>,
    auto_hardlink: bool,
    wal_path: Option<PathBuf>,
}

impl ConduitPlugin {
    pub fn new(staging_dir: Option<PathBuf>, auto_hardlink: bool, wal_path: Option<PathBuf>) -> Self {
        if let Some(ref wal_path) = wal_path {
            if let Some(parent) = wal_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
        }
        if let Some(ref staging_dir) = staging_dir {
            let _ = fs::create_dir_all(staging_dir);
        }
        Self {
            staging_dir,
            auto_hardlink,
            wal_path,
        }
    }

    pub fn perform_hardlinks(
        &self,
        source_dir: &Path,
        name: &str,
        files: &[synapse_meta::File],
    ) -> std::io::Result<Option<PathBuf>> {
        let Some(ref staging_root) = self.staging_dir else {
            return Ok(None);
        };
        if !self.auto_hardlink {
            return Ok(None);
        }

        if files.is_empty() || files.len() == 1 {
            // Single-file torrent
            let src = source_dir.join(name);
            let dst = staging_root.join(name);
            Self::link_or_copy(&src, &dst)?;
            Ok(Some(dst))
        } else {
            // Multi-file torrent
            let target_root = staging_root.join(name);
            for file in files {
                let src = source_dir.join(&file.path);
                let dst = staging_root.join(&file.path);
                if src.exists() {
                    Self::link_or_copy(&src, &dst)?;
                }
            }
            Ok(Some(target_root))
        }
    }

/// Hardlinks `src` to `dst`, falling back to a real copy across filesystem boundaries
/// (`EXDEV`) — crate-visible so `instructions::ConduitInstructionsPlugin` can reuse the same
/// link-or-copy semantics for its own "post_cmd said hardlink" case instead of duplicating it.
pub(crate) fn link_or_copy(src: &Path, dst: &Path) -> std::io::Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    if dst.exists() {
        let _ = fs::remove_file(dst);
    }
    match fs::hard_link(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
            debug!("Cross-device hardlink detected for {:?} -> {:?}, falling back to copy", src, dst);
            fs::copy(src, dst)?;
            Ok(())
        }
        Err(e) => {
            if e.raw_os_error() == Some(18) {
                debug!("Cross-device hardlink (EXDEV) detected for {:?} -> {:?}, falling back to copy", src, dst);
                fs::copy(src, dst)?;
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

    fn append_to_wal(&self, wal_path: &Path, event: &TorrentCompletedEvent) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(wal_path)?;

        let line = serde_json::to_string(event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        writeln!(file, "{}", line)?;
        file.sync_all()?;
        debug!("Appended completion event for {} to WAL", event.info_hash_hex);
        Ok(())
    }

    /// Reads and clears unacknowledged records from the offline WAL.
    pub fn drain_wal(&self) -> std::io::Result<Vec<TorrentCompletedEvent>> {
        let Some(ref wal_path) = self.wal_path else {
            return Ok(Vec::new());
        };

        if !wal_path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(wal_path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(event) = serde_json::from_str::<TorrentCompletedEvent>(&line) {
                events.push(event);
            }
        }

        // Truncate WAL after draining
        let _ = fs::remove_file(wal_path);

        Ok(events)
    }
}

#[async_trait]
impl LifecyclePlugin for ConduitPlugin {
    fn name(&self) -> &str {
        "conduit"
    }

    async fn on_torrent_completed(&self, event: &TorrentCompletedEvent) -> Result<(), LifecycleError> {
        if let Some(ref wal_path) = self.wal_path {
            if let Err(e) = self.append_to_wal(wal_path, event) {
                error!("Failed to append completion event to WAL {:?}: {}", wal_path, e);
                return Err(LifecycleError::Io(e));
            }
        }
        Ok(())
    }
}

/// Post-Script Plugin: invokes an external shell script, binary, or copy utility asynchronously upon completion.
pub struct PostScriptPlugin {
    plugin_name: String,
    script_path: PathBuf,
}

impl PostScriptPlugin {
    pub fn new(plugin_name: impl Into<String>, script_path: PathBuf) -> Self {
        Self {
            plugin_name: plugin_name.into(),
            script_path,
        }
    }
}

#[async_trait]
impl LifecyclePlugin for PostScriptPlugin {
    fn name(&self) -> &str {
        &self.plugin_name
    }

    async fn on_torrent_completed(&self, event: &TorrentCompletedEvent) -> Result<(), LifecycleError> {
        if !self.script_path.exists() {
            warn!("Post-processing script {:?} not found, skipping execution", self.script_path);
            return Ok(());
        }

        info!("Executing {} post-processing script: {:?}", self.plugin_name, self.script_path);

        let staged = event.staged_path.clone().unwrap_or_default();
        let status = tokio::process::Command::new(&self.script_path)
            .arg(&event.info_hash_hex)
            .arg(&event.name)
            .arg(&event.source_path)
            .arg(&staged)
            .arg(event.total_bytes.to_string())
            .env("SYNAPSE_INFO_HASH", &event.info_hash_hex)
            .env("SYNAPSE_TORRENT_NAME", &event.name)
            .env("SYNAPSE_SOURCE_PATH", &event.source_path)
            .env("SYNAPSE_STAGED_PATH", &staged)
            .env("SYNAPSE_TOTAL_BYTES", event.total_bytes.to_string())
            .env("SYNAPSE_TIMESTAMP_MS", event.timestamp_ms.to_string())
            .status()
            .await;

        match status {
            Ok(s) if s.success() => {
                info!("Post-processing script {:?} completed successfully", self.script_path);
                Ok(())
            }
            Ok(s) => {
                warn!("Post-processing script {:?} exited with non-zero status: {}", self.script_path, s);
                Err(LifecycleError::Plugin {
                    plugin: self.plugin_name.clone(),
                    message: format!("Script exited with {}", s),
                })
            }
            Err(e) => {
                error!("Failed to spawn post-processing script {:?}: {}", self.script_path, e);
                Err(LifecycleError::Io(e))
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct LifecycleConfig {
    pub staging_dir: Option<PathBuf>,
    pub auto_hardlink: bool,
    pub wal_path: Option<PathBuf>,
    pub post_script: Option<PathBuf>,
    pub copy_script: Option<PathBuf>,
    /// `Some` registers `instructions::ConduitInstructionsPlugin`; `None` (the default) means
    /// disabled — see that module for what it does.
    pub instructions: Option<crate::instructions::InstructionsConfig>,
}

pub struct ConduitLifecycleDispatcher {
    conduit_plugin: Arc<ConduitPlugin>,
    plugins: Vec<Arc<dyn LifecyclePlugin>>,
}

impl ConduitLifecycleDispatcher {
    pub fn new(config: LifecycleConfig) -> Self {
        let conduit_plugin = Arc::new(ConduitPlugin::new(
            config.staging_dir.clone(),
            config.auto_hardlink,
            config.wal_path.clone(),
        ));

        let mut plugins: Vec<Arc<dyn LifecyclePlugin>> = vec![conduit_plugin.clone()];

        if let Some(post_script) = config.post_script {
            plugins.push(Arc::new(PostScriptPlugin::new("post_script", post_script)));
        }
        if let Some(copy_script) = config.copy_script {
            plugins.push(Arc::new(PostScriptPlugin::new("copy_script", copy_script)));
        }
        if let Some(instructions_cfg) = config.instructions {
            plugins.push(Arc::new(crate::instructions::ConduitInstructionsPlugin::new(instructions_cfg)));
        }

        Self {
            conduit_plugin,
            plugins,
        }
    }

    /// Registers an additional custom plugin into the lifecycle dispatch pipeline.
    pub fn with_plugin(mut self, plugin: Arc<dyn LifecyclePlugin>) -> Self {
        self.plugins.push(plugin);
        self
    }

    pub fn register_plugin(&mut self, plugin: Arc<dyn LifecyclePlugin>) {
        self.plugins.push(plugin);
    }

    /// Handles completion of a torrent by performing staging hardlinks and dispatching to all registered plugins.
    #[allow(clippy::too_many_arguments)]
    pub async fn on_torrent_completed(
        &self,
        info_hash: [u8; 20],
        name: &str,
        total_bytes: u64,
        download_dir: &Path,
        files: &[synapse_meta::File],
        trackers: &[String],
    ) -> Result<TorrentCompletedEvent, LifecycleError> {
        let hash_hex = hex::encode(info_hash);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let source_path = download_dir.join(name);
        let mut staged_path: Option<String> = None;

        // Perform staging hardlinks via conduit plugin
        match self.conduit_plugin.perform_hardlinks(download_dir, name, files) {
            Ok(Some(staged)) => {
                info!("Successfully staged hardlinks for {} in {:?}", name, staged);
                staged_path = Some(staged.to_string_lossy().to_string());
            }
            Ok(None) => {}
            Err(e) => {
                warn!("Failed to stage hardlinks for {}: {} (falling back to direct path)", name, e);
            }
        }

        let event = TorrentCompletedEvent {
            info_hash_hex: hash_hex,
            name: name.to_string(),
            total_bytes,
            download_dir: download_dir.to_string_lossy().to_string(),
            source_path: source_path.to_string_lossy().to_string(),
            staged_path,
            timestamp_ms: now_ms,
            trackers: trackers.to_vec(),
            files: files.iter().map(|f| CompletedFileInfo { path: f.path.to_string_lossy().to_string(), length: f.length }).collect(),
        };

        // Dispatch to all registered plugins asynchronously
        for plugin in &self.plugins {
            if let Err(e) = plugin.on_torrent_completed(&event).await {
                error!("Plugin {} failed on completed event for {}: {}", plugin.name(), event.name, e);
            }
        }

        Ok(event)
    }

    /// Access the underlying ConduitPlugin for WAL drainage.
    pub fn conduit_plugin(&self) -> &ConduitPlugin {
        &self.conduit_plugin
    }

    /// Reads and clears unacknowledged records from the offline WAL.
    pub fn drain_wal(&self) -> std::io::Result<Vec<TorrentCompletedEvent>> {
        self.conduit_plugin.drain_wal()
    }
}
