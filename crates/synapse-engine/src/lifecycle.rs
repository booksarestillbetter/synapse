//! Post-download lifecycle & completion-processing engine for Synapse 2.0.
//!
//! Provides a pluggable post-processing pipeline (`LifecyclePlugin` trait):
//! - `StagingPlugin`: instant piece/torrent completion event dispatch, automatic payload
//!   hardlinking into staging directories, and offline Write-Ahead Log (WAL) recording for reliable
//!   event replay with an external consumer (e.g. a management app), if one is watching.
//! - `PostScriptPlugin`: non-blocking execution of external post-processing scripts or copy-scripts
//!   with rich environment variable and argument passing.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

/// Default timeout enforced on external lifecycle post/copy scripts before SIGKILL.
pub const DEFAULT_SCRIPT_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum byte length of potentially large environment variables (`SYNAPSE_FILES`,
/// `SYNAPSE_TRACKERS`, `SYNAPSE_EVENT_JSON`) before truncation to avoid OS `E2BIG`.
pub const MAX_ENV_FIELD_BYTES: usize = 32 * 1024;

static TEMP_EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn truncate_env_value(s: &str, max_bytes: usize) -> (&str, bool) {
    if s.len() <= max_bytes {
        return (s, false);
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (&s[..end], true)
}

struct TempEventJsonGuard(PathBuf);

impl Drop for TempEventJsonGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn write_temp_event_json(info_hash_hex: &str, json: &str) -> std::io::Result<TempEventJsonGuard> {
    let temp_dir = std::env::temp_dir();
    let pid = std::process::id();
    let prefix = info_hash_hex.get(..8).unwrap_or(info_hash_hex);
    for _ in 0..16 {
        let seq = TEMP_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = temp_dir.join(format!("synapse_event_{pid}_{seq}_{prefix}.json"));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(mut file) => {
                file.write_all(json.as_bytes())?;
                file.flush()?;
                return Ok(TempEventJsonGuard(path));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "failed to allocate unique temporary event JSON file",
    ))
}

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
    /// plugins that route by tracker (see `instructions::InstructionsWebhookPlugin`, which
    /// mirrors the same tracker-domain/regex media-type matching a management app's own
    /// routing rules would use).
    #[serde(default)]
    pub trackers: Vec<String>,
    #[serde(default)]
    pub files: Vec<CompletedFileInfo>,
}

/// Pluggable lifecycle handler for post-download processing and external integrations.
#[async_trait]
pub trait LifecyclePlugin: Send + Sync {
    fn name(&self) -> &str;
    async fn on_torrent_completed(
        &self,
        event: &TorrentCompletedEvent,
    ) -> Result<(), LifecycleError>;
}

/// Staging plugin: automates payload hardlinking and offline WAL persistence.
pub struct StagingPlugin {
    staging_dir: Option<PathBuf>,
    auto_hardlink: bool,
    wal_path: Option<PathBuf>,
    wal_lock: Arc<parking_lot::Mutex<()>>,
}

impl StagingPlugin {
    pub fn new(
        staging_dir: Option<PathBuf>,
        auto_hardlink: bool,
        wal_path: Option<PathBuf>,
    ) -> Self {
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
            wal_lock: Arc::new(parking_lot::Mutex::new(())),
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

        if files.is_empty() {
            // Legacy/empty-files fallback
            let rel = Path::new(name);
            crate::fs::verify_no_symlinks_under(source_dir, rel)?;
            crate::fs::verify_no_symlinks_under(staging_root, rel)?;
            let src = source_dir.join(rel);
            let dst = staging_root.join(rel);
            Self::link_or_copy(&src, &dst)?;
            Ok(Some(dst))
        } else if files.len() == 1 {
            // Single-file torrent (may still have a nested relative path)
            let rel = &files[0].path;
            crate::fs::verify_no_symlinks_under(source_dir, rel)?;
            crate::fs::verify_no_symlinks_under(staging_root, rel)?;
            let src = source_dir.join(rel);
            let dst = staging_root.join(rel);
            Self::link_or_copy(&src, &dst)?;
            Ok(Some(dst))
        } else {
            // Multi-file torrent
            let name_rel = Path::new(name);
            crate::fs::verify_no_symlinks_under(staging_root, name_rel)?;
            let target_root = staging_root.join(name_rel);
            for file in files {
                crate::fs::verify_no_symlinks_under(source_dir, &file.path)?;
                crate::fs::verify_no_symlinks_under(staging_root, &file.path)?;
                let src = source_dir.join(&file.path);
                let dst = staging_root.join(&file.path);
                if src.exists() {
                    Self::link_or_copy(&src, &dst)?;
                }
            }
            Ok(Some(target_root))
        }
    }

    fn make_temp_sibling(dst: &Path) -> PathBuf {
        static TMP_STAGE_COUNTER: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let parent = dst
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let seq = TMP_STAGE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        parent.join(format!(".synapse_stage_tmp.{}.{}", std::process::id(), seq))
    }

    pub(crate) fn is_same_file(
        src_meta: &fs::Metadata,
        dst_meta: &fs::Metadata,
        src: &Path,
        dst: &Path,
    ) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if src_meta.dev() == dst_meta.dev() && src_meta.ino() == dst_meta.ino() {
                return true;
            }
        }
        #[cfg(not(unix))]
        let _ = (src_meta, dst_meta);
        match (fs::canonicalize(src), fs::canonicalize(dst)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }

    pub(crate) fn copy_via_temp_and_rename(src: &Path, dst: &Path) -> std::io::Result<()> {
        struct CleanOnDrop(PathBuf);
        impl Drop for CleanOnDrop {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.0);
            }
        }
        let guard = CleanOnDrop(Self::make_temp_sibling(dst));
        fs::copy(src, &guard.0)?;
        fs::rename(&guard.0, dst)?;
        std::mem::forget(guard);
        Ok(())
    }

    /// Hardlinks `src` to `dst`, falling back to a real copy across filesystem boundaries
    /// (`EXDEV`) — crate-visible so `instructions::InstructionsWebhookPlugin` can reuse the same
    /// link-or-copy semantics for its own "post_cmd said hardlink" case instead of duplicating it.
    pub(crate) fn link_or_copy(src: &Path, dst: &Path) -> std::io::Result<()> {
        struct CleanOnDrop(PathBuf);
        impl Drop for CleanOnDrop {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.0);
            }
        }

        let src_meta = fs::symlink_metadata(src)?;
        if !src_meta.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("source {:?} is not a regular file", src),
            ));
        }

        if let Some(parent) = dst.parent() {
            if let Ok(pmeta) = fs::symlink_metadata(parent) {
                if pmeta.file_type().is_symlink() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("destination parent {:?} is a symlink", parent),
                    ));
                }
            }
            fs::create_dir_all(parent)?;
        }

        match fs::symlink_metadata(dst) {
            Ok(dst_meta) => {
                if dst_meta.file_type().is_symlink() || dst_meta.file_type().is_dir() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("destination {:?} is a symlink or directory", dst),
                    ));
                }
                if Self::is_same_file(&src_meta, &dst_meta, src, dst) {
                    return Ok(());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }

        let guard = CleanOnDrop(Self::make_temp_sibling(dst));
        match fs::hard_link(src, &guard.0) {
            Ok(()) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::CrossesDevices
                    || e.raw_os_error() == Some(18) =>
            {
                debug!(
                    "Cross-device hardlink detected for {:?} -> {:?}, falling back to copy",
                    src, dst
                );
                fs::copy(src, &guard.0)?;
            }
            Err(e) => return Err(e),
        }
        fs::rename(&guard.0, dst)?;
        std::mem::forget(guard);
        Ok(())
    }

    fn append_to_wal(&self, wal_path: &Path, event: &TorrentCompletedEvent) -> std::io::Result<()> {
        let _guard = self.wal_lock.lock();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(wal_path)?;

        let line = serde_json::to_string(event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        writeln!(file, "{}", line)?;
        file.sync_all()?;
        debug!(
            "Appended completion event for {} to WAL",
            event.info_hash_hex
        );
        Ok(())
    }

    /// Reads and clears unacknowledged records from the offline WAL.
    pub fn drain_wal(&self) -> std::io::Result<Vec<TorrentCompletedEvent>> {
        let Some(ref wal_path) = self.wal_path else {
            return Ok(Vec::new());
        };

        let _guard = self.wal_lock.lock();
        if !wal_path.exists() {
            return Ok(Vec::new());
        }

        // Atomically detach the live WAL via rename before parsing so concurrent appends start a clean file.
        let drained_path = Self::make_temp_sibling(wal_path);
        fs::rename(wal_path, &drained_path)?;

        let file = File::open(&drained_path)?;
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

        let _ = fs::remove_file(&drained_path);

        Ok(events)
    }
}

#[async_trait]
impl LifecyclePlugin for StagingPlugin {
    fn name(&self) -> &str {
        "staging"
    }

    async fn on_torrent_completed(
        &self,
        event: &TorrentCompletedEvent,
    ) -> Result<(), LifecycleError> {
        if let Some(ref wal_path) = self.wal_path {
            if let Err(e) = self.append_to_wal(wal_path, event) {
                error!(
                    "Failed to append completion event to WAL {:?}: {}",
                    wal_path, e
                );
                return Err(LifecycleError::Io(e));
            }
        }
        Ok(())
    }
}

/// Post-Script Plugin: invokes an external shell script, binary, or copy utility asynchronously
/// upon completion. Fully self-sufficient — every field of `TorrentCompletedEvent` reaches the
/// script one way or another (individual `SYNAPSE_*` variables for the common ones, the full
/// event as JSON in `SYNAPSE_EVENT_JSON` for anything else), so a script doesn't need to call
/// back into synapse or any other service to learn what it needs to know. See
/// `doc/POST_SCRIPTS.md` for the full reference and an example script.
pub struct PostScriptPlugin {
    plugin_name: String,
    script_path: PathBuf,
    timeout: Duration,
}

impl PostScriptPlugin {
    pub fn new(plugin_name: impl Into<String>, script_path: PathBuf) -> Self {
        Self {
            plugin_name: plugin_name.into(),
            script_path,
            timeout: DEFAULT_SCRIPT_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = if timeout.is_zero() {
            DEFAULT_SCRIPT_TIMEOUT
        } else {
            timeout
        };
        self
    }
}

#[async_trait]
impl LifecyclePlugin for PostScriptPlugin {
    fn name(&self) -> &str {
        &self.plugin_name
    }

    async fn on_torrent_completed(
        &self,
        event: &TorrentCompletedEvent,
    ) -> Result<(), LifecycleError> {
        if !self.script_path.exists() {
            warn!(
                "Post-processing script {:?} not found, skipping execution",
                self.script_path
            );
            return Ok(());
        }

        info!(
            "Executing {} post-processing script: {:?}",
            self.plugin_name, self.script_path
        );

        let staged = event.staged_path.clone().unwrap_or_default();
        // Newline-joined, not comma-joined: a tracker URL's query string or a file's path can
        // itself contain a comma, but BitTorrent paths and announce URLs can never contain a
        // literal newline, so this splits back apart unambiguously in a shell script
        // (`while IFS= read -r line; do ...; done <<< "$SYNAPSE_FILES"`).
        let file_paths_full = event
            .files
            .iter()
            .map(|f| f.path.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let trackers_full = event.trackers.join("\n");
        let event_json = serde_json::to_string(event).unwrap_or_default();

        let (file_paths, files_truncated) =
            truncate_env_value(&file_paths_full, MAX_ENV_FIELD_BYTES);
        let (trackers, trackers_truncated) =
            truncate_env_value(&trackers_full, MAX_ENV_FIELD_BYTES);
        let (event_json_env, event_json_truncated) =
            truncate_env_value(&event_json, MAX_ENV_FIELD_BYTES);

        let temp_json_guard = write_temp_event_json(&event.info_hash_hex, &event_json)?;

        let mut cmd = tokio::process::Command::new(&self.script_path);
        cmd.arg(&event.info_hash_hex)
            .arg(&event.name)
            .arg(&event.source_path)
            .arg(&staged)
            .arg(event.total_bytes.to_string())
            .env("SYNAPSE_INFO_HASH", &event.info_hash_hex)
            .env("SYNAPSE_TORRENT_NAME", &event.name)
            .env("SYNAPSE_DOWNLOAD_DIR", &event.download_dir)
            .env("SYNAPSE_SOURCE_PATH", &event.source_path)
            .env("SYNAPSE_STAGED_PATH", &staged)
            .env("SYNAPSE_TOTAL_BYTES", event.total_bytes.to_string())
            .env("SYNAPSE_TIMESTAMP_MS", event.timestamp_ms.to_string())
            .env("SYNAPSE_FILE_COUNT", event.files.len().to_string())
            .env("SYNAPSE_FILES", file_paths)
            .env("SYNAPSE_TRACKERS", trackers)
            .env("SYNAPSE_EVENT_JSON", event_json_env)
            .env("SYNAPSE_EVENT_JSON_FILE", &temp_json_guard.0)
            .stdin(std::process::Stdio::piped())
            .kill_on_drop(true);

        if files_truncated {
            cmd.env("SYNAPSE_FILES_TRUNCATED", "1");
        }
        if trackers_truncated {
            cmd.env("SYNAPSE_TRACKERS_TRUNCATED", "1");
        }
        if event_json_truncated {
            cmd.env("SYNAPSE_EVENT_JSON_TRUNCATED", "1");
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                error!(
                    "Failed to spawn post-processing script {:?}: {}",
                    self.script_path, e
                );
                return Err(LifecycleError::Io(e));
            }
        };

        let status = tokio::time::timeout(self.timeout, async {
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                if let Err(e) = stdin.write_all(event_json.as_bytes()).await {
                    if e.kind() != std::io::ErrorKind::BrokenPipe {
                        return Err(e);
                    }
                }
                let _ = stdin.shutdown().await;
            }
            child.wait().await
        })
        .await;

        match status {
            Ok(Ok(s)) if s.success() => {
                info!(
                    "Post-processing script {:?} completed successfully",
                    self.script_path
                );
                Ok(())
            }
            Ok(Ok(s)) => {
                warn!(
                    "Post-processing script {:?} exited with non-zero status: {}",
                    self.script_path, s
                );
                Err(LifecycleError::Plugin {
                    plugin: self.plugin_name.clone(),
                    message: format!("Script exited with {}", s),
                })
            }
            Ok(Err(e)) => {
                error!(
                    "Failed waiting on post-processing script {:?}: {}",
                    self.script_path, e
                );
                Err(LifecycleError::Io(e))
            }
            Err(_) => {
                warn!(
                    "Post-processing script {:?} timed out after {:?}; terminating child",
                    self.script_path, self.timeout
                );
                let _ = child.kill().await;
                let _ = child.wait().await;
                Err(LifecycleError::Plugin {
                    plugin: self.plugin_name.clone(),
                    message: format!("Script timed out after {:?}", self.timeout),
                })
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
    /// Maximum runtime allowed for external `post_script` / `copy_script` processes.
    /// `None` defaults to `DEFAULT_SCRIPT_TIMEOUT` (300s).
    pub script_timeout: Option<Duration>,
    /// `Some` registers `instructions::InstructionsWebhookPlugin`; `None` (the default) means
    /// disabled — see that module for what it does.
    pub instructions: Option<crate::instructions::InstructionsConfig>,
}

pub struct LifecycleDispatcher {
    staging_plugin: Arc<StagingPlugin>,
    plugins: Vec<Arc<dyn LifecyclePlugin>>,
}

impl LifecycleDispatcher {
    pub fn new(config: LifecycleConfig) -> Self {
        let staging_plugin = Arc::new(StagingPlugin::new(
            config.staging_dir.clone(),
            config.auto_hardlink,
            config.wal_path.clone(),
        ));

        let mut plugins: Vec<Arc<dyn LifecyclePlugin>> = vec![staging_plugin.clone()];
        let script_timeout = config.script_timeout.unwrap_or(DEFAULT_SCRIPT_TIMEOUT);

        if let Some(post_script) = config.post_script {
            plugins.push(Arc::new(
                PostScriptPlugin::new("post_script", post_script).with_timeout(script_timeout),
            ));
        }
        if let Some(copy_script) = config.copy_script {
            plugins.push(Arc::new(
                PostScriptPlugin::new("copy_script", copy_script).with_timeout(script_timeout),
            ));
        }
        if let Some(instructions_cfg) = config.instructions {
            plugins.push(Arc::new(
                crate::instructions::InstructionsWebhookPlugin::new(instructions_cfg),
            ));
        }

        Self {
            staging_plugin,
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

        // Perform staging hardlinks via the staging plugin
        match self
            .staging_plugin
            .perform_hardlinks(download_dir, name, files)
        {
            Ok(Some(staged)) => {
                info!("Successfully staged hardlinks for {} in {:?}", name, staged);
                staged_path = Some(staged.to_string_lossy().to_string());
            }
            Ok(None) => {}
            Err(e) => {
                warn!(
                    "Failed to stage hardlinks for {}: {} (falling back to direct path)",
                    name, e
                );
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
            files: files
                .iter()
                .map(|f| CompletedFileInfo {
                    path: f.path.to_string_lossy().to_string(),
                    length: f.length,
                })
                .collect(),
        };

        // Dispatch to all registered plugins asynchronously
        for plugin in &self.plugins {
            if let Err(e) = plugin.on_torrent_completed(&event).await {
                error!(
                    "Plugin {} failed on completed event for {}: {}",
                    plugin.name(),
                    event.name,
                    e
                );
            }
        }

        Ok(event)
    }

    /// Access the underlying StagingPlugin for WAL drainage.
    pub fn staging_plugin(&self) -> &StagingPlugin {
        &self.staging_plugin
    }

    /// Reads and clears unacknowledged records from the offline WAL.
    pub fn drain_wal(&self) -> std::io::Result<Vec<TorrentCompletedEvent>> {
        self.staging_plugin.drain_wal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_or_copy_same_file_and_hardlink_preserve_content() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("payload.bin");
        std::fs::write(&file, b"important data").unwrap();

        // Same path must be a safe no-op, not unlink-then-fail.
        StagingPlugin::link_or_copy(&file, &file).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"important data");

        // Pre-existing hardlink to the same inode must also be a safe no-op.
        let alias = dir.path().join("alias.bin");
        std::fs::hard_link(&file, &alias).unwrap();
        StagingPlugin::link_or_copy(&file, &alias).unwrap();
        assert_eq!(std::fs::read(&alias).unwrap(), b"important data");

        // Failed replacement must leave an existing destination untouched.
        let missing = dir.path().join("does_not_exist.bin");
        let existing_dst = dir.path().join("keep.bin");
        std::fs::write(&existing_dst, b"do not lose me").unwrap();
        assert!(StagingPlugin::link_or_copy(&missing, &existing_dst).is_err());
        assert_eq!(std::fs::read(&existing_dst).unwrap(), b"do not lose me");
    }
}
