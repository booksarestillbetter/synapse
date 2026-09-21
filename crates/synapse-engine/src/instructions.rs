//! "Ask conduit where this goes" completion plugin — an in-process replacement for the
//! Transmission `script-torrent-done-filename` + copy2queue.py/.pl hook conduit already
//! generates for other clients (see conduit's `GET /api/sync/hook-script` and
//! `src/api/sync_routes.rs::classify_file`/`notify_download`). Instead of conduit generating a
//! shell script that gets exec'd, synapse makes the same two HTTP calls itself and performs
//! the file placement in-process.
//!
//! The wire contract (what synapse sends, what it expects back) isn't conduit-specific — see
//! `doc/COMPLETION_INSTRUCTIONS.md` for the full spec if you're pointing this at something
//! other than conduit.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::lifecycle::{ConduitPlugin, LifecycleError, LifecyclePlugin, TorrentCompletedEvent};

#[derive(Debug, Clone)]
pub struct InstructionsConfig {
    /// Base URL, e.g. "http://127.0.0.1:4242" — `/api/sync/classify` and
    /// `/api/sync/notify-download` are appended.
    pub url: String,
    pub token: Option<String>,
    pub node_name: String,
    pub timeout: Duration,
    pub fallback_dir: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct ClassifyRequest<'a> {
    name: &'a str,
    hash: &'a str,
    node: &'a str,
    dir: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tracker: Option<&'a str>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    trackers: &'a [String],
    total_bytes: u64,
}

#[derive(Debug, Deserialize, Default)]
struct ClassifyResponse {
    #[serde(default)]
    target_dir: String,
    #[serde(default)]
    post_cmd: String,
    #[serde(default)]
    queue: String,
}

#[derive(Debug, Serialize)]
struct NotifyRequest<'a> {
    hash: &'a str,
    name: &'a str,
    node: &'a str,
    path: &'a str,
    queue: &'a str,
    target_dir: &'a str,
}

/// Whether to hardlink, copy, or move each file — decided from the instructions response's
/// `post_cmd` (see doc/COMPLETION_INSTRUCTIONS.md). synapse interprets its *intent* rather
/// than literally shelling it out (unlike copy2queue.py/.pl, which exec the string directly)
/// — no shell-injection surface from a value that came back over the network, and it works
/// the same way regardless of what's actually installed in the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileOp {
    Hardlink,
    Copy,
    Move,
}

impl FileOp {
    fn from_post_cmd(cmd: &str) -> Self {
        let lower = cmd.trim().to_lowercase();
        if lower.starts_with("mv") {
            FileOp::Move
        } else if lower.contains("-l") || lower.contains("--link") || lower.contains("hardlink") {
            FileOp::Hardlink
        } else {
            FileOp::Copy
        }
    }

    fn apply(self, src: &Path, dst: &Path) -> std::io::Result<()> {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match self {
            FileOp::Hardlink => ConduitPlugin::link_or_copy(src, dst),
            FileOp::Copy => {
                std::fs::copy(src, dst)?;
                Ok(())
            }
            FileOp::Move => match std::fs::rename(src, dst) {
                Ok(()) => Ok(()),
                Err(e) if e.raw_os_error() == Some(18) /* EXDEV */ => {
                    std::fs::copy(src, dst)?;
                    std::fs::remove_file(src)?;
                    Ok(())
                }
                Err(e) => Err(e),
            },
        }
    }
}

pub struct ConduitInstructionsPlugin {
    http: reqwest::Client,
    config: InstructionsConfig,
}

impl ConduitInstructionsPlugin {
    pub fn new(config: InstructionsConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .unwrap_or_default();
        Self { http, config }
    }

    fn authed(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.config.token.as_deref() {
            Some(t) if !t.is_empty() => req.bearer_auth(t),
            _ => req,
        }
    }

    async fn classify(
        &self,
        event: &TorrentCompletedEvent,
    ) -> Result<ClassifyResponse, reqwest::Error> {
        let url = format!(
            "{}/api/sync/classify",
            self.config.url.trim_end_matches('/')
        );
        let body = ClassifyRequest {
            name: &event.name,
            hash: &event.info_hash_hex,
            node: &self.config.node_name,
            dir: &event.download_dir,
            tracker: event.trackers.first().map(String::as_str),
            trackers: &event.trackers,
            total_bytes: event.total_bytes,
        };
        let req = self.authed(self.http.post(&url).json(&body));
        req.send()
            .await?
            .error_for_status()?
            .json::<ClassifyResponse>()
            .await
    }

    async fn notify(
        &self,
        event: &TorrentCompletedEvent,
        queue: &str,
        target_dir: &str,
        final_path: &str,
    ) {
        let url = format!(
            "{}/api/sync/notify-download",
            self.config.url.trim_end_matches('/')
        );
        let body = NotifyRequest {
            hash: &event.info_hash_hex,
            name: &event.name,
            node: &self.config.node_name,
            path: final_path,
            queue,
            target_dir,
        };
        let req = self.authed(self.http.post(&url).json(&body));
        if let Err(e) = req.send().await {
            // Non-fatal: file placement already happened by the time this runs, this is just
            // telling conduit about it for its own event log / notifications.
            warn!(
                "conduit_instructions: notify-download failed (file already placed): {}",
                e
            );
        }
    }

    /// Places every file in `event.files` (or the whole torrent, for a single-file one) into
    /// `target_dir`, using `op` for each. Returns the destination root.
    fn place_files(
        &self,
        event: &TorrentCompletedEvent,
        target_dir: &Path,
        op: FileOp,
    ) -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(target_dir)?;
        let dest_root = target_dir.join(&event.name);

        if event.files.is_empty() {
            let src = Path::new(&event.download_dir).join(&event.name);
            op.apply(&src, &dest_root)?;
        } else {
            for f in &event.files {
                let src = Path::new(&event.download_dir).join(&f.path);
                let dst = target_dir.join(&f.path);
                if src.exists() {
                    op.apply(&src, &dst)?;
                }
            }
        }
        Ok(dest_root)
    }
}

#[async_trait]
impl LifecyclePlugin for ConduitInstructionsPlugin {
    fn name(&self) -> &str {
        "conduit_instructions"
    }

    async fn on_torrent_completed(
        &self,
        event: &TorrentCompletedEvent,
    ) -> Result<(), LifecycleError> {
        match self.classify(event).await {
            Ok(resp) if !resp.target_dir.is_empty() => {
                let op = FileOp::from_post_cmd(&resp.post_cmd);
                match self.place_files(event, Path::new(&resp.target_dir), op) {
                    Ok(final_path) => {
                        info!(
                            "conduit_instructions: placed '{}' into {} (queue={}, op={:?})",
                            event.name, resp.target_dir, resp.queue, op
                        );
                        self.notify(
                            event,
                            &resp.queue,
                            &resp.target_dir,
                            &final_path.to_string_lossy(),
                        )
                        .await;
                    }
                    Err(e) => {
                        error!(
                            "conduit_instructions: failed to place '{}' into {}: {}",
                            event.name, resp.target_dir, e
                        );
                        return Err(LifecycleError::Staging(e.to_string()));
                    }
                }
            }
            Ok(_) => {
                debug!(
                    "conduit_instructions: classify returned no target_dir for '{}', leaving at {}",
                    event.name, event.download_dir
                );
            }
            Err(e) => match &self.config.fallback_dir {
                Some(fallback) => {
                    warn!(
                        "conduit_instructions: {} unreachable ({}), falling back to {}",
                        self.config.url,
                        e,
                        fallback.display()
                    );
                    if let Err(e) = self.place_files(event, fallback, FileOp::Hardlink) {
                        error!(
                            "conduit_instructions: fallback placement into {} also failed: {}",
                            fallback.display(),
                            e
                        );
                    }
                }
                None => {
                    warn!(
                        "conduit_instructions: {} unreachable ({}), leaving '{}' at {}",
                        self.config.url, e, event.name, event.download_dir
                    );
                }
            },
        }
        Ok(())
    }
}
