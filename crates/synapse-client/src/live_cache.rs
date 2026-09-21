//! High-performance local caching engine backed by the live delta stream.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::client::SynapseClient;
use synapse_proto::v2::torrent_list_event::Event;
use synapse_proto::v2::{TorrentDelta, TorrentSummary};

/// Thread-safe in-memory cache of all active swarms synchronized via sparse delta streams.
#[derive(Clone)]
pub struct SynapseLiveCache {
    torrents: Arc<RwLock<HashMap<String, TorrentSummary>>>,
    connected: Arc<AtomicBool>,
    _task_handle: Arc<AbortOnDrop>,
}

struct AbortOnDrop(JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl SynapseLiveCache {
    /// Spawns a background task maintaining a synchronized local replica of all swarms.
    pub fn spawn(client: SynapseClient) -> Self {
        let torrents = Arc::new(RwLock::new(HashMap::new()));
        let connected = Arc::new(AtomicBool::new(false));

        let cache_clone = torrents.clone();
        let conn_clone = connected.clone();

        let handle = tokio::spawn(async move {
            run_delta_sync_loop(client, cache_clone, conn_clone).await;
        });

        Self {
            torrents,
            connected,
            _task_handle: Arc::new(AbortOnDrop(handle)),
        }
    }

    /// Whether the background stream is actively connected to the Synapse daemon.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    /// Returns a point-in-time snapshot list of all currently tracked torrents.
    pub fn list_torrents(&self) -> Vec<TorrentSummary> {
        self.torrents.read().values().cloned().collect()
    }

    /// Looks up a specific torrent by its info-hash.
    pub fn get_torrent(&self, hash: &str) -> Option<TorrentSummary> {
        self.torrents.read().get(hash).cloned()
    }

    /// Returns the total number of cached torrents.
    pub fn count(&self) -> usize {
        self.torrents.read().len()
    }
}

async fn run_delta_sync_loop(
    client: SynapseClient,
    torrents: Arc<RwLock<HashMap<String, TorrentSummary>>>,
    connected: Arc<AtomicBool>,
) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(30);

    loop {
        debug!(
            "Connecting to Synapse live delta stream at {}",
            client.endpoint()
        );
        match client.subscribe_torrents(250, 100).await {
            Ok(mut stream) => {
                info!("Connected to Synapse live delta stream");
                connected.store(true, Ordering::Release);
                backoff = Duration::from_secs(1);

                let mut snapshot_buffer: Vec<TorrentSummary> = Vec::new();

                while let Ok(Some(event)) = stream.message().await {
                    match event.event {
                        Some(Event::Snapshot(chunk)) => {
                            snapshot_buffer.extend(chunk.items);
                            if chunk.is_last_chunk {
                                let mut map = HashMap::with_capacity(snapshot_buffer.len());
                                for t in snapshot_buffer.drain(..) {
                                    map.insert(t.hash.clone(), t);
                                }
                                *torrents.write() = map;
                                debug!(
                                    "Applied full torrent snapshot ({} swarms)",
                                    torrents.read().len()
                                );
                            }
                        }
                        Some(Event::Added(t)) => {
                            torrents.write().insert(t.hash.clone(), t);
                        }
                        Some(Event::Updated(delta)) => {
                            apply_delta(&mut torrents.write(), delta);
                        }
                        Some(Event::RemovedHash(hash)) => {
                            torrents.write().remove(&hash);
                        }
                        None => {}
                    }
                }
                warn!("Synapse delta stream ended, will reconnect");
                connected.store(false, Ordering::Release);
            }
            Err(e) => {
                connected.store(false, Ordering::Release);
                warn!(
                    "Failed to connect to Synapse stream: {e}; retrying in {:?}",
                    backoff
                );
            }
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(max_backoff);
    }
}

fn apply_delta(torrents: &mut HashMap<String, TorrentSummary>, delta: TorrentDelta) {
    if let Some(t) = torrents.get_mut(&delta.hash) {
        if let Some(progress) = delta.progress {
            t.progress = progress;
        }
        if let Some(state) = delta.state {
            t.state = state;
        }
        if let Some(rate_dl) = delta.rate_download {
            t.rate_download = rate_dl;
        }
        if let Some(rate_ul) = delta.rate_upload {
            t.rate_upload = rate_ul;
        }
        if let Some(peers) = delta.peers_connected {
            t.peers_connected = peers;
        }
        if let Some(sending) = delta.peers_sending {
            t.peers_sending = sending;
        }
        if let Some(eta) = delta.eta_seconds {
            t.eta_seconds = eta;
        }
        if let Some(ratio) = delta.ratio {
            t.ratio = ratio;
        }
        if delta.error_message.is_some() {
            t.error_message = delta.error_message;
        }
    }
}
