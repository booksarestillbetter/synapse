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
                backoff = Duration::from_secs(1);

                let mut snapshot_buffer: Vec<TorrentSummary> = Vec::new();

                while let Ok(Some(event)) = stream.message().await {
                    apply_stream_event(&mut snapshot_buffer, &torrents, &connected, event.event);
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

fn apply_stream_event(
    snapshot_buffer: &mut Vec<TorrentSummary>,
    torrents: &RwLock<HashMap<String, TorrentSummary>>,
    connected: &AtomicBool,
    event: Option<Event>,
) {
    match event {
        Some(Event::Snapshot(chunk)) => {
            snapshot_buffer.extend(chunk.items);
            if chunk.is_last_chunk {
                let mut map = HashMap::with_capacity(snapshot_buffer.len());
                for t in snapshot_buffer.drain(..) {
                    map.insert(t.hash.clone(), t);
                }
                let len = map.len();
                *torrents.write() = map;
                connected.store(true, Ordering::Release);
                debug!("Applied full torrent snapshot ({len} swarms)");
            }
        }
        Some(Event::Added(t)) => {
            torrents.write().insert(t.hash.clone(), t);
        }
        Some(Event::Updated(delta)) => {
            apply_delta(&mut torrents.write(), delta);
        }
        Some(Event::UpdatedBatch(batch)) => {
            let mut map = torrents.write();
            for delta in batch.deltas {
                apply_delta(&mut map, delta);
            }
        }
        Some(Event::RemovedHash(hash)) => {
            torrents.write().remove(&hash);
        }
        None => {}
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
        if let Some(err) = delta.error_message {
            t.error_message = if err.is_empty() { None } else { Some(err) };
        }
        if let Some(qp) = delta.queue_position {
            t.queue_position = qp;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synapse_proto::v2::TorrentSnapshotChunk;

    #[test]
    fn apply_delta_updates_queue_position_and_clears_error_on_empty_string() {
        let mut map = HashMap::new();
        map.insert(
            "aa".repeat(20),
            TorrentSummary {
                hash: "aa".repeat(20),
                error_message: Some("tracker timeout".to_string()),
                queue_position: 2,
                ..Default::default()
            },
        );

        apply_delta(
            &mut map,
            TorrentDelta {
                hash: "aa".repeat(20),
                error_message: Some(String::new()),
                queue_position: Some(0),
                ..Default::default()
            },
        );

        let item = map.get(&"aa".repeat(20)).unwrap();
        assert_eq!(item.error_message, None);
        assert_eq!(item.queue_position, 0);
    }

    #[test]
    fn connected_stays_false_until_last_snapshot_chunk_arrives() {
        let torrents = RwLock::new(HashMap::new());
        let connected = AtomicBool::new(false);
        let mut buf = Vec::new();

        apply_stream_event(
            &mut buf,
            &torrents,
            &connected,
            Some(Event::Snapshot(TorrentSnapshotChunk {
                items: vec![TorrentSummary {
                    hash: "bb".repeat(20),
                    ..Default::default()
                }],
                chunk_index: 0,
                total_chunks: 2,
                is_last_chunk: false,
            })),
        );
        assert!(!connected.load(Ordering::Acquire));
        assert!(torrents.read().is_empty());

        apply_stream_event(
            &mut buf,
            &torrents,
            &connected,
            Some(Event::Snapshot(TorrentSnapshotChunk {
                items: vec![TorrentSummary {
                    hash: "cc".repeat(20),
                    ..Default::default()
                }],
                chunk_index: 1,
                total_chunks: 2,
                is_last_chunk: true,
            })),
        );
        assert!(connected.load(Ordering::Acquire));
        assert_eq!(torrents.read().len(), 2);
    }

    #[test]
    fn updated_batch_applies_all_deltas_to_cached_torrents() {
        let h1 = "dd".repeat(20);
        let h2 = "ee".repeat(20);
        let torrents = RwLock::new(HashMap::from([
            (
                h1.clone(),
                TorrentSummary {
                    hash: h1.clone(),
                    progress: 0.1,
                    ..Default::default()
                },
            ),
            (
                h2.clone(),
                TorrentSummary {
                    hash: h2.clone(),
                    progress: 0.2,
                    ..Default::default()
                },
            ),
        ]));
        let connected = AtomicBool::new(true);
        let mut buf = Vec::new();

        apply_stream_event(
            &mut buf,
            &torrents,
            &connected,
            Some(Event::UpdatedBatch(synapse_proto::v2::TorrentDeltaBatch {
                deltas: vec![
                    TorrentDelta {
                        hash: h1.clone(),
                        progress: Some(0.9),
                        rate_download: Some(1234),
                        ..Default::default()
                    },
                    TorrentDelta {
                        hash: h2.clone(),
                        progress: Some(1.0),
                        rate_upload: Some(5678),
                        ..Default::default()
                    },
                ],
            })),
        );

        let guard = torrents.read();
        assert_eq!(guard[&h1].progress, 0.9);
        assert_eq!(guard[&h1].rate_download, 1234);
        assert_eq!(guard[&h2].progress, 1.0);
        assert_eq!(guard[&h2].rate_upload, 5678);
    }
}
