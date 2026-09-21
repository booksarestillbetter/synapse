use crate::proto::v2::{TorrentDelta, TorrentListEvent, TorrentSummary};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tokio::time::interval;

#[derive(Debug, Clone)]
pub struct EventBus {
    sender: broadcast::Sender<TorrentListEvent>,
    sequence_id: Arc<AtomicU64>,
    pending_deltas: Arc<DashMap<String, TorrentDelta>>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            sequence_id: Arc::new(AtomicU64::new(1)),
            pending_deltas: Arc::new(DashMap::new()),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TorrentListEvent> {
        self.sender.subscribe()
    }

    pub fn emit_summary_added(&self, summary: TorrentSummary) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let seq = self.sequence_id.fetch_add(1, Ordering::SeqCst);
        let event = TorrentListEvent {
            sequence_id: seq,
            timestamp_ms: now_ms,
            event: Some(crate::proto::v2::torrent_list_event::Event::Added(summary)),
        };
        let _ = self.sender.send(event);
    }

    pub fn emit_removed(&self, hash: String) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let seq = self.sequence_id.fetch_add(1, Ordering::SeqCst);
        let event = TorrentListEvent {
            sequence_id: seq,
            timestamp_ms: now_ms,
            event: Some(crate::proto::v2::torrent_list_event::Event::RemovedHash(
                hash.clone(),
            )),
        };
        self.pending_deltas.remove(&hash);
        let _ = self.sender.send(event);
    }

    pub fn record_delta(&self, delta: TorrentDelta) {
        self.pending_deltas
            .entry(delta.hash.clone())
            .and_modify(|existing| {
                if let Some(p) = delta.progress {
                    existing.progress = Some(p);
                }
                if let Some(s) = delta.state {
                    existing.state = Some(s);
                }
                if let Some(rd) = delta.rate_download {
                    existing.rate_download = Some(rd);
                }
                if let Some(ru) = delta.rate_upload {
                    existing.rate_upload = Some(ru);
                }
                if let Some(pc) = delta.peers_connected {
                    existing.peers_connected = Some(pc);
                }
                if let Some(ps) = delta.peers_sending {
                    existing.peers_sending = Some(ps);
                }
                if let Some(eta) = delta.eta_seconds {
                    existing.eta_seconds = Some(eta);
                }
                if let Some(r) = delta.ratio {
                    existing.ratio = Some(r);
                }
                if let Some(err) = &delta.error_message {
                    existing.error_message = Some(err.clone());
                }
            })
            .or_insert(delta);
    }

    pub fn start_flusher(self: Arc<Self>, flush_interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = interval(flush_interval);
            loop {
                ticker.tick().await;
                if self.pending_deltas.is_empty() {
                    continue;
                }

                // Atomically drain pending deltas shard-by-shard to avoid dropping concurrent inserts
                let mut deltas = Vec::new();
                self.pending_deltas.retain(|_, v| {
                    deltas.push(v.clone());
                    false
                });

                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;

                for delta in deltas {
                    let seq = self.sequence_id.fetch_add(1, Ordering::SeqCst);
                    let event = TorrentListEvent {
                        sequence_id: seq,
                        timestamp_ms: now_ms,
                        event: Some(crate::proto::v2::torrent_list_event::Event::Updated(delta)),
                    };
                    let _ = self.sender.send(event);
                }
            }
        })
    }
}
