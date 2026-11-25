use crate::proto::v2::{TorrentDelta, TorrentDeltaBatch, TorrentListEvent, TorrentSummary};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tokio::time::interval;

const MAX_DELTAS_PER_BATCH: usize = 500;

#[derive(Debug, Clone)]
pub struct EventBus {
    sender: broadcast::Sender<TorrentListEvent>,
    sequence_id: Arc<AtomicU64>,
    pending_deltas: Arc<DashMap<String, TorrentDelta>>,
    lagged_events_total: Arc<AtomicU64>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            sequence_id: Arc::new(AtomicU64::new(1)),
            pending_deltas: Arc::new(DashMap::new()),
            lagged_events_total: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_lag(&self, skipped: u64) {
        self.lagged_events_total
            .fetch_add(skipped, Ordering::Relaxed);
    }

    pub fn lagged_events_total(&self) -> u64 {
        self.lagged_events_total.load(Ordering::Relaxed)
    }

    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TorrentListEvent> {
        self.sender.subscribe()
    }

    pub fn emit_summary_added(&self, summary: TorrentSummary) {
        self.pending_deltas.remove(&summary.hash);
        if self.sender.receiver_count() == 0 {
            return;
        }
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
        self.pending_deltas.remove(&hash);
        if self.sender.receiver_count() == 0 {
            return;
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let seq = self.sequence_id.fetch_add(1, Ordering::SeqCst);
        let event = TorrentListEvent {
            sequence_id: seq,
            timestamp_ms: now_ms,
            event: Some(crate::proto::v2::torrent_list_event::Event::RemovedHash(
                hash,
            )),
        };
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
                if let Some(qp) = delta.queue_position {
                    existing.queue_position = Some(qp);
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

                if self.sender.receiver_count() == 0 {
                    continue;
                }

                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;

                if deltas.len() == 1 {
                    let seq = self.sequence_id.fetch_add(1, Ordering::SeqCst);
                    let event = TorrentListEvent {
                        sequence_id: seq,
                        timestamp_ms: now_ms,
                        event: Some(crate::proto::v2::torrent_list_event::Event::Updated(
                            deltas.pop().expect("len checked"),
                        )),
                    };
                    let _ = self.sender.send(event);
                } else {
                    while !deltas.is_empty() {
                        let chunk: Vec<TorrentDelta> = deltas
                            .drain(..deltas.len().min(MAX_DELTAS_PER_BATCH))
                            .collect();
                        let seq = self.sequence_id.fetch_add(1, Ordering::SeqCst);
                        let event = TorrentListEvent {
                            sequence_id: seq,
                            timestamp_ms: now_ms,
                            event: Some(crate::proto::v2::torrent_list_event::Event::UpdatedBatch(
                                TorrentDeltaBatch { deltas: chunk },
                            )),
                        };
                        let _ = self.sender.send(event);
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::v2::torrent_list_event::Event;

    #[tokio::test]
    async fn single_delta_emits_updated_and_multi_delta_emits_bounded_batches() {
        let bus = Arc::new(EventBus::new(32));
        assert_eq!(bus.subscriber_count(), 0);

        // Zero-subscriber emission skips sequence allocation and clears pending deltas.
        bus.emit_summary_added(TorrentSummary {
            hash: "00".repeat(20),
            ..Default::default()
        });
        bus.record_delta(TorrentDelta {
            hash: "00".repeat(20),
            progress: Some(0.1),
            ..Default::default()
        });
        bus.emit_removed("00".repeat(20));

        let mut rx = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 1);
        let flusher = bus.clone().start_flusher(Duration::from_millis(15));

        // 1) Single delta emits backwards-compatible Event::Updated.
        bus.record_delta(TorrentDelta {
            hash: "aa".repeat(20),
            progress: Some(0.5),
            ..Default::default()
        });
        let single = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(single.event, Some(Event::Updated(d)) if d.progress == Some(0.5)));

        // 2) >500 deltas coalesce into chunks of <= 500 via Event::UpdatedBatch.
        for i in 0..505u32 {
            bus.record_delta(TorrentDelta {
                hash: format!("{i:040x}"),
                rate_download: Some(u64::from(i)),
                ..Default::default()
            });
        }
        let mut received = Vec::new();
        while received.len() < 505 {
            let ev = tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            match ev.event {
                Some(Event::UpdatedBatch(batch)) => {
                    assert!(batch.deltas.len() <= MAX_DELTAS_PER_BATCH);
                    received.extend(batch.deltas);
                }
                other => panic!("expected UpdatedBatch, got {other:?}"),
            }
        }
        assert_eq!(received.len(), 505);
        flusher.abort();
    }
}
