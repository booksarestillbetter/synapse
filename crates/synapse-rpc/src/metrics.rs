//! Prometheus Metrics Exporter for Synapse 2.0.
//!
//! Generates standard Prometheus exposition text format at `/metrics` reporting
//! swarm counts, bandwidth throughput, disk I/O, peer connections, and health.

use std::fmt::Write;

#[derive(Debug, Clone, Default)]
pub struct PrometheusSnapshot {
    pub total_torrents: usize,
    pub downloading_torrents: usize,
    pub seeding_torrents: usize,
    pub paused_torrents: usize,
    pub bytes_downloaded: u64,
    pub bytes_uploaded: u64,
    pub download_rate: u64,
    pub upload_rate: u64,
    pub connected_peers: usize,
    pub circuit_breakers_tripped: usize,
    pub dht_nodes: usize,
}

pub fn render_prometheus_metrics(snapshot: &PrometheusSnapshot) -> String {
    let mut out = String::with_capacity(1024);

    writeln!(out, "# HELP synapse_torrents_total Total number of managed torrents by state").unwrap();
    writeln!(out, "# TYPE synapse_torrents_total gauge").unwrap();
    writeln!(out, "synapse_torrents_total{{state=\"total\"}} {}", snapshot.total_torrents).unwrap();
    writeln!(out, "synapse_torrents_total{{state=\"downloading\"}} {}", snapshot.downloading_torrents).unwrap();
    writeln!(out, "synapse_torrents_total{{state=\"seeding\"}} {}", snapshot.seeding_torrents).unwrap();
    writeln!(out, "synapse_torrents_total{{state=\"paused\"}} {}", snapshot.paused_torrents).unwrap();

    writeln!(out, "# HELP synapse_bytes_downloaded_total Total bytes downloaded across all swarms").unwrap();
    writeln!(out, "# TYPE synapse_bytes_downloaded_total counter").unwrap();
    writeln!(out, "synapse_bytes_downloaded_total {}", snapshot.bytes_downloaded).unwrap();

    writeln!(out, "# HELP synapse_bytes_uploaded_total Total bytes uploaded across all swarms").unwrap();
    writeln!(out, "# TYPE synapse_bytes_uploaded_total counter").unwrap();
    writeln!(out, "synapse_bytes_uploaded_total {}", snapshot.bytes_uploaded).unwrap();

    writeln!(out, "# HELP synapse_download_rate_bytes Current global download rate in bytes/sec").unwrap();
    writeln!(out, "# TYPE synapse_download_rate_bytes gauge").unwrap();
    writeln!(out, "synapse_download_rate_bytes {}", snapshot.download_rate).unwrap();

    writeln!(out, "# HELP synapse_upload_rate_bytes Current global upload rate in bytes/sec").unwrap();
    writeln!(out, "# TYPE synapse_upload_rate_bytes gauge").unwrap();
    writeln!(out, "synapse_upload_rate_bytes {}", snapshot.upload_rate).unwrap();

    writeln!(out, "# HELP synapse_peers_connected_total Total active connected peer sockets").unwrap();
    writeln!(out, "# TYPE synapse_peers_connected_total gauge").unwrap();
    writeln!(out, "synapse_peers_connected_total {}", snapshot.connected_peers).unwrap();

    writeln!(out, "# HELP synapse_circuit_breakers_tripped Number of currently tripped peer circuit breakers").unwrap();
    writeln!(out, "# TYPE synapse_circuit_breakers_tripped gauge").unwrap();
    writeln!(out, "synapse_circuit_breakers_tripped {}", snapshot.circuit_breakers_tripped).unwrap();

    writeln!(out, "# HELP synapse_dht_nodes_total Number of good routing nodes in Kademlia DHT table").unwrap();
    writeln!(out, "# TYPE synapse_dht_nodes_total gauge").unwrap();
    writeln!(out, "synapse_dht_nodes_total {}", snapshot.dht_nodes).unwrap();

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_prometheus_metrics_format() {
        let snapshot = PrometheusSnapshot {
            total_torrents: 42,
            downloading_torrents: 10,
            seeding_torrents: 30,
            paused_torrents: 2,
            bytes_downloaded: 1073741824,
            bytes_uploaded: 2147483648,
            download_rate: 10485760,
            upload_rate: 5242880,
            connected_peers: 150,
            circuit_breakers_tripped: 0,
            dht_nodes: 384,
        };

        let rendered = render_prometheus_metrics(&snapshot);
        assert!(rendered.contains("synapse_torrents_total{state=\"total\"} 42"));
        assert!(rendered.contains("synapse_bytes_downloaded_total 1073741824"));
        assert!(rendered.contains("synapse_download_rate_bytes 10485760"));
        assert!(rendered.contains("synapse_dht_nodes_total 384"));
    }
}
