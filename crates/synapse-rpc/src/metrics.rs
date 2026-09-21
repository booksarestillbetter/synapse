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
    pub nat_mapped_port: Option<u16>,
    pub chokes_total: u64,
    pub unchokes_total: u64,
    pub piece_requests_total: u64,
    pub piece_rejects_total: u64,
    pub hash_fails_total: u64,
    pub peer_bans_total: u64,
    pub disk_write_queue_bytes: usize,
    pub utp_packet_loss_total: u64,
    pub dht_dos_blocks_total: u64,
}

pub fn render_prometheus_metrics(snapshot: &PrometheusSnapshot) -> String {
    let mut out = String::with_capacity(2048);

    writeln!(
        out,
        "# HELP synapse_torrents_total Total number of managed torrents by state"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_torrents_total gauge").unwrap();
    writeln!(
        out,
        "synapse_torrents_total{{state=\"total\"}} {}",
        snapshot.total_torrents
    )
    .unwrap();
    writeln!(
        out,
        "synapse_torrents_total{{state=\"downloading\"}} {}",
        snapshot.downloading_torrents
    )
    .unwrap();
    writeln!(
        out,
        "synapse_torrents_total{{state=\"seeding\"}} {}",
        snapshot.seeding_torrents
    )
    .unwrap();
    writeln!(
        out,
        "synapse_torrents_total{{state=\"paused\"}} {}",
        snapshot.paused_torrents
    )
    .unwrap();

    writeln!(
        out,
        "# HELP synapse_bytes_downloaded_total Total bytes downloaded across all swarms"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_bytes_downloaded_total counter").unwrap();
    writeln!(
        out,
        "synapse_bytes_downloaded_total {}",
        snapshot.bytes_downloaded
    )
    .unwrap();

    writeln!(
        out,
        "# HELP synapse_bytes_uploaded_total Total bytes uploaded across all swarms"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_bytes_uploaded_total counter").unwrap();
    writeln!(
        out,
        "synapse_bytes_uploaded_total {}",
        snapshot.bytes_uploaded
    )
    .unwrap();

    writeln!(
        out,
        "# HELP synapse_download_rate_bytes Current global download rate in bytes/sec"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_download_rate_bytes gauge").unwrap();
    writeln!(
        out,
        "synapse_download_rate_bytes {}",
        snapshot.download_rate
    )
    .unwrap();

    writeln!(
        out,
        "# HELP synapse_upload_rate_bytes Current global upload rate in bytes/sec"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_upload_rate_bytes gauge").unwrap();
    writeln!(out, "synapse_upload_rate_bytes {}", snapshot.upload_rate).unwrap();

    writeln!(
        out,
        "# HELP synapse_peers_connected_total Total active connected peer sockets"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_peers_connected_total gauge").unwrap();
    writeln!(
        out,
        "synapse_peers_connected_total {}",
        snapshot.connected_peers
    )
    .unwrap();

    writeln!(
        out,
        "# HELP synapse_circuit_breakers_tripped Number of currently tripped peer circuit breakers"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_circuit_breakers_tripped gauge").unwrap();
    writeln!(
        out,
        "synapse_circuit_breakers_tripped {}",
        snapshot.circuit_breakers_tripped
    )
    .unwrap();

    writeln!(
        out,
        "# HELP synapse_dht_nodes_total Number of good routing nodes in Kademlia DHT table"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_dht_nodes_total gauge").unwrap();
    writeln!(out, "synapse_dht_nodes_total {}", snapshot.dht_nodes).unwrap();

    if let Some(port) = snapshot.nat_mapped_port {
        writeln!(
            out,
            "# HELP synapse_nat_mapped_port Externally mapped NAT port via UPnP or NAT-PMP"
        )
        .unwrap();
        writeln!(out, "# TYPE synapse_nat_mapped_port gauge").unwrap();
        writeln!(out, "synapse_nat_mapped_port {}", port).unwrap();
    }

    writeln!(
        out,
        "# HELP synapse_chokes_total Total number of peer choke decisions executed"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_chokes_total counter").unwrap();
    writeln!(out, "synapse_chokes_total {}", snapshot.chokes_total).unwrap();

    writeln!(
        out,
        "# HELP synapse_unchokes_total Total number of peer unchoke decisions executed"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_unchokes_total counter").unwrap();
    writeln!(out, "synapse_unchokes_total {}", snapshot.unchokes_total).unwrap();

    writeln!(
        out,
        "# HELP synapse_choke_decisions_total Total choke and unchoke decisions executed"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_choke_decisions_total counter").unwrap();
    writeln!(
        out,
        "synapse_choke_decisions_total{{action=\"choke\"}} {}",
        snapshot.chokes_total
    )
    .unwrap();
    writeln!(
        out,
        "synapse_choke_decisions_total{{action=\"unchoke\"}} {}",
        snapshot.unchokes_total
    )
    .unwrap();

    writeln!(
        out,
        "# HELP synapse_piece_requests_total Total piece/block requests sent and received"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_piece_requests_total counter").unwrap();
    writeln!(
        out,
        "synapse_piece_requests_total {}",
        snapshot.piece_requests_total
    )
    .unwrap();

    writeln!(
        out,
        "# HELP synapse_piece_rejects_total Total piece/block requests rejected"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_piece_rejects_total counter").unwrap();
    writeln!(
        out,
        "synapse_piece_rejects_total {}",
        snapshot.piece_rejects_total
    )
    .unwrap();

    writeln!(
        out,
        "# HELP synapse_requests_rejected_total Total piece/block requests rejected alias"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_requests_rejected_total counter").unwrap();
    writeln!(
        out,
        "synapse_requests_rejected_total {}",
        snapshot.piece_rejects_total
    )
    .unwrap();

    writeln!(
        out,
        "# HELP synapse_piece_hash_failures_total Total piece hash check verification failures"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_piece_hash_failures_total counter").unwrap();
    writeln!(
        out,
        "synapse_piece_hash_failures_total {}",
        snapshot.hash_fails_total
    )
    .unwrap();

    writeln!(out, "# HELP synapse_peer_bans_total Total peers banned due to protocol violations or hash fails").unwrap();
    writeln!(out, "# TYPE synapse_peer_bans_total counter").unwrap();
    writeln!(out, "synapse_peer_bans_total {}", snapshot.peer_bans_total).unwrap();

    writeln!(
        out,
        "# HELP synapse_disk_write_queue_bytes Current queued in-flight disk write bytes"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_disk_write_queue_bytes gauge").unwrap();
    writeln!(
        out,
        "synapse_disk_write_queue_bytes {}",
        snapshot.disk_write_queue_bytes
    )
    .unwrap();

    writeln!(
        out,
        "# HELP synapse_utp_packet_loss_total Total retransmitted or lost uTP packets"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_utp_packet_loss_total counter").unwrap();
    writeln!(
        out,
        "synapse_utp_packet_loss_total {}",
        snapshot.utp_packet_loss_total
    )
    .unwrap();

    writeln!(
        out,
        "# HELP synapse_utp_packets_lost_total Total retransmitted or lost uTP packets alias"
    )
    .unwrap();
    writeln!(out, "# TYPE synapse_utp_packets_lost_total counter").unwrap();
    writeln!(
        out,
        "synapse_utp_packets_lost_total {}",
        snapshot.utp_packet_loss_total
    )
    .unwrap();

    writeln!(out, "# HELP synapse_dht_dos_blocked_total Total DHT messages dropped by rate limiting and DoS mitigation").unwrap();
    writeln!(out, "# TYPE synapse_dht_dos_blocked_total counter").unwrap();
    writeln!(
        out,
        "synapse_dht_dos_blocked_total {}",
        snapshot.dht_dos_blocks_total
    )
    .unwrap();

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
            nat_mapped_port: Some(54321),
            chokes_total: 12,
            unchokes_total: 15,
            piece_requests_total: 1000,
            piece_rejects_total: 5,
            hash_fails_total: 1,
            peer_bans_total: 2,
            disk_write_queue_bytes: 65536,
            utp_packet_loss_total: 8,
            dht_dos_blocks_total: 19,
        };

        let rendered = render_prometheus_metrics(&snapshot);
        assert!(rendered.contains("synapse_torrents_total{state=\"total\"} 42"));
        assert!(rendered.contains("synapse_bytes_downloaded_total 1073741824"));
        assert!(rendered.contains("synapse_download_rate_bytes 10485760"));
        assert!(rendered.contains("synapse_dht_nodes_total 384"));
        assert!(rendered.contains("synapse_nat_mapped_port 54321"));
        assert!(rendered.contains("synapse_chokes_total 12"));
        assert!(rendered.contains("synapse_unchokes_total 15"));
        assert!(rendered.contains("synapse_choke_decisions_total{action=\"choke\"} 12"));
        assert!(rendered.contains("synapse_choke_decisions_total{action=\"unchoke\"} 15"));
        assert!(rendered.contains("synapse_piece_requests_total 1000"));
        assert!(rendered.contains("synapse_piece_rejects_total 5"));
        assert!(rendered.contains("synapse_requests_rejected_total 5"));
        assert!(rendered.contains("synapse_piece_hash_failures_total 1"));
        assert!(rendered.contains("synapse_peer_bans_total 2"));
        assert!(rendered.contains("synapse_disk_write_queue_bytes 65536"));
        assert!(rendered.contains("synapse_utp_packet_loss_total 8"));
        assert!(rendered.contains("synapse_utp_packets_lost_total 8"));
        assert!(rendered.contains("synapse_dht_dos_blocked_total 19"));
    }
}
