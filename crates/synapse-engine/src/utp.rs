//! BEP 29 Micro Transport Protocol (uTP) Connection Engine & LEDBAT Congestion Control.
//!
//! Provides delay-based congestion control (LEDBAT) over UDP to prevent saturating
//! user internet links while maintaining high-speed BitTorrent throughput.

use bytes::Bytes;
use std::time::{SystemTime, UNIX_EPOCH};
use synapse_wire::{UtpHeader, UtpPacket, UtpType};

/// Target queuing delay in microseconds (100ms per BEP 29).
pub const LEDBAT_TARGET_DELAY_US: u32 = 100_000;
/// Minimum window size in bytes (2 packets ~ 3000 bytes).
pub const MIN_CWND_BYTES: u32 = 3_000;
/// Maximum default window size in bytes (10MB).
pub const MAX_CWND_BYTES: u32 = 10 * 1024 * 1024;

/// LEDBAT (Low Extra Delay Background Transport) Delay-Based Congestion Controller.
#[derive(Debug, Clone)]
pub struct LedbatCongestionController {
    pub target_delay_us: u32,
    pub max_window_bytes: u32,
    pub base_delay_us: u32,
    pub cur_delay_us: u32,
}

impl LedbatCongestionController {
    pub fn new() -> Self {
        Self {
            target_delay_us: LEDBAT_TARGET_DELAY_US,
            max_window_bytes: MIN_CWND_BYTES,
            base_delay_us: u32::MAX,
            cur_delay_us: 0,
        }
    }

    /// Records an ACK with its one-way delay sample and adapts the congestion window.
    pub fn on_ack(&mut self, bytes_acked: u32, delay_sample_us: u32) {
        if delay_sample_us == 0 {
            return;
        }

        if delay_sample_us < self.base_delay_us {
            self.base_delay_us = delay_sample_us;
        }
        self.cur_delay_us = delay_sample_us;

        let queue_delay = delay_sample_us.saturating_sub(self.base_delay_us);
        let off_target = (self.target_delay_us as f64 - queue_delay as f64) / (self.target_delay_us as f64);

        // Standard LEDBAT window adaptation formula:
        // window_delta = GAIN * off_target * (bytes_acked / max_window)
        let window_factor = (bytes_acked as f64) / (self.max_window_bytes.max(1) as f64);
        let delta = (3000.0 * off_target * window_factor) as i32;

        if delta >= 0 {
            self.max_window_bytes = (self.max_window_bytes + delta as u32).min(MAX_CWND_BYTES);
        } else {
            let decrease = (-delta) as u32;
            self.max_window_bytes = self.max_window_bytes.saturating_sub(decrease).max(MIN_CWND_BYTES);
        }
    }
}

impl Default for LedbatCongestionController {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtpConnectionState {
    SynSent,
    Connected,
    FinSent,
    Closed,
    Reset,
}

/// uTP Connection instance tracking sequence numbers, connection IDs, and LEDBAT state.
#[derive(Debug, Clone)]
pub struct UtpConnection {
    pub recv_conn_id: u16,
    pub send_conn_id: u16,
    pub seq_nr: u16,
    pub ack_nr: u16,
    pub state: UtpConnectionState,
    pub congestion: LedbatCongestionController,
    pub last_remote_timestamp_us: u32,
}

impl UtpConnection {
    /// Creates a new outgoing uTP connection with a given base `recv_conn_id`.
    pub fn new_outgoing(conn_id: u16) -> Self {
        Self {
            recv_conn_id: conn_id,
            send_conn_id: conn_id.wrapping_add(1),
            seq_nr: 1,
            ack_nr: 0,
            state: UtpConnectionState::SynSent,
            congestion: LedbatCongestionController::new(),
            last_remote_timestamp_us: 0,
        }
    }

    /// Creates a new incoming uTP connection from a received `Syn` packet.
    pub fn new_incoming(syn_packet: &UtpPacket) -> Self {
        let send_id = syn_packet.header.connection_id;
        let recv_id = send_id.wrapping_add(1);
        Self {
            recv_conn_id: recv_id,
            send_conn_id: send_id,
            seq_nr: 100, // Initial random sequence number
            ack_nr: syn_packet.header.seq_nr,
            state: UtpConnectionState::Connected,
            congestion: LedbatCongestionController::new(),
            last_remote_timestamp_us: syn_packet.header.timestamp_us,
        }
    }

    fn now_micros() -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u32
    }

    /// Builds a SYN packet to initiate a connection.
    pub fn build_syn_packet(&mut self) -> UtpPacket {
        let mut header = UtpHeader::new(
            UtpType::Syn,
            self.recv_conn_id,
            self.seq_nr,
            0,
            self.congestion.max_window_bytes,
        );
        header.timestamp_us = Self::now_micros();
        UtpPacket::new(header, Bytes::new())
    }

    /// Builds a STATE (ACK) packet.
    pub fn build_state_packet(&self) -> UtpPacket {
        let mut header = UtpHeader::new(
            UtpType::State,
            self.send_conn_id,
            self.seq_nr,
            self.ack_nr,
            self.congestion.max_window_bytes,
        );
        header.timestamp_us = Self::now_micros();
        header.timestamp_diff_us = header.timestamp_us.wrapping_sub(self.last_remote_timestamp_us);
        UtpPacket::new(header, Bytes::new())
    }

    /// Builds a DATA packet carrying payload bytes.
    pub fn build_data_packet(&mut self, payload: Bytes) -> UtpPacket {
        let mut header = UtpHeader::new(
            UtpType::Data,
            self.send_conn_id,
            self.seq_nr,
            self.ack_nr,
            self.congestion.max_window_bytes,
        );
        header.timestamp_us = Self::now_micros();
        header.timestamp_diff_us = header.timestamp_us.wrapping_sub(self.last_remote_timestamp_us);

        self.seq_nr = self.seq_nr.wrapping_add(1);
        UtpPacket::new(header, payload)
    }

    /// Builds a FIN packet to gracefully close the connection.
    pub fn build_fin_packet(&mut self) -> UtpPacket {
        self.state = UtpConnectionState::FinSent;
        let mut header = UtpHeader::new(
            UtpType::Fin,
            self.send_conn_id,
            self.seq_nr,
            self.ack_nr,
            self.congestion.max_window_bytes,
        );
        header.timestamp_us = Self::now_micros();
        header.timestamp_diff_us = header.timestamp_us.wrapping_sub(self.last_remote_timestamp_us);

        self.seq_nr = self.seq_nr.wrapping_add(1);
        UtpPacket::new(header, Bytes::new())
    }

    /// Ingests a received packet, updates internal state, sequence numbers, LEDBAT delay,
    /// and returns received payload data if applicable.
    pub fn on_packet_recv(&mut self, packet: &UtpPacket) -> Result<Option<Bytes>, &'static str> {
        self.last_remote_timestamp_us = packet.header.timestamp_us;

        // Feed LEDBAT delay sample
        if packet.header.timestamp_diff_us > 0 {
            self.congestion.on_ack(1400, packet.header.timestamp_diff_us);
        }

        match packet.header.ptype {
            UtpType::State => {
                if self.state == UtpConnectionState::SynSent {
                    self.state = UtpConnectionState::Connected;
                    self.ack_nr = packet.header.seq_nr;
                }
                Ok(None)
            }
            UtpType::Data => {
                self.ack_nr = packet.header.seq_nr;
                Ok(Some(packet.payload.clone()))
            }
            UtpType::Fin => {
                self.ack_nr = packet.header.seq_nr;
                self.state = UtpConnectionState::Closed;
                Ok(None)
            }
            UtpType::Reset => {
                self.state = UtpConnectionState::Reset;
                Err("uTP connection reset by peer")
            }
            UtpType::Syn => {
                self.state = UtpConnectionState::Connected;
                self.ack_nr = packet.header.seq_nr;
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ledbat_congestion_window_adaptation() {
        let mut ledbat = LedbatCongestionController::new();
        assert_eq!(ledbat.max_window_bytes, MIN_CWND_BYTES);

        // Low queue delay (< 100ms) -> Congestion window expands
        ledbat.on_ack(1400, 20_000); // 20ms base
        let initial_base = ledbat.base_delay_us;
        assert_eq!(initial_base, 20_000);

        ledbat.on_ack(1400, 30_000); // 10ms queue delay -> well under target 100ms
        assert!(ledbat.max_window_bytes > MIN_CWND_BYTES);

        // High queue delay (> 100ms) -> Congestion window contracts
        let expanded_cwnd = ledbat.max_window_bytes;
        ledbat.on_ack(1400, 150_000); // 130ms queue delay -> exceeds target 100ms
        assert!(ledbat.max_window_bytes < expanded_cwnd);
    }

    #[test]
    fn test_utp_connection_handshake_and_data_exchange() {
        // 1. Client creates outgoing connection and sends SYN
        let mut client = UtpConnection::new_outgoing(0x8888);
        assert_eq!(client.state, UtpConnectionState::SynSent);
        let syn_pkt = client.build_syn_packet();

        // 2. Server creates incoming connection from SYN and replies with STATE
        let mut server = UtpConnection::new_incoming(&syn_pkt);
        assert_eq!(server.state, UtpConnectionState::Connected);
        let state_pkt = server.build_state_packet();

        // 3. Client receives STATE -> enters Connected
        let data = client.on_packet_recv(&state_pkt).unwrap();
        assert!(data.is_none());
        assert_eq!(client.state, UtpConnectionState::Connected);

        // 4. Client sends DATA packet
        let payload = Bytes::from_static(b"synapse utp block chunk 0");
        let data_pkt = client.build_data_packet(payload.clone());

        // 5. Server receives DATA packet
        let received = server.on_packet_recv(&data_pkt).unwrap().unwrap();
        assert_eq!(received, payload);

        // 6. Client sends FIN to close
        let fin_pkt = client.build_fin_packet();
        assert_eq!(client.state, UtpConnectionState::FinSent);

        server.on_packet_recv(&fin_pkt).unwrap();
        assert_eq!(server.state, UtpConnectionState::Closed);
    }
}
