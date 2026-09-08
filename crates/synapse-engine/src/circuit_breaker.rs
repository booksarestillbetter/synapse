//! Built-in Peer & Swarm Circuit Breakers for Synapse 2.0.
//!
//! Protects the reactor from reconnection storms, cascading peer handshake timeouts,
//! and repeated I/O errors by isolating unhealthy endpoints under exponential backoff.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Healthy,
    Tripped,
    HalfOpenCanary,
}

#[derive(Debug, Clone)]
pub struct EndpointCircuitInfo {
    pub consecutive_failures: u32,
    pub state: CircuitState,
    pub last_failure: Option<Instant>,
    pub backoff_duration: Duration,
    pub canary_in_flight: bool,
}

impl Default for EndpointCircuitInfo {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            state: CircuitState::Healthy,
            last_failure: None,
            backoff_duration: Duration::from_secs(30),
            canary_in_flight: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerCircuitBreaker {
    endpoints: Arc<RwLock<HashMap<SocketAddr, EndpointCircuitInfo>>>,
    failure_threshold: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl Default for PeerCircuitBreaker {
    fn default() -> Self {
        Self::new(3, Duration::from_secs(30), Duration::from_secs(600))
    }
}

impl PeerCircuitBreaker {
    pub fn new(failure_threshold: u32, initial_backoff: Duration, max_backoff: Duration) -> Self {
        Self {
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            failure_threshold,
            initial_backoff,
            max_backoff,
        }
    }

    /// Checks if a connection attempt is allowed to the given peer address.
    pub fn can_connect(&self, addr: &SocketAddr) -> bool {
        let mut map = self.endpoints.write();
        let entry = map.entry(*addr).or_default();

        match entry.state {
            CircuitState::Healthy => true,
            CircuitState::Tripped => {
                if let Some(last_fail) = entry.last_failure {
                    if last_fail.elapsed() >= entry.backoff_duration {
                        entry.state = CircuitState::HalfOpenCanary;
                        entry.canary_in_flight = true;
                        info!(
                            "Peer circuit breaker for {} transitioned to HalfOpenCanary. Testing canary connection.",
                            addr
                        );
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpenCanary => {
                if !entry.canary_in_flight {
                    entry.canary_in_flight = true;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Records a successful connection / handshake with the peer, resetting the breaker.
    pub fn record_success(&self, addr: &SocketAddr) {
        let mut map = self.endpoints.write();
        if let Some(entry) = map.get_mut(addr) {
            if entry.state != CircuitState::Healthy {
                info!("Canary connection succeeded for peer {}! Circuit Breaker reset to Healthy.", addr);
            }
            entry.consecutive_failures = 0;
            entry.state = CircuitState::Healthy;
            entry.last_failure = None;
            entry.backoff_duration = self.initial_backoff;
            entry.canary_in_flight = false;
        }
    }

    /// Records a failed connection attempt, handshake error, or I/O reset.
    pub fn record_failure(&self, addr: &SocketAddr) {
        let mut map = self.endpoints.write();
        let entry = map.entry(*addr).or_default();

        entry.consecutive_failures += 1;
        entry.last_failure = Some(Instant::now());
        entry.canary_in_flight = false;

        if entry.consecutive_failures >= self.failure_threshold {
            if entry.state == CircuitState::Healthy {
                warn!(
                    "Peer {} failed {} consecutive times. Tripping Peer Circuit Breaker (backoff: {:?}).",
                    addr, entry.consecutive_failures, self.initial_backoff
                );
                entry.state = CircuitState::Tripped;
                entry.backoff_duration = self.initial_backoff;
            } else if entry.state == CircuitState::HalfOpenCanary {
                entry.state = CircuitState::Tripped;
                entry.backoff_duration = (entry.backoff_duration * 2).min(self.max_backoff);
                warn!(
                    "Canary connection failed for peer {}. Doubling backoff to {:?}.",
                    addr, entry.backoff_duration
                );
            }
        }
    }

    /// Returns the circuit status of a specific peer endpoint.
    pub fn get_status(&self, addr: &SocketAddr) -> EndpointCircuitInfo {
        self.endpoints.read().get(addr).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_circuit_breaker_flow() {
        let cb = PeerCircuitBreaker::new(3, Duration::from_millis(50), Duration::from_millis(500));
        let addr: SocketAddr = "192.168.1.100:6881".parse().unwrap();

        assert!(cb.can_connect(&addr));

        cb.record_failure(&addr);
        cb.record_failure(&addr);
        assert!(cb.can_connect(&addr));

        // 3rd failure trips the breaker
        cb.record_failure(&addr);
        assert!(!cb.can_connect(&addr));
        assert_eq!(cb.get_status(&addr).state, CircuitState::Tripped);

        // Sleep past backoff
        std::thread::sleep(Duration::from_millis(60));

        // Canary probe allowed
        assert!(cb.can_connect(&addr));
        assert_eq!(cb.get_status(&addr).state, CircuitState::HalfOpenCanary);

        // Second simultaneous connection blocked while canary in flight
        assert!(!cb.can_connect(&addr));

        // Success resets breaker
        cb.record_success(&addr);
        assert!(cb.can_connect(&addr));
        assert_eq!(cb.get_status(&addr).state, CircuitState::Healthy);
    }
}
