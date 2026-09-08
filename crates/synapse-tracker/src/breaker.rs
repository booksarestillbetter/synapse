use parking_lot::RwLock;
use std::collections::HashMap;
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
pub struct HostCircuitInfo {
    pub consecutive_failures: u32,
    pub state: CircuitState,
    pub last_failure: Option<Instant>,
    pub backoff_duration: Duration,
    pub canary_in_flight: bool,
}

impl Default for HostCircuitInfo {
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

#[derive(Debug, Clone, Default)]
pub struct CanaryCircuitBreaker {
    hosts: Arc<RwLock<HashMap<String, HostCircuitInfo>>>,
    failure_threshold: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl CanaryCircuitBreaker {
    pub fn new(failure_threshold: u32, initial_backoff: Duration, max_backoff: Duration) -> Self {
        Self {
            hosts: Arc::new(RwLock::new(HashMap::new())),
            failure_threshold,
            initial_backoff,
            max_backoff,
        }
    }

    pub fn extract_host(url_str: &str) -> String {
        if let Ok(u) = url::Url::parse(url_str) {
            u.host_str().unwrap_or(url_str).to_lowercase()
        } else {
            url_str.to_lowercase()
        }
    }

    pub fn can_announce(&self, tracker_url: &str) -> bool {
        let host = Self::extract_host(tracker_url);
        let mut map = self.hosts.write();
        let entry = map.entry(host.clone()).or_default();

        match entry.state {
            CircuitState::Healthy => true,
            CircuitState::Tripped => {
                if let Some(last_fail) = entry.last_failure {
                    if last_fail.elapsed() >= entry.backoff_duration {
                        entry.state = CircuitState::HalfOpenCanary;
                        entry.canary_in_flight = true;
                        info!(
                            "Circuit breaker for host {} transitioned to HalfOpenCanary. Dispatching canary probe.",
                            host
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

    pub fn record_success(&self, tracker_url: &str) {
        let host = Self::extract_host(tracker_url);
        let mut map = self.hosts.write();
        if let Some(entry) = map.get_mut(&host) {
            if entry.state != CircuitState::Healthy {
                info!("Canary probe succeeded for host {}! Circuit Breaker reset to Healthy.", host);
            }
            entry.consecutive_failures = 0;
            entry.state = CircuitState::Healthy;
            entry.last_failure = None;
            entry.backoff_duration = self.initial_backoff;
            entry.canary_in_flight = false;
        }
    }

    pub fn record_failure(&self, tracker_url: &str) {
        let host = Self::extract_host(tracker_url);
        let mut map = self.hosts.write();
        let entry = map.entry(host.clone()).or_default();

        entry.consecutive_failures += 1;
        entry.last_failure = Some(Instant::now());
        entry.canary_in_flight = false;

        if entry.consecutive_failures >= self.failure_threshold {
            if entry.state == CircuitState::Healthy {
                warn!(
                    "Tracker host {} failed {} consecutive times. Tripping Canary Circuit Breaker (Swarm Pressure Relief active).",
                    host, entry.consecutive_failures
                );
                entry.state = CircuitState::Tripped;
                entry.backoff_duration = self.initial_backoff;
            } else if entry.state == CircuitState::HalfOpenCanary {
                entry.state = CircuitState::Tripped;
                entry.backoff_duration = (entry.backoff_duration * 2).min(self.max_backoff);
                warn!(
                    "Canary probe failed for host {}. Doubling backoff to {:?}.",
                    host, entry.backoff_duration
                );
            }
        }
    }

    pub fn get_host_status(&self, tracker_url: &str) -> HostCircuitInfo {
        let host = Self::extract_host(tracker_url);
        self.hosts.read().get(&host).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_trips_and_canary_probes() {
        let cb = CanaryCircuitBreaker::new(3, Duration::from_millis(50), Duration::from_millis(500));
        let tracker_url = "http://tracker.torrent.org:8080/announce";

        // Initial state is healthy
        assert!(cb.can_announce(tracker_url));

        // 2 failures: still healthy
        cb.record_failure(tracker_url);
        cb.record_failure(tracker_url);
        assert!(cb.can_announce(tracker_url));

        // 3rd failure: trips breaker into Swarm Pressure Relief
        cb.record_failure(tracker_url);
        assert!(!cb.can_announce(tracker_url));
        assert_eq!(cb.get_host_status(tracker_url).state, CircuitState::Tripped);

        // While tripped, subsequent requests from all swarms are blocked
        assert!(!cb.can_announce(tracker_url));

        // Wait for initial backoff (50ms)
        std::thread::sleep(Duration::from_millis(60));

        // Transition to HalfOpenCanary: first request allowed as canary probe
        assert!(cb.can_announce(tracker_url));

        // Second simultaneous request from another swarm is blocked while canary is in flight
        assert!(!cb.can_announce(tracker_url));

        // Canary probe succeeds: circuit resets to healthy
        cb.record_success(tracker_url);
        assert!(cb.can_announce(tracker_url));
        assert_eq!(cb.get_host_status(tracker_url).state, CircuitState::Healthy);
    }
}
