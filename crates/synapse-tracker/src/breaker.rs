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
    Recovering,
}

#[derive(Debug, Clone)]
pub struct HostCircuitInfo {
    pub consecutive_failures: u32,
    pub state: CircuitState,
    pub last_failure: Option<Instant>,
    pub backoff_duration: Duration,
    pub canary_in_flight: bool,
    pub recovery_started_at: Option<Instant>,
    pub consecutive_successes: u32,
    pub last_dispatched: Option<Instant>,
}

impl Default for HostCircuitInfo {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            state: CircuitState::Healthy,
            last_failure: None,
            backoff_duration: Duration::from_secs(30),
            canary_in_flight: false,
            recovery_started_at: None,
            consecutive_successes: 0,
            last_dispatched: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CanaryCircuitBreaker {
    hosts: Arc<RwLock<HashMap<String, HostCircuitInfo>>>,
    failure_threshold: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
    recovery_duration: Duration,
}

impl Default for CanaryCircuitBreaker {
    fn default() -> Self {
        Self::new(3, Duration::from_secs(30), Duration::from_secs(600))
    }
}

impl CanaryCircuitBreaker {
    pub fn new(failure_threshold: u32, initial_backoff: Duration, max_backoff: Duration) -> Self {
        Self {
            hosts: Arc::new(RwLock::new(HashMap::new())),
            failure_threshold,
            initial_backoff,
            max_backoff,
            recovery_duration: Duration::from_secs(30),
        }
    }

    pub fn with_recovery_duration(mut self, duration: Duration) -> Self {
        self.recovery_duration = duration;
        self
    }

    pub fn extract_host(url_str: &str) -> String {
        if let Ok(u) = url::Url::parse(url_str) {
            u.host_str().unwrap_or(url_str).to_lowercase()
        } else {
            url_str.to_lowercase()
        }
    }

    /// Checks whether an announce request to this tracker URL is permitted.
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
                    entry.last_dispatched = Some(Instant::now());
                    true
                } else {
                    false
                }
            }
            CircuitState::Recovering => {
                let now = Instant::now();
                let started_at = entry.recovery_started_at.unwrap_or(now);
                let elapsed = now.saturating_duration_since(started_at);

                // Check for graduation to Healthy:
                // Recovery window has elapsed and we've accumulated at least 5 consecutive successes without failure
                if elapsed >= self.recovery_duration && entry.consecutive_successes >= 5 {
                    info!(
                        "Host {} completed recovery ramp-up with {} successes. Circuit breaker promoted to Healthy.",
                        host, entry.consecutive_successes
                    );
                    entry.state = CircuitState::Healthy;
                    entry.recovery_started_at = None;
                    entry.last_dispatched = Some(now);
                    return true;
                }

                // Progressive rate limiter / levee:
                // - Early ramp (first 33% of recovery window): 1 request per 3s (or scaled proportionally)
                // - Mid ramp (33% - 66%): 1 request per 1s
                // - Late ramp (last 33%): 1 request per 333ms (3 req/s)
                let min_interval = if elapsed < self.recovery_duration / 3 {
                    (self.recovery_duration / 10).max(Duration::from_millis(50))
                } else if elapsed < (self.recovery_duration * 2) / 3 {
                    (self.recovery_duration / 30).max(Duration::from_millis(25))
                } else {
                    (self.recovery_duration / 90).max(Duration::from_millis(10))
                };

                if let Some(last) = entry.last_dispatched {
                    if now.saturating_duration_since(last) < min_interval {
                        return false;
                    }
                }

                entry.last_dispatched = Some(now);
                true
            }
        }
    }

    /// Records a successful announce, transitioning from canary to recovering ramp-up,
    /// or progressing through recovery towards healthy.
    pub fn record_success(&self, tracker_url: &str) {
        let host = Self::extract_host(tracker_url);
        let mut map = self.hosts.write();
        if let Some(entry) = map.get_mut(&host) {
            match entry.state {
                CircuitState::HalfOpenCanary => {
                    info!(
                        "Canary probe succeeded for host {}! Circuit breaker entering Recovering ramp-up phase.",
                        host
                    );
                    entry.consecutive_failures = 0;
                    entry.state = CircuitState::Recovering;
                    entry.recovery_started_at = Some(Instant::now());
                    entry.consecutive_successes = 1;
                    entry.last_failure = None;
                    entry.backoff_duration = self.initial_backoff;
                    entry.canary_in_flight = false;
                    entry.last_dispatched = Some(Instant::now());
                }
                CircuitState::Recovering => {
                    entry.consecutive_successes += 1;
                    entry.consecutive_failures = 0;
                    entry.canary_in_flight = false;
                }
                CircuitState::Healthy => {
                    entry.consecutive_failures = 0;
                    entry.last_failure = None;
                    entry.canary_in_flight = false;
                }
                CircuitState::Tripped => {
                    entry.consecutive_failures = 0;
                    entry.canary_in_flight = false;
                }
            }
        }
    }

    /// Records a failed announce. If the host is in `Recovering`, immediately aborts
    /// the recovery and re-trips with doubled exponential backoff.
    pub fn record_failure(&self, tracker_url: &str) {
        let host = Self::extract_host(tracker_url);
        let mut map = self.hosts.write();
        let entry = map.entry(host.clone()).or_default();

        entry.consecutive_failures += 1;
        entry.last_failure = Some(Instant::now());
        entry.canary_in_flight = false;
        entry.consecutive_successes = 0;

        match entry.state {
            CircuitState::Healthy => {
                if entry.consecutive_failures >= self.failure_threshold {
                    warn!(
                        "Tracker host {} failed {} consecutive times. Tripping Canary Circuit Breaker (Swarm Pressure Relief active).",
                        host, entry.consecutive_failures
                    );
                    entry.state = CircuitState::Tripped;
                    entry.backoff_duration = self.initial_backoff;
                    entry.recovery_started_at = None;
                }
            }
            CircuitState::HalfOpenCanary => {
                entry.state = CircuitState::Tripped;
                entry.backoff_duration = (entry.backoff_duration * 2).min(self.max_backoff);
                entry.recovery_started_at = None;
                warn!(
                    "Canary probe failed for host {}. Doubling backoff to {:?}.",
                    host, entry.backoff_duration
                );
            }
            CircuitState::Recovering => {
                // Relapse during ramp-up: abort immediately and double backoff penalty!
                entry.state = CircuitState::Tripped;
                entry.backoff_duration = (entry.backoff_duration * 2).min(self.max_backoff);
                entry.recovery_started_at = None;
                warn!(
                    "Host {} relapsed and failed during recovery ramp-up. Aborting recovery and re-tripping circuit breaker to {:?}.",
                    host, entry.backoff_duration
                );
            }
            CircuitState::Tripped => {}
        }
    }

    /// Returns the number of currently tripped tracker host circuit breakers.
    pub fn tripped_count(&self) -> usize {
        self.hosts
            .read()
            .values()
            .filter(|e| e.state == CircuitState::Tripped)
            .count()
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
        let cb = CanaryCircuitBreaker::new(3, Duration::from_millis(50), Duration::from_millis(500))
            .with_recovery_duration(Duration::from_millis(100));
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

        // Canary probe succeeds: circuit enters Recovering ramp-up
        cb.record_success(tracker_url);
        assert_eq!(cb.get_host_status(tracker_url).state, CircuitState::Recovering);

        // Rapid back-to-back request is throttled by ramp-up rate limiter
        assert!(!cb.can_announce(tracker_url));

        // Sleep to pass through ramp-up window and accumulate successes
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(25));
            if cb.can_announce(tracker_url) {
                cb.record_success(tracker_url);
            }
        }

        std::thread::sleep(Duration::from_millis(100));
        assert!(cb.can_announce(tracker_url));
        assert_eq!(cb.get_host_status(tracker_url).state, CircuitState::Healthy);
    }

    #[test]
    fn test_circuit_breaker_recovering_relapse_aborts_to_tripped() {
        let cb = CanaryCircuitBreaker::new(3, Duration::from_millis(50), Duration::from_millis(500));
        let tracker_url = "http://tracker.relapse.org:8080/announce";

        cb.record_failure(tracker_url);
        cb.record_failure(tracker_url);
        cb.record_failure(tracker_url);
        assert_eq!(cb.get_host_status(tracker_url).state, CircuitState::Tripped);

        std::thread::sleep(Duration::from_millis(60));
        assert!(cb.can_announce(tracker_url)); // Canary dispatched
        cb.record_success(tracker_url);
        assert_eq!(cb.get_host_status(tracker_url).state, CircuitState::Recovering);

        // Failure during recovery ramp-up immediately aborts to Tripped with doubled backoff!
        cb.record_failure(tracker_url);
        let status = cb.get_host_status(tracker_url);
        assert_eq!(status.state, CircuitState::Tripped);
        assert_eq!(status.backoff_duration, Duration::from_millis(100)); // 50ms * 2
    }
}
