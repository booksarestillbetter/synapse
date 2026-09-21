use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
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

    /// Snapshot of every host this breaker is currently tracking, keyed by lowercased
    /// hostname (the same key space `can_announce`/`record_success`/`record_failure` use).
    pub fn all_hosts(&self) -> Vec<(String, HostCircuitInfo)> {
        self.hosts
            .read()
            .iter()
            .map(|(host, info)| (host.clone(), info.clone()))
            .collect()
    }

    /// Forces a host's breaker into `Tripped`, as if it had just failed `failure_threshold`
    /// consecutive times. Used for manual/administrative overrides (e.g. from an external
    /// control-plane client).
    pub fn force_trip(&self, host: &str) {
        let host = host.to_lowercase();
        let mut map = self.hosts.write();
        let entry = map.entry(host.clone()).or_default();
        entry.state = CircuitState::Tripped;
        entry.consecutive_failures = self.failure_threshold.max(entry.consecutive_failures);
        entry.last_failure = Some(Instant::now());
        entry.backoff_duration = self.initial_backoff;
        entry.canary_in_flight = false;
        entry.recovery_started_at = None;
        entry.consecutive_successes = 0;
        warn!("Tracker host {} force-tripped via manual override.", host);
    }

    /// Clears a single host's breaker state entirely, returning it to `Healthy` on the
    /// next check. Used for manual/administrative overrides.
    pub fn force_reset(&self, host: &str) {
        let host = host.to_lowercase();
        self.hosts.write().remove(&host);
        info!(
            "Tracker host {} circuit breaker force-reset via manual override.",
            host
        );
    }

    /// The configured recovery ramp window, for callers deriving a recovery-progress
    /// percentage from a `HostCircuitInfo` snapshot's `recovery_started_at`.
    pub fn recovery_duration(&self) -> Duration {
        self.recovery_duration
    }

    /// Derives a 0-100 recovery-progress percentage from a status snapshot, or `None`
    /// if the host isn't currently `Recovering`.
    pub fn recovery_progress_pct(&self, info: &HostCircuitInfo) -> Option<f32> {
        if info.state != CircuitState::Recovering {
            return None;
        }
        let started_at = info.recovery_started_at?;
        let elapsed = started_at.elapsed().as_secs_f32();
        let total = self.recovery_duration.as_secs_f32().max(0.001);
        Some((elapsed / total * 100.0).clamp(0.0, 100.0))
    }

    /// Derives remaining backoff time in milliseconds from a status snapshot, or `0` if
    /// the host isn't currently `Tripped` (or has no recorded failure yet).
    pub fn backoff_remaining_ms(&self, info: &HostCircuitInfo) -> u64 {
        if info.state != CircuitState::Tripped {
            return 0;
        }
        let Some(last_failure) = info.last_failure else {
            return 0;
        };
        let elapsed = last_failure.elapsed();
        info.backoff_duration.saturating_sub(elapsed).as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_trips_and_canary_probes() {
        let cb =
            CanaryCircuitBreaker::new(3, Duration::from_millis(50), Duration::from_millis(500))
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
        assert_eq!(
            cb.get_host_status(tracker_url).state,
            CircuitState::Recovering
        );

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
        let cb =
            CanaryCircuitBreaker::new(3, Duration::from_millis(50), Duration::from_millis(500));
        let tracker_url = "http://tracker.relapse.org:8080/announce";

        cb.record_failure(tracker_url);
        cb.record_failure(tracker_url);
        cb.record_failure(tracker_url);
        assert_eq!(cb.get_host_status(tracker_url).state, CircuitState::Tripped);

        std::thread::sleep(Duration::from_millis(60));
        assert!(cb.can_announce(tracker_url)); // Canary dispatched
        cb.record_success(tracker_url);
        assert_eq!(
            cb.get_host_status(tracker_url).state,
            CircuitState::Recovering
        );

        // Failure during recovery ramp-up immediately aborts to Tripped with doubled backoff!
        cb.record_failure(tracker_url);
        let status = cb.get_host_status(tracker_url);
        assert_eq!(status.state, CircuitState::Tripped);
        assert_eq!(status.backoff_duration, Duration::from_millis(100)); // 50ms * 2
    }

    #[test]
    fn test_all_hosts_lists_every_tracked_host() {
        let cb =
            CanaryCircuitBreaker::new(3, Duration::from_millis(50), Duration::from_millis(500));
        cb.record_failure("http://tracker-a.org/announce");
        cb.record_failure("http://tracker-b.org/announce");

        let hosts = cb.all_hosts();
        let host_names: Vec<&str> = hosts.iter().map(|(h, _)| h.as_str()).collect();
        assert!(host_names.contains(&"tracker-a.org"));
        assert!(host_names.contains(&"tracker-b.org"));
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn test_force_trip_and_force_reset() {
        let cb =
            CanaryCircuitBreaker::new(3, Duration::from_millis(50), Duration::from_millis(500));
        let tracker_url = "http://tracker.override.org/announce";

        // Healthy by default
        assert!(cb.can_announce(tracker_url));

        cb.force_trip("tracker.override.org");
        assert_eq!(cb.get_host_status(tracker_url).state, CircuitState::Tripped);
        assert!(!cb.can_announce(tracker_url));

        cb.force_reset("tracker.override.org");
        assert_eq!(cb.get_host_status(tracker_url).state, CircuitState::Healthy);
        assert!(cb.can_announce(tracker_url));
    }

    #[test]
    fn test_recovery_progress_and_backoff_remaining_derivation() {
        let cb =
            CanaryCircuitBreaker::new(3, Duration::from_millis(100), Duration::from_millis(1000))
                .with_recovery_duration(Duration::from_millis(200));
        let tracker_url = "http://tracker.derived.org/announce";

        // Tripped: backoff_remaining_ms should be close to the full initial backoff.
        cb.record_failure(tracker_url);
        cb.record_failure(tracker_url);
        cb.record_failure(tracker_url);
        let status = cb.get_host_status(tracker_url);
        assert_eq!(status.state, CircuitState::Tripped);
        let remaining = cb.backoff_remaining_ms(&status);
        assert!(remaining > 0 && remaining <= 100);
        assert_eq!(cb.recovery_progress_pct(&status), None);

        // Recovering: recovery_progress_pct should be Some and increase over time.
        std::thread::sleep(Duration::from_millis(110));
        assert!(cb.can_announce(tracker_url));
        cb.record_success(tracker_url);
        let status = cb.get_host_status(tracker_url);
        assert_eq!(status.state, CircuitState::Recovering);
        assert_eq!(cb.backoff_remaining_ms(&status), 0);
        let pct = cb
            .recovery_progress_pct(&status)
            .expect("should be Some while Recovering");
        assert!((0.0..=100.0).contains(&pct));
    }
}
