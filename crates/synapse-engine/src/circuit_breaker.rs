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

const CANARY_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_TRACKED_PEERS: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Healthy,
    Tripped,
    HalfOpenCanary,
    Recovering,
}

#[derive(Debug, Clone)]
pub struct EndpointCircuitInfo {
    pub consecutive_failures: u32,
    pub state: CircuitState,
    pub last_failure: Option<Instant>,
    pub backoff_duration: Duration,
    pub canary_in_flight: bool,
    pub canary_started_at: Option<Instant>,
    pub recovery_started_at: Option<Instant>,
    pub consecutive_successes: u32,
    pub last_dispatched: Option<Instant>,
}

impl Default for EndpointCircuitInfo {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            state: CircuitState::Healthy,
            last_failure: None,
            backoff_duration: Duration::from_secs(30),
            canary_in_flight: false,
            canary_started_at: None,
            recovery_started_at: None,
            consecutive_successes: 0,
            last_dispatched: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerCircuitBreaker {
    endpoints: Arc<RwLock<HashMap<SocketAddr, EndpointCircuitInfo>>>,
    failure_threshold: Arc<RwLock<u32>>,
    initial_backoff: Arc<RwLock<Duration>>,
    max_backoff: Arc<RwLock<Duration>>,
    recovery_duration: Arc<RwLock<Duration>>,
    enabled: Arc<RwLock<bool>>,
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
            failure_threshold: Arc::new(RwLock::new(failure_threshold)),
            initial_backoff: Arc::new(RwLock::new(initial_backoff)),
            max_backoff: Arc::new(RwLock::new(max_backoff)),
            recovery_duration: Arc::new(RwLock::new(Duration::from_secs(30))),
            enabled: Arc::new(RwLock::new(true)),
        }
    }

    /// Sets the ramp-up recovery duration.
    pub fn set_recovery_duration(&self, duration: Duration) {
        *self.recovery_duration.write() = duration;
    }

    /// Dynamically update circuit breaker configuration parameters in-flight.
    pub fn configure(
        &self,
        enabled: bool,
        failure_threshold: u32,
        initial_backoff: Duration,
        max_backoff: Duration,
    ) {
        *self.enabled.write() = enabled;
        *self.failure_threshold.write() = failure_threshold;
        *self.initial_backoff.write() = initial_backoff;
        *self.max_backoff.write() = max_backoff;
    }

    /// Returns whether the circuit breaker is currently enabled.
    pub fn is_enabled(&self) -> bool {
        *self.enabled.read()
    }

    /// Returns the number of currently tripped peer circuit breakers.
    pub fn tripped_count(&self) -> usize {
        self.endpoints
            .read()
            .values()
            .filter(|e| e.state == CircuitState::Tripped)
            .count()
    }

    /// Resets all endpoint breaker history back to healthy.
    pub fn reset(&self) {
        self.endpoints.write().clear();
    }

    fn evict_one(map: &mut HashMap<SocketAddr, EndpointCircuitInfo>) {
        const STALE_TRIPPED_CUTOFF: Duration = Duration::from_secs(3600);
        let key = map
            .iter()
            .find(|(_, info)| info.state == CircuitState::Healthy)
            .or_else(|| {
                map.iter().find(|(_, info)| {
                    info.state == CircuitState::Tripped
                        && info.last_failure.is_some_and(|f| {
                            f.elapsed() >= info.backoff_duration.max(STALE_TRIPPED_CUTOFF)
                        })
                })
            })
            .map(|(k, _)| *k)
            .or_else(|| {
                map.iter()
                    .min_by_key(|(_, info)| info.last_failure)
                    .map(|(k, _)| *k)
            });
        if let Some(k) = key {
            map.remove(&k);
        }
    }

    /// Checks if a connection attempt is allowed to the given peer address.
    pub fn can_connect(&self, addr: &SocketAddr) -> bool {
        if !*self.enabled.read() {
            return true;
        }

        {
            let map = self.endpoints.read();
            match map.get(addr) {
                None => return true,
                Some(entry) if entry.state == CircuitState::Healthy => return true,
                Some(entry)
                    if entry.state == CircuitState::Tripped
                        && entry
                            .last_failure
                            .is_none_or(|f| f.elapsed() < entry.backoff_duration) =>
                {
                    return false;
                }
                Some(_) => {}
            }
        }

        let mut map = self.endpoints.write();
        let Some(entry) = map.get_mut(addr) else {
            return true;
        };

        match entry.state {
            CircuitState::Healthy => true,
            CircuitState::Tripped => {
                if let Some(last_fail) = entry.last_failure {
                    if last_fail.elapsed() >= entry.backoff_duration {
                        let now = Instant::now();
                        entry.state = CircuitState::HalfOpenCanary;
                        entry.canary_in_flight = true;
                        entry.canary_started_at = Some(now);
                        entry.last_dispatched = Some(now);
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
                let timed_out = entry
                    .canary_started_at
                    .is_some_and(|started| started.elapsed() >= CANARY_TIMEOUT);
                if !entry.canary_in_flight || timed_out {
                    let now = Instant::now();
                    entry.canary_in_flight = true;
                    entry.canary_started_at = Some(now);
                    entry.last_dispatched = Some(now);
                    true
                } else {
                    false
                }
            }
            CircuitState::Recovering => {
                let now = Instant::now();
                let started_at = entry.recovery_started_at.unwrap_or(now);
                let elapsed = now.saturating_duration_since(started_at);
                let recovery_duration = *self.recovery_duration.read();

                // Promotion check: recovery window elapsed and at least 3 successful handshakes
                if elapsed >= recovery_duration && entry.consecutive_successes >= 3 {
                    info!(
                        "Peer {} completed recovery ramp-up with {} successes. Circuit breaker promoted to Healthy.",
                        addr, entry.consecutive_successes
                    );
                    map.remove(addr);
                    return true;
                }

                // Progressive dial pacing to avoid simultaneous connection spam to that endpoint
                let min_interval = if elapsed < recovery_duration / 2 {
                    (recovery_duration / 6).max(Duration::from_millis(50))
                } else {
                    (recovery_duration / 20).max(Duration::from_millis(20))
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

    /// Records a successful connection / handshake with the peer, initiating recovery ramp-up.
    pub fn record_success(&self, addr: &SocketAddr) {
        if !*self.enabled.read() {
            return;
        }
        if !self.endpoints.read().contains_key(addr) {
            return;
        }

        let initial_backoff = *self.initial_backoff.read();
        let mut map = self.endpoints.write();
        let remove_healthy = match map.get_mut(addr) {
            Some(entry) => {
                entry.canary_started_at = None;
                match entry.state {
                    CircuitState::HalfOpenCanary => {
                        info!(
                            "Canary connection succeeded for peer {}! Entering Recovering ramp-up phase.",
                            addr
                        );
                        entry.consecutive_failures = 0;
                        entry.state = CircuitState::Recovering;
                        entry.recovery_started_at = Some(Instant::now());
                        entry.consecutive_successes = 1;
                        entry.last_failure = None;
                        entry.backoff_duration = initial_backoff;
                        entry.canary_in_flight = false;
                        entry.last_dispatched = Some(Instant::now());
                        false
                    }
                    CircuitState::Recovering => {
                        entry.consecutive_successes += 1;
                        entry.consecutive_failures = 0;
                        entry.canary_in_flight = false;
                        false
                    }
                    CircuitState::Healthy => true,
                    CircuitState::Tripped => {
                        entry.consecutive_failures = 0;
                        entry.canary_in_flight = false;
                        false
                    }
                }
            }
            None => false,
        };
        if remove_healthy {
            map.remove(addr);
        }
    }

    /// Records a failed connection attempt, handshake error, or I/O reset.
    pub fn record_failure(&self, addr: &SocketAddr) {
        if !*self.enabled.read() {
            return;
        }

        let failure_threshold = *self.failure_threshold.read();
        let initial_backoff = *self.initial_backoff.read();
        let max_backoff = *self.max_backoff.read();

        let mut map = self.endpoints.write();
        if !map.contains_key(addr) && map.len() >= MAX_TRACKED_PEERS {
            Self::evict_one(&mut map);
        }
        let entry = map.entry(*addr).or_default();

        entry.consecutive_failures += 1;
        entry.last_failure = Some(Instant::now());
        entry.canary_in_flight = false;
        entry.canary_started_at = None;
        entry.consecutive_successes = 0;

        match entry.state {
            CircuitState::Healthy => {
                if entry.consecutive_failures >= failure_threshold {
                    warn!(
                        "Peer circuit breaker tripped for {} after {} consecutive failures. Backing off for {:?}.",
                        addr, entry.consecutive_failures, initial_backoff
                    );
                    entry.state = CircuitState::Tripped;
                    entry.backoff_duration = initial_backoff;
                    entry.recovery_started_at = None;
                }
            }
            CircuitState::HalfOpenCanary => {
                entry.state = CircuitState::Tripped;
                entry.backoff_duration = (entry.backoff_duration * 2).min(max_backoff);
                entry.recovery_started_at = None;
                warn!(
                    "Canary connection failed for peer {}. Doubling backoff to {:?}.",
                    addr, entry.backoff_duration
                );
            }
            CircuitState::Recovering => {
                // Relapse during ramp-up: abort immediately and double backoff penalty!
                entry.state = CircuitState::Tripped;
                entry.backoff_duration = (entry.backoff_duration * 2).min(max_backoff);
                entry.recovery_started_at = None;
                warn!(
                    "Peer {} relapsed and failed during recovery ramp-up. Aborting recovery and re-tripping circuit breaker to {:?}.",
                    addr, entry.backoff_duration
                );
            }
            CircuitState::Tripped => {}
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
        cb.set_recovery_duration(Duration::from_millis(100));
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

        // Canary success transitions to Recovering
        cb.record_success(&addr);
        assert_eq!(cb.get_status(&addr).state, CircuitState::Recovering);

        // Rapid back-to-back dial is throttled
        assert!(!cb.can_connect(&addr));

        // Complete ramp-up
        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(25));
            if cb.can_connect(&addr) {
                cb.record_success(&addr);
            }
        }

        std::thread::sleep(Duration::from_millis(100));
        assert!(cb.can_connect(&addr));
        assert_eq!(cb.get_status(&addr).state, CircuitState::Healthy);
    }

    #[test]
    fn test_peer_circuit_breaker_recovering_relapse_aborts_to_tripped() {
        let cb = PeerCircuitBreaker::new(3, Duration::from_millis(50), Duration::from_millis(500));
        let addr: SocketAddr = "192.168.1.200:6881".parse().unwrap();

        cb.record_failure(&addr);
        cb.record_failure(&addr);
        cb.record_failure(&addr);
        assert_eq!(cb.get_status(&addr).state, CircuitState::Tripped);

        std::thread::sleep(Duration::from_millis(60));
        assert!(cb.can_connect(&addr)); // Canary dispatched
        cb.record_success(&addr);
        assert_eq!(cb.get_status(&addr).state, CircuitState::Recovering);

        // Failure during recovery ramp-up immediately aborts to Tripped with doubled backoff!
        cb.record_failure(&addr);
        let status = cb.get_status(&addr);
        assert_eq!(status.state, CircuitState::Tripped);
        assert_eq!(status.backoff_duration, Duration::from_millis(100)); // 50ms * 2
    }

    #[test]
    fn healthy_read_fast_path_stuck_canary_timeout_and_bounded_eviction() {
        let cb = PeerCircuitBreaker::new(1, Duration::from_millis(5), Duration::from_secs(1));
        let healthy: SocketAddr = "198.51.100.1:6881".parse().unwrap();
        assert!(cb.can_connect(&healthy));
        assert!(
            cb.endpoints.read().is_empty(),
            "healthy peer check must not allocate or insert"
        );

        let stuck: SocketAddr = "198.51.100.2:6881".parse().unwrap();
        cb.record_failure(&stuck);
        std::thread::sleep(Duration::from_millis(10));
        assert!(cb.can_connect(&stuck));
        assert!(!cb.can_connect(&stuck));
        {
            let mut map = cb.endpoints.write();
            map.get_mut(&stuck).unwrap().canary_started_at =
                Some(Instant::now() - CANARY_TIMEOUT - Duration::from_secs(1));
        }
        assert!(
            cb.can_connect(&stuck),
            "stuck canary past CANARY_TIMEOUT should allow re-probing"
        );

        for idx in 0..=MAX_TRACKED_PEERS {
            let ip = std::net::Ipv4Addr::from((idx as u32) + 0xC633_6400);
            let port = 1024 + (idx % 60_000) as u16;
            cb.record_failure(&SocketAddr::from((ip, port)));
        }
        assert_eq!(cb.endpoints.read().len(), MAX_TRACKED_PEERS);
    }

    #[test]
    fn healthy_record_success_and_graduation_retain_zero_entries() {
        let cb = PeerCircuitBreaker::new(2, Duration::from_millis(5), Duration::from_secs(1));
        cb.set_recovery_duration(Duration::from_millis(10));
        let addr: SocketAddr = "198.51.100.77:6881".parse().unwrap();

        cb.record_success(&addr);
        assert!(cb.endpoints.read().is_empty());

        cb.record_failure(&addr);
        assert_eq!(cb.endpoints.read().len(), 1);
        cb.record_success(&addr);
        assert!(
            cb.endpoints.read().is_empty(),
            "healthy peer entry must be removed on success"
        );

        cb.record_failure(&addr);
        cb.record_failure(&addr);
        std::thread::sleep(Duration::from_millis(10));
        assert!(cb.can_connect(&addr));
        cb.record_success(&addr);
        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(4));
            let _ = cb.can_connect(&addr);
            cb.record_success(&addr);
        }
        std::thread::sleep(Duration::from_millis(15));
        assert!(cb.can_connect(&addr));
        assert!(
            cb.endpoints.read().is_empty(),
            "graduated peer must be removed from map"
        );
    }
}
