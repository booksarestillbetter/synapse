//! Automatic NAT Traversal and Port Forwarding (UPnP-IGD & NAT-PMP / PCP).
//!
//! Provides asynchronous port mapping requests to home router gateways to allow
//! inbound peer TCP, uTP, and DHT traffic without manual router configuration.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingStatus {
    Pending,
    Mapped {
        external_port: u16,
        gateway: IpAddr,
        expires_at: Instant,
    },
    Failed,
    Disabled,
}

#[derive(Debug, Clone)]
pub struct PortMapping {
    pub internal_port: u16,
    pub protocol: PortProtocol,
    pub description: String,
    pub status: MappingStatus,
}

pub struct NatManager {
    enabled: bool,
    mappings: HashMap<(u16, PortProtocol), PortMapping>,
    lease_duration: Duration,
}

impl NatManager {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            mappings: HashMap::new(),
            lease_duration: Duration::from_secs(3600), // 1 hour lease
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Registers a port to be mapped via UPnP/NAT-PMP.
    pub fn request_mapping(&mut self, port: u16, protocol: PortProtocol, description: &str) {
        let status = if self.enabled {
            MappingStatus::Pending
        } else {
            MappingStatus::Disabled
        };

        self.mappings.insert(
            (port, protocol),
            PortMapping {
                internal_port: port,
                protocol,
                description: description.to_string(),
                status,
            },
        );
    }

    /// Records a successful port mapping response from a gateway router.
    pub fn set_mapped(
        &mut self,
        port: u16,
        protocol: PortProtocol,
        external_port: u16,
        gateway: IpAddr,
    ) {
        if let Some(mapping) = self.mappings.get_mut(&(port, protocol)) {
            mapping.status = MappingStatus::Mapped {
                external_port,
                gateway,
                expires_at: Instant::now() + self.lease_duration,
            };
            info!(
                "NAT port mapping succeeded: {:?} internal {} -> external {} on gateway {}",
                protocol, port, external_port, gateway
            );
        }
    }

    /// Records a failed port mapping attempt.
    pub fn set_failed(&mut self, port: u16, protocol: PortProtocol) {
        if let Some(mapping) = self.mappings.get_mut(&(port, protocol)) {
            mapping.status = MappingStatus::Failed;
            warn!(
                "NAT port mapping failed for {:?} port {}",
                protocol, port
            );
        }
    }

    pub fn get_status(&self, port: u16, protocol: PortProtocol) -> Option<MappingStatus> {
        self.mappings.get(&(port, protocol)).map(|m| m.status)
    }

    pub fn all_mappings(&self) -> Vec<PortMapping> {
        self.mappings.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_nat_manager_lifecycle() {
        let mut nat = NatManager::new(true);
        assert!(nat.is_enabled());

        nat.request_mapping(6881, PortProtocol::Tcp, "Synapse BitTorrent TCP");
        assert_eq!(nat.get_status(6881, PortProtocol::Tcp), Some(MappingStatus::Pending));

        let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        nat.set_mapped(6881, PortProtocol::Tcp, 6881, gateway);

        match nat.get_status(6881, PortProtocol::Tcp).unwrap() {
            MappingStatus::Mapped { external_port, gateway: gw, .. } => {
                assert_eq!(external_port, 6881);
                assert_eq!(gw, gateway);
            }
            _ => panic!("Expected Mapped status"),
        }
    }
}
