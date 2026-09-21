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
        let status = MappingStatus::Mapped {
            external_port,
            gateway,
            expires_at: Instant::now() + self.lease_duration,
        };
        if let Some(mapping) = self.mappings.get_mut(&(port, protocol)) {
            mapping.status = status;
        } else {
            self.mappings.insert(
                (port, protocol),
                PortMapping {
                    internal_port: port,
                    protocol,
                    description: "Auto-mapped port".to_string(),
                    status,
                },
            );
        }
        info!(
            "NAT port mapping succeeded: {:?} internal {} -> external {} on gateway {}",
            protocol, port, external_port, gateway
        );
    }

    /// Records a failed port mapping attempt.
    pub fn set_failed(&mut self, port: u16, protocol: PortProtocol) {
        if let Some(mapping) = self.mappings.get_mut(&(port, protocol)) {
            mapping.status = MappingStatus::Failed;
        } else {
            self.mappings.insert(
                (port, protocol),
                PortMapping {
                    internal_port: port,
                    protocol,
                    description: "Port mapping".to_string(),
                    status: MappingStatus::Failed,
                },
            );
        }
        warn!("NAT port mapping failed for {:?} port {}", protocol, port);
    }

    pub fn get_status(&self, port: u16, protocol: PortProtocol) -> Option<MappingStatus> {
        self.mappings.get(&(port, protocol)).map(|m| m.status)
    }

    pub fn mapped_external_port(&self, port: u16, protocol: PortProtocol) -> Option<u16> {
        match self.mappings.get(&(port, protocol))?.status {
            MappingStatus::Mapped { external_port, .. } => Some(external_port),
            _ => None,
        }
    }

    pub fn all_mappings(&self) -> Vec<PortMapping> {
        self.mappings.values().cloned().collect()
    }

    /// Attempts a NAT-PMP port mapping request against a gateway address and updates status.
    pub async fn attempt_natpmp_mapping(
        &mut self,
        gateway: std::net::SocketAddr,
        port: u16,
        protocol: PortProtocol,
    ) -> Result<u16, String> {
        if !self.enabled {
            return Err("NAT port mapping is disabled".to_string());
        }
        match send_natpmp_mapping(gateway, protocol, port, port, 3600).await {
            Ok(result) => {
                self.set_mapped(port, protocol, result.external_port, gateway.ip());
                Ok(result.external_port)
            }
            Err(e) => {
                self.set_failed(port, protocol);
                Err(e)
            }
        }
    }
}

pub const NATPMP_PORT: u16 = 5351;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatPmpMappingResult {
    pub internal_port: u16,
    pub external_port: u16,
    pub lifetime_secs: u32,
}

pub fn encode_natpmp_mapping_request(
    protocol: PortProtocol,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0] = 0; // Version 0 (NAT-PMP)
    buf[1] = match protocol {
        PortProtocol::Udp => 1,
        PortProtocol::Tcp => 2,
    };
    buf[2..4].copy_from_slice(&0u16.to_be_bytes()); // Reserved
    buf[4..6].copy_from_slice(&internal_port.to_be_bytes());
    buf[6..8].copy_from_slice(&suggested_external_port.to_be_bytes());
    buf[8..12].copy_from_slice(&lifetime_secs.to_be_bytes());
    buf
}

pub fn decode_natpmp_mapping_response(
    buf: &[u8],
    protocol: PortProtocol,
) -> Result<NatPmpMappingResult, String> {
    if buf.len() < 16 {
        return Err("NAT-PMP response too short".to_string());
    }
    if buf[0] != 0 {
        return Err(format!("Unsupported NAT-PMP version {}", buf[0]));
    }
    let expected_opcode = match protocol {
        PortProtocol::Udp => 129,
        PortProtocol::Tcp => 130,
    };
    if buf[1] != expected_opcode {
        return Err(format!(
            "Unexpected opcode in NAT-PMP response: expected {}, got {}",
            expected_opcode, buf[1]
        ));
    }
    let result_code = u16::from_be_bytes([buf[2], buf[3]]);
    if result_code != 0 {
        return Err(format!("NAT-PMP error result code {}", result_code));
    }
    let internal_port = u16::from_be_bytes([buf[8], buf[9]]);
    let external_port = u16::from_be_bytes([buf[10], buf[11]]);
    let lifetime_secs = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    Ok(NatPmpMappingResult {
        internal_port,
        external_port,
        lifetime_secs,
    })
}

/// Dispatches a NAT-PMP mapping request to a specific gateway router.
/// Strictly enforces gateway source-address validation per libtorrent `natpmp.cpp:635`.
pub async fn send_natpmp_mapping(
    gateway: std::net::SocketAddr,
    protocol: PortProtocol,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
) -> Result<NatPmpMappingResult, String> {
    let bind_addr: std::net::SocketAddr = if gateway.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("failed to bind UDP socket for NAT-PMP: {e}"))?;

    let req = encode_natpmp_mapping_request(
        protocol,
        internal_port,
        suggested_external_port,
        lifetime_secs,
    );
    sock.send_to(&req, gateway)
        .await
        .map_err(|e| format!("failed to send NAT-PMP request to {gateway}: {e}"))?;

    // Wait for the gateway's answer, ignoring datagrams from any other source (gateway-source
    // validation, libtorrent natpmp.cpp:635): a host on the LAN must not be able to inject a
    // mapping result, nor make us give up early by racing a bogus packet in first.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut buf = [0u8; 64];
    loop {
        let (n, from_addr) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf))
            .await
            .map_err(|_| "NAT-PMP request timed out".to_string())?
            .map_err(|e| format!("failed to receive NAT-PMP response: {e}"))?;
        if from_addr.ip() != gateway.ip() {
            continue;
        }
        return decode_natpmp_mapping_response(&buf[..n], protocol);
    }
}

/// The IPv4 default gateway, read from the routing table. Only Linux exposes this without
/// extra tooling (`/proc/net/route`); elsewhere `None`, and callers fall back to guessing
/// common router addresses.
pub fn default_gateway_v4() -> Option<std::net::Ipv4Addr> {
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_proc_net_route(&table)
}

/// Parses `/proc/net/route` text: the first line is a header; each row is
/// `Iface Destination Gateway Flags ...` with little-endian hex addresses. The default route
/// has destination `00000000` and the `RTF_GATEWAY` (0x2) flag.
pub fn parse_proc_net_route(table: &str) -> Option<std::net::Ipv4Addr> {
    table.lines().skip(1).find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[1] != "00000000" {
            return None;
        }
        let flags = u32::from_str_radix(f[3], 16).ok()?;
        if flags & 0x2 == 0 {
            return None;
        }
        let gw = u32::from_str_radix(f[2], 16).ok()?;
        (gw != 0).then(|| std::net::Ipv4Addr::from(gw.to_le_bytes()))
    })
}

/// Validates that a UPnP location URL points to a legitimate gateway IP and does NOT
/// trigger SSRF to arbitrary hostnames, public endpoints, or different addresses (libtorrent upnp.cpp:161).
pub fn validate_upnp_location_url(location: &str, gateway_ip: IpAddr) -> Result<url::Url, String> {
    let parsed =
        url::Url::parse(location).map_err(|e| format!("invalid UPnP location URL: {e}"))?;
    if parsed.scheme() != "http" {
        return Err("UPnP location URL scheme must be HTTP".to_string());
    }
    let host_str = parsed
        .host_str()
        .ok_or_else(|| "UPnP location URL missing host".to_string())?;

    if let Ok(ip) = host_str.parse::<IpAddr>() {
        if ip != gateway_ip {
            return Err(format!(
                "UPnP security error: location host IP {ip} does not match gateway IP {gateway_ip}"
            ));
        }
    } else {
        return Err(
            "UPnP security error: host must be an IP literal matching gateway, not a hostname"
                .to_string(),
        );
    }
    Ok(parsed)
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
        assert_eq!(
            nat.get_status(6881, PortProtocol::Tcp),
            Some(MappingStatus::Pending)
        );

        let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        nat.set_mapped(6881, PortProtocol::Tcp, 6881, gateway);

        match nat.get_status(6881, PortProtocol::Tcp).unwrap() {
            MappingStatus::Mapped {
                external_port,
                gateway: gw,
                ..
            } => {
                assert_eq!(external_port, 6881);
                assert_eq!(gw, gateway);
            }
            _ => panic!("Expected Mapped status"),
        }
        assert_eq!(
            nat.mapped_external_port(6881, PortProtocol::Tcp),
            Some(6881)
        );
    }

    #[test]
    fn test_natpmp_request_encode_and_response_decode() {
        let req = encode_natpmp_mapping_request(PortProtocol::Tcp, 6881, 6881, 3600);
        assert_eq!(req.len(), 12);
        assert_eq!(req[0], 0); // version
        assert_eq!(req[1], 2); // TCP
        assert_eq!(u16::from_be_bytes([req[4], req[5]]), 6881);
        assert_eq!(u32::from_be_bytes([req[8], req[9], req[10], req[11]]), 3600);

        let mut resp = [0u8; 16];
        resp[0] = 0; // version
        resp[1] = 130; // 128 + 2 (TCP response)
        resp[2..4].copy_from_slice(&0u16.to_be_bytes()); // result code: Success
        resp[4..8].copy_from_slice(&12345u32.to_be_bytes()); // epoch
        resp[8..10].copy_from_slice(&6881u16.to_be_bytes()); // internal
        resp[10..12].copy_from_slice(&54321u16.to_be_bytes()); // external
        resp[12..16].copy_from_slice(&3600u32.to_be_bytes()); // lifetime

        let result = decode_natpmp_mapping_response(&resp, PortProtocol::Tcp).unwrap();
        assert_eq!(result.internal_port, 6881);
        assert_eq!(result.external_port, 54321);
        assert_eq!(result.lifetime_secs, 3600);
    }

    #[test]
    fn test_upnp_location_url_security_validation() {
        let gw = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Legitimate gateway URL
        assert!(validate_upnp_location_url("http://192.168.1.1:49152/rootDesc.xml", gw).is_ok());

        // Mismatched IP (SSRF attempt to a different internal host)
        assert!(validate_upnp_location_url("http://192.168.1.50:49152/rootDesc.xml", gw).is_err());

        // Public/external IP (SSRF attempt to external)
        assert!(validate_upnp_location_url("http://8.8.8.8:49152/rootDesc.xml", gw).is_err());

        // DNS name (DNS rebinding attempt)
        assert!(
            validate_upnp_location_url("http://attacker.example.com/rootDesc.xml", gw).is_err()
        );

        // Non-HTTP scheme
        assert!(validate_upnp_location_url("ftp://192.168.1.1/rootDesc.xml", gw).is_err());
    }

    #[test]
    fn default_gateway_is_parsed_from_proc_net_route() {
        let table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\n\
                     eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n";
        assert_eq!(
            parse_proc_net_route(table),
            Some(Ipv4Addr::new(192, 168, 2, 1))
        );
        // No default route, or one without a gateway, yields nothing.
        assert_eq!(
            parse_proc_net_route("Iface\tDestination\tGateway\tFlags\n"),
            None
        );
        assert_eq!(
            parse_proc_net_route("Iface\tD\tG\tF\nlo\t00000000\t00000000\t0001\n"),
            None
        );
    }
}
