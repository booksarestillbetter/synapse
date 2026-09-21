//! Automatic port mapping on the local gateway: PCP (RFC 6887), NAT-PMP (RFC 6886) and UPnP
//! Internet Gateway Device, tried in that order.
//!
//! Every message that arrives from the network is treated as hostile. Replies must come from
//! the address we asked; a UPnP device's description and control URLs must point at the very
//! host that answered the discovery request (libtorrent `upnp.cpp:161`), on a non-public
//! address, so a spoofed SSDP reply cannot make the daemon fetch or POST to arbitrary hosts.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use url::Url;

use crate::nat::{send_natpmp_mapping, validate_upnp_location_url, PortProtocol, NATPMP_PORT};

/// Largest UPnP description or SOAP response we will read.
const MAX_HTTP_BODY: usize = 128 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
/// Multicast group and port SSDP searches are sent to.
pub const SSDP_MULTICAST: &str = "239.255.255.250:1900";

// ---------------------------------------------------------------------------------------
// PCP
// ---------------------------------------------------------------------------------------

/// PCP `MAP` request/response size: 24-byte header + 36-byte MAP option.
pub const PCP_MAP_LEN: usize = 60;

fn pcp_protocol_number(protocol: PortProtocol) -> u8 {
    match protocol {
        PortProtocol::Tcp => 6,
        PortProtocol::Udp => 17,
    }
}

fn to_v4_mapped(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Builds a PCP `MAP` request (RFC 6887 sections 7.1 and 11.1).
pub fn encode_pcp_map_request(
    nonce: &[u8; 12],
    client_ip: IpAddr,
    protocol: PortProtocol,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
) -> [u8; PCP_MAP_LEN] {
    let mut b = [0u8; PCP_MAP_LEN];
    b[0] = 2; // version
    b[1] = 1; // R=0 (request), opcode MAP
    b[4..8].copy_from_slice(&lifetime_secs.to_be_bytes());
    b[8..24].copy_from_slice(&to_v4_mapped(client_ip));
    b[24..36].copy_from_slice(nonce);
    b[36] = pcp_protocol_number(protocol);
    b[40..42].copy_from_slice(&internal_port.to_be_bytes());
    b[42..44].copy_from_slice(&suggested_external_port.to_be_bytes());
    // Suggested external address left as all zeros ("any").
    b
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcpMapping {
    pub external_port: u16,
    pub lifetime_secs: u32,
}

/// Why a PCP exchange failed; `UnsupportedVersion` means the gateway speaks only NAT-PMP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcpError {
    UnsupportedVersion,
    Refused(u8),
    Malformed(&'static str),
}

pub fn decode_pcp_map_response(
    buf: &[u8],
    nonce: &[u8; 12],
    protocol: PortProtocol,
    internal_port: u16,
) -> Result<PcpMapping, PcpError> {
    if buf.len() >= 4 && buf[0] == 0 && buf[2..4] == [0, 1] {
        // A NAT-PMP-only gateway answers an unknown version with "unsupported version".
        return Err(PcpError::UnsupportedVersion);
    }
    if buf.len() < PCP_MAP_LEN {
        return Err(PcpError::Malformed("PCP response too short"));
    }
    if buf[0] != 2 {
        return Err(PcpError::Malformed("not a PCP version 2 response"));
    }
    if buf[1] != 0x81 {
        return Err(PcpError::Malformed("not a MAP response"));
    }
    let result = buf[3];
    if result == 1 {
        return Err(PcpError::UnsupportedVersion);
    }
    if result != 0 {
        return Err(PcpError::Refused(result));
    }
    // The response must echo our nonce, protocol and internal port: it is the only thing tying
    // it to our request.
    if buf[24..36] != nonce[..]
        || buf[36] != pcp_protocol_number(protocol)
        || u16::from_be_bytes([buf[40], buf[41]]) != internal_port
    {
        return Err(PcpError::Malformed("response does not match the request"));
    }
    Ok(PcpMapping {
        external_port: u16::from_be_bytes([buf[42], buf[43]]),
        lifetime_secs: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
    })
}

/// The local IPv4 address used to reach `target` (the address a gateway sees us as).
pub async fn local_ip_towards(target: SocketAddr) -> std::io::Result<IpAddr> {
    let bind: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .expect("literal");
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.connect(target).await?;
    Ok(sock.local_addr()?.ip())
}

/// Requests a PCP mapping from `gateway`.
pub async fn send_pcp_mapping(
    gateway: SocketAddr,
    protocol: PortProtocol,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
) -> Result<PcpMapping, PcpError> {
    let bind: SocketAddr = if gateway.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .expect("literal");
    let sock = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|_| PcpError::Malformed("bind failed"))?;
    sock.connect(gateway)
        .await
        .map_err(|_| PcpError::Malformed("connect failed"))?;
    let client_ip = sock
        .local_addr()
        .map_err(|_| PcpError::Malformed("no local address"))?
        .ip();
    let nonce: [u8; 12] = rand::random();
    let req = encode_pcp_map_request(
        &nonce,
        client_ip,
        protocol,
        internal_port,
        suggested_external_port,
        lifetime_secs,
    );
    sock.send(&req)
        .await
        .map_err(|_| PcpError::Malformed("send failed"))?;
    let mut buf = [0u8; 128];
    // `connect` makes the kernel discard datagrams from any other source, so whatever arrives
    // here came from the gateway address.
    let n = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf))
        .await
        .map_err(|_| PcpError::Malformed("PCP request timed out"))?
        .map_err(|_| PcpError::Malformed("receive failed"))?;
    decode_pcp_map_response(&buf[..n], &nonce, protocol, internal_port)
}

// ---------------------------------------------------------------------------------------
// UPnP IGD
// ---------------------------------------------------------------------------------------

/// A UPnP gateway service that can map ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpnpService {
    /// SOAP endpoint (already validated to be on the gateway's own address).
    pub control_url: Url,
    /// e.g. `urn:schemas-upnp-org:service:WANIPConnection:1`.
    pub service_type: String,
    /// Our address as the gateway sees us (`NewInternalClient`).
    pub local_ip: Ipv4Addr,
}

fn msearch(st: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n"
    )
}

/// Extracts the `LOCATION` header of an SSDP response.
pub fn parse_ssdp_location(response: &str) -> Option<String> {
    response.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case("location")
            .then(|| v.trim().to_string())
    })
}

/// Text of the first `<tag>...</tag>` in `xml` (no attributes, no nesting: enough for UPnP
/// device descriptions and SOAP replies, and deliberately not a general XML parser).
fn tag_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim())
}

/// Finds a WAN IP/PPP connection service in an IGD description and returns
/// `(service type, control URL)` resolved against `location` (or `<URLBase>`). The result must
/// still point at `gateway_ip`; anything else is refused.
pub fn parse_igd_description(
    xml: &str,
    location: &Url,
    gateway_ip: IpAddr,
) -> Option<(String, Url)> {
    let base = tag_text(xml, "URLBase")
        .and_then(|b| Url::parse(b).ok())
        .unwrap_or_else(|| location.clone());
    let mut rest = xml;
    while let Some(i) = rest.find("<service>") {
        let block_start = i + "<service>".len();
        let Some(len) = rest[block_start..].find("</service>") else {
            break;
        };
        let block = &rest[block_start..block_start + len];
        rest = &rest[block_start + len..];
        let (Some(service_type), Some(control)) = (
            tag_text(block, "serviceType"),
            tag_text(block, "controlURL"),
        ) else {
            continue;
        };
        if !(service_type.contains(":WANIPConnection:")
            || service_type.contains(":WANPPPConnection:"))
        {
            continue;
        }
        let Ok(url) = base.join(control) else {
            continue;
        };
        if validate_upnp_location_url(url.as_str(), gateway_ip).is_ok() {
            return Some((service_type.to_string(), url));
        }
    }
    None
}

fn soap_envelope(service_type: &str, action: &str, args: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
         <u:{action} xmlns:u=\"{service_type}\">{args}</u:{action}></s:Body></s:Envelope>"
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn add_port_mapping_body(
    service_type: &str,
    external_port: u16,
    protocol: PortProtocol,
    internal_port: u16,
    internal_client: Ipv4Addr,
    description: &str,
    lease_secs: u32,
) -> String {
    let proto = match protocol {
        PortProtocol::Tcp => "TCP",
        PortProtocol::Udp => "UDP",
    };
    soap_envelope(
        service_type,
        "AddPortMapping",
        &format!(
            "<NewRemoteHost></NewRemoteHost><NewExternalPort>{external_port}</NewExternalPort>\
             <NewProtocol>{proto}</NewProtocol><NewInternalPort>{internal_port}</NewInternalPort>\
             <NewInternalClient>{internal_client}</NewInternalClient><NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>{}</NewPortMappingDescription>\
             <NewLeaseDuration>{lease_secs}</NewLeaseDuration>",
            xml_escape(description)
        ),
    )
}

pub fn delete_port_mapping_body(
    service_type: &str,
    external_port: u16,
    protocol: PortProtocol,
) -> String {
    let proto = match protocol {
        PortProtocol::Tcp => "TCP",
        PortProtocol::Udp => "UDP",
    };
    soap_envelope(
        service_type,
        "DeletePortMapping",
        &format!(
            "<NewRemoteHost></NewRemoteHost><NewExternalPort>{external_port}</NewExternalPort><NewProtocol>{proto}</NewProtocol>"
        ),
    )
}

/// The UPnP error code of a SOAP fault, if the response is one.
pub fn parse_soap_error_code(body: &str) -> Option<u32> {
    tag_text(body, "errorCode")?.parse().ok()
}

fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())
}

/// Reads at most `MAX_HTTP_BODY` bytes of a response body.
async fn read_capped(mut resp: reqwest::Response) -> Result<String, String> {
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + chunk.len() > MAX_HTTP_BODY {
            return Err("UPnP response too large".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Sends an SSDP search to `ssdp_target` and returns the validated `(description URL, gateway
/// address)` of every Internet Gateway Device that answered within `timeout`.
pub async fn discover_igd(ssdp_target: SocketAddr, timeout: Duration) -> Vec<(Url, IpAddr)> {
    let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
        return Vec::new();
    };
    for st in [
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    ] {
        let _ = sock.send_to(msearch(st).as_bytes(), ssdp_target).await;
    }
    let deadline = tokio::time::Instant::now() + timeout;
    let mut found: Vec<(Url, IpAddr)> = Vec::new();
    let mut buf = [0u8; 2048];
    while let Ok(Ok((n, from))) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await
    {
        let Ok(text) = std::str::from_utf8(&buf[..n]) else {
            continue;
        };
        let Some(location) = parse_ssdp_location(text) else {
            continue;
        };
        // The description must live on the device that answered, and that device must be local.
        if synapse_tracker::safe_http::is_public_ip(from.ip()) {
            continue;
        }
        let Ok(url) = validate_upnp_location_url(&location, from.ip()) else {
            continue;
        };
        if !found.iter().any(|(u, _)| *u == url) {
            found.push((url, from.ip()));
        }
    }
    found
}

/// Loads a discovered device's description and extracts its WAN connection service.
pub async fn load_igd_service(location: &Url, gateway_ip: IpAddr) -> Result<UpnpService, String> {
    let client = http_client()?;
    let resp = client
        .get(location.clone())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("UPnP description returned HTTP {}", resp.status()));
    }
    let xml = read_capped(resp).await?;
    let (service_type, control_url) = parse_igd_description(&xml, location, gateway_ip)
        .ok_or_else(|| "UPnP description has no usable WAN connection service".to_string())?;
    let port = control_url.port_or_known_default().unwrap_or(80);
    let local_ip = match local_ip_towards(SocketAddr::new(gateway_ip, port))
        .await
        .map_err(|e| e.to_string())?
    {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Err("UPnP mapping needs an IPv4 local address".into()),
    };
    Ok(UpnpService {
        control_url,
        service_type,
        local_ip,
    })
}

async fn soap_call(service: &UpnpService, action: &str, body: String) -> Result<String, String> {
    let client = http_client()?;
    let resp = client
        .post(service.control_url.clone())
        .header("Content-Type", "text/xml; charset=\"utf-8\"")
        .header(
            "SOAPAction",
            format!("\"{}#{}\"", service.service_type, action),
        )
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let ok = resp.status().is_success();
    let text = read_capped(resp).await?;
    if ok {
        Ok(text)
    } else if let Some(code) = parse_soap_error_code(&text) {
        Err(format!("UPnP error {code}"))
    } else {
        Err("UPnP request failed".into())
    }
}

/// `AddPortMapping` for the same external and internal port. Some routers only allow permanent
/// leases (error 725); that is retried once with lease 0.
pub async fn upnp_add_mapping(
    service: &UpnpService,
    protocol: PortProtocol,
    port: u16,
    description: &str,
    lease_secs: u32,
) -> Result<u32, String> {
    let body = add_port_mapping_body(
        &service.service_type,
        port,
        protocol,
        port,
        service.local_ip,
        description,
        lease_secs,
    );
    match soap_call(service, "AddPortMapping", body).await {
        Ok(_) => Ok(lease_secs),
        Err(e) if e.contains("725") => {
            let body = add_port_mapping_body(
                &service.service_type,
                port,
                protocol,
                port,
                service.local_ip,
                description,
                0,
            );
            soap_call(service, "AddPortMapping", body).await.map(|_| 0)
        }
        Err(e) => Err(e),
    }
}

pub async fn upnp_delete_mapping(
    service: &UpnpService,
    protocol: PortProtocol,
    port: u16,
) -> Result<(), String> {
    soap_call(
        service,
        "DeletePortMapping",
        delete_port_mapping_body(&service.service_type, port, protocol),
    )
    .await
    .map(|_| ())
}

// ---------------------------------------------------------------------------------------
// Unified mapper
// ---------------------------------------------------------------------------------------

/// How a mapping was obtained (and so how it is renewed and removed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    Pcp(SocketAddr),
    NatPmp(SocketAddr),
    Upnp(UpnpService),
}

impl Method {
    pub fn name(&self) -> &'static str {
        match self {
            Method::Pcp(_) => "PCP",
            Method::NatPmp(_) => "NAT-PMP",
            Method::Upnp(_) => "UPnP",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub method: Method,
    pub external_port: u16,
    /// Seconds until the mapping expires (0 = permanent).
    pub lifetime_secs: u32,
    pub gateway: IpAddr,
}

/// Where to look for a gateway.
#[derive(Debug, Clone)]
pub struct Discovery {
    /// Candidate PCP / NAT-PMP endpoints (`gateway:5351`).
    pub gateways: Vec<SocketAddr>,
    /// Where SSDP searches are sent.
    pub ssdp_target: SocketAddr,
    pub ssdp_timeout: Duration,
}

impl Discovery {
    /// The OS default gateway where known, plus common home-router addresses, and the standard
    /// SSDP multicast group.
    pub fn system_default() -> Self {
        let mut gateways = Vec::new();
        if let Some(gw) = crate::nat::default_gateway_v4() {
            gateways.push(SocketAddr::new(gw.into(), NATPMP_PORT));
        }
        for guess in [
            "192.168.1.1",
            "192.168.0.1",
            "10.0.0.1",
            "10.0.1.1",
            "172.16.0.1",
        ] {
            let gw = SocketAddr::new(guess.parse().expect("literal"), NATPMP_PORT);
            if !gateways.contains(&gw) {
                gateways.push(gw);
            }
        }
        Discovery {
            gateways,
            ssdp_target: SSDP_MULTICAST.parse().expect("literal"),
            ssdp_timeout: Duration::from_secs(3),
        }
    }
}

const LEASE_SECS: u32 = 3600;

/// Obtains a mapping for `port`, trying PCP, then NAT-PMP, then UPnP against every candidate.
pub async fn acquire(
    discovery: &Discovery,
    protocol: PortProtocol,
    port: u16,
    description: &str,
) -> Result<Mapping, String> {
    let mut errors: Vec<String> = Vec::new();
    for gw in &discovery.gateways {
        match send_pcp_mapping(*gw, protocol, port, port, LEASE_SECS).await {
            Ok(m) => {
                return Ok(Mapping {
                    method: Method::Pcp(*gw),
                    external_port: m.external_port,
                    lifetime_secs: m.lifetime_secs,
                    gateway: gw.ip(),
                })
            }
            Err(PcpError::UnsupportedVersion) | Err(PcpError::Malformed(_)) => {}
            Err(PcpError::Refused(code)) => errors.push(format!("PCP refused with result {code}")),
        }
        match send_natpmp_mapping(*gw, protocol, port, port, LEASE_SECS).await {
            Ok(m) => {
                return Ok(Mapping {
                    method: Method::NatPmp(*gw),
                    external_port: m.external_port,
                    lifetime_secs: m.lifetime_secs,
                    gateway: gw.ip(),
                })
            }
            Err(e) => errors.push(e),
        }
    }
    for (location, gateway_ip) in discover_igd(discovery.ssdp_target, discovery.ssdp_timeout).await
    {
        match load_igd_service(&location, gateway_ip).await {
            Ok(service) => {
                match upnp_add_mapping(&service, protocol, port, description, LEASE_SECS).await {
                    Ok(lease) => {
                        return Ok(Mapping {
                            method: Method::Upnp(service),
                            external_port: port,
                            lifetime_secs: lease,
                            gateway: gateway_ip,
                        })
                    }
                    Err(e) => errors.push(e),
                }
            }
            Err(e) => errors.push(e),
        }
    }
    errors.dedup();
    Err(if errors.is_empty() {
        "no gateway answered".to_string()
    } else {
        errors.join("; ")
    })
}

/// Renews `mapping` using the method that created it.
pub async fn renew(
    mapping: &Mapping,
    protocol: PortProtocol,
    port: u16,
    description: &str,
) -> Result<Mapping, String> {
    let mut next = mapping.clone();
    match &mapping.method {
        Method::Pcp(gw) => {
            let m = send_pcp_mapping(*gw, protocol, port, mapping.external_port, LEASE_SECS)
                .await
                .map_err(|e| format!("{e:?}"))?;
            next.external_port = m.external_port;
            next.lifetime_secs = m.lifetime_secs;
        }
        Method::NatPmp(gw) => {
            let m =
                send_natpmp_mapping(*gw, protocol, port, mapping.external_port, LEASE_SECS).await?;
            next.external_port = m.external_port;
            next.lifetime_secs = m.lifetime_secs;
        }
        Method::Upnp(service) => {
            next.lifetime_secs =
                upnp_add_mapping(service, protocol, port, description, LEASE_SECS).await?;
        }
    }
    Ok(next)
}

/// Removes a mapping (best effort; leases expire on their own anyway).
pub async fn release(mapping: &Mapping, protocol: PortProtocol, port: u16) {
    match &mapping.method {
        Method::Pcp(gw) => {
            let _ = send_pcp_mapping(*gw, protocol, port, mapping.external_port, 0).await;
        }
        Method::NatPmp(gw) => {
            let _ = send_natpmp_mapping(*gw, protocol, port, mapping.external_port, 0).await;
        }
        Method::Upnp(service) => {
            let _ = upnp_delete_mapping(service, protocol, mapping.external_port).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcp_map_request_has_the_rfc_6887_layout() {
        let nonce = [7u8; 12];
        let req = encode_pcp_map_request(
            &nonce,
            "192.168.1.20".parse().unwrap(),
            PortProtocol::Tcp,
            6881,
            6881,
            3600,
        );
        assert_eq!(req.len(), 60);
        assert_eq!(&req[..2], &[2, 1], "version 2, MAP request");
        assert_eq!(u32::from_be_bytes(req[4..8].try_into().unwrap()), 3600);
        // Client address is IPv4-mapped IPv6: ::ffff:192.168.1.20.
        assert_eq!(&req[8..18], &[0u8; 10]);
        assert_eq!(&req[18..24], &[0xff, 0xff, 192, 168, 1, 20]);
        assert_eq!(&req[24..36], &nonce);
        assert_eq!(req[36], 6, "TCP");
        assert_eq!(u16::from_be_bytes([req[40], req[41]]), 6881);
        assert_eq!(u16::from_be_bytes([req[42], req[43]]), 6881);
    }

    fn pcp_response(nonce: &[u8; 12], result: u8, ext: u16) -> Vec<u8> {
        let mut b = vec![0u8; 60];
        b[0] = 2;
        b[1] = 0x81;
        b[3] = result;
        b[4..8].copy_from_slice(&1800u32.to_be_bytes());
        b[24..36].copy_from_slice(nonce);
        b[36] = 6;
        b[40..42].copy_from_slice(&6881u16.to_be_bytes());
        b[42..44].copy_from_slice(&ext.to_be_bytes());
        b
    }

    #[test]
    fn pcp_response_decoding_checks_nonce_protocol_port_and_result() {
        let nonce = [9u8; 12];
        let ok = decode_pcp_map_response(
            &pcp_response(&nonce, 0, 50000),
            &nonce,
            PortProtocol::Tcp,
            6881,
        )
        .unwrap();
        assert_eq!((ok.external_port, ok.lifetime_secs), (50000, 1800));
        assert_eq!(
            decode_pcp_map_response(
                &pcp_response(&[1u8; 12], 0, 50000),
                &nonce,
                PortProtocol::Tcp,
                6881
            ),
            Err(PcpError::Malformed("response does not match the request"))
        );
        assert!(decode_pcp_map_response(
            &pcp_response(&nonce, 0, 50000),
            &nonce,
            PortProtocol::Udp,
            6881
        )
        .is_err());
        assert!(decode_pcp_map_response(
            &pcp_response(&nonce, 0, 50000),
            &nonce,
            PortProtocol::Tcp,
            1
        )
        .is_err());
        assert_eq!(
            decode_pcp_map_response(&pcp_response(&nonce, 2, 0), &nonce, PortProtocol::Tcp, 6881),
            Err(PcpError::Refused(2))
        );
        assert_eq!(
            decode_pcp_map_response(&pcp_response(&nonce, 1, 0), &nonce, PortProtocol::Tcp, 6881),
            Err(PcpError::UnsupportedVersion)
        );
        // A NAT-PMP-only gateway's "unsupported version" reply (version 0, result 1).
        let natpmp_unsupported = [0u8, 128, 0, 1, 0, 0, 0, 0];
        assert_eq!(
            decode_pcp_map_response(&natpmp_unsupported, &nonce, PortProtocol::Tcp, 6881),
            Err(PcpError::UnsupportedVersion)
        );
        assert!(decode_pcp_map_response(&[2, 0x81, 0], &nonce, PortProtocol::Tcp, 6881).is_err());
    }

    const DESCRIPTION: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
 <serviceList><service>
   <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
   <controlURL>/ctl/L3F</controlURL></service></serviceList>
 <deviceList><device><deviceList><device><serviceList><service>
   <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
   <controlURL>/ctl/IPConn</controlURL>
 </service></serviceList></device></deviceList></device></deviceList>
</device></root>"#;

    #[test]
    fn igd_description_yields_the_wan_connection_control_url_on_the_gateway() {
        let gw: IpAddr = "192.168.1.1".parse().unwrap();
        let loc = Url::parse("http://192.168.1.1:5000/rootDesc.xml").unwrap();
        let (st, url) = parse_igd_description(DESCRIPTION, &loc, gw).unwrap();
        assert_eq!(st, "urn:schemas-upnp-org:service:WANIPConnection:1");
        assert_eq!(url.as_str(), "http://192.168.1.1:5000/ctl/IPConn");
    }

    #[test]
    fn a_control_url_pointing_off_the_gateway_is_refused() {
        let gw: IpAddr = "192.168.1.1".parse().unwrap();
        let loc = Url::parse("http://192.168.1.1:5000/rootDesc.xml").unwrap();
        let evil = DESCRIPTION.replace("/ctl/IPConn", "http://169.254.169.254/latest/meta-data");
        assert!(
            parse_igd_description(&evil, &loc, gw).is_none(),
            "cloud metadata endpoint"
        );
        let evil = DESCRIPTION.replace("/ctl/IPConn", "http://attacker.example/ctl");
        assert!(parse_igd_description(&evil, &loc, gw).is_none());
        let with_base = DESCRIPTION.replace("<root ", "<URLBase>http://10.9.9.9/</URLBase><root ");
        assert!(
            parse_igd_description(&with_base, &loc, gw).is_none(),
            "URLBase must not redirect us elsewhere"
        );
    }

    #[test]
    fn ssdp_location_and_soap_helpers() {
        let resp = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLocation: http://192.168.1.1:5000/rootDesc.xml\r\nST: x\r\n\r\n";
        assert_eq!(
            parse_ssdp_location(resp).as_deref(),
            Some("http://192.168.1.1:5000/rootDesc.xml")
        );
        assert_eq!(parse_ssdp_location("HTTP/1.1 200 OK\r\n\r\n"), None);

        let body = add_port_mapping_body(
            "urn:x:WANIPConnection:1",
            6881,
            PortProtocol::Udp,
            6881,
            "192.168.1.20".parse().unwrap(),
            "Syn<ap>se & co",
            3600,
        );
        assert!(body.contains("<NewProtocol>UDP</NewProtocol>"));
        assert!(body.contains("<NewInternalClient>192.168.1.20</NewInternalClient>"));
        assert!(
            body.contains("Syn&lt;ap&gt;se &amp; co"),
            "description must be XML-escaped"
        );
        assert!(
            delete_port_mapping_body("urn:x:WANIPConnection:1", 6881, PortProtocol::Tcp)
                .contains("DeletePortMapping")
        );
        assert_eq!(parse_soap_error_code("<s:Fault><detail><UPnPError><errorCode>718</errorCode></UPnPError></detail></s:Fault>"), Some(718));
        assert_eq!(parse_soap_error_code("<ok/>"), None);
    }
}
