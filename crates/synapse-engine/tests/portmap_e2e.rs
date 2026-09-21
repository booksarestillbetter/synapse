//! PCP, NAT-PMP and UPnP port mapping against mock gateways on loopback.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use synapse_engine::nat::PortProtocol;
use synapse_engine::portmap::{acquire, release, renew, Discovery, Method};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

fn no_ssdp(gateways: Vec<SocketAddr>) -> Discovery {
    Discovery {
        gateways,
        // Nothing listens here, so SSDP finds nothing.
        ssdp_target: "127.0.0.1:9".parse().unwrap(),
        ssdp_timeout: Duration::from_millis(150),
    }
}

/// A gateway answering PCP MAP requests (or, when `pcp` is false, replying "unsupported
/// version" as a NAT-PMP-only router does, then serving NAT-PMP).
async fn spawn_pcp_natpmp_gateway(pcp: bool, external: u16) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 128];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            if buf[0] == 2 && n == 60 {
                if !pcp {
                    let _ = sock.send_to(&[0, 130, 0, 1, 0, 0, 0, 0], from).await; // NAT-PMP: unsupported version
                    continue;
                }
                let mut r = buf[..60].to_vec();
                r[1] = 0x81;
                r[3] = 0;
                r[4..8].copy_from_slice(&3600u32.to_be_bytes());
                r[42..44].copy_from_slice(&external.to_be_bytes());
                let _ = sock.send_to(&r, from).await;
            } else if buf[0] == 0 && n == 12 {
                let mut r = [0u8; 16];
                r[1] = 128 + buf[1];
                r[8..10].copy_from_slice(&buf[4..6]);
                r[10..12].copy_from_slice(&external.to_be_bytes());
                r[12..16].copy_from_slice(&3600u32.to_be_bytes());
                let _ = sock.send_to(&r, from).await;
            }
        }
    });
    addr
}

#[tokio::test]
async fn pcp_is_preferred_and_natpmp_is_the_fallback() {
    let pcp = spawn_pcp_natpmp_gateway(true, 40001).await;
    let m = acquire(&no_ssdp(vec![pcp]), PortProtocol::Tcp, 6881, "t")
        .await
        .unwrap();
    assert!(matches!(m.method, Method::Pcp(_)), "{:?}", m.method);
    assert_eq!((m.external_port, m.lifetime_secs), (40001, 3600));

    let old = spawn_pcp_natpmp_gateway(false, 40002).await;
    let m = acquire(&no_ssdp(vec![old]), PortProtocol::Udp, 6881, "t")
        .await
        .unwrap();
    assert!(matches!(m.method, Method::NatPmp(_)), "{:?}", m.method);
    assert_eq!(m.external_port, 40002);

    // Renewal keeps the method; release does not error even if the gateway ignores it.
    let renewed = renew(&m, PortProtocol::Udp, 6881, "t").await.unwrap();
    assert!(matches!(renewed.method, Method::NatPmp(_)));
    release(&renewed, PortProtocol::Udp, 6881).await;
}

#[tokio::test]
async fn a_dead_gateway_yields_an_error_not_a_hang() {
    let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let start = std::time::Instant::now();
    let res = acquire(&no_ssdp(vec![dead]), PortProtocol::Tcp, 6881, "t").await;
    assert!(res.is_err());
    assert!(start.elapsed() < Duration::from_secs(15));
}

/// Mock UPnP IGD: an SSDP responder, an HTTP server for the description and the control URL.
/// Records every SOAP action received.
struct MockIgd {
    ssdp: SocketAddr,
    actions: Arc<Mutex<Vec<String>>>,
}

async fn spawn_igd(location_host_override: Option<&'static str>) -> MockIgd {
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http.local_addr().unwrap();
    let actions = Arc::new(Mutex::new(Vec::new()));
    let actions2 = actions.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = http.accept().await else {
                return;
            };
            let actions = actions2.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut n = 0;
                // Read until the headers (and, for POST, the short body) have arrived.
                loop {
                    let Ok(k) = s.read(&mut buf[n..]).await else {
                        return;
                    };
                    if k == 0 {
                        break;
                    }
                    n += k;
                    let text = String::from_utf8_lossy(&buf[..n]).to_string();
                    if let Some(h) = text.find("\r\n\r\n") {
                        let want = text
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if n >= h + 4 + want {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = if text.starts_with("GET /desc.xml") {
                    r#"<root><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl</controlURL></service></serviceList></device></root>"#.to_string()
                } else if text.starts_with("POST /ctl") {
                    let action = text
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("soapaction:"))
                        .map(|l| {
                            l["soapaction:".len()..]
                                .trim()
                                .trim_matches('"')
                                .to_string()
                        })
                        .unwrap_or_default();
                    actions.lock().unwrap().push(format!(
                        "{action} :: {}",
                        text.split("\r\n\r\n").nth(1).unwrap_or("")
                    ));
                    "<ok/>".to_string()
                } else {
                    String::new()
                };
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });

    let ssdp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ssdp_addr = ssdp.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while let Ok((_, from)) = ssdp.recv_from(&mut buf).await {
            let host = location_host_override
                .map(str::to_string)
                .unwrap_or_else(|| "127.0.0.1".to_string());
            let reply = format!(
                "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLOCATION: http://{host}:{}/desc.xml\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n",
                http_addr.port()
            );
            let _ = ssdp.send_to(reply.as_bytes(), from).await;
        }
    });
    MockIgd {
        ssdp: ssdp_addr,
        actions,
    }
}

fn igd_discovery(igd: &MockIgd) -> Discovery {
    Discovery {
        gateways: vec![],
        ssdp_target: igd.ssdp,
        ssdp_timeout: Duration::from_millis(500),
    }
}

#[tokio::test]
async fn upnp_maps_renews_and_releases_through_the_gateways_soap_endpoint() {
    let igd = spawn_igd(None).await;
    let m = acquire(&igd_discovery(&igd), PortProtocol::Tcp, 6881, "Synapse")
        .await
        .unwrap();
    assert!(matches!(m.method, Method::Upnp(_)));
    assert_eq!(m.external_port, 6881);

    renew(&m, PortProtocol::Tcp, 6881, "Synapse").await.unwrap();
    release(&m, PortProtocol::Tcp, 6881).await;

    let actions = igd.actions.lock().unwrap().clone();
    assert_eq!(actions.len(), 3, "{actions:?}");
    assert!(
        actions[0].contains("WANIPConnection:1#AddPortMapping")
            && actions[0].contains("<NewExternalPort>6881</NewExternalPort>")
    );
    assert!(
        actions[0].contains("<NewProtocol>TCP</NewProtocol>")
            && actions[0].contains("<NewInternalClient>127.0.0.1</NewInternalClient>")
    );
    assert!(actions[1].contains("#AddPortMapping"));
    assert!(actions[2].contains("#DeletePortMapping"));
}

#[tokio::test]
async fn an_ssdp_reply_pointing_the_description_at_another_host_is_ignored() {
    // The responder is 127.0.0.1 but claims its description lives at 10.9.8.7: a spoofed
    // reply must not make the daemon fetch a URL on some other host.
    let igd = spawn_igd(Some("10.9.8.7")).await;
    let res = acquire(&igd_discovery(&igd), PortProtocol::Tcp, 6881, "Synapse").await;
    assert!(res.is_err(), "{res:?}");
    assert!(igd.actions.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_engine_maps_its_listen_port_through_the_gateway_and_uses_the_external_port() {
    use diskio::DiskEngine;
    use synapse_engine::SwarmEngine;

    let gw = spawn_pcp_natpmp_gateway(true, 40123).await;
    let engine = Arc::new(
        SwarmEngine::new(Arc::new(DiskEngine::auto().await), [5u8; 20])
            .with_nat_discovery(no_ssdp(vec![gw])),
    );
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    engine
        .clone()
        .start_listener(format!("127.0.0.1:{port}").parse().unwrap())
        .await
        .unwrap();

    // The mapping is negotiated in the background; the advertised port becomes the external one.
    let mut advertised = 0;
    for _ in 0..100 {
        advertised = engine.public_listen_port();
        if advertised == 40123 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        advertised, 40123,
        "the engine did not adopt the gateway's external port"
    );
}
