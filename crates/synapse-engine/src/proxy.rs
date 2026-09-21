//! Outbound proxy support: SOCKS5 (RFC 1928, with RFC 1929 username/password) and HTTP CONNECT.
//!
//! One proxy, configured once for the process, carries the peer connections we open and (through
//! `synapse_tracker::safe_http`) the HTTP requests to trackers, web seeds, feeds and search
//! engines. Nothing that would bypass it is left running: with a proxy for peer connections uTP is
//! not used, and with `force_proxy` the daemon starts no UDP services and no listeners, so the
//! only traffic that leaves the host goes through the proxy.

use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const PROXY_TIMEOUT: Duration = Duration::from_secs(15);
/// The largest HTTP CONNECT reply head we read.
const MAX_CONNECT_REPLY: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    Socks5,
    Http,
}

#[derive(Debug, Clone)]
pub struct ProxySettings {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub auth: Option<(String, String)>,
    /// Open peer connections through the proxy.
    pub proxy_peer_connections: bool,
    /// Send tracker, web seed, RSS, search and update requests through the proxy.
    pub proxy_http: bool,
    /// Let the proxy resolve host names (SOCKS5h): no DNS query leaves this host.
    pub proxy_hostnames: bool,
    /// Anonymous mode: nothing may bypass the proxy (see the module docs).
    pub force_proxy: bool,
}

impl ProxySettings {
    /// The proxy URL `reqwest` understands (`socks5h://`, `socks5://` or `http://`).
    pub fn url(&self) -> String {
        let scheme = match (self.kind, self.proxy_hostnames) {
            (ProxyKind::Socks5, true) => "socks5h",
            (ProxyKind::Socks5, false) => "socks5",
            (ProxyKind::Http, _) => "http",
        };
        let auth = self
            .auth
            .as_ref()
            .map(|(u, p)| format!("{}:{}@", encode_userinfo(u), encode_userinfo(p)))
            .unwrap_or_default();
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("{scheme}://{auth}{host}:{}", self.port)
    }
}

fn encode_userinfo(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

static GLOBAL: RwLock<Option<ProxySettings>> = RwLock::new(None);

/// Installs (or clears) the process-wide proxy, including the one `safe_http` uses.
pub fn set_global(settings: Option<ProxySettings>) {
    synapse_tracker::safe_http::set_proxy(
        settings
            .as_ref()
            .filter(|s| s.proxy_http)
            .map(ProxySettings::url),
    );
    *GLOBAL.write().unwrap_or_else(|e| e.into_inner()) = settings;
}

pub fn global() -> Option<ProxySettings> {
    GLOBAL.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// True when peer connections must not use UDP (uTP): a proxy carries them, and it carries TCP.
pub fn peers_use_proxy() -> bool {
    global().is_some_and(|p| p.proxy_peer_connections)
}

pub fn force_proxy() -> bool {
    global().is_some_and(|p| p.force_proxy)
}

/// Opens a TCP connection to a peer, through the proxy when peer connections are proxied.
pub async fn connect_peer(addr: SocketAddr) -> std::io::Result<TcpStream> {
    match global().filter(|p| p.proxy_peer_connections) {
        Some(proxy) => connect_via(&proxy, addr).await,
        None => TcpStream::connect(addr).await,
    }
}

/// Connects to `target` through `proxy`.
pub async fn connect_via(proxy: &ProxySettings, target: SocketAddr) -> std::io::Result<TcpStream> {
    let attempt = async {
        let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port)).await?;
        stream.set_nodelay(true).ok();
        match proxy.kind {
            ProxyKind::Socks5 => socks5_connect(&mut stream, proxy, target).await?,
            ProxyKind::Http => http_connect(&mut stream, proxy, target).await?,
        }
        Ok::<_, std::io::Error>(stream)
    };
    tokio::time::timeout(PROXY_TIMEOUT, attempt)
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "proxy handshake timed out")
        })?
}

fn proxy_error(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionRefused, msg.into())
}

async fn socks5_connect(
    stream: &mut TcpStream,
    proxy: &ProxySettings,
    target: SocketAddr,
) -> std::io::Result<()> {
    // Greeting: version 5, and the methods we can do.
    let methods: &[u8] = if proxy.auth.is_some() {
        &[0x00, 0x02]
    } else {
        &[0x00]
    };
    let mut hello = vec![0x05, methods.len() as u8];
    hello.extend_from_slice(methods);
    stream.write_all(&hello).await?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    if choice[0] != 0x05 {
        return Err(proxy_error("not a SOCKS5 proxy"));
    }
    match choice[1] {
        0x00 => {}
        0x02 => {
            let (user, pass) = proxy
                .auth
                .as_ref()
                .ok_or_else(|| proxy_error("the proxy wants credentials"))?;
            if user.len() > 255 || pass.len() > 255 {
                return Err(proxy_error("proxy credentials are too long"));
            }
            let mut auth = vec![0x01, user.len() as u8];
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth).await?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await?;
            if status[1] != 0x00 {
                return Err(proxy_error("the proxy rejected the credentials"));
            }
        }
        _ => {
            return Err(proxy_error(
                "the proxy accepts none of our authentication methods",
            ))
        }
    }
    // CONNECT to an address (peers are always addresses, so nothing is resolved locally).
    let mut req = vec![0x05, 0x01, 0x00];
    match target {
        SocketAddr::V4(a) => {
            req.push(0x01);
            req.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            req.push(0x04);
            req.extend_from_slice(&a.ip().octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&req).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(proxy_error("malformed SOCKS5 reply"));
    }
    if head[1] != 0x00 {
        return Err(proxy_error(format!(
            "the proxy refused the connection (code {})",
            head[1]
        )));
    }
    // Skip the bound address in the reply.
    let skip = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0]) + 2
        }
        _ => return Err(proxy_error("malformed SOCKS5 reply address")),
    };
    let mut discard = vec![0u8; skip];
    stream.read_exact(&mut discard).await?;
    Ok(())
}

async fn http_connect(
    stream: &mut TcpStream,
    proxy: &ProxySettings,
    target: SocketAddr,
) -> std::io::Result<()> {
    use base64::Engine as _;
    let authority = target.to_string();
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some((user, pass)) = &proxy.auth {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    // Read the reply head byte by byte so nothing of the tunnelled stream is consumed.
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_CONNECT_REPLY {
            return Err(proxy_error("the proxy's reply is too long"));
        }
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    let status = text.split_whitespace().nth(1).unwrap_or("");
    if status.starts_with('2') {
        Ok(())
    } else {
        Err(proxy_error(format!(
            "the proxy refused CONNECT: {}",
            text.lines().next().unwrap_or("")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn settings(kind: ProxyKind, port: u16, auth: Option<(&str, &str)>) -> ProxySettings {
        ProxySettings {
            kind,
            host: "127.0.0.1".into(),
            port,
            auth: auth.map(|(u, p)| (u.into(), p.into())),
            proxy_peer_connections: true,
            proxy_http: true,
            proxy_hostnames: true,
            force_proxy: false,
        }
    }

    /// A SOCKS5 proxy that (optionally) demands credentials, then relays to the requested address.
    async fn socks5_server(
        creds: Option<(&'static str, &'static str)>,
    ) -> (u16, tokio::sync::oneshot::Receiver<SocketAddr>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            let mut hello = [0u8; 2];
            c.read_exact(&mut hello).await.unwrap();
            let mut methods = vec![0u8; hello[1] as usize];
            c.read_exact(&mut methods).await.unwrap();
            match creds {
                Some((u, p)) => {
                    assert!(methods.contains(&0x02));
                    c.write_all(&[5, 2]).await.unwrap();
                    let mut v = [0u8; 2];
                    c.read_exact(&mut v).await.unwrap();
                    let mut user = vec![0u8; v[1] as usize];
                    c.read_exact(&mut user).await.unwrap();
                    let mut plen = [0u8; 1];
                    c.read_exact(&mut plen).await.unwrap();
                    let mut pass = vec![0u8; plen[0] as usize];
                    c.read_exact(&mut pass).await.unwrap();
                    let ok = user == u.as_bytes() && pass == p.as_bytes();
                    c.write_all(&[1, if ok { 0 } else { 1 }]).await.unwrap();
                    if !ok {
                        return;
                    }
                }
                None => c.write_all(&[5, 0]).await.unwrap(),
            }
            let mut req = [0u8; 10];
            c.read_exact(&mut req).await.unwrap();
            assert_eq!(&req[..4], &[5, 1, 0, 1]);
            let target = SocketAddr::from((
                [req[4], req[5], req[6], req[7]],
                u16::from_be_bytes([req[8], req[9]]),
            ));
            let _ = tx.send(target);
            c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            // Echo, to show the tunnel carries data both ways.
            let mut buf = [0u8; 64];
            while let Ok(n) = c.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                c.write_all(&buf[..n]).await.unwrap();
            }
        });
        (port, rx)
    }

    #[tokio::test]
    async fn socks5_tunnels_to_the_requested_peer_with_and_without_credentials() {
        let target: SocketAddr = "203.0.113.7:6881".parse().unwrap();
        for creds in [None, Some(("alice", "s3cret"))] {
            let (port, seen) = socks5_server(creds).await;
            let mut s = connect_via(&settings(ProxyKind::Socks5, port, creds), target)
                .await
                .unwrap();
            assert_eq!(
                seen.await.unwrap(),
                target,
                "the proxy is asked for the peer's address"
            );
            s.write_all(b"ping").await.unwrap();
            let mut back = [0u8; 4];
            s.read_exact(&mut back).await.unwrap();
            assert_eq!(&back, b"ping");
        }
        // Wrong credentials are refused.
        let (port, _) = socks5_server(Some(("alice", "s3cret"))).await;
        let err = connect_via(
            &settings(ProxyKind::Socks5, port, Some(("alice", "wrong"))),
            target,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("credentials"), "{err}");
    }

    #[tokio::test]
    async fn http_connect_tunnels_and_leaves_the_stream_untouched() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let head = tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 512];
            let mut n = 0;
            while !buf[..n].ends_with(b"\r\n\r\n") {
                n += c.read(&mut buf[n..]).await.unwrap();
            }
            // Reply and immediately send tunnelled bytes in the same write.
            c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nHELLO")
                .await
                .unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        let target: SocketAddr = "[2001:db8::9]:51413".parse().unwrap();
        let mut s = connect_via(
            &settings(ProxyKind::Http, port, Some(("bob", "pw"))),
            target,
        )
        .await
        .unwrap();
        let mut hello = [0u8; 5];
        s.read_exact(&mut hello).await.unwrap();
        assert_eq!(
            &hello, b"HELLO",
            "no tunnelled byte was swallowed with the reply head"
        );
        let head = head.await.unwrap();
        assert!(
            head.starts_with("CONNECT [2001:db8::9]:51413 HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(
            head.contains("Proxy-Authorization: Basic Ym9iOnB3"),
            "{head}"
        );

        // A refusal surfaces as an error.
        let refuse = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rport = refuse.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut c, _) = refuse.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let _ = c.read(&mut buf).await;
            let _ = c.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
        });
        let err = connect_via(&settings(ProxyKind::Http, rport, None), target)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("403"), "{err}");
    }

    #[test]
    fn the_proxy_url_carries_credentials_and_the_dns_choice() {
        let mut p = settings(ProxyKind::Socks5, 1080, Some(("us er", "p@ss:w/rd")));
        assert_eq!(p.url(), "socks5h://us%20er:p%40ss%3Aw%2Frd@127.0.0.1:1080");
        p.proxy_hostnames = false;
        p.auth = None;
        assert_eq!(p.url(), "socks5://127.0.0.1:1080");
        p.kind = ProxyKind::Http;
        p.host = "::1".into();
        assert_eq!(p.url(), "http://[::1]:1080");
    }
}
