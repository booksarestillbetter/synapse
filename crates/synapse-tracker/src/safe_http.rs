//! SSRF-resistant, size-bounded HTTP GET, shared by tracker announces/scrapes, webseed
//! range requests, and `.torrent` URL fetches.
//!
//! The URLs fetched here come from untrusted places (a `.torrent`'s announce list and
//! `url-list`, a tracker's redirect, an API caller), so a plain HTTP client would let a
//! hostile torrent make the daemon probe or attack services on its own network. Rules:
//!
//! * Only `http`/`https`.
//! * The host is resolved by us, once per hop, and the connection is pinned to exactly
//!   the addresses we checked (no DNS-rebinding window between check and connect).
//! * An origin that resolves to a non-public address (loopback, private, link-local, ULA,
//!   ...) is subject to the caller's [`LocalPolicy`]. A host that resolves to a mix of
//!   public and non-public addresses counts as non-public.
//! * A redirect from a public origin to a non-public target is refused, at most
//!   [`MAX_REDIRECTS`] redirects are followed, and userinfo is dropped when a redirect
//!   changes host.
//! * The body is streamed and abandoned the moment it exceeds the caller's cap, whatever
//!   `Content-Length` claims. No `Accept-Encoding` is sent, so a compressed-bomb response
//!   is never inflated.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use url::Url;

static PROXY: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// Sends every request through `proxy_url` (`socks5h://...`, `socks5://...` or `http://...`), or
/// back to direct connections with `None`. With a proxy the proxy is the network boundary, so
/// host names are not resolved here (that would leak the lookup); literal addresses are still
/// checked against the local-network rules.
pub fn set_proxy(proxy_url: Option<String>) {
    *PROXY.write().unwrap_or_else(|e| e.into_inner()) = proxy_url;
}

fn proxy() -> Option<String> {
    PROXY.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Redirects followed before giving up (libtorrent's `max_http_recv_buffer`-era default of 5).
pub const MAX_REDIRECTS: usize = 5;

/// What to do when the *initial* URL points at a non-public address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPolicy {
    /// Refuse. For URLs that arrive inside torrents (web seeds) and have no business
    /// pointing at the local network.
    Deny,
    /// Allow only when some path segment is one of these (e.g. `announce`, `scrape`), so
    /// a torrent's tracker URL cannot be aimed at an arbitrary local admin endpoint.
    AllowPathSegments(&'static [&'static str]),
    /// Allow anything. For URLs the operator supplied themselves (an API call), where a
    /// LAN indexer is legitimate. Redirects from a public origin to a local target are
    /// still refused.
    AllowAny,
}

#[derive(Debug, Clone)]
pub struct FetchOptions {
    pub timeout: Duration,
    pub max_body: usize,
    pub user_agent: &'static str,
    pub local: LocalPolicy,
    /// Value for a `Range` header, e.g. `bytes=0-16383`.
    pub range: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("invalid URL: {0}")]
    InvalidUrl(&'static str),
    #[error("request blocked: {0}")]
    Blocked(&'static str),
    #[error("too many redirects")]
    TooManyRedirects,
    #[error("response body exceeded {0} bytes")]
    TooLarge(usize),
    #[error("could not resolve host")]
    Resolve,
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
}

pub struct Fetched {
    pub status: u16,
    /// `Content-Range` header of the final response, if any.
    pub content_range: Option<String>,
    pub body: Vec<u8>,
}

/// True for addresses reachable on the public internet; false for anything an outside
/// party must not be able to make us contact.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_public_v4(mapped);
            }
            let s = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link local fe80::/10
                || (s[0] == 0x2001 && s[1] == 0x0db8)) // documentation
        }
    }
}

fn is_public_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    !(v4.is_unspecified()
        || v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_documentation()
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT 100.64.0.0/10
        || o[0] == 0
        || o[0] >= 240) // reserved
}

/// Resolves `url`'s host to the concrete addresses we will connect to.
async fn resolve(url: &Url) -> Result<Vec<SocketAddr>, FetchError> {
    let host = url
        .host_str()
        .ok_or(FetchError::InvalidUrl("missing host"))?;
    let port = url
        .port_or_known_default()
        .ok_or(FetchError::InvalidUrl("no port"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| FetchError::Resolve)?
        .collect();
    if addrs.is_empty() {
        return Err(FetchError::Resolve);
    }
    Ok(addrs)
}

fn path_has_segment(url: &Url, allowed: &[&str]) -> bool {
    url.path_segments()
        .is_some_and(|mut segs| segs.any(|s| allowed.contains(&s)))
}

/// Decides whether a hop to `url`, which resolved to `addrs`, is allowed, given whether
/// the chain started at a public origin and the caller's local policy.
fn check_hop(
    url: &Url,
    addrs: &[SocketAddr],
    origin_public: bool,
    local: LocalPolicy,
) -> Result<(), FetchError> {
    if addrs.iter().all(|a| is_public_ip(a.ip())) {
        return Ok(());
    }
    if origin_public {
        return Err(FetchError::Blocked(
            "redirect from a public host to a non-public address",
        ));
    }
    match local {
        LocalPolicy::Deny => Err(FetchError::Blocked("non-public address not permitted")),
        LocalPolicy::AllowAny => Ok(()),
        LocalPolicy::AllowPathSegments(allowed) => {
            if path_has_segment(url, allowed) {
                Ok(())
            } else {
                Err(FetchError::Blocked(
                    "non-public tracker URL must target an announce/scrape path",
                ))
            }
        }
    }
}

/// Performs a redirect-checked, size-capped GET. See the module docs for the rules.
pub async fn fetch(url: &Url, opts: &FetchOptions) -> Result<Fetched, FetchError> {
    let mut current = url.clone();
    let mut origin_public: Option<bool> = None;

    for hop in 0..=MAX_REDIRECTS {
        if current.scheme() != "http" && current.scheme() != "https" {
            return Err(FetchError::InvalidUrl("only http and https are allowed"));
        }
        let proxy_url = proxy();
        let host_is_name = current.host_str().is_some_and(|h| {
            h.trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .is_err()
        });
        // Through a proxy a host name is the proxy's business to resolve.
        let addrs = if proxy_url.is_some() && host_is_name {
            Vec::new()
        } else {
            resolve(&current).await?
        };
        let public = addrs.iter().all(|a| is_public_ip(a.ip()));
        let origin_is_public = *origin_public.get_or_insert(public);
        // The first hop has no "origin" to be redirected from: it is judged by the local
        // policy alone (origin_public is false when it is itself local).
        check_hop(
            &current,
            &addrs,
            if hop == 0 { false } else { origin_is_public },
            opts.local,
        )?;

        let mut builder = reqwest::Client::builder()
            .timeout(opts.timeout)
            .user_agent(opts.user_agent)
            .redirect(reqwest::redirect::Policy::none());
        if let Some(proxy_url) = &proxy_url {
            builder = builder.proxy(reqwest::Proxy::all(proxy_url).map_err(FetchError::Http)?);
        } else if let Some(host) = current.host_str() {
            if host.parse::<IpAddr>().is_err() && !host.starts_with('[') {
                builder = builder.resolve_to_addrs(host, &addrs);
            }
        }
        let client = builder.build()?;
        let mut req = client.get(current.clone());
        if let Some(ref range) = opts.range {
            req = req.header(reqwest::header::RANGE, range);
        }
        let mut resp = req.send().await?;

        let status = resp.status();
        if status.is_redirection() {
            let Some(location) = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
            else {
                return Err(FetchError::InvalidUrl("redirect without a Location header"));
            };
            let mut next = current
                .join(location)
                .map_err(|_| FetchError::InvalidUrl("invalid redirect target"))?;
            if next.host_str() != current.host_str() {
                let _ = next.set_username("");
                let _ = next.set_password(None);
            }
            current = next;
            continue;
        }

        if let Some(len) = resp.content_length() {
            if len > opts.max_body as u64 {
                return Err(FetchError::TooLarge(opts.max_body));
            }
        }
        let content_range = resp
            .headers()
            .get(reqwest::header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > opts.max_body {
                return Err(FetchError::TooLarge(opts.max_body));
            }
            body.extend_from_slice(&chunk);
        }
        return Ok(Fetched {
            status: status.as_u16(),
            content_range,
            body,
        });
    }
    Err(FetchError::TooManyRedirects)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn classifies_public_and_non_public_addresses() {
        for public in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public_ip(ip(public)), "{public} should be public");
        }
        for local in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_public_ip(ip(local)), "{local} should not be public");
        }
        assert!(
            is_public_ip(ip("172.32.0.1")),
            "172.32/16 is outside RFC 1918"
        );
        assert!(is_public_ip(ip("100.128.0.1")), "just outside CGNAT");
    }

    fn sa(s: &str) -> Vec<SocketAddr> {
        vec![SocketAddr::new(ip(s), 80)]
    }

    #[test]
    fn local_policy_governs_the_first_hop() {
        let tracker = Url::parse("http://192.168.1.10/announce?k=1").unwrap();
        let admin = Url::parse("http://192.168.1.10/admin/reboot").unwrap();
        let allow = LocalPolicy::AllowPathSegments(&["announce", "scrape"]);
        assert!(check_hop(&tracker, &sa("192.168.1.10"), false, allow).is_ok());
        assert!(check_hop(&admin, &sa("192.168.1.10"), false, allow).is_err());
        assert!(check_hop(&tracker, &sa("192.168.1.10"), false, LocalPolicy::Deny).is_err());
        assert!(check_hop(&admin, &sa("192.168.1.10"), false, LocalPolicy::AllowAny).is_ok());
    }

    #[test]
    fn a_public_origin_can_never_redirect_to_a_non_public_target() {
        let target = Url::parse("http://127.0.0.1/announce").unwrap();
        for policy in [
            LocalPolicy::Deny,
            LocalPolicy::AllowAny,
            LocalPolicy::AllowPathSegments(&["announce"]),
        ] {
            assert!(check_hop(&target, &sa("127.0.0.1"), true, policy).is_err());
        }
        let ok = Url::parse("http://8.8.8.8/announce").unwrap();
        assert!(check_hop(&ok, &sa("8.8.8.8"), true, LocalPolicy::Deny).is_ok());
    }

    #[test]
    fn mixed_public_and_private_resolution_counts_as_non_public() {
        let u = Url::parse("http://rebind.example/x").unwrap();
        let addrs = vec![
            SocketAddr::new(ip("8.8.8.8"), 80),
            SocketAddr::new(ip("10.0.0.1"), 80),
        ];
        assert!(check_hop(&u, &addrs, false, LocalPolicy::Deny).is_err());
    }
}
