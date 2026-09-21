//! BEP 26 Zeroconf peer advertising and discovery (multicast DNS service discovery).
//!
//! A client publishes itself as the DNS-SD instance `<peer-id-hex>._bittorrent._tcp.local` and
//! for every torrent it shares a subtype `_<info-hash-hex>._sub._bittorrent._tcp.local` that
//! points at that instance; it finds other peers by browsing the subtype of a torrent. This
//! module builds and reads the mDNS messages: PTR questions and answers, and the SRV (port, host)
//! and A/AAAA (address) records that turn an instance into a peer address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const MDNS_IPV4: &str = "224.0.0.251:5353";
pub const MDNS_IPV6: &str = "[ff02::fb]:5353";

const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;
const CLASS_IN: u16 = 1;
const CACHE_FLUSH: u16 = 0x8000;
const RECORD_TTL: u32 = 120;
/// The most records read from one message, so a crafted packet cannot burn CPU.
const MAX_RECORDS: usize = 256;

pub const SERVICE: &str = "_bittorrent._tcp.local";

/// `_<info-hash-hex>._sub._bittorrent._tcp.local`: what peers of one torrent are listed under.
pub fn sub_service_name(info_hash: &[u8; 20]) -> String {
    format!("_{}._sub.{SERVICE}", hex(info_hash))
}

/// `<peer-id-hex>._bittorrent._tcp.local`: one client.
pub fn instance_name(peer_id: &[u8; 20]) -> String {
    format!("{}.{SERVICE}", hex(peer_id))
}

/// `<peer-id-hex>.local`: the host that instance runs on.
pub fn host_name(peer_id: &[u8; 20]) -> String {
    format!("{}.local", hex(peer_id))
}

fn hex(bytes: &[u8; 20]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The info hash a `_<hex>._sub._bittorrent._tcp.local` name is for.
pub fn info_hash_of_sub_service(name: &str) -> Option<[u8; 20]> {
    let hex = name
        .strip_prefix('_')?
        .strip_suffix(&format!("._sub.{SERVICE}"))?;
    if hex.len() != 40 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn push_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let bytes = label.as_bytes();
        out.push(bytes.len().min(63) as u8);
        out.extend_from_slice(&bytes[..bytes.len().min(63)]);
    }
    out.push(0);
}

fn header(flags: u16, questions: u16, answers: u16) -> Vec<u8> {
    let mut h = Vec::with_capacity(12);
    h.extend_from_slice(&0u16.to_be_bytes()); // mDNS uses id 0
    h.extend_from_slice(&flags.to_be_bytes());
    h.extend_from_slice(&questions.to_be_bytes());
    h.extend_from_slice(&answers.to_be_bytes());
    h.extend_from_slice(&[0u8; 4]);
    h
}

/// A query asking who is on each of `names` (PTR questions). Keep to a handful of names per
/// message so it fits one datagram.
pub fn build_query(names: &[String]) -> Vec<u8> {
    let mut msg = header(0, names.len() as u16, 0);
    for name in names {
        push_name(&mut msg, name);
        msg.extend_from_slice(&TYPE_PTR.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    }
    msg
}

fn push_record(out: &mut Vec<u8>, name: &str, rtype: u16, rdata: &[u8]) {
    push_name(out, name);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&(CLASS_IN | CACHE_FLUSH).to_be_bytes());
    out.extend_from_slice(&RECORD_TTL.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
}

/// An announcement/response: PTR records from the parent service and from each torrent's
/// subtype to our instance, the instance's SRV (port and host) and TXT, and the host's addresses.
pub fn build_response(
    peer_id: &[u8; 20],
    info_hashes: &[[u8; 20]],
    port: u16,
    addrs: &[IpAddr],
) -> Vec<u8> {
    let instance = instance_name(peer_id);
    let host = host_name(peer_id);
    let mut records: Vec<u8> = Vec::new();
    let mut count = 0u16;

    let mut ptr_rdata = Vec::new();
    push_name(&mut ptr_rdata, &instance);
    push_record(&mut records, SERVICE, TYPE_PTR, &ptr_rdata);
    count += 1;
    for hash in info_hashes {
        push_record(&mut records, &sub_service_name(hash), TYPE_PTR, &ptr_rdata);
        count += 1;
    }
    let mut srv = Vec::new();
    srv.extend_from_slice(&[0, 0, 0, 0]); // priority, weight
    srv.extend_from_slice(&port.to_be_bytes());
    push_name(&mut srv, &host);
    push_record(&mut records, &instance, TYPE_SRV, &srv);
    push_record(&mut records, &instance, TYPE_TXT, &[0]);
    count += 2;
    for addr in addrs {
        match addr {
            IpAddr::V4(a) => push_record(&mut records, &host, TYPE_A, &a.octets()),
            IpAddr::V6(a) => push_record(&mut records, &host, TYPE_AAAA, &a.octets()),
        }
        count += 1;
    }
    let mut msg = header(0x8400, 0, count); // response, authoritative
    msg.extend_from_slice(&records);
    msg
}

/// What a received message says, reduced to what BEP 26 uses.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DnsMessage {
    pub is_response: bool,
    /// Names asked about (PTR questions).
    pub questions: Vec<String>,
    /// `(name, target)` PTR answers.
    pub ptr: Vec<(String, String)>,
    /// `(instance, port, host)` SRV answers.
    pub srv: Vec<(String, u16, String)>,
    /// `(host, address)` A / AAAA answers.
    pub addrs: Vec<(String, IpAddr)>,
}

/// Reads a DNS name at `pos`, following compression pointers (at most a few, never forward
/// past a loop). Returns the lower-cased dotted name and the position just after it.
fn read_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    let mut total = 0usize;
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let low = *buf.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            jumps += 1;
            if jumps > 8 {
                return None;
            }
            pos = ((len & 0x3F) << 8) | low;
            continue;
        }
        if len > 63 {
            return None;
        }
        let label = buf.get(pos + 1..pos + 1 + len)?;
        total += len + 1;
        if total > 255 {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += 1 + len;
    }
    Some((labels.join("."), end.unwrap_or(pos)))
}

/// Parses an mDNS message. Anything malformed yields `None`.
pub fn parse_message(buf: &[u8]) -> Option<DnsMessage> {
    if buf.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let ns = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let ar = u16::from_be_bytes([buf[10], buf[11]]) as usize;
    if qd + an + ns + ar > MAX_RECORDS {
        return None;
    }
    let mut msg = DnsMessage {
        is_response: flags & 0x8000 != 0,
        ..Default::default()
    };
    let mut pos = 12;
    for _ in 0..qd {
        let (name, next) = read_name(buf, pos)?;
        let qtype = u16::from_be_bytes([*buf.get(next)?, *buf.get(next + 1)?]);
        pos = next + 4;
        if qtype == TYPE_PTR {
            msg.questions.push(name);
        }
    }
    for _ in 0..an + ns + ar {
        let (name, next) = read_name(buf, pos)?;
        let rtype = u16::from_be_bytes([*buf.get(next)?, *buf.get(next + 1)?]);
        let rdlen = u16::from_be_bytes([*buf.get(next + 8)?, *buf.get(next + 9)?]) as usize;
        let rdata_at = next + 10;
        let rdata = buf.get(rdata_at..rdata_at + rdlen)?;
        pos = rdata_at + rdlen;
        match rtype {
            TYPE_PTR => {
                let (target, _) = read_name(buf, rdata_at)?;
                msg.ptr.push((name, target));
            }
            TYPE_SRV if rdlen >= 7 => {
                let port = u16::from_be_bytes([rdata[4], rdata[5]]);
                let (host, _) = read_name(buf, rdata_at + 6)?;
                msg.srv.push((name, port, host));
            }
            TYPE_A if rdlen == 4 => msg.addrs.push((
                name,
                IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            )),
            TYPE_AAAA if rdlen == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                msg.addrs.push((name, IpAddr::V6(Ipv6Addr::from(o))));
            }
            _ => {}
        }
    }
    Some(msg)
}

/// The peers a response lists for torrents: every PTR under a `_<hash>._sub._bittorrent._tcp`
/// name whose instance has a SRV record and whose host has an address in the same message.
pub fn discovered_peers(msg: &DnsMessage) -> Vec<([u8; 20], std::net::SocketAddr)> {
    let mut out = Vec::new();
    for (name, instance) in &msg.ptr {
        let Some(hash) = info_hash_of_sub_service(name) else {
            continue;
        };
        for (srv_name, port, host) in &msg.srv {
            if srv_name != instance || *port == 0 {
                continue;
            }
            for (addr_host, ip) in &msg.addrs {
                if addr_host == host {
                    out.push((hash, std::net::SocketAddr::new(*ip, *port)));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: [u8; 20] = [0xAB; 20];
    const PEER: [u8; 20] = *b"-SY2200-abcdefghijkl";

    #[test]
    fn names_follow_the_bep() {
        assert_eq!(
            sub_service_name(&HASH),
            format!("_{}._sub._bittorrent._tcp.local", "ab".repeat(20))
        );
        assert_eq!(
            info_hash_of_sub_service(&sub_service_name(&HASH)),
            Some(HASH)
        );
        assert_eq!(
            info_hash_of_sub_service("_zz._sub._bittorrent._tcp.local"),
            None
        );
        assert_eq!(info_hash_of_sub_service("_bittorrent._tcp.local"), None);
        assert!(instance_name(&PEER).ends_with("._bittorrent._tcp.local"));
    }

    #[test]
    fn a_query_lists_the_subtypes_asked_about() {
        let names = vec![sub_service_name(&HASH), sub_service_name(&[1; 20])];
        let msg = parse_message(&build_query(&names)).unwrap();
        assert!(!msg.is_response);
        assert_eq!(msg.questions, names);
    }

    #[test]
    fn a_response_yields_the_peers_it_announces() {
        let addrs = [
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 9)),
            IpAddr::V6("fe80::1".parse().unwrap()),
        ];
        let bytes = build_response(&PEER, &[HASH, [2; 20]], 6881, &addrs);
        let msg = parse_message(&bytes).unwrap();
        assert!(msg.is_response);
        let mut found = discovered_peers(&msg);
        found.sort();
        let mut expected = vec![
            (HASH, "192.168.1.9:6881".parse().unwrap()),
            (HASH, "[fe80::1]:6881".parse().unwrap()),
            ([2; 20], "192.168.1.9:6881".parse().unwrap()),
            ([2; 20], "[fe80::1]:6881".parse().unwrap()),
        ];
        expected.sort();
        assert_eq!(found, expected);
    }

    #[test]
    fn malformed_and_hostile_messages_are_rejected_without_panicking() {
        assert!(parse_message(&[]).is_none());
        assert!(parse_message(&[0; 11]).is_none());
        // Claims 1000 records.
        let mut many = header(0x8400, 0, 1000);
        many.extend_from_slice(&[0; 32]);
        assert!(parse_message(&many).is_none());
        // A compression pointer that points at itself.
        let mut looped = header(0, 1, 0);
        looped.extend_from_slice(&[0xC0, 12, 0, 12, 0, 1]);
        assert!(parse_message(&looped).is_none());
        // Truncations of a valid message never panic.
        let valid = build_response(&PEER, &[HASH], 1, &[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        for cut in 0..valid.len() {
            let _ = parse_message(&valid[..cut]);
        }
        // A response with SRV port 0 or no matching address yields no peer.
        let no_addr = build_response(&PEER, &[HASH], 6881, &[]);
        assert!(discovered_peers(&parse_message(&no_addr).unwrap()).is_empty());
        let zero_port = build_response(&PEER, &[HASH], 0, &[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        assert!(discovered_peers(&parse_message(&zero_port).unwrap()).is_empty());
    }
}
