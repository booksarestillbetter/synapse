//! Sharing one UDP port between the uTP transport and the DHT.
//!
//! Both want "the peer port" on UDP (uTP so peers can reach us, the DHT because that is the
//! port operators forward). Two sockets cannot bind the same UDP port, so a [`UdpMux`] owns
//! the real socket and hands each protocol a [`UdpTransport`]: the demultiplexer reads every
//! datagram once and routes it by its first byte. A KRPC (DHT) message is a bencoded
//! dictionary, so it starts with `d`; a uTP packet starts with `(type << 4) | version` where
//! the version is 1, so it can never be `d` (0x64). Sends go straight to the real socket.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

fn is_transient_udp_recv_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
    )
}

fn is_fatal_udp_recv_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::NotConnected
    )
}

/// Datagrams buffered per protocol before further ones for that protocol are dropped. UDP is
/// lossy anyway, and dropping keeps a slow consumer from stalling the other protocol.
const QUEUE_DEPTH: usize = 1024;

/// A UDP endpoint: either a plain socket, or one protocol's view of a shared [`UdpMux`].
pub enum UdpTransport {
    Plain(UdpSocket),
    Shared(SharedUdp),
}

/// One protocol's channel-backed view of a shared socket.
pub struct SharedUdp {
    real: Arc<UdpSocket>,
    rx: Mutex<mpsc::Receiver<(Bytes, SocketAddr)>>,
}

impl From<UdpSocket> for UdpTransport {
    fn from(s: UdpSocket) -> Self {
        UdpTransport::Plain(s)
    }
}

impl UdpTransport {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            UdpTransport::Plain(s) => s.local_addr(),
            UdpTransport::Shared(s) => s.real.local_addr(),
        }
    }

    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        match self {
            UdpTransport::Plain(s) => s.send_to(buf, target).await,
            UdpTransport::Shared(s) => s.real.send_to(buf, target).await,
        }
    }

    /// Receives one datagram as a `Bytes` buffer.
    ///
    /// On shared muxed endpoints this delivers the demultiplexer's `Bytes` directly without an
    /// extra copy or touching `scratch`. On plain sockets it reads into `scratch` and copies the
    /// received slice into `Bytes`.
    pub async fn recv_bytes(&self, scratch: &mut [u8]) -> io::Result<(Bytes, SocketAddr)> {
        match self {
            UdpTransport::Plain(s) => {
                let (n, from) = s.recv_from(scratch).await?;
                Ok((Bytes::copy_from_slice(&scratch[..n]), from))
            }
            UdpTransport::Shared(s) => s.rx.lock().await.recv().await.ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "UDP demultiplexer stopped")
            }),
        }
    }

    /// Receives one datagram, truncating it to `buf` like `UdpSocket::recv_from`.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            UdpTransport::Plain(s) => s.recv_from(buf).await,
            UdpTransport::Shared(s) => {
                let (data, from) = s.rx.lock().await.recv().await.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "UDP demultiplexer stopped")
                })?;
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok((n, from))
            }
        }
    }
}

/// Which protocol a datagram on a shared port belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpProtocol {
    Dht,
    Utp,
}

/// Classifies a datagram by its first byte (see the module docs). Empty datagrams are uTP's
/// problem (it will discard them).
pub fn classify(datagram: &[u8]) -> UdpProtocol {
    if datagram.first() == Some(&b'd') {
        UdpProtocol::Dht
    } else {
        UdpProtocol::Utp
    }
}

/// The two protocol endpoints produced by [`UdpMux::bind`].
pub struct UdpMux {
    pub dht: UdpTransport,
    pub utp: UdpTransport,
    pub local_addr: SocketAddr,
}

impl UdpMux {
    /// Binds `addr` and starts the demultiplexer task. The task ends when both endpoints
    /// have been dropped.
    pub async fn bind(addr: SocketAddr) -> io::Result<UdpMux> {
        let real = Arc::new(UdpSocket::bind(addr).await?);
        let local_addr = real.local_addr()?;
        let (dht_tx, dht_rx) = mpsc::channel(QUEUE_DEPTH);
        let (utp_tx, utp_rx) = mpsc::channel(QUEUE_DEPTH);
        let reader = real.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            let both_closed = async {
                tokio::join!(dht_tx.closed(), utp_tx.closed());
            };
            tokio::pin!(both_closed);

            loop {
                let (n, from) = tokio::select! {
                    biased;
                    _ = &mut both_closed => break,
                    res = reader.recv_from(&mut buf) => match res {
                        Ok(v) => v,
                        // ICMP "port unreachable" and transient signals say nothing about socket health.
                        Err(e) if is_transient_udp_recv_error(&e) => continue,
                        Err(e) if is_fatal_udp_recv_error(&e) => break,
                        Err(_) => {
                            tokio::select! {
                                _ = &mut both_closed => break,
                                _ = tokio::time::sleep(Duration::from_millis(25)) => continue,
                            }
                        }
                    },
                };
                let target = match classify(&buf[..n]) {
                    UdpProtocol::Dht => &dht_tx,
                    UdpProtocol::Utp => &utp_tx,
                };
                if dht_tx.is_closed() && utp_tx.is_closed() {
                    break;
                }
                if let Ok(permit) = target.try_reserve() {
                    permit.send((Bytes::copy_from_slice(&buf[..n]), from));
                }
            }
        });
        Ok(UdpMux {
            dht: UdpTransport::Shared(SharedUdp {
                real: real.clone(),
                rx: Mutex::new(dht_rx),
            }),
            utp: UdpTransport::Shared(SharedUdp {
                real,
                rx: Mutex::new(utp_rx),
            }),
            local_addr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn krpc_and_utp_datagrams_are_told_apart_by_their_first_byte() {
        assert_eq!(
            classify(b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q4:ping1:t2:aa1:y1:qe"),
            UdpProtocol::Dht
        );
        // uTP: (type << 4) | version 1 for ST_DATA, ST_FIN, ST_STATE, ST_RESET, ST_SYN.
        for first in [0x01u8, 0x11, 0x21, 0x31, 0x41] {
            assert_eq!(classify(&[first, 0, 0]), UdpProtocol::Utp);
        }
        assert_eq!(classify(&[]), UdpProtocol::Utp);
    }

    #[tokio::test]
    async fn both_protocols_receive_only_their_own_datagrams_on_one_port() {
        let mux = UdpMux::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = mux.local_addr;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"d1:y1:qe", addr).await.unwrap();
        client.send_to(&[0x41, 0, 0, 0], addr).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, from) = mux.dht.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"d1:y1:qe");
        assert_eq!(from, client.local_addr().unwrap());
        let (n, _) = mux.utp.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0x41, 0, 0, 0]);

        // Replies from either endpoint leave through the shared socket.
        mux.dht.send_to(b"reply", from).await.unwrap();
        let (n, src) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!((&buf[..n], src), (&b"reply"[..], addr));
    }

    #[tokio::test]
    async fn mux_stops_and_releases_socket_when_both_endpoints_drop() {
        let mux = UdpMux::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = mux.local_addr;
        drop(mux);

        let mut rebound = false;
        for _ in 0..50 {
            if UdpSocket::bind(addr).await.is_ok() {
                rebound = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            rebound,
            "mux demultiplexer task must exit and release socket when both endpoints drop"
        );
    }

    #[tokio::test]
    async fn recv_bytes_works_for_shared_mux_and_plain_transport() {
        let mux = UdpMux::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let plain_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let plain_addr = plain_sock.local_addr().unwrap();
        let plain = UdpTransport::Plain(plain_sock);

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"d1:y1:qe", mux.local_addr).await.unwrap();
        sender
            .send_to(&[0x41, 0x00, 0x01, 0x02], mux.local_addr)
            .await
            .unwrap();
        sender.send_to(b"plain-datagram", plain_addr).await.unwrap();

        let mut scratch = [0u8; 64];
        let (dht_bytes, from_dht) = mux.dht.recv_bytes(&mut scratch).await.unwrap();
        assert_eq!(&dht_bytes[..], b"d1:y1:qe");
        assert_eq!(from_dht, sender.local_addr().unwrap());

        let (utp_bytes, _) = mux.utp.recv_bytes(&mut scratch).await.unwrap();
        assert_eq!(&utp_bytes[..], &[0x41, 0x00, 0x01, 0x02]);

        let (plain_bytes, from_plain) = plain.recv_bytes(&mut scratch).await.unwrap();
        assert_eq!(&plain_bytes[..], b"plain-datagram");
        assert_eq!(from_plain, sender.local_addr().unwrap());
    }
}
