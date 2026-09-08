use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    PlaintextOnly,
    PreferEncrypted,
    ForcedEncrypted,
}

#[derive(Debug, Clone)]
pub struct Rc4Cipher {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4Cipher {
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (idx, val) in s.iter_mut().enumerate() {
            *val = idx as u8;
        }

        let mut j: u8 = 0;
        let key_len = key.len();
        if key_len > 0 {
            for i in 0..256 {
                j = j.wrapping_add(s[i]).wrapping_add(key[i % key_len]);
                s.swap(i, j as usize);
            }
        }

        let mut cipher = Self { s, i: 0, j: 0 };
        cipher.discard(1024);
        cipher
    }

    pub fn discard(&mut self, count: usize) {
        let mut dummy = vec![0u8; count.min(1024)];
        let mut remaining = count;
        while remaining > 0 {
            let chunk = remaining.min(dummy.len());
            self.apply_keystream(&mut dummy[..chunk]);
            remaining -= chunk;
        }
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let idx = (self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize;
            let k = self.s[idx];
            *byte ^= k;
        }
    }
}

pub struct EncryptedStream<S> {
    stream: S,
    encryptor: Option<Rc4Cipher>,
    decryptor: Option<Rc4Cipher>,
    write_buf: Vec<u8>,
    write_offset: usize,
}

impl<S> EncryptedStream<S> {
    pub fn new_plain(stream: S) -> Self {
        Self {
            stream,
            encryptor: None,
            decryptor: None,
            write_buf: Vec::new(),
            write_offset: 0,
        }
    }

    pub fn new_encrypted(stream: S, enc_key: &[u8], dec_key: &[u8]) -> Self {
        Self {
            stream,
            encryptor: Some(Rc4Cipher::new(enc_key)),
            decryptor: Some(Rc4Cipher::new(dec_key)),
            write_buf: Vec::new(),
            write_offset: 0,
        }
    }

    pub fn is_encrypted(&self) -> bool {
        self.encryptor.is_some()
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled_before = buf.filled().len();
        let res = Pin::new(&mut self.stream).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let filled_after = buf.filled().len();
            if filled_after > filled_before {
                if let Some(dec) = &mut self.decryptor {
                    let new_bytes = &mut buf.filled_mut()[filled_before..filled_after];
                    dec.apply_keystream(new_bytes);
                }
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Self {
            stream,
            encryptor,
            write_buf,
            write_offset,
            ..
        } = self.get_mut();

        // First flush any pending write buffer from earlier partial writes
        while *write_offset < write_buf.len() {
            let pending = &write_buf[*write_offset..];
            match Pin::new(&mut *stream).poll_write(cx, pending) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write buffered encrypted data to stream",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    *write_offset += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        write_buf.clear();
        *write_offset = 0;

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if let Some(enc) = encryptor {
            let mut encrypted = buf.to_vec();
            enc.apply_keystream(&mut encrypted);

            // Attempt immediate write to underlying stream
            match Pin::new(&mut *stream).poll_write(cx, &encrypted) {
                Poll::Ready(Ok(n)) => {
                    if n < encrypted.len() {
                        *write_buf = encrypted;
                        *write_offset = n;
                    }
                    Poll::Ready(Ok(buf.len()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => {
                    *write_buf = encrypted;
                    *write_offset = 0;
                    Poll::Ready(Ok(buf.len()))
                }
            }
        } else {
            Pin::new(&mut *stream).poll_write(cx, buf)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Self {
            stream,
            write_buf,
            write_offset,
            ..
        } = self.get_mut();

        while *write_offset < write_buf.len() {
            let pending = &write_buf[*write_offset..];
            match Pin::new(&mut *stream).poll_write(cx, pending) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to flush encrypted buffer to stream",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    *write_offset += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        write_buf.clear();
        *write_offset = 0;
        Pin::new(stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.as_mut().poll_flush(cx);
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_rc4_roundtrip() {
        let key = b"secret_peer_encryption_key_12345";
        let mut enc = Rc4Cipher::new(key);
        let mut dec = Rc4Cipher::new(key);

        let original = b"Hello, BitTorrent Protocol Encryption (BEP 8)".to_vec();
        let mut encrypted = original.clone();

        enc.apply_keystream(&mut encrypted);
        assert_ne!(original, encrypted);

        let mut decrypted = encrypted.clone();
        dec.apply_keystream(&mut decrypted);
        assert_eq!(original, decrypted);
    }

    #[tokio::test]
    async fn test_encrypted_stream_async_duplex() {
        let (client_raw, server_raw) = tokio::io::duplex(64);
        let enc_key = b"client_to_server_encryption_key";
        let dec_key = b"server_to_client_encryption_key";

        let mut client = EncryptedStream::new_encrypted(client_raw, enc_key, dec_key);
        let mut server = EncryptedStream::new_encrypted(server_raw, dec_key, enc_key);

        let message = b"High-scale Synapse 2.0 streaming encryption test payload!";
        client.write_all(message).await.unwrap();
        client.flush().await.unwrap();

        let mut received = vec![0u8; message.len()];
        server.read_exact(&mut received).await.unwrap();

        assert_eq!(&received[..], message);
    }
}
