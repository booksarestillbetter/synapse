use num_bigint::BigUint;
use rand::RngCore;
use sha1::{Digest, Sha1};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    PlaintextOnly,
    PreferEncrypted,
    ForcedEncrypted,
}

impl EncryptionMode {
    pub fn from_str_opt(s: &str) -> Self {
        match s {
            "plaintext_only" | "disabled" => EncryptionMode::PlaintextOnly,
            "require_encrypted" | "forced" => EncryptionMode::ForcedEncrypted,
            _ => EncryptionMode::PreferEncrypted,
        }
    }
}

pub const PRIME_P_HEX: &str = "\
    FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
    29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
    EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
    E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF";

pub const CRYPTO_PLAINTEXT: u32 = 0x01;
pub const CRYPTO_RC4: u32 = 0x02;

#[derive(Debug, Clone)]
pub struct DhKeyPair {
    pub private_key: BigUint,
    pub public_key: [u8; 96],
}

impl DhKeyPair {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut priv_bytes = [0u8; 20];
        rng.fill_bytes(&mut priv_bytes);
        let private_key = BigUint::from_bytes_be(&priv_bytes);

        let p_bytes = hex::decode(PRIME_P_HEX).expect("valid hex for prime P");
        let p = BigUint::from_bytes_be(&p_bytes);
        let g = BigUint::from(2u32);

        let pub_big = g.modpow(&private_key, &p);
        let pub_raw = pub_big.to_bytes_be();
        let mut public_key = [0u8; 96];
        if pub_raw.len() <= 96 {
            public_key[96 - pub_raw.len()..].copy_from_slice(&pub_raw);
        } else {
            public_key.copy_from_slice(&pub_raw[pub_raw.len() - 96..]);
        }

        Self {
            private_key,
            public_key,
        }
    }

    pub fn compute_shared_secret(&self, remote_public: &[u8; 96]) -> [u8; 96] {
        let p_bytes = hex::decode(PRIME_P_HEX).expect("valid hex for prime P");
        let p = BigUint::from_bytes_be(&p_bytes);
        let remote_big = BigUint::from_bytes_be(remote_public);

        let secret_big = remote_big.modpow(&self.private_key, &p);
        let secret_raw = secret_big.to_bytes_be();
        let mut secret = [0u8; 96];
        if secret_raw.len() <= 96 {
            secret[96 - secret_raw.len()..].copy_from_slice(&secret_raw);
        } else {
            secret.copy_from_slice(&secret_raw[secret_raw.len() - 96..]);
        }
        secret
    }
}

pub fn sha1_hash(parts: &[&[u8]]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

pub fn mse_req1(s: &[u8; 96]) -> [u8; 20] {
    sha1_hash(&[b"req1", s])
}

pub fn mse_req2(skey: &[u8; 20]) -> [u8; 20] {
    sha1_hash(&[b"req2", skey])
}

pub fn mse_req3(s: &[u8; 96]) -> [u8; 20] {
    sha1_hash(&[b"req3", s])
}

pub fn mse_sync_hash(skey: &[u8; 20], s: &[u8; 96]) -> [u8; 20] {
    let r2 = mse_req2(skey);
    let r3 = mse_req3(s);
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = r2[i] ^ r3[i];
    }
    out
}

pub fn mse_derive_keys(s: &[u8; 96], skey: &[u8; 20]) -> ([u8; 20], [u8; 20]) {
    let key_a = sha1_hash(&[b"keyA", s, skey]);
    let key_b = sha1_hash(&[b"keyB", s, skey]);
    (key_a, key_b)
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

#[derive(Debug)]
pub struct EncryptedStream<S> {
    stream: S,
    encryptor: Option<Rc4Cipher>,
    decryptor: Option<Rc4Cipher>,
    read_buf: Vec<u8>,
    read_offset: usize,
    write_buf: Vec<u8>,
    write_offset: usize,
}

impl<S> EncryptedStream<S> {
    pub fn new_plain(stream: S) -> Self {
        Self {
            stream,
            encryptor: None,
            decryptor: None,
            read_buf: Vec::new(),
            read_offset: 0,
            write_buf: Vec::new(),
            write_offset: 0,
        }
    }

    pub fn new_plain_with_buffer(stream: S, initial_buf: Vec<u8>) -> Self {
        Self {
            stream,
            encryptor: None,
            decryptor: None,
            read_buf: initial_buf,
            read_offset: 0,
            write_buf: Vec::new(),
            write_offset: 0,
        }
    }

    pub fn new_encrypted(stream: S, enc_key: &[u8], dec_key: &[u8]) -> Self {
        Self {
            stream,
            encryptor: Some(Rc4Cipher::new(enc_key)),
            decryptor: Some(Rc4Cipher::new(dec_key)),
            read_buf: Vec::new(),
            read_offset: 0,
            write_buf: Vec::new(),
            write_offset: 0,
        }
    }

    pub fn from_ciphers_with_buffer(
        stream: S,
        encryptor: Option<Rc4Cipher>,
        decryptor: Option<Rc4Cipher>,
        initial_buf: Vec<u8>,
    ) -> Self {
        Self {
            stream,
            encryptor,
            decryptor,
            read_buf: initial_buf,
            read_offset: 0,
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
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_offset < this.read_buf.len() {
            let available = &this.read_buf[this.read_offset..];
            let to_copy = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_copy]);
            this.read_offset += to_copy;
            if this.read_offset >= this.read_buf.len() {
                this.read_buf.clear();
                this.read_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }

        let filled_before = buf.filled().len();
        let res = Pin::new(&mut this.stream).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let filled_after = buf.filled().len();
            if filled_after > filled_before {
                if let Some(dec) = &mut this.decryptor {
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

/// Initiator handshake for BitTorrent Message Stream Encryption (MSE).
pub async fn mse_handshake_initiator<S>(
    mut stream: S,
    info_hash: [u8; 20],
    mode: EncryptionMode,
    initial_payload: &[u8],
) -> Result<EncryptedStream<S>, io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if mode == EncryptionMode::PlaintextOnly {
        return Ok(EncryptedStream::new_plain(stream));
    }

    let dh = DhKeyPair::generate();
    // Step 1: Send Ya (96 bytes)
    stream.write_all(&dh.public_key).await?;
    stream.flush().await?;

    // Step 2: Read Yb (96 bytes)
    let mut their_pub = [0u8; 96];
    stream.read_exact(&mut their_pub).await?;

    // Compute S and keys
    let s = dh.compute_shared_secret(&their_pub);
    let (key_a, key_b) = mse_derive_keys(&s, &info_hash);

    let req1 = mse_req1(&s);
    let sync_hash = mse_sync_hash(&info_hash, &s);

    let mut enc_a = Rc4Cipher::new(&key_a);
    let mut dec_b = Rc4Cipher::new(&key_b);

    // crypto_provide: bit 0: Plaintext (0x01), bit 1: RC4 (0x02)
    let crypto_provide: u32 = match mode {
        EncryptionMode::ForcedEncrypted => CRYPTO_RC4,
        _ => CRYPTO_PLAINTEXT | CRYPTO_RC4,
    };

    // Encrypt: VC (8 zeros) + crypto_provide (4 bytes) + len(PadC) (2 bytes = 0) + len(IA) (2 bytes) + IA
    let mut encrypted_payload = Vec::new();
    encrypted_payload.extend_from_slice(&[0u8; 8]); // VC
    encrypted_payload.extend_from_slice(&crypto_provide.to_be_bytes());
    encrypted_payload.extend_from_slice(&0u16.to_be_bytes()); // PadC len = 0
    let ia_len = initial_payload.len() as u16;
    encrypted_payload.extend_from_slice(&ia_len.to_be_bytes());
    encrypted_payload.extend_from_slice(initial_payload);

    enc_a.apply_keystream(&mut encrypted_payload);

    // Send req1 + sync_hash + encrypted_payload
    stream.write_all(&req1).await?;
    stream.write_all(&sync_hash).await?;
    stream.write_all(&encrypted_payload).await?;
    stream.flush().await?;

    // Receive receiver response:
    // Decrypt VC (8 bytes) + crypto_select (4 bytes) + len(PadD) (2 bytes) + PadD
    let mut resp = [0u8; 14];
    stream.read_exact(&mut resp).await?;
    dec_b.apply_keystream(&mut resp);

    if resp[0..8] != [0u8; 8] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MSE handshake verification failed (VC mismatch)",
        ));
    }

    let crypto_select = u32::from_be_bytes([resp[8], resp[9], resp[10], resp[11]]);
    let pad_d_len = u16::from_be_bytes([resp[12], resp[13]]) as usize;
    if pad_d_len > 512 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MSE PadD too large",
        ));
    }
    if pad_d_len > 0 {
        let mut pad_d = vec![0u8; pad_d_len];
        stream.read_exact(&mut pad_d).await?;
        dec_b.apply_keystream(&mut pad_d);
    }

    match crypto_select {
        CRYPTO_RC4 => Ok(EncryptedStream::from_ciphers_with_buffer(
            stream,
            Some(enc_a),
            Some(dec_b),
            Vec::new(),
        )),
        CRYPTO_PLAINTEXT => {
            if mode == EncryptionMode::ForcedEncrypted {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "peer chose plaintext but forced encryption is required",
                ))
            } else {
                Ok(EncryptedStream::new_plain(stream))
            }
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported crypto_select: {other}"),
        )),
    }
}

#[derive(Debug)]
pub enum ReceiverHandshakeResult<S> {
    Encrypted {
        stream: EncryptedStream<S>,
        info_hash: [u8; 20],
        initial_payload: Vec<u8>,
    },
    Plaintext {
        stream: EncryptedStream<S>,
    },
}

/// Receiver handshake for BitTorrent Message Stream Encryption (MSE).
/// Distinguishes incoming plaintext BitTorrent handshakes from MSE key exchange.
pub async fn mse_handshake_receiver<S, F>(
    mut stream: S,
    mode: EncryptionMode,
    find_info_hash: F,
) -> Result<ReceiverHandshakeResult<S>, io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn(&[u8; 20]) -> Option<[u8; 20]>,
{
    // Read first 20 bytes to differentiate plaintext BitTorrent handshake from MSE Ya
    let mut initial_20 = [0u8; 20];
    stream.read_exact(&mut initial_20).await?;

    // Check if plaintext BitTorrent handshake: 0x13 + "BitTorrent protocol"
    if initial_20[0] == 19 && &initial_20[1..20] == b"BitTorrent protocol" {
        if mode == EncryptionMode::ForcedEncrypted {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "incoming plaintext connection rejected (encryption required)",
            ));
        }
        let stream = EncryptedStream::new_plain_with_buffer(stream, initial_20.to_vec());
        return Ok(ReceiverHandshakeResult::Plaintext { stream });
    }

    if mode == EncryptionMode::PlaintextOnly {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "incoming encrypted connection rejected (plaintext only configured)",
        ));
    }

    // Otherwise, read remaining 76 bytes of Ya (96 bytes total)
    let mut ya = [0u8; 96];
    ya[..20].copy_from_slice(&initial_20);
    stream.read_exact(&mut ya[20..]).await?;

    let dh = DhKeyPair::generate();
    let s = dh.compute_shared_secret(&ya);

    // Send Yb (96 bytes)
    stream.write_all(&dh.public_key).await?;
    stream.flush().await?;

    let req1 = mse_req1(&s);

    // Read until we find req1 (up to 512 bytes of PadA)
    let mut window = [0u8; 20];
    stream.read_exact(&mut window).await?;

    let mut pad_bytes_read = 0;
    while window != req1 {
        if pad_bytes_read > 512 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MSE sync pattern (req1) not found within 512 pad bytes",
            ));
        }
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).await?;
        window.rotate_left(1);
        window[19] = b[0];
        pad_bytes_read += 1;
    }

    // Read 20 bytes of sync_hash
    let mut sync_hash = [0u8; 20];
    stream.read_exact(&mut sync_hash).await?;

    // Find which info_hash matches: sync_hash ^ req3(S) == req2(info_hash)
    let req3 = mse_req3(&s);
    let mut target_req2 = [0u8; 20];
    for i in 0..20 {
        target_req2[i] = sync_hash[i] ^ req3[i];
    }

    let info_hash = find_info_hash(&target_req2).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no matching torrent info hash for MSE synchronization",
        )
    })?;

    let (key_a, key_b) = mse_derive_keys(&s, &info_hash);
    let mut dec_a = Rc4Cipher::new(&key_a);
    let mut enc_b = Rc4Cipher::new(&key_b);

    // Decrypt VC (8 bytes) + crypto_provide (4 bytes) + pad_c_len (2 bytes)
    let mut header = [0u8; 14];
    stream.read_exact(&mut header).await?;
    dec_a.apply_keystream(&mut header);

    if header[0..8] != [0u8; 8] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MSE receiver VC verification failed",
        ));
    }

    let crypto_provide = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
    let pad_c_len = u16::from_be_bytes([header[12], header[13]]) as usize;
    if pad_c_len > 512 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MSE PadC too large",
        ));
    }
    if pad_c_len > 0 {
        let mut pad_c = vec![0u8; pad_c_len];
        stream.read_exact(&mut pad_c).await?;
        dec_a.apply_keystream(&mut pad_c);
    }

    // Decrypt len(IA) (2 bytes)
    let mut ia_len_bytes = [0u8; 2];
    stream.read_exact(&mut ia_len_bytes).await?;
    dec_a.apply_keystream(&mut ia_len_bytes);
    let ia_len = u16::from_be_bytes(ia_len_bytes) as usize;

    let mut initial_payload = vec![0u8; ia_len];
    if ia_len > 0 {
        stream.read_exact(&mut initial_payload).await?;
        dec_a.apply_keystream(&mut initial_payload);
    }

    // Select crypto mode
    let crypto_select = if (crypto_provide & CRYPTO_RC4) != 0
        && mode != EncryptionMode::PlaintextOnly
    {
        CRYPTO_RC4
    } else if (crypto_provide & CRYPTO_PLAINTEXT) != 0 && mode != EncryptionMode::ForcedEncrypted {
        CRYPTO_PLAINTEXT
    } else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "incompatible crypto negotiation options",
        ));
    };

    // Send receiver response: encrypted VC (8 bytes) + crypto_select (4 bytes) + len(PadD) (0)
    let mut resp = Vec::new();
    resp.extend_from_slice(&[0u8; 8]);
    resp.extend_from_slice(&crypto_select.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    enc_b.apply_keystream(&mut resp);

    stream.write_all(&resp).await?;
    stream.flush().await?;

    let stream = if crypto_select == CRYPTO_RC4 {
        EncryptedStream::from_ciphers_with_buffer(
            stream,
            Some(enc_b),
            Some(dec_a),
            initial_payload.clone(),
        )
    } else {
        EncryptedStream::new_plain_with_buffer(stream, initial_payload.clone())
    };

    Ok(ReceiverHandshakeResult::Encrypted {
        stream,
        info_hash,
        initial_payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_dh_key_exchange_and_shared_secret() {
        let alice = DhKeyPair::generate();
        let bob = DhKeyPair::generate();

        let s_alice = alice.compute_shared_secret(&bob.public_key);
        let s_bob = bob.compute_shared_secret(&alice.public_key);

        assert_eq!(s_alice, s_bob);
    }

    #[tokio::test]
    async fn test_mse_handshake_initiator_and_receiver_duplex() {
        let (client_raw, server_raw) = tokio::io::duplex(1024);
        let info_hash = [0x55u8; 20];

        let server_task = tokio::spawn(async move {
            let target_req2 = mse_req2(&info_hash);
            let res = mse_handshake_receiver(server_raw, EncryptionMode::PreferEncrypted, |r2| {
                if *r2 == target_req2 {
                    Some(info_hash)
                } else {
                    None
                }
            })
            .await
            .unwrap();

            match res {
                ReceiverHandshakeResult::Encrypted {
                    mut stream,
                    info_hash: matched_ih,
                    initial_payload,
                } => {
                    assert_eq!(matched_ih, info_hash);
                    assert_eq!(initial_payload, b"initial_handshake_68_bytes");
                    assert!(stream.is_encrypted());

                    let mut read_initial = vec![0u8; initial_payload.len()];
                    stream.read_exact(&mut read_initial).await.unwrap();
                    assert_eq!(&read_initial[..], b"initial_handshake_68_bytes");

                    // Read subsequent message
                    let mut msg = [0u8; 12];
                    stream.read_exact(&mut msg).await.unwrap();
                    assert_eq!(&msg, b"ping_payload");

                    // Reply
                    stream.write_all(b"pong_payload").await.unwrap();
                    stream.flush().await.unwrap();
                }
                _ => panic!("Expected Encrypted receiver handshake result"),
            }
        });

        let client_task = tokio::spawn(async move {
            let mut stream = mse_handshake_initiator(
                client_raw,
                info_hash,
                EncryptionMode::PreferEncrypted,
                b"initial_handshake_68_bytes",
            )
            .await
            .unwrap();

            assert!(stream.is_encrypted());

            // Write subsequent message
            stream.write_all(b"ping_payload").await.unwrap();
            stream.flush().await.unwrap();

            // Read reply
            let mut reply = [0u8; 12];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"pong_payload");
        });

        client_task.await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_mse_plaintext_fallback_and_forced_encryption_enforcement() {
        // Case 1: Plaintext handshake to receiver with PreferEncrypted
        let (client_raw, server_raw) = tokio::io::duplex(1024);
        let client_task = tokio::spawn(async move {
            let mut client = client_raw;
            let mut bth = [0u8; 20];
            bth[0] = 19;
            bth[1..20].copy_from_slice(b"BitTorrent protocol");
            client.write_all(&bth).await.unwrap();
            client.flush().await.unwrap();
        });

        let server_res =
            mse_handshake_receiver(server_raw, EncryptionMode::PreferEncrypted, |_| None)
                .await
                .unwrap();
        assert!(matches!(
            server_res,
            ReceiverHandshakeResult::Plaintext { .. }
        ));
        client_task.await.unwrap();

        // Case 2: Plaintext handshake to receiver with ForcedEncrypted -> rejected
        let (client_raw, server_raw) = tokio::io::duplex(1024);
        let client_task = tokio::spawn(async move {
            let mut client = client_raw;
            let mut bth = [0u8; 20];
            bth[0] = 19;
            bth[1..20].copy_from_slice(b"BitTorrent protocol");
            client.write_all(&bth).await.unwrap();
            client.flush().await.unwrap();
        });

        let server_err =
            mse_handshake_receiver(server_raw, EncryptionMode::ForcedEncrypted, |_| None).await;
        assert!(server_err.is_err());
        client_task.await.unwrap();
    }
}
