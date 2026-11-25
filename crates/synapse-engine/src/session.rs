//! Atomic Session State Persistence (WAL / State storage) for Synapse 2.0.
//!
//! Stores active torrent state (info hash, metadata, resume bitfields, download directory,
//! and statistics) so swarms can resume instantly across daemon restarts without re-checking
//! or re-downloading existing verified pieces.

use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use synapse_picker::Bitfield;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TorrentSessionState {
    pub info_hash_hex: String,
    pub name: String,
    pub download_dir: String,
    pub bitfield_hex: String,
    pub total_pieces: usize,
    pub total_size: u64,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub added_at: i64,
    pub is_paused: bool,
    #[serde(default)]
    pub ratio: Option<f32>,
    #[serde(default)]
    pub magnet_uri: Option<String>,
    #[serde(default)]
    pub raw_bencode_hex: Option<String>,
    /// Per-file priorities (0 = skip). Empty means "all default", which is also what sessions
    /// written before priorities were persisted deserialize to.
    #[serde(default)]
    pub file_priorities: Vec<u8>,
    /// Sequential (in-order) piece picking, set per torrent.
    #[serde(default)]
    pub sequential: bool,
    /// Replacement tracker list set through the API. `None` means "use the torrent's own".
    #[serde(default)]
    pub tracker_override: Option<Vec<String>>,
    /// Optional user-assigned category (e.g. "tv", "movies", "linux").
    #[serde(default)]
    pub category: Option<String>,
    /// Optional user-assigned tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Per-torrent ratio limit; when reached while seeding, auto-stops the torrent.
    #[serde(default)]
    pub seed_ratio_limit: Option<f64>,
    /// Per-torrent idle/seed time limit in seconds; when reached while seeding, auto-stops.
    #[serde(default)]
    pub seed_time_limit_secs: Option<u64>,
    /// Whether super-seeding mode is enabled for this torrent.
    #[serde(default)]
    pub super_seeding: bool,
    /// Whether first and last piece priority is enabled for this torrent.
    #[serde(default)]
    pub first_last_piece_priority: bool,
    /// Persistent position in the download queue.
    #[serde(default)]
    pub queue_position: Option<u32>,
    /// Per-torrent download rate limit in bytes/sec (0 = unlimited), set through the API.
    #[serde(default)]
    pub download_limit_bytes: u64,
    /// Per-torrent upload rate limit in bytes/sec (0 = unlimited), set through the API.
    #[serde(default)]
    pub upload_limit_bytes: u64,
}

impl TorrentSessionState {
    pub fn info_hash(&self) -> Option<[u8; 20]> {
        let bytes = hex::decode(&self.info_hash_hex).ok()?;
        if bytes.len() == 20 {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            Some(arr)
        } else {
            None
        }
    }

    pub fn to_bitfield(&self) -> Option<Bitfield> {
        let bytes = hex::decode(&self.bitfield_hex).ok()?;
        Bitfield::from_bytes(&bytes, self.total_pieces)
    }

    pub fn effective_ratio(&self) -> f32 {
        if let Some(r) = self.ratio {
            r
        } else if self.downloaded_bytes > 0 {
            self.uploaded_bytes as f32 / self.downloaded_bytes as f32
        } else if self.total_size > 0 && self.uploaded_bytes > 0 {
            self.uploaded_bytes as f32 / self.total_size as f32
        } else {
            0.0
        }
    }
}

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use redb::{Database, ReadableTable, TableDefinition};
use std::sync::Arc;

const TORRENTS_TABLE: TableDefinition<&[u8; 20], &[u8]> = TableDefinition::new("session_torrents");
const TORRENT_METADATA_TABLE: TableDefinition<&[u8; 20], &[u8]> =
    TableDefinition::new("torrent_metadata");
const TORRENT_STATE_TABLE: TableDefinition<&[u8; 20], &[u8]> =
    TableDefinition::new("torrent_state");
const AEAD_VERSION_AAD: u8 = 0x02;
const COMPACT_STATE_MAGIC: &[u8; 4] = b"SYN1";

fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn write_opt_str(buf: &mut Vec<u8>, opt: Option<&str>) {
    match opt {
        Some(s) => {
            buf.push(1);
            write_bytes(buf, s.as_bytes());
        }
        None => buf.push(0),
    }
}

fn invalid_state(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

fn read_slice<'a>(data: &'a [u8], pos: &mut usize, n: usize) -> std::io::Result<&'a [u8]> {
    let end = pos
        .checked_add(n)
        .filter(|&e| e <= data.len())
        .ok_or_else(|| invalid_state("truncated compact session state"))?;
    let out = &data[*pos..end];
    *pos = end;
    Ok(out)
}

fn read_u8(data: &[u8], pos: &mut usize) -> std::io::Result<u8> {
    Ok(read_slice(data, pos, 1)?[0])
}

fn read_u32(data: &[u8], pos: &mut usize) -> std::io::Result<u32> {
    let s = read_slice(data, pos, 4)?;
    Ok(u32::from_le_bytes(s.try_into().unwrap()))
}

fn read_u64(data: &[u8], pos: &mut usize) -> std::io::Result<u64> {
    let s = read_slice(data, pos, 8)?;
    Ok(u64::from_le_bytes(s.try_into().unwrap()))
}

fn read_i64(data: &[u8], pos: &mut usize) -> std::io::Result<i64> {
    let s = read_slice(data, pos, 8)?;
    Ok(i64::from_le_bytes(s.try_into().unwrap()))
}

fn read_bytes(data: &[u8], pos: &mut usize) -> std::io::Result<Vec<u8>> {
    let len = read_u32(data, pos)? as usize;
    Ok(read_slice(data, pos, len)?.to_vec())
}

fn read_str(data: &[u8], pos: &mut usize) -> std::io::Result<String> {
    let bytes = read_bytes(data, pos)?;
    String::from_utf8(bytes).map_err(|_| invalid_state("non-UTF-8 string in compact session state"))
}

fn read_opt_str(data: &[u8], pos: &mut usize) -> std::io::Result<Option<String>> {
    match read_u8(data, pos)? {
        0 => Ok(None),
        1 => Ok(Some(read_str(data, pos)?)),
        _ => Err(invalid_state("invalid option tag in compact session state")),
    }
}

fn encode_compact_state(hash: &[u8; 20], state: &TorrentSessionState) -> Vec<u8> {
    let bf_bytes = hex::decode(&state.bitfield_hex).unwrap_or_default();
    let mut out = Vec::with_capacity(
        64 + state.name.len()
            + state.download_dir.len()
            + bf_bytes.len()
            + state.file_priorities.len(),
    );
    out.extend_from_slice(COMPACT_STATE_MAGIC);
    out.extend_from_slice(hash);
    write_bytes(&mut out, state.name.as_bytes());
    write_bytes(&mut out, state.download_dir.as_bytes());
    write_bytes(&mut out, &bf_bytes);
    out.extend_from_slice(&(state.total_pieces as u64).to_le_bytes());
    out.extend_from_slice(&state.total_size.to_le_bytes());
    out.extend_from_slice(&state.uploaded_bytes.to_le_bytes());
    out.extend_from_slice(&state.downloaded_bytes.to_le_bytes());
    out.extend_from_slice(&state.added_at.to_le_bytes());
    out.push(u8::from(state.is_paused));
    match state.ratio {
        Some(r) => {
            out.push(1);
            out.extend_from_slice(&r.to_le_bytes());
        }
        None => out.push(0),
    }
    write_opt_str(&mut out, state.magnet_uri.as_deref());
    write_bytes(&mut out, &state.file_priorities);
    out.push(u8::from(state.sequential));
    match &state.tracker_override {
        Some(list) => {
            out.push(1);
            out.extend_from_slice(&(list.len() as u32).to_le_bytes());
            for item in list {
                write_bytes(&mut out, item.as_bytes());
            }
        }
        None => out.push(0),
    }
    write_opt_str(&mut out, state.category.as_deref());
    out.extend_from_slice(&(state.tags.len() as u32).to_le_bytes());
    for tag in &state.tags {
        write_bytes(&mut out, tag.as_bytes());
    }
    match state.seed_ratio_limit {
        Some(v) => {
            out.push(1);
            out.extend_from_slice(&v.to_le_bytes());
        }
        None => out.push(0),
    }
    match state.seed_time_limit_secs {
        Some(v) => {
            out.push(1);
            out.extend_from_slice(&v.to_le_bytes());
        }
        None => out.push(0),
    }
    out.push(u8::from(state.super_seeding));
    out.push(u8::from(state.first_last_piece_priority));
    match state.queue_position {
        Some(pos) => {
            out.push(1);
            out.extend_from_slice(&pos.to_le_bytes());
        }
        None => out.push(0),
    }
    out.extend_from_slice(&state.download_limit_bytes.to_le_bytes());
    out.extend_from_slice(&state.upload_limit_bytes.to_le_bytes());
    out
}

fn decode_compact_state(data: &[u8]) -> std::io::Result<TorrentSessionState> {
    let mut pos = 0usize;
    let magic = read_slice(data, &mut pos, 4)?;
    if magic != COMPACT_STATE_MAGIC {
        return Err(invalid_state("unexpected compact session state magic"));
    }
    let hash_slice = read_slice(data, &mut pos, 20)?;
    let info_hash_hex = hex::encode(hash_slice);
    let name = read_str(data, &mut pos)?;
    let download_dir = read_str(data, &mut pos)?;
    let bf_bytes = read_bytes(data, &mut pos)?;
    let bitfield_hex = if bf_bytes.is_empty() {
        String::new()
    } else {
        hex::encode(&bf_bytes)
    };
    let total_pieces = read_u64(data, &mut pos)? as usize;
    let total_size = read_u64(data, &mut pos)?;
    let uploaded_bytes = read_u64(data, &mut pos)?;
    let downloaded_bytes = read_u64(data, &mut pos)?;
    let added_at = read_i64(data, &mut pos)?;
    let is_paused = read_u8(data, &mut pos)? != 0;
    let ratio = match read_u8(data, &mut pos)? {
        0 => None,
        1 => Some(f32::from_le_bytes(
            read_slice(data, &mut pos, 4)?.try_into().unwrap(),
        )),
        _ => return Err(invalid_state("invalid ratio tag")),
    };
    let magnet_uri = read_opt_str(data, &mut pos)?;
    let file_priorities = read_bytes(data, &mut pos)?;
    let sequential = read_u8(data, &mut pos)? != 0;
    let tracker_override = match read_u8(data, &mut pos)? {
        0 => None,
        1 => {
            let count = read_u32(data, &mut pos)? as usize;
            let mut items = Vec::with_capacity(count.min(256));
            for _ in 0..count {
                items.push(read_str(data, &mut pos)?);
            }
            Some(items)
        }
        _ => return Err(invalid_state("invalid tracker_override tag")),
    };
    let category = read_opt_str(data, &mut pos)?;
    let tag_count = read_u32(data, &mut pos)? as usize;
    let mut tags = Vec::with_capacity(tag_count.min(256));
    for _ in 0..tag_count {
        tags.push(read_str(data, &mut pos)?);
    }
    let seed_ratio_limit = match read_u8(data, &mut pos)? {
        0 => None,
        1 => Some(f64::from_le_bytes(
            read_slice(data, &mut pos, 8)?.try_into().unwrap(),
        )),
        _ => return Err(invalid_state("invalid seed_ratio_limit tag")),
    };
    let seed_time_limit_secs = match read_u8(data, &mut pos)? {
        0 => None,
        1 => Some(read_u64(data, &mut pos)?),
        _ => return Err(invalid_state("invalid seed_time_limit_secs tag")),
    };
    let super_seeding = read_u8(data, &mut pos)? != 0;
    let first_last_piece_priority = read_u8(data, &mut pos)? != 0;
    let queue_position = match read_u8(data, &mut pos)? {
        0 => None,
        1 => Some(read_u32(data, &mut pos)?),
        _ => return Err(invalid_state("invalid queue_position tag")),
    };
    let download_limit_bytes = read_u64(data, &mut pos)?;
    let upload_limit_bytes = read_u64(data, &mut pos)?;

    Ok(TorrentSessionState {
        info_hash_hex,
        name,
        download_dir,
        bitfield_hex,
        total_pieces,
        total_size,
        uploaded_bytes,
        downloaded_bytes,
        added_at,
        is_paused,
        ratio,
        magnet_uri,
        raw_bencode_hex: None,
        file_priorities,
        sequential,
        tracker_override,
        category,
        tags,
        seed_ratio_limit,
        seed_time_limit_secs,
        super_seeding,
        first_last_piece_priority,
        queue_position,
        download_limit_bytes,
        upload_limit_bytes,
    })
}

fn to_io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

fn encrypt_for(
    cipher: &ChaCha20Poly1305,
    info_hash: &[u8; 20],
    plaintext: &[u8],
) -> std::io::Result<Vec<u8>> {
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: info_hash.as_slice(),
            },
        )
        .map_err(|e| std::io::Error::other(format!("AEAD encrypt error: {e}")))?;
    let mut payload = Vec::with_capacity(1 + 12 + ciphertext.len());
    payload.push(AEAD_VERSION_AAD);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    Ok(payload)
}

fn decrypt_for(
    cipher: &ChaCha20Poly1305,
    info_hash: &[u8; 20],
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    // A legacy (pre-versioning) payload is just a random 96-bit nonce followed by
    // ciphertext, with no marker byte, so its first byte collides with
    // `AEAD_VERSION_AAD` about 1-in-256 times. Treat the marker as a hint, not a
    // determination: if the v2 (AAD-bound) interpretation fails to decrypt, fall back
    // to the legacy framing before giving up, rather than misreporting a legacy record
    // as corrupt.
    if payload.first() == Some(&AEAD_VERSION_AAD) && payload.len() >= 13 {
        let (nonce_bytes, ciphertext) = payload[1..].split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        if let Ok(plaintext) = cipher.decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: info_hash.as_slice(),
            },
        ) {
            return Ok(plaintext);
        }
    }

    // Legacy unversioned format (no AAD).
    if payload.len() < 12 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted payload too short for AEAD nonce",
        ));
    }
    let (nonce_bytes, ciphertext) = payload.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("AEAD decrypt failed: {e}"),
        )
    })
}

#[derive(Clone)]
pub struct SessionStore {
    db: Arc<Database>,
    cipher: Arc<ChaCha20Poly1305>,
    session_dir: PathBuf,
}

impl SessionStore {
    pub fn new(session_dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let session_dir = session_dir.as_ref().to_path_buf();
        fs::create_dir_all(&session_dir)?;

        let key = if let Ok(env_key) = std::env::var("SYNAPSE_SESSION_KEY") {
            let bytes = hex::decode(env_key.trim()).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid SYNAPSE_SESSION_KEY hex: {e}"),
                )
            })?;
            if bytes.len() != 32 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "SYNAPSE_SESSION_KEY must be 32 bytes (64 hex characters)",
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        } else {
            let key_path = session_dir.join("session.key");
            match fs::symlink_metadata(&key_path) {
                Ok(meta) => {
                    if !meta.file_type().is_file() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "session.key must be a regular file, not a symlink",
                        ));
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
                    }
                    let mut f = File::open(&key_path)?;
                    let mut buf = [0u8; 32];
                    f.read_exact(&mut buf)?;
                    buf
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let generated = ChaCha20Poly1305::generate_key(&mut OsRng);
                    let key_bytes: [u8; 32] = generated.into();
                    #[cfg(unix)]
                    let mut f = {
                        use std::os::unix::fs::OpenOptionsExt;
                        fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .custom_flags(libc::O_NOFOLLOW)
                            .open(&key_path)?
                    };
                    #[cfg(not(unix))]
                    let mut f = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&key_path)?;
                    f.write_all(&key_bytes)?;
                    f.sync_all()?;
                    key_bytes
                }
                Err(e) => return Err(e),
            }
        };

        Self::with_key(session_dir, key)
    }

    pub fn with_key(session_dir: impl AsRef<Path>, key_bytes: [u8; 32]) -> std::io::Result<Self> {
        let session_dir = session_dir.as_ref().to_path_buf();
        fs::create_dir_all(&session_dir)?;

        let db_path = session_dir.join("session.db");
        let db = Database::create(&db_path).map_err(to_io_err)?;

        // Ensure tables exist
        let write_tx = db.begin_write().map_err(to_io_err)?;
        {
            let _ = write_tx.open_table(TORRENTS_TABLE).map_err(to_io_err)?;
            let _ = write_tx
                .open_table(TORRENT_METADATA_TABLE)
                .map_err(to_io_err)?;
            let _ = write_tx
                .open_table(TORRENT_STATE_TABLE)
                .map_err(to_io_err)?;
        }
        write_tx.commit().map_err(to_io_err)?;

        let key = Key::from_slice(&key_bytes);
        let cipher = Arc::new(ChaCha20Poly1305::new(key));
        let store = Self {
            db: Arc::new(db),
            cipher,
            session_dir: session_dir.clone(),
        };

        // Automatically migrate any legacy flat .json files from previous versions
        store.migrate_legacy_json_if_needed(&session_dir);

        Ok(store)
    }

    pub fn session_dir(&self) -> &Path {
        &self.session_dir
    }

    /// Atomically persists encrypted torrent session state to the embedded database.
    pub fn save_torrent(&self, state: &TorrentSessionState) -> std::io::Result<()> {
        self.save_torrents_batch(std::slice::from_ref(state))
    }

    /// Persists immutable raw `.torrent` metadata bytes once under `torrent_metadata`.
    pub fn save_metadata(&self, info_hash: &[u8; 20], raw_bencode: &[u8]) -> std::io::Result<()> {
        let write_tx = self.db.begin_write().map_err(to_io_err)?;
        {
            let mut table = write_tx
                .open_table(TORRENT_METADATA_TABLE)
                .map_err(to_io_err)?;
            let encrypted = encrypt_for(&self.cipher, info_hash, raw_bencode)?;
            table
                .insert(info_hash, encrypted.as_slice())
                .map_err(to_io_err)?;
        }
        write_tx.commit().map_err(to_io_err)?;
        Ok(())
    }

    /// Loads immutable raw `.torrent` metadata bytes from `torrent_metadata` (or legacy table).
    pub fn load_metadata(&self, info_hash: &[u8; 20]) -> std::io::Result<Option<Vec<u8>>> {
        let read_tx = self.db.begin_read().map_err(to_io_err)?;
        if let Ok(meta_table) = read_tx.open_table(TORRENT_METADATA_TABLE) {
            if let Some(guard) = meta_table.get(info_hash).map_err(to_io_err)? {
                return decrypt_for(&self.cipher, info_hash, guard.value()).map(Some);
            }
        }
        if let Ok(legacy_table) = read_tx.open_table(TORRENTS_TABLE) {
            if let Some(guard) = legacy_table.get(info_hash).map_err(to_io_err)? {
                let decrypted = decrypt_for(&self.cipher, info_hash, guard.value())?;
                if let Ok(state) = serde_json::from_slice::<TorrentSessionState>(&decrypted) {
                    if let Some(ref hex_str) = state.raw_bencode_hex {
                        if let Ok(raw) = hex::decode(hex_str) {
                            return Ok(Some(raw));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    /// Atomically persists ONLY mutable compact binary state for dirty torrents into
    /// `torrent_state` in a single transaction, without touching immutable metadata.
    pub fn save_states_batch(&self, states: &[TorrentSessionState]) -> std::io::Result<()> {
        if states.is_empty() {
            return Ok(());
        }
        let write_tx = self.db.begin_write().map_err(to_io_err)?;
        {
            let mut state_table = write_tx
                .open_table(TORRENT_STATE_TABLE)
                .map_err(to_io_err)?;
            for state in states {
                let hash = state.info_hash().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid info_hash_hex in session state",
                    )
                })?;
                let compact = encode_compact_state(&hash, state);
                let encrypted = encrypt_for(&self.cipher, &hash, &compact)?;
                state_table
                    .insert(&hash, encrypted.as_slice())
                    .map_err(to_io_err)?;
            }
        }
        write_tx.commit().map_err(to_io_err)?;
        debug!(
            "Persisted batch of {} compact encrypted session states",
            states.len()
        );
        Ok(())
    }

    /// Atomically persists a batch of encrypted torrent session states in a single `redb`
    /// write transaction (one fsync instead of N), storing immutable metadata separately in
    /// `torrent_metadata` only when `raw_bencode_hex` is supplied.
    pub fn save_torrents_batch(&self, states: &[TorrentSessionState]) -> std::io::Result<()> {
        if states.is_empty() {
            return Ok(());
        }
        let write_tx = self.db.begin_write().map_err(to_io_err)?;
        {
            let mut state_table = write_tx
                .open_table(TORRENT_STATE_TABLE)
                .map_err(to_io_err)?;
            let mut meta_table = write_tx
                .open_table(TORRENT_METADATA_TABLE)
                .map_err(to_io_err)?;
            for state in states {
                let hash = state.info_hash().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid info_hash_hex in session state",
                    )
                })?;
                let compact = encode_compact_state(&hash, state);
                let encrypted_state = encrypt_for(&self.cipher, &hash, &compact)?;
                state_table
                    .insert(&hash, encrypted_state.as_slice())
                    .map_err(to_io_err)?;

                if let Some(ref hex_str) = state.raw_bencode_hex {
                    if let Ok(raw_bencode) = hex::decode(hex_str) {
                        let encrypted_meta = encrypt_for(&self.cipher, &hash, &raw_bencode)?;
                        meta_table
                            .insert(&hash, encrypted_meta.as_slice())
                            .map_err(to_io_err)?;
                    }
                }
            }
        }
        write_tx.commit().map_err(to_io_err)?;
        debug!(
            "Persisted batch of {} encrypted session states",
            states.len()
        );
        Ok(())
    }

    /// Loads a single persisted torrent session state by info hash hex.
    pub fn load_torrent(
        &self,
        info_hash_hex: &str,
    ) -> std::io::Result<Option<TorrentSessionState>> {
        let bytes = hex::decode(info_hash_hex)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        if bytes.len() != 20 {
            return Ok(None);
        }
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&bytes);

        let read_tx = self.db.begin_read().map_err(to_io_err)?;
        if let Ok(state_table) = read_tx.open_table(TORRENT_STATE_TABLE) {
            if let Some(v) = state_table.get(&hash).map_err(to_io_err)? {
                let decrypted = decrypt_for(&self.cipher, &hash, v.value())?;
                let mut state = decode_compact_state(&decrypted)?;
                if let Ok(meta_table) = read_tx.open_table(TORRENT_METADATA_TABLE) {
                    if let Some(mv) = meta_table.get(&hash).map_err(to_io_err)? {
                        let raw = decrypt_for(&self.cipher, &hash, mv.value())?;
                        state.raw_bencode_hex = Some(hex::encode(&raw));
                    }
                }
                return Ok(Some(state));
            }
        }

        let table = match read_tx.open_table(TORRENTS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(to_io_err(e)),
        };
        let value = match table.get(&hash).map_err(to_io_err)? {
            Some(v) => v,
            None => return Ok(None),
        };
        let decrypted = decrypt_for(&self.cipher, &hash, value.value())?;
        let state = serde_json::from_slice(&decrypted)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Some(state))
    }

    /// Loads all persisted torrent session states paired with raw metadata bytes (without hex
    /// inflation) in a single read transaction across split and legacy tables.
    pub fn load_all_entries(&self) -> std::io::Result<Vec<(TorrentSessionState, Option<Vec<u8>>)>> {
        let read_tx = self.db.begin_read().map_err(to_io_err)?;
        let mut metadata_map: std::collections::HashMap<[u8; 20], Vec<u8>> =
            std::collections::HashMap::new();
        match read_tx.open_table(TORRENT_METADATA_TABLE) {
            Ok(meta_table) => {
                for item in meta_table.iter().map_err(to_io_err)? {
                    let (key, value) = item.map_err(to_io_err)?;
                    match decrypt_for(&self.cipher, key.value(), value.value()) {
                        Ok(raw) => {
                            metadata_map.insert(*key.value(), raw);
                        }
                        Err(e) => warn!("Failed to decrypt session metadata record: {e}"),
                    }
                }
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {}
            Err(e) => return Err(to_io_err(e)),
        }

        let mut entries = Vec::new();
        let mut seen = std::collections::HashSet::new();

        match read_tx.open_table(TORRENT_STATE_TABLE) {
            Ok(state_table) => {
                for item in state_table.iter().map_err(to_io_err)? {
                    let (key, value) = item.map_err(to_io_err)?;
                    let hash = *key.value();
                    match decrypt_for(&self.cipher, &hash, value.value()) {
                        Ok(decrypted) => match decode_compact_state(&decrypted) {
                            Ok(state) => {
                                seen.insert(hash);
                                let raw = metadata_map.remove(&hash);
                                entries.push((state, raw));
                            }
                            Err(e) => warn!("Failed to decode compact session state: {e}"),
                        },
                        Err(e) => warn!("Failed to decrypt session state record: {e}"),
                    }
                }
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {}
            Err(e) => return Err(to_io_err(e)),
        }

        match read_tx.open_table(TORRENTS_TABLE) {
            Ok(legacy_table) => {
                for item in legacy_table.iter().map_err(to_io_err)? {
                    let (key, value) = item.map_err(to_io_err)?;
                    let hash = *key.value();
                    if seen.contains(&hash) {
                        continue;
                    }
                    match decrypt_for(&self.cipher, &hash, value.value()) {
                        Ok(decrypted) => {
                            match serde_json::from_slice::<TorrentSessionState>(&decrypted) {
                                Ok(mut state) => {
                                    let raw = state
                                        .raw_bencode_hex
                                        .take()
                                        .and_then(|h| hex::decode(&h).ok());
                                    entries.push((state, raw));
                                }
                                Err(e) => {
                                    warn!("Failed to deserialize legacy encrypted session payload: {e}")
                                }
                            }
                        }
                        Err(e) => warn!("Failed to decrypt legacy session record: {e}"),
                    }
                }
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {}
            Err(e) => return Err(to_io_err(e)),
        }

        info!(
            "Loaded {} encrypted torrent session states from database",
            entries.len()
        );
        Ok(entries)
    }

    /// Loads all persisted torrent session state files from disk via single sequential database scan.
    pub fn load_all(&self) -> std::io::Result<Vec<TorrentSessionState>> {
        let entries = self.load_all_entries()?;
        Ok(entries
            .into_iter()
            .map(|(mut state, raw)| {
                state.raw_bencode_hex = raw.as_deref().map(hex::encode);
                state
            })
            .collect())
    }

    /// Removes the persisted session state for a torrent from the database.
    pub fn remove_torrent(&self, info_hash: &[u8; 20]) -> std::io::Result<()> {
        let write_tx = self.db.begin_write().map_err(to_io_err)?;
        {
            if let Ok(mut table) = write_tx.open_table(TORRENTS_TABLE) {
                let _ = table.remove(info_hash);
            }
            if let Ok(mut table) = write_tx.open_table(TORRENT_METADATA_TABLE) {
                let _ = table.remove(info_hash);
            }
            if let Ok(mut table) = write_tx.open_table(TORRENT_STATE_TABLE) {
                let _ = table.remove(info_hash);
            }
        }
        write_tx.commit().map_err(to_io_err)?;
        debug!("Removed session state for {}", hex::encode(info_hash));
        Ok(())
    }

    /// Verifies that the underlying redb database accepts read transactions.
    pub fn is_healthy(&self) -> bool {
        self.db.begin_read().is_ok()
    }

    fn migrate_legacy_json_if_needed(&self, session_dir: &Path) {
        let torrents_dir = session_dir.join("torrents");
        if !torrents_dir.exists() || !torrents_dir.is_dir() {
            return;
        }

        let Ok(entries) = fs::read_dir(&torrents_dir) else {
            return;
        };

        let mut migrated_count = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(mut file) = File::open(&path) {
                    let mut contents = String::new();
                    if file.read_to_string(&mut contents).is_ok() {
                        if let Ok(state) = serde_json::from_str::<TorrentSessionState>(&contents) {
                            if self.save_torrent(&state).is_ok() {
                                migrated_count += 1;
                            }
                        }
                    }
                }
            }
        }

        if migrated_count > 0 {
            info!(
                "Migrated {} legacy .json session files to encrypted session.db",
                migrated_count
            );
            let migrated_dir = session_dir.join("torrents.migrated");
            if fs::rename(&torrents_dir, &migrated_dir).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&migrated_dir, fs::Permissions::from_mode(0o700));
                    if let Ok(entries) = fs::read_dir(&migrated_dir) {
                        for entry in entries.flatten() {
                            let _ = fs::set_permissions(
                                entry.path(),
                                fs::Permissions::from_mode(0o600),
                            );
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_aead_binds_info_hash_and_reads_legacy_records() {
        let key = Key::from_slice(&[0x42u8; 32]);
        let cipher = ChaCha20Poly1305::new(key);
        let hash_a = [0x11u8; 20];
        let hash_b = [0x22u8; 20];

        let ct = encrypt_for(&cipher, &hash_a, b"secret-state").unwrap();
        assert_eq!(ct[0], AEAD_VERSION_AAD);
        assert_eq!(decrypt_for(&cipher, &hash_a, &ct).unwrap(), b"secret-state");
        assert!(
            decrypt_for(&cipher, &hash_b, &ct).is_err(),
            "ciphertext swapped under a different info_hash must fail AEAD authentication"
        );

        // Legacy unversioned payload (without version prefix byte) still decrypts for backwards compatibility.
        let nonce = Nonce::from_slice(&[0x07u8; 12]);
        let legacy_ct = cipher.encrypt(nonce, b"legacy-state".as_ref()).unwrap();
        let mut legacy_payload = Vec::with_capacity(12 + legacy_ct.len());
        legacy_payload.extend_from_slice(&[0x07u8; 12]);
        legacy_payload.extend_from_slice(&legacy_ct);
        assert_eq!(
            decrypt_for(&cipher, &hash_b, &legacy_payload).unwrap(),
            b"legacy-state"
        );
    }

    #[test]
    fn compact_binary_roundtrip_and_split_metadata_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::with_key(dir.path(), [0x55u8; 32]).unwrap();
        let hash = [0x99u8; 20];
        let raw_bencode = b"d4:infod4:name4:test6:lengthi4096e12:piece lengthi4096e6:pieces20:aaaaaaaaaaaaaaaaaaaaee";

        store.save_metadata(&hash, raw_bencode).unwrap();

        let state = TorrentSessionState {
            info_hash_hex: hex::encode(hash),
            name: "SplitTest".into(),
            download_dir: "/tmp/downloads".into(),
            bitfield_hex: "f0a0".into(),
            total_pieces: 12,
            total_size: 4096,
            uploaded_bytes: 12345,
            downloaded_bytes: 2048,
            added_at: 1_700_000_123,
            is_paused: true,
            ratio: Some(6.02),
            magnet_uri: Some("magnet:?xt=urn:btih:9999".into()),
            raw_bencode_hex: None,
            file_priorities: vec![0, 4, 7],
            sequential: true,
            tracker_override: Some(vec!["http://127.0.0.1:6969/announce".into()]),
            category: Some("linux".into()),
            tags: vec!["iso".into(), "fast".into()],
            seed_ratio_limit: Some(2.5),
            seed_time_limit_secs: Some(3600),
            super_seeding: true,
            first_last_piece_priority: true,
            queue_position: Some(7),
            download_limit_bytes: 50_000,
            upload_limit_bytes: 25_000,
        };
        store
            .save_states_batch(std::slice::from_ref(&state))
            .unwrap();

        let loaded = store.load_torrent(&hex::encode(hash)).unwrap().unwrap();
        assert_eq!(loaded.name, state.name);
        assert_eq!(loaded.download_dir, state.download_dir);
        assert_eq!(loaded.bitfield_hex, state.bitfield_hex);
        assert_eq!(loaded.uploaded_bytes, state.uploaded_bytes);
        assert_eq!(loaded.downloaded_bytes, state.downloaded_bytes);
        assert_eq!(loaded.is_paused, state.is_paused);
        assert_eq!(loaded.ratio, state.ratio);
        assert_eq!(loaded.magnet_uri, state.magnet_uri);
        assert_eq!(loaded.file_priorities, state.file_priorities);
        assert_eq!(loaded.sequential, state.sequential);
        assert_eq!(loaded.tracker_override, state.tracker_override);
        assert_eq!(loaded.category, state.category);
        assert_eq!(loaded.tags, state.tags);
        assert_eq!(loaded.seed_ratio_limit, state.seed_ratio_limit);
        assert_eq!(loaded.seed_time_limit_secs, state.seed_time_limit_secs);
        assert_eq!(loaded.super_seeding, state.super_seeding);
        assert_eq!(
            loaded.first_last_piece_priority,
            state.first_last_piece_priority
        );
        assert_eq!(loaded.queue_position, state.queue_position);
        assert_eq!(loaded.download_limit_bytes, state.download_limit_bytes);
        assert_eq!(loaded.upload_limit_bytes, state.upload_limit_bytes);
        assert_eq!(loaded.raw_bencode_hex, Some(hex::encode(raw_bencode)));

        let entries = store.load_all_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.as_deref(), Some(raw_bencode.as_slice()));

        // Legacy JSON record in TORRENTS_TABLE remains readable via fallback.
        let legacy_hash = [0x77u8; 20];
        let legacy_state = TorrentSessionState {
            info_hash_hex: hex::encode(legacy_hash),
            name: "LegacyRecord".into(),
            raw_bencode_hex: Some(hex::encode(b"d4:infodee")),
            ..Default::default()
        };
        let write_tx = store.db.begin_write().unwrap();
        {
            let mut table = write_tx.open_table(TORRENTS_TABLE).unwrap();
            let json = serde_json::to_vec(&legacy_state).unwrap();
            let enc = encrypt_for(&store.cipher, &legacy_hash, &json).unwrap();
            table.insert(&legacy_hash, enc.as_slice()).unwrap();
        }
        write_tx.commit().unwrap();

        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(
            store
                .load_torrent(&hex::encode(legacy_hash))
                .unwrap()
                .unwrap()
                .name,
            "LegacyRecord"
        );
        store.remove_torrent(&legacy_hash).unwrap();
        assert!(store
            .load_torrent(&hex::encode(legacy_hash))
            .unwrap()
            .is_none());
    }
}
