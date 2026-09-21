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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use redb::{Database, ReadableTable, TableDefinition};
use std::sync::Arc;

const TORRENTS_TABLE: TableDefinition<&[u8; 20], &[u8]> = TableDefinition::new("session_torrents");

fn to_io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

fn encrypt(cipher: &ChaCha20Poly1305, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| std::io::Error::other(format!("AEAD encrypt error: {e}")))?;
    let mut payload = Vec::with_capacity(12 + ciphertext.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    Ok(payload)
}

fn decrypt(cipher: &ChaCha20Poly1305, payload: &[u8]) -> std::io::Result<Vec<u8>> {
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
            if key_path.exists() {
                let mut f = File::open(&key_path)?;
                let mut buf = [0u8; 32];
                f.read_exact(&mut buf)?;
                buf
            } else {
                let generated = ChaCha20Poly1305::generate_key(&mut OsRng);
                let key_bytes: [u8; 32] = generated.into();
                let mut f = File::create(&key_path)?;
                f.write_all(&key_bytes)?;
                f.sync_all()?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
                }
                key_bytes
            }
        };

        Self::with_key(session_dir, key)
    }

    pub fn with_key(session_dir: impl AsRef<Path>, key_bytes: [u8; 32]) -> std::io::Result<Self> {
        let session_dir = session_dir.as_ref().to_path_buf();
        fs::create_dir_all(&session_dir)?;

        let db_path = session_dir.join("session.db");
        let db = Database::create(&db_path).map_err(to_io_err)?;

        // Ensure table exists
        let write_tx = db.begin_write().map_err(to_io_err)?;
        {
            let _ = write_tx.open_table(TORRENTS_TABLE).map_err(to_io_err)?;
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
        let hash = state.info_hash().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid info_hash_hex in session state",
            )
        })?;

        // If the state being saved does not carry raw_bencode_hex, check whether an existing
        // record for this torrent already has raw_bencode_hex saved in the database. If so, preserve
        // it rather than overwriting it with None.
        let state_to_save = if state.raw_bencode_hex.is_none() {
            if let Ok(Some(existing)) = self.load_torrent(&state.info_hash_hex) {
                if existing.raw_bencode_hex.is_some() {
                    let mut s = state.clone();
                    s.raw_bencode_hex = existing.raw_bencode_hex;
                    s
                } else {
                    state.clone()
                }
            } else {
                state.clone()
            }
        } else {
            state.clone()
        };

        let data = serde_json::to_vec(&state_to_save)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let encrypted = encrypt(&self.cipher, &data)?;

        let write_tx = self.db.begin_write().map_err(to_io_err)?;
        {
            let mut table = write_tx.open_table(TORRENTS_TABLE).map_err(to_io_err)?;
            table
                .insert(&hash, encrypted.as_slice())
                .map_err(to_io_err)?;
        }
        write_tx.commit().map_err(to_io_err)?;
        debug!(
            "Persisted encrypted session state for {}",
            state.info_hash_hex
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
        let table = match read_tx.open_table(TORRENTS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(to_io_err(e)),
        };
        let value = match table.get(&hash).map_err(to_io_err)? {
            Some(v) => v,
            None => return Ok(None),
        };
        let decrypted = decrypt(&self.cipher, value.value())?;
        let state = serde_json::from_slice(&decrypted)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Some(state))
    }

    /// Loads all persisted torrent session state files from disk via single sequential database scan.
    pub fn load_all(&self) -> std::io::Result<Vec<TorrentSessionState>> {
        let read_tx = self.db.begin_read().map_err(to_io_err)?;
        let table = match read_tx.open_table(TORRENTS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(to_io_err(e)),
        };

        let mut states = Vec::new();
        let iter = table.iter().map_err(to_io_err)?;
        for item in iter {
            let (_key, value) = item.map_err(to_io_err)?;
            match decrypt(&self.cipher, value.value()) {
                Ok(decrypted) => match serde_json::from_slice::<TorrentSessionState>(&decrypted) {
                    Ok(state) => states.push(state),
                    Err(e) => warn!("Failed to deserialize encrypted session payload: {e}"),
                },
                Err(e) => warn!("Failed to decrypt session record: {e}"),
            }
        }

        info!(
            "Loaded {} encrypted torrent session states from database",
            states.len()
        );
        Ok(states)
    }

    /// Removes the persisted session state for a torrent from the database.
    pub fn remove_torrent(&self, info_hash: &[u8; 20]) -> std::io::Result<()> {
        let write_tx = self.db.begin_write().map_err(to_io_err)?;
        {
            let mut table = write_tx.open_table(TORRENTS_TABLE).map_err(to_io_err)?;
            table.remove(info_hash).map_err(to_io_err)?;
        }
        write_tx.commit().map_err(to_io_err)?;
        debug!("Removed session state for {}", hex::encode(info_hash));
        Ok(())
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
            let _ = fs::rename(&torrents_dir, &migrated_dir);
        }
    }
}
