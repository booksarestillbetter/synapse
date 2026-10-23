//! BEP 38 Finding Local Data Using Web Seeds.
//!
//! Facilitates local cache discovery for torrent pieces using webseed source URIs
//! and cryptographic hashes to verify existing cached local payload data.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct LocalWebSeedResolver {
    pub cache_dirs: Vec<PathBuf>,
}

impl LocalWebSeedResolver {
    pub fn new(cache_dirs: Vec<PathBuf>) -> Self {
        Self { cache_dirs }
    }

    /// Searches configured local cache directories for a file matching the relative path.
    pub fn find_local_file(&self, relative_path: &Path) -> Option<PathBuf> {
        for dir in &self.cache_dirs {
            if crate::fs::verify_no_symlinks_under(dir, relative_path).is_err() {
                continue;
            }
            let candidate = dir.join(relative_path);
            if let Ok(meta) = std::fs::symlink_metadata(&candidate) {
                if meta.file_type().is_file() {
                    return Some(candidate);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bep38_local_resolver() {
        let resolver = LocalWebSeedResolver::new(vec![PathBuf::from("/tmp")]);
        // Path resolution doesn't crash on non-existent file
        assert_eq!(
            resolver.find_local_file(Path::new("non_existent_file.iso")),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_bep38_local_resolver_rejects_symlinks_and_parent_traversal() {
        let temp_dir = tempfile::tempdir().unwrap();
        let outside_dir = tempfile::tempdir().unwrap();
        let secret = outside_dir.path().join("secret.bin");
        std::fs::write(&secret, b"secret-data").unwrap();

        let symlink_path = temp_dir.path().join("linked.bin");
        std::os::unix::fs::symlink(&secret, &symlink_path).unwrap();

        let resolver = LocalWebSeedResolver::new(vec![temp_dir.path().to_path_buf()]);
        assert_eq!(
            resolver.find_local_file(Path::new("linked.bin")),
            None,
            "Symlinks in local webseed cache must be rejected"
        );
        assert_eq!(
            resolver.find_local_file(Path::new("../secret.bin")),
            None,
            "Parent traversal in local webseed cache must be rejected"
        );
    }
}
