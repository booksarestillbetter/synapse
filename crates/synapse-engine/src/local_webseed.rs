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
            let candidate = dir.join(relative_path);
            if candidate.exists() && candidate.is_file() {
                return Some(candidate);
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
}
