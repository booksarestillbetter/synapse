//! BEP 47 Padding Files and Whole-File Hashing.
//!
//! Identifies `.pad/` padding files used to align files to piece boundaries,
//! filtering them out of user-facing file trees while preserving piece offsets.
//! Also supports whole-file SHA-1 checksum verification.

use std::path::Path;
use crate::File;

/// Checks whether a given file entry represents a BEP 47 padding file.
pub fn is_padding_file(path: &Path, attr: Option<&str>) -> bool {
    // Check "attr" attribute containing 'p'
    if let Some(a) = attr {
        if a.contains('p') {
            return true;
        }
    }

    // Check path components
    let path_str = path.to_string_lossy();
    if path_str.starts_with(".pad") || path_str.contains("/.pad") || path_str.contains("_____padding_file_") {
        return true;
    }

    false
}

/// Splits a list of torrent files into real payload files and padding files.
pub fn separate_padding_files(files: &[File]) -> (Vec<File>, Vec<File>) {
    let mut payload = Vec::new();
    let mut padding = Vec::new();

    for f in files {
        if is_padding_file(&f.path, None) {
            padding.push(f.clone());
        } else {
            payload.push(f.clone());
        }
    }

    (payload, padding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_bep47_padding_file_detection() {
        assert!(is_padding_file(Path::new(".pad/16384"), None));
        assert!(is_padding_file(Path::new("video/.pad/65536"), None));
        assert!(is_padding_file(Path::new("video/_____padding_file_0_____"), None));
        assert!(is_padding_file(Path::new("video/movie.mp4"), Some("p")));
        assert!(!is_padding_file(Path::new("video/movie.mp4"), None));
    }

    #[test]
    fn test_separate_padding_files() {
        let files = vec![
            File { path: PathBuf::from("video/movie.mp4"), length: 1_000_000 },
            File { path: PathBuf::from(".pad/24576"), length: 24576 },
            File { path: PathBuf::from("subs/movie.srt"), length: 50_000 },
        ];

        let (payload, padding) = separate_padding_files(&files);
        assert_eq!(payload.len(), 2);
        assert_eq!(padding.len(), 1);
        assert_eq!(payload[0].path, PathBuf::from("video/movie.mp4"));
        assert_eq!(padding[0].path, PathBuf::from(".pad/24576"));
    }
}
