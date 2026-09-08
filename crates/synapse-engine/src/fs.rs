//! Filesystem utilities, including real-time available disk space queries.

use std::path::Path;

/// Queries the available disk space in bytes for unprivileged users on the filesystem
/// containing `path`. If `path` does not exist, it traverses upward to find the nearest
/// existing ancestor directory.
#[allow(clippy::unnecessary_cast)]
pub fn get_available_disk_space(path: &Path) -> u64 {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let mut current = path;
        while !current.exists() {
            if let Some(parent) = current.parent() {
                if parent.as_os_str().is_empty() {
                    break;
                }
                current = parent;
            } else {
                break;
            }
        }

        let target = if current.as_os_str().is_empty() || !current.exists() {
            Path::new(".")
        } else {
            current
        };

        let c_path = match CString::new(target.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => return 0,
        };

        unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
                let fragment_size = if stat.f_frsize > 0 {
                    stat.f_frsize as u64
                } else {
                    stat.f_bsize as u64
                };
                (stat.f_bavail as u64).saturating_mul(fragment_size)
            } else {
                0
            }
        }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_available_disk_space() {
        let space = get_available_disk_space(Path::new("."));
        #[cfg(unix)]
        assert!(space > 0, "Current directory should report > 0 bytes available");
    }

    #[test]
    fn test_get_available_disk_space_nonexistent_subpath() {
        let nonexistent = Path::new("./some/deeply/nested/nonexistent/dir");
        let space = get_available_disk_space(nonexistent);
        #[cfg(unix)]
        assert!(space > 0, "Non-existent path should resolve to existing parent and report > 0 bytes");
    }
}
