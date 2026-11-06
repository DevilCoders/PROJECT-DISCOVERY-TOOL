use pyo3::prelude::*;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, ReadDir};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[pyclass]
struct Walker {
    root: PathBuf,
    stack: Vec<(PathBuf, ReadDir, usize)>,
    excluded_names: HashSet<String>,
    excluded_paths: HashSet<String>,
}

/// Relative path as an OS string. PyO3 converts it losslessly (surrogateescape on
/// POSIX, WTF-16 on Windows), so non-UTF-8 names stay openable. Python normalizes
/// separators on Windows only, because a backslash is a legal POSIX name character.
fn relative_path(root: &Path, path: &Path) -> OsString {
    path.strip_prefix(root).unwrap_or(path).as_os_str().to_os_string()
}

/// Case-folded text used only for exclusion matching.
fn match_key(path: &OsString) -> String {
    let text = path.to_string_lossy();
    #[cfg(windows)]
    let text = text.replace('\\', "/");
    text.to_lowercase()
}

fn mode_bits(metadata: &fs::Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        Some(metadata.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        // Windows ACLs are not POSIX mode bits; report unknown rather than 0000.
        let _ = metadata;
        None
    }
}

fn hidden_entry(name: &str, metadata: &fs::Metadata) -> bool {
    if name.starts_with('.') {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        return metadata.file_attributes() & 0x2 != 0;
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

fn modified_ns(metadata: &fs::Metadata) -> u64 {
    metadata.modified().ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn identity_ns(metadata: &fs::Metadata) -> (Option<u64>, Option<u64>, Option<u64>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let changed = (metadata.ctime() as i128) * 1_000_000_000
            + (metadata.ctime_nsec() as i128);
        let changed = changed.max(0).min(u64::MAX as i128) as u64;
        return (Some(metadata.dev()), Some(metadata.ino()), Some(changed));
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        (None, None, None)
    }
}

#[pymethods]
impl Walker {
    #[new]
    fn new(root: String, excluded_names: Vec<String>, excluded_paths: Vec<String>) -> PyResult<Self> {
        let root = PathBuf::from(root);
        let initial = fs::read_dir(&root)
            .map_err(|error| pyo3::exceptions::PyOSError::new_err(error.to_string()))?;
        Ok(Self {
            root,
            stack: vec![(PathBuf::new(), initial, 0)],
            excluded_names: excluded_names.into_iter().map(|value| value.to_lowercase()).collect(),
            excluded_paths: excluded_paths.into_iter().map(|value| value.to_lowercase()).collect(),
        })
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    #[allow(clippy::type_complexity)]
    fn __next__(&mut self) -> PyResult<Option<(OsString, String, u64, Option<u32>, u64, bool, OsString, Option<String>, usize, Option<u64>, Option<u64>, Option<u64>)>> {
        loop {
            let (parent, next_entry, parent_depth) = match self.stack.last_mut() {
                Some((path, entries, depth)) => (path.clone(), entries.next(), *depth),
                None => return Ok(None),
            };

            let entry = match next_entry {
                Some(Ok(entry)) => entry,
                Some(Err(error)) => {
                    self.stack.pop();
                    let rel = if parent.as_os_str().is_empty() {
                        OsString::from(".")
                    } else {
                        relative_path(&self.root, &parent)
                    };
                    return Ok(Some((rel, "directory_error".to_string(), 0, None, 0, false,
                                    OsString::new(), Some(error.to_string()), parent_depth,
                                    None, None, None)));
                }
                None => {
                    self.stack.pop();
                    continue;
                }
            };

            let path = entry.path();
            let rel = relative_path(&self.root, &path);
            let depth = parent_depth + 1;
            let metadata = match fs::symlink_metadata(&path) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(Some((rel, "entry_error".to_string(), 0, None, 0, false,
                                    OsString::new(), Some(error.to_string()), depth,
                                    None, None, None)));
                }
            };

            let file_type = metadata.file_type();
            let name = entry.file_name().to_string_lossy().into_owned();
            let hidden = hidden_entry(&name, &metadata);
            let size = metadata.len();
            let mode = mode_bits(&metadata);
            let mtime = modified_ns(&metadata);
            let (device, inode, changed) = identity_ns(&metadata);
            let mut target = OsString::new();
            let mut error = None;
            let kind = if file_type.is_symlink() {
                match fs::read_link(&path) {
                    Ok(value) => target = value.into_os_string(),
                    Err(value) => error = Some(value.to_string()),
                }
                "symlink"
            } else if file_type.is_dir() {
                let name_key = name.to_lowercase();
                let path_key = match_key(&rel);
                if !self.excluded_names.contains(&name_key) &&
                   !self.excluded_paths.contains(&path_key) {
                    match fs::read_dir(&path) {
                        Ok(children) => self.stack.push((path.clone(), children, depth)),
                        Err(value) => error = Some(value.to_string()),
                    }
                }
                "directory"
            } else if file_type.is_file() {
                "file"
            } else {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileTypeExt;
                    if file_type.is_fifo() { "fifo" }
                    else if file_type.is_socket() { "socket" }
                    else if file_type.is_block_device() { "block_device" }
                    else if file_type.is_char_device() { "character_device" }
                    else { "unknown_special" }
                }
                #[cfg(not(unix))]
                {
                    "unknown_special"
                }
            };

            return Ok(Some((rel, kind.to_string(), size, mode, mtime, hidden,
                            target, error, depth, device, inode, changed)));
        }
    }
}

#[pymodule]
fn _walker(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Walker>()?;
    Ok(())
}
