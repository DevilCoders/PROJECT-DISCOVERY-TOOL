use pyo3::prelude::*;
use pyo3::types::PyTuple;
use pyo3::IntoPyObjectExt;
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
    // The directory whose entries were pushed last, so skip_directory() can drop them.
    last_pushed: Option<PathBuf>,
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

/// Signed nanoseconds since the Unix epoch, as os.lstat() reports them: times before 1970
/// (such as the 1601 FILETIME zero some extractors leave) are negative, not 0.
fn modified_ns(metadata: &fs::Metadata) -> i64 {
    match metadata.modified() {
        Ok(value) => match value.duration_since(UNIX_EPOCH) {
            Ok(after) => after.as_nanos().min(i64::MAX as u128) as i64,
            Err(before) => -(before.duration().as_nanos().min(i64::MAX as u128) as i64),
        },
        Err(_) => 0,
    }
}

/// (owner uid, group gid, attribute bits): POSIX ownership; Windows FILE_ATTRIBUTE_* bits,
/// or BSD/macOS st_flags. Python turns the bits into names.
fn ownership(metadata: &fs::Metadata) -> (Option<u32>, Option<u32>, Option<u32>) {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        return (None, None, Some(metadata.file_attributes()));
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::macos::fs::MetadataExt as MacMetadataExt;
        use std::os::unix::fs::MetadataExt;
        return (Some(metadata.uid()), Some(metadata.gid()), Some(metadata.st_flags()));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::os::unix::fs::MetadataExt;
        return (Some(metadata.uid()), Some(metadata.gid()), None);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        (None, None, None)
    }
}

/// The device number (st_rdev) of a block or character device; Python splits it into
/// major and minor numbers with the platform's own encoding.
fn device_number(metadata: &fs::Metadata) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let file_type = metadata.file_type();
        if file_type.is_block_device() || file_type.is_char_device() {
            return Some(metadata.rdev());
        }
        return None;
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
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

/// One walked entry. PyO3 converts Rust tuples of at most 12 items, so the entry is handed
/// to Python as a flat tuple built here: (relative path, kind, size, mode, mtime_ns, hidden,
/// link target, error, depth, device, inode, ctime_ns, owner uid, group gid, attribute bits,
/// device number of a block or character device).
struct Entry {
    rel: OsString,
    kind: &'static str,
    size: u64,
    mode: Option<u32>,
    mtime: i64,
    hidden: bool,
    target: OsString,
    error: Option<String>,
    depth: usize,
    identity: (Option<u64>, Option<u64>, Option<u64>),
    ownership: (Option<u32>, Option<u32>, Option<u32>),
    rdev: Option<u64>,
}

impl Entry {
    /// An entry whose metadata could not be read.
    fn failed(rel: OsString, kind: &'static str, error: String, depth: usize) -> Self {
        Self {
            rel, kind, size: 0, mode: None, mtime: 0, hidden: false, target: OsString::new(),
            error: Some(error), depth, identity: (None, None, None), ownership: (None, None, None),
            rdev: None,
        }
    }

    fn into_tuple(self, py: Python<'_>) -> PyResult<Bound<'_, PyTuple>> {
        let (device, inode, changed) = self.identity;
        let (owner, group, attributes) = self.ownership;
        PyTuple::new(py, [
            self.rel.into_bound_py_any(py)?,
            self.kind.into_bound_py_any(py)?,
            self.size.into_bound_py_any(py)?,
            self.mode.into_bound_py_any(py)?,
            self.mtime.into_bound_py_any(py)?,
            self.hidden.into_bound_py_any(py)?,
            self.target.into_bound_py_any(py)?,
            self.error.into_bound_py_any(py)?,
            self.depth.into_bound_py_any(py)?,
            device.into_bound_py_any(py)?,
            inode.into_bound_py_any(py)?,
            changed.into_bound_py_any(py)?,
            owner.into_bound_py_any(py)?,
            group.into_bound_py_any(py)?,
            attributes.into_bound_py_any(py)?,
            self.rdev.into_bound_py_any(py)?,
        ])
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
            last_pushed: None,
        })
    }

    /// Do not descend into the directory just yielded. The caller decides exclusions with
    /// full Unicode case folding, which Rust's to_lowercase() does not implement, so both
    /// backends prune exactly the directories they record as pruned.
    fn skip_directory(&mut self) -> bool {
        match (self.last_pushed.take(), self.stack.last()) {
            (Some(pushed), Some((top, _, _))) if *top == pushed => {
                self.stack.pop();
                true
            }
            _ => false,
        }
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// The next entry as a flat tuple (see Entry), or None when the walk is complete.
    fn __next__<'py>(&mut self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyTuple>>> {
        match self.next_entry() {
            Some(entry) => entry.into_tuple(py).map(Some),
            None => Ok(None),
        }
    }
}

impl Walker {
    fn next_entry(&mut self) -> Option<Entry> {
        self.last_pushed = None;
        loop {
            let (parent, next_entry, parent_depth) = match self.stack.last_mut() {
                Some((path, entries, depth)) => (path.clone(), entries.next(), *depth),
                None => return None,
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
                    return Some(Entry::failed(rel, "directory_error", error.to_string(), parent_depth));
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
                    return Some(Entry::failed(rel, "entry_error", error.to_string(), depth));
                }
            };

            let file_type = metadata.file_type();
            let name = entry.file_name().to_string_lossy().into_owned();
            let hidden = hidden_entry(&name, &metadata);
            let size = metadata.len();
            let mode = mode_bits(&metadata);
            let mtime = modified_ns(&metadata);
            let (device, inode, changed) = identity_ns(&metadata);
            let (owner, group, attributes) = ownership(&metadata);
            let rdev = device_number(&metadata);
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
                        Ok(children) => {
                            self.stack.push((path.clone(), children, depth));
                            self.last_pushed = Some(path.clone());
                        }
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

            return Some(Entry {
                rel, kind, size, mode, mtime, hidden, target, error, depth,
                identity: (device, inode, changed), ownership: (owner, group, attributes), rdev,
            });
        }
    }
}

#[pymodule]
fn _walker(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Walker>()?;
    // Python uses a build only when it yields every field it records (see Entry).
    module.add("ENTRY_FIELDS", 16usize)?;
    Ok(())
}
