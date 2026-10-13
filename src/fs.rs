use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemKind {
    File,
    Dir,
    Other,
}

#[derive(Clone, Debug)]
pub struct DirItem {
    pub name: String,
    pub kind: ItemKind,
    pub age: Option<Duration>,
}

pub trait FileView {
    /// Scanners report a path only when this returns false, so an answer that
    /// cannot be known (offline drive, network share, access denied) is true.
    fn exists(&self, path: &str) -> bool;
    /// Same rule as `exists`: true when the answer cannot be known.
    fn is_dir(&self, path: &str) -> bool;
    /// File size in bytes, for preview totals. `None` when unknown.
    fn len(&self, path: &str) -> Option<u64> {
        let _ = path;
        None
    }
    fn read(&self, path: &str) -> Option<Vec<u8>>;
    fn list(&self, dir: &str) -> Vec<DirItem>;
    fn remove_file(&mut self, path: &str) -> Result<(), String>;
    fn copy_file(&mut self, from: &str, to: &str) -> Result<(), String>;
    fn var(&self, name: &str) -> Option<String>;
}

#[derive(Clone, Debug)]
enum FsNode {
    File {
        bytes: Vec<u8>,
        age: Option<Duration>,
    },
    Dir,
}

#[derive(Clone, Debug, Default)]
pub struct MemoryFs {
    nodes: HashMap<String, FsNode>,
    vars: HashMap<String, String>,
}

impl MemoryFs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_var(&mut self, name: &str, value: &str) {
        self.vars.insert(name.to_string(), value.to_string());
    }

    pub fn add_file(&mut self, path: &str) {
        self.add_file_bytes(path, Vec::new(), None);
    }

    pub fn add_file_bytes(&mut self, path: &str, bytes: Vec<u8>, age: Option<Duration>) {
        let path = norm(path);
        self.ensure_parents(&path);
        self.nodes.insert(path, FsNode::File { bytes, age });
    }

    pub fn add_dir(&mut self, path: &str) {
        let path = norm(path);
        self.ensure_parents(&path);
        self.nodes.insert(path, FsNode::Dir);
    }

    fn ensure_parents(&mut self, path: &str) {
        let mut built = String::new();
        let parts: Vec<&str> = path.split('\\').collect();
        for (index, part) in parts.iter().enumerate() {
            if index + 1 == parts.len() {
                break;
            }
            if !built.is_empty() {
                built.push('\\');
            }
            built.push_str(part);
            self.nodes.entry(built.clone()).or_insert(FsNode::Dir);
        }
    }
}

fn norm(path: &str) -> String {
    path.trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase()
}

impl FileView for MemoryFs {
    fn exists(&self, path: &str) -> bool {
        self.nodes.contains_key(&norm(path))
    }

    fn is_dir(&self, path: &str) -> bool {
        matches!(self.nodes.get(&norm(path)), Some(FsNode::Dir))
    }

    fn len(&self, path: &str) -> Option<u64> {
        match self.nodes.get(&norm(path)) {
            Some(FsNode::File { bytes, .. }) => Some(bytes.len() as u64),
            _ => None,
        }
    }

    fn read(&self, path: &str) -> Option<Vec<u8>> {
        match self.nodes.get(&norm(path)) {
            Some(FsNode::File { bytes, .. }) => Some(bytes.clone()),
            _ => None,
        }
    }

    fn list(&self, dir: &str) -> Vec<DirItem> {
        let dir = norm(dir);
        let prefix = format!("{dir}\\");
        let mut items = Vec::new();
        for (path, node) in &self.nodes {
            let Some(name) = path.strip_prefix(&prefix) else {
                continue;
            };
            if name.is_empty() || name.contains('\\') {
                continue;
            }
            let (kind, age) = match node {
                FsNode::Dir => (ItemKind::Dir, None),
                FsNode::File { age, .. } => (ItemKind::File, *age),
            };
            items.push(DirItem {
                name: name.to_string(),
                kind,
                age,
            });
        }
        items.sort_by(|left, right| left.name.cmp(&right.name));
        items
    }

    fn remove_file(&mut self, path: &str) -> Result<(), String> {
        match self.nodes.remove(&norm(path)) {
            Some(FsNode::File { .. }) => Ok(()),
            Some(other) => {
                self.nodes.insert(norm(path), other);
                Err("not a file".into())
            }
            None => Err("file not found".into()),
        }
    }

    fn copy_file(&mut self, from: &str, to: &str) -> Result<(), String> {
        let bytes = match self.nodes.get(&norm(from)) {
            Some(FsNode::File { bytes, .. }) => bytes.clone(),
            _ => return Err("file not found".into()),
        };
        self.add_file_bytes(to, bytes, None);
        Ok(())
    }

    fn var(&self, name: &str) -> Option<String> {
        self.vars.iter().find_map(|(key, value)| {
            if key.eq_ignore_ascii_case(name) && !value.is_empty() {
                Some(value.clone())
            } else {
                None
            }
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct HostFs;

/// Only a drive-letter path on a mounted fixed disk can be proven missing.
/// USB sticks, card readers, DVDs, mapped network drives, UNC shares, and
/// unplugged drives all look "missing" when they are only out of reach.
#[cfg(windows)]
fn on_local_fixed_drive(path: &str) -> bool {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    const DRIVE_FIXED: u32 = 3;
    let bytes = path.trim().as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return false;
    }
    if bytes[2] != b'\\' && bytes[2] != b'/' {
        return false;
    }
    let root: Vec<u16> = format!("{}:\\", bytes[0] as char)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe { GetDriveTypeW(root.as_ptr()) == DRIVE_FIXED }
}

#[cfg(not(windows))]
fn on_local_fixed_drive(path: &str) -> bool {
    !path.starts_with("\\\\")
}

impl FileView for HostFs {
    fn exists(&self, path: &str) -> bool {
        if !on_local_fixed_drive(path) {
            return true;
        }
        Path::new(path).try_exists().unwrap_or(true)
    }

    fn is_dir(&self, path: &str) -> bool {
        if !on_local_fixed_drive(path) {
            return true;
        }
        match std::fs::metadata(path) {
            Ok(meta) => meta.is_dir(),
            Err(err) => err.kind() != std::io::ErrorKind::NotFound,
        }
    }

    fn len(&self, path: &str) -> Option<u64> {
        if !on_local_fixed_drive(path) {
            return None;
        }
        std::fs::metadata(path).ok().filter(|meta| meta.is_file()).map(|meta| meta.len())
    }

    fn read(&self, path: &str) -> Option<Vec<u8>> {
        std::fs::read(path).ok()
    }

    fn list(&self, dir: &str) -> Vec<DirItem> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut items = Vec::new();
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let kind = if file_type.is_symlink() {
                ItemKind::Other
            } else if file_type.is_dir() {
                ItemKind::Dir
            } else if file_type.is_file() {
                ItemKind::File
            } else {
                ItemKind::Other
            };
            let age = entry.metadata().ok().and_then(|meta| {
                meta.modified()
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
            });
            items.push(DirItem {
                name: entry.file_name().to_string_lossy().into_owned(),
                kind,
                age,
            });
        }
        items
    }

    fn remove_file(&mut self, path: &str) -> Result<(), String> {
        std::fs::remove_file(path).map_err(|err| err.to_string())
    }

    fn copy_file(&mut self, from: &str, to: &str) -> Result<(), String> {
        if let Some(parent) = Path::new(to).parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        std::fs::copy(from, to)
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    fn var(&self, name: &str) -> Option<String> {
        if let Ok(value) = std::env::var(name) {
            if !value.is_empty() {
                return Some(value);
            }
        }
        std::env::vars().find_map(|(key, value)| {
            if key.eq_ignore_ascii_case(name) && !value.is_empty() {
                Some(value)
            } else {
                None
            }
        })
    }
}
