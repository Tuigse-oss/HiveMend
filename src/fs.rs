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
    /// Precise kind for a staged path. Unknown paths report `Other`, which
    /// the shredder refuses, so an answer that cannot be known is safe.
    fn kind_of(&self, path: &str) -> ItemKind {
        if self.is_dir(path) {
            ItemKind::Dir
        } else if self.exists(path) {
            ItemKind::File
        } else {
            ItemKind::Other
        }
    }
    /// True when the file carries both hidden and system attributes.
    fn is_hidden_system(&self, path: &str) -> bool {
        let _ = path;
        false
    }
    fn remove_file(&mut self, path: &str) -> Result<(), String>;
    fn copy_file(&mut self, from: &str, to: &str) -> Result<(), String>;
    /// Overwrite `bytes.len()` bytes at `offset`. May extend a short file.
    fn write_at(&mut self, path: &str, offset: u64, bytes: &[u8]) -> Result<(), String>;
    /// Flush buffers and metadata for a shredded file.
    fn sync_file(&mut self, path: &str) -> Result<(), String>;
    /// Truncate (or zero-extend) a file.
    fn set_len(&mut self, path: &str, len: u64) -> Result<(), String>;
    /// Rename a file. Refuses directories and existing targets.
    fn rename_file(&mut self, from: &str, to: &str) -> Result<(), String>;
    /// Remove an empty directory.
    fn remove_dir(&mut self, path: &str) -> Result<(), String>;
    /// Read up to `len` bytes at `offset` for the verify pass.
    fn read_at(&self, path: &str, offset: u64, len: usize) -> Option<Vec<u8>>;
    fn var(&self, name: &str) -> Option<String>;
}

#[derive(Clone, Debug)]
enum FsNode {
    File {
        bytes: Vec<u8>,
        age: Option<Duration>,
    },
    Dir,
    /// Stands in for symlinks and reparse points.
    Other,
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

    pub fn add_other(&mut self, path: &str) {
        let path = norm(path);
        self.ensure_parents(&path);
        self.nodes.insert(path, FsNode::Other);
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
                FsNode::Other => (ItemKind::Other, None),
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

    fn kind_of(&self, path: &str) -> ItemKind {
        match self.nodes.get(&norm(path)) {
            Some(FsNode::Dir) => ItemKind::Dir,
            Some(FsNode::File { .. }) => ItemKind::File,
            _ => ItemKind::Other,
        }
    }

    fn write_at(&mut self, path: &str, offset: u64, bytes: &[u8]) -> Result<(), String> {
        let offset = offset as usize;
        match self.nodes.get_mut(&norm(path)) {
            Some(FsNode::File { bytes: body, .. }) => {
                if body.len() < offset {
                    body.resize(offset, 0);
                }
                let end = offset + bytes.len();
                if body.len() < end {
                    body.resize(end, 0);
                }
                body[offset..end].copy_from_slice(bytes);
                Ok(())
            }
            _ => Err("file not found".into()),
        }
    }

    fn sync_file(&mut self, path: &str) -> Result<(), String> {
        match self.nodes.get(&norm(path)) {
            Some(FsNode::File { .. }) => Ok(()),
            _ => Err("file not found".into()),
        }
    }

    fn set_len(&mut self, path: &str, len: u64) -> Result<(), String> {
        match self.nodes.get_mut(&norm(path)) {
            Some(FsNode::File { bytes, .. }) => {
                bytes.resize(len as usize, 0);
                Ok(())
            }
            _ => Err("file not found".into()),
        }
    }

    fn rename_file(&mut self, from: &str, to: &str) -> Result<(), String> {
        let from = norm(from);
        let to = norm(to);
        if self.nodes.contains_key(&to) {
            return Err("target already exists".into());
        }
        match self.nodes.remove(&from) {
            Some(node @ FsNode::File { .. }) => {
                self.ensure_parents(&to);
                self.nodes.insert(to, node);
                Ok(())
            }
            Some(other) => {
                self.nodes.insert(from, other);
                Err("not a file".into())
            }
            None => Err("file not found".into()),
        }
    }

    fn remove_dir(&mut self, path: &str) -> Result<(), String> {
        let path = norm(path);
        match self.nodes.get(&path) {
            Some(FsNode::Dir) => {}
            _ => return Err("directory not found".into()),
        }
        let prefix = format!("{path}\\");
        if self.nodes.keys().any(|key| key.starts_with(&prefix)) {
            return Err("directory not empty".into());
        }
        self.nodes.remove(&path);
        Ok(())
    }

    fn read_at(&self, path: &str, offset: u64, len: usize) -> Option<Vec<u8>> {
        match self.nodes.get(&norm(path)) {
            Some(FsNode::File { bytes, .. }) => {
                let offset = (offset as usize).min(bytes.len());
                let end = offset.saturating_add(len).min(bytes.len());
                Some(bytes[offset..end].to_vec())
            }
            _ => None,
        }
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

    fn kind_of(&self, path: &str) -> ItemKind {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return ItemKind::Other;
        };
        let kind = meta.file_type();
        if kind.is_symlink() {
            ItemKind::Other
        } else if kind.is_dir() {
            ItemKind::Dir
        } else if kind.is_file() {
            ItemKind::File
        } else {
            ItemKind::Other
        }
    }

    fn is_hidden_system(&self, path: &str) -> bool {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Storage::FileSystem::GetFileAttributesW;
            const INVALID: u32 = 0xffff_ffff;
            const HIDDEN: u32 = 0x2;
            const SYSTEM: u32 = 0x4;
            let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
            attrs != INVALID && attrs & (HIDDEN | SYSTEM) == (HIDDEN | SYSTEM)
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            false
        }
    }

    fn write_at(&mut self, path: &str, offset: u64, bytes: &[u8]) -> Result<(), String> {
        use std::io::{Seek, SeekFrom, Write};
        let mut file =
            std::fs::OpenOptions::new().write(true).open(path).map_err(|err| err.to_string())?;
        file.seek(SeekFrom::Start(offset)).map_err(|err| err.to_string())?;
        file.write_all(bytes).map_err(|err| err.to_string())
    }

    fn sync_file(&mut self, path: &str) -> Result<(), String> {
        let file =
            std::fs::OpenOptions::new().write(true).open(path).map_err(|err| err.to_string())?;
        file.sync_all().map_err(|err| err.to_string())
    }

    fn set_len(&mut self, path: &str, len: u64) -> Result<(), String> {
        let file =
            std::fs::OpenOptions::new().write(true).open(path).map_err(|err| err.to_string())?;
        file.set_len(len).map_err(|err| err.to_string())
    }

    fn rename_file(&mut self, from: &str, to: &str) -> Result<(), String> {
        if self.kind_of(from) != ItemKind::File {
            return Err("not a file".into());
        }
        if self.exists(to) {
            return Err("target already exists".into());
        }
        std::fs::rename(from, to).map_err(|err| err.to_string())
    }

    fn remove_dir(&mut self, path: &str) -> Result<(), String> {
        std::fs::remove_dir(path).map_err(|err| err.to_string())
    }

    fn read_at(&self, path: &str, offset: u64, len: usize) -> Option<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = std::fs::File::open(path).ok()?;
        file.seek(SeekFrom::Start(offset)).ok()?;
        let mut buf = Vec::new();
        file.take(len as u64).read_to_end(&mut buf).ok()?;
        Some(buf)
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
