use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemKind {
    File,
    Dir,
    Other,
}

/// A system folder that refusal checks and launched tools are anchored to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnownDir {
    Windows,
    System,
    ProgramFiles,
    ProgramFilesX86,
    ProgramData,
}

impl KnownDir {
    pub const PROTECTED: [KnownDir; 4] = [
        KnownDir::Windows,
        KnownDir::ProgramFiles,
        KnownDir::ProgramFilesX86,
        KnownDir::ProgramData,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::System => "System32",
            Self::ProgramFiles => "Program Files",
            Self::ProgramFilesX86 => "Program Files (x86)",
            Self::ProgramData => "ProgramData",
        }
    }
}

/// True for a fully qualified drive path such as `C:\Windows`: a letter, a
/// colon, a backslash, and at least one more character, and no component that
/// resolves differently from its spelling.
pub fn is_drive_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() > 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && !path.contains('/')
        && !crate::pathutil::has_unsafe_fs_component(path)
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
    /// Where a system folder really is. On the host this comes from the
    /// Windows APIs, never the environment, which a launcher controls. The
    /// default (used by `MemoryFs`) reads the matching variable.
    fn known_dir(&self, dir: KnownDir) -> Option<String> {
        match dir {
            KnownDir::Windows => self.var("SystemRoot").or_else(|| self.var("windir")),
            KnownDir::System => self
                .known_dir(KnownDir::Windows)
                .map(|root| format!("{}\\System32", root.trim_end_matches('\\'))),
            KnownDir::ProgramFiles => self.var("ProgramFiles"),
            KnownDir::ProgramFilesX86 => self.var("ProgramFiles(x86)"),
            KnownDir::ProgramData => self.var("ProgramData"),
        }
    }
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

    /// A test filesystem with the standard Windows folders defined, as every
    /// delete and shred check requires them.
    pub fn with_windows_dirs() -> Self {
        let mut fs = Self::new();
        fs.set_var("SystemRoot", r"C:\Windows");
        fs.set_var("ProgramFiles", r"C:\Program Files");
        fs.set_var("ProgramFiles(x86)", r"C:\Program Files (x86)");
        fs.set_var("ProgramData", r"C:\ProgramData");
        fs
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

/// Open a staged file for the shredder's overwrite, truncate, and verify
/// passes while refusing reparse points (symlinks, junctions). `shred_allowed`
/// checks the path with no-follow metadata, but a path could be swapped for a
/// link between that check and this open. Opening with
/// `FILE_FLAG_OPEN_REPARSE_POINT` grabs the link itself, never its target, and
/// the attribute check then refuses it, so an overwrite can never be redirected
/// into another file through a TOCTOU swap.
#[cfg(windows)]
fn open_regular(path: &str, write: bool) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::other("refusing a reparse point"));
    }
    Ok(file)
}

#[cfg(not(windows))]
fn open_regular(path: &str, write: bool) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(write)
        .open(path)
}

/// A system folder from the Windows APIs: the Windows and System32 folders
/// from `GetSystemWindowsDirectoryW`/`GetSystemDirectoryW`, the rest from
/// `SHGetKnownFolderPath`. None of them read the environment. `None` unless
/// the answer is a fully qualified drive path.
#[cfg(windows)]
pub fn host_known_dir(dir: KnownDir) -> Option<String> {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::SystemInformation::{
        GetSystemDirectoryW, GetSystemWindowsDirectoryW,
    };
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, SHGetKnownFolderPath,
    };
    let text = match dir {
        KnownDir::Windows | KnownDir::System => {
            let mut buf = [0u16; 520];
            let len = unsafe {
                if dir == KnownDir::Windows {
                    GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32)
                } else {
                    GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32)
                }
            } as usize;
            if len == 0 || len >= buf.len() {
                return None;
            }
            String::from_utf16(&buf[..len]).ok()?
        }
        KnownDir::ProgramFiles | KnownDir::ProgramFilesX86 | KnownDir::ProgramData => {
            let id = match dir {
                KnownDir::ProgramFiles => &FOLDERID_ProgramFiles,
                KnownDir::ProgramFilesX86 => &FOLDERID_ProgramFilesX86,
                _ => &FOLDERID_ProgramData,
            };
            let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
            let hr = unsafe { SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut raw) };
            let text = if hr == 0 && !raw.is_null() {
                let len = (0..).take_while(|&i| unsafe { *raw.add(i) } != 0).count();
                String::from_utf16(unsafe { std::slice::from_raw_parts(raw, len) }).ok()
            } else {
                None
            };
            unsafe { CoTaskMemFree(raw as *const _) };
            text?
        }
    };
    let text = text.trim_end_matches('\\').to_string();
    is_drive_absolute(&text).then_some(text)
}

impl FileView for HostFs {
    fn known_dir(&self, dir: KnownDir) -> Option<String> {
        #[cfg(windows)]
        {
            host_known_dir(dir)
        }
        #[cfg(not(windows))]
        {
            let _ = dir;
            None
        }
    }

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
        std::fs::metadata(path)
            .ok()
            .filter(|meta| meta.is_file())
            .map(|meta| meta.len())
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
        let mut file = open_regular(path, true).map_err(|err| err.to_string())?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|err| err.to_string())?;
        file.write_all(bytes).map_err(|err| err.to_string())
    }

    fn sync_file(&mut self, path: &str) -> Result<(), String> {
        let file = open_regular(path, true).map_err(|err| err.to_string())?;
        file.sync_all().map_err(|err| err.to_string())
    }

    fn set_len(&mut self, path: &str, len: u64) -> Result<(), String> {
        let file = open_regular(path, true).map_err(|err| err.to_string())?;
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
        let mut file = open_regular(path, false).ok()?;
        file.seek(SeekFrom::Start(offset)).ok()?;
        let mut buf = Vec::new();
        file.take(len as u64).read_to_end(&mut buf).ok()?;
        Some(buf)
    }

    fn var(&self, name: &str) -> Option<String> {
        if let Ok(value) = std::env::var(name)
            && !value.is_empty()
        {
            return Some(value);
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

/// Live Windows test. Read-only folder lookups.
#[cfg(all(test, windows))]
mod live_tests {
    use super::*;

    #[test]
    fn live_known_dirs_are_absolute_and_nested_as_expected() {
        let windows = host_known_dir(KnownDir::Windows).expect("Windows folder");
        let system = host_known_dir(KnownDir::System).expect("System32 folder");
        for dir in KnownDir::PROTECTED {
            let path = host_known_dir(dir).unwrap_or_else(|| panic!("{dir:?} missing"));
            assert!(is_drive_absolute(&path), "{dir:?}: {path}");
            assert!(!path.ends_with('\\'), "{dir:?}: {path}");
        }
        assert!(
            system
                .to_ascii_lowercase()
                .starts_with(&(windows.to_ascii_lowercase() + "\\")),
            "{system} is not under {windows}"
        );
        assert!(std::path::Path::new(&system).join("reg.exe").is_file());
        assert!(std::path::Path::new(&system).join("cipher.exe").is_file());
    }
}
