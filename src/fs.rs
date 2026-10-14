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
    /// The running account's local application data folder.
    LocalAppData,
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
            Self::LocalAppData => "Local AppData",
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

/// What [`FileView::pin_acquire`] grants on a pinned object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Read only: a backup about to be restored.
    Read,
    /// Read, write, rename, and delete: the shredder.
    Write,
    /// Read and delete: a delete that keeps a copy first.
    ReadDelete,
    /// Delete only.
    Delete,
}

/// A file or folder opened by handle and identified. Every change goes
/// through this handle, so a path swapped after the checks cannot redirect it.
#[derive(Debug)]
pub struct Pinned {
    /// Where the object really is: the path Windows reports for the open
    /// handle, with junctions, symlinks, 8.3 names, and SUBST drives resolved.
    pub real_path: String,
    pub kind: ItemKind,
    pub len: u64,
    /// Names (hard links) the file has. Overwriting one changes them all.
    pub links: u32,
    pub hidden_system: bool,
    handle: PinHandle,
}

impl Pinned {
    /// The open handle, for security queries on the pinned object itself.
    #[cfg(windows)]
    pub fn raw_handle(&self) -> Option<std::os::windows::io::RawHandle> {
        use std::os::windows::io::AsRawHandle;
        match &self.handle {
            PinHandle::Host(file) => Some(file.as_raw_handle()),
            PinHandle::Memory(_) => None,
        }
    }
}

#[derive(Debug)]
enum PinHandle {
    Host(std::fs::File),
    /// `MemoryFs` node key.
    Memory(String),
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
    /// Open `path` itself, never following a final reparse point, and report
    /// what it really is. The handle is read-attributes only: refusal checks
    /// run on [`Pinned::real_path`] before [`FileView::pin_acquire`] grants
    /// anything that can change the object. A reparse point, or anything
    /// off a fixed local drive, is refused here.
    fn pin(&self, path: &str) -> Result<Pinned, String>;
    /// Gain `access` on the pinned object through its own handle, never by
    /// reopening the path, so it is still the object that was checked.
    fn pin_acquire(&mut self, pin: &mut Pinned, access: Access) -> Result<(), String>;
    /// Read up to `len` bytes at `offset`, for the verify pass and copies.
    fn pin_read_at(&self, pin: &Pinned, offset: u64, len: usize) -> Option<Vec<u8>>;
    /// Overwrite `bytes.len()` bytes at `offset`. May extend a short file.
    fn pin_write_at(&mut self, pin: &Pinned, offset: u64, bytes: &[u8]) -> Result<(), String>;
    /// Flush buffers and metadata for a shredded file.
    fn pin_sync(&mut self, pin: &Pinned) -> Result<(), String>;
    /// Truncate (or zero-extend) a file.
    fn pin_set_len(&mut self, pin: &Pinned, len: u64) -> Result<(), String>;
    /// Rename within the object's own folder. Refuses an existing name.
    fn pin_rename(&mut self, pin: &mut Pinned, name: &str) -> Result<(), String>;
    /// Delete the pinned file, or empty folder.
    fn pin_delete(&mut self, pin: Pinned) -> Result<(), String>;
    /// Copy the pinned file's bytes to a new file at `to`, creating its
    /// folders. Never overwrites.
    fn pin_copy_to(&mut self, pin: &Pinned, to: &str) -> Result<(), String>;
    /// Create a new, empty file at `path` (creating its folders) and pin it
    /// with write access. Never opens an existing file or a link in its place;
    /// callers check [`Pinned::real_path`] and delete it if it landed
    /// somewhere it should not.
    fn pin_create_new(&mut self, path: &str) -> Result<Pinned, String>;
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
            KnownDir::LocalAppData => self.var("LOCALAPPDATA"),
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
    /// Alias prefix -> real prefix, standing in for junctions, 8.3 names,
    /// and SUBST drives: `pin` reports the real path.
    aliases: Vec<(String, String)>,
    links: HashMap<String, u32>,
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

    /// Make `alias` (and everything under it) resolve to `real` when pinned.
    pub fn add_alias(&mut self, alias: &str, real: &str) {
        self.aliases.push((norm(alias), norm(real)));
    }

    /// Give a file `count` hard links.
    pub fn set_links(&mut self, path: &str, count: u32) {
        self.links.insert(norm(path), count);
    }

    fn resolve(&self, path: &str) -> String {
        let path = norm(path);
        for (alias, real) in &self.aliases {
            if path == *alias {
                return real.clone();
            }
            if let Some(rest) = path.strip_prefix(&format!("{alias}\\")) {
                return format!("{real}\\{rest}");
            }
        }
        path
    }

    fn pinned_key<'a>(&self, pin: &'a Pinned) -> Result<&'a str, String> {
        match &pin.handle {
            PinHandle::Memory(key) => Ok(key),
            PinHandle::Host(_) => Err("not a MemoryFs handle".into()),
        }
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
    fn pin(&self, path: &str) -> Result<Pinned, String> {
        let key = self.resolve(path);
        let (kind, len) = match self.nodes.get(&key) {
            Some(FsNode::File { bytes, .. }) => (ItemKind::File, bytes.len() as u64),
            Some(FsNode::Dir) => (ItemKind::Dir, 0),
            Some(FsNode::Other) => return Err("refusing a reparse point".into()),
            None => return Err("file not found (os error 2)".into()),
        };
        Ok(Pinned {
            real_path: key.clone(),
            kind,
            len,
            links: self.links.get(&key).copied().unwrap_or(1),
            hidden_system: self.is_hidden_system(&key),
            handle: PinHandle::Memory(key),
        })
    }

    fn pin_acquire(&mut self, pin: &mut Pinned, _access: Access) -> Result<(), String> {
        let key = self.pinned_key(pin)?;
        if self.nodes.contains_key(key) {
            Ok(())
        } else {
            Err("file not found (os error 2)".into())
        }
    }

    fn pin_read_at(&self, pin: &Pinned, offset: u64, len: usize) -> Option<Vec<u8>> {
        match self.nodes.get(self.pinned_key(pin).ok()?) {
            Some(FsNode::File { bytes, .. }) => {
                let offset = (offset as usize).min(bytes.len());
                let end = offset.saturating_add(len).min(bytes.len());
                Some(bytes[offset..end].to_vec())
            }
            _ => None,
        }
    }

    fn pin_write_at(&mut self, pin: &Pinned, offset: u64, bytes: &[u8]) -> Result<(), String> {
        let key = self.pinned_key(pin)?.to_string();
        let offset = offset as usize;
        match self.nodes.get_mut(&key) {
            Some(FsNode::File { bytes: body, .. }) => {
                let end = offset + bytes.len();
                if body.len() < end {
                    body.resize(end, 0);
                }
                body[offset..end].copy_from_slice(bytes);
                Ok(())
            }
            _ => Err("file not found (os error 2)".into()),
        }
    }

    fn pin_sync(&mut self, pin: &Pinned) -> Result<(), String> {
        match self.nodes.get(self.pinned_key(pin)?) {
            Some(FsNode::File { .. }) => Ok(()),
            _ => Err("file not found (os error 2)".into()),
        }
    }

    fn pin_set_len(&mut self, pin: &Pinned, len: u64) -> Result<(), String> {
        let key = self.pinned_key(pin)?.to_string();
        match self.nodes.get_mut(&key) {
            Some(FsNode::File { bytes, .. }) => {
                bytes.resize(len as usize, 0);
                Ok(())
            }
            _ => Err("file not found (os error 2)".into()),
        }
    }

    fn pin_rename(&mut self, pin: &mut Pinned, name: &str) -> Result<(), String> {
        if name.is_empty() || name.contains(['\\', '/']) {
            return Err("not a plain file name".into());
        }
        let from = self.pinned_key(pin)?.to_string();
        let (dir, _) = from.rsplit_once('\\').ok_or("no parent folder")?;
        let to = format!("{dir}\\{}", norm(name));
        if self.nodes.contains_key(&to) {
            return Err("target already exists".into());
        }
        let node = self
            .nodes
            .remove(&from)
            .ok_or("file not found (os error 2)")?;
        self.nodes.insert(to.clone(), node);
        pin.real_path = to.clone();
        pin.handle = PinHandle::Memory(to);
        Ok(())
    }

    fn pin_delete(&mut self, pin: Pinned) -> Result<(), String> {
        let key = self.pinned_key(&pin)?.to_string();
        match self.nodes.get(&key) {
            Some(FsNode::File { .. }) => {}
            Some(FsNode::Dir) => {
                let prefix = format!("{key}\\");
                if self.nodes.keys().any(|other| other.starts_with(&prefix)) {
                    return Err("directory not empty".into());
                }
            }
            _ => return Err("file not found (os error 2)".into()),
        }
        self.nodes.remove(&key);
        Ok(())
    }

    fn pin_create_new(&mut self, path: &str) -> Result<Pinned, String> {
        let key = self.resolve(path);
        if self.nodes.contains_key(&key) {
            return Err("target already exists".into());
        }
        self.ensure_parents(&key);
        self.nodes.insert(
            key.clone(),
            FsNode::File {
                bytes: Vec::new(),
                age: None,
            },
        );
        Ok(Pinned {
            real_path: key.clone(),
            kind: ItemKind::File,
            len: 0,
            links: 1,
            hidden_system: false,
            handle: PinHandle::Memory(key),
        })
    }

    fn pin_copy_to(&mut self, pin: &Pinned, to: &str) -> Result<(), String> {
        let bytes = match self.nodes.get(self.pinned_key(pin)?) {
            Some(FsNode::File { bytes, .. }) => bytes.clone(),
            _ => return Err("file not found (os error 2)".into()),
        };
        if self.nodes.contains_key(&norm(to)) {
            return Err("target already exists".into());
        }
        self.add_file_bytes(to, bytes, None);
        Ok(())
    }

    fn exists(&self, path: &str) -> bool {
        self.nodes.contains_key(&self.resolve(path))
    }

    fn is_dir(&self, path: &str) -> bool {
        matches!(self.nodes.get(&self.resolve(path)), Some(FsNode::Dir))
    }

    fn len(&self, path: &str) -> Option<u64> {
        match self.nodes.get(&self.resolve(path)) {
            Some(FsNode::File { bytes, .. }) => Some(bytes.len() as u64),
            _ => None,
        }
    }

    fn read(&self, path: &str) -> Option<Vec<u8>> {
        match self.nodes.get(&self.resolve(path)) {
            Some(FsNode::File { bytes, .. }) => Some(bytes.clone()),
            _ => None,
        }
    }

    fn list(&self, dir: &str) -> Vec<DirItem> {
        let dir = self.resolve(dir);
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

    fn kind_of(&self, path: &str) -> ItemKind {
        match self.nodes.get(&self.resolve(path)) {
            Some(FsNode::Dir) => ItemKind::Dir,
            Some(FsNode::File { .. }) => ItemKind::File,
            _ => ItemKind::Other,
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
        FOLDERID_LocalAppData, FOLDERID_ProgramData, FOLDERID_ProgramFiles,
        FOLDERID_ProgramFilesX86, SHGetKnownFolderPath,
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
        KnownDir::ProgramFiles
        | KnownDir::ProgramFilesX86
        | KnownDir::ProgramData
        | KnownDir::LocalAppData => {
            let id = match dir {
                KnownDir::ProgramFiles => &FOLDERID_ProgramFiles,
                KnownDir::ProgramFilesX86 => &FOLDERID_ProgramFilesX86,
                KnownDir::LocalAppData => &FOLDERID_LocalAppData,
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
    fn pin(&self, path: &str) -> Result<Pinned, String> {
        host::pin(path)
    }

    fn pin_acquire(&mut self, pin: &mut Pinned, access: Access) -> Result<(), String> {
        let PinHandle::Host(file) = &pin.handle else {
            return Err("not a host handle".into());
        };
        let file = host::reopen(file, pin.kind, access, &pin.real_path)?;
        pin.handle = PinHandle::Host(file);
        Ok(())
    }

    fn pin_read_at(&self, pin: &Pinned, offset: u64, len: usize) -> Option<Vec<u8>> {
        let PinHandle::Host(file) = &pin.handle else {
            return None;
        };
        let mut buf = vec![0u8; len];
        let mut got = 0;
        while got < len {
            match host::read_at(file, &mut buf[got..], offset + got as u64) {
                Ok(0) => break,
                Ok(count) => got += count,
                Err(_) => return None,
            }
        }
        buf.truncate(got);
        Some(buf)
    }

    fn pin_write_at(&mut self, pin: &Pinned, offset: u64, bytes: &[u8]) -> Result<(), String> {
        let PinHandle::Host(file) = &pin.handle else {
            return Err("not a host handle".into());
        };
        let mut done = 0;
        while done < bytes.len() {
            match host::write_at(file, &bytes[done..], offset + done as u64) {
                Ok(0) => return Err("write made no progress".into()),
                Ok(count) => done += count,
                Err(err) => return Err(err.to_string()),
            }
        }
        Ok(())
    }

    fn pin_sync(&mut self, pin: &Pinned) -> Result<(), String> {
        let PinHandle::Host(file) = &pin.handle else {
            return Err("not a host handle".into());
        };
        file.sync_all().map_err(|err| err.to_string())
    }

    fn pin_set_len(&mut self, pin: &Pinned, len: u64) -> Result<(), String> {
        let PinHandle::Host(file) = &pin.handle else {
            return Err("not a host handle".into());
        };
        file.set_len(len).map_err(|err| err.to_string())
    }

    fn pin_rename(&mut self, pin: &mut Pinned, name: &str) -> Result<(), String> {
        if name.is_empty() || name.contains(['\\', '/', ':']) {
            return Err("not a plain file name".into());
        }
        let PinHandle::Host(file) = &pin.handle else {
            return Err("not a host handle".into());
        };
        host::rename(file, &pin.real_path, name)?;
        if let Some((dir, _)) = pin.real_path.rsplit_once('\\') {
            pin.real_path = format!("{dir}\\{name}");
        }
        Ok(())
    }

    fn pin_delete(&mut self, pin: Pinned) -> Result<(), String> {
        let PinHandle::Host(file) = pin.handle else {
            return Err("not a host handle".into());
        };
        host::delete(file, &pin.real_path)
    }

    fn pin_create_new(&mut self, path: &str) -> Result<Pinned, String> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        host::create_new(path)
    }

    fn pin_copy_to(&mut self, pin: &Pinned, to: &str) -> Result<(), String> {
        use std::io::Write;
        let bytes = self
            .pin_read_at(pin, 0, pin.len as usize)
            .filter(|bytes| bytes.len() as u64 == pin.len)
            .ok_or("could not read the file to copy")?;
        if let Some(parent) = Path::new(to).parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(to)
            .map_err(|err| err.to_string())?;
        out.write_all(&bytes).map_err(|err| err.to_string())?;
        out.sync_all().map_err(|err| err.to_string())
    }

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

/// Handle-level file operations behind [`HostFs`]'s `pin_*` methods.
#[cfg(windows)]
mod host {
    use super::{Access, ItemKind, PinHandle, Pinned};
    use std::os::windows::fs::{FileExt, OpenOptionsExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Wdk::Storage::FileSystem::{FileRenameInformation, NtSetInformationFile};
    use windows_sys::Win32::Foundation::{
        GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, RtlNtStatusToDosError,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SYSTEM, FILE_DISPOSITION_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED,
        FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FileDispositionInfo, GetDriveTypeW, GetFileInformationByHandle,
        GetFinalPathNameByHandleW, ReOpenFile, SetFileInformationByHandle, VOLUME_NAME_DOS,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    const DELETE: u32 = 0x0001_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const FILE_TRAVERSE: u32 = 0x0000_0020;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const DRIVE_FIXED: u32 = 3;
    const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const FLAGS: u32 = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;

    fn last_error() -> String {
        std::io::Error::last_os_error().to_string()
    }

    pub fn pin(path: &str) -> Result<Pinned, String> {
        // Read rights only: identifying an object must not need, or grant,
        // any right that could change it. READ_CONTROL lets trust checks read
        // the owner and DACL through this same handle; a file that does not
        // grant it is pinned without it, and such a check then fails closed.
        let open = |access: u32| {
            std::fs::OpenOptions::new()
                .access_mode(access)
                .share_mode(SHARE_ALL)
                .custom_flags(FLAGS)
                .open(path)
        };
        let file = open(READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .or_else(|_| open(FILE_READ_ATTRIBUTES | SYNCHRONIZE))
            .map_err(|err| err.to_string())?;
        identify(file, path)
    }

    /// `CREATE_NEW` never opens an existing file and fails on an existing
    /// link, so the handle is always a file this call made.
    pub fn create_new(path: &str) -> Result<Pinned, String> {
        // `write(true)` only satisfies std's create check; `access_mode`
        // sets the rights actually requested.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .create_new(true)
            .open(path)
            .map_err(|err| err.to_string())?;
        identify(file, path)
    }

    fn identify(file: std::fs::File, path: &str) -> Result<Pinned, String> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) } == 0 {
            return Err(last_error());
        }
        let attrs = info.dwFileAttributes;
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!(
                "{path} is a link or junction; links are never followed"
            ));
        }
        let real_path = final_path(&file)?;
        let drive: Vec<u16> = format!("{}\\\0", &real_path[..2]).encode_utf16().collect();
        if unsafe { GetDriveTypeW(drive.as_ptr()) } != DRIVE_FIXED {
            return Err(format!("{path} is not on a fixed local drive"));
        }
        Ok(Pinned {
            real_path,
            kind: if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
                ItemKind::Dir
            } else {
                ItemKind::File
            },
            len: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
            links: info.nNumberOfLinks,
            hidden_system: attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
                == (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM),
            handle: PinHandle::Host(file),
        })
    }

    /// The handle's own path as Windows resolves it, as a plain `X:\...`
    /// path. A network or volume-GUID answer is refused.
    fn final_path(file: &std::fs::File) -> Result<String, String> {
        let mut buf = vec![0u16; 1024];
        loop {
            let len = unsafe {
                GetFinalPathNameByHandleW(
                    file.as_raw_handle() as _,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                )
            } as usize;
            if len == 0 {
                return Err(last_error());
            }
            if len < buf.len() {
                buf.truncate(len);
                break;
            }
            buf.resize(len + 1, 0);
        }
        let text = String::from_utf16(&buf).map_err(|_| "path is not valid UTF-16".to_string())?;
        let plain = text.strip_prefix(r"\\?\").unwrap_or(&text);
        let bytes = plain.as_bytes();
        if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || &bytes[1..3] != b":\\" {
            return Err(format!("{text} is not on a local drive"));
        }
        Ok(plain.to_string())
    }

    pub fn reopen(
        file: &std::fs::File,
        kind: ItemKind,
        access: Access,
        real_path: &str,
    ) -> Result<std::fs::File, String> {
        let wanted = match access {
            Access::Read => GENERIC_READ | SYNCHRONIZE,
            Access::Write => GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
            Access::ReadDelete => GENERIC_READ | DELETE | SYNCHRONIZE,
            Access::Delete => DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        };
        if kind == ItemKind::Dir {
            // ReOpenFile refuses directory handles, so open the real path
            // again without following links and accept the new handle only
            // if it is the very object still held open by the pin.
            let again = std::fs::OpenOptions::new()
                .access_mode(wanted)
                .share_mode(SHARE_ALL)
                .custom_flags(FLAGS)
                .open(real_path)
                .map_err(|err| err.to_string())?;
            if file_id(&again)? != file_id(file)? {
                return Err(format!("{real_path} changed since it was checked"));
            }
            return Ok(again);
        }
        let handle = unsafe {
            ReOpenFile(
                file.as_raw_handle() as _,
                wanted,
                SHARE_ALL,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(last_error());
        }
        Ok(unsafe { std::fs::File::from_raw_handle(handle as _) })
    }

    /// Volume serial and file index: the identity of an open object.
    fn file_id(file: &std::fs::File) -> Result<(u32, u32, u32), String> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) } == 0 {
            return Err(last_error());
        }
        Ok((
            info.dwVolumeSerialNumber,
            info.nFileIndexHigh,
            info.nFileIndexLow,
        ))
    }

    pub fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        file.seek_read(buf, offset)
    }

    pub fn write_at(file: &std::fs::File, buf: &[u8], offset: u64) -> std::io::Result<usize> {
        file.seek_write(buf, offset)
    }

    /// Rename through the handle within its own folder. A bare name with no
    /// root directory would be resolved against the process's current
    /// directory, so the file's parent folder is opened (never following a
    /// link), checked to still be the file's real parent, and passed as
    /// `RootDirectory`. Never replaces an existing name.
    pub fn rename(file: &std::fs::File, path: &str, name: &str) -> Result<(), String> {
        let current = final_path(file)?;
        let (parent, _) = current
            .rsplit_once('\\')
            .ok_or_else(|| format!("{path}: no parent folder"))?;
        let parent_path = if parent.len() == 2 {
            format!("{parent}\\")
        } else {
            parent.to_string()
        };
        let dir = std::fs::OpenOptions::new()
            .access_mode(FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .share_mode(SHARE_ALL)
            .custom_flags(FLAGS)
            .open(&parent_path)
            .map_err(|err| format!("{path}: {err}"))?;
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(dir.as_raw_handle() as _, &mut info) } == 0 {
            return Err(format!("{path}: {}", last_error()));
        }
        let attrs = info.dwFileAttributes;
        if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 || attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!("{path}: its folder is not a plain folder"));
        }
        let dir_real = final_path(&dir)?;
        let still_inside = final_path(file)?.rsplit_once('\\').is_some_and(|(now, _)| {
            now.trim_end_matches('\\')
                .eq_ignore_ascii_case(dir_real.trim_end_matches('\\'))
        });
        if !still_inside {
            return Err(format!("{path} moved while it was being renamed"));
        }
        let units: Vec<u16> = name.encode_utf16().collect();
        let name_at = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
        let len_at = std::mem::offset_of!(FILE_RENAME_INFO, FileNameLength);
        let root_at = std::mem::offset_of!(FILE_RENAME_INFO, RootDirectory);
        let size = name_at + (units.len() + 1) * 2;
        // u64 storage keeps the struct's handle field aligned. Zeroed flags
        // mean ReplaceIfExists is false.
        let mut buf = vec![0u64; size.div_ceil(8)];
        let bytes =
            unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, buf.len() * 8) };
        let root = dir.as_raw_handle() as usize;
        bytes[root_at..root_at + std::mem::size_of::<usize>()].copy_from_slice(&root.to_ne_bytes());
        bytes[len_at..len_at + 4].copy_from_slice(&((units.len() * 2) as u32).to_le_bytes());
        for (index, unit) in units.iter().enumerate() {
            let at = name_at + index * 2;
            bytes[at..at + 2].copy_from_slice(&unit.to_le_bytes());
        }
        // SetFileInformationByHandle refuses a RootDirectory, so call the
        // native API it wraps; FILE_RENAME_INFORMATION has the same layout.
        let mut status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        let status = unsafe {
            NtSetInformationFile(
                file.as_raw_handle() as _,
                &mut status_block,
                buf.as_ptr() as *const _,
                size as u32,
                FileRenameInformation,
            )
        };
        drop(dir);
        if status < 0 {
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(format!(
                "{path}: {}",
                std::io::Error::from_raw_os_error(code as i32)
            ));
        }
        Ok(())
    }

    /// Mark the pinned object for deletion through its handle; it goes when
    /// the handle closes, here.
    pub fn delete(file: std::fs::File, path: &str) -> Result<(), String> {
        let info = FILE_DISPOSITION_INFO { DeleteFile: true };
        let ok = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle() as _,
                FileDispositionInfo,
                &info as *const _ as *const _,
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        };
        if ok == 0 {
            return Err(format!("{path}: {}", last_error()));
        }
        drop(file);
        Ok(())
    }
}

/// Off Windows `HostFs` only serves tests and the demo; pins are plain opens.
#[cfg(not(windows))]
mod host {
    use super::{Access, ItemKind, PinHandle, Pinned};
    use std::os::unix::fs::FileExt;

    pub fn pin(path: &str) -> Result<Pinned, String> {
        let meta = std::fs::symlink_metadata(path).map_err(|err| err.to_string())?;
        if meta.file_type().is_symlink() {
            return Err(format!("{path} is a link; links are never followed"));
        }
        let file = std::fs::File::open(path).map_err(|err| err.to_string())?;
        Ok(Pinned {
            real_path: path.to_string(),
            kind: if meta.is_dir() {
                ItemKind::Dir
            } else {
                ItemKind::File
            },
            len: meta.len(),
            links: 1,
            hidden_system: false,
            handle: PinHandle::Host(file),
        })
    }

    pub fn create_new(path: &str) -> Result<Pinned, String> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|err| err.to_string())?;
        Ok(Pinned {
            real_path: path.to_string(),
            kind: ItemKind::File,
            len: 0,
            links: 1,
            hidden_system: false,
            handle: PinHandle::Host(file),
        })
    }

    pub fn reopen(
        file: &std::fs::File,
        _kind: ItemKind,
        _access: Access,
        _real_path: &str,
    ) -> Result<std::fs::File, String> {
        file.try_clone().map_err(|err| err.to_string())
    }

    pub fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        file.read_at(buf, offset)
    }

    pub fn write_at(file: &std::fs::File, buf: &[u8], offset: u64) -> std::io::Result<usize> {
        file.write_at(buf, offset)
    }

    pub fn rename(_file: &std::fs::File, path: &str, name: &str) -> Result<(), String> {
        let to = std::path::Path::new(path).with_file_name(name);
        if to.exists() {
            return Err("target already exists".into());
        }
        std::fs::rename(path, to).map_err(|err| err.to_string())
    }

    pub fn delete(_file: std::fs::File, path: &str) -> Result<(), String> {
        let meta = std::fs::symlink_metadata(path).map_err(|err| err.to_string())?;
        if meta.is_dir() {
            std::fs::remove_dir(path)
        } else {
            std::fs::remove_file(path)
        }
        .map_err(|err| err.to_string())
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

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    #[test]
    fn live_pin_reports_the_long_name_behind_an_8_3_alias() {
        use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
        let dir =
            std::env::temp_dir().join(format!("HiveMendLongFolderName{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("payload.txt");
        std::fs::write(&file, b"x").unwrap();
        let long = file.display().to_string();
        let mut buf = vec![0u16; 1024];
        let len =
            unsafe { GetShortPathNameW(wide(&long).as_ptr(), buf.as_mut_ptr(), buf.len() as u32) }
                as usize;
        let short = String::from_utf16_lossy(&buf[..len]);
        let pin = HostFs.pin(&short).expect("pin short path");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(len > 0, "GetShortPathNameW failed");
        assert!(
            pin.real_path
                .to_ascii_lowercase()
                .contains(&format!("hivemendlongfoldername{}", std::process::id())),
            "{short} pinned as {}",
            pin.real_path
        );
    }

    #[test]
    fn live_pin_resolves_a_subst_drive_to_the_real_volume() {
        use windows_sys::Win32::Storage::FileSystem::GetLogicalDrives;
        let dir = std::env::temp_dir().join(format!("hivemend-subst-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("payload.txt"), b"x").unwrap();
        let used = unsafe { GetLogicalDrives() };
        let Some(letter) = (b'M'..=b'Y')
            .rev()
            .find(|letter| used & (1 << (letter - b'A')) == 0)
        else {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        };
        let drive = format!("{}:", letter as char);
        let made = std::process::Command::new("subst")
            .arg(&drive)
            .arg(&dir)
            .output()
            .expect("run subst");
        let pinned = made
            .status
            .success()
            .then(|| HostFs.pin(&format!(r"{drive}\payload.txt")));
        let _ = std::process::Command::new("subst")
            .args([&drive, "/D"])
            .output();
        let _ = std::fs::remove_dir_all(&dir);
        let pin = pinned.expect("subst failed").expect("pin through subst");
        assert!(
            !pin.real_path
                .to_ascii_uppercase()
                .starts_with(&drive.to_ascii_uppercase()),
            "{} still names the SUBST drive",
            pin.real_path
        );
        assert!(
            pin.real_path.ends_with(r"\payload.txt"),
            "{}",
            pin.real_path
        );
    }

    #[test]
    fn live_pin_refuses_a_junction_itself() {
        let dir = std::env::temp_dir().join(format!("hivemend-pinj-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("target")).unwrap();
        let link = dir.join("link");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(dir.join("target"))
            .output()
            .expect("run mklink");
        let err = HostFs.pin(&link.display().to_string()).map(|_| ());
        let _ = std::fs::remove_dir_all(&dir);
        assert!(made.status.success());
        assert!(err.unwrap_err().contains("never followed"));
    }
}
