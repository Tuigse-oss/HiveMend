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

/// The largest file a backup copies or a restore reads back in one piece.
/// Backed-up files are shortcuts, a few kilobytes each.
pub const MAX_COPY_BYTES: u64 = 16 * 1024 * 1024;

/// The length to read for a copy, or why it is too large to copy.
pub fn copy_len(pin: &Pinned) -> Result<usize, String> {
    if pin.len > MAX_COPY_BYTES {
        return Err(format!(
            "{} is {} bytes, too large to back up here",
            pin.real_path, pin.len
        ));
    }
    Ok(pin.len as usize)
}

/// What [`FileView::pin_acquire`] grants on a pinned object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Read only: a backup about to be restored.
    Read,
    /// Read and delete: a delete that keeps a copy first.
    ReadDelete,
    /// Delete only.
    Delete,
    /// Delete, with only reading shared: refused while another program
    /// has the file open to write or delete it, and no other program can
    /// write to it while held. The pin's age is read again through it.
    DeleteExclusive,
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
    /// Time since the object was last written, from the open handle, when
    /// known. Age-based cleaning checks it on the object it deletes.
    pub age: Option<Duration>,
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
    /// callers treat as unsafe to act on, so an answer that cannot be known is safe.
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
    /// Flush buffers and metadata for a written file.
    fn pin_sync(&mut self, pin: &Pinned) -> Result<(), String>;
    /// Delete the pinned file, or empty folder.
    fn pin_delete(&mut self, pin: Pinned) -> Result<(), String>;
    /// Copy the pinned file's bytes to a new file at `to`, creating its
    /// folders. Never overwrites.
    fn pin_copy_to(&mut self, pin: &Pinned, to: &str) -> Result<(), String>;
    /// Create a new, empty file at `path` and pin it with write access,
    /// making any missing folders. The nearest folder that exists is held
    /// from its check to the end, and each missing folder and the file are
    /// made relative to held handles, never through a link, so the file
    /// lands exactly where `allowed` was asked about: nothing is made unless
    /// `allowed(fs, real path)` accepts it. On any failure, whatever this
    /// call made is removed again through its own handles.
    fn pin_create_confined(
        &mut self,
        path: &str,
        allowed: &dyn Fn(&dyn FileView, &str) -> bool,
    ) -> Result<Pinned, String>;
    /// True when the file has named data streams besides the download
    /// marker (Zone.Identifier). A copy of the main stream does not hold
    /// them, so such a file cannot be backed up by copying.
    fn extra_streams(&self, path: &str) -> Result<bool, String> {
        let _ = path;
        Ok(false)
    }
    /// True when the file has any named data stream, the download marker
    /// included. A backup copy holds only the main stream, so a file with
    /// any is not removed by repair.
    fn named_streams(&self, path: &str) -> Result<bool, String> {
        self.extra_streams(path)
    }
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
    /// Files with named data streams besides the download marker.
    streams: Vec<String>,
    /// Files with only the download marker (Zone.Identifier).
    markers: Vec<String>,
    /// Files another program holds open to write: exclusive access fails.
    busy: Vec<String>,
    /// Files written after they were pinned: exclusive access sees a fresh age.
    written_since: Vec<String>,
}

impl MemoryFs {
    pub fn new() -> Self {
        Self::default()
    }

    /// A test filesystem with the standard Windows folders defined, as every
    /// delete check requires them.
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

    /// Have another program hold `path` open for writing.
    pub fn set_busy(&mut self, path: &str) {
        self.busy.push(norm(path));
    }

    /// Have `path` written after it is pinned and before it is deleted.
    pub fn set_written_since(&mut self, path: &str) {
        self.written_since.push(norm(path));
    }

    /// Give a file the download marker (Zone.Identifier) and no other stream.
    pub fn add_download_marker(&mut self, path: &str) {
        self.markers.push(norm(path));
    }

    /// Give a file a named data stream besides the download marker.
    pub fn add_stream(&mut self, path: &str) {
        self.streams.push(norm(path));
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
    fn extra_streams(&self, path: &str) -> Result<bool, String> {
        Ok(self.streams.contains(&self.resolve(path)))
    }

    fn named_streams(&self, path: &str) -> Result<bool, String> {
        let path = self.resolve(path);
        Ok(self.streams.contains(&path) || self.markers.contains(&path))
    }

    fn pin(&self, path: &str) -> Result<Pinned, String> {
        let key = self.resolve(path);
        let (kind, len, age) = match self.nodes.get(&key) {
            Some(FsNode::File { bytes, age }) => (ItemKind::File, bytes.len() as u64, *age),
            Some(FsNode::Dir) => (ItemKind::Dir, 0, None),
            Some(FsNode::Other) => return Err("refusing a reparse point".into()),
            None => return Err("file not found (os error 2)".into()),
        };
        Ok(Pinned {
            real_path: key.clone(),
            kind,
            len,
            links: self.links.get(&key).copied().unwrap_or(1),
            hidden_system: self.is_hidden_system(&key),
            age,
            handle: PinHandle::Memory(key),
        })
    }

    fn pin_acquire(&mut self, pin: &mut Pinned, access: Access) -> Result<(), String> {
        let key = self.pinned_key(pin)?.to_string();
        if !self.nodes.contains_key(&key) {
            return Err("file not found (os error 2)".into());
        }
        if access == Access::DeleteExclusive {
            if self.busy.contains(&key) {
                return Err("the file is being used by another process (os error 32)".into());
            }
            if self.written_since.contains(&key) {
                pin.age = Some(Duration::ZERO);
            }
        }
        Ok(())
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

    fn pin_create_confined(
        &mut self,
        path: &str,
        allowed: &dyn Fn(&dyn FileView, &str) -> bool,
    ) -> Result<Pinned, String> {
        let path = norm(path);
        let mut anchor = path.as_str();
        let mut rest: Vec<&str> = Vec::new();
        while !self.is_dir(anchor) {
            let Some((parent, name)) = anchor.rsplit_once('\\') else {
                return Err("refused: no part of its folder exists".into());
            };
            rest.push(name);
            anchor = parent;
        }
        let key = rest
            .iter()
            .rev()
            .fold(self.resolve(anchor), |path, part| format!(r"{path}\{part}"));
        if !allowed(self, &key) {
            return Err(format!("refused: it resolves to {key}"));
        }
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
            age: None,
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

/// Named data streams besides the main one and the download marker.
#[cfg(windows)]
pub(crate) fn host_extra_streams(path: &str) -> Result<bool, String> {
    host_streams(path, true)
}

/// Named data streams besides the main one; `allow_marker` also passes the
/// download marker (Zone.Identifier).
#[cfg(windows)]
fn host_streams(path: &str, allow_marker: bool) -> Result<bool, String> {
    use windows_sys::Win32::Foundation::{ERROR_HANDLE_EOF, GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard,
        WIN32_FIND_STREAM_DATA,
    };
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut data: WIN32_FIND_STREAM_DATA = unsafe { std::mem::zeroed() };
    let handle = unsafe {
        FindFirstStreamW(
            wide.as_ptr(),
            FindStreamInfoStandard,
            &mut data as *mut _ as *mut _,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return if unsafe { GetLastError() } == ERROR_HANDLE_EOF {
            Ok(false)
        } else {
            Err(std::io::Error::last_os_error().to_string())
        };
    }
    let mut extra = false;
    loop {
        let len = data
            .cStreamName
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(data.cStreamName.len());
        let name = String::from_utf16_lossy(&data.cStreamName[..len]).to_ascii_lowercase();
        if name != "::$data" && !(allow_marker && name == ":zone.identifier:$data") {
            extra = true;
            break;
        }
        if unsafe { FindNextStreamW(handle, &mut data as *mut _ as *mut _) } == 0 {
            if unsafe { GetLastError() } != ERROR_HANDLE_EOF {
                unsafe { FindClose(handle) };
                return Err(std::io::Error::last_os_error().to_string());
            }
            break;
        }
    }
    unsafe { FindClose(handle) };
    Ok(extra)
}

/// True when the open file has a named data stream besides the download
/// marker (Zone.Identifier), read through the handle.
#[cfg(windows)]
pub(crate) fn host_handle_streams(file: &std::fs::File) -> Result<bool, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_HANDLE_EOF, ERROR_MORE_DATA};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_STREAM_INFO, FileStreamInfo, GetFileInformationByHandleEx,
    };
    let mut buffer = vec![0u64; 512];
    loop {
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as _,
                FileStreamInfo,
                buffer.as_mut_ptr() as _,
                (buffer.len() * 8) as u32,
            )
        };
        if ok != 0 {
            break;
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error().map(|code| code as u32) {
            // No streams at all: nothing extra.
            Some(ERROR_HANDLE_EOF) => return Ok(false),
            Some(ERROR_MORE_DATA) if buffer.len() < 1 << 20 => {
                buffer.resize(buffer.len() * 4, 0);
            }
            _ => return Err(format!("could not list its data streams: {err}")),
        }
    }
    let base = buffer.as_ptr() as *const u8;
    let total = buffer.len() * 8;
    let head = std::mem::offset_of!(FILE_STREAM_INFO, StreamName);
    let mut offset = 0usize;
    loop {
        if offset + head > total {
            return Err("unreadable data stream list".into());
        }
        let entry = unsafe { &*(base.add(offset) as *const FILE_STREAM_INFO) };
        let bytes = entry.StreamNameLength as usize;
        if offset + head + bytes > total {
            return Err("unreadable data stream list".into());
        }
        let units: Vec<u16> = (0..bytes / 2)
            .map(|i| unsafe {
                std::ptr::read_unaligned(base.add(offset + head + i * 2) as *const u16)
            })
            .collect();
        let name = String::from_utf16_lossy(&units);
        if !name.eq_ignore_ascii_case("::$DATA")
            && !name.eq_ignore_ascii_case(":Zone.Identifier:$DATA")
        {
            return Ok(true);
        }
        if entry.NextEntryOffset == 0 {
            return Ok(false);
        }
        offset += entry.NextEntryOffset as usize;
    }
}

/// Open or create the child `name` of the held folder `dir`, relative to
/// that handle and never following a link (`NtCreateFile` with a root
/// directory and `FILE_OPEN_REPARSE_POINT`). `sddl` gives a new object its
/// security. Fails with the NT status.
#[cfg(windows)]
pub(crate) fn host_open_in(
    dir: &std::fs::File,
    name: &str,
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
    sddl: Option<&str>,
) -> Result<std::fs::File, i32> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::NtCreateFile;
    use windows_sys::Win32::Foundation::{HANDLE, LocalFree, UNICODE_STRING};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    const OBJ_CASE_INSENSITIVE: u32 = 0x40;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0020;
    const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    if name.is_empty() || name.contains(['\\', '/']) {
        return Err(-1);
    }
    let units: Vec<u16> = name.encode_utf16().collect();
    let bytes = (units.len() * 2) as u16;
    let object_name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: units.as_ptr() as _,
    };
    let mut sd: *mut core::ffi::c_void = std::ptr::null_mut();
    if let Some(sddl) = sddl {
        let text: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(-1);
        }
    }
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: dir.as_raw_handle() as HANDLE,
        ObjectName: &object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: sd as _,
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle: HANDLE = std::ptr::null_mut();
    let mut status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut status_block,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            options | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    if !sd.is_null() {
        unsafe { LocalFree(sd as _) };
    }
    if status < 0 {
        return Err(status);
    }
    Ok(unsafe { std::fs::File::from_raw_handle(handle as _) })
}

/// Mark an open file, or empty folder, to be deleted when its last handle
/// closes. The handle needs delete access.
#[cfg(windows)]
pub(crate) fn host_dispose(file: &std::fs::File) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as _,
            FileDispositionInfo,
            &info as *const _ as *const _,
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        ) != 0
    }
}

/// An NT status as the matching Windows error text.
#[cfg(windows)]
pub(crate) fn nt_status_text(status: i32) -> String {
    if status == -1 {
        return "invalid name".into();
    }
    let code = unsafe { windows_sys::Win32::Foundation::RtlNtStatusToDosError(status) };
    std::io::Error::from_raw_os_error(code as i32).to_string()
}

/// Where an open file really is, from its handle, as a drive path.
#[cfg(windows)]
pub(crate) fn host_final_path(file: &std::fs::File) -> Result<String, String> {
    host::final_path(file)
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
        if access == Access::DeleteExclusive {
            // Now that nothing else can write it, its age is final.
            pin.age = host::handle_age(&file);
        }
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

    fn pin_delete(&mut self, pin: Pinned) -> Result<(), String> {
        let PinHandle::Host(file) = pin.handle else {
            return Err("not a host handle".into());
        };
        host::delete(file, &pin.real_path)
    }

    fn named_streams(&self, path: &str) -> Result<bool, String> {
        #[cfg(windows)]
        {
            host_streams(path, false)
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            Ok(false)
        }
    }

    fn extra_streams(&self, path: &str) -> Result<bool, String> {
        #[cfg(windows)]
        {
            host_extra_streams(path)
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            Ok(false)
        }
    }

    fn pin_create_confined(
        &mut self,
        path: &str,
        allowed: &dyn Fn(&dyn FileView, &str) -> bool,
    ) -> Result<Pinned, String> {
        host::create_confined(path, &|real| allowed(&HostFs, real))
    }

    fn pin_copy_to(&mut self, pin: &Pinned, to: &str) -> Result<(), String> {
        use std::io::Write;
        let bytes = self
            .pin_read_at(pin, 0, copy_len(pin)?)
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
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SYSTEM, FILE_DISPOSITION_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FileDispositionInfo, GetDriveTypeW, GetFileInformationByHandle, GetFinalPathNameByHandleW,
        ReOpenFile, SetFileInformationByHandle, VOLUME_NAME_DOS,
    };

    const DELETE: u32 = 0x0001_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
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

    /// See [`super::FileView::pin_create_confined`]. The nearest existing
    /// folder is opened without following a link and held, without delete
    /// sharing, to the end: it cannot be renamed or replaced, nor can any
    /// folder above it while a handle inside is open. Its real path comes
    /// from that handle. Every new folder and the file are created
    /// (`FILE_CREATE`, never opening something already there) relative to
    /// the held handle of the folder above.
    pub fn create_confined(path: &str, allowed: &dyn Fn(&str) -> bool) -> Result<Pinned, String> {
        use crate::fs::{host_dispose, host_open_in, nt_status_text};
        const FILE_LIST_DIRECTORY: u32 = 0x0001;
        const FILE_ADD_FILE: u32 = 0x0002;
        const FILE_ADD_SUBDIRECTORY: u32 = 0x0004;
        const FILE_TRAVERSE: u32 = 0x0020;
        const FILE_READ_ATTRIBUTES: u32 = 0x0080;
        const FILE_CREATE: u32 = 2;
        const FILE_DIRECTORY_FILE: u32 = 0x0001;
        const FILE_NON_DIRECTORY_FILE: u32 = 0x0040;
        const FOLDER: u32 = FILE_LIST_DIRECTORY
            | FILE_ADD_FILE
            | FILE_ADD_SUBDIRECTORY
            | FILE_TRAVERSE
            | FILE_READ_ATTRIBUTES
            | SYNCHRONIZE;
        let path = path.trim_end_matches('\\');
        let mut anchor = path;
        let mut rest: Vec<&str> = Vec::new();
        let held = loop {
            let opened = std::fs::OpenOptions::new()
                .access_mode(FOLDER)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FLAGS)
                .open(anchor);
            match opened {
                Ok(file) => break file,
                Err(err) if matches!(err.raw_os_error(), Some(2 | 3)) => {
                    let Some((parent, name)) = anchor.rsplit_once('\\') else {
                        return Err("refused: no part of its folder exists".into());
                    };
                    if name.is_empty() || parent.is_empty() {
                        return Err("refused: no part of its folder exists".into());
                    }
                    rest.push(name);
                    anchor = parent;
                }
                Err(err) => return Err(format!("refused: {anchor}: {err}")),
            }
        };
        let Some(leaf) = rest.first().copied() else {
            return Err("target already exists".into());
        };
        let anchor_pin = identify(held, anchor).map_err(|err| format!("refused: {err}"))?;
        if anchor_pin.kind != ItemKind::Dir {
            return Err(format!("refused: {anchor} is not a folder"));
        }
        let projected = rest.iter().rev().fold(
            anchor_pin.real_path.trim_end_matches('\\').to_string(),
            |path, part| format!(r"{path}\{part}"),
        );
        if !allowed(&projected) {
            return Err(format!("refused: it resolves to {projected}"));
        }
        let PinHandle::Host(anchor_file) = &anchor_pin.handle else {
            return Err("not a host handle".into());
        };
        // Undo in reverse, each deleted and closed before its parent.
        let undo = |mut made: Vec<std::fs::File>| -> String {
            let mut left = 0;
            while let Some(item) = made.pop() {
                if !host_dispose(&item) {
                    left += 1;
                }
                drop(item);
            }
            if left == 0 {
                String::new()
            } else {
                format!(" ({left} new item(s) could not be removed again)")
            }
        };
        let mut made: Vec<std::fs::File> = Vec::new();
        for name in rest[1..].iter().rev() {
            let parent = made.last().unwrap_or(anchor_file);
            match host_open_in(
                parent,
                name,
                FOLDER | DELETE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_CREATE,
                FILE_DIRECTORY_FILE,
                None,
            ) {
                Ok(dir) => made.push(dir),
                Err(status) => {
                    let note = undo(made);
                    return Err(format!(
                        "could not create the folder {name}: {}{note}",
                        nt_status_text(status)
                    ));
                }
            }
        }
        let parent = made.last().unwrap_or(anchor_file);
        let file = match host_open_in(
            parent,
            leaf,
            GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
            FILE_SHARE_READ,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE,
            None,
        ) {
            Ok(file) => file,
            Err(status) => {
                let note = undo(made);
                return Err(format!(
                    "could not create {path}: {}{note}",
                    nt_status_text(status)
                ));
            }
        };
        // A second handle, so the file can still be removed if it cannot
        // be identified.
        let spare = file.try_clone().map_err(|err| err.to_string());
        let pin = identify(file, path).and_then(|pin| {
            if pin.real_path.eq_ignore_ascii_case(&projected) {
                Ok(pin)
            } else {
                Err(format!("it landed at {} instead", pin.real_path))
            }
        });
        match (pin, spare) {
            (Ok(pin), _) => {
                // The new folders stay; their handles close here.
                drop(made);
                drop(anchor_pin);
                Ok(pin)
            }
            (Err(err), spare) => {
                if let Ok(spare) = spare {
                    made.push(spare);
                }
                let note = undo(made);
                Err(format!("refused: {err}{note}"))
            }
        }
    }

    /// How long ago a FILETIME (100 ns ticks since 1601) was, if it is in
    /// the past.
    fn filetime_age(ticks: u64) -> Option<std::time::Duration> {
        const UNIX_OFFSET_SECS: u64 = 11_644_473_600;
        let micros = (ticks / 10).checked_sub(UNIX_OFFSET_SECS * 1_000_000)?;
        let when = std::time::UNIX_EPOCH + std::time::Duration::from_micros(micros);
        std::time::SystemTime::now().duration_since(when).ok()
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
            age: filetime_age(
                ((info.ftLastWriteTime.dwHighDateTime as u64) << 32)
                    | info.ftLastWriteTime.dwLowDateTime as u64,
            ),
            handle: PinHandle::Host(file),
        })
    }

    /// The handle's own path as Windows resolves it, as a plain `X:\...`
    /// path. A network or volume-GUID answer is refused.
    pub(crate) fn final_path(file: &std::fs::File) -> Result<String, String> {
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
            Access::ReadDelete => GENERIC_READ | DELETE | SYNCHRONIZE,
            Access::Delete | Access::DeleteExclusive => DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        };
        let share = if access == Access::DeleteExclusive {
            FILE_SHARE_READ
        } else {
            SHARE_ALL
        };
        if kind == ItemKind::Dir {
            // ReOpenFile refuses directory handles, so open the real path
            // again without following links and accept the new handle only
            // if it is the very object still held open by the pin.
            let again = std::fs::OpenOptions::new()
                .access_mode(wanted)
                .share_mode(share)
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
                share,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(last_error());
        }
        Ok(unsafe { std::fs::File::from_raw_handle(handle as _) })
    }

    /// How long ago the open file was last written.
    pub fn handle_age(file: &std::fs::File) -> Option<std::time::Duration> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) } == 0 {
            return None;
        }
        filetime_age(
            ((info.ftLastWriteTime.dwHighDateTime as u64) << 32)
                | info.ftLastWriteTime.dwLowDateTime as u64,
        )
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
            age: meta.modified().ok().and_then(|when| when.elapsed().ok()),
            handle: PinHandle::Host(file),
        })
    }

    pub fn create_confined(path: &str, allowed: &dyn Fn(&str) -> bool) -> Result<Pinned, String> {
        if !allowed(path) {
            return Err(format!("refused: it resolves to {path}"));
        }
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
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
            age: None,
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

    pub fn handle_age(file: &std::fs::File) -> Option<std::time::Duration> {
        file.metadata()
            .ok()
            .and_then(|meta| meta.modified().ok())
            .and_then(|when| when.elapsed().ok())
    }

    pub fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        file.read_at(buf, offset)
    }

    pub fn write_at(file: &std::fs::File, buf: &[u8], offset: u64) -> std::io::Result<usize> {
        file.write_at(buf, offset)
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
    fn live_extra_data_streams_are_seen_and_the_download_marker_is_not() {
        let path = std::env::temp_dir().join(format!("hm-streams-{}.lnk", std::process::id()));
        let text = path.display().to_string();
        std::fs::write(&path, b"lnk").unwrap();
        let plain = host_extra_streams(&text);
        std::fs::write(
            format!("{text}:Zone.Identifier"),
            b"[ZoneTransfer]\r\nZoneId=3",
        )
        .unwrap();
        let marked = host_extra_streams(&text);
        let marked_named = HostFs.named_streams(&text);
        std::fs::write(format!("{text}:notes"), b"hidden").unwrap();
        let extra = host_extra_streams(&text);
        let _ = std::fs::remove_file(&path);
        assert_eq!(plain, Ok(false));
        assert_eq!(marked, Ok(false));
        // Repair's stricter rule counts the marker: a copy would lose it.
        assert_eq!(marked_named, Ok(true));
        assert_eq!(extra, Ok(true));
    }

    #[test]
    fn live_a_pinned_file_reports_its_age_from_the_handle() {
        let path = std::env::temp_dir().join(format!("hm-age-{}.tmp", std::process::id()));
        std::fs::write(&path, b"x").unwrap();
        let pin = HostFs.pin(&path.display().to_string()).expect("pin");
        let age = pin.age.expect("an age");
        drop(pin);
        let _ = std::fs::remove_file(&path);
        assert!(
            age < Duration::from_secs(120),
            "a new file looked {age:?} old"
        );
    }

    #[test]
    fn live_exclusive_delete_refuses_an_open_writer_and_rereads_the_age() {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let old = std::time::SystemTime::now() - Duration::from_secs(3 * 24 * 3600);
        let busy = dir.join(format!("hm-excl-busy-{pid}.tmp"));
        let written = dir.join(format!("hm-excl-written-{pid}.tmp"));
        for path in [&busy, &written] {
            let file = std::fs::File::create(path).unwrap();
            file.set_modified(old).unwrap();
        }
        let mut fs = HostFs;
        // Another program has it open for writing: exclusive access fails.
        let writer = std::fs::OpenOptions::new().write(true).open(&busy).unwrap();
        let mut pin = fs.pin(&busy.display().to_string()).expect("pin");
        let refused = fs.pin_acquire(&mut pin, Access::DeleteExclusive);
        drop(pin);
        drop(writer);
        // Old when pinned, written before the exclusive open: the age is new.
        let mut pin = fs.pin(&written.display().to_string()).expect("pin");
        let pinned_age = pin.age;
        std::fs::write(&written, b"new").unwrap();
        let taken = fs.pin_acquire(&mut pin, Access::DeleteExclusive);
        let fresh_age = pin.age;
        // Held exclusively, nobody else can open it to write.
        let blocked = std::fs::OpenOptions::new().write(true).open(&written);
        drop(pin);
        let _ = std::fs::remove_file(&busy);
        let _ = std::fs::remove_file(&written);
        let err = refused.expect_err("an open writer was not noticed");
        assert!(err.contains("os error 32"), "{err}");
        assert!(pinned_age.unwrap() > Duration::from_secs(2 * 24 * 3600));
        taken.expect("exclusive open");
        assert!(
            fresh_age.unwrap() < Duration::from_secs(120),
            "{fresh_age:?}"
        );
        assert!(blocked.is_err(), "a writer got in while it was held");
    }

    #[test]
    fn live_new_folders_land_only_where_they_were_checked() {
        let base = std::env::temp_dir().join(format!("hm-confined-{}", std::process::id()));
        let place = base.join("place");
        let outside = base.join("outside");
        std::fs::create_dir_all(&place).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let target = place.join("new1").join("new2").join("x.lnk");
        let swaps = std::cell::RefCell::new(Vec::new());
        let asked = std::cell::RefCell::new(String::new());
        let made = HostFs.pin_create_confined(&target.display().to_string(), &|_, real| {
            // After the check: move the folder (or the one above it) away
            // and put a junction to `outside` in its place.
            let moved = std::fs::rename(&place, base.join("place-old")).is_ok();
            let above = std::fs::rename(&base, base.with_extension("old")).is_ok();
            if moved {
                let _ = std::process::Command::new("cmd")
                    .args(["/C", "mklink", "/J"])
                    .arg(&place)
                    .arg(&outside)
                    .output();
            }
            swaps.borrow_mut().extend([moved, above]);
            *asked.borrow_mut() = real.to_string();
            true
        });
        let real = made
            .as_ref()
            .map(|pin| pin.real_path.clone())
            .map_err(String::clone);
        drop(made);
        let outside_entries = std::fs::read_dir(&outside)
            .map(|dir| dir.count())
            .unwrap_or(0);
        // Refused: nothing at all is made.
        let refused_target = place.join("other").join("deeper").join("y.lnk");
        let refused =
            HostFs.pin_create_confined(&refused_target.display().to_string(), &|_, _| false);
        let other_made = place.join("other").exists();
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(base.with_extension("old"));
        assert_eq!(*swaps.borrow(), [false, false], "a held folder moved");
        let real = real.expect("created");
        assert!(
            real.eq_ignore_ascii_case(&asked.borrow()),
            "{real} vs {}",
            asked.borrow()
        );
        assert!(real.ends_with(r"place\new1\new2\x.lnk"), "{real}");
        assert_eq!(outside_entries, 0, "something landed outside");
        assert!(refused.is_err());
        assert!(!other_made, "a refused creation made a folder");
    }

    #[test]
    fn live_a_junction_on_the_way_is_judged_by_where_it_leads() {
        let base = std::env::temp_dir().join(format!("hm-confined-j-{}", std::process::id()));
        let outside = base.join("outside");
        std::fs::create_dir_all(outside.join("sub")).unwrap();
        let link = base.join("j");
        let linked = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .output()
            .expect("run mklink");
        // Through the junction to a folder that exists: judged by its real
        // path, and refused here, so nothing is made.
        let through = link.join("sub").join("new").join("x.lnk");
        let asked = std::cell::RefCell::new(String::new());
        let refused = HostFs.pin_create_confined(&through.display().to_string(), &|_, real| {
            *asked.borrow_mut() = real.to_string();
            false
        });
        // The junction itself as the nearest folder: never used.
        let at_link = link.join("missing").join("x.lnk");
        let at_link_result =
            HostFs.pin_create_confined(&at_link.display().to_string(), &|_, _| true);
        let leaked = outside.join("sub").join("new").exists() || outside.join("missing").exists();
        let _ = std::fs::remove_dir_all(&base);
        assert!(linked.status.success());
        assert!(refused.is_err());
        assert!(
            asked.borrow().contains(r"outside\sub\new\x.lnk"),
            "{}",
            asked.borrow()
        );
        let err = at_link_result.err().unwrap_or_default();
        assert!(err.contains("link or junction"), "{err}");
        assert!(!leaked, "something was made through the junction");
    }

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

    #[test]
    fn live_a_file_swapped_after_pinning_is_not_the_one_deleted() {
        let dir = std::env::temp_dir().join(format!("hivemend-swap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("target.tmp");
        let moved = dir.join("moved.tmp");
        std::fs::write(&path, b"pinned").unwrap();
        let mut fs = HostFs;
        let mut pin = fs.pin(&path.display().to_string()).expect("pin");
        fs.pin_acquire(&mut pin, Access::Delete)
            .expect("delete access");
        // Swap: the pinned file moves away and a decoy takes its name.
        std::fs::rename(&path, &moved).expect("move pinned file");
        std::fs::write(&path, b"decoy").unwrap();
        fs.pin_delete(pin).expect("delete through the pin");
        let moved_gone = !moved.exists();
        let decoy = std::fs::read(&path).ok();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(moved_gone, "the pinned object itself is deleted");
        assert_eq!(decoy, Some(b"decoy".to_vec()), "the decoy is untouched");
    }
}
