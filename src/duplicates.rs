//! Duplicate file finder: files with the same size and the same content.
//!
//! Finding only reads. Removing is checked again file by file just before
//! it happens: one copy of every set is always kept, protected folders are
//! refused, and a file is only removed when its bytes still match the kept
//! copy and it is not the same file reached by another name (a hard link).
//! Both files are held open from the check to the move, and everything
//! after opening them goes through those handles, so the file moved is
//! the file that was compared. Removed files go to the Recycle Bin.

use std::collections::BTreeMap;

use crate::diskspace::{DirLister, DiskEntry};
use crate::pathutil::{has_unsafe_fs_component, path_under};

/// A file's identity: volume serial number and file index.
pub type FileId = (u64, u64);

/// Reads file contents for comparing.
pub trait ContentReader {
    /// The file's identity, length, and a 128-bit hash of its first
    /// `limit` bytes (all of it when `None`).
    fn fingerprint(&self, path: &str, limit: Option<u64>) -> Result<(FileId, u64, u128), String>;
    /// True when both held files hold exactly the same bytes, read
    /// through their handles.
    fn same_content(&self, a: &Held, b: &Held) -> Result<bool, String>;
    /// Hold the file open: while the result lives, no other program can
    /// write to, delete, or rename it. A file to remove (`keep` false) is
    /// held with the right to move it, so it can go by that same handle.
    fn hold(&self, path: &str, keep: bool) -> Result<Held, String>;
}

/// A file held open by [`ContentReader::hold`], with what was learned
/// through its handle.
pub struct Held {
    /// Where the file really is, from the open handle.
    pub real_path: String,
    /// It has named data streams besides the download marker
    /// (Zone.Identifier), which a byte compare does not cover.
    pub extra_streams: bool,
    /// Identity and length, from the handle.
    pub id: FileId,
    pub len: u64,
    guard: Box<dyn std::any::Any>,
}

impl Held {
    pub fn new(
        real_path: String,
        extra_streams: bool,
        id: FileId,
        len: u64,
        guard: Box<dyn std::any::Any>,
    ) -> Self {
        Self {
            real_path,
            extra_streams,
            id,
            len,
            guard,
        }
    }

    /// What holds it open (an open file, on the host).
    pub fn guard<T: 'static>(&self) -> Option<&T> {
        self.guard.downcast_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DupGroup {
    /// Size of each copy.
    pub bytes: u64,
    pub files: Vec<String>,
}

impl DupGroup {
    /// Space freed by keeping one copy.
    pub fn extra(&self) -> u64 {
        self.bytes * (self.files.len() as u64).saturating_sub(1)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DupReport {
    pub root: String,
    /// Largest saving first.
    pub groups: Vec<DupGroup>,
    pub files_seen: u64,
    pub unreadable: u64,
    pub canceled: bool,
    /// The search stopped at [`MAX_CANDIDATES`] files or
    /// [`crate::diskspace::MAX_FOLDERS`] folders: only part of it was searched.
    pub incomplete: bool,
}

/// How many leading bytes are compared before reading whole files.
const PREFIX: u64 = 64 * 1024;

/// The most files one search keeps as possible copies (about 200 MB of
/// paths at most); past it the search compares what it has and says it is
/// incomplete.
pub const MAX_CANDIDATES: usize = 1_000_000;

/// Folder names never searched: Windows' own bookkeeping.
const SKIPPED_DIRS: [&str; 2] = ["$Recycle.Bin", "System Volume Information"];

/// Find sets of identical files of at least `min_bytes` under `root`,
/// leaving out the `protected` folders. `progress(text, done, total)`
/// returns false to stop; `total` is 0 while folders are still being read.
pub fn find_duplicates(
    lister: &dyn DirLister,
    reader: &dyn ContentReader,
    root: &str,
    min_bytes: u64,
    protected: &[String],
    progress: &mut dyn FnMut(&str, usize, usize) -> bool,
) -> DupReport {
    find_within(
        lister,
        reader,
        root,
        min_bytes,
        protected,
        (MAX_CANDIDATES, crate::diskspace::MAX_FOLDERS),
        progress,
    )
}

fn find_within(
    lister: &dyn DirLister,
    reader: &dyn ContentReader,
    root: &str,
    min_bytes: u64,
    protected: &[String],
    (max_candidates, max_folders): (usize, usize),
    progress: &mut dyn FnMut(&str, usize, usize) -> bool,
) -> DupReport {
    let root = root.trim_end_matches('\\').to_string();
    let mut report = DupReport {
        root: root.clone(),
        ..DupReport::default()
    };
    let mut by_size: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    let mut kept = 0usize;
    let mut folders = 1usize;
    let mut pending = vec![root];
    while let Some(dir) = pending.pop() {
        let text = |seen: u64| format!("Looking at {seen} files. Reading {dir}");
        if !progress(&text(report.files_seen), 0, 0) {
            report.canceled = true;
            return report;
        }
        let mut listed = 0u64;
        let mut visit = |entry: DiskEntry| -> bool {
            listed += 1;
            if listed.is_multiple_of(crate::diskspace::CHECK_EVERY)
                && !progress(&text(report.files_seen), 0, 0)
            {
                report.canceled = true;
                return false;
            }
            if entry.name == "." || entry.name == ".." || entry.name.is_empty() || entry.link {
                // Links, junctions, and cloud placeholders (reparse points)
                // are never followed or read.
                return true;
            }
            let path = format!("{dir}\\{}", entry.name);
            if entry.dir {
                let skipped = SKIPPED_DIRS
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(&entry.name))
                    || protected.iter().any(|root| path_under(&path, root));
                if !skipped {
                    if folders >= max_folders {
                        report.incomplete = true;
                        return false;
                    }
                    folders += 1;
                    pending.push(path);
                }
            } else {
                report.files_seen += 1;
                if entry.bytes >= min_bytes.max(1) {
                    if kept >= max_candidates {
                        report.incomplete = true;
                        return false;
                    }
                    kept += 1;
                    by_size.entry(entry.bytes).or_default().push(path);
                }
            }
            true
        };
        if lister.list(&format!("{dir}\\"), &mut visit).is_err() {
            report.unreadable += 1;
        }
        if report.canceled {
            return report;
        }
        if report.incomplete {
            break;
        }
    }
    let candidates: Vec<(u64, Vec<String>)> = by_size
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .collect();
    let total: usize = candidates.iter().map(|(_, paths)| paths.len()).sum();
    let mut done = 0usize;
    for (bytes, paths) in candidates {
        // First the leading bytes, then whole files for what still matches.
        let mut by_prefix: BTreeMap<u128, Vec<String>> = BTreeMap::new();
        let mut seen_ids: Vec<FileId> = Vec::new();
        for path in paths {
            done += 1;
            if !progress(
                &format!("Comparing files ({done} of {total})..."),
                done,
                total,
            ) {
                report.canceled = true;
                break;
            }
            match reader.fingerprint(&path, Some(PREFIX)) {
                // A second name for a file already seen is not a copy.
                Ok((id, len, _)) if seen_ids.contains(&id) || len != bytes => {}
                Ok((id, _, hash)) => {
                    seen_ids.push(id);
                    by_prefix.entry(hash).or_default().push(path);
                }
                Err(_) => report.unreadable += 1,
            }
        }
        for (_, same_start) in by_prefix {
            if same_start.len() < 2 {
                continue;
            }
            if bytes <= PREFIX {
                report.groups.push(DupGroup {
                    bytes,
                    files: same_start,
                });
                continue;
            }
            let mut by_full: BTreeMap<u128, Vec<String>> = BTreeMap::new();
            for path in same_start {
                if !progress(
                    &format!("Comparing files ({done} of {total})..."),
                    done,
                    total,
                ) {
                    report.canceled = true;
                    break;
                }
                match reader.fingerprint(&path, None) {
                    Ok((_, len, hash)) if len == bytes => {
                        by_full.entry(hash).or_default().push(path)
                    }
                    Ok(_) => {}
                    Err(_) => report.unreadable += 1,
                }
            }
            for (_, files) in by_full {
                if files.len() > 1 {
                    report.groups.push(DupGroup { bytes, files });
                }
            }
        }
        if report.canceled {
            break;
        }
    }
    for group in &mut report.groups {
        group.files.sort_by_key(|path| path.to_lowercase());
    }
    report
        .groups
        .sort_by(|a, b| b.extra().cmp(&a.extra()).then(a.files.cmp(&b.files)));
    report
}

/// Remove `remove` (indexes into the set's files) with `recycle`, checking
/// each file just before: a copy of the set is kept and held open (so it
/// cannot change or go away meanwhile), each file to remove is held open
/// against writes, renames and deletes from its check until `recycle` moves
/// it by that handle, its real location must be outside the protected
/// folders, it must not be the kept copy under another name, it must have
/// no extra data streams, and its bytes, read through both handles, must
/// still match the kept copy. Returns each path with what happened.
pub fn remove_checked(
    reader: &dyn ContentReader,
    group: &DupGroup,
    remove: &[usize],
    protected: &[String],
    recycle: &mut dyn FnMut(&str, &Held) -> Result<(), String>,
) -> Vec<(String, Result<(), String>)> {
    let kept: Vec<&String> = group
        .files
        .iter()
        .enumerate()
        .filter(|(index, _)| !remove.contains(index))
        .map(|(_, path)| path)
        .collect();
    // The first kept copy that can be held and still has the set's size;
    // it stays held until every file of the set is done.
    let keeper = kept.iter().find_map(|path| {
        let held = reader.hold(path, true).ok()?;
        (held.len == group.bytes).then_some(held)
    });
    let mut out = Vec::new();
    for index in remove {
        let Some(path) = group.files.get(*index) else {
            continue;
        };
        let verdict = (|| {
            let keeper = keeper
                .as_ref()
                .ok_or("no copy of this set is being kept, or the kept copy changed")?;
            let bytes = path.as_bytes();
            let plain = bytes.len() > 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && bytes[2] == b'\\'
                && !has_unsafe_fs_component(path)
                && !path.contains('/');
            if !plain {
                return Err("not a plain local path".to_string());
            }
            if protected.iter().any(|root| path_under(path, root)) {
                return Err("inside a protected Windows or program folder".to_string());
            }
            let held = reader.hold(path, false)?;
            // The spelling can hide where it is (a SUBST drive, a junction
            // in a parent folder): check the real location too.
            if protected
                .iter()
                .any(|root| path_under(&held.real_path, root))
            {
                return Err(format!(
                    "it is really in a protected folder ({})",
                    held.real_path
                ));
            }
            if held.extra_streams {
                return Err("it has extra data streams a byte compare does not cover".to_string());
            }
            if held.id == keeper.id {
                return Err("it is the kept copy under another name (a hard link)".to_string());
            }
            if held.len != group.bytes {
                return Err("it changed since the search".to_string());
            }
            if !reader.same_content(keeper, &held)? {
                return Err("its contents no longer match the kept copy".to_string());
            }
            // Still held against writes and renames: what was compared is
            // what goes, moved by this handle.
            recycle(path, &held)
        })();
        out.push((path.clone(), verdict));
    }
    out
}

/// The host's files, read through a handle that does not follow links.
/// When `stop` is set, reading a large file gives up between chunks once
/// it turns true, so Cancel does not wait for a whole file.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HostContent {
    pub stop: Option<&'static std::sync::atomic::AtomicBool>,
}

#[cfg(windows)]
impl HostContent {
    fn stopped(&self) -> Result<(), String> {
        match self.stop {
            Some(flag) if flag.load(std::sync::atomic::Ordering::SeqCst) => Err("stopped".into()),
            _ => Ok(()),
        }
    }
}

#[cfg(windows)]
fn open_plain(path: &str) -> Result<(std::fs::File, FileId, u64), String> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)
        .map_err(|err| err.to_string())?;
    let (id, len) = check_plain(&file)?;
    Ok((file, id, len))
}

/// Identity and length of an open file, refusing links, folders, and cloud
/// placeholders.
#[cfg(windows)]
fn check_plain(file: &std::fs::File) -> Result<(FileId, u64), String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_REPARSE_POINT, GetFileInformationByHandle,
    };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let odd = FILE_ATTRIBUTE_DIRECTORY
        | FILE_ATTRIBUTE_REPARSE_POINT
        | FILE_ATTRIBUTE_RECALL_ON_OPEN
        | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
    if info.dwFileAttributes & odd != 0 {
        return Err("a link, folder, or cloud placeholder".into());
    }
    let id = (
        u64::from(info.dwVolumeSerialNumber),
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    );
    let len = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
    Ok((id, len))
}

#[cfg(windows)]
impl ContentReader for HostContent {
    fn hold(&self, path: &str, keep: bool) -> Result<Held, String> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Foundation::GENERIC_READ;
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, SYNCHRONIZE,
        };
        // Only reading is shared: nothing can write, rename, or delete it
        // while held. A file to remove is also opened with delete access,
        // which is what moves it to the Recycle Bin by this handle.
        let access = if keep {
            GENERIC_READ | SYNCHRONIZE
        } else {
            GENERIC_READ | DELETE | SYNCHRONIZE
        };
        let file = std::fs::OpenOptions::new()
            .access_mode(access)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|err| err.to_string())?;
        let (id, len) = check_plain(&file)?;
        let real_path = crate::fs::host_final_path(&file)?;
        let extra_streams = crate::fs::host_handle_streams(&file)?;
        Ok(Held::new(real_path, extra_streams, id, len, Box::new(file)))
    }

    fn fingerprint(&self, path: &str, limit: Option<u64>) -> Result<(FileId, u64, u128), String> {
        use std::hash::Hasher;
        use std::io::Read;
        let (file, id, len) = open_plain(path)?;
        let mut first = std::hash::DefaultHasher::new();
        let mut second = std::hash::DefaultHasher::new();
        second.write_u64(0x6869_7665_6d65_6e64);
        let mut reader = file.take(limit.unwrap_or(u64::MAX));
        let mut buffer = vec![0u8; 1 << 20];
        loop {
            self.stopped()?;
            let read = reader.read(&mut buffer).map_err(|err| err.to_string())?;
            if read == 0 {
                break;
            }
            first.write(&buffer[..read]);
            second.write(&buffer[..read]);
        }
        let hash = (u128::from(first.finish()) << 64) | u128::from(second.finish());
        Ok((id, len, hash))
    }

    fn same_content(&self, a: &Held, b: &Held) -> Result<bool, String> {
        use std::os::windows::fs::FileExt;
        let (Some(left), Some(right)) = (a.guard::<std::fs::File>(), b.guard::<std::fs::File>())
        else {
            return Err("not held by Hivemend".into());
        };
        let (_, left_len) = check_plain(left)?;
        let (_, right_len) = check_plain(right)?;
        if left_len != right_len {
            return Ok(false);
        }
        let mut one = vec![0u8; 1 << 20];
        let mut two = vec![0u8; 1 << 20];
        let mut offset = 0u64;
        // Read at explicit offsets, so it never depends on where an
        // earlier read left either handle.
        let fill = |file: &std::fs::File, buf: &mut [u8], at: u64| -> Result<usize, String> {
            let mut got = 0;
            while got < buf.len() {
                let read = file
                    .seek_read(&mut buf[got..], at + got as u64)
                    .map_err(|err| err.to_string())?;
                if read == 0 {
                    break;
                }
                got += read;
            }
            Ok(got)
        };
        while offset < left_len {
            self.stopped()?;
            let want = ((left_len - offset) as usize).min(one.len());
            if fill(left, &mut one[..want], offset)? != want
                || fill(right, &mut two[..want], offset)? != want
            {
                return Ok(false);
            }
            if one[..want] != two[..want] {
                return Ok(false);
            }
            offset += want as u64;
        }
        Ok(true)
    }
}

/// Move a held file to this account's Recycle Bin by its handle. A file
/// that cannot go there that way (a drive without a Recycle Bin) is left
/// where it is; nothing is ever deleted for good.
#[cfg(windows)]
pub fn recycle(held: &Held) -> Result<(), String> {
    let file = held
        .guard::<std::fs::File>()
        .ok_or("not held by Hivemend")?;
    crate::recycle::recycle_held(file).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Default)]
    struct World {
        dirs: BTreeMap<String, Vec<DiskEntry>>,
        /// path -> (id, content)
        files: RefCell<HashMap<String, (FileId, Vec<u8>)>>,
        /// alias prefix -> real prefix (a SUBST drive, a junction).
        aliases: Vec<(String, String)>,
        /// Files with extra data streams.
        streams: Vec<String>,
    }

    impl World {
        fn dir(&mut self, parent: &str, name: &str, link: bool) {
            self.dirs
                .entry(format!("{parent}\\"))
                .or_default()
                .push(DiskEntry {
                    name: name.into(),
                    dir: true,
                    link,
                    bytes: 0,
                });
            self.dirs.entry(format!("{parent}\\{name}\\")).or_default();
        }
        fn file(&mut self, dir: &str, name: &str, id: u64, content: &[u8]) {
            self.dirs
                .entry(format!("{dir}\\"))
                .or_default()
                .push(DiskEntry {
                    name: name.into(),
                    dir: false,
                    link: false,
                    bytes: content.len() as u64,
                });
            self.files
                .borrow_mut()
                .insert(format!("{dir}\\{name}"), ((1, id), content.to_vec()));
        }
    }

    impl DirLister for World {
        fn list(
            &self,
            dir: &str,
            visit: &mut dyn FnMut(DiskEntry) -> bool,
        ) -> Result<bool, String> {
            let entries = self.dirs.get(dir).ok_or("denied")?;
            Ok(entries.iter().cloned().all(visit))
        }
    }

    impl ContentReader for World {
        fn fingerprint(
            &self,
            path: &str,
            limit: Option<u64>,
        ) -> Result<(FileId, u64, u128), String> {
            let files = self.files.borrow();
            let (id, content) = files.get(path).ok_or("missing")?;
            let take = limit.map_or(content.len(), |limit| content.len().min(limit as usize));
            let mut hash = 0u128;
            for byte in &content[..take] {
                hash = hash.wrapping_mul(31).wrapping_add(u128::from(*byte));
            }
            Ok((*id, content.len() as u64, hash))
        }
        fn same_content(&self, a: &Held, b: &Held) -> Result<bool, String> {
            let files = self.files.borrow();
            let content = |held: &Held| {
                let path = held.guard::<String>().ok_or("not held")?;
                files.get(path).map(|(_, content)| content).ok_or("missing")
            };
            Ok(content(a)? == content(b)?)
        }
        fn hold(&self, path: &str, _keep: bool) -> Result<Held, String> {
            if !self.files.borrow().contains_key(path) {
                return Err("missing".into());
            }
            let real = self
                .aliases
                .iter()
                .find_map(|(alias, real)| {
                    path.strip_prefix(alias.as_str())
                        .map(|rest| format!("{real}{rest}"))
                })
                .unwrap_or_else(|| path.to_string());
            let (id, content) = self.files.borrow()[path].clone();
            Ok(Held::new(
                real,
                self.streams.contains(&path.to_string()),
                id,
                content.len() as u64,
                Box::new(path.to_string()),
            ))
        }
    }

    /// Each path with what happened to it.
    type Results = Vec<(String, Result<(), String>)>;

    /// Remove with a recorder in place of the Recycle Bin.
    fn remove(world: &World, group: &DupGroup, remove: &[usize]) -> (Results, Vec<String>) {
        let mut moved = Vec::new();
        let results = remove_checked(world, group, remove, &protected(), &mut |path, held| {
            assert_eq!(held.guard::<String>().map(String::as_str), Some(path));
            moved.push(path.to_string());
            Ok(())
        });
        (results, moved)
    }

    fn world() -> World {
        let mut world = World::default();
        world.dir("C:", "Users", false);
        world.dir("C:", "Windows", false);
        world.dir(r"C:\Users", "Shortcut", true);
        world.file(r"C:\Users", "a.jpg", 1, b"photo-one");
        world.file(r"C:\Users", "b.jpg", 2, b"photo-one");
        world.file(r"C:\Users", "c.jpg", 3, b"photo-two");
        // Same name, other content.
        world.file(r"C:\Users", "d.jpg", 4, b"photo-xxx");
        // A hard link: a second name for file 1.
        world.file(r"C:\Users", "link.jpg", 1, b"photo-one");
        // Protected copies are never offered.
        world.file(r"C:\Windows", "a.jpg", 9, b"photo-one");
        world.file(r"C:\Users", "tiny", 5, b"x");
        world.file(r"C:\Users", "tiny2", 6, b"x");
        world
    }

    fn protected() -> Vec<String> {
        vec![r"C:\Windows".to_string()]
    }

    /// One folder of `files` same-sized files, made up as it is listed.
    struct Many {
        files: u64,
    }

    impl DirLister for Many {
        fn list(
            &self,
            dir: &str,
            visit: &mut dyn FnMut(DiskEntry) -> bool,
        ) -> Result<bool, String> {
            if dir != "C:\\" {
                return Ok(true);
            }
            for index in 0..self.files {
                let entry = DiskEntry {
                    name: format!("f{index}.bin"),
                    dir: false,
                    link: false,
                    bytes: 10,
                };
                if !visit(entry) {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }

    #[test]
    fn cancel_works_inside_one_huge_folder() {
        let many = Many { files: 50_000_000 };
        let mut seen = 0;
        let report = find_duplicates(&many, &world(), "C:", 2, &[], &mut |text, _, _| {
            seen += 1;
            !text.starts_with("Looking at 1") || text.starts_with("Looking at 1 ")
        });
        assert!(report.canceled);
        assert!(report.files_seen < 20_000, "{}", report.files_seen);
        assert!(seen > 1);
    }

    #[test]
    fn a_search_past_its_limits_compares_what_it_has_and_says_so() {
        let mut world = world();
        for index in 0..50u64 {
            world.file(r"C:\Users", &format!("more{index}.bin"), 100 + index, b"zz");
        }
        let few = find_within(
            &world,
            &world,
            r"C:\",
            2,
            &protected(),
            (10, 1000),
            &mut |_, _, _| true,
        );
        assert!(few.incomplete);
        assert!(!few.canceled);
        let shallow = find_within(
            &world,
            &world,
            r"C:\",
            2,
            &protected(),
            (1000, 1),
            &mut |_, _, _| true,
        );
        assert!(shallow.incomplete);
        let full = find_duplicates(&world, &world, r"C:\", 2, &protected(), &mut |_, _, _| true);
        assert!(!full.incomplete);
    }

    #[test]
    fn finds_copies_by_content_not_name_or_link() {
        let world = world();
        let report = find_duplicates(&world, &world, r"C:\", 2, &protected(), &mut |_, _, _| true);
        assert_eq!(
            report.groups,
            [DupGroup {
                bytes: 9,
                files: vec![r"C:\Users\a.jpg".into(), r"C:\Users\b.jpg".into()],
            }]
        );
        assert_eq!(report.groups[0].extra(), 9);
    }

    #[test]
    fn removal_keeps_a_copy_and_rechecks_contents() {
        let world = world();
        let group = DupGroup {
            bytes: 9,
            files: vec![r"C:\Users\a.jpg".into(), r"C:\Users\b.jpg".into()],
        };
        let (ok, moved) = remove(&world, &group, &[1]);
        assert!(ok[0].1.is_ok());
        assert_eq!(moved, [r"C:\Users\b.jpg"]);
        // Removing every copy is refused: nothing is kept, nothing moves.
        let (all, moved) = remove(&world, &group, &[0, 1]);
        assert!(all.iter().all(|(_, verdict)| verdict.is_err()));
        assert!(moved.is_empty());
        // A copy that changed since the search stays.
        world
            .files
            .borrow_mut()
            .get_mut(r"C:\Users\b.jpg")
            .unwrap()
            .1 = b"photo-new".to_vec();
        let (changed, moved) = remove(&world, &group, &[1]);
        assert!(changed[0].1.is_err());
        assert!(moved.is_empty());
        // A hard link to the kept file is not a copy.
        let linked = DupGroup {
            bytes: 9,
            files: vec![r"C:\Users\a.jpg".into(), r"C:\Users\link.jpg".into()],
        };
        assert!(remove(&world, &linked, &[1]).0[0].1.is_err());
        // Protected folders are refused even if offered.
        let inside = DupGroup {
            bytes: 9,
            files: vec![r"C:\Users\a.jpg".into(), r"C:\Windows\a.jpg".into()],
        };
        assert!(remove(&world, &inside, &[1]).0[0].1.is_err());
    }

    #[test]
    fn a_protected_folder_reached_another_way_is_refused() {
        let mut world = world();
        // X: is a SUBST drive for the Windows folder.
        world.aliases.push((r"X:".into(), r"C:\Windows".into()));
        world.file("X:", "a.jpg", 9, b"photo-one");
        let group = DupGroup {
            bytes: 9,
            files: vec![r"C:\Users\a.jpg".into(), r"X:\a.jpg".into()],
        };
        let (results, moved) = remove(&world, &group, &[1]);
        assert!(
            results[0]
                .1
                .as_ref()
                .is_err_and(|why| why.contains("really")),
            "{results:?}"
        );
        assert!(moved.is_empty());
    }

    #[test]
    fn a_file_with_extra_data_streams_is_not_a_plain_copy() {
        let mut world = world();
        world.streams.push(r"C:\Users\b.jpg".into());
        let group = DupGroup {
            bytes: 9,
            files: vec![r"C:\Users\a.jpg".into(), r"C:\Users\b.jpg".into()],
        };
        let (results, moved) = remove(&world, &group, &[1]);
        assert!(
            results[0]
                .1
                .as_ref()
                .is_err_and(|why| why.contains("streams"))
        );
        assert!(moved.is_empty());
    }
}

/// Live Windows test: a real Recycle Bin move of a temporary file, which it
/// then removes again.
#[cfg(all(test, windows))]
mod live_tests {
    use super::*;

    fn forget_recycled(item: &str) {
        let _ = std::fs::remove_file(item);
        if let Some((dir, name)) = item.rsplit_once('\\')
            && let Some(rest) = name.strip_prefix("$R")
        {
            let _ = std::fs::remove_file(format!("{dir}\\$I{rest}"));
        }
    }

    #[test]
    fn live_only_the_checked_copy_reaches_the_recycle_bin() {
        let base = std::env::temp_dir().join(format!("hm-dup-live-{}", std::process::id()));
        let dir = base.join("set");
        std::fs::create_dir_all(&dir).unwrap();
        let keep = dir.join("keep.bin");
        let cand = dir.join("cand.bin");
        std::fs::write(&keep, b"same bytes").unwrap();
        std::fs::write(&cand, b"same bytes").unwrap();
        let group = DupGroup {
            bytes: 10,
            files: vec![keep.display().to_string(), cand.display().to_string()],
        };
        let mut swaps = Vec::new();
        let mut landed = None;
        let mut replaced = false;
        let results = remove_checked(
            &HostContent::default(),
            &group,
            &[1],
            &[],
            &mut |path, held| {
                // Between the check and the move, nothing may change or
                // swap out either file.
                let write =
                    |at: &std::path::Path| std::fs::OpenOptions::new().write(true).open(at).is_ok();
                swaps.push((
                    "rename it",
                    std::fs::rename(path, dir.join("x.bin")).is_ok(),
                ));
                swaps.push(("delete it", std::fs::remove_file(path).is_ok()));
                swaps.push(("write it", write(std::path::Path::new(path))));
                swaps.push(("delete the keeper", std::fs::remove_file(&keep).is_ok()));
                swaps.push(("write the keeper", write(&keep)));
                // A folder rename with a stand-in left at the old path must
                // not change which file moves.
                if std::fs::rename(&dir, base.join("set-moved")).is_ok() {
                    std::fs::create_dir(&dir).unwrap();
                    std::fs::write(&cand, b"stand in!!").unwrap();
                    replaced = true;
                }
                let file = held.guard::<std::fs::File>().unwrap();
                let to = crate::recycle::recycle_held(file)?;
                landed = Some((to, held.id));
                Ok(())
            },
        );
        let (to, checked) = landed.clone().unwrap_or_default();
        let moved = std::fs::File::open(&to).ok();
        let moved_id = moved.as_ref().and_then(|file| check_plain(file).ok());
        let moved_bytes = std::fs::read(&to).ok();
        let keeper_dir = if replaced {
            base.join("set-moved")
        } else {
            dir.clone()
        };
        let keeper_bytes = std::fs::read(keeper_dir.join("keep.bin")).ok();
        let stand_in = replaced.then(|| std::fs::read(&cand).ok());
        drop(moved);
        forget_recycled(&to);
        let _ = std::fs::remove_dir_all(&base);
        assert!(results[0].1.is_ok(), "{results:?}");
        for (what, worked) in &swaps {
            assert!(!worked, "could {what} while it was held");
        }
        assert!(to.contains("\\$Recycle.Bin\\S-1-"), "{to}");
        assert_eq!(
            moved_id.map(|(id, _)| id),
            Some(checked),
            "another file moved"
        );
        assert_eq!(moved_bytes.as_deref(), Some(&b"same bytes"[..]));
        assert_eq!(keeper_bytes.as_deref(), Some(&b"same bytes"[..]));
        if let Some(stand_in) = stand_in {
            assert_eq!(stand_in.as_deref(), Some(&b"stand in!!"[..]));
        }
    }

    #[test]
    fn live_a_copy_open_for_writing_is_left_where_it_is() {
        let base = std::env::temp_dir().join(format!("hm-dup-busy-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let keep = base.join("keep.bin");
        let cand = base.join("cand.bin");
        std::fs::write(&keep, b"same").unwrap();
        std::fs::write(&cand, b"same").unwrap();
        let writer = std::fs::OpenOptions::new().write(true).open(&cand).unwrap();
        let group = DupGroup {
            bytes: 4,
            files: vec![keep.display().to_string(), cand.display().to_string()],
        };
        let mut called = false;
        let results = remove_checked(&HostContent::default(), &group, &[1], &[], &mut |_, _| {
            called = true;
            Ok(())
        });
        drop(writer);
        let still = std::fs::read(&cand).ok();
        let _ = std::fs::remove_dir_all(&base);
        assert!(results[0].1.is_err(), "{results:?}");
        assert!(!called);
        assert_eq!(still.as_deref(), Some(&b"same"[..]));
    }
}
