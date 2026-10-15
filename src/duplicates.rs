//! Duplicate file finder: files with the same size and the same content.
//!
//! Finding only reads. Removing is checked again file by file just before
//! it happens: one copy of every set is always kept, protected folders are
//! refused, and a file is only removed when its bytes still match the kept
//! copy and it is not the same file reached by another name (a hard link).
//! Removed files go to the Recycle Bin.

use std::collections::BTreeMap;

use crate::diskspace::DirLister;
use crate::pathutil::{has_unsafe_fs_component, path_under};

/// A file's identity: volume serial number and file index.
pub type FileId = (u64, u64);

/// Reads file contents for comparing.
pub trait ContentReader {
    /// The file's identity, length, and a 128-bit hash of its first
    /// `limit` bytes (all of it when `None`).
    fn fingerprint(&self, path: &str, limit: Option<u64>) -> Result<(FileId, u64, u128), String>;
    /// True when both files hold exactly the same bytes.
    fn same_content(&self, a: &str, b: &str) -> Result<bool, String>;
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
}

/// How many leading bytes are compared before reading whole files.
const PREFIX: u64 = 64 * 1024;

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
    let root = root.trim_end_matches('\\').to_string();
    let mut report = DupReport {
        root: root.clone(),
        ..DupReport::default()
    };
    let mut by_size: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    let mut pending = vec![root];
    while let Some(dir) = pending.pop() {
        if !progress(
            &format!("Looking at {} files. Reading {dir}", report.files_seen),
            0,
            0,
        ) {
            report.canceled = true;
            return report;
        }
        let Ok(listing) = lister.list(&format!("{dir}\\")) else {
            report.unreadable += 1;
            continue;
        };
        for entry in listing {
            if entry.name == "." || entry.name == ".." || entry.name.is_empty() || entry.link {
                // Links, junctions, and cloud placeholders (reparse points)
                // are never followed or read.
                continue;
            }
            let path = format!("{dir}\\{}", entry.name);
            if entry.dir {
                let skipped = SKIPPED_DIRS
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(&entry.name))
                    || protected.iter().any(|root| path_under(&path, root));
                if !skipped {
                    pending.push(path);
                }
            } else {
                report.files_seen += 1;
                if entry.bytes >= min_bytes.max(1) {
                    by_size.entry(entry.bytes).or_default().push(path);
                }
            }
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

/// Check, just before removing, which of `remove` (indexes into the set's
/// files) may go. Every removal needs a kept copy whose bytes it still
/// matches. Returns each path with the reason it must stay, if any.
pub fn check_removal(
    reader: &dyn ContentReader,
    group: &DupGroup,
    remove: &[usize],
    protected: &[String],
) -> Vec<(String, Result<(), String>)> {
    let kept: Vec<&String> = group
        .files
        .iter()
        .enumerate()
        .filter(|(index, _)| !remove.contains(index))
        .map(|(_, path)| path)
        .collect();
    let keeper = kept.iter().find_map(|path| {
        reader
            .fingerprint(path, Some(0))
            .ok()
            .filter(|(_, len, _)| *len == group.bytes)
            .map(|(id, _, _)| (*path, id))
    });
    let mut out = Vec::new();
    for index in remove {
        let Some(path) = group.files.get(*index) else {
            continue;
        };
        let verdict = (|| {
            let (keep_path, keep_id) =
                keeper.ok_or("no copy of this set is being kept, or the kept copy changed")?;
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
            let (id, len, _) = reader.fingerprint(path, Some(0))?;
            if id == keep_id {
                return Err("it is the kept copy under another name (a hard link)".to_string());
            }
            if len != group.bytes {
                return Err("it changed since the search".to_string());
            }
            if !reader.same_content(keep_path, path)? {
                return Err("its contents no longer match the kept copy".to_string());
            }
            Ok(())
        })();
        out.push((path.clone(), verdict));
    }
    out
}

/// The host's files, read through a handle that does not follow links.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HostContent;

#[cfg(windows)]
fn open_plain(path: &str) -> Result<(std::fs::File, FileId, u64), String> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFileInformationByHandle,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)
        .map_err(|err| err.to_string())?;
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
    Ok((file, id, len))
}

#[cfg(windows)]
impl ContentReader for HostContent {
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

    fn same_content(&self, a: &str, b: &str) -> Result<bool, String> {
        use std::io::Read;
        let (mut left, _, left_len) = open_plain(a)?;
        let (mut right, _, right_len) = open_plain(b)?;
        if left_len != right_len {
            return Ok(false);
        }
        let mut one = vec![0u8; 1 << 20];
        let mut two = vec![0u8; 1 << 20];
        loop {
            let read = left.read(&mut one).map_err(|err| err.to_string())?;
            if read == 0 {
                return Ok(right.read(&mut two[..1]).map_err(|err| err.to_string())? == 0);
            }
            right
                .read_exact(&mut two[..read])
                .map_err(|err| err.to_string())?;
            if one[..read] != two[..read] {
                return Ok(false);
            }
        }
    }
}

/// Move one file to the Recycle Bin. Windows warns first if the file
/// would be deleted for good instead (a drive without a Recycle Bin, or a
/// file too big for it); declining leaves it in place.
#[cfg(windows)]
pub fn recycle(path: &str) -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::{
        FO_DELETE, FOF_ALLOWUNDO, FOF_NOCONFIRMATION, FOF_NOERRORUI, FOF_SILENT,
        FOF_WANTNUKEWARNING, SHFILEOPSTRUCTW, SHFileOperationW,
    };
    // Double NUL terminated, as SHFileOperationW requires.
    let from: Vec<u16> = path.encode_utf16().chain([0, 0]).collect();
    let mut op: SHFILEOPSTRUCTW = unsafe { std::mem::zeroed() };
    op.wFunc = FO_DELETE;
    op.pFrom = from.as_ptr();
    op.fFlags =
        (FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI | FOF_WANTNUKEWARNING)
            as u16;
    let status = unsafe { SHFileOperationW(&mut op) };
    if status != 0 {
        return Err(format!("the Recycle Bin refused it ({status:#x})"));
    }
    if op.fAnyOperationsAborted != 0 {
        return Err("left in place".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diskspace::DiskEntry;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Default)]
    struct World {
        dirs: BTreeMap<String, Vec<DiskEntry>>,
        /// path -> (id, content)
        files: RefCell<HashMap<String, (FileId, Vec<u8>)>>,
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
        fn list(&self, dir: &str) -> Result<Vec<DiskEntry>, String> {
            self.dirs.get(dir).cloned().ok_or("denied".into())
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
        fn same_content(&self, a: &str, b: &str) -> Result<bool, String> {
            let files = self.files.borrow();
            Ok(files.get(a).ok_or("missing")?.1 == files.get(b).ok_or("missing")?.1)
        }
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
        let ok = check_removal(&world, &group, &[1], &protected());
        assert!(ok[0].1.is_ok());
        // Removing every copy is refused: nothing is kept.
        let all = check_removal(&world, &group, &[0, 1], &protected());
        assert!(all.iter().all(|(_, verdict)| verdict.is_err()));
        // A copy that changed since the search stays.
        world
            .files
            .borrow_mut()
            .get_mut(r"C:\Users\b.jpg")
            .unwrap()
            .1 = b"photo-new".to_vec();
        let changed = check_removal(&world, &group, &[1], &protected());
        assert!(changed[0].1.is_err());
        // A hard link to the kept file is not a copy.
        let linked = DupGroup {
            bytes: 9,
            files: vec![r"C:\Users\a.jpg".into(), r"C:\Users\link.jpg".into()],
        };
        assert!(
            check_removal(&world, &linked, &[1], &protected())[0]
                .1
                .is_err()
        );
        // Protected folders are refused even if offered.
        let inside = DupGroup {
            bytes: 9,
            files: vec![r"C:\Users\a.jpg".into(), r"C:\Windows\a.jpg".into()],
        };
        assert!(
            check_removal(&world, &inside, &[1], &protected())[0]
                .1
                .is_err()
        );
    }
}
