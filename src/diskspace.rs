//! Disk space analyzer: how much each folder holds, the largest files, and
//! the totals by kind of file. It only reads.
//!
//! Junctions, symbolic links, and other reparse-point folders are never
//! followed, so nothing is counted twice and the walk cannot loop or leave
//! the folder it was given.

/// One item in a folder listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskEntry {
    pub name: String,
    pub dir: bool,
    /// A reparse point (junction, symbolic link, mount point).
    pub link: bool,
    pub bytes: u64,
}

/// Lists one folder. `Err` means it could not be read.
pub trait DirLister {
    fn list(&self, dir: &str) -> Result<Vec<DiskEntry>, String>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirNode {
    pub name: String,
    /// Bytes in this folder and everything below it.
    pub bytes: u64,
    pub files: u64,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigFile {
    pub path: String,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    Videos,
    Pictures,
    Music,
    Documents,
    Archives,
    Programs,
    Other,
}

impl FileKind {
    pub const ALL: [FileKind; 7] = [
        FileKind::Videos,
        FileKind::Pictures,
        FileKind::Music,
        FileKind::Documents,
        FileKind::Archives,
        FileKind::Programs,
        FileKind::Other,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Videos => "Videos",
            Self::Pictures => "Pictures",
            Self::Music => "Music",
            Self::Documents => "Documents",
            Self::Archives => "Archives and disk images",
            Self::Programs => "Programs and libraries",
            Self::Other => "Everything else",
        }
    }

    pub fn of(name: &str) -> Self {
        let ext = name
            .rsplit_once('.')
            .map(|(_, ext)| ext.to_ascii_lowercase())
            .unwrap_or_default();
        match ext.as_str() {
            "mp4" | "mkv" | "avi" | "mov" | "wmv" | "webm" | "m4v" | "mpg" | "mpeg" | "flv"
            | "m2ts" => Self::Videos,
            "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "heic" | "heif" | "tif" | "tiff"
            | "raw" | "cr2" | "cr3" | "nef" | "arw" | "dng" | "psd" | "svg" | "ico" => {
                Self::Pictures
            }
            "mp3" | "flac" | "wav" | "aac" | "m4a" | "ogg" | "opus" | "wma" | "aiff" | "mid" => {
                Self::Music
            }
            "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods" | "odp"
            | "rtf" | "txt" | "md" | "csv" | "epub" => Self::Documents,
            "zip" | "7z" | "rar" | "tar" | "gz" | "tgz" | "bz2" | "xz" | "zst" | "iso" | "img"
            | "vhd" | "vhdx" | "wim" | "esd" | "cab" => Self::Archives,
            "exe" | "dll" | "sys" | "msi" | "msp" | "msix" | "appx" | "pak" | "so" => {
                Self::Programs
            }
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiskReport {
    pub root: String,
    /// Index 0 is `root`; a parent always comes before its children.
    pub nodes: Vec<DirNode>,
    /// The largest files, biggest first.
    pub largest: Vec<BigFile>,
    /// Bytes and file count per kind, in [`FileKind::ALL`] order.
    pub kinds: Vec<(FileKind, u64, u64)>,
    /// Folders that could not be read.
    pub unreadable: u64,
    /// Junctions and links that were not followed.
    pub links_skipped: u64,
    pub canceled: bool,
}

impl DiskReport {
    /// Full path of a folder in the tree.
    pub fn path_of(&self, index: usize) -> String {
        let mut parts = Vec::new();
        let mut at = Some(index);
        while let Some(node) = at {
            if node == 0 {
                break;
            }
            parts.push(self.nodes[node].name.as_str());
            at = self.nodes[node].parent;
        }
        let mut path = self.root.trim_end_matches('\\').to_string();
        for part in parts.iter().rev() {
            path.push('\\');
            path.push_str(part);
        }
        if path.len() == 2 && path.ends_with(':') {
            path.push('\\');
        }
        path
    }

    /// The children of a folder, largest first.
    pub fn children_by_size(&self, index: usize) -> Vec<usize> {
        let mut children = self.nodes[index].children.clone();
        children.sort_by(|a, b| {
            self.nodes[*b]
                .bytes
                .cmp(&self.nodes[*a].bytes)
                .then_with(|| self.nodes[*a].name.cmp(&self.nodes[*b].name))
        });
        children
    }
}

/// How many of the largest files a report keeps.
pub const LARGEST_KEPT: usize = 100;

/// Walk `root`. `progress(files, bytes, folder)` is called for each folder
/// with the totals so far and returns false to stop; a stopped walk
/// reports what it counted.
pub fn analyze(
    lister: &dyn DirLister,
    root: &str,
    progress: &mut dyn FnMut(u64, u64, &str) -> bool,
) -> DiskReport {
    let root = root.trim_end_matches('\\').to_string();
    let mut report = DiskReport {
        root: root.clone(),
        nodes: vec![DirNode {
            name: root.clone(),
            bytes: 0,
            files: 0,
            parent: None,
            children: Vec::new(),
        }],
        kinds: FileKind::ALL.iter().map(|kind| (*kind, 0, 0)).collect(),
        ..DiskReport::default()
    };
    let mut files_seen = 0u64;
    let mut bytes_seen = 0u64;
    // (node, path) to visit, depth first.
    let mut pending = vec![(0usize, root.clone())];
    while let Some((node, path)) = pending.pop() {
        if !progress(files_seen, bytes_seen, &path) {
            report.canceled = true;
            break;
        }
        let listing = match lister.list(&format!("{path}\\")) {
            Ok(listing) => listing,
            Err(_) => {
                report.unreadable += 1;
                continue;
            }
        };
        for entry in listing {
            if entry.name == "." || entry.name == ".." || entry.name.is_empty() {
                continue;
            }
            let full = format!("{path}\\{}", entry.name);
            if entry.dir {
                if entry.link {
                    report.links_skipped += 1;
                    continue;
                }
                let child = report.nodes.len();
                report.nodes.push(DirNode {
                    name: entry.name.clone(),
                    bytes: 0,
                    files: 0,
                    parent: Some(node),
                    children: Vec::new(),
                });
                report.nodes[node].children.push(child);
                pending.push((child, full));
            } else {
                files_seen += 1;
                bytes_seen += entry.bytes;
                report.nodes[node].bytes += entry.bytes;
                report.nodes[node].files += 1;
                let kind = FileKind::of(&entry.name);
                if let Some(slot) = report.kinds.iter_mut().find(|(have, _, _)| *have == kind) {
                    slot.1 += entry.bytes;
                    slot.2 += 1;
                }
                keep_largest(&mut report.largest, full, entry.bytes);
            }
        }
    }
    // Children come after their parent, so one backward pass totals the tree.
    for index in (1..report.nodes.len()).rev() {
        let (bytes, files) = (report.nodes[index].bytes, report.nodes[index].files);
        if let Some(parent) = report.nodes[index].parent {
            report.nodes[parent].bytes += bytes;
            report.nodes[parent].files += files;
        }
    }
    report
}

fn keep_largest(largest: &mut Vec<BigFile>, path: String, bytes: u64) {
    if largest.len() >= LARGEST_KEPT && largest.last().is_some_and(|last| last.bytes >= bytes) {
        return;
    }
    let at = largest.partition_point(|have| have.bytes >= bytes);
    largest.insert(at, BigFile { path, bytes });
    largest.truncate(LARGEST_KEPT);
}

/// The host's folders, listed with FindFirstFileExW (large fetch, no short
/// names). Long paths use the `\\?\` form.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HostLister;

#[cfg(windows)]
impl DirLister for HostLister {
    fn list(&self, dir: &str) -> Result<Vec<DiskEntry>, String> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FIND_FIRST_EX_LARGE_FETCH,
            FindClose, FindExInfoBasic, FindExSearchNameMatch, FindFirstFileExW, FindNextFileW,
            WIN32_FIND_DATAW,
        };
        let pattern = if dir.len() > 240 && !dir.starts_with(r"\\") {
            format!(r"\\?\{dir}*")
        } else {
            format!("{dir}*")
        };
        let wide: Vec<u16> = pattern.encode_utf16().chain(std::iter::once(0)).collect();
        let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
        let handle = unsafe {
            FindFirstFileExW(
                wide.as_ptr(),
                FindExInfoBasic,
                &mut data as *mut _ as *mut _,
                FindExSearchNameMatch,
                std::ptr::null(),
                FIND_FIRST_EX_LARGE_FETCH,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut entries = Vec::new();
        loop {
            let len = data
                .cFileName
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(data.cFileName.len());
            entries.push(DiskEntry {
                name: String::from_utf16_lossy(&data.cFileName[..len]),
                dir: data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
                link: data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
                bytes: (u64::from(data.nFileSizeHigh) << 32) | u64::from(data.nFileSizeLow),
            });
            if unsafe { FindNextFileW(handle, &mut data) } == 0 {
                break;
            }
        }
        unsafe { FindClose(handle) };
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Fake {
        dirs: BTreeMap<String, Vec<DiskEntry>>,
    }

    impl Fake {
        fn file(&mut self, dir: &str, name: &str, bytes: u64) {
            self.entry(dir, name, false, false, bytes);
        }
        fn entry(&mut self, dir: &str, name: &str, is_dir: bool, link: bool, bytes: u64) {
            self.dirs
                .entry(format!("{dir}\\"))
                .or_default()
                .push(DiskEntry {
                    name: name.into(),
                    dir: is_dir,
                    link,
                    bytes,
                });
        }
    }

    impl DirLister for Fake {
        fn list(&self, dir: &str) -> Result<Vec<DiskEntry>, String> {
            self.dirs.get(dir).cloned().ok_or("denied".into())
        }
    }

    fn world() -> Fake {
        let mut fake = Fake::default();
        fake.entry("C:", "Users", true, false, 0);
        fake.entry("C:", "Docs and Settings", true, true, 0);
        fake.entry("C:", "Locked", true, false, 0);
        fake.file("C:", "pagefile.sys", 4000);
        fake.entry(r"C:\Users", "me", true, false, 0);
        fake.file(r"C:\Users\me", "movie.MKV", 3000);
        fake.file(r"C:\Users\me", "notes.txt", 10);
        fake.file(r"C:\Users\me", "photo.jpg", 500);
        // The link points back at the root: never followed.
        fake.entry(r"C:\Users\me", "Loop", true, true, 0);
        fake
    }

    #[test]
    fn totals_folders_without_following_links() {
        let report = analyze(&world(), r"C:\", &mut |_, _, _| true);
        assert_eq!(report.nodes[0].bytes, 7510);
        assert_eq!(report.nodes[0].files, 4);
        assert_eq!(report.links_skipped, 2);
        assert_eq!(report.unreadable, 1, "Locked could not be listed");
        let top: Vec<String> = report
            .children_by_size(0)
            .iter()
            .map(|index| report.path_of(*index))
            .collect();
        assert_eq!(top, [r"C:\Users", r"C:\Locked"]);
        assert_eq!(report.path_of(0), r"C:\");
        let users = report.children_by_size(0)[0];
        assert_eq!(report.nodes[users].bytes, 3510);
        let me = report.nodes[users].children[0];
        assert_eq!(report.path_of(me), r"C:\Users\me");
    }

    #[test]
    fn keeps_the_largest_files_and_kinds() {
        let report = analyze(&world(), r"C:\", &mut |_, _, _| true);
        let paths: Vec<&str> = report.largest.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                r"C:\pagefile.sys",
                r"C:\Users\me\movie.MKV",
                r"C:\Users\me\photo.jpg",
                r"C:\Users\me\notes.txt"
            ]
        );
        let kind = |k: FileKind| report.kinds.iter().find(|(have, _, _)| *have == k).unwrap();
        assert_eq!(kind(FileKind::Videos).1, 3000);
        assert_eq!(kind(FileKind::Pictures).2, 1);
        assert_eq!(kind(FileKind::Programs).1, 4000);
        let mut many = Vec::new();
        for size in 0..(LARGEST_KEPT as u64 + 50) {
            keep_largest(&mut many, format!("f{size}"), size);
        }
        assert_eq!(many.len(), LARGEST_KEPT);
        assert_eq!(many[0].bytes, LARGEST_KEPT as u64 + 49);
        assert!(many.windows(2).all(|pair| pair[0].bytes >= pair[1].bytes));
    }

    #[test]
    fn a_stopped_walk_reports_what_it_counted() {
        let mut calls = 0;
        let report = analyze(&world(), r"C:\", &mut |_, _, _| {
            calls += 1;
            calls < 2
        });
        assert!(report.canceled);
        assert_eq!(report.nodes[0].files, 1, "only the root was listed");
    }
}
