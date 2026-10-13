//! File shredder: multi-pass overwrite, rename, delete, with verify.
//!
//! No backup is possible, so safety comes from explicit staging,
//! absolute refusals, per-item errors, and cancel. Pass counts are named
//! by count only; no certification is claimed.

use crate::fs::{FileView, ItemKind};
use crate::pathutil::shred_allowed;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShredMethod {
    OnePass,
    ThreePass,
    SevenPass,
}

impl ShredMethod {
    pub fn passes(self) -> usize {
        match self {
            Self::OnePass => 1,
            Self::ThreePass => 3,
            Self::SevenPass => 7,
        }
    }

    pub fn from_passes(passes: u8) -> Option<Self> {
        match passes {
            1 => Some(Self::OnePass),
            3 => Some(Self::ThreePass),
            7 => Some(Self::SevenPass),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::OnePass => "1 pass",
            Self::ThreePass => "3 passes",
            Self::SevenPass => "7 passes",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShredOptions {
    pub method: ShredMethod,
    pub rename: bool,
}

impl Default for ShredOptions {
    fn default() -> Self {
        Self {
            method: ShredMethod::ThreePass,
            rename: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShredTarget {
    pub path: String,
    pub is_dir: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ShredOutcome {
    pub shredded: usize,
    pub bytes: u64,
    /// Original paths fully shredded (pre-rename), for follow-up work.
    pub shredded_paths: Vec<String>,
    pub refused: Vec<String>,
    pub errors: Vec<String>,
    pub canceled: bool,
}

/// Overwrite chunk and verify window. Small enough for the stack caller to
/// reuse, big enough that large files shred in few syscalls.
const CHUNK: usize = 64 * 1024;

/// Deterministic stream cipher for pass patterns. Seeded per job from time
/// plus process id; tests pass a fixed seed.
#[derive(Clone, Debug)]
pub struct XorShift(u64);

impl XorShift {
    pub fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }

    pub fn next_u8(&mut self) -> u8 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        (x >> 56) as u8
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for slot in buf.iter_mut() {
            *slot = self.next_u8();
        }
    }
}

/// Job seed from wall time and process id. Failure falls back to the
/// process id alone rather than a constant.
pub fn random_seed() -> u64 {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|span| span.as_nanos() as u64)
        .unwrap_or(0);
    time ^ ((std::process::id() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))
}

/// Fill one chunk of a pass. Pass 1 writes zeros, pass 2 writes ones, later
/// passes write random bytes. Each chunk has its own stream, so the verify
/// pass can regenerate exactly the windows it checks.
fn pass_fill(pass: usize, seed: u64, file_no: u64, chunk_no: u64, buf: &mut [u8]) {
    match pass {
        0 => buf.fill(0),
        1 => buf.fill(0xff),
        _ => {
            let mixed = seed
                ^ file_no.wrapping_mul(0x9e37_79b9_7f4a_7c15)
                ^ (pass as u64).wrapping_mul(0xc2b2_9b5d_4e9c_6d6f)
                ^ chunk_no.wrapping_mul(0x1656_67b1_9b09_7d0b);
            XorShift::new(mixed).fill(buf);
        }
    }
}

/// Regenerate the expected bytes for `[offset, offset + len)` of a pass.
fn expected_bytes(pass: usize, seed: u64, file_no: u64, offset: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut at = offset;
    while out.len() < len {
        let chunk_no = at / CHUNK as u64;
        let within = (at % CHUNK as u64) as usize;
        let mut chunk = vec![0u8; CHUNK];
        pass_fill(pass, seed, file_no, chunk_no, &mut chunk);
        let take = (len - out.len()).min(CHUNK - within);
        out.extend_from_slice(&chunk[within..within + take]);
        at += take as u64;
    }
    out
}

/// Shred explicitly staged top-level paths. `progress(done, total, name)`
/// runs before every pass with `total = files x passes`; returning false
/// cancels after the finished files, which stay deleted.
pub fn shred_paths(
    fs: &mut dyn FileView,
    targets: &[ShredTarget],
    opts: &ShredOptions,
    seed: u64,
    progress: &mut dyn FnMut(usize, usize, &str) -> bool,
) -> ShredOutcome {
    let mut outcome = ShredOutcome::default();
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    for target in targets {
        if let Err(reason) = shred_allowed(fs, &target.path) {
            outcome.refused.push(reason);
            continue;
        }
        match fs.kind_of(&target.path) {
            ItemKind::File if !target.is_dir => files.push(target.path.clone()),
            ItemKind::Dir if target.is_dir => {
                collect_dir(fs, &target.path, 0, &mut files, &mut dirs, &mut outcome);
            }
            _ => outcome
                .refused
                .push(format!("{} changed since staging", target.path)),
        }
    }
    let passes = opts.method.passes();
    let total = files.len() * passes;
    let mut done = 0usize;
    for (file_no, path) in files.iter().enumerate() {
        match shred_file(
            fs,
            path,
            file_no as u64,
            opts,
            seed,
            &mut done,
            total,
            progress,
        ) {
            FileDone::Shredded(bytes) => {
                outcome.shredded += 1;
                outcome.bytes += bytes;
                outcome.shredded_paths.push(path.clone());
            }
            FileDone::Failed(reason) => outcome.errors.push(reason),
            FileDone::Refused(reason) => outcome.refused.push(reason),
            FileDone::Canceled => {
                outcome.canceled = true;
                return outcome;
            }
        }
    }
    if total > 0 {
        progress(total, total, "");
    }
    for dir in dirs {
        if let Err(err) = fs.remove_dir(&dir) {
            outcome.errors.push(format!("{dir}: {err}"));
        }
    }
    outcome
}

enum FileDone {
    Shredded(u64),
    Failed(String),
    Refused(String),
    Canceled,
}

/// Walk a staged directory depth-first. Files join the shred list; links
/// are refused; directories queue deepest-first for post-order removal.
fn collect_dir(
    fs: &dyn FileView,
    dir: &str,
    depth: usize,
    files: &mut Vec<String>,
    dirs: &mut Vec<String>,
    outcome: &mut ShredOutcome,
) {
    if depth > 64 {
        outcome.errors.push(format!("{dir}: nested too deeply"));
        return;
    }
    for entry in fs.list(dir) {
        let path = format!("{dir}\\{}", entry.name);
        match entry.kind {
            ItemKind::File => files.push(path),
            ItemKind::Dir => collect_dir(fs, &path, depth + 1, files, dirs, outcome),
            ItemKind::Other => outcome.refused.push(format!("{path}: link skipped")),
        }
    }
    dirs.push(dir.to_string());
}

fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

#[allow(clippy::too_many_arguments)]
fn shred_file(
    fs: &mut dyn FileView,
    path: &str,
    file_no: u64,
    opts: &ShredOptions,
    seed: u64,
    done: &mut usize,
    total: usize,
    progress: &mut dyn FnMut(usize, usize, &str) -> bool,
) -> FileDone {
    // Re-gate every file: a staged path could have been swapped for a link.
    if let Err(reason) = shred_allowed(fs, path) {
        return FileDone::Refused(reason);
    }
    let Some(len) = fs.len(path) else {
        return FileDone::Refused(format!("{path} cannot be sized"));
    };
    let name = file_name(path).to_string();
    let passes = opts.method.passes();
    for pass in 0..passes {
        if !progress(*done, total, &name) {
            return FileDone::Canceled;
        }
        if len > 0
            && let Err(err) = overwrite_pass(fs, path, len, pass, seed, file_no)
        {
            return FileDone::Failed(format!("{path}: {err}"));
        }
        *done += 1;
    }
    if len > 0 && !verify_file(fs, path, len, passes - 1, seed, file_no) {
        return FileDone::Failed(format!("{path}: verify failed, file kept"));
    }
    let mut current = path.to_string();
    if len > 0
        && let Err(err) = fs.set_len(&current, 0)
    {
        return FileDone::Failed(format!("{path}: {err}"));
    }
    if opts.rename {
        match random_sibling(&current, seed, file_no) {
            Some(next) => match fs.rename_file(&current, &next) {
                Ok(()) => current = next,
                Err(err) => return FileDone::Failed(format!("{path}: {err}")),
            },
            None => return FileDone::Failed(format!("{path}: no usable name found")),
        }
    }
    match fs.remove_file(&current) {
        Ok(()) => FileDone::Shredded(len),
        Err(err) => FileDone::Failed(format!("{path}: {err}")),
    }
}

fn overwrite_pass(
    fs: &mut dyn FileView,
    path: &str,
    len: u64,
    pass: usize,
    seed: u64,
    file_no: u64,
) -> Result<(), String> {
    let mut buf = vec![0u8; CHUNK.min(len as usize).max(1)];
    let mut offset = 0u64;
    while offset < len {
        let chunk_no = offset / CHUNK as u64;
        let take = ((len - offset) as usize).min(buf.len());
        pass_fill(pass, seed, file_no, chunk_no, &mut buf[..take]);
        fs.write_at(path, offset, &buf[..take])?;
        offset += take as u64;
    }
    fs.sync_file(path)
}

/// Read back the first and last windows and compare against regenerated
/// pattern bytes. Anything unreadable or mismatched fails closed.
fn verify_file(
    fs: &dyn FileView,
    path: &str,
    len: u64,
    pass: usize,
    seed: u64,
    file_no: u64,
) -> bool {
    if len == 0 {
        return true;
    }
    let head = (len as usize).min(CHUNK);
    if !window_matches(fs, path, pass, seed, file_no, 0, head) {
        return false;
    }
    if len as usize > head {
        let tail = (len as usize).min(CHUNK);
        let offset = len - tail as u64;
        if !window_matches(fs, path, pass, seed, file_no, offset, tail) {
            return false;
        }
    }
    true
}

fn window_matches(
    fs: &dyn FileView,
    path: &str,
    pass: usize,
    seed: u64,
    file_no: u64,
    offset: u64,
    len: usize,
) -> bool {
    match fs.read_at(path, offset, len) {
        Some(got) => got.len() == len && got == expected_bytes(pass, seed, file_no, offset, len),
        None => false,
    }
}

const RENAME_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// A random sibling name the length of the original file name.
fn random_sibling(path: &str, seed: u64, file_no: u64) -> Option<String> {
    let split = path.rfind(['\\', '/'])?;
    let (dir, name) = (&path[..split], &path[split + 1..]);
    let chars = name.chars().count();
    if dir.is_empty() || chars == 0 {
        return None;
    }
    let mut rng = XorShift::new(seed ^ file_no.wrapping_mul(0xd6e8_feb8_6659_fd0d));
    for _ in 0..8 {
        let mut fresh = String::with_capacity(chars);
        for _ in 0..chars {
            fresh.push(RENAME_ALPHABET[(rng.next_u8() as usize) % RENAME_ALPHABET.len()] as char);
        }
        if fresh != name {
            return Some(format!("{dir}\\{fresh}"));
        }
    }
    None
}

// ---- recycle bin ----

#[derive(Clone, Debug)]
pub struct RecycleItem {
    pub drive: String,
    pub sid: String,
    /// Full `$R` data path: this gets shredded.
    pub data: String,
    /// Full `$I` metadata path: deleted after its data shreds.
    pub meta: String,
    /// Original file name.
    pub display: String,
    pub bytes: u64,
}

/// Pair `$I` metadata names with `$R` data names by suffix. Only complete
/// pairs shred; strays are reported and left alone. `desktop.ini` is folder
/// furniture, not content, and is skipped silently.
pub fn recycle_pairs(names: &[String]) -> (Vec<(String, String)>, Vec<String>) {
    use std::collections::HashMap;
    let mut metas: HashMap<String, String> = HashMap::new();
    let mut datas: HashMap<String, String> = HashMap::new();
    let mut strays = Vec::new();
    for name in names {
        let upper = name.to_ascii_uppercase();
        if upper == "DESKTOP.INI" {
            continue;
        }
        if let Some(key) = upper.strip_prefix("$I")
            && !key.is_empty()
        {
            metas.insert(key.to_string(), name.clone());
        } else if let Some(key) = upper.strip_prefix("$R")
            && !key.is_empty()
        {
            datas.insert(key.to_string(), name.clone());
        } else {
            strays.push(name.clone());
        }
    }
    let mut pairs = Vec::new();
    let mut keys: Vec<String> = metas.keys().cloned().collect();
    keys.sort();
    for key in keys {
        match (metas.remove(&key), datas.remove(&key)) {
            (Some(meta), Some(data)) => pairs.push((meta, data)),
            (Some(meta), None) => strays.push(meta),
            _ => {}
        }
    }
    let mut lone: Vec<String> = datas.into_values().collect();
    lone.sort();
    strays.extend(lone);
    (pairs, strays)
}

/// Original file name from a `$I` metadata blob: u64 version, u64 size,
/// u64 deletion time, u32 name length in UTF-16 units including the
/// trailing NUL, then the UTF-16 path. Base name only. Later blob
/// versions may append sections after the name; they are ignored.
pub fn recycle_display_name(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 28 {
        return None;
    }
    let count = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]) as usize;
    if count == 0 || count > 4096 {
        return None;
    }
    let end = 28usize.saturating_add(count.saturating_mul(2));
    if bytes.len() < end {
        return None;
    }
    let wide: Vec<u16> = bytes[28..end]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let path = String::from_utf16_lossy(&wide);
    let base = path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .trim_matches('\0')
        .trim();
    if base.is_empty() {
        None
    } else {
        Some(base.to_string())
    }
}

/// List shreddable Recycle Bin contents across fixed drives, plus notes for
/// strays. Unreadable SID folders look empty here and fail per item later.
pub fn list_recycle_bin(fs: &dyn FileView, drives: &[String]) -> (Vec<RecycleItem>, Vec<String>) {
    let mut items = Vec::new();
    let mut notes = Vec::new();
    for drive in drives {
        let bin = format!("{}\\$Recycle.Bin", drive.trim_end_matches(['\\', '/']));
        let sids: Vec<String> = fs
            .list(&bin)
            .into_iter()
            .filter(|entry| entry.kind == ItemKind::Dir)
            .map(|entry| entry.name)
            .collect();
        for sid in sids {
            let dir = format!("{bin}\\{sid}");
            let names: Vec<String> = fs.list(&dir).into_iter().map(|entry| entry.name).collect();
            let (pairs, strays) = recycle_pairs(&names);
            for stray in strays {
                notes.push(format!("{dir}\\{stray} is unpaired; left alone"));
            }
            for (meta, data) in pairs {
                let data_path = format!("{dir}\\{data}");
                let meta_path = format!("{dir}\\{meta}");
                let display = fs
                    .read(&meta_path)
                    .and_then(|bytes| recycle_display_name(&bytes))
                    .unwrap_or_else(|| data.clone());
                items.push(RecycleItem {
                    drive: drive.clone(),
                    sid: sid.clone(),
                    data: data_path.clone(),
                    meta: meta_path,
                    display,
                    bytes: fs.len(&data_path).unwrap_or(0),
                });
            }
        }
    }
    items.sort_by(|left, right| left.data.cmp(&right.data));
    notes.sort();
    (items, notes)
}

/// Shred bin data files, then delete the metadata of each shredded one.
pub fn shred_recycle_items(
    fs: &mut dyn FileView,
    items: &[RecycleItem],
    opts: &ShredOptions,
    seed: u64,
    progress: &mut dyn FnMut(usize, usize, &str) -> bool,
) -> ShredOutcome {
    let targets: Vec<ShredTarget> = items
        .iter()
        .map(|item| ShredTarget {
            path: item.data.clone(),
            is_dir: false,
        })
        .collect();
    let mut outcome = shred_paths(fs, &targets, opts, seed, progress);
    for item in items {
        if outcome.shredded_paths.iter().any(|path| path == &item.data)
            && let Err(err) = fs.remove_file(&item.meta)
        {
            outcome.errors.push(format!("{}: {err}", item.meta));
        }
    }
    outcome
}

// ---- media ----

/// True when a `STORAGE_DEVICE_SEEK_PENALTY_DESCRIPTOR` reports no seek
/// penalty (SSD/NVMe): ULONG Version, ULONG Size, BOOLEAN SeekPenalty.
pub fn seek_penalty_false(descriptor: &[u8]) -> Option<bool> {
    descriptor.get(8).map(|flag| *flag == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{DirItem, MemoryFs};

    const SEED: u64 = 0x1234_5678_9abc_def0;

    fn allow(_done: usize, _total: usize, _name: &str) -> bool {
        true
    }

    fn target(path: &str, is_dir: bool) -> ShredTarget {
        ShredTarget {
            path: path.to_string(),
            is_dir,
        }
    }

    /// A `$I` blob in the on-disk layout: version, size, time, UTF-16
    /// unit count including the NUL, path, NUL.
    fn meta_blob(path: &str) -> Vec<u8> {
        let mut blob = vec![0u8; 24];
        blob[0] = 2;
        let wide: Vec<u16> = path.encode_utf16().collect();
        blob.extend_from_slice(&((wide.len() + 1) as u32).to_le_bytes());
        for unit in wide {
            blob.extend_from_slice(&unit.to_le_bytes());
        }
        blob.extend_from_slice(&[0u8; 2]);
        blob
    }

    /// MemoryFs with one path flagged hidden+system, to exercise the veto.
    struct HiddenFs {
        inner: MemoryFs,
        flagged: String,
    }

    impl FileView for HiddenFs {
        fn exists(&self, path: &str) -> bool {
            self.inner.exists(path)
        }
        fn is_dir(&self, path: &str) -> bool {
            self.inner.is_dir(path)
        }
        fn len(&self, path: &str) -> Option<u64> {
            self.inner.len(path)
        }
        fn read(&self, path: &str) -> Option<Vec<u8>> {
            self.inner.read(path)
        }
        fn list(&self, dir: &str) -> Vec<DirItem> {
            self.inner.list(dir)
        }
        fn kind_of(&self, path: &str) -> ItemKind {
            self.inner.kind_of(path)
        }
        fn is_hidden_system(&self, path: &str) -> bool {
            path.eq_ignore_ascii_case(&self.flagged)
        }
        fn remove_file(&mut self, path: &str) -> Result<(), String> {
            self.inner.remove_file(path)
        }
        fn copy_file(&mut self, from: &str, to: &str) -> Result<(), String> {
            self.inner.copy_file(from, to)
        }
        fn write_at(&mut self, path: &str, offset: u64, bytes: &[u8]) -> Result<(), String> {
            self.inner.write_at(path, offset, bytes)
        }
        fn sync_file(&mut self, path: &str) -> Result<(), String> {
            self.inner.sync_file(path)
        }
        fn set_len(&mut self, path: &str, len: u64) -> Result<(), String> {
            self.inner.set_len(path, len)
        }
        fn rename_file(&mut self, from: &str, to: &str) -> Result<(), String> {
            self.inner.rename_file(from, to)
        }
        fn remove_dir(&mut self, path: &str) -> Result<(), String> {
            self.inner.remove_dir(path)
        }
        fn read_at(&self, path: &str, offset: u64, len: usize) -> Option<Vec<u8>> {
            self.inner.read_at(path, offset, len)
        }
        fn var(&self, name: &str) -> Option<String> {
            self.inner.var(name)
        }
    }

    #[test]
    fn one_pass_shreds_file_and_counts_bytes() {
        let mut fs = MemoryFs::new();
        fs.add_file_bytes(r"C:\Docs\secret.txt", vec![0x41; 100], None);
        let opts = ShredOptions {
            method: ShredMethod::OnePass,
            rename: true,
        };
        let outcome = shred_paths(
            &mut fs,
            &[target(r"C:\Docs\secret.txt", false)],
            &opts,
            SEED,
            &mut allow,
        );
        assert_eq!(outcome.shredded, 1);
        assert_eq!(outcome.bytes, 100);
        assert_eq!(
            outcome.shredded_paths,
            vec![r"C:\Docs\secret.txt".to_string()]
        );
        assert!(outcome.refused.is_empty());
        assert!(outcome.errors.is_empty());
        assert!(!outcome.canceled);
        assert!(!fs.exists(r"C:\Docs\secret.txt"));
        assert!(fs.list(r"C:\Docs").is_empty());
    }

    #[test]
    fn progress_counts_files_times_passes() {
        let mut fs = MemoryFs::new();
        fs.add_file_bytes(r"C:\Docs\a.txt", vec![1; 10], None);
        fs.add_file_bytes(r"C:\Docs\b.txt", vec![2; 10], None);
        let mut calls: Vec<(usize, usize, String)> = Vec::new();
        let mut progress = |done: usize, total: usize, name: &str| {
            calls.push((done, total, name.to_string()));
            true
        };
        let outcome = shred_paths(
            &mut fs,
            &[
                target(r"C:\Docs\a.txt", false),
                target(r"C:\Docs\b.txt", false),
            ],
            &ShredOptions::default(),
            SEED,
            &mut progress,
        );
        assert_eq!(outcome.shredded, 2);
        assert_eq!(calls.len(), 2 * 3 + 1);
        for (index, (done, total, name)) in calls.iter().enumerate().take(6) {
            assert_eq!((*done, *total), (index, 6));
            assert!(!name.is_empty());
        }
        assert_eq!(calls[6], (6, 6, String::new()));
    }

    #[test]
    fn empty_file_shreds() {
        let mut fs = MemoryFs::new();
        fs.add_file(r"C:\Docs\empty.dat");
        let outcome = shred_paths(
            &mut fs,
            &[target(r"C:\Docs\empty.dat", false)],
            &ShredOptions::default(),
            SEED,
            &mut allow,
        );
        assert_eq!(outcome.shredded, 1);
        assert_eq!(outcome.bytes, 0);
        assert!(!fs.exists(r"C:\Docs\empty.dat"));
    }

    #[test]
    fn directory_recurses_and_removes_deepest_first() {
        let mut fs = MemoryFs::new();
        fs.add_file_bytes(r"C:\Docs\Tree\a.txt", vec![1; 8], None);
        fs.add_file_bytes(r"C:\Docs\Tree\Sub\b.txt", vec![2; 8], None);
        let outcome = shred_paths(
            &mut fs,
            &[target(r"C:\Docs\Tree", true)],
            &ShredOptions::default(),
            SEED,
            &mut allow,
        );
        assert_eq!(outcome.shredded, 2);
        assert_eq!(outcome.bytes, 16);
        assert!(outcome.errors.is_empty());
        assert!(!fs.exists(r"C:\Docs\Tree"));
        assert!(fs.is_dir(r"C:\Docs"));
    }

    #[test]
    fn directory_with_link_skips_link_and_reports_parent() {
        let mut fs = MemoryFs::new();
        fs.add_file_bytes(r"C:\Docs\Mixed\ok.txt", vec![1; 8], None);
        fs.add_other(r"C:\Docs\Mixed\link.lnk");
        let outcome = shred_paths(
            &mut fs,
            &[target(r"C:\Docs\Mixed", true)],
            &ShredOptions::default(),
            SEED,
            &mut allow,
        );
        assert_eq!(outcome.shredded, 1);
        assert_eq!(outcome.refused.len(), 1);
        assert!(outcome.refused[0].contains("link.lnk"));
        assert_eq!(outcome.errors.len(), 1);
        assert!(outcome.errors[0].contains("Mixed"));
        assert!(fs.exists(r"C:\Docs\Mixed"));
    }

    #[test]
    fn link_target_is_refused() {
        let mut fs = MemoryFs::new();
        fs.add_other(r"C:\Docs\alias.lnk");
        let outcome = shred_paths(
            &mut fs,
            &[target(r"C:\Docs\alias.lnk", false)],
            &ShredOptions::default(),
            SEED,
            &mut allow,
        );
        assert_eq!(outcome.shredded, 0);
        assert_eq!(outcome.refused.len(), 1);
        assert!(outcome.refused[0].contains("link"));
        assert!(fs.exists(r"C:\Docs\alias.lnk"));
    }

    #[test]
    fn hidden_system_file_is_refused() {
        let mut inner = MemoryFs::new();
        inner.add_file_bytes(r"C:\Docs\page.dat", vec![1; 8], None);
        let mut fs = HiddenFs {
            inner,
            flagged: r"C:\Docs\page.dat".to_string(),
        };
        let outcome = shred_paths(
            &mut fs,
            &[target(r"C:\Docs\page.dat", false)],
            &ShredOptions::default(),
            SEED,
            &mut allow,
        );
        assert_eq!(outcome.shredded, 0);
        assert_eq!(outcome.refused.len(), 1);
        assert!(outcome.refused[0].contains("hidden system"));
        assert!(fs.exists(r"C:\Docs\page.dat"));
    }

    #[test]
    fn missing_path_is_refused() {
        let mut fs = MemoryFs::new();
        let outcome = shred_paths(
            &mut fs,
            &[target(r"C:\Docs\gone.txt", false)],
            &ShredOptions::default(),
            SEED,
            &mut allow,
        );
        assert_eq!(outcome.shredded, 0);
        assert_eq!(outcome.refused.len(), 1);
        assert!(outcome.refused[0].contains("does not exist"));
    }

    #[test]
    fn relative_path_and_root_are_refused() {
        let mut fs = MemoryFs::new();
        fs.add_file_bytes(r"C:\Docs\a.txt", vec![1; 4], None);
        let outcome = shred_paths(
            &mut fs,
            &[target(r"Docs\a.txt", false), target(r"C:\", true)],
            &ShredOptions::default(),
            SEED,
            &mut allow,
        );
        assert_eq!(outcome.shredded, 0);
        assert_eq!(outcome.refused.len(), 2);
        assert!(fs.exists(r"C:\Docs\a.txt"));
    }

    #[test]
    fn protected_folders_are_refused() {
        let mut fs = MemoryFs::new();
        fs.set_var("ProgramFiles", r"C:\Program Files");
        fs.add_file_bytes(r"C:\Windows\Temp\x.dat", vec![1; 4], None);
        fs.add_file_bytes(r"C:\Program Files\App\x.exe", vec![1; 4], None);
        fs.add_file_bytes(r"C:\HiveMend\settings.ini", vec![1; 4], None);
        let outcome = shred_paths(
            &mut fs,
            &[
                target(r"C:\Windows\Temp\x.dat", false),
                target(r"C:\Program Files\App\x.exe", false),
                target(r"C:\HiveMend\settings.ini", false),
            ],
            &ShredOptions::default(),
            SEED,
            &mut allow,
        );
        assert_eq!(outcome.shredded, 0);
        assert_eq!(outcome.refused.len(), 3);
        assert!(
            outcome
                .refused
                .iter()
                .any(|note| note.contains("Windows folder"))
        );
        assert!(
            outcome
                .refused
                .iter()
                .any(|note| note.contains("program folder"))
        );
        assert!(
            outcome
                .refused
                .iter()
                .any(|note| note.contains("app data folder"))
        );
    }

    #[test]
    fn type_mismatch_is_refused() {
        let mut fs = MemoryFs::new();
        fs.add_file_bytes(r"C:\Docs\a.txt", vec![1; 4], None);
        fs.add_dir(r"C:\Docs\Sub");
        let outcome = shred_paths(
            &mut fs,
            &[
                target(r"C:\Docs\a.txt", true),
                target(r"C:\Docs\Sub", false),
            ],
            &ShredOptions::default(),
            SEED,
            &mut allow,
        );
        assert_eq!(outcome.shredded, 0);
        assert_eq!(outcome.refused.len(), 2);
        assert!(
            outcome
                .refused
                .iter()
                .all(|note| note.contains("changed since staging"))
        );
    }

    #[test]
    fn cancel_stops_after_finished_files() {
        let mut fs = MemoryFs::new();
        fs.add_file_bytes(r"C:\Docs\a.txt", vec![1; 8], None);
        fs.add_file_bytes(r"C:\Docs\b.txt", vec![2; 8], None);
        let mut progress = |done: usize, _total: usize, _name: &str| done < 1;
        let opts = ShredOptions {
            method: ShredMethod::OnePass,
            rename: true,
        };
        let outcome = shred_paths(
            &mut fs,
            &[
                target(r"C:\Docs\a.txt", false),
                target(r"C:\Docs\b.txt", false),
            ],
            &opts,
            SEED,
            &mut progress,
        );
        assert!(outcome.canceled);
        assert_eq!(outcome.shredded, 1);
        assert!(!fs.exists(r"C:\Docs\a.txt"));
        assert!(fs.exists(r"C:\Docs\b.txt"));
    }

    #[test]
    fn recycle_pairs_match_and_report_strays() {
        let names: Vec<String> = [
            "$IABC",
            "$rabc",
            "$Ilone",
            "$Rlone2",
            "desktop.ini",
            "notes.txt",
            "$I",
            "$R",
        ]
        .iter()
        .map(|name| name.to_string())
        .collect();
        let (pairs, strays) = recycle_pairs(&names);
        assert_eq!(pairs, vec![("$IABC".to_string(), "$rabc".to_string())]);
        assert_eq!(strays.len(), 5);
        assert!(strays.iter().any(|name| name == "$Ilone"));
        assert!(strays.iter().any(|name| name == "$Rlone2"));
        assert!(strays.iter().any(|name| name == "notes.txt"));
        assert!(
            !strays
                .iter()
                .any(|name| name.eq_ignore_ascii_case("desktop.ini"))
        );
    }

    #[test]
    fn recycle_display_name_parses_blob() {
        let blob = meta_blob(r"C:\Users\Test\My Doc.txt");
        assert_eq!(recycle_display_name(&blob), Some("My Doc.txt".to_string()));
        assert_eq!(recycle_display_name(&[0u8; 8]), None);
        let mut zero = meta_blob(r"C:\x.txt");
        zero[24..28].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(recycle_display_name(&zero), None);
    }

    #[test]
    fn recycle_display_name_matches_capture() {
        // Bytes captured from a real Windows 11 bin: version 2, size
        // 0xac000, deletion time, 59 UTF-16 units, NUL-terminated path.
        let mut blob = vec![
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0a, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x40, 0xe7, 0x03, 0x9d, 0x0d, 0x97, 0xdc, 0x01, 0x3b, 0x00, 0x00, 0x00,
        ];
        let path = r"C:\q2starter\q2advanceog_win11_modern_res_1080_1440_4k.exe";
        assert_eq!(path.encode_utf16().count() + 1, 0x3b);
        for unit in path.encode_utf16() {
            blob.extend_from_slice(&unit.to_le_bytes());
        }
        blob.extend_from_slice(&[0u8; 2]);
        assert_eq!(
            recycle_display_name(&blob),
            Some("q2advanceog_win11_modern_res_1080_1440_4k.exe".to_string())
        );
    }

    fn recycle_fs() -> MemoryFs {
        let mut fs = MemoryFs::new();
        fs.add_file_bytes(r"C:\$Recycle.Bin\S-1-5-21-1\$Rabc.txt", vec![7; 32], None);
        fs.add_file_bytes(
            r"C:\$Recycle.Bin\S-1-5-21-1\$Iabc.txt",
            meta_blob(r"C:\Users\Test\old.txt"),
            None,
        );
        fs.add_file_bytes(r"C:\$Recycle.Bin\S-1-5-21-1\$Ilone", vec![0; 8], None);
        fs.add_file(r"C:\$Recycle.Bin\S-1-5-21-1\desktop.ini");
        fs
    }

    #[test]
    fn list_recycle_bin_finds_pairs() {
        let fs = recycle_fs();
        let (items, notes) = list_recycle_bin(&fs, &["C:".to_string()]);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].display, "old.txt");
        assert_eq!(items[0].bytes, 32);
        assert_eq!(items[0].sid, "s-1-5-21-1");
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("$ilone") && notes[0].contains("unpaired"));
    }

    #[test]
    fn shred_recycle_items_removes_meta_of_shredded() {
        let mut fs = recycle_fs();
        let (items, _) = list_recycle_bin(&fs, &["C:".to_string()]);
        let outcome =
            shred_recycle_items(&mut fs, &items, &ShredOptions::default(), SEED, &mut allow);
        assert_eq!(outcome.shredded, 1);
        assert_eq!(outcome.bytes, 32);
        assert!(outcome.errors.is_empty());
        assert!(!fs.exists(r"C:\$Recycle.Bin\S-1-5-21-1\$Rabc.txt"));
        assert!(!fs.exists(r"C:\$Recycle.Bin\S-1-5-21-1\$Iabc.txt"));
        assert!(fs.exists(r"C:\$Recycle.Bin\S-1-5-21-1\$Ilone"));
    }

    #[test]
    fn verify_rejects_tampered_bytes() {
        let mut fs = MemoryFs::new();
        fs.add_file_bytes(r"C:\Docs\v.dat", vec![0; 100], None);
        assert!(verify_file(&fs, r"C:\Docs\v.dat", 100, 0, SEED, 0));
        fs.write_at(r"C:\Docs\v.dat", 50, &[0x41]).unwrap();
        assert!(!verify_file(&fs, r"C:\Docs\v.dat", 100, 0, SEED, 0));
    }

    #[test]
    fn seek_penalty_descriptor_parses() {
        // Full 12-byte descriptors, as the Windows caller hands over.
        assert_eq!(
            seek_penalty_false(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Some(true)
        );
        assert_eq!(
            seek_penalty_false(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),
            Some(false)
        );
        assert_eq!(seek_penalty_false(&[0; 8]), None);
    }

    #[test]
    fn method_from_passes_round_trips() {
        assert_eq!(ShredMethod::from_passes(1), Some(ShredMethod::OnePass));
        assert_eq!(ShredMethod::from_passes(3), Some(ShredMethod::ThreePass));
        assert_eq!(ShredMethod::from_passes(7), Some(ShredMethod::SevenPass));
        assert_eq!(ShredMethod::from_passes(0), None);
        assert_eq!(ShredMethod::from_passes(5), None);
        assert_eq!(ShredMethod::OnePass.passes(), 1);
        assert_eq!(ShredMethod::ThreePass.passes(), 3);
        assert_eq!(ShredMethod::SevenPass.passes(), 7);
    }
}

/// Live Windows test. Shreds one file it creates under the temp folder, so it
/// exercises the real HostFs overwrite, verify, truncate, rename, and delete
/// path end to end without touching anything else.
#[cfg(all(test, windows))]
mod live_tests {
    use super::*;
    use crate::fs::HostFs;

    #[test]
    fn live_shred_removes_a_real_temp_file() {
        let dir = std::env::temp_dir().join(format!("hivemend-shred-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("make temp dir");
        let path = dir.join("secret.bin");
        std::fs::write(&path, vec![0xABu8; 4096]).expect("write temp file");
        let text = path.display().to_string();

        // A plain temp-folder file must pass the staging gate.
        assert!(
            shred_allowed(&HostFs, &text).is_ok(),
            "temp file should be shreddable"
        );

        let outcome = shred_paths(
            &mut HostFs,
            &[ShredTarget {
                path: text.clone(),
                is_dir: false,
            }],
            &ShredOptions {
                method: ShredMethod::ThreePass,
                rename: true,
            },
            0x1234_5678_9abc_def0,
            &mut |_, _, _| true,
        );
        assert_eq!(outcome.shredded, 1, "errors: {:?}", outcome.errors);
        assert_eq!(outcome.bytes, 4096);
        assert!(outcome.errors.is_empty(), "errors: {:?}", outcome.errors);
        assert!(outcome.refused.is_empty(), "refused: {:?}", outcome.refused);
        assert!(
            !std::path::Path::new(&text).exists(),
            "shredded file still present"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
