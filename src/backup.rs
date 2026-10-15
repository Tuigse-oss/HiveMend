use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::model::{Finding, RegValue, Repair, ValueKind};
use crate::pathutil::canonical_path;
use crate::registry::{RegError, Registry};

/// Registry paths cannot nest deeper than this, and a backup that stops short
/// of the whole tree would let repair delete more than it saved.
const MAX_EXPORT_DEPTH: usize = 512;
const FILE_LINE: &str = "; file ";
const FILE_ARROW: &str = " => ";
/// Marker line every backup written here carries. Restore refuses files
/// without it, so a stray Regedit export or downloaded tweak can never be
/// merged by mistake. It is a mistake-guard, not a signature.
const BACKUP_MARKER: &str = "; Hive Mend backup.";
/// Service start-type backups carried their own marker before the markers were
/// unified. Restore still accepts it so a services backup written by an older
/// build can be undone.
const SERVICES_BACKUP_MARKER: &str = "; Hive Mend services backup.";

pub fn backup_name(now: SystemTime) -> String {
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("hive-mend-{}.reg", ymd_hms(secs))
}

/// A reserved backup file, written only through the handle that created
/// it, so nothing else can be truncated or redirected in its place.
/// Every [`append`](BackupWriter::append) is flushed to disk before it
/// returns: a repair deletes only after its record is durable.
pub struct BackupWriter {
    file: std::fs::File,
    path: PathBuf,
    started: bool,
}

impl BackupWriter {
    /// Reserve `<dir>\<stem>.reg`, or `<stem>-2.reg` and so on, by creating
    /// it. Two repairs in the same second never share a file.
    pub fn reserve(dir: &Path, stem: &str) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        for attempt in 0..10_000u32 {
            let name = if attempt == 0 {
                format!("{stem}.reg")
            } else {
                format!("{stem}-{}.reg", attempt + 1)
            };
            let path = dir.join(&name);
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                // Delete access, so an unused reservation is removed through
                // this handle; read sharing only, so nothing else can write,
                // rename, or delete it while it is held.
                const DELETE: u32 = 0x0001_0000;
                const GENERIC_WRITE: u32 = 0x4000_0000;
                const SYNCHRONIZE: u32 = 0x0010_0000;
                const FILE_SHARE_READ: u32 = 0x1;
                options.access_mode(GENERIC_WRITE | DELETE | SYNCHRONIZE);
                options.share_mode(FILE_SHARE_READ);
            }
            match options.open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        file,
                        path,
                        started: false,
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not reserve a unique backup name",
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// True until something has been written.
    pub fn is_empty(&self) -> bool {
        !self.started
    }

    /// Append `text` as UTF-16 (with the byte-order mark first) and flush it
    /// to disk.
    pub fn append(&mut self, text: &str) -> std::io::Result<()> {
        use std::io::Write;
        let mut bytes = Vec::with_capacity(text.len() * 2 + 2);
        if !self.started {
            bytes.extend([0xFF, 0xFE]);
        }
        for unit in text.encode_utf16() {
            bytes.extend(unit.to_le_bytes());
        }
        self.file.write_all(&bytes)?;
        self.file.sync_data()?;
        self.started = true;
        Ok(())
    }

    /// Remove an unused reservation, through its own handle. A file that
    /// has been written is a recovery record and is kept.
    pub fn discard(self) {
        if self.started {
            return;
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
            };
            let info = FILE_DISPOSITION_INFO { DeleteFile: true };
            unsafe {
                SetFileInformationByHandle(
                    self.file.as_raw_handle() as _,
                    FileDispositionInfo,
                    &info as *const _ as *const _,
                    std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
                );
            }
        }
        #[cfg(not(windows))]
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// A writer for tests, reserved in this process's own temp folder.
#[cfg(test)]
pub(crate) fn test_writer(stem: &str) -> BackupWriter {
    let dir = std::env::temp_dir().join(format!("hm-tests-{}", std::process::id()));
    BackupWriter::reserve(&dir, stem).expect("reserve a test backup")
}

/// Reserve the next `hive-mend-<time>.reg` in `dir`.
pub fn reserve_backup(dir: &Path, now: SystemTime) -> std::io::Result<BackupWriter> {
    let name = backup_name(now);
    BackupWriter::reserve(dir, name.strip_suffix(".reg").unwrap_or(&name))
}

/// The registry sections a backup holds for `repairs`, without the file's
/// header, and the keys that could not be read.
pub fn registry_sections(reg: &dyn Registry, repairs: &[Repair]) -> (String, Vec<String>) {
    let registry: Vec<Repair> = repairs
        .iter()
        .filter(|repair| {
            matches!(
                repair,
                Repair::DeleteKey { .. } | Repair::DeleteValue { .. }
            )
        })
        .cloned()
        .collect();
    let plan = export_repairs(reg, &registry, Path::new("unused.reg"));
    let body = plan
        .body
        .split_once(HEADER_END)
        .map(|(_, rest)| rest.to_string())
        .unwrap_or_default();
    (body, plan.unreadable)
}

/// The last line of every backup's header.
const HEADER_END: &str = "; Restore it from the Restore page in Hivemend.\r\n";

/// What a repair is about to remove, in `.reg` form.
pub struct BackupPlan {
    pub body: String,
    /// Keys that could not be read completely. Repair leaves every finding
    /// under these alone, because the backup could not put them back.
    pub unreadable: Vec<String>,
    /// Shortcut path and the copy kept next to the backup.
    pub file_copies: Vec<(String, PathBuf)>,
}

impl BackupPlan {
    pub fn covers(&self, key: &str) -> bool {
        let key = canonical_path(key);
        !self
            .unreadable
            .iter()
            .any(|bad| bad.eq_ignore_ascii_case(&key))
    }

    pub fn copy_for(&self, path: &str) -> Option<&Path> {
        self.file_copies
            .iter()
            .find(|(original, _)| original.eq_ignore_ascii_case(path))
            .map(|(_, copy)| copy.as_path())
    }
}

/// The folder that holds shortcut copies for one backup file.
pub fn files_dir(backup_file: &Path) -> PathBuf {
    let stem = backup_file
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("hive-mend");
    backup_file
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!("{stem}-files"))
}

pub fn export_backup(reg: &dyn Registry, findings: &[Finding], backup_file: &Path) -> BackupPlan {
    let repairs: Vec<Repair> = findings
        .iter()
        .map(|finding| finding.repair.clone())
        .collect();
    export_repairs(reg, &repairs, backup_file)
}

/// Same `.reg` backup as [`export_backup`], for callers whose removals are
/// not scan findings (privacy categories build `Repair` values directly).
pub fn export_repairs(reg: &dyn Registry, repairs: &[Repair], backup_file: &Path) -> BackupPlan {
    let mut trees: Vec<String> = Vec::new();
    let mut values: Vec<(String, Vec<String>)> = Vec::new();
    let mut files: Vec<(String, bool)> = Vec::new();
    for repair in repairs {
        match repair {
            Repair::DeleteKey { key } => {
                let key = canonical_path(key);
                if !trees.iter().any(|have| have.eq_ignore_ascii_case(&key)) {
                    trees.push(key);
                }
            }
            Repair::DeleteValue { key, name } => {
                let key = canonical_path(key);
                match values
                    .iter_mut()
                    .find(|(have, _)| have.eq_ignore_ascii_case(&key))
                {
                    Some((_, names)) => {
                        if !names.contains(name) {
                            names.push(name.clone());
                        }
                    }
                    None => values.push((key, vec![name.clone()])),
                }
            }
            Repair::DeleteFile { path, keep_copy } => {
                if !files
                    .iter()
                    .any(|(have, _)| have.eq_ignore_ascii_case(path))
                {
                    files.push((path.clone(), *keep_copy));
                }
            }
            Repair::None => {}
        }
    }
    trees.sort_by_key(|key| key.to_ascii_lowercase());
    values.sort_by_key(|(key, _)| key.to_ascii_lowercase());

    let mut body = String::from("Windows Registry Editor Version 5.00\r\n\r\n");
    body.push_str(BACKUP_MARKER);
    body.push_str("\r\n");
    body.push_str(HEADER_END);
    let mut unreadable = Vec::new();

    for key in trees {
        let mut section = String::new();
        match export_tree(reg, &key, 0, &mut section) {
            Ok(()) => {
                body.push_str("\r\n");
                body.push_str(&section);
            }
            Err(RegError::NotFound) => {
                body.push_str(&format!("\r\n; already gone {key}\r\n"));
            }
            Err(err) => {
                body.push_str(&format!(
                    "\r\n; not backed up, left alone: {key}: {err}\r\n"
                ));
                unreadable.push(key);
            }
        }
    }

    for (key, names) in values {
        // A single value backup must validate names too: a Run value whose
        // name holds CR/LF or trailing whitespace cannot round-trip, so the
        // whole key is marked uncovered and repair leaves every value under it.
        if unrepresentable_name(&key) || names.iter().any(|name| unrepresentable_name(name)) {
            body.push_str(&format!(
                "\r\n; not backed up, left alone: {key}: a value name cannot be represented in a .reg backup\r\n"
            ));
            unreadable.push(key);
            continue;
        }
        match reg.values(&key) {
            Ok(present) => {
                body.push_str(&format!("\r\n[{key}]\r\n"));
                for name in names {
                    match present
                        .iter()
                        .find(|value| value.name.eq_ignore_ascii_case(&name))
                    {
                        Some(value) => {
                            body.push_str(&format_value(value));
                            body.push_str("\r\n");
                        }
                        None => {
                            body.push_str(&format!("; already gone {}\r\n", value_label(&name)));
                        }
                    }
                }
            }
            Err(RegError::NotFound) => body.push_str(&format!("\r\n; already gone {key}\r\n")),
            Err(err) => {
                body.push_str(&format!(
                    "\r\n; not backed up, left alone: {key}: {err}\r\n"
                ));
                unreadable.push(key);
            }
        }
    }

    let mut file_copies = Vec::new();
    if !files.is_empty() {
        let dir = files_dir(backup_file);
        body.push_str("\r\n; Files\r\n");
        for (index, (path, keep_copy)) in files.into_iter().enumerate() {
            if keep_copy {
                let name = Path::new(&path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("shortcut.lnk");
                let copy = dir.join(format!("{:04}-{name}", index + 1));
                body.push_str(&format!(
                    "{FILE_LINE}{path}{FILE_ARROW}{}\r\n",
                    copy.display()
                ));
                file_copies.push((path, copy));
            } else {
                body.push_str(&format!("; removed without a copy {path}\r\n"));
            }
        }
    }

    BackupPlan {
        body,
        unreadable,
        file_copies,
    }
}

fn value_label(name: &str) -> String {
    if name.is_empty() {
        "(default)".into()
    } else {
        name.to_string()
    }
}

fn export_tree(
    reg: &dyn Registry,
    path: &str,
    depth: usize,
    body: &mut String,
) -> Result<(), RegError> {
    if depth > MAX_EXPORT_DEPTH {
        return Err(RegError::Message(format!("{path} is nested too deeply")));
    }
    let values = reg.values(path)?;
    // A key or value name with a control character (CR, LF, NUL, ...) cannot
    // be written as an exact quoted `.reg` name, so the backup would not round
    // trip. Refuse the whole key rather than let repair delete something the
    // backup cannot put back.
    if unrepresentable_name(path) {
        return Err(RegError::Message(format!(
            "{path}: key name cannot be represented in a .reg backup"
        )));
    }
    if let Some(value) = values
        .iter()
        .find(|value| unrepresentable_name(&value.name))
    {
        return Err(RegError::Message(format!(
            "{path}: value name {:?} cannot be represented in a .reg backup",
            value.name
        )));
    }
    body.push_str(&format!("[{}]\r\n", canonical_path(path)));
    for value in values {
        body.push_str(&format_value(&value));
        body.push_str("\r\n");
    }
    body.push_str("\r\n");
    let children = match reg.subkeys(path) {
        Ok(children) => children,
        Err(RegError::NotFound) => Vec::new(),
        Err(err) => return Err(err),
    };
    for child in children {
        let child_path = format!("{}\\{child}", canonical_path(path));
        match export_tree(reg, &child_path, depth + 1, body) {
            Ok(()) => {}
            // A child that was just listed but cannot be read back (a name
            // canonicalization would alter, such as trailing whitespace, or a
            // child removed mid-read) must not be silently dropped: delete_tree
            // would still remove it with no backup. Fail the key's coverage.
            Err(RegError::NotFound) => {
                return Err(RegError::Message(format!(
                    "{child_path}: a listed subkey could not be backed up"
                )));
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

pub(crate) fn format_value(value: &RegValue) -> String {
    let name = if value.name.is_empty() {
        "@".to_string()
    } else {
        format!("\"{}\"", escape_reg(&value.name))
    };
    match &value.data {
        ValueKind::Sz(text) if text.chars().all(|ch| ch >= ' ') => {
            format!("{name}=\"{}\"", escape_reg(text))
        }
        ValueKind::Sz(text) => hex_value(&name, 1, utf16_bytes(text)),
        ValueKind::ExpandSz(text) => hex_value(&name, 2, utf16_bytes(text)),
        ValueKind::Dword(data) => format!("{name}=dword:{data:08x}"),
        ValueKind::MultiSz(parts) => {
            let mut bytes = Vec::new();
            for part in parts {
                bytes.extend(utf16_bytes(part));
            }
            bytes.extend([0, 0]);
            hex_value(&name, 7, bytes)
        }
        ValueKind::Binary(bytes) => hex_value(&name, 3, bytes.clone()),
        ValueKind::Other { kind, bytes } => hex_value(&name, *kind, bytes.clone()),
    }
}

fn escape_reg(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

/// A control character (below U+0020) in a key or value name cannot survive a
/// quoted `.reg` round trip: CR/LF break the line, NUL truncates on import.
fn has_control_char(text: &str) -> bool {
    text.chars().any(|ch| (ch as u32) < 0x20)
}

/// A key or value name this backup cannot reproduce byte-for-byte, so repair
/// must leave it alone: a control character breaks or truncates the `.reg`
/// line, and leading or trailing whitespace is dropped when the path is
/// canonicalized, so the name written would not match the name removed.
fn unrepresentable_name(name: &str) -> bool {
    has_control_char(name) || name != name.trim()
}

fn utf16_bytes(text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for unit in text.encode_utf16() {
        bytes.extend(unit.to_le_bytes());
    }
    bytes.extend([0, 0]);
    bytes
}

/// `hex:` for REG_BINARY, `hex(N):` with N in hexadecimal for other types,
/// wrapped like Regedit so long values import cleanly.
fn hex_value(name: &str, kind: u32, bytes: Vec<u8>) -> String {
    let mut out = if kind == 3 {
        format!("{name}=hex:")
    } else {
        format!("{name}=hex({kind:x}):")
    };
    let mut line_len = out.len();
    for (index, byte) in bytes.iter().enumerate() {
        let last = index + 1 == bytes.len();
        out.push_str(&format!("{byte:02x}"));
        line_len += 2;
        if !last {
            out.push(',');
            line_len += 1;
            if line_len >= 76 {
                out.push_str("\\\r\n  ");
                line_len = 2;
            }
        }
    }
    out
}

pub fn ymd_hms(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    format!("{year:04}{month:02}{day:02}-{hour:02}{minute:02}{second:02}")
}

/// Howard Hinnant's civil_from_days, days since Unix epoch.
fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = (if month <= 2 { y + 1 } else { y }) as i32;
    (year, month, day)
}

/// A `.reg` body as Regedit writes it: UTF-16LE with a byte-order mark.
pub fn encode_reg(body: &str) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xFE];
    for unit in body.encode_utf16() {
        bytes.extend(unit.to_le_bytes());
    }
    bytes
}

/// Read a `.reg` file written by this program or by Regedit (UTF-16 or ANSI).
pub fn read_backup(path: &Path) -> Result<String, std::io::Error> {
    let bytes = std::fs::read(path)?;
    Ok(crate::rules::decode_text_owned(bytes))
}

/// What a backup file would put back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BackupSummary {
    pub keys: usize,
    pub values: usize,
    pub files: Vec<(String, PathBuf)>,
    /// Restoring writes to HKEY_LOCAL_MACHINE or another machine-wide hive.
    pub machine_wide: bool,
    /// Restoring writes to HKEY_CURRENT_USER.
    pub per_user: bool,
}

impl BackupSummary {
    pub fn parse(text: &str) -> Self {
        let mut summary = Self::default();
        let mut continued = false;
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            let was_continued = continued;
            continued = line.ends_with('\\');
            if was_continued {
                continue;
            }
            if let Some(key) = line.strip_prefix('[') {
                summary.keys += 1;
                let upper = key.to_ascii_uppercase();
                if upper.starts_with("HKEY_CURRENT_USER") || upper.starts_with("-HKEY_CURRENT_USER")
                {
                    summary.per_user = true;
                }
                if !upper.starts_with("HKEY_CURRENT_USER")
                    && !upper.starts_with("-HKEY_CURRENT_USER")
                {
                    summary.machine_wide = true;
                }
            } else if line.starts_with('"') || line.starts_with('@') {
                summary.values += 1;
            } else if let Some(rest) = line.strip_prefix(FILE_LINE)
                && let Some((original, copy)) = rest.split_once(FILE_ARROW)
            {
                summary
                    .files
                    .push((original.trim().to_string(), PathBuf::from(copy.trim())));
            }
        }
        summary
    }
}

#[derive(Clone, Debug)]
pub struct BackupInfo {
    pub path: PathBuf,
    /// Which store the file was listed from.
    pub store: crate::store::Store,
    pub modified: Option<SystemTime>,
    pub size: u64,
    pub summary: BackupSummary,
}

/// `.reg` files in one backup folder, newest first.
pub fn list_backups(dir: &Path, store: crate::store::Store) -> Vec<BackupInfo> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let is_reg = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("reg"));
        if !is_reg || !path.is_file() {
            continue;
        }
        let meta = entry.metadata().ok();
        let summary = read_backup(&path)
            .map(|text| BackupSummary::parse(&text))
            .unwrap_or_default();
        found.push(BackupInfo {
            store,
            modified: meta.as_ref().and_then(|meta| meta.modified().ok()),
            size: meta.map(|meta| meta.len()).unwrap_or(0),
            path,
            summary,
        });
    }
    found.sort_by_key(|info| std::cmp::Reverse(info.modified));
    found
}

/// True when the text carries a Hivemend marker line: the unified marker, or
/// the older services-only marker so a services backup can still be restored.
pub fn is_hive_mend_backup(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        line == BACKUP_MARKER || line == SERVICES_BACKUP_MARKER
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Repair, ScannerId};
    use crate::registry::MemoryRegistry;

    fn finding(key: &str, repair: Repair) -> Finding {
        Finding {
            scanner: ScannerId::StartupPrograms,
            scanner_name: "Startup Programs".into(),
            key: key.into(),
            value: None,
            detail: "missing".into(),
            repair,
        }
    }

    #[test]
    fn unix_epoch_is_1970() {
        assert_eq!(ymd_hms(0), "19700101-000000");
        assert!(ymd_hms(1_276_180_432).starts_with("20100610-"));
    }

    #[test]
    fn marker_distinguishes_own_backups_from_stray_reg_files() {
        let mut reg = MemoryRegistry::new();
        reg.set_sz(r"HKCU\Software\X", "Old", r"C:\Missing\old.exe");
        let plan = export_backup(
            &reg,
            &[finding(
                r"HKCU\Software\X",
                Repair::DeleteValue {
                    key: r"HKCU\Software\X".into(),
                    name: "Old".into(),
                },
            )],
            Path::new("test.reg"),
        );
        assert!(is_hive_mend_backup(&plan.body));
        assert!(!is_hive_mend_backup(
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\X]\r\n"
        ));
        assert!(!is_hive_mend_backup(""));
    }

    #[test]
    fn restore_accepts_the_services_backup_marker() {
        // New services backups carry the unified marker.
        assert!(is_hive_mend_backup(
            "Windows Registry Editor Version 5.00\r\n\r\n; Hive Mend backup.\r\n"
        ));
        // Older services backups carried only their own marker; still accepted.
        assert!(is_hive_mend_backup(
            "Windows Registry Editor Version 5.00\r\n\r\n; Hive Mend services backup.\r\n"
        ));
    }

    #[test]
    fn a_reserved_backup_is_written_through_its_own_handle() {
        let dir = std::env::temp_dir().join(format!("hivemend-reserve-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let now = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let mut first = reserve_backup(&dir, now).unwrap();
        let second = reserve_backup(&dir, now).unwrap();
        assert_ne!(first.path(), second.path());
        assert!(first.path().exists() && second.path().exists());
        // The matching sidecar directories differ too.
        assert_ne!(files_dir(first.path()), files_dir(second.path()));
        first
            .append("Windows Registry Editor Version 5.00\r\n")
            .unwrap();
        first.append("; Hive Mend backup.\r\n").unwrap();
        let text = read_backup(first.path()).unwrap();
        assert!(text.starts_with("Windows Registry Editor Version 5.00"));
        assert!(is_hive_mend_backup(&text));
        // An unused reservation goes; a written one is kept.
        let (first_path, second_path) = (first.path().to_path_buf(), second.path().to_path_buf());
        first.discard();
        second.discard();
        assert!(first_path.exists());
        assert!(!second_path.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_control_char_value_name_leaves_the_key_uncovered() {
        let mut reg = MemoryRegistry::new();
        let key = r"HKCU\Software\Weird";
        reg.set_sz(key, "ok", "fine");
        reg.set_sz(key, "bad\nname", "x");
        let plan = export_repairs(
            &reg,
            &[Repair::DeleteKey { key: key.into() }],
            Path::new("t.reg"),
        );
        // The key cannot round-trip, so repair must leave it alone.
        assert!(!plan.covers(key));
        assert!(
            plan.unreadable
                .iter()
                .any(|bad| bad.eq_ignore_ascii_case(&canonical_path(key)))
        );
    }

    #[test]
    fn a_control_char_in_a_deletevalue_name_leaves_the_key_uncovered() {
        // The single-value backup path must validate names too, not only the
        // whole-key export.
        let mut reg = MemoryRegistry::new();
        let key = r"HKCU\Software\Run";
        reg.set_sz(key, "Good", "x");
        reg.set_sz(key, "Bad\r\nEntry", "y");
        let plan = export_repairs(
            &reg,
            &[Repair::DeleteValue {
                key: key.into(),
                name: "Bad\r\nEntry".into(),
            }],
            Path::new("t.reg"),
        );
        assert!(!plan.covers(key));
    }

    #[test]
    fn a_subkey_name_that_cannot_be_reproduced_leaves_the_parent_uncovered() {
        use crate::model::RegValue;
        use crate::registry::{RegError, Registry};

        // A registry whose parent lists a child whose name ends in a space —
        // a name canonicalization would alter, so it cannot be backed up.
        struct TrailingSpace;
        impl Registry for TrailingSpace {
            fn subkeys(&self, path: &str) -> Result<Vec<String>, RegError> {
                if canonical_path(path).eq_ignore_ascii_case(r"HKEY_CURRENT_USER\Software\App") {
                    Ok(vec!["Saved ".to_string()])
                } else {
                    Ok(Vec::new())
                }
            }
            fn values(&self, _path: &str) -> Result<Vec<RegValue>, RegError> {
                Ok(Vec::new())
            }
            fn delete_value(&mut self, _path: &str, _name: &str) -> Result<(), RegError> {
                Ok(())
            }
            fn delete_tree(&mut self, _path: &str) -> Result<(), RegError> {
                Ok(())
            }
        }

        let parent = r"HKCU\Software\App";
        let plan = export_repairs(
            &TrailingSpace,
            &[Repair::DeleteKey { key: parent.into() }],
            Path::new("t.reg"),
        );
        // The listed child could not be exported, so the whole tree is left.
        assert!(!plan.covers(parent));
    }

    #[test]
    fn backup_exports_only_the_value_that_repair_would_remove() {
        let mut reg = MemoryRegistry::new();
        let run = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        reg.set_sz(run, "Old", r"C:\Missing\old.exe");
        reg.set_sz(run, "Keep", r"C:\Program Files\Keep\keep.exe");
        let plan = export_backup(
            &reg,
            &[finding(
                run,
                Repair::DeleteValue {
                    key: run.into(),
                    name: "Old".into(),
                },
            )],
            Path::new("/tmp/b.reg"),
        );
        assert!(
            plan.body
                .starts_with("Windows Registry Editor Version 5.00")
        );
        assert!(plan.body.contains(r#""Old"="C:\\Missing\\old.exe""#));
        assert!(!plan.body.contains("Keep"));
        assert!(plan.unreadable.is_empty());
        let summary = BackupSummary::parse(&plan.body);
        assert_eq!(summary.values, 1);
        assert!(!summary.machine_wide);
    }

    #[test]
    fn key_backup_includes_the_whole_tree_and_qword_types() {
        let mut reg = MemoryRegistry::new();
        let mut deep =
            String::from(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Gone");
        for level in 0..10 {
            deep.push_str(&format!("\\L{level}"));
        }
        reg.set_sz(&deep, "Leaf", "bottom");
        reg.set(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Gone",
            "Size",
            ValueKind::Other {
                kind: 11,
                bytes: vec![1, 0, 0, 0, 0, 0, 0, 0],
            },
        );
        let key = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Gone";
        let plan = export_backup(
            &reg,
            &[finding(key, Repair::DeleteKey { key: key.into() })],
            Path::new("/tmp/b.reg"),
        );
        assert!(plan.body.contains(r#""Leaf"="bottom""#), "{}", plan.body);
        assert!(
            plan.body
                .contains(r#""Size"=hex(b):01,00,00,00,00,00,00,00"#)
        );
        let summary = BackupSummary::parse(&plan.body);
        assert_eq!(summary.keys, 11);
        assert!(summary.machine_wide);
    }

    #[test]
    fn long_binary_values_wrap_like_regedit() {
        let value = RegValue {
            name: "Blob".into(),
            data: ValueKind::Binary(vec![0xab; 100]),
        };
        let text = format_value(&value);
        assert!(text.starts_with(r#""Blob"=hex:ab,ab"#));
        assert!(text.contains("\\\r\n  ab"));
        let joined: String = text.split("\\\r\n  ").collect::<Vec<_>>().join("");
        assert_eq!(joined.matches("ab").count(), 100);
    }

    #[test]
    fn shortcut_copies_get_unique_names_and_are_listed() {
        let reg = MemoryRegistry::new();
        let one = r"C:\Users\Ada\Desktop\Tool.lnk";
        let two = r"C:\Users\Ada\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Tool.lnk";
        let plan = export_backup(
            &reg,
            &[
                finding(
                    one,
                    Repair::DeleteFile {
                        path: one.into(),
                        keep_copy: true,
                    },
                ),
                finding(
                    two,
                    Repair::DeleteFile {
                        path: two.into(),
                        keep_copy: true,
                    },
                ),
            ],
            Path::new("/backups/hive-mend-1.reg"),
        );
        let first = plan.copy_for(one).unwrap().to_path_buf();
        let second = plan.copy_for(two).unwrap().to_path_buf();
        assert_ne!(first, second);
        assert!(first.starts_with("/backups/hive-mend-1-files"));
        let summary = BackupSummary::parse(&plan.body);
        assert_eq!(summary.files.len(), 2);
        assert_eq!(summary.files[0].0, one);
        assert_eq!(summary.files[0].1, first);
    }
}
