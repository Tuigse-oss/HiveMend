//! Cookies to keep: trim a browser's cookie database down to the sites the
//! user listed, instead of deleting the whole file.
//!
//! The database is only edited while the browser is closed (the privacy
//! item's running-process check), and while Hivemend holds it alone: see
//! [`trim_cookies`]. The rows to remove are deleted in one transaction and
//! SQLite's integrity check must pass; any failure puts back a copy taken
//! in memory under the same lock. No spare copy of the cookies is left on
//! disk, since one would undo the cleaning.

use std::path::{Path, PathBuf};

/// Parse the keep list: one site per line (`example.com`), `#` comments.
/// Returns the sites and a warning for each line that is not a site name.
pub fn parse_keep_list(text: &str) -> (Vec<String>, Vec<String>) {
    let mut sites = Vec::new();
    let mut warnings = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let site = line
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_start_matches('.')
            .trim_end_matches('/')
            .to_ascii_lowercase();
        let valid = site.contains('.')
            && !site.starts_with('-')
            && site.split('.').all(|label| {
                !label.is_empty()
                    && label
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
            });
        if valid {
            if !sites.contains(&site) {
                sites.push(site);
            }
        } else {
            warnings.push(format!("line {}: {line} is not a site name", number + 1));
        }
    }
    (sites, warnings)
}

/// True when a cookie for `host` (`.example.com`, `www.example.com`) belongs
/// to a kept site or one of its subdomains.
pub fn keeps(host: &str, sites: &[String]) -> bool {
    let host = host.trim_start_matches('.').to_ascii_lowercase();
    sites.iter().any(|site| {
        host == *site
            || host
                .strip_suffix(site.as_str())
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

/// Which table and column hold the cookie host, by database file name.
pub fn cookie_schema(file_name: &str) -> (&'static str, &'static str) {
    if file_name.eq_ignore_ascii_case("cookies.sqlite") {
        ("moz_cookies", "host")
    } else {
        ("cookies", "host_key")
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CookieCount {
    pub removed: usize,
    pub kept: usize,
}

fn open(path: &Path, flags: rusqlite::OpenFlags) -> Result<rusqlite::Connection, String> {
    let conn = rusqlite::Connection::open_with_flags(path, flags).map_err(|err| err.to_string())?;
    // A browser holding the database makes this fail at once, not wait.
    conn.busy_timeout(std::time::Duration::ZERO)
        .map_err(|err| err.to_string())?;
    Ok(conn)
}

/// Every cookie row: (rowid, host).
fn rows(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
) -> Result<Vec<(i64, String)>, String> {
    // The names come from `cookie_schema`, never from outside.
    let mut statement = conn
        .prepare(&format!("SELECT rowid, {column} FROM {table}"))
        .map_err(|err| format!("not a cookie database: {err}"))?;
    statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|err| err.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())
}

/// Count what trimming would remove, without changing anything.
pub fn count_cookies(path: &Path, sites: &[String]) -> Result<CookieCount, String> {
    let path = &spelled_out(path);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let (table, column) = cookie_schema(name);
    let conn = open(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let mut count = CookieCount::default();
    for (_, host) in rows(&conn, table, column)? {
        if keeps(&host, sites) {
            count.kept += 1;
        } else {
            count.removed += 1;
        }
    }
    Ok(count)
}

/// SQLite's side files: the rollback journal, the write-ahead log, and its
/// index. Each one present is checked like the database itself, since
/// SQLite writes through whatever file has that name.
const SIDE_SUFFIXES: [&str; 3] = ["-journal", "-wal", "-shm"];

fn side_path(path: &Path, suffix: &str) -> PathBuf {
    let mut side = path.as_os_str().to_owned();
    side.push(suffix);
    PathBuf::from(side)
}

const COPY_TAG: &str = ".hivemend-copy";

/// Copies an earlier run left behind (it keeps one when it cannot put a
/// database back).
fn leftover_copies(path: &Path) -> Vec<PathBuf> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return Vec::new();
    };
    let prefix = name.to_ascii_lowercase();
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|found| {
                    found
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(str::to_ascii_lowercase)
                        .is_some_and(|n| n.starts_with(&prefix) && n.contains(COPY_TAG))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Open `path` without following a link and check that it is a plain file
/// with one name, really at that path. Returns the handle and the file's
/// identity. With `hold`, the handle reads and shares only reading and
/// writing: until it is dropped nothing can rename, replace, or delete the
/// file, or rename a folder above it, while SQLite can still open it.
#[cfg(windows)]
fn check_plain_file(path: &Path, hold: bool) -> Result<(std::fs::File, (u64, u64)), String> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, SYNCHRONIZE,
    };
    let shown = path.display().to_string();
    let (access, share) = if hold {
        (
            GENERIC_READ | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )
    } else {
        (
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )
    };
    let file = std::fs::OpenOptions::new()
        .access_mode(access)
        .share_mode(share)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|err| format!("{shown}: {err}"))?;
    let id = verify_held(&file, path)?;
    Ok((file, id))
}

/// Create `path` as a new, empty side file for SQLite to use, held like a
/// checked one (sharing reading and writing only) and verified the same way.
#[cfg(windows)]
fn create_side_file(path: &Path) -> Result<(std::fs::File, (u64, u64)), String> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
    };
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|err| format!("{}: {err}", path.display()))?;
    let id = verify_held(&file, path)?;
    Ok((file, id))
}

#[cfg(not(windows))]
fn create_side_file(path: &Path) -> Result<(std::fs::File, (u64, u64)), String> {
    use std::os::unix::fs::MetadataExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| format!("{}: {err}", path.display()))?;
    let meta = file.metadata().map_err(|err| err.to_string())?;
    Ok((file, (meta.dev(), meta.ino())))
}

/// The open file must be a plain file with one name, really at `path`
/// (with any short names spelled out). Returns its identity.
#[cfg(windows)]
fn verify_held(file: &std::fs::File, path: &Path) -> Result<(u64, u64), String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        GetFileInformationByHandle,
    };
    let shown = path.display().to_string();
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) } == 0 {
        return Err(format!("{shown}: {}", std::io::Error::last_os_error()));
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(format!("{shown} is not a plain file"));
    }
    if info.nNumberOfLinks != 1 {
        return Err(format!("{shown} has more than one name (a hard link)"));
    }
    // The real path from the handle must be the given one, with any short
    // (8.3) names spelled out: a link anywhere on the way makes them differ.
    let real = crate::fs::host_final_path(file)?;
    let expected = long_path(&shown).unwrap_or_else(|| shown.clone());
    if !real.eq_ignore_ascii_case(&expected) {
        return Err(format!("{shown} is really {real}"));
    }
    Ok((
        u64::from(info.dwVolumeSerialNumber),
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

/// `path` with any short (8.3) names spelled out (as it is when it does not
/// exist or cannot be read).
fn spelled_out(path: &Path) -> PathBuf {
    #[cfg(windows)]
    if let Some(long) = path.to_str().and_then(long_path) {
        return PathBuf::from(long);
    }
    path.to_path_buf()
}

/// `path` with its short (8.3) names spelled out; links are not resolved.
#[cfg(windows)]
fn long_path(path: &str) -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::GetLongPathNameW;
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut buf = vec![0u16; 1024];
    let len =
        unsafe { GetLongPathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
    (len > 0 && len < buf.len()).then(|| String::from_utf16_lossy(&buf[..len]))
}

#[cfg(not(windows))]
fn check_plain_file(path: &Path, _hold: bool) -> Result<(std::fs::File, (u64, u64)), String> {
    use std::os::unix::fs::MetadataExt;
    let shown = path.display();
    let meta = std::fs::symlink_metadata(path).map_err(|err| format!("{shown}: {err}"))?;
    if !meta.is_file() {
        return Err(format!("{shown} is not a plain file"));
    }
    if meta.nlink() != 1 {
        return Err(format!("{shown} has more than one name (a hard link)"));
    }
    let file = std::fs::File::open(path).map_err(|err| format!("{shown}: {err}"))?;
    Ok((file, (meta.dev(), meta.ino())))
}

/// A side file held for the whole edit, and whether Hivemend made it.
struct HeldSide {
    path: PathBuf,
    file: std::fs::File,
    #[cfg_attr(not(windows), allow(dead_code))]
    id: (u64, u64),
}

/// Hold every side file that exists, after checking it, and make (and hold)
/// the one SQLite will write if it is missing: the rollback journal, or the
/// write-ahead log for a WAL database. Nothing else may be opened.
fn bind_side_files(path: &Path, wal: bool) -> Result<Vec<HeldSide>, String> {
    let mut held = Vec::new();
    for suffix in SIDE_SUFFIXES {
        let side = side_path(path, suffix);
        let needed = (suffix == "-journal" && !wal) || (suffix == "-wal" && wal);
        match std::fs::symlink_metadata(&side) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if needed {
                    let (file, id) = create_side_file(&side)?;
                    held.push(HeldSide {
                        path: side,
                        file,
                        id,
                    });
                }
            }
            Err(err) => return Err(format!("{}: {err}", side.display())),
            Ok(_) => {
                let (file, id) = check_plain_file(&side, true)?;
                held.push(HeldSide {
                    path: side,
                    file,
                    id,
                });
            }
        }
    }
    Ok(held)
}

/// True when the database's header says it uses a write-ahead log.
fn uses_wal(db: &std::fs::File) -> Result<bool, String> {
    let mut header = [0u8; 20];
    #[cfg(windows)]
    let read = {
        use std::os::windows::fs::FileExt;
        db.seek_read(&mut header, 0)
    };
    #[cfg(not(windows))]
    let read = {
        use std::os::unix::fs::FileExt;
        db.read_at(&mut header, 0)
    };
    match read {
        Ok(20) => Ok(header[18] == 2 || header[19] == 2),
        Ok(_) => Err("not a cookie database: too short".into()),
        Err(err) => Err(err.to_string()),
    }
}

/// Points in a trim where a test can step in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// The database is held alone and checked; nothing is written yet.
    Locked,
    /// The rows are removed and committed; the checks are next.
    Committed,
}

/// Remove every cookie not for a kept site, in place.
///
/// The database is held so it cannot be renamed or replaced, and it and
/// every SQLite side file must be a plain file with one name at its own
/// path, before SQLite opens anything. SQLite then takes it alone for the
/// whole run (no other program can read or write it), the files are checked
/// again, and a consistent copy is taken in memory with SQLite's backup.
/// The rows go in one transaction. If anything fails after the commit, the
/// copy is put back through the same locked connection; only if that fails
/// is the copy saved beside the database, and its place reported. Nothing
/// else ever writes a copy of the cookies to disk.
pub fn trim_cookies(path: &Path, sites: &[String]) -> Result<CookieCount, String> {
    trim_with(path, sites, &mut |_| Ok(()))
}

fn trim_with(
    path: &Path,
    sites: &[String],
    at: &mut dyn FnMut(Stage) -> Result<(), String>,
) -> Result<CookieCount, String> {
    let unchanged = |message: String| format!("{message}. Nothing was changed");
    // SQLite names the side files after the spelling it is given, so a
    // short (8.3) spelling would miss the real ones: use the long form.
    let path = &spelled_out(path);
    let earlier = leftover_copies(path);
    if !earlier.is_empty() {
        return Err(format!(
            "an earlier copy is still at {}; Hivemend kept it because a database could not be put back. Check it, then delete it to clean again",
            earlier[0].display()
        ));
    }
    let (held, id) = check_plain_file(path, true).map_err(unchanged)?;
    #[cfg(not(windows))]
    let _ = id;
    let wal = uses_wal(&held).map_err(unchanged)?;
    let sides = bind_side_files(path, wal).map_err(unchanged)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let (table, column) = cookie_schema(name);
    // SQLite may open only the held, verified objects; see sqlite_bind.
    #[cfg(windows)]
    let vfs = {
        let mut allowed = vec![crate::sqlite_bind::Allowed {
            path: path.display().to_string(),
            id,
        }];
        allowed.extend(sides.iter().map(|side| crate::sqlite_bind::Allowed {
            path: side.path.display().to_string(),
            id: side.id,
        }));
        crate::sqlite_bind::BoundVfs::register(allowed).map_err(unchanged)?
    };
    let refused = || {
        #[cfg(windows)]
        {
            let refused = vfs.refused();
            if !refused.is_empty() {
                return format!(" (refused: {})", refused.join("; "));
            }
        }
        String::new()
    };
    let flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    #[cfg(windows)]
    let opened = rusqlite::Connection::open_with_flags_and_vfs(path, flags, vfs.name());
    #[cfg(not(windows))]
    let opened = rusqlite::Connection::open_with_flags(path, flags);
    let mut conn = opened.map_err(|err| unchanged(format!("{err}{}", refused())))?;
    conn.busy_timeout(std::time::Duration::ZERO)
        .map_err(|err| unchanged(err.to_string()))?;
    // Take the database alone, and keep it until the connection closes: an
    // empty exclusive transaction takes the lock and the locking mode keeps
    // it. If any other program has it open, this fails before any write.
    // The side files are kept, never deleted: a rollback journal is cut to
    // nothing on each commit, and a write-ahead log is kept after closing.
    // Removed rows are overwritten, not just unlinked, so a removed cookie
    // does not linger in free pages of the database.
    conn.pragma_update(None, "locking_mode", "EXCLUSIVE")
        .and_then(|()| conn.pragma_update(None, "secure_delete", "ON"))
        .and_then(|()| {
            if wal {
                keep_wal(&conn)
            } else {
                let mode: String =
                    conn.query_row("PRAGMA journal_mode=TRUNCATE", [], |row| row.get(0))?;
                if mode.eq_ignore_ascii_case("truncate") {
                    Ok(())
                } else {
                    Err(rusqlite::Error::InvalidQuery)
                }
            }
        })
        .and_then(|()| conn.execute_batch("BEGIN EXCLUSIVE; COMMIT;"))
        .map_err(|err| unchanged(format!("{}{}", busy(err), refused())))?;
    at(Stage::Locked).map_err(unchanged)?;
    let mut snapshot =
        rusqlite::Connection::open_in_memory().map_err(|err| unchanged(err.to_string()))?;
    copy_all(&conn, &mut snapshot)
        .map_err(|err| unchanged(format!("could not copy it first: {err}")))?;
    let count = match remove_rows(&mut conn, table, column, sites) {
        Ok(count) => count,
        Err(Edit {
            message,
            changed: false,
        }) => return Err(unchanged(message)),
        Err(Edit { message, .. }) => return Err(put_back(conn, &snapshot, path, message)),
    };
    match at(Stage::Committed).and_then(|()| settle(&conn)) {
        Ok(()) => {
            let closed = conn.close().map_err(|(_, err)| err.to_string());
            // No removed cookie may linger in a side file.
            let lingering: Vec<String> = sides
                .iter()
                .filter(|side| !side.path.to_string_lossy().ends_with("-shm"))
                .filter(|side| side.file.metadata().map(|meta| meta.len()).unwrap_or(1) > 0)
                .map(|side| side.path.display().to_string())
                .collect();
            drop(sides);
            drop(held);
            closed.map_err(|err| {
                format!("the cookies were removed, but closing the database failed: {err}")
            })?;
            if !lingering.is_empty() {
                return Err(format!(
                    "the cookies were removed, but {} still holds data",
                    lingering.join(", ")
                ));
            }
            Ok(count)
        }
        Err(err) => Err(put_back(conn, &snapshot, path, err)),
    }
}

/// Keep the write-ahead log file when the connection closes (SQLite would
/// otherwise delete it, and a file of that name could be made anew).
fn keep_wal(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let mut on: std::ffi::c_int = 1;
    let rc = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            conn.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
            &mut on as *mut std::ffi::c_int as *mut std::ffi::c_void,
        )
    };
    if rc == rusqlite::ffi::SQLITE_OK {
        Ok(())
    } else {
        Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rc),
            Some("could not keep the write-ahead log".into()),
        ))
    }
}

fn busy(err: rusqlite::Error) -> String {
    match err.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            "another program is using the database".to_string()
        }
        _ => err.to_string(),
    }
}

/// Copy the whole of `from` into `to` in one step.
fn copy_all(from: &rusqlite::Connection, to: &mut rusqlite::Connection) -> Result<(), String> {
    let backup = rusqlite::backup::Backup::new(from, to).map_err(|err| err.to_string())?;
    match backup.step(-1).map_err(|err| err.to_string())? {
        rusqlite::backup::StepResult::Done => Ok(()),
        other => Err(format!("the copy did not finish ({other:?})")),
    }
}

/// Why removing rows failed, and whether it may have written anything.
struct Edit {
    message: String,
    changed: bool,
}

fn remove_rows(
    conn: &mut rusqlite::Connection,
    table: &str,
    column: &str,
    sites: &[String],
) -> Result<CookieCount, Edit> {
    let before = |message: String| Edit {
        message,
        changed: false,
    };
    let mut count = CookieCount::default();
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)
        .map_err(|err| before(busy(err)))?;
    let all = rows(&tx, table, column).map_err(before)?;
    {
        let mut delete = tx
            .prepare(&format!("DELETE FROM {table} WHERE rowid = ?1"))
            .map_err(|err| before(err.to_string()))?;
        for (rowid, host) in all {
            if keeps(&host, sites) {
                count.kept += 1;
            } else {
                delete
                    .execute([rowid])
                    .map_err(|err| before(err.to_string()))?;
                count.removed += 1;
            }
        }
    }
    // Until the commit, a failure rolls the transaction back itself. A
    // failed commit may have written part of it, so it is put back.
    tx.commit().map_err(|err| Edit {
        message: err.to_string(),
        changed: true,
    })?;
    Ok(count)
}

/// After the commit: the integrity check must pass, and a write-ahead log
/// is folded back in so no removed row lingers there.
fn settle(conn: &rusqlite::Connection) -> Result<(), String> {
    let check: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|err| err.to_string())?;
    if check != "ok" {
        return Err(format!(
            "the database failed its check after the edit: {check}"
        ));
    }
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|err| err.to_string())?;
    if mode.eq_ignore_ascii_case("wal") {
        // The first column is 1 when the checkpoint was blocked, which is
        // not a failed query but is a failed clean.
        let blocked: i64 = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .map_err(|err| err.to_string())?;
        if blocked != 0 {
            return Err("the write-ahead log could not be folded in".into());
        }
    }
    Ok(())
}

/// Put the copy taken under the lock back through the same connection,
/// which still holds the database alone. If that fails, save the copy
/// beside the database so nothing is lost, and say where it is.
fn put_back(
    mut conn: rusqlite::Connection,
    snapshot: &rusqlite::Connection,
    path: &Path,
    err: String,
) -> String {
    let restored = copy_all(snapshot, &mut conn).and_then(|()| {
        let check: String = conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|err| err.to_string())?;
        if check == "ok" { Ok(()) } else { Err(check) }
    });
    match restored {
        Ok(()) => match conn.close() {
            Ok(()) => format!("{err}. The database was put back as it was"),
            Err((_, why)) => {
                format!("{err}. The database was put back as it was, but closing it failed: {why}")
            }
        },
        Err(why) => {
            drop(conn);
            match save_copy(snapshot, path) {
                Ok(copy) => format!(
                    "{err}. Putting the database back also failed ({why}), so a copy of it as it was is kept at {}; Hivemend leaves this database alone until that copy is gone",
                    copy.display()
                ),
                Err(save) => format!(
                    "{err}. Putting the database back also failed ({why}), and saving a copy of it failed too ({save})"
                ),
            }
        }
    }
}

/// Save the in-memory copy to a new file beside the database, never over
/// an existing one.
fn save_copy(snapshot: &rusqlite::Connection, path: &Path) -> Result<PathBuf, String> {
    for attempt in 0..100u32 {
        let mut name = path.as_os_str().to_owned();
        name.push(format!("{COPY_TAG}-{}-{attempt}", std::process::id()));
        let copy = PathBuf::from(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&copy)
        {
            Ok(mut file) => {
                // Written through the handle that made the file, never by
                // opening its name again.
                use std::io::Write;
                let data = snapshot
                    .serialize(rusqlite::MAIN_DB)
                    .map_err(|err| format!("{}: {err}", copy.display()))?;
                file.write_all(&data)
                    .and_then(|()| file.sync_all())
                    .map_err(|err| format!("{}: {err}", copy.display()))?;
                return Ok(copy);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.to_string()),
        }
    }
    Err("no free name for the copy".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_list_lines_become_sites() {
        let (sites, warnings) = parse_keep_list(
            "# mine\nGitHub.com\nhttps://mail.google.com/\n.example.org\nnot a site\nlocalhost\n",
        );
        assert_eq!(sites, ["github.com", "mail.google.com", "example.org"]);
        assert_eq!(warnings.len(), 2);
    }

    #[test]
    fn subdomains_are_kept_but_lookalikes_are_not() {
        let sites = vec!["github.com".to_string()];
        assert!(keeps(".github.com", &sites));
        assert!(keeps("gist.github.com", &sites));
        assert!(keeps("GITHUB.COM", &sites));
        assert!(!keeps("notgithub.com", &sites));
        assert!(!keeps("github.com.evil.net", &sites));
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hm-cookies-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_db(path: &Path, table: &str, column: &str, hosts: &[&str]) {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE {table} ({column} TEXT NOT NULL, name TEXT, value TEXT);"
        ))
        .unwrap();
        for host in hosts {
            conn.execute(
                &format!("INSERT INTO {table} ({column}, name, value) VALUES (?1, 'id', 'x')"),
                [host],
            )
            .unwrap();
        }
    }

    #[test]
    fn trimming_keeps_listed_sites_and_leaves_no_copy() {
        let dir = scratch("trim");
        let db = dir.join("Cookies");
        make_db(
            &db,
            "cookies",
            "host_key",
            &[
                ".github.com",
                "ads.example.net",
                "github.com",
                ".tracker.io",
            ],
        );
        let sites = vec!["github.com".to_string()];
        assert_eq!(
            count_cookies(&db, &sites).unwrap(),
            CookieCount {
                removed: 2,
                kept: 2
            }
        );
        assert_eq!(
            trim_cookies(&db, &sites).unwrap(),
            CookieCount {
                removed: 2,
                kept: 2
            }
        );
        assert_eq!(
            count_cookies(&db, &sites).unwrap(),
            CookieCount {
                removed: 0,
                kept: 2
            }
        );
        assert_only_the_database(&dir, "Cookies");
        // Firefox names its table and column differently.
        let fox = dir.join("cookies.sqlite");
        make_db(&fox, "moz_cookies", "host", &[".github.com", ".tracker.io"]);
        assert_eq!(
            trim_cookies(&fox, &sites).unwrap(),
            CookieCount {
                removed: 1,
                kept: 1
            }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_removed_cookie_does_not_linger_in_the_file() {
        let dir = scratch("secure-delete");
        let db = dir.join("Cookies");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE cookies (host_key TEXT NOT NULL, name TEXT, value TEXT);")
            .unwrap();
        conn.execute(
            "INSERT INTO cookies VALUES ('.tracker.io', 'id', 'SECRETVALUE1234567890')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cookies VALUES ('.github.com', 'id', 'keepme')",
            [],
        )
        .unwrap();
        drop(conn);
        trim_cookies(&db, &["github.com".to_string()]).unwrap();
        let bytes = std::fs::read(&db).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let has = |needle: &[u8]| bytes.windows(needle.len()).any(|window| window == needle);
        assert!(
            !has(b"SECRETVALUE1234567890"),
            "the removed value is still in the file"
        );
        assert!(!has(b".tracker.io"));
        assert!(has(b"keepme"));
    }

    #[test]
    fn an_earlier_copy_is_never_overwritten() {
        let dir = scratch("leftover");
        let db = dir.join("Cookies");
        make_db(&db, "cookies", "host_key", &[".tracker.io"]);
        let earlier = dir.join("Cookies.hivemend-copy-1-0");
        std::fs::write(&earlier, b"the only good copy").unwrap();
        let before = std::fs::read(&db).unwrap();
        let err = trim_cookies(&db, &["github.com".to_string()]).unwrap_err();
        assert!(err.contains("earlier copy"), "{err}");
        assert_eq!(std::fs::read(&earlier).unwrap(), b"the only good copy");
        assert_eq!(std::fs::read(&db).unwrap(), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_database_another_program_holds_is_left_unchanged() {
        let dir = scratch("busy");
        let db = dir.join("cookies.sqlite");
        make_db(&db, "moz_cookies", "host", &[".github.com", ".tracker.io"]);
        let reader = rusqlite::Connection::open(&db).unwrap();
        reader.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        // Another program holding a read transaction blocks TRUNCATE.
        reader
            .execute_batch("BEGIN; SELECT count(*) FROM moz_cookies;")
            .unwrap();
        let err = trim_cookies(&db, &["github.com".to_string()]).unwrap_err();
        assert!(err.contains("another program"), "{err}");
        assert!(err.contains("Nothing was changed"), "{err}");
        reader.execute_batch("COMMIT;").unwrap();
        drop(reader);
        let sites = vec!["zz.invalid".to_string()];
        assert_eq!(count_cookies(&db, &sites).unwrap().removed, 2, "unchanged");
        let copies = leftover_copies(&db);
        assert!(copies.is_empty(), "{copies:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_edit_puts_the_database_back() {
        let dir = scratch("fail");
        let db = dir.join("Cookies");
        // Not a cookie database: the edit fails and the file is unchanged.
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE other (x TEXT); INSERT INTO other VALUES ('keep me');")
            .unwrap();
        drop(conn);
        let before = std::fs::read(&db).unwrap();
        assert!(trim_cookies(&db, &["github.com".to_string()]).is_err());
        assert_eq!(std::fs::read(&db).unwrap(), before);
        assert_only_the_database(&dir, "Cookies");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn hosts(db: &Path, table: &str, column: &str) -> Vec<String> {
        let conn = rusqlite::Connection::open(db).unwrap();
        let mut hosts: Vec<String> = conn
            .prepare(&format!("SELECT {column} FROM {table}"))
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        hosts.sort();
        hosts
    }

    /// Nothing but the database and empty side files: no copy of the
    /// cookies, and nothing removed lingering in a journal or log.
    fn assert_only_the_database(dir: &Path, db: &str) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == db {
                continue;
            }
            assert!(
                SIDE_SUFFIXES
                    .iter()
                    .any(|suffix| name == format!("{db}{suffix}")),
                "{name} was left beside {db}"
            );
            assert_eq!(
                entry.metadata().unwrap().len(),
                0,
                "{name} still holds data"
            );
        }
    }

    /// A second program's attempt to read and to write, with no waiting.
    fn other_program(db: &Path) -> (bool, bool) {
        let other = rusqlite::Connection::open(db).unwrap();
        other.busy_timeout(std::time::Duration::ZERO).unwrap();
        let read = other
            .query_row("SELECT count(*) FROM moz_cookies", [], |row| {
                row.get::<_, i64>(0)
            })
            .is_ok();
        let wrote = other
            .execute("INSERT INTO moz_cookies (host) VALUES ('.late.io')", [])
            .is_ok();
        (read, wrote)
    }

    #[test]
    fn no_other_program_can_read_or_write_while_trimming() {
        for mode in ["DELETE", "WAL"] {
            let dir = scratch(&format!("alone-{mode}"));
            let db = dir.join("cookies.sqlite");
            make_db(&db, "moz_cookies", "host", &[".github.com", ".tracker.io"]);
            rusqlite::Connection::open(&db)
                .unwrap()
                .pragma_update(None, "journal_mode", mode)
                .unwrap();
            let mut seen = None;
            let count = trim_with(&db, &["github.com".to_string()], &mut |stage| {
                if stage == Stage::Locked {
                    seen = Some(other_program(&db));
                }
                Ok(())
            })
            .unwrap();
            assert_eq!(
                count,
                CookieCount {
                    removed: 1,
                    kept: 1
                }
            );
            assert_eq!(seen, Some((false, false)), "{mode}: another program got in");
            assert_eq!(hosts(&db, "moz_cookies", "host"), [".github.com"]);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn a_failure_after_the_commit_puts_every_row_back_under_the_lock() {
        for mode in ["DELETE", "WAL"] {
            let dir = scratch(&format!("putback-{mode}"));
            let db = dir.join("cookies.sqlite");
            make_db(
                &db,
                "moz_cookies",
                "host",
                &[".github.com", ".tracker.io", ".ads.net"],
            );
            rusqlite::Connection::open(&db)
                .unwrap()
                .pragma_update(None, "journal_mode", mode)
                .unwrap();
            let before = hosts(&db, "moz_cookies", "host");
            let mut seen = None;
            let err = trim_with(&db, &["github.com".to_string()], &mut |stage| {
                if stage == Stage::Committed {
                    // Still held alone while the copy goes back.
                    seen = Some(other_program(&db));
                    return Err("injected failure".into());
                }
                Ok(())
            })
            .unwrap_err();
            assert!(err.contains("injected failure"), "{err}");
            assert!(err.contains("put back as it was"), "{err}");
            assert_eq!(seen, Some((false, false)), "{mode}: another program got in");
            assert_eq!(hosts(&db, "moz_cookies", "host"), before, "{mode}");
            let check: String = rusqlite::Connection::open(&db)
                .unwrap()
                .query_row("PRAGMA integrity_check", [], |row| row.get(0))
                .unwrap();
            assert_eq!(check, "ok");
            assert_only_the_database(&dir, "cookies.sqlite");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn a_linked_database_or_side_file_is_refused_before_any_write() {
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let dir = scratch(&format!("link{suffix}"));
            let db = dir.join("Cookies");
            make_db(&db, "cookies", "host_key", &[".tracker.io"]);
            let outside = dir.join("unrelated.dat");
            let linked = side_path(&db, suffix);
            if suffix.is_empty() {
                std::fs::hard_link(&db, &outside).unwrap();
            } else {
                std::fs::write(&outside, b"not part of the database").unwrap();
                std::fs::hard_link(&outside, &linked).unwrap();
            }
            let db_before = std::fs::read(&db).unwrap();
            let outside_before = std::fs::read(&outside).unwrap();
            let err = trim_cookies(&db, &["github.com".to_string()]).unwrap_err();
            assert!(err.contains("hard link"), "{suffix}: {err}");
            assert!(err.contains("Nothing was changed"), "{suffix}: {err}");
            assert_eq!(std::fs::read(&db).unwrap(), db_before, "{suffix}");
            assert_eq!(std::fs::read(&outside).unwrap(), outside_before, "{suffix}");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn a_copy_that_cannot_be_put_back_is_saved_and_named() {
        let dir = scratch("saved");
        let db = dir.join("Cookies");
        make_db(&db, "cookies", "host_key", &[".github.com", ".tracker.io"]);
        let mut snapshot = rusqlite::Connection::open_in_memory().unwrap();
        copy_all(&rusqlite::Connection::open(&db).unwrap(), &mut snapshot).unwrap();
        // A read-only connection cannot take the copy back.
        let stuck = open(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let message = put_back(stuck, &snapshot, &db, "injected failure".into());
        let copies = leftover_copies(&db);
        assert_eq!(copies.len(), 1, "{message}");
        assert!(
            message.contains(&copies[0].display().to_string()),
            "{message}"
        );
        assert_eq!(
            hosts(&copies[0], "cookies", "host_key"),
            [".github.com", ".tracker.io"]
        );
        // The kept copy stops later edits until the user deals with it.
        let err = trim_cookies(&db, &["github.com".to_string()]).unwrap_err();
        assert!(err.contains("earlier copy"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn live_the_database_and_its_folder_stay_put_while_trimming() {
        let dir = scratch("stay");
        let db = dir.join("cookies.sqlite");
        make_db(&db, "moz_cookies", "host", &[".github.com", ".tracker.io"]);
        let mut moved = Vec::new();
        let journal = side_path(&db, "-journal");
        trim_with(&db, &["github.com".to_string()], &mut |stage| {
            moved.push(std::fs::rename(&db, dir.join("swap.sqlite")).is_ok());
            moved.push(std::fs::rename(&dir, dir.with_extension("moved")).is_ok());
            // The side file SQLite writes cannot be swapped either.
            moved.push(std::fs::rename(&journal, dir.join("swap-journal")).is_ok());
            moved.push(std::fs::remove_file(&journal).is_ok());
            let _ = stage;
            Ok(())
        })
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(dir.with_extension("moved"));
        assert_eq!(
            moved, [false; 8],
            "the database, its folder, or its journal moved"
        );
    }

    #[cfg(windows)]
    #[test]
    fn live_a_short_name_spelling_is_still_the_same_database() {
        use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
        let dir = scratch("short-name-spelling");
        let db = dir.join("cookies.sqlite");
        make_db(&db, "moz_cookies", "host", &[".github.com", ".tracker.io"]);
        let long = db.display().to_string();
        let wide: Vec<u16> = long.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = vec![0u16; 1024];
        let len = unsafe { GetShortPathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) }
            as usize;
        let short = String::from_utf16_lossy(&buf[..len]);
        let trimmed = trim_cookies(Path::new(&short), &["github.com".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(len > 0);
        assert_eq!(
            trimmed,
            Ok(CookieCount {
                removed: 1,
                kept: 1
            }),
            "{short}"
        );
    }
}
