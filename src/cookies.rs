//! Cookies to keep: trim a browser's cookie database down to the sites the
//! user listed, instead of deleting the whole file.
//!
//! The database is only edited while the browser is closed (the privacy
//! item's running-process check). It is copied first; the rows to remove
//! are deleted in one transaction; SQLite's integrity check must pass. Any
//! failure puts the copy back. A successful edit deletes the copy, since a
//! spare copy of the cookies would undo the cleaning.

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

/// The side files that hold database content. The `-shm` index is not
/// content: SQLite rebuilds it, and another program can hold it mapped.
const SIDE_SUFFIXES: [&str; 2] = ["-wal", "-journal"];

/// The database and whichever SQLite side files it has.
fn with_side_files(path: &Path) -> Vec<PathBuf> {
    let mut files = vec![path.to_path_buf()];
    for suffix in SIDE_SUFFIXES {
        let mut side = path.as_os_str().to_owned();
        side.push(suffix);
        let side = PathBuf::from(side);
        if std::fs::symlink_metadata(&side).is_ok() {
            files.push(side);
        }
    }
    files
}

const COPY_TAG: &str = ".hivemend-copy";

/// Copies an earlier run left behind (it keeps them when it cannot put a
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

/// Copy `file` to a new, unused name beside it. Never overwrites anything.
fn copy_new(file: &Path) -> Result<PathBuf, String> {
    use std::io::Write;
    let mut from = std::fs::File::open(file).map_err(|err| err.to_string())?;
    for attempt in 0..100u32 {
        let mut name = file.as_os_str().to_owned();
        name.push(format!("{COPY_TAG}-{}-{attempt}", std::process::id()));
        let copy = PathBuf::from(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&copy)
        {
            Ok(mut to) => {
                let written = std::io::copy(&mut from, &mut to)
                    .and_then(|_| to.flush())
                    .and_then(|()| to.sync_all());
                return match written {
                    Ok(()) => Ok(copy),
                    Err(err) => {
                        drop(to);
                        let _ = std::fs::remove_file(&copy);
                        Err(err.to_string())
                    }
                };
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.to_string()),
        }
    }
    Err("no free name for the copy".into())
}

/// What trimming did. `leftovers` are copies of the old cookies that could
/// not be deleted afterwards; the caller reports them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trimmed {
    pub count: CookieCount,
    pub leftovers: Vec<PathBuf>,
}

/// Remove every cookie not for a kept site. The database and its side files
/// are copied first and put back if anything fails; a copy is only deleted
/// once it is no longer needed.
pub fn trim_cookies(path: &Path, sites: &[String]) -> Result<Trimmed, String> {
    let earlier = leftover_copies(path);
    if !earlier.is_empty() {
        return Err(format!(
            "an earlier copy is still at {}; Hivemend kept it because a database could not be put back. Check it, then delete it to clean again",
            earlier[0].display()
        ));
    }
    let files = with_side_files(path);
    for file in &files {
        let meta = std::fs::symlink_metadata(file).map_err(|err| err.to_string())?;
        if !meta.is_file() {
            return Err(format!("{} is not a plain file", file.display()));
        }
    }
    let mut copies = Vec::new();
    for file in &files {
        match copy_new(file) {
            Ok(copy) => copies.push((file.clone(), copy)),
            Err(err) => {
                for (_, made) in &copies {
                    let _ = std::fs::remove_file(made);
                }
                return Err(format!(
                    "could not copy it first, so nothing was changed: {err}"
                ));
            }
        }
    }
    match edit(path, sites) {
        Err(Edit {
            message,
            changed: false,
        }) => {
            // Nothing was written: there is nothing to put back.
            for (_, copy) in &copies {
                let _ = std::fs::remove_file(copy);
            }
            Err(format!("{message}. Nothing was changed"))
        }
        Ok(count) => {
            let mut leftovers = Vec::new();
            for (_, copy) in &copies {
                if std::fs::remove_file(copy).is_err() {
                    leftovers.push(copy.clone());
                }
            }
            Ok(Trimmed { count, leftovers })
        }
        Err(Edit { message: err, .. }) => {
            // Put every file back as it was. Side files the failed edit
            // created, and the rebuilt-on-open index, are removed so they
            // cannot be paired with the old database.
            let mut failed = Vec::new();
            for (file, copy) in &copies {
                if let Err(why) = std::fs::copy(copy, file) {
                    failed.push(format!("{}: {why}", file.display()));
                }
            }
            let mut index = path.as_os_str().to_owned();
            index.push("-shm");
            let stale = with_side_files(path)
                .into_iter()
                .filter(|side| !files.contains(side))
                .chain(Some(PathBuf::from(index)).filter(|shm| shm.exists()));
            for side in stale {
                if std::fs::remove_file(&side).is_err() {
                    failed.push(format!("{}: could not remove it", side.display()));
                }
            }
            if !failed.is_empty() {
                // The copies are the only good version now: keep them.
                return Err(format!(
                    "{err}. Putting the database back also failed ({}), so the copies were kept beside it ({})",
                    failed.join("; "),
                    copies[0].1.display()
                ));
            }
            for (_, copy) in &copies {
                let _ = std::fs::remove_file(copy);
            }
            Err(format!("{err}. The database was put back as it was"))
        }
    }
}

/// Why an edit failed, and whether it had already written anything.
struct Edit {
    message: String,
    changed: bool,
}

fn edit(path: &Path, sites: &[String]) -> Result<CookieCount, Edit> {
    let before = |message: String| Edit {
        message,
        changed: false,
    };
    let after = |message: String| Edit {
        message,
        changed: true,
    };
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let (table, column) = cookie_schema(name);
    let mut conn = open(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(before)?;
    // Hold the database alone for the whole edit: if any other program has
    // it open, this fails before anything is written.
    let busy = |err: rusqlite::Error| {
        before(match err.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
                "another program is using the database".to_string()
            }
            _ => err.to_string(),
        })
    };
    conn.pragma_update(None, "locking_mode", "EXCLUSIVE")
        .map_err(busy)?;
    let mut count = CookieCount::default();
    {
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)
            .map_err(busy)?;
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
        // Until the commit, a failure rolls the transaction back itself.
        tx.commit().map_err(|err| after(err.to_string()))?;
    }
    let check: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|err| after(err.to_string()))?;
    if check != "ok" {
        return Err(after(format!(
            "the database failed its check after the edit: {check}"
        )));
    }
    // Fold a write-ahead log back in so no removed row lingers there.
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|err| after(err.to_string()))?;
    if mode.eq_ignore_ascii_case("wal") {
        // The first column is 1 when the checkpoint was blocked, which is
        // not a failed query but is a failed clean.
        let blocked: i64 = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .map_err(|err| after(err.to_string()))?;
        if blocked != 0 {
            return Err(after("the write-ahead log could not be folded in".into()));
        }
    }
    conn.close().map_err(|(_, err)| after(err.to_string()))?;
    Ok(count)
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
            trim_cookies(&db, &sites).unwrap().count,
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
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["Cookies"], "no copy is left behind");
        // Firefox names its table and column differently.
        let fox = dir.join("cookies.sqlite");
        make_db(&fox, "moz_cookies", "host", &[".github.com", ".tracker.io"]);
        assert_eq!(
            trim_cookies(&fox, &sites).unwrap().count,
            CookieCount {
                removed: 1,
                kept: 1
            }
        );
        let _ = std::fs::remove_dir_all(&dir);
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
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["Cookies"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
