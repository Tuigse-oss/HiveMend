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

/// The database and whichever SQLite side files it has.
fn with_side_files(path: &Path) -> Vec<PathBuf> {
    let mut files = vec![path.to_path_buf()];
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut side = path.as_os_str().to_owned();
        side.push(suffix);
        let side = PathBuf::from(side);
        if side.exists() {
            files.push(side);
        }
    }
    files
}

fn backup_name(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".hivemend-copy");
    PathBuf::from(name)
}

/// Remove every cookie not for a kept site. The database is copied first
/// and put back if anything fails.
pub fn trim_cookies(path: &Path, sites: &[String]) -> Result<CookieCount, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|err| err.to_string())?;
    if !meta.is_file() {
        return Err("not a plain file".into());
    }
    let files = with_side_files(path);
    let mut copies = Vec::new();
    for file in &files {
        let copy = backup_name(file);
        if let Err(err) = std::fs::copy(file, &copy) {
            for (_, made) in &copies {
                let _ = std::fs::remove_file(made);
            }
            let _ = std::fs::remove_file(&copy);
            return Err(format!(
                "could not copy it first, so nothing was changed: {err}"
            ));
        }
        copies.push((file.clone(), copy));
    }
    let result = edit(path, sites);
    if result.is_err() {
        // Put every file back as it was, side files included.
        for (file, copy) in &copies {
            let _ = std::fs::copy(copy, file);
        }
        for file in &files {
            if !copies.iter().any(|(had, _)| had == file) {
                let _ = std::fs::remove_file(file);
            }
        }
    }
    for (_, copy) in &copies {
        let _ = std::fs::remove_file(copy);
    }
    result
}

fn edit(path: &Path, sites: &[String]) -> Result<CookieCount, String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let (table, column) = cookie_schema(name);
    let mut conn = open(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let mut count = CookieCount::default();
    {
        let tx = conn.transaction().map_err(|err| err.to_string())?;
        let all = rows(&tx, table, column)?;
        {
            let mut delete = tx
                .prepare(&format!("DELETE FROM {table} WHERE rowid = ?1"))
                .map_err(|err| err.to_string())?;
            for (rowid, host) in all {
                if keeps(&host, sites) {
                    count.kept += 1;
                } else {
                    delete.execute([rowid]).map_err(|err| err.to_string())?;
                    count.removed += 1;
                }
            }
        }
        tx.commit().map_err(|err| err.to_string())?;
    }
    let check: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|err| err.to_string())?;
    if check != "ok" {
        return Err(format!(
            "the database failed its check after the edit: {check}"
        ));
    }
    // Fold a write-ahead log back in so no removed row lingers there.
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|err| err.to_string())?;
    if mode.eq_ignore_ascii_case("wal") {
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .map_err(|err| err.to_string())?;
    }
    conn.close().map_err(|(_, err)| err.to_string())?;
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
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["Cookies"], "no copy is left behind");
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
