//! A SQLite VFS that lets one connection open only files Hivemend has
//! verified and holds: the cookie database and its side files.
//!
//! It forwards everything to Windows' own VFS, with two exceptions. An
//! open of a named file is allowed only for a path on the bound list, and
//! after Windows' VFS has opened it, the object behind SQLite's own handle
//! must be the very file Hivemend verified (same volume and file index, one
//! name, not a link); anything else is closed again and refused. Temporary
//! files SQLite makes for itself (no name, or deleted on close) pass. A
//! delete of a bound file is refused, so SQLite can never remove, and
//! later recreate, a verified file under its name. Hivemend's own handles
//! on the bound files keep them from being renamed or replaced meanwhile.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use rusqlite::ffi;

/// One file the connection may open: its full path and identity.
pub struct Allowed {
    pub path: String,
    pub id: (u64, u64),
}

struct State {
    base: *mut ffi::sqlite3_vfs,
    allowed: Vec<Allowed>,
    refused: Mutex<Vec<String>>,
}

/// A registered VFS for one edit; unregistered when dropped (after the
/// connection that used it is closed).
pub struct BoundVfs {
    vfs: Box<ffi::sqlite3_vfs>,
    name: CString,
    state: Box<State>,
}

static NEXT: AtomicU32 = AtomicU32::new(0);

fn key(path: &str) -> String {
    path.replace('/', "\\").to_lowercase()
}

impl BoundVfs {
    pub fn register(allowed: Vec<Allowed>) -> Result<Self, String> {
        let base = unsafe { ffi::sqlite3_vfs_find(std::ptr::null()) };
        if base.is_null() {
            return Err("SQLite has no file system layer".into());
        }
        let name = CString::new(format!(
            "hivemend-bound-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ))
        .map_err(|err| err.to_string())?;
        let state = Box::new(State {
            base,
            allowed: allowed
                .into_iter()
                .map(|allowed| Allowed {
                    path: key(&allowed.path),
                    id: allowed.id,
                })
                .collect(),
            refused: Mutex::new(Vec::new()),
        });
        let base_ref = unsafe { &*base };
        let mut vfs = Box::new(ffi::sqlite3_vfs {
            // Version 1: SQLite then never asks for the later methods.
            iVersion: 1,
            szOsFile: base_ref.szOsFile,
            mxPathname: base_ref.mxPathname,
            pNext: std::ptr::null_mut(),
            zName: name.as_ptr(),
            pAppData: &*state as *const State as *mut c_void,
            xOpen: Some(open),
            xDelete: Some(delete),
            xAccess: Some(access),
            xFullPathname: Some(full_pathname),
            xDlOpen: Some(dl_open),
            xDlError: Some(dl_error),
            xDlSym: Some(dl_sym),
            xDlClose: Some(dl_close),
            xRandomness: Some(randomness),
            xSleep: Some(sleep),
            xCurrentTime: Some(current_time),
            xGetLastError: Some(get_last_error),
            xCurrentTimeInt64: None,
            xSetSystemCall: None,
            xGetSystemCall: None,
            xNextSystemCall: None,
        });
        let rc = unsafe { ffi::sqlite3_vfs_register(&mut *vfs, 0) };
        if rc != ffi::SQLITE_OK {
            return Err(format!("could not set up SQLite's file layer ({rc})"));
        }
        Ok(Self { vfs, name, state })
    }

    pub fn name(&self) -> &str {
        self.name.to_str().unwrap_or_default()
    }

    /// Files the connection tried to open or delete and was refused.
    pub fn refused(&self) -> Vec<String> {
        self.state
            .refused
            .lock()
            .map(|list| list.clone())
            .unwrap_or_default()
    }
}

impl Drop for BoundVfs {
    fn drop(&mut self) {
        unsafe { ffi::sqlite3_vfs_unregister(&mut *self.vfs) };
    }
}

unsafe fn state<'a>(vfs: *mut ffi::sqlite3_vfs) -> &'a State {
    unsafe { &*((*vfs).pAppData as *const State) }
}

fn refuse(state: &State, what: String) {
    if let Ok(mut list) = state.refused.lock() {
        list.push(what);
    }
}

/// Volume serial, file index, link count, and attributes of an open handle.
fn identity(handle: *mut c_void) -> Option<((u64, u64), u32, u32)> {
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle as _, &mut info) } == 0 {
        return None;
    }
    Some((
        (
            u64::from(info.dwVolumeSerialNumber),
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        ),
        info.nNumberOfLinks,
        info.dwFileAttributes,
    ))
}

unsafe extern "C" fn open(
    vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };
    let state = unsafe { state(vfs) };
    let base = state.base;
    let Some(base_open) = (unsafe { (*base).xOpen }) else {
        return ffi::SQLITE_CANTOPEN;
    };
    // SQLite's own temporary files: no name, or removed when closed.
    if name.is_null() || flags & ffi::SQLITE_OPEN_DELETEONCLOSE != 0 {
        return unsafe { base_open(base, name, file, flags, out_flags) };
    }
    let path = unsafe { CStr::from_ptr(name) }
        .to_string_lossy()
        .into_owned();
    let Some(allowed) = state
        .allowed
        .iter()
        .find(|allowed| allowed.path == key(&path))
    else {
        refuse(state, format!("{path}: not a file Hivemend checked"));
        return ffi::SQLITE_CANTOPEN;
    };
    let rc = unsafe { base_open(base, name, file, flags, out_flags) };
    if rc != ffi::SQLITE_OK {
        return rc;
    }
    // The object behind SQLite's own handle must be the verified one.
    let methods = unsafe { (*file).pMethods };
    let mut handle: *mut c_void = std::ptr::null_mut();
    let got = if methods.is_null() {
        ffi::SQLITE_ERROR
    } else {
        match unsafe { (*methods).xFileControl } {
            Some(control) => unsafe {
                control(
                    file,
                    ffi::SQLITE_FCNTL_WIN32_GET_HANDLE,
                    &mut handle as *mut *mut c_void as *mut c_void,
                )
            },
            None => ffi::SQLITE_ERROR,
        }
    };
    let same = got == ffi::SQLITE_OK
        && !handle.is_null()
        && identity(handle).is_some_and(|(id, links, attributes)| {
            id == allowed.id
                && links == 1
                && attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) == 0
        });
    if !same {
        if !methods.is_null()
            && let Some(close) = unsafe { (*methods).xClose }
        {
            unsafe { close(file) };
        }
        unsafe { (*file).pMethods = std::ptr::null() };
        refuse(state, format!("{path}: not the file Hivemend checked"));
        return ffi::SQLITE_CANTOPEN;
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn delete(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    sync_dir: c_int,
) -> c_int {
    let state = unsafe { state(vfs) };
    if !name.is_null() {
        let path = unsafe { CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned();
        if state
            .allowed
            .iter()
            .any(|allowed| allowed.path == key(&path))
        {
            refuse(state, format!("{path}: SQLite asked to delete it"));
            return ffi::SQLITE_IOERR_DELETE;
        }
    }
    let base = state.base;
    match unsafe { (*base).xDelete } {
        Some(base_delete) => unsafe { base_delete(base, name, sync_dir) },
        None => ffi::SQLITE_IOERR_DELETE,
    }
}

unsafe extern "C" fn access(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    let base = unsafe { state(vfs) }.base;
    match unsafe { (*base).xAccess } {
        Some(f) => unsafe { f(base, name, flags, out) },
        None => ffi::SQLITE_ERROR,
    }
}

unsafe extern "C" fn full_pathname(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    n_out: c_int,
    out: *mut c_char,
) -> c_int {
    let base = unsafe { state(vfs) }.base;
    match unsafe { (*base).xFullPathname } {
        Some(f) => unsafe { f(base, name, n_out, out) },
        None => ffi::SQLITE_ERROR,
    }
}

unsafe extern "C" fn dl_open(vfs: *mut ffi::sqlite3_vfs, name: *const c_char) -> *mut c_void {
    let base = unsafe { state(vfs) }.base;
    match unsafe { (*base).xDlOpen } {
        Some(f) => unsafe { f(base, name) },
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn dl_error(vfs: *mut ffi::sqlite3_vfs, n: c_int, out: *mut c_char) {
    let base = unsafe { state(vfs) }.base;
    if let Some(f) = unsafe { (*base).xDlError } {
        unsafe { f(base, n, out) }
    }
}

type DlSym = unsafe extern "C" fn(*mut ffi::sqlite3_vfs, *mut c_void, *const c_char);

unsafe extern "C" fn dl_sym(
    vfs: *mut ffi::sqlite3_vfs,
    handle: *mut c_void,
    symbol: *const c_char,
) -> Option<DlSym> {
    let base = unsafe { state(vfs) }.base;
    match unsafe { (*base).xDlSym } {
        Some(f) => unsafe { f(base, handle, symbol) },
        None => None,
    }
}

unsafe extern "C" fn dl_close(vfs: *mut ffi::sqlite3_vfs, handle: *mut c_void) {
    let base = unsafe { state(vfs) }.base;
    if let Some(f) = unsafe { (*base).xDlClose } {
        unsafe { f(base, handle) }
    }
}

unsafe extern "C" fn randomness(vfs: *mut ffi::sqlite3_vfs, n: c_int, out: *mut c_char) -> c_int {
    let base = unsafe { state(vfs) }.base;
    match unsafe { (*base).xRandomness } {
        Some(f) => unsafe { f(base, n, out) },
        None => 0,
    }
}

unsafe extern "C" fn sleep(vfs: *mut ffi::sqlite3_vfs, micros: c_int) -> c_int {
    let base = unsafe { state(vfs) }.base;
    match unsafe { (*base).xSleep } {
        Some(f) => unsafe { f(base, micros) },
        None => 0,
    }
}

unsafe extern "C" fn current_time(vfs: *mut ffi::sqlite3_vfs, out: *mut f64) -> c_int {
    let base = unsafe { state(vfs) }.base;
    match unsafe { (*base).xCurrentTime } {
        Some(f) => unsafe { f(base, out) },
        None => ffi::SQLITE_ERROR,
    }
}

unsafe extern "C" fn get_last_error(
    vfs: *mut ffi::sqlite3_vfs,
    n: c_int,
    out: *mut c_char,
) -> c_int {
    let base = unsafe { state(vfs) }.base;
    match unsafe { (*base).xGetLastError } {
        Some(f) => unsafe { f(base, n, out) },
        None => 0,
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    fn identity_of(path: &std::path::Path) -> (u64, u64) {
        use std::os::windows::io::AsRawHandle;
        let file = std::fs::File::open(path).unwrap();
        identity(file.as_raw_handle() as _).unwrap().0
    }

    fn database(dir: &std::path::Path) -> std::path::PathBuf {
        let db = dir.join("bound.sqlite");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE t (x TEXT); INSERT INTO t VALUES ('keep');")
            .unwrap();
        drop(conn);
        db
    }

    fn try_write(db: &std::path::Path, vfs: &BoundVfs) -> rusqlite::Result<()> {
        let conn = rusqlite::Connection::open_with_flags_and_vfs(
            db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
            vfs.name(),
        )?;
        conn.execute_batch("PRAGMA journal_mode=TRUNCATE; INSERT INTO t VALUES ('new');")
    }

    #[test]
    fn live_sqlite_cannot_open_a_side_file_that_was_not_verified() {
        let dir = std::env::temp_dir().join(format!("hm-bound-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = database(&dir);
        let before = std::fs::read(&db).unwrap();
        // Only the database is bound: the journal SQLite needs to write is
        // not, so the write is refused before it starts.
        let vfs = BoundVfs::register(vec![Allowed {
            path: db.display().to_string(),
            id: identity_of(&db),
        }])
        .unwrap();
        let unbound = try_write(&db, &vfs);
        let refused = vfs.refused();
        drop(vfs);
        // The journal bound with another file's identity: refused too.
        let journal = dir.join("bound.sqlite-journal");
        std::fs::write(&journal, b"").unwrap();
        let other = dir.join("other.bin");
        std::fs::write(&other, b"x").unwrap();
        let vfs = BoundVfs::register(vec![
            Allowed {
                path: db.display().to_string(),
                id: identity_of(&db),
            },
            Allowed {
                path: journal.display().to_string(),
                id: identity_of(&other),
            },
        ])
        .unwrap();
        let wrong = try_write(&db, &vfs);
        let wrong_refused = vfs.refused();
        drop(vfs);
        // Bound correctly: the write goes through.
        let vfs = BoundVfs::register(vec![
            Allowed {
                path: db.display().to_string(),
                id: identity_of(&db),
            },
            Allowed {
                path: journal.display().to_string(),
                id: identity_of(&journal),
            },
        ])
        .unwrap();
        let right = try_write(&db, &vfs);
        drop(vfs);
        let after_unbound = before.clone();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(unbound.is_err(), "an unverified journal was used");
        assert!(
            refused.iter().any(|item| item.contains("-journal")),
            "{refused:?}"
        );
        assert!(wrong.is_err(), "a journal of the wrong identity was used");
        assert!(
            wrong_refused
                .iter()
                .any(|item| item.contains("not the file")),
            "{wrong_refused:?}"
        );
        assert!(right.is_ok(), "{right:?}");
        assert_eq!(after_unbound, before);
    }
}
