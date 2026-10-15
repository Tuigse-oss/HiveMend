//! Where Hivemend keeps its data, split by trust.
//!
//! - Per-user data (settings, the ignore list, custom privacy targets, and
//!   backups written without elevation) lives in the account's Local AppData.
//! - Backups written by an elevated instance live in a protected store under
//!   ProgramData. It is created with an explicit owner and DACL, and an
//!   existing folder there is used only if it still has that shape; it is
//!   never repaired in place, since whoever made it could still own what is
//!   inside.
//! - The old shared folder `C:\HiveMend`, which any signed-in account can
//!   write, is never moved or deleted. Its backups are listed as untrusted
//!   and restore only without elevation, which can change only the current
//!   user's hive.
//!
//! An elevated instance restores only from the protected store, reading a
//! checked file through a pinned handle and importing an exact snapshot of
//! the bytes it checked.

use std::path::{Path, PathBuf};

#[cfg(windows)]
use crate::backup::is_hive_mend_backup;
use crate::backup::{BackupSummary, files_dir};
use crate::fs::{Access, FileView, ItemKind, KnownDir, Pinned};
use crate::pathutil::{
    file_delete_allowed, has_unsafe_fs_component, known_root, normalize_fs, path_under,
    under_windows_dir,
};

/// The pre-split shared data folder.
pub const LEGACY_DIR: &str = r"C:\HiveMend";
const APP: &str = "HiveMend";
/// Largest backup a restore will read.
#[cfg_attr(not(windows), allow(dead_code))]
const MAX_BACKUP_BYTES: u64 = 64 * 1024 * 1024;

/// Which store a backup came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Store {
    /// The per-user folder.
    User,
    /// The protected machine-wide store an elevated instance writes.
    Protected,
    /// The old shared `C:\HiveMend` folder.
    Legacy,
}

impl Store {
    /// Whether an elevated instance may restore from this store.
    pub fn elevated_may_restore(self) -> bool {
        self == Store::Protected
    }
}

/// The per-user data folder, from the API. `None` when it cannot be located.
pub fn user_dir(fs: &dyn FileView) -> Option<PathBuf> {
    known_root(fs, KnownDir::LocalAppData).map(|root| Path::new(&root).join(APP))
}

/// The protected store's folder under ProgramData.
pub fn protected_dir(fs: &dyn FileView) -> Option<PathBuf> {
    known_root(fs, KnownDir::ProgramData).map(|root| Path::new(&root).join(APP))
}

/// Every folder Hivemend keeps data in. Privacy deletes refuse all
/// of them; one that cannot be located is simply not listed, because the
/// protected roots check already refuses everything when ProgramData or the
/// other system folders are unknown.
pub fn data_roots(fs: &dyn FileView) -> Vec<String> {
    let mut roots = vec![LEGACY_DIR.to_string()];
    for dir in [user_dir(fs), protected_dir(fs)].into_iter().flatten() {
        roots.push(dir.display().to_string());
    }
    // Where per-user files go when Local AppData cannot be located: inside
    // Temp, so it must be protected from Temp cleaning explicitly.
    roots.push(fallback_dir().display().to_string());
    roots
}

fn fallback_dir() -> PathBuf {
    std::env::temp_dir().join(APP)
}

fn user_file(name: &str) -> PathBuf {
    user_dir(&crate::fs::HostFs)
        .unwrap_or_else(fallback_dir)
        .join(name)
}

pub fn exclusions_file() -> PathBuf {
    user_file("ignore.txt")
}

pub fn settings_file() -> PathBuf {
    user_file("settings.ini")
}

pub fn custom_privacy_file() -> PathBuf {
    user_file("privacy-custom.ini")
}

pub fn cookies_keep_file() -> PathBuf {
    user_file("cookies-keep.txt")
}

/// Copy per-user files from the legacy folder the first time, when the
/// per-user copy does not exist yet. Only a non-elevated instance does this:
/// the legacy folder is writable by every account, which is no worse than the
/// user's own folder for the user's own settings, but must never feed an
/// elevated instance. Nothing in the legacy folder is moved or deleted.
pub fn adopt_legacy_settings() {
    if elevated() {
        return;
    }
    let Some(dir) = user_dir(&crate::fs::HostFs) else {
        return;
    };
    for name in ["settings.ini", "ignore.txt", "privacy-custom.ini"] {
        let to = dir.join(name);
        if to.exists() {
            continue;
        }
        let from = Path::new(LEGACY_DIR).join(name);
        let mut fs = crate::fs::HostFs;
        let Ok(mut pin) = fs.pin(&from.display().to_string()) else {
            continue;
        };
        if pin.kind != ItemKind::File || pin.len > 1024 * 1024 {
            continue;
        }
        if fs.pin_acquire(&mut pin, Access::Read).is_err() {
            continue;
        }
        let _ = fs.pin_copy_to(&pin, &to.display().to_string());
    }
}

/// True when this process runs with an elevated (administrator) token.
#[cfg(windows)]
pub fn elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TokenElevation};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    const TOKEN_QUERY: u32 = 0x0008;
    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut info = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut got = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            &mut info as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut got,
        )
    };
    unsafe { CloseHandle(token) };
    ok != 0 && info.TokenIsElevated != 0
}

#[cfg(not(windows))]
pub fn elevated() -> bool {
    false
}

/// The backups folder this process writes to: the protected store, created or
/// checked, when elevated; the per-user folder otherwise.
pub fn backups_dir() -> Result<PathBuf, String> {
    let fs = crate::fs::HostFs;
    if elevated() {
        let root = protected_dir(&fs).ok_or("could not locate the ProgramData folder")?;
        ensure_protected(&root)?;
        let backups = root.join("backups");
        ensure_protected(&backups)?;
        Ok(backups)
    } else {
        let backups = user_dir(&fs)
            .ok_or("could not locate the Local AppData folder")?
            .join("backups");
        std::fs::create_dir_all(&backups).map_err(|err| format!("{}: {err}", backups.display()))?;
        Ok(backups)
    }
}

/// Where [`backups_dir`] writes, without creating or checking anything: for
/// display.
pub fn backups_location() -> Option<PathBuf> {
    let fs = crate::fs::HostFs;
    let base = if elevated() {
        protected_dir(&fs)
    } else {
        user_dir(&fs)
    };
    base.map(|dir| dir.join("backups"))
}

/// The backup folders to list, with the store each belongs to. Folders that
/// do not exist are skipped; nothing is created here.
pub fn backup_stores() -> Vec<(Store, PathBuf)> {
    let fs = crate::fs::HostFs;
    let mut stores = Vec::new();
    if let Some(dir) = protected_dir(&fs) {
        stores.push((Store::Protected, dir.join("backups")));
    }
    if let Some(dir) = user_dir(&fs) {
        stores.push((Store::User, dir.join("backups")));
    }
    stores.push((Store::Legacy, Path::new(LEGACY_DIR).join("backups")));
    stores.retain(|(_, dir)| dir.is_dir());
    stores
}

/// Where a backup file sits, judged by its real path.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn store_of(fs: &dyn FileView, real_path: &str) -> Store {
    if let Some(dir) = protected_dir(fs)
        && path_under(real_path, &dir.join("backups").display().to_string())
    {
        return Store::Protected;
    }
    if let Some(dir) = user_dir(fs)
        && path_under(real_path, &dir.join("backups").display().to_string())
    {
        return Store::User;
    }
    Store::Legacy
}

/// Read a backup for restore through a pinned handle. An elevated caller gets
/// it only from the protected store, and only when the file itself is owned
/// by an administrator account and writable by nothing else.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn read_restorable(
    fs: &mut dyn FileView,
    file: &Path,
    elevated: bool,
) -> Result<(String, Vec<u8>), String> {
    let shown = file.display().to_string();
    let mut pin = fs.pin(&shown).map_err(|err| format!("{shown}: {err}"))?;
    if pin.kind != ItemKind::File || pin.links != 1 {
        return Err(format!("{shown} is not a plain single-name file"));
    }
    if pin.len > MAX_BACKUP_BYTES {
        return Err(format!("{shown} is too large to be a Hivemend backup"));
    }
    let real = pin.real_path.clone();
    if elevated {
        if store_of(&*fs, &real) != Store::Protected {
            return Err(format!(
                "{shown} is not in the protected backup store, so it is not restored with \
                 administrator rights. Restore it from Hivemend started without \
                 administrator rights; that can put back only your own (HKCU) entries."
            ));
        }
        check_owner_and_dacl(&pin, &shown)?;
    }
    fs.pin_acquire(&mut pin, Access::Read)?;
    let bytes = fs
        .pin_read_at(&pin, 0, pin.len as usize)
        .filter(|bytes| bytes.len() as u64 == pin.len)
        .ok_or_else(|| format!("could not read {shown}"))?;
    Ok((real, bytes))
}

/// Put back shortcut copies whose original is still missing, confined at both
/// ends: the saved copy must really be inside this backup's own `-files`
/// folder, and the destination must pass the same rule repair used to remove
/// it (Start Menu, Desktop, or temp; never the Windows folder). The new file
/// is created without following links, checked by its real path, and removed
/// again if it landed anywhere else. Nothing existing is overwritten.
pub fn restore_files(
    fs: &mut dyn FileView,
    backup_real: &str,
    summary: &BackupSummary,
) -> (usize, Vec<String>) {
    let mut restored = 0;
    let mut errors = Vec::new();
    let files = files_dir(Path::new(backup_real)).display().to_string();
    let files_real = fs.pin(&files).map(|pin| pin.real_path).ok();
    for (original, copy) in &summary.files {
        match restore_one(fs, files_real.as_deref(), original, copy) {
            Ok(true) => restored += 1,
            Ok(false) => {}
            Err(err) => errors.push(format!("{original}: {err}")),
        }
    }
    (restored, errors)
}

fn destination_allowed(fs: &dyn FileView, path: &str) -> bool {
    file_delete_allowed(path) && !under_windows_dir(fs, path) && !has_unsafe_fs_component(path)
}

fn restore_one(
    fs: &mut dyn FileView,
    files_real: Option<&str>,
    original: &str,
    copy: &Path,
) -> Result<bool, String> {
    let original = normalize_fs(original);
    if !destination_allowed(&*fs, &original) {
        return Err("refused: not a place repair removes shortcuts from".into());
    }
    if fs.exists(&original) {
        return Ok(false);
    }
    let copy_text = copy.display().to_string();
    let mut source = fs
        .pin(&copy_text)
        .map_err(|err| format!("the saved copy {copy_text}: {err}"))?;
    let inside = files_real.is_some_and(|dir| {
        path_under(&source.real_path, dir) && !source.real_path.eq_ignore_ascii_case(dir)
    });
    if !inside || source.kind != ItemKind::File || source.links != 1 {
        return Err(format!(
            "refused: the saved copy {copy_text} is not inside this backup's own files folder"
        ));
    }
    fs.pin_acquire(&mut source, Access::Read)?;
    let bytes = fs
        .pin_read_at(&source, 0, crate::fs::copy_len(&source)?)
        .filter(|bytes| bytes.len() as u64 == source.len)
        .ok_or("could not read the saved copy")?;
    // Where it would really land, before anything is created: the nearest
    // folder that exists, resolved, plus the parts still to be made. A
    // refused restore must not have made folders somewhere else first.
    let mut anchor = original.as_str();
    let mut rest: Vec<&str> = Vec::new();
    while !(fs.exists(anchor) && fs.is_dir(anchor)) {
        let Some((parent, name)) = anchor.rsplit_once('\\') else {
            return Err("refused: no part of its folder exists".into());
        };
        rest.push(name);
        anchor = parent;
    }
    let real_anchor = fs
        .pin(anchor)
        .map_err(|err| format!("refused: {anchor}: {err}"))?
        .real_path;
    let projected = rest.iter().rev().fold(
        real_anchor.trim_end_matches('\\').to_string(),
        |path, part| format!(r"{path}\{part}"),
    );
    if !destination_allowed(&*fs, &projected) {
        return Err(format!("refused: it resolves to {projected}"));
    }
    let target = fs.pin_create_new(&original)?;
    if !destination_allowed(&*fs, &target.real_path) {
        let real = target.real_path.clone();
        let _ = fs.pin_delete(target);
        return Err(format!("refused: it resolves to {real}"));
    }
    let written = fs
        .pin_write_at(&target, 0, &bytes)
        .and_then(|()| fs.pin_sync(&target));
    if let Err(err) = written {
        let _ = fs.pin_delete(target);
        return Err(err);
    }
    Ok(true)
}

/// Restore a backup end to end: read it through a checked handle, import an
/// exact snapshot of the checked bytes with `reg.exe`, then put back its
/// confined shortcut copies.
#[cfg(windows)]
pub fn restore_backup(file: &Path) -> Result<(BackupSummary, usize, Vec<String>), String> {
    let elevated = elevated();
    let mut fs = crate::fs::HostFs;
    let (real, bytes) = read_restorable(&mut fs, file, elevated)?;
    let text = crate::rules::decode_text_owned(bytes);
    if !is_hive_mend_backup(&text) {
        return Err(format!(
            "{} is not a Hivemend backup; refusing to restore it",
            file.display()
        ));
    }
    let summary = BackupSummary::parse(&text);
    let parsed = crate::regfile::parse_backup(&text)
        .map_err(|why| format!("{} cannot be restored: {why}", file.display()))?;
    let (ops, notes) = restore_scope(parsed, elevated);
    // Written through the link-refusing registry layer in one transaction:
    // all of it, or nothing.
    let (keys, values) = if ops.is_empty() {
        (0, 0)
    } else {
        crate::regfile::apply_ops(&mut crate::WindowsRegistry, &ops)
            .map_err(|err| format!("nothing was restored: {err}"))?
    };
    let applied = BackupSummary {
        keys,
        values,
        files: summary.files.clone(),
        machine_wide: elevated && keys > 0,
        per_user: !elevated && keys > 0,
    };
    let (files, mut errors) = restore_files(&mut fs, &real, &summary);
    errors.extend(notes);
    Ok((applied, files, errors))
}

/// The operations this window may apply, and notes on what is left for the
/// other kind of window. An administrator window writes only machine-wide
/// keys (a per-user key can be redirected by programs running without
/// elevation); a normal window writes only its own HKEY_CURRENT_USER.
pub fn restore_scope(
    parsed: crate::regfile::ParsedBackup,
    elevated: bool,
) -> (Vec<crate::regfile::RegOp>, Vec<String>) {
    let (mine, other): (Vec<_>, Vec<_>) = parsed.ops.into_iter().partition(|op| {
        if elevated {
            !crate::pathutil::per_user_key(op.key())
        } else {
            op.key().starts_with("HKEY_CURRENT_USER")
        }
    });
    let mut notes = Vec::new();
    let mut other_keys: Vec<String> = other
        .iter()
        .map(|op| op.key().to_ascii_lowercase())
        .collect();
    other_keys.sort();
    other_keys.dedup();
    if !other_keys.is_empty() {
        notes.push(if elevated {
            format!(
                "{} per-user keys were not restored here; restore this backup again from Hivemend started without administrator rights",
                other_keys.len()
            )
        } else {
            format!(
                "{} machine-wide keys need administrator rights; restore this backup again from Hivemend run as administrator",
                other_keys.len()
            )
        });
    }
    if parsed.left_out > 0 {
        notes.push(format!(
            "{} entries the repair did not remove were left out",
            parsed.left_out
        ));
    }
    (mine, notes)
}

/// Create the protected folder with its explicit owner and DACL, or check an
/// existing one. Never repairs an existing folder: whoever created it could
/// still own files inside.
#[cfg(windows)]
pub fn ensure_protected(dir: &Path) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    // Owner Administrators; protected DACL (no inheritance from ProgramData):
    // SYSTEM and Administrators full control, Users read and execute.
    const SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
    let shown = dir.display().to_string();
    let sddl: Vec<u16> = SDDL.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(format!(
            "could not build the security descriptor for {shown}"
        ));
    }
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let wide: Vec<u16> = shown.encode_utf16().chain(std::iter::once(0)).collect();
    let created = unsafe { CreateDirectoryW(wide.as_ptr(), &attrs) } != 0;
    let code = unsafe { GetLastError() };
    unsafe { LocalFree(sd as _) };
    if !created && code != ERROR_ALREADY_EXISTS {
        return Err(format!(
            "could not create {shown}: {}",
            std::io::Error::from_raw_os_error(code as i32)
        ));
    }
    check_protected_dir(dir)
}

#[cfg(not(windows))]
pub fn ensure_protected(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|err| err.to_string())
}

/// The folder must be a real directory (no reparse point) whose real path is
/// the expected one, owned by an administrator account, and writable by
/// nothing but SYSTEM, Administrators, and TrustedInstaller.
#[cfg(windows)]
fn check_protected_dir(dir: &Path) -> Result<(), String> {
    let shown = dir.display().to_string();
    let pin = crate::fs::HostFs
        .pin(&shown)
        .map_err(|err| format!("{shown}: {err}"))?;
    if pin.kind != ItemKind::Dir {
        return Err(format!("{shown} is not a folder"));
    }
    if !normalize_fs(&pin.real_path).eq_ignore_ascii_case(&normalize_fs(&shown)) {
        return Err(format!("{shown} resolves to {}", pin.real_path));
    }
    check_owner_and_dacl(&pin, &shown)
}

/// SIDs trusted to own or write protected data.
#[cfg(windows)]
const TRUSTED_SIDS: &[&str] = &[
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// Owner must be trusted; every allow ACE that grants any write-type right
/// must name a trusted SID (or be CREATOR OWNER on an inherit-only ACE, which
/// only ever applies to what trusted accounts create). A missing DACL means
/// everyone has full control, so it fails.
#[cfg(windows)]
fn check_owner_and_dacl(pin: &Pinned, shown: &str) -> Result<(), String> {
    let handle = pin.raw_handle().ok_or("not a host handle")?;
    check_handle_owner_and_dacl(handle, shown, None)
}

/// [`check_owner_and_dacl`] on an open handle; `also` is one more SID
/// trusted beside the administrator ones (the account's own folder).
#[cfg(windows)]
pub(crate) fn check_handle_owner_and_dacl(
    handle: std::os::windows::io::RawHandle,
    shown: &str,
    also: Option<&str>,
) -> Result<(), String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, OWNER_SECURITY_INFORMATION, PSID,
    };
    const WRITE_BITS: u32 = 0x0000_0002 // write data / add file
        | 0x0000_0004 // append data / add subfolder
        | 0x0000_0010 // write extended attributes
        | 0x0000_0040 // delete child
        | 0x0000_0100 // write attributes
        | 0x0001_0000 // delete
        | 0x0004_0000 // write DAC
        | 0x0008_0000 // write owner
        | 0x1000_0000 // generic all
        | 0x4000_0000; // generic write
    const INHERIT_ONLY: u8 = 0x08;
    let trusted = |sid: &str| TRUSTED_SIDS.contains(&sid) || also == Some(sid);
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = std::ptr::null_mut();
    let rc = unsafe {
        GetSecurityInfo(
            handle as _,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        return Err(format!(
            "could not read the security of {shown}: {}",
            std::io::Error::from_raw_os_error(rc as i32)
        ));
    }
    let sid_text = |sid: PSID| -> String {
        let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 || raw.is_null() {
            return String::new();
        }
        let len = (0..).take_while(|&i| unsafe { *raw.add(i) } != 0).count();
        let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw, len) });
        unsafe { LocalFree(raw as _) };
        text
    };
    let result = (|| {
        let owner_sid = sid_text(owner);
        if !trusted(&owner_sid) {
            return Err(format!(
                "{shown} is owned by {owner_sid}, not {}",
                if also.is_some() {
                    "this account or an administrator account"
                } else {
                    "an administrator account"
                }
            ));
        }
        if dacl.is_null() {
            return Err(format!(
                "{shown} has no access list, so everyone can change it"
            ));
        }
        let count = unsafe { (*dacl).AceCount };
        for index in 0..count as u32 {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
                return Err(format!("could not read the access list of {shown}"));
            }
            let header = unsafe { *(ace as *const ACE_HEADER) };
            // Deny entries only take rights away.
            if header.AceType == 1 {
                continue;
            }
            let mask = unsafe { *((ace as *const u8).add(4) as *const u32) };
            if mask & WRITE_BITS == 0 {
                continue;
            }
            // Plain and callback allow entries carry the SID right after the
            // mask; any other allow-type entry granting a write is refused.
            if header.AceType != 0 && header.AceType != 9 {
                return Err(format!("{shown} has an access entry Hivemend cannot check"));
            }
            let sid = sid_text(unsafe { (ace as *mut u8).add(8) } as PSID);
            let creator_owner = sid == "S-1-3-0" && header.AceFlags & INHERIT_ONLY != 0;
            if !trusted(&sid) && !creator_owner {
                return Err(format!("{shown} lets {sid} change it"));
            }
        }
        Ok(())
    })();
    unsafe { LocalFree(sd as _) };
    result
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn check_owner_and_dacl(_pin: &Pinned, _shown: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemoryFs;

    const LOCAL: &str = r"C:\Users\me\AppData\Local";

    fn fs() -> MemoryFs {
        let mut fs = MemoryFs::with_windows_dirs();
        fs.set_var("LOCALAPPDATA", LOCAL);
        fs
    }

    fn summary(files: &[(&str, &str)]) -> BackupSummary {
        BackupSummary {
            files: files
                .iter()
                .map(|(original, copy)| (original.to_string(), PathBuf::from(copy)))
                .collect(),
            ..BackupSummary::default()
        }
    }

    #[test]
    fn each_window_restores_only_its_own_part_of_a_mixed_backup() {
        let text = "Windows Registry Editor Version 5.00\r\n\r\n; Hive Mend backup.\r\n\r\n\
            [HKEY_LOCAL_MACHINE\\SOFTWARE\\A]\r\n\"x\"=dword:00000001\r\n\r\n\
            [HKEY_CURRENT_USER\\Software\\B]\r\n\"y\"=\"2\"\r\n\r\n\
            [HKEY_USERS\\S-1-5-21-9\\Software\\C]\r\n\"z\"=\"3\"\r\n";
        let parsed = crate::regfile::parse_backup(text).unwrap();
        let (admin, admin_notes) = restore_scope(parsed.clone(), true);
        assert!(
            admin
                .iter()
                .all(|op| op.key().starts_with("HKEY_LOCAL_MACHINE"))
        );
        assert!(!admin.is_empty());
        assert!(
            admin_notes[0].contains("2 per-user keys"),
            "{admin_notes:?}"
        );
        let (normal, normal_notes) = restore_scope(parsed, false);
        assert!(
            normal
                .iter()
                .all(|op| op.key().starts_with("HKEY_CURRENT_USER"))
        );
        assert!(!normal.is_empty());
        assert!(
            normal_notes[0].contains("need administrator rights"),
            "{normal_notes:?}"
        );
    }

    #[test]
    fn a_file_too_large_to_copy_is_refused_before_reading() {
        use crate::fs::{MAX_COPY_BYTES, copy_len};
        let mut fs = MemoryFs::new();
        fs.add_file_bytes(r"C:\big.lnk", vec![0; MAX_COPY_BYTES as usize + 1], None);
        fs.add_file_bytes(r"C:\small.lnk", vec![0; 64], None);
        assert!(copy_len(&fs.pin(r"C:\big.lnk").unwrap()).is_err());
        assert_eq!(copy_len(&fs.pin(r"C:\small.lnk").unwrap()), Ok(64));
    }

    #[test]
    fn the_fallback_data_folder_is_always_protected() {
        // With no Local AppData, per-user files land in Temp\HiveMend; Temp
        // cleaning must still refuse that folder.
        let fs = MemoryFs::new();
        assert!(user_dir(&fs).is_none());
        let roots = data_roots(&fs);
        let fallback = fallback_dir().display().to_string();
        assert!(roots.contains(&fallback), "{roots:?}");
        assert!(
            user_file("settings.ini")
                .starts_with(user_dir(&crate::fs::HostFs).unwrap_or_else(fallback_dir))
        );
    }

    #[test]
    fn an_elevated_restore_reads_only_from_the_protected_store() {
        let mut fs = fs();
        let user = format!(r"{LOCAL}\HiveMend\backups\hive-mend-1.reg");
        let legacy = r"C:\HiveMend\backups\hive-mend-2.reg";
        let protected = r"C:\ProgramData\HiveMend\backups\hive-mend-3.reg";
        for path in [user.as_str(), legacy, protected] {
            fs.add_file_bytes(path, b"; Hive Mend backup.".to_vec(), None);
        }
        for path in [user.as_str(), legacy] {
            let err = read_restorable(&mut fs, Path::new(path), true).unwrap_err();
            assert!(err.contains("not in the protected backup store"), "{err}");
            // Without elevation the same file is readable: it can only
            // change what this account could change anyway.
            assert!(read_restorable(&mut fs, Path::new(path), false).is_ok());
        }
        assert_eq!(store_of(&fs, protected), Store::Protected);
        assert_eq!(store_of(&fs, &user), Store::User);
        assert_eq!(store_of(&fs, legacy), Store::Legacy);
    }

    #[test]
    fn a_backup_read_through_an_alias_is_judged_by_its_real_path() {
        // A path spelled inside the protected store that really leads into
        // the legacy folder is not trusted.
        let mut fs = fs();
        fs.add_file_bytes(r"C:\HiveMend\backups\planted.reg", vec![1], None);
        fs.add_dir(r"C:\ProgramData\HiveMend");
        fs.add_alias(r"C:\ProgramData\HiveMend\backups", r"C:\HiveMend\backups");
        let err = read_restorable(
            &mut fs,
            Path::new(r"C:\ProgramData\HiveMend\backups\planted.reg"),
            true,
        )
        .unwrap_err();
        assert!(err.contains("not in the protected backup store"), "{err}");
    }

    #[test]
    fn file_restore_is_confined_at_both_ends() {
        let mut fs = fs();
        let backup = r"C:\ProgramData\HiveMend\backups\hive-mend-1.reg";
        let files = r"C:\ProgramData\HiveMend\backups\hive-mend-1-files";
        let desktop = r"C:\Users\me\Desktop";
        fs.add_file_bytes(backup, vec![1], None);
        fs.add_file_bytes(&format!(r"{files}\0001-good.lnk"), b"good".to_vec(), None);
        fs.add_file_bytes(r"C:\Users\me\secret.txt", b"secret".to_vec(), None);
        fs.add_file_bytes(&format!(r"{desktop}\present.lnk"), b"mine".to_vec(), None);
        fs.add_file_bytes(&format!(r"{files}\0004-present.lnk"), b"old".to_vec(), None);
        fs.add_dir(r"C:\Windows\System32");
        fs.add_dir(desktop);
        fs.add_alias(&format!(r"{desktop}\sys"), r"C:\Windows\System32");
        let (restored, errors) = restore_files(
            &mut fs,
            backup,
            &summary(&[
                // Allowed: saved copy inside this backup's files folder.
                (
                    &format!(r"{desktop}\good.lnk"),
                    &format!(r"{files}\0001-good.lnk"),
                ),
                // Source outside the files folder: refused.
                (&format!(r"{desktop}\stolen.lnk"), r"C:\Users\me\secret.txt"),
                // Destination where repair never removes shortcuts: refused.
                (
                    r"C:\Windows\System32\evil.dll",
                    &format!(r"{files}\0001-good.lnk"),
                ),
                // Already present: left alone, never overwritten.
                (
                    &format!(r"{desktop}\present.lnk"),
                    &format!(r"{files}\0004-present.lnk"),
                ),
                // Spelled on the Desktop, really in System32: refused by its
                // real path before anything is created.
                (
                    &format!(r"{desktop}\sys\x.lnk"),
                    &format!(r"{files}\0001-good.lnk"),
                ),
                // The same, with folders still to be made: none are made.
                (
                    &format!(r"{desktop}\sys\new\deeper\y.lnk"),
                    &format!(r"{files}\0001-good.lnk"),
                ),
            ]),
        );
        assert_eq!(restored, 1, "{errors:?}");
        assert_eq!(errors.len(), 4, "{errors:?}");
        assert!(
            !fs.exists(r"C:\Windows\System32\new"),
            "a folder was made outside"
        );
        assert_eq!(
            fs.read(&format!(r"{desktop}\good.lnk")),
            Some(b"good".to_vec())
        );
        assert!(!fs.exists(&format!(r"{desktop}\stolen.lnk")));
        assert!(!fs.exists(r"C:\Windows\System32\evil.dll"));
        assert!(!fs.exists(r"C:\Windows\System32\x.lnk"));
        assert_eq!(
            fs.read(&format!(r"{desktop}\present.lnk")),
            Some(b"mine".to_vec())
        );
    }

    #[test]
    fn every_data_folder_is_a_data_root() {
        let fs = fs();
        let roots = data_roots(&fs);
        for path in [
            format!(r"{LOCAL}\HiveMend\settings.ini"),
            r"C:\HiveMend\backups\old.reg".to_string(),
            r"C:\ProgramData\HiveMend\backups\new.reg".to_string(),
        ] {
            assert!(roots.iter().any(|root| path_under(&path, root)), "{path}");
        }
        // The legacy folder, Local AppData, ProgramData, and the Temp
        // fallback for when Local AppData cannot be located.
        assert_eq!(roots.len(), 4);
        assert!(roots.contains(&fallback_dir().display().to_string()));
    }
}

/// Live Windows tests. They read security descriptors and create only
/// scratch folders under the temp directory and Local AppData.
#[cfg(all(test, windows))]
mod live_tests {
    use super::*;
    use crate::fs::HostFs;

    #[test]
    fn live_a_folder_owned_by_a_standard_account_is_not_trusted() {
        // A folder this test creates is owned by the running account, just as
        // a folder pre-created in ProgramData by another user would be.
        let dir = std::env::temp_dir().join(format!("hivemend-untrusted-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let result = check_protected_dir(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        if elevated() {
            // An elevated token may own it as Administrators; the Users
            // write entries inherited from the temp folder still fail it.
            assert!(result.is_err());
        } else {
            let err = result.unwrap_err();
            assert!(err.contains("owned by"), "{err}");
        }
    }

    #[test]
    fn live_a_system_owned_folder_with_admin_only_writes_is_trusted() {
        let windows = crate::fs::host_known_dir(KnownDir::Windows).unwrap();
        check_protected_dir(Path::new(&windows)).expect("the Windows folder passes");
    }

    #[test]
    fn live_a_junction_cannot_pass_for_the_protected_folder() {
        let base = std::env::temp_dir().join(format!("hivemend-pj-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let windows = crate::fs::host_known_dir(KnownDir::Windows).unwrap();
        let link = base.join("store");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&windows)
            .output()
            .expect("run mklink");
        let result = check_protected_dir(&link);
        let _ = std::fs::remove_dir_all(&base);
        assert!(made.status.success());
        assert!(
            result.is_err(),
            "a junction to a trusted folder must not pass"
        );
    }

    #[test]
    fn live_file_restore_removes_a_file_that_lands_outside_its_place() {
        // The destination is spelled under temp but a junction carries it into
        // a Local AppData scratch folder, where repair never removes shortcuts.
        let local = crate::fs::host_known_dir(KnownDir::LocalAppData).unwrap();
        let elsewhere = Path::new(&local).join(format!("hivemend-landing-{}", std::process::id()));
        let base = std::env::temp_dir().join(format!("hivemend-restore-{}", std::process::id()));
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(base.join("hm-files")).unwrap();
        std::fs::write(base.join("hm.reg"), b"x").unwrap();
        std::fs::write(base.join("hm-files").join("0001-a.lnk"), b"shortcut").unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(base.join("j"))
            .arg(&elsewhere)
            .output()
            .expect("run mklink");
        let mut fs = HostFs;
        let backup_real = fs
            .pin(&base.join("hm.reg").display().to_string())
            .unwrap()
            .real_path;
        let good = base.join("restored.lnk").display().to_string();
        let bad = base.join("j").join("x.lnk").display().to_string();
        let copy = base.join("hm-files").join("0001-a.lnk");
        let summary = BackupSummary {
            files: vec![(good.clone(), copy.clone()), (bad, copy)],
            ..BackupSummary::default()
        };
        let (restored, errors) = restore_files(&mut fs, &backup_real, &summary);
        let landed = elsewhere.join("x.lnk").exists();
        let good_bytes = std::fs::read(&good).ok();
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&elsewhere);
        assert!(made.status.success());
        assert_eq!(restored, 1, "{errors:?}");
        assert_eq!(good_bytes, Some(b"shortcut".to_vec()));
        // Refused either because the folder is a junction (it is never
        // followed) or by its real path; never created outside first.
        assert!(
            errors
                .iter()
                .any(|err| err.contains("resolves to") || err.contains("link or junction")),
            "{errors:?}"
        );
        assert!(!landed, "a file landed outside its place");
    }

    /// Runs only elevated (it skips otherwise): creates a scratch protected
    /// folder under ProgramData exactly as the store is created, checks it
    /// passes, and checks a backup file inside reads for an elevated restore
    /// only when it sits in the protected store.
    #[test]
    fn live_elevated_protected_folder_is_created_owned_and_checked() {
        if !elevated() {
            eprintln!("skipped: needs an elevated test run");
            return;
        }
        let data = crate::fs::host_known_dir(KnownDir::ProgramData).unwrap();
        let dir = Path::new(&data).join(format!("HiveMendTest{}", std::process::id()));
        let result = (|| {
            ensure_protected(&dir)?;
            ensure_protected(&dir.join("backups"))?;
            // Re-checking an existing, correct folder passes.
            ensure_protected(&dir)?;
            let file = dir.join("backups").join("x.reg");
            std::fs::write(&file, b"; Hive Mend backup.").map_err(|err| err.to_string())?;
            let pin = crate::fs::HostFs
                .pin(&file.display().to_string())
                .map_err(|err| err.to_string())?;
            check_owner_and_dacl(&pin, "x.reg")
        })();
        let _ = std::fs::remove_dir_all(&dir);
        result.expect("protected folder round trip");
    }
}
