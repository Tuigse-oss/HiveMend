//! Moving a held file into the Recycle Bin through its open handle.
//!
//! The Shell's own delete works on a path, so whatever is at that path when
//! it acts is what goes. Here the file that was checked is renamed, through
//! the handle that has held it since the check, into this account's Recycle
//! Bin folder on the same drive. The new name is relative to a handle held on
//! that folder, and the `$I` record Explorer reads to list and restore it is
//! created relative to the same handle first. Nothing is ever deleted for
//! good: if any step cannot be done this way, the file stays where it is.

// Off Windows only the tests use the pure parts.
#![cfg_attr(not(windows), allow(dead_code))]

/// The `$I` record (version 2, Windows 10 and later): version, size,
/// deletion time, then the original path's length in UTF-16 units (with its
/// terminating NUL) and the path.
pub fn info_record(original: &str, len: u64, deleted: u64) -> Vec<u8> {
    let wide: Vec<u16> = original.encode_utf16().chain(std::iter::once(0)).collect();
    let mut out = Vec::with_capacity(28 + wide.len() * 2);
    out.extend_from_slice(&2u64.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&deleted.to_le_bytes());
    out.extend_from_slice(&(wide.len() as u32).to_le_bytes());
    for unit in wide {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// The extension the recycled name keeps, so Explorer shows the right icon:
/// the original file name's last `.` part, or nothing.
pub fn kept_extension(original: &str) -> &str {
    let name = original.rsplit('\\').next().unwrap_or(original);
    match name.rfind('.') {
        Some(dot) if dot > 0 && !name[dot..].contains([' ', ':']) => &name[dot..],
        _ => "",
    }
}

/// Six characters from A-Z and 0-9, as the Shell uses.
fn random_id(seed: u64) -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(seed);
    let mut value = hasher.finish();
    let digits = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..6)
        .map(|_| {
            let digit = digits[(value % 36) as usize] as char;
            value /= 36;
            digit
        })
        .collect()
}

#[cfg(windows)]
pub use host::recycle_held;

#[cfg(windows)]
mod host {
    use crate::fs::{host_dispose as dispose, host_open_in as open_in};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_RENAME_INFORMATION, FileRenameInformation, NtSetInformationFile,
    };
    use windows_sys::Win32::Foundation::{HANDLE, RtlNtStatusToDosError};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetDriveTypeW, GetFileInformationByHandle, GetVolumePathNameW,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    const SYNCHRONIZE: u32 = 0x0010_0000;
    const DELETE: u32 = 0x0001_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_LIST_DIRECTORY: u32 = 0x0001;
    const FILE_ADD_FILE: u32 = 0x0002;
    const FILE_TRAVERSE: u32 = 0x0020;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const DRIVE_FIXED: u32 = 3;
    const FILE_CREATE: u32 = 2;
    const FILE_OPEN_IF: u32 = 3;
    const FILE_DIRECTORY_FILE: u32 = 0x0001;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0040;
    const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32 as i32;
    const ERROR_ALREADY_EXISTS: i32 = 183;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn info(file: &std::fs::File) -> Result<BY_HANDLE_FILE_INFORMATION, String> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(info)
    }

    fn status_text(status: i32) -> String {
        format!("status {:#010x}", status as u32)
    }

    /// The account running Hivemend, as a SID string.
    fn user_sid() -> Result<String, String> {
        use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows_sys::Win32::Security::{
            GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        let mut token: HANDLE = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut buffer = vec![0u64; 64];
        let mut needed = 0u32;
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr() as _,
                (buffer.len() * 8) as u32,
                &mut needed,
            )
        };
        unsafe { CloseHandle(token) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
        let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut raw) } == 0 || raw.is_null() {
            return Err("could not read this account's SID".into());
        }
        let len = (0..).take_while(|&i| unsafe { *raw.add(i) } != 0).count();
        let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw, len) });
        unsafe { LocalFree(raw as _) };
        if !sid.starts_with("S-1-") || !sid[4..].chars().all(|c| c.is_ascii_digit() || c == '-') {
            return Err(format!("unexpected account SID {sid}"));
        }
        Ok(sid)
    }

    /// This account's Recycle Bin folder on the drive holding `original`,
    /// held open so it cannot be renamed or removed, with its real path.
    fn open_bin(original: &str) -> Result<(std::fs::File, String), String> {
        let mut root = vec![0u16; 1024];
        let path = wide(original);
        if unsafe { GetVolumePathNameW(path.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
            return Err(format!(
                "could not tell which drive it is on: {}",
                std::io::Error::last_os_error()
            ));
        }
        let len = root.iter().position(|&unit| unit == 0).unwrap_or(0);
        let root = String::from_utf16_lossy(&root[..len]);
        if unsafe { GetDriveTypeW(wide(&root).as_ptr()) } != DRIVE_FIXED {
            return Err("its drive has no Recycle Bin".into());
        }
        let shown_root = format!("{}$Recycle.Bin", root);
        let bin_root = std::fs::OpenOptions::new()
            .access_mode(FILE_TRAVERSE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&shown_root)
            .map_err(|err| {
                if err.kind() == std::io::ErrorKind::NotFound {
                    "its drive's Recycle Bin is not set up yet (delete any file on that drive in Explorer once, then try again)".to_string()
                } else {
                    format!("could not open {shown_root}: {err}")
                }
            })?;
        let attributes = info(&bin_root)?.dwFileAttributes;
        if attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(format!("{shown_root} is not a plain folder"));
        }
        let sid = user_sid()?;
        // As the Shell makes it: only this account, SYSTEM and
        // Administrators, nothing inherited.
        let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})");
        let bin = open_in(
            &bin_root,
            &sid,
            FILE_LIST_DIRECTORY
                | FILE_ADD_FILE
                | FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | READ_CONTROL
                | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN_IF,
            FILE_DIRECTORY_FILE,
            Some(&sddl),
        )
        .map_err(|status| {
            format!(
                "could not open this account's Recycle Bin folder ({})",
                status_text(status)
            )
        })?;
        let attributes = info(&bin)?.dwFileAttributes;
        if attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err("this account's Recycle Bin folder is not a plain folder".into());
        }
        let shown = format!("{shown_root}\\{sid}");
        crate::store::check_handle_owner_and_dacl(bin.as_raw_handle(), &shown, Some(&sid))?;
        let real = crate::fs::host_final_path(&bin)?;
        Ok((bin, real))
    }

    /// Rename the open `file` to `name` inside the held folder `dir`.
    /// (`SetFileInformationByHandle` refuses a folder handle as the base of
    /// the new name, so this goes to the NT call it wraps.)
    fn rename_into(file: &std::fs::File, dir: &std::fs::File, name: &str) -> std::io::Result<()> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let head = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
        let size = std::mem::size_of::<FILE_RENAME_INFORMATION>() + units.len() * 2;
        let mut buffer = vec![0u64; size.div_ceil(8)];
        let info = buffer.as_mut_ptr() as *mut FILE_RENAME_INFORMATION;
        unsafe {
            // Never replace: a name already taken fails.
            (*info).Anonymous.Flags = 0;
            (*info).RootDirectory = dir.as_raw_handle() as HANDLE;
            (*info).FileNameLength = (units.len() * 2) as u32;
            std::ptr::copy_nonoverlapping(
                units.as_ptr(),
                (buffer.as_mut_ptr() as *mut u8).add(head) as *mut u16,
                units.len(),
            );
        }
        let mut status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        let status = unsafe {
            NtSetInformationFile(
                file.as_raw_handle() as _,
                &mut status_block,
                buffer.as_ptr() as *const _,
                size as u32,
                FileRenameInformation,
            )
        };
        if status < 0 {
            return Err(std::io::Error::from_raw_os_error(
                unsafe { RtlNtStatusToDosError(status) } as i32,
            ));
        }
        Ok(())
    }

    fn now() -> u64 {
        let mut time = unsafe { std::mem::zeroed() };
        unsafe {
            windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime(&mut time)
        };
        (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
    }

    /// Move the open `file` into this account's Recycle Bin on its drive, by
    /// its handle (which must carry delete access). Returns where it went.
    /// On any failure the file stays where it is; it is never deleted.
    pub fn recycle_held(file: &std::fs::File) -> Result<String, String> {
        use std::io::Write;
        let original = crate::fs::host_final_path(file)?;
        let held = info(file)?;
        if held.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err("not a plain file".into());
        }
        let len = (u64::from(held.nFileSizeHigh) << 32) | u64::from(held.nFileSizeLow);
        let (bin, bin_path) = open_bin(&original)?;
        if info(&bin)?.dwVolumeSerialNumber != held.dwVolumeSerialNumber {
            return Err("its drive's Recycle Bin is on another volume".into());
        }
        let extension = super::kept_extension(&original);
        let record = super::info_record(&original, len, now());
        for attempt in 0..16u64 {
            let id = super::random_id(now() ^ attempt);
            let item = format!("$R{id}{extension}");
            let mut info_file = match open_in(
                &bin,
                &format!("$I{id}{extension}"),
                GENERIC_WRITE | DELETE | SYNCHRONIZE,
                0,
                FILE_CREATE,
                FILE_NON_DIRECTORY_FILE,
                None,
            ) {
                Ok(info_file) => info_file,
                Err(STATUS_OBJECT_NAME_COLLISION) => continue,
                Err(status) => {
                    return Err(format!(
                        "could not write its Recycle Bin record ({})",
                        status_text(status)
                    ));
                }
            };
            if let Err(err) = info_file
                .write_all(&record)
                .and_then(|()| info_file.sync_all())
            {
                dispose(&info_file);
                return Err(format!("could not write its Recycle Bin record: {err}"));
            }
            match rename_into(file, &bin, &item) {
                Ok(()) => {
                    notify(&original);
                    return Ok(format!("{bin_path}\\{item}"));
                }
                Err(err) => {
                    dispose(&info_file);
                    if err.raw_os_error() == Some(ERROR_ALREADY_EXISTS) {
                        continue;
                    }
                    return Err(format!("could not move it to the Recycle Bin: {err}"));
                }
            }
        }
        Err("could not find a free name in the Recycle Bin".into())
    }

    /// Tell Explorer, so open windows and the Recycle Bin icon update.
    fn notify(original: &str) {
        use windows_sys::Win32::UI::Shell::{SHCNE_DELETE, SHCNF_PATHW, SHChangeNotify};
        let path = wide(original);
        unsafe {
            SHChangeNotify(
                SHCNE_DELETE as i32,
                SHCNF_PATHW,
                path.as_ptr() as _,
                std::ptr::null(),
            )
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_record_is_the_version_2_layout() {
        let record = info_record(r"C:\a.txt", 5, 0x0102_0304_0506_0708);
        assert_eq!(&record[..8], &2u64.to_le_bytes());
        assert_eq!(&record[8..16], &5u64.to_le_bytes());
        assert_eq!(&record[16..24], &0x0102_0304_0506_0708u64.to_le_bytes());
        // Eight characters plus the NUL.
        assert_eq!(&record[24..28], &9u32.to_le_bytes());
        assert_eq!(record.len(), 28 + 9 * 2);
        assert_eq!(&record[28..30], &[b'C', 0]);
        assert_eq!(&record[record.len() - 2..], &[0, 0]);
    }

    #[test]
    fn the_recycled_name_keeps_only_a_real_extension() {
        assert_eq!(kept_extension(r"C:\d\photo.JPG"), ".JPG");
        assert_eq!(kept_extension(r"C:\d\archive.tar.gz"), ".gz");
        assert_eq!(kept_extension(r"C:\d\.profile"), "");
        assert_eq!(kept_extension(r"C:\d.x\README"), "");
        assert_eq!(kept_extension(r"C:\d\odd. name"), "");
    }

    #[test]
    fn ids_are_six_shell_characters() {
        let id = random_id(7);
        assert_eq!(id.len(), 6);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        );
    }
}
