//! Windows backends for the shredder: fixed-drive list and SSD detection.

use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetDriveTypeW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::{
    IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery, STORAGE_PROPERTY_QUERY,
    StorageDeviceSeekPenaltyProperty,
};

const DRIVE_FIXED: u32 = 3;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `X:\` roots of mounted fixed disks, for bin listing and cipher.
pub fn fixed_drives() -> Vec<String> {
    let mut drives = Vec::new();
    for code in b'A'..=b'Z' {
        let root = format!("{}:\\", code as char);
        let path = wide(&root);
        if unsafe { GetDriveTypeW(path.as_ptr()) } == DRIVE_FIXED {
            drives.push(root);
        }
    }
    drives
}

/// Whether a drive sits on flash. `None` when the volume cannot be asked
/// (access denied, offline), which the page reports as unknown rather than
/// guessing. The handle asks for no access rights, so the query works
/// without elevation.
pub fn volume_ssd(drive: &str) -> Option<bool> {
    let letter = drive.trim().as_bytes().first()?.to_ascii_uppercase();
    if !letter.is_ascii_alphabetic() {
        return None;
    }
    let path = wide(&format!("\\\\.\\{}:", letter as char));
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return None;
    }
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceSeekPenaltyProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };
    // STORAGE_DEVICE_SEEK_PENALTY_DESCRIPTOR: ULONG Version, ULONG Size,
    // BOOLEAN flag. windows-sys does not ship the struct, so read raw bytes
    // and reuse the tested parser.
    let mut out = [0u8; 12];
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query as *const _ as *const _,
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            out.as_mut_ptr() as *mut _,
            out.len() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    unsafe { CloseHandle(handle) };
    if ok == 0 || returned as usize != out.len() {
        return None;
    }
    crate::shredder::seek_penalty_false(&out)
}
