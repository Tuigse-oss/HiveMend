//! Windows backends for privacy: running-process checks over ToolHelp,
//! and clipboard, Recycle Bin, drive, and cipher targets over Shell.

use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetDriveTypeW};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, CountClipboardFormats, EmptyClipboard, OpenClipboard,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
    TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessW, DETACHED_PROCESS, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows_sys::Win32::UI::Shell::{
    SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI, SHERB_NOSOUND, SHEmptyRecycleBinW,
    SHQUERYRBINFO, SHQueryRecycleBinW,
};

use crate::privacy::{ProcessList, SystemTargets};

const DRIVE_FIXED: u32 = 3;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsProcessList;

impl ProcessList for WindowsProcessList {
    fn running(&self, exe: &str) -> bool {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            // Unknown: fail closed, the category waits for the next run.
            return true;
        }
        unsafe {
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut found = false;
            if Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    let len = entry
                        .szExeFile
                        .iter()
                        .position(|&unit| unit == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                    if name.eq_ignore_ascii_case(exe) {
                        found = true;
                        break;
                    }
                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
            found
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsSystemTargets;

impl SystemTargets for WindowsSystemTargets {
    fn clipboard_items(&self) -> usize {
        usize::from(unsafe { CountClipboardFormats() } > 0)
    }

    fn clear_clipboard(&mut self) -> Result<(), String> {
        unsafe {
            if OpenClipboard(ptr::null_mut()) == 0 {
                return Err("in use by another program".into());
            }
            let ok = EmptyClipboard();
            CloseClipboard();
            if ok == 0 {
                return Err("could not empty".into());
            }
            Ok(())
        }
    }

    fn bin_items(&self) -> (usize, u64) {
        let mut info: SHQUERYRBINFO = unsafe { std::mem::zeroed() };
        info.cbSize = std::mem::size_of::<SHQUERYRBINFO>() as u32;
        let status = unsafe { SHQueryRecycleBinW(ptr::null(), &mut info) };
        if status != 0 {
            return (0, 0);
        }
        (info.i64NumItems.max(0) as usize, info.i64Size.max(0) as u64)
    }

    fn empty_bin(&mut self) -> Result<(), String> {
        let status = unsafe {
            SHEmptyRecycleBinW(
                ptr::null_mut(),
                ptr::null(),
                SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(format!("the Recycle Bin refused ({status:#x})"))
        }
    }

    fn fixed_drives(&self) -> Vec<String> {
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

    fn free_bytes(&self, drive: &str) -> u64 {
        let path = wide(drive);
        let mut free = 0u64;
        let mut total = 0u64;
        let mut total_free = 0u64;
        let ok = unsafe { GetDiskFreeSpaceExW(path.as_ptr(), &mut free, &mut total, &mut total_free) };
        if ok == 0 { 0 } else { free }
    }

    fn wipe_free_space(&mut self, drive: &str) -> Result<(), String> {
        let system = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let mut command: Vec<u16> =
            format!("{system}\\System32\\cipher.exe /w:{drive}\0").encode_utf16().collect();
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut child: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            CreateProcessW(
                ptr::null(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                CREATE_NO_WINDOW | DETACHED_PROCESS,
                ptr::null(),
                ptr::null(),
                &startup,
                &mut child,
            )
        };
        if ok == 0 {
            return Err(format!("could not start cipher ({})", unsafe { GetLastError() }));
        }
        unsafe {
            CloseHandle(child.hProcess);
            CloseHandle(child.hThread);
        }
        Ok(())
    }
}
