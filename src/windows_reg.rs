use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
    ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    HKEY_USERS, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE, KEY_WOW64_64KEY,
    REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ, RegCloseKey, RegDeleteTreeW,
    RegDeleteValueW, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW,
};

use crate::model::{RegValue, ValueKind};
use crate::pathutil::canonical_path;
use crate::registry::{RegError, Registry};

const DELETE_ACCESS: u32 = 0x0001_0000;

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsRegistry;

struct Opened {
    key: HKEY,
    close: bool,
}

impl Drop for Opened {
    fn drop(&mut self) {
        if self.close {
            unsafe {
                RegCloseKey(self.key);
            }
        }
    }
}

impl Registry for WindowsRegistry {
    fn subkeys(&self, path: &str) -> Result<Vec<String>, RegError> {
        let opened = open(path, false)?;
        let mut names = Vec::new();
        let mut index = 0u32;
        loop {
            let mut name = [0u16; 256];
            let mut len = name.len() as u32;
            let rc = unsafe {
                RegEnumKeyExW(
                    opened.key,
                    index,
                    name.as_mut_ptr(),
                    &mut len,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS {
                return Err(RegError::Message(format!(
                    "RegEnumKeyExW {path} failed ({rc})"
                )));
            }
            names.push(String::from_utf16_lossy(&name[..len as usize]));
            index = index.saturating_add(1);
        }
        Ok(names)
    }

    fn values(&self, path: &str) -> Result<Vec<RegValue>, RegError> {
        let opened = open(path, false)?;
        let mut values = Vec::new();
        let mut index = 0u32;
        loop {
            let mut name = vec![0u16; 16_384];
            let mut name_len = name.len() as u32;
            let mut kind = 0u32;
            let mut data_len = 0u32;
            let rc = unsafe {
                RegEnumValueW(
                    opened.key,
                    index,
                    name.as_mut_ptr(),
                    &mut name_len,
                    ptr::null(),
                    &mut kind,
                    ptr::null_mut(),
                    &mut data_len,
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA {
                return Err(RegError::Message(format!(
                    "RegEnumValueW {path} failed ({rc})"
                )));
            }
            let value_name = String::from_utf16_lossy(&name[..name_len as usize]);
            let data = read_value(&opened, &value_name, kind, data_len)?;
            values.push(RegValue {
                name: value_name,
                data,
            });
            index = index.saturating_add(1);
        }
        Ok(values)
    }

    fn delete_value(&mut self, path: &str, name: &str) -> Result<(), RegError> {
        let opened = open(path, true)?;
        let wide = wide(name);
        let rc = unsafe { RegDeleteValueW(opened.key, wide.as_ptr()) };
        if rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND {
            return Err(RegError::NotFound);
        }
        if rc != ERROR_SUCCESS {
            return Err(failure(rc, format!("RegDeleteValueW {path}\\{name} failed ({rc})")));
        }
        Ok(())
    }

    fn delete_tree(&mut self, path: &str) -> Result<(), RegError> {
        let (parent, leaf) = split_parent(path)?;
        let opened = open(&parent, true)?;
        let wide = wide(&leaf);
        let rc = unsafe { RegDeleteTreeW(opened.key, wide.as_ptr()) };
        if rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND {
            return Err(RegError::NotFound);
        }
        if rc != ERROR_SUCCESS {
            return Err(failure(rc, format!("RegDeleteTreeW {path} failed ({rc})")));
        }
        Ok(())
    }
}

fn failure(rc: u32, message: String) -> RegError {
    if rc == ERROR_ACCESS_DENIED {
        RegError::Denied(message)
    } else {
        RegError::Message(message)
    }
}

/// Reads the whole value. A backup that dropped part of a value would put
/// back something different from what repair removed.
fn read_value(opened: &Opened, name: &str, kind: u32, size: u32) -> Result<ValueKind, RegError> {
    let mut bytes = vec![0u8; size as usize];
    let mut got = size;
    let mut read_kind = kind;
    let wide = wide(name);
    let rc = unsafe {
        RegQueryValueExW(
            opened.key,
            wide.as_ptr(),
            ptr::null(),
            &mut read_kind,
            bytes.as_mut_ptr(),
            &mut got,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(RegError::Message(format!(
            "RegQueryValueExW {name} failed ({rc})"
        )));
    }
    bytes.truncate(got as usize);
    Ok(decode_value(read_kind, &bytes))
}

fn decode_value(kind: u32, bytes: &[u8]) -> ValueKind {
    match kind {
        REG_SZ => ValueKind::Sz(decode_sz(bytes)),
        REG_EXPAND_SZ => ValueKind::ExpandSz(decode_sz(bytes)),
        REG_DWORD if bytes.len() >= 4 => {
            ValueKind::Dword(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }
        REG_MULTI_SZ => ValueKind::MultiSz(decode_multi(bytes)),
        REG_BINARY => ValueKind::Binary(bytes.to_vec()),
        _ => ValueKind::Other {
            kind,
            bytes: bytes.to_vec(),
        },
    }
}

fn decode_sz(bytes: &[u8]) -> String {
    let mut units = Vec::new();
    for chunk in bytes.chunks(2) {
        if chunk.len() < 2 {
            break;
        }
        let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    String::from_utf16_lossy(&units)
}

fn decode_multi(bytes: &[u8]) -> Vec<String> {
    let mut units = Vec::new();
    let mut parts = Vec::new();
    for chunk in bytes.chunks(2) {
        if chunk.len() < 2 {
            break;
        }
        let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
        if unit == 0 {
            if units.is_empty() {
                break;
            }
            parts.push(String::from_utf16_lossy(&units));
            units.clear();
        } else {
            units.push(unit);
        }
    }
    if !units.is_empty() {
        parts.push(String::from_utf16_lossy(&units));
    }
    parts
}

fn open(path: &str, write: bool) -> Result<Opened, RegError> {
    let path = canonical_path(path);
    let mut parts = path.split('\\');
    let hive_name = parts
        .next()
        .ok_or_else(|| RegError::Message(format!("empty registry path {path}")))?;
    let hive = hive(hive_name)
        .ok_or_else(|| RegError::Message(format!("unknown registry hive in {path}")))?;
    let subkey = parts.collect::<Vec<_>>().join("\\");
    if subkey.is_empty() {
        return Ok(Opened {
            key: hive,
            close: false,
        });
    }
    let mut access = KEY_READ | KEY_WOW64_64KEY;
    if write {
        access |= KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | DELETE_ACCESS;
    }
    match open_raw(hive, &subkey, access) {
        Ok(key) => Ok(Opened { key, close: true }),
        Err(OpenFail::Missing) => Err(RegError::NotFound),
        Err(OpenFail::Code(_code)) if access & KEY_WOW64_64KEY != 0 => {
            match open_raw(hive, &subkey, access & !KEY_WOW64_64KEY) {
                Ok(key) => Ok(Opened { key, close: true }),
                Err(OpenFail::Missing) => Err(RegError::NotFound),
                Err(OpenFail::Code(code)) => {
                    Err(failure(code, format!("RegOpenKeyExW {path} failed ({code})")))
                }
            }
        }
        Err(OpenFail::Code(code)) => {
            Err(failure(code, format!("RegOpenKeyExW {path} failed ({code})")))
        }
    }
}

enum OpenFail {
    Missing,
    Code(u32),
}

fn open_raw(hive: HKEY, subkey: &str, access: u32) -> Result<HKEY, OpenFail> {
    let wide = wide(subkey);
    let mut opened = ptr::null_mut();
    let rc = unsafe { RegOpenKeyExW(hive, wide.as_ptr(), 0, access, &mut opened) };
    if rc == ERROR_SUCCESS && !opened.is_null() {
        Ok(opened)
    } else if rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND {
        Err(OpenFail::Missing)
    } else {
        Err(OpenFail::Code(rc))
    }
}

fn hive(name: &str) -> Option<HKEY> {
    match name {
        "HKEY_LOCAL_MACHINE" => Some(HKEY_LOCAL_MACHINE),
        "HKEY_CURRENT_USER" => Some(HKEY_CURRENT_USER),
        "HKEY_CLASSES_ROOT" => Some(HKEY_CLASSES_ROOT),
        "HKEY_USERS" => Some(HKEY_USERS),
        "HKEY_CURRENT_CONFIG" => Some(HKEY_CURRENT_CONFIG),
        _ => None,
    }
}

fn split_parent(path: &str) -> Result<(String, String), RegError> {
    let path = canonical_path(path);
    let mut parts: Vec<&str> = path.split('\\').filter(|part| !part.is_empty()).collect();
    let leaf = parts
        .pop()
        .ok_or_else(|| RegError::Message("cannot delete a hive root".into()))?
        .to_string();
    if parts.is_empty() {
        return Err(RegError::Message("cannot delete a hive root".into()));
    }
    Ok((parts.join("\\"), leaf))
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}
