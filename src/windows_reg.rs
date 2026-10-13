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
        // An embedded NUL would truncate the name at the Win32 boundary and
        // could address a different value, so refuse it before opening.
        if name.contains('\0') {
            return Err(RegError::Message(format!(
                "{path}: value name contains a NUL and cannot be addressed safely"
            )));
        }
        let opened = open(path, true)?;
        let wide = wide(name);
        let rc = unsafe { RegDeleteValueW(opened.key, wide.as_ptr()) };
        if rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND {
            return Err(RegError::NotFound);
        }
        if rc != ERROR_SUCCESS {
            return Err(failure(
                rc,
                format!("RegDeleteValueW {path}\\{name} failed ({rc})"),
            ));
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
    // An embedded NUL truncates the name at the Win32 boundary, so re-querying
    // by it could read a different value. Refuse rather than back up the wrong
    // bytes; the key is then reported unreadable and left alone.
    if name.contains('\0') {
        return Err(RegError::Message(format!(
            "value name {name:?} contains a NUL and cannot be read back safely"
        )));
    }
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
        // Keep decoded text only when it re-encodes to the exact original
        // bytes. A non-canonical string (odd length, a missing or extra NUL,
        // bytes after the terminator, or unpaired UTF-16) is preserved raw, so
        // a backup round-trips the value rather than silently rewriting it.
        REG_SZ => round_trip_sz(bytes)
            .map(ValueKind::Sz)
            .unwrap_or_else(|| other(kind, bytes)),
        REG_EXPAND_SZ => round_trip_sz(bytes)
            .map(ValueKind::ExpandSz)
            .unwrap_or_else(|| other(kind, bytes)),
        // A DWORD is exactly four bytes. Any other length keeps its raw bytes.
        REG_DWORD if bytes.len() == 4 => {
            ValueKind::Dword(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }
        REG_MULTI_SZ => {
            let parts = decode_multi(bytes);
            if multi_sz_bytes(&parts) == bytes {
                ValueKind::MultiSz(parts)
            } else {
                other(kind, bytes)
            }
        }
        REG_BINARY => ValueKind::Binary(bytes.to_vec()),
        _ => other(kind, bytes),
    }
}

fn other(kind: u32, bytes: &[u8]) -> ValueKind {
    ValueKind::Other {
        kind,
        bytes: bytes.to_vec(),
    }
}

/// Re-encode a UTF-16 string the way a canonical REG_SZ is stored.
fn sz_bytes(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2 + 2);
    for unit in text.encode_utf16() {
        out.extend(unit.to_le_bytes());
    }
    out.extend([0, 0]);
    out
}

/// Decode a REG_SZ/REG_EXPAND_SZ buffer only when the decode is reversible:
/// the decoded text must re-encode to the exact original bytes.
fn round_trip_sz(bytes: &[u8]) -> Option<String> {
    let text = decode_sz(bytes);
    (sz_bytes(&text) == bytes).then_some(text)
}

/// Re-encode a MULTI_SZ the way a canonical value is stored: each element
/// NUL-terminated, then a final NUL.
fn multi_sz_bytes(parts: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        for unit in part.encode_utf16() {
            out.extend(unit.to_le_bytes());
        }
        out.extend([0, 0]);
    }
    out.extend([0, 0]);
    out
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
                Err(OpenFail::Code(code)) => Err(failure(
                    code,
                    format!("RegOpenKeyExW {path} failed ({code})"),
                )),
            }
        }
        Err(OpenFail::Code(code)) => Err(failure(
            code,
            format!("RegOpenKeyExW {path} failed ({code})"),
        )),
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

/// Live Windows tests. They touch one throwaway key under the current
/// user's hive (never HKLM, never anything real) and remove it on Drop,
/// so a failing assert cannot leave residue behind.
#[cfg(all(test, windows))]
mod live_tests {
    use super::*;
    use crate::model::ValueKind;
    use windows_sys::Win32::System::Registry::{
        KEY_WOW64_64KEY, KEY_WRITE, REG_DWORD, REG_SZ, RegCreateKeyExW, RegDeleteKeyExW,
        RegSetValueExW,
    };

    #[test]
    fn canonical_sz_round_trips_but_noncanonical_is_preserved_raw() {
        // Canonical `AB\0`.
        assert_eq!(
            decode_value(REG_SZ, &sz_bytes("AB")),
            ValueKind::Sz("AB".into())
        );
        // No trailing NUL: preserved raw so the backup keeps the exact bytes.
        assert!(matches!(
            decode_value(REG_SZ, &[0x41, 0, 0x42, 0]),
            ValueKind::Other { .. }
        ));
        // Bytes after the terminator: preserved raw.
        let mut trailing = sz_bytes("AB");
        trailing.extend([0x43, 0]);
        assert!(matches!(
            decode_value(REG_SZ, &trailing),
            ValueKind::Other { .. }
        ));
        // Odd length: preserved raw.
        assert!(matches!(
            decode_value(REG_SZ, &[0x41, 0, 0x42]),
            ValueKind::Other { .. }
        ));
    }

    #[test]
    fn dword_must_be_exactly_four_bytes() {
        assert_eq!(decode_value(REG_DWORD, &[1, 0, 0, 0]), ValueKind::Dword(1));
        assert!(matches!(
            decode_value(REG_DWORD, &[1, 0, 0, 0, 0]),
            ValueKind::Other { .. }
        ));
        assert!(matches!(
            decode_value(REG_DWORD, &[1, 0]),
            ValueKind::Other { .. }
        ));
    }

    #[test]
    fn delete_value_refuses_a_name_with_an_embedded_nul() {
        // The guard returns before the key is opened, so no registry access
        // happens; a NUL must never reach the NUL-terminated Win32 call.
        let mut reg = WindowsRegistry;
        let err = reg
            .delete_value(r"HKCU\Software\HiveMendTest\Nope", "abc\0tail")
            .unwrap_err();
        assert!(matches!(err, RegError::Message(msg) if msg.contains("NUL")));
    }

    struct TestKey {
        root: String,
    }

    impl TestKey {
        fn create() -> Self {
            let root = format!(r"HKCU\Software\HiveMendTest{}", std::process::id());
            let subkey = root.strip_prefix("HKCU\\").unwrap().to_string();
            unsafe {
                let mut key: HKEY = ptr::null_mut();
                let mut disposition = 0u32;
                let child = wide(&format!("{subkey}\\Child"));
                let rc = RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    child.as_ptr(),
                    0,
                    ptr::null(),
                    0,
                    KEY_WRITE | KEY_WOW64_64KEY,
                    ptr::null(),
                    &mut key,
                    &mut disposition,
                );
                assert_eq!(rc, ERROR_SUCCESS, "test key setup failed");
                let text: Vec<u16> = "hello".encode_utf16().chain(std::iter::once(0)).collect();
                let name = wide("Text");
                let rc = RegSetValueExW(
                    key,
                    name.as_ptr(),
                    0,
                    REG_SZ,
                    text.as_ptr() as *const u8,
                    (text.len() * 2) as u32,
                );
                assert_eq!(rc, ERROR_SUCCESS, "test value setup failed");
                let name = wide("Num");
                let rc = RegSetValueExW(
                    key,
                    name.as_ptr(),
                    0,
                    REG_DWORD,
                    42u32.to_le_bytes().as_ptr(),
                    4,
                );
                assert_eq!(rc, ERROR_SUCCESS, "test value setup failed");
                RegCloseKey(key);
            }
            Self { root }
        }
    }

    impl Drop for TestKey {
        fn drop(&mut self) {
            let mut reg = WindowsRegistry;
            let _ = reg.delete_tree(&self.root);
            let subkey = match self.root.strip_prefix("HKCU\\") {
                Some(rest) => rest,
                None => return,
            };
            let wide = wide(subkey);
            unsafe {
                RegDeleteKeyExW(HKEY_CURRENT_USER, wide.as_ptr(), KEY_WOW64_64KEY, 0);
            }
        }
    }

    #[test]
    fn live_registry_round_trip() {
        let key = TestKey::create();
        let reg = WindowsRegistry;
        let kids = reg.subkeys(&key.root).expect("list test key");
        assert!(kids.iter().any(|name| name == "Child"));
        let child = format!(r"{}\Child", key.root);
        let values = reg.values(&child).expect("read test values");
        assert!(
            values
                .iter()
                .any(|value| value.name == "Text"
                    && value.data == ValueKind::Sz("hello".to_string()))
        );
        assert!(
            values
                .iter()
                .any(|value| value.name == "Num" && value.data == ValueKind::Dword(42))
        );
        let mut reg = reg;
        reg.delete_value(&child, "Text").expect("delete test value");
        let values = reg.values(&child).expect("re-read test values");
        assert!(!values.iter().any(|value| value.name == "Text"));
        // delete_tree removes the whole subtree. Delete the child first,
        // which empties the root's listing, then the root itself, which is
        // then gone rather than present-but-empty.
        reg.delete_tree(&child).expect("delete child subtree");
        let kids = reg.subkeys(&key.root).expect("list emptied key");
        assert!(kids.is_empty());
        reg.delete_tree(&key.root).expect("delete test tree");
        assert!(matches!(reg.subkeys(&key.root), Err(RegError::NotFound)));
    }

    #[test]
    fn live_missing_key_reads_fail_cleanly() {
        let reg = WindowsRegistry;
        assert!(reg.subkeys(r"HKCU\Software\HiveMendNoSuchKey").is_err());
        assert!(reg.values(r"HKCU\Software\HiveMendNoSuchKey").is_err());
    }
}
