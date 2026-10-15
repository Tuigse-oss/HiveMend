use std::ptr;

use windows_sys::Wdk::System::Registry::{
    KeyFlagsInformation, KeyNameInformation, NtDeleteKey, NtQueryKey,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
    ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    HKEY_USERS, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_READ,
    KEY_SET_VALUE, KEY_WOW64_64KEY, REG_BINARY, REG_CREATED_NEW_KEY, REG_DWORD, REG_EXPAND_SZ,
    REG_LINK, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE, REG_OPTION_OPEN_LINK, REG_SZ, RegCloseKey,
    RegCreateKeyExW, RegCreateKeyTransactedW, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW,
    RegOpenKeyExW, RegOpenKeyTransactedW, RegQueryValueExW, RegSetValueExW,
};

use crate::model::{RegValue, ValueKind};
use crate::pathutil::canonical_path;
use crate::registry::{RegError, RegTransaction, Registry};

const DELETE_ACCESS: u32 = 0x0001_0000;
/// `KEY_FLAGS_INFORMATION.KeyFlags` bit for a symbolic-link key.
const REG_FLAG_LINK: u32 = 0x2;
/// Links one path may cross. Windows' own chains are two deep
/// (`Hardware Profiles\Current` -> `CurrentControlSet` -> `ControlSetNNN`).
const MAX_LINK_HOPS: usize = 4;
/// Matches the backup's export depth: a delete never goes deeper than a
/// backup could have saved.
const MAX_DELETE_DEPTH: usize = 512;

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsRegistry;

thread_local! {
    /// The transaction every open and create on this thread goes through
    /// while a [`WindowsTransaction`] call runs; null otherwise.
    static TX: std::cell::Cell<windows_sys::Win32::Foundation::HANDLE> =
        const { std::cell::Cell::new(ptr::null_mut()) };
}

/// Sets this thread's transaction for one call and clears it after.
struct TxScope(windows_sys::Win32::Foundation::HANDLE);

impl TxScope {
    fn enter(tx: windows_sys::Win32::Foundation::HANDLE) -> Self {
        Self(TX.with(|cell| cell.replace(tx)))
    }
}

impl Drop for TxScope {
    fn drop(&mut self) {
        TX.with(|cell| cell.set(self.0));
    }
}

/// A Windows registry transaction (KTM). Every key it opens or creates goes
/// through the same link-refusing walk as [`WindowsRegistry`], transacted.
/// Windows aborts it if anything else changes a key it has written, so the
/// commit then fails and nothing it did is applied; dropping it uncommitted
/// rolls it back.
pub struct WindowsTransaction {
    tx: windows_sys::Win32::Foundation::HANDLE,
    done: bool,
    /// The value name `touch` writes and removes again, new for each
    /// transaction.
    marker: Vec<u16>,
}

/// A fresh marker value name.
fn touch_marker() -> Vec<u16> {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|time| time.as_nanos())
            .unwrap_or_default(),
    );
    wide(&format!("Hivemend transaction {:016x}", hasher.finish()))
}

impl WindowsTransaction {
    pub fn begin() -> Result<Self, RegError> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::CreateTransaction;
        let tx = unsafe {
            CreateTransaction(
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                0,
                0,
                0,
                ptr::null_mut(),
            )
        };
        if tx == INVALID_HANDLE_VALUE || tx.is_null() {
            return Err(RegError::Message(format!(
                "registry transactions are not available ({})",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self {
            tx,
            done: false,
            marker: touch_marker(),
        })
    }
}

impl Drop for WindowsTransaction {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::Storage::FileSystem::RollbackTransaction;
        unsafe {
            if !self.done {
                RollbackTransaction(self.tx);
            }
            CloseHandle(self.tx);
        }
    }
}

impl Registry for WindowsTransaction {
    fn subkeys(&self, path: &str) -> Result<Vec<String>, RegError> {
        let _scope = TxScope::enter(self.tx);
        WindowsRegistry.subkeys(path)
    }
    fn values(&self, path: &str) -> Result<Vec<RegValue>, RegError> {
        let _scope = TxScope::enter(self.tx);
        WindowsRegistry.values(path)
    }
    fn delete_value(&mut self, path: &str, name: &str) -> Result<(), RegError> {
        let _scope = TxScope::enter(self.tx);
        WindowsRegistry.delete_value(path, name)
    }
    fn delete_tree(&mut self, path: &str) -> Result<(), RegError> {
        let _scope = TxScope::enter(self.tx);
        WindowsRegistry.delete_tree(path)
    }
    fn set_value(&mut self, path: &str, name: &str, data: &ValueKind) -> Result<(), RegError> {
        let _scope = TxScope::enter(self.tx);
        WindowsRegistry.set_value(path, name, data)
    }
}

impl WindowsTransaction {
    /// Write the marker value to `key` inside the transaction and remove
    /// it again, so the key is part of the transaction.
    fn touch_inside(&self, key: &str) -> Result<(), RegError> {
        let _scope = TxScope::enter(self.tx);
        let opened = open(key, true)?;
        let name = &self.marker;
        let marker = 1u32.to_le_bytes();
        let set = unsafe {
            RegSetValueExW(
                opened.key,
                name.as_ptr(),
                0,
                REG_DWORD,
                marker.as_ptr(),
                marker.len() as u32,
            )
        };
        if set != ERROR_SUCCESS {
            return Err(failure(
                set,
                format!("{key}: could not start its transaction ({set})"),
            ));
        }
        let removed = unsafe { RegDeleteValueW(opened.key, name.as_ptr()) };
        if removed != ERROR_SUCCESS {
            return Err(failure(
                removed,
                format!("{key}: could not start its transaction ({removed})"),
            ));
        }
        Ok(())
    }
}

impl RegTransaction for WindowsTransaction {
    fn delete_tree_exact(&mut self, path: &str, expected: &[String]) -> Result<(), RegError> {
        let _scope = TxScope::enter(self.tx);
        delete_tree_checked(path, Some(expected))
    }

    fn require_trusted(&self, key: &str) -> Result<(), RegError> {
        let _scope = TxScope::enter(self.tx);
        require_trusted_key(key)
    }

    fn touch(&mut self, key: &str) -> Result<(), RegError> {
        self.touch_inside(key)?;
        // Outside the transaction a value of that name must not exist: if it
        // does, the transaction's write and delete stood in for a value
        // someone else owns, and committing would remove it. One that
        // appears later changes a touched key, which fails the commit.
        let plain = open(key, false)?;
        let present = unsafe {
            RegQueryValueExW(
                plain.key,
                self.marker.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if present == ERROR_SUCCESS {
            return Err(RegError::Message(format!(
                "{key} has a value with the name Hivemend uses to start its transaction; left alone"
            )));
        }
        Ok(())
    }

    fn commit(mut self: Box<Self>) -> Result<(), RegError> {
        use windows_sys::Win32::Storage::FileSystem::CommitTransaction;
        let ok = unsafe { CommitTransaction(self.tx) };
        self.done = true;
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            return Err(RegError::Message(format!(
                "the change was not applied: another program changed the key meanwhile, or Windows refused ({err})"
            )));
        }
        Ok(())
    }
}

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
        enum_subkeys(opened.key, path)
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

    fn set_value(&mut self, path: &str, name: &str, data: &ValueKind) -> Result<(), RegError> {
        // An embedded NUL would truncate the name at the Win32 boundary.
        if name.contains('\0') {
            return Err(RegError::Message(format!(
                "{path}: value name contains a NUL and cannot be addressed safely"
            )));
        }
        let opened = match open(path, true) {
            Ok(opened) => opened,
            Err(RegError::NotFound) => create_key(path, 0)?,
            Err(err) => return Err(err),
        };
        let (kind, bytes) = encode_value(data);
        let wide = wide(name);
        let rc = unsafe {
            RegSetValueExW(
                opened.key,
                wide.as_ptr(),
                0,
                kind,
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(failure(
                rc,
                format!("RegSetValueExW {path}\\{name} failed ({rc})"),
            ));
        }
        Ok(())
    }

    fn begin(&mut self) -> Result<Box<dyn RegTransaction + '_>, RegError> {
        Ok(Box::new(WindowsTransaction::begin()?))
    }

    fn delete_tree(&mut self, path: &str) -> Result<(), RegError> {
        delete_tree_checked(path, None)
    }
}

#[cfg(test)]
thread_local! {
    /// Tests of other behaviour on HKCU keys, in an elevated test run, set
    /// the trust rule aside on their own thread.
    static TRUST_ANYWAY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Delete `path` and its subtree. Pin the whole subtree first, refusing any
/// link in it, and only then delete through the pinned handles
/// (RegDeleteTreeW reopens by name and follows links, so a link anywhere
/// below would have it empty the link's target instead). With `expected`,
/// the pinned keys must be exactly those, or nothing is deleted.
fn delete_tree_checked(path: &str, expected: Option<&[String]>) -> Result<(), RegError> {
    let (parent, leaf) = split_parent(path)?;
    let parent = open(&parent, false)?;
    let root = open_child(
        parent.key,
        &leaf,
        KEY_READ | DELETE_ACCESS | KEY_WOW64_64KEY,
    )
    .map_err(|fail| fail.into_error(path))?;
    let tree = pin_subtree(root, &canonical_path(path), 0)?;
    if let Some(expected) = expected {
        let mut pinned = Vec::new();
        pinned_paths(&tree, &mut pinned);
        if !crate::registry::same_keys(&pinned, expected) {
            return Err(RegError::Message(format!(
                "{path} changed while it was being removed (a key appeared or went); nothing was removed"
            )));
        }
    }
    delete_pinned(tree)
}

fn pinned_paths(tree: &Pinned, out: &mut Vec<String>) {
    out.push(canonical_path(&tree.path));
    for child in &tree.children {
        pinned_paths(child, out);
    }
}

/// As an administrator, refuse a key (or, for one that does not exist yet,
/// the nearest key above it) that programs running without elevation can
/// change. Without elevation there is nothing to refuse: the window can only
/// do what its own account can.
pub(crate) fn require_trusted_key(path: &str) -> Result<(), RegError> {
    #[cfg(test)]
    if TRUST_ANYWAY.with(|flag| flag.get()) {
        return Ok(());
    }
    if !crate::store::elevated() {
        return Ok(());
    }
    let mut at = canonical_path(path);
    loop {
        match open(&at, false) {
            Ok(opened) => {
                return crate::store::check_registry_key_security(opened.key as _, &at).map_err(
                    |why| {
                        RegError::Denied(format!("{why}; an administrator window leaves it alone"))
                    },
                );
            }
            Err(RegError::NotFound) => match split_parent(&at) {
                Ok((parent, _)) => at = parent,
                Err(_) => return Err(RegError::NotFound),
            },
            Err(err) => return Err(err),
        }
    }
}

/// One key of a subtree pinned for deletion: its handle, opened without
/// following links, and its children.
struct Pinned {
    key: Opened,
    path: String,
    children: Vec<Pinned>,
}

fn pin_subtree(key: Opened, path: &str, depth: usize) -> Result<Pinned, RegError> {
    if depth > MAX_DELETE_DEPTH {
        return Err(RegError::Message(format!("{path}: nested too deeply")));
    }
    if is_link(key.key)? {
        return Err(RegError::Message(format!(
            "{path} is a registry link; links are never deleted or followed"
        )));
    }
    let mut children = Vec::new();
    for name in enum_subkeys(key.key, path)? {
        let child_path = format!("{path}\\{name}");
        if name.contains('\0') {
            return Err(RegError::Message(format!(
                "{child_path}: key name contains a NUL and cannot be addressed safely"
            )));
        }
        let child = open_child(key.key, &name, KEY_READ | DELETE_ACCESS | KEY_WOW64_64KEY)
            .map_err(|fail| fail.into_error(&child_path))?;
        children.push(pin_subtree(child, &child_path, depth + 1)?);
    }
    Ok(Pinned {
        key,
        path: path.to_string(),
        children,
    })
}

/// Delete a pinned subtree deepest-first through the held handles. A key that
/// gained a child since it was pinned refuses to go, so nothing unpinned is
/// ever removed.
fn delete_pinned(tree: Pinned) -> Result<(), RegError> {
    for child in tree.children {
        delete_pinned(child)?;
    }
    let status = unsafe { NtDeleteKey(tree.key.key as _) };
    if status < 0 {
        const STATUS_ACCESS_DENIED: i32 = 0xC000_0022_u32 as i32;
        let message = format!("deleting {} failed (NTSTATUS {status:#x})", tree.path);
        if status == STATUS_ACCESS_DENIED {
            return Err(RegError::Denied(message));
        }
        return Err(RegError::Message(message));
    }
    Ok(())
}

fn enum_subkeys(key: HKEY, path: &str) -> Result<Vec<String>, RegError> {
    let mut names = Vec::new();
    let mut index = 0u32;
    loop {
        let mut name = [0u16; 256];
        let mut len = name.len() as u32;
        let rc = unsafe {
            RegEnumKeyExW(
                key,
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

/// Create the last component of `path` under its existing parent, reached by
/// the same link-checked walk as every other open. A name that already exists
/// as a link is refused rather than created through.
/// Open `path` for writing values, creating it and any missing parent keys
/// one level at a time. Each level is opened without following links and
/// refused if it is one, so a value is never written through a link.
fn create_key(path: &str, depth: usize) -> Result<Opened, RegError> {
    if depth > MAX_LINK_HOPS + 64 {
        return Err(RegError::Message(format!("{path}: too deep to create")));
    }
    let (parent, leaf) = split_parent(path)?;
    let parent = match open_with(&parent, KEY_CREATE_SUB_KEY) {
        Ok(parent) => parent,
        Err(RegError::NotFound) => {
            drop(create_key(&parent, depth + 1)?);
            open_with(&parent, KEY_CREATE_SUB_KEY)?
        }
        Err(err) => return Err(err),
    };
    if let Ok(existing) = open_child(
        parent.key,
        &leaf,
        KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_WOW64_64KEY,
    ) {
        if is_link(existing.key)? {
            return Err(RegError::Message(format!(
                "{path} is a registry link; links are never written through"
            )));
        }
        return Ok(existing);
    }
    let wide = wide(&leaf);
    let mut key: HKEY = ptr::null_mut();
    let mut disposition = 0u32;
    let tx = TX.with(|cell| cell.get());
    let rc = unsafe {
        if tx.is_null() {
            RegCreateKeyExW(
                parent.key,
                wide.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                ptr::null(),
                &mut key,
                &mut disposition,
            )
        } else {
            RegCreateKeyTransactedW(
                parent.key,
                wide.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                ptr::null(),
                &mut key,
                &mut disposition,
                tx,
                ptr::null(),
            )
        }
    };
    if rc != ERROR_SUCCESS || key.is_null() {
        return Err(failure(rc, format!("RegCreateKeyExW {path} failed ({rc})")));
    }
    let opened = Opened { key, close: true };
    // The key was missing a moment ago. If the create opened an existing
    // key instead, something appeared in between, possibly a link that the
    // create followed: refuse rather than write to whatever it reached.
    if disposition != REG_CREATED_NEW_KEY {
        return Err(RegError::Message(format!(
            "{path} appeared while it was being created; nothing was written"
        )));
    }
    if is_link(opened.key)? {
        return Err(RegError::Message(format!(
            "{path} became a registry link while it was created"
        )));
    }
    Ok(opened)
}

/// A value's registry type and raw bytes, as RegSetValueExW takes them.
fn encode_value(data: &ValueKind) -> (u32, Vec<u8>) {
    data.encoded()
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

/// Open a key without following any registry symbolic link implicitly. The
/// path is walked one component at a time with `REG_OPTION_OPEN_LINK`; a
/// component that is a link is crossed only when it is one Windows itself
/// defines and points where Windows points it ([`system_link_target`]), and
/// the walk then restarts from that target. Any other link is refused, so a
/// read, backup, or delete always reaches the key its path names.
fn open(path: &str, write: bool) -> Result<Opened, RegError> {
    if write {
        open_with(
            path,
            KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | DELETE_ACCESS,
        )
    } else {
        open_with(path, 0)
    }
}

/// Open `path` with read access plus `extra`, crossing only the links
/// Windows itself defines.
fn open_with(path: &str, extra: u32) -> Result<Opened, RegError> {
    let access = KEY_READ | KEY_WOW64_64KEY | extra;
    let original = canonical_path(path);
    let mut current = original.clone();
    for _ in 0..=MAX_LINK_HOPS {
        match walk(&current, access)? {
            Walk::Reached(key) => return Ok(key),
            Walk::Crossed(next) => current = next,
        }
    }
    Err(RegError::Message(format!(
        "{original}: too many registry links to follow"
    )))
}

enum Walk {
    Reached(Opened),
    /// A system link was crossed; continue from this path.
    Crossed(String),
}

fn walk(path: &str, access: u32) -> Result<Walk, RegError> {
    let mut parts = path.split('\\');
    let hive_name = parts
        .next()
        .ok_or_else(|| RegError::Message(format!("empty registry path {path}")))?;
    let hive = hive(hive_name)
        .ok_or_else(|| RegError::Message(format!("unknown registry hive in {path}")))?;
    let parts: Vec<&str> = parts.collect();
    let mut current = Opened {
        key: hive,
        close: false,
    };
    for (index, part) in parts.iter().enumerate() {
        let last = index + 1 == parts.len();
        // Every component needs KEY_QUERY_VALUE to read a link's target.
        let want = if last {
            access | KEY_QUERY_VALUE
        } else {
            KEY_QUERY_VALUE | KEY_WOW64_64KEY
        };
        let next = open_child(current.key, part, want).map_err(|fail| fail.into_error(path))?;
        if is_link(next.key)? {
            let target = link_target(next.key)
                .ok_or_else(|| RegError::Message(format!("{path}: unreadable registry link")))?;
            let parent = key_name(current.key).unwrap_or_default();
            let Some(mapped) = system_link_target(&parent, part, &target) else {
                let walked = std::iter::once(hive_name)
                    .chain(parts[..=index].iter().copied())
                    .collect::<Vec<_>>()
                    .join("\\");
                return Err(RegError::Message(format!(
                    "{walked} is a registry link to {target}; links are not followed"
                )));
            };
            let rest = parts[index + 1..].join("\\");
            return Ok(Walk::Crossed(if rest.is_empty() {
                mapped
            } else {
                format!("{mapped}\\{rest}")
            }));
        }
        current = next;
    }
    Ok(Walk::Reached(current))
}

enum OpenFail {
    Missing,
    Code(u32),
}

impl OpenFail {
    fn into_error(self, path: &str) -> RegError {
        match self {
            OpenFail::Missing => RegError::NotFound,
            OpenFail::Code(code) => failure(code, format!("RegOpenKeyExW {path} failed ({code})")),
        }
    }
}

/// Open one child of `parent` without following it if it is a link. A
/// name with an embedded NUL or separator is refused: it would address a
/// different key than the one listed.
fn open_child(parent: HKEY, name: &str, access: u32) -> Result<Opened, OpenFail> {
    if name.is_empty() || name.contains('\0') || name.contains('\\') {
        return Err(OpenFail::Code(ERROR_PATH_NOT_FOUND));
    }
    let tx = TX.with(|cell| cell.get());
    let open = |access: u32| {
        let wide = wide(name);
        let mut opened = ptr::null_mut();
        let rc = unsafe {
            if tx.is_null() {
                RegOpenKeyExW(
                    parent,
                    wide.as_ptr(),
                    REG_OPTION_OPEN_LINK,
                    access,
                    &mut opened,
                )
            } else {
                RegOpenKeyTransactedW(
                    parent,
                    wide.as_ptr(),
                    REG_OPTION_OPEN_LINK,
                    access,
                    &mut opened,
                    tx,
                    ptr::null(),
                )
            }
        };
        if rc == ERROR_SUCCESS && !opened.is_null() {
            Ok(Opened {
                key: opened,
                close: true,
            })
        } else if rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND {
            Err(OpenFail::Missing)
        } else {
            Err(OpenFail::Code(rc))
        }
    };
    match open(access) {
        Err(OpenFail::Code(_)) if access & KEY_WOW64_64KEY != 0 => open(access & !KEY_WOW64_64KEY),
        other => other,
    }
}

/// True when the key itself is a symbolic link, from the kernel's key flags
/// rather than from a value anyone could write.
fn is_link(key: HKEY) -> Result<bool, RegError> {
    let mut info = [0u32; 3];
    let mut got = 0u32;
    let status = unsafe {
        NtQueryKey(
            key as _,
            KeyFlagsInformation,
            info.as_mut_ptr() as *mut _,
            std::mem::size_of_val(&info) as u32,
            &mut got,
        )
    };
    if status < 0 {
        return Err(RegError::Message(format!(
            "could not read registry key flags (NTSTATUS {status:#x})"
        )));
    }
    Ok(info[1] & REG_FLAG_LINK != 0)
}

/// A link key's `SymbolicLinkValue`: a native path such as
/// `\REGISTRY\MACHINE\SYSTEM\ControlSet001`.
fn link_target(key: HKEY) -> Option<String> {
    let name = wide("SymbolicLinkValue");
    let mut buf = vec![0u16; 1024];
    let mut len = (buf.len() * 2) as u32;
    let mut kind = 0u32;
    let rc = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            ptr::null(),
            &mut kind,
            buf.as_mut_ptr() as *mut u8,
            &mut len,
        )
    };
    if rc != ERROR_SUCCESS || kind != REG_LINK || !len.is_multiple_of(2) {
        return None;
    }
    buf.truncate(len as usize / 2);
    while buf.last() == Some(&0) {
        buf.pop();
    }
    String::from_utf16(&buf).ok()
}

/// The kernel's name for an open key, such as `\REGISTRY\USER\S-1-5-21-...`.
fn key_name(key: HKEY) -> Option<String> {
    let mut buf = vec![0u32; 1024];
    let mut got = 0u32;
    let status = unsafe {
        NtQueryKey(
            key as _,
            KeyNameInformation,
            buf.as_mut_ptr() as *mut _,
            (buf.len() * 4) as u32,
            &mut got,
        )
    };
    if status < 0 {
        return None;
    }
    let bytes = buf[0] as usize;
    let units = unsafe { std::slice::from_raw_parts(buf.as_ptr().add(1) as *const u16, bytes / 2) };
    String::from_utf16(units).ok()
}

/// Where a Windows-defined registry link may lead, as a hive path, or `None`
/// for any other link. `parent` is the kernel name of the key holding the
/// link, `name` the link's own name, and `target` its `SymbolicLinkValue`.
/// Each rule pins both where the link sits and exactly where it points:
///
/// - `SYSTEM\CurrentControlSet` -> `SYSTEM\ControlSetNNN`
/// - `SYSTEM\ControlSetNNN\Hardware Profiles\Current` ->
///   `SYSTEM\CurrentControlSet\Hardware Profiles\NNNN`
/// - a user hive's `Software\Classes` -> that same user's `_Classes` hive
/// - `SOFTWARE\WOW6432Node\Classes` -> `SOFTWARE\Classes\Wow6432Node`
/// - a WOW64 shared key, `<root>\WOW6432Node\<rel>` -> `<root>\<rel>`: the
///   same key in the native view, for the machine and user software and
///   classes roots
pub(crate) fn system_link_target(parent: &str, name: &str, target: &str) -> Option<String> {
    let parent = parent.to_ascii_uppercase();
    let name = name.to_ascii_uppercase();
    let upper = target.to_ascii_uppercase();
    if wow64_shared_key(&format!("{parent}\\{name}"), &upper) {
        return hive_path(target);
    }
    let digits = |text: &str, count: usize| {
        text.len() == count && text.bytes().all(|byte| byte.is_ascii_digit())
    };
    let ok = match (parent.as_str(), name.as_str()) {
        ("\\REGISTRY\\MACHINE\\SYSTEM", "CURRENTCONTROLSET") => upper
            .strip_prefix("\\REGISTRY\\MACHINE\\SYSTEM\\CONTROLSET")
            .is_some_and(|rest| digits(rest, 3)),
        (_, "CURRENT") => {
            parent
                .strip_prefix("\\REGISTRY\\MACHINE\\SYSTEM\\CONTROLSET")
                .and_then(|rest| rest.strip_suffix("\\HARDWARE PROFILES"))
                .is_some_and(|set| digits(set, 3))
                && upper
                    .strip_prefix(
                        "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\HARDWARE PROFILES\\",
                    )
                    .is_some_and(|profile| digits(profile, 4))
        }
        (_, "CLASSES") if parent == "\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432NODE" => {
            upper == "\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES\\WOW6432NODE"
        }
        (_, "CLASSES") => parent
            .strip_prefix("\\REGISTRY\\USER\\")
            .and_then(|rest| rest.strip_suffix("\\SOFTWARE"))
            .is_some_and(|sid| {
                sid.starts_with("S-1-")
                    && !sid.contains('\\')
                    && upper == format!("\\REGISTRY\\USER\\{sid}_CLASSES")
            }),
        _ => false,
    };
    if !ok {
        return None;
    }
    hive_path(target)
}

/// True for a WOW64 shared key: a link in the 32-bit view whose target is the
/// very same path in the native view. Both arguments are upper-case.
fn wow64_shared_key(link: &str, target: &str) -> bool {
    const NODE: &str = "\\WOW6432NODE\\";
    let Some(at) = link.find(NODE) else {
        return false;
    };
    let (root, rel) = (&link[..at], &link[at + NODE.len()..]);
    if rel.is_empty() || rel.contains(NODE) {
        return false;
    }
    let user_root = root.strip_prefix("\\REGISTRY\\USER\\").is_some_and(|rest| {
        rest.strip_suffix("\\SOFTWARE")
            .or_else(|| rest.strip_suffix("_CLASSES"))
            .is_some_and(|sid| sid.starts_with("S-1-") && !sid.contains('\\'))
    });
    let machine_root =
        root == "\\REGISTRY\\MACHINE\\SOFTWARE" || root == "\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES";
    (user_root || machine_root) && target == format!("{root}\\{rel}")
}

/// Map a native `\REGISTRY\...` path to a hive path, keeping its spelling.
fn hive_path(target: &str) -> Option<String> {
    let upper = target.to_ascii_uppercase();
    let rest = |prefix: &str| target.get(prefix.len()..).map(str::to_string);
    if upper.starts_with("\\REGISTRY\\MACHINE\\") {
        rest("\\REGISTRY\\MACHINE\\").map(|rest| format!("HKEY_LOCAL_MACHINE\\{rest}"))
    } else if upper.starts_with("\\REGISTRY\\USER\\") {
        rest("\\REGISTRY\\USER\\").map(|rest| format!("HKEY_USERS\\{rest}"))
    } else {
        None
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
        KEY_ALL_ACCESS, KEY_CREATE_LINK, KEY_WOW64_64KEY, KEY_WRITE, REG_DWORD,
        REG_OPTION_CREATE_LINK, REG_OPTION_VOLATILE, REG_SZ, RegCreateKeyExW, RegDeleteKeyExW,
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
    fn live_a_value_named_like_the_marker_is_never_removed() {
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = WindowsRegistry.delete_tree(&self.0);
            }
        }
        let root = Cleanup(format!(
            r"HKCU\Software\HiveMendMarkerTest{}",
            std::process::id()
        ));
        let mut reg = WindowsRegistry;
        reg.set_value(&root.0, "stale", &ValueKind::Dword(1))
            .unwrap();
        let mut tx = WindowsTransaction::begin().unwrap();
        // Another program's value that happens to carry the marker's name,
        // with raw bytes of an unusual type.
        let name = String::from_utf16_lossy(&tx.marker[..tx.marker.len() - 1]);
        let theirs = ValueKind::Other {
            kind: 11,
            bytes: vec![9, 8, 7, 6, 5, 4, 3, 2],
        };
        reg.set_value(&root.0, &name, &theirs).unwrap();
        let touched = tx.touch(&root.0);
        drop(tx);
        let after = reg.values(&root.0).unwrap();
        assert!(touched.is_err(), "the key was not refused");
        assert!(
            after
                .iter()
                .any(|value| value.name == name && value.data == theirs),
            "their value was changed or removed: {after:?}"
        );
    }

    #[test]
    fn live_a_key_created_elsewhere_during_removal_stops_it() {
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = WindowsRegistry.delete_tree(&self.0);
            }
        }
        let root = Cleanup(format!(
            r"HKCU\Software\HiveMendExactTest{}",
            std::process::id()
        ));
        let tree = format!(r"{}\Tree", root.0);
        let mut reg = WindowsRegistry;
        reg.set_value(&format!(r"{tree}\A"), "x", &ValueKind::Dword(1))
            .unwrap();
        let mut tx = WindowsTransaction::begin().unwrap();
        let expected = vec![canonical_path(&tree), canonical_path(&format!(r"{tree}\A"))];
        tx.touch(&tree).unwrap();
        tx.touch(&format!(r"{tree}\A")).unwrap();
        // Created by another program after the tree was recorded.
        reg.set_value(&format!(r"{tree}\Late"), "y", &ValueKind::Dword(2))
            .unwrap();
        let deleted = tx.delete_tree_exact(&tree, &expected);
        let committed = if deleted.is_ok() {
            Box::new(tx).commit()
        } else {
            drop(tx);
            Err(RegError::Message("not deleted".into()))
        };
        let late = reg.values(&format!(r"{tree}\Late"));
        assert!(committed.is_err(), "the removal went through");
        assert!(late.is_ok(), "the late key was removed without a backup");
        assert!(reg.values(&format!(r"{tree}\A")).is_ok(), "rolled back");
    }

    /// Runs only elevated (it skips otherwise).
    #[test]
    fn live_elevated_a_machine_key_users_can_change_is_refused() {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
        use windows_sys::Win32::System::Registry::RegSetKeySecurity;
        if !crate::store::elevated() {
            eprintln!("skipped: needs an elevated test run");
            return;
        }
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = WindowsRegistry.delete_tree(&self.0);
            }
        }
        let root = Cleanup(format!(
            r"HKLM\SOFTWARE\HiveMendTrustTest{}",
            std::process::id()
        ));
        let open_key = format!(r"{}\Open", root.0);
        let closed_key = format!(r"{}\Closed", root.0);
        let mut reg = WindowsRegistry;
        reg.set_value(&open_key, "x", &ValueKind::Dword(1)).unwrap();
        reg.set_value(&closed_key, "x", &ValueKind::Dword(1))
            .unwrap();
        // Users get full control of Open.
        let sddl = wide("D:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KA;;;BU)");
        let mut sd = ptr::null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    ptr::null_mut(),
                )
            },
            0
        );
        let opened = open_with(&open_key, 0x0004_0000).unwrap(); // WRITE_DAC
        let rc = unsafe { RegSetKeySecurity(opened.key, DACL_SECURITY_INFORMATION, sd) };
        unsafe { LocalFree(sd as _) };
        drop(opened);
        assert_eq!(rc, ERROR_SUCCESS);
        let refused = require_trusted_key(&open_key);
        let below = require_trusted_key(&format!(r"{open_key}\NotYet\Deeper"));
        let allowed = require_trusted_key(&closed_key);
        assert!(matches!(refused, Err(RegError::Denied(_))), "{refused:?}");
        assert!(matches!(below, Err(RegError::Denied(_))), "{below:?}");
        assert!(allowed.is_ok(), "{allowed:?}");
        // Keys whose default security lets only SYSTEM and Administrators
        // write are accepted.
        for key in [r"HKLM\SOFTWARE\Classes", r"HKLM\SOFTWARE"] {
            let trusted = require_trusted_key(key);
            assert!(trusted.is_ok(), "{key}: {trusted:?}");
        }
        // Windows' default security on these lets TERMINAL SERVER USER
        // write: refused, and the message says who.
        for key in [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs",
        ] {
            match require_trusted_key(key) {
                Err(RegError::Denied(why)) => {
                    assert!(why.contains("TERMINAL SERVER USER"), "{key}: {why}")
                }
                other => panic!("{key}: {other:?}"),
            }
        }
    }

    #[test]
    fn live_a_transaction_fails_when_a_touched_key_changes_elsewhere() {
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = WindowsRegistry.delete_tree(&self.0);
            }
        }
        let root = Cleanup(format!(
            r"HKCU\Software\HiveMendTxTest{}",
            std::process::id()
        ));
        let child = format!(r"{}\Child", root.0);
        let mut reg = WindowsRegistry;
        reg.set_value(&root.0, "keep", &ValueKind::Dword(1))
            .unwrap();
        reg.set_value(&root.0, "stale", &ValueKind::Dword(1))
            .unwrap();
        reg.set_value(&child, "x", &ValueKind::Dword(1)).unwrap();

        // Changed elsewhere after the touch: the commit fails, nothing applied.
        let mut tx = WindowsTransaction::begin().unwrap();
        tx.touch(&root.0).unwrap();
        reg.set_value(&root.0, "keep", &ValueKind::Dword(2))
            .unwrap();
        let _ = tx.delete_value(&root.0, "stale");
        assert!(Box::new(tx).commit().is_err());
        assert!(
            reg.values(&root.0)
                .unwrap()
                .iter()
                .any(|v| v.name == "stale")
        );

        // Dropped without commit: rolled back.
        let mut tx = WindowsTransaction::begin().unwrap();
        tx.touch(&root.0).unwrap();
        tx.delete_value(&root.0, "stale").unwrap();
        assert!(
            !tx.values(&root.0)
                .unwrap()
                .iter()
                .any(|v| v.name == "stale")
        );
        assert!(
            reg.values(&root.0)
                .unwrap()
                .iter()
                .any(|v| v.name == "stale")
        );
        drop(tx);
        assert!(
            reg.values(&root.0)
                .unwrap()
                .iter()
                .any(|v| v.name == "stale")
        );

        // Untouched by anyone else: a whole subtree goes on commit.
        let mut tx = WindowsTransaction::begin().unwrap();
        tx.touch(&child).unwrap();
        tx.delete_tree(&child).unwrap();
        assert!(
            reg.subkeys(&root.0).unwrap().iter().any(|k| k == "Child"),
            "visible before commit"
        );
        Box::new(tx).commit().unwrap();
        assert!(!reg.subkeys(&root.0).unwrap().iter().any(|k| k == "Child"));
    }

    #[test]
    fn live_restore_writes_in_one_transaction_and_never_through_a_link() {
        use crate::regfile::{RegOp, apply_ops};
        // This test is about links; the trust rule has its own test.
        TRUST_ANYWAY.with(|flag| flag.set(true));
        let keys = LinkedKeys::create_named("Restore");
        let mut reg = WindowsRegistry;
        let restored = keys.path("Restored");
        let ok = vec![
            RegOp::CreateKey(restored.clone()),
            RegOp::SetValue {
                key: restored.clone(),
                name: "x".into(),
                data: ValueKind::Dword(7),
            },
        ];
        apply_ops(&mut reg, &ok).expect("plain restore");
        assert!(
            reg.values(&restored)
                .unwrap()
                .iter()
                .any(|v| v.name == "x" && v.data == ValueKind::Dword(7))
        );
        // Through the link: refused, and the first write of the same
        // restore is rolled back with it.
        let through = vec![
            RegOp::SetValue {
                key: restored.clone(),
                name: "y".into(),
                data: ValueKind::Dword(8),
            },
            RegOp::SetValue {
                key: keys.path(r"Holder\Link"),
                name: "planted".into(),
                data: ValueKind::Dword(1),
            },
        ];
        assert!(apply_ops(&mut reg, &through).is_err());
        let target = reg.values(&keys.path("Target")).unwrap();
        assert!(
            !target.iter().any(|v| v.name == "planted"),
            "written through a link"
        );
        assert!(
            !reg.values(&restored).unwrap().iter().any(|v| v.name == "y"),
            "a failed restore left part of itself"
        );
    }

    #[test]
    fn live_set_value_creates_missing_parent_keys() {
        // A fresh profile has no StartupApproved key yet; writing a flag
        // there must create every missing level, not fail with not found.
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = WindowsRegistry.delete_tree(&self.0);
            }
        }
        // Its own root: the other live tests share TestKey's.
        let root = Cleanup(format!(
            r"HKCU\Software\HiveMendCreateTest{}",
            std::process::id()
        ));
        let mut reg = WindowsRegistry;
        assert!(matches!(reg.values(&root.0), Err(RegError::NotFound)));
        let deep = format!(r"{}\New\Deeper\Leaf", root.0);
        assert!(matches!(reg.values(&deep), Err(RegError::NotFound)));
        let data = ValueKind::Binary(vec![3, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
        reg.set_value(&deep, "Flag", &data)
            .expect("write through new keys");
        let values = reg.values(&deep).expect("read new key");
        assert!(
            values
                .iter()
                .any(|value| value.name == "Flag" && value.data == data)
        );
        // Writing again replaces the value in the key that now exists.
        reg.set_value(&deep, "Flag", &ValueKind::Dword(2))
            .expect("rewrite");
        let values = reg.values(&deep).expect("re-read new key");
        assert!(
            values
                .iter()
                .any(|value| value.name == "Flag" && value.data == ValueKind::Dword(2))
        );
    }

    #[test]
    fn live_missing_key_reads_fail_cleanly() {
        let reg = WindowsRegistry;
        assert!(reg.subkeys(r"HKCU\Software\HiveMendNoSuchKey").is_err());
        assert!(reg.values(r"HKCU\Software\HiveMendNoSuchKey").is_err());
    }

    #[test]
    fn only_windows_defined_links_with_their_own_targets_are_crossed() {
        let sid = "S-1-5-21-1-2-3-1001";
        let user_software = format!(r"\REGISTRY\USER\{sid}\Software");
        assert_eq!(
            system_link_target(
                r"\REGISTRY\MACHINE\SYSTEM",
                "CurrentControlSet",
                r"\Registry\Machine\SYSTEM\ControlSet001"
            )
            .as_deref(),
            Some(r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001")
        );
        assert_eq!(
            system_link_target(
                r"\REGISTRY\MACHINE\SYSTEM\ControlSet002\Hardware Profiles",
                "Current",
                r"\Registry\Machine\SYSTEM\CurrentControlSet\Hardware Profiles\0001"
            )
            .as_deref(),
            Some(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Hardware Profiles\0001")
        );
        assert_eq!(
            system_link_target(
                &user_software,
                "Classes",
                &format!(r"\Registry\User\{sid}_Classes")
            ),
            Some(format!(r"HKEY_USERS\{sid}_Classes"))
        );
        assert_eq!(
            system_link_target(
                r"\REGISTRY\MACHINE\SOFTWARE\WOW6432Node",
                "Classes",
                r"\REGISTRY\MACHINE\SOFTWARE\Classes\Wow6432Node"
            )
            .as_deref(),
            Some(r"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Wow6432Node")
        );
        // Right place, wrong target; or a target that only looks right.
        for (parent, name, target) in [
            (
                r"\REGISTRY\MACHINE\SYSTEM",
                "CurrentControlSet",
                r"\REGISTRY\MACHINE\SOFTWARE",
            ),
            (
                r"\REGISTRY\MACHINE\SYSTEM",
                "CurrentControlSet",
                r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services",
            ),
            (
                r"\REGISTRY\MACHINE\SYSTEM",
                "CurrentControlSet",
                r"\REGISTRY\MACHINE\SYSTEM\ControlSet01",
            ),
            (
                user_software.as_str(),
                "Classes",
                r"\REGISTRY\USER\S-1-5-18_Classes",
            ),
            (
                user_software.as_str(),
                "Classes",
                r"\REGISTRY\MACHINE\SOFTWARE\Classes",
            ),
        ] {
            assert!(
                system_link_target(parent, name, target).is_none(),
                "{parent}\\{name} -> {target}"
            );
        }
        // WOW64 shared keys: the 32-bit view links to the same native path.
        assert_eq!(
            system_link_target(
                r"\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion",
                "App Paths",
                r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
            )
            .as_deref(),
            Some(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths")
        );
        assert!(
            system_link_target(
                r"\REGISTRY\MACHINE\SOFTWARE\Classes\Wow6432Node",
                "TypeLib",
                r"\REGISTRY\MACHINE\SOFTWARE\Classes\TypeLib"
            )
            .is_some()
        );
        for (parent, name, target) in [
            // Shared-key shape, but pointing somewhere else.
            (
                r"\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion",
                "App Paths",
                r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services",
            ),
            (
                r"\REGISTRY\MACHINE\SOFTWARE\WOW6432Node",
                "Vendor",
                r"\REGISTRY\MACHINE\SOFTWARE\Other",
            ),
            // A Wow6432Node segment under some other root.
            (
                r"\REGISTRY\MACHINE\SYSTEM\Wow6432Node",
                "Services",
                r"\REGISTRY\MACHINE\SYSTEM\Services",
            ),
        ] {
            assert!(
                system_link_target(parent, name, target).is_none(),
                "{parent}\\{name} -> {target}"
            );
        }
        // A link anywhere else is never crossed, whatever it points at.
        assert!(
            system_link_target(
                &format!(r"\REGISTRY\USER\{sid}\Software\Vendor"),
                "CurrentControlSet",
                r"\REGISTRY\MACHINE\SYSTEM\ControlSet001"
            )
            .is_none()
        );
    }

    #[test]
    fn live_reads_cross_the_windows_defined_links() {
        let reg = WindowsRegistry;
        let services = reg
            .subkeys(r"HKLM\SYSTEM\CurrentControlSet\Services")
            .expect("CurrentControlSet link is crossed");
        assert!(
            services
                .iter()
                .any(|name| name.eq_ignore_ascii_case("RpcSs"))
        );
        reg.subkeys(r"HKCU\Software\Classes")
            .expect("per-user Classes link is crossed");
        reg.subkeys(r"HKLM\SOFTWARE\WOW6432Node\Classes")
            .expect("WOW6432Node Classes link is crossed");
        reg.values(r"HKCR\.txt").expect("merged classes view opens");
    }

    #[test]
    fn live_every_control_set_protects_services_and_session_manager() {
        let reg = WindowsRegistry;
        let mut sets: Vec<String> = reg
            .subkeys(r"HKLM\SYSTEM")
            .expect("list SYSTEM")
            .into_iter()
            .filter(|name| {
                name.len() == 13
                    && name[..10].eq_ignore_ascii_case("ControlSet")
                    && name[10..].bytes().all(|byte| byte.is_ascii_digit())
            })
            .collect();
        assert!(!sets.is_empty(), "no numbered control sets found");
        // The live CurrentControlSet link resolves to one of them.
        let current = open_child(
            HKEY_LOCAL_MACHINE,
            "SYSTEM",
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
        )
        .ok()
        .and_then(|system| open_child(system.key, "CurrentControlSet", KEY_QUERY_VALUE).ok())
        .expect("open CurrentControlSet as a link");
        assert!(is_link(current.key).unwrap());
        let target = link_target(current.key).expect("link target");
        let mapped = system_link_target(r"\REGISTRY\MACHINE\SYSTEM", "CurrentControlSet", &target)
            .expect("live target is accepted");
        assert!(
            sets.iter().any(
                |set| mapped.eq_ignore_ascii_case(&format!(r"HKEY_LOCAL_MACHINE\SYSTEM\{set}"))
            ),
            "{mapped} not among {sets:?}"
        );
        sets.push("CurrentControlSet".into());
        for set in &sets {
            for key in [
                format!(r"HKLM\SYSTEM\{set}\Services\RpcSs"),
                format!(r"HKLM\SYSTEM\{set}\Services\RpcSs\Parameters"),
                format!(r"HKLM\SYSTEM\{set}\Control\Session Manager"),
                format!(r"HKLM\SYSTEM\{set}\Control\SafeBoot\Minimal"),
            ] {
                assert!(crate::pathutil::is_protected_key(&key), "{key}");
                assert!(!crate::pathutil::key_delete_allowed(&key), "{key}");
            }
        }
    }

    /// A throwaway HKCU tree holding `Target` (with a value) and `Link`, a
    /// registry symbolic link to it. Drop removes the link itself first,
    /// through a no-follow handle, then the tree.
    struct LinkedKeys {
        root: String,
    }

    impl LinkedKeys {
        fn create() -> Self {
            Self::create_named("")
        }

        fn create_named(tag: &str) -> Self {
            let root = format!(r"HKCU\Software\HiveMendLinkTest{tag}{}", std::process::id());
            let subkey = root.strip_prefix("HKCU\\").unwrap().to_string();
            // The guard exists before any setup step can fail, so a failed
            // assert still cleans up.
            let keys = Self { root };
            let create = |path: &str, options: u32, access: u32| unsafe {
                let mut key: HKEY = ptr::null_mut();
                let rc = RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    wide(path).as_ptr(),
                    0,
                    ptr::null(),
                    options,
                    access | KEY_WOW64_64KEY,
                    ptr::null(),
                    &mut key,
                    ptr::null_mut(),
                );
                assert_eq!(rc, ERROR_SUCCESS, "creating {path} failed");
                Opened { key, close: true }
            };
            let target = create(&format!(r"{subkey}\Target"), 0, KEY_WRITE | KEY_QUERY_VALUE);
            let text: Vec<u16> = wide("keep me");
            unsafe {
                RegSetValueExW(
                    target.key,
                    wide("Keep").as_ptr(),
                    0,
                    REG_SZ,
                    text.as_ptr() as *const u8,
                    (text.len() * 2) as u32,
                );
            }
            let native = key_name(target.key).expect("target kernel name");
            drop(create(&format!(r"{subkey}\Holder"), 0, KEY_WRITE));
            let link = create(
                &format!(r"{subkey}\Holder\Link"),
                REG_OPTION_CREATE_LINK | REG_OPTION_VOLATILE,
                KEY_ALL_ACCESS | KEY_CREATE_LINK,
            );
            let units: Vec<u16> = native.encode_utf16().collect();
            let rc = unsafe {
                RegSetValueExW(
                    link.key,
                    wide("SymbolicLinkValue").as_ptr(),
                    0,
                    REG_LINK,
                    units.as_ptr() as *const u8,
                    (units.len() * 2) as u32,
                )
            };
            assert_eq!(rc, ERROR_SUCCESS, "link target setup failed");
            keys
        }

        fn path(&self, rest: &str) -> String {
            format!(r"{}\{rest}", self.root)
        }
    }

    impl Drop for LinkedKeys {
        fn drop(&mut self) {
            let subkey = self.root.strip_prefix("HKCU\\").unwrap().to_string();
            // Walk to Holder one component at a time, then delete Link itself
            // through a no-follow handle so its target is untouched.
            let mut parent = Opened {
                key: HKEY_CURRENT_USER,
                close: false,
            };
            for part in subkey.split('\\').chain(["Holder"]) {
                match open_child(parent.key, part, KEY_READ) {
                    Ok(next) => parent = next,
                    Err(_) => break,
                }
            }
            if let Ok(link) = open_child(parent.key, "Link", DELETE_ACCESS | KEY_READ) {
                unsafe { NtDeleteKey(link.key as _) };
            }
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
    fn live_a_planted_link_is_never_followed_or_deleted_through() {
        let keys = LinkedKeys::create();
        let mut reg = WindowsRegistry;
        let link = keys.path(r"Holder\Link");
        // Reads through the link are refused, not redirected.
        let err = reg.values(&link).unwrap_err();
        assert!(
            matches!(&err, RegError::Message(msg) if msg.contains("registry link")),
            "{err:?}"
        );
        // A value delete through it is refused and the target keeps its value.
        assert!(reg.delete_value(&link, "Keep").is_err());
        // Deleting the link, or a tree holding it, is refused before anything
        // is removed: RegDeleteTreeW would have emptied the target instead.
        assert!(reg.delete_tree(&link).is_err());
        assert!(reg.delete_tree(&keys.path("Holder")).is_err());
        let kept = reg
            .values(&keys.path("Target"))
            .expect("target still readable");
        assert!(
            kept.iter()
                .any(|value| value.name == "Keep" && value.data == ValueKind::Sz("keep me".into()))
        );
        assert!(
            reg.subkeys(&keys.path("Holder"))
                .unwrap()
                .contains(&"Link".to_string())
        );
    }
}
