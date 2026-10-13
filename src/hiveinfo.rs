//! Read-only registry-hive inventory.
//!
//! Offline compaction (save each hive, swap at reboot) is deliberately
//! not offered: everything written between the save and the reboot would
//! be silently discarded, and a failed swap leaves the machine
//! unbootable. This module only lists which hives back which keys and
//! how big their files are. Parsing stays platform-free so the unit
//! tests run anywhere; only `gather_hives` touches Windows.

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HiveEntry {
    /// e.g. `HKEY_LOCAL_MACHINE\SOFTWARE`.
    pub key: String,
    /// e.g. `C:\Windows\System32\config\SOFTWARE`. Empty when unknown.
    pub file: String,
    /// File size. `None` when the file could not be statted.
    pub bytes: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct HiveInventory {
    pub entries: Vec<HiveEntry>,
}

impl HiveInventory {
    /// Combined size of the entries whose size is known.
    pub fn total_bytes(&self) -> u64 {
        self.entries.iter().filter_map(|entry| entry.bytes).sum()
    }
}

/// A `hivelist` value name (`\REGISTRY\MACHINE\SOFTWARE`) becomes the key
/// it backs (`HKEY_LOCAL_MACHINE\SOFTWARE`). Anything outside the machine
/// and user hives is rejected.
pub fn hivelist_key(name: &str) -> Option<String> {
    let rest = name
        .strip_prefix("\\REGISTRY\\")
        .or_else(|| name.strip_prefix("\\registry\\"))?;
    if rest.is_empty() {
        return None;
    }
    let (root, tail) = match rest.split_once('\\') {
        Some((root, tail)) if !tail.is_empty() => (root, tail),
        _ => return None,
    };
    if root.eq_ignore_ascii_case("MACHINE") {
        Some(format!("HKEY_LOCAL_MACHINE\\{tail}"))
    } else if root.eq_ignore_ascii_case("USER") {
        Some(format!("HKEY_USERS\\{tail}"))
    } else {
        None
    }
}

/// A `\Device\HarddiskVolumeN\...` path becomes a drive-letter path using
/// a volume-to-drive map. The character after the volume must be a
/// backslash, so `HarddiskVolume1` never matches `HarddiskVolume10`.
pub fn device_path_to_drive(device_path: &str, drives: &[(String, String)]) -> Option<String> {
    for (volume, drive) in drives {
        if let Some(rest) = device_path.strip_prefix(volume.as_str())
            && rest.starts_with('\\')
        {
            return Some(format!("{drive}{rest}"));
        }
    }
    None
}

/// Read the live inventory from `HKLM\...\hivelist`. World-readable; every
/// failure degrades one entry to unknown instead of failing the list.
#[cfg(windows)]
pub fn gather_hives() -> HiveInventory {
    use windows_sys::Win32::Foundation::ERROR_NO_MORE_ITEMS;
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, RegCloseKey, RegEnumValueW, RegOpenKeyExW,
    };

    let mut drives = Vec::new();
    for code in b'A'..=b'Z' {
        let drive = format!("{}:", code as char);
        let name: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
        let mut target = vec![0u16; 256];
        // The target can be a multi-string; the first entry is the volume.
        let chars =
            unsafe { QueryDosDeviceW(name.as_ptr(), target.as_mut_ptr(), target.len() as u32) };
        if chars > 1 {
            let volume = String::from_utf16_lossy(&target[..chars as usize - 1]);
            let volume = volume.split('\0').next().unwrap_or("").to_string();
            if !volume.is_empty() {
                drives.push((volume, drive));
            }
        }
    }

    let mut inventory = HiveInventory::default();
    let subkey: Vec<u16> = r"SYSTEM\CurrentControlSet\Control\hivelist"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut key: HKEY = std::ptr::null_mut();
    if unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut key,
        )
    } != 0
        || key.is_null()
    {
        return inventory;
    }
    let mut index = 0u32;
    loop {
        let mut name = vec![0u16; 512];
        let mut name_len = name.len() as u32;
        let mut data = vec![0u8; 2048];
        let mut data_len = data.len() as u32;
        let rc = unsafe {
            RegEnumValueW(
                key,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                std::ptr::null(),
                std::ptr::null_mut(),
                data.as_mut_ptr(),
                &mut data_len,
            )
        };
        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        index += 1;
        if rc != 0 {
            continue;
        }
        let value_name = String::from_utf16_lossy(&name[..name_len as usize]);
        let Some(hive_key) = hivelist_key(value_name.trim_end_matches('\0')) else {
            continue;
        };
        let units = data_len as usize / 2;
        let device_path = String::from_utf16_lossy(&name_units(&data, units))
            .trim_end_matches('\0')
            .to_string();
        let file = device_path_to_drive(&device_path, &drives).unwrap_or_default();
        let bytes = if file.is_empty() {
            None
        } else {
            std::fs::metadata(&file).ok().map(|meta| meta.len())
        };
        inventory.entries.push(HiveEntry {
            key: hive_key,
            file,
            bytes,
        });
        if index > 512 {
            break;
        }
    }
    unsafe { RegCloseKey(key) };
    inventory
        .entries
        .sort_by(|left, right| left.key.cmp(&right.key));
    inventory
}

/// Reinterpret the first `units` UTF-16 units of a byte buffer.
#[cfg(windows)]
fn name_units(data: &[u8], units: usize) -> Vec<u16> {
    data.chunks_exact(2)
        .take(units)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_and_user_hives_parse() {
        assert_eq!(
            hivelist_key("\\REGISTRY\\MACHINE\\SOFTWARE"),
            Some("HKEY_LOCAL_MACHINE\\SOFTWARE".to_string())
        );
        assert_eq!(
            hivelist_key("\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001"),
            Some("HKEY_USERS\\S-1-5-21-1-2-3-1001".to_string())
        );
        assert_eq!(
            hivelist_key("\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001_CLASSES"),
            Some("HKEY_USERS\\S-1-5-21-1-2-3-1001_CLASSES".to_string())
        );
    }

    #[test]
    fn malformed_hivelist_names_rejected() {
        assert_eq!(hivelist_key(""), None);
        assert_eq!(hivelist_key("\\REGISTRY\\"), None);
        assert_eq!(hivelist_key("\\REGISTRY\\MACHINE"), None);
        assert_eq!(hivelist_key("\\REGISTRY\\MACHINE\\"), None);
        assert_eq!(hivelist_key("\\REGISTRY\\OTHER\\X"), None);
        assert_eq!(hivelist_key("HKEY_LOCAL_MACHINE\\SOFTWARE"), None);
    }

    #[test]
    fn device_paths_translate_by_volume() {
        let drives = vec![
            ("\\Device\\HarddiskVolume4".to_string(), "C:".to_string()),
            ("\\Device\\HarddiskVolume9".to_string(), "D:".to_string()),
        ];
        assert_eq!(
            device_path_to_drive(
                "\\Device\\HarddiskVolume4\\Windows\\System32\\config\\SOFTWARE",
                &drives
            ),
            Some("C:\\Windows\\System32\\config\\SOFTWARE".to_string())
        );
        assert_eq!(
            device_path_to_drive("\\Device\\HarddiskVolume9\\pagefile.sys", &drives),
            Some("D:\\pagefile.sys".to_string())
        );
        assert_eq!(
            device_path_to_drive("\\Device\\HarddiskVolume7\\x", &drives),
            None
        );
        assert_eq!(device_path_to_drive("C:\\Windows", &drives), None);
    }

    #[test]
    fn volume_prefixes_do_not_collide() {
        let drives = vec![("\\Device\\HarddiskVolume1".to_string(), "C:".to_string())];
        assert_eq!(
            device_path_to_drive("\\Device\\HarddiskVolume10\\x", &drives),
            None
        );
        assert_eq!(
            device_path_to_drive("\\Device\\HarddiskVolume1\\x", &drives),
            Some("C:\\x".to_string())
        );
    }

    #[test]
    fn totals_skip_unknown_sizes() {
        let inventory = HiveInventory {
            entries: vec![
                HiveEntry {
                    key: "a".into(),
                    file: "a".into(),
                    bytes: Some(100),
                },
                HiveEntry {
                    key: "b".into(),
                    file: String::new(),
                    bytes: None,
                },
                HiveEntry {
                    key: "c".into(),
                    file: "c".into(),
                    bytes: Some(50),
                },
            ],
        };
        assert_eq!(inventory.total_bytes(), 150);
        assert_eq!(HiveInventory::default().total_bytes(), 0);
    }
}

/// Live Windows test. Read-only hive enumeration.
#[cfg(all(test, windows))]
mod live_tests {
    use super::*;

    #[test]
    fn live_gather_finds_system_hive() {
        let inventory = gather_hives();
        assert!(inventory.entries.len() >= 5, "too few hives");
        let system = inventory
            .entries
            .iter()
            .find(|entry| entry.key == r"HKEY_LOCAL_MACHINE\SYSTEM")
            .expect("SYSTEM hive");
        assert!(!system.file.is_empty());
        assert!(system.bytes.unwrap_or(0) > 0);
        assert!(inventory.total_bytes() > 0);
    }
}
