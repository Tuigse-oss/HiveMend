//! Read-only PC snapshot for the Monitor page: memory, system-drive
//! space, uptime, and the Windows version. Gathering only reads; the
//! formatting helpers are pure so they are tested on any platform.

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SystemSnapshot {
    pub os: String,
    pub memory_total: u64,
    pub memory_avail: u64,
    pub disk_total: u64,
    pub disk_free: u64,
    pub system_drive: String,
    pub uptime_secs: u64,
}

impl SystemSnapshot {
    pub fn memory_used(&self) -> u64 {
        self.memory_total.saturating_sub(self.memory_avail)
    }

    pub fn memory_used_percent(&self) -> u64 {
        percent(self.memory_used(), self.memory_total)
    }

    pub fn disk_used_percent(&self) -> u64 {
        percent(
            self.disk_total.saturating_sub(self.disk_free),
            self.disk_total,
        )
    }
}

/// Whole percent of `part` over `total`, 0 when the total is unknown.
pub fn percent(part: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    ((part as u128 * 100) / total as u128).min(100) as u64
}

/// `15360` becomes `15.0 MB`; bytes stay bare below one kilobyte.
/// `1234567` as `1,234,567`.
pub fn group_digits(number: u64) -> String {
    let digits = number.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    let rounded = (value * 10.0).round() / 10.0;
    if rounded.fract() == 0.0 {
        format!("{rounded:.0} {}", UNITS[unit])
    } else {
        format!("{rounded:.1} {}", UNITS[unit])
    }
}

/// `90061` becomes `1d 1h`; short uptimes show minutes or seconds.
pub fn format_uptime(secs: u64) -> String {
    const DAY: u64 = 86_400;
    const HOUR: u64 = 3_600;
    const MINUTE: u64 = 60;
    if secs >= DAY {
        format!("{}d {}h", secs / DAY, secs % DAY / HOUR)
    } else if secs >= HOUR {
        format!("{}h {}m", secs / HOUR, secs % HOUR / MINUTE)
    } else if secs >= MINUTE {
        format!("{}m", secs / MINUTE)
    } else {
        format!("{secs}s")
    }
}

/// Read the live snapshot. Only compiled on Windows; every call only reads.
#[cfg(windows)]
pub fn gather() -> SystemSnapshot {
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    use windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;
    use windows_sys::Win32::System::SystemInformation::{
        GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX,
    };

    let mut snapshot = SystemSnapshot::default();

    unsafe {
        let mut memory: MEMORYSTATUSEX = std::mem::zeroed();
        memory.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut memory) != 0 {
            snapshot.memory_total = memory.ullTotalPhys;
            snapshot.memory_avail = memory.ullAvailPhys;
        }
    }

    let system_root = crate::fs::host_known_dir(crate::fs::KnownDir::Windows)
        .unwrap_or_else(|| r"C:\Windows".into());
    let drive = system_root
        .chars()
        .next()
        .map(|letter| format!("{letter}:"))
        .unwrap_or_else(|| "C:".into());
    snapshot.system_drive = drive.clone();
    let root = format!("{drive}\\");

    unsafe {
        let path: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
        let (mut free_to_caller, mut total, mut total_free) = (0u64, 0u64, 0u64);
        if GetDiskFreeSpaceExW(
            path.as_ptr(),
            &mut free_to_caller,
            &mut total,
            &mut total_free,
        ) != 0
        {
            snapshot.disk_total = total;
            snapshot.disk_free = free_to_caller;
        }
    }

    snapshot.uptime_secs = unsafe { GetTickCount64() } / 1000;

    let product = reg_string(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "ProductName",
    );
    let display = reg_string(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "DisplayVersion",
    );
    let build = reg_string(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "CurrentBuild",
    );
    snapshot.os = os_label(product, display, build);

    snapshot
}

/// Build the OS line from the registry values. Windows 11 still reports
/// `ProductName` as "Windows 10", so promote the name when the build number
/// is 22000 or higher; the build itself is the authoritative signal.
#[cfg(any(windows, test))]
fn os_label(product: Option<String>, display: Option<String>, build: Option<String>) -> String {
    let build_num = build
        .as_deref()
        .and_then(|text| text.trim().parse::<u32>().ok());
    let product = product.map(|name| {
        if build_num.is_some_and(|num| num >= 22_000) && name.contains("Windows 10") {
            name.replace("Windows 10", "Windows 11")
        } else {
            name
        }
    });
    match (product, display, build) {
        (Some(product), Some(display), Some(build)) => {
            format!("{product}, version {display} (build {build})")
        }
        (Some(product), _, _) => product,
        _ => "Windows".into(),
    }
}

#[cfg(windows)]
fn reg_string(
    hive: windows_sys::Win32::System::Registry::HKEY,
    key: &str,
    value: &str,
) -> Option<String> {
    use windows_sys::Win32::System::Registry::{RRF_RT_REG_SZ, RegGetValueW};
    let key: Vec<u16> = key.encode_utf16().chain(std::iter::once(0)).collect();
    let value: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let mut bytes = vec![0u16; 256];
    let mut len = (bytes.len() * 2) as u32;
    let rc = unsafe {
        RegGetValueW(
            hive,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            bytes.as_mut_ptr() as *mut _,
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    let units = (len as usize / 2).min(bytes.len());
    let text = String::from_utf16_lossy(&bytes[..units]);
    Some(text.trim_end_matches('\0').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_counts_use_the_largest_sensible_unit() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1024), "1 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024 * 512), "512 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1536), "1.5 GB");
        assert_eq!(format_bytes(1024_u64.pow(4)), "1 TB");
    }

    #[test]
    fn counts_are_grouped_in_thousands() {
        assert_eq!(group_digits(0), "0");
        assert_eq!(group_digits(999), "999");
        assert_eq!(group_digits(1000), "1,000");
        assert_eq!(group_digits(1948380), "1,948,380");
    }

    #[test]
    fn uptimes_shorten_as_they_shrink() {
        assert_eq!(format_uptime(45), "45s");
        assert_eq!(format_uptime(60), "1m");
        assert_eq!(format_uptime(3600 + 120), "1h 2m");
        assert_eq!(format_uptime(86_400 + 3600), "1d 1h");
    }

    #[test]
    fn os_label_promotes_windows_11_by_build() {
        let s = |text: &str| Some(text.to_string());
        // Win11 reports ProductName "Windows 10"; build >= 22000 promotes it.
        assert_eq!(
            os_label(s("Windows 10 Pro"), s("23H2"), s("22631")),
            "Windows 11 Pro, version 23H2 (build 22631)"
        );
        // Genuine Windows 10 is left alone.
        assert_eq!(
            os_label(s("Windows 10 Pro"), s("22H2"), s("19045")),
            "Windows 10 Pro, version 22H2 (build 19045)"
        );
        // A non-numeric or missing build never promotes.
        assert_eq!(
            os_label(s("Windows 10 Home"), s("22H2"), s("nonsense")),
            "Windows 10 Home, version 22H2 (build nonsense)"
        );
        assert_eq!(os_label(s("Windows 10 Pro"), None, None), "Windows 10 Pro");
        assert_eq!(os_label(None, None, None), "Windows");
    }

    #[test]
    fn percents_clamp_and_survive_zero_totals() {
        assert_eq!(percent(1, 0), 0);
        assert_eq!(percent(1, 2), 50);
        assert_eq!(percent(3, 2), 100);
        let snapshot = SystemSnapshot {
            memory_total: 8000,
            memory_avail: 2000,
            disk_total: 100,
            disk_free: 25,
            ..SystemSnapshot::default()
        };
        assert_eq!(snapshot.memory_used(), 6000);
        assert_eq!(snapshot.memory_used_percent(), 75);
        assert_eq!(snapshot.disk_used_percent(), 75);
    }
}

/// Live Windows test. Read-only snapshot; asserts shape, not values.
#[cfg(all(test, windows))]
mod live_tests {
    use super::*;

    #[test]
    fn live_gather_snapshot_sane() {
        let snapshot = gather();
        assert!(!snapshot.os.is_empty());
        assert!(!snapshot.system_drive.is_empty());
        assert!(snapshot.memory_total > 0);
        assert!(snapshot.disk_total > 0);
    }
}
