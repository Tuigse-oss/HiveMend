pub mod art;
mod backup;
mod cookies;
mod demo;
mod diskspace;
mod duplicates;
mod engine;
mod exclude;
mod fs;
mod hiveinfo;
mod ignore;
mod lnk;
mod model;
mod pathutil;
mod privacy;
mod programs;
mod registry;
#[cfg(windows)]
pub mod restorepoint;
mod rules;
mod scanners;
mod services;
mod settings;
mod startup;
mod store;
mod sysinfo;
mod tools;

#[cfg(windows)]
mod windows_privacy;
#[cfg(windows)]
mod windows_reg;
#[cfg(windows)]
mod windows_services;

#[cfg(windows)]
pub use backup::import_reg_file;
pub use backup::{
    BackupInfo, BackupSummary, backup_name, encode_reg, is_hive_mend_backup, list_backups,
    machine_sections_only, read_backup, reserve_backup_path, write_backup,
};
pub use cookies::{CookieCount, count_cookies, keeps, parse_keep_list, trim_cookies};
pub use demo::sample_world;
#[cfg(windows)]
pub use diskspace::HostLister;
pub use diskspace::{
    BigFile, DirLister, DirNode, DiskEntry, DiskReport, FileKind, LARGEST_KEPT, analyze,
};
pub use duplicates::{
    ContentReader, DupGroup, DupReport, FileId, Held, find_duplicates, remove_checked,
};
#[cfg(windows)]
pub use duplicates::{HostContent, recycle};
pub use engine::{
    Engine, RepairOutcome, ScanReport, repair, repair_with_progress, scan, scan_with_progress,
    still_reported,
};
pub use exclude::{Exclusion, Exclusions};
#[cfg(windows)]
pub use fs::host_known_dir;
pub use fs::{FileView, HostFs, ItemKind, KnownDir, MemoryFs};
#[cfg(windows)]
pub use hiveinfo::gather_hives;
pub use hiveinfo::{HiveEntry, HiveInventory, device_path_to_drive, hivelist_key};
pub use model::{Error, Finding, Repair, ScanOptions, ScannerId, ValueKind};
pub use pathutil::{paths_in_command, per_user_key, protected_roots};
pub use privacy::{
    CleanOutcome, CookieKeep, DirSpec, ItemOutcome, Preview, PreviewItem, PrivacyGroup,
    PrivacyItem, PrivacyTarget, ProcessList, SystemTargets, ValueMatch, build_items,
    clean_with_progress, cookie_keep_choice, leave_per_user_registry, mask_matches, parse_custom,
    preview, privacy_reg_allowed, set_cookie_keep, uninstall_present,
};
pub use programs::{InstalledProgram, Launch, ProgramScope, list_programs, uninstall_launch};
pub use registry::{MemoryRegistry, RegTransaction, Registry};
pub use rules::decode_text_owned;
pub use services::{
    MemoryServiceStore, NEVER_TOUCH, SUGGESTED, ServiceChange, ServiceInfo, ServiceOutcome,
    ServiceState, ServiceStore, StartType, StoreError, Transition, TuneupProfile, TuneupTarget,
    apply_start_changes, export_start_backup, is_never_touch, plan_profile, refuse_change,
    refuse_start, refuse_stop, service_key, sort_services, start_services, stop_services,
    tuneup_allowed,
};
pub use settings::Settings;
pub use startup::{
    StartupItem, StartupOutcome, StartupScope, approved_bytes, filetime_now, list_startup,
    set_startup, startup_backup,
};
#[cfg(windows)]
pub use sysinfo::gather as gather_snapshot;
pub use sysinfo::{SystemSnapshot, format_bytes, format_uptime, group_digits, percent};
pub use tools::{WINDOWS_TOOLS, WindowsTool, expand_target, is_openable};

#[cfg(windows)]
pub use windows_privacy::{WindowsProcessList, WindowsSystemTargets};
#[cfg(windows)]
pub use windows_reg::{WindowsRegistry, WindowsTransaction};
#[cfg(windows)]
pub use windows_services::ScmServiceStore;

#[cfg(windows)]
pub use store::restore_backup;
pub use store::{
    LEGACY_DIR, Store, adopt_legacy_settings, backup_stores, backups_dir, backups_location,
    cookies_keep_file, custom_privacy_file, elevated, exclusions_file, protected_dir,
    restore_files, settings_file, user_dir,
};

/// The shipped exe must start on a clean Windows install, which has no
/// Visual C++ runtime. This test binary is built with the same flags as the
/// exe (`.cargo/config.toml`), so its own import table shows whether the C
/// runtime was linked statically.
#[cfg(all(test, windows, target_env = "msvc"))]
mod runtime_tests {
    /// DLL names in a PE file's import table.
    fn imported_dlls(image: &[u8]) -> Vec<String> {
        let u16_at = |at: usize| u16::from_le_bytes([image[at], image[at + 1]]) as usize;
        let u32_at = |at: usize| {
            u32::from_le_bytes([image[at], image[at + 1], image[at + 2], image[at + 3]]) as usize
        };
        let pe = u32_at(0x3c);
        assert_eq!(&image[pe..pe + 4], b"PE\0\0", "not a PE image");
        let coff = pe + 4;
        let sections = u16_at(coff + 2);
        let optional = coff + 20;
        let optional_size = u16_at(coff + 16);
        assert_eq!(u16_at(optional), 0x20b, "expected a PE32+ image");
        // Data directory 1 (imports) of a PE32+ optional header.
        let imports_rva = u32_at(optional + 120);
        let table = optional + optional_size;
        let to_offset = |rva: usize| {
            (0..sections)
                .map(|index| table + index * 40)
                .find_map(|section| {
                    let virtual_address = u32_at(section + 12);
                    let size = u32_at(section + 8).max(u32_at(section + 16));
                    (rva >= virtual_address && rva < virtual_address + size)
                        .then(|| rva - virtual_address + u32_at(section + 20))
                })
                .expect("RVA outside every section")
        };
        let mut names = Vec::new();
        let mut descriptor = to_offset(imports_rva);
        while u32_at(descriptor + 12) != 0 {
            let name = to_offset(u32_at(descriptor + 12));
            let end = image[name..].iter().position(|byte| *byte == 0).unwrap();
            names.push(String::from_utf8_lossy(&image[name..name + end]).to_ascii_lowercase());
            descriptor += 20;
        }
        names
    }

    #[test]
    fn the_c_runtime_is_linked_statically() {
        let exe = std::env::current_exe().unwrap();
        let names = imported_dlls(&std::fs::read(&exe).unwrap());
        assert!(names.iter().any(|name| name == "kernel32.dll"), "{names:?}");
        let runtime: Vec<&String> = names
            .iter()
            .filter(|name| {
                name.starts_with("vcruntime")
                    || name.starts_with("msvcp")
                    || name.starts_with("ucrtbase")
                    || name.starts_with("api-ms-win-crt-")
            })
            .collect();
        assert!(
            runtime.is_empty(),
            "linked against the C runtime DLLs {runtime:?}; a clean Windows install lacks them"
        );
    }
}

#[cfg(test)]
mod notices_tests {
    /// Crates that only run while building; keep in step with
    /// scripts/third-party-notices.py.
    const BUILD_ONLY: &[&str] = &[
        "cc",
        "clap_derive",
        "find-msvc-tools",
        "heck",
        "hive-mend",
        "pkg-config",
        "proc-macro2",
        "quote",
        "shlex",
        "syn",
        "unicode-ident",
        "vcpkg",
    ];

    #[test]
    fn the_notices_cover_every_linked_crate() {
        let lock = include_str!("../Cargo.lock");
        let notices = include_str!("../THIRD-PARTY-NOTICES.txt");
        let mut lines = lock.lines();
        while let Some(line) = lines.next() {
            let Some(name) = line
                .strip_prefix("name = \"")
                .and_then(|rest| rest.strip_suffix('"'))
            else {
                continue;
            };
            let version = lines
                .next()
                .and_then(|line| line.strip_prefix("version = \""))
                .and_then(|rest| rest.strip_suffix('"'))
                .unwrap_or_default();
            if BUILD_ONLY.contains(&name) {
                continue;
            }
            assert!(
                notices.contains(&format!("{name} {version} (license:")),
                "{name} {version} is missing from THIRD-PARTY-NOTICES.txt; run scripts/third-party-notices.py"
            );
        }
        assert!(notices.contains("The Rust Standard Library"));
    }
}
