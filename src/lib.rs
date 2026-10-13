mod backup;
mod demo;
mod engine;
mod exclude;
mod fs;
mod hiveinfo;
mod ignore;
mod lnk;
mod model;
mod pathutil;
mod privacy;
mod registry;
mod rules;
mod scanners;
mod services;
mod settings;
mod shredder;
mod sysinfo;
mod tools;

#[cfg(windows)]
mod windows_privacy;
#[cfg(windows)]
mod windows_reg;
#[cfg(windows)]
mod windows_services;
#[cfg(windows)]
mod windows_shredder;

#[cfg(windows)]
pub use backup::import_reg_file;
pub use backup::{
    BackupInfo, BackupSummary, backup_name, list_backups, read_backup, restore_files,
};
pub use demo::sample_world;
pub use engine::{
    Engine, RepairOutcome, ScanReport, repair, repair_with_progress, scan, scan_with_progress,
    still_reported,
};
pub use exclude::{Exclusion, Exclusions};
pub use fs::{FileView, HostFs, ItemKind, MemoryFs};
#[cfg(windows)]
pub use hiveinfo::gather_hives;
pub use hiveinfo::{HiveEntry, HiveInventory, device_path_to_drive, hivelist_key};
pub use model::{Error, Finding, Repair, ScanOptions, ScannerId};
pub use pathutil::shred_allowed;
pub use privacy::{
    CleanOutcome, DirSpec, ItemOutcome, Preview, PreviewItem, PrivacyGroup, PrivacyItem,
    PrivacyTarget, ProcessList, SystemTargets, ValueMatch, build_items, clean_with_progress,
    mask_matches, parse_custom, preview, privacy_reg_allowed, uninstall_present,
};
pub use registry::MemoryRegistry;
pub use rules::decode_text_owned;
pub use services::{
    MemoryServiceStore, NEVER_TOUCH, SUGGESTED, ServiceChange, ServiceInfo, ServiceOutcome,
    ServiceState, ServiceStore, StartType, StoreError, TuneupProfile, TuneupTarget,
    apply_start_changes, export_start_backup, is_never_touch, plan_profile, refuse_change,
    refuse_start, refuse_stop, service_key, sort_services, start_services, stop_services,
    tuneup_allowed,
};
pub use settings::Settings;
pub use shredder::{
    RecycleItem, ShredMethod, ShredOptions, ShredOutcome, ShredTarget, list_recycle_bin,
    random_seed, recycle_display_name, recycle_pairs, seek_penalty_false, shred_paths,
    shred_recycle_items,
};
#[cfg(windows)]
pub use sysinfo::gather as gather_snapshot;
pub use sysinfo::{SystemSnapshot, format_bytes, format_uptime, percent};
pub use tools::{WINDOWS_TOOLS, WindowsTool, expand_target, is_openable};

#[cfg(windows)]
pub use windows_privacy::{WindowsProcessList, WindowsSystemTargets};
#[cfg(windows)]
pub use windows_reg::WindowsRegistry;
#[cfg(windows)]
pub use windows_services::ScmServiceStore;
#[cfg(windows)]
pub use windows_shredder::{fixed_drives, volume_ssd};

/// Where the window and the command line keep backups, settings, and the
/// ignore list.
pub const DATA_DIR: &str = r"C:\HiveMend";

/// Pre-rename data folder, moved aside once by `migrate_data_dir`.
const LEGACY_DATA_DIR: &str = r"C:\RegistryMaster";

/// Move the pre-rename data folder into place. Best-effort: when the new
/// folder already exists, or the move fails, the old folder is left
/// untouched. Nothing is ever deleted.
pub fn migrate_data_dir() {
    if std::path::Path::new(DATA_DIR).exists() {
        return;
    }
    let legacy = std::path::Path::new(LEGACY_DATA_DIR);
    if !legacy.exists() {
        return;
    }
    let _ = std::fs::rename(legacy, DATA_DIR);
}

pub fn backups_dir() -> std::path::PathBuf {
    std::path::Path::new(DATA_DIR).join("backups")
}

pub fn exclusions_file() -> std::path::PathBuf {
    std::path::Path::new(DATA_DIR).join("ignore.txt")
}

pub fn settings_file() -> std::path::PathBuf {
    std::path::Path::new(DATA_DIR).join("settings.ini")
}

pub fn custom_privacy_file() -> std::path::PathBuf {
    std::path::Path::new(DATA_DIR).join("privacy-custom.ini")
}
