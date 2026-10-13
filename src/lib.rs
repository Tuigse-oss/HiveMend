mod backup;
mod demo;
mod engine;
mod exclude;
mod fs;
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

pub use backup::{BackupInfo, BackupSummary, backup_name, list_backups, read_backup, restore_files};
#[cfg(windows)]
pub use backup::import_reg_file;
pub use demo::sample_world;
pub use engine::{
    Engine, RepairOutcome, ScanReport, repair, repair_with_progress, scan, scan_with_progress,
    still_reported,
};
pub use exclude::{Exclusion, Exclusions};
pub use settings::Settings;
pub use fs::{FileView, HostFs, ItemKind, MemoryFs};
pub use model::{Error, Finding, Repair, ScanOptions, ScannerId};
pub use privacy::{
    CleanOutcome, DirSpec, ItemOutcome, Preview, PreviewItem, PrivacyGroup, PrivacyItem,
    PrivacyTarget, ProcessList, SystemTargets, ValueMatch, build_items, clean_with_progress,
    mask_matches, parse_custom, preview, privacy_reg_allowed, uninstall_present,
};
pub use pathutil::shred_allowed;
pub use rules::decode_text_owned;
pub use registry::MemoryRegistry;
pub use services::{
    NEVER_TOUCH, SUGGESTED, MemoryServiceStore, ServiceChange, ServiceInfo, ServiceOutcome,
    ServiceState, ServiceStore, StartType, StoreError, TuneupProfile, TuneupTarget,
    apply_start_changes, export_start_backup, is_never_touch, plan_profile, refuse_change,
    refuse_start, refuse_stop, service_key, sort_services, start_services, stop_services,
    tuneup_allowed,
};
pub use shredder::{
    RecycleItem, ShredMethod, ShredOptions, ShredOutcome, ShredTarget, list_recycle_bin,
    random_seed, recycle_display_name, recycle_pairs, seek_penalty_false, shred_paths,
    shred_recycle_items,
};
pub use sysinfo::{SystemSnapshot, format_bytes, format_uptime, percent};
#[cfg(windows)]
pub use sysinfo::gather as gather_snapshot;
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
pub const DATA_DIR: &str = r"C:\RegistryMaster";

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
