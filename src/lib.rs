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
mod windows_shredder;

#[cfg(windows)]
pub use backup::import_reg_file;
pub use backup::{
    BackupInfo, BackupSummary, backup_name, is_hive_mend_backup, list_backups, read_backup,
    reserve_backup_path,
};
pub use demo::sample_world;
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
    ServiceState, ServiceStore, StartType, StoreError, Transition, TuneupProfile, TuneupTarget,
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

#[cfg(windows)]
pub use store::restore_backup;
pub use store::{
    LEGACY_DIR, Store, adopt_legacy_settings, backup_stores, backups_dir, backups_location,
    custom_privacy_file, elevated, exclusions_file, protected_dir, restore_files, settings_file,
    user_dir,
};
