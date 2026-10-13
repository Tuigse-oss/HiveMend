mod backup;
mod demo;
mod engine;
mod exclude;
mod fs;
mod ignore;
mod lnk;
mod model;
mod pathutil;
mod registry;
mod rules;
mod scanners;
mod settings;
mod sysinfo;
mod tools;

#[cfg(windows)]
mod windows_reg;

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
pub use fs::{HostFs, MemoryFs};
pub use model::{Error, Finding, Repair, ScanOptions, ScannerId};
pub use registry::MemoryRegistry;
pub use sysinfo::{SystemSnapshot, format_bytes, format_uptime, percent};
#[cfg(windows)]
pub use sysinfo::gather as gather_snapshot;
pub use tools::{WINDOWS_TOOLS, WindowsTool, expand_target, is_openable};

#[cfg(windows)]
pub use windows_reg::WindowsRegistry;

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
