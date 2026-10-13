//! Windows services: read-only listing plus gated start-type and state
//! changes.
//!
//! Listing never writes. Every change goes through tick, confirm, backup,
//! apply: the old `Start` values are exported to a `.reg` backup first, and
//! anything the backup could not read is left alone. The scan/repair
//! engine never touches service keys; this module is the only pathway.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::backup::{BackupPlan, write_backup};
use crate::model::Error;
use crate::registry::{RegError, Registry};

/// How Windows starts a service. `AutomaticDelayed` is `Start=2` plus the
/// `DelayedAutostart` flag; changing it to anything else drops the delay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartType {
    Boot,
    System,
    Automatic,
    AutomaticDelayed,
    Manual,
    Disabled,
}

impl StartType {
    /// `delayed` is the `DelayedAutostart` flag, which only matters for
    /// `Start=2`. Unknown `Start` values are rejected, never guessed.
    pub fn from_dword(start: u32, delayed: bool) -> Option<Self> {
        match start {
            0 => Some(Self::Boot),
            1 => Some(Self::System),
            2 if delayed => Some(Self::AutomaticDelayed),
            2 => Some(Self::Automatic),
            3 => Some(Self::Manual),
            4 => Some(Self::Disabled),
            _ => None,
        }
    }

    pub fn dword(self) -> u32 {
        match self {
            Self::Boot => 0,
            Self::System => 1,
            Self::Automatic | Self::AutomaticDelayed => 2,
            Self::Manual => 3,
            Self::Disabled => 4,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Boot => "Boot",
            Self::System => "System",
            Self::Automatic => "Automatic",
            Self::AutomaticDelayed => "Automatic (Delayed)",
            Self::Manual => "Manual",
            Self::Disabled => "Disabled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState {
    Running,
    Stopped,
    Paused,
    /// Start-pending, stop-pending, and anything else.
    Other,
}

impl ServiceState {
    pub fn from_dword(state: u32) -> Self {
        match state {
            1 => Self::Stopped,
            4 => Self::Running,
            7 => Self::Paused,
            _ => Self::Other,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Running => "Running",
            Self::Stopped => "Stopped",
            Self::Paused => "Paused",
            Self::Other => "Changing",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceInfo {
    /// Short name, as in `sc.exe` and the `Services` key.
    pub name: String,
    pub display_name: String,
    pub start: StartType,
    pub state: ServiceState,
}

/// A backend failure. `denied` means Windows refused for lack of rights,
/// usually an unelevated process changing a service.
#[derive(Clone, Debug)]
pub struct StoreError {
    pub message: String,
    pub denied: bool,
}

impl StoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            denied: false,
        }
    }

    pub fn denied(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            denied: true,
        }
    }
}

impl From<StoreError> for Error {
    fn from(value: StoreError) -> Self {
        Self(value.message)
    }
}

pub trait ServiceStore {
    fn list(&self) -> Result<Vec<ServiceInfo>, Error>;
    fn set_start(&mut self, name: &str, to: StartType) -> Result<(), StoreError>;
    /// `Ok(true)` when the state changed, `Ok(false)` when it already had it.
    fn start(&mut self, name: &str) -> Result<bool, StoreError>;
    fn stop(&mut self, name: &str) -> Result<bool, StoreError>;
}

/// In-memory store for tests. Pure plumbing; the refusal rules live in
/// the apply layer so every backend inherits them.
#[derive(Clone, Debug, Default)]
pub struct MemoryServiceStore {
    services: BTreeMap<String, ServiceInfo>,
}

impl MemoryServiceStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, info: ServiceInfo) {
        self.services.insert(info.name.to_ascii_lowercase(), info);
    }

    #[cfg(test)]
    fn find(&self, name: &str) -> Option<&ServiceInfo> {
        self.services.get(&name.to_ascii_lowercase())
    }

    fn find_mut(&mut self, name: &str) -> Option<&mut ServiceInfo> {
        self.services.get_mut(&name.to_ascii_lowercase())
    }
}

impl ServiceStore for MemoryServiceStore {
    fn list(&self) -> Result<Vec<ServiceInfo>, Error> {
        Ok(self.services.values().cloned().collect())
    }

    fn set_start(&mut self, name: &str, to: StartType) -> Result<(), StoreError> {
        match self.find_mut(name) {
            Some(info) => {
                info.start = to;
                Ok(())
            }
            None => Err(StoreError::new(format!("{name}: no such service"))),
        }
    }

    fn start(&mut self, name: &str) -> Result<bool, StoreError> {
        match self.find_mut(name) {
            None => Err(StoreError::new(format!("{name}: no such service"))),
            Some(info) if info.start == StartType::Disabled => {
                Err(StoreError::new("cannot start a disabled service"))
            }
            Some(info) if info.state == ServiceState::Running => Ok(false),
            Some(info) => {
                info.state = ServiceState::Running;
                Ok(true)
            }
        }
    }

    fn stop(&mut self, name: &str) -> Result<bool, StoreError> {
        match self.find_mut(name) {
            None => Err(StoreError::new(format!("{name}: no such service"))),
            Some(info) if info.state == ServiceState::Stopped => Ok(false),
            Some(info) => {
                info.state = ServiceState::Stopped;
                Ok(true)
            }
        }
    }
}

/// Services Hive Mend refuses to change or stop: the RPC and logon
/// core, the security and update stack, and session basics. Starting one
/// is transient and stays allowed.
pub const NEVER_TOUCH: &[&str] = &[
    "RpcSs",
    "DcomLaunch",
    "RpcEptMapper",
    "WinDefend",
    "WdNisSvc",
    "Sense",
    "MpsSvc",
    "wuauserv",
    "BITS",
    "WaaSMedicSvc",
    "TrustedInstaller",
    "CryptSvc",
    "SamSs",
    "EventLog",
    "PlugPlay",
    "Power",
    "ProfSvc",
    "Schedule",
];

pub fn is_never_touch(name: &str) -> bool {
    NEVER_TOUCH
        .iter()
        .any(|protected| protected.eq_ignore_ascii_case(name))
}

/// Why a start-type change must not happen, if it must not.
pub fn refuse_change(info: &ServiceInfo) -> Option<String> {
    match info.start {
        StartType::Boot | StartType::System => {
            Some("it is a boot driver and cannot be changed here".into())
        }
        _ if is_never_touch(&info.name) => Some(format!(
            "{} is protected because Windows needs it to boot, update, or stay secure",
            info.display_name
        )),
        _ => None,
    }
}

/// Stopping is refused for boot drivers and protected services. Stopping
/// the wrong one crashes Windows on the spot, so this list is absolute.
pub fn refuse_stop(info: &ServiceInfo) -> Option<String> {
    match info.start {
        StartType::Boot | StartType::System => {
            Some("it is a boot driver and cannot be stopped here".into())
        }
        _ if is_never_touch(&info.name) => Some(format!(
            "stopping {} would destabilize Windows",
            info.display_name
        )),
        _ => None,
    }
}

/// Starting is transient, so only boot drivers are refused.
pub fn refuse_start(info: &ServiceInfo) -> Option<String> {
    match info.start {
        StartType::Boot | StartType::System => {
            Some("it is a boot driver and cannot be started here".into())
        }
        _ => None,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TuneupTarget {
    pub name: &'static str,
    pub to: StartType,
    pub why: &'static str,
}

#[derive(Clone, Copy, Debug)]
pub struct TuneupProfile {
    pub id: &'static str,
    pub name: &'static str,
    pub blurb: &'static str,
    pub targets: &'static [TuneupTarget],
}

/// The built-in suggestion set: services that are safe to start on demand
/// instead of at boot. Every row still needs its own tick, and rows that
/// are absent, already Manual, or protected are skipped, never forced.
pub const SUGGESTED: TuneupProfile = TuneupProfile {
    id: "suggested",
    name: "Suggested Manual starts",
    blurb: "A short list of services that are safe to start on demand. Every row applies only if ticked.",
    targets: &[
        TuneupTarget {
            name: "DiagTrack",
            to: StartType::Manual,
            why: "Usage telemetry only; safe to start on demand.",
        },
        TuneupTarget {
            name: "TrkWks",
            to: StartType::Manual,
            why: "Link tracking; starts on demand when needed.",
        },
        TuneupTarget {
            name: "SysMain",
            to: StartType::Manual,
            why: "App pre-launch cache; safe to start on demand.",
        },
        TuneupTarget {
            name: "Fax",
            to: StartType::Manual,
            why: "Fax sharing; unused on nearly all modern PCs.",
        },
        TuneupTarget {
            name: "WMPNetworkSvc",
            to: StartType::Manual,
            why: "Media library sharing; only needed for streaming.",
        },
    ],
};

/// Suggestions only ever tighten Automatic starts to Manual. Anything
/// else (Disabled loosening, protected names) is rejected.
pub fn tuneup_allowed(name: &str, from: StartType, to: StartType) -> bool {
    to == StartType::Manual
        && matches!(from, StartType::Automatic | StartType::AutomaticDelayed)
        && !is_never_touch(name)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceChange {
    pub name: String,
    pub display_name: String,
    pub from: StartType,
    pub to: StartType,
    pub why: String,
}

/// Turn a profile into concrete rows against the listed services. Absent
/// services, protected names, boot drivers, loosening moves, and rows
/// that already match are skipped.
pub fn plan_profile(profile: &TuneupProfile, current: &[ServiceInfo]) -> Vec<ServiceChange> {
    let mut changes = Vec::new();
    for target in profile.targets {
        let Some(info) = current
            .iter()
            .find(|info| info.name.eq_ignore_ascii_case(target.name))
        else {
            continue;
        };
        if info.start == target.to {
            continue;
        }
        if !tuneup_allowed(&info.name, info.start, target.to) {
            continue;
        }
        changes.push(ServiceChange {
            name: info.name.clone(),
            display_name: info.display_name.clone(),
            from: info.start,
            to: target.to,
            why: target.why.to_string(),
        });
    }
    changes
}

/// Registry key holding a service's `Start` value.
pub fn service_key(name: &str) -> String {
    format!(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{name}")
}

/// Export the current `Start` (and `DelayedAutostart`, when present) values
/// so the Restore page can put them back. Services that cannot be read are
/// reported in `unreadable` and must be left alone.
pub fn export_start_backup(reg: &dyn Registry, names: &[String]) -> BackupPlan {
    let mut body = String::from("Windows Registry Editor Version 5.00\r\n\r\n");
    body.push_str("; Hive Mend services backup.\r\n");
    body.push_str("; Restore it from the Restore page in Hive Mend.\r\n");
    let mut unreadable = Vec::new();
    for name in names {
        let key = service_key(name);
        match reg.values(&key) {
            Ok(present) => {
                let start = present
                    .iter()
                    .find(|value| value.name.eq_ignore_ascii_case("Start"));
                let delayed = present
                    .iter()
                    .find(|value| value.name.eq_ignore_ascii_case("DelayedAutostart"));
                match start {
                    Some(value) => match &value.data {
                        crate::model::ValueKind::Dword(data) => {
                            body.push_str(&format!("\r\n[{key}]\r\n"));
                            body.push_str(&format!("\"Start\"=dword:{data:08x}\r\n"));
                            if let Some(delayed) = delayed {
                                match &delayed.data {
                                    crate::model::ValueKind::Dword(data) => {
                                        body.push_str(&format!(
                                            "\"DelayedAutostart\"=dword:{data:08x}\r\n"
                                        ));
                                    }
                                    _ => {
                                        body.push_str(&format!(
                                            "\r\n; not backed up, left alone: {key}: DelayedAutostart is not a DWORD\r\n"
                                        ));
                                        unreadable.push(key);
                                    }
                                }
                            }
                        }
                        _ => {
                            body.push_str(&format!(
                                "\r\n; not backed up, left alone: {key}: Start is not a DWORD\r\n"
                            ));
                            unreadable.push(key);
                        }
                    },
                    None => {
                        body.push_str(&format!(
                            "\r\n; not backed up, left alone: {key}: no Start value\r\n"
                        ));
                        unreadable.push(key);
                    }
                }
            }
            Err(RegError::NotFound) => {
                body.push_str(&format!("\r\n; no such service key, left alone: {key}\r\n"));
                unreadable.push(key);
            }
            Err(err) => {
                body.push_str(&format!(
                    "\r\n; not backed up, left alone: {key}: {err}\r\n"
                ));
                unreadable.push(key);
            }
        }
    }
    BackupPlan {
        body,
        unreadable,
        file_copies: Vec::new(),
    }
}

#[derive(Debug, Default)]
pub struct ServiceOutcome {
    pub backup_file: PathBuf,
    /// Human-readable applied rows, such as `Print Spooler: Automatic -> Manual`.
    pub applied: Vec<String>,
    pub already_correct: usize,
    /// `Name: reason` for refused rows.
    pub refused: Vec<String>,
    /// Service names the backup could not read, left alone.
    pub not_backed_up: Vec<String>,
    pub denied: usize,
    pub errors: Vec<String>,
}

/// Write the backup, then apply each start-type change the backup covers.
/// `progress(done, total)` runs after each change.
pub fn apply_start_changes(
    store: &mut dyn ServiceStore,
    reg: &dyn Registry,
    changes: &[ServiceChange],
    backup_file: &Path,
    progress: &mut dyn FnMut(usize, usize),
) -> Result<ServiceOutcome, Error> {
    let names: Vec<String> = changes.iter().map(|change| change.name.clone()).collect();
    let plan = export_start_backup(reg, &names);
    write_backup(backup_file, &plan.body)?;
    let mut outcome = ServiceOutcome {
        backup_file: backup_file.to_path_buf(),
        ..ServiceOutcome::default()
    };
    let current = store.list()?;
    for (index, change) in changes.iter().enumerate() {
        let key = service_key(&change.name);
        if !plan.covers(&key) {
            outcome.not_backed_up.push(change.name.clone());
            progress(index + 1, changes.len());
            continue;
        }
        let Some(info) = current
            .iter()
            .find(|info| info.name.eq_ignore_ascii_case(&change.name))
        else {
            outcome
                .errors
                .push(format!("{}: no longer listed", change.name));
            progress(index + 1, changes.len());
            continue;
        };
        if matches!(change.to, StartType::Boot | StartType::System) {
            outcome.refused.push(format!(
                "{}: Hive Mend never sets a Boot or System start",
                info.name
            ));
            progress(index + 1, changes.len());
            continue;
        }
        if let Some(reason) = refuse_change(info) {
            outcome.refused.push(format!("{}: {reason}", info.name));
            progress(index + 1, changes.len());
            continue;
        }
        if info.start == change.to {
            outcome.already_correct += 1;
            progress(index + 1, changes.len());
            continue;
        }
        match store.set_start(&info.name, change.to) {
            Ok(()) => outcome.applied.push(format!(
                "{}: {} -> {}",
                info.display_name,
                info.start.label(),
                change.to.label()
            )),
            Err(err) => {
                if err.denied {
                    outcome.denied += 1;
                }
                outcome
                    .errors
                    .push(format!("{}: {}", info.name, err.message));
            }
        }
        progress(index + 1, changes.len());
    }
    Ok(outcome)
}

/// Start each named service. No backup: starting is transient.
pub fn start_services(
    store: &mut dyn ServiceStore,
    names: &[String],
    progress: &mut dyn FnMut(usize, usize),
) -> ServiceOutcome {
    let mut outcome = ServiceOutcome::default();
    let current = match store.list() {
        Ok(current) => current,
        Err(err) => {
            outcome.errors.push(err.0);
            return outcome;
        }
    };
    for (index, name) in names.iter().enumerate() {
        let Some(info) = current
            .iter()
            .find(|info| info.name.eq_ignore_ascii_case(name))
        else {
            outcome.errors.push(format!("{name}: no longer listed"));
            progress(index + 1, names.len());
            continue;
        };
        if let Some(reason) = refuse_start(info) {
            outcome.refused.push(format!("{}: {reason}", info.name));
            progress(index + 1, names.len());
            continue;
        }
        if info.state == ServiceState::Running {
            outcome.already_correct += 1;
            progress(index + 1, names.len());
            continue;
        }
        match store.start(&info.name) {
            Ok(true) => outcome
                .applied
                .push(format!("{}: started", info.display_name)),
            Ok(false) => outcome.already_correct += 1,
            Err(err) => {
                if err.denied {
                    outcome.denied += 1;
                }
                outcome
                    .errors
                    .push(format!("{}: {}", info.name, err.message));
            }
        }
        progress(index + 1, names.len());
    }
    outcome
}

/// Stop each named service. No backup: stopping is transient.
pub fn stop_services(
    store: &mut dyn ServiceStore,
    names: &[String],
    progress: &mut dyn FnMut(usize, usize),
) -> ServiceOutcome {
    let mut outcome = ServiceOutcome::default();
    let current = match store.list() {
        Ok(current) => current,
        Err(err) => {
            outcome.errors.push(err.0);
            return outcome;
        }
    };
    for (index, name) in names.iter().enumerate() {
        let Some(info) = current
            .iter()
            .find(|info| info.name.eq_ignore_ascii_case(name))
        else {
            outcome.errors.push(format!("{name}: no longer listed"));
            progress(index + 1, names.len());
            continue;
        };
        if let Some(reason) = refuse_stop(info) {
            outcome.refused.push(format!("{}: {reason}", info.name));
            progress(index + 1, names.len());
            continue;
        }
        if info.state == ServiceState::Stopped {
            outcome.already_correct += 1;
            progress(index + 1, names.len());
            continue;
        }
        match store.stop(&info.name) {
            Ok(true) => outcome
                .applied
                .push(format!("{}: stopped", info.display_name)),
            Ok(false) => outcome.already_correct += 1,
            Err(err) => {
                if err.denied {
                    outcome.denied += 1;
                }
                outcome
                    .errors
                    .push(format!("{}: {}", info.name, err.message));
            }
        }
        progress(index + 1, names.len());
    }
    outcome
}

/// Services sorted for display, by display name.
pub fn sort_services(services: &mut [ServiceInfo]) {
    services.sort_by_key(|info| info.display_name.to_ascii_lowercase());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::BackupSummary;
    use crate::model::ValueKind;
    use crate::registry::MemoryRegistry;

    fn info(name: &str, start: StartType, state: ServiceState) -> ServiceInfo {
        ServiceInfo {
            name: name.into(),
            display_name: format!("{name} display"),
            start,
            state,
        }
    }

    #[test]
    fn start_types_round_trip_and_reject_unknown_dwords() {
        assert_eq!(StartType::from_dword(0, false), Some(StartType::Boot));
        assert_eq!(StartType::from_dword(1, false), Some(StartType::System));
        assert_eq!(StartType::from_dword(2, false), Some(StartType::Automatic));
        assert_eq!(
            StartType::from_dword(2, true),
            Some(StartType::AutomaticDelayed)
        );
        assert_eq!(StartType::from_dword(3, false), Some(StartType::Manual));
        assert_eq!(StartType::from_dword(4, false), Some(StartType::Disabled));
        assert_eq!(StartType::from_dword(5, false), None);
        assert_eq!(StartType::from_dword(99, true), None);
        assert_eq!(StartType::Automatic.dword(), 2);
        assert_eq!(StartType::AutomaticDelayed.dword(), 2);
        assert_eq!(ServiceState::from_dword(1), ServiceState::Stopped);
        assert_eq!(ServiceState::from_dword(4), ServiceState::Running);
        assert_eq!(ServiceState::from_dword(7), ServiceState::Paused);
        assert_eq!(ServiceState::from_dword(2), ServiceState::Other);
    }

    #[test]
    fn plan_skips_absent_protected_boot_loosening_and_done_rows() {
        let current = [
            info("RpcSs", StartType::Automatic, ServiceState::Running),
            info("wuauserv", StartType::Manual, ServiceState::Stopped),
            info("Fax", StartType::Automatic, ServiceState::Stopped),
            info("SysMain", StartType::Manual, ServiceState::Running),
            info("RemoteRegistry", StartType::Disabled, ServiceState::Stopped),
            info(
                "DelayedSvc",
                StartType::AutomaticDelayed,
                ServiceState::Running,
            ),
            info("BootDrv", StartType::Boot, ServiceState::Running),
        ];
        let profile = TuneupProfile {
            id: "test",
            name: "test",
            blurb: "test",
            targets: &[
                TuneupTarget {
                    name: "RpcSs",
                    to: StartType::Manual,
                    why: "protected",
                },
                TuneupTarget {
                    name: "Fax",
                    to: StartType::Manual,
                    why: "fax",
                },
                TuneupTarget {
                    name: "SysMain",
                    to: StartType::Manual,
                    why: "done",
                },
                TuneupTarget {
                    name: "RemoteRegistry",
                    to: StartType::Manual,
                    why: "loosening",
                },
                TuneupTarget {
                    name: "DelayedSvc",
                    to: StartType::Manual,
                    why: "delayed",
                },
                TuneupTarget {
                    name: "BootDrv",
                    to: StartType::Manual,
                    why: "boot",
                },
                TuneupTarget {
                    name: "Missing",
                    to: StartType::Manual,
                    why: "absent",
                },
            ],
        };
        let changes = plan_profile(&profile, &current);
        let names: Vec<&str> = changes.iter().map(|change| change.name.as_str()).collect();
        assert_eq!(names, ["Fax", "DelayedSvc"]);
        assert_eq!(changes[0].from, StartType::Automatic);
        assert_eq!(changes[0].why, "fax");
    }

    #[test]
    fn suggested_profile_only_tightens_to_manual() {
        assert!(!SUGGESTED.targets.is_empty());
        let mut names = Vec::new();
        for target in SUGGESTED.targets {
            assert_eq!(target.to, StartType::Manual, "{}", target.name);
            assert!(!is_never_touch(target.name), "{}", target.name);
            assert!(!target.why.is_empty(), "{}", target.name);
            assert!(!names.contains(&target.name), "dup {}", target.name);
            names.push(target.name);
        }
    }

    #[test]
    fn start_backup_parses_machine_wide_and_flags_unreadable() {
        let mut reg = MemoryRegistry::new();
        reg.set_dword(&service_key("DiagTrack"), "Start", 2);
        reg.set_dword(&service_key("DelayedSvc"), "Start", 2);
        reg.set_dword(&service_key("DelayedSvc"), "DelayedAutostart", 1);
        let plan = export_start_backup(
            &reg,
            &["DiagTrack".into(), "DelayedSvc".into(), "Missing".into()],
        );
        assert!(plan.body.contains("\"Start\"=dword:00000002"));
        assert!(plan.body.contains("\"DelayedAutostart\"=dword:00000001"));
        assert_eq!(plan.unreadable.len(), 1);
        assert!(!plan.covers(&service_key("Missing")));
        assert!(plan.covers(&service_key("DiagTrack")));
        let summary = BackupSummary::parse(&plan.body);
        assert_eq!(summary.keys, 2);
        assert_eq!(summary.values, 3);
        assert!(summary.machine_wide);
        assert!(summary.files.is_empty());
    }

    #[test]
    fn memory_store_round_trips_start_and_state() {
        let mut store = MemoryServiceStore::new();
        store.insert(info("Fax", StartType::Automatic, ServiceState::Stopped));
        store.insert(info("Old", StartType::Disabled, ServiceState::Stopped));
        assert_eq!(store.list().unwrap().len(), 2);
        store.set_start("fax", StartType::Manual).unwrap();
        assert_eq!(
            store.find("FAX").unwrap().start,
            StartType::Manual,
            "names match case-insensitively"
        );
        assert!(store.set_start("Missing", StartType::Manual).is_err());
        assert_eq!(store.start("Fax").unwrap(), true);
        assert_eq!(store.start("Fax").unwrap(), false);
        assert_eq!(store.stop("Fax").unwrap(), true);
        assert_eq!(store.stop("Fax").unwrap(), false);
        assert!(store.start("Old").unwrap_err().message.contains("disabled"));
    }

    fn keyed_registry() -> MemoryRegistry {
        let mut reg = MemoryRegistry::new();
        reg.set_dword(&service_key("Good"), "Start", 2);
        reg.set_dword(&service_key("RpcSs"), "Start", 2);
        reg.set_dword(&service_key("Done"), "Start", 3);
        reg.set(&service_key("Odd"), "Start", ValueKind::Sz("x".into()));
        reg
    }

    fn change(name: &str, to: StartType) -> ServiceChange {
        ServiceChange {
            name: name.into(),
            display_name: format!("{name} display"),
            from: StartType::Automatic,
            to,
            why: String::new(),
        }
    }

    #[test]
    fn apply_writes_backup_first_and_skips_unreadable_and_refused() {
        let mut store = MemoryServiceStore::new();
        store.insert(info("Good", StartType::Automatic, ServiceState::Stopped));
        store.insert(info("RpcSs", StartType::Automatic, ServiceState::Running));
        store.insert(info("Done", StartType::Manual, ServiceState::Stopped));
        store.insert(info("Odd", StartType::Automatic, ServiceState::Stopped));
        let reg = keyed_registry();
        let backup = std::env::temp_dir().join("hive-mend-services-test.reg");
        let changes = [
            change("Good", StartType::Manual),
            change("RpcSs", StartType::Manual),
            change("Done", StartType::Manual),
            change("Odd", StartType::Manual),
            change("Missing", StartType::Manual),
        ];
        let outcome =
            apply_start_changes(&mut store, &reg, &changes, &backup, &mut |_, _| {}).unwrap();
        assert_eq!(outcome.applied.len(), 1);
        assert!(outcome.applied[0].contains("Good display"));
        assert_eq!(outcome.already_correct, 1);
        assert_eq!(outcome.refused.len(), 1);
        assert!(outcome.refused[0].starts_with("RpcSs:"));
        assert_eq!(
            outcome.not_backed_up,
            vec!["Odd".to_string(), "Missing".to_string()]
        );
        assert!(outcome.errors.is_empty());
        assert_eq!(store.find("Good").unwrap().start, StartType::Manual);
        assert_eq!(store.find("RpcSs").unwrap().start, StartType::Automatic);
        let text = crate::backup::read_backup(&backup).unwrap();
        assert!(text.contains("[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Good]"));
        assert!(text.contains("\"Start\"=dword:00000002"));
        let _ = std::fs::remove_file(&backup);
    }

    #[test]
    fn apply_refuses_boot_targets_whatever_the_row_says() {
        let mut store = MemoryServiceStore::new();
        store.insert(info("Good", StartType::Automatic, ServiceState::Stopped));
        let reg = keyed_registry();
        let backup = std::env::temp_dir().join("hive-mend-services-boot-test.reg");
        let outcome = apply_start_changes(
            &mut store,
            &reg,
            &[change("Good", StartType::Boot)],
            &backup,
            &mut |_, _| {},
        )
        .unwrap();
        assert!(outcome.applied.is_empty());
        assert_eq!(outcome.refused.len(), 1);
        assert_eq!(store.find("Good").unwrap().start, StartType::Automatic);
        let _ = std::fs::remove_file(&backup);
    }

    #[test]
    fn start_and_stop_honor_refusals_and_current_state() {
        let mut store = MemoryServiceStore::new();
        store.insert(info("RpcSs", StartType::Automatic, ServiceState::Running));
        store.insert(info("BootDrv", StartType::Boot, ServiceState::Running));
        store.insert(info("Spooler", StartType::Automatic, ServiceState::Stopped));
        let stopped = stop_services(
            &mut store,
            &[
                "RpcSs".into(),
                "BootDrv".into(),
                "Spooler".into(),
                "Missing".into(),
            ],
            &mut |_, _| {},
        );
        assert_eq!(stopped.refused.len(), 2);
        assert_eq!(stopped.already_correct, 1);
        assert_eq!(stopped.errors.len(), 1);
        let started = start_services(
            &mut store,
            &["RpcSs".into(), "BootDrv".into(), "Spooler".into()],
            &mut |_, _| {},
        );
        assert_eq!(started.applied.len(), 1);
        assert_eq!(started.already_correct, 1);
        assert_eq!(started.refused.len(), 1);
    }

    #[test]
    fn services_sort_by_display_name() {
        let mut services = [
            info("zebra", StartType::Manual, ServiceState::Stopped),
            info("apple", StartType::Manual, ServiceState::Stopped),
        ];
        services[0].display_name = "Zebra".into();
        services[1].display_name = "apple".into();
        let mut list = services.to_vec();
        sort_services(&mut list);
        assert_eq!(list[0].name, "apple");
    }
}
