use std::path::Path;

use crate::backup::{BackupPlan, export_backup, write_backup};
use crate::fs::{Access, FileView, ItemKind};
use crate::ignore::{IgnoreDb, load_ignore_file};
use crate::model::{Error, Finding, Repair, ScanOptions, ScannerId};
use crate::pathutil::{
    canonical_path, file_delete_allowed, is_protected_key, key_delete_allowed, under_windows_dir,
};
use crate::registry::{RegError, Registry};
use crate::rules::{RuleSet, builtin_deep_roots, decode_text_owned, load_rules_file};
use crate::scanners::{ScanCtx, run_scanner};

pub struct Engine {
    pub rules: RuleSet,
    pub ignore: IgnoreDb,
    pub deep_roots: Vec<String>,
}

impl Engine {
    pub fn try_builtin() -> Result<Self, Error> {
        Ok(Self {
            rules: RuleSet::try_builtin()?,
            ignore: IgnoreDb::default(),
            deep_roots: builtin_deep_roots(),
        })
    }

    /// `data_dir` is an extracted legacy cleaner `app` folder, or its `Data` folder.
    /// Original `rmscan.xml`, `keys.dat`, `values.dat`, and `map.dat` are added when present.
    pub fn load(rules_path: Option<&Path>, data_dir: Option<&Path>) -> Result<Self, Error> {
        let mut rules = match rules_path {
            Some(path) => load_rules_file(path)?,
            None => RuleSet::try_builtin()?,
        };
        let mut ignore = IgnoreDb::default();
        let mut deep_roots = builtin_deep_roots();
        if let Some(dir) = data_dir {
            let data = if dir.join("Data").is_dir() {
                dir.join("Data")
            } else {
                dir.to_path_buf()
            };
            let rules_file = data.join("rmscan.xml");
            if rules_file.exists() {
                rules.merge_file(&decode_text_owned(std::fs::read(&rules_file)?))?;
            }
            load_ignore_file(&data.join("keys.dat"), true, &mut ignore)?;
            load_ignore_file(&data.join("values.dat"), false, &mut ignore)?;
            let map_file = data.join("map.dat");
            if map_file.exists() {
                for line in decode_text_owned(std::fs::read(&map_file)?).lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with("[**") || line.starts_with('#') {
                        continue;
                    }
                    let path = canonical_path(line);
                    if !deep_roots
                        .iter()
                        .any(|have| have.eq_ignore_ascii_case(&path))
                    {
                        deep_roots.push(path);
                    }
                }
            }
        }
        Ok(Self {
            rules,
            ignore,
            deep_roots,
        })
    }
}

pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
    /// The progress callback asked to stop. `findings` is incomplete.
    pub canceled: bool,
}

pub fn scan(
    engine: &Engine,
    reg: &dyn Registry,
    fs: &dyn FileView,
    opts: &ScanOptions,
) -> ScanReport {
    scan_with_progress(engine, reg, fs, opts, &mut |_, _, _| true)
}

/// `progress(step, total, scanner_name)` runs before each scanner. Returning
/// false stops the scan.
pub fn scan_with_progress(
    engine: &Engine,
    reg: &dyn Registry,
    fs: &dyn FileView,
    opts: &ScanOptions,
    progress: &mut dyn FnMut(usize, usize, &str) -> bool,
) -> ScanReport {
    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    let chosen: Vec<_> = engine
        .rules
        .scanners
        .iter()
        .filter(|scanner| selected(scanner.id, scanner.enabled, opts))
        .collect();
    for (step, scanner) in chosen.iter().enumerate() {
        if !progress(step, chosen.len(), &scanner.name) {
            return ScanReport {
                findings: Vec::new(),
                warnings,
                canceled: true,
            };
        }
        let mut ctx = ScanCtx {
            reg,
            fs,
            ignore: &engine.ignore,
            wow64: opts.wow64,
            warnings: &mut warnings,
        };
        run_scanner(&mut ctx, scanner, &engine.deep_roots, &mut findings);
    }
    findings.sort_by(|left, right| {
        left.scanner
            .cmp(&right.scanner)
            .then(
                left.key
                    .to_ascii_lowercase()
                    .cmp(&right.key.to_ascii_lowercase()),
            )
            .then(left.value.cmp(&right.value))
    });
    findings.dedup_by(|left, right| {
        left.scanner == right.scanner
            && left.key.eq_ignore_ascii_case(&right.key)
            && left.value == right.value
            && left.detail == right.detail
    });
    progress(chosen.len(), chosen.len(), "");
    ScanReport {
        findings,
        warnings,
        canceled: false,
    }
}

/// The selected findings that a fresh scan still reports. Anything fixed,
/// reinstalled, or changed since the first scan drops out before repair.
pub fn still_reported(selected: &[Finding], fresh: &[Finding]) -> Vec<Finding> {
    selected
        .iter()
        .filter(|finding| {
            fresh.iter().any(|now| {
                now.scanner == finding.scanner && same_target(&now.repair, &finding.repair)
            })
        })
        .cloned()
        .collect()
}

fn same_target(left: &Repair, right: &Repair) -> bool {
    match (left, right) {
        (Repair::DeleteKey { key: a }, Repair::DeleteKey { key: b }) => {
            canonical_path(a).eq_ignore_ascii_case(&canonical_path(b))
        }
        (Repair::DeleteValue { key: a, name: x }, Repair::DeleteValue { key: b, name: y }) => {
            canonical_path(a).eq_ignore_ascii_case(&canonical_path(b)) && x.eq_ignore_ascii_case(y)
        }
        (Repair::DeleteFile { path: a, .. }, Repair::DeleteFile { path: b, .. }) => {
            a.eq_ignore_ascii_case(b)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemoryFs;
    use crate::model::{RegValue, ScannerId};
    use crate::registry::MemoryRegistry;

    /// A registry where one key cannot be read, as with a locked-down ACL.
    struct Locked {
        inner: MemoryRegistry,
        locked: String,
    }

    impl Registry for Locked {
        fn subkeys(&self, path: &str) -> Result<Vec<String>, RegError> {
            if canonical_path(path).eq_ignore_ascii_case(&self.locked) {
                return Err(RegError::Denied("access denied".into()));
            }
            self.inner.subkeys(path)
        }
        fn values(&self, path: &str) -> Result<Vec<RegValue>, RegError> {
            self.inner.values(path)
        }
        fn delete_value(&mut self, path: &str, name: &str) -> Result<(), RegError> {
            self.inner.delete_value(path, name)
        }
        fn delete_tree(&mut self, path: &str) -> Result<(), RegError> {
            self.inner.delete_tree(path)
        }
    }

    fn uninstall_finding(name: &str) -> Finding {
        let key = format!(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{name}"
        );
        Finding {
            scanner: ScannerId::AddRemovePrograms,
            scanner_name: "Add/Remove Programs".into(),
            key: key.clone(),
            value: None,
            detail: "orphaned".into(),
            repair: Repair::DeleteKey { key },
        }
    }

    fn temp_file_finding(path: &str) -> Finding {
        Finding {
            scanner: ScannerId::TempShortcuts,
            scanner_name: "Temp files".into(),
            key: path.into(),
            value: None,
            detail: "temporary file".into(),
            repair: Repair::DeleteFile {
                path: path.into(),
                keep_copy: false,
            },
        }
    }

    #[test]
    fn file_delete_checks_where_the_file_really_is() {
        let mut fs = MemoryFs::with_windows_dirs();
        let temp = r"C:\Users\me\AppData\Local\Temp";
        fs.add_file_bytes(&format!(r"{temp}\real.tmp"), vec![1; 4], None);
        // A temp-looking path that really leads into System32 and into a
        // documents folder: both spellings pass the textual rule.
        fs.add_file_bytes(r"C:\Windows\System32\kernel.dll", vec![2; 4], None);
        fs.add_file_bytes(r"C:\Users\me\Documents\thesis.docx", vec![3; 4], None);
        fs.add_alias(&format!(r"{temp}\sys"), r"C:\Windows\System32");
        fs.add_alias(&format!(r"{temp}\docs"), r"C:\Users\me\Documents");
        let backup = std::env::temp_dir().join(format!(
            "hive-mend-pinned-delete-{}.reg",
            std::process::id()
        ));
        let findings = [
            temp_file_finding(&format!(r"{temp}\real.tmp")),
            temp_file_finding(&format!(r"{temp}\sys\kernel.dll")),
            temp_file_finding(&format!(r"{temp}\docs\thesis.docx")),
        ];
        let outcome = repair(&mut MemoryRegistry::new(), &mut fs, &findings, &backup).unwrap();
        let _ = std::fs::remove_file(&backup);
        assert_eq!(outcome.applied, 1);
        assert_eq!(outcome.refused, 2);
        assert!(!fs.exists(&format!(r"{temp}\real.tmp")));
        assert_eq!(fs.read(r"C:\Windows\System32\kernel.dll"), Some(vec![2; 4]));
        assert_eq!(
            fs.read(r"C:\Users\me\Documents\thesis.docx"),
            Some(vec![3; 4])
        );
    }

    #[test]
    fn repair_leaves_alone_what_the_backup_could_not_read() {
        let mut inner = MemoryRegistry::new();
        let base = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        inner.set_sz(&format!(r"{base}\Readable"), "DisplayName", "Readable");
        inner.set_sz(&format!(r"{base}\Locked\Child"), "DisplayName", "Locked");
        let mut reg = Locked {
            inner,
            locked: canonical_path(&format!(r"{base}\Locked")),
        };
        let backup = std::env::temp_dir().join("hive-mend-locked-test.reg");
        let findings = [uninstall_finding("Readable"), uninstall_finding("Locked")];
        let outcome = repair(&mut reg, &mut MemoryFs::new(), &findings, &backup).unwrap();
        assert_eq!(outcome.applied, 1);
        assert_eq!(outcome.not_backed_up, 1);
        assert!(reg.inner.subkeys(&format!(r"{base}\Locked")).is_ok());
        assert!(reg.inner.values(&format!(r"{base}\Readable")).is_err());
        let _ = std::fs::remove_file(&backup);
    }

    #[test]
    fn recheck_drops_findings_that_are_fixed_since_the_scan() {
        let selected = [uninstall_finding("Gone"), uninstall_finding("Reinstalled")];
        let mut fresh = uninstall_finding("gone");
        if let Repair::DeleteKey { key } = &mut fresh.repair {
            *key = key.to_ascii_lowercase();
        }
        let kept = still_reported(&selected, &[fresh]);
        assert_eq!(kept.len(), 1);
        assert!(kept[0].key.ends_with("Gone"));
    }

    #[test]
    fn merges_extracted_legacy_rules_when_present() {
        let app = Path::new("/tmp/rm10/app");
        if !app.join("Data/rmscan.xml").exists() {
            return;
        }
        let engine = Engine::load(None, Some(app)).unwrap();
        let startup = engine.rules.get(ScannerId::StartupPrograms).unwrap();
        assert!(
            startup
                .paths
                .iter()
                .any(|path| { path.path.to_ascii_lowercase().contains("runservices") })
        );
        assert!(
            startup
                .paths
                .iter()
                .any(|path| path.path.to_ascii_lowercase().ends_with("\\run"))
        );
        assert!(engine.ignore.key_fragments.len() > 10);
        assert!(engine.deep_roots.len() > 20);
    }
}

fn selected(id: ScannerId, enabled: bool, opts: &ScanOptions) -> bool {
    if !opts.only.is_empty() {
        return opts.only.contains(&id);
    }
    if id == ScannerId::DeepScan {
        return enabled || opts.include_deep;
    }
    enabled
}

#[derive(Debug, Default)]
pub struct RepairOutcome {
    pub backup_file: std::path::PathBuf,
    /// Removed.
    pub applied: usize,
    /// Already gone when repair reached it.
    pub already_gone: usize,
    /// Report-only findings, and anything a safety rule refused.
    pub refused: usize,
    /// Left alone because the backup could not read it first.
    pub not_backed_up: usize,
    /// Failed because the process lacks rights, usually a machine-wide key
    /// without "Run as administrator". Also counted in `errors`.
    pub denied: usize,
    pub errors: Vec<String>,
    /// Findings that are no longer a problem: removed or already gone.
    pub resolved: Vec<Finding>,
}

impl RepairOutcome {
    pub fn skipped(&self) -> usize {
        self.already_gone + self.refused + self.not_backed_up
    }
}

pub fn repair(
    reg: &mut dyn Registry,
    fs: &mut dyn FileView,
    findings: &[Finding],
    backup_file: &Path,
) -> Result<RepairOutcome, Error> {
    repair_with_progress(reg, fs, findings, backup_file, &mut |_, _| {})
}

/// Writes the backup, then removes each finding the backup covers.
/// `progress(done, total)` runs after each finding.
///
/// A value added between the backup read and its deletion would be removed
/// without being in the backup; the window is milliseconds, and anything
/// the backup could not read is skipped rather than deleted.
pub fn repair_with_progress(
    reg: &mut dyn Registry,
    fs: &mut dyn FileView,
    findings: &[Finding],
    backup_file: &Path,
    progress: &mut dyn FnMut(usize, usize),
) -> Result<RepairOutcome, Error> {
    let plan = export_backup(reg, findings, backup_file);
    write_backup(backup_file, &plan.body)?;
    let mut outcome = RepairOutcome {
        backup_file: backup_file.to_path_buf(),
        ..RepairOutcome::default()
    };
    for (index, finding) in findings.iter().enumerate() {
        match apply(reg, fs, finding, &plan) {
            Applied::Removed => {
                outcome.applied += 1;
                outcome.resolved.push(finding.clone());
            }
            Applied::AlreadyGone => {
                outcome.already_gone += 1;
                outcome.resolved.push(finding.clone());
            }
            Applied::Refused => outcome.refused += 1,
            Applied::NotBackedUp => outcome.not_backed_up += 1,
            Applied::Failed { message, denied } => {
                if denied {
                    outcome.denied += 1;
                }
                outcome.errors.push(format!("{}: {message}", finding.key));
            }
        }
        progress(index + 1, findings.len());
    }
    Ok(outcome)
}

enum Applied {
    Removed,
    AlreadyGone,
    Refused,
    NotBackedUp,
    Failed { message: String, denied: bool },
}

fn reg_result(result: Result<(), RegError>) -> Applied {
    match result {
        Ok(()) => Applied::Removed,
        Err(RegError::NotFound) => Applied::AlreadyGone,
        Err(RegError::Denied(message)) => Applied::Failed {
            message,
            denied: true,
        },
        Err(RegError::Message(message)) => Applied::Failed {
            message,
            denied: false,
        },
    }
}

fn apply(
    reg: &mut dyn Registry,
    fs: &mut dyn FileView,
    finding: &Finding,
    plan: &BackupPlan,
) -> Applied {
    match &finding.repair {
        Repair::None => Applied::Refused,
        Repair::DeleteValue { key, name } => {
            if is_protected_key(key) {
                return Applied::Refused;
            }
            if !plan.covers(key) {
                return Applied::NotBackedUp;
            }
            reg_result(reg.delete_value(key, name))
        }
        Repair::DeleteKey { key } => {
            if !key_delete_allowed(key) {
                return Applied::Refused;
            }
            if !plan.covers(key) {
                return Applied::NotBackedUp;
            }
            reg_result(reg.delete_tree(key))
        }
        Repair::DeleteFile { path, keep_copy } => {
            if !file_delete_allowed(path) {
                return Applied::Refused;
            }
            let copy = if *keep_copy {
                match plan.copy_for(path) {
                    Some(copy) => Some(copy.to_string_lossy().to_string()),
                    None => return Applied::NotBackedUp,
                }
            } else {
                None
            };
            delete_file_pinned(fs, path, copy.as_deref())
        }
    }
}

/// Delete a stale shortcut or temp file through one checked handle. The
/// object is pinned first, the same rules are applied to the real path
/// Windows reports for it (so a junction, link, or 8.3 name cannot carry the
/// delete somewhere the spelling would never be allowed), and the copy and
/// the delete both go through that handle.
fn delete_file_pinned(fs: &mut dyn FileView, path: &str, copy: Option<&str>) -> Applied {
    let mut pin = match fs.pin(path) {
        Ok(pin) => pin,
        Err(err) if err.contains("not found") || err.contains("os error 2") => {
            return Applied::AlreadyGone;
        }
        Err(_) => return Applied::Refused,
    };
    let real = pin.real_path.clone();
    if pin.kind != ItemKind::File || !file_delete_allowed(&real) || under_windows_dir(&*fs, &real) {
        return Applied::Refused;
    }
    let access = if copy.is_some() {
        Access::ReadDelete
    } else {
        Access::Delete
    };
    if let Err(err) = fs.pin_acquire(&mut pin, access) {
        return Applied::Failed {
            denied: err.contains("os error 5"),
            message: err,
        };
    }
    if let Some(copy) = copy
        && let Err(err) = fs.pin_copy_to(&pin, copy)
    {
        return Applied::Failed {
            message: format!("could not save a copy first: {err}"),
            denied: false,
        };
    }
    match fs.pin_delete(pin) {
        Ok(()) => Applied::Removed,
        Err(err) if err.contains("not found") || err.contains("os error 2") => Applied::AlreadyGone,
        Err(err) => Applied::Failed {
            denied: err.contains("os error 5"),
            message: err,
        },
    }
}
