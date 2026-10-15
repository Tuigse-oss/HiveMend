use std::path::Path;

use crate::backup::{BackupPlan, BackupWriter, export_backup, registry_sections};
use crate::fs::{Access, FileView, ItemKind};
use crate::ignore::{IgnoreDb, load_ignore_file};
use crate::model::{Error, Finding, Repair, ScanOptions, ScannerId};
use crate::pathutil::{
    canonical_path, file_delete_allowed, is_protected_key, key_delete_allowed, under_windows_dir,
};
use crate::registry::{RegError, RegTransaction, Registry};
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
    use crate::model::ValueKind;
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
        fn begin(&mut self) -> Result<Box<dyn RegTransaction + '_>, RegError> {
            let locked = self.locked.clone();
            Ok(Box::new(crate::registry::DenyTx {
                inner: self.inner.begin()?,
                deny_subkeys: Some(locked),
                deny_values: None,
                deny_writes: None,
            }))
        }
    }

    #[test]
    fn a_shortcut_with_extra_data_streams_is_not_removed() {
        let mut fs = MemoryFs::with_windows_dirs();
        let desktop = r"C:\Users\me\Desktop";
        fs.add_file_bytes(&format!(r"{desktop}\plain.lnk"), b"lnk".to_vec(), None);
        fs.add_file_bytes(&format!(r"{desktop}\streams.lnk"), b"lnk".to_vec(), None);
        fs.add_stream(&format!(r"{desktop}\streams.lnk"));
        fs.add_file_bytes(&format!(r"{desktop}\marked.lnk"), b"lnk".to_vec(), None);
        fs.add_download_marker(&format!(r"{desktop}\marked.lnk"));
        let copies = r"C:\Users\me\AppData\Local\HiveMend\backups\b-files";
        let streams = delete_file_pinned(
            &mut fs,
            &format!(r"{desktop}\streams.lnk"),
            Some(&format!(r"{copies}\0001-streams.lnk")),
        );
        assert!(matches!(streams, Applied::NotBackedUp));
        assert!(fs.exists(&format!(r"{desktop}\streams.lnk")));
        // The download marker is a stream too: it would be lost.
        let marked = delete_file_pinned(
            &mut fs,
            &format!(r"{desktop}\marked.lnk"),
            Some(&format!(r"{copies}\0003-marked.lnk")),
        );
        assert!(matches!(marked, Applied::NotBackedUp));
        assert!(fs.exists(&format!(r"{desktop}\marked.lnk")));
        // A stream added after the copy, before the delete: it stays.
        fs.add_file_bytes(&format!(r"{desktop}\late.lnk"), b"lnk".to_vec(), None);
        fs.set_streams_late(&format!(r"{desktop}\late.lnk"));
        let late = delete_file_pinned(
            &mut fs,
            &format!(r"{desktop}\late.lnk"),
            Some(&format!(r"{copies}\0004-late.lnk")),
        );
        assert!(matches!(late, Applied::NotBackedUp));
        assert!(fs.exists(&format!(r"{desktop}\late.lnk")));
        let plain = delete_file_pinned(
            &mut fs,
            &format!(r"{desktop}\plain.lnk"),
            Some(&format!(r"{copies}\0002-plain.lnk")),
        );
        assert!(matches!(plain, Applied::Removed));
        assert!(fs.exists(&format!(r"{copies}\0002-plain.lnk")));
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
        let mut backup = crate::backup::test_writer("hive-mend-pinned-delete");
        let findings = [
            temp_file_finding(&format!(r"{temp}\real.tmp")),
            temp_file_finding(&format!(r"{temp}\sys\kernel.dll")),
            temp_file_finding(&format!(r"{temp}\docs\thesis.docx")),
        ];
        let outcome = repair(&mut MemoryRegistry::new(), &mut fs, &findings, &mut backup).unwrap();
        let _ = std::fs::remove_file(backup.path());
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
    fn a_registry_entry_changed_during_repair_is_not_removed() {
        let base = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        let mut reg = MemoryRegistry::new();
        reg.set_sz(&format!(r"{base}\Stale"), "DisplayName", "Stale");
        reg.set_sz(&format!(r"{base}\Stale\Child"), "x", "1");
        reg.set_sz(&format!(r"{base}\Other"), "DisplayName", "Other");
        // Another program writes under Stale while the repair runs.
        reg.changed_elsewhere.push(format!(r"{base}\Stale\Child"));
        let mut backup = crate::backup::test_writer("hive-mend-tx-conflict");
        let findings = [uninstall_finding("Stale"), uninstall_finding("Other")];
        let outcome = repair(&mut reg, &mut MemoryFs::new(), &findings, &mut backup).unwrap();
        assert_eq!(outcome.applied, 1, "{:?}", outcome.errors);
        assert_eq!(outcome.errors.len(), 1);
        assert!(
            reg.subkeys(&format!(r"{base}\Stale")).is_ok(),
            "a changed entry was removed"
        );
        assert!(reg.values(&format!(r"{base}\Other")).is_err());
        let text = crate::backup::read_backup(backup.path()).unwrap();
        assert!(text.contains("; entry 1\r\n"));
        assert!(text.contains("; entry 1 was not removed"));
        assert!(text.contains("; entry 2\r\n"));
        assert!(!text.contains("; entry 2 was not removed"));
        let _ = std::fs::remove_file(backup.path());
    }

    /// The real backup a mixed repair writes restores every registry entry
    /// it removed, whether or not the file part was refused.
    #[test]
    fn a_mixed_repair_backup_restores_every_registry_entry() {
        use crate::regfile::{RegOp, apply_ops, parse_backup};
        let base = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        for refuse_file in [false, true] {
            let mut reg = MemoryRegistry::new();
            reg.set_sz(&format!(r"{base}\Stale"), "DisplayName", "Stale");
            reg.set(
                &format!(r"{base}\Stale\Child"),
                "raw",
                ValueKind::Other {
                    kind: 11,
                    bytes: vec![1, 2, 3, 4, 5, 6, 7, 8],
                },
            );
            let mut fs = MemoryFs::with_windows_dirs();
            let shortcut = if refuse_file {
                r"C:\Windows\old.lnk".to_string()
            } else {
                r"C:\Users\me\Desktop\old.lnk".to_string()
            };
            fs.add_file_bytes(&shortcut, b"lnk".to_vec(), None);
            let temp = r"C:\Users\me\AppData\Local\Temp\x.tmp";
            fs.add_file_bytes(temp, vec![0; 4], None);
            let mut lnk = temp_file_finding(&shortcut);
            lnk.repair = Repair::DeleteFile {
                path: shortcut.clone(),
                keep_copy: true,
            };
            let findings = [lnk, temp_file_finding(temp), uninstall_finding("Stale")];
            let mut backup = crate::backup::test_writer("hive-mend-mixed");
            let outcome = repair(&mut reg, &mut fs, &findings, &mut backup).unwrap();
            let text = crate::backup::read_backup(backup.path()).unwrap();
            let _ = std::fs::remove_file(backup.path());
            assert!(
                reg.subkeys(&format!(r"{base}\Stale")).is_err(),
                "not removed"
            );
            assert!(text.contains("; Files"), "{text}");
            let parsed = parse_backup(&text).unwrap();
            assert!(parsed.unconfirmed.is_empty(), "{:?}", parsed.unconfirmed);
            assert!(
                parsed
                    .ops
                    .iter()
                    .any(|op| matches!(op, RegOp::CreateKey(key) if key.ends_with(r"Stale\Child"))),
                "{text}"
            );
            let summary = crate::backup::BackupSummary::parse(&text);
            assert_eq!(summary.keys, 2, "the listing agrees with the restore");
            let mut fresh = MemoryRegistry::new();
            apply_ops(&mut fresh, &parsed.ops).unwrap();
            assert_eq!(
                fresh.values(&format!(r"{base}\Stale\Child")).unwrap()[0].data,
                ValueKind::Other {
                    kind: 11,
                    bytes: vec![1, 2, 3, 4, 5, 6, 7, 8]
                }
            );
            assert_eq!(
                fresh.values(&format!(r"{base}\Stale")).unwrap()[0].data,
                ValueKind::Sz("Stale".into())
            );
            assert_eq!(outcome.errors.len(), 0, "{:?}", outcome.errors);
        }
    }

    #[test]
    fn an_entry_without_its_removed_line_is_never_restored() {
        use crate::regfile::parse_backup;
        let base = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        let mut reg = MemoryRegistry::new();
        reg.set_sz(&format!(r"{base}\Stale"), "DisplayName", "Stale");
        reg.set_sz(&format!(r"{base}\Other"), "DisplayName", "Other");
        // Stale changes elsewhere, so its transaction aborts.
        reg.changed_elsewhere.push(format!(r"{base}\Stale"));
        let mut backup = crate::backup::test_writer("hive-mend-unconfirmed");
        repair(
            &mut reg,
            &mut MemoryFs::new(),
            &[uninstall_finding("Stale"), uninstall_finding("Other")],
            &mut backup,
        )
        .unwrap();
        let text = crate::backup::read_backup(backup.path()).unwrap();
        let _ = std::fs::remove_file(backup.path());
        // Even if the "was not removed" line had not been written (a run
        // stopped there), entry 1 has no "removed" line: never restored.
        let without_note = text.replace("; entry 1 was not removed\r\n", "");
        for text in [&text, &without_note] {
            let parsed = parse_backup(text).unwrap();
            assert!(
                parsed.ops.iter().all(|op| !op.key().ends_with("Stale")),
                "an aborted entry would be restored"
            );
            assert!(parsed.ops.iter().any(|op| op.key().ends_with("Other")));
        }
        let parsed = parse_backup(&without_note).unwrap();
        assert_eq!(parsed.unconfirmed.len(), 1, "it is listed for review");
        // A save cut off after the last confirmed entry loses only the tail.
        let cut = format!("{text}\r\n; entry 3\r\n[{base}\\Half]\r\n\"x\"=hex:01,02,\\");
        let parsed = parse_backup(&cut).unwrap();
        assert!(parsed.cut_off);
        assert!(parsed.ops.iter().any(|op| op.key().ends_with("Other")));
    }

    #[test]
    fn an_administrator_leaves_keys_others_can_change_alone() {
        let base = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        let mut reg = MemoryRegistry::new();
        reg.set_sz(&format!(r"{base}\Open"), "DisplayName", "Open");
        reg.set_sz(&format!(r"{base}\Open\Deep"), "x", "1");
        reg.set_sz(&format!(r"{base}\Closed"), "DisplayName", "Closed");
        reg.untrusted.push(format!(r"{base}\Open\Deep"));
        let mut backup = crate::backup::test_writer("hive-mend-untrusted");
        let outcome = repair(
            &mut reg,
            &mut MemoryFs::new(),
            &[uninstall_finding("Open"), uninstall_finding("Closed")],
            &mut backup,
        )
        .unwrap();
        let _ = std::fs::remove_file(backup.path());
        assert!(reg.values(&format!(r"{base}\Open\Deep")).is_ok(), "changed");
        assert!(reg.values(&format!(r"{base}\Closed")).is_err());
        assert_eq!(outcome.applied, 1);
        // A restore into such a key changes nothing at all.
        let ops = vec![
            crate::regfile::RegOp::CreateKey(format!(r"{base}\New")),
            crate::regfile::RegOp::CreateKey(format!(r"{base}\Open\Deep\Below")),
        ];
        assert!(crate::regfile::apply_ops(&mut reg, &ops).is_err());
        assert!(reg.values(&format!(r"{base}\New")).is_err());
    }

    #[test]
    fn a_key_that_appears_during_removal_stops_it() {
        let base = r"HKEY_LOCAL_MACHINE\SOFTWARE\Test";
        let mut reg = MemoryRegistry::new();
        reg.set_sz(&format!(r"{base}\Tree"), "x", "1");
        {
            let mut tx = reg.begin().unwrap();
            let expected = vec![crate::pathutil::canonical_path(&format!(r"{base}\Tree"))];
            // A child that was not there when the tree was recorded.
            tx.set_value(&format!(r"{base}\Tree\Late"), "y", &ValueKind::Dword(1))
                .unwrap();
            assert!(
                tx.delete_tree_exact(&format!(r"{base}\Tree"), &expected)
                    .is_err()
            );
        }
        assert!(reg.values(&format!(r"{base}\Tree")).is_ok());
    }

    #[test]
    fn without_registry_transactions_nothing_is_removed() {
        // A registry that cannot offer transactions: scan-only.
        struct NoTx(MemoryRegistry);
        impl Registry for NoTx {
            fn subkeys(&self, path: &str) -> Result<Vec<String>, RegError> {
                self.0.subkeys(path)
            }
            fn values(&self, path: &str) -> Result<Vec<RegValue>, RegError> {
                self.0.values(path)
            }
            fn delete_value(&mut self, path: &str, name: &str) -> Result<(), RegError> {
                self.0.delete_value(path, name)
            }
            fn delete_tree(&mut self, path: &str) -> Result<(), RegError> {
                self.0.delete_tree(path)
            }
        }
        let base = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        let mut inner = MemoryRegistry::new();
        inner.set_sz(&format!(r"{base}\Stale"), "DisplayName", "Stale");
        let mut reg = NoTx(inner);
        let mut backup = crate::backup::test_writer("hive-mend-no-tx");
        let outcome = repair(
            &mut reg,
            &mut MemoryFs::new(),
            &[uninstall_finding("Stale")],
            &mut backup,
        )
        .unwrap();
        assert_eq!(outcome.applied, 0);
        assert!(reg.0.values(&format!(r"{base}\Stale")).is_ok());
        let _ = std::fs::remove_file(backup.path());
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
        let mut backup = crate::backup::test_writer("hive-mend-locked-test");
        let findings = [uninstall_finding("Readable"), uninstall_finding("Locked")];
        let outcome = repair(&mut reg, &mut MemoryFs::new(), &findings, &mut backup).unwrap();
        assert_eq!(outcome.applied, 1);
        assert_eq!(outcome.not_backed_up, 1);
        assert!(reg.inner.subkeys(&format!(r"{base}\Locked")).is_ok());
        assert!(reg.inner.values(&format!(r"{base}\Readable")).is_err());
        let _ = std::fs::remove_file(backup.path());
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
    backup: &mut BackupWriter,
) -> Result<RepairOutcome, Error> {
    repair_with_progress(reg, fs, findings, backup, &mut |_, _| {})
}

/// Removes each finding, recording it in `backup` first.
/// `progress(done, total)` runs after each finding.
///
/// Each registry finding is removed in its own registry transaction: its
/// keys are touched first, its backup section is read through the
/// transaction and flushed to disk, then it is deleted and committed. If
/// anything else changes those keys meanwhile, the commit fails and nothing
/// is removed. Where transactions are not available, registry findings are
/// left alone (scan-only); there is no fallback to an ordinary delete.
pub fn repair_with_progress(
    reg: &mut dyn Registry,
    fs: &mut dyn FileView,
    findings: &[Finding],
    backup: &mut BackupWriter,
    progress: &mut dyn FnMut(usize, usize),
) -> Result<RepairOutcome, Error> {
    // The header and the shortcut copies' lines go first; registry entries
    // are appended one by one as each is removed.
    let files: Vec<Finding> = findings
        .iter()
        .filter(|finding| matches!(finding.repair, Repair::DeleteFile { .. }))
        .cloned()
        .collect();
    let plan = export_backup(reg, &files, backup.path());
    backup.append(&plan.body)?;
    let mut outcome = RepairOutcome {
        backup_file: backup.path().to_path_buf(),
        ..RepairOutcome::default()
    };
    let mut stopped: Option<String> = None;
    for (index, finding) in findings.iter().enumerate() {
        if let Some(why) = stopped.take() {
            // Everything after a failed backup write is left alone.
            outcome.errors.push(why);
            outcome.not_backed_up += findings.len() - index;
            break;
        }
        let applied = match &finding.repair {
            Repair::DeleteValue { key, .. } if is_protected_key(key) => Applied::Refused,
            Repair::DeleteKey { key } if !key_delete_allowed(key) => Applied::Refused,
            Repair::DeleteValue { .. } | Repair::DeleteKey { .. } => {
                match delete_in_transaction(reg, &finding.repair, backup, index + 1) {
                    Ok(Deleted::Removed) => Applied::Removed,
                    Ok(Deleted::AlreadyGone) => Applied::AlreadyGone,
                    Ok(Deleted::NotBackedUp) => Applied::NotBackedUp,
                    Ok(Deleted::TooLarge) => {
                        outcome.errors.push(format!(
                            "{}: left alone; its backup would be larger than a restore accepts",
                            finding.key
                        ));
                        Applied::NotBackedUp
                    }
                    Ok(Deleted::BackupFailed(why)) => {
                        stopped = Some(format!(
                            "the backup could not be written ({why}), so the repair stopped; nothing more was changed"
                        ));
                        Applied::NotBackedUp
                    }
                    Ok(Deleted::RemovedUnconfirmed(why)) => {
                        stopped = Some(format!(
                            "{}: removed, but its backup record could not be completed ({why}); its saved data is in the backup as entry {}, which a restore lists but does not put back by itself. The repair stopped",
                            finding.key,
                            index + 1
                        ));
                        Applied::Removed
                    }
                    Err(err) => reg_result(Err(err)),
                }
            }
            _ => apply(reg, fs, finding, &plan),
        };
        match applied {
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
    if let Some(why) = stopped {
        outcome.errors.push(why);
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

/// What one transactional registry removal did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Deleted {
    Removed,
    AlreadyGone,
    /// Its backup section could not be read in full, or would not restore;
    /// nothing was removed.
    NotBackedUp,
    /// Its section would make the backup larger than a restore accepts;
    /// nothing was removed.
    TooLarge,
    /// The backup could not be written; nothing was removed, and the job
    /// stops here.
    BackupFailed(String),
    /// Removed, but the line confirming it could not be written, so a
    /// restore will not put it back by itself; the job stops here.
    RemovedUnconfirmed(String),
}

/// Remove one registry target (`DeleteKey` or `DeleteValue`) in its own
/// transaction, recording it in `backup` as entry `entry`: touch every key
/// it covers (refusing any an administrator must not change), export its
/// section through the transaction, check that the section reads back as a
/// restore would read it, append and flush it, delete exactly the keys
/// touched, commit, and only then append `; entry N removed`. A restore
/// puts back only confirmed entries, so a run that stops at any point
/// never offers back data that was not removed. On any failure the
/// transaction rolls back. Callers check their own safety rules
/// (protected keys) before calling.
pub(crate) fn delete_in_transaction(
    reg: &mut dyn Registry,
    repair: &Repair,
    backup: &mut BackupWriter,
    entry: usize,
) -> Result<Deleted, RegError> {
    let (key, tree) = match repair {
        Repair::DeleteKey { key } => (key.as_str(), true),
        Repair::DeleteValue { key, .. } => (key.as_str(), false),
        Repair::DeleteFile { .. } | Repair::None => return Ok(Deleted::NotBackedUp),
    };
    if backup.has_failed() {
        return Ok(Deleted::BackupFailed(
            "an earlier write to the backup failed".into(),
        ));
    }
    let mut tx = reg.begin()?;
    let mut touched = Vec::new();
    match touch_all(&mut *tx, key, tree, 0, &mut touched) {
        Ok(()) => {}
        Err(RegError::NotFound) => return Ok(Deleted::AlreadyGone),
        // Part of it cannot be read, so it could not be backed up anyway.
        Err(_)
            if !registry_sections(&*tx, std::slice::from_ref(repair))
                .1
                .is_empty() =>
        {
            return Ok(Deleted::NotBackedUp);
        }
        Err(err) => return Err(err),
    }
    let (section, unreadable) = registry_sections(&*tx, std::slice::from_ref(repair));
    if !unreadable.is_empty() || !reads_back(&section) {
        return Ok(Deleted::NotBackedUp);
    }
    match backup.append(&format!("\r\n; entry {entry}\r\n{section}")) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::FileTooLarge => {
            return Ok(Deleted::TooLarge);
        }
        Err(err) => return Ok(Deleted::BackupFailed(err.to_string())),
    }
    let deleted = match repair {
        Repair::DeleteKey { key } => tx.delete_tree_exact(key, &touched),
        Repair::DeleteValue { key, name } => tx.delete_value(key, name),
        Repair::DeleteFile { .. } | Repair::None => Ok(()),
    };
    // Lines saying an entry was not removed are only for people reading
    // the file: an unconfirmed entry is never restored anyway.
    let not_removed = |backup: &mut BackupWriter| {
        let _ = backup.append(&format!("; entry {entry} was not removed\r\n"));
    };
    match deleted {
        Ok(()) => {}
        Err(RegError::NotFound) => {
            not_removed(backup);
            return Ok(Deleted::AlreadyGone);
        }
        Err(err) => {
            not_removed(backup);
            return Err(err);
        }
    }
    if let Err(err) = tx.commit() {
        not_removed(backup);
        return Err(err);
    }
    match backup.append(&format!("; entry {entry} removed\r\n")) {
        Ok(()) => Ok(Deleted::Removed),
        Err(err) => Ok(Deleted::RemovedUnconfirmed(err.to_string())),
    }
}

/// True when `section` reads back, through the restore's own parser, as
/// at least one change: the backup will put back what it is about to stand
/// for.
fn reads_back(section: &str) -> bool {
    let probe = format!(
        "Windows Registry Editor Version 5.00\r\n\r\n{}\r\n; entry 1\r\n{section}; entry 1 removed\r\n",
        crate::regfile::FORMAT_2
    );
    crate::regfile::parse_backup(&probe)
        .is_ok_and(|parsed| !parsed.ops.is_empty() && parsed.unconfirmed.is_empty())
}

/// Touch `key` and, for a tree, every key below it, so a change to any of
/// them from elsewhere fails the transaction's commit; `touched` receives
/// each key, the set the delete may remove and nothing more.
fn touch_all(
    tx: &mut dyn RegTransaction,
    key: &str,
    tree: bool,
    depth: usize,
    touched: &mut Vec<String>,
) -> Result<(), RegError> {
    if depth > 512 {
        return Err(RegError::Message(format!("{key} is nested too deeply")));
    }
    tx.require_trusted(key)?;
    tx.touch(key)?;
    touched.push(crate::pathutil::canonical_path(key));
    if tree {
        for child in tx.subkeys(key)? {
            touch_all(tx, &format!("{key}\\{child}"), true, depth + 1, touched)?;
        }
    }
    Ok(())
}

fn apply(
    reg: &mut dyn Registry,
    fs: &mut dyn FileView,
    finding: &Finding,
    plan: &BackupPlan,
) -> Applied {
    match &finding.repair {
        Repair::None => Applied::Refused,
        // Registry removals happen only in delete_in_transaction.
        Repair::DeleteValue { .. } | Repair::DeleteKey { .. } => {
            let _ = reg;
            Applied::Refused
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
    // A shortcut kept as a copy is taken so nothing else can write, rename,
    // or delete it, and its length is read again through that hold.
    let access = if copy.is_some() {
        Access::ReadDeleteExclusive
    } else {
        Access::Delete
    };
    if let Err(err) = fs.pin_acquire(&mut pin, access) {
        return Applied::Failed {
            denied: err.contains("os error 5") || err.contains("os error 32"),
            message: err,
        };
    }
    // The copy holds the main data stream only; a file with any named
    // stream (the download marker included) could not be put back whole,
    // so it is left alone. Checked through the held handle.
    if copy.is_some() && fs.pin_named_streams(&pin) != Ok(false) {
        return Applied::NotBackedUp;
    }
    if let Some(copy) = copy {
        let len = pin.len;
        if let Err(err) = fs.pin_copy_to(&pin, copy) {
            return Applied::Failed {
                message: format!("could not save a copy first: {err}"),
                denied: false,
            };
        }
        // Deleted only while still exactly what was copied.
        return match fs.pin_delete_unchanged(pin, len) {
            Ok(()) => Applied::Removed,
            Err(err) if err.contains("changed while") => Applied::NotBackedUp,
            Err(err) => Applied::Failed {
                denied: err.contains("os error 5"),
                message: err,
            },
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

/// Live Windows test: a stale-file repair whose path runs through a junction
/// into System32 is refused by the object's real path. The target,
/// ntoskrnl.exe, is owned by TrustedInstaller, so even an elevated run could
/// not change it if the check regressed.
#[cfg(all(test, windows))]
mod live_tests {
    use super::*;
    use crate::fs::{HostFs, KnownDir, host_known_dir};
    use crate::model::ScannerId;
    use crate::registry::MemoryRegistry;

    #[test]
    fn live_a_temp_path_through_a_junction_into_system32_is_refused() {
        let system = host_known_dir(KnownDir::System).unwrap();
        let victim = Path::new(&system).join("ntoskrnl.exe");
        let before = std::fs::metadata(&victim).expect("ntoskrnl.exe metadata");
        let dir = std::env::temp_dir().join(format!("hivemend-junction-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let link = dir.join("j");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&system)
            .output()
            .expect("run mklink");
        let spelled = link.join("ntoskrnl.exe").display().to_string();
        let finding = Finding {
            scanner: ScannerId::TempShortcuts,
            scanner_name: "Temp files".into(),
            key: spelled.clone(),
            value: None,
            detail: "temporary file".into(),
            repair: Repair::DeleteFile {
                path: spelled,
                keep_copy: false,
            },
        };
        let mut backup = crate::backup::BackupWriter::reserve(&dir, "backup").unwrap();
        let outcome = repair(
            &mut MemoryRegistry::new(),
            &mut HostFs,
            std::slice::from_ref(&finding),
            &mut backup,
        );
        // remove_dir_all removes the junction itself, never its target.
        let _ = std::fs::remove_dir_all(&dir);
        assert!(made.status.success(), "mklink /J failed: {made:?}");
        let outcome = outcome.expect("repair runs");
        assert_eq!(outcome.applied, 0);
        assert_eq!(outcome.refused, 1, "errors: {:?}", outcome.errors);
        let after = std::fs::metadata(&victim).unwrap();
        assert_eq!(before.len(), after.len());
        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
    }
}
