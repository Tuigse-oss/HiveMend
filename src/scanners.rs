use crate::fs::{FileView, ItemKind};
use crate::ignore::IgnoreDb;
use crate::lnk::lnk_target;
use crate::model::{
    Finding, PathKind, RegValue, Repair, RulePath, ScannerDef, ScannerId, ValueKind,
};
use crate::pathutil::{
    bare_name_present, canonical_path, expand_env, file_delete_allowed, file_present, hive_views,
    is_protected_key, key_delete_allowed, looks_like_stored_path, paths_in_command, system_root,
    under_windows_dir,
};
use crate::registry::{RegError, Registry};

const DEEP_VALUE_BUDGET: usize = 20_000;
const DEEP_FINDING_CAP: usize = 500;
const TEMP_FINDING_CAP: usize = 2_000;
/// A day, so files that a running installer or app still needs are left alone.
const TEMP_MIN_AGE_SECS: u64 = 86_400;

pub struct ScanCtx<'a> {
    pub reg: &'a dyn Registry,
    pub fs: &'a dyn FileView,
    pub ignore: &'a IgnoreDb,
    pub wow64: bool,
    pub warnings: &'a mut Vec<String>,
}

pub fn run_scanner(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    deep_roots: &[String],
    findings: &mut Vec<Finding>,
) {
    scan_typed_rules(ctx, scanner, findings);
    match scanner.id {
        ScannerId::SoftwareLocations => app_paths(ctx, scanner, findings),
        ScannerId::RegistryIntegrity => shell_folders(ctx, scanner, findings),
        ScannerId::WindowsFonts => fonts(ctx, scanner, findings),
        ScannerId::HelpResources => help_files(ctx, scanner, findings),
        ScannerId::SharedDlls => shared_dlls(ctx, scanner, findings),
        ScannerId::StartupPrograms => startup(ctx, scanner, findings),
        ScannerId::AddRemovePrograms => uninstall(ctx, scanner, findings),
        ScannerId::VirtualDevices => virtual_devices(ctx, scanner, findings),
        ScannerId::FileExtensions => file_extensions(ctx, scanner, findings),
        ScannerId::TempShortcuts => temp_and_shortcuts(ctx, scanner, findings),
        ScannerId::CustomControls => custom_controls(ctx, scanner, findings),
        ScannerId::DeepScan => deep_scan(ctx, scanner, deep_roots, findings),
    }
}

fn app_paths(ctx: &mut ScanCtx<'_>, scanner: &ScannerDef, findings: &mut Vec<Finding>) {
    for root in each_view(&inherited_paths(scanner), ctx.wow64) {
        for name in read_subkeys(ctx, &root) {
            let key = format!("{root}\\{name}");
            if skip_key(ctx, &key) {
                continue;
            }
            let paths = texts(&read_values(ctx, &key))
                .into_iter()
                .flat_map(|text| paths_in_command(&text))
                .collect::<Vec<_>>();
            if let Some(missing) = every_outside_path_missing(ctx, &paths) {
                push_key(findings, scanner, &key, format!("missing {missing}"));
            }
        }
    }
}

fn shell_folders(ctx: &mut ScanCtx<'_>, scanner: &ScannerDef, findings: &mut Vec<Finding>) {
    for root in each_view(&inherited_paths(scanner), ctx.wow64) {
        for value in read_values(ctx, &root) {
            if value.name.starts_with('!') {
                continue;
            }
            let Some(text) = value.data.as_text() else {
                continue;
            };
            let expanded = expand_env(ctx.fs, text.trim());
            if expanded.is_empty() || expanded.contains('%') || skip_text(ctx, &expanded) {
                continue;
            }
            if ctx.fs.is_dir(&expanded) {
                continue;
            }
            findings.push(make(
                scanner,
                &root,
                Some(value.name),
                format!("shell folder is missing {expanded}"),
                Repair::None,
            ));
        }
    }
}

fn fonts(ctx: &mut ScanCtx<'_>, scanner: &ScannerDef, findings: &mut Vec<Finding>) {
    let fonts_dir = format!("{}\\Fonts", system_root(ctx.fs));
    for root in each_view(&inherited_paths(scanner), ctx.wow64) {
        for value in read_values(ctx, &root) {
            let Some(text) = value.data.as_text() else {
                continue;
            };
            let file = expand_env(ctx.fs, &font_file(&fonts_dir, text));
            if file.contains('%') || skip_text(ctx, &file) || file_present(ctx.fs, &file) {
                continue;
            }
            push_value(
                findings,
                scanner,
                &root,
                &value.name,
                format!("missing font {file}"),
            );
        }
    }
}

fn help_files(ctx: &mut ScanCtx<'_>, scanner: &ScannerDef, findings: &mut Vec<Finding>) {
    for root in each_view(&inherited_paths(scanner), ctx.wow64) {
        for value in read_values(ctx, &root) {
            let Some(text) = value.data.as_text() else {
                continue;
            };
            for path in paths_in_command(text) {
                let expanded = expand_env(ctx.fs, &path);
                if expanded.contains('%')
                    || skip_text(ctx, &expanded)
                    || file_present(ctx.fs, &expanded)
                {
                    continue;
                }
                push_value(
                    findings,
                    scanner,
                    &root,
                    &value.name,
                    format!("missing help file {expanded}"),
                );
                break;
            }
        }
    }
}

fn shared_dlls(ctx: &mut ScanCtx<'_>, scanner: &ScannerDef, findings: &mut Vec<Finding>) {
    for root in each_view(&inherited_paths(scanner), ctx.wow64) {
        for value in read_values(ctx, &root) {
            let path = value.name.trim().trim_matches('"');
            if path.is_empty() || skip_text(ctx, path) {
                continue;
            }
            let expanded = expand_env(ctx.fs, path);
            if expanded.contains('%')
                || under_windows_dir(ctx.fs, &expanded)
                || file_present(ctx.fs, &expanded)
            {
                continue;
            }
            push_value(
                findings,
                scanner,
                &root,
                &value.name,
                format!("missing shared file {expanded}"),
            );
        }
    }
}

fn startup(ctx: &mut ScanCtx<'_>, scanner: &ScannerDef, findings: &mut Vec<Finding>) {
    for root in each_view(&inherited_paths(scanner), ctx.wow64) {
        for value in startup_values(&root, &read_values(ctx, &root)) {
            let Some(text) = value.data.as_text() else {
                continue;
            };
            if text.trim().is_empty() || skip_text(ctx, text) {
                continue;
            }
            let paths = paths_in_command(text);
            let missing = missing_outside(ctx, &paths);
            if missing.is_empty() {
                continue;
            }
            push_value(
                findings,
                scanner,
                &root,
                &value.name,
                format!("missing {}", missing.join(", ")),
            );
        }
    }
}

fn uninstall(ctx: &mut ScanCtx<'_>, scanner: &ScannerDef, findings: &mut Vec<Finding>) {
    for root in each_view(&inherited_paths(scanner), ctx.wow64) {
        if root.to_ascii_lowercase().ends_with("\\installer\\folders") {
            installer_folders(ctx, scanner, &root, findings);
            continue;
        }
        for name in read_subkeys(ctx, &root) {
            if is_kb(&name) {
                continue;
            }
            let key = format!("{root}\\{name}");
            if skip_key(ctx, &key) {
                continue;
            }
            let values = read_values(ctx, &key);
            if dword(&values, "SystemComponent") == Some(1)
                || dword(&values, "WindowsInstaller") == Some(1)
            {
                continue;
            }
            if text_value(&values, "ParentKeyName").is_some_and(|text| !text.trim().is_empty()) {
                continue;
            }
            let mut paths = Vec::new();
            for name in [
                "DisplayIcon",
                "UninstallString",
                "QuietUninstallString",
                "InstallLocation",
                "InstallSource",
            ] {
                if let Some(text) = text_value(&values, name) {
                    paths.extend(paths_in_command(&text));
                }
            }
            if let Some(missing) = every_outside_path_missing(ctx, &paths) {
                push_key(
                    findings,
                    scanner,
                    &key,
                    format!("orphaned install, missing {missing}"),
                );
            }
        }
    }
}

fn installer_folders(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for value in read_values(ctx, root) {
        let path = value.name.trim().trim_end_matches('\\');
        if !looks_like_stored_path(path) || skip_text(ctx, path) {
            continue;
        }
        let expanded = expand_env(ctx.fs, path);
        if expanded.contains('%')
            || under_windows_dir(ctx.fs, &expanded)
            || ctx.fs.is_dir(&expanded)
        {
            continue;
        }
        push_value(
            findings,
            scanner,
            root,
            &value.name,
            format!("installer folder is missing {expanded}"),
        );
    }
}

fn virtual_devices(ctx: &mut ScanCtx<'_>, scanner: &ScannerDef, findings: &mut Vec<Finding>) {
    for root in each_view(&inherited_paths(scanner), ctx.wow64) {
        let lower = root.to_ascii_lowercase();
        if lower.ends_with("\\services\\vxd") {
            for name in read_subkeys(ctx, &root) {
                let key = format!("{root}\\{name}");
                let values = read_values(ctx, &key);
                let mut paths = Vec::new();
                for value in &values {
                    if let Some(text) = value.data.as_text() {
                        paths.extend(paths_in_command(text));
                    }
                }
                let missing = missing_outside(ctx, &paths);
                if missing.is_empty() {
                    continue;
                }
                let repair = if key_delete_allowed(&key) {
                    Repair::DeleteKey { key: key.clone() }
                } else {
                    Repair::None
                };
                findings.push(make(
                    scanner,
                    &key,
                    None,
                    format!("missing virtual device {}", missing.join(", ")),
                    repair,
                ));
            }
            continue;
        }
        for value in read_values(ctx, &root) {
            let Some(text) = value.data.as_text() else {
                continue;
            };
            let missing = missing_outside(ctx, &paths_in_command(text));
            if missing.is_empty() {
                continue;
            }
            push_value(
                findings,
                scanner,
                &root,
                &value.name,
                format!("missing virtual device {}", missing.join(", ")),
            );
        }
    }
}

fn file_extensions(ctx: &mut ScanCtx<'_>, scanner: &ScannerDef, findings: &mut Vec<Finding>) {
    let roots = [
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts",
        r"HKEY_CURRENT_USER\Software\Classes",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Classes",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes",
    ];
    for root in roots {
        let root = canonical_path(root);
        if root.to_ascii_lowercase().ends_with("\\fileexts") {
            scan_file_exts(ctx, scanner, &root, findings);
        } else {
            scan_class_commands(ctx, scanner, &root, findings);
        }
    }
}

fn scan_file_exts(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for ext in read_subkeys(ctx, root) {
        let list = format!("{root}\\{ext}\\OpenWithList");
        for value in read_values(ctx, &list) {
            if value.name.eq_ignore_ascii_case("MRUList") {
                continue;
            }
            let Some(text) = value.data.as_text() else {
                continue;
            };
            let text = text.trim();
            if text.is_empty() || skip_text(ctx, text) {
                continue;
            }
            let present = if text.contains('\\') || text.contains(':') {
                let paths = paths_in_command(text);
                paths.is_empty() || missing_outside(ctx, &paths).is_empty()
            } else if !text.to_ascii_lowercase().ends_with(".exe") {
                // Store app ids such as `Microsoft.WindowsNotepad_8wekyb3d8bbwe!App`.
                true
            } else {
                !application_known_missing(ctx, text)
            };
            if present {
                continue;
            }
            push_value(
                findings,
                scanner,
                &list,
                &value.name,
                format!("open-with target {text} is missing"),
            );
        }
        let progids_key = format!("{root}\\{ext}\\OpenWithProgids");
        for value in read_values(ctx, &progids_key) {
            if value.name.is_empty() || value.name.eq_ignore_ascii_case("MRUList") {
                continue;
            }
            if progid_registered(ctx, &value.name) {
                continue;
            }
            push_value(
                findings,
                scanner,
                &progids_key,
                &value.name,
                format!("open-with program {} is not registered", value.name),
            );
        }
    }
}

fn scan_class_commands(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for name in read_subkeys(ctx, root) {
        if !name.starts_with('.') {
            continue;
        }
        let ext_key = format!("{root}\\{name}");
        check_command(
            ctx,
            scanner,
            &format!("{ext_key}\\shell\\open\\command"),
            findings,
        );
        let values = read_values(ctx, &ext_key);
        if let Some(progid) = text_value(&values, "") {
            let progid = progid.trim();
            if !progid.is_empty() && !progid.contains('\\') && !progid.contains('%') {
                check_command(
                    ctx,
                    scanner,
                    &format!("{root}\\{progid}\\shell\\open\\command"),
                    findings,
                );
            }
        }
    }
}

fn check_command(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    key: &str,
    findings: &mut Vec<Finding>,
) {
    if skip_key(ctx, key) {
        return;
    }
    let values = read_values(ctx, key);
    let Some(text) = text_value(&values, "") else {
        return;
    };
    let paths = paths_in_command(&text);
    let missing = missing_outside(ctx, &paths);
    if missing.is_empty() {
        return;
    }
    push_value(
        findings,
        scanner,
        key,
        "",
        format!("open command is missing {}", missing.join(", ")),
    );
}

fn temp_and_shortcuts(ctx: &mut ScanCtx<'_>, scanner: &ScannerDef, findings: &mut Vec<Finding>) {
    let mut dirs = Vec::new();
    if let Some(appdata) = ctx.fs.var("APPDATA") {
        dirs.push(format!(
            "{appdata}\\Microsoft\\Windows\\Start Menu\\Programs"
        ));
    }
    if let Some(program_data) = ctx.fs.var("ProgramData") {
        dirs.push(format!(
            "{program_data}\\Microsoft\\Windows\\Start Menu\\Programs"
        ));
    }
    let mut shortcut_findings = 0usize;
    for dir in &dirs {
        scan_shortcut_tree(ctx, scanner, dir, 0, &mut shortcut_findings, findings);
    }
    for dir in desktop_dirs(ctx) {
        scan_shortcut_tree(ctx, scanner, &dir, 8, &mut shortcut_findings, findings);
    }

    let mut temp_dirs = Vec::new();
    if let Some(temp) = ctx.fs.var("TEMP") {
        temp_dirs.push(temp);
    }
    if let Some(tmp) = ctx.fs.var("TMP")
        && !temp_dirs.iter().any(|have| have.eq_ignore_ascii_case(&tmp))
    {
        temp_dirs.push(tmp);
    }
    let mut temp_findings = 0usize;
    for dir in temp_dirs {
        for item in ctx.fs.list(&dir) {
            if temp_findings >= TEMP_FINDING_CAP || item.kind != ItemKind::File {
                continue;
            }
            if item.name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            if item
                .age
                .is_some_and(|age| age.as_secs() < TEMP_MIN_AGE_SECS)
            {
                continue;
            }
            let path = format!("{dir}\\{}", item.name);
            if !file_delete_allowed(&path) {
                continue;
            }
            push_file(findings, scanner, &path, "temporary file".into(), false);
            temp_findings += 1;
        }
    }
}

fn custom_controls(ctx: &mut ScanCtx<'_>, scanner: &ScannerDef, findings: &mut Vec<Finding>) {
    let roots = [
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID",
        r"HKEY_CURRENT_USER\Software\Classes\CLSID",
    ];
    for root in roots {
        let root = canonical_path(root);
        for guid in read_subkeys(ctx, &root) {
            let key = format!("{root}\\{guid}");
            if findings.iter().any(|finding| {
                finding.scanner == ScannerId::CustomControls
                    && finding.key.eq_ignore_ascii_case(&key)
            }) {
                continue;
            }
            let mut missing = None;
            let mut present = false;
            for leaf in ["InprocServer32", "LocalServer32"] {
                let values = read_values(ctx, &format!("{key}\\{leaf}"));
                let Some(text) = text_value(&values, "") else {
                    continue;
                };
                if text.trim().is_empty() {
                    continue;
                }
                match server_missing(ctx, &text) {
                    Some(path) => {
                        missing.get_or_insert(path);
                    }
                    None => present = true,
                }
            }
            // A class with one working server still works. Only flag it when
            // every server it names is gone.
            if present {
                continue;
            }
            if let Some(missing) = missing {
                push_key(
                    findings,
                    scanner,
                    &key,
                    format!("missing control {missing}"),
                );
            }
        }
    }
}

fn deep_scan(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    roots: &[String],
    findings: &mut Vec<Finding>,
) {
    let before = findings.len();
    let mut budget = DEEP_VALUE_BUDGET;
    for root in each_view(roots, ctx.wow64) {
        walk_deep(ctx, scanner, &root, 0, &mut budget, findings);
        if findings.len() - before >= DEEP_FINDING_CAP || budget == 0 {
            ctx.warnings
                .push("deep scan stopped at its safety limit".into());
            break;
        }
    }
}

fn walk_deep(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    path: &str,
    depth: usize,
    budget: &mut usize,
    findings: &mut Vec<Finding>,
) {
    if *budget == 0 || findings.len() >= DEEP_FINDING_CAP || depth > 6 || skip_key(ctx, path) {
        return;
    }
    if is_protected_key(path) {
        return;
    }
    for value in read_values(ctx, path) {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let Some(text) = value.data.as_text() else {
            continue;
        };
        if !looks_like_stored_path(text) || skip_text(ctx, text) {
            continue;
        }
        let extracted = paths_in_command(text);
        let candidates = if extracted.is_empty() {
            vec![text.to_string()]
        } else {
            extracted
        };
        for candidate in candidates {
            let expanded = expand_env(ctx.fs, &candidate);
            if expanded.contains('%')
                || under_windows_dir(ctx.fs, &expanded)
                || file_present(ctx.fs, &expanded)
            {
                continue;
            }
            let repair = if is_protected_key(path) {
                Repair::None
            } else {
                Repair::DeleteValue {
                    key: path.to_string(),
                    name: value.name.clone(),
                }
            };
            findings.push(make(
                scanner,
                path,
                Some(value.name.clone()),
                format!("missing {expanded}"),
                repair,
            ));
            if findings.len() >= DEEP_FINDING_CAP {
                return;
            }
        }
    }
    if depth == 6 {
        return;
    }
    for child in read_subkeys(ctx, path) {
        walk_deep(
            ctx,
            scanner,
            &format!("{path}\\{child}"),
            depth + 1,
            budget,
            findings,
        );
    }
}

fn every_outside_path_missing(ctx: &ScanCtx<'_>, paths: &[String]) -> Option<String> {
    if paths.is_empty() {
        return None;
    }
    let mut saw_outside = false;
    let mut first_missing = None;
    for path in paths {
        let expanded = expand_env(ctx.fs, path);
        if expanded.contains('%') || skip_text(ctx, &expanded) {
            return None;
        }
        if under_windows_dir(ctx.fs, &expanded) {
            if file_present(ctx.fs, &expanded) {
                return None;
            }
            continue;
        }
        saw_outside = true;
        if file_present(ctx.fs, &expanded) || ctx.fs.is_dir(&expanded) {
            return None;
        }
        if first_missing.is_none() {
            first_missing = Some(expanded);
        }
    }
    if saw_outside { first_missing } else { None }
}

fn missing_outside(ctx: &ScanCtx<'_>, paths: &[String]) -> Vec<String> {
    let mut missing = Vec::new();
    for path in paths {
        let expanded = expand_env(ctx.fs, path);
        if expanded.contains('%')
            || skip_text(ctx, &expanded)
            || under_windows_dir(ctx.fs, &expanded)
            || file_present(ctx.fs, &expanded)
            || ctx.fs.is_dir(&expanded)
        {
            continue;
        }
        missing.push(expanded);
    }
    missing
}

fn startup_values<'a>(key: &str, values: &'a [RegValue]) -> Vec<&'a RegValue> {
    let lower = key.to_ascii_lowercase();
    if lower.contains("\\windows nt\\") && lower.ends_with("\\windows") {
        values
            .iter()
            .filter(|value| {
                value.name.eq_ignore_ascii_case("load") || value.name.eq_ignore_ascii_case("run")
            })
            .collect()
    } else {
        values.iter().collect()
    }
}

fn font_file(fonts_dir: &str, text: &str) -> String {
    let text = text.trim().trim_matches('"');
    let file = text.split(',').next().unwrap_or(text).trim();
    if file.contains('\\') || file.contains('%') || file.len() > 2 && file.as_bytes()[1] == b':' {
        file.to_string()
    } else {
        format!("{fonts_dir}\\{file}")
    }
}

fn texts(values: &[RegValue]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| value.data.as_text().map(str::to_string))
        .collect()
}

fn text_value(values: &[RegValue], name: &str) -> Option<String> {
    values.iter().find_map(|value| {
        if value.name.eq_ignore_ascii_case(name) {
            value.data.as_text().map(str::to_string)
        } else {
            None
        }
    })
}

fn dword(values: &[RegValue], name: &str) -> Option<u32> {
    values.iter().find_map(|value| {
        if value.name.eq_ignore_ascii_case(name) {
            match value.data {
                ValueKind::Dword(data) => Some(data),
                _ => None,
            }
        } else {
            None
        }
    })
}

fn is_kb(name: &str) -> bool {
    let rest = name.get(2..).unwrap_or("");
    name.len() > 2
        && name[..2].eq_ignore_ascii_case("KB")
        && !rest.is_empty()
        && rest.chars().all(|ch| ch.is_ascii_digit())
}

fn desktop_dirs(ctx: &ScanCtx<'_>) -> Vec<String> {
    let mut dirs = Vec::new();
    if let Some(profile) = ctx.fs.var("USERPROFILE") {
        dirs.push(format!("{profile}\\Desktop"));
        dirs.push(format!("{profile}\\OneDrive\\Desktop"));
    }
    if let Some(public) = ctx.fs.var("PUBLIC") {
        dirs.push(format!("{public}\\Desktop"));
    }
    dirs
}

fn scan_shortcut_tree(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    dir: &str,
    depth: usize,
    count: &mut usize,
    findings: &mut Vec<Finding>,
) {
    if depth > 8 || *count >= 2_000 {
        return;
    }
    let items = ctx.fs.list(dir);
    for item in items {
        if *count >= 2_000 {
            return;
        }
        let path = format!("{dir}\\{}", item.name);
        if item.kind == ItemKind::Dir {
            scan_shortcut_tree(ctx, scanner, &path, depth + 1, count, findings);
            continue;
        }
        if item.kind != ItemKind::File || !item.name.to_ascii_lowercase().ends_with(".lnk") {
            continue;
        }
        let Some(bytes) = ctx.fs.read(&path) else {
            continue;
        };
        let Some(target) = lnk_target(&bytes) else {
            continue;
        };
        let expanded = expand_env(ctx.fs, &target);
        if expanded.contains('%')
            || under_windows_dir(ctx.fs, &expanded)
            || file_present(ctx.fs, &expanded)
        {
            continue;
        }
        push_file(
            findings,
            scanner,
            &path,
            format!("shortcut target {expanded} is missing"),
            true,
        );
        *count += 1;
    }
}

fn inherited_paths(scanner: &ScannerDef) -> Vec<String> {
    scanner
        .paths
        .iter()
        .filter(|path| path.kind == PathKind::Inherited)
        .map(|path| path.path.clone())
        .collect()
}

fn scan_typed_rules(ctx: &mut ScanCtx<'_>, scanner: &ScannerDef, findings: &mut Vec<Finding>) {
    let typed: Vec<RulePath> = scanner
        .paths
        .iter()
        .filter(|path| path.kind != PathKind::Inherited)
        .cloned()
        .collect();
    for rule in typed {
        for root in hive_views(&rule.path, ctx.wow64) {
            match rule.kind {
                PathKind::Inherited => {}
                PathKind::ValueNamePath => scan_named_paths(ctx, scanner, &root, false, findings),
                PathKind::MuiCache => scan_named_paths(ctx, scanner, &root, true, findings),
                PathKind::StartupApproved => scan_startup_approved(ctx, scanner, &root, findings),
                PathKind::AssociationToast => {
                    scan_association_toasts(ctx, scanner, &root, findings)
                }
                PathKind::ShellCommand => scan_shell_commands(ctx, scanner, &root, findings),
                PathKind::ShellHandler => scan_shell_handlers(ctx, scanner, &root, findings),
                PathKind::ClsidKey => scan_clsid_keys(ctx, scanner, &root, findings),
                PathKind::IeExtension => scan_ie_extensions(ctx, scanner, &root, findings),
                PathKind::TypeLib => scan_typelib(ctx, scanner, &root, findings),
                PathKind::DefaultIcon => scan_default_icons(ctx, scanner, &root, findings),
                PathKind::Applications => scan_applications(ctx, scanner, &root, findings),
                PathKind::SoundEvent => scan_sound_events(ctx, scanner, &root, findings),
                PathKind::ArpCache => scan_arp_cache(ctx, scanner, &root, findings),
                PathKind::StartMenuClient => scan_start_menu_clients(ctx, scanner, &root, findings),
                PathKind::UserAssist => scan_userassist(ctx, scanner, &root, findings),
                PathKind::PathValue => scan_path_values(ctx, scanner, &root, 0, findings),
                PathKind::UrlProtocol => scan_url_protocols(ctx, scanner, &root, findings),
                PathKind::ClsidValue => scan_clsid_values(ctx, scanner, &root, findings),
                PathKind::Autoplay => scan_autoplay(ctx, scanner, &root, findings),
                PathKind::Codec => scan_codecs(ctx, scanner, &root, findings),
                PathKind::AppInit => scan_appinit(ctx, scanner, &root, findings),
                PathKind::CommandAutorun => scan_command_autorun(ctx, scanner, &root, findings),
                PathKind::InstallerSource => scan_installer_sources(ctx, scanner, &root, findings),
                PathKind::FirewallRule => scan_firewall_rules(ctx, scanner, &root, findings),
            }
        }
    }
}

fn scan_named_paths(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    mui_cache: bool,
    findings: &mut Vec<Finding>,
) {
    for value in read_values(ctx, root) {
        let Some(path) = named_file_path(&value.name, mui_cache) else {
            continue;
        };
        if skip_text(ctx, &path) || skip_key(ctx, root) {
            continue;
        }
        let expanded = expand_env(ctx.fs, &path);
        if expanded.contains('%')
            || under_windows_dir(ctx.fs, &expanded)
            || file_present(ctx.fs, &expanded)
            || ctx.fs.is_dir(&expanded)
        {
            continue;
        }
        push_value(
            findings,
            scanner,
            root,
            &value.name,
            format!("missing {expanded}"),
        );
    }
}

fn named_file_path(name: &str, mui_cache: bool) -> Option<String> {
    let mut path = name.trim().trim_matches('"').to_string();
    if mui_cache {
        let lower = path.to_ascii_lowercase();
        for suffix in [".friendlyappname", ".applicationcompany"] {
            if lower.ends_with(suffix) {
                path.truncate(path.len() - suffix.len());
                break;
            }
        }
    }
    if looks_like_stored_path(&path) {
        Some(path)
    } else {
        None
    }
}

fn scan_startup_approved(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    let lower = root.to_ascii_lowercase();
    for value in read_values(ctx, root) {
        if value.name.is_empty() {
            continue;
        }
        let alive = if lower.ends_with("\\startupfolder") {
            startup_shortcut_exists(ctx, &value.name)
        } else if lower.ends_with("\\run32") {
            named_value_exists(
                ctx,
                r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                &value.name,
            )
        } else {
            named_value_exists(
                ctx,
                r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
                &value.name,
            ) || named_value_exists(
                ctx,
                r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                &value.name,
            )
        };
        if alive {
            continue;
        }
        push_value(
            findings,
            scanner,
            root,
            &value.name,
            format!("startup approval for {} has no startup entry", value.name),
        );
    }
}

fn startup_shortcut_exists(ctx: &mut ScanCtx<'_>, name: &str) -> bool {
    let mut dirs = Vec::new();
    if let Some(appdata) = ctx.fs.var("APPDATA") {
        dirs.push(format!(
            "{appdata}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        ));
    }
    if let Some(program_data) = ctx.fs.var("ProgramData") {
        dirs.push(format!(
            "{program_data}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        ));
    }
    dirs.iter().any(|dir| {
        ctx.fs
            .list(dir)
            .iter()
            .any(|item| item.kind == ItemKind::File && item.name.eq_ignore_ascii_case(name))
    })
}

fn named_value_exists(ctx: &mut ScanCtx<'_>, key: &str, name: &str) -> bool {
    read_values(ctx, key)
        .iter()
        .any(|value| value.name.eq_ignore_ascii_case(name))
}

fn scan_association_toasts(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for value in read_values(ctx, root) {
        let name = value.name.trim();
        if name.is_empty() || toast_is_store(name) {
            continue;
        }
        let stale = if let Some(exe) = applications_exe(name) {
            !application_registered(ctx, &exe)
        } else if let Some((progid, _)) = name.split_once("_.") {
            !progid.is_empty() && !progid.contains('\\') && !progid_registered(ctx, progid)
        } else {
            false
        };
        if stale {
            push_value(
                findings,
                scanner,
                root,
                name,
                format!("file association {name} has no registered program"),
            );
        }
    }
}

fn toast_is_store(name: &str) -> bool {
    let left = name.split_once("_.").map(|(left, _)| left).unwrap_or(name);
    left.to_ascii_lowercase().starts_with("appx")
}

fn applications_exe(name: &str) -> Option<String> {
    let rest = name
        .strip_prefix("Applications\\")
        .or_else(|| name.strip_prefix("applications\\"))?;
    let exe = rest.split_once("_.").map(|(exe, _)| exe).unwrap_or(rest);
    if exe.is_empty() {
        None
    } else {
        Some(exe.to_string())
    }
}

fn application_registered(ctx: &mut ScanCtx<'_>, exe: &str) -> bool {
    if exe.contains('\\') || exe.contains(':') {
        return file_present(ctx.fs, exe);
    }
    if bare_name_present(ctx.fs, exe) {
        return true;
    }
    let file = if exe.to_ascii_lowercase().ends_with(".exe") {
        exe.to_string()
    } else {
        format!("{exe}.exe")
    };
    // A registration counts when the program it points at is still there, or
    // when it names no program that could be checked.
    let app_paths = [
        format!(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\App Paths\{file}"),
        format!(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{file}"),
        format!(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\{file}"
        ),
    ];
    let applications = [
        format!(r"HKEY_CURRENT_USER\Software\Classes\Applications\{file}"),
        format!(r"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Applications\{file}"),
    ];
    let registered = |ctx: &mut ScanCtx<'_>, key: &str, target: &str| {
        let values = read_values(ctx, key);
        if values.is_empty() && read_subkeys(ctx, key).is_empty() {
            return false;
        }
        match text_value(&read_values(ctx, target), "") {
            Some(text) if !text.trim().is_empty() => missing_paths(ctx, &text).is_empty(),
            _ => true,
        }
    };
    app_paths.iter().any(|key| registered(ctx, key, key))
        || applications
            .iter()
            .any(|key| registered(ctx, key, &format!("{key}\\shell\\open\\command")))
}

/// A bare program name is only known to be gone when Windows has a
/// registration for it and every registration points at a missing file.
/// Store apps and programs picked with "Browse" have no registration at all,
/// so an unregistered name proves nothing.
fn application_known_missing(ctx: &mut ScanCtx<'_>, exe: &str) -> bool {
    if bare_name_present(ctx.fs, exe) {
        return false;
    }
    let targets = [
        format!(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\App Paths\{exe}"),
        format!(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe}"),
        format!(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\{exe}"
        ),
        format!(r"HKEY_CURRENT_USER\Software\Classes\Applications\{exe}\shell\open\command"),
        format!(r"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Applications\{exe}\shell\open\command"),
    ];
    let mut missing = 0;
    for key in targets {
        let Some(text) = text_value(&read_values(ctx, &key), "") else {
            continue;
        };
        if text.trim().is_empty() || missing_paths(ctx, &text).is_empty() {
            return false;
        }
        missing += 1;
    }
    missing > 0
}

fn progid_registered(ctx: &mut ScanCtx<'_>, progid: &str) -> bool {
    [
        format!(r"HKEY_CURRENT_USER\Software\Classes\{progid}"),
        format!(r"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\{progid}"),
        format!(r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\{progid}"),
    ]
    .iter()
    .any(|key| !read_values(ctx, key).is_empty() || !read_subkeys(ctx, key).is_empty())
}

fn scan_shell_commands(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for verb in read_subkeys(ctx, root) {
        check_command(ctx, scanner, &format!("{root}\\{verb}\\command"), findings);
    }
}

fn scan_shell_handlers(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for name in read_subkeys(ctx, root) {
        let key = format!("{root}\\{name}");
        let values = read_values(ctx, &key);
        let clsid = text_value(&values, "")
            .filter(|text| looks_like_clsid(text))
            .or_else(|| looks_like_clsid(&name).then(|| name.clone()));
        let Some(clsid) = clsid else {
            continue;
        };
        if let Some(missing) = broken_server(ctx, &clsid) {
            push_key(
                findings,
                scanner,
                &key,
                format!("shell handler {name} is missing {missing}"),
            );
        }
    }
}

fn scan_clsid_keys(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for name in read_subkeys(ctx, root) {
        if !looks_like_clsid(&name) {
            continue;
        }
        let key = format!("{root}\\{name}");
        if let Some(missing) = broken_server(ctx, &name) {
            push_key(
                findings,
                scanner,
                &key,
                format!("shell class {name} is missing {missing}"),
            );
        }
    }
}

fn scan_ie_extensions(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for name in read_subkeys(ctx, root) {
        let key = format!("{root}\\{name}");
        let values = read_values(ctx, &key);
        for field in ["Exec", "Script"] {
            let Some(text) = text_value(&values, field) else {
                continue;
            };
            let missing = missing_outside(ctx, &paths_in_command(&text));
            if missing.is_empty() {
                continue;
            }
            push_key(
                findings,
                scanner,
                &key,
                format!("browser extension is missing {}", missing.join(", ")),
            );
            break;
        }
    }
}

fn looks_like_clsid(text: &str) -> bool {
    let text = text.trim().trim_matches('"');
    text.starts_with('{') && text.ends_with('}') && text.len() == 38
}

fn broken_server(ctx: &mut ScanCtx<'_>, clsid: &str) -> Option<String> {
    let clsid = clsid.trim().trim_matches('"');
    let roots = [
        format!(r"HKEY_CURRENT_USER\Software\Classes\CLSID\{clsid}"),
        format!(r"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{clsid}"),
        format!(r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{clsid}"),
    ];
    let mut missing = None;
    let mut present = false;
    for root in roots {
        for leaf in ["InprocServer32", "LocalServer32"] {
            let values = read_values(ctx, &format!("{root}\\{leaf}"));
            let Some(text) = text_value(&values, "") else {
                continue;
            };
            if text.trim().is_empty() {
                continue;
            }
            match server_missing(ctx, &text) {
                Some(path) => {
                    missing.get_or_insert(path);
                }
                None => present = true,
            }
        }
    }
    if present { None } else { missing }
}

/// The server binary of an `InprocServer32` or `LocalServer32` value, when it
/// is verifiably gone. Values look like `"C:\x\app.exe" /Automation`,
/// `%ProgramFiles%\x\app.dll`, or a bare `mscoree.dll`.
fn server_missing(ctx: &ScanCtx<'_>, text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() || skip_text(ctx, text) {
        return None;
    }
    let paths = paths_in_command(text);
    if let Some(first) = paths.first() {
        return missing_outside(ctx, std::slice::from_ref(first))
            .into_iter()
            .next();
    }
    let first = text
        .split_whitespace()
        .next()
        .unwrap_or(text)
        .trim_matches('"');
    if first.contains(['\\', '/', ':', '%']) || !first.contains('.') {
        return None;
    }
    if bare_name_present(ctx.fs, first) {
        None
    } else {
        Some(first.to_string())
    }
}

fn scan_typelib(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for guid in read_subkeys(ctx, root) {
        if !looks_like_clsid(&guid) {
            continue;
        }
        let guid_key = format!("{root}\\{guid}");
        for version in read_subkeys(ctx, &guid_key) {
            let version_key = format!("{guid_key}\\{version}");
            typelib_platform(ctx, scanner, &format!("{version_key}\\win32"), findings);
            typelib_platform(ctx, scanner, &format!("{version_key}\\win64"), findings);
            for locale in read_subkeys(ctx, &version_key) {
                let lower = locale.to_ascii_lowercase();
                if matches!(lower.as_str(), "win32" | "win64" | "flags" | "helpdir") {
                    continue;
                }
                typelib_platform(
                    ctx,
                    scanner,
                    &format!("{version_key}\\{locale}\\win32"),
                    findings,
                );
                typelib_platform(
                    ctx,
                    scanner,
                    &format!("{version_key}\\{locale}\\win64"),
                    findings,
                );
            }
        }
    }
}

fn typelib_platform(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    key: &str,
    findings: &mut Vec<Finding>,
) {
    let values = read_values(ctx, key);
    let Some(text) = text_value(&values, "") else {
        return;
    };
    let missing = missing_paths(ctx, &text);
    if missing.is_empty() {
        return;
    }
    push_value(
        findings,
        scanner,
        key,
        "",
        format!("type library is missing {}", missing.join(", ")),
    );
}

fn scan_default_icons(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for name in read_subkeys(ctx, root) {
        let key = format!("{root}\\{name}\\DefaultIcon");
        let text = text_value(&read_values(ctx, &key), "").unwrap_or_default();
        flag_path_text(ctx, scanner, findings, &key, "", &text, "default icon");
    }
}

fn scan_applications(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for name in read_subkeys(ctx, root) {
        check_command(
            ctx,
            scanner,
            &format!("{root}\\{name}\\shell\\open\\command"),
            findings,
        );
        let icon = format!("{root}\\{name}\\DefaultIcon");
        let text = text_value(&read_values(ctx, &icon), "").unwrap_or_default();
        flag_path_text(ctx, scanner, findings, &icon, "", &text, "default icon");
    }
}

fn scan_sound_events(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for app in read_subkeys(ctx, root) {
        let app_key = format!("{root}\\{app}");
        for event in read_subkeys(ctx, &app_key) {
            let key = format!("{app_key}\\{event}\\.Current");
            let Some(text) = text_value(&read_values(ctx, &key), "") else {
                continue;
            };
            let trimmed = text.trim();
            if trimmed.is_empty() || trimmed.eq_ignore_ascii_case(".none") {
                continue;
            }
            flag_path_text(ctx, scanner, findings, &key, "", trimmed, "sound file");
        }
    }
}

fn scan_arp_cache(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for name in read_subkeys(ctx, root) {
        if is_kb(&name) || uninstall_key_exists(ctx, &name) {
            continue;
        }
        let key = format!("{root}\\{name}");
        let values = read_values(ctx, &key);
        if values.iter().any(|value| path_still_present(ctx, value)) {
            continue;
        }
        push_key(
            findings,
            scanner,
            &key,
            format!("add/remove cache {name} has no uninstall entry"),
        );
    }
}

fn uninstall_key_exists(ctx: &mut ScanCtx<'_>, name: &str) -> bool {
    [
        format!(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{name}"),
        format!(r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{name}"),
        format!(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\{name}"),
    ]
    .iter()
    .any(|key| !read_values(ctx, key).is_empty() || !read_subkeys(ctx, key).is_empty())
}

fn path_still_present(ctx: &ScanCtx<'_>, value: &RegValue) -> bool {
    let mut texts = Vec::new();
    if let Some(text) = value.data.as_text() {
        texts.push(text.to_string());
    }
    if looks_like_stored_path(&value.name) {
        texts.push(value.name.clone());
    }
    texts.into_iter().any(|text| {
        missing_paths(ctx, &text).is_empty()
            && (paths_in_command(&text).iter().any(|path| {
                let expanded = expand_env(ctx.fs, path);
                !expanded.contains('%')
                    && (file_present(ctx.fs, &expanded) || ctx.fs.is_dir(&expanded))
            }) || {
                let expanded = expand_env(ctx.fs, &text);
                looks_like_stored_path(&expanded)
                    && (file_present(ctx.fs, &expanded) || ctx.fs.is_dir(&expanded))
            })
    })
}

fn scan_start_menu_clients(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for name in read_subkeys(ctx, root) {
        let key = format!("{root}\\{name}");
        let command = format!("{key}\\shell\\open\\command");
        let Some(text) = text_value(&read_values(ctx, &command), "") else {
            continue;
        };
        let Some(missing) = every_outside_path_missing(ctx, &paths_in_command(&text)) else {
            continue;
        };
        push_key(
            findings,
            scanner,
            &key,
            format!("browser {name} is missing {missing}"),
        );
    }
}

fn scan_userassist(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    let counts = if root.to_ascii_lowercase().ends_with("\\count") {
        vec![root.to_string()]
    } else {
        read_subkeys(ctx, root)
            .into_iter()
            .map(|guid| format!("{root}\\{guid}\\Count"))
            .collect()
    };
    for count in counts {
        for value in read_values(ctx, &count) {
            let Some(path) = userassist_path(&value.name) else {
                continue;
            };
            let missing = missing_paths(ctx, &path);
            if missing.is_empty() {
                continue;
            }
            push_value(
                findings,
                scanner,
                &count,
                &value.name,
                format!("run history is missing {}", missing.join(", ")),
            );
        }
    }
}

fn userassist_path(name: &str) -> Option<String> {
    let decoded = rot13(name);
    let lower = decoded.to_ascii_lowercase();
    if lower.starts_with("ueme_ctlsession")
        || lower.starts_with("ueme_uiqcut")
        || lower.starts_with("ueme_uiscut")
    {
        return None;
    }
    let rest = decoded
        .strip_prefix("UEME_RUNPATH:")
        .or_else(|| decoded.strip_prefix("UEME_RUNPIDL:"))
        .unwrap_or(decoded.as_str())
        .trim();
    if looks_like_stored_path(rest) {
        Some(rest.to_string())
    } else {
        None
    }
}

fn rot13(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            'A'..='Z' => char::from(b'A' + (ch as u8 - b'A' + 13) % 26),
            'a'..='z' => char::from(b'a' + (ch as u8 - b'a' + 13) % 26),
            _ => ch,
        })
        .collect()
}

fn scan_path_values(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    depth: usize,
    findings: &mut Vec<Finding>,
) {
    if depth > 1 || root.to_ascii_lowercase().contains("\\policies\\") {
        return;
    }
    let values = read_values(ctx, root);
    for value in values {
        let Some(text) = value.data.as_text().map(str::to_string) else {
            continue;
        };
        let name = value.name.clone();
        flag_path_text(ctx, scanner, findings, root, &name, &text, "stored path");
    }
    if depth == 1 {
        return;
    }
    for child in read_subkeys(ctx, root) {
        scan_path_values(
            ctx,
            scanner,
            &format!("{root}\\{child}"),
            depth + 1,
            findings,
        );
    }
}

fn scan_url_protocols(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for name in read_subkeys(ctx, root) {
        let lower = name.to_ascii_lowercase();
        if lower.starts_with('.')
            || lower.starts_with('{')
            || lower.starts_with('*')
            || lower.starts_with("ms-")
        {
            continue;
        }
        const SKIP: &[&str] = &[
            "clsid",
            "typelib",
            "interface",
            "appid",
            "applications",
            "record",
            "wow6432node",
            "local settings",
            "activatableclasses",
            "allfilesystemobjects",
            "directory",
            "drive",
            "folder",
            "unknown",
            "systemfileassociations",
            "http",
            "https",
            "ftp",
            "file",
            "mailto",
            "search",
            "search-ms",
        ];
        if SKIP.contains(&lower.as_str()) {
            continue;
        }
        check_command(
            ctx,
            scanner,
            &format!("{root}\\{name}\\shell\\open\\command"),
            findings,
        );
    }
}

fn scan_clsid_values(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for value in read_values(ctx, root) {
        let clsid = if looks_like_clsid(&value.name) {
            Some(value.name.clone())
        } else {
            value
                .data
                .as_text()
                .map(str::trim)
                .filter(|text| looks_like_clsid(text))
                .map(str::to_string)
        };
        let Some(clsid) = clsid else {
            continue;
        };
        if let Some(missing) = broken_server(ctx, &clsid) {
            push_value(
                findings,
                scanner,
                root,
                &value.name,
                format!("handler {clsid} is missing {missing}"),
            );
        }
    }
}

fn scan_autoplay(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for name in read_subkeys(ctx, root) {
        let key = format!("{root}\\{name}");
        let values = read_values(ctx, &key);
        let Some(icon) = text_value(&values, "DefaultIcon") else {
            continue;
        };
        let missing = missing_paths(ctx, &icon);
        if missing.is_empty() {
            continue;
        }
        push_key(
            findings,
            scanner,
            &key,
            format!("autoplay handler {name} is missing {}", missing.join(", ")),
        );
    }
}

fn scan_codecs(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for value in read_values(ctx, root) {
        let Some(text) = value.data.as_text().map(str::trim).map(str::to_string) else {
            continue;
        };
        if text.is_empty() {
            continue;
        }
        let lower = text.to_ascii_lowercase();
        let missing = if text.contains('\\') || text.contains(':') || text.contains('%') {
            missing_paths(ctx, &text)
        } else if lower.ends_with(".dll") || lower.ends_with(".drv") {
            if bare_name_present(ctx.fs, &text) {
                Vec::new()
            } else {
                vec![text.clone()]
            }
        } else {
            Vec::new()
        };
        if missing.is_empty() {
            continue;
        }
        push_value(
            findings,
            scanner,
            root,
            &value.name,
            format!("codec is missing {}", missing.join(", ")),
        );
    }
}

fn scan_appinit(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    let values = read_values(ctx, root);
    let Some(text) = text_value(&values, "AppInit_DLLs") else {
        return;
    };
    let parts: Vec<String> = text
        .split([',', ';'])
        .map(|part| part.trim().trim_matches('"').to_string())
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        return;
    }
    let missing: Vec<String> = parts
        .iter()
        .filter(|part| dll_missing(ctx, part))
        .cloned()
        .collect();
    if missing.len() != parts.len() {
        return;
    }
    push_value(
        findings,
        scanner,
        root,
        "AppInit_DLLs",
        format!("AppInit DLLs are missing {}", missing.join(", ")),
    );
}

fn dll_missing(ctx: &ScanCtx<'_>, text: &str) -> bool {
    if text.contains('\\') || text.contains(':') || text.contains('%') {
        !missing_paths(ctx, text).is_empty()
    } else {
        !bare_name_present(ctx.fs, text)
    }
}

fn scan_command_autorun(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    let values = read_values(ctx, root);
    let Some(text) = text_value(&values, "Autorun") else {
        return;
    };
    flag_path_text(
        ctx,
        scanner,
        findings,
        root,
        "Autorun",
        &text,
        "command autorun",
    );
}

fn scan_installer_sources(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    // Windows Installer owns this data. Removing a source or cached package
    // value can break repair and uninstall of the product, so these entries
    // are reported and never changed.
    for sid in read_subkeys(ctx, root) {
        let products = format!("{root}\\{sid}\\Products");
        for product in read_subkeys(ctx, &products) {
            let props = format!("{products}\\{product}\\InstallProperties");
            let values = read_values(ctx, &props);
            for field in ["InstallSource", "LastUsedSource", "LocalPackage"] {
                let Some(text) = text_value(&values, field) else {
                    continue;
                };
                let missing = missing_paths(ctx, &text);
                if missing.is_empty() {
                    continue;
                }
                findings.push(make(
                    scanner,
                    &props,
                    Some(field.to_string()),
                    format!("installer source is missing {}", missing.join(", ")),
                    Repair::None,
                ));
            }
        }
    }
}

fn scan_firewall_rules(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    root: &str,
    findings: &mut Vec<Finding>,
) {
    for value in read_values(ctx, root) {
        let Some(text) = value.data.as_text() else {
            continue;
        };
        let Some(app) = firewall_app(text) else {
            continue;
        };
        let missing = missing_paths(ctx, &app);
        if missing.is_empty() {
            continue;
        }
        push_value(
            findings,
            scanner,
            root,
            &value.name,
            format!("firewall rule is missing {}", missing.join(", ")),
        );
    }
}

fn firewall_app(text: &str) -> Option<String> {
    text.split('|').find_map(|part| {
        let part = part.trim();
        let (name, value) = part.split_once('=')?;
        if name.eq_ignore_ascii_case("App") {
            let value = value.trim().trim_matches('"');
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        } else {
            None
        }
    })
}

fn flag_path_text(
    ctx: &mut ScanCtx<'_>,
    scanner: &ScannerDef,
    findings: &mut Vec<Finding>,
    key: &str,
    value: &str,
    text: &str,
    label: &str,
) {
    if text.trim().is_empty() {
        return;
    }
    let missing = missing_paths(ctx, text);
    if missing.is_empty() {
        return;
    }
    push_value(
        findings,
        scanner,
        key,
        value,
        format!("{label} is missing {}", missing.join(", ")),
    );
}

fn missing_paths(ctx: &ScanCtx<'_>, text: &str) -> Vec<String> {
    let mut paths = paths_in_command(text);
    if paths.is_empty() && looks_like_stored_path(text) {
        paths.push(text.trim().trim_matches('"').to_string());
    }
    missing_outside(ctx, &paths)
}

fn each_view(paths: &[String], wow64: bool) -> Vec<String> {
    let mut views = Vec::new();
    for path in paths {
        for view in hive_views(path, wow64) {
            if !views
                .iter()
                .any(|have: &String| have.eq_ignore_ascii_case(&view))
            {
                views.push(view);
            }
        }
    }
    views
}

fn skip_key(ctx: &ScanCtx<'_>, path: &str) -> bool {
    ctx.ignore.skips_key(path)
}

fn skip_text(ctx: &ScanCtx<'_>, text: &str) -> bool {
    ctx.ignore.skips_value(text)
}

fn read_subkeys(ctx: &mut ScanCtx<'_>, path: &str) -> Vec<String> {
    let result = ctx.reg.subkeys(path);
    match result {
        Ok(keys) => keys,
        Err(RegError::NotFound) => Vec::new(),
        Err(err) => {
            ctx.warnings.push(format!("{path}: {err}"));
            Vec::new()
        }
    }
}

fn read_values(ctx: &mut ScanCtx<'_>, path: &str) -> Vec<RegValue> {
    let result = ctx.reg.values(path);
    match result {
        Ok(values) => values,
        Err(RegError::NotFound) => Vec::new(),
        Err(err) => {
            ctx.warnings.push(format!("{path}: {err}"));
            Vec::new()
        }
    }
}

fn push_key(findings: &mut Vec<Finding>, scanner: &ScannerDef, key: &str, detail: String) {
    let repair = if key_delete_allowed(key) {
        Repair::DeleteKey {
            key: canonical_path(key),
        }
    } else {
        Repair::None
    };
    findings.push(make(scanner, key, None, detail, repair));
}

fn push_value(
    findings: &mut Vec<Finding>,
    scanner: &ScannerDef,
    key: &str,
    name: &str,
    detail: String,
) {
    let repair = if is_protected_key(key) {
        Repair::None
    } else {
        Repair::DeleteValue {
            key: canonical_path(key),
            name: name.to_string(),
        }
    };
    findings.push(make(scanner, key, Some(name.to_string()), detail, repair));
}

fn push_file(
    findings: &mut Vec<Finding>,
    scanner: &ScannerDef,
    path: &str,
    detail: String,
    keep_copy: bool,
) {
    let repair = if file_delete_allowed(path) {
        Repair::DeleteFile {
            path: path.to_string(),
            keep_copy,
        }
    } else {
        Repair::None
    };
    findings.push(Finding {
        scanner: scanner.id,
        scanner_name: scanner.name.clone(),
        key: path.to_string(),
        value: None,
        detail,
        repair,
    });
}

fn make(
    scanner: &ScannerDef,
    key: &str,
    value: Option<String>,
    detail: String,
    repair: Repair,
) -> Finding {
    Finding {
        scanner: scanner.id,
        scanner_name: scanner.name.clone(),
        key: canonical_path(key),
        value,
        detail,
        repair,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Engine, scan};
    use crate::fs::MemoryFs;
    use crate::model::ScanOptions;
    use crate::registry::MemoryRegistry;

    #[test]
    fn windows_10_and_11_rules_ignore_live_entries() {
        let mut fs = MemoryFs::new();
        fs.set_var("SystemRoot", r"C:\Windows");
        fs.set_var("APPDATA", r"C:\Users\Ada\AppData\Roaming");
        fs.set_var("ProgramData", r"C:\ProgramData");
        fs.add_file(r"C:\Program Files\Keep\keep.exe");
        fs.add_file(
            r"C:\Users\Ada\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\keep.lnk",
        );

        let mut reg = MemoryRegistry::new();
        reg.set_sz(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\keep.exe",
            "",
            r"C:\Program Files\Keep\keep.exe",
        );
        reg.set_sz(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "Keep",
            r"C:\Program Files\Keep\keep.exe",
        );
        let approved =
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
        reg.set(approved, "Keep", ValueKind::Binary(vec![2, 0, 0, 0]));
        reg.set(approved, "Ghost", ValueKind::Binary(vec![3, 0, 0, 0]));
        let folder = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";
        reg.set(folder, "keep.lnk", ValueKind::Binary(vec![2, 0, 0, 0]));
        reg.set(folder, "ghost.lnk", ValueKind::Binary(vec![3, 0, 0, 0]));

        reg.set_sz(
            r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
            r"C:\Missing\layer.exe",
            "WIN8RTM",
        );
        reg.set_sz(
            r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
            r"C:\Program Files\Keep\keep.exe",
            "WIN8RTM",
        );
        reg.set(
            r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
            r"C:\Missing\store.exe",
            ValueKind::Binary(vec![1]),
        );
        reg.set_sz(
            r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
            r"C:\Missing\mui.exe.FriendlyAppName",
            "Old",
        );
        reg.set_dword(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
            r"C:\Missing\switched.exe",
            4,
        );
        reg.set_dword(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch",
            r"C:\Missing\launch.exe",
            2,
        );

        let toasts = r"HKCU\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts";
        reg.set_dword(toasts, r"Applications\gone.exe_.txt", 0);
        reg.set_dword(toasts, r"Applications\keep.exe_.txt", 0);
        reg.set_dword(toasts, r"AppXabc_.txt", 0);

        reg.set_sz(
            r"HKCU\Software\Classes\*\shell\Old\command",
            "",
            r"C:\Missing\menu.exe %1",
        );
        reg.set_sz(
            r"HKCU\Software\Classes\*\shell\Keep\command",
            "",
            r"C:\Program Files\Keep\keep.exe %1",
        );
        reg.set_sz(
            r"HKCU\Software\Classes\*\shellex\ContextMenuHandlers\Old",
            "",
            "{11111111-1111-1111-1111-111111111111}",
        );
        reg.set_sz(
            r"HKCU\Software\Classes\CLSID\{11111111-1111-1111-1111-111111111111}\InprocServer32",
            "",
            r"C:\Missing\menu.dll",
        );
        reg.set_sz(
            r"HKCU\Software\Classes\*\shellex\ContextMenuHandlers\Builtin",
            "",
            "{22222222-2222-2222-2222-222222222222}",
        );
        reg.set_sz(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\Old",
            "",
            "{44444444-4444-4444-4444-444444444444}",
        );
        reg.set_sz(
            r"HKLM\SOFTWARE\Classes\CLSID\{44444444-4444-4444-4444-444444444444}\InprocServer32",
            "",
            r"C:\Missing\overlay.dll",
        );
        reg.set_sz(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{33333333-3333-3333-3333-333333333333}",
            "",
            "Old BHO",
        );
        reg.set_sz(
            r"HKLM\SOFTWARE\Classes\CLSID\{33333333-3333-3333-3333-333333333333}\InprocServer32",
            "",
            r"C:\Missing\bho.dll",
        );
        reg.set_sz(
            r"HKLM\SOFTWARE\Microsoft\Internet Explorer\Extensions\{55555555-5555-5555-5555-555555555555}",
            "Exec",
            r"C:\Missing\button.exe",
        );

        let report = scan(
            &Engine::try_builtin().unwrap(),
            &reg,
            &fs,
            &ScanOptions::default(),
        );
        let text = report
            .findings
            .iter()
            .map(|finding| {
                format!(
                    "{} {}",
                    finding.value.as_deref().unwrap_or(""),
                    finding.detail
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        for needle in [
            "Ghost",
            "ghost.lnk",
            r"C:\Missing\layer.exe",
            r"C:\Missing\store.exe",
            r"C:\Missing\mui.exe",
            r"C:\Missing\switched.exe",
            r"C:\Missing\launch.exe",
            "gone.exe",
            r"C:\Missing\menu.exe",
            "shell handler Old",
            "overlay.dll",
            "bho.dll",
            "button.exe",
        ] {
            assert!(text.contains(needle), "missing {needle} in:\n{text}");
        }
        for absent in [
            "AppXabc",
            "Builtin",
            r"Program Files\Keep",
            "startup approval for Keep",
        ] {
            assert!(!text.contains(absent), "unexpected {absent} in:\n{text}");
        }
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.value.as_deref() != Some("Keep"))
        );
    }

    #[test]
    fn extra_cleaner_rules_keep_live_windows_entries() {
        let mut fs = MemoryFs::new();
        fs.set_var("SystemRoot", r"C:\Windows");
        fs.set_var("APPDATA", r"C:\Users\Ada\AppData\Roaming");
        fs.set_var("ProgramData", r"C:\ProgramData");
        fs.add_file(r"C:\Program Files\Keep\keep.exe");
        fs.add_file(r"C:\Users\Ada\Pictures\wall.jpg");
        fs.add_file_bytes(
            r"C:\Users\Ada\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Games\old.lnk",
            crate::lnk::sample_lnk(r"C:\Missing\game.exe"),
            None,
        );
        fs.add_file_bytes(
            r"C:\Users\Ada\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Games\keep.lnk",
            crate::lnk::sample_lnk(r"C:\Program Files\Keep\keep.exe"),
            None,
        );

        let mut reg = MemoryRegistry::new();
        let old_lib = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}";
        let live_lib = "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}";
        reg.set_sz(
            &format!(r"HKLM\SOFTWARE\Classes\TypeLib\{old_lib}\1.0\0\win32"),
            "",
            r"C:\Missing\old.tlb",
        );
        reg.set_sz(
            &format!(r"HKLM\SOFTWARE\Classes\TypeLib\{live_lib}\1.0\0\win32"),
            "",
            r"C:\Windows\System32\stdole2.tlb",
        );
        reg.set_sz(
            r"HKCU\Software\Classes\Old.App\DefaultIcon",
            "",
            r"C:\Missing\old.exe,0",
        );
        reg.set_sz(
            r"HKCU\Software\Classes\Keep.App\DefaultIcon",
            "",
            r"C:\Program Files\Keep\keep.exe,0",
        );
        reg.set_sz(
            r"HKCU\Software\Classes\Applications\old.exe\shell\open\command",
            "",
            r"C:\Missing\old.exe",
        );
        reg.set_sz(
            r"HKCU\Software\Classes\Applications\keep.exe\shell\open\command",
            "",
            r"C:\Program Files\Keep\keep.exe",
        );
        reg.set_sz(
            r"HKCU\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current",
            "",
            r"C:\Missing\ding.wav",
        );
        reg.set_sz(
            r"HKCU\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current",
            "",
            r"C:\Windows\Media\notify.wav",
        );
        reg.set_sz(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Keep",
            "DisplayName",
            "Keep",
        );
        let cache = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Management\ARPCache";
        reg.set_sz(&format!(r"{cache}\Keep"), "DisplayName", "Keep");
        reg.set_sz(&format!(r"{cache}\OldApp"), "DisplayName", "Old");
        reg.set_sz(
            &format!(r"{cache}\StillThere"),
            "InstallLocation",
            r"C:\Program Files\Keep",
        );
        reg.set_sz(
            r"HKLM\SOFTWARE\Clients\StartMenuInternet\OldBrowser\shell\open\command",
            "",
            r"C:\Missing\oldbrowser.exe",
        );
        reg.set_sz(
            r"HKLM\SOFTWARE\Clients\StartMenuInternet\Live\shell\open\command",
            "",
            r"C:\Program Files\Keep\keep.exe",
        );
        let count = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count";
        reg.set(
            count,
            &rot13(r"C:\Missing\assisted.exe"),
            ValueKind::Binary(vec![1]),
        );
        reg.set(
            count,
            &rot13(r"C:\Program Files\Keep\keep.exe"),
            ValueKind::Binary(vec![1]),
        );
        reg.set(count, "HRZR_PGYFRFFVBA", ValueKind::Binary(vec![1]));
        reg.set_sz(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers",
            "BackgroundHistoryPath0",
            r"C:\Missing\wall.jpg",
        );
        reg.set_sz(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers",
            "BackgroundHistoryPath1",
            r"C:\Users\Ada\Pictures\wall.jpg",
        );
        reg.set_sz(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen",
            "Image",
            r"C:\Missing\lock.jpg",
        );
        reg.set_sz(
            r"HKCU\Software\Classes\oldapp\shell\open\command",
            "",
            r"C:\Missing\oldapp.exe",
        );
        reg.set_sz(
            r"HKCU\Software\Classes\http\shell\open\command",
            "",
            r"C:\Missing\http.exe",
        );
        reg.set_sz(
            r"HKCU\Software\Classes\ms-settings\shell\open\command",
            "",
            r"C:\Missing\settings.exe",
        );

        let report = scan(
            &Engine::try_builtin().unwrap(),
            &reg,
            &fs,
            &ScanOptions::default(),
        );
        let text = report
            .findings
            .iter()
            .map(|finding| {
                format!(
                    "{} {} {}",
                    finding.key,
                    finding.value.as_deref().unwrap_or(""),
                    finding.detail
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        for needle in [
            r"C:\Missing\old.tlb",
            r"C:\Missing\old.exe",
            r"C:\Missing\ding.wav",
            "OldApp",
            "OldBrowser",
            r"C:\Missing\assisted.exe",
            r"C:\Missing\wall.jpg",
            r"C:\Missing\lock.jpg",
            r"C:\Missing\oldapp.exe",
            r"C:\Missing\game.exe",
        ] {
            assert!(text.contains(needle), "missing {needle} in:\n{text}");
        }
        for absent in [
            "stdole2.tlb",
            "notify.wav",
            "http.exe",
            "settings.exe",
            r"Pictures\wall.jpg",
            r"Programs\Games\keep.lnk",
            "HRZR_PGYFRFFVBA",
        ] {
            assert!(!text.contains(absent), "unexpected {absent} in:\n{text}");
        }
        assert!(report.findings.iter().all(|finding| {
            let key = finding.key.to_ascii_lowercase();
            !key.ends_with("\\keep") && !key.ends_with("\\stillthere") && !key.ends_with("\\live")
        }));
    }

    #[test]
    fn community_leftovers_keep_live_handlers() {
        let mut fs = MemoryFs::new();
        fs.set_var("SystemRoot", r"C:\Windows");
        fs.add_file(r"C:\Windows\System32\msvc.dll");
        fs.add_file(r"C:\Program Files\Keep\keep.exe");

        let mut reg = MemoryRegistry::new();
        let dead = "{11111111-1111-1111-1111-111111111111}";
        let quiet = "{22222222-2222-2222-2222-222222222222}";
        reg.set_sz(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
            dead,
            "",
        );
        reg.set_sz(
            &format!(r"HKLM\SOFTWARE\Classes\CLSID\{dead}\InprocServer32"),
            "",
            r"C:\Missing\hook.dll",
        );
        reg.set_sz(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
            quiet,
            "built in",
        );
        reg.set_sz(
            r"HKLM\SOFTWARE\Clients\Mail\OldMail\shell\open\command",
            "",
            r"C:\Missing\mail.exe",
        );
        reg.set_sz(
            r"HKLM\SOFTWARE\Clients\Mail\Live\shell\open\command",
            "",
            r"C:\Program Files\Keep\keep.exe",
        );
        reg.set_sz(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "AppInit_DLLs",
            r"C:\Missing\inject.dll",
        );
        let rules = r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
        reg.set_sz(
            rules,
            "OldApp",
            r"v2.30|Action=Allow|Dir=In|App=C:\Missing\fw.exe|Name=Old|",
        );
        reg.set_sz(
            rules,
            "PortOnly",
            r"v2.30|Action=Allow|Protocol=6|Name=Port|",
        );
        reg.set_sz(
            rules,
            "System",
            r"v2.30|Action=Allow|App=C:\Windows\System32\svchost.exe|Name=System|",
        );
        reg.set_sz(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\OpenWithProgids",
            "Gone.Prog",
            "",
        );
        reg.set_sz(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\OpenWithProgids",
            "Keep.Prog",
            "",
        );
        reg.set_sz(r"HKCU\Software\Classes\Keep.Prog", "", "Keep");
        reg.set_sz(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\Handlers\OldCam",
            "DefaultIcon",
            r"C:\Missing\cam.exe,0",
        );
        reg.set_sz(
            &format!(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{dead}"),
            "",
            "",
        );
        reg.set_sz(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32",
            "vidc.old",
            r"C:\Missing\codec.dll",
        );
        reg.set_sz(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32",
            "vidc.msvc",
            "msvc.dll",
        );
        reg.set_sz(
            r"HKCU\Software\Microsoft\Command Processor",
            "Autorun",
            r"C:\Missing\init.bat",
        );
        reg.set_sz(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\ABC\InstallProperties",
            "InstallSource",
            r"C:\Missing\cd",
        );
        reg.set_sz(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\ABC\InstallProperties",
            "LocalPackage",
            r"C:\Windows\Installer\abc.msi",
        );
        reg.set_sz(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Themes",
            "CurrentTheme",
            r"C:\Missing\theme.theme",
        );

        let report = scan(
            &Engine::try_builtin().unwrap(),
            &reg,
            &fs,
            &ScanOptions::default(),
        );
        let text = report
            .findings
            .iter()
            .map(|finding| {
                format!(
                    "{} {} {}",
                    finding.key,
                    finding.value.as_deref().unwrap_or(""),
                    finding.detail
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        for needle in [
            r"C:\Missing\hook.dll",
            r"C:\Missing\mail.exe",
            r"C:\Missing\inject.dll",
            r"C:\Missing\fw.exe",
            "Gone.Prog",
            r"C:\Missing\cam.exe",
            r"C:\Missing\codec.dll",
            r"C:\Missing\init.bat",
            r"C:\Missing\cd",
            r"C:\Missing\theme.theme",
        ] {
            assert!(text.contains(needle), "missing {needle} in:\n{text}");
        }
        for absent in [
            "PortOnly",
            "svchost.exe",
            "Keep.Prog",
            "msvc.dll",
            r"Windows\Installer\abc.msi",
            quiet,
        ] {
            assert!(!text.contains(absent), "unexpected {absent} in:\n{text}");
        }
        assert!(
            report
                .findings
                .iter()
                .all(|finding| !finding.key.to_ascii_lowercase().ends_with("\\live"))
        );
    }
}
