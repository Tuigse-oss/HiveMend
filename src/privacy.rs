//! Privacy cleaning: per-category preview (never writes) and clean with
//! backup-first registry deletes, running-app vetoes, and path guards.
//!
//! Only user-scope tracks ship: HKCU history lists, the user's temp
//! folders, the clipboard, the Recycle Bin, browser caches (plus whole
//! history and cookie files while the browser is closed), a curated set
//! of installed applications, user-defined custom entries, and free-space
//! wiping delegated to cipher. Nothing machine-wide, nothing under the
//! Windows directory, no thumbnail or Prefetch cleaning.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::backup::{export_repairs, write_backup};
use crate::fs::{Access, FileView, ItemKind};
use crate::model::{Error, Repair};
use crate::pathutil::{
    canonical_path, expand_env, has_unsafe_fs_component, is_protected_key, normalize_fs,
    path_under, protected_roots,
};
use crate::registry::{RegError, Registry};

/// Processes that veto a category while they run, lowercase exe names.
pub trait ProcessList {
    fn running(&self, exe: &str) -> bool;
}

/// Whole-system targets the portable core cannot reach on its own. The
/// Windows backend implements these over Shell and cipher; tests use a fake.
pub trait SystemTargets {
    /// Clipboard payloads waiting (0 or 1).
    fn clipboard_items(&self) -> usize;
    fn clear_clipboard(&mut self) -> Result<(), String>;
    /// Recycle Bin (items, bytes) across all fixed drives.
    fn bin_items(&self) -> (usize, u64);
    fn empty_bin(&mut self) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivacyGroup {
    Windows,
    Browsers,
    Plugins,
    Custom,
}

impl PrivacyGroup {
    pub fn label(self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::Browsers => "Browsers",
            Self::Plugins => "Applications",
            Self::Custom => "Custom",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValueMatch {
    /// Names with the prefix plus digits only (`url1`, `url2`).
    PrefixDigits(String),
    Exact(Vec<String>),
}

impl ValueMatch {
    fn matches(&self, name: &str) -> bool {
        match self {
            Self::PrefixDigits(prefix) => {
                // Compare as bytes: a `name[..prefix.len()]` slice would panic
                // when that offset falls inside a multi-byte character (an
                // ordinary Unicode registry value name such as `éé`).
                let name = name.as_bytes();
                let prefix = prefix.as_bytes();
                name.len() > prefix.len()
                    && name[..prefix.len()].eq_ignore_ascii_case(prefix)
                    && name[prefix.len()..].iter().all(u8::is_ascii_digit)
            }
            Self::Exact(names) => names.iter().any(|want| want.eq_ignore_ascii_case(name)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirSpec {
    /// `%VAR%` plus a subpath, for example `TEMP` plus `""`.
    Env { var: String, sub: String },
    /// An already-resolved directory (custom entries).
    Fixed(String),
    /// Every `%LOCALAPPDATA%\<vendor>\User Data\<profile>\<sub>`.
    Chromium { vendor: String, sub: String },
    /// Every Firefox profile dir plus `sub`.
    Firefox { sub: String },
    /// Every Firefox local profile dir (`%LOCALAPPDATA%\Mozilla\Firefox\
    /// Profiles\<profile>`) plus `sub`, where Firefox keeps its cache.
    FirefoxLocal { sub: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivacyTarget {
    /// Delete a whole registry tree.
    RegTree {
        key: String,
    },
    /// Delete matched values on one key. The key itself stays.
    RegValues {
        key: String,
        values: ValueMatch,
    },
    /// Files under a directory. Only plain files go; symlinks never do.
    DirFiles {
        dir: DirSpec,
        mask: String,
        recursive: bool,
        min_age: Option<Duration>,
    },
    /// Named files, optionally with their `-wal`/`-shm`/`-journal` sidecars.
    ExactFiles {
        dir: DirSpec,
        names: Vec<String>,
        sidecars: bool,
    },
    /// A browser's cookie database in each profile (`names` relative to the
    /// profile, first match used), with its SQLite side files.
    Cookies {
        dir: DirSpec,
        names: Vec<String>,
        keep: CookieKeep,
    },
    Clipboard,
    RecycleBin,
}

/// What a clean does with cookie databases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CookieKeep {
    /// Delete the database files.
    All,
    /// Remove every cookie except those for these sites.
    Sites(Vec<String>),
    /// Leave cookies alone, for this reason.
    LeaveAlone(String),
}

#[derive(Clone, Debug)]
pub struct PrivacyItem {
    /// Stable id, persisted when ticked (`user-temp`, `custom`, `freespace-C`).
    pub id: String,
    pub name: String,
    pub group: PrivacyGroup,
    /// One line saying what goes away.
    pub detail: String,
    /// Refuse while any of these runs.
    pub veto_exes: Vec<String>,
    /// Plugin gate: Uninstall DisplayName substring that must be present.
    pub detect: Option<String>,
    pub targets: Vec<PrivacyTarget>,
    /// Extra confirm line, for the wipe's slow-runtime warning.
    pub confirm_note: Option<String>,
    /// Parse-time problems (custom entries). Shown as restrictions.
    pub warnings: Vec<String>,
}

fn item(
    id: &str,
    name: &str,
    group: PrivacyGroup,
    detail: &str,
    targets: Vec<PrivacyTarget>,
) -> PrivacyItem {
    PrivacyItem {
        id: id.to_string(),
        name: name.to_string(),
        group,
        detail: detail.to_string(),
        veto_exes: Vec::new(),
        detect: None,
        targets,
        confirm_note: None,
        warnings: Vec::new(),
    }
}

/// The built-in catalog. Free-space rows are added per fixed drive by
/// [`build_items`]; custom rows come from [`parse_custom`].
fn builtin_items() -> Vec<PrivacyItem> {
    let explorer = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer";
    let mut items = vec![
        item(
            "run-dialog",
            "Run + dialog history",
            PrivacyGroup::Windows,
            "Run box entries and open/save dialog history.",
            vec![
                PrivacyTarget::RegTree {
                    key: format!(r"{explorer}\RunMRU"),
                },
                PrivacyTarget::RegTree {
                    key: format!(r"{explorer}\ComDlg32\LastVisitedPidlMRU"),
                },
                PrivacyTarget::RegTree {
                    key: format!(r"{explorer}\ComDlg32\LastVisitedPidlMRULegacy"),
                },
                PrivacyTarget::RegTree {
                    key: format!(r"{explorer}\ComDlg32\OpenSavePidlMRU"),
                },
            ],
        ),
        item(
            "typed-paths",
            "Typed paths and addresses",
            PrivacyGroup::Windows,
            "Explorer address bar and typed web addresses.",
            vec![
                PrivacyTarget::RegValues {
                    key: format!(r"{explorer}\TypedPaths"),
                    values: ValueMatch::PrefixDigits("url".into()),
                },
                PrivacyTarget::RegValues {
                    key: r"HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\TypedURLs".into(),
                    values: ValueMatch::PrefixDigits("url".into()),
                },
            ],
        ),
        item(
            "recent-docs",
            "Recent documents",
            PrivacyGroup::Windows,
            "Recent documents history.",
            vec![PrivacyTarget::RegTree {
                key: format!(r"{explorer}\RecentDocs"),
            }],
        ),
        item(
            "find-history",
            "Find and search history",
            PrivacyGroup::Windows,
            "Legacy find-computer and search-assistant entries.",
            vec![
                PrivacyTarget::RegTree {
                    key: format!(r"{explorer}\Doc Find Spec MRU"),
                },
                PrivacyTarget::RegTree {
                    key: format!(r"{explorer}\FindComputerMRU"),
                },
                PrivacyTarget::RegTree {
                    key: r"HKEY_CURRENT_USER\Software\Microsoft\Search Assistant\ACMru".into(),
                },
            ],
        ),
        item(
            "user-temp",
            "Temporary files",
            PrivacyGroup::Windows,
            "Files older than 48 hours in your Temp folders.",
            vec![
                PrivacyTarget::DirFiles {
                    dir: DirSpec::Env {
                        var: "TEMP".into(),
                        sub: String::new(),
                    },
                    mask: "*.*".into(),
                    recursive: true,
                    min_age: Some(Duration::from_secs(48 * 3600)),
                },
                PrivacyTarget::DirFiles {
                    dir: DirSpec::Env {
                        var: "TMP".into(),
                        sub: String::new(),
                    },
                    mask: "*.*".into(),
                    recursive: true,
                    min_age: Some(Duration::from_secs(48 * 3600)),
                },
            ],
        ),
        item(
            "clipboard",
            "Clipboard",
            PrivacyGroup::Windows,
            "Whatever is currently copied.",
            vec![PrivacyTarget::Clipboard],
        ),
        item(
            "recycle-bin",
            "Recycle Bin",
            PrivacyGroup::Windows,
            "Everything currently in the bin, all drives.",
            vec![PrivacyTarget::RecycleBin],
        ),
    ];
    for (vendor, id, name) in [
        ("Google\\Chrome", "chrome-cache", "Chrome cache"),
        ("Microsoft\\Edge", "edge-cache", "Edge cache"),
    ] {
        let mut targets = Vec::new();
        for sub in ["Cache", "Code Cache", "GPUCache", "Service Worker"] {
            targets.push(PrivacyTarget::DirFiles {
                dir: DirSpec::Chromium {
                    vendor: vendor.into(),
                    sub: sub.into(),
                },
                mask: "*.*".into(),
                recursive: true,
                min_age: None,
            });
        }
        items.push(item(
            id,
            name,
            PrivacyGroup::Browsers,
            "Cached web files. Locked files are skipped.",
            targets,
        ));
    }
    items.push(item(
        "firefox-cache",
        "Firefox cache",
        PrivacyGroup::Browsers,
        "Cached web files. Locked files are skipped.",
        vec![PrivacyTarget::DirFiles {
            dir: DirSpec::FirefoxLocal {
                sub: "cache2".into(),
            },
            mask: "*.*".into(),
            recursive: true,
            min_age: None,
        }],
    ));
    // Closed-browser lists stay clear of saved logins, autofill, and
    // bookmarks: Login Data, Web Data, and places.sqlite hold passwords
    // and bookmarks, which no confirm can give back.
    for (vendor, id, name, exe) in [
        (
            "Google\\Chrome",
            "chrome-data",
            "Chrome history + cookies (closed)",
            "chrome.exe",
        ),
        (
            "Microsoft\\Edge",
            "edge-data",
            "Edge history + cookies (closed)",
            "msedge.exe",
        ),
    ] {
        let mut closed = item(
            id,
            name,
            PrivacyGroup::Browsers,
            "Browsing history and cookies, only while the browser is closed.",
            vec![
                PrivacyTarget::ExactFiles {
                    dir: DirSpec::Chromium {
                        vendor: vendor.into(),
                        sub: String::new(),
                    },
                    names: vec!["History".to_string()],
                    sidecars: true,
                },
                // Version 96 and later keep cookies under Network.
                PrivacyTarget::Cookies {
                    dir: DirSpec::Chromium {
                        vendor: vendor.into(),
                        sub: String::new(),
                    },
                    names: vec![r"Network\Cookies".to_string(), "Cookies".to_string()],
                    keep: CookieKeep::All,
                },
            ],
        );
        closed.veto_exes.push(exe.to_string());
        items.push(closed);
    }
    let mut fox = item(
        "firefox-data",
        "Firefox cookies + form history (closed)",
        PrivacyGroup::Browsers,
        "Cookies and saved form entries, only while the browser is closed. Browsing history and bookmarks stay.",
        vec![
            PrivacyTarget::ExactFiles {
                dir: DirSpec::Firefox { sub: String::new() },
                names: vec!["formhistory.sqlite".to_string()],
                sidecars: true,
            },
            PrivacyTarget::Cookies {
                dir: DirSpec::Firefox { sub: String::new() },
                names: vec!["cookies.sqlite".to_string()],
                keep: CookieKeep::All,
            },
        ],
    );
    fox.veto_exes.push("firefox.exe".to_string());
    items.push(fox);
    let mut rar = item(
        "plugin-winrar",
        "WinRAR history",
        PrivacyGroup::Plugins,
        "Archive names and dialog history.",
        vec![
            PrivacyTarget::RegTree {
                key: r"HKEY_CURRENT_USER\Software\WinRAR\ArcHistory".into(),
            },
            PrivacyTarget::RegTree {
                key: r"HKEY_CURRENT_USER\Software\WinRAR\DialogEditHistory\ArcName".into(),
            },
        ],
    );
    rar.detect = Some("WinRAR".into());
    rar.veto_exes.push("winrar.exe".into());
    items.push(rar);
    let mut zip = item(
        "plugin-7zip",
        "7-Zip history",
        PrivacyGroup::Plugins,
        "Copied folders and panel history.",
        vec![PrivacyTarget::RegValues {
            key: r"HKEY_CURRENT_USER\Software\7-ZIP\FM".into(),
            values: ValueMatch::Exact(
                ["CopyHistory", "FolderHistory", "PanelPath"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            ),
        }],
    );
    zip.detect = Some("7-Zip".into());
    zip.veto_exes.push("7zFM.exe".into());
    items.push(zip);
    items
}

/// The privacy categories offered on this PC.
pub fn build_items() -> Vec<PrivacyItem> {
    builtin_items()
}

/// What to do with cookies, from reading the keep list. Anything uncertain
/// (an unreadable list, a line that is not a site, an elevated window with
/// sites listed) leaves cookies alone: it must never widen what is removed.
/// Returns the choice and the list's warnings.
pub fn cookie_keep_choice(
    read: std::io::Result<String>,
    elevated: bool,
) -> (CookieKeep, Vec<String>) {
    let text = match read {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return (CookieKeep::All, Vec::new());
        }
        Err(err) => {
            return (
                CookieKeep::LeaveAlone(format!(
                    "Cookies are left alone: your cookies-to-keep list could not be read ({err})."
                )),
                Vec::new(),
            );
        }
        Ok(text) => text,
    };
    let (sites, warnings) = crate::cookies::parse_keep_list(&text);
    let keep = if !warnings.is_empty() {
        CookieKeep::LeaveAlone(
            "Cookies are left alone until every line of your cookies-to-keep list is a site name."
                .to_string(),
        )
    } else if sites.is_empty() {
        CookieKeep::All
    } else if elevated {
        CookieKeep::LeaveAlone(
            "You keep some cookies, so an administrator window leaves cookies alone. Start Hivemend without administrator rights to clean them."
                .to_string(),
        )
    } else {
        CookieKeep::Sites(sites)
    };
    (keep, warnings)
}

/// For an administrator window: drop per-user registry targets, which a
/// program running without elevation can redirect, and say so on the row.
/// Their history is cleaned from a normal window.
pub fn leave_per_user_registry(items: &mut [PrivacyItem]) {
    for item in items {
        let before = item.targets.len();
        item.targets.retain(|target| match target {
            PrivacyTarget::RegTree { key } | PrivacyTarget::RegValues { key, .. } => {
                !crate::pathutil::per_user_key(key)
            }
            _ => true,
        });
        if item.targets.len() != before {
            item.warnings.push(
                "Its registry entries are cleaned from Hivemend started without administrator rights."
                    .to_string(),
            );
        }
    }
}

/// Apply the cookies-to-keep choice to every item that holds cookies.
pub fn set_cookie_keep(items: &mut [PrivacyItem], keep: &CookieKeep) {
    for item in items {
        let mut holds = false;
        for target in &mut item.targets {
            if let PrivacyTarget::Cookies { keep: have, .. } = target {
                *have = keep.clone();
                holds = true;
            }
        }
        if holds {
            // Firefox's item clears form history; Chrome's and Edge's clear
            // browsing history.
            let other = if item.id.starts_with("firefox") {
                "Saved form entries"
            } else {
                "Browsing history"
            };
            item.detail = match keep {
                CookieKeep::All => {
                    format!("{other} and cookies, only while the browser is closed.")
                }
                CookieKeep::Sites(sites) => format!(
                    "{other} and cookies, only while the browser is closed. Cookies for {} on your keep list stay.",
                    if sites.len() == 1 {
                        "the 1 site".to_string()
                    } else {
                        format!("the {} sites", sites.len())
                    }
                ),
                CookieKeep::LeaveAlone(_) => {
                    format!("{other}, only while the browser is closed. Cookies are left alone.")
                }
            };
        }
    }
}

/// The first cookie database present in a profile, of `names`.
fn cookie_db(fs: &dyn FileView, dir: &str, names: &[String]) -> Option<String> {
    names
        .iter()
        .map(|name| format!("{dir}\\{name}"))
        .find(|path| fs.exists(path) && !fs.is_dir(path))
}

/// Case-insensitive `*`/`?` mask over a file name. `*.*` matches everything.
pub fn mask_matches(name: &str, mask: &str) -> bool {
    if mask == "*.*" {
        return true;
    }
    mask_matches_inner(&name.to_ascii_lowercase(), &mask.to_ascii_lowercase())
}

fn mask_matches_inner(name: &str, mask: &str) -> bool {
    let name: Vec<char> = name.chars().collect();
    let mask: Vec<char> = mask.chars().collect();
    let mut nx = 0usize;
    let mut mx = 0usize;
    let mut star: Option<usize> = None;
    let mut back = 0usize;
    while nx < name.len() {
        if mx < mask.len() && (mask[mx] == '?' || mask[mx] == name[nx]) {
            nx += 1;
            mx += 1;
        } else if mx < mask.len() && mask[mx] == '*' {
            star = Some(mx);
            mx += 1;
            back = nx;
        } else if let Some(at) = star {
            mx = at + 1;
            back += 1;
            nx = back;
        } else {
            return false;
        }
    }
    while mx < mask.len() && mask[mx] == '*' {
        mx += 1;
    }
    mx == mask.len()
}

/// Uninstall DisplayName substring search, both registry views.
pub fn uninstall_present(reg: &dyn Registry, needle: &str) -> bool {
    for root in [
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        // Programs installed just for this account.
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    ] {
        let Ok(entries) = reg.subkeys(root) else {
            continue;
        };
        for entry in entries {
            let key = format!(r"{root}\{entry}");
            let Ok(values) = reg.values(&key) else {
                continue;
            };
            for value in values {
                if value.name.eq_ignore_ascii_case("DisplayName")
                    && let Some(text) = value.data.as_text()
                    && text
                        .to_ascii_lowercase()
                        .contains(&needle.to_ascii_lowercase())
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Resolve a directory spec to existing directories, plus notes for roots
/// that could not be resolved (unknown `%VAR%`).
fn resolve_dirs(fs: &dyn FileView, spec: &DirSpec) -> (Vec<String>, Vec<String>) {
    let mut dirs = Vec::new();
    let mut notes = Vec::new();
    let mut push = |dir: String| {
        let dir = normalize_fs(&dir);
        if !dirs
            .iter()
            .any(|have: &String| have.eq_ignore_ascii_case(&dir))
        {
            dirs.push(dir);
        }
    };
    match spec {
        DirSpec::Env { var, sub } => {
            let root = expand_env(fs, &format!("%{var}%"));
            if root.contains('%') {
                notes.push(format!("%{var}% is not set"));
            } else {
                let dir = if sub.is_empty() {
                    root
                } else {
                    format!("{root}\\{sub}")
                };
                if fs.is_dir(&dir) {
                    push(dir);
                }
            }
        }
        DirSpec::Fixed(dir) => {
            if fs.is_dir(dir) {
                push(dir.clone());
            }
        }
        DirSpec::Chromium { vendor, sub } => {
            let base = expand_env(fs, "%LOCALAPPDATA%");
            if base.contains('%') {
                notes.push("%LOCALAPPDATA% is not set".to_string());
                return (dirs, notes);
            }
            let users = format!("{base}\\{vendor}\\User Data");
            for profile in child_dirs(fs, &users) {
                let dir = if sub.is_empty() {
                    profile
                } else {
                    format!("{profile}\\{sub}")
                };
                if fs.is_dir(&dir) {
                    push(dir);
                }
            }
        }
        DirSpec::FirefoxLocal { sub } => {
            let base = expand_env(fs, "%LOCALAPPDATA%");
            if base.contains('%') {
                notes.push("%LOCALAPPDATA% is not set".to_string());
                return (dirs, notes);
            }
            let profiles = format!("{base}\\Mozilla\\Firefox\\Profiles");
            for profile in child_dirs(fs, &profiles) {
                let dir = if sub.is_empty() {
                    profile
                } else {
                    format!("{profile}\\{sub}")
                };
                if fs.is_dir(&dir) {
                    push(dir);
                }
            }
        }
        DirSpec::Firefox { sub } => {
            let base = expand_env(fs, "%APPDATA%");
            if base.contains('%') {
                notes.push("%APPDATA% is not set".to_string());
                return (dirs, notes);
            }
            let home = format!("{base}\\Mozilla\\Firefox");
            for profile in firefox_profiles(fs, &home) {
                let dir = if sub.is_empty() {
                    profile
                } else {
                    format!("{profile}\\{sub}")
                };
                if fs.is_dir(&dir) {
                    push(dir);
                }
            }
        }
    }
    (dirs, notes)
}

fn child_dirs(fs: &dyn FileView, dir: &str) -> Vec<String> {
    fs.list(dir)
        .into_iter()
        .filter(|item| item.kind == ItemKind::Dir)
        .map(|item| format!("{dir}\\{}", item.name))
        .collect()
}

/// Firefox profiles from `profiles.ini` plus the `Profiles` folder, so a
/// missing ini still finds default locations.
fn firefox_profiles(fs: &dyn FileView, home: &str) -> Vec<String> {
    let mut profiles = Vec::new();
    let mut push = |dir: String| {
        if !profiles
            .iter()
            .any(|have: &String| have.eq_ignore_ascii_case(&dir))
        {
            profiles.push(dir);
        }
    };
    let ini = format!("{home}\\profiles.ini");
    if let Some(bytes) = fs.read(&ini) {
        let text = String::from_utf8_lossy(&bytes);
        let mut relative = true;
        for line in text.lines() {
            let line = line.trim();
            if line.eq_ignore_ascii_case("IsRelative=0") {
                relative = false;
            } else if line.eq_ignore_ascii_case("IsRelative=1") {
                relative = true;
            } else if let Some(path) = line.strip_prefix("Path=") {
                let path = path.trim();
                if path.is_empty() {
                    continue;
                }
                let dir = normalize_fs(&if relative || !looks_absolute(path) {
                    format!("{home}\\{path}")
                } else {
                    path.to_string()
                });
                if fs.is_dir(&dir) {
                    push(dir);
                }
            }
        }
    }
    for profile in child_dirs(fs, &format!("{home}\\Profiles")) {
        push(profile);
    }
    profiles
}

fn looks_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    (bytes.len() > 2 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/'))
        || path.starts_with("\\\\")
}

/// Registry deletes stay in the current user's hive, out of protected keys,
/// and below a plausible depth (a whole-hive or `Software` delete is never
/// a privacy target, no matter who asked).
pub fn privacy_reg_allowed(key: &str) -> bool {
    let canonical = canonical_path(key);
    if !canonical
        .to_ascii_lowercase()
        .starts_with("hkey_current_user\\")
    {
        return false;
    }
    if is_protected_key(&canonical) {
        return false;
    }
    canonical.split('\\').count() >= 4
}

/// File deletes stay on local absolute paths, out of the Windows and
/// program folders and the app's own data dir, and inside the resolved root.
fn privacy_file_allowed(fs: &dyn FileView, root: &str, path: &str) -> bool {
    let path = normalize_fs(path);
    if !looks_absolute(&path) || path.contains("..") || has_unsafe_fs_component(&path) {
        return false;
    }
    if !path_under(&path, root) {
        return false;
    }
    privacy_location_allowed(fs, &path)
}

/// Outside the Windows, Program Files, and ProgramData folders (located by
/// API; a folder that cannot be located refuses everything) and outside the
/// app data folder.
fn privacy_location_allowed(fs: &dyn FileView, path: &str) -> bool {
    let Ok(roots) = protected_roots(fs) else {
        return false;
    };
    !roots.iter().any(|dir| path_under(path, dir))
        && !crate::store::data_roots(fs)
            .iter()
            .any(|dir| path_under(path, dir))
}

// ---- preview ----

/// Restriction lines shown per item before they collapse into a count.
const MAX_NOTES: usize = 25;

fn push_note(notes: &mut Vec<String>, extra: &mut usize, note: String) {
    if notes.len() < MAX_NOTES {
        notes.push(note);
    } else {
        *extra += 1;
    }
}

#[derive(Clone, Debug, Default)]
pub struct PreviewItem {
    pub id: String,
    pub files: usize,
    pub values: usize,
    /// Non-file, non-value payloads (clipboard).
    pub other: usize,
    /// Cookies removed from a database that is kept.
    pub cookies: usize,
    pub bytes: u64,
    pub restricted: Vec<String>,
    pub restricted_extra: usize,
    pub skipped_running: bool,
    pub gated_out: bool,
}

impl PreviewItem {
    fn blank(id: &str) -> Self {
        Self {
            id: id.to_string(),
            ..Self::default()
        }
    }

    fn note(&mut self, note: String) {
        push_note(&mut self.restricted, &mut self.restricted_extra, note);
    }
}

#[derive(Clone, Debug, Default)]
pub struct Preview {
    pub items: Vec<PreviewItem>,
}

impl Preview {
    pub fn files(&self) -> usize {
        self.items.iter().map(|item| item.files).sum()
    }

    pub fn values(&self) -> usize {
        self.items.iter().map(|item| item.values).sum()
    }

    pub fn bytes(&self) -> u64 {
        self.items.iter().map(|item| item.bytes).sum()
    }
}

/// Count what `clean_with_progress` would remove. Never writes.
pub fn preview(
    reg: &dyn Registry,
    fs: &dyn FileView,
    sys: &dyn SystemTargets,
    procs: &dyn ProcessList,
    items: &[PrivacyItem],
) -> Preview {
    let mut out = Preview::default();
    for item in items {
        let mut row = PreviewItem::blank(&item.id);
        for warning in &item.warnings {
            row.note(warning.clone());
        }
        if let Some(exe) = item.veto_exes.iter().find(|exe| procs.running(exe)) {
            row.skipped_running = true;
            row.note(format!("close {} first", exe));
            out.items.push(row);
            continue;
        }
        if let Some(needle) = &item.detect
            && !uninstall_present(reg, needle)
        {
            row.gated_out = true;
            row.note("application is not installed".to_string());
            out.items.push(row);
            continue;
        }
        // TEMP and TMP usually resolve to one directory; each directory
        // is walked once per item no matter how many targets name it.
        let mut walked = HashSet::new();
        for target in &item.targets {
            preview_target(reg, fs, sys, target, &mut row, &mut walked);
        }
        out.items.push(row);
    }
    out
}

fn preview_target(
    reg: &dyn Registry,
    fs: &dyn FileView,
    sys: &dyn SystemTargets,
    target: &PrivacyTarget,
    row: &mut PreviewItem,
    walked: &mut HashSet<String>,
) {
    match target {
        PrivacyTarget::RegTree { key } => {
            if !privacy_reg_allowed(key) {
                row.note(format!("refused: {key}"));
                return;
            }
            row.values += count_tree(reg, key, 0, row);
        }
        PrivacyTarget::RegValues { key, values } => {
            if !privacy_reg_allowed(key) {
                row.note(format!("refused: {key}"));
                return;
            }
            match reg.values(key) {
                Ok(present) => {
                    row.values += present
                        .iter()
                        .filter(|value| values.matches(&value.name))
                        .count();
                }
                Err(RegError::NotFound) => {}
                Err(err) => row.note(format!("cannot read {key}: {err}")),
            }
        }
        PrivacyTarget::DirFiles {
            dir,
            mask,
            recursive,
            min_age,
        } => {
            let (dirs, notes) = resolve_dirs(fs, dir);
            for note in notes {
                row.note(note);
            }
            for dir in dirs {
                let gate = format!(
                    "{}\0{}\0{}\0{:?}",
                    dir.to_ascii_lowercase(),
                    mask.to_ascii_lowercase(),
                    recursive,
                    min_age
                );
                if !walked.insert(gate) {
                    continue;
                }
                let mut hits = Vec::new();
                walk_files(fs, &dir, mask, *recursive, *min_age, 0, &mut hits, row);
                for hit in hits {
                    row.files += 1;
                    row.bytes += hit.bytes;
                }
            }
        }
        PrivacyTarget::ExactFiles {
            dir,
            names,
            sidecars,
        } => {
            let (dirs, notes) = resolve_dirs(fs, dir);
            for note in notes {
                row.note(note);
            }
            for dir in dirs {
                let gate = format!(
                    "{}\0{}\0{}",
                    dir.to_ascii_lowercase(),
                    names.join("|").to_ascii_lowercase(),
                    sidecars
                );
                if !walked.insert(gate) {
                    continue;
                }
                for name in names {
                    for path in with_sidecars(&dir, name, *sidecars) {
                        if fs.is_dir(&path) {
                            row.note(format!("not a file: {path}"));
                        } else if fs.exists(&path) {
                            row.files += 1;
                            row.bytes += fs.len(&path).unwrap_or(0);
                        }
                    }
                }
            }
        }
        PrivacyTarget::Cookies { dir, names, keep } => {
            if let CookieKeep::LeaveAlone(reason) = keep {
                row.note(reason.clone());
                return;
            }
            let (dirs, notes) = resolve_dirs(fs, dir);
            for note in notes {
                row.note(note);
            }
            for dir in dirs {
                if !walked.insert(format!("cookies\0{}", dir.to_ascii_lowercase())) {
                    continue;
                }
                let Some(db) = cookie_db(fs, &dir, names) else {
                    continue;
                };
                match keep {
                    CookieKeep::Sites(sites) => {
                        match crate::cookies::count_cookies(std::path::Path::new(&db), sites) {
                            Ok(count) => row.cookies += count.removed,
                            Err(err) => row.note(format!("cannot read {db}: {err}")),
                        }
                    }
                    _ => {
                        for path in with_sidecars(&dir, &db[dir.len() + 1..], true) {
                            if fs.exists(&path) && !fs.is_dir(&path) {
                                row.files += 1;
                                row.bytes += fs.len(&path).unwrap_or(0);
                            }
                        }
                    }
                }
            }
        }
        PrivacyTarget::Clipboard => {
            row.other += sys.clipboard_items();
        }
        PrivacyTarget::RecycleBin => {
            let (count, bytes) = sys.bin_items();
            row.files += count;
            row.bytes += bytes;
        }
    }
}

/// Registry values under a tree, for preview counts and delete credit.
fn count_tree(reg: &dyn Registry, key: &str, depth: usize, row: &mut PreviewItem) -> usize {
    if depth > 32 {
        row.note(format!("{key} is nested too deeply"));
        return 0;
    }
    let values = match reg.values(key) {
        Ok(values) => values,
        Err(RegError::NotFound) => return 0,
        Err(err) => {
            row.note(format!("cannot read {key}: {err}"));
            return 0;
        }
    };
    let mut count = values.len();
    let children = match reg.subkeys(key) {
        Ok(children) => children,
        Err(RegError::NotFound) => Vec::new(),
        Err(err) => {
            row.note(format!("cannot read {key}: {err}"));
            return count;
        }
    };
    for child in children {
        count += count_tree(reg, &format!("{key}\\{child}"), depth + 1, row);
    }
    count
}

struct FileHit {
    path: String,
    bytes: u64,
}

#[allow(clippy::too_many_arguments)]
fn walk_files(
    fs: &dyn FileView,
    dir: &str,
    mask: &str,
    recursive: bool,
    min_age: Option<Duration>,
    depth: usize,
    hits: &mut Vec<FileHit>,
    row: &mut PreviewItem,
) {
    if depth > 64 {
        return;
    }
    for entry in fs.list(dir) {
        let path = format!("{dir}\\{}", entry.name);
        match entry.kind {
            ItemKind::File => {
                if !mask_matches(&entry.name, mask) {
                    continue;
                }
                if let Some(min) = min_age {
                    match entry.age {
                        Some(age) if age >= min => {}
                        Some(_) => continue,
                        None => {
                            row.note(format!("age unknown: {path}"));
                            continue;
                        }
                    }
                }
                let bytes = fs.len(&path).unwrap_or(0);
                hits.push(FileHit { path, bytes });
            }
            ItemKind::Dir => {
                if recursive {
                    walk_files(fs, &path, mask, recursive, min_age, depth + 1, hits, row);
                }
            }
            ItemKind::Other => row.note(format!("not a plain file: {path}")),
        }
    }
}

fn with_sidecars(dir: &str, name: &str, sidecars: bool) -> Vec<String> {
    let mut paths = vec![format!("{dir}\\{name}")];
    if sidecars {
        for suffix in ["-wal", "-shm", "-journal"] {
            paths.push(format!("{dir}\\{name}{suffix}"));
        }
    }
    paths
}

// ---- clean ----

#[derive(Clone, Debug, Default)]
pub struct ItemOutcome {
    pub id: String,
    pub files: usize,
    pub values: usize,
    pub other: usize,
    /// Cookies removed from a database that is kept.
    pub cookies: usize,
    pub bytes: u64,
    pub already_gone: usize,
    pub restricted: Vec<String>,
    pub restricted_extra: usize,
    pub skipped_running: bool,
    pub gated_out: bool,
    pub note: String,
}

impl ItemOutcome {
    fn blank(id: &str) -> Self {
        Self {
            id: id.to_string(),
            ..Self::default()
        }
    }

    fn note(&mut self, note: String) {
        push_note(&mut self.restricted, &mut self.restricted_extra, note);
    }
}

#[derive(Debug, Default)]
pub struct CleanOutcome {
    pub items: Vec<ItemOutcome>,
    pub backup_file: PathBuf,
    pub canceled: bool,
    pub errors: Vec<String>,
}

impl CleanOutcome {
    pub fn files(&self) -> usize {
        self.items.iter().map(|item| item.files).sum()
    }

    pub fn values(&self) -> usize {
        self.items.iter().map(|item| item.values).sum()
    }

    pub fn bytes(&self) -> u64 {
        self.items.iter().map(|item| item.bytes).sum()
    }
}

/// A registry removal plus the preview value count it pays on success.
type PlannedRepair = (Repair, usize);

/// Remove the selected items. `progress(done, total, name)` runs before each
/// item; returning false cancels after the finished items.
pub fn clean_with_progress(
    reg: &mut dyn Registry,
    fs: &mut dyn FileView,
    sys: &mut dyn SystemTargets,
    procs: &dyn ProcessList,
    items: &[PrivacyItem],
    backup_file: &Path,
    progress: &mut dyn FnMut(usize, usize, &str) -> bool,
) -> Result<CleanOutcome, Error> {
    enum Planned {
        Skip(ItemOutcome),
        Run {
            repairs: Vec<PlannedRepair>,
            pre: Vec<String>,
        },
    }
    let mut planned = Vec::with_capacity(items.len());
    for item in items {
        let mut skip = ItemOutcome::blank(&item.id);
        for warning in &item.warnings {
            skip.note(warning.clone());
        }
        if let Some(exe) = item.veto_exes.iter().find(|exe| procs.running(exe)) {
            skip.skipped_running = true;
            skip.note(format!("close {} first", exe));
            planned.push(Planned::Skip(skip));
            continue;
        }
        if let Some(needle) = &item.detect
            && !uninstall_present(reg, needle)
        {
            skip.gated_out = true;
            skip.note("application is not installed".to_string());
            planned.push(Planned::Skip(skip));
            continue;
        }
        let mut repairs = Vec::new();
        let mut pre = Vec::new();
        collect_repairs(reg, item, &mut repairs, &mut pre);
        planned.push(Planned::Run { repairs, pre });
    }

    let all: Vec<Repair> = planned
        .iter()
        .flat_map(|step| match step {
            Planned::Run { repairs, .. } => {
                repairs.iter().map(|(repair, _)| repair.clone()).collect()
            }
            Planned::Skip(_) => Vec::new(),
        })
        .collect();
    let plan = export_repairs(reg, &all, backup_file);
    write_backup(backup_file, &plan.body)?;

    let total = planned
        .iter()
        .filter(|step| matches!(step, Planned::Run { .. }))
        .count();
    let mut outcome = CleanOutcome {
        backup_file: backup_file.to_path_buf(),
        ..CleanOutcome::default()
    };
    let mut done = 0usize;
    for (item, step) in items.iter().zip(planned) {
        match step {
            Planned::Skip(skip) => outcome.items.push(skip),
            Planned::Run { repairs, pre } => {
                if !progress(done, total, &item.name) {
                    outcome.canceled = true;
                    return Ok(outcome);
                }
                // Check again right before acting: the program may have
                // started since the plan was made (earlier items take time).
                if let Some(exe) = item.veto_exes.iter().find(|exe| procs.running(exe)) {
                    let mut skip = ItemOutcome::blank(&item.id);
                    skip.skipped_running = true;
                    skip.note(format!("close {exe} first"));
                    outcome.items.push(skip);
                    done += 1;
                    continue;
                }
                outcome.items.push(execute_item(
                    reg,
                    fs,
                    sys,
                    item,
                    &repairs,
                    pre,
                    &plan,
                    &mut outcome.errors,
                ));
                done += 1;
            }
        }
    }
    progress(total, total, "");
    Ok(outcome)
}

/// Fresh enumeration of an item's registry repairs, so a preview from
/// minutes ago cannot delete something that changed shape since.
fn collect_repairs(
    reg: &dyn Registry,
    item: &PrivacyItem,
    repairs: &mut Vec<PlannedRepair>,
    pre: &mut Vec<String>,
) {
    for target in &item.targets {
        match target {
            PrivacyTarget::RegTree { key } => {
                if !privacy_reg_allowed(key) {
                    pre.push(format!("refused: {key}"));
                    continue;
                }
                let mut counter = PreviewItem::blank(&item.id);
                let credit = count_tree(reg, key, 0, &mut counter);
                for note in counter.restricted {
                    pre.push(note);
                }
                repairs.push((Repair::DeleteKey { key: key.clone() }, credit));
            }
            PrivacyTarget::RegValues { key, values } => {
                if !privacy_reg_allowed(key) {
                    pre.push(format!("refused: {key}"));
                    continue;
                }
                match reg.values(key) {
                    Ok(present) => {
                        for value in present.iter().filter(|value| values.matches(&value.name)) {
                            repairs.push((
                                Repair::DeleteValue {
                                    key: key.clone(),
                                    name: value.name.clone(),
                                },
                                1,
                            ));
                        }
                    }
                    Err(RegError::NotFound) => {}
                    Err(err) => pre.push(format!("cannot read {key}: {err}")),
                }
            }
            PrivacyTarget::DirFiles { .. }
            | PrivacyTarget::ExactFiles { .. }
            | PrivacyTarget::Cookies { .. }
            | PrivacyTarget::Clipboard
            | PrivacyTarget::RecycleBin => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_item(
    reg: &mut dyn Registry,
    fs: &mut dyn FileView,
    sys: &mut dyn SystemTargets,
    item: &PrivacyItem,
    repairs: &[PlannedRepair],
    pre: Vec<String>,
    plan: &crate::backup::BackupPlan,
    errors: &mut Vec<String>,
) -> ItemOutcome {
    let mut done = ItemOutcome::blank(&item.id);
    for warning in &item.warnings {
        done.note(warning.clone());
    }
    for note in pre {
        done.note(note);
    }
    for (repair, credit) in repairs {
        apply_repair(reg, repair, *credit, plan, &mut done, errors);
    }
    let mut walked = HashSet::new();
    for target in &item.targets {
        match target {
            PrivacyTarget::RegTree { .. } | PrivacyTarget::RegValues { .. } => {}
            PrivacyTarget::DirFiles {
                dir,
                mask,
                recursive,
                min_age,
            } => {
                let (dirs, notes) = resolve_dirs(fs, dir);
                for note in notes {
                    done.note(note);
                }
                for dir in dirs {
                    let gate = format!(
                        "{}\0{}\0{}\0{:?}",
                        dir.to_ascii_lowercase(),
                        mask.to_ascii_lowercase(),
                        recursive,
                        min_age
                    );
                    if !walked.insert(gate) {
                        continue;
                    }
                    let mut counter = PreviewItem::blank(&item.id);
                    let mut hits = Vec::new();
                    walk_files(
                        fs,
                        &dir,
                        mask,
                        *recursive,
                        *min_age,
                        0,
                        &mut hits,
                        &mut counter,
                    );
                    for note in counter.restricted {
                        done.note(note);
                    }
                    done.restricted_extra += counter.restricted_extra;
                    for hit in hits {
                        delete_file(fs, &dir, &hit, &mut done, errors);
                    }
                }
            }
            PrivacyTarget::ExactFiles {
                dir,
                names,
                sidecars,
            } => {
                let (dirs, notes) = resolve_dirs(fs, dir);
                for note in notes {
                    done.note(note);
                }
                for dir in dirs {
                    let gate = format!(
                        "{}\0{}\0{}",
                        dir.to_ascii_lowercase(),
                        names.join("|").to_ascii_lowercase(),
                        sidecars
                    );
                    if !walked.insert(gate) {
                        continue;
                    }
                    for name in names {
                        for path in with_sidecars(&dir, name, *sidecars) {
                            if fs.is_dir(&path) {
                                done.note(format!("not a file: {path}"));
                                continue;
                            }
                            if !fs.exists(&path) {
                                continue;
                            }
                            let bytes = fs.len(&path).unwrap_or(0);
                            let hit = FileHit { path, bytes };
                            delete_file(fs, &dir, &hit, &mut done, errors);
                        }
                    }
                }
            }
            PrivacyTarget::Cookies { dir, names, keep } => {
                if let CookieKeep::LeaveAlone(reason) = keep {
                    done.note(reason.clone());
                    continue;
                }
                let (dirs, notes) = resolve_dirs(fs, dir);
                for note in notes {
                    done.note(note);
                }
                for dir in dirs {
                    if !walked.insert(format!("cookies\0{}", dir.to_ascii_lowercase())) {
                        continue;
                    }
                    let Some(db) = cookie_db(fs, &dir, names) else {
                        continue;
                    };
                    match keep {
                        CookieKeep::Sites(sites) => {
                            trim_cookie_db(fs, &dir, &db, sites, &mut done, errors);
                        }
                        _ => {
                            for path in with_sidecars(&dir, &db[dir.len() + 1..], true) {
                                if !fs.exists(&path) || fs.is_dir(&path) {
                                    continue;
                                }
                                let bytes = fs.len(&path).unwrap_or(0);
                                let hit = FileHit { path, bytes };
                                delete_file(fs, &dir, &hit, &mut done, errors);
                            }
                        }
                    }
                }
            }
            PrivacyTarget::Clipboard => {
                if sys.clipboard_items() == 0 {
                    done.already_gone += 1;
                } else {
                    match sys.clear_clipboard() {
                        Ok(()) => done.other += 1,
                        Err(err) => done.note(format!("clipboard: {err}")),
                    }
                }
            }
            PrivacyTarget::RecycleBin => {
                let (count, bytes) = sys.bin_items();
                if count == 0 {
                    done.already_gone += 1;
                } else {
                    match sys.empty_bin() {
                        Ok(()) => {
                            done.files += count;
                            done.bytes += bytes;
                        }
                        Err(err) => {
                            if err.to_ascii_lowercase().contains("denied") {
                                done.note(format!("recycle bin: {err}"));
                            } else {
                                errors.push(format!("recycle bin: {err}"));
                            }
                        }
                    }
                }
            }
        }
    }
    done
}

fn apply_repair(
    reg: &mut dyn Registry,
    repair: &Repair,
    credit: usize,
    plan: &crate::backup::BackupPlan,
    done: &mut ItemOutcome,
    errors: &mut Vec<String>,
) {
    let key = match repair {
        Repair::DeleteKey { key } | Repair::DeleteValue { key, .. } => key,
        Repair::DeleteFile { .. } | Repair::None => return,
    };
    if !privacy_reg_allowed(key) {
        done.note(format!("refused: {key}"));
        return;
    }
    if !plan.covers(key) {
        done.note(format!("not backed up, left alone: {key}"));
        return;
    }
    let result = match repair {
        Repair::DeleteKey { key } => reg.delete_tree(key),
        Repair::DeleteValue { key, name } => reg.delete_value(key, name),
        Repair::DeleteFile { .. } | Repair::None => return,
    };
    match result {
        Ok(()) => done.values += credit,
        Err(RegError::NotFound) => done.already_gone += 1,
        Err(RegError::Denied(message)) => done.note(format!("{key}: {message}")),
        Err(RegError::Message(message)) => errors.push(format!("{key}: {message}")),
    }
}

/// Trim one cookie database to the kept sites, after the same location
/// checks a delete gets: the file and the profile are both resolved, so a
/// link cannot carry the edit outside the profile.
fn trim_cookie_db(
    fs: &mut dyn FileView,
    root: &str,
    db: &str,
    sites: &[String],
    done: &mut ItemOutcome,
    errors: &mut Vec<String>,
) {
    if !privacy_file_allowed(fs, root, db) {
        done.note(format!("refused: {db}"));
        return;
    }
    let real = match fs.pin(db) {
        // A second name for the database would be edited too.
        Ok(pin) if pin.kind == ItemKind::File && pin.links > 1 => {
            done.note(format!(
                "refused: {db} has more than one name (a hard link)"
            ));
            return;
        }
        Ok(pin) if pin.kind == ItemKind::File => pin.real_path.clone(),
        Ok(_) => {
            done.note(format!("not a file: {db}"));
            return;
        }
        Err(err) => {
            done.note(format!("refused: {db}: {err}"));
            return;
        }
    };
    let real_root = fs
        .pin(root)
        .map(|pin| pin.real_path)
        .unwrap_or_else(|_| root.to_string());
    if !privacy_file_allowed(fs, &real_root, &real) {
        done.note(format!("refused: {db} (it resolves to {real})"));
        return;
    }
    match crate::cookies::trim_cookies(std::path::Path::new(&real), sites) {
        Ok(trimmed) => {
            done.cookies += trimmed.count.removed;
            for copy in trimmed.leftovers {
                errors.push(format!(
                    "a copy of the old cookies could not be deleted; delete it yourself: {}",
                    copy.display()
                ));
            }
        }
        Err(err) => errors.push(format!("cookies in {db}: {err}")),
    }
}

fn delete_file(
    fs: &mut dyn FileView,
    root: &str,
    hit: &FileHit,
    done: &mut ItemOutcome,
    errors: &mut Vec<String>,
) {
    if !privacy_file_allowed(fs, root, &hit.path) {
        done.note(format!("refused: {}", hit.path));
        return;
    }
    // Pin the object and check where it really is: the root and the file are
    // both resolved, so a junction or link inside a cache folder cannot carry
    // the delete outside it. The delete goes through the checked handle.
    let mut pin = match fs.pin(&hit.path) {
        Ok(pin) => pin,
        Err(err) if err.contains("not found") || err.contains("os error 2") => {
            done.already_gone += 1;
            return;
        }
        Err(err) => {
            done.note(format!("refused: {}: {err}", hit.path));
            return;
        }
    };
    if pin.kind != ItemKind::File {
        done.note(format!("not a file: {}", hit.path));
        return;
    }
    let real_root = fs
        .pin(root)
        .map(|pin| pin.real_path)
        .unwrap_or_else(|_| root.to_string());
    if !privacy_file_allowed(fs, &real_root, &pin.real_path) {
        done.note(format!(
            "refused: {} (it resolves to {})",
            hit.path, pin.real_path
        ));
        return;
    }
    let result = fs
        .pin_acquire(&mut pin, Access::Delete)
        .and_then(|()| fs.pin_delete(pin));
    match result {
        Ok(()) => {
            done.files += 1;
            done.bytes += hit.bytes;
        }
        Err(err) if err.contains("not found") || err.contains("os error 2") => {
            done.already_gone += 1;
        }
        Err(err)
            if err.contains("os error 5")
                || err.contains("os error 32")
                || err.to_ascii_lowercase().contains("denied")
                || err.to_ascii_lowercase().contains("being used") =>
        {
            done.note(format!("{}: {}", hit.path, short_reason(&err)));
        }
        Err(err) => errors.push(format!("{}: {err}", hit.path)),
    }
}

fn short_reason(err: &str) -> &str {
    if err.contains("os error 32") || err.to_ascii_lowercase().contains("being used") {
        "in use"
    } else if err.contains("os error 5") || err.to_ascii_lowercase().contains("denied") {
        "access denied"
    } else {
        "could not delete"
    }
}

// ---- custom entries ----

/// Parse user-defined targets, one per line:
/// `file=<path>`, `files=<dir>|<mask>`, `files-rec=<dir>|<mask>`,
/// `value=<key>|<name>`. Returns the Custom item plus refusal reasons.
pub fn parse_custom(text: &str, fs: &dyn FileView) -> PrivacyItem {
    let mut custom = item(
        "custom",
        "Custom items",
        PrivacyGroup::Custom,
        "Your own files, folders, and registry values.",
        Vec::new(),
    );
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim().trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lineno = index + 1;
        let Some((kind, rest)) = line.split_once('=') else {
            custom.warnings.push(format!(
                "line {lineno}: want file=, files=, files-rec=, or value="
            ));
            continue;
        };
        match kind.trim().to_ascii_lowercase().as_str() {
            "file" => match custom_file(rest.trim(), fs) {
                Ok(target) => custom.targets.push(target),
                Err(reason) => custom.warnings.push(format!("line {lineno}: {reason}")),
            },
            "files" | "files-rec" => {
                let recursive = kind.trim().eq_ignore_ascii_case("files-rec");
                match custom_dir(rest.trim(), recursive, fs) {
                    Ok(target) => custom.targets.push(target),
                    Err(reason) => custom.warnings.push(format!("line {lineno}: {reason}")),
                }
            }
            "value" => match custom_value(rest.trim()) {
                Ok(target) => custom.targets.push(target),
                Err(reason) => custom.warnings.push(format!("line {lineno}: {reason}")),
            },
            _ => custom.warnings.push(format!(
                "line {lineno}: want file=, files=, files-rec=, or value="
            )),
        }
    }
    custom
}

/// Roots a custom file target may live under: the temp folders and the
/// browser profile homes.
fn custom_roots(fs: &dyn FileView) -> Vec<String> {
    let mut roots = Vec::new();
    for var in ["TEMP", "TMP"] {
        if let Some(dir) = fs.var(var)
            && !dir.is_empty()
        {
            roots.push(normalize_fs(&dir));
        }
    }
    if let Some(local) = fs.var("LOCALAPPDATA") {
        for vendor in ["Google\\Chrome\\User Data", "Microsoft\\Edge\\User Data"] {
            roots.push(normalize_fs(&format!("{local}\\{vendor}")));
        }
    }
    if let Some(roaming) = fs.var("APPDATA") {
        roots.push(normalize_fs(&format!("{roaming}\\Mozilla\\Firefox")));
    }
    roots
}

fn under_custom_root(path: &str, roots: &[String]) -> bool {
    let lower = normalize_fs(path).to_ascii_lowercase();
    roots.iter().any(|root| {
        let root = root.to_ascii_lowercase();
        lower == root || lower.starts_with(&(root + "\\"))
    })
}

fn custom_file(raw: &str, fs: &dyn FileView) -> Result<PrivacyTarget, String> {
    if raw.is_empty() {
        return Err("file= needs a path".to_string());
    }
    if raw.contains('*') || raw.contains('?') {
        return Err("file= takes an exact path, no wildcards (use files=)".to_string());
    }
    let path = normalize_fs(&expand_env(fs, raw));
    if path.contains('%') {
        return Err(format!("cannot resolve {raw}"));
    }
    if !looks_absolute(&path) || path.contains("..") {
        return Err(format!("{raw} is not an absolute path"));
    }
    if !under_custom_root(&path, &custom_roots(fs)) {
        return Err("custom files must live under a Temp folder or a browser profile".to_string());
    }
    let Some(split) = path.rfind('\\') else {
        return Err(format!("{raw} is not a file path"));
    };
    let (dir, name) = (&path[..split], &path[split + 1..]);
    if name.is_empty() {
        return Err(format!("{raw} is not a file path"));
    }
    Ok(PrivacyTarget::ExactFiles {
        dir: DirSpec::Fixed(dir.to_string()),
        names: vec![name.to_string()],
        sidecars: false,
    })
}

fn custom_dir(raw: &str, recursive: bool, fs: &dyn FileView) -> Result<PrivacyTarget, String> {
    let Some((dir, mask)) = raw.split_once('|') else {
        return Err("files= needs <dir>|<mask>".to_string());
    };
    let mask = mask.trim();
    if mask.is_empty() || mask.contains('\\') || mask.contains('/') || mask.contains("..") {
        return Err(format!("bad mask in {raw}"));
    }
    let dir = normalize_fs(&expand_env(fs, dir.trim()));
    if dir.contains('%') {
        return Err(format!("cannot resolve {raw}"));
    }
    if !looks_absolute(&dir) || dir.contains("..") {
        return Err(format!("{raw} is not an absolute path"));
    }
    if !under_custom_root(&dir, &custom_roots(fs)) {
        return Err(
            "custom folders must live under a Temp folder or a browser profile".to_string(),
        );
    }
    Ok(PrivacyTarget::DirFiles {
        dir: DirSpec::Fixed(dir),
        mask: mask.to_string(),
        recursive,
        min_age: None,
    })
}

fn custom_value(raw: &str) -> Result<PrivacyTarget, String> {
    let Some((key, name)) = raw.split_once('|') else {
        return Err("value= needs <key>|<name>".to_string());
    };
    let key = canonical_path(key.trim());
    let name = name.trim();
    if name.is_empty() || name.contains('*') || name.contains('?') {
        return Err("value= needs an exact value name".to_string());
    }
    if !privacy_reg_allowed(&key) {
        return Err(format!("{key} is outside the current user's history keys"));
    }
    Ok(PrivacyTarget::RegValues {
        key,
        values: ValueMatch::Exact(vec![name.to_string()]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemoryFs;
    use crate::model::ValueKind;
    use crate::registry::MemoryRegistry;

    #[test]
    fn prefix_digits_handles_unicode_names_without_panicking() {
        let spec = ValueMatch::PrefixDigits("url".into());
        // A multi-byte name whose byte length exceeds the prefix must not
        // panic on a non-boundary slice, and must not match.
        assert!(!spec.matches("éé"));
        assert!(!spec.matches("url"));
        assert!(!spec.matches("urlx"));
        assert!(spec.matches("url1"));
        assert!(spec.matches("URL42"));
    }

    struct FakeProcs {
        running: Vec<String>,
    }

    impl ProcessList for FakeProcs {
        fn running(&self, exe: &str) -> bool {
            self.running
                .iter()
                .any(|name| name.eq_ignore_ascii_case(exe))
        }
    }

    fn quiet() -> FakeProcs {
        FakeProcs {
            running: Vec::new(),
        }
    }

    #[derive(Default)]
    struct FakeSys {
        clipboard: usize,
        bin: (usize, u64),
        cleared: bool,
        emptied: bool,
    }

    impl SystemTargets for FakeSys {
        fn clipboard_items(&self) -> usize {
            self.clipboard
        }

        fn clear_clipboard(&mut self) -> Result<(), String> {
            self.cleared = true;
            self.clipboard = 0;
            Ok(())
        }

        fn bin_items(&self) -> (usize, u64) {
            self.bin
        }

        fn empty_bin(&mut self) -> Result<(), String> {
            self.emptied = true;
            self.bin = (0, 0);
            Ok(())
        }
    }

    const EXPLORER: &str = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer";

    fn seed_reg() -> MemoryRegistry {
        let mut reg = MemoryRegistry::new();
        reg.set_sz(&format!(r"{EXPLORER}\RunMRU"), "a", "mspaint");
        reg.set_sz(&format!(r"{EXPLORER}\RunMRU"), "MRUList", "a");
        reg.set_sz(
            r"HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\TypedURLs",
            "url1",
            "https://example.com",
        );
        reg.set(
            &format!(r"{EXPLORER}\RecentDocs"),
            "MRUListEx",
            ValueKind::Binary(vec![0, 0, 0, 0]),
        );
        reg.set_sz(&format!(r"{EXPLORER}\RecentDocs\.txt"), "0", "note");
        // Decoys the cleaner must never touch.
        reg.set_sz(
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Shell",
            "explorer",
        );
        reg
    }

    fn seed_fs() -> MemoryFs {
        let mut fs = MemoryFs::with_windows_dirs();
        fs.set_var("TEMP", r"C:\Users\test\AppData\Local\Temp");
        fs.set_var("TMP", r"C:\Users\test\AppData\Local\Temp");
        fs.set_var("LOCALAPPDATA", r"C:\Users\test\AppData\Local");
        fs.set_var("APPDATA", r"C:\Users\test\AppData\Roaming");
        fs.set_var("SystemRoot", r"C:\Windows");
        fs.set_var("ProgramFiles", r"C:\Program Files");
        fs.set_var("ProgramFiles(x86)", r"C:\Program Files (x86)");
        let old = Some(Duration::from_secs(49 * 3600));
        let fresh = Some(Duration::from_secs(3600));
        fs.add_file_bytes(
            r"C:\Users\test\AppData\Local\Temp\old.tmp",
            vec![1; 10],
            old,
        );
        fs.add_file_bytes(
            r"C:\Users\test\AppData\Local\Temp\sub\older.tmp",
            vec![1; 20],
            old,
        );
        fs.add_file_bytes(
            r"C:\Users\test\AppData\Local\Temp\fresh.tmp",
            vec![1; 30],
            fresh,
        );
        fs.add_file_bytes(
            r"C:\Users\test\AppData\Local\Temp\mystery.tmp",
            vec![1; 5],
            None,
        );
        fs.add_file_bytes(
            r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\Cache\f_000001",
            vec![1; 100],
            None,
        );
        fs.add_file_bytes(
            r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\History",
            vec![1; 50],
            None,
        );
        fs.add_file_bytes(
            r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\History-wal",
            vec![1; 8],
            None,
        );
        // Saved logins and autofill: never a clean target.
        fs.add_file_bytes(
            r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            vec![1; 60],
            None,
        );
        fs.add_file_bytes(
            r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\Web Data",
            vec![1; 70],
            None,
        );
        fs.add_file_bytes(r"C:\Windows\Temp\system.tmp", vec![1; 40], old);
        fs
    }

    fn builtin(id: &str) -> PrivacyItem {
        builtin_items()
            .into_iter()
            .find(|item| item.id == id)
            .expect("built-in id")
    }

    #[test]
    fn preview_counts_without_mutating() {
        let reg = seed_reg();
        let fs = seed_fs();
        let sys = FakeSys {
            clipboard: 1,
            bin: (2, 70),
            ..FakeSys::default()
        };
        let before_reg = format!("{:?}", reg);
        let before_fs = format!("{:?}", fs);
        let items = [
            "run-dialog",
            "typed-paths",
            "recent-docs",
            "user-temp",
            "clipboard",
            "recycle-bin",
        ]
        .into_iter()
        .map(builtin)
        .collect::<Vec<_>>();
        let report = preview(&reg, &fs, &sys, &quiet(), &items);
        assert_eq!(format!("{:?}", reg), before_reg);
        assert_eq!(format!("{:?}", fs), before_fs);
        let row = |id: &str| report.items.iter().find(|row| row.id == id).unwrap();
        assert_eq!(row("run-dialog").values, 2);
        assert_eq!(row("typed-paths").values, 1);
        // MRUListEx plus the .txt child value.
        assert_eq!(row("recent-docs").values, 2);
        // Two old temp files (TEMP and TMP resolve to one dir); fresh and
        // unknown-age files are skipped, the system temp file is out of scope.
        assert_eq!(row("user-temp").files, 2);
        assert_eq!(row("user-temp").bytes, 30);
        assert!(
            row("user-temp")
                .restricted
                .iter()
                .any(|note| note.contains("age unknown"))
        );
        assert_eq!(row("clipboard").other, 1);
        assert_eq!(row("recycle-bin").files, 2);
        assert_eq!(row("recycle-bin").bytes, 70);
    }

    #[test]
    fn clean_honors_ticks_veto_and_backup() {
        let mut reg = seed_reg();
        let mut fs = seed_fs();
        let mut sys = FakeSys::default();
        let backup = std::env::temp_dir().join("hive-mend-privacy-test.reg");
        // chrome-data is vetoed by a running browser; user-temp is not ticked.
        let procs = FakeProcs {
            running: vec!["chrome.exe".into()],
        };
        let items = [
            builtin("chrome-data"),
            builtin("chrome-cache"),
            builtin("run-dialog"),
        ]
        .to_vec();
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &procs,
            &items,
            &backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        let row = |id: &str| outcome.items.iter().find(|row| row.id == id).unwrap();
        assert!(row("chrome-data").skipped_running);
        assert_eq!(row("chrome-cache").files, 1);
        assert_eq!(row("chrome-cache").bytes, 100);
        assert_eq!(row("run-dialog").values, 2);
        // Vetoed and unticked tracks are untouched.
        assert!(fs.exists(r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\History"));
        assert!(fs.exists(r"C:\Users\test\AppData\Local\Temp\old.tmp"));
        assert!(reg.values(&format!(r"{EXPLORER}\RunMRU")).is_err());
        // The backup covers the removed values and restores through reg.exe.
        let body = crate::backup::read_backup(&backup).unwrap();
        assert!(body.contains("RunMRU"));
        assert!(body.contains("mspaint"));
        assert!(body.starts_with("Windows Registry Editor Version 5.00"));
        let _ = std::fs::remove_file(&backup);
    }

    #[test]
    fn clean_skips_what_the_backup_could_not_read() {
        struct Locked {
            inner: MemoryRegistry,
            locked: String,
        }

        impl Registry for Locked {
            fn subkeys(&self, path: &str) -> Result<Vec<String>, RegError> {
                self.inner.subkeys(path)
            }

            fn values(&self, path: &str) -> Result<Vec<crate::model::RegValue>, RegError> {
                if crate::pathutil::canonical_path(path).eq_ignore_ascii_case(&self.locked) {
                    return Err(RegError::Denied("access denied".into()));
                }
                self.inner.values(path)
            }

            fn delete_value(&mut self, path: &str, name: &str) -> Result<(), RegError> {
                self.inner.delete_value(path, name)
            }

            fn delete_tree(&mut self, path: &str) -> Result<(), RegError> {
                self.inner.delete_tree(path)
            }
        }

        let mut reg = Locked {
            inner: seed_reg(),
            locked: crate::pathutil::canonical_path(&format!(r"{EXPLORER}\RunMRU")),
        };
        let mut fs = seed_fs();
        let mut sys = FakeSys::default();
        let backup = std::env::temp_dir().join("hive-mend-privacy-locked-test.reg");
        let items = [builtin("run-dialog"), builtin("typed-paths")].to_vec();
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &items,
            &backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        let row = |id: &str| outcome.items.iter().find(|row| row.id == id).unwrap();
        assert_eq!(row("run-dialog").values, 0);
        assert!(
            row("run-dialog")
                .restricted
                .iter()
                .any(|note| note.contains("not backed up"))
        );
        assert_eq!(row("typed-paths").values, 1);
        assert!(reg.inner.values(&format!(r"{EXPLORER}\RunMRU")).is_ok());
        let _ = std::fs::remove_file(&backup);
    }

    #[test]
    fn custom_entries_validate_paths_keys_and_forms() {
        let fs = seed_fs();
        let custom = parse_custom(
            "file=%TEMP%\\app\\session.log\n\
             files=%TEMP%\\app|*.log\n\
             files-rec=%TMP%\\app|*.tmp\n\
             value=HKCU\\Software\\Example\\App|Recent\n\
             file=C:\\Windows\\Temp\\evil.tmp\n\
             file=%TEMP%\\app\\*.log\n\
             files=C:\\Data|x\n\
             value=HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon|Shell\n\
             value=HKLM\\Software\\Example|Recent\n\
             bogus line\n",
            &fs,
        );
        assert_eq!(custom.targets.len(), 4);
        assert_eq!(custom.warnings.len(), 6);
        assert!(
            custom
                .warnings
                .iter()
                .any(|note| note.contains("browser profile"))
        );
        assert!(
            custom
                .warnings
                .iter()
                .any(|note| note.contains("no wildcards"))
        );
        assert!(custom.warnings.iter().any(|note| note.contains("Winlogon")));
        assert!(
            custom
                .warnings
                .iter()
                .any(|note| note.contains("HKEY_LOCAL_MACHINE"))
        );
    }

    #[test]
    fn reg_and_file_gates_refuse_machine_scope_and_system_paths() {
        assert!(!privacy_reg_allowed(r"HKLM\Software\Example"));
        assert!(!privacy_reg_allowed(
            r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        ));
        assert!(!privacy_reg_allowed(r"HKEY_CURRENT_USER\Software"));
        assert!(privacy_reg_allowed(&format!(r"{EXPLORER}\RunMRU")));
        let fs = seed_fs();
        let temp = r"C:\Users\test\AppData\Local\Temp";
        assert!(privacy_file_allowed(&fs, temp, &format!(r"{temp}\a.tmp")));
        assert!(!privacy_file_allowed(&fs, temp, r"C:\Windows\Temp\a.tmp"));
        assert!(!privacy_file_allowed(
            &fs,
            temp,
            r"C:\Program Files\App\a.tmp"
        ));
        assert!(!privacy_file_allowed(
            &fs,
            temp,
            r"C:\HiveMend\backups\a.reg"
        ));
        assert!(!privacy_file_allowed(&fs, temp, r"C:\Users\test\a.tmp"));
    }

    #[test]
    fn a_cache_file_that_resolves_outside_its_root_is_not_deleted() {
        let mut fs = MemoryFs::with_windows_dirs();
        let root = r"C:\Users\me\AppData\Local\Temp";
        fs.add_file_bytes(&format!(r"{root}\ok.tmp"), vec![1; 8], None);
        fs.add_file_bytes(r"C:\Users\me\Documents\keep.txt", vec![2; 8], None);
        fs.add_alias(&format!(r"{root}\out"), r"C:\Users\me\Documents");
        let mut done = ItemOutcome::blank("test");
        let mut errors = Vec::new();
        for path in [format!(r"{root}\ok.tmp"), format!(r"{root}\out\keep.txt")] {
            let hit = FileHit { path, bytes: 8 };
            delete_file(&mut fs, root, &hit, &mut done, &mut errors);
        }
        assert_eq!(done.files, 1);
        assert!(errors.is_empty(), "{errors:?}");
        assert!(
            done.restricted
                .iter()
                .any(|note| note.contains("resolves to"))
        );
        assert_eq!(fs.read(r"C:\Users\me\Documents\keep.txt"), Some(vec![2; 8]));
    }

    #[test]
    fn file_gate_refuses_everything_when_a_system_folder_is_unknown() {
        let temp = r"C:\Users\test\AppData\Local\Temp";
        let file = format!(r"{temp}\a.tmp");
        assert!(privacy_file_allowed(
            &MemoryFs::with_windows_dirs(),
            temp,
            &file
        ));
        let mut fs = MemoryFs::with_windows_dirs();
        fs.set_var("ProgramFiles(x86)", "");
        assert!(!privacy_file_allowed(&fs, temp, &file));
        // ProgramData is protected for privacy deletes too.
        let data = r"C:\ProgramData\Vendor";
        assert!(!privacy_file_allowed(
            &MemoryFs::with_windows_dirs(),
            data,
            &format!(r"{data}\x.log")
        ));
    }

    #[test]
    fn masks_match_dos_style_case_insensitively() {
        assert!(mask_matches("anything", "*.*"));
        assert!(mask_matches("F_000001", "*.*"));
        assert!(mask_matches("debug.LOG", "*.log"));
        assert!(!mask_matches("debug.log.bak", "*.log"));
        assert!(mask_matches("url12", "url*"));
        assert!(mask_matches("ab", "a?"));
        assert!(!mask_matches("abc", "a?"));
        assert!(mask_matches("History-wal", "History*"));
    }

    #[test]
    fn unresolved_vars_report_restricted_not_silent() {
        let reg = seed_reg();
        let mut fs = MemoryFs::with_windows_dirs();
        fs.set_var("SystemRoot", r"C:\Windows");
        let sys = FakeSys::default();
        let report = preview(&reg, &fs, &sys, &quiet(), &[builtin("user-temp")]);
        assert_eq!(report.items[0].files, 0);
        assert!(
            report.items[0]
                .restricted
                .iter()
                .any(|note| note.contains("%TEMP%"))
        );
        assert!(
            report.items[0]
                .restricted
                .iter()
                .any(|note| note.contains("%TMP%"))
        );
    }

    #[test]
    fn special_targets_count_and_clean() {
        let mut reg = seed_reg();
        let mut fs = seed_fs();
        let mut sys = FakeSys {
            clipboard: 1,
            bin: (2, 70),
            ..FakeSys::default()
        };
        let items = [builtin("clipboard"), builtin("recycle-bin")].to_vec();
        let report = preview(&reg, &fs, &sys, &quiet(), &items);
        assert_eq!(report.items[0].other, 1);
        assert_eq!(report.items[1].files, 2);
        let backup = std::env::temp_dir().join("hive-mend-privacy-special-test.reg");
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &items,
            &backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        assert!(sys.cleared && sys.emptied);
        assert_eq!(outcome.items[0].other, 1);
        assert_eq!(outcome.items[1].files, 2);
        let _ = std::fs::remove_file(&backup);
    }

    #[test]
    fn no_category_overwrites_free_space() {
        // Overwriting a drive's free space does not reliably erase anything
        // on an SSD or NVMe drive and only adds wear, so it is not offered.
        assert!(
            build_items()
                .iter()
                .all(|item| !item.id.starts_with("freespace"))
        );
    }

    #[test]
    fn cancel_keeps_finished_items_and_stops() {
        let mut reg = seed_reg();
        let mut fs = seed_fs();
        let mut sys = FakeSys::default();
        let backup = std::env::temp_dir().join("hive-mend-privacy-cancel-test.reg");
        let items = [builtin("run-dialog"), builtin("typed-paths")].to_vec();
        let mut calls = 0;
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &items,
            &backup,
            &mut |_, _, _| {
                calls += 1;
                calls < 2
            },
        )
        .unwrap();
        assert!(outcome.canceled);
        assert_eq!(outcome.items.len(), 1);
        assert_eq!(outcome.items[0].id, "run-dialog");
        assert!(reg.values(&format!(r"{EXPLORER}\RunMRU")).is_err());
        let _ = std::fs::remove_file(&backup);
    }

    #[test]
    fn plugin_items_gate_on_installed_apps() {
        let mut reg = seed_reg();
        let fs = seed_fs();
        let sys = FakeSys::default();
        reg.set_sz(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinRAR",
            "DisplayName",
            "WinRAR 7.20 (64-bit)",
        );
        reg.set_sz(
            r"HKEY_CURRENT_USER\Software\WinRAR\ArcHistory",
            "0",
            "c.rar",
        );
        let items = [builtin("plugin-winrar"), builtin("plugin-7zip")].to_vec();
        let report = preview(&reg, &fs, &sys, &quiet(), &items);
        assert!(!report.items[0].gated_out);
        assert_eq!(report.items[0].values, 1);
        assert!(report.items[1].gated_out);
        let backup = std::env::temp_dir().join("hive-mend-privacy-plugin-test.reg");
        let outcome = clean_with_progress(
            &mut reg,
            &mut MemoryFs::with_windows_dirs(),
            &mut FakeSys::default(),
            &quiet(),
            &items,
            &backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        assert_eq!(outcome.items[0].values, 1);
        assert!(outcome.items[1].gated_out);
        let _ = std::fs::remove_file(&backup);
    }

    #[test]
    fn firefox_profiles_come_from_ini_and_folder() {
        let mut fs = MemoryFs::with_windows_dirs();
        fs.set_var("APPDATA", r"C:\Users\test\AppData\Roaming");
        let home = r"C:\Users\test\AppData\Roaming\Mozilla\Firefox";
        fs.add_file_bytes(
            &format!("{home}\\profiles.ini"),
            b"[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/abc.default\n".to_vec(),
            None,
        );
        fs.add_dir(&format!("{home}\\Profiles\\abc.default"));
        fs.add_dir(&format!("{home}\\Profiles\\plain.default"));
        let profiles = firefox_profiles(&fs, home);
        assert_eq!(profiles.len(), 2);
    }

    #[test]
    fn exact_files_take_sidecars_and_leave_the_rest() {
        let mut reg = seed_reg();
        let mut fs = seed_fs();
        let mut sys = FakeSys::default();
        let backup = std::env::temp_dir().join("hive-mend-privacy-sidecar-test.reg");
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &[builtin("chrome-data")],
            &backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        // History plus its -wal sidecar; -shm/-journal were absent.
        assert_eq!(outcome.items[0].files, 2);
        assert_eq!(outcome.items[0].bytes, 58);
        assert!(!fs.exists(r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\History"));
        // Saved logins and autofill survive the clean.
        assert!(
            fs.exists(r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\Login Data")
        );
        assert!(fs.exists(r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\Web Data"));
        assert!(
            fs.exists(
                r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\Cache\f_000001"
            )
        );
        let _ = std::fs::remove_file(&backup);
    }

    #[test]
    fn current_chromium_cookies_under_network_are_cleaned() {
        let mut reg = seed_reg();
        let mut fs = seed_fs();
        let profile = r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default";
        fs.add_file_bytes(&format!(r"{profile}\Network\Cookies"), vec![0; 40], None);
        fs.add_file_bytes(
            &format!(r"{profile}\Network\Cookies-journal"),
            vec![0; 2],
            None,
        );
        let mut sys = FakeSys::default();
        let backup = std::env::temp_dir().join("hive-mend-privacy-network-cookies.reg");
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &[builtin("chrome-data")],
            &backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        assert!(!fs.exists(&format!(r"{profile}\Network\Cookies")));
        assert!(!fs.exists(&format!(r"{profile}\Network\Cookies-journal")));
        assert!(!fs.exists(&format!(r"{profile}\History")));
        assert_eq!(
            outcome.items[0].files, 4,
            "History + wal, Cookies + journal"
        );
        let _ = std::fs::remove_file(&backup);
    }

    #[test]
    fn an_administrator_window_leaves_per_user_registry_targets() {
        let mut items = builtin_items();
        let before: usize = items.iter().map(|item| item.targets.len()).sum();
        leave_per_user_registry(&mut items);
        let after: usize = items.iter().map(|item| item.targets.len()).sum();
        assert!(after < before);
        for item in &items {
            for target in &item.targets {
                if let PrivacyTarget::RegTree { key } | PrivacyTarget::RegValues { key, .. } =
                    target
                {
                    assert!(!crate::pathutil::per_user_key(key), "{key}");
                }
            }
        }
        let run = items.iter().find(|item| item.id == "run-dialog").unwrap();
        assert!(!run.warnings.is_empty());
    }

    #[test]
    fn a_browser_that_starts_after_planning_is_still_respected() {
        // Closed while the plan is made, running by the time its turn comes.
        struct StartsLater(std::cell::Cell<u32>);
        impl ProcessList for StartsLater {
            fn running(&self, _exe: &str) -> bool {
                let calls = self.0.get() + 1;
                self.0.set(calls);
                calls > 1
            }
        }
        let mut reg = seed_reg();
        let mut fs = seed_fs();
        let mut sys = FakeSys::default();
        let history = r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\History";
        assert!(fs.exists(history));
        let backup = std::env::temp_dir().join("hive-mend-privacy-starts-later.reg");
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &StartsLater(std::cell::Cell::new(0)),
            &[builtin("chrome-data")],
            &backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        assert!(outcome.items[0].skipped_running);
        assert!(fs.exists(history), "a running browser's files were cleaned");
        let _ = std::fs::remove_file(&backup);
    }

    #[test]
    fn firefox_cache_is_found_in_the_local_profile_folder() {
        let mut fs = MemoryFs::with_windows_dirs();
        fs.set_var("LOCALAPPDATA", r"C:\Users\test\AppData\Local");
        fs.set_var("APPDATA", r"C:\Users\test\AppData\Roaming");
        let cache = r"C:\Users\test\AppData\Local\Mozilla\Firefox\Profiles\abc.default\cache2";
        fs.add_file_bytes(&format!(r"{cache}\entries\A1"), vec![0; 10], None);
        let (dirs, _) = resolve_dirs(
            &fs,
            &DirSpec::FirefoxLocal {
                sub: "cache2".into(),
            },
        );
        assert_eq!(dirs, [cache.to_string()]);
        let fox = builtin("firefox-data");
        assert!(fox.name.contains("form history"));
        assert!(
            !fox.detail
                .to_ascii_lowercase()
                .starts_with("browsing history")
        );
    }

    #[test]
    fn a_program_installed_for_this_account_counts_as_installed() {
        let mut reg = MemoryRegistry::new();
        assert!(!uninstall_present(&reg, "WinRAR"));
        reg.set_sz(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\WinRAR archiver",
            "DisplayName",
            "WinRAR 7.10 (64-bit)",
        );
        assert!(uninstall_present(&reg, "WinRAR"));
    }

    #[test]
    fn an_uncertain_keep_list_never_widens_what_is_removed() {
        use std::io::{Error, ErrorKind};
        let absent = cookie_keep_choice(Err(Error::from(ErrorKind::NotFound)), false);
        assert_eq!(absent.0, CookieKeep::All);
        let unreadable = cookie_keep_choice(Err(Error::from(ErrorKind::PermissionDenied)), false);
        assert!(matches!(unreadable.0, CookieKeep::LeaveAlone(_)));
        let invalid = cookie_keep_choice(Ok("not a site\n".into()), false);
        assert!(matches!(invalid.0, CookieKeep::LeaveAlone(_)));
        assert_eq!(invalid.1.len(), 1);
        let mixed = cookie_keep_choice(Ok("github.com\nnot a site\n".into()), false);
        assert!(matches!(mixed.0, CookieKeep::LeaveAlone(_)));
        let comments = cookie_keep_choice(Ok("# nothing kept\n".into()), false);
        assert_eq!(comments.0, CookieKeep::All);
        let sites = cookie_keep_choice(Ok("github.com\n".into()), false);
        assert_eq!(sites.0, CookieKeep::Sites(vec!["github.com".into()]));
        let elevated = cookie_keep_choice(Ok("github.com\n".into()), true);
        assert!(matches!(elevated.0, CookieKeep::LeaveAlone(_)));
    }

    #[test]
    fn cookies_left_alone_are_not_touched() {
        let mut reg = seed_reg();
        let mut fs = seed_fs();
        let profile = r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default";
        fs.add_file_bytes(&format!(r"{profile}\Network\Cookies"), vec![0; 40], None);
        let mut items = vec![builtin("chrome-data")];
        set_cookie_keep(
            &mut items,
            &CookieKeep::LeaveAlone("kept by request".into()),
        );
        assert!(items[0].detail.contains("Cookies are left alone"));
        let mut sys = FakeSys::default();
        let report = preview(&reg, &fs, &sys, &quiet(), &items);
        assert!(
            report.items[0]
                .restricted
                .iter()
                .any(|note| note == "kept by request")
        );
        let backup = std::env::temp_dir().join("hive-mend-privacy-cookies-alone.reg");
        clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &items,
            &backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        assert!(fs.exists(&format!(r"{profile}\Network\Cookies")));
        assert!(
            !fs.exists(&format!(r"{profile}\History")),
            "history still goes"
        );
        let _ = std::fs::remove_file(&backup);
    }
}
