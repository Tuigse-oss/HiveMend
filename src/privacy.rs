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
use std::path::PathBuf;
use std::time::Duration;

use crate::backup::{BackupWriter, export_repairs};
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
    // Browser databases are only ever edited, never deleted: a database and
    // its journal or log cannot be removed together all-or-nothing across a
    // crash, so cookies are removed from inside the database by SQLite.
    // Saved logins, autofill, bookmarks, and history are not touched.
    for (vendor, id, name, exe) in [
        (
            "Google\\Chrome",
            "chrome-data",
            "Chrome cookies (closed)",
            "chrome.exe",
        ),
        (
            "Microsoft\\Edge",
            "edge-data",
            "Edge cookies (closed)",
            "msedge.exe",
        ),
    ] {
        let mut closed = item(
            id,
            name,
            PrivacyGroup::Browsers,
            "Cookies, only while the browser is closed.",
            vec![
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
        "Firefox cookies (closed)",
        PrivacyGroup::Browsers,
        "Cookies, only while the browser is closed.",
        vec![PrivacyTarget::Cookies {
            dir: DirSpec::Firefox { sub: String::new() },
            names: vec!["cookies.sqlite".to_string()],
            keep: CookieKeep::All,
        }],
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

/// For an administrator window: browser history and cookie items do
/// nothing, and say so. Their files sit in folders programs running without
/// elevation can change, and the keep list that governs them is per-user.
pub fn leave_browsers_alone(items: &mut [PrivacyItem]) {
    for item in items {
        let browser = item
            .targets
            .iter()
            .any(|target| matches!(target, PrivacyTarget::Cookies { .. }));
        if browser {
            item.targets.clear();
            item.warnings.push(
                "Browser data is cleaned from Hivemend started without administrator rights."
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
            item.detail = match keep {
                CookieKeep::All => "Cookies, only while the browser is closed.".to_string(),
                CookieKeep::Sites(sites) => format!(
                    "Cookies, only while the browser is closed. Cookies for {} on your keep list stay.",
                    if sites.len() == 1 {
                        "the 1 site".to_string()
                    } else {
                        format!("the {} sites", sites.len())
                    }
                ),
                CookieKeep::LeaveAlone(_) => "Cookies are left alone.".to_string(),
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
/// that could not be resolved (unknown `%VAR%`). Profile discovery asks
/// `keep_going` as it goes; `None` means it was told to stop, and the caller
/// stops too, using nothing it found.
fn resolve_dirs(
    fs: &dyn FileView,
    spec: &DirSpec,
    keep_going: &mut dyn FnMut() -> bool,
) -> Option<(Vec<String>, Vec<String>)> {
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
                return Some((dirs, notes));
            }
            let users = format!("{base}\\{vendor}\\User Data");
            for profile in child_dirs(fs, &users, &mut notes, keep_going)? {
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
                return Some((dirs, notes));
            }
            let profiles = format!("{base}\\Mozilla\\Firefox\\Profiles");
            for profile in child_dirs(fs, &profiles, &mut notes, keep_going)? {
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
                return Some((dirs, notes));
            }
            let home = format!("{base}\\Mozilla\\Firefox");
            for profile in firefox_profiles(fs, &home, &mut notes, keep_going)? {
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
    Some((dirs, notes))
}

/// The most profile folders looked at under one folder.
const MAX_PROFILES: usize = 1_000;

/// How many listed entries or profile paths between `keep_going` checks.
const DISCOVERY_CHECK_EVERY: usize = 64;

/// Folders in `dir`, at most [`MAX_PROFILES`]; a note says when there
/// were more, so the rest is never taken as looked at. `None` when
/// `keep_going` said stop.
fn child_dirs(
    fs: &dyn FileView,
    dir: &str,
    notes: &mut Vec<String>,
    keep_going: &mut dyn FnMut() -> bool,
) -> Option<Vec<String>> {
    let mut dirs = Vec::new();
    let mut more = false;
    let mut seen = 0usize;
    let mut stopped = false;
    fs.list_each(dir, &mut |item| {
        seen += 1;
        if seen.is_multiple_of(DISCOVERY_CHECK_EVERY) && !keep_going() {
            stopped = true;
            return false;
        }
        if item.kind != ItemKind::Dir {
            return true;
        }
        if dirs.len() == MAX_PROFILES {
            more = true;
            return false;
        }
        dirs.push(format!("{dir}\\{}", item.name));
        true
    });
    if more {
        notes.push(format!(
            "{dir}: more than {MAX_PROFILES} profiles; only the first {MAX_PROFILES} were looked at"
        ));
    }
    if stopped {
        return None;
    }
    Some(dirs)
}

/// The largest `profiles.ini` read. Firefox writes a few hundred bytes per
/// profile, so this holds far more than [`MAX_PROFILES`] of them.
const MAX_PROFILES_INI: usize = 1 << 20;

/// Firefox profiles from `profiles.ini` plus the `Profiles` folder, so a
/// missing ini still finds default locations. Together they are capped at
/// [`MAX_PROFILES`], with a note when there were more; an oversized ini is
/// not read. `None` when `keep_going` said stop.
fn firefox_profiles(
    fs: &dyn FileView,
    home: &str,
    notes: &mut Vec<String>,
    keep_going: &mut dyn FnMut() -> bool,
) -> Option<Vec<String>> {
    let mut profiles = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut more = false;
    // False once full: the caller stops looking.
    let mut push = |dir: String| -> bool {
        if seen.contains(&dir.to_ascii_lowercase()) {
            return true;
        }
        if profiles.len() == MAX_PROFILES {
            more = true;
            return false;
        }
        seen.insert(dir.to_ascii_lowercase());
        profiles.push(dir);
        true
    };
    // Paths the ini names, each looked up at most once; at most
    // MAX_PROFILES of them are looked up at all.
    let mut named = std::collections::HashSet::new();
    let mut stopped = false;
    let mut ini_more = false;
    let ini = format!("{home}\\profiles.ini");
    match fs.read_head(&ini, MAX_PROFILES_INI + 1) {
        Some(bytes) if bytes.len() > MAX_PROFILES_INI => notes.push(format!(
            "{ini} is larger than {} KB, so it was not read; only the Profiles folder was looked at",
            MAX_PROFILES_INI / 1024
        )),
        Some(bytes) => {
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
                    if !named.insert(dir.to_ascii_lowercase()) {
                        continue;
                    }
                    if named.len() > MAX_PROFILES {
                        ini_more = true;
                        break;
                    }
                    if named.len().is_multiple_of(DISCOVERY_CHECK_EVERY) && !keep_going() {
                        stopped = true;
                        break;
                    }
                    if fs.is_dir(&dir) && !push(dir) {
                        break;
                    }
                }
            }
        }
        None => {}
    }
    if stopped {
        return None;
    }
    for profile in child_dirs(fs, &format!("{home}\\Profiles"), notes, keep_going)? {
        if !push(profile) {
            break;
        }
    }
    if more || ini_more {
        notes.push(format!(
            "{home}: more than {MAX_PROFILES} profiles; only the first {MAX_PROFILES} were looked at"
        ));
    }
    Some(profiles)
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
    /// Stopped before every category was counted: not a complete preview.
    pub canceled: bool,
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
    preview_with(reg, fs, sys, procs, items, &mut || true)
}

/// [`preview`] that asks `keep_going` between categories, between folders,
/// and every few thousand files inside a large folder, and stops as soon as
/// it says no; the result is then marked canceled.
pub fn preview_with(
    reg: &dyn Registry,
    fs: &dyn FileView,
    sys: &dyn SystemTargets,
    procs: &dyn ProcessList,
    items: &[PrivacyItem],
    keep_going: &mut dyn FnMut() -> bool,
) -> Preview {
    let mut out = Preview::default();
    for item in items {
        if !keep_going() {
            out.canceled = true;
            return out;
        }
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
            if !preview_target(reg, fs, sys, target, &mut row, &mut walked, keep_going) {
                out.canceled = true;
                return out;
            }
        }
        out.items.push(row);
    }
    out
}

/// False when `keep_going` stopped it.
fn preview_target(
    reg: &dyn Registry,
    fs: &dyn FileView,
    sys: &dyn SystemTargets,
    target: &PrivacyTarget,
    row: &mut PreviewItem,
    walked: &mut HashSet<String>,
    keep_going: &mut dyn FnMut() -> bool,
) -> bool {
    match target {
        PrivacyTarget::RegTree { key } => {
            if !privacy_reg_allowed(key) {
                row.note(format!("refused: {key}"));
                return true;
            }
            row.values += count_tree(reg, key, 0, row);
        }
        PrivacyTarget::RegValues { key, values } => {
            if !privacy_reg_allowed(key) {
                row.note(format!("refused: {key}"));
                return true;
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
            let Some((dirs, notes)) = resolve_dirs(fs, dir, keep_going) else {
                return false;
            };
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
                let mut counted = (0usize, 0u64);
                let mut budget = WalkBudget::new(false);
                let finished = walk_files(
                    fs,
                    &dir,
                    mask,
                    *recursive,
                    *min_age,
                    0,
                    &mut |hit| {
                        counted.0 += 1;
                        counted.1 += hit.bytes;
                        true
                    },
                    keep_going,
                    &mut budget,
                    row,
                );
                row.files += counted.0;
                row.bytes += counted.1;
                if let Some(note) = budget.shortfall(&dir) {
                    row.note(note);
                }
                if !finished && !budget.exhausted {
                    return false;
                }
            }
        }
        PrivacyTarget::ExactFiles {
            dir,
            names,
            sidecars,
        } => {
            let Some((dirs, notes)) = resolve_dirs(fs, dir, keep_going) else {
                return false;
            };
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
                    if *sidecars {
                        row.note(format!("{dir}\\{name}: database files are not deleted"));
                        continue;
                    }
                    let path = format!("{dir}\\{name}");
                    if fs.is_dir(&path) {
                        row.note(format!("not a file: {path}"));
                    } else if fs.exists(&path) {
                        row.files += 1;
                        row.bytes += fs.len(&path).unwrap_or(0);
                    }
                }
            }
        }
        PrivacyTarget::Cookies { dir, names, keep } => {
            if let CookieKeep::LeaveAlone(reason) = keep {
                row.note(reason.clone());
                return true;
            }
            let Some((dirs, notes)) = resolve_dirs(fs, dir, keep_going) else {
                return false;
            };
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
                    _ => match crate::cookies::count_cookies(std::path::Path::new(&db), &[]) {
                        Ok(count) => row.cookies += count.removed,
                        Err(err) => row.note(format!("cannot read {db}: {err}")),
                    },
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
    true
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
    /// The age the file had to have to be listed; checked again on the
    /// object about to be deleted.
    min_age: Option<Duration>,
}

/// The most files one clean takes from one folder walk, and the most bytes
/// of their paths; past either the rest are left for another run, and the
/// clean says so.
const MAX_WALK_HITS: usize = 100_000;
const MAX_WALK_HIT_BYTES: usize = 64 * 1024 * 1024;

/// The most folders one walk visits or queues; past it the walk stops and
/// says it covered only part.
const MAX_WALK_FOLDERS: usize = 100_000;

/// Folders a walk may still queue, and whether it ran out.
/// What a walk may still keep, and why it stopped short, if it did.
struct WalkBudget {
    folders_left: usize,
    /// Bytes of path text it may still keep: queued folders always, and
    /// the files it hands on when `charge_hits` (a clean keeps them).
    bytes_left: usize,
    charge_hits: bool,
    /// A folder or byte limit was reached.
    exhausted: bool,
    /// Folders deeper than the walk goes were not looked at.
    too_deep: bool,
}

impl WalkBudget {
    fn new(charge_hits: bool) -> Self {
        Self {
            folders_left: MAX_WALK_FOLDERS,
            bytes_left: MAX_WALK_HIT_BYTES,
            charge_hits,
            exhausted: false,
            too_deep: false,
        }
    }

    /// Take `bytes` of path text from the budget, or say it ran out.
    fn charge(&mut self, bytes: usize) -> bool {
        if bytes > self.bytes_left {
            self.exhausted = true;
            return false;
        }
        self.bytes_left -= bytes;
        true
    }

    /// The note saying how a walk of `dir` fell short, if it did.
    fn shortfall(&self, dir: &str) -> Option<String> {
        if self.exhausted {
            Some(format!(
                "{dir}: too large to go through at once (more than {MAX_WALK_FOLDERS} folders or {} MB of paths); the rest was not looked at",
                MAX_WALK_HIT_BYTES / (1024 * 1024)
            ))
        } else if self.too_deep {
            Some(format!(
                "{dir}: folders more than {MAX_WALK_DEPTH} levels down were not looked at"
            ))
        } else {
            None
        }
    }
}

/// How deep a walk goes.
const MAX_WALK_DEPTH: usize = 64;

/// Walk `dir` for files matching `mask`, one entry at a time, handing each
/// to `on_hit` (false stops the walk). `keep_going` is asked for every
/// folder and every [`crate::diskspace::CHECK_EVERY`] entries. Returns false
/// when the walk was stopped.
#[allow(clippy::too_many_arguments)]
fn walk_files(
    fs: &dyn FileView,
    dir: &str,
    mask: &str,
    recursive: bool,
    min_age: Option<Duration>,
    depth: usize,
    on_hit: &mut dyn FnMut(FileHit) -> bool,
    keep_going: &mut dyn FnMut() -> bool,
    budget: &mut WalkBudget,
    row: &mut PreviewItem,
) -> bool {
    if depth > MAX_WALK_DEPTH {
        // Not looked at, and said so: never reported as covered.
        budget.too_deep = true;
        return true;
    }
    if !keep_going() {
        return false;
    }
    let mut subdirs = Vec::new();
    let mut listed = 0u64;
    let mut going = true;
    fs.list_each(dir, &mut |entry| {
        listed += 1;
        if listed.is_multiple_of(crate::diskspace::CHECK_EVERY) && !keep_going() {
            going = false;
            return false;
        }
        let path = format!("{dir}\\{}", entry.name);
        match entry.kind {
            ItemKind::File => {
                if !mask_matches(&entry.name, mask) {
                    return true;
                }
                if let Some(min) = min_age {
                    match entry.age {
                        Some(age) if age >= min => {}
                        Some(_) => return true,
                        None => {
                            row.note(format!("age unknown: {path}"));
                            return true;
                        }
                    }
                }
                if budget.charge_hits && !budget.charge(path.len()) {
                    going = false;
                    return false;
                }
                let bytes = fs.len(&path).unwrap_or(0);
                if !on_hit(FileHit {
                    path,
                    bytes,
                    min_age,
                }) {
                    going = false;
                    return false;
                }
            }
            ItemKind::Dir => {
                if recursive {
                    if budget.folders_left == 0 || !budget.charge(path.len()) {
                        budget.exhausted = true;
                        going = false;
                        return false;
                    }
                    budget.folders_left -= 1;
                    subdirs.push(path);
                }
            }
            ItemKind::Other => row.note(format!("not a plain file: {path}")),
        }
        true
    });
    if !going {
        return false;
    }
    for path in subdirs {
        if !walk_files(
            fs,
            &path,
            mask,
            recursive,
            min_age,
            depth + 1,
            on_hit,
            keep_going,
            budget,
            row,
        ) {
            return false;
        }
    }
    true
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
    /// Cancel stopped this category part way; the rest of it was left.
    pub canceled: bool,
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
    backup: &mut BackupWriter,
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

    // The header now; each registry entry is appended as it is removed.
    let header = export_repairs(reg, &[], backup.path());
    backup.append(&header.body)?;

    let total = planned
        .iter()
        .filter(|step| matches!(step, Planned::Run { .. }))
        .count();
    let mut outcome = CleanOutcome {
        backup_file: backup.path().to_path_buf(),
        ..CleanOutcome::default()
    };
    let mut entry = 0usize;
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
                let step = execute_item(
                    reg,
                    fs,
                    sys,
                    procs,
                    &mut || progress(done, total, &item.name),
                    item,
                    &repairs,
                    pre,
                    backup,
                    &mut entry,
                    &mut outcome.errors,
                );
                let canceled = step.canceled;
                outcome.items.push(step);
                done += 1;
                if canceled {
                    outcome.canceled = true;
                    return Ok(outcome);
                }
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
    procs: &dyn ProcessList,
    keep_going: &mut dyn FnMut() -> bool,
    item: &PrivacyItem,
    repairs: &[PlannedRepair],
    pre: Vec<String>,
    backup: &mut BackupWriter,
    entry: &mut usize,
    errors: &mut Vec<String>,
) -> ItemOutcome {
    let mut done = ItemOutcome::blank(&item.id);
    // Checked again right before each database set is taken: a program
    // that starts part way through stops the rest of its category.
    let started = |done: &mut ItemOutcome| {
        let exe = item.veto_exes.iter().find(|exe| procs.running(exe))?;
        done.skipped_running = true;
        done.note(format!(
            "{exe} started, so the rest of this category was left alone"
        ));
        Some(())
    };
    for warning in &item.warnings {
        done.note(warning.clone());
    }
    for note in pre {
        done.note(note);
    }
    for (repair, credit) in repairs {
        *entry += 1;
        apply_repair(reg, repair, *credit, backup, *entry, &mut done, errors);
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
                let Some((dirs, notes)) = resolve_dirs(fs, dir, keep_going) else {
                    done.canceled = true;
                    return done;
                };
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
                    let mut budget = WalkBudget::new(true);
                    let finished = walk_files(
                        fs,
                        &dir,
                        mask,
                        *recursive,
                        *min_age,
                        0,
                        &mut |hit| {
                            hits.push(hit);
                            hits.len() < MAX_WALK_HITS
                        },
                        keep_going,
                        &mut budget,
                        &mut counter,
                    );
                    for note in counter.restricted {
                        done.note(note);
                    }
                    done.restricted_extra += counter.restricted_extra;
                    if let Some(note) = budget.shortfall(&dir) {
                        done.note(note);
                    }
                    if !finished && !budget.exhausted && hits.len() < MAX_WALK_HITS {
                        // Canceled while listing: nothing from this walk goes.
                        done.canceled = true;
                        return done;
                    } else if !finished && !budget.exhausted {
                        done.note(format!(
                            "{dir}: more than {} files; the rest were left for another clean",
                            hits.len()
                        ));
                    }
                    for (index, hit) in hits.into_iter().enumerate() {
                        if index % 256 == 255 && !keep_going() {
                            done.canceled = true;
                            return done;
                        }
                        delete_file(fs, &dir, &hit, &mut done, errors);
                    }
                }
            }
            PrivacyTarget::ExactFiles {
                dir,
                names,
                sidecars,
            } => {
                let Some((dirs, notes)) = resolve_dirs(fs, dir, keep_going) else {
                    done.canceled = true;
                    return done;
                };
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
                        if started(&mut done).is_some() {
                            return done;
                        }
                        // A file with side files is a database set, which
                        // Hivemend does not delete.
                        if *sidecars {
                            done.note(format!("{dir}\\{name}: database files are not deleted"));
                            continue;
                        }
                        let path = format!("{dir}\\{name}");
                        if fs.is_dir(&path) {
                            done.note(format!("not a file: {path}"));
                            continue;
                        }
                        if !fs.exists(&path) {
                            continue;
                        }
                        let hit = FileHit {
                            bytes: fs.len(&path).unwrap_or(0),
                            path,
                            min_age: None,
                        };
                        delete_file(fs, &dir, &hit, &mut done, errors);
                    }
                }
            }
            PrivacyTarget::Cookies { dir, names, keep } => {
                if let CookieKeep::LeaveAlone(reason) = keep {
                    done.note(reason.clone());
                    continue;
                }
                let Some((dirs, notes)) = resolve_dirs(fs, dir, keep_going) else {
                    done.canceled = true;
                    return done;
                };
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
                    if started(&mut done).is_some() {
                        return done;
                    }
                    match keep {
                        CookieKeep::Sites(sites) => {
                            trim_cookie_db(fs, &dir, &db, sites, &mut done, errors);
                        }
                        // Every cookie, by the same edit: the database is
                        // never deleted.
                        _ => trim_cookie_db(fs, &dir, &db, &[], &mut done, errors),
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
    backup: &mut BackupWriter,
    entry: usize,
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
    // Recorded, removed, and committed in one registry transaction; a
    // change from elsewhere meanwhile leaves it in place.
    match crate::engine::delete_in_transaction(reg, repair, backup, entry) {
        Ok(crate::engine::Deleted::Removed) => done.values += credit,
        Ok(crate::engine::Deleted::AlreadyGone) => done.already_gone += 1,
        Ok(crate::engine::Deleted::NotBackedUp) => {
            done.note(format!("not backed up, left alone: {key}"));
        }
        Ok(crate::engine::Deleted::Untrusted(why)) => done.note(why),
        Ok(crate::engine::Deleted::TooLarge) => {
            done.note(format!(
                "left alone, its backup would be larger than a restore accepts: {key}"
            ));
        }
        Ok(crate::engine::Deleted::BackupFailed(why)) => {
            // The writer refuses everything after a failed write, so no
            // registry entry is removed from here on; say so once.
            let message = format!(
                "the backup could not be written ({why}); no more registry entries were removed"
            );
            if !errors.contains(&message) {
                errors.push(message);
            }
        }
        Ok(crate::engine::Deleted::RemovedUnconfirmed(why)) => {
            done.values += credit;
            errors.push(format!(
                "{key}: removed, but its backup record could not be completed ({why}); its saved data is in the backup as entry {entry}, which a restore lists but does not put back by itself"
            ));
        }
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
        Ok(count) => done.cookies += count.removed,
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
    // A file listed for being old is taken so nothing else can write it,
    // then its age is read again: written to, or replaced, since it was
    // listed, or busy now, and it stays.
    let result = if let Some(min) = hit.min_age {
        match fs.pin_acquire(&mut pin, Access::DeleteExclusive) {
            Ok(()) if !pin.age.is_some_and(|age| age >= min) => {
                done.note(format!(
                    "changed since it was listed, left alone: {}",
                    hit.path
                ));
                return;
            }
            Ok(()) => fs.pin_delete(pin),
            Err(err) => Err(err),
        }
    } else {
        fs.pin_acquire(&mut pin, Access::Delete)
            .and_then(|()| fs.pin_delete(pin))
    };
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
        let mut backup = crate::backup::test_writer("hive-mend-privacy-test");
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
            &mut backup,
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
        let body = crate::backup::read_backup(backup.path()).unwrap();
        assert!(body.contains("RunMRU"));
        assert!(body.contains("mspaint"));
        assert!(body.starts_with("Windows Registry Editor Version 5.00"));
        let _ = std::fs::remove_file(backup.path());
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

            fn begin(&mut self) -> Result<Box<dyn crate::registry::RegTransaction + '_>, RegError> {
                let locked = self.locked.clone();
                Ok(Box::new(crate::registry::DenyTx {
                    inner: self.inner.begin()?,
                    deny_subkeys: None,
                    deny_values: Some(locked),
                    deny_writes: None,
                }))
            }
        }

        let mut reg = Locked {
            inner: seed_reg(),
            locked: crate::pathutil::canonical_path(&format!(r"{EXPLORER}\RunMRU")),
        };
        let mut fs = seed_fs();
        let mut sys = FakeSys::default();
        let mut backup = crate::backup::test_writer("hive-mend-privacy-locked-test");
        let items = [builtin("run-dialog"), builtin("typed-paths")].to_vec();
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &items,
            &mut backup,
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
        let _ = std::fs::remove_file(backup.path());
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
            let hit = FileHit {
                path,
                bytes: 8,
                min_age: None,
            };
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
        let mut backup = crate::backup::test_writer("hive-mend-privacy-special-test");
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &items,
            &mut backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        assert!(sys.cleared && sys.emptied);
        assert_eq!(outcome.items[0].other, 1);
        assert_eq!(outcome.items[1].files, 2);
        let _ = std::fs::remove_file(backup.path());
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
        let mut backup = crate::backup::test_writer("hive-mend-privacy-cancel-test");
        let items = [builtin("run-dialog"), builtin("typed-paths")].to_vec();
        let mut calls = 0;
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &items,
            &mut backup,
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
        let _ = std::fs::remove_file(backup.path());
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
        let mut backup = crate::backup::test_writer("hive-mend-privacy-plugin-test");
        let outcome = clean_with_progress(
            &mut reg,
            &mut MemoryFs::with_windows_dirs(),
            &mut FakeSys::default(),
            &quiet(),
            &items,
            &mut backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        assert_eq!(outcome.items[0].values, 1);
        assert!(outcome.items[1].gated_out);
        let _ = std::fs::remove_file(backup.path());
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
        let profiles = firefox_profiles(&fs, home, &mut Vec::new(), &mut || true).unwrap();
        assert_eq!(profiles.len(), 2);
    }

    #[test]
    fn firefox_profiles_stay_within_the_limit_from_both_sources() {
        let mut fs = MemoryFs::with_windows_dirs();
        let home = r"C:\Users\test\AppData\Roaming\Mozilla\Firefox";
        // The ini names MAX_PROFILES profiles, the folder holds as many
        // others (and repeats of the ini's ones in other letter case).
        let mut ini = String::new();
        for n in 0..MAX_PROFILES {
            ini.push_str(&format!(
                "[Profile{n}]\nIsRelative=1\nPath=Profiles/ini{n}\n"
            ));
            fs.add_dir(&format!(r"{home}\Profiles\ini{n}"));
        }
        for n in 0..MAX_PROFILES / 2 {
            fs.add_dir(&format!(r"{home}\Profiles\dir{n}"));
        }
        fs.add_file_bytes(&format!(r"{home}\profiles.ini"), ini.into_bytes(), None);
        let mut notes = Vec::new();
        let profiles = firefox_profiles(&fs, home, &mut notes, &mut || true).unwrap();
        assert_eq!(profiles.len(), MAX_PROFILES);
        let unique: std::collections::HashSet<String> = profiles
            .iter()
            .map(|dir| dir.to_ascii_lowercase())
            .collect();
        assert_eq!(unique.len(), MAX_PROFILES);
        assert!(
            notes
                .iter()
                .any(|note| note.contains("more than") && note.contains(home)),
            "{notes:?}"
        );

        // Within the limit, repeats count once and nothing is noted.
        let mut fs = MemoryFs::with_windows_dirs();
        fs.add_file_bytes(
            &format!(r"{home}\profiles.ini"),
            b"[Profile0]\nIsRelative=1\nPath=Profiles/A\n[Profile1]\nIsRelative=0\nPath=C:\\Users\\test\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\a\n".to_vec(),
            None,
        );
        fs.add_dir(&format!(r"{home}\Profiles\a"));
        let mut notes = Vec::new();
        assert_eq!(
            firefox_profiles(&fs, home, &mut notes, &mut || true)
                .unwrap()
                .len(),
            1
        );
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn profile_discovery_stops_when_cancelled() {
        let mut fs = MemoryFs::with_windows_dirs();
        let home = r"C:\Users\test\AppData\Roaming\Mozilla\Firefox";
        let mut ini = String::new();
        for n in 0..900 {
            ini.push_str(&format!(
                "[Profile{n}]\nIsRelative=1\nPath=Profiles/ini{n}\n"
            ));
            fs.add_dir(&format!(r"{home}\Profiles\ini{n}"));
        }
        fs.add_file_bytes(&format!(r"{home}\profiles.ini"), ini.into_bytes(), None);
        let users = r"C:\Users\test\AppData\Local\Google\Chrome\User Data";
        for n in 0..900 {
            fs.add_dir(&format!(r"{users}\P{n:04}"));
        }
        let all = firefox_profiles(&fs, home, &mut Vec::new(), &mut || true).unwrap();
        assert_eq!(all.len(), 900);
        // Told to stop: nothing found is handed back, and it asks only once.
        let mut asked = 0;
        let stopped = firefox_profiles(&fs, home, &mut Vec::new(), &mut || {
            asked += 1;
            false
        });
        assert_eq!(stopped, None);
        assert_eq!(asked, 1);
        let mut asked = 0;
        let stopped = child_dirs(&fs, users, &mut Vec::new(), &mut || {
            asked += 1;
            false
        });
        assert_eq!(stopped, None);
        assert_eq!(asked, 1);
    }

    /// Cancel while browser profiles are still being found: Clean edits no
    /// cookie database and says it was cancelled, and Preview says so too.
    #[test]
    fn cancel_during_profile_discovery_stops_preview_and_clean() {
        let mut reg = seed_reg();
        let mut fs = seed_fs();
        let mut sys = FakeSys::default();
        let users = r"C:\Users\test\AppData\Local\Google\Chrome\User Data";
        for n in 0..300 {
            fs.add_file_bytes(
                &format!(r"{users}\P{n:03}\Network\Cookies"),
                vec![7; 64],
                None,
            );
        }
        let items = vec![builtin("chrome-data")];
        // The first question (before the category) says go on; every one
        // after it, which discovery asks, says stop.
        let mut calls = 0;
        let preview = preview_with(&reg, &fs, &sys, &quiet(), &items, &mut || {
            calls += 1;
            calls < 2
        });
        assert!(calls >= 2, "discovery never asked");
        assert!(preview.canceled);
        assert!(preview.items.is_empty());
        let mut backup = crate::backup::test_writer("hive-mend-privacy-discovery-cancel");
        let mut calls = 0;
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &items,
            &mut backup,
            &mut |_, _, _| {
                calls += 1;
                calls < 2
            },
        )
        .unwrap();
        let _ = std::fs::remove_file(backup.path());
        assert!(calls >= 2, "discovery never asked");
        assert!(outcome.canceled);
        assert!(outcome.items[0].canceled);
        assert_eq!(outcome.items[0].cookies, 0);
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert!(
            outcome.items[0]
                .restricted
                .iter()
                .all(|note| !note.contains("Cookies")),
            "a database was looked at: {:?}",
            outcome.items[0].restricted
        );
        for n in 0..300 {
            let db = format!(r"{users}\P{n:03}\Network\Cookies");
            assert_eq!(fs.read(&db), Some(vec![7; 64]), "{db}");
        }
    }

    #[test]
    fn an_oversized_profiles_ini_is_not_read() {
        let mut fs = MemoryFs::with_windows_dirs();
        let home = r"C:\Users\test\AppData\Roaming\Mozilla\Firefox";
        let mut ini = b"[Profile0]\nIsRelative=1\nPath=Profiles/listed\n".to_vec();
        ini.resize(MAX_PROFILES_INI + 1, b';');
        fs.add_file_bytes(&format!(r"{home}\profiles.ini"), ini, None);
        fs.add_dir(&format!(r"{home}\elsewhere"));
        fs.add_dir(&format!(r"{home}\Profiles\plain"));
        let mut notes = Vec::new();
        let profiles = firefox_profiles(&fs, home, &mut notes, &mut || true).unwrap();
        assert_eq!(profiles, vec![format!(r"{home}\Profiles\plain")]);
        assert!(
            notes.iter().any(|note| note.contains("not read")),
            "{notes:?}"
        );
    }

    /// Browser categories never delete a database file: cookies are only
    /// removed from inside the database by SQLite, and history, logins,
    /// and form data stay.
    #[test]
    fn browser_categories_delete_no_database_files() {
        let mut reg = seed_reg();
        let mut fs = seed_fs();
        let profile = r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default";
        fs.add_file_bytes(&format!(r"{profile}\Network\Cookies"), vec![0; 40], None);
        fs.add_file_bytes(
            &format!(r"{profile}\Network\Cookies-journal"),
            vec![0; 2],
            None,
        );
        let before: Vec<String> = [
            "History",
            "History-wal",
            "Login Data",
            "Web Data",
            r"Network\Cookies",
            r"Network\Cookies-journal",
        ]
        .iter()
        .map(|name| format!(r"{profile}\{name}"))
        .filter(|path| fs.exists(path))
        .collect();
        assert!(before.len() >= 4);
        let mut sys = FakeSys::default();
        let mut backup = crate::backup::test_writer("hive-mend-privacy-no-db-delete");
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &[
                builtin("chrome-data"),
                builtin("edge-data"),
                builtin("firefox-data"),
            ],
            &mut backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        let _ = std::fs::remove_file(backup.path());
        for path in &before {
            assert!(fs.exists(path), "{path} was deleted");
        }
        assert!(outcome.items.iter().all(|item| item.files == 0));
        assert!(
            builtin("chrome-data")
                .targets
                .iter()
                .all(|target| matches!(target, PrivacyTarget::Cookies { .. }))
        );
    }

    #[test]
    fn a_custom_file_with_side_files_is_never_deleted_as_a_set() {
        let mut reg = seed_reg();
        let mut fs = seed_fs();
        let temp = r"C:\Users\test\AppData\Local\Temp";
        fs.add_file_bytes(&format!(r"{temp}\one.log"), vec![1; 3], None);
        let mut set = builtin("user-temp");
        set.targets = vec![PrivacyTarget::ExactFiles {
            dir: DirSpec::Fixed(temp.into()),
            names: vec!["one.log".into()],
            sidecars: true,
        }];
        let mut single = set.clone();
        single.id = "single".into();
        single.targets = vec![PrivacyTarget::ExactFiles {
            dir: DirSpec::Fixed(temp.into()),
            names: vec!["one.log".into()],
            sidecars: false,
        }];
        let mut sys = FakeSys::default();
        let mut backup = crate::backup::test_writer("hive-mend-privacy-single");
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &[set],
            &mut backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        assert!(fs.exists(&format!(r"{temp}\one.log")), "deleted as a set");
        assert!(
            outcome.items[0]
                .restricted
                .iter()
                .any(|note| note.contains("not deleted"))
        );
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &[single],
            &mut backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        let _ = std::fs::remove_file(backup.path());
        assert!(!fs.exists(&format!(r"{temp}\one.log")));
        assert_eq!(outcome.items[0].files, 1);
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
        let mut backup = crate::backup::test_writer("hive-mend-privacy-starts-later");
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &StartsLater(std::cell::Cell::new(0)),
            &[builtin("chrome-data")],
            &mut backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        assert!(outcome.items[0].skipped_running);
        assert!(fs.exists(history), "a running browser's files were cleaned");
        let _ = std::fs::remove_file(backup.path());
    }

    #[test]
    fn an_administrator_window_leaves_browser_data_alone() {
        let mut items: Vec<PrivacyItem> = build_items()
            .into_iter()
            .filter(|item| ["chrome-data", "edge-data", "user-temp"].contains(&item.id.as_str()))
            .collect();
        leave_browsers_alone(&mut items);
        for item in &items {
            let browser = item.id != "user-temp";
            assert_eq!(item.targets.is_empty(), browser, "{}", item.id);
            assert_eq!(!item.warnings.is_empty(), browser, "{}", item.id);
        }
        let mut reg = seed_reg();
        let mut fs = seed_fs();
        let mut sys = FakeSys::default();
        let history = r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\History";
        let chrome: Vec<PrivacyItem> = items
            .iter()
            .filter(|item| item.id == "chrome-data")
            .cloned()
            .collect();
        let mut backup = crate::backup::test_writer("hive-mend-privacy-admin-browsers");
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &chrome,
            &mut backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        assert!(
            fs.exists(history),
            "an administrator window cleaned browser data"
        );
        assert_eq!(outcome.items[0].files, 0);
        let _ = std::fs::remove_file(backup.path());
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
            &mut || true,
        )
        .unwrap();
        assert_eq!(dirs, [cache.to_string()]);
        let fox = builtin("firefox-data");
        assert!(fox.name.contains("cookies"));
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
    fn a_temp_file_written_since_it_was_listed_is_left_alone() {
        let mut fs = MemoryFs::with_windows_dirs();
        let temp = r"C:\Users\test\AppData\Local\Temp";
        let day = Duration::from_secs(24 * 3600);
        // Listed as older than two days, but written an hour ago since.
        fs.add_file_bytes(
            &format!(r"{temp}\fresh.tmp"),
            vec![1; 8],
            Some(Duration::from_secs(3600)),
        );
        fs.add_file_bytes(&format!(r"{temp}\old.tmp"), vec![1; 8], Some(day * 3));
        let mut done = ItemOutcome::blank("user-temp");
        let mut errors = Vec::new();
        for name in ["fresh.tmp", "old.tmp"] {
            let hit = FileHit {
                path: format!(r"{temp}\{name}"),
                bytes: 8,
                min_age: Some(day * 2),
            };
            delete_file(&mut fs, temp, &hit, &mut done, &mut errors);
        }
        assert!(
            fs.exists(&format!(r"{temp}\fresh.tmp")),
            "a recently written file was deleted"
        );
        assert!(!fs.exists(&format!(r"{temp}\old.tmp")));
        assert_eq!(done.files, 1);
    }

    #[test]
    fn an_old_file_written_or_opened_after_listing_is_left_alone() {
        let mut fs = MemoryFs::with_windows_dirs();
        let temp = r"C:\Users\test\AppData\Local\Temp";
        let day = Duration::from_secs(24 * 3600);
        for name in ["written.tmp", "busy.tmp", "old.tmp"] {
            fs.add_file_bytes(&format!(r"{temp}\{name}"), vec![1; 8], Some(day * 3));
        }
        // Old when pinned, written between the pin and the exclusive open.
        fs.set_written_since(&format!(r"{temp}\written.tmp"));
        // Held open by another program for writing.
        fs.set_busy(&format!(r"{temp}\busy.tmp"));
        let mut done = ItemOutcome::blank("user-temp");
        let mut errors = Vec::new();
        for name in ["written.tmp", "busy.tmp", "old.tmp"] {
            let hit = FileHit {
                path: format!(r"{temp}\{name}"),
                bytes: 8,
                min_age: Some(day * 2),
            };
            delete_file(&mut fs, temp, &hit, &mut done, &mut errors);
        }
        assert!(fs.exists(&format!(r"{temp}\written.tmp")));
        assert!(fs.exists(&format!(r"{temp}\busy.tmp")));
        assert!(!fs.exists(&format!(r"{temp}\old.tmp")));
        assert_eq!(done.files, 1);
        assert!(errors.is_empty(), "{errors:?}");
        assert!(
            done.restricted
                .iter()
                .any(|note| note.contains("busy.tmp") && note.contains("in use")),
            "{:?}",
            done.restricted
        );
    }

    #[test]
    fn a_canceled_preview_stops_inside_a_large_folder_and_says_so() {
        let reg = seed_reg();
        let mut fs = seed_fs();
        let temp = r"C:\Users\test\AppData\Local\Temp";
        let day = Duration::from_secs(24 * 3600);
        for index in 0..20_000 {
            fs.add_file_bytes(&format!(r"{temp}\f{index}.tmp"), vec![0], Some(day * 9));
        }
        let sys = FakeSys::default();
        let mut asked = 0;
        let report = preview_with(
            &reg,
            &fs,
            &sys,
            &quiet(),
            &[builtin("user-temp")],
            &mut || {
                asked += 1;
                asked < 4
            },
        );
        assert!(report.canceled);
        let counted: usize = report.items.iter().map(|item| item.files).sum();
        assert!(counted < 20_000, "{counted}");
        let whole = preview(&reg, &fs, &sys, &quiet(), &[builtin("user-temp")]);
        assert!(!whole.canceled);
        assert!(whole.files() >= 20_000);
    }

    #[test]
    fn long_folder_paths_count_against_the_walk_budget() {
        let mut fs = MemoryFs::with_windows_dirs();
        let temp = r"C:\Users\test\AppData\Local\Temp";
        let long = "x".repeat(200);
        for index in 0..200 {
            fs.add_dir(&format!(r"{temp}\{long}{index}"));
        }
        let mut row = PreviewItem::blank("user-temp");
        let mut budget = WalkBudget::new(false);
        budget.bytes_left = 5_000;
        let finished = walk_files(
            &fs,
            temp,
            "*",
            true,
            None,
            0,
            &mut |_| true,
            &mut || true,
            &mut budget,
            &mut row,
        );
        // No file matched, yet the queued folder paths alone ran it out.
        assert!(!finished);
        assert!(budget.exhausted);
        assert!(budget.folders_left > MAX_WALK_FOLDERS - 30, "kept too many");
        assert!(budget.shortfall(temp).unwrap().contains("too large"));
    }

    #[test]
    fn files_too_deep_or_past_the_profile_limit_are_reported_not_skipped_silently() {
        let mut reg = seed_reg();
        let mut fs = seed_fs();
        let temp = r"C:\Users\test\AppData\Local\Temp";
        let mut deep = temp.to_string();
        for level in 0..70 {
            deep.push_str(&format!(r"\d{level}"));
        }
        let day = Duration::from_secs(24 * 3600);
        fs.add_file_bytes(&format!(r"{deep}\x.tmp"), vec![0], Some(day * 9));
        let sys = FakeSys::default();
        let preview = preview(&reg, &fs, &sys, &quiet(), &[builtin("user-temp")]);
        assert!(
            preview.items[0]
                .restricted
                .iter()
                .any(|note| note.contains("levels down")),
            "{:?}",
            preview.items[0].restricted
        );
        let mut sys = FakeSys::default();
        let mut backup = crate::backup::test_writer("hive-mend-privacy-deep");
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &[builtin("user-temp")],
            &mut backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        let _ = std::fs::remove_file(backup.path());
        assert!(fs.exists(&format!(r"{deep}\x.tmp")));
        assert!(
            outcome.items[0]
                .restricted
                .iter()
                .any(|note| note.contains("levels down")),
            "{:?}",
            outcome.items[0].restricted
        );
        // More profiles than are looked at: said, not silently cut.
        let users = r"C:\Users\test\AppData\Local\Google\Chrome\User Data";
        for index in 0..1_001 {
            fs.add_dir(&format!(r"{users}\P{index:04}"));
        }
        let (_, notes) = resolve_dirs(
            &fs,
            &DirSpec::Chromium {
                vendor: "Google\\Chrome".into(),
                sub: String::new(),
            },
            &mut || true,
        )
        .unwrap();
        assert!(
            notes
                .iter()
                .any(|note| note.contains("more than 1000 profiles")),
            "{notes:?}"
        );
    }

    #[test]
    fn a_walk_out_of_folders_stops_and_says_so() {
        let mut fs = MemoryFs::with_windows_dirs();
        let temp = r"C:\Users\test\AppData\Local\Temp";
        for index in 0..50 {
            fs.add_dir(&format!(r"{temp}\d{index}"));
        }
        let mut row = PreviewItem::blank("user-temp");
        let mut budget = WalkBudget::new(false);
        budget.folders_left = 5;
        let finished = walk_files(
            &fs,
            temp,
            "*",
            true,
            None,
            0,
            &mut |_| true,
            &mut || true,
            &mut budget,
            &mut row,
        );
        assert!(!finished);
        assert!(budget.exhausted);
    }

    #[test]
    fn cancel_stops_a_clean_inside_a_large_folder() {
        let mut reg = seed_reg();
        let mut fs = seed_fs();
        let temp = r"C:\Users\test\AppData\Local\Temp";
        let day = Duration::from_secs(24 * 3600);
        for index in 0..20_000 {
            fs.add_file_bytes(&format!(r"{temp}\c{index}.tmp"), vec![0], Some(day * 9));
        }
        let mut sys = FakeSys::default();
        let mut backup = crate::backup::test_writer("hive-mend-privacy-cancel-inside");
        let mut calls = 0;
        let outcome = clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &[builtin("user-temp")],
            &mut backup,
            // Yes for the category itself and the start of its walk; no
            // from the first check inside the folder.
            &mut |_, _, _| {
                calls += 1;
                calls <= 2
            },
        )
        .unwrap();
        let _ = std::fs::remove_file(backup.path());
        assert!(outcome.canceled);
        assert!(outcome.items[0].canceled);
        assert_eq!(outcome.items[0].files, 0, "files went after Cancel");
        assert!(fs.exists(&format!(r"{temp}\c19999.tmp")));
    }

    #[test]
    fn a_walk_stops_when_its_files_are_enough() {
        let mut fs = MemoryFs::with_windows_dirs();
        let temp = r"C:\Users\test\AppData\Local\Temp";
        for index in 0..50 {
            fs.add_file_bytes(&format!(r"{temp}\sub\f{index}.tmp"), vec![0], None);
        }
        let mut row = PreviewItem::blank("user-temp");
        let mut hits = Vec::new();
        let finished = walk_files(
            &fs,
            temp,
            "*",
            true,
            None,
            0,
            &mut |hit| {
                hits.push(hit);
                hits.len() < 10
            },
            &mut || true,
            &mut WalkBudget::new(false),
            &mut row,
        );
        assert!(!finished);
        assert_eq!(hits.len(), 10);
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
        let mut backup = crate::backup::test_writer("hive-mend-privacy-cookies-alone");
        clean_with_progress(
            &mut reg,
            &mut fs,
            &mut sys,
            &quiet(),
            &items,
            &mut backup,
            &mut |_, _, _| true,
        )
        .unwrap();
        assert!(fs.exists(&format!(r"{profile}\Network\Cookies")));
        assert!(fs.exists(&format!(r"{profile}\History")));
        let _ = std::fs::remove_file(backup.path());
    }
}
