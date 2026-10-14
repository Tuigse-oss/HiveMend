//! Startup manager: the programs Windows starts at sign-in, as Task Manager's
//! Startup tab lists them (the `Run` keys and the Startup folders), with the
//! same enable/disable switch Task Manager uses.
//!
//! Disabling never deletes anything. Windows keeps a per-item flag under
//! `Explorer\StartupApproved`: a 12-byte binary value whose first byte is
//! even when the item may run (`02`) and odd when it is disabled (`03`,
//! followed by the FILETIME it was turned off). Hivemend writes the same
//! values, so Task Manager and Hivemend always agree, and a `.reg` backup of
//! the previous flags is written first so every change can be undone.

use crate::backup::format_value;
use crate::fs::{FileView, ItemKind, KnownDir};
use crate::model::{RegValue, ValueKind};
use crate::pathutil::known_root;
use crate::registry::{RegError, Registry};

const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";
const STARTUP_FOLDER: &str = r"Microsoft\Windows\Start Menu\Programs\Startup";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupScope {
    /// The current user's own startup items.
    User,
    /// Items that start for every user; changing them needs administrator rights.
    Machine,
}

impl StartupScope {
    pub fn label(self) -> &'static str {
        match self {
            Self::User => "Your account",
            Self::Machine => "All users",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartupItem {
    /// The `Run` value name, or the file name in a Startup folder.
    pub name: String,
    /// What it starts: the command line, or a shortcut's target.
    pub command: String,
    pub scope: StartupScope,
    /// Where it is registered: the `Run` key or the folder, for display.
    pub location: String,
    /// The `StartupApproved` key holding this item's flag.
    pub approved_key: String,
    pub enabled: bool,
}

/// Every startup item, sorted by name.
pub fn list_startup(reg: &dyn Registry, fs: &dyn FileView) -> Vec<StartupItem> {
    let mut items = Vec::new();
    let sources = [
        (
            format!(r"HKEY_CURRENT_USER\{RUN}"),
            format!(r"HKEY_CURRENT_USER\{APPROVED}\Run"),
            StartupScope::User,
        ),
        (
            format!(r"HKEY_LOCAL_MACHINE\{RUN}"),
            format!(r"HKEY_LOCAL_MACHINE\{APPROVED}\Run"),
            StartupScope::Machine,
        ),
        (
            format!(r"HKEY_LOCAL_MACHINE\{RUN32}"),
            format!(r"HKEY_LOCAL_MACHINE\{APPROVED}\Run32"),
            StartupScope::Machine,
        ),
    ];
    for (key, approved_key, scope) in sources {
        let approved = flags(reg, &approved_key);
        for value in reg.values(&key).unwrap_or_default() {
            let Some(command) = value.data.as_text() else {
                continue;
            };
            if value.name.is_empty() {
                continue;
            }
            items.push(StartupItem {
                enabled: enabled_in(&approved, &value.name),
                name: value.name.clone(),
                command: command.to_string(),
                scope,
                location: key.clone(),
                approved_key: approved_key.clone(),
            });
        }
    }
    let folders = [
        (
            fs.var("APPDATA"),
            format!(r"HKEY_CURRENT_USER\{APPROVED}\StartupFolder"),
            StartupScope::User,
        ),
        (
            known_root(fs, KnownDir::ProgramData),
            format!(r"HKEY_LOCAL_MACHINE\{APPROVED}\StartupFolder"),
            StartupScope::Machine,
        ),
    ];
    for (root, approved_key, scope) in folders {
        let Some(root) = root else {
            continue;
        };
        let dir = format!(r"{}\{STARTUP_FOLDER}", root.trim_end_matches('\\'));
        let approved = flags(reg, &approved_key);
        for entry in fs.list(&dir) {
            if entry.kind != ItemKind::File || entry.name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let path = format!(r"{dir}\{}", entry.name);
            let command = if entry.name.to_ascii_lowercase().ends_with(".lnk") {
                fs.read(&path)
                    .and_then(|bytes| crate::lnk::lnk_target(&bytes))
                    .unwrap_or_else(|| path.clone())
            } else {
                path.clone()
            };
            items.push(StartupItem {
                enabled: enabled_in(&approved, &entry.name),
                name: entry.name.clone(),
                command,
                scope,
                location: dir.clone(),
                approved_key: approved_key.clone(),
            });
        }
    }
    items.sort_by_key(|item| item.name.to_ascii_lowercase());
    items
}

fn flags(reg: &dyn Registry, key: &str) -> Vec<RegValue> {
    reg.values(key).unwrap_or_default()
}

/// No flag means Windows runs the item; an odd first byte means disabled.
fn enabled_in(flags: &[RegValue], name: &str) -> bool {
    match flags
        .iter()
        .find(|value| value.name.eq_ignore_ascii_case(name))
    {
        Some(value) => match &value.data {
            ValueKind::Binary(bytes) | ValueKind::Other { bytes, .. } => {
                bytes.first().is_none_or(|first| first & 1 == 0)
            }
            _ => true,
        },
        None => true,
    }
}

/// The flag Task Manager writes: `02` and zeros to allow, `03` and the time
/// (a FILETIME) to disable.
pub fn approved_bytes(enable: bool, filetime: u64) -> Vec<u8> {
    let mut bytes = vec![if enable { 0x02 } else { 0x03 }, 0, 0, 0];
    bytes.extend(if enable { 0 } else { filetime }.to_le_bytes());
    bytes
}

/// Now as a Windows FILETIME (100 ns ticks since 1601).
pub fn filetime_now() -> u64 {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (unix.as_secs() + 11_644_473_600) * 10_000_000 + u64::from(unix.subsec_nanos() / 100)
}

/// A `.reg` backup of the current flags of `items`: the value as it is now,
/// or a delete line when there is none, so restoring puts every flag back
/// exactly. Items whose flag cannot be represented are reported, not
/// changed.
pub fn startup_backup(reg: &dyn Registry, items: &[&StartupItem]) -> (String, Vec<String>) {
    let mut body = String::from("Windows Registry Editor Version 5.00\r\n\r\n");
    body.push_str("; Hive Mend backup.\r\n");
    body.push_str("; Hivemend startup backup.\r\n");
    body.push_str("; Restore it from the Restore page in Hivemend.\r\n");
    let mut refused = Vec::new();
    for item in items {
        if item.name.chars().any(|ch| (ch as u32) < 0x20) {
            refused.push(item.name.clone());
            continue;
        }
        let current = flags(reg, &item.approved_key)
            .into_iter()
            .find(|value| value.name.eq_ignore_ascii_case(&item.name));
        body.push_str(&format!("\r\n[{}]\r\n", item.approved_key));
        match current {
            Some(value) => body.push_str(&format_value(&value)),
            None => body.push_str(&format!(
                "\"{}\"=-",
                item.name.replace('\\', "\\\\").replace('"', "\\\"")
            )),
        }
        body.push_str("\r\n");
    }
    (body, refused)
}

#[derive(Clone, Debug, Default)]
pub struct StartupOutcome {
    pub changed: usize,
    pub already: usize,
    pub denied: usize,
    pub errors: Vec<String>,
}

/// Turn `items` on or off. The caller has already written the backup from
/// [`startup_backup`]; items it refused are skipped by name.
pub fn set_startup(
    reg: &mut dyn Registry,
    items: &[&StartupItem],
    enable: bool,
    filetime: u64,
    skip: &[String],
) -> StartupOutcome {
    let mut outcome = StartupOutcome::default();
    for item in items {
        if skip.contains(&item.name) {
            continue;
        }
        if item.enabled == enable {
            outcome.already += 1;
            continue;
        }
        let data = ValueKind::Binary(approved_bytes(enable, filetime));
        match reg.set_value(&item.approved_key, &item.name, &data) {
            Ok(()) => outcome.changed += 1,
            Err(RegError::Denied(message)) => {
                outcome.denied += 1;
                outcome.errors.push(format!("{}: {message}", item.name));
            }
            Err(err) => outcome.errors.push(format!("{}: {err}", item.name)),
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemoryFs;
    use crate::registry::MemoryRegistry;

    fn world() -> (MemoryRegistry, MemoryFs) {
        let mut reg = MemoryRegistry::new();
        reg.set_sz(
            &format!(r"HKCU\{RUN}"),
            "Chat",
            r#""C:\Users\me\AppData\Local\Chat\chat.exe" --minimized"#,
        );
        reg.set_sz(
            &format!(r"HKLM\{RUN}"),
            "Audio",
            r"C:\Program Files\Audio\tray.exe",
        );
        reg.set_sz(
            &format!(r"HKLM\{RUN32}"),
            "Updater",
            r"C:\Program Files (x86)\U\u.exe",
        );
        reg.set(
            &format!(r"HKCU\{APPROVED}\Run"),
            "Chat",
            ValueKind::Binary(approved_bytes(false, 42)),
        );
        let mut fs = MemoryFs::with_windows_dirs();
        fs.set_var("APPDATA", r"C:\Users\me\AppData\Roaming");
        fs.add_file(&format!(
            r"C:\Users\me\AppData\Roaming\{STARTUP_FOLDER}\Notes.lnk"
        ));
        fs.add_file(&format!(
            r"C:\Users\me\AppData\Roaming\{STARTUP_FOLDER}\desktop.ini"
        ));
        fs.add_file(&format!(r"C:\ProgramData\{STARTUP_FOLDER}\Sync.lnk"));
        (reg, fs)
    }

    #[test]
    fn lists_run_keys_and_startup_folders_with_their_flags() {
        let (reg, fs) = world();
        let items = list_startup(&reg, &fs);
        // Windows names are case-insensitive (the test filesystem lowercases).
        let names: Vec<String> = items
            .iter()
            .map(|item| item.name.to_ascii_lowercase())
            .collect();
        assert_eq!(names, ["audio", "chat", "notes.lnk", "sync.lnk", "updater"]);
        let chat = items.iter().find(|item| item.name == "Chat").unwrap();
        assert!(!chat.enabled, "flag 03 means disabled");
        assert_eq!(chat.scope, StartupScope::User);
        let updater = items.iter().find(|item| item.name == "Updater").unwrap();
        assert!(updater.enabled, "no flag means enabled");
        assert!(updater.approved_key.ends_with(r"StartupApproved\Run32"));
        let sync = items
            .iter()
            .find(|item| item.name.eq_ignore_ascii_case("Sync.lnk"))
            .unwrap();
        assert_eq!(sync.scope, StartupScope::Machine);
        assert!(
            sync.approved_key
                .ends_with(r"StartupApproved\StartupFolder")
        );
    }

    #[test]
    fn toggling_writes_task_manager_flags_and_the_backup_restores_them() {
        let (mut reg, fs) = world();
        let items = list_startup(&reg, &fs);
        let chat = items.iter().find(|item| item.name == "Chat").unwrap();
        let audio = items.iter().find(|item| item.name == "Audio").unwrap();
        let (backup, refused) = startup_backup(&reg, &[chat, audio]);
        assert!(refused.is_empty());
        assert!(crate::backup::is_hive_mend_backup(&backup));
        // Chat had a disabled flag; Audio had none, so restore deletes it.
        assert!(backup.contains("\"Chat\"=hex:03,00,00,00,"), "{backup}");
        assert!(backup.contains("\"Audio\"=-"), "{backup}");
        let outcome = set_startup(&mut reg, &[chat, audio], true, 99, &[]);
        assert_eq!(outcome.changed, 1, "Chat turns on");
        assert_eq!(outcome.already, 1, "Audio was already on");
        let again = list_startup(&reg, &fs);
        assert!(again.iter().all(|item| item.enabled));
        let off = set_startup(&mut reg, &[&again[0]], false, 1234, &[]);
        assert_eq!(off.changed, 1);
        let flag = reg
            .values(&again[0].approved_key)
            .unwrap()
            .into_iter()
            .find(|value| value.name == again[0].name)
            .unwrap();
        assert_eq!(flag.data, ValueKind::Binary(approved_bytes(false, 1234)));
    }

    #[test]
    fn flag_bytes_match_task_manager() {
        assert_eq!(
            approved_bytes(true, 5),
            [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        let off = approved_bytes(false, 0x0102_0304_0506_0708);
        assert_eq!(off[..4], [3, 0, 0, 0]);
        assert_eq!(off[4..], 0x0102_0304_0506_0708u64.to_le_bytes());
        assert!(enabled_in(&[], "x"));
        let disabled = [RegValue {
            name: "X".into(),
            data: ValueKind::Binary(vec![7, 0, 0, 0]),
        }];
        assert!(!enabled_in(&disabled, "x"));
    }
}
