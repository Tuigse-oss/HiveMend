//! Installed programs, as Windows' Programs and Features lists them, and the
//! program's own uninstaller to run for one.
//!
//! Hivemend never removes a program itself: it starts the uninstaller the
//! program registered. The command is resolved to one existing `.exe` by
//! rules stricter than Windows' own: a quoted path is taken as written, an
//! unquoted path must end in `.exe` at a space or the end and exist, and a
//! bare name (`MsiExec.exe`) is only looked for in System32, never the
//! current folder or `PATH`. An elevated window only starts uninstallers
//! kept in the Windows or Program Files folders, which only administrators
//! can change; anything else is started from a normal window, where it asks
//! for administrator rights itself if it needs them.

use crate::fs::{FileView, KnownDir};
use crate::model::ValueKind;
use crate::pathutil::{expand_env, has_unsafe_fs_component, known_root, path_under};
use crate::registry::Registry;

const UNINSTALL: &str = r"Microsoft\Windows\CurrentVersion\Uninstall";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgramScope {
    /// Installed for the current user only.
    User,
    /// Installed for every user.
    Machine,
}

impl ProgramScope {
    pub fn label(self) -> &'static str {
        match self {
            Self::User => "Your account",
            Self::Machine => "All users",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledProgram {
    pub name: String,
    pub publisher: String,
    pub version: String,
    /// `yyyy-mm-dd`, or empty when the installer did not say.
    pub installed: String,
    /// Estimated size in bytes, when the installer recorded one.
    pub size: Option<u64>,
    pub scope: ProgramScope,
    /// The uninstall key, for display and for confirming the row again.
    pub key: String,
    /// The command the program registered to remove itself.
    pub uninstall: String,
    pub install_location: String,
}

/// Every program Programs and Features would list, sorted by name.
pub fn list_programs(reg: &dyn Registry) -> Vec<InstalledProgram> {
    let sources = [
        (
            format!(r"HKEY_LOCAL_MACHINE\SOFTWARE\{UNINSTALL}"),
            ProgramScope::Machine,
        ),
        (
            format!(r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\{UNINSTALL}"),
            ProgramScope::Machine,
        ),
        (
            format!(r"HKEY_CURRENT_USER\Software\{UNINSTALL}"),
            ProgramScope::User,
        ),
    ];
    let mut programs: Vec<InstalledProgram> = Vec::new();
    for (root, scope) in sources {
        for sub in reg.subkeys(&root).unwrap_or_default() {
            let key = format!(r"{root}\{sub}");
            if let Some(program) = read_program(reg, &key, &sub, scope)
                && !programs.iter().any(|have| {
                    have.scope == program.scope
                        && have.name.eq_ignore_ascii_case(&program.name)
                        && have.version == program.version
                })
            {
                programs.push(program);
            }
        }
    }
    programs.sort_by_key(|program| program.name.to_lowercase());
    programs
}

fn read_program(
    reg: &dyn Registry,
    key: &str,
    sub: &str,
    scope: ProgramScope,
) -> Option<InstalledProgram> {
    let values = reg.values(key).ok()?;
    let text = |name: &str| {
        values
            .iter()
            .find(|value| value.name.eq_ignore_ascii_case(name))
            .and_then(|value| value.data.as_text())
            .map(|text| text.trim().to_string())
            .unwrap_or_default()
    };
    let dword = |name: &str| {
        values
            .iter()
            .find(|value| value.name.eq_ignore_ascii_case(name))
            .and_then(|value| match value.data {
                ValueKind::Dword(number) => Some(number),
                _ => None,
            })
    };
    let name = text("DisplayName");
    // The same rules as Programs and Features: hidden components, updates
    // listed under their parent, and nameless keys are not programs.
    if name.is_empty()
        || dword("SystemComponent") == Some(1)
        || !text("ParentKeyName").is_empty()
        || matches!(
            text("ReleaseType").to_ascii_lowercase().as_str(),
            "security update" | "update rollup" | "hotfix" | "update"
        )
    {
        return None;
    }
    let mut uninstall = text("UninstallString");
    if uninstall.is_empty()
        && dword("WindowsInstaller") == Some(1)
        && sub.starts_with('{')
        && sub.ends_with('}')
    {
        uninstall = format!("MsiExec.exe /X{sub}");
    }
    if uninstall.is_empty() {
        return None;
    }
    let date = text("InstallDate");
    let installed = if date.len() == 8 && date.bytes().all(|byte| byte.is_ascii_digit()) {
        format!("{}-{}-{}", &date[..4], &date[4..6], &date[6..])
    } else {
        String::new()
    };
    Some(InstalledProgram {
        name,
        publisher: text("Publisher"),
        version: text("DisplayVersion"),
        installed,
        size: dword("EstimatedSize")
            .filter(|kb| *kb > 0)
            .map(|kb| u64::from(kb) * 1024),
        scope,
        key: key.to_string(),
        uninstall,
        install_location: text("InstallLocation"),
    })
}

/// The program to start and its arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launch {
    pub exe: String,
    pub params: String,
}

/// Resolve an uninstall command to one existing `.exe` and its arguments,
/// or say why it cannot be started safely. `elevated` is whether it would
/// run with administrator rights.
pub fn uninstall_launch(
    fs: &dyn FileView,
    command: &str,
    elevated: bool,
) -> Result<Launch, String> {
    let system_dir =
        known_root(fs, KnownDir::System).ok_or("the System32 folder could not be located")?;
    let command = expand_env(fs, command.trim());
    let (exe, params) = if let Some(rest) = command.strip_prefix('"') {
        let end = rest
            .find('"')
            .ok_or("the uninstall command has an unclosed quote")?;
        (rest[..end].trim().to_string(), rest[end + 1..].trim())
    } else {
        let first_end = command.find(' ').unwrap_or(command.len());
        if !command[..first_end].contains(['\\', '/', ':']) {
            (
                command[..first_end].to_string(),
                command[first_end..].trim(),
            )
        } else {
            // An unquoted path with spaces: the first prefix that ends in
            // `.exe` at a space (or the end) and names a file.
            let mut found = None;
            let mut ends: Vec<usize> = command
                .char_indices()
                .filter(|(_, ch)| *ch == ' ')
                .map(|(at, _)| at)
                .collect();
            ends.push(command.len());
            for end in ends {
                let candidate = &command[..end];
                if candidate.to_ascii_lowercase().ends_with(".exe") && is_file(fs, candidate) {
                    found = Some((candidate.to_string(), command[end..].trim()));
                    break;
                }
            }
            found.ok_or("could not tell which program the uninstall command runs")?
        }
    };
    let exe = if exe.contains(['\\', '/', ':']) {
        exe
    } else {
        // A bare name is a Windows tool (MsiExec.exe, rundll32.exe) in
        // System32, or an app alias such as winget.exe in the account's
        // WindowsApps folder. Nothing in the current folder or elsewhere on
        // PATH is ever run.
        let name = if exe.to_ascii_lowercase().ends_with(".exe") {
            exe
        } else {
            format!("{exe}.exe")
        };
        if name.contains("..") {
            return Err("the uninstall command names an unexpected program".into());
        }
        let in_system = format!(r"{system_dir}\{name}");
        let alias = known_root(fs, KnownDir::LocalAppData)
            .map(|root| format!(r"{root}\Microsoft\WindowsApps\{name}"))
            .filter(|alias| is_file(fs, alias));
        match alias {
            Some(alias) if !is_file(fs, &in_system) => alias,
            _ => in_system,
        }
    };
    let bytes = exe.as_bytes();
    let drive_absolute =
        bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    if !drive_absolute || has_unsafe_fs_component(&exe) || exe.contains('/') {
        return Err(format!(
            "the uninstaller path {exe} is not a plain local path"
        ));
    }
    if !exe.to_ascii_lowercase().ends_with(".exe") {
        return Err(format!("the uninstaller {exe} is not a program (.exe)"));
    }
    if !is_file(fs, &exe) {
        return Err(format!("the uninstaller {exe} is missing"));
    }
    if elevated {
        let trusted = [
            KnownDir::Windows,
            KnownDir::ProgramFiles,
            KnownDir::ProgramFilesX86,
        ]
        .iter()
        .filter_map(|dir| known_root(fs, *dir))
        .any(|root| path_under(&exe, &root));
        if !trusted {
            return Err(format!(
                "{exe} is outside the Windows and Program Files folders, so it is not started with administrator rights. Open Hivemend without administrator rights to start it; it will ask for permission if it needs it"
            ));
        }
    }
    Ok(Launch {
        exe,
        params: params.to_string(),
    })
}

fn is_file(fs: &dyn FileView, path: &str) -> bool {
    fs.exists(path) && !fs.is_dir(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemoryFs;
    use crate::registry::MemoryRegistry;

    fn world() -> MemoryRegistry {
        let mut reg = MemoryRegistry::new();
        let hklm = format!(r"HKLM\SOFTWARE\{UNINSTALL}");
        let app = format!(r"{hklm}\App");
        reg.set_sz(&app, "DisplayName", "Paint Pro");
        reg.set_sz(&app, "DisplayVersion", "2.1");
        reg.set_sz(&app, "Publisher", "Paint Co");
        reg.set_sz(&app, "InstallDate", "20260914");
        reg.set_dword(&app, "EstimatedSize", 2048);
        reg.set_sz(
            &app,
            "UninstallString",
            r#""C:\Program Files\Paint Pro\uninst.exe" /S"#,
        );
        let msi = format!(r"{hklm}\{{11111111-2222-3333-4444-555555555555}}");
        reg.set_sz(&msi, "DisplayName", "Runtime");
        reg.set_dword(&msi, "WindowsInstaller", 1);
        let hidden = format!(r"{hklm}\Hidden");
        reg.set_sz(&hidden, "DisplayName", "Component");
        reg.set_sz(&hidden, "UninstallString", "x.exe");
        reg.set_dword(&hidden, "SystemComponent", 1);
        let update = format!(r"{hklm}\KB1");
        reg.set_sz(&update, "DisplayName", "Update for Paint Pro");
        reg.set_sz(&update, "UninstallString", "x.exe");
        reg.set_sz(&update, "ParentKeyName", "App");
        reg.set_sz(&format!(r"{hklm}\Nameless"), "UninstallString", "x.exe");
        // The same program seen through the 32-bit view is listed once.
        let wow = format!(r"HKLM\SOFTWARE\WOW6432Node\{UNINSTALL}\App");
        reg.set_sz(&wow, "DisplayName", "Paint Pro");
        reg.set_sz(&wow, "DisplayVersion", "2.1");
        reg.set_sz(&wow, "UninstallString", "x.exe");
        let user = format!(r"HKCU\Software\{UNINSTALL}\Chat");
        reg.set_sz(&user, "DisplayName", "chat");
        reg.set_sz(
            &user,
            "UninstallString",
            r"C:\Users\me\AppData\Local\Chat\Update.exe --uninstall",
        );
        reg
    }

    #[test]
    fn lists_programs_like_programs_and_features() {
        let programs = list_programs(&world());
        let names: Vec<&str> = programs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["chat", "Paint Pro", "Runtime"]);
        let paint = &programs[1];
        assert_eq!(paint.installed, "2026-09-14");
        assert_eq!(paint.size, Some(2048 * 1024));
        assert_eq!(paint.scope, ProgramScope::Machine);
        assert_eq!(programs[0].scope, ProgramScope::User);
        // An MSI product without its own command uninstalls by product code.
        assert_eq!(
            programs[2].uninstall,
            "MsiExec.exe /X{11111111-2222-3333-4444-555555555555}"
        );
    }

    fn fs() -> MemoryFs {
        let mut fs = MemoryFs::with_windows_dirs();
        fs.add_file(r"C:\Windows\System32\msiexec.exe");
        fs.add_file(r"C:\Program Files\Paint Pro\uninst.exe");
        fs.add_file(r"C:\Program Files\Paint Pro\Uninstall Tool.exe");
        fs.add_file(r"C:\Program Files\Paint Pro\notes.txt");
        fs
    }

    #[test]
    fn uninstall_commands_resolve_to_one_existing_exe() {
        let fs = fs();
        let quoted =
            uninstall_launch(&fs, r#""C:\Program Files\Paint Pro\uninst.exe" /S"#, false).unwrap();
        assert_eq!(quoted.exe, r"C:\Program Files\Paint Pro\uninst.exe");
        assert_eq!(quoted.params, "/S");
        // Unquoted with spaces: the full path, not `C:\Program`.
        let unquoted = uninstall_launch(
            &fs,
            r"C:\Program Files\Paint Pro\Uninstall Tool.exe /quiet",
            false,
        )
        .unwrap();
        assert_eq!(
            unquoted.exe,
            r"C:\Program Files\Paint Pro\Uninstall Tool.exe"
        );
        assert_eq!(unquoted.params, "/quiet");
        let expanded =
            uninstall_launch(&fs, r"%ProgramFiles%\Paint Pro\uninst.exe", false).unwrap();
        assert_eq!(expanded.exe, r"C:\Program Files\Paint Pro\uninst.exe");
        // A bare tool name is taken from System32 only.
        let msi = uninstall_launch(&fs, "MsiExec.exe /X{1-2}", false).unwrap();
        assert_eq!(msi.exe, r"C:\Windows\System32\MsiExec.exe");
        assert_eq!(msi.params, "/X{1-2}");
    }

    #[test]
    fn unclear_or_unsafe_uninstall_commands_are_refused() {
        let mut fs = fs();
        // `C:\Program.exe` exists, but `C:\Program` is never taken for it:
        // only a prefix ending in `.exe` counts.
        fs.add_file(r"C:\Program.exe");
        let refused = [
            r"C:\Program Files\Paint Pro\missing.exe",
            r#""C:\Program Files\Paint Pro\notes.txt""#,
            r"Paint Pro\uninst.exe",
            r"\\server\share\uninst.exe",
            r#""C:\Program Files\Paint Pro\..\..\Windows\System32\msiexec.exe""#,
            r#""C:\Program Files\Paint Pro\uninst.exe /S"#,
            "notthere.exe /x",
            r"..\uninst.exe",
        ];
        for command in refused {
            assert!(
                uninstall_launch(&fs, command, false).is_err(),
                "{command} should be refused"
            );
        }
        let ok = uninstall_launch(&fs, r"C:\Program Files\Paint Pro\uninst.exe", false).unwrap();
        assert_eq!(ok.exe, r"C:\Program Files\Paint Pro\uninst.exe");
    }

    #[test]
    fn bare_app_aliases_come_from_the_accounts_windows_apps_folder() {
        let mut fs = fs();
        fs.set_var("LOCALAPPDATA", r"C:\Users\me\AppData\Local");
        let command = "winget uninstall --product-code Tool_Source";
        assert!(
            uninstall_launch(&fs, command, false).is_err(),
            "no alias yet"
        );
        fs.add_file(r"C:\Users\me\AppData\Local\Microsoft\WindowsApps\winget.exe");
        let launch = uninstall_launch(&fs, command, false).unwrap();
        assert_eq!(
            launch.exe,
            r"C:\Users\me\AppData\Local\Microsoft\WindowsApps\winget.exe"
        );
        assert_eq!(launch.params, "uninstall --product-code Tool_Source");
        // An alias never shadows a System32 tool, and is not run elevated.
        fs.add_file(r"C:\Users\me\AppData\Local\Microsoft\WindowsApps\msiexec.exe");
        let msi = uninstall_launch(&fs, "MsiExec.exe /X{1-2}", false).unwrap();
        assert_eq!(msi.exe, r"C:\Windows\System32\MsiExec.exe");
        assert!(uninstall_launch(&fs, command, true).is_err());
    }

    #[test]
    fn elevated_windows_start_only_admin_owned_uninstallers() {
        let mut fs = fs();
        let user_exe = r"C:\Users\me\AppData\Local\Chat\Update.exe";
        fs.add_file(user_exe);
        let command = format!("{user_exe} --uninstall");
        assert!(uninstall_launch(&fs, &command, false).is_ok());
        assert!(uninstall_launch(&fs, &command, true).is_err());
        for command in [
            r#""C:\Program Files\Paint Pro\uninst.exe" /S"#,
            "MsiExec.exe /X{1-2}",
        ] {
            assert!(uninstall_launch(&fs, command, true).is_ok(), "{command}");
        }
    }
}
