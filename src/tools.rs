//! Windows tools shortcuts: the "Help Center" page.
//!
//! Every entry opens a screen that ships with Windows. Hive Mend only
//! opens them; anything changed inside one is the user's own doing in a
//! Microsoft console. Targets use the same `%SystemRoot%` templates as the
//! original, updated for Windows 10 and 11 (dead CPLs replaced by their
//! Settings URIs).

use crate::art::Icon;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowsTool {
    /// Short name shown on the tile.
    pub name: &'static str,
    /// One-line description shown under the name.
    pub description: &'static str,
    /// The Hive Mend icon shown on the tile.
    pub icon: Icon,
    /// `%SystemRoot%` template, plain exe name, or Settings URI.
    pub target: &'static str,
}

pub const WINDOWS_TOOLS: &[WindowsTool] = &[
    WindowsTool {
        name: "Computer Management",
        description: "Manage local users, disks, and services",
        icon: Icon::Settings,
        target: r"%SystemRoot%\System32\compmgmt.msc",
    },
    WindowsTool {
        name: "Device Manager",
        description: "Manage and configure hardware devices",
        icon: Icon::Settings,
        target: r"%SystemRoot%\System32\devmgmt.msc",
    },
    WindowsTool {
        name: "Disk Management",
        description: "Manage disks, volumes, and drive letters",
        icon: Icon::Optimize,
        target: r"%SystemRoot%\System32\diskmgmt.msc",
    },
    WindowsTool {
        name: "Event Viewer",
        description: "Read Windows and application logs",
        icon: Icon::Scan,
        target: r"%SystemRoot%\System32\eventvwr.msc",
    },
    WindowsTool {
        name: "Services",
        description: "View and manage Windows services",
        icon: Icon::Optimize,
        target: r"%SystemRoot%\System32\services.msc",
    },
    WindowsTool {
        name: "Local Users and Groups",
        description: "Manage user accounts and groups",
        icon: Icon::Privacy,
        target: r"%SystemRoot%\System32\lusrmgr.msc",
    },
    WindowsTool {
        name: "Group Policy Editor",
        description: "Computer and user configuration",
        icon: Icon::Privacy,
        target: r"%SystemRoot%\System32\gpedit.msc",
    },
    WindowsTool {
        name: "Local Security Settings",
        description: "Manage the local security policy",
        icon: Icon::Privacy,
        target: r"%SystemRoot%\System32\secpol.msc",
    },
    WindowsTool {
        name: "Performance Monitor",
        description: "Watch CPU, memory, and disk counters",
        icon: Icon::Monitor,
        target: r"%SystemRoot%\System32\perfmon.msc",
    },
    WindowsTool {
        name: "System Information",
        description: "Hardware and software summary",
        icon: Icon::About,
        target: r"%SystemRoot%\System32\msinfo32.exe",
    },
    WindowsTool {
        name: "System Properties",
        description: "Computer name and protection settings",
        icon: Icon::Settings,
        target: r"%SystemRoot%\System32\sysdm.cpl",
    },
    WindowsTool {
        name: "System Restore",
        description: "Restore points and system recovery",
        icon: Icon::Restore,
        target: r"%SystemRoot%\System32\rstrui.exe",
    },
    WindowsTool {
        name: "Control Panel",
        description: "Classic Windows settings",
        icon: Icon::Settings,
        target: r"%SystemRoot%\System32\control.exe",
    },
    WindowsTool {
        name: "Windows Security",
        description: "Virus, firewall, and device protection",
        icon: Icon::Privacy,
        target: "windowsdefender:",
    },
    WindowsTool {
        name: "Windows Update",
        description: "Check for and install updates",
        icon: Icon::Restore,
        target: "ms-settings:windowsupdate",
    },
];

/// Expand `%SystemRoot%` (any casing) in a tool target. URIs and plain
/// names pass through unchanged.
pub fn expand_target(template: &str, system_root: &str) -> String {
    let mut out = String::with_capacity(template.len() + system_root.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && template[i..].len() >= 12
            && template[i..i + 12].eq_ignore_ascii_case("%systemroot%")
        {
            out.push_str(system_root);
            i += 12;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// True for targets ShellExecute can open: a file path or a URI scheme.
pub fn is_openable(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    lower.ends_with(".msc")
        || lower.ends_with(".cpl")
        || lower.ends_with(".exe")
        || target.contains(':')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn tools_cover_the_original_help_center() {
        assert!(WINDOWS_TOOLS.len() >= 14, "one tile per original shortcut");
        for tool in WINDOWS_TOOLS {
            assert!(!tool.name.is_empty(), "tool name");
            assert!(!tool.description.is_empty(), "{}", tool.name);
            assert!(
                is_openable(&expand_target(tool.target, r"C:\Windows")),
                "{} target should be openable: {}",
                tool.name,
                tool.target
            );
        }
        let names: HashSet<_> = WINDOWS_TOOLS.iter().map(|tool| tool.name).collect();
        assert_eq!(names.len(), WINDOWS_TOOLS.len(), "duplicate tool names");
    }

    #[test]
    fn expand_target_only_touches_system_root() {
        assert_eq!(
            expand_target(r"%SystemRoot%\System32\compmgmt.msc", r"D:\Win"),
            r"D:\Win\System32\compmgmt.msc"
        );
        assert_eq!(
            expand_target(r"%systemroot%\x", r"C:\Windows"),
            r"C:\Windows\x"
        );
        assert_eq!(
            expand_target("ms-settings:windowsupdate", r"C:\Windows"),
            "ms-settings:windowsupdate"
        );
        assert_eq!(expand_target("control.exe", r"C:\Windows"), "control.exe");
    }
}
