//! Window settings and the status summary, kept between runs.

use std::path::Path;

use crate::model::ScannerId;

/// Window appearance: fixed light or dark, or the Windows app theme.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ThemeMode {
    Light,
    #[default]
    System,
    Dark,
}

impl ThemeMode {
    pub fn code(self) -> &'static str {
        match self {
            ThemeMode::Light => "light",
            ThemeMode::System => "system",
            ThemeMode::Dark => "dark",
        }
    }

    /// Light, System, or Dark, case-insensitively; anything else is not a
    /// theme. Shared by the settings file, the machine default the
    /// installer writes, and the installer's /Theme switch, so all three
    /// accept (and reject) the same spellings.
    pub fn parse_any(text: &str) -> Option<Self> {
        match text.trim().to_lowercase().as_str() {
            "light" => Some(ThemeMode::Light),
            "system" => Some(ThemeMode::System),
            "dark" => Some(ThemeMode::Dark),
            _ => None,
        }
    }

    pub fn parse(text: &str) -> Self {
        Self::parse_any(text).unwrap_or(ThemeMode::System)
    }
}

/// Which theme wins: an explicit per-user choice first (an explicit System
/// counts, so it masks the machine default), then the machine default the
/// installer wrote, then System. Pure, so the precedence is testable
/// without touching the registry.
pub fn resolve_theme(user: Option<ThemeMode>, machine: Option<ThemeMode>) -> ThemeMode {
    user.or(machine).unwrap_or(ThemeMode::System)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// Scanners left out of a full scan. Every scanner, Deep Scan included,
    /// is on by default.
    pub disabled: Vec<ScannerId>,
    /// Window appearance. System (the default) follows Windows.
    pub theme: ThemeMode,
    /// Whether the theme came from an explicit choice (the Appearance
    /// pills, or a theme line already in the file). Only an explicit
    /// choice is saved and only it overrides the machine default, so
    /// merely opening the app never masks an installer's default.
    pub theme_explicit: bool,
    pub last_scan: String,
    pub last_problems: Option<usize>,
    pub last_repair: String,
    /// Privacy category ids left ticked. Empty means nothing ticked.
    pub privacy_ticked: Vec<String>,
    /// Repairs skip the Windows restore point. Off by default: an elevated
    /// repair asks Windows for one first.
    pub skip_restore_point: bool,
}

impl Settings {
    pub fn parse(text: &str) -> Self {
        let mut settings = Self::default();
        for line in text.lines() {
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim();
            match name.trim() {
                "disabled" => {
                    settings.disabled = value.split(',').filter_map(ScannerId::parse).collect();
                }
                "last_scan" => settings.last_scan = value.to_string(),
                "last_problems" => settings.last_problems = value.parse().ok(),
                "last_repair" => settings.last_repair = value.to_string(),
                "privacy_ticked" => {
                    settings.privacy_ticked = value
                        .split(',')
                        .map(|id| id.trim().to_string())
                        .filter(|id| !id.is_empty())
                        .collect();
                }
                "restore_point" => settings.skip_restore_point = value == "0",
                // A valid theme line in the file is itself an explicit
                // choice: the writer only saves one for an explicit pick.
                // An invalid line is ignored, never an explicit System.
                "theme" => {
                    if let Some(mode) = ThemeMode::parse_any(value) {
                        settings.theme = mode;
                        settings.theme_explicit = true;
                    }
                }
                _ => {}
            }
        }
        settings
    }

    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .map(|text| Self::parse(&text))
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.to_text())
    }

    pub fn to_text(&self) -> String {
        let disabled: Vec<&str> = self.disabled.iter().map(|id| id.code()).collect();
        let mut text = format!("disabled={}\r\n", disabled.join(","));
        text.push_str(&format!("last_scan={}\r\n", one_line(&self.last_scan)));
        if let Some(count) = self.last_problems {
            text.push_str(&format!("last_problems={count}\r\n"));
        }
        text.push_str(&format!("last_repair={}\r\n", one_line(&self.last_repair)));
        if self.skip_restore_point {
            text.push_str("restore_point=0\r\n");
        }
        if !self.privacy_ticked.is_empty() {
            text.push_str(&format!(
                "privacy_ticked={}\r\n",
                self.privacy_ticked.join(",")
            ));
        }
        // An explicit System is saved too: it must keep overriding the
        // machine default after a restart.
        if self.theme != ThemeMode::System || self.theme_explicit {
            text.push_str(&format!("theme={}\r\n", self.theme.code()));
        }
        text
    }

    pub fn enabled(&self, id: ScannerId) -> bool {
        !self.disabled.contains(&id)
    }

    pub fn set_enabled(&mut self, id: ScannerId, on: bool) {
        self.disabled.retain(|have| *have != id);
        if !on {
            self.disabled.push(id);
        }
    }

    /// Scanners for a full scan, in engine order.
    pub fn full_scan(&self) -> Vec<ScannerId> {
        ScannerId::ALL
            .iter()
            .copied()
            .filter(|id| self.enabled(*id))
            .collect()
    }
}

fn one_line(text: &str) -> String {
    text.replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_round_trip() {
        let mut settings = Settings::default();
        assert_eq!(settings.theme, ThemeMode::System);
        settings.theme = ThemeMode::Dark;
        assert_eq!(Settings::parse(&settings.to_text()).theme, ThemeMode::Dark);
        settings.theme = ThemeMode::Light;
        assert_eq!(Settings::parse(&settings.to_text()).theme, ThemeMode::Light);
    }

    #[test]
    fn theme_names_parse_case_insensitively_and_reject_other_words() {
        use ThemeMode::{Dark, Light, System};
        assert_eq!(ThemeMode::parse_any("dark"), Some(Dark));
        assert_eq!(ThemeMode::parse_any("DARK"), Some(Dark));
        assert_eq!(ThemeMode::parse_any("  Light "), Some(Light));
        assert_eq!(ThemeMode::parse_any("SYSTEM"), Some(System));
        assert_eq!(ThemeMode::parse_any(""), None);
        assert_eq!(ThemeMode::parse_any("neon"), None);
        assert_eq!(ThemeMode::parse_any("darkmode"), None);
    }

    #[test]
    fn explicit_user_choice_beats_machine_default_beats_system() {
        use ThemeMode::{Dark, Light, System};
        assert_eq!(resolve_theme(Some(Dark), Some(Light)), Dark);
        assert_eq!(resolve_theme(None, Some(Dark)), Dark);
        assert_eq!(resolve_theme(None, None), System);
        // An explicit System masks a machine Dark: picking System in the
        // app must stick even when the installer chose Dark.
        assert_eq!(resolve_theme(Some(System), Some(Dark)), System);
    }

    #[test]
    fn an_explicit_system_is_saved_and_survives_a_reload() {
        // Merely opening the app writes no theme line, so an installer's
        // machine default keeps applying until the user picks.
        let plain = Settings::default();
        assert!(!plain.theme_explicit);
        assert!(!plain.to_text().contains("theme="));
        // Picking System explicitly saves it, and reloading keeps it
        // explicit, so it still masks the machine default.
        let chosen = Settings {
            theme: ThemeMode::System,
            theme_explicit: true,
            ..Settings::default()
        };
        assert!(chosen.to_text().contains("theme=system"));
        let again = Settings::parse(&chosen.to_text());
        assert_eq!(again.theme, ThemeMode::System);
        assert!(again.theme_explicit);
        // An invalid line is ignored, never an explicit System.
        let broken = Settings::parse("theme=neon\r\n");
        assert_eq!(broken.theme, ThemeMode::System);
        assert!(!broken.theme_explicit);
    }

    #[test]
    fn deep_scan_is_on_by_default_and_settings_round_trip() {
        let mut settings = Settings::default();
        assert!(settings.full_scan().contains(&ScannerId::DeepScan));
        assert!(settings.full_scan().contains(&ScannerId::CustomControls));
        settings.set_enabled(ScannerId::DeepScan, false);
        settings.set_enabled(ScannerId::TempShortcuts, false);
        settings.last_scan = "10/12/2026 15:30".into();
        settings.last_problems = Some(12);
        settings.last_repair = "Removed 3\nBackup x".into();
        settings.privacy_ticked = ["user-temp".to_string(), "clipboard".to_string()].to_vec();
        let again = Settings::parse(&settings.to_text());
        // A saved choice to leave Deep Scan out is kept.
        assert!(!again.full_scan().contains(&ScannerId::DeepScan));
        assert!(!again.full_scan().contains(&ScannerId::TempShortcuts));
        assert_eq!(again.last_problems, Some(12));
        assert_eq!(again.last_repair, "Removed 3 Backup x");
        assert_eq!(again.privacy_ticked, ["user-temp", "clipboard"]);
        assert!(Settings::default().privacy_ticked.is_empty());
        // Restore points are on unless turned off, and the choice is kept.
        assert!(!Settings::default().skip_restore_point);
        let off = Settings {
            skip_restore_point: true,
            ..Settings::default()
        };
        assert!(Settings::parse(&off.to_text()).skip_restore_point);
    }
}
