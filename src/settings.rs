//! Window settings and the status summary, kept between runs.

use std::path::Path;

use crate::model::ScannerId;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// Scanners left out of a full scan. Every scanner, Deep Scan included,
    /// is on by default.
    pub disabled: Vec<ScannerId>,
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
