//! Entries the user chose to ignore. They never show up in a scan, so they
//! can never be repaired by accident, from the window or the command line.

use std::path::Path;

use crate::model::Finding;
use crate::pathutil::canonical_path;

const HEADER: &str = "# Registry Master ignore list.\r\n\
# One entry per line: a registry key or file path, then optionally a tab and a value name.\r\n";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Exclusions {
    entries: Vec<Exclusion>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exclusion {
    pub key: String,
    /// `Some("")` is the key's default value. `None` covers the key itself.
    pub value: Option<String>,
}

impl Exclusion {
    pub fn of(finding: &Finding) -> Self {
        Self {
            key: canonical_path(&finding.key),
            value: finding.value.clone(),
        }
    }

    pub fn label(&self) -> String {
        match self.value.as_deref() {
            None => self.key.clone(),
            Some("") => format!("{}  (default)", self.key),
            Some(name) => format!("{}  {name}", self.key),
        }
    }

    fn matches(&self, finding: &Finding) -> bool {
        canonical_path(&finding.key).eq_ignore_ascii_case(&self.key)
            && match (&self.value, &finding.value) {
                (None, None) => true,
                (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
                _ => false,
            }
    }
}

impl Exclusions {
    pub fn parse(text: &str) -> Self {
        let mut entries = Vec::new();
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let (key, value) = match line.split_once('\t') {
                Some((key, value)) => (key, Some(value.to_string())),
                None => (line, None),
            };
            let key = canonical_path(key.trim());
            if !key.is_empty() {
                entries.push(Exclusion { key, value });
            }
        }
        Self { entries }
    }

    /// A missing or unreadable file is an empty list.
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .map(|bytes| Self::parse(&crate::rules::decode_text_owned(bytes)))
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.to_text())
    }

    pub fn to_text(&self) -> String {
        let mut text = String::from(HEADER);
        for entry in &self.entries {
            text.push_str(&entry.key);
            if let Some(value) = &entry.value {
                text.push('\t');
                text.push_str(value);
            }
            text.push_str("\r\n");
        }
        text
    }

    pub fn entries(&self) -> &[Exclusion] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, finding: &Finding) -> bool {
        self.entries.iter().any(|entry| entry.matches(finding))
    }

    /// Returns false when the finding was already ignored.
    pub fn add(&mut self, finding: &Finding) -> bool {
        if self.contains(finding) {
            return false;
        }
        self.entries.push(Exclusion::of(finding));
        true
    }

    pub fn remove(&mut self, index: usize) {
        if index < self.entries.len() {
            self.entries.remove(index);
        }
    }

    /// Drop ignored findings. Returns how many were dropped.
    pub fn filter(&self, findings: &mut Vec<Finding>) -> usize {
        let before = findings.len();
        findings.retain(|finding| !self.contains(finding));
        before - findings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Repair, ScannerId};

    fn finding(key: &str, value: Option<&str>) -> Finding {
        Finding {
            scanner: ScannerId::StartupPrograms,
            scanner_name: "Startup Programs".into(),
            key: key.into(),
            value: value.map(str::to_string),
            detail: "missing".into(),
            repair: Repair::None,
        }
    }

    #[test]
    fn round_trips_keys_values_and_default_values() {
        let mut list = Exclusions::default();
        assert!(list.add(&finding(r"HKCU\Software\Old", None)));
        assert!(list.add(&finding(r"HKEY_CURRENT_USER\Run", Some("Tool"))));
        assert!(list.add(&finding(r"HKEY_CURRENT_USER\Cmd", Some(""))));
        assert!(!list.add(&finding(r"hkey_current_user\run", Some("TOOL"))));
        let again = Exclusions::parse(&list.to_text());
        assert_eq!(again, list);
        let mut findings = vec![
            finding(r"HKEY_CURRENT_USER\Software\Old", None),
            finding(r"HKEY_CURRENT_USER\Software\Old", Some("Other")),
            finding(r"HKEY_CURRENT_USER\Run", Some("tool")),
            finding(r"HKEY_CURRENT_USER\Cmd", Some("")),
            finding(r"HKEY_CURRENT_USER\Cmd", Some("Autorun")),
        ];
        assert_eq!(again.filter(&mut findings), 3);
        assert_eq!(findings.len(), 2);
    }
}
