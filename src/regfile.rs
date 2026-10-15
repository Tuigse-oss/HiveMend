//! Reading Hivemend's own `.reg` backups back into registry operations, so
//! a restore writes through the same link-refusing registry layer as
//! everything else (never through `reg.exe`), inside one transaction.

use crate::model::ValueKind;
use crate::pathutil::{canonical_hive, canonical_path};
use crate::registry::{RegError, Registry};

/// One change a backup asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegOp {
    /// `[KEY]`: the key exists.
    CreateKey(String),
    /// `[-KEY]`: the key and everything below it is removed.
    DeleteKey(String),
    SetValue {
        key: String,
        name: String,
        data: ValueKind,
    },
    /// `"name"=-`: the value is removed.
    DeleteValue { key: String, name: String },
}

impl RegOp {
    pub fn key(&self) -> &str {
        match self {
            Self::CreateKey(key) | Self::DeleteKey(key) => key,
            Self::SetValue { key, .. } | Self::DeleteValue { key, .. } => key,
        }
    }
}

/// The registry part of a backup, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedBackup {
    pub ops: Vec<RegOp>,
    /// Entries the backup marks as not removed (a repair that was rolled
    /// back); their sections are left out of `ops`.
    pub left_out: usize,
}

/// Parse a backup's registry sections. Anything this program does not
/// write is an error, so a damaged or foreign file restores nothing.
pub fn parse_backup(text: &str) -> Result<ParsedBackup, String> {
    let mut lines = text.lines().map(|line| line.trim_end_matches('\r'));
    match lines.next().map(|line| line.trim_start_matches('\u{feff}')) {
        Some("Windows Registry Editor Version 5.00") => {}
        _ => return Err("it does not start like a registry export".into()),
    }
    // (entry, op); entry 0 is outside any numbered entry.
    let mut ops: Vec<(usize, RegOp)> = Vec::new();
    let mut not_removed: Vec<usize> = Vec::new();
    let mut entry = 0usize;
    let mut key: Option<String> = None;
    let mut pending = String::new();
    for (number, raw) in lines.enumerate() {
        let line_no = number + 2;
        if !pending.is_empty() {
            pending.push_str(raw.trim_start());
        } else {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(comment) = line.strip_prefix(';') {
                let comment = comment.trim();
                if comment == "Files" {
                    break;
                }
                if let Some(rest) = comment.strip_prefix("entry ") {
                    if let Some(id) = rest.strip_suffix(" was not removed") {
                        not_removed.push(id.parse().map_err(|_| bad(line_no))?);
                    } else {
                        entry = rest.parse().map_err(|_| bad(line_no))?;
                        key = None;
                    }
                }
                continue;
            }
            if let Some(header) = line.strip_prefix('[') {
                let header = header.strip_suffix(']').ok_or_else(|| bad(line_no))?;
                let (delete, path) = match header.strip_prefix('-') {
                    Some(path) => (true, path),
                    None => (false, header),
                };
                let path = registry_path(path).ok_or_else(|| bad(line_no))?;
                if delete {
                    ops.push((entry, RegOp::DeleteKey(path)));
                    key = None;
                } else {
                    ops.push((entry, RegOp::CreateKey(path.clone())));
                    key = Some(path);
                }
                continue;
            }
            pending.push_str(line);
        }
        if let Some(open) = pending.strip_suffix('\\') {
            pending = open.to_string();
            continue;
        }
        let line = std::mem::take(&mut pending);
        let key = key.clone().ok_or_else(|| bad(line_no))?;
        ops.push((entry, value_op(&key, &line).ok_or_else(|| bad(line_no))?));
    }
    if !pending.is_empty() {
        return Err("it ends in the middle of a value".into());
    }
    let left_out = not_removed.len();
    let ops = ops
        .into_iter()
        .filter(|(entry, _)| *entry == 0 || !not_removed.contains(entry))
        .map(|(_, op)| op)
        .collect();
    Ok(ParsedBackup { ops, left_out })
}

fn bad(line: usize) -> String {
    format!("line {line} is not something Hivemend writes")
}

/// A key path with a known hive, canonical.
fn registry_path(path: &str) -> Option<String> {
    let hive = path.split('\\').next()?;
    canonical_hive(hive)?;
    if path.contains("\\\\") || path.ends_with('\\') {
        return None;
    }
    Some(canonical_path(path))
}

/// `"name"=...` or `@=...` under `key`.
fn value_op(key: &str, line: &str) -> Option<RegOp> {
    let (name, rest) = if let Some(rest) = line.strip_prefix("@=") {
        (String::new(), rest)
    } else {
        let (name, after) = quoted(line)?;
        (name, after.strip_prefix('=')?)
    };
    let key = key.to_string();
    if rest == "-" {
        return Some(RegOp::DeleteValue { key, name });
    }
    let data = if rest.starts_with('"') {
        let (text, after) = quoted(rest)?;
        if !after.is_empty() {
            return None;
        }
        ValueKind::Sz(text)
    } else if let Some(hex) = rest.strip_prefix("dword:") {
        if hex.len() != 8 {
            return None;
        }
        ValueKind::Dword(u32::from_str_radix(hex, 16).ok()?)
    } else if let Some(bytes) = rest.strip_prefix("hex:") {
        ValueKind::Binary(hex_bytes(bytes)?)
    } else {
        let typed = rest.strip_prefix("hex(")?;
        let (kind, bytes) = typed.split_once("):")?;
        let kind = u32::from_str_radix(kind, 16).ok()?;
        // The exact bytes, whatever the type: written back as they were.
        ValueKind::Other {
            kind,
            bytes: hex_bytes(bytes)?,
        }
    };
    Some(RegOp::SetValue { key, name, data })
}

/// A `"..."` string with `\\` and `\"` escapes; returns it and the rest.
fn quoted(text: &str) -> Option<(String, &str)> {
    let body = text.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = body.char_indices();
    while let Some((index, ch)) = chars.next() {
        match ch {
            '\\' => match chars.next()? {
                (_, '\\') => out.push('\\'),
                (_, '"') => out.push('"'),
                _ => return None,
            },
            '"' => return Some((out, &body[index + 1..])),
            ch => out.push(ch),
        }
    }
    None
}

fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    if text.trim().is_empty() {
        return Some(Vec::new());
    }
    text.split(',')
        .map(|part| u8::from_str_radix(part.trim(), 16).ok())
        .collect()
}

/// Apply `ops` through `reg` in one transaction: all of them, or none.
/// Returns the number of keys and values written or removed.
pub fn apply_ops(reg: &mut dyn Registry, ops: &[RegOp]) -> Result<(usize, usize), RegError> {
    let mut tx = reg.begin()?;
    let mut keys = 0;
    let mut values = 0;
    for op in ops {
        match op {
            RegOp::CreateKey(key) => {
                // Writing and removing a marker creates the key if needed,
                // through the same link-refusing creation as any write.
                if tx.values(key).is_err() {
                    tx.set_value(key, MARKER, &ValueKind::Dword(0))?;
                    tx.delete_value(key, MARKER)?;
                }
                keys += 1;
            }
            RegOp::DeleteKey(key) => {
                match tx.delete_tree(key) {
                    Ok(()) | Err(RegError::NotFound) => {}
                    Err(err) => return Err(err),
                }
                keys += 1;
            }
            RegOp::SetValue { key, name, data } => {
                tx.set_value(key, name, data)?;
                values += 1;
            }
            RegOp::DeleteValue { key, name } => {
                match tx.delete_value(key, name) {
                    Ok(()) | Err(RegError::NotFound) => {}
                    Err(err) => return Err(err),
                }
                values += 1;
            }
        }
    }
    tx.commit()?;
    Ok((keys, values))
}

const MARKER: &str = "Hivemend restore {6f1d2a5e-hm}";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RegValue, Repair};
    use crate::registry::MemoryRegistry;

    fn values() -> Vec<(&'static str, ValueKind)> {
        vec![
            ("", ValueKind::Sz("default".into())),
            (
                "quoted",
                ValueKind::Sz(r#"C:\Program Files\App\"x".exe"#.into()),
            ),
            ("control", ValueKind::Sz("line\nbreak".into())),
            ("expand", ValueKind::ExpandSz(r"%SystemRoot%\x.dll".into())),
            ("multi", ValueKind::MultiSz(vec!["a".into(), "b c".into()])),
            ("binary", ValueKind::Binary((0u8..=200).collect())),
            ("empty", ValueKind::Binary(Vec::new())),
            ("dword", ValueKind::Dword(0xdead_beef)),
            (
                "qword",
                ValueKind::Other {
                    kind: 11,
                    bytes: vec![1, 2, 3, 4, 5, 6, 7, 8],
                },
            ),
            (
                "odd",
                ValueKind::Other {
                    kind: 1,
                    bytes: vec![0x41, 0x00, 0x42],
                },
            ),
        ]
    }

    #[test]
    fn every_value_type_round_trips_through_a_backup() {
        let key = r"HKEY_CURRENT_USER\Software\RoundTrip";
        let mut source = MemoryRegistry::new();
        for (name, data) in values() {
            source.set(key, name, data);
        }
        source.set(&format!(r"{key}\Child"), "c", ValueKind::Dword(1));
        source.set(&format!(r"{key}\Empty\Deeper"), "d", ValueKind::Dword(2));
        let (body, unreadable) =
            crate::backup::registry_sections(&source, &[Repair::DeleteKey { key: key.into() }]);
        assert!(unreadable.is_empty());
        let text =
            format!("Windows Registry Editor Version 5.00\r\n\r\n; Hive Mend backup.\r\n{body}");
        let parsed = parse_backup(&text).unwrap();
        let mut restored = MemoryRegistry::new();
        apply_ops(&mut restored, &parsed.ops).unwrap();
        let encoded = |reg: &MemoryRegistry, path: &str| -> Vec<(String, (u32, Vec<u8>))> {
            let mut out: Vec<_> = reg
                .values(path)
                .unwrap()
                .into_iter()
                .map(|RegValue { name, data }| (name, data.encoded()))
                .collect();
            out.sort();
            out
        };
        for path in [
            key.to_string(),
            format!(r"{key}\Child"),
            format!(r"{key}\Empty\Deeper"),
        ] {
            assert_eq!(encoded(&restored, &path), encoded(&source, &path), "{path}");
        }
    }

    #[test]
    fn entries_marked_not_removed_are_left_out() {
        let text = "Windows Registry Editor Version 5.00\r\n\r\n; Hive Mend backup.\r\n\
            \r\n; entry 1\r\n[HKEY_CURRENT_USER\\Software\\A]\r\n\"x\"=dword:00000001\r\n\
            ; entry 1 was not removed\r\n\
            \r\n; entry 2\r\n[HKEY_CURRENT_USER\\Software\\B]\r\n\"y\"=\"2\"\r\n";
        let parsed = parse_backup(text).unwrap();
        assert_eq!(parsed.left_out, 1);
        assert!(parsed.ops.iter().all(|op| !op.key().ends_with(r"\A")));
        assert!(parsed.ops.iter().any(|op| op.key().ends_with(r"\B")));
    }

    #[test]
    fn deletions_and_damage_are_handled() {
        let text = "Windows Registry Editor Version 5.00\r\n\r\n\
            [HKEY_CURRENT_USER\\Software\\Run]\r\n\"Gone\"=-\r\n\
            [-HKEY_CURRENT_USER\\Software\\Old]\r\n";
        let parsed = parse_backup(text).unwrap();
        assert!(parsed.ops.contains(&RegOp::DeleteValue {
            key: r"HKEY_CURRENT_USER\Software\Run".into(),
            name: "Gone".into(),
        }));
        assert!(
            parsed
                .ops
                .contains(&RegOp::DeleteKey(r"HKEY_CURRENT_USER\Software\Old".into()))
        );
        for broken in [
            "not a registry file",
            "Windows Registry Editor Version 5.00\r\n\"orphan\"=dword:00000001\r\n",
            "Windows Registry Editor Version 5.00\r\n[HKEY_NOWHERE\\X]\r\n",
            "Windows Registry Editor Version 5.00\r\n[HKEY_CURRENT_USER\\X]\r\n\"v\"=dword:1\r\n",
            "Windows Registry Editor Version 5.00\r\n[HKEY_CURRENT_USER\\X]\r\n\"v\"=hex:01,\\\r\n",
        ] {
            assert!(parse_backup(broken).is_err(), "{broken:?}");
        }
    }

    #[test]
    fn a_failed_restore_changes_nothing() {
        // The second key cannot be written: the first write must not stay.
        struct Refuses(MemoryRegistry);
        impl Registry for Refuses {
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
            fn begin(&mut self) -> Result<Box<dyn crate::registry::RegTransaction + '_>, RegError> {
                Ok(Box::new(crate::registry::DenyTx {
                    inner: self.0.begin()?,
                    deny_subkeys: None,
                    deny_values: None,
                    deny_writes: Some(r"HKEY_CURRENT_USER\Software\Locked".into()),
                }))
            }
        }
        let mut reg = Refuses(MemoryRegistry::new());
        reg.0.set_sz(r"HKCU\Software\Keep", "v", "old");
        let ops = vec![
            RegOp::SetValue {
                key: r"HKEY_CURRENT_USER\Software\Keep".into(),
                name: "v".into(),
                data: ValueKind::Sz("new".into()),
            },
            RegOp::SetValue {
                key: r"HKEY_CURRENT_USER\Software\Locked".into(),
                name: "v".into(),
                data: ValueKind::Sz("x".into()),
            },
        ];
        assert!(apply_ops(&mut reg, &ops).is_err());
        assert_eq!(
            reg.0.values(r"HKCU\Software\Keep").unwrap()[0].data,
            ValueKind::Sz("old".into())
        );
    }
}
