use std::collections::BTreeMap;
use std::path::Path;

use crate::model::{Error, PathKind, RulePath, ScannerDef, ScannerId};
use crate::pathutil::canonical_path;

const BUILTIN_XML: &str = include_str!("../rules/scanners.xml");

#[derive(Clone, Debug)]
pub struct RuleSet {
    pub scanners: Vec<ScannerDef>,
}

impl RuleSet {
    pub fn builtin() -> Self {
        parse_rules_xml(BUILTIN_XML).expect("built-in scanner rules")
    }

    pub fn get(&self, id: ScannerId) -> Option<&ScannerDef> {
        self.scanners.iter().find(|scanner| scanner.id == id)
    }

    pub fn merge_file(&mut self, xml: &str) -> Result<(), Error> {
        let extra = parse_rules_xml(xml)?;
        for incoming in extra.scanners {
            if let Some(existing) = self
                .scanners
                .iter_mut()
                .find(|scanner| scanner.id == incoming.id)
            {
                for path in incoming.paths {
                    push_unique(&mut existing.paths, path);
                }
            } else {
                self.scanners.push(incoming);
            }
        }
        Ok(())
    }
}

pub fn load_rules_file(path: &Path) -> Result<RuleSet, Error> {
    let bytes = std::fs::read(path)?;
    parse_rules_xml(&decode_text_owned(bytes))
}

pub fn builtin_deep_roots() -> Vec<String> {
    [
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\App Paths",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SharedDLLs",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts",
    ]
    .into_iter()
    .map(canonical_path)
    .collect()
}

fn push_unique(paths: &mut Vec<RulePath>, path: RulePath) {
    let canonical = canonical_path(&path.path);
    if !paths
        .iter()
        .any(|have| have.kind == path.kind && have.path.eq_ignore_ascii_case(&canonical))
    {
        paths.push(RulePath {
            path: canonical,
            kind: path.kind,
        });
    }
}

fn parse_kind(text: Option<&str>) -> Result<PathKind, Error> {
    match text.unwrap_or("").trim().to_ascii_lowercase().as_str() {
        "" | "inherited" => Ok(PathKind::Inherited),
        "value-name-path" => Ok(PathKind::ValueNamePath),
        "mui-cache" => Ok(PathKind::MuiCache),
        "startup-approved" => Ok(PathKind::StartupApproved),
        "association-toast" => Ok(PathKind::AssociationToast),
        "shell-command" => Ok(PathKind::ShellCommand),
        "shell-handler" => Ok(PathKind::ShellHandler),
        "clsid-key" => Ok(PathKind::ClsidKey),
        "ie-extension" => Ok(PathKind::IeExtension),
        "typelib" => Ok(PathKind::TypeLib),
        "default-icon" => Ok(PathKind::DefaultIcon),
        "applications" => Ok(PathKind::Applications),
        "sound-event" => Ok(PathKind::SoundEvent),
        "arp-cache" => Ok(PathKind::ArpCache),
        "start-menu-client" => Ok(PathKind::StartMenuClient),
        "user-assist" => Ok(PathKind::UserAssist),
        "path-value" => Ok(PathKind::PathValue),
        "url-protocol" => Ok(PathKind::UrlProtocol),
        "clsid-value" => Ok(PathKind::ClsidValue),
        "autoplay" => Ok(PathKind::Autoplay),
        "codec" => Ok(PathKind::Codec),
        "appinit" => Ok(PathKind::AppInit),
        "command-autorun" => Ok(PathKind::CommandAutorun),
        "installer-source" => Ok(PathKind::InstallerSource),
        "firewall-rule" => Ok(PathKind::FirewallRule),
        other => Err(Error(format!("unknown rule kind '{other}'"))),
    }
}

pub fn decode_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return utf16_le(&bytes[2..]);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let swapped: Vec<u8> = bytes[2..]
            .chunks(2)
            .flat_map(|chunk| {
                if chunk.len() == 2 {
                    vec![chunk[1], chunk[0]]
                } else {
                    vec![]
                }
            })
            .collect();
        return utf16_le(&swapped);
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8_lossy(bytes).into_owned()
}

/// Owned [`decode_text`]: when the bytes are valid UTF-8 the allocation is
/// reused instead of copied.
pub fn decode_text_owned(bytes: Vec<u8>) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        return decode_text(&bytes);
    }
    let mut bytes = bytes;
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        bytes.drain(..3);
    }
    String::from_utf8_lossy_owned(bytes)
}

fn utf16_le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks(2)
        .filter_map(|chunk| {
            if chunk.len() == 2 {
                Some(u16::from_le_bytes([chunk[0], chunk[1]]))
            } else {
                None
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

enum Token {
    Open { name: String, attrs: Attrs },
    Close { name: String },
}

#[derive(Default)]
struct Attrs(BTreeMap<String, String>);

impl Attrs {
    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

pub fn parse_rules_xml(xml: &str) -> Result<RuleSet, Error> {
    let tokens = tokenize(xml)?;
    let mut scanners = Vec::new();
    let mut current: Option<ScannerDef> = None;
    for token in tokens {
        match token {
            Token::Open { name, attrs } if name.eq_ignore_ascii_case("Scanner") => {
                if current.is_some() {
                    return Err(Error("nested Scanner element".into()));
                }
                let id = attrs
                    .get("ID")
                    .and_then(ScannerId::parse)
                    .ok_or_else(|| Error("Scanner is missing a known ID".into()))?;
                let label = attrs.get("NAME").unwrap_or(id.code()).trim().to_string();
                let enabled = attrs.get("STATE").unwrap_or("1") != "0";
                current = Some(ScannerDef {
                    id,
                    name: label,
                    paths: Vec::new(),
                    enabled,
                });
            }
            Token::Open { name, attrs } if name.eq_ignore_ascii_case("Paths") => {
                if let (Some(scanner), Some(data)) = (current.as_mut(), attrs.get("DATA")) {
                    let data = data.trim();
                    if !data.is_empty() {
                        let kind = parse_kind(attrs.get("KIND"))?;
                        push_unique(
                            &mut scanner.paths,
                            RulePath {
                                path: data.to_string(),
                                kind,
                            },
                        );
                    }
                }
            }
            Token::Close { name } if name.eq_ignore_ascii_case("Scanner") => {
                if let Some(scanner) = current.take() {
                    scanners.push(scanner);
                }
            }
            _ => {}
        }
    }
    if scanners.is_empty() {
        return Err(Error("no Scanner elements in rules".into()));
    }
    Ok(RuleSet { scanners })
}

fn tokenize(xml: &str) -> Result<Vec<Token>, Error> {
    let mut tokens = Vec::new();
    let bytes = xml.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let Some(rel) = xml[index..].find('<') else {
            break;
        };
        index += rel;
        if xml[index..].starts_with("<!--") {
            index = xml[index..]
                .find("-->")
                .map(|end| index + end + 3)
                .unwrap_or(xml.len());
            continue;
        }
        if xml[index..].starts_with("<?") {
            index = xml[index..]
                .find("?>")
                .map(|end| index + end + 2)
                .unwrap_or(xml.len());
            continue;
        }
        let end = xml[index..]
            .find('>')
            .map(|end| index + end)
            .ok_or_else(|| Error("unclosed XML tag".into()))?;
        let body = &xml[index + 1..end];
        index = end + 1;
        let body = body.trim();
        if let Some(name) = body.strip_prefix('/') {
            tokens.push(Token::Close {
                name: name.split_whitespace().next().unwrap_or(name).to_string(),
            });
            continue;
        }
        let self_closing = body.ends_with('/');
        let body = body.trim_end_matches('/').trim();
        let mut parts = body.split_whitespace();
        let name = parts.next().unwrap_or("").to_string();
        let attr_text = body[name.len()..].trim();
        let _ = self_closing;
        tokens.push(Token::Open {
            name,
            attrs: parse_attrs(attr_text),
        });
    }
    Ok(tokens)
}

fn parse_attrs(text: &str) -> Attrs {
    let mut attrs = Attrs::default();
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        while index < chars.len() && chars[index].is_whitespace() {
            index += 1;
        }
        let start = index;
        while index < chars.len() && chars[index] != '=' && !chars[index].is_whitespace() {
            index += 1;
        }
        if start == index {
            break;
        }
        let name: String = chars[start..index].iter().collect();
        while index < chars.len() && chars[index] != '=' {
            index += 1;
        }
        if index >= chars.len() {
            break;
        }
        index += 1;
        while index < chars.len() && chars[index].is_whitespace() {
            index += 1;
        }
        if index >= chars.len() {
            break;
        }
        let quote = chars[index];
        if quote != '"' && quote != '\'' {
            break;
        }
        index += 1;
        let value_start = index;
        while index < chars.len() && chars[index] != quote {
            index += 1;
        }
        let value: String = chars[value_start..index].iter().collect();
        attrs.0.insert(name, decode_entities(&value));
        if index < chars.len() {
            index += 1;
        }
    }
    attrs
}

fn decode_entities(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_cover_the_classic_scanners() {
        let rules = RuleSet::builtin();
        assert_eq!(rules.scanners.len(), 12);
        let startup = rules.get(ScannerId::StartupPrograms).unwrap();
        assert!(startup.enabled);
        assert!(startup.paths.iter().any(|path| {
            path.kind == PathKind::Inherited
                && path.path.eq_ignore_ascii_case(
                    r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
                )
        }));
        assert!(
            startup
                .paths
                .iter()
                .any(|path| path.kind == PathKind::StartupApproved)
        );
        assert!(
            rules
                .get(ScannerId::SoftwareLocations)
                .unwrap()
                .paths
                .iter()
                .any(|path| path.kind == PathKind::ValueNamePath
                    && path
                        .path
                        .to_ascii_lowercase()
                        .contains("appcompatflags\\layers"))
        );
        assert!(!rules.get(ScannerId::DeepScan).unwrap().enabled);
    }

    #[test]
    fn parses_utf16_legacy_rules_when_extracted() {
        let path = Path::new("/tmp/rm10/app/Data/rmscan.xml");
        if !path.exists() {
            return;
        }
        let rules = load_rules_file(path).unwrap();
        let locations = rules.get(ScannerId::SoftwareLocations).unwrap();
        assert!(locations.paths.len() >= 2);
        let startup = rules.get(ScannerId::StartupPrograms).unwrap();
        assert!(
            startup
                .paths
                .iter()
                .any(|path| path.path.to_ascii_lowercase().contains("runservices"))
        );
    }

    #[test]
    fn owned_decoding_matches_borrowed_decoding() {
        let cases: Vec<Vec<u8>> = vec![
            b"<Scanner></Scanner>".to_vec(),
            b"\xEF\xBB\xBFplain".to_vec(),
            b"\xFF\xFEh\x00i\x00".to_vec(),
            b"\xFE\xFF\x00h\x00i".to_vec(),
            b"broken \xFF bytes".to_vec(),
        ];
        for bytes in cases {
            assert_eq!(decode_text_owned(bytes.clone()), decode_text(&bytes));
        }
        assert_eq!(decode_text_owned(b"plain".to_vec()), "plain");
    }
}
