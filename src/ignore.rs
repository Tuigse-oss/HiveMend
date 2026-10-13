use std::path::Path;

use crate::model::Error;
use crate::rules::decode_text_owned;

#[derive(Clone, Debug, Default)]
pub struct IgnoreDb {
    pub key_fragments: Vec<String>,
    pub value_fragments: Vec<String>,
}

impl IgnoreDb {
    pub fn skips_key(&self, path: &str) -> bool {
        contains_fragment(&self.key_fragments, path)
    }

    pub fn skips_value(&self, text: &str) -> bool {
        contains_fragment(&self.value_fragments, text)
    }
}

fn contains_fragment(fragments: &[String], text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    fragments.iter().any(|fragment| lower.contains(fragment))
}

pub fn load_ignore_file(path: &Path, into_keys: bool, db: &mut IgnoreDb) -> Result<(), Error> {
    if !path.exists() {
        return Ok(());
    }
    let text = decode_text_owned(std::fs::read(path)?);
    let target = if into_keys {
        &mut db.key_fragments
    } else {
        &mut db.value_fragments
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("[**") || line.starts_with('#') {
            continue;
        }
        let fragment = line.to_ascii_lowercase();
        if fragment == "\\*" || target.iter().any(|have| have == &fragment) {
            continue;
        }
        target.push(fragment);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn reads_legacy_ignore_lists_when_extracted() {
        let keys = Path::new("/tmp/rm10/app/Data/keys.dat");
        if !keys.exists() {
            return;
        }
        let mut db = IgnoreDb::default();
        load_ignore_file(keys, true, &mut db).unwrap();
        load_ignore_file(Path::new("/tmp/rm10/app/Data/values.dat"), false, &mut db).unwrap();
        assert!(db.key_fragments.len() > 10);
        assert!(db.skips_value("package.msi"));
        assert!(!db.skips_key(r"HKEY_CURRENT_USER\Software\RegistryMaster"));
    }
}
