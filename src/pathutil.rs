use crate::fs::FileView;

pub fn canonical_hive(name: &str) -> Option<&'static str> {
    match name.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => Some("HKEY_LOCAL_MACHINE"),
        "HKCU" | "HKEY_CURRENT_USER" => Some("HKEY_CURRENT_USER"),
        "HKCR" | "HKEY_CLASSES_ROOT" => Some("HKEY_CLASSES_ROOT"),
        "HKU" | "HKEY_USERS" => Some("HKEY_USERS"),
        "HKCC" | "HKEY_CURRENT_CONFIG" => Some("HKEY_CURRENT_CONFIG"),
        _ => None,
    }
}

pub fn canonical_path(path: &str) -> String {
    let trimmed = path.trim().trim_matches(['\\', '/']);
    let mut parts: Vec<String> = trimmed
        .split(['\\', '/'])
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect();
    if let Some(hive) = parts.first().and_then(|name| canonical_hive(name)) {
        parts[0] = hive.to_string();
    }
    parts.join("\\")
}

/// 32-bit software on 64-bit Windows lives under `WOW6432Node`, not a
/// reflected key. Reflection itself was removed after Windows 7.
pub fn wow_mirror(path: &str) -> Option<String> {
    let canonical = canonical_path(path);
    let lower = canonical.to_ascii_lowercase();
    let prefix = "hkey_local_machine\\software\\";
    let rest = lower.strip_prefix(prefix)?;
    if rest.is_empty() || rest.starts_with("wow6432node") {
        return None;
    }
    let original_rest = &canonical["HKEY_LOCAL_MACHINE\\SOFTWARE\\".len()..];
    Some(format!(
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\{original_rest}"
    ))
}

pub fn hive_views(path: &str, wow64: bool) -> Vec<String> {
    let canonical = canonical_path(path);
    let mut views = vec![canonical.clone()];
    if wow64 && let Some(mirror) = wow_mirror(&canonical) {
        views.push(mirror);
    }
    views
}

pub fn expand_env(fs: &dyn FileView, input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '%'
            && let Some(end) = chars[index + 1..].iter().position(|ch| *ch == '%')
        {
            let name: String = chars[index + 1..index + 1 + end].iter().collect();
            if !name.is_empty()
                && let Some(value) = lookup_var(fs, &name)
            {
                out.push_str(&value);
                index += end + 2;
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

fn lookup_var(fs: &dyn FileView, name: &str) -> Option<String> {
    if let Some(value) = fs.var(name) {
        return Some(value);
    }
    for alias in var_aliases(name) {
        if let Some(value) = fs.var(alias) {
            return Some(value);
        }
    }
    None
}

fn var_aliases(name: &str) -> &'static [&'static str] {
    match name.to_ascii_lowercase().as_str() {
        "systemroot" | "windir" => &["SystemRoot", "windir", "WINDIR"],
        "programfiles" => &["ProgramFiles", "PROGRAMFILES"],
        "programfiles(x86)" => &["ProgramFiles(x86)", "PROGRAMFILES(X86)"],
        "commonprogramfiles" => &["CommonProgramFiles"],
        "commonprogramfiles(x86)" => &["CommonProgramFiles(x86)"],
        "userprofile" => &["USERPROFILE", "UserProfile"],
        "temp" | "tmp" => &["TEMP", "TMP"],
        "appdata" => &["APPDATA"],
        "localappdata" => &["LOCALAPPDATA"],
        "programdata" => &["ProgramData", "PROGRAMDATA"],
        _ => &[],
    }
}

pub fn system_root(fs: &dyn FileView) -> String {
    lookup_var(fs, "SystemRoot").unwrap_or_else(|| "C:\\Windows".to_string())
}

pub fn normalize_fs(path: &str) -> String {
    let expanded = path.trim().trim_matches('"');
    let mut out = expanded.replace('/', "\\");
    while out.contains("\\\\") && !out.starts_with("\\\\") {
        out = out.replace("\\\\", "\\");
    }
    out
}

pub fn under_windows_dir(fs: &dyn FileView, path: &str) -> bool {
    let root = normalize_fs(&system_root(fs)).to_ascii_lowercase();
    let path = normalize_fs(path).to_ascii_lowercase();
    path == root || path.starts_with(&(root + "\\"))
}

/// True unless the file is verifiably gone. A path with an unresolved
/// `%VAR%` cannot be checked, so it counts as present.
pub fn file_present(fs: &dyn FileView, path: &str) -> bool {
    let path = normalize_fs(&expand_env(fs, path));
    if path.contains('%') {
        return true;
    }
    if fs.exists(&path) {
        return true;
    }
    if let Some(alt) = swap_system32(&path)
        && fs.exists(&alt)
    {
        return true;
    }
    swap_program_files(fs, &path).is_some_and(|alt| fs.exists(&alt))
}

/// 32-bit registrations under `WOW6432Node` often store `%ProgramFiles%`,
/// which a 32-bit process expands to `Program Files (x86)`. This process is
/// 64-bit, so try the other Program Files folder before calling a file gone.
fn swap_program_files(fs: &dyn FileView, path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    for (from, to) in [
        ("CommonProgramFiles", "CommonProgramFiles(x86)"),
        ("CommonProgramFiles(x86)", "CommonProgramFiles"),
        ("ProgramFiles", "ProgramFiles(x86)"),
        ("ProgramFiles(x86)", "ProgramFiles"),
    ] {
        let (Some(from_dir), Some(to_dir)) = (lookup_var(fs, from), lookup_var(fs, to)) else {
            continue;
        };
        let from_dir = normalize_fs(&from_dir).trim_end_matches('\\').to_string();
        let prefix = format!("{}\\", from_dir.to_ascii_lowercase());
        if lower.starts_with(&prefix) {
            return Some(format!(
                "{}\\{}",
                normalize_fs(&to_dir).trim_end_matches('\\'),
                &path[prefix.len()..]
            ));
        }
    }
    None
}

fn swap_system32(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    const SYSTEM32: &str = "\\system32\\";
    const SYSWOW64: &str = "\\syswow64\\";
    if let Some(index) = lower.find(SYSTEM32) {
        let mut swapped = String::new();
        swapped.push_str(&path[..index]);
        swapped.push_str("\\SysWOW64\\");
        swapped.push_str(&path[index + SYSTEM32.len()..]);
        return Some(swapped);
    }
    if let Some(index) = lower.find(SYSWOW64) {
        let mut swapped = String::new();
        swapped.push_str(&path[..index]);
        swapped.push_str("\\System32\\");
        swapped.push_str(&path[index + SYSWOW64.len()..]);
        return Some(swapped);
    }
    None
}

/// Pull filesystem paths out of a command, icon (`path,0`), or rundll32 line.
pub fn paths_in_command(command: &str) -> Vec<String> {
    // `@C:\Windows\System32\x.dll,-12` is an indirect resource string.
    let trimmed = command.trim();
    let trimmed = trimmed.strip_prefix('@').unwrap_or(trimmed);
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut found = Vec::new();
    if let Some(rest) = strip_host(trimmed, "rundll32") {
        found.extend(paths_in_command(rest));
        return dedup_paths(found);
    }
    if let Some(rest) = strip_host(trimmed, "regsvr32") {
        found.extend(paths_in_command(rest));
        return dedup_paths(found);
    }
    collect_paths(trimmed, &mut found);
    dedup_paths(found)
}

fn strip_host<'a>(command: &'a str, host: &str) -> Option<&'a str> {
    let lower = command.to_ascii_lowercase();
    let host_exe = format!("{host}.exe");
    if lower.starts_with(host_exe.as_str()) {
        return Some(command[host_exe.len()..].trim());
    }
    if lower.starts_with(host) {
        let after = &command[host.len()..];
        if after.starts_with([' ', '\t']) {
            return Some(after.trim());
        }
    }
    None
}

fn collect_paths(text: &str, found: &mut Vec<String>) {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return;
    }
    if let Some(rest) = trimmed.strip_prefix('"')
        && let Some(end) = rest.find('"')
    {
        push_path(found, &rest[..end]);
        collect_paths(rest[end + 1..].trim(), found);
        return;
    }
    if starts_like_path(trimmed) {
        if let Some(end) = extension_end(trimmed) {
            push_path(found, &trimmed[..end]);
            let rest = trimmed[end..].trim();
            if !rest.is_empty() {
                collect_paths(rest, found);
            }
            return;
        }
        let end = trimmed
            .find(" /")
            .or_else(|| trimmed.find(" -"))
            .unwrap_or(trimmed.len());
        push_path(found, trimmed[..end].trim());
        return;
    }
    if let Some(index) = find_later_path(trimmed)
        && index > 0
    {
        collect_paths(&trimmed[index..], found);
    }
}

fn starts_like_path(text: &str) -> bool {
    let bytes = text.as_bytes();
    (bytes.len() > 2 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/'))
        || text.starts_with("\\\\")
        || text.starts_with('%')
}

fn extension_end(text: &str) -> Option<usize> {
    let lower = text.to_ascii_lowercase();
    let mut best: Option<usize> = None;
    for ext in [
        ".exe", ".dll", ".ocx", ".bat", ".cmd", ".scr", ".com", ".pif", ".sys", ".drv", ".vxd",
        ".ttf", ".otf", ".chm", ".hlp", ".lnk",
    ] {
        let mut search = 0;
        while let Some(index) = lower[search..].find(ext) {
            let end = search + index + ext.len();
            let boundary = end == text.len()
                || text[end..]
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_whitespace() || ch == ',' || ch == '"');
            if boundary && best.map(|have| end < have).unwrap_or(true) {
                best = Some(end);
            }
            search += index + ext.len();
            if search >= lower.len() {
                break;
            }
        }
    }
    best
}

fn find_later_path(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    for index in 0..bytes.len().saturating_sub(2) {
        if index > 0 && !bytes[index - 1].is_ascii_whitespace() && bytes[index - 1] != b'"' {
            continue;
        }
        if bytes[index].is_ascii_alphabetic()
            && bytes[index + 1] == b':'
            && bytes.get(index + 2) == Some(&b'\\')
        {
            return Some(index);
        }
    }
    None
}

fn push_path(found: &mut Vec<String>, raw: &str) {
    let mut path = raw.trim().trim_matches('"').to_string();
    if let Some((left, _)) = path.rsplit_once(',')
        && (left.contains('\\') || left.contains(':'))
    {
        path = left.to_string();
    }
    path = path.trim().trim_end_matches('\\').to_string();
    // Type libraries are stored as `file.dll\2`: a resource index, not a folder.
    if let Some((left, index)) = path.rsplit_once('\\')
        && !index.is_empty()
        && index.chars().all(|ch| ch.is_ascii_digit())
        && has_extension(left)
    {
        path = left.to_string();
    }
    if path.len() < 3 {
        return;
    }
    let looks_like_path = path.as_bytes().get(1) == Some(&b':')
        || path.starts_with("\\\\")
        || path.contains('%')
        || path.contains('\\');
    if looks_like_path {
        found.push(normalize_fs(&path));
    }
}

fn has_extension(path: &str) -> bool {
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path);
    name.rsplit_once('.').is_some_and(|(stem, ext)| {
        !stem.is_empty()
            && (1..=4).contains(&ext.len())
            && ext.chars().all(|ch| ch.is_ascii_alphanumeric())
    })
}

fn dedup_paths(paths: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for path in paths {
        if !out
            .iter()
            .any(|have: &String| have.eq_ignore_ascii_case(&path))
        {
            out.push(path);
        }
    }
    out
}

pub fn bare_name_present(fs: &dyn FileView, name: &str) -> bool {
    if name.contains('\\')
        || name.contains('/')
        || name.contains('%')
        || name.len() > 2 && name.as_bytes()[1] == b':'
    {
        return file_present(fs, name);
    }
    let root = system_root(fs);
    let mut dirs = vec![
        root.clone(),
        format!("{root}\\System32"),
        format!("{root}\\SysWOW64"),
    ];
    for var in [
        "ProgramFiles",
        "ProgramFiles(x86)",
        "CommonProgramFiles",
        "CommonProgramFiles(x86)",
        "LOCALAPPDATA",
        "APPDATA",
        "ProgramData",
    ] {
        if let Some(dir) = lookup_var(fs, var) {
            dirs.push(dir.clone());
            dirs.push(format!("{dir}\\Programs"));
        }
    }
    if let Some(path_var) = lookup_var(fs, "PATH") {
        for dir in path_var.split(';') {
            if !dir.trim().is_empty() {
                dirs.push(dir.trim().to_string());
            }
        }
    }
    dirs.iter()
        .any(|dir| file_present(fs, &format!("{dir}\\{name}")))
}

pub fn is_protected_key(path: &str) -> bool {
    let lower = canonical_path(path).to_ascii_lowercase();
    if lower.contains("\\services\\vxd\\") || lower.contains("\\firewallpolicy\\firewallrules") {
        return false;
    }
    const BLOCKS: &[&str] = &[
        "\\winlogon",
        "\\currentcontrolset\\services\\",
        "\\control\\session manager",
        "\\component based servicing",
        "\\windows\\currentversion\\sidebyside",
        "\\microsoft\\cryptography",
        "\\userchoice",
        "\\image file execution options",
        "\\control\\safeboot",
        "\\control\\class\\",
        "\\currentversion\\explorer\\clsid",
        "\\currentversion\\installer\\userdata",
        "\\currentversion\\appx",
        "\\currentversion\\appmodel",
    ];
    BLOCKS.iter().any(|block| lower.contains(block))
}

pub fn key_delete_allowed(path: &str) -> bool {
    if is_protected_key(path) {
        return false;
    }
    let lower = canonical_path(path).to_ascii_lowercase();
    let markers = [
        "\\app paths\\",
        "\\uninstall\\",
        "\\services\\vxd\\",
        "\\clsid\\",
        "\\contextmenuhandlers\\",
        "\\dragdrophandlers\\",
        "\\copyhookhandlers\\",
        "\\propertysheethandlers\\",
        "\\shelliconoverlayidentifiers\\",
        "\\browser helper objects\\",
        "\\internet explorer\\extensions\\",
        "\\arpcache\\",
        "\\startmenuinternet\\",
        "\\namespace\\",
        "\\shellserviceobjects\\",
        "\\autoplayhandlers\\handlers\\",
    ];
    markers.iter().any(|marker| {
        if let Some(index) = lower.find(marker) {
            let after = &lower[index + marker.len()..];
            !after.is_empty() && !after.contains('\\')
        } else {
            false
        }
    })
}

/// Machine-wide keys and shared folders need an elevated process to change.
pub fn needs_admin(target: &str) -> bool {
    let lower = canonical_path(target).to_ascii_lowercase();
    lower.starts_with("hkey_local_machine")
        || lower.starts_with("hkey_classes_root")
        || lower.starts_with("hkey_users")
        || lower.contains("\\programdata\\")
        || lower.contains("\\users\\public\\")
}

pub fn file_delete_allowed(path: &str) -> bool {
    let lower = normalize_fs(path).to_ascii_lowercase();
    if lower.ends_with("\\desktop.ini") {
        return false;
    }
    lower.contains("\\temp\\")
        || lower.contains("\\start menu\\programs\\")
        || lower.contains("\\desktop\\")
}

/// Shredder staging gate. Only absolute local files and folders outside
/// the Windows, program, and app-data folders may shred. Errors name the
/// rule that fired and are absolute: no caller may override a refusal.
pub fn shred_allowed(fs: &dyn crate::fs::FileView, path: &str) -> Result<(), String> {
    use crate::fs::ItemKind;
    let clean = normalize_fs(path);
    let bytes = clean.as_bytes();
    let absolute = bytes.len() > 2 && bytes[1] == b':' && bytes[2] == b'\\';
    if !absolute || clean.contains("..") {
        return Err(format!("{path} is not an absolute local path"));
    }
    if clean.len() == 3 {
        return Err("a drive root cannot be shredded".to_string());
    }
    match fs.kind_of(&clean) {
        ItemKind::File | ItemKind::Dir => {}
        ItemKind::Other => {
            if !fs.exists(&clean) {
                return Err(format!("{path} does not exist"));
            }
            return Err(format!("{path} is a link; links are never followed"));
        }
    }
    if fs.is_hidden_system(&clean) {
        return Err(format!("{path} is a hidden system file"));
    }
    let lower = clean.to_ascii_lowercase();
    let under = |root: &str| {
        let root = normalize_fs(root).to_ascii_lowercase();
        lower == root || lower.starts_with(&(root + "\\"))
    };
    if under(&system_root(fs)) {
        return Err(format!("{path} is inside the Windows folder"));
    }
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramData"] {
        if let Some(dir) = fs.var(var)
            && !dir.is_empty()
            && under(&dir)
        {
            return Err(format!("{path} is inside a program folder"));
        }
    }
    if under(crate::DATA_DIR) {
        return Err(format!("{path} is inside the app data folder"));
    }
    Ok(())
}

pub fn looks_like_stored_path(text: &str) -> bool {
    let text = text.trim().trim_matches('"');
    let text = text.strip_prefix('@').unwrap_or(text);
    if text.len() < 4 || text.len() > 520 {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("http:") || lower.starts_with("https:") || lower.starts_with("mailto:") {
        return false;
    }
    let drive = text.as_bytes().get(1) == Some(&b':');
    let unc = text.starts_with("\\\\");
    let env = text.contains('%') && (text.contains('\\') || text.contains('/'));
    drive || unc || env
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemoryFs;

    #[test]
    fn mirrors_hklm_software_into_wow64() {
        let mirror = wow_mirror(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run").unwrap();
        assert_eq!(
            mirror,
            r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
        );
        assert!(wow_mirror(&mirror).is_none());
    }

    #[test]
    fn splits_quoted_commands_and_rundll32() {
        let paths = paths_in_command(r#""C:\Program Files\Old\app.exe" --flag"#);
        assert_eq!(paths, vec![r"C:\Program Files\Old\app.exe"]);
        let dll = paths_in_command(r#"rundll32.exe "C:\Missing\hook.dll",Entry"#);
        assert_eq!(dll, vec![r"C:\Missing\hook.dll"]);
        let icon = paths_in_command(r"C:\Apps\tool.exe,0");
        assert_eq!(icon, vec![r"C:\Apps\tool.exe"]);
        let directory = paths_in_command(r"C:\Program Files\Keep");
        assert_eq!(directory, vec![r"C:\Program Files\Keep"]);
    }

    #[test]
    fn strips_typelib_resource_index_and_indirect_prefix() {
        assert_eq!(
            paths_in_command(r"C:\Program Files (x86)\Google\updater.exe\6"),
            vec![r"C:\Program Files (x86)\Google\updater.exe"]
        );
        assert_eq!(
            paths_in_command(r"@C:\WINDOWS\System32\msrating.dll,3"),
            vec![r"C:\WINDOWS\System32\msrating.dll"]
        );
        assert!(looks_like_stored_path(
            r"@C:\WINDOWS\System32\msrating.dll,3"
        ));
        assert_eq!(paths_in_command(r"C:\Data\2024\5"), vec![r"C:\Data\2024\5"]);
    }

    #[test]
    fn unresolved_variables_and_x86_program_files_count_as_present() {
        let mut fs = MemoryFs::new();
        fs.set_var("ProgramFiles", r"C:\Program Files");
        fs.set_var("ProgramFiles(x86)", r"C:\Program Files (x86)");
        fs.set_var("CommonProgramFiles", r"C:\Program Files\Common Files");
        fs.set_var(
            "CommonProgramFiles(x86)",
            r"C:\Program Files (x86)\Common Files",
        );
        fs.add_file(r"C:\Program Files (x86)\Common Files\Microsoft Shared\DAO\dao360.dll");
        assert!(file_present(
            &fs,
            r"%CommonProgramFiles%\Microsoft Shared\DAO\dao360.dll"
        ));
        assert!(file_present(&fs, r"%NoSuchVariable%\tool.exe"));
        assert!(!file_present(
            &fs,
            r"%CommonProgramFiles%\Microsoft Shared\DAO\gone.dll"
        ));
    }

    #[test]
    fn system32_and_syswow64_count_as_the_same_file() {
        let mut fs = MemoryFs::new();
        fs.set_var("SystemRoot", r"C:\Windows");
        fs.add_file(r"C:\Windows\SysWOW64\comctl32.dll");
        assert!(file_present(&fs, r"C:\Windows\System32\comctl32.dll"));
    }

    #[test]
    fn protects_winlogon_and_allows_an_app_paths_child() {
        assert!(is_protected_key(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        ));
        assert!(key_delete_allowed(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\gone.exe"
        ));
        assert!(key_delete_allowed(
            r"HKCU\Software\Classes\*\shellex\ContextMenuHandlers\Old"
        ));
        assert!(!key_delete_allowed(
            r"HKCU\Software\Classes\*\shellex\ContextMenuHandlers"
        ));
        assert!(!key_delete_allowed(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
        ));
    }
}
