use crate::fs::{FileView, ItemKind, KnownDir, is_drive_absolute};

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
    // Split on backslash only. A forward slash is a legal character inside a
    // registry key name (for example a `text/html` content-type key), so
    // treating it as a separator would rename the key and make a backup miss
    // the real child that repair then deletes with its parent.
    let trimmed = path.trim().trim_matches('\\');
    let mut parts: Vec<String> = trimmed
        .split('\\')
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

/// A system folder as the refusal checks must see it: from the Windows APIs
/// on the host, and only when it is a fully qualified drive path.
pub fn known_root(fs: &dyn FileView, dir: KnownDir) -> Option<String> {
    let root = normalize_fs(&fs.known_dir(dir)?);
    let root = root.trim_end_matches('\\').to_string();
    is_drive_absolute(&root).then_some(root)
}

/// Every folder a delete or shred must stay out of, or an error naming the
/// one that could not be located. A missing root refuses the operation
/// instead of silently dropping that protection.
pub fn protected_roots(fs: &dyn FileView) -> Result<Vec<String>, String> {
    KnownDir::PROTECTED
        .iter()
        .map(|dir| {
            known_root(fs, *dir)
                .ok_or_else(|| format!("the {} folder could not be located", dir.label()))
        })
        .collect()
}

/// The Windows folder for locating files during a scan. Refusal checks use
/// [`protected_roots`] or [`under_windows_dir`], which fail closed instead.
pub fn system_root(fs: &dyn FileView) -> String {
    known_root(fs, KnownDir::Windows).unwrap_or_else(|| "C:\\Windows".to_string())
}

pub fn normalize_fs(path: &str) -> String {
    let expanded = path.trim().trim_matches('"');
    let mut out = expanded.replace('/', "\\");
    while out.contains("\\\\") && !out.starts_with("\\\\") {
        out = out.replace("\\\\", "\\");
    }
    out
}

/// True when a path component would make the resolved target differ from its
/// spelling, so a textual refusal check cannot be trusted. Win32 strips a
/// trailing dot or space from each component, and `.`/`..` walk the tree, so
/// `C:\.` and `C:\.\Windows` name the drive root and the Windows folder while
/// reading as something the protected-root prefixes do not match. This is a
/// fail-closed interim guard, not a full reparse/alias resolver.
pub fn has_unsafe_fs_component(path: &str) -> bool {
    let norm = normalize_fs(path);
    let rest = match norm.split_once(":\\") {
        Some((_, rest)) => rest,
        None => norm.strip_prefix("\\\\").unwrap_or(norm.as_str()),
    };
    rest.split('\\')
        .any(|part| part == "." || part == ".." || part.ends_with('.') || part.ends_with(' '))
}

/// True when `path` is inside the Windows folder, or when that folder cannot
/// be located: scanners skip such paths, so an unknown root errs toward
/// leaving things alone.
pub fn under_windows_dir(fs: &dyn FileView, path: &str) -> bool {
    let Some(root) = known_root(fs, KnownDir::Windows) else {
        return true;
    };
    path_under(path, &root)
}

/// Case-insensitive `path == root` or `path` inside `root`, after
/// normalizing separators.
pub fn path_under(path: &str, root: &str) -> bool {
    let root = normalize_fs(root)
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    let path = normalize_fs(path).to_ascii_lowercase();
    !root.is_empty() && (path == root || path.starts_with(&(root + "\\")))
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
    // A trailing `,<index>` is an icon or resource index (`shell32.dll,-57`).
    // Strip only a numeric suffix: a comma can also sit inside a real file
    // name (`Tool,Pro.exe`), and truncating there invents a missing path.
    if let Some((left, index)) = path.rsplit_once(',')
        && (left.contains('\\') || left.contains(':'))
        && is_resource_index(index)
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

/// From the paths pulled out of a single command, the ones whose absence means
/// the command is broken: the program it launches (the first path) and any
/// code file it loads. A data or output argument — a `--log out.txt` path — is
/// not a dependency, so a present program with a missing data argument is not
/// stale and must not be offered for deletion.
pub fn command_dependencies(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .enumerate()
        .filter(|(index, path)| *index == 0 || is_code_file(path))
        .map(|(_, path)| path.clone())
        .collect()
}

/// A file a command executes or loads, by extension: programs, libraries,
/// drivers, scripts. Data and document files are not code.
fn is_code_file(path: &str) -> bool {
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path);
    let lower = name.to_ascii_lowercase();
    const CODE: &[&str] = &[
        ".exe", ".dll", ".ocx", ".sys", ".drv", ".vxd", ".scr", ".com", ".cpl", ".bat", ".cmd",
        ".pif", ".msc",
    ];
    CODE.iter().any(|ext| lower.ends_with(ext))
}

/// A `,<index>` suffix on a command is a resource or icon index, always a
/// (possibly negative) integer. A comma followed by anything else belongs to
/// the file name.
fn is_resource_index(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
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

/// `SYSTEM\<control set>\Services\...` under any control set the service
/// control manager keeps: `CurrentControlSet` and the numbered `ControlSet001`,
/// `ControlSet002`, ... clones. A rules file that names a numbered set would
/// otherwise reach a service the `CurrentControlSet` spelling protects.
fn under_any_services(lower: &str) -> bool {
    lower.contains("\\currentcontrolset\\services\\")
        || lower.split("\\controlset").skip(1).any(|segment| {
            let digits = segment.bytes().take_while(u8::is_ascii_digit).count();
            digits > 0 && segment[digits..].starts_with("\\services\\")
        })
}

pub fn is_protected_key(path: &str) -> bool {
    let lower = canonical_path(path).to_ascii_lowercase();
    if lower.contains("\\services\\vxd\\") || lower.contains("\\firewallpolicy\\firewallrules") {
        return false;
    }
    if under_any_services(&lower) {
        return true;
    }
    const BLOCKS: &[&str] = &[
        "\\winlogon",
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
    if lower.ends_with("\\desktop.ini") || has_unsafe_fs_component(path) {
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
    let clean = normalize_fs(path);
    let bytes = clean.as_bytes();
    let absolute = bytes.len() > 2 && bytes[1] == b':' && bytes[2] == b'\\';
    if !absolute || clean.contains("..") {
        return Err(format!("{path} is not an absolute local path"));
    }
    if clean.len() == 3 {
        return Err("a drive root cannot be shredded".to_string());
    }
    // `C:\.`, trailing dots or spaces, and the like resolve to a different
    // object than they spell, so no textual root check below can be trusted.
    if has_unsafe_fs_component(&clean) {
        return Err(format!("{path} has an ambiguous path component"));
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
    shred_location_allowed(fs, path, &clean)
}

/// The location rules of [`shred_allowed`], applied to `clean`: outside the
/// Windows, Program Files, and ProgramData folders (located by API, refusing
/// when one cannot be found) and outside the app data folder. `shred_file`
/// runs this again on the path Windows reports for the opened file.
pub fn shred_location_allowed(
    fs: &dyn crate::fs::FileView,
    path: &str,
    clean: &str,
) -> Result<(), String> {
    let roots = protected_roots(fs).map_err(|why| format!("{path} refused: {why}"))?;
    if let Some(windows) = roots.first()
        && path_under(clean, windows)
    {
        return Err(format!("{path} is inside the Windows folder"));
    }
    if roots.iter().skip(1).any(|root| path_under(clean, root)) {
        return Err(format!("{path} is inside a program folder"));
    }
    if path_under(clean, crate::DATA_DIR) {
        return Err(format!("{path} is inside the app data folder"));
    }
    Ok(())
}

/// Pin a staged shred target and check the object itself, not just its
/// spelling: [`shred_allowed`] on the path, then the same location rules on
/// the real path Windows reports for the open handle (junctions, links, 8.3
/// names, and SUBST resolved). A file with more than one hard link is refused,
/// since overwriting it would change every other name too. Only then is write
/// or delete access gained, on that same handle.
pub fn pin_for_shred(
    fs: &mut dyn FileView,
    path: &str,
    want: ItemKind,
) -> Result<crate::fs::Pinned, String> {
    shred_allowed(&*fs, path)?;
    let mut pin = fs.pin(path).map_err(|err| format!("{path}: {err}"))?;
    if pin.kind != want {
        return Err(format!("{path} changed since staging"));
    }
    if pin.hidden_system {
        return Err(format!("{path} is a hidden system file"));
    }
    let real = normalize_fs(&pin.real_path);
    if !is_drive_absolute(&real) {
        return Err(format!("{path} resolves to {real}, not a local path"));
    }
    shred_location_allowed(&*fs, path, &real)
        .map_err(|why| format!("{why} (it resolves to {real})"))?;
    if pin.kind == ItemKind::File && pin.links > 1 {
        return Err(format!(
            "{path} has other hard links; shredding it would overwrite them too"
        ));
    }
    let access = if want == ItemKind::File {
        crate::fs::Access::Write
    } else {
        crate::fs::Access::Delete
    };
    fs.pin_acquire(&mut pin, access)
        .map_err(|err| format!("{path}: {err}"))?;
    Ok(pin)
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

    #[test]
    fn canonical_path_keeps_forward_slashes_in_key_names() {
        assert_eq!(
            canonical_path(r"HKCR\MIME\Database\Content Type\text/html"),
            r"HKEY_CLASSES_ROOT\MIME\Database\Content Type\text/html"
        );
    }

    #[test]
    fn command_dependencies_drop_data_arguments_but_keep_code() {
        let with_log = vec![
            r"C:\Apps\runner.exe".to_string(),
            r"C:\Logs\next.log".to_string(),
        ];
        assert_eq!(
            command_dependencies(&with_log),
            vec![r"C:\Apps\runner.exe".to_string()]
        );
        // A loaded library is still a dependency.
        let with_dll = vec![
            r"C:\Apps\host.exe".to_string(),
            r"C:\Apps\plugin.dll".to_string(),
        ];
        assert_eq!(command_dependencies(&with_dll), with_dll);
    }

    #[test]
    fn keeps_a_comma_inside_a_file_name_but_strips_an_icon_index() {
        assert_eq!(
            paths_in_command(r"C:\Apps\Tool,Pro.exe"),
            vec![r"C:\Apps\Tool,Pro.exe"]
        );
        assert_eq!(
            paths_in_command(r"C:\Windows\System32\shell32.dll,-57"),
            vec![r"C:\Windows\System32\shell32.dll"]
        );
    }

    #[test]
    fn protects_services_under_a_numbered_control_set() {
        assert!(is_protected_key(
            r"HKLM\SYSTEM\ControlSet001\Services\Dnscache"
        ));
        assert!(is_protected_key(
            r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache"
        ));
        // VxD cleanup stays allowed under any control set.
        assert!(!is_protected_key(
            r"HKLM\SYSTEM\ControlSet002\Services\VxD\Old"
        ));
    }

    #[test]
    fn flags_dot_and_trailing_dot_components() {
        assert!(has_unsafe_fs_component(r"C:\."));
        assert!(has_unsafe_fs_component(r"C:\.\Windows\System32\x.dll"));
        assert!(has_unsafe_fs_component(r"C:\Apps\bad. \child.txt"));
        assert!(!has_unsafe_fs_component(
            r"C:\Users\Me\AppData\Local\Temp\a.tmp"
        ));
    }

    #[test]
    fn a_missing_protected_root_refuses_instead_of_dropping_the_check() {
        // ProgramData is not defined: the gate must refuse, not skip it.
        let mut fs = MemoryFs::new();
        fs.set_var("SystemRoot", r"C:\Windows");
        fs.set_var("ProgramFiles", r"C:\Program Files");
        fs.set_var("ProgramFiles(x86)", r"C:\Program Files (x86)");
        fs.add_file(r"C:\ProgramData\Vendor\x.dat");
        fs.add_file(r"C:\Docs\a.txt");
        let err = shred_allowed(&fs, r"C:\ProgramData\Vendor\x.dat").unwrap_err();
        assert!(err.contains("could not be located"), "{err}");
        assert!(shred_allowed(&fs, r"C:\Docs\a.txt").is_err());
        fs.set_var("ProgramData", r"C:\ProgramData");
        assert!(shred_allowed(&fs, r"C:\Docs\a.txt").is_ok());
        assert!(shred_allowed(&fs, r"C:\ProgramData\Vendor\x.dat").is_err());
    }

    #[test]
    fn a_relative_or_ambiguous_windows_root_is_not_trusted() {
        // A root that is not a plain drive path cannot anchor a refusal, so
        // scanners treat everything as inside it and leave it alone.
        for root in ["Windows", r"\Windows", r"C:\.\Windows", r"C:\Windows.", ""] {
            let mut fs = MemoryFs::new();
            fs.set_var("SystemRoot", root);
            assert!(known_root(&fs, KnownDir::Windows).is_none(), "{root:?}");
            assert!(under_windows_dir(&fs, r"C:\Docs\a.txt"), "{root:?}");
        }
        let fs = MemoryFs::with_windows_dirs();
        assert!(under_windows_dir(&fs, r"C:\WINDOWS\System32\x.dll"));
        assert!(!under_windows_dir(&fs, r"C:\WindowsApps\x.dll"));
    }

    #[test]
    fn shred_refuses_dot_root_and_dot_traversal() {
        let fs = MemoryFs::new();
        assert!(shred_allowed(&fs, r"C:\.").is_err());
        assert!(shred_allowed(&fs, r"C:\.\Windows\System32\drivers\etc\hosts").is_err());
    }
}
