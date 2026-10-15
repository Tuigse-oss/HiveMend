/// Enough of [MS-SHLLINK] to read a shortcut's local target path.
pub fn lnk_target(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 76 || u32::from_le_bytes(bytes[0..4].try_into().ok()?) != 0x4C {
        return None;
    }
    let flags = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
    // ForceNoLinkInfo: Windows ignores the cached path. HasExpString: the
    // target comes from an environment-variable block. Either way the
    // cached local path is not what the shortcut opens, so give no answer
    // rather than one that could make a working shortcut look broken.
    const FORCE_NO_LINK_INFO: u32 = 0x100;
    const HAS_EXP_STRING: u32 = 0x200;
    if flags & (FORCE_NO_LINK_INFO | HAS_EXP_STRING) != 0 {
        return None;
    }
    let mut cursor = 76usize;
    if flags & 0x1 != 0 {
        if cursor + 2 > bytes.len() {
            return None;
        }
        let id_list = u16::from_le_bytes(bytes[cursor..cursor + 2].try_into().ok()?) as usize;
        cursor += 2 + id_list;
    }
    if flags & 0x2 == 0 || cursor + 28 > bytes.len() {
        return None;
    }
    let info = &bytes[cursor..];
    let info_size = u32::from_le_bytes(info[0..4].try_into().ok()?) as usize;
    let header_size = u32::from_le_bytes(info[4..8].try_into().ok()?) as usize;
    let info_flags = u32::from_le_bytes(info[8..12].try_into().ok()?);
    if info_size > info.len() || header_size < 28 || info_flags & 0x1 == 0 {
        return None;
    }
    // The target is the base path plus a common suffix. A non-empty suffix
    // (in either form) is not modelled here, so give no answer.
    let suffix_empty =
        |offset: usize| offset == 0 || info.get(offset).is_none_or(|byte| *byte == 0);
    let suffix_off = u32::from_le_bytes(info[24..28].try_into().ok()?) as usize;
    if suffix_off >= info_size || !suffix_empty(suffix_off) {
        return None;
    }
    if header_size >= 0x24 && 36 <= info.len() {
        let suffix_wide = u32::from_le_bytes(info[32..36].try_into().ok()?) as usize;
        if suffix_wide != 0
            && (suffix_wide + 1 >= info_size
                || info[suffix_wide] != 0
                || info[suffix_wide + 1] != 0)
        {
            return None;
        }
    }
    if header_size >= 0x24 && header_size + 4 <= info.len() {
        let unicode_off = u32::from_le_bytes(info[28..32].try_into().ok()?) as usize;
        if unicode_off > 0
            && unicode_off < info_size
            && let Some(text) = read_utf16(&info[unicode_off..info_size])
            && !text.is_empty()
        {
            return Some(text);
        }
    }
    let local_off = u32::from_le_bytes(info[16..20].try_into().ok()?) as usize;
    if local_off == 0 || local_off >= info_size {
        return None;
    }
    let end = info[local_off..info_size]
        .iter()
        .position(|byte| *byte == 0)
        .map(|index| local_off + index)
        .unwrap_or(info_size);
    let raw = &info[local_off..end];
    // The local base path here is ANSI, in the machine's code page. Without
    // that code page a non-ASCII name cannot be reconstructed, and a lossy
    // UTF-8 decode would invent a different path that then looks missing and
    // gets the working shortcut deleted. Decode ASCII only; a non-ASCII
    // ANSI-only link yields no target, so it is left alone, not repaired.
    if !raw.is_ascii() {
        return None;
    }
    let text = String::from_utf8_lossy(raw).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn read_utf16(bytes: &[u8]) -> Option<String> {
    let mut units = Vec::new();
    let mut index = 0;
    while index + 1 < bytes.len() {
        let unit = u16::from_le_bytes([bytes[index], bytes[index + 1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
        index += 2;
    }
    // Strict: a replacement character would name a different, missing file.
    String::from_utf16(&units).ok()
}

pub fn sample_lnk(target: &str) -> Vec<u8> {
    let path = target.as_bytes();
    let mut info = Vec::new();
    let header_size = 28u32;
    let local_off = header_size;
    let info_size = header_size + path.len() as u32 + 1;
    info.extend(info_size.to_le_bytes());
    info.extend(header_size.to_le_bytes());
    info.extend(1u32.to_le_bytes());
    info.extend(0u32.to_le_bytes());
    info.extend(local_off.to_le_bytes());
    info.extend(0u32.to_le_bytes());
    info.extend(0u32.to_le_bytes());
    info.extend(path);
    info.push(0);

    let mut bytes = vec![0u8; 76];
    bytes[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
    bytes[20..24].copy_from_slice(&0x2u32.to_le_bytes());
    bytes.extend(info);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_local_path_from_a_shortcut() {
        let bytes = sample_lnk(r"C:\Missing\old.exe");
        assert_eq!(lnk_target(&bytes).as_deref(), Some(r"C:\Missing\old.exe"));
    }

    /// Build a shortcut whose ANSI local path is the given raw bytes, so a
    /// non-ASCII (code-page) byte can be injected that a `&str` could not hold.
    fn ansi_lnk(path: &[u8]) -> Vec<u8> {
        let header_size = 28u32;
        let local_off = header_size;
        let info_size = header_size + path.len() as u32 + 1;
        let mut info = Vec::new();
        info.extend(info_size.to_le_bytes());
        info.extend(header_size.to_le_bytes());
        info.extend(1u32.to_le_bytes());
        info.extend(0u32.to_le_bytes());
        info.extend(local_off.to_le_bytes());
        info.extend(0u32.to_le_bytes());
        info.extend(0u32.to_le_bytes());
        info.extend(path);
        info.push(0);
        let mut bytes = vec![0u8; 76];
        bytes[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        bytes[20..24].copy_from_slice(&0x2u32.to_le_bytes());
        bytes.extend(info);
        bytes
    }

    #[test]
    fn shortcuts_that_do_not_use_the_cached_path_give_no_target() {
        for flag in [0x100u32, 0x200] {
            let mut bytes = sample_lnk(r"C:\Missing\old.exe");
            let flags = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) | flag;
            bytes[20..24].copy_from_slice(&flags.to_le_bytes());
            assert_eq!(lnk_target(&bytes), None, "flag {flag:#x}");
        }
        // A non-empty common path suffix is part of the target.
        let mut bytes = ansi_lnk(b"C:\\Share\0sub\\app.exe");
        let info = 76;
        // Point CommonPathSuffixOffset at "sub\app.exe".
        let suffix_at = 28 + b"C:\\Share\0".len() as u32;
        bytes[info + 24..info + 28].copy_from_slice(&suffix_at.to_le_bytes());
        assert_eq!(lnk_target(&bytes), None);
    }

    #[test]
    fn ascii_ansi_path_still_reads() {
        let bytes = ansi_lnk(br"C:\Apps\plain.exe");
        assert_eq!(lnk_target(&bytes).as_deref(), Some(r"C:\Apps\plain.exe"));
    }

    #[test]
    fn non_ascii_ansi_path_is_left_alone() {
        // `café.exe` in Windows-1252: the 0xE9 byte is not valid UTF-8 and has
        // no meaning without the code page, so the target is not guessed.
        let bytes = ansi_lnk(b"C:\\Apps\\caf\xE9.exe");
        assert_eq!(lnk_target(&bytes), None);
    }
}
