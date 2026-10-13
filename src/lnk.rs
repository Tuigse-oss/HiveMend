/// Enough of [MS-SHLLINK] to read a shortcut's local target path.
pub fn lnk_target(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 76 || u32::from_le_bytes(bytes[0..4].try_into().ok()?) != 0x4C {
        return None;
    }
    let flags = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
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
    if header_size >= 0x24 && header_size + 4 <= info.len() {
        let unicode_off = u32::from_le_bytes(info[28..32].try_into().ok()?) as usize;
        if unicode_off > 0 && unicode_off < info_size {
            if let Some(text) = read_utf16(&info[unicode_off..info_size]) {
                if !text.is_empty() {
                    return Some(text);
                }
            }
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
    let text = String::from_utf8_lossy(&info[local_off..end])
        .trim()
        .to_string();
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
    Some(String::from_utf16_lossy(&units))
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
}
