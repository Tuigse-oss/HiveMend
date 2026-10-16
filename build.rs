//! Embeds `hive-mend.manifest`, the beehive icon, and the version details
//! with the MSVC linker, so no resource compiler or extra crate is needed:
//! the icon is drawn by the same code as the window's artwork (`src/art.rs`)
//! and written straight into a `.res` file, which the linker accepts.

#[allow(dead_code)]
#[path = "src/art.rs"]
mod art;

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=hive-mend.manifest");
    println!("cargo:rerun-if-changed=src/art.rs");
    println!("cargo:rerun-if-changed=assets/tuigse-emblem-256.bgra");
    let windows = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if !(windows && msvc) {
        return;
    }
    let manifest =
        Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("hive-mend.manifest");
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:NO");
    println!(
        "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
        manifest.display()
    );
    let res = Path::new(&std::env::var("OUT_DIR").unwrap()).join("hivemend.res");
    std::fs::write(&res, resources()).expect("write hivemend.res");
    println!("cargo:rustc-link-arg-bins={}", res.display());
}

const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;
const RT_VERSION: u16 = 16;
const ICON_SIZES: [usize; 6] = [16, 24, 32, 48, 64, 256];

/// A `.res` file: the beehive icon group and the version resource.
fn resources() -> Vec<u8> {
    let mut out = Vec::new();
    // Every .res file starts with an empty entry.
    entry(&mut out, 0, 0, 0, &[]);
    let mut group = Vec::new();
    group.extend(0u16.to_le_bytes());
    group.extend(1u16.to_le_bytes());
    group.extend((ICON_SIZES.len() as u16).to_le_bytes());
    for (index, size) in ICON_SIZES.iter().enumerate() {
        let id = index as u16 + 1;
        let image = icon_image(*size);
        let edge = if *size >= 256 { 0 } else { *size as u8 };
        group.extend([edge, edge, 0, 0]);
        group.extend(1u16.to_le_bytes());
        group.extend(32u16.to_le_bytes());
        group.extend((image.len() as u32).to_le_bytes());
        group.extend(id.to_le_bytes());
        entry(&mut out, RT_ICON, id, 0x1010, &image);
    }
    entry(&mut out, RT_GROUP_ICON, 1, 0x1030, &group);
    entry(&mut out, RT_VERSION, 1, 0x0030, &version_info());
    out
}

/// One resource entry with ordinal type and name, padded to a DWORD.
fn entry(out: &mut Vec<u8>, kind: u16, name: u16, flags: u16, data: &[u8]) {
    out.extend((data.len() as u32).to_le_bytes());
    out.extend(32u32.to_le_bytes());
    out.extend([0xff, 0xff]);
    out.extend(kind.to_le_bytes());
    out.extend([0xff, 0xff]);
    out.extend(name.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(flags.to_le_bytes());
    out.extend(if kind == 0 { 0u16 } else { 0x0409u16 }.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// The beehive at `size` pixels: a PNG for 256, a 32-bit DIB otherwise.
fn icon_image(size: usize) -> Vec<u8> {
    let rgba = art::render_rgba(art::Icon::Logo, size);
    if size >= 256 {
        return art::encode_png(size, size, &rgba);
    }
    let mask_row = size.div_ceil(32) * 4;
    let mut out = Vec::new();
    out.extend(40u32.to_le_bytes());
    out.extend((size as i32).to_le_bytes());
    out.extend((size as i32 * 2).to_le_bytes());
    out.extend(1u16.to_le_bytes());
    out.extend(32u16.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(((size * size * 4 + mask_row * size) as u32).to_le_bytes());
    out.extend([0u8; 16]);
    // Pixels bottom-up as BGRA, then an all-zero AND mask (alpha decides).
    for y in (0..size).rev() {
        for x in 0..size {
            let px = &rgba[(y * size + x) * 4..][..4];
            out.extend([px[2], px[1], px[0], px[3]]);
        }
    }
    out.extend(vec![0u8; mask_row * size]);
    out
}

/// `VS_VERSIONINFO`: what file Properties and Task Manager show.
fn version_info() -> Vec<u8> {
    let version = env!("CARGO_PKG_VERSION");
    let parts: Vec<u32> = version
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .chain(std::iter::repeat(0))
        .take(4)
        .collect();
    let ms = (parts[0] << 16) | parts[1];
    let ls = (parts[2] << 16) | parts[3];
    let mut fixed = Vec::new();
    for value in [
        0xfeef_04bdu32,
        0x0001_0000,
        ms,
        ls,
        ms,
        ls,
        0x3f,
        0,
        0x0004_0004,
        1,
        0,
        0,
        0,
    ] {
        fixed.extend(value.to_le_bytes());
    }
    let strings: Vec<Vec<u8>> = [
        ("CompanyName", "TUIGSE LLC"),
        ("FileDescription", "Hivemend"),
        ("FileVersion", version),
        ("InternalName", "Hivemend"),
        ("LegalCopyright", "Copyright 2026 TUIGSE LLC"),
        ("OriginalFilename", "Hivemend.exe"),
        ("ProductName", "Hivemend"),
        ("ProductVersion", version),
    ]
    .iter()
    .map(|(key, value)| {
        let text = utf16z(value);
        node(key, &text, (text.len() / 2) as u16, true, &[])
    })
    .collect();
    let table = node("040904B0", &[], 0, true, &strings);
    let string_info = node("StringFileInfo", &[], 0, true, &[table]);
    let mut translation = Vec::new();
    translation.extend(0x0409u16.to_le_bytes());
    translation.extend(0x04b0u16.to_le_bytes());
    let var = node("Translation", &translation, 4, false, &[]);
    let var_info = node("VarFileInfo", &[], 0, true, &[var]);
    node(
        "VS_VERSION_INFO",
        &fixed,
        fixed.len() as u16,
        false,
        &[string_info, var_info],
    )
}

/// One version-resource block: length, value length, type, key, value, and
/// children, each aligned to 32 bits.
fn node(key: &str, value: &[u8], value_len: u16, text: bool, children: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![0, 0];
    out.extend(value_len.to_le_bytes());
    out.extend((text as u16).to_le_bytes());
    out.extend(utf16z(key));
    pad(&mut out);
    out.extend(value);
    for child in children {
        pad(&mut out);
        out.extend(child);
    }
    let len = out.len() as u16;
    out[..2].copy_from_slice(&len.to_le_bytes());
    out
}

fn pad(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn utf16z(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}
