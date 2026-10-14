//! Render every icon at two sizes onto a preview sheet:
//! `cargo run --example icon_sheet -- out.png`

use hive_mend::art::{Icon, encode_png, render_rgba};

fn main() {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "icons.png".into());
    let (big, small, pad) = (128usize, 48usize, 24usize);
    let cell = big + pad;
    let width = cell * Icon::ALL.len() + pad;
    let height = big + small + pad * 3;
    // Light card background, like the window's action cards.
    let mut sheet: Vec<u8> = [248u8, 250, 248, 255].repeat(width * height);
    let mut place = |icon: Icon, size: usize, x0: usize, y0: usize| {
        let px = render_rgba(icon, size);
        for y in 0..size {
            for x in 0..size {
                let s = &px[(y * size + x) * 4..][..4];
                let d = &mut sheet[((y0 + y) * width + x0 + x) * 4..][..4];
                let a = s[3] as u32;
                for c in 0..3 {
                    d[c] = ((s[c] as u32 * a + d[c] as u32 * (255 - a)) / 255) as u8;
                }
            }
        }
    };
    for (i, icon) in Icon::ALL.iter().enumerate() {
        let x = pad + i * cell;
        place(*icon, big, x, pad);
        place(*icon, small, x + (big - small) / 2, pad * 2 + big);
    }
    std::fs::write(&out, encode_png(width, height, &sheet)).expect("write sheet");
    println!("wrote {out} ({width}x{height})");
}
