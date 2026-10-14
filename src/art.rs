//! Hive Mend's artwork, drawn in code: Celtic and Scottish symbols for each
//! tool, rendered with anti-aliasing at whatever pixel size the window needs.
//! Nothing is loaded from disk, so the exe carries its own art and it stays
//! sharp at every display scale.
//!
//! Shapes are described in a 100 x 100 design space (y down) and rasterized
//! with 4 x 4 supersampling. Knotwork is drawn as one ribbon whose crossings
//! alternate over and under along the curve, the way Celtic interlace is.

use std::f32::consts::PI;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Icon {
    Logo,
    Scan,
    Optimize,
    Monitor,
    Privacy,
    Shredder,
    Restore,
    Settings,
    About,
    Tools,
    /// Home-page status: the last scan found nothing.
    StatusOk,
    /// Home-page status: the last scan found stale entries.
    StatusWarn,
    /// Home-page status: no scan yet.
    StatusUnknown,
    /// The TUIGSE LLC emblem, the publisher's mark (an embedded image, not
    /// drawn in code).
    Tuigse,
}

impl Icon {
    pub const ALL: [Icon; 14] = [
        Icon::Logo,
        Icon::Scan,
        Icon::Optimize,
        Icon::Monitor,
        Icon::Privacy,
        Icon::Shredder,
        Icon::Restore,
        Icon::Settings,
        Icon::About,
        Icon::Tools,
        Icon::StatusOk,
        Icon::StatusWarn,
        Icon::StatusUnknown,
        Icon::Tuigse,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Icon::Logo => "logo",
            Icon::Scan => "scan",
            Icon::Optimize => "optimize",
            Icon::Monitor => "monitor",
            Icon::Privacy => "privacy",
            Icon::Shredder => "shredder",
            Icon::Restore => "restore",
            Icon::Settings => "settings",
            Icon::About => "about",
            Icon::Tools => "tools",
            Icon::StatusOk => "status-ok",
            Icon::StatusWarn => "status-warn",
            Icon::StatusUnknown => "status-unknown",
            Icon::Tuigse => "tuigse",
        }
    }
}

/// Render `icon` at `size` x `size` pixels as straight (not premultiplied)
/// RGBA, rows top to bottom.
pub fn render_rgba(icon: Icon, size: usize) -> Vec<u8> {
    let canvas = draw(icon, size);
    let mut out = Vec::with_capacity(size * size * 4);
    for px in &canvas.px {
        let a = px[3];
        let un = |c: f32| {
            if a > 0.0 {
                (c / a * 255.0).round().clamp(0.0, 255.0) as u8
            } else {
                0
            }
        };
        out.extend([un(px[0]), un(px[1]), un(px[2]), (a * 255.0).round() as u8]);
    }
    out
}

/// Render `icon` as premultiplied BGRA rows top to bottom: the layout a
/// 32-bit top-down DIB section expects for `AlphaBlend`.
pub fn render_bgra_premultiplied(icon: Icon, size: usize) -> Vec<u8> {
    let canvas = draw(icon, size);
    let mut out = Vec::with_capacity(size * size * 4);
    for px in &canvas.px {
        let byte = |c: f32| (c * 255.0).round().clamp(0.0, 255.0) as u8;
        out.extend([byte(px[2]), byte(px[1]), byte(px[0]), byte(px[3])]);
    }
    out
}

// ---- palette -------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Rgba(f32, f32, f32, f32);

const fn rgb(r: u8, g: u8, b: u8) -> Rgba {
    Rgba(r as f32 / 255.0, g as f32 / 255.0, b as f32 / 255.0, 1.0)
}

fn with_alpha(c: Rgba, a: f32) -> Rgba {
    Rgba(c.0, c.1, c.2, a)
}

fn mix(a: Rgba, b: Rgba, t: f32) -> Rgba {
    let t = t.clamp(0.0, 1.0);
    Rgba(
        a.0 + (b.0 - a.0) * t,
        a.1 + (b.1 - a.1) * t,
        a.2 + (b.2 - a.2) * t,
        a.3 + (b.3 - a.3) * t,
    )
}

const INK: Rgba = rgb(28, 46, 34);
const GREEN_DARK: Rgba = rgb(22, 86, 48);
const GREEN: Rgba = rgb(38, 130, 70);
const GREEN_LIGHT: Rgba = rgb(132, 196, 148);
const GOLD_LIGHT: Rgba = rgb(246, 214, 120);
const GOLD: Rgba = rgb(204, 160, 52);
const GOLD_DARK: Rgba = rgb(128, 92, 24);
const STRAW_LIGHT: Rgba = rgb(240, 202, 116);
const STRAW: Rgba = rgb(196, 144, 58);
const STRAW_DARK: Rgba = rgb(118, 78, 28);
const SILVER_LIGHT: Rgba = rgb(244, 246, 248);
const SILVER: Rgba = rgb(170, 178, 188);
const SILVER_DARK: Rgba = rgb(92, 100, 112);
const PAPER: Rgba = rgb(252, 250, 242);
const HILT: Rgba = rgb(40, 34, 32);
const HEATHER: Rgba = rgb(128, 70, 150);
const HEATHER_LIGHT: Rgba = rgb(186, 128, 204);
const SHADOW: Rgba = Rgba(0.0, 0.0, 0.0, 0.16);

// ---- rasterizer ----------------------------------------------------------

type P = (f32, f32);
/// One bit per sample of a pixel's 4 x 4 grid.
type Mask = Vec<u16>;
const SS: usize = 4;

struct Canvas {
    n: usize,
    /// Pixels per design unit.
    k: f32,
    /// Premultiplied RGBA, 0..1.
    px: Vec<[f32; 4]>,
}

impl Canvas {
    fn new(n: usize) -> Self {
        Self {
            n,
            k: n as f32 / 100.0,
            px: vec![[0.0; 4]; n * n],
        }
    }

    fn empty(&self) -> Mask {
        vec![0; self.n * self.n]
    }

    /// Set the bits of every sample inside the design-space box for which
    /// `inside` holds.
    fn fill_where(&self, mask: &mut Mask, lo: P, hi: P, inside: impl Fn(P) -> bool) {
        let n = self.n as isize;
        let x0 = ((lo.0 * self.k).floor() as isize).clamp(0, n);
        let y0 = ((lo.1 * self.k).floor() as isize).clamp(0, n);
        let x1 = ((hi.0 * self.k).ceil() as isize + 1).clamp(0, n);
        let y1 = ((hi.1 * self.k).ceil() as isize + 1).clamp(0, n);
        for y in y0..y1 {
            for x in x0..x1 {
                let mut bits = 0u16;
                for s in 0..SS * SS {
                    let sx = (s % SS) as f32 + 0.5;
                    let sy = (s / SS) as f32 + 0.5;
                    let p = (
                        (x as f32 + sx / SS as f32) / self.k,
                        (y as f32 + sy / SS as f32) / self.k,
                    );
                    if inside(p) {
                        bits |= 1 << s;
                    }
                }
                mask[(y * n + x) as usize] |= bits;
            }
        }
    }

    fn circle(&self, c: P, r: f32) -> Mask {
        self.ellipse(c, r, r)
    }

    fn ellipse(&self, c: P, rx: f32, ry: f32) -> Mask {
        let mut m = self.empty();
        self.fill_where(&mut m, (c.0 - rx, c.1 - ry), (c.0 + rx, c.1 + ry), |p| {
            let dx = (p.0 - c.0) / rx;
            let dy = (p.1 - c.1) / ry;
            dx * dx + dy * dy <= 1.0
        });
        m
    }

    /// Even-odd fill of a closed polygon.
    fn polygon(&self, pts: &[P]) -> Mask {
        let mut m = self.empty();
        let (lo, hi) = bounds(pts, 0.0);
        self.fill_where(&mut m, lo, hi, |p| inside_polygon(pts, p));
        m
    }

    /// A round-capped, round-joined stroke along `pts`.
    fn stroke(&self, pts: &[P], width: f32, closed: bool) -> Mask {
        let mut m = self.empty();
        let hw = width / 2.0;
        let count = if closed { pts.len() } else { pts.len() - 1 };
        for i in 0..count {
            let a = pts[i];
            let b = pts[(i + 1) % pts.len()];
            let lo = (a.0.min(b.0) - hw, a.1.min(b.1) - hw);
            let hi = (a.0.max(b.0) + hw, a.1.max(b.1) + hw);
            self.fill_where(&mut m, lo, hi, |p| seg_dist(p, a, b) <= hw);
        }
        m
    }

    fn paint(&mut self, m: &Mask, c: Rgba) {
        self.paint_with(m, |_| c);
    }

    /// Composite `color(p)` (p is the pixel centre in design units) over the
    /// canvas wherever `m` covers, weighted by coverage.
    fn paint_with(&mut self, m: &Mask, color: impl Fn(P) -> Rgba) {
        for (i, bits) in m.iter().enumerate() {
            if *bits == 0 {
                continue;
            }
            let cover = bits.count_ones() as f32 / (SS * SS) as f32;
            let p = (
                ((i % self.n) as f32 + 0.5) / self.k,
                ((i / self.n) as f32 + 0.5) / self.k,
            );
            let c = color(p);
            let a = c.3 * cover;
            let px = &mut self.px[i];
            px[0] = c.0 * a + px[0] * (1.0 - a);
            px[1] = c.1 * a + px[1] * (1.0 - a);
            px[2] = c.2 * a + px[2] * (1.0 - a);
            px[3] = a + px[3] * (1.0 - a);
        }
    }

    /// A ribbon with a dark edge: edge stroke, then the fill stroke.
    fn ribbon(&mut self, pts: &[P], width: f32, edge: f32, fill: Rgba, line: Rgba, closed: bool) {
        let outer = self.stroke(pts, width + 2.0 * edge, closed);
        self.paint(&outer, line);
        let inner = self.stroke(pts, width, closed);
        self.paint_with(&inner, |p| shade(fill, p));
    }

    /// Celtic interlace: draw the closed `curve` as a ribbon, then redraw a
    /// short piece of it at every other crossing along the curve, so the
    /// strand alternates over and under.
    fn knot(&mut self, curve: &[P], width: f32, edge: f32, fill: Rgba, line: Rgba) {
        self.ribbon(curve, width, edge, fill, line, true);
        let path = Path::new(curve, true);
        let mut events: Vec<(f32, usize)> = Vec::new();
        let m = curve.len();
        let mut crossing = 0usize;
        for i in 0..m {
            for j in i + 2..m {
                if i == 0 && j == m - 1 {
                    continue;
                }
                let (a, b) = (curve[i], curve[(i + 1) % m]);
                let (c, d) = (curve[j], curve[(j + 1) % m]);
                if let Some((u, v)) = seg_intersect(a, b, c, d) {
                    events.push((path.cum[i] + u * path.len(i), crossing));
                    events.push((path.cum[j] + v * path.len(j), crossing));
                    crossing += 1;
                }
            }
        }
        events.sort_by(|x, y| x.0.total_cmp(&y.0));
        let reach = width + 2.0 * edge;
        for (k, (s, _)) in events.iter().enumerate() {
            if k % 2 != 0 {
                continue;
            }
            let edge_piece = path.slice(s - reach, s + reach);
            let fill_piece = path.slice(s - reach - edge * 2.0, s + reach + edge * 2.0);
            let outer = self.stroke(&edge_piece, width + 2.0 * edge, false);
            self.paint(&outer, line);
            let inner = self.stroke(&fill_piece, width, false);
            self.paint_with(&inner, |p| shade(fill, p));
        }
    }

    /// Two open strands woven together: wherever they cross, they take turns
    /// lying on top, counted along the first strand.
    fn plait(&mut self, a: &[P], b: &[P], width: f32, edge: f32, fill: Rgba, line: Rgba) {
        self.ribbon(a, width, edge, fill, line, false);
        self.ribbon(b, width, edge, fill, line, false);
        let pa = Path::new(a, false);
        let pb = Path::new(b, false);
        let mut hits: Vec<(f32, f32)> = Vec::new();
        for i in 0..a.len() - 1 {
            for j in 0..b.len() - 1 {
                if let Some((u, v)) = seg_intersect(a[i], a[i + 1], b[j], b[j + 1]) {
                    hits.push((pa.cum[i] + u * pa.len(i), pb.cum[j] + v * pb.len(j)));
                }
            }
        }
        hits.sort_by(|x, y| x.0.total_cmp(&y.0));
        let reach = width + 2.0 * edge;
        for (k, (sa, sb)) in hits.iter().enumerate() {
            let (path, s) = if k % 2 == 0 { (&pa, *sa) } else { (&pb, *sb) };
            let edge_piece = path.slice(s - reach, s + reach);
            let fill_piece = path.slice(s - reach - edge * 2.0, s + reach + edge * 2.0);
            let outer = self.stroke(&edge_piece, width + 2.0 * edge, false);
            self.paint(&outer, line);
            let inner = self.stroke(&fill_piece, width, false);
            self.paint_with(&inner, |p| shade(fill, p));
        }
    }

    fn shadow(&mut self, c: P, rx: f32, ry: f32) {
        let m = self.ellipse(c, rx, ry);
        self.paint_with(&m, |p| {
            let dx = (p.0 - c.0) / rx;
            let dy = (p.1 - c.1) / ry;
            let fade = 1.0 - (dx * dx + dy * dy).sqrt();
            with_alpha(SHADOW, SHADOW.3 * fade.clamp(0.0, 1.0) * 1.6)
        });
    }
}

/// Lighter at the top, darker at the bottom: a soft glossy shading.
fn shade(c: Rgba, p: P) -> Rgba {
    let t = (p.1 / 100.0).clamp(0.0, 1.0);
    let light = mix(c, Rgba(1.0, 1.0, 1.0, c.3), 0.28 * (1.0 - t));
    mix(light, Rgba(0.0, 0.0, 0.0, c.3), 0.18 * t)
}

/// Vertical gradient from `top` (at y0) to `bottom` (at y1).
fn vgrad(top: Rgba, bottom: Rgba, y0: f32, y1: f32) -> impl Fn(P) -> Rgba {
    move |p| mix(top, bottom, (p.1 - y0) / (y1 - y0))
}

fn and(a: &Mask, b: &Mask) -> Mask {
    a.iter().zip(b).map(|(x, y)| x & y).collect()
}

// ---- geometry ------------------------------------------------------------

/// A polyline with arc-length positions, for cutting pieces out by length.
struct Path {
    pts: Vec<P>,
    cum: Vec<f32>,
    total: f32,
    closed: bool,
}

impl Path {
    fn new(pts: &[P], closed: bool) -> Self {
        let mut cum = Vec::with_capacity(pts.len() + 1);
        let mut total = 0.0;
        let count = if closed { pts.len() } else { pts.len() - 1 };
        for i in 0..count {
            cum.push(total);
            total += dist(pts[i], pts[(i + 1) % pts.len()]);
        }
        cum.push(total);
        Self {
            pts: pts.to_vec(),
            cum,
            total,
            closed,
        }
    }

    fn len(&self, i: usize) -> f32 {
        self.cum[i + 1] - self.cum[i]
    }

    fn at(&self, s: f32) -> P {
        let s = if self.closed {
            s.rem_euclid(self.total)
        } else {
            s.clamp(0.0, self.total)
        };
        let i = match self.cum.binary_search_by(|c| c.total_cmp(&s)) {
            Ok(i) => i.min(self.cum.len() - 2),
            Err(i) => i.saturating_sub(1).min(self.cum.len() - 2),
        };
        let a = self.pts[i];
        let b = self.pts[(i + 1) % self.pts.len()];
        let t = if self.len(i) > 0.0 {
            (s - self.cum[i]) / self.len(i)
        } else {
            0.0
        };
        (a.0 + (b.0 - a.0) * t, a.1 + (b.1 - a.1) * t)
    }

    fn slice(&self, s0: f32, s1: f32) -> Vec<P> {
        let steps = 24;
        (0..=steps)
            .map(|k| self.at(s0 + (s1 - s0) * k as f32 / steps as f32))
            .collect()
    }
}

fn dist(a: P, b: P) -> f32 {
    ((a.0 - b.0).powi(2) + (a.1 - b.1).powi(2)).sqrt()
}

fn seg_dist(p: P, a: P, b: P) -> f32 {
    let (dx, dy) = (b.0 - a.0, b.1 - a.1);
    let len2 = dx * dx + dy * dy;
    let t = if len2 > 0.0 {
        (((p.0 - a.0) * dx + (p.1 - a.1) * dy) / len2).clamp(0.0, 1.0)
    } else {
        0.0
    };
    dist(p, (a.0 + dx * t, a.1 + dy * t))
}

/// Proper crossing of segments ab and cd: the fractions along each.
fn seg_intersect(a: P, b: P, c: P, d: P) -> Option<(f32, f32)> {
    let r = (b.0 - a.0, b.1 - a.1);
    let s = (d.0 - c.0, d.1 - c.1);
    let denom = r.0 * s.1 - r.1 * s.0;
    if denom.abs() < 1e-9 {
        return None;
    }
    let q = (c.0 - a.0, c.1 - a.1);
    let u = (q.0 * s.1 - q.1 * s.0) / denom;
    let v = (q.0 * r.1 - q.1 * r.0) / denom;
    ((0.0..1.0).contains(&u) && (0.0..1.0).contains(&v)).then_some((u, v))
}

fn inside_polygon(pts: &[P], p: P) -> bool {
    let mut inside = false;
    let mut j = pts.len() - 1;
    for i in 0..pts.len() {
        let (a, b) = (pts[i], pts[j]);
        if (a.1 > p.1) != (b.1 > p.1) && p.0 < (b.0 - a.0) * (p.1 - a.1) / (b.1 - a.1) + a.0 {
            inside = !inside;
        }
        j = i;
    }
    inside
}

fn bounds(pts: &[P], pad: f32) -> (P, P) {
    let mut lo = (f32::MAX, f32::MAX);
    let mut hi = (f32::MIN, f32::MIN);
    for p in pts {
        lo = (lo.0.min(p.0), lo.1.min(p.1));
        hi = (hi.0.max(p.0), hi.1.max(p.1));
    }
    ((lo.0 - pad, lo.1 - pad), (hi.0 + pad, hi.1 + pad))
}

/// Points on a circle from `a0` to `a1` degrees (0 = right, clockwise on
/// screen).
fn arc(c: P, r: f32, a0: f32, a1: f32, steps: usize) -> Vec<P> {
    (0..=steps)
        .map(|k| {
            let a = (a0 + (a1 - a0) * k as f32 / steps as f32).to_radians();
            (c.0 + r * a.cos(), c.1 + r * a.sin())
        })
        .collect()
}

fn cubic(p0: P, p1: P, p2: P, p3: P, steps: usize) -> Vec<P> {
    (0..=steps)
        .map(|k| {
            let t = k as f32 / steps as f32;
            let u = 1.0 - t;
            let w = [u * u * u, 3.0 * u * u * t, 3.0 * u * t * t, t * t * t];
            (
                w[0] * p0.0 + w[1] * p1.0 + w[2] * p2.0 + w[3] * p3.0,
                w[0] * p0.1 + w[1] * p1.1 + w[2] * p2.1 + w[3] * p3.1,
            )
        })
        .collect()
}

/// A torus-knot projection with `lobes` lobes and `turns` windings, centred
/// on `c` with outer radius `r`. (2, 3) is the trefoil.
fn torus_knot(c: P, r: f32, turns: f32, lobes: f32, steps: usize) -> Vec<P> {
    (0..steps)
        .map(|k| {
            let t = 2.0 * PI * k as f32 / steps as f32;
            let rr = (2.0 + (lobes * t).cos()) / 3.0 * r;
            (c.0 + rr * (turns * t).cos(), c.1 + rr * (turns * t).sin())
        })
        .collect()
}

/// A spiral around `c` from radius `r0` to `r1`, starting at `a0` degrees and
/// turning `turns` times (negative turns run counterclockwise on screen).
fn spiral(c: P, r0: f32, r1: f32, a0: f32, turns: f32, steps: usize) -> Vec<P> {
    (0..=steps)
        .map(|k| {
            let t = k as f32 / steps as f32;
            let a = (a0 + turns * 360.0 * t).to_radians();
            let r = r0 + (r1 - r0) * t;
            (c.0 + r * a.cos(), c.1 + r * a.sin())
        })
        .collect()
}

// ---- the icons -----------------------------------------------------------

fn draw(icon: Icon, size: usize) -> Canvas {
    let mut cv = Canvas::new(size);
    if icon == Icon::Tuigse {
        cv.px = emblem(size);
        return cv;
    }
    match icon {
        Icon::Logo => logo(&mut cv),
        Icon::Scan => scan(&mut cv),
        Icon::Optimize => optimize(&mut cv),
        Icon::Monitor => monitor(&mut cv),
        Icon::Privacy => privacy(&mut cv),
        Icon::Shredder => shredder(&mut cv),
        Icon::Restore => restore(&mut cv),
        Icon::Settings => settings(&mut cv),
        Icon::About => about(&mut cv),
        Icon::Tools => tools(&mut cv),
        Icon::StatusOk => status(&mut cv, Status::Ok),
        Icon::StatusWarn => status(&mut cv, Status::Warn),
        Icon::StatusUnknown => status(&mut cv, Status::Unknown),
        Icon::Tuigse => unreachable!("drawn from the embedded image above"),
    }
    cv
}

/// A straw skep beehive bound with a green Celtic plait.
fn logo(cv: &mut Canvas) {
    cv.shadow((50.0, 90.0), 36.0, 5.0);
    let mut dome = cubic((14.0, 84.0), (10.0, 40.0), (28.0, 12.0), (50.0, 12.0), 40);
    dome.extend(cubic(
        (50.0, 12.0),
        (72.0, 12.0),
        (90.0, 40.0),
        (86.0, 84.0),
        40,
    ));
    let body = cv.polygon(&dome);
    cv.paint_with(&body, vgrad(STRAW_LIGHT, STRAW, 12.0, 84.0));
    // The coils of straw.
    for k in 1..7 {
        let y = 12.0 + k as f32 * 10.5;
        let coil: Vec<P> = (0..=40)
            .map(|i| {
                let x = 6.0 + 88.0 * i as f32 / 40.0;
                (x, y + 3.0 * (PI * (x - 6.0) / 88.0).sin())
            })
            .collect();
        let line = and(&cv.stroke(&coil, 2.2, false), &body);
        cv.paint(&line, STRAW_DARK);
    }
    // A green band with a gold plait across it.
    let band_top: Vec<P> = (0..=40)
        .map(|i| {
            let x = 4.0 + 92.0 * i as f32 / 40.0;
            (x, 55.0 + 3.0 * (PI * (x - 4.0) / 92.0).sin())
        })
        .collect();
    let mut band = band_top.clone();
    band.extend(band_top.iter().rev().map(|p| (p.0, p.1 + 15.0)));
    let band_mask = and(&cv.polygon(&band), &body);
    cv.paint_with(&band_mask, vgrad(GREEN, GREEN_DARK, 55.0, 73.0));
    let wave = |phase: f32| -> Vec<P> {
        (0..=80)
            .map(|i| {
                let x = 16.0 + 68.0 * i as f32 / 80.0;
                let mid = 62.5 + 3.0 * (PI * (x - 4.0) / 92.0).sin();
                (x, mid + 4.0 * (x / 68.0 * 6.0 * PI + phase).sin())
            })
            .collect()
    };
    cv.plait(&wave(0.0), &wave(PI), 2.6, 0.9, GOLD, GOLD_DARK);
    // The entrance.
    let door: Vec<P> = arc((50.0, 84.0), 8.0, 180.0, 360.0, 20);
    let door_mask = cv.polygon(&door);
    cv.paint(&door_mask, rgb(54, 34, 18));
    let outline = cv.stroke(&dome, 2.4, true);
    cv.paint(&outline, STRAW_DARK);
}

/// A magnifying glass over a trefoil knot.
fn scan(cv: &mut Canvas) {
    cv.shadow((52.0, 91.0), 34.0, 5.0);
    let c = (42.0, 42.0);
    let glass = cv.circle(c, 27.0);
    cv.paint_with(&glass, |p| {
        with_alpha(
            mix(rgb(236, 248, 238), GREEN_LIGHT, (p.1 - 15.0) / 54.0),
            0.95,
        )
    });
    let knot = torus_knot((42.0, 43.0), 20.0, 2.0, 3.0, 360);
    cv.knot(&knot, 4.2, 1.0, GOLD, GOLD_DARK);
    // Handle, then the rim over the handle's end.
    let handle = [(62.0, 62.0), (85.0, 85.0)];
    let grip = cv.stroke(&handle, 14.0, false);
    cv.paint(&grip, INK);
    let grip_fill = cv.stroke(&handle, 10.5, false);
    cv.paint_with(
        &grip_fill,
        vgrad(rgb(140, 92, 44), rgb(84, 52, 22), 60.0, 88.0),
    );
    let rim = cv.stroke(&arc(c, 27.0, 0.0, 360.0, 120), 8.0, true);
    cv.paint(&rim, INK);
    let rim_fill = cv.stroke(&arc(c, 27.0, 0.0, 360.0, 120), 5.4, true);
    cv.paint_with(&rim_fill, vgrad(GREEN, GREEN_DARK, 12.0, 72.0));
    // A glint on the glass.
    let glint = cv.stroke(&arc(c, 19.0, 200.0, 250.0, 20), 3.0, false);
    cv.paint(&glint, Rgba(1.0, 1.0, 1.0, 0.8));
}

/// A triskele: three spirals turning from one centre.
fn optimize(cv: &mut Canvas) {
    cv.shadow((50.0, 92.0), 34.0, 5.0);
    let c = (50.0, 50.0);
    let disc = cv.circle(c, 42.0);
    cv.paint_with(&disc, vgrad(GOLD_LIGHT, GOLD, 8.0, 92.0));
    let rim = cv.stroke(&arc(c, 42.0, 0.0, 360.0, 160), 3.0, true);
    cv.paint(&rim, GOLD_DARK);
    for k in 0..3 {
        let toward = -90.0 + 120.0 * k as f32;
        let a = toward.to_radians();
        let hub = (c.0 + 19.0 * a.cos(), c.1 + 19.0 * a.sin());
        // Start where the spiral's outer turn touches the centre, then curl
        // inward around the hub.
        let back = (toward + 180.0).rem_euclid(360.0);
        let mut arm = vec![c];
        arm.extend(spiral(hub, 17.0, 2.5, back, 1.35, 160));
        cv.ribbon(&arm, 5.6, 1.2, GREEN, INK, false);
    }
    let dot = cv.circle(c, 4.0);
    cv.paint(&dot, INK);
}

/// A gold pulse line on a Celtic roundel.
fn monitor(cv: &mut Canvas) {
    cv.shadow((50.0, 92.0), 34.0, 5.0);
    let c = (50.0, 50.0);
    let disc = cv.circle(c, 42.0);
    cv.paint_with(&disc, vgrad(GREEN, GREEN_DARK, 8.0, 92.0));
    for (r, w) in [(42.0, 4.5), (35.0, 1.6)] {
        let ring = cv.stroke(&arc(c, r, 0.0, 360.0, 160), w, true);
        cv.paint(&ring, GOLD);
    }
    let pulse = [
        (16.0, 54.0),
        (32.0, 54.0),
        (38.0, 42.0),
        (46.0, 70.0),
        (54.0, 28.0),
        (61.0, 60.0),
        (66.0, 54.0),
        (84.0, 54.0),
    ];
    cv.ribbon(&pulse, 4.4, 1.1, GOLD_LIGHT, GOLD_DARK, false);
}

/// A shield bearing a four-looped knot.
fn privacy(cv: &mut Canvas) {
    cv.shadow((50.0, 93.0), 30.0, 4.5);
    let mut shield = vec![(16.0, 14.0), (84.0, 14.0)];
    shield.extend(cubic(
        (84.0, 14.0),
        (86.0, 52.0),
        (72.0, 76.0),
        (50.0, 90.0),
        40,
    ));
    shield.extend(cubic(
        (50.0, 90.0),
        (28.0, 76.0),
        (14.0, 52.0),
        (16.0, 14.0),
        40,
    ));
    let face = cv.polygon(&shield);
    cv.paint_with(&face, vgrad(GREEN, GREEN_DARK, 14.0, 90.0));
    let rim = cv.stroke(&shield, 4.5, true);
    cv.paint(&rim, GOLD);
    let knot = torus_knot((50.0, 47.0), 25.0, 3.0, 4.0, 480);
    cv.knot(&knot, 3.4, 0.9, GOLD_LIGHT, GOLD_DARK);
}

/// A sgian-dubh cutting through a sheet that is coming apart in strips.
fn shredder(cv: &mut Canvas) {
    cv.shadow((50.0, 93.0), 34.0, 4.5);
    let edge = rgb(112, 112, 104);
    // The sheet, whole at the top and fanning out in strips below.
    let sheet = [(16.0, 8.0), (66.0, 8.0), (66.0, 50.0), (16.0, 50.0)];
    let sheet_mask = cv.polygon(&sheet);
    cv.paint_with(&sheet_mask, vgrad(PAPER, rgb(236, 232, 220), 8.0, 50.0));
    let sheet_edge = cv.stroke(
        &[(16.0, 50.0), (16.0, 8.0), (66.0, 8.0), (66.0, 50.0)],
        2.0,
        false,
    );
    cv.paint(&sheet_edge, edge);
    for line_y in [18.0, 26.0, 34.0, 42.0] {
        let line = cv.stroke(&[(23.0, line_y), (59.0, line_y)], 2.2, false);
        cv.paint(&line, rgb(176, 186, 180));
    }
    for (k, len) in [34.0f32, 28.0, 38.0, 26.0, 32.0].into_iter().enumerate() {
        let x = 16.0 + k as f32 * 10.0;
        let lean = (k as f32 - 2.0) * 2.4;
        let strip = [
            (x, 50.0),
            (x + 8.0, 50.0),
            (x + 8.0 + lean, 50.0 + len),
            (x + lean, 50.0 + len),
        ];
        let strip_mask = cv.polygon(&strip);
        cv.paint_with(&strip_mask, vgrad(rgb(236, 232, 220), PAPER, 50.0, 88.0));
        let strip_edge = cv.stroke(&strip, 1.6, true);
        cv.paint(&strip_edge, edge);
    }
    // The knife: a broad blade, a gold collar, a dark hilt with a gold band,
    // and a gold pommel.
    let blade = [(92.0, 6.0), (62.0, 50.0), (52.0, 40.0)];
    let blade_mask = cv.polygon(&blade);
    cv.paint_with(&blade_mask, vgrad(SILVER_LIGHT, SILVER, 6.0, 50.0));
    let blade_edge = cv.stroke(&blade, 1.8, true);
    cv.paint(&blade_edge, SILVER_DARK);
    let fuller = cv.stroke(&[(88.0, 11.0), (59.0, 44.0)], 1.4, false);
    cv.paint(&fuller, SILVER_DARK);
    let collar_line = [(51.0, 53.0), (61.0, 43.0)];
    let collar_edge = cv.stroke(&collar_line, 7.5, false);
    cv.paint(&collar_edge, GOLD_DARK);
    let collar = cv.stroke(&collar_line, 5.0, false);
    cv.paint(&collar, GOLD);
    let hilt_line = [(52.0, 52.0), (30.0, 74.0)];
    let hilt_edge = cv.stroke(&hilt_line, 14.0, false);
    cv.paint(&hilt_edge, INK);
    let hilt = cv.stroke(&hilt_line, 11.0, false);
    cv.paint_with(&hilt, vgrad(rgb(84, 72, 66), HILT, 50.0, 76.0));
    let band = cv.stroke(&[(44.5, 59.5), (37.5, 66.5)], 3.2, false);
    let band = and(&band, &cv.stroke(&hilt_line, 11.0, false));
    cv.paint(&band, GOLD);
    let pommel = cv.circle((27.5, 76.5), 8.0);
    cv.paint(&pommel, GOLD_DARK);
    let pommel_face = cv.circle((27.5, 76.5), 6.4);
    cv.paint_with(&pommel_face, vgrad(GOLD_LIGHT, GOLD, 70.0, 83.0));
}

/// A Celtic spiral that turns back on itself into an arrow: undo.
fn restore(cv: &mut Canvas) {
    cv.shadow((50.0, 92.0), 34.0, 5.0);
    let c = (50.0, 50.0);
    let path = spiral(c, 6.0, 34.0, 90.0, -1.55, 220);
    cv.ribbon(&path, 7.0, 1.4, GREEN, INK, false);
    // Arrowhead along the spiral's last direction.
    let n = path.len();
    let tip_base = path[n - 1];
    let prev = path[n - 6];
    let (dx, dy) = (tip_base.0 - prev.0, tip_base.1 - prev.1);
    let len = (dx * dx + dy * dy).sqrt();
    let (ux, uy) = (dx / len, dy / len);
    let (nx, ny) = (-uy, ux);
    let head = [
        (tip_base.0 + ux * 13.0, tip_base.1 + uy * 13.0),
        (tip_base.0 + nx * 10.0, tip_base.1 + ny * 10.0),
        (tip_base.0 - nx * 10.0, tip_base.1 - ny * 10.0),
    ];
    let head_mask = cv.polygon(&head);
    cv.paint(&head_mask, GREEN);
    let head_edge = cv.stroke(&head, 2.0, true);
    cv.paint(&head_edge, INK);
    let dot = cv.circle(c, 5.0);
    cv.paint_with(&dot, vgrad(GOLD_LIGHT, GOLD_DARK, 45.0, 55.0));
}

/// A penannular brooch: the open Celtic ring with its pin.
fn settings(cv: &mut Canvas) {
    cv.shadow((50.0, 92.0), 34.0, 5.0);
    let c = (50.0, 52.0);
    // The pin lies behind the ring at the top and in front at the bottom.
    let pin = [(24.0, 22.0), (78.0, 86.0)];
    let pin_edge = cv.stroke(&pin, 6.0, false);
    cv.paint(&pin_edge, SILVER_DARK);
    let pin_fill = cv.stroke(&pin, 3.8, false);
    cv.paint_with(&pin_fill, vgrad(SILVER_LIGHT, SILVER, 20.0, 88.0));
    let ring = arc(c, 30.0, 115.0, 425.0, 160);
    cv.ribbon(&ring, 9.0, 1.4, GOLD, GOLD_DARK, false);
    // A running knot line along the ring.
    let inlay = arc(c, 30.0, 125.0, 415.0, 160);
    let inlay_mask = cv.stroke(&inlay, 2.2, false);
    cv.paint(&inlay_mask, GOLD_DARK);
    // The terminals at the gap.
    for a in [115.0f32, 425.0] {
        let r = a.to_radians();
        let t = (c.0 + 30.0 * r.cos(), c.1 + 30.0 * r.sin());
        let knob = cv.circle(t, 8.5);
        cv.paint(&knob, GOLD_DARK);
        let face = cv.circle(t, 7.0);
        cv.paint_with(&face, vgrad(GOLD_LIGHT, GOLD, t.1 - 7.0, t.1 + 7.0));
        let stone = cv.circle(t, 3.4);
        cv.paint(&stone, GREEN);
    }
    // The pin's lower half crosses in front of the ring.
    let front = [(58.0, 62.0), (78.0, 86.0)];
    let front_edge = cv.stroke(&front, 6.0, false);
    cv.paint(&front_edge, SILVER_DARK);
    let front_fill = cv.stroke(&front, 3.8, false);
    cv.paint_with(&front_fill, vgrad(SILVER_LIGHT, SILVER, 60.0, 88.0));
    let head = cv.circle((24.0, 22.0), 5.0);
    cv.paint(&head, SILVER_DARK);
    let head_face = cv.circle((24.0, 22.0), 3.8);
    cv.paint(&head_face, SILVER_LIGHT);
}

/// The thistle, Scotland's emblem.
fn about(cv: &mut Canvas) {
    cv.shadow((50.0, 93.0), 26.0, 4.0);
    let stem = cv.stroke(&[(50.0, 92.0), (50.0, 58.0)], 6.0, false);
    cv.paint(&stem, GREEN_DARK);
    for side in [-1.0f32, 1.0] {
        let leaf = [
            (50.0, 84.0),
            (50.0 + side * 8.0, 70.0),
            (50.0 + side * 15.0, 74.0),
            (50.0 + side * 20.0, 62.0),
            (50.0 + side * 27.0, 66.0),
            (50.0 + side * 36.0, 54.0),
            (50.0 + side * 30.0, 64.0),
            (50.0 + side * 34.0, 72.0),
            (50.0 + side * 22.0, 74.0),
            (50.0 + side * 20.0, 82.0),
            (50.0 + side * 8.0, 82.0),
            (50.0, 88.0),
        ];
        let leaf_mask = cv.polygon(&leaf);
        cv.paint_with(&leaf_mask, vgrad(GREEN, GREEN_DARK, 58.0, 86.0));
        let vein = cv.stroke(&[(50.0, 84.0), (50.0 + side * 30.0, 60.0)], 1.4, false);
        cv.paint(&vein, GREEN_LIGHT);
    }
    // The flower: a brush of heather-purple florets.
    for k in 0..15 {
        let a = (-150.0 + 120.0 * k as f32 / 14.0).to_radians();
        let base = (50.0 + 6.0 * a.cos(), 42.0 + 4.0 * a.sin());
        let tip = (50.0 + 24.0 * a.cos(), 40.0 + 30.0 * a.sin());
        let floret = cv.stroke(&[base, tip], 3.4, false);
        let color = if k % 2 == 0 { HEATHER } else { HEATHER_LIGHT };
        cv.paint(&floret, color);
    }
    // The bract: a green bulb with a crosshatch of scales.
    let bulb = cv.ellipse((50.0, 56.0), 15.0, 13.0);
    cv.paint_with(&bulb, vgrad(GREEN, GREEN_DARK, 43.0, 69.0));
    for k in -3..=3 {
        let o = k as f32 * 7.0;
        for (a, b) in [
            ((36.0 + o, 44.0), (64.0 + o, 70.0)),
            ((64.0 + o, 44.0), (36.0 + o, 70.0)),
        ] {
            let line = and(&cv.stroke(&[a, b], 1.2, false), &bulb);
            cv.paint(&line, GREEN_LIGHT);
        }
    }
    let rim_pts: Vec<P> = arc((0.0, 0.0), 1.0, 0.0, 360.0, 80)
        .into_iter()
        .map(|p| (50.0 + 15.0 * p.0, 56.0 + 13.0 * p.1))
        .collect();
    let rim = cv.stroke(&rim_pts, 1.4, true);
    cv.paint(&rim, GREEN_DARK);
}

/// An open-ended spanner with a green, gold-banded grip.
fn tools(cv: &mut Canvas) {
    cv.shadow((50.0, 92.0), 32.0, 4.5);
    let head = (66.0, 32.0);
    // The handle runs from the head down to the lower left.
    let handle = [(58.0, 40.0), (22.0, 76.0)];
    cv.ribbon(&handle, 11.0, 1.4, GOLD, GOLD_DARK, false);
    let grip = [(44.0, 54.0), (22.0, 76.0)];
    let grip_edge = cv.stroke(&grip, 13.8, false);
    cv.paint(&grip_edge, INK);
    let grip_fill = cv.stroke(&grip, 11.0, false);
    cv.paint_with(&grip_fill, vgrad(GREEN, GREEN_DARK, 50.0, 80.0));
    for t in [0.3f32, 0.65] {
        let c = (44.0 - 22.0 * t, 54.0 + 22.0 * t);
        let band = cv.stroke(
            &[(c.0 - 4.0, c.1 - 4.0), (c.0 + 4.0, c.1 + 4.0)],
            2.2,
            false,
        );
        cv.paint(&band, GOLD_LIGHT);
    }
    // The open jaw: a thick ring with its mouth to the upper right.
    let jaw = arc(head, 15.0, 0.0 + 30.0, 360.0 - 60.0, 120);
    cv.ribbon(&jaw, 11.0, 1.4, GOLD, GOLD_DARK, false);
    let end = cv.circle((22.0, 76.0), 5.4);
    cv.paint(&end, INK);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Ok,
    Warn,
    Unknown,
}

/// A status badge: a roundel with a check, an exclamation mark, or a
/// question mark.
fn status(cv: &mut Canvas, state: Status) {
    let c = (50.0, 50.0);
    let (top, bottom, rim, mark) = match state {
        Status::Ok => (GREEN, GREEN_DARK, GOLD, rgb(255, 255, 255)),
        Status::Warn => (GOLD_LIGHT, GOLD, GOLD_DARK, INK),
        Status::Unknown => (
            rgb(214, 222, 216),
            rgb(168, 180, 172),
            rgb(132, 146, 138),
            INK,
        ),
    };
    let disc = cv.circle(c, 44.0);
    cv.paint_with(&disc, vgrad(top, bottom, 6.0, 94.0));
    let ring = cv.stroke(&arc(c, 44.0, 0.0, 360.0, 180), 5.0, true);
    cv.paint(&ring, rim);
    let inner = cv.stroke(&arc(c, 36.5, 0.0, 360.0, 180), 1.6, true);
    cv.paint(&inner, with_alpha(rim, 0.8));
    match state {
        Status::Ok => {
            let check = cv.stroke(&[(31.0, 52.0), (45.0, 66.0), (70.0, 36.0)], 10.0, false);
            cv.paint(&check, mark);
        }
        Status::Warn => {
            let bar = cv.stroke(&[(50.0, 26.0), (50.0, 56.0)], 10.0, false);
            cv.paint(&bar, mark);
            let dot = cv.circle((50.0, 71.0), 6.0);
            cv.paint(&dot, mark);
        }
        Status::Unknown => {
            let mut hook = arc((50.0, 38.0), 12.0, 200.0, 420.0, 60);
            hook.push((50.0, 56.0));
            let curve = cv.stroke(&hook, 9.0, false);
            cv.paint(&curve, mark);
            let dot = cv.circle((50.0, 71.0), 5.6);
            cv.paint(&dot, mark);
        }
    }
}

/// One anti-aliased circle `2 * radius` pixels square, opaque BGRA: a `fill`
/// disc inside a `border` ring `border_px` thick, over `behind`. Its four
/// quarters become the corners of a smoothly rounded rectangle.
pub fn corner_sprite(
    radius: usize,
    fill: (u8, u8, u8),
    border: (u8, u8, u8),
    border_px: f32,
    behind: (u8, u8, u8),
) -> Vec<u8> {
    let n = radius * 2;
    let r = radius as f32;
    let mut out = Vec::with_capacity(n * n * 4);
    for y in 0..n {
        for x in 0..n {
            let (mut f, mut b) = (0.0f32, 0.0f32);
            for s in 0..SS * SS {
                let px = x as f32 + ((s % SS) as f32 + 0.5) / SS as f32;
                let py = y as f32 + ((s / SS) as f32 + 0.5) / SS as f32;
                let d = ((px - r).powi(2) + (py - r).powi(2)).sqrt();
                if d <= r - border_px {
                    f += 1.0;
                } else if d <= r {
                    b += 1.0;
                }
            }
            let total = (SS * SS) as f32;
            let (f, b) = (f / total, b / total);
            let o = 1.0 - f - b;
            let blend = |i: usize| {
                let c = |t: (u8, u8, u8)| [t.0, t.1, t.2][i] as f32;
                (c(fill) * f + c(border) * b + c(behind) * o).round() as u8
            };
            out.extend([blend(2), blend(1), blend(0), 255]);
        }
    }
    out
}

/// The TUIGSE LLC emblem: 256 x 256 straight-alpha BGRA, cropped to a
/// circle. Made from TUIGSE's own logo artwork (`tuigse2.jpg`).
const EMBLEM: &[u8] = include_bytes!("../assets/tuigse-emblem-256.bgra");
const EMBLEM_SIZE: usize = 256;

/// The emblem scaled to `size` by area averaging (premultiplied RGBA), so it
/// stays smooth at every display scale.
fn emblem(size: usize) -> Vec<[f32; 4]> {
    let scale = EMBLEM_SIZE as f32 / size as f32;
    let mut out = vec![[0.0f32; 4]; size * size];
    for y in 0..size {
        for x in 0..size {
            let (x0, x1) = (x as f32 * scale, (x + 1) as f32 * scale);
            let (y0, y1) = (y as f32 * scale, (y + 1) as f32 * scale);
            let mut acc = [0.0f32; 4];
            let mut weight = 0.0f32;
            for sy in y0.floor() as usize..(y1.ceil() as usize).min(EMBLEM_SIZE) {
                let wy = (y1.min(sy as f32 + 1.0) - y0.max(sy as f32)).max(0.0);
                for sx in x0.floor() as usize..(x1.ceil() as usize).min(EMBLEM_SIZE) {
                    let wx = (x1.min(sx as f32 + 1.0) - x0.max(sx as f32)).max(0.0);
                    let w = wx * wy;
                    let i = (sy * EMBLEM_SIZE + sx) * 4;
                    let a = EMBLEM[i + 3] as f32 / 255.0;
                    acc[0] += EMBLEM[i + 2] as f32 / 255.0 * a * w;
                    acc[1] += EMBLEM[i + 1] as f32 / 255.0 * a * w;
                    acc[2] += EMBLEM[i] as f32 / 255.0 * a * w;
                    acc[3] += a * w;
                    weight += w;
                }
            }
            if weight > 0.0 {
                out[y * size + x] = acc.map(|v| v / weight);
            }
        }
    }
    out
}

/// Minimal PNG encoder (stored deflate blocks), for previews and tests.
pub fn encode_png(width: usize, height: usize, rgba: &[u8]) -> Vec<u8> {
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for byte in data {
            crc ^= *byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    0xedb8_8320 ^ (crc >> 1)
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }
    fn chunk(out: &mut Vec<u8>, kind: &[u8], data: &[u8]) {
        out.extend((data.len() as u32).to_be_bytes());
        let mut body = kind.to_vec();
        body.extend(data);
        out.extend(&body);
        out.extend(crc32(&body).to_be_bytes());
    }
    let mut raw = Vec::with_capacity(height * (width * 4 + 1));
    for row in rgba.chunks(width * 4) {
        raw.push(0);
        raw.extend(row);
    }
    let mut z = vec![0x78, 0x01];
    let blocks: Vec<&[u8]> = raw.chunks(65_535).collect();
    for (i, block) in blocks.iter().enumerate() {
        z.push((i + 1 == blocks.len()) as u8);
        z.extend((block.len() as u16).to_le_bytes());
        z.extend((!(block.len() as u16)).to_le_bytes());
        z.extend(*block);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for byte in &raw {
        a = (a + *byte as u32) % 65_521;
        b = (b + a) % 65_521;
    }
    z.extend(((b << 16) | a).to_be_bytes());
    let mut out = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
    let mut header = Vec::new();
    header.extend((width as u32).to_be_bytes());
    header.extend((height as u32).to_be_bytes());
    header.extend([8, 6, 0, 0, 0]);
    chunk(&mut out, b"IHDR", &header);
    chunk(&mut out, b"IDAT", &z);
    chunk(&mut out, b"IEND", &[]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_icon_draws_something_inside_its_square() {
        for icon in Icon::ALL {
            let rgba = render_rgba(icon, 48);
            assert_eq!(rgba.len(), 48 * 48 * 4);
            let covered = rgba.chunks(4).filter(|px| px[3] > 0).count();
            assert!(covered > 48 * 48 / 8, "{icon:?} draws almost nothing");
            // The corners stay transparent: icons sit on any background.
            assert_eq!(rgba[3], 0, "{icon:?} top-left corner");
        }
    }

    #[test]
    fn premultiplied_output_never_exceeds_alpha() {
        let bgra = render_bgra_premultiplied(Icon::Scan, 32);
        for px in bgra.chunks(4) {
            assert!(px[0] <= px[3] && px[1] <= px[3] && px[2] <= px[3]);
        }
    }
}
