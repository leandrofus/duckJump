//! Framebuffer and tile encoding for graphical sessions, shared by duckjumpd
//! (VNC) and the duckjumpd-rdp worker.
//!
//! Changed pixels are cut into tiles of at most TILE x TILE. A one-colour
//! tile becomes FILL; a tile with few colours (text, UI) becomes PNG, which
//! keeps it sharp; anything else (photos, gradients) becomes JPEG.

use std::collections::HashSet;

use bytes::Bytes;
use duckjump_proto::gfx::{Display, Rect, CODEC_JPEG, CODEC_PNG};

/// The remote screen, 3 bytes (R, G, B) per pixel.
pub struct Framebuffer {
    pub width: u16,
    pub height: u16,
    pub rgb: Vec<u8>,
}

impl Framebuffer {
    pub fn new(width: u16, height: u16) -> Self {
        Self { width, height, rgb: vec![0; width as usize * height as usize * 3] }
    }

    pub fn resize(&mut self, width: u16, height: u16) {
        *self = Framebuffer::new(width, height);
    }

    pub fn in_bounds(&self, x: u16, y: u16, w: u16, h: u16) -> bool {
        x as u32 + w as u32 <= self.width as u32 && y as u32 + h as u32 <= self.height as u32
    }

    /// Sets one pixel from B, G, R bytes (RFB's little-endian 32 bpp order).
    #[inline]
    pub fn set(&mut self, x: usize, y: usize, bgr: &[u8]) {
        let i = (y * self.width as usize + x) * 3;
        self.rgb[i] = bgr[2];
        self.rgb[i + 1] = bgr[1];
        self.rgb[i + 2] = bgr[0];
    }

    pub fn copy_rect(&mut self, sx: u16, sy: u16, dx: u16, dy: u16, w: u16, h: u16) {
        let stride = self.width as usize * 3;
        let row = w as usize * 3;
        let mut tmp = vec![0u8; row * h as usize];
        for r in 0..h as usize {
            let s = (sy as usize + r) * stride + sx as usize * 3;
            tmp[r * row..(r + 1) * row].copy_from_slice(&self.rgb[s..s + row]);
        }
        for r in 0..h as usize {
            let d = (dy as usize + r) * stride + dx as usize * 3;
            self.rgb[d..d + row].copy_from_slice(&tmp[r * row..(r + 1) * row]);
        }
    }

    /// The pixels of a region, row by row (R, G, B).
    pub fn region(&self, x: u16, y: u16, w: u16, h: u16) -> Vec<u8> {
        let stride = self.width as usize * 3;
        let row = w as usize * 3;
        let mut out = Vec::with_capacity(row * h as usize);
        for r in 0..h as usize {
            let s = (y as usize + r) * stride + x as usize * 3;
            out.extend_from_slice(&self.rgb[s..s + row]);
        }
        out
    }
}

/// What one screen update changed, in order.
#[derive(Debug, Clone, PartialEq)]
pub enum Damage {
    Pixels { x: u16, y: u16, w: u16, h: u16 },
    Copy { sx: u16, sy: u16, x: u16, y: u16, w: u16, h: u16 },
    Resize { width: u16, height: u16 },
    /// RGBA pixels, hotspot at (hx, hy).
    Cursor { hx: u16, hy: u16, w: u16, h: u16, rgba: Vec<u8> },
}

const TILE: u16 = 128;
const PNG_MAX_COLOURS: usize = 256;
const JPEG_QUALITY: u8 = 80;

pub fn encode(damage: &[Damage], fb: &Framebuffer) -> anyhow::Result<Vec<Display>> {
    let mut out = Vec::new();
    for d in damage {
        match *d {
            Damage::Resize { width, height } => {
                out.push(Display::Size { width, height });
                // The whole screen follows (servers send it), nothing to do here.
            }
            Damage::Copy { sx, sy, x, y, w, h } => out.push(Display::Copy { src_x: sx, src_y: sy, rect: Rect { x, y, w, h } }),
            Damage::Pixels { x, y, w, h } => tiles(fb, x, y, w, h, &mut out)?,
            Damage::Cursor { hx, hy, w, h, ref rgba } => {
                let png = if w == 0 || h == 0 { Bytes::new() } else { encode_png(rgba, w, h, png::ColorType::Rgba)? };
                out.push(Display::Cursor { hot_x: hx, hot_y: hy, w, h, png });
            }
        }
    }
    Ok(out)
}

/// The whole screen (first frame, or after a resize).
pub fn full(fb: &Framebuffer) -> anyhow::Result<Vec<Display>> {
    let mut out = vec![Display::Size { width: fb.width, height: fb.height }];
    tiles(fb, 0, 0, fb.width, fb.height, &mut out)?;
    Ok(out)
}

/// Encodes one region of the framebuffer.
pub fn encode_rect(fb: &Framebuffer, x: u16, y: u16, w: u16, h: u16) -> anyhow::Result<Vec<Display>> {
    let mut out = Vec::new();
    tiles(fb, x, y, w, h, &mut out)?;
    Ok(out)
}

fn tiles(fb: &Framebuffer, x: u16, y: u16, w: u16, h: u16, out: &mut Vec<Display>) -> anyhow::Result<()> {
    let mut ty = 0;
    while ty < h {
        let th = TILE.min(h - ty);
        let mut tx = 0;
        while tx < w {
            let tw = TILE.min(w - tx);
            out.push(tile(fb, Rect { x: x + tx, y: y + ty, w: tw, h: th })?);
            tx += tw;
        }
        ty += th;
    }
    Ok(())
}

fn tile(fb: &Framebuffer, rect: Rect) -> anyhow::Result<Display> {
    let rgb = fb.region(rect.x, rect.y, rect.w, rect.h);
    let mut colours = HashSet::new();
    for p in rgb.chunks_exact(3) {
        colours.insert([p[0], p[1], p[2]]);
        if colours.len() > PNG_MAX_COLOURS {
            break;
        }
    }
    if colours.len() == 1 {
        let c = *colours.iter().next().unwrap();
        return Ok(Display::Fill { rect, rgb: c });
    }
    if colours.len() <= PNG_MAX_COLOURS {
        return Ok(Display::Image { rect, codec: CODEC_PNG, data: encode_png(&rgb, rect.w, rect.h, png::ColorType::Rgb)? });
    }
    let mut jpeg = Vec::new();
    jpeg_encoder::Encoder::new(&mut jpeg, JPEG_QUALITY).encode(&rgb, rect.w, rect.h, jpeg_encoder::ColorType::Rgb)?;
    Ok(Display::Image { rect, codec: CODEC_JPEG, data: jpeg.into() })
}

/// PNG of RGBA pixels (cursors).
pub fn encode_png_rgba(px: &[u8], w: u16, h: u16) -> anyhow::Result<Bytes> {
    encode_png(px, w, h, png::ColorType::Rgba)
}

fn encode_png(px: &[u8], w: u16, h: u16, colour: png::ColorType) -> anyhow::Result<Bytes> {
    let mut buf = Vec::new();
    {
        let mut e = png::Encoder::new(&mut buf, w as u32, h as u32);
        e.set_color(colour);
        e.set_depth(png::BitDepth::Eight);
        e.set_compression(png::Compression::Fast);
        let mut wr = e.write_header()?;
        wr.write_image_data(px)?;
    }
    Ok(buf.into())
}

/// Regions changed since the last frame was sent, for sources that push
/// updates on their own (RDP): while the client is still drawing a frame,
/// updates accumulate here and go out together, with the latest pixels.
#[derive(Debug, Default)]
pub struct Dirty {
    rects: Vec<Rect>,
}

/// Past this many rectangles, they collapse into their bounding box.
const MAX_DIRTY: usize = 48;

impl Dirty {
    pub fn add(&mut self, r: Rect) {
        if r.w == 0 || r.h == 0 {
            return;
        }
        let mut r = r;
        // Merge with anything it touches, repeatedly (merging can create new contacts).
        loop {
            let before = self.rects.len();
            self.rects.retain(|o| {
                if touches(&r, o) {
                    r = union(&r, o);
                    false
                } else {
                    true
                }
            });
            if self.rects.len() == before {
                break;
            }
        }
        self.rects.push(r);
        if self.rects.len() > MAX_DIRTY {
            let all = self.rects.iter().copied().reduce(|a, b| union(&a, &b)).unwrap();
            self.rects = vec![all];
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rects.is_empty()
    }

    pub fn take(&mut self) -> Vec<Rect> {
        std::mem::take(&mut self.rects)
    }
}

fn touches(a: &Rect, b: &Rect) -> bool {
    let (ax2, ay2) = (a.x as u32 + a.w as u32, a.y as u32 + a.h as u32);
    let (bx2, by2) = (b.x as u32 + b.w as u32, b.y as u32 + b.h as u32);
    (a.x as u32) <= bx2 && (b.x as u32) <= ax2 && (a.y as u32) <= by2 && (b.y as u32) <= ay2
}

fn union(a: &Rect, b: &Rect) -> Rect {
    let x = a.x.min(b.x);
    let y = a.y.min(b.y);
    let x2 = (a.x as u32 + a.w as u32).max(b.x as u32 + b.w as u32);
    let y2 = (a.y as u32 + a.h as u32).max(b.y as u32 + b.h as u32);
    Rect { x, y, w: (x2 - x as u32) as u16, h: (y2 - y as u32) as u16 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fb_with(w: u16, h: u16, f: impl Fn(usize, usize) -> [u8; 3]) -> Framebuffer {
        let mut fb = Framebuffer::new(w, h);
        for y in 0..h as usize {
            for x in 0..w as usize {
                let i = (y * w as usize + x) * 3;
                fb.rgb[i..i + 3].copy_from_slice(&f(x, y));
            }
        }
        fb
    }

    #[test]
    fn picks_fill_png_or_jpeg() {
        let solid = fb_with(64, 64, |_, _| [10, 20, 30]);
        assert!(matches!(full(&solid).unwrap()[1], Display::Fill { rgb: [10, 20, 30], .. }));

        let text = fb_with(64, 64, |x, y| if (x / 4 + y / 4) % 2 == 0 { [0, 0, 0] } else { [255, 255, 255] });
        assert!(matches!(full(&text).unwrap()[1], Display::Image { codec: CODEC_PNG, .. }));

        let photo = fb_with(64, 64, |x, y| [(x * 4) as u8, (y * 4) as u8, ((x + y) * 2) as u8]);
        assert!(matches!(full(&photo).unwrap()[1], Display::Image { codec: CODEC_JPEG, .. }));
    }

    #[test]
    fn dirty_merges_touching_rects() {
        let mut d = Dirty::default();
        d.add(Rect { x: 0, y: 0, w: 10, h: 10 });
        d.add(Rect { x: 10, y: 0, w: 10, h: 10 }); // adjacent: merges
        d.add(Rect { x: 100, y: 100, w: 5, h: 5 }); // separate
        let r = d.take();
        assert_eq!(r.len(), 2);
        assert!(r.contains(&Rect { x: 0, y: 0, w: 20, h: 10 }));
        assert!(d.is_empty());
        for i in 0..100u16 {
            d.add(Rect { x: i * 20, y: 0, w: 5, h: 5 });
        }
        assert!(d.take().len() <= MAX_DIRTY);
    }

    #[test]
    fn splits_into_tiles() {
        let fb = fb_with(300, 130, |_, _| [1, 2, 3]);
        let ops = full(&fb).unwrap();
        // SIZE + 3 columns (128,128,44) x 2 rows (128,2)
        assert_eq!(ops.len(), 1 + 6);
        let covered: u32 = ops[1..].iter().map(|o| match o {
            Display::Fill { rect, .. } => rect.w as u32 * rect.h as u32,
            _ => 0,
        }).sum();
        assert_eq!(covered, 300 * 130);
    }
}
