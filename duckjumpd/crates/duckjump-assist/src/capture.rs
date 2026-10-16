use duckjump_gfx::{Damage, Framebuffer};
use duckjump_proto::gfx::{Display, Rect};
use tracing::{info, warn};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{self, ConnectionExt, ImageFormat};
use x11rb::rust_connection::RustConnection;

/// Trait abstracting OS-level display capture.
pub trait ScreenCapturer: Send {
    /// Captures the current screen and updates the internal framebuffer.
    /// Returns the list of damage events (areas changed).
    fn capture(&mut self) -> anyhow::Result<Vec<Damage>>;

    /// Returns a reference to the current framebuffer.
    fn framebuffer(&self) -> &Framebuffer;

    /// Generates full initial frame (size + full screen tiles).
    fn initial_frame(&self) -> anyhow::Result<Vec<Display>> {
        duckjump_gfx::full(self.framebuffer())
    }

    /// Generates incremental updates for the damage produced by the last capture.
    fn encode_damage(&self, damage: &[Damage]) -> anyhow::Result<Vec<Display>> {
        duckjump_gfx::encode(damage, self.framebuffer())
    }
}

/// Compares `fb.rgb` with `prev_rgb` in 64x64 blocks, coalesces dirty rects,
/// and returns the changed areas as `Damage::Pixels`.
fn detect_damage(fb: &Framebuffer, prev_rgb: &mut Vec<u8>) -> Vec<Damage> {
    if prev_rgb.len() != fb.rgb.len() {
        *prev_rgb = fb.rgb.clone();
        return vec![Damage::Pixels {
            x: 0,
            y: 0,
            w: fb.width,
            h: fb.height,
        }];
    }

    let mut dirty = duckjump_gfx::Dirty::default();
    let block_size = 64u16;
    let w = fb.width;
    let h = fb.height;

    for by in (0..h).step_by(block_size as usize) {
        let bh = block_size.min(h - by);
        for bx in (0..w).step_by(block_size as usize) {
            let bw = block_size.min(w - bx);
            let mut changed = false;

            for r in 0..bh {
                let y = (by + r) as usize;
                let row_start = (y * w as usize + bx as usize) * 3;
                let row_len = bw as usize * 3;
                if fb.rgb[row_start..row_start + row_len] != prev_rgb[row_start..row_start + row_len] {
                    changed = true;
                    break;
                }
            }

            if changed {
                dirty.add(Rect {
                    x: bx,
                    y: by,
                    w: bw,
                    h: bh,
                });
            }
        }
    }

    let rects = dirty.take();
    if !rects.is_empty() {
        prev_rgb.copy_from_slice(&fb.rgb);
    }

    rects
        .into_iter()
        .map(|r| Damage::Pixels {
            x: r.x,
            y: r.y,
            w: r.w,
            h: r.h,
        })
        .collect()
}

/// Decodes PNG data into `fb.rgb` (resizing `fb` if dimensions differ).
fn decode_png_to_fb(png_bytes: &[u8], fb: &mut Framebuffer) -> anyhow::Result<()> {
    let cursor = std::io::Cursor::new(png_bytes);
    let decoder = png::Decoder::new(cursor);
    let mut reader = decoder.read_info()?;
    let info = reader.info();
    let width = info.width as u16;
    let height = info.height as u16;

    if fb.width != width || fb.height != height {
        fb.resize(width, height);
    }

    let buf_size = reader.output_buffer_size().unwrap_or(width as usize * height as usize * 4);
    let mut buf = vec![0; buf_size];
    let output_info = reader.next_frame(&mut buf)?;
    let raw = &buf[..output_info.buffer_size()];

    match output_info.color_type {
        png::ColorType::Rgb => {
            fb.rgb.copy_from_slice(raw);
        }
        png::ColorType::Rgba => {
            for (i, px) in raw.chunks_exact(4).enumerate() {
                let out = i * 3;
                fb.rgb[out] = px[0];
                fb.rgb[out + 1] = px[1];
                fb.rgb[out + 2] = px[2];
            }
        }
        png::ColorType::Grayscale => {
            for (i, &g) in raw.iter().enumerate() {
                let out = i * 3;
                fb.rgb[out] = g;
                fb.rgb[out + 1] = g;
                fb.rgb[out + 2] = g;
            }
        }
        other => anyhow::bail!("Unsupported PNG color format: {:?}", other),
    }

    Ok(())
}

/// Real X11 screen capturer via `x11rb`.
pub struct X11Capturer {
    conn: RustConnection,
    root: u32,
    pub width: u16,
    pub height: u16,
}

impl X11Capturer {
    pub fn try_new() -> anyhow::Result<Self> {
        let (conn, screen_num) = x11rb::connect(None)
            .map_err(|e| anyhow::anyhow!("Failed to connect to X11 display: {}", e))?;
        let setup = conn.setup();
        let screen = setup
            .roots
            .get(screen_num)
            .ok_or_else(|| anyhow::anyhow!("No X11 root screen at index {}", screen_num))?;
        let root = screen.root;
        let width = screen.width_in_pixels;
        let height = screen.height_in_pixels;

        Ok(Self {
            conn,
            root,
            width,
            height,
        })
    }

    pub fn capture_to_fb(&mut self, fb: &mut Framebuffer) -> anyhow::Result<()> {
        let geom = self.conn.get_geometry(self.root)?.reply()?;
        let width = geom.width;
        let height = geom.height;
        if fb.width != width || fb.height != height {
            fb.resize(width, height);
            self.width = width;
            self.height = height;
        }

        let reply = xproto::get_image(
            &self.conn,
            ImageFormat::Z_PIXMAP,
            self.root,
            0,
            0,
            width,
            height,
            !0,
        )?
        .reply()?;

        let data = &reply.data;
        if data.len() >= width as usize * height as usize * 4 {
            for (i, chunk) in data.chunks_exact(4).take(width as usize * height as usize).enumerate() {
                let out = i * 3;
                fb.rgb[out] = chunk[2];     // R
                fb.rgb[out + 1] = chunk[1]; // G
                fb.rgb[out + 2] = chunk[0]; // B
            }
        } else if data.len() >= width as usize * height as usize * 3 {
            for (i, chunk) in data.chunks_exact(3).take(width as usize * height as usize).enumerate() {
                let out = i * 3;
                fb.rgb[out] = chunk[2];     // R
                fb.rgb[out + 1] = chunk[1]; // G
                fb.rgb[out + 2] = chunk[0]; // B
            }
        } else {
            anyhow::bail!("Unexpected X11 image data length: {}", data.len());
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum WaylandCommandKind {
    Grim,
    GnomeDbus,
    GnomeScreenshot,
    Spectacle,
    Import,
}

/// Real Wayland / Linux CLI screen capturer.
pub struct CommandCapturer {
    kind: WaylandCommandKind,
    tmp_path: std::path::PathBuf,
}

impl CommandCapturer {
    pub fn try_detect() -> Option<Self> {
        let tmp_file = std::env::temp_dir().join(format!("duckjump_capture_{}.png", std::process::id()));
        let tmp_str = tmp_file.to_string_lossy().to_string();

        // 1. Check grim (Sway, Hyprland, wlroots, standard Wayland)
        if std::process::Command::new("grim").arg("-h").output().is_ok() {
            if let Ok(status) = std::process::Command::new("grim")
                .args(["-t", "png", &tmp_str])
                .status()
            {
                if status.success() && tmp_file.exists() {
                    let _ = std::fs::remove_file(&tmp_file);
                    return Some(Self {
                        kind: WaylandCommandKind::Grim,
                        tmp_path: tmp_file,
                    });
                }
            }
        }

        // 2. Check gdbus calling org.gnome.Shell.Screenshot (GNOME on Fedora)
        let gdbus_res = std::process::Command::new("gdbus")
            .args([
                "call",
                "--session",
                "--dest",
                "org.gnome.Shell.Screenshot",
                "--object-path",
                "/org/gnome/Shell/Screenshot",
                "--method",
                "org.gnome.Shell.Screenshot.Screenshot",
                "false",
                "false",
                &tmp_str,
            ])
            .output();
        if let Ok(out) = gdbus_res {
            if out.status.success() && tmp_file.exists() {
                let _ = std::fs::remove_file(&tmp_file);
                return Some(Self {
                    kind: WaylandCommandKind::GnomeDbus,
                    tmp_path: tmp_file,
                });
            }
        }

        // 3. Check gnome-screenshot
        if std::process::Command::new("gnome-screenshot").arg("--version").output().is_ok() {
            if let Ok(status) = std::process::Command::new("gnome-screenshot")
                .args(["-f", &tmp_str])
                .status()
            {
                if status.success() && tmp_file.exists() {
                    let _ = std::fs::remove_file(&tmp_file);
                    return Some(Self {
                        kind: WaylandCommandKind::GnomeScreenshot,
                        tmp_path: tmp_file,
                    });
                }
            }
        }

        // 4. Check spectacle (KDE Plasma)
        if std::process::Command::new("spectacle").arg("-v").output().is_ok() {
            if let Ok(status) = std::process::Command::new("spectacle")
                .args(["-b", "-n", "-o", &tmp_str])
                .status()
            {
                if status.success() && tmp_file.exists() {
                    let _ = std::fs::remove_file(&tmp_file);
                    return Some(Self {
                        kind: WaylandCommandKind::Spectacle,
                        tmp_path: tmp_file,
                    });
                }
            }
        }

        // 5. Check import (ImageMagick)
        if std::process::Command::new("import").arg("-version").output().is_ok() {
            if let Ok(status) = std::process::Command::new("import")
                .args(["-window", "root", &tmp_str])
                .status()
            {
                if status.success() && tmp_file.exists() {
                    let _ = std::fs::remove_file(&tmp_file);
                    return Some(Self {
                        kind: WaylandCommandKind::Import,
                        tmp_path: tmp_file,
                    });
                }
            }
        }

        None
    }

    pub fn capture_to_fb(&self, fb: &mut Framebuffer) -> anyhow::Result<()> {
        let tmp_str = self.tmp_path.to_string_lossy().to_string();
        let status = match self.kind {
            WaylandCommandKind::Grim => {
                std::process::Command::new("grim")
                    .args(["-t", "png", &tmp_str])
                    .status()?
            }
            WaylandCommandKind::GnomeDbus => {
                std::process::Command::new("gdbus")
                    .args([
                        "call",
                        "--session",
                        "--dest",
                        "org.gnome.Shell.Screenshot",
                        "--object-path",
                        "/org/gnome/Shell/Screenshot",
                        "--method",
                        "org.gnome.Shell.Screenshot.Screenshot",
                        "false",
                        "false",
                        &tmp_str,
                    ])
                    .status()?
            }
            WaylandCommandKind::GnomeScreenshot => {
                std::process::Command::new("gnome-screenshot")
                    .args(["-f", &tmp_str])
                    .status()?
            }
            WaylandCommandKind::Spectacle => {
                std::process::Command::new("spectacle")
                    .args(["-b", "-n", "-o", &tmp_str])
                    .status()?
            }
            WaylandCommandKind::Import => {
                std::process::Command::new("import")
                    .args(["-window", "root", &tmp_str])
                    .status()?
            }
        };

        if !status.success() {
            anyhow::bail!("Screen capture command {:?} exited with error: {:?}", self.kind, status);
        }

        let bytes = std::fs::read(&self.tmp_path)?;
        let _ = std::fs::remove_file(&self.tmp_path);
        decode_png_to_fb(&bytes, fb)?;
        Ok(())
    }
}

impl Drop for CommandCapturer {
    fn drop(&mut self) {
        if self.tmp_path.exists() {
            let _ = std::fs::remove_file(&self.tmp_path);
        }
    }
}

/// Real Linux Screen Capturer supporting X11, Wayland compositors, and simulated fallback.
pub enum LinuxScreenCapturer {
    X11 {
        capturer: X11Capturer,
        fb: Framebuffer,
        prev_rgb: Vec<u8>,
    },
    Command {
        capturer: CommandCapturer,
        fb: Framebuffer,
        prev_rgb: Vec<u8>,
    },
    Mock(MockCapturer),
}

impl ScreenCapturer for LinuxScreenCapturer {
    fn capture(&mut self) -> anyhow::Result<Vec<Damage>> {
        match self {
            Self::X11 { capturer, fb, prev_rgb } => {
                capturer.capture_to_fb(fb)?;
                Ok(detect_damage(fb, prev_rgb))
            }
            Self::Command { capturer, fb, prev_rgb } => {
                capturer.capture_to_fb(fb)?;
                Ok(detect_damage(fb, prev_rgb))
            }
            Self::Mock(mock) => mock.capture(),
        }
    }

    fn framebuffer(&self) -> &Framebuffer {
        match self {
            Self::X11 { fb, .. } => fb,
            Self::Command { fb, .. } => fb,
            Self::Mock(mock) => mock.framebuffer(),
        }
    }
}

/// Automatically selects and initializes the best screen capture backend available on the system.
pub fn create_best_capturer(fallback_w: u16, fallback_h: u16) -> Box<dyn ScreenCapturer> {
    let is_wayland = std::env::var("WAYLAND_DISPLAY").is_ok();

    if is_wayland {
        info!("Wayland desktop detected (WAYLAND_DISPLAY is set)");
        if let Some(cmd) = CommandCapturer::try_detect() {
            info!("Successfully initialized Wayland capture backend: {:?}", cmd.kind);
            let mut fb = Framebuffer::new(fallback_w, fallback_h);
            if let Ok(()) = cmd.capture_to_fb(&mut fb) {
                let prev_rgb = fb.rgb.clone();
                return Box::new(LinuxScreenCapturer::Command {
                    capturer: cmd,
                    fb,
                    prev_rgb,
                });
            }
        }
    }

    // Try X11 / XWayland capture
    if std::env::var("DISPLAY").is_ok() {
        match X11Capturer::try_new() {
            Ok(mut x11) => {
                info!("Successfully connected to X11/XWayland display ({}x{})", x11.width, x11.height);
                let mut fb = Framebuffer::new(x11.width, x11.height);
                if let Ok(()) = x11.capture_to_fb(&mut fb) {
                    let prev_rgb = fb.rgb.clone();
                    return Box::new(LinuxScreenCapturer::X11 {
                        capturer: x11,
                        fb,
                        prev_rgb,
                    });
                }
            }
            Err(e) => {
                info!("X11 capture connection failed: {}", e);
            }
        }
    }

    // Secondary attempt at command capture if X11 failed
    if let Some(cmd) = CommandCapturer::try_detect() {
        info!("Using CLI capture backend: {:?}", cmd.kind);
        let mut fb = Framebuffer::new(fallback_w, fallback_h);
        if let Ok(()) = cmd.capture_to_fb(&mut fb) {
            let prev_rgb = fb.rgb.clone();
            return Box::new(LinuxScreenCapturer::Command {
                capturer: cmd,
                fb,
                prev_rgb,
            });
        }
    }

    warn!("No active X11 or Wayland capture backend succeeded; falling back to simulated MockCapturer");
    Box::new(LinuxScreenCapturer::Mock(MockCapturer::new(fallback_w, fallback_h)))
}

/// Simulated desktop environment for headless CI / unit testing.
pub struct MockCapturer {
    fb: Framebuffer,
    frame_counter: u64,
    blink_state: bool,
}

impl MockCapturer {
    pub fn new(width: u16, height: u16) -> Self {
        let mut capturer = Self {
            fb: Framebuffer::new(width, height),
            frame_counter: 0,
            blink_state: false,
        };
        capturer.draw_desktop();
        capturer
    }

    fn draw_rect(&mut self, x: u16, y: u16, w: u16, h: u16, rgb: [u8; 3]) {
        let bgr = [rgb[2], rgb[1], rgb[0]];
        for dy in 0..h as usize {
            for dx in 0..w as usize {
                let px = x as usize + dx;
                let py = y as usize + dy;
                if px < self.fb.width as usize && py < self.fb.height as usize {
                    self.fb.set(px, py, &bgr);
                }
            }
        }
    }

    fn draw_desktop(&mut self) {
        let w = self.fb.width;
        let h = self.fb.height;

        self.draw_rect(0, 0, w, h, [20, 28, 44]);
        self.draw_rect(0, 0, w, 32, [12, 16, 24]);
        self.draw_rect(16, 11, 10, 10, [16, 185, 129]);
        self.draw_rect(34, 12, 280, 8, [148, 163, 184]);
        self.draw_rect(w.saturating_sub(120), 12, 90, 8, [203, 213, 225]);

        let win_x = (w.saturating_sub(760)) / 2;
        let win_y = (h.saturating_sub(440)) / 2;
        let win_w = 760.min(w - 20);
        let win_h = 440.min(h - 50);

        self.draw_rect(win_x.saturating_sub(1), win_y.saturating_sub(1), win_w + 2, win_h + 2, [30, 41, 59]);
        self.draw_rect(win_x, win_y, win_w, 34, [30, 41, 59]);
        self.draw_rect(win_x + 14, win_y + 11, 12, 12, [239, 68, 68]);
        self.draw_rect(win_x + 32, win_y + 11, 12, 12, [245, 158, 11]);
        self.draw_rect(win_x + 50, win_y + 11, 12, 12, [16, 185, 129]);
        self.draw_rect(win_x + 80, win_y + 13, 240, 8, [203, 213, 225]);

        self.draw_rect(win_x, win_y + 34, win_w, win_h - 34, [8, 12, 20]);
        let start_y = win_y + 54;
        self.draw_rect(win_x + 24, start_y, 140, 7, [52, 211, 153]);
        self.draw_rect(win_x + 172, start_y, 360, 7, [241, 245, 249]);

        self.draw_rect(win_x + 24, start_y + 24, 420, 6, [148, 163, 184]);
        self.draw_rect(win_x + 24, start_y + 42, 380, 6, [148, 163, 184]);
        self.draw_rect(win_x + 24, start_y + 60, 460, 6, [148, 163, 184]);
        self.draw_rect(win_x + 24, start_y + 78, 320, 6, [56, 189, 248]);
    }
}

impl ScreenCapturer for MockCapturer {
    fn capture(&mut self) -> anyhow::Result<Vec<Damage>> {
        self.frame_counter += 1;
        let mut damage = Vec::new();

        if self.frame_counter % 4 == 0 {
            self.blink_state = !self.blink_state;

            let w = self.fb.width;
            let h = self.fb.height;
            let win_x = (w.saturating_sub(760)) / 2;
            let win_y = (h.saturating_sub(440)) / 2;
            let cursor_x = win_x + 300;
            let cursor_y = win_y + 168;
            let cur_w = 9u16;
            let cur_h = 14u16;

            let color = if self.blink_state {
                [241, 245, 249]
            } else {
                [8, 12, 20]
            };

            self.draw_rect(cursor_x, cursor_y, cur_w, cur_h, color);
            damage.push(Damage::Pixels { x: cursor_x, y: cursor_y, w: cur_w, h: cur_h });
        }

        Ok(damage)
    }

    fn framebuffer(&self) -> &Framebuffer {
        &self.fb
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_capturer_produces_valid_djtp_display() {
        let capturer = MockCapturer::new(1280, 800);
        let frames = capturer.initial_frame().expect("initial frame must succeed");
        assert!(!frames.is_empty(), "initial frame must not be empty");
        assert!(matches!(frames[0], Display::Size { width: 1280, height: 800 }));
    }

    #[test]
    fn test_damage_detection() {
        let mut fb = Framebuffer::new(128, 128);
        let mut prev = fb.rgb.clone();
        let damage = detect_damage(&fb, &mut prev);
        assert!(damage.is_empty(), "Identical framebuffers should have zero damage");

        fb.set(10, 10, &[255, 0, 0]);
        let damage = detect_damage(&fb, &mut prev);
        assert_eq!(damage.len(), 1, "Modified pixel should produce damage");
    }
}
