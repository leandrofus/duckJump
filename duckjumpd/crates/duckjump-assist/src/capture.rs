use duckjump_gfx::{Damage, Framebuffer};
use duckjump_proto::gfx::Display;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{self, ConnectionExt, ImageFormat};
use x11rb::rust_connection::RustConnection;

/// Trait abstracting OS-level display capture.
pub trait ScreenCapturer: Send {
    /// Human-readable name describing the active capture engine and resolution.
    fn name(&self) -> String;

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

/// Compares `fb.rgb` with `prev_rgb` in 64x64 blocks, coalescing only contiguous horizontal spans.
/// Crucially, disjoint changed areas are NEVER collapsed into a full-screen bounding box.
pub fn detect_damage(fb: &Framebuffer, prev_rgb: &mut Vec<u8>) -> Vec<Damage> {
    if prev_rgb.len() != fb.rgb.len() {
        *prev_rgb = fb.rgb.clone();
        return vec![Damage::Pixels {
            x: 0,
            y: 0,
            w: fb.width,
            h: fb.height,
        }];
    }

    let block_size = 64u16;
    let w = fb.width;
    let h = fb.height;
    let mut damage = Vec::new();

    for by in (0..h).step_by(block_size as usize) {
        let bh = block_size.min(h - by);
        let mut span_start: Option<u16> = None;
        let mut span_end: u16 = 0;

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
                match span_start {
                    Some(_) => {
                        span_end = bx + bw;
                    }
                    None => {
                        span_start = Some(bx);
                        span_end = bx + bw;
                    }
                }
            } else if let Some(start_x) = span_start {
                damage.push(Damage::Pixels {
                    x: start_x,
                    y: by,
                    w: span_end - start_x,
                    h: bh,
                });
                span_start = None;
            }
        }

        if let Some(start_x) = span_start {
            damage.push(Damage::Pixels {
                x: start_x,
                y: by,
                w: span_end - start_x,
                h: bh,
            });
        }
    }

    if !damage.is_empty() {
        prev_rgb.copy_from_slice(&fb.rgb);
    }

    damage
}

/// Decodes uncompressed 24-bit or 32-bit BMP data directly into `fb.rgb`.
/// This operates in sub-millisecond time (<1ms) without any zlib/deflate decompression.
fn decode_bmp_to_fb(bmp_bytes: &[u8], fb: &mut Framebuffer) -> anyhow::Result<()> {
    if bmp_bytes.len() < 54 || &bmp_bytes[0..2] != b"BM" {
        anyhow::bail!("Invalid BMP signature");
    }
    let data_offset = u32::from_le_bytes(bmp_bytes[10..14].try_into()?) as usize;
    let width = i32::from_le_bytes(bmp_bytes[18..22].try_into()?).unsigned_abs() as u16;
    let raw_height = i32::from_le_bytes(bmp_bytes[22..26].try_into()?);
    let top_down = raw_height < 0;
    let height = raw_height.unsigned_abs() as u16;
    let bpp = u16::from_le_bytes(bmp_bytes[28..30].try_into()?);

    if fb.width != width || fb.height != height {
        fb.resize(width, height);
    }

    let bytes_per_pixel = (bpp / 8) as usize;
    if bytes_per_pixel < 3 {
        anyhow::bail!("Unsupported BMP bit depth: {}", bpp);
    }

    let row_size = ((width as usize * bytes_per_pixel + 3) / 4) * 4;
    let pixels = &bmp_bytes[data_offset..];

    for y in 0..height as usize {
        let src_y = if top_down { y } else { height as usize - 1 - y };
        let src_row = src_y * row_size;
        let dst_row = y * width as usize * 3;

        if src_row + width as usize * bytes_per_pixel <= pixels.len() {
            let row = &pixels[src_row..src_row + width as usize * bytes_per_pixel];
            for (x, px) in row.chunks_exact(bytes_per_pixel).enumerate() {
                let out = dst_row + x * 3;
                fb.rgb[out] = px[2];     // R (BMP is BGR)
                fb.rgb[out + 1] = px[1]; // G
                fb.rgb[out + 2] = px[0]; // B
            }
        }
    }
    Ok(())
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

fn decode_image_to_fb(bytes: &[u8], fb: &mut Framebuffer) -> anyhow::Result<()> {
    if bytes.len() >= 2 && &bytes[0..2] == b"BM" {
        return decode_bmp_to_fb(bytes, fb);
    }
    decode_png_to_fb(bytes, fb)
}

/// Real X11 screen capturer via `x11rb`.
pub struct X11Capturer {
    conn: RustConnection,
    root: u32,
    pub depth: u8,
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
        let depth = screen.root_depth;
        let width = screen.width_in_pixels;
        let height = screen.height_in_pixels;

        Ok(Self {
            conn,
            root,
            depth,
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

        // In X11 protocol GetImage, if format is ZPixmap, plane_mask must NOT have bits set beyond depth,
        // otherwise X server returns BadValue. On standard 24-bit TrueColor visual: mask must be 0x00FFFFFF.
        let plane_mask = if self.depth >= 32 {
            !0
        } else if self.depth > 0 {
            (1u32 << self.depth).wrapping_sub(1)
        } else {
            0x00FFFFFF
        };

        let reply = match xproto::get_image(
            &self.conn,
            ImageFormat::Z_PIXMAP,
            self.root,
            0,
            0,
            width,
            height,
            plane_mask,
        ) {
            Ok(cookie) => match cookie.reply() {
                Ok(r) => r,
                Err(_) => {
                    xproto::get_image(
                        &self.conn,
                        ImageFormat::Z_PIXMAP,
                        self.root,
                        0,
                        0,
                        width,
                        height,
                        0x00FFFFFF,
                    )?.reply()?
                }
            },
            Err(_) => {
                xproto::get_image(
                    &self.conn,
                    ImageFormat::Z_PIXMAP,
                    self.root,
                    0,
                    0,
                    width,
                    height,
                    0x00FFFFFF,
                )?.reply()?
            }
        };

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandKind {
    CinnamonScreenshot,
    Spectacle,
    Grim,
    GnomeScreenshot,
    Scrot,
}

fn execute_with_timeout(
    mut cmd: std::process::Command,
    timeout: std::time::Duration,
) -> anyhow::Result<std::process::ExitStatus> {
    let mut child = cmd.spawn()?;
    let start = std::time::Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) => return Ok(status),
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    anyhow::bail!("Screen capture command timed out after {:?}", timeout);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

/// Real Linux CLI screen capturer supporting Cinnamon, KDE, GNOME, Wayland, and X11 tools.
pub struct CommandCapturer {
    kind: CommandKind,
    tmp_path: std::path::PathBuf,
}

impl CommandCapturer {
    pub fn try_detect() -> Option<Self> {
        let pid = std::process::id();
        let tmp_bmp = std::env::temp_dir().join(format!("duckjump_capture_{}.bmp", pid));
        let tmp_png = std::env::temp_dir().join(format!("duckjump_capture_{}.png", pid));
        let tmp_bmp_str = tmp_bmp.to_string_lossy().to_string();
        let tmp_png_str = tmp_png.to_string_lossy().to_string();

        let desktop = std::env::var("XDG_CURRENT_DESKTOP")
            .unwrap_or_default()
            .to_lowercase();

        // Tailor candidate priorities based on the desktop environment in use:
        let candidates = if desktop.contains("cinnamon") {
            vec![
                CommandKind::CinnamonScreenshot,
                CommandKind::Scrot,
                CommandKind::Grim,
                CommandKind::GnomeScreenshot,
                CommandKind::Spectacle,
            ]
        } else if desktop.contains("kde") || desktop.contains("plasma") {
            vec![
                CommandKind::Grim,
                CommandKind::Spectacle,
                CommandKind::Scrot,
                CommandKind::CinnamonScreenshot,
                CommandKind::GnomeScreenshot,
            ]
        } else if desktop.contains("gnome") {
            vec![
                CommandKind::GnomeScreenshot,
                CommandKind::Grim,
                CommandKind::Scrot,
                CommandKind::CinnamonScreenshot,
                CommandKind::Spectacle,
            ]
        } else {
            vec![
                CommandKind::Grim,
                CommandKind::Scrot,
                CommandKind::CinnamonScreenshot,
                CommandKind::GnomeScreenshot,
                CommandKind::Spectacle,
            ]
        };

        for kind in candidates {
            // 1. Try uncompressed BMP first for ultra-fast disk write & sub-millisecond decode
            if Self::probe(kind, &tmp_bmp, &tmp_bmp_str) {
                let _ = std::fs::remove_file(&tmp_bmp);
                return Some(Self {
                    kind,
                    tmp_path: tmp_bmp,
                });
            }
            // 2. Fallback to PNG if BMP is not supported by the tool
            if Self::probe(kind, &tmp_png, &tmp_png_str) {
                let _ = std::fs::remove_file(&tmp_png);
                return Some(Self {
                    kind,
                    tmp_path: tmp_png,
                });
            }
        }

        None
    }

    fn probe(kind: CommandKind, tmp_file: &std::path::Path, tmp_str: &str) -> bool {
        let (cmd, timeout_ms) = match kind {
            CommandKind::Grim => {
                let mut c = std::process::Command::new("grim");
                c.args([tmp_str]);
                (c, 1500)
            }
            CommandKind::Scrot => {
                let mut c = std::process::Command::new("scrot");
                c.args(["-o", tmp_str]);
                (c, 1500)
            }
            CommandKind::CinnamonScreenshot => {
                let mut c = std::process::Command::new("cinnamon-screenshot");
                c.args(["-f", tmp_str]);
                (c, 2000)
            }
            CommandKind::GnomeScreenshot => {
                let mut c = std::process::Command::new("gnome-screenshot");
                c.args(["-f", tmp_str]);
                (c, 2000)
            }
            CommandKind::Spectacle => {
                let mut c = std::process::Command::new("spectacle");
                c.args(["-b", "-n", "-o", tmp_str]);
                // Spectacle is a full Qt/KDE application requiring ~1.5s startup initialization
                (c, 4500)
            }
        };
        let mut cmd = cmd;
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        if let Ok(st) = execute_with_timeout(cmd, std::time::Duration::from_millis(timeout_ms)) {
            if st.success() && tmp_file.exists() {
                if let Ok(meta) = tmp_file.metadata() {
                    return meta.len() > 0;
                }
            }
        }
        false
    }

    pub fn capture_to_fb(&self, fb: &mut Framebuffer) -> anyhow::Result<()> {
        let tmp_str = self.tmp_path.to_string_lossy().to_string();
        let (cmd, timeout_ms) = match self.kind {
            CommandKind::Grim => {
                let mut c = std::process::Command::new("grim");
                c.args([&tmp_str]);
                (c, 2000)
            }
            CommandKind::Scrot => {
                let mut c = std::process::Command::new("scrot");
                c.args(["-o", &tmp_str]);
                (c, 2000)
            }
            CommandKind::CinnamonScreenshot => {
                let mut c = std::process::Command::new("cinnamon-screenshot");
                c.args(["-f", &tmp_str]);
                (c, 3000)
            }
            CommandKind::Spectacle => {
                let mut c = std::process::Command::new("spectacle");
                c.args(["-b", "-n", "-o", &tmp_str]);
                (c, 5000)
            }
            CommandKind::GnomeScreenshot => {
                let mut c = std::process::Command::new("gnome-screenshot");
                c.args(["-f", &tmp_str]);
                (c, 3000)
            }
        };
        let mut cmd = cmd;
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        let status = execute_with_timeout(cmd, std::time::Duration::from_millis(timeout_ms))?;
        if !status.success() {
            anyhow::bail!("Screen capture command {:?} exited with error: {:?}", self.kind, status);
        }

        let bytes = std::fs::read(&self.tmp_path)?;
        let _ = std::fs::remove_file(&self.tmp_path);
        decode_image_to_fb(&bytes, fb)?;
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
    fn name(&self) -> String {
        match self {
            Self::X11 { capturer, fb, .. } => {
                format!("X11 Nativo Directo (GetImage, {}x{}, {} bpp, latencia ~1-3ms)", fb.width, fb.height, capturer.depth)
            }
            Self::Command { capturer, fb, .. } => {
                let fmt_name = if capturer.tmp_path.extension().map(|s| s == "bmp").unwrap_or(false) {
                    "BMP sin compresión (<1ms decode)"
                } else {
                    "PNG"
                };
                format!("CLI Subprocess ({:?}, {}x{}, {})", capturer.kind, fb.width, fb.height, fmt_name)
            }
            Self::Mock(mock) => mock.name(),
        }
    }

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
pub fn create_best_capturer(fallback_w: u16, fallback_h: u16) -> anyhow::Result<Box<dyn ScreenCapturer>> {
    // 1. Try X11 / XWayland capture FIRST whenever DISPLAY is available.
    // X11 direct memory capture takes ~1-3ms, compared to ~250ms for CLI screenshot tools.
    if let Ok(disp) = std::env::var("DISPLAY") {
        match X11Capturer::try_new() {
            Ok(mut x11) => {
                let mut fb = Framebuffer::new(x11.width, x11.height);
                match x11.capture_to_fb(&mut fb) {
                    Ok(()) => {
                        println!("⚡ Captura activa: X11 nativo directo ({}x{}, latencia sub-10ms)", x11.width, x11.height);
                        let prev_rgb = fb.rgb.clone();
                        return Ok(Box::new(LinuxScreenCapturer::X11 {
                            capturer: x11,
                            fb,
                            prev_rgb,
                        }));
                    }
                    Err(e) => {
                        let is_wayland = std::env::var("WAYLAND_DISPLAY").is_ok();
                        if is_wayland {
                            println!("ℹ️ [AVISO] Sesión Wayland activa: Xwayland ({}) no permite lectura directa de ventana raíz.", disp);
                            println!("          Buscando herramienta nativa de escritorio compatible...");
                        } else {
                            println!("⚠️ [AVISO] Conexión X11 activa ({}) pero falló captura GetImage: {:#}", disp, e);
                        }
                    }
                }
            }
            Err(e) => {
                println!("⚠️ [AVISO] X11 no pudo conectar en DISPLAY={}: {:#}", disp, e);
            }
        }
    } else {
        println!("ℹ️ [AVISO] DISPLAY no definido en el entorno (sesión Wayland pura).");
    }

    // 2. Try CLI capture (Grim, Scrot, Cinnamon, GNOME, Spectacle) if X11 was not available
    if let Some(cmd) = CommandCapturer::try_detect() {
        let fmt_name = if cmd.tmp_path.extension().map(|s| s == "bmp").unwrap_or(false) {
            "BMP sin compresión (<1ms decode)"
        } else {
            "PNG"
        };
        println!("📸 Captura activa: Herramienta de escritorio ({:?}, formato {})", cmd.kind, fmt_name);
        let mut fb = Framebuffer::new(fallback_w, fallback_h);
        if let Ok(()) = cmd.capture_to_fb(&mut fb) {
            let prev_rgb = fb.rgb.clone();
            return Ok(Box::new(LinuxScreenCapturer::Command {
                capturer: cmd,
                fb,
                prev_rgb,
            }));
        }
    }

    // Explicit mock simulation ONLY when requested via environment variable for headless testing
    if std::env::var("DUCKJUMP_MOCK_DISPLAY").is_ok() {
        println!("⚠️ Captura activa: Simulación de escritorio (Mock solicitado por DUCKJUMP_MOCK_DISPLAY=1)");
        return Ok(Box::new(LinuxScreenCapturer::Mock(MockCapturer::new(fallback_w, fallback_h))));
    }

    anyhow::bail!(
        "No se pudo inicializar la captura de pantalla real en este equipo.\n\
         • En sesiones Wayland (KDE/GNOME), asegúrese de tener disponible una herramienta de captura instalada (ej. spectacle o grim).\n\
         • Alternativamente, inicie sesión en una sesión X11 (ej. Cinnamon o Plasma X11/Xorg) para captura directa nativa a 60 FPS sin herramientas externas."
    );
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
    fn name(&self) -> String {
        format!("Mock Headless Simulado ({}x{})", self.fb.width, self.fb.height)
    }

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

    #[test]
    fn test_bmp_decoding() {
        // Construct a minimal 2x2 24-bit uncompressed BMP:
        // Header: 14 + 40 = 54 bytes. Each row: 2 px * 3 bytes = 6 bytes -> padded to 8 bytes.
        let mut bmp = vec![0u8; 54 + 16];
        bmp[0] = b'B';
        bmp[1] = b'M';
        let size = 54 + 16u32;
        bmp[2..6].copy_from_slice(&size.to_le_bytes());
        bmp[10..14].copy_from_slice(&54u32.to_le_bytes());
        bmp[14..18].copy_from_slice(&40u32.to_le_bytes());
        bmp[18..22].copy_from_slice(&2i32.to_le_bytes());  // width = 2
        bmp[22..26].copy_from_slice(&(-2i32).to_le_bytes()); // height = -2 (top-down)
        bmp[26..28].copy_from_slice(&1u16.to_le_bytes());  // planes = 1
        bmp[28..30].copy_from_slice(&24u16.to_le_bytes()); // bpp = 24

        // Row 0: pixel (0,0) Red (BGR: 0, 0, 255), pixel (1,0) Green (BGR: 0, 255, 0)
        let row0 = 54;
        bmp[row0] = 0; bmp[row0 + 1] = 0; bmp[row0 + 2] = 255;
        bmp[row0 + 3] = 0; bmp[row0 + 4] = 255; bmp[row0 + 5] = 0;

        let mut fb = Framebuffer::new(1, 1);
        decode_bmp_to_fb(&bmp, &mut fb).expect("BMP decode must succeed");
        assert_eq!(fb.width, 2);
        assert_eq!(fb.height, 2);
        // Check pixel (0,0) in RGB
        assert_eq!(fb.rgb[0], 255);
        assert_eq!(fb.rgb[1], 0);
        assert_eq!(fb.rgb[2], 0);
    }
}
