use std::io::Read;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use ashpd::desktop::{
    PersistMode,
    remote_desktop::{
        Axis, DeviceType, KeyState, NotifyKeyboardKeysymOptions,
        NotifyPointerAxisDiscreteOptions, NotifyPointerButtonOptions,
        NotifyPointerMotionAbsoluteOptions, RemoteDesktop, SelectDevicesOptions,
    },
    screencast::{CursorMode, Screencast, SelectSourcesOptions, SourceType},
    Session,
};
use ashpd::enumflags2::BitFlags;
use duckjump_gfx::{Damage, Framebuffer};
use duckjump_proto::gfx::Input;
use tracing::{debug, info};

use crate::capture::{detect_damage, ScreenCapturer};

const USER_OVERRIDE_DURATION: Duration = Duration::from_secs(2);



/// Unified Wayland RemoteDesktop Session handling PipeWire capture and input injection.
pub struct WaylandSession {
    remote_desktop: Arc<RemoteDesktop>,
    session: Arc<Session<RemoteDesktop>>,
    pub node_id: u32,
    pub width: u16,
    pub height: u16,
    last_local_interaction: Option<Instant>,
    enabled: bool,
    prev_buttons: u8,
}

impl WaylandSession {
    pub async fn init() -> anyhow::Result<Self> {
        info!("Iniciando conexión con Portal Wayland (RemoteDesktop + ScreenCast)...");
        let remote_desktop = Arc::new(RemoteDesktop::new().await?);
        let screencast = Screencast::new().await?;
        let session = Arc::new(remote_desktop.create_session(Default::default()).await?);

        let dev_opts = SelectDevicesOptions::default()
            .set_devices(DeviceType::Keyboard | DeviceType::Pointer)
            .set_persist_mode(PersistMode::DoNot);

        remote_desktop.select_devices(&session, dev_opts).await
            .context("Fallo en RemoteDesktop::select_devices")?;

        let src_opts = SelectSourcesOptions::default()
            .set_cursor_mode(CursorMode::Embedded)
            .set_sources(BitFlags::from(SourceType::Monitor))
            .set_multiple(false)
            .set_persist_mode(PersistMode::DoNot);

        screencast.select_sources(&session, src_opts).await
            .context("Fallo en Screencast::select_sources")?;

        println!("🔒 Solicitando autorización de escritorio remoto al usuario en pantalla...");
        let response = remote_desktop
            .start(&session, None, Default::default())
            .await?
            .response()
            .context("El usuario canceló o rechazó el diálogo de compartir pantalla")?;

        let streams = response.streams();
        let stream = streams.first().context("No se seleccionó ningún stream de pantalla")?;
        let node_id = stream.pipe_wire_node_id();

        let (w, h) = stream.size().unwrap_or((1920, 1080));
        let width = w.max(1) as u16;
        let height = h.max(1) as u16;

        println!("✅ Sesión Wayland RemoteDesktop autorizada: Stream Node ID {}, resolución {}x{}", node_id, width, height);

        Ok(Self {
            remote_desktop,
            session,
            node_id,
            width,
            height,
            last_local_interaction: None,
            enabled: true,
            prev_buttons: 0,
        })
    }

    #[allow(dead_code)]
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn is_operator_allowed(&self) -> bool {
        if !self.enabled {
            return false;
        }
        if let Some(last) = self.last_local_interaction {
            if last.elapsed() < USER_OVERRIDE_DURATION {
                return false;
            }
        }
        true
    }

    pub async fn handle_remote_input(&mut self, input: Input) -> bool {
        if !self.is_operator_allowed() {
            return false;
        }

        match input {
            Input::Pointer { x, y, buttons } => {
                let stream_id = self.node_id;
                let rd = self.remote_desktop.clone();
                let sess = self.session.clone();

                // 1. Absolute pointer motion within stream
                let _ = rd.notify_pointer_motion_absolute(
                    &sess,
                    stream_id,
                    x as f64,
                    y as f64,
                    NotifyPointerMotionAbsoluteOptions::default(),
                ).await;

                // 2. Buttons: BTN_LEFT (0x110 = 272), BTN_RIGHT (0x111 = 273), BTN_MIDDLE (0x112 = 274)
                let btn_changes = [
                    (1u8, 272i32), // Left
                    (2u8, 274i32), // Middle
                    (4u8, 273i32), // Right
                ];
                for (bit, code) in btn_changes {
                    if (buttons & bit) != (self.prev_buttons & bit) {
                        let state = if (buttons & bit) != 0 { KeyState::Pressed } else { KeyState::Released };
                        let _ = rd.notify_pointer_button(&sess, code, state, NotifyPointerButtonOptions::default()).await;
                    }
                }

                // 3. Scroll wheels: discrete vertical axis steps
                if (buttons & 8) != 0 && (self.prev_buttons & 8) == 0 {
                    let _ = rd.notify_pointer_axis_discrete(&sess, Axis::Vertical, -1, NotifyPointerAxisDiscreteOptions::default()).await;
                }
                if (buttons & 16) != 0 && (self.prev_buttons & 16) == 0 {
                    let _ = rd.notify_pointer_axis_discrete(&sess, Axis::Vertical, 1, NotifyPointerAxisDiscreteOptions::default()).await;
                }

                self.prev_buttons = buttons;
                true
            }
            Input::Key { keysym, down, .. } => {
                let rd = self.remote_desktop.clone();
                let sess = self.session.clone();
                let state = if down { KeyState::Pressed } else { KeyState::Released };
                let _ = rd.notify_keyboard_keysym(&sess, keysym as i32, state, NotifyKeyboardKeysymOptions::default()).await;
                true
            }
            _ => false,
        }
    }
}

/// Wayland Screen Capturer using GStreamer pipewiresrc pipeline into stdout.
pub struct WaylandPipeWireCapturer {
    pub width: u16,
    pub height: u16,
    child: Child,
    stdout: ChildStdout,
    raw_buffer: Vec<u8>,
    fb: Framebuffer,
    prev_rgb: Vec<u8>,
}

impl WaylandPipeWireCapturer {
    pub fn start(node_id: u32, width: u16, height: u16) -> anyhow::Result<Self> {
        let mut cmd = Command::new("gst-launch-1.0");
        cmd.args([
            "-q",
            "pipewiresrc",
            &format!("path={}", node_id),
            "do-timestamp=true",
            "!",
            &format!("video/x-raw,format=BGRx,width={},height={}", width, height),
            "!",
            "fdsink",
            "fd=1",
            "sync=false",
        ]);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::null());

        let mut child = cmd.spawn().context(
            "No se pudo ejecutar gst-launch-1.0. Asegúrese de tener instalado el paquete gstreamer1-tools / gstreamer1-pipewire"
        )?;

        let stdout = child.stdout.take().context("No se pudo obtener stdout de gst-launch-1.0")?;
        let frame_size = width as usize * height as usize * 4;
        let raw_buffer = vec![0u8; frame_size];

        let mut capturer = Self {
            width,
            height,
            child,
            stdout,
            raw_buffer,
            fb: Framebuffer::new(width, height),
            prev_rgb: vec![0u8; width as usize * height as usize * 3],
        };

        // Capture initial frame to fill initial framebuffer
        capturer.read_next_frame()?;
        capturer.prev_rgb = capturer.fb.rgb.clone();

        Ok(capturer)
    }

    fn read_next_frame(&mut self) -> anyhow::Result<()> {
        self.stdout.read_exact(&mut self.raw_buffer)?;

        let w = self.width as usize;
        let h = self.height as usize;
        let pixels = w * h;

        for (i, chunk) in self.raw_buffer.chunks_exact(4).take(pixels).enumerate() {
            let out = i * 3;
            self.fb.rgb[out] = chunk[2];     // R
            self.fb.rgb[out + 1] = chunk[1]; // G
            self.fb.rgb[out + 2] = chunk[0]; // B
        }

        Ok(())
    }
}

impl Drop for WaylandPipeWireCapturer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl ScreenCapturer for WaylandPipeWireCapturer {
    fn name(&self) -> String {
        format!("Wayland Nativo (Portal RemoteDesktop + PipeWire, {}x{}, latencia sub-10ms)", self.width, self.height)
    }

    fn capture(&mut self) -> anyhow::Result<Vec<Damage>> {
        self.read_next_frame()?;
        Ok(detect_damage(&self.fb, &mut self.prev_rgb))
    }

    fn framebuffer(&self) -> &Framebuffer {
        &self.fb
    }
}
