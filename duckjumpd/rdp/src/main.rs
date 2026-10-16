//! duckjumpd-rdp: RDP worker. duckjumpd starts one per RDP session and talks DJTP
//! with it over stdin/stdout (logs go to stderr). The protocol work is
//! IronRDP's; this program turns the remote screen into DJTP display frames
//! (duckjump-gfx) and browser input into RDP fast-path input.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Context};
use futures::{SinkExt, StreamExt};
use ironrdp::connector::{self, ConnectionResult, Credentials};
use ironrdp::graphics::image_processing::PixelFormat;
use ironrdp::input::{Database, MouseButton, MousePosition, Operation, Scancode, WheelRotations};
use ironrdp::pdu::gcc::KeyboardType;
use ironrdp::pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp::pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_tokio::{split_tokio_framed, FramedWrite as _, NetworkClient};
use duckjump_gfx::{Dirty, Framebuffer};
use duckjump_proto::gfx::{Display, Input, Rect};
use duckjump_proto::{Control, ErrorCode, Frame, FrameCodec, RdpParams, Ready, Relay, Target};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, warn};

type Out = FramedWrite<tokio::io::Stdout, FrameCodec>;
type In = FramedRead<tokio::io::Stdin, FrameCodec>;

// Generous: after NLA succeeds, Windows logs the user on (profile, group
// policy) before the capabilities exchange, and a fresh logon can take a
// minute; mstsc waits too.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(90);

/// An error the gateway should show with a specific code.
#[derive(Debug)]
struct Fail(ErrorCode, String);

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.1)
    }
}
impl std::error::Error for Fail {}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,ironrdp=warn,sspi=warn".into()))
        .init();
    let mut rx: In = FramedRead::new(tokio::io::stdin(), FrameCodec);
    let mut tx: Out = FramedWrite::new(tokio::io::stdout(), FrameCodec);

    let hello = match rx.next().await {
        Some(Ok(Frame::Control(Control::Hello(h)))) => h,
        _ => {
            eprintln!("duckjumpd-rdp: expected a Hello frame on stdin (this program is started by duckjumpd)");
            return std::process::ExitCode::FAILURE;
        }
    };
    let Target::Rdp(params) = hello.target else {
        eprintln!("duckjumpd-rdp: not an RDP target");
        return std::process::ExitCode::FAILURE;
    };
    match run(&hello.session_id, params, hello.relay, &mut rx, &mut tx).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            let (code, msg) = match e.downcast_ref::<Fail>() {
                Some(f) => (f.0, f.1.clone()),
                None => (ErrorCode::ConnectFailed, format!("{e:#}")),
            };
            warn!("session failed: {msg}");
            let _ = tx.send(Frame::Control(Control::Error { code, message: msg })).await;
            std::process::ExitCode::FAILURE
        }
    }
}

/// Kerberos would need to reach a KDC; NTLM (the usual NLA path) needs no
/// network, so requests are refused instead of pulling in an HTTP client.
struct NoNetwork;

impl NetworkClient for NoNetwork {
    async fn send(&mut self, _: &connector::sspi::generator::NetworkRequest) -> connector::ConnectorResult<Vec<u8>> {
        Err(connector::general_err!("Kerberos (KDC access) is not supported; use NTLM"))
    }
}

/// No credentials: connect without NLA and without autologon, so Windows
/// shows its own login screen inside the session (if the server allows it).
fn anonymous(p: &RdpParams) -> bool {
    p.username.is_empty() && p.password.is_empty()
}

fn connector_config(p: &RdpParams) -> connector::Config {
    let (tls, credssp) = match p.security.as_str() {
        _ if anonymous(p) => (true, false),
        "nla" => (true, true),
        "tls" => (true, false),
        _ => (true, true), // "any": offer both, the server chooses
    };
    connector::Config {
        credentials: Credentials::UsernamePassword { username: p.username.clone(), password: p.password.clone() },
        domain: p.domain.clone().filter(|d| !d.is_empty()),
        enable_tls: tls,
        enable_credssp: credssp,
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: connector::DesktopSize { width: p.width.clamp(200, 8192), height: p.height.clamp(200, 8192) },
        bitmap: None,
        client_build: 0,
        client_name: "duckjump".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        platform: MajorPlatformType::UNIX,
        enable_server_pointer: true,
        request_data: None,
        // With credentials, log straight in; without, show the login screen.
        autologon: !anonymous(p),
        enable_audio_playback: false,
        compression_type: None,
        pointer_software_rendering: false,
        multitransport_flags: None,
        performance_flags: PerformanceFlags::default(),
        desktop_scale_factor: 0,
        hardware_id: None,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
    }
}

trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}
type Upgraded = ironrdp_tokio::TokioFramed<Box<dyn AsyncReadWrite + Unpin + Send + Sync>>;

async fn connect(p: &RdpParams, relay: Option<&Relay>) -> anyhow::Result<(ConnectionResult, Upgraded, String)> {
    let (stream, client_addr): (_, SocketAddr) = duckjump_net::dial(&p.host, p.port, relay).await.map_err(|e| Fail(ErrorCode::ConnectFailed, format!("{e:#}")))?;
    let mut framed = ironrdp_tokio::TokioFramed::new(stream);

    let drdynvc = ironrdp::dvc::DrdynvcClient::new()
        .with_dynamic_channel(ironrdp::displaycontrol::client::DisplayControlClient::new(|_| Ok(Vec::new())));
    let mut connector = connector::ClientConnector::new(connector_config(p), client_addr).with_static_channel(drdynvc);

    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector).await.map_err(|e| describe("RDP negotiation", &e, anonymous(p)))?;
    let (initial, leftover) = framed.into_inner();
    let (tls, cert) = ironrdp_tls::upgrade(initial, &p.host).await.map_err(|e| Fail(ErrorCode::ConnectFailed, format!("TLS: {e}")))?;
    let public_key = ironrdp_tls::extract_tls_server_public_key(&cert)
        .ok_or_else(|| Fail(ErrorCode::ConnectFailed, "cannot read the server's TLS public key".into()))?
        .to_owned();

    // Pin the server key like an SSH host key. CredSSP has not run yet:
    // an unknown key stops here, before the password goes anywhere.
    let fingerprint = format!("SHA256:{}", hex(&Sha256::digest(&public_key)));
    match &p.cert_fingerprint {
        Some(want) if want != &fingerprint => {
            return Err(Fail(ErrorCode::HostKeyMismatch, format!("server key changed: got {fingerprint}")).into());
        }
        None if !p.trust_unknown => return Err(Fail(ErrorCode::HostKeyUnknown, fingerprint).into()),
        _ => {}
    }

    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let erased: Box<dyn AsyncReadWrite + Unpin + Send + Sync> = Box::new(tls);
    let mut framed = ironrdp_tokio::TokioFramed::new_with_leftover(erased, leftover);
    let result = ironrdp_tokio::connect_finalize(upgraded, connector, &mut framed, &mut NoNetwork, p.host.as_str().into(), public_key, None)
        .await
        .map_err(|e| {
            debug!("connection failed: {e:?}");
            describe("RDP connection", &e, anonymous(p))
        })?;
    Ok((result, framed, fingerprint))
}

/// Turns an IronRDP connection error into what the user should see: no
/// source locations, and credential problems reported as such.
fn describe(stage: &str, e: &connector::ConnectorError, anonymous: bool) -> Fail {
    use connector::ConnectorErrorKind as K;
    match e.kind() {
        K::Credssp(se) => {
            debug!("CredSSP: {se}");
            Fail(ErrorCode::AuthFailed, "NLA authentication failed: wrong username or password, or the account may not log on remotely".into())
        }
        K::AccessDenied => Fail(ErrorCode::AuthFailed, "access denied by the server".into()),
        K::Negotiation(n) => {
            use ironrdp::pdu::nego::FailureCode as F;
            if anonymous && n.code() == F::HYBRID_REQUIRED_BY_SERVER {
                // NLA authenticates before the session exists: no login screen
                // is possible, the client has to ask for credentials.
                return Fail(ErrorCode::CredentialsRequired, "the server requires NLA, so it needs your credentials before the session starts".into());
            }
            let why = match n.code() {
                F::HYBRID_REQUIRED_BY_SERVER => "the server requires NLA: set the connection's security to Automatic or NLA",
                F::SSL_REQUIRED_BY_SERVER => "the server does not support NLA: set the connection's security to TLS",
                F::SSL_NOT_ALLOWED_BY_SERVER => "the server only offers legacy RDP security, which is not supported (enable TLS/NLA on the server)",
                F::SSL_CERT_NOT_ON_SERVER => "the server has no TLS certificate configured",
                _ => "the server refused the requested security mode",
            };
            Fail(ErrorCode::ConnectFailed, format!("{stage}: {why}"))
        }
        K::Reason(r) => Fail(ErrorCode::ConnectFailed, format!("{stage}: {r}")),
        other => Fail(ErrorCode::ConnectFailed, format!("{stage}: {other}")),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Frame sender with flow control: one frame in flight; changes accumulate
/// in `dirty` until the client acknowledges.
struct Screen {
    fb: Framebuffer,
    dirty: Dirty,
    frame: u32,
    in_flight: bool,
}

impl Screen {
    fn new(w: u16, h: u16) -> Self {
        Self { fb: Framebuffer::new(w, h), dirty: Dirty::default(), frame: 0, in_flight: false }
    }

    /// Copies an updated region (inclusive bounds) from the decoded RGBA image.
    fn update(&mut self, img: &DecodedImage, left: u16, top: u16, right: u16, bottom: u16) {
        let (w, h) = (img.width(), img.height());
        if w != self.fb.width || h != self.fb.height || left >= w || top >= h {
            return;
        }
        let (right, bottom) = (right.min(w - 1), bottom.min(h - 1));
        let data = img.data();
        for y in top as usize..=bottom as usize {
            for x in left as usize..=right as usize {
                let s = (y * w as usize + x) * 4;
                let d = (y * w as usize + x) * 3;
                self.fb.rgb[d..d + 3].copy_from_slice(&data[s..s + 3]);
            }
        }
        self.dirty.add(Rect { x: left, y: top, w: right - left + 1, h: bottom - top + 1 });
    }

    async fn flush(&mut self, tx: &mut Out) -> anyhow::Result<()> {
        if self.in_flight || self.dirty.is_empty() {
            return Ok(());
        }
        let rects = self.dirty.take();
        let area: u32 = rects.iter().map(|r| r.w as u32 * r.h as u32).sum();
        let started = std::time::Instant::now();
        let fb = &self.fb;
        let ops = tokio::task::block_in_place(|| -> anyhow::Result<Vec<Display>> {
            let mut all = Vec::new();
            for r in rects {
                all.extend(duckjump_gfx::encode_rect(fb, r.x, r.y, r.w, r.h)?);
            }
            Ok(all)
        })?;
        let encode_ms = started.elapsed().as_secs_f64() * 1000.0;
        let mut bytes = 0usize;
        let n = ops.len();
        for op in ops {
            let b = op.encode();
            bytes += b.len();
            tx.feed(Frame::Display(b)).await?;
        }
        self.frame = self.frame.wrapping_add(1);
        debug!(frame = self.frame, px = area, ops = n, kb = bytes / 1024, encode_ms = format!("{encode_ms:.1}"), "frame");
        tx.send(Frame::Display(Display::Sync { frame: self.frame }.encode())).await?;
        self.in_flight = true;
        Ok(())
    }

    async fn resize(&mut self, w: u16, h: u16, tx: &mut Out) -> anyhow::Result<()> {
        *self = Screen::new(w, h);
        tx.send(Frame::Display(Display::Size { width: w, height: h }.encode())).await?;
        Ok(())
    }
}

/// Fallback scancodes for keys the browser sent without one.
fn keysym_scancode(keysym: u32) -> Option<u16> {
    Some(match keysym {
        0xff08 => 0x0e,   // BackSpace
        0xff09 => 0x0f,   // Tab
        0xff0d => 0x1c,   // Return
        0xff1b => 0x01,   // Escape
        0xffff => 0xe053, // Delete
        0xff63 => 0xe052, // Insert
        0xff50 => 0xe047, // Home
        0xff57 => 0xe04f, // End
        0xff55 => 0xe049, // Page_Up
        0xff56 => 0xe051, // Page_Down
        0xff51 => 0xe04b, // Left
        0xff52 => 0xe048, // Up
        0xff53 => 0xe04d, // Right
        0xff54 => 0xe050, // Down
        0xffe1 => 0x2a,   // Shift_L
        0xffe2 => 0x36,   // Shift_R
        0xffe3 => 0x1d,   // Control_L
        0xffe4 => 0xe01d, // Control_R
        0xffe9 => 0x38,   // Alt_L
        0xffea | 0xfe03 => 0xe038, // Alt_R / AltGr
        0xffeb => 0xe05b, // Super_L
        0xffec => 0xe05c, // Super_R
        0xffe5 => 0x3a,   // Caps_Lock
        k @ 0xffbe..=0xffc7 => (0x3b + (k - 0xffbe)) as u16, // F1-F10
        0xffc8 => 0x57,   // F11
        0xffc9 => 0x58,   // F12
        _ => return None,
    })
}

fn keysym_char(keysym: u32) -> Option<char> {
    match keysym {
        0x20..=0xff => char::from_u32(keysym),
        k if k & 0xff00_0000 == 0x0100_0000 => char::from_u32(k & 0x00ff_ffff),
        _ => None,
    }
}

const BUTTONS: [(u8, MouseButton); 3] = [(1, MouseButton::Left), (2, MouseButton::Middle), (4, MouseButton::Right)];

fn input_ops(input: Input, buttons: &mut u8) -> Vec<Operation> {
    match input {
        Input::Key { keysym, down, scancode } => {
            let sc = if scancode != 0 { Some(scancode) } else { keysym_scancode(keysym) };
            match (sc, keysym_char(keysym)) {
                (Some(sc), _) => vec![if down { Operation::KeyPressed(Scancode::from_u16(sc)) } else { Operation::KeyReleased(Scancode::from_u16(sc)) }],
                (None, Some(c)) => vec![if down { Operation::UnicodeKeyPressed(c) } else { Operation::UnicodeKeyReleased(c) }],
                (None, None) => vec![],
            }
        }
        Input::Pointer { x, y, buttons: mask } => {
            let mut ops = vec![Operation::MouseMove(MousePosition { x, y })];
            for (bit, b) in BUTTONS {
                match (*buttons & bit != 0, mask & bit != 0) {
                    (false, true) => ops.push(Operation::MouseButtonPressed(b)),
                    (true, false) => ops.push(Operation::MouseButtonReleased(b)),
                    _ => {}
                }
            }
            *buttons = mask & 7;
            // Wheel bits 3-6: one notch each (120 units, as Windows does).
            for (bit, vertical, units) in [(8u8, true, 120i16), (16, true, -120), (32, false, -120), (64, false, 120)] {
                if mask & bit != 0 {
                    ops.push(Operation::WheelRotations(WheelRotations { is_vertical: vertical, rotation_units: units }));
                }
            }
            ops
        }
        Input::Ack { .. } => vec![],
    }
}

async fn run(session_id: &str, p: RdpParams, relay: Option<Relay>, rx: &mut In, tx: &mut Out) -> anyhow::Result<()> {
    let (result, framed, fingerprint) = match tokio::time::timeout(CONNECT_TIMEOUT, connect(&p, relay.as_ref())).await {
        Ok(r) => r?,
        Err(_) => bail!(Fail(ErrorCode::ConnectFailed, "timed out".into())),
    };
    let size = result.desktop_size;
    info!(host = %p.host, width = size.width, height = size.height, "rdp connected");

    let (mut reader, mut writer) = split_tokio_framed(framed);
    let mut image = DecodedImage::new(PixelFormat::RgbA32, size.width, size.height);
    let activation_factory = result.activation_factory;
    let mut stage: ActiveStage = ActiveStageBuilder {
        static_channels: result.static_channels,
        user_channel_id: result.user_channel_id,
        io_channel_id: result.io_channel_id,
        message_channel_id: result.message_channel_id,
        share_id: result.share_id,
        compression_type: result.compression_type,
        enable_server_pointer: result.enable_server_pointer,
        pointer_software_rendering: result.pointer_software_rendering,
    }
    .build();

    tx.send(Frame::Control(Control::Ready(Ready { session_id: session_id.into(), host_key_fingerprint: Some(fingerprint) }))).await?;
    let mut screen = Screen::new(size.width, size.height);
    screen.resize(size.width, size.height, tx).await?;

    let mut db = Database::new();
    let mut buttons = 0u8;
    let mut closing = false;
    let mut end_reason: Option<String> = None;

    loop {
        let outputs = tokio::select! {
            pdu = reader.read_pdu() => {
                let (action, payload) = pdu.context("reading from the RDP server")?;
                stage.process(&mut image, action, &payload)?
            }
            f = rx.next() => match f {
                Some(Ok(Frame::InputEvent(b))) => match Input::decode(&b) {
                    Some(Input::Ack { frame }) => {
                        if frame == screen.frame {
                            screen.in_flight = false;
                            screen.flush(tx).await?;
                        }
                        continue;
                    }
                    Some(input) => {
                        let events = db.apply(input_ops(input, &mut buttons));
                        if events.is_empty() { continue; }
                        stage.process_fastpath_input(&mut image, &events)?
                    }
                    None => continue,
                },
                Some(Ok(Frame::Control(Control::Resize { cols, rows }))) => {
                    match stage.encode_resize(u32::from(cols).clamp(200, 8192), u32::from(rows).clamp(200, 8192), None, None) {
                        Some(frame) => vec![ActiveStageOutput::ResponseFrame(frame?)],
                        None => continue, // server without dynamic resize
                    }
                }
                Some(Ok(Frame::Control(Control::Close { .. }))) | None => {
                    if closing { break; }
                    closing = true;
                    let mut out = stage.graceful_shutdown()?;
                    db.release_all();
                    out.push(ActiveStageOutput::Terminate(ironrdp::session::GracefulDisconnectReason::UserInitiated));
                    out
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(e.into()),
            },
        };

        let mut terminate = false;
        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(frame) => writer.write_all(&frame).await.context("writing to the RDP server")?,
                ActiveStageOutput::GraphicsUpdate(r) => screen.update(&image, r.left, r.top, r.right, r.bottom),
                ActiveStageOutput::PointerDefault => {
                    tx.send(Frame::Display(Display::Cursor { hot_x: 0, hot_y: 0, w: 0, h: 0, png: Default::default() }.encode())).await?;
                }
                ActiveStageOutput::PointerHidden => {
                    let png = duckjump_gfx::encode_png_rgba(&[0, 0, 0, 0], 1, 1)?;
                    tx.send(Frame::Display(Display::Cursor { hot_x: 0, hot_y: 0, w: 1, h: 1, png }.encode())).await?;
                }
                ActiveStageOutput::PointerBitmap(ptr) => {
                    if ptr.width > 0 && ptr.height > 0 && ptr.bitmap_data.len() >= ptr.width as usize * ptr.height as usize * 4 {
                        let png = duckjump_gfx::encode_png_rgba(&ptr.bitmap_data, ptr.width, ptr.height)?;
                        tx.send(Frame::Display(Display::Cursor { hot_x: ptr.hotspot_x, hot_y: ptr.hotspot_y, w: ptr.width, h: ptr.height, png }.encode())).await?;
                    }
                }
                ActiveStageOutput::PointerPosition { .. } => {}
                ActiveStageOutput::DeactivateAll => {
                    // Deactivation-Reactivation Sequence (the server changed the desktop).
                    debug!("deactivation-reactivation sequence");
                    let mut seq = activation_factory.create();
                    let mut buf = ironrdp::core::WriteBuf::new();
                    loop {
                        let written = ironrdp_tokio::single_sequence_step_read(&mut reader, &mut seq, &mut buf).await?;
                        if written.size().is_some() {
                            writer.write_all(buf.filled()).await?;
                        }
                        if let connector::connection_activation::ConnectionActivationState::Finalized { desktop_size, share_id, enable_server_pointer, pointer_software_rendering } = seq.connection_activation_state() {
                            image = DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
                            stage.set_fastpath_processor(ironrdp::session::fast_path::ProcessorBuilder {
                                io_channel_id: seq.io_channel_id(),
                                user_channel_id: seq.user_channel_id(),
                                share_id,
                                enable_server_pointer,
                                pointer_software_rendering,
                                bulk_decompressor: None,
                            }.build());
                            stage.set_share_id(share_id);
                            stage.set_enable_server_pointer(enable_server_pointer);
                            screen.resize(desktop_size.width, desktop_size.height, tx).await?;
                            break;
                        }
                    }
                }
                ActiveStageOutput::Terminate(reason) => {
                    info!(?reason, "rdp session ended");
                    if !matches!(reason, ironrdp::session::GracefulDisconnectReason::UserInitiated) {
                        // e.g. "Another user connected to the server, forcing the disconnection…"
                        let text = format!("{reason}");
                        end_reason = Some(text.split("] ").last().unwrap_or(&text).to_string());
                    }
                    terminate = true;
                }
                _ => {}
            }
        }
        screen.flush(tx).await?;
        if terminate {
            break;
        }
    }
    let _ = tx.send(Frame::Control(Control::Exit { status: None, reason: end_reason })).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_buttons_and_wheel() {
        let mut b = 0;
        let ops = input_ops(Input::Pointer { x: 10, y: 20, buttons: 1 }, &mut b);
        assert!(matches!(ops.as_slice(), [Operation::MouseMove(_), Operation::MouseButtonPressed(MouseButton::Left)]));
        let ops = input_ops(Input::Pointer { x: 10, y: 20, buttons: 0 }, &mut b);
        assert!(matches!(ops.as_slice(), [Operation::MouseMove(_), Operation::MouseButtonReleased(MouseButton::Left)]));
        let ops = input_ops(Input::Pointer { x: 0, y: 0, buttons: 8 }, &mut b);
        assert!(matches!(ops.as_slice(), [Operation::MouseMove(_), Operation::WheelRotations(WheelRotations { is_vertical: true, rotation_units: 120 })]));
        assert_eq!(b, 0, "wheel bits are not buttons");
    }

    #[test]
    fn keys_prefer_scancode_then_unicode() {
        let mut b = 0;
        assert!(matches!(input_ops(Input::Key { keysym: 0x61, down: true, scancode: 0x1e }, &mut b).as_slice(), [Operation::KeyPressed(_)]));
        assert!(matches!(input_ops(Input::Key { keysym: 0xf1, down: true, scancode: 0 }, &mut b).as_slice(), [Operation::UnicodeKeyPressed('ñ')]));
        assert!(matches!(input_ops(Input::Key { keysym: 0xff0d, down: false, scancode: 0 }, &mut b).as_slice(), [Operation::KeyReleased(_)]));
        assert!(input_ops(Input::Key { keysym: 0xfe50, down: true, scancode: 0 }, &mut b).is_empty()); // dead key
    }
}
