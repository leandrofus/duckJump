//! One attended support session: connects to the gateway, shows the
//! verification code, and streams the screen once the operator has
//! verified it. Front ends (the CLI, the desktop app) follow it through
//! [`Event`]s and end it with the [`CancellationToken`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use serde::Serialize;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::capture::{self, ScreenCapturer};
use crate::{input, totp, wayland};

/// Where to connect and what to capture.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Gateway URL (http, https, ws or wss).
    pub server: String,
    /// Support session token.
    pub token: String,
    /// Verification code (or legacy TOTP secret) when the gateway sends none.
    pub code: Option<String>,
    /// Capture size when the screen size cannot be detected.
    pub width: u16,
    pub height: u16,
}

/// What happens during a session, in order.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// The control channel is up.
    Connected,
    /// The code the user reads to the operator ("123 456").
    Code { code: String },
    /// The screen capture backend is ready.
    CaptureReady { engine: String },
    /// The operator entered the right code: the screen is being shared.
    Verified,
    /// The operator's viewer acknowledged the first frame.
    Streaming,
    /// Once a second while streaming.
    Stats { fps: f64, rtt_ms: Option<f64>, kb_per_sec: f64, capture_ms: f64 },
}

/// Why a session ended without an error.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// The local user stopped it.
    Local,
    /// The gateway or the operator closed it.
    Server,
    /// The session already ended or expired (HTTP 410).
    Expired,
    /// No such session (HTTP 404).
    NotFound,
}

pub fn format_verification_code(raw: &str) -> String {
    let clean: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() == 6 && clean.chars().all(|c| c.is_ascii_digit()) {
        format!("{} {}", &clean[..3], &clean[3..])
    } else if !clean.is_empty() {
        if let Ok((c, _)) = totp::current_totp(&clean) {
            format!("{} {}", &c[..3], &c[3..])
        } else {
            clean
        }
    } else {
        "------".to_string()
    }
}

pub fn ws_url(server: &str, token: &str, stream: &str) -> String {
    let s = server.trim_end_matches('/');
    let base = if s.starts_with("https://") {
        s.replacen("https://", "wss://", 1)
    } else if s.starts_with("http://") {
        s.replacen("http://", "ws://", 1)
    } else if s.starts_with("wss://") || s.starts_with("ws://") {
        s.to_string()
    } else {
        format!("ws://{}", s)
    };
    format!("{}/api/v1/support/agent-tunnel/{}?stream={}", base, token, stream)
}

/// This machine's name, for the operator's session list.
pub fn hostname() -> String {
    for var in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(h) = std::env::var(var) {
            if !h.trim().is_empty() {
                return h.trim().to_string();
            }
        }
    }
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "client-machine".to_string())
}

/// Aborts the task when dropped, so a cancelled session leaves nothing running.
struct Task(JoinHandle<()>);

impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Runs the session until it ends or `cancel` fires. Errors are failures
/// (gateway unreachable, no screen capture); a normal end is an [`EndReason`].
pub async fn run_session(
    cfg: SessionConfig,
    events: UnboundedSender<Event>,
    cancel: CancellationToken,
) -> anyhow::Result<EndReason> {
    tokio::select! {
        r = run(cfg, events) => r,
        _ = cancel.cancelled() => {
            info!("Desconexión solicitada por el usuario local.");
            Ok(EndReason::Local)
        }
    }
}

enum ActiveInputBackend {
    X11(Box<input::InputController>),
    Wayland(Arc<tokio::sync::Mutex<wayland::WaylandSession>>),
}

async fn run(cfg: SessionConfig, events: UnboundedSender<Event>) -> anyhow::Result<EndReason> {
    let emit = |e: Event| {
        let _ = events.send(e);
    };
    info!(server = %cfg.server, "Connecting to duckJump Gateway...");

    // 1. Control channel
    let control_url = ws_url(&cfg.server, &cfg.token, "control");
    let (mut control_ws, _) = match tokio_tungstenite::connect_async(&control_url).await {
        Ok(ws) => ws,
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("410") {
                return Ok(EndReason::Expired);
            } else if err_str.contains("404") {
                return Ok(EndReason::NotFound);
            }
            anyhow::bail!("no se pudo conectar con el gateway ({}): {}", cfg.server, e);
        }
    };

    let control_header = serde_json::json!({
        "stream": "control",
        "hostname": hostname(),
        "os": std::env::consts::OS,
    });
    control_ws.send(Message::Text(control_header.to_string().into())).await?;
    emit(Event::Connected);

    // The gateway's first message carries the verification code.
    let mut code_raw = cfg.code.clone().unwrap_or_default();
    if let Some(Ok(Message::Text(txt))) = control_ws.next().await {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
            if let Some(c) = v.get("code").and_then(|s| s.as_str()) {
                code_raw = c.to_string();
            } else if let Some(sec) = v.get("totp_secret").and_then(|s| s.as_str()) {
                code_raw = sec.to_string();
            }
        }
    }
    let display_code = format_verification_code(&code_raw);
    info!("Esperando que el operador verifique el código de soporte: [ {} ]", display_code);
    emit(Event::Code { code: display_code });

    // 2. Display channel
    let display_url = ws_url(&cfg.server, &cfg.token, "display");
    let (display_ws, _) = tokio_tungstenite::connect_async(&display_url)
        .await
        .map_err(|e| anyhow::anyhow!("no se pudo abrir el canal de pantalla: {}", e))?;
    let (mut disp_write, mut disp_read) = display_ws.split();

    let is_wayland = std::env::var("WAYLAND_DISPLAY").is_ok()
        || std::env::var("XDG_SESSION_TYPE").map(|s| s.to_lowercase() == "wayland").unwrap_or(false);

    let (mut capturer, input_backend): (Box<dyn ScreenCapturer>, ActiveInputBackend) = if is_wayland {
        info!("Sesión Wayland detectada. Inicializando Portal RemoteDesktop nativo...");
        let sess = wayland::WaylandSession::init()
            .await
            .map_err(|e| anyhow::anyhow!("portal Wayland: {:#}", e))?;
        let pw_cap = wayland::WaylandPipeWireCapturer::start(sess.node_id, sess.width, sess.height)
            .map_err(|e| anyhow::anyhow!("captura PipeWire: {:#}", e))?;
        (Box::new(pw_cap), ActiveInputBackend::Wayland(Arc::new(tokio::sync::Mutex::new(sess))))
    } else {
        info!("Sesión X11 detectada. Usando capturador de memoria directa X11...");
        let cap = capture::create_best_capturer(cfg.width, cfg.height)?;
        let mut ctrl = input::InputController::new();
        ctrl.set_enabled(true);
        (cap, ActiveInputBackend::X11(Box::new(ctrl)))
    };
    info!("Motor de captura inicializado: {}", capturer.name());
    emit(Event::CaptureReady { engine: capturer.name().to_string() });

    let verified = Arc::new(AtomicBool::new(false));
    let acked_frame = Arc::new(AtomicU32::new(0));
    let sent_timestamps = Arc::new(Mutex::new(HashMap::<u32, Instant>::new()));
    let last_rtt_us = Arc::new(AtomicU64::new(0));

    // Control messages: the operator's verification.
    let mut control_task = Task(tokio::spawn({
        let verified = verified.clone();
        let events = events.clone();
        async move {
            while let Some(msg) = control_ws.next().await {
                match msg {
                    Ok(Message::Text(txt)) => {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
                            let t = v.get("type").and_then(|s| s.as_str());
                            if (t == Some("totp_verified") || t == Some("code_verified")) && !verified.swap(true, Ordering::Relaxed) {
                                info!("Código de verificación aceptado por el operador. Transmisión de pantalla activada.");
                                let _ = events.send(Event::Verified);
                            }
                        }
                    }
                    Ok(Message::Close(_)) => break,
                    Err(e) => {
                        warn!("Error en canal de control: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
        }
    }));

    // Display channel input: operator input and viewer render ACKs.
    let mut input_task = Task(tokio::spawn({
        let acked = acked_frame.clone();
        let sent_ts = sent_timestamps.clone();
        let last_rtt = last_rtt_us.clone();
        let events = events.clone();
        let mut backend = input_backend;
        async move {
            let mut streaming = false;
            while let Some(msg) = disp_read.next().await {
                match msg {
                    Ok(Message::Binary(bin)) if !bin.is_empty() => {
                        let slice = if bin[0] == 0x05 { &bin[1..] } else { &bin[..] };
                        match duckjump_proto::gfx::Input::decode(slice) {
                            Some(duckjump_proto::gfx::Input::Ack { frame }) => {
                                acked.store(frame, Ordering::Release);
                                let mut map = sent_ts.lock().unwrap();
                                if let Some(sent_at) = map.remove(&frame) {
                                    let rtt = sent_at.elapsed();
                                    last_rtt.store(rtt.as_micros() as u64, Ordering::Relaxed);
                                    debug!(frame, rtt_ms = rtt.as_secs_f64() * 1000.0, "ACK del visor");
                                }
                                if map.len() > 128 {
                                    map.retain(|&f, _| frame.saturating_sub(f) < 120);
                                }
                                drop(map);
                                if !streaming {
                                    streaming = true;
                                    let _ = events.send(Event::Streaming);
                                }
                            }
                            Some(other) => match &mut backend {
                                ActiveInputBackend::X11(ctrl) => {
                                    ctrl.handle_remote_input(other);
                                }
                                ActiveInputBackend::Wayland(sess) => {
                                    sess.lock().await.handle_remote_input(other).await;
                                }
                            },
                            None => {}
                        }
                    }
                    Ok(Message::Close(_)) => break,
                    Err(e) => {
                        warn!("Display input error: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
        }
    }));

    let mut interval = tokio::time::interval(Duration::from_millis(16)); // up to ~60 FPS
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut sent_initial = false;
    let mut frame_counter: u32 = 0;
    let mut last_send_time = Instant::now();

    let mut stats_window_start = Instant::now();
    let mut stats_frames = 0u32;
    let mut stats_cap_total = Duration::ZERO;
    let mut stats_enc_total = Duration::ZERO;
    let mut stats_send_total = Duration::ZERO;
    let mut stats_tiles_total = 0usize;
    let mut stats_bytes_total = 0usize;

    loop {
        tokio::select! {
            _ = &mut control_task.0 => {
                info!("Canal de control cerrado por el servidor.");
                break;
            }
            _ = &mut input_task.0 => {
                info!("Canal de entrada cerrado por el servidor.");
                break;
            }
            _ = interval.tick() => {
                if !verified.load(Ordering::Relaxed) {
                    continue;
                }
                if !sent_initial {
                    let t_cap_start = Instant::now();
                    let Ok(initial_tiles) = capturer.initial_frame() else { continue };
                    let cap_dur = t_cap_start.elapsed();
                    let t_send_start = Instant::now();
                    let mut init_bytes = 0usize;
                    let tile_cnt = initial_tiles.len();
                    for tile in initial_tiles {
                        let bytes = tile.encode();
                        init_bytes += bytes.len();
                        if disp_write.feed(Message::Binary(bytes)).await.is_err() {
                            return Ok(EndReason::Server);
                        }
                    }
                    frame_counter += 1;
                    let sync_bytes = duckjump_proto::gfx::Display::Sync { frame: frame_counter }.encode();
                    init_bytes += sync_bytes.len();
                    if disp_write.feed(Message::Binary(sync_bytes)).await.is_err() || disp_write.flush().await.is_err() {
                        return Ok(EndReason::Server);
                    }
                    sent_timestamps.lock().unwrap().insert(frame_counter, Instant::now());
                    info!(
                        "Frame inicial #{} enviado ({} tiles, {:.1} KB) | Captura: {:.1}ms | Red WS: {:.1}ms",
                        frame_counter, tile_cnt, init_bytes as f64 / 1024.0,
                        cap_dur.as_secs_f64() * 1000.0, t_send_start.elapsed().as_secs_f64() * 1000.0
                    );
                    sent_initial = true;
                    last_send_time = Instant::now();
                    continue;
                }

                // Adaptive rate control on the viewer's render ACKs: up to two
                // frames in flight sustains 60 FPS without piling up lag.
                let in_flight = frame_counter.saturating_sub(acked_frame.load(Ordering::Acquire));
                let ack_timed_out = last_send_time.elapsed() > Duration::from_millis(120);
                if in_flight <= 1 || ack_timed_out {
                    let t_cap_start = Instant::now();
                    if let Ok(damage) = capturer.capture() {
                        let cap_dur = t_cap_start.elapsed();
                        if !damage.is_empty() {
                            let t_enc_start = Instant::now();
                            if let Ok(updates) = capturer.encode_damage(&damage) {
                                let enc_dur = t_enc_start.elapsed();
                                let t_send_start = Instant::now();
                                let mut frame_bytes = 0usize;
                                let tile_cnt = updates.len();
                                for u in updates {
                                    let b = u.encode();
                                    frame_bytes += b.len();
                                    if let Err(e) = disp_write.feed(Message::Binary(b)).await {
                                        info!("Sesión cerrada por el servidor ({})", e);
                                        return Ok(EndReason::Server);
                                    }
                                }
                                frame_counter += 1;
                                let sync_b = duckjump_proto::gfx::Display::Sync { frame: frame_counter }.encode();
                                frame_bytes += sync_b.len();
                                if disp_write.feed(Message::Binary(sync_b)).await.is_err() || disp_write.flush().await.is_err() {
                                    return Ok(EndReason::Server);
                                }
                                let send_dur = t_send_start.elapsed();
                                last_send_time = Instant::now();
                                sent_timestamps.lock().unwrap().insert(frame_counter, Instant::now());

                                stats_frames += 1;
                                stats_cap_total += cap_dur;
                                stats_enc_total += enc_dur;
                                stats_send_total += send_dur;
                                stats_tiles_total += tile_cnt;
                                stats_bytes_total += frame_bytes;
                            }
                        }
                    }
                }

                let elapsed = stats_window_start.elapsed();
                if elapsed >= Duration::from_secs(1) {
                    if stats_frames > 0 {
                        let n = stats_frames as f64;
                        let fps = n / elapsed.as_secs_f64();
                        let avg_cap = stats_cap_total.as_secs_f64() * 1000.0 / n;
                        let avg_enc = stats_enc_total.as_secs_f64() * 1000.0 / n;
                        let avg_send = stats_send_total.as_secs_f64() * 1000.0 / n;
                        let kb_sec = (stats_bytes_total as f64 / 1024.0) / elapsed.as_secs_f64();
                        let rtt_us = last_rtt_us.load(Ordering::Relaxed);
                        let rtt_ms = (rtt_us > 0).then(|| rtt_us as f64 / 1000.0);
                        debug!(
                            fps, ?rtt_ms, avg_cap, avg_enc, avg_send, kb_sec,
                            tiles_per_frame = stats_tiles_total as f64 / n,
                            in_flight = frame_counter.saturating_sub(acked_frame.load(Ordering::Acquire)),
                            "estadísticas de transmisión"
                        );
                        if avg_cap > 50.0 {
                            warn!("Captura lenta ({:.1}ms). Puede deberse a herramienta CLI en vez de X11 directo.", avg_cap);
                        }
                        if rtt_us > 400_000 {
                            warn!("RTT elevado ({:.1}ms). El visor o la red están acumulando retraso.", rtt_us as f64 / 1000.0);
                        }
                        emit(Event::Stats { fps, rtt_ms, kb_per_sec: kb_sec, capture_ms: avg_cap });
                    }
                    stats_window_start = Instant::now();
                    stats_frames = 0;
                    stats_cap_total = Duration::ZERO;
                    stats_enc_total = Duration::ZERO;
                    stats_send_total = Duration::ZERO;
                    stats_tiles_total = 0;
                    stats_bytes_total = 0;
                }
            }
        }
    }

    let _ = disp_write.close().await;
    Ok(EndReason::Server)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_formatting() {
        assert_eq!(format_verification_code("501986"), "501 986");
        assert_eq!(format_verification_code(" 501 986 "), "501 986");
        assert_eq!(format_verification_code(""), "------");
    }

    #[test]
    fn ws_urls() {
        assert_eq!(ws_url("https://gw:8443/", "t", "control"), "wss://gw:8443/api/v1/support/agent-tunnel/t?stream=control");
        assert_eq!(ws_url("http://gw", "t", "display"), "ws://gw/api/v1/support/agent-tunnel/t?stream=display");
        assert_eq!(ws_url("gw:8088", "t", "display"), "ws://gw:8088/api/v1/support/agent-tunnel/t?stream=display");
    }

    #[test]
    fn events_serialize_for_the_front_end() {
        let v = serde_json::to_value(Event::Code { code: "501 986".into() }).unwrap();
        assert_eq!(v, serde_json::json!({"type": "code", "code": "501 986"}));
        assert_eq!(serde_json::to_value(EndReason::NotFound).unwrap(), "not_found");
    }

    #[tokio::test]
    async fn cancel_ends_a_session_that_cannot_connect_yet() {
        // A listener that accepts but never answers the WebSocket handshake.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let _hold = tokio::spawn(async move {
            let _conn = l.accept().await;
            std::future::pending::<()>().await;
        });
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        let cfg = SessionConfig { server: format!("http://{}", addr), token: "t".into(), code: None, width: 640, height: 480 };
        let h = tokio::spawn(run_session(cfg, tx, cancel.clone()));
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        let r = tokio::time::timeout(Duration::from_secs(2), h).await.unwrap().unwrap().unwrap();
        assert_eq!(r, EndReason::Local);
    }
}
