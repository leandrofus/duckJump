use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use tracing::{info, warn};

#[allow(unused_imports)]
use crate::capture::ScreenCapturer;

mod capture;
mod input;
mod totp;

#[derive(Parser, Debug)]
#[command(name = "duckjump-assist", about = "duckJump on-demand remote support agent")]
struct Args {
    /// Gateway server URL (e.g. http://100.83.173.113:8888 or wss://bastion:8443)
    #[arg(short, long, env = "DUCKJUMP_SUPPORT_SERVER")]
    server: Option<String>,

    /// Session token provided by the support link
    #[arg(short, long, env = "DUCKJUMP_SUPPORT_TOKEN")]
    token: Option<String>,

    /// Verification code or PIN
    #[arg(long, alias = "code", env = "DUCKJUMP_SUPPORT_CODE")]
    code: Option<String>,

    /// TOTP Secret (Base32) for offline verification (legacy)
    #[arg(long, env = "DUCKJUMP_SUPPORT_TOTP_SECRET")]
    totp_secret: Option<String>,

    /// Desktop capture width
    #[arg(long, default_value_t = 1280)]
    width: u16,

    /// Desktop capture height
    #[arg(long, default_value_t = 800)]
    height: u16,

    /// Run a diagnostic self-test without connecting to a gateway
    #[arg(long)]
    test: bool,
}

fn format_verification_code(raw: &str) -> String {
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

fn print_banner(code: Option<&str>) {
    println!();
    println!("╔════════════════════════════════════════════════════════════════════╗");
    println!("║       🦆 duckJump Assist — Asistencia Remota A Demanda            ║");
    println!("║                 (Estrictamente Asistido)                           ║");
    println!("╠════════════════════════════════════════════════════════════════════╣");
    println!("║  Este programa permite que un técnico de soporte autorizado vea y  ║");
    println!("║  asista en su equipo de forma interactiva y temporal.             ║");
    println!("║                                                                    ║");
    if let Some(c) = code {
        println!("║           >>> CÓDIGO DE VERIFICACIÓN: [ {} ] <<<              ║", c);
        println!("║                                                                    ║");
        println!("║  Indique este código a su operador de soporte para comenzar.       ║");
    }
    println!("║                                                                    ║");
    println!("║  • El operador NO puede acceder sin este código de verificación.   ║");
    println!("║  • Usted mantiene el control del ratón y teclado en todo momento.  ║");
    println!("║  • Presione Ctrl+C en cualquier momento para DESCONECTAR de golpe. ║");
    println!("╚════════════════════════════════════════════════════════════════════╝");
    println!();
}

fn ws_url(server: &str, token: &str, stream: &str) -> String {
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    if args.test {
        info!("Running duckjump-assist self-test...");
        let code = format_verification_code(args.code.as_deref().unwrap_or(args.totp_secret.as_deref().unwrap_or("749201")));
        print_banner(Some(&code));

        let mut capturer = capture::create_best_capturer(args.width, args.height);
        let initial = capturer.initial_frame()?;
        info!(tiles = initial.len(), "Captured initial DJTP display frame successfully");

        let damage = capturer.capture()?;
        let updates = capturer.encode_damage(&damage)?;
        info!(updates = updates.len(), "Encoded incremental DJTP display damage successfully");

        let mut input_ctrl = input::InputController::new();
        input_ctrl.set_enabled(true);
        info!("Input controller initialized and ready");
        println!("✅ Self-test completed successfully.");
        return Ok(());
    }

    let server = match args.server {
        Some(s) => s,
        None => {
            let code = format_verification_code(args.code.as_deref().unwrap_or(args.totp_secret.as_deref().unwrap_or("749201")));
            print_banner(Some(&code));
            println!("Presione Ctrl+C para finalizar.");
            tokio::signal::ctrl_c().await?;
            return Ok(());
        }
    };

    let token = match args.token {
        Some(t) => t,
        None => {
            anyhow::bail!("Session token is required when connecting to server (use --token <TOKEN>)");
        }
    };

    info!(server = %server, token = %token, "Connecting to duckJump Gateway...");

    // 1. Connect Control Channel
    let control_url = ws_url(&server, &token, "control");
    let (mut control_ws, _) = match tokio_tungstenite::connect_async(&control_url).await {
        Ok(ws) => ws,
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("410") {
                eprintln!("\n╔════════════════════════════════════════════════════════════════════╗");
                eprintln!("║  ⚠️  SESIÓN DE ASISTENCIA FINALIZADA (HTTP 410 Gone)              ║");
                eprintln!("╠════════════════════════════════════════════════════════════════════╣");
                eprintln!("║  Esta sesión de soporte ya ha concluido o ha expirado.             ║");
                eprintln!("║  Por motivos de seguridad, los enlaces son de un solo uso.         ║");
                eprintln!("║                                                                    ║");
                eprintln!("║  👉 Solicite a su operador técnico que le envíe un nuevo enlace.   ║");
                eprintln!("╚════════════════════════════════════════════════════════════════════╝\n");
                return Ok(());
            } else if err_str.contains("404") {
                eprintln!("\n❌ Error: El token o enlace de soporte no existe o ha expirado (HTTP 404).\n");
                return Ok(());
            }
            anyhow::bail!("Failed to connect to gateway control channel {}: {}", control_url, e);
        }
    };

    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "client-machine".to_string());
    let os = std::env::consts::OS.to_string();

    let control_header = serde_json::json!({
        "stream": "control",
        "hostname": hostname,
        "os": os,
    });
    control_ws.send(tokio_tungstenite::tungstenite::Message::Text(control_header.to_string().into())).await?;

    // Read initial config from gateway (includes dynamic verification code)
    let mut code_raw = args.code.clone().or_else(|| args.totp_secret.clone()).unwrap_or_default();
    if let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(txt))) = control_ws.next().await {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
            if let Some(c) = v.get("code").and_then(|s| s.as_str()) {
                code_raw = c.to_string();
            } else if let Some(sec) = v.get("totp_secret").and_then(|s| s.as_str()) {
                code_raw = sec.to_string();
            }
        }
    }

    let display_code = format_verification_code(&code_raw);
    print_banner(Some(&display_code));
    info!("Conectado al servidor. Esperando que el operador verifique el código de soporte: [ {} ]", display_code);

    // 2. Connect Display Channel
    let display_url = ws_url(&server, &token, "display");
    let (display_ws, _) = tokio_tungstenite::connect_async(&display_url).await
        .map_err(|e| anyhow::anyhow!("Failed to connect to gateway display channel: {}", e))?;

    let (mut disp_write, mut disp_read) = display_ws.split();
    let mut interval = tokio::time::interval(Duration::from_millis(16)); // Target up to 60 FPS (~16.6ms)
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let acked_frame = Arc::new(AtomicU32::new(0));
    let acked_writer = acked_frame.clone();
    let acked_reader = acked_frame.clone();

    let sent_timestamps = Arc::new(Mutex::new(HashMap::<u32, Instant>::new()));
    let sent_ts_input = sent_timestamps.clone();
    let sent_ts_capture = sent_timestamps.clone();

    let last_rtt_us = Arc::new(AtomicU64::new(0));
    let last_rtt_writer = last_rtt_us.clone();
    let last_rtt_reader = last_rtt_us.clone();

    let mut input_ctrl = input::InputController::new();
    input_ctrl.set_enabled(true);

    let verified = Arc::new(AtomicBool::new(false));
    let verified_writer = verified.clone();

    // Dedicated Ctrl+C watcher that exits immediately
    tokio::spawn(async {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            println!("\n👋 Asistencia remota finalizada por el usuario local (Ctrl+C).");
            std::process::exit(0);
        }
    });

    // Control message receiver loop
    let mut control_task = tokio::spawn(async move {
        while let Some(msg) = control_ws.next().await {
            match msg {
                Ok(tokio_tungstenite::tungstenite::Message::Text(txt)) => {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
                        let t = v.get("type").and_then(|s| s.as_str());
                        if t == Some("totp_verified") || t == Some("code_verified") {
                            info!("✅ ¡Código de verificación aceptado por el operador! Transmisión de pantalla activada.");
                            verified_writer.store(true, Ordering::Relaxed);
                        }
                    }
                }
                Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => {
                    info!("Canal de control cerrado por el servidor.");
                    break;
                }
                Err(e) => {
                    warn!("Error en canal de control: {}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    // Display incoming events (input from operator + client render ACKs)
    let mut input_task = tokio::spawn(async move {
        while let Some(msg) = disp_read.next().await {
            match msg {
                Ok(tokio_tungstenite::tungstenite::Message::Binary(bin)) => {
                    if !bin.is_empty() {
                        let slice = if bin[0] == 0x05 { &bin[1..] } else { &bin[..] };
                        if let Some(input) = duckjump_proto::gfx::Input::decode(slice) {
                            match input {
                                duckjump_proto::gfx::Input::Ack { frame } => {
                                    acked_writer.store(frame, Ordering::Release);
                                    let mut map = sent_ts_input.lock().unwrap();
                                    if let Some(sent_at) = map.remove(&frame) {
                                        let rtt = sent_at.elapsed();
                                        last_rtt_writer.store(rtt.as_micros() as u64, Ordering::Relaxed);
                                        if frame <= 3 {
                                            println!("⏱️ [TRACE] Frame #{} ACK recibido del visor! Latencia RTT: {:.1} ms", frame, rtt.as_secs_f64() * 1000.0);
                                        }
                                    }
                                    if map.len() > 128 {
                                        map.retain(|&f, _| frame.saturating_sub(f) < 120);
                                    }
                                }
                                other => {
                                    input_ctrl.handle_remote_input(other);
                                }
                            }
                        }
                    }
                }
                Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => break,
                Err(e) => {
                    warn!("Display input error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    // Main capture loop (Adaptive up to 60 FPS with real-time telemetry traces)
    println!("Presione Ctrl+C en cualquier momento para finalizar.");
    let mut capturer = capture::create_best_capturer(args.width, args.height);
    println!("🔍 [TRACE] Motor de captura inicializado: {}", capturer.name());

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

    'capture_loop: loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Desconexión solicitada por el usuario local (Ctrl+C).");
                break 'capture_loop;
            }
            _ = &mut control_task => {
                info!("Canal de control cerrado por el servidor.");
                break 'capture_loop;
            }
            _ = &mut input_task => {
                info!("Canal de entrada cerrado por el servidor.");
                break 'capture_loop;
            }
            _ = interval.tick() => {
                if verified.load(Ordering::Relaxed) {
                    if !sent_initial {
                        let t_cap_start = Instant::now();
                        if let Ok(initial_tiles) = capturer.initial_frame() {
                            let cap_dur = t_cap_start.elapsed();
                            let t_send_start = Instant::now();
                            let mut init_bytes = 0usize;
                            let tile_cnt = initial_tiles.len();
                            for tile in initial_tiles {
                                let bytes = tile.encode();
                                init_bytes += bytes.len();
                                if let Err(e) = disp_write.feed(tokio_tungstenite::tungstenite::Message::Binary(bytes.into())).await {
                                    info!("Error o cierre enviando frame inicial: {}", e);
                                    break 'capture_loop;
                                }
                            }
                            frame_counter += 1;
                            let sync = duckjump_proto::gfx::Display::Sync { frame: frame_counter };
                            let sync_bytes = sync.encode();
                            init_bytes += sync_bytes.len();
                            if let Err(_) = disp_write.feed(tokio_tungstenite::tungstenite::Message::Binary(sync_bytes.into())).await {
                                break 'capture_loop;
                            }
                            if let Err(_) = disp_write.flush().await {
                                break 'capture_loop;
                            }
                            let send_dur = t_send_start.elapsed();
                            sent_ts_capture.lock().unwrap().insert(frame_counter, Instant::now());
                            println!(
                                "⏱️ [TRACE] Frame inicial #{} enviado ({} tiles, {:.1} KB) | Captura: {:.1}ms | Red WS: {:.1}ms",
                                frame_counter, tile_cnt, init_bytes as f64 / 1024.0, cap_dur.as_secs_f64() * 1000.0, send_dur.as_secs_f64() * 1000.0
                            );
                            sent_initial = true;
                            last_send_time = Instant::now();
                        }
                    } else {
                        // Adaptive low-latency rate control based on client render ACKs:
                        // Double-buffering: allow up to 2 frames in flight so pipelined 60 FPS is sustained
                        // without waiting for full round trips, but capping maximum buffered lag at ~33ms.
                        let last_ack = acked_reader.load(Ordering::Acquire);
                        let in_flight = frame_counter.saturating_sub(last_ack);
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
                                            if let Err(e) = disp_write.feed(tokio_tungstenite::tungstenite::Message::Binary(b.into())).await {
                                                info!("Sesión cerrada por el servidor ({})", e);
                                                break 'capture_loop;
                                            }
                                        }
                                        frame_counter += 1;
                                        let sync = duckjump_proto::gfx::Display::Sync { frame: frame_counter };
                                        let sync_b = sync.encode();
                                        frame_bytes += sync_b.len();
                                        if let Err(_) = disp_write.feed(tokio_tungstenite::tungstenite::Message::Binary(sync_b.into())).await {
                                            break 'capture_loop;
                                        }
                                        if let Err(_) = disp_write.flush().await {
                                            break 'capture_loop;
                                        }
                                        let send_dur = t_send_start.elapsed();
                                        last_send_time = Instant::now();
                                        sent_ts_capture.lock().unwrap().insert(frame_counter, Instant::now());

                                        if frame_counter <= 3 {
                                            println!(
                                                "⏱️ [TRACE] Frame #{} enviado | Cap: {:.1}ms | Enc: {:.1}ms ({} tiles, {:.1} KB) | Red: {:.1}ms",
                                                frame_counter,
                                                cap_dur.as_secs_f64() * 1000.0,
                                                enc_dur.as_secs_f64() * 1000.0,
                                                tile_cnt,
                                                frame_bytes as f64 / 1024.0,
                                                send_dur.as_secs_f64() * 1000.0,
                                            );
                                        }

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

                        // Periodic 1-second telemetry report:
                        let elapsed = stats_window_start.elapsed();
                        if elapsed >= Duration::from_millis(1000) {
                            if stats_frames > 0 {
                                let fps = stats_frames as f64 / elapsed.as_secs_f64();
                                let avg_cap = (stats_cap_total.as_secs_f64() * 1000.0) / stats_frames as f64;
                                let avg_enc = (stats_enc_total.as_secs_f64() * 1000.0) / stats_frames as f64;
                                let avg_send = (stats_send_total.as_secs_f64() * 1000.0) / stats_frames as f64;
                                let avg_tiles = stats_tiles_total as f64 / stats_frames as f64;
                                let kb_sec = (stats_bytes_total as f64 / 1024.0) / elapsed.as_secs_f64();
                                let rtt_us = last_rtt_reader.load(Ordering::Relaxed);
                                let rtt_str = if rtt_us > 0 {
                                    format!("{:.1}ms", rtt_us as f64 / 1000.0)
                                } else {
                                    "esperando ACK".to_string()
                                };
                                let current_in_flight = frame_counter.saturating_sub(acked_reader.load(Ordering::Acquire));

                                println!(
                                    "⏱️ [TRACE] FPS: {:>4.1} | RTT Visor: {:>7} | Cap: {:>4.1}ms | Enc: {:>4.1}ms ({:>4.1} tiles/f, {:>5.0} KB/s) | Red: {:>4.1}ms | En vuelo: {}",
                                    fps, rtt_str, avg_cap, avg_enc, avg_tiles, kb_sec, avg_send, current_in_flight
                                );

                                if avg_cap > 50.0 {
                                    println!("⚠️ [TRACE ALERTA] Captura lenta ({:.1}ms). Puede deberse a herramienta CLI en vez de X11 directo.", avg_cap);
                                }
                                if rtt_us > 400_000 {
                                    println!("⚠️ [TRACE ALERTA] RTT elevado ({:.1}ms). El visor o la red están acumulando retraso.", rtt_us as f64 / 1000.0);
                                }
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
        }
    }

    control_task.abort();
    input_task.abort();
    let _ = disp_write.close().await;
    println!("\n👋 Asistencia finalizada.");
    std::process::exit(0);
}
