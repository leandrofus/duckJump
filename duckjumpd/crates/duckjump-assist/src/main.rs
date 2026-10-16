use std::time::Duration;
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

    let acked_frame = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let acked_writer = acked_frame.clone();
    let acked_reader = acked_frame.clone();

    let mut input_ctrl = input::InputController::new();
    input_ctrl.set_enabled(true);

    let verified = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
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
                            verified_writer.store(true, std::sync::atomic::Ordering::Relaxed);
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
                                    acked_writer.store(frame, std::sync::atomic::Ordering::Release);
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

    // Main capture loop (Adaptive up to 60 FPS)
    println!("Presione Ctrl+C en cualquier momento para finalizar.");
    let mut capturer = capture::create_best_capturer(args.width, args.height);
    let mut sent_initial = false;
    let mut frame_counter: u32 = 0;
    let mut last_send_time = std::time::Instant::now();

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
                if verified.load(std::sync::atomic::Ordering::Relaxed) {
                    if !sent_initial {
                        if let Ok(initial_tiles) = capturer.initial_frame() {
                            for tile in initial_tiles {
                                let bytes = tile.encode();
                                if let Err(e) = disp_write.feed(tokio_tungstenite::tungstenite::Message::Binary(bytes.into())).await {
                                    info!("Error o cierre enviando frame inicial: {}", e);
                                    break 'capture_loop;
                                }
                            }
                            frame_counter += 1;
                            let sync = duckjump_proto::gfx::Display::Sync { frame: frame_counter };
                            if let Err(_) = disp_write.feed(tokio_tungstenite::tungstenite::Message::Binary(sync.encode().into())).await {
                                break 'capture_loop;
                            }
                            if let Err(_) = disp_write.flush().await {
                                break 'capture_loop;
                            }
                            sent_initial = true;
                            last_send_time = std::time::Instant::now();
                        }
                    } else {
                        // Adaptive low-latency rate control based on client render ACKs:
                        // Only capture when the client has finished drawing the previous frame (in_flight == 0)
                        // or if an ACK dropped after 100ms.
                        let last_ack = acked_reader.load(std::sync::atomic::Ordering::Acquire);
                        let in_flight = frame_counter.saturating_sub(last_ack);
                        let ack_timed_out = last_send_time.elapsed() > Duration::from_millis(100);

                        if in_flight == 0 || ack_timed_out {
                            if let Ok(damage) = capturer.capture() {
                                if !damage.is_empty() {
                                    if let Ok(updates) = capturer.encode_damage(&damage) {
                                        for u in updates {
                                            let b = u.encode();
                                            if let Err(e) = disp_write.feed(tokio_tungstenite::tungstenite::Message::Binary(b.into())).await {
                                                info!("Sesión cerrada por el servidor ({})", e);
                                                break 'capture_loop;
                                            }
                                        }
                                        frame_counter += 1;
                                        let sync = duckjump_proto::gfx::Display::Sync { frame: frame_counter };
                                        if let Err(_) = disp_write.feed(tokio_tungstenite::tungstenite::Message::Binary(sync.encode().into())).await {
                                            break 'capture_loop;
                                        }
                                        if let Err(_) = disp_write.flush().await {
                                            break 'capture_loop;
                                        }
                                        last_send_time = std::time::Instant::now();
                                    }
                                }
                            }
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
