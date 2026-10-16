use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use duckjump_assist::{capture, format_verification_code, input, run_session, CancellationToken, EndReason, Event, SessionConfig};

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

fn print_gone() {
    eprintln!("\n╔════════════════════════════════════════════════════════════════════╗");
    eprintln!("║  ⚠️  SESIÓN DE ASISTENCIA FINALIZADA (HTTP 410 Gone)              ║");
    eprintln!("╠════════════════════════════════════════════════════════════════════╣");
    eprintln!("║  Esta sesión de soporte ya ha concluido o ha expirado.             ║");
    eprintln!("║  Por motivos de seguridad, los enlaces son de un solo uso.         ║");
    eprintln!("║                                                                    ║");
    eprintln!("║  👉 Solicite a su operador técnico que le envíe un nuevo enlace.   ║");
    eprintln!("╚════════════════════════════════════════════════════════════════════╝\n");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(duckjump_assist::DEFAULT_LOG_FILTER)))
        .init();
    let args = Args::parse();
    let fallback_code = args.code.clone().or_else(|| args.totp_secret.clone());

    if args.test {
        info!("Running duckjump-assist self-test...");
        print_banner(Some(&format_verification_code(fallback_code.as_deref().unwrap_or("749201"))));

        let mut capturer = capture::create_best_capturer(args.width, args.height)?;
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

    let Some(server) = args.server else {
        print_banner(Some(&format_verification_code(fallback_code.as_deref().unwrap_or("749201"))));
        println!("Presione Ctrl+C para finalizar.");
        tokio::signal::ctrl_c().await?;
        return Ok(());
    };
    let Some(token) = args.token else {
        anyhow::bail!("Session token is required when connecting to server (use --token <TOKEN>)");
    };

    let cancel = CancellationToken::new();
    tokio::spawn({
        let cancel = cancel.clone();
        async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                cancel.cancel();
            }
        }
    });

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev {
                Event::Code { code } => {
                    print_banner(Some(&code));
                    println!("Presione Ctrl+C en cualquier momento para finalizar.");
                }
                Event::Verified => println!("✅ ¡Código aceptado por el operador! Compartiendo pantalla."),
                Event::Stats { fps, rtt_ms, kb_per_sec, capture_ms } => {
                    let rtt = rtt_ms.map_or("esperando ACK".to_string(), |r| format!("{:.1}ms", r));
                    println!("⏱️ FPS: {:>4.1} | RTT Visor: {:>7} | Cap: {:>4.1}ms | {:>5.0} KB/s", fps, rtt, capture_ms, kb_per_sec);
                }
                _ => {}
            }
        }
    });

    let cfg = SessionConfig { server, token, code: fallback_code, width: args.width, height: args.height };
    match run_session(cfg, tx, cancel).await {
        Ok(EndReason::Expired) => print_gone(),
        Ok(EndReason::NotFound) => eprintln!("\n❌ Error: El token o enlace de soporte no existe o ha expirado (HTTP 404).\n"),
        Ok(EndReason::Local) => println!("\n👋 Asistencia remota finalizada por el usuario local."),
        Ok(EndReason::Server) => println!("\n👋 Asistencia finalizada."),
        Err(e) => {
            eprintln!("\n❌ {:#}\n", e);
            std::process::exit(1);
        }
    }
    Ok(())
}
