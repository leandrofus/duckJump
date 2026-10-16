//! paltad: session daemon. Rust replacement for guacd speaking PTP.

mod net;
mod rdp;
mod recording;
mod rfb;
mod session;
mod ssh;
mod vnc;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use tokio::net::TcpListener;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Config {
    /// Address to listen on. Keep it on loopback or a private network: the
    /// gateway hands paltad live credentials.
    #[arg(long, env = "PALTAD_LISTEN", default_value = "127.0.0.1:4823")]
    pub listen: String,

    /// Shared secret the gateway must present in `Hello`.
    /// Can also come from --token-file, or from the systemd credential
    /// `paltad-token` (LoadCredential=), keeping it out of the environment.
    #[arg(long, env = "PALTAD_TOKEN", hide_env_values = true, default_value = "")]
    pub token: String,

    /// File holding the shared secret (instead of --token).
    #[arg(long, env = "PALTAD_TOKEN_FILE")]
    pub token_file: Option<PathBuf>,

    /// Where session recordings are written.
    #[arg(long, env = "PALTAD_RECORDINGS", default_value = "./recordings")]
    pub recordings: PathBuf,

    /// The RDP worker binary (default: paltad-rdp next to this executable).
    #[arg(long, env = "PALTAD_RDP_WORKER")]
    pub rdp_worker: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,russh=warn".into()),
        )
        .init();

    let mut cfg = Config::parse();
    if cfg.rdp_worker.is_none() {
        cfg.rdp_worker = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("paltad-rdp")));
    }
    if cfg.token.is_empty() {
        let file = cfg.token_file.clone().or_else(|| {
            let p = PathBuf::from(std::env::var_os("CREDENTIALS_DIRECTORY")?).join("paltad-token");
            p.exists().then_some(p)
        });
        if let Some(f) = file {
            cfg.token = std::fs::read_to_string(&f)
                .with_context(|| format!("reading {}", f.display()))?
                .trim()
                .to_string();
        }
    }
    anyhow::ensure!(cfg.token.len() >= 16, "PALTAD_TOKEN must be at least 16 characters");
    std::fs::create_dir_all(&cfg.recordings)
        .with_context(|| format!("creating {}", cfg.recordings.display()))?;

    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("binding {}", cfg.listen))?;
    info!(listen = %cfg.listen, "paltad ready");

    let cfg = Arc::new(cfg);
    loop {
        let (sock, peer) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = session::handle(sock, cfg).await {
                error!(%peer, "session failed: {e:#}");
            }
        });
    }
}
