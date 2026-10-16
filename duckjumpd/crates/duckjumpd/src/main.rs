//! duckjumpd: session daemon. Rust replacement for guacd speaking DJTP.

mod rdp;
mod recording;
mod rfb;
mod s3;
mod session;
mod sftp;
mod ssh;
mod vnc;
mod worker;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Config {
    /// Address to listen on. Keep it on loopback or a private network: the
    /// gateway hands duckjumpd live credentials.
    #[arg(long, env = "DUCKJUMPD_LISTEN", default_value = "127.0.0.1:4823")]
    pub listen: String,

    /// Shared secret the gateway must present in `Hello`.
    /// Can also come from --token-file, or from the systemd credential
    /// `duckjumpd-token` (LoadCredential=), keeping it out of the environment.
    #[arg(long, env = "DUCKJUMPD_TOKEN", hide_env_values = true, default_value = "")]
    pub token: String,

    /// File holding the shared secret (instead of --token).
    #[arg(long, env = "DUCKJUMPD_TOKEN_FILE")]
    pub token_file: Option<PathBuf>,

    /// Where session recordings are written.
    #[arg(long, env = "DUCKJUMPD_RECORDINGS", default_value = "./recordings")]
    pub recordings: PathBuf,

    /// The RDP worker binary (default: duckjumpd-rdp next to this executable).
    #[arg(long, env = "DUCKJUMPD_RDP_WORKER")]
    pub rdp_worker: Option<PathBuf>,

    /// Serve the gateway link over TLS 1.3 with this certificate (PEM), for
    /// a gateway on another host. The gateway pins it (DUCKJUMPD_TLS_FINGERPRINT).
    #[arg(long, env = "DUCKJUMPD_TLS_CERT", requires = "tls_key")]
    pub tls_cert: Option<PathBuf>,

    /// Private key for --tls-cert (PEM).
    #[arg(long, env = "DUCKJUMPD_TLS_KEY", requires = "tls_cert")]
    pub tls_key: Option<PathBuf>,

    /// Print the fingerprint of --tls-cert (for DUCKJUMPD_TLS_FINGERPRINT) and exit.
    #[arg(long)]
    pub print_fingerprint: bool,

    /// Run SSH and VNC sessions inside duckjumpd instead of one worker process
    /// per session (RDP always gets its own process).
    #[arg(long, env = "DUCKJUMPD_IN_PROCESS")]
    pub in_process: bool,

    /// This executable, started as `duckjumpd worker` for each session.
    #[arg(skip)]
    pub self_exe: Option<PathBuf>,

    /// Move finished recordings to this S3-compatible endpoint (e.g.
    /// https://s3.eu-west-1.amazonaws.com, http://minio:9000). The gateway
    /// then reads them from the bucket: no shared disk needed.
    #[arg(long, env = "DUCKJUMP_S3_ENDPOINT")]
    pub s3_endpoint: Option<String>,

    #[arg(long, env = "DUCKJUMP_S3_BUCKET", default_value = "")]
    pub s3_bucket: String,

    #[arg(long, env = "DUCKJUMP_S3_REGION", default_value = "us-east-1")]
    pub s3_region: String,

    /// Object key prefix.
    #[arg(long, env = "DUCKJUMP_S3_PREFIX", default_value = "recordings/")]
    pub s3_prefix: String,

    #[arg(long, env = "DUCKJUMP_S3_ACCESS_KEY", default_value = "")]
    pub s3_access_key: String,

    /// Secret key; or DUCKJUMP_S3_SECRET_KEY_FILE, or the systemd credential s3-secret-key.
    #[arg(long, env = "DUCKJUMP_S3_SECRET_KEY", hide_env_values = true, default_value = "")]
    pub s3_secret_key: String,

    /// Path-style URLs (endpoint/bucket/key), as MinIO wants.
    #[arg(long, env = "DUCKJUMP_S3_PATH_STYLE", value_parser = clap::builder::BoolishValueParser::new(), default_value = "false")]
    pub s3_path_style: bool,

    #[arg(skip)]
    pub upload_kick: Option<Arc<tokio::sync::Notify>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    legacy_env();
    // `duckjumpd worker`: one SSH or VNC session on stdin/stdout, started by duckjumpd.
    if std::env::args().nth(1).as_deref() == Some(worker::ARG) {
        return worker::serve().await;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,russh=warn".into()),
        )
        .init();

    let mut cfg = Config::parse();
    let tls = match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(c), Some(k)) => {
            let cert = std::fs::read(c).with_context(|| format!("reading {}", c.display()))?;
            let key = std::fs::read(k).with_context(|| format!("reading {}", k.display()))?;
            let (conf, fp) = duckjump_net::server_config(&cert, &key)?;
            if cfg.print_fingerprint {
                println!("{fp}");
                return Ok(());
            }
            info!(fingerprint = %fp, "TLS enabled for the gateway link");
            Some(duckjump_net::tokio_rustls::TlsAcceptor::from(Arc::new(conf)))
        }
        _ => {
            anyhow::ensure!(!cfg.print_fingerprint, "--print-fingerprint needs --tls-cert and --tls-key");
            None
        }
    };
    cfg.self_exe = std::env::current_exe().ok();
    if cfg.rdp_worker.is_none() {
        cfg.rdp_worker = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("duckjumpd-rdp")));
    }
    if cfg.token.is_empty() {
        let file = cfg.token_file.clone().or_else(|| {
            let dir = PathBuf::from(std::env::var_os("CREDENTIALS_DIRECTORY")?);
            // paltad-token: its name before the rename.
            ["duckjumpd-token", "paltad-token"].into_iter().map(|n| dir.join(n)).find(|p| p.exists())
        });
        if let Some(f) = file {
            cfg.token = std::fs::read_to_string(&f)
                .with_context(|| format!("reading {}", f.display()))?
                .trim()
                .to_string();
        }
    }
    anyhow::ensure!(cfg.token.len() >= 16, "DUCKJUMPD_TOKEN must be at least 16 characters");
    std::fs::create_dir_all(&cfg.recordings)
        .with_context(|| format!("creating {}", cfg.recordings.display()))?;

    if let Some(endpoint) = cfg.s3_endpoint.clone().filter(|e| !e.is_empty()) {
        let mut secret = cfg.s3_secret_key.clone();
        if secret.is_empty() {
            let file = std::env::var_os("DUCKJUMP_S3_SECRET_KEY_FILE").map(PathBuf::from).or_else(|| {
                let p = PathBuf::from(std::env::var_os("CREDENTIALS_DIRECTORY")?).join("s3-secret-key");
                p.exists().then_some(p)
            });
            if let Some(f) = file {
                secret = std::fs::read_to_string(&f).with_context(|| format!("reading {}", f.display()))?.trim().to_string();
            }
        }
        let s3 = s3::S3::new(&endpoint, &cfg.s3_bucket, &cfg.s3_region, &cfg.s3_access_key, &secret, &cfg.s3_prefix, cfg.s3_path_style)?;
        info!(endpoint = %endpoint, bucket = %cfg.s3_bucket, prefix = %cfg.s3_prefix, "finished recordings go to S3");
        let kick = Arc::new(tokio::sync::Notify::new());
        cfg.upload_kick = Some(kick.clone());
        tokio::spawn(s3::uploader(Arc::new(s3), cfg.recordings.clone(), kick));
    }

    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("binding {}", cfg.listen))?;
    if tls.is_none() && !listener.local_addr()?.ip().is_loopback() {
        warn!(listen = %cfg.listen, "the gateway link is not encrypted and listens beyond this host: add --tls-cert/--tls-key");
    }
    info!(listen = %cfg.listen, isolated = !cfg.in_process, "duckjumpd ready");

    let cfg = Arc::new(cfg);
    loop {
        let (sock, peer) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let (cfg, tls) = (cfg.clone(), tls.clone());
        tokio::spawn(async move {
            let stream: duckjump_net::Stream = match tls {
                Some(acc) => match tokio::time::timeout(std::time::Duration::from_secs(10), acc.accept(sock)).await {
                    Ok(Ok(s)) => Box::new(s),
                    Ok(Err(e)) => return warn!(%peer, "TLS handshake failed: {e}"),
                    Err(_) => return warn!(%peer, "TLS handshake timed out"),
                },
                None => Box::new(sock),
            };
            if let Err(e) = session::handle(stream, cfg).await {
                error!(%peer, "session failed: {e:#}");
            }
        });
    }
}

/// DuckJump used to be called palta: PALTA_* / PALTAD_* variables still work
/// (copied to DUCKJUMP_* / DUCKJUMPD_* when those are unset).
fn legacy_env() {
    for (k, v) in std::env::vars() {
        let new = if let Some(rest) = k.strip_prefix("PALTAD_") {
            format!("DUCKJUMPD_{rest}")
        } else if let Some(rest) = k.strip_prefix("PALTA_") {
            format!("DUCKJUMP_{rest}")
        } else {
            continue;
        };
        if std::env::var_os(&new).is_none() {
            eprintln!("warning: {k} is deprecated; rename it to {new}");
            // Before any other thread reads the environment.
            std::env::set_var(&new, v);
        }
    }
}
