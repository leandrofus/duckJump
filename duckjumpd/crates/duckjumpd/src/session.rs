use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use futures::{SinkExt, StreamExt};
use duckjump_proto::{Control, ErrorCode, Frame, FrameCodec, Hello, Target, PROTOCOL_VERSION};
use duckjump_net::Stream;
use tokio_util::codec::Framed;
use tracing::{info, info_span, Instrument};

use crate::Config;

/// The link to the gateway (TCP or TLS), or to the parent duckjumpd in a worker.
pub type Conn = Framed<Stream, FrameCodec>;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn handle(sock: Stream, cfg: Arc<Config>) -> anyhow::Result<()> {
    let mut conn = Framed::new(sock, FrameCodec);

    let first = tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.next())
        .await
        .context("handshake timed out")?;
    let hello = match first {
        Some(Ok(Frame::Control(Control::Hello(h)))) => h,
        Some(Ok(_)) => bail!("expected hello"),
        Some(Err(e)) => return Err(e.into()),
        None => return Ok(()),
    };

    if !constant_time_eq(hello.token.as_bytes(), cfg.token.as_bytes()) {
        reject(&mut conn, ErrorCode::Unauthorized, "bad token").await;
        bail!("rejected hello with bad token");
    }
    if hello.version != PROTOCOL_VERSION {
        let msg = format!("daemon speaks v{PROTOCOL_VERSION}, got v{}", hello.version);
        reject(&mut conn, ErrorCode::UnsupportedVersion, &msg).await;
        bail!(msg);
    }

    let span = info_span!("session", id = %hello.session_id);
    async move {
        info!(target_ = ?hello.target, "session start");
        let res = run(hello, &mut conn, &cfg).await;
        info!("session end");
        // Its recording, if any, is finished now: ship it.
        if let Some(k) = &cfg.upload_kick {
            k.notify_one();
        }
        res
    }
    .instrument(span)
    .await
}

async fn run(hello: Hello, conn: &mut Conn, cfg: &Config) -> anyhow::Result<()> {
    if let Target::Rdp(_) = &hello.target {
        let worker = cfg.rdp_worker.clone().unwrap_or_else(|| "duckjumpd-rdp".into());
        let rec = hello.recording.clone().map(|r| (cfg.recordings.as_path(), r));
        return crate::rdp::run(hello, conn, &worker, rec).await;
    }
    if !cfg.in_process {
        let exe = cfg.self_exe.clone().unwrap_or_else(|| "duckjumpd".into());
        let rec = hello.recording.clone().map(|r| (cfg.recordings.as_path(), r));
        return crate::worker::relay(hello, conn, &exe, &[crate::worker::ARG], rec).await;
    }
    match hello.target {
        Target::Ssh(params) => {
            let recorder = match &hello.recording {
                Some(r) => Some(crate::recording::Recorder::create(&cfg.recordings, r)?),
                None => None,
            };
            crate::ssh::run(&hello.session_id, params, hello.relay, conn, recorder).await
        }
        // The graphical recorder needs the desktop size, known after the handshake.
        Target::Vnc(params) => {
            let rec = hello.recording.map(|r| (cfg.recordings.as_path(), r));
            crate::vnc::run(&hello.session_id, params, hello.relay, conn, rec).await
        }
        Target::Sftp(params) => crate::sftp::run(&hello.session_id, params, hello.relay, conn).await,
        Target::Rdp(_) => unreachable!("handled above"),
    }
}

pub async fn reject(conn: &mut Conn, code: ErrorCode, message: &str) {
    let _ = conn
        .send(Frame::Control(Control::Error { code, message: message.into() }))
        .await;
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
