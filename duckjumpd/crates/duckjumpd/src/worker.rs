//! Session worker processes. Every session runs in a process of its own
//! (like guacd's per-connection processes): RDP in `duckjumpd-rdp`, SSH and VNC
//! in `duckjumpd worker` (this executable). A worker speaks DJTP on stdin/stdout;
//! this module relays frames between it and the gateway and records the
//! session here, in the trusted process. A crash, a leak or a compromise in
//! one session's protocol stack stays inside its worker.
//!
//! `duckjumpd --in-process` keeps SSH and VNC in the daemon instead.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context;
use futures::{SinkExt, StreamExt};
use duckjump_proto::gfx::OP_SIZE;
use duckjump_proto::{Control, ErrorCode, Frame, FrameCodec, Hello, Recording, Target};
use tokio::process::Command;
use tokio_util::codec::{Framed, FramedRead, FramedWrite};
use tracing::{info, warn};

use crate::recording::{GfxRecorder, Recorder};
use crate::session::{reject, Conn};

/// First argument that turns duckjumpd into a worker.
pub const ARG: &str = "worker";

const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// Worker side: reads the Hello from stdin and runs the session.
pub async fn serve() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,russh=warn".into()),
        )
        .init();
    let io: duckjump_net::Stream = Box::new(tokio::io::join(tokio::io::stdin(), tokio::io::stdout()));
    let mut conn: Conn = Framed::new(io, FrameCodec);
    let hello = match tokio::time::timeout(HELLO_TIMEOUT, conn.next()).await.context("waiting for hello")? {
        Some(Ok(Frame::Control(Control::Hello(h)))) => h,
        Some(Ok(_)) => anyhow::bail!("expected hello"),
        Some(Err(e)) => return Err(e.into()),
        None => return Ok(()),
    };
    let span = tracing::info_span!("worker", session = %hello.session_id);
    let _g = span.enter();
    // Recording happens in the parent: the worker never gets a recording plan.
    match hello.target {
        Target::Ssh(p) => crate::ssh::run(&hello.session_id, p, hello.relay, &mut conn, None).await,
        Target::Vnc(p) => crate::vnc::run(&hello.session_id, p, hello.relay, &mut conn, None).await,
        Target::Sftp(p) => crate::sftp::run(&hello.session_id, p, hello.relay, &mut conn).await,
        Target::Rdp(_) => anyhow::bail!("RDP runs in duckjumpd-rdp"),
    }
}

/// What the parent records.
enum Rec {
    None,
    /// Terminal: header written once the worker says Ready.
    Cast { spec: Option<Recorder>, active: Option<Recorder>, cols: u16, rows: u16, term: String },
    /// Graphical: starts with the first SIZE (its header holds the size).
    Gfx { dir: PathBuf, spec: Recording, active: Option<GfxRecorder> },
}

/// Parent side: starts `worker` (with `args`), hands it the Hello and relays
/// the session.
pub async fn relay(mut hello: Hello, conn: &mut Conn, worker: &Path, args: &[&str], recording: Option<(&Path, Recording)>) -> anyhow::Result<()> {
    let mut rec = match (&hello.target, recording) {
        (_, None) => Rec::None,
        (Target::Ssh(p), Some((dir, spec))) => Rec::Cast {
            spec: Some(Recorder::create(dir, &spec)?),
            active: None,
            cols: p.cols,
            rows: p.rows,
            term: p.term.clone(),
        },
        (_, Some((dir, spec))) => Rec::Gfx { dir: dir.to_owned(), spec, active: None },
    };

    let mut child = match Command::new(worker)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            reject(conn, ErrorCode::Internal, "the session worker could not be started").await;
            return Err(e).with_context(|| format!("starting {}", worker.display()));
        }
    };
    let mut to_worker = FramedWrite::new(child.stdin.take().unwrap(), FrameCodec);
    let mut from_worker = FramedRead::new(child.stdout.take().unwrap(), FrameCodec);

    // The worker needs the target, not the gateway's token or our recording plan.
    hello.token = String::new();
    hello.recording = None;
    to_worker.send(Frame::Control(Control::Hello(hello))).await?;

    let mut flush_tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            f = from_worker.next() => match f {
                Some(Ok(frame)) => {
                    let mut done = false;
                    match (&frame, &mut rec) {
                        (Frame::Control(Control::Ready(_)), Rec::Cast { spec, active, cols, rows, term }) => {
                            if let Some(mut r) = spec.take() {
                                r.header(*cols, *rows, term)?;
                                *active = Some(r);
                            }
                        }
                        (Frame::Output(b), Rec::Cast { active: Some(r), .. }) => r.output(b)?,
                        (Frame::Display(b), Rec::Gfx { dir, spec, active }) => {
                            if active.is_none() && b.first() == Some(&OP_SIZE) && b.len() >= 5 {
                                let (w, h) = (u16::from_be_bytes([b[1], b[2]]), u16::from_be_bytes([b[3], b[4]]));
                                *active = Some(GfxRecorder::create(dir, spec, w, h)?);
                            }
                            if let Some(r) = active.as_mut() { r.display(b)?; }
                        }
                        _ => {}
                    }
                    // A failed file operation leaves the session open.
                    if matches!(&frame, Frame::Control(Control::Exit { .. }))
                        || matches!(&frame, Frame::Control(Control::Error { code, .. }) if *code != ErrorCode::FsFailed)
                    {
                        done = true;
                    }
                    conn.send(frame).await?;
                    if done { break; }
                }
                Some(Err(e)) => { warn!("session worker sent a bad frame: {e}"); break; }
                None => {
                    // Worker gone without saying goodbye: it crashed.
                    reject(conn, ErrorCode::Internal, "the session worker stopped unexpectedly").await;
                    break;
                }
            },
            f = conn.next() => match f {
                Some(Ok(frame @ (Frame::Input(_) | Frame::InputEvent(_) | Frame::Control(Control::Clipboard { .. } | Control::Resize { .. }
                    | Control::FsList { .. } | Control::FsRead { .. } | Control::FsWrite { .. } | Control::FsEnd)))) => {
                    match (&frame, &mut rec) {
                        (Frame::Input(b), Rec::Cast { active: Some(r), .. }) => r.input(b)?,
                        (Frame::Control(Control::Resize { cols, rows }), Rec::Cast { active: Some(r), .. }) => r.resize(*cols, *rows)?,
                        (Frame::InputEvent(b), Rec::Gfx { active: Some(r), .. }) => r.input(b)?,
                        _ => {}
                    }
                    if to_worker.send(frame).await.is_err() { break; }
                }
                Some(Ok(Frame::Control(Control::Close { .. }))) | None => {
                    let _ = to_worker.send(Frame::Control(Control::Close { reason: None })).await;
                    break;
                }
                Some(Ok(other)) => warn!(?other, "unexpected frame from gateway"),
                Some(Err(e)) => { warn!("gateway connection: {e}"); break; }
            },
            _ = flush_tick.tick() => match &mut rec {
                Rec::Cast { active: Some(r), .. } => r.flush_if_due()?,
                Rec::Gfx { active: Some(r), .. } => r.flush_if_due()?,
                _ => {}
            },
        }
    }

    // Give the worker a moment to disconnect cleanly, then make sure it is gone.
    drop(to_worker);
    match tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
        Ok(Ok(st)) => info!(status = %st, "session worker exited"),
        _ => {
            warn!("session worker did not exit; killing it");
            let _ = child.kill().await;
        }
    }
    let finished = match rec {
        Rec::Cast { active: Some(r), .. } => Some(tokio::task::spawn_blocking(move || r.finish()).await?),
        // Created, but the session never started (no gateway record points at it).
        Rec::Cast { spec: Some(r), .. } => {
            r.discard();
            None
        }
        Rec::Gfx { active: Some(r), .. } => Some(tokio::task::spawn_blocking(move || r.finish()).await?),
        _ => None,
    };
    match finished {
        Some(Ok(path)) => info!(recording = %path.display(), "recording saved"),
        Some(Err(e)) => warn!("finishing recording: {e}"),
        None => {}
    }
    Ok(())
}
