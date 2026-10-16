//! RDP sessions run in a separate worker process, `paltad-rdp` (one per
//! session, like guacd's per-connection processes). It speaks PTP on
//! stdin/stdout; this module relays frames between it and the gateway and
//! records the session here, in the trusted process.
//!
//! Why a separate process: the RDP stack (TLS, CredSSP/NTLM, bitmap codecs)
//! is the most exposed parsing surface, so a crash or compromise stays inside
//! the worker; and IronRDP pins dependency versions that conflict with russh.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context;
use futures::{SinkExt, StreamExt};
use palta_proto::gfx::OP_SIZE;
use palta_proto::{Control, ErrorCode, Frame, FrameCodec, Hello, Recording};
use tokio::process::Command;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{info, warn};

use crate::recording::GfxRecorder;
use crate::session::{reject, Conn};

pub async fn run(mut hello: Hello, conn: &mut Conn, worker: &Path, recording: Option<(&Path, Recording)>) -> anyhow::Result<()> {
    let mut child = match Command::new(worker)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            reject(conn, ErrorCode::Internal, "the RDP worker could not be started").await;
            return Err(e).with_context(|| format!("starting {}", worker.display()));
        }
    };
    let mut to_worker = FramedWrite::new(child.stdin.take().unwrap(), FrameCodec);
    let mut from_worker = FramedRead::new(child.stdout.take().unwrap(), FrameCodec);

    // The worker needs the target, not the gateway's token or our recording plan.
    hello.token = String::new();
    hello.recording = None;
    to_worker.send(Frame::Control(Control::Hello(hello))).await?;

    let mut rec: Option<GfxRecorder> = None;
    let mut flush_tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            f = from_worker.next() => match f {
                Some(Ok(frame)) => {
                    let mut done = false;
                    match &frame {
                        Frame::Display(b) => {
                            // The recorder starts with the first SIZE (its header holds the size).
                            if rec.is_none() && b.first() == Some(&OP_SIZE) && b.len() >= 5 {
                                if let Some((dir, spec)) = recording.as_ref() {
                                    let (w, h) = (u16::from_be_bytes([b[1], b[2]]), u16::from_be_bytes([b[3], b[4]]));
                                    rec = Some(GfxRecorder::create(dir, spec, w, h)?);
                                }
                            }
                            if let Some(r) = rec.as_mut() { r.display(b)?; }
                        }
                        Frame::Control(Control::Exit { .. } | Control::Error { .. }) => done = true,
                        _ => {}
                    }
                    conn.send(frame).await?;
                    if done { break; }
                }
                Some(Err(e)) => { warn!("rdp worker sent a bad frame: {e}"); break; }
                None => {
                    // Worker gone without saying goodbye: it crashed.
                    reject(conn, ErrorCode::Internal, "the RDP worker stopped unexpectedly").await;
                    break;
                }
            },
            f = conn.next() => match f {
                Some(Ok(frame @ Frame::InputEvent(_))) => {
                    if let (Some(r), Frame::InputEvent(b)) = (rec.as_mut(), &frame) { r.input(b)?; }
                    if to_worker.send(frame).await.is_err() { break; }
                }
                Some(Ok(frame @ Frame::Control(Control::Clipboard { .. } | Control::Resize { .. }))) => {
                    if to_worker.send(frame).await.is_err() { break; }
                }
                Some(Ok(Frame::Control(Control::Close { .. }))) | None => {
                    let _ = to_worker.send(Frame::Control(Control::Close { reason: None })).await;
                    break;
                }
                Some(Ok(other)) => warn!(?other, "unexpected frame from gateway"),
                Some(Err(e)) => { warn!("gateway connection: {e}"); break; }
            },
            _ = flush_tick.tick() => {
                if let Some(r) = rec.as_mut() { r.flush_if_due()?; }
            }
        }
    }

    // Give the worker a moment to disconnect cleanly, then make sure it is gone.
    drop(to_worker);
    match tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
        Ok(Ok(st)) => info!(status = %st, "rdp worker exited"),
        _ => {
            warn!("rdp worker did not exit; killing it");
            let _ = child.kill().await;
        }
    }
    if let Some(r) = rec {
        match tokio::task::spawn_blocking(move || r.finish()).await? {
            Ok(path) => info!(recording = %path.display(), "recording saved"),
            Err(e) => warn!("finishing recording: {e}"),
        }
    }
    Ok(())
}
