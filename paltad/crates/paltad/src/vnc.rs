//! VNC sessions: an RFB client (crate::rfb) whose screen updates become PTP
//! display frames (crate::display), with keyboard, pointer and clipboard
//! from the browser.
//!
//! Flow control: after each frame the daemon waits for the client's ACK
//! before asking the server for the next incremental update.

use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use futures::{SinkExt, StreamExt};
use palta_proto::gfx::{Display, Input};
use palta_proto::{Control, ErrorCode, Frame, Ready, Recording, Relay, VncParams};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::recording::GfxRecorder;
use crate::rfb::{self, AuthError, Decoder, Framebuffer, ServerMsg};
use crate::session::{reject, Conn};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

enum FromServer {
    Frame(Vec<Display>),
    Clipboard(String),
    Closed(Option<anyhow::Error>),
}

pub async fn run(
    session_id: &str,
    p: VncParams,
    relay: Option<Relay>,
    conn: &mut Conn,
    recording: Option<(&Path, Recording)>,
) -> anyhow::Result<()> {
    let connect = async {
        let mut s = crate::net::dial(&p.host, p.port, relay.as_ref()).await?;
        let _ = s.set_nodelay(true);
        let init = rfb::handshake(&mut s, p.password.as_deref(), !p.exclusive).await?;
        anyhow::Ok((s, init))
    };
    let (stream, init) = match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            let code = if e.downcast_ref::<AuthError>().is_some() { ErrorCode::AuthFailed } else { ErrorCode::ConnectFailed };
            reject(conn, code, &format!("{e:#}")).await;
            return Err(e).context("vnc connect");
        }
        Err(_) => {
            reject(conn, ErrorCode::ConnectFailed, "timed out").await;
            anyhow::bail!("vnc connect timed out");
        }
    };
    info!(host = %p.host, desktop = %init.name, width = init.width, height = init.height, "vnc connected");

    let (mut rd, mut wr) = tokio::io::split(stream);
    rfb::set_pixel_format(&mut wr).await?;
    rfb::set_encodings(&mut wr, rfb::ENCODINGS).await?;
    rfb::update_request(&mut wr, false, init.width, init.height).await?;

    let mut rec = match recording {
        Some((dir, spec)) => Some(GfxRecorder::create(dir, &spec, init.width, init.height)?),
        None => None,
    };

    // Server side: read, apply to the framebuffer, encode.
    let (tx_srv, mut rx_srv) = mpsc::channel::<FromServer>(4);
    let reader = tokio::spawn(async move {
        let mut fb = Framebuffer::new(init.width, init.height);
        let mut dec = Decoder::default();
        loop {
            let msg = match dec.read(&mut rd, &mut fb).await {
                Ok(m) => m,
                Err(e) => {
                    let eof = e.downcast_ref::<std::io::Error>().is_some_and(|io| io.kind() == std::io::ErrorKind::UnexpectedEof);
                    let _ = tx_srv.send(FromServer::Closed((!eof).then_some(e))).await;
                    return;
                }
            };
            let ev = match msg {
                ServerMsg::Update(damage) => {
                    // Image encoding is CPU work: keep it off the async workers.
                    match tokio::task::block_in_place(|| palta_gfx::encode(&damage, &fb)) {
                        Ok(ops) => FromServer::Frame(ops),
                        Err(e) => FromServer::Closed(Some(e)),
                    }
                }
                ServerMsg::CutText(t) => FromServer::Clipboard(t),
                ServerMsg::Bell => continue,
            };
            if tx_srv.send(ev).await.is_err() {
                return;
            }
        }
    });

    conn.send(Frame::Control(Control::Ready(Ready { session_id: session_id.into(), host_key_fingerprint: None })))
        .await?;
    let size = Display::Size { width: init.width, height: init.height }.encode();
    if let Some(r) = rec.as_mut() {
        r.display(&size)?;
    }
    conn.send(Frame::Display(size)).await?;

    let (width, height) = (init.width, init.height);
    let mut screen = (width, height);
    let mut frame: u32 = 0;
    let mut update_pending = true; // the initial full request
    // After a resize the framebuffer starts black: ask for the whole screen,
    // not just what changes from now on.
    let mut need_full = false;
    let mut flush_tick = tokio::time::interval(Duration::from_secs(1));
    let mut end_reason: Option<String> = None;

    loop {
        tokio::select! {
            ev = rx_srv.recv() => match ev {
                Some(FromServer::Frame(ops)) => {
                    update_pending = false;
                    if ops.is_empty() {
                        rfb::update_request(&mut wr, !need_full, screen.0, screen.1).await?;
                        need_full = false;
                        update_pending = true;
                        continue;
                    }
                    for op in &ops {
                        if let Display::Size { width, height } = op {
                            screen = (*width, *height);
                            need_full = true;
                        }
                        let b = op.encode();
                        if let Some(r) = rec.as_mut() { r.display(&b)?; }
                        conn.send(Frame::Display(b)).await?;
                    }
                    frame = frame.wrapping_add(1);
                    conn.send(Frame::Display(Display::Sync { frame }.encode())).await?;
                }
                Some(FromServer::Clipboard(text)) => {
                    conn.send(Frame::Control(Control::Clipboard { text })).await?;
                }
                Some(FromServer::Closed(err)) => {
                    if let Some(e) = err { warn!("vnc server: {e:#}"); end_reason = Some(format!("{e:#}")); }
                    break;
                }
                None => break,
            },
            f = conn.next() => match f {
                Some(Ok(Frame::InputEvent(b))) => {
                    if let Some(r) = rec.as_mut() { r.input(&b)?; }
                    match Input::decode(&b) {
                        Some(Input::Key { keysym, down, .. }) => rfb::key_event(&mut wr, keysym, down).await?,
                        Some(Input::Pointer { x, y, buttons }) => rfb::pointer_event(&mut wr, buttons, x.min(screen.0.saturating_sub(1)), y.min(screen.1.saturating_sub(1))).await?,
                        Some(Input::Ack { frame: acked }) => {
                            if acked == frame && !update_pending {
                                rfb::update_request(&mut wr, !need_full, screen.0, screen.1).await?;
                                need_full = false;
                                update_pending = true;
                            }
                        }
                        None => warn!("malformed input event"),
                    }
                }
                Some(Ok(Frame::Control(Control::Clipboard { text }))) => rfb::cut_text(&mut wr, &text).await?,
                Some(Ok(Frame::Control(Control::Close { .. }))) | None => break,
                Some(Ok(other)) => warn!(?other, "unexpected frame from gateway"),
                Some(Err(e)) => return Err(e.into()),
            },
            _ = flush_tick.tick() => {
                if let Some(r) = rec.as_mut() { r.flush_if_due()?; }
            }
        }
    }

    reader.abort();
    let _ = wr.shutdown().await;
    if let Some(reason) = end_reason {
        let _ = conn.send(Frame::Control(Control::Error { code: ErrorCode::Internal, message: reason })).await;
    } else {
        let _ = conn.send(Frame::Control(Control::Exit { status: None, reason: None })).await;
    }
    if let Some(r) = rec {
        match tokio::task::spawn_blocking(move || r.finish()).await? {
            Ok(path) => info!(recording = %path.display(), "recording saved"),
            Err(e) => warn!("finishing recording: {e}"),
        }
    }
    Ok(())
}
