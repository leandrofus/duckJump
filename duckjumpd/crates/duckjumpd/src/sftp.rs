//! File transfer sessions: SFTP over an SSH connection authenticated like a
//! terminal session (vaulted or prompted credentials, pinned host key). The
//! gateway asks for one operation at a time (DJTP Fs* messages); file bytes
//! travel in Output frames (from the host) and Input frames (to the host).
//! The gateway keeps the copy, the hash and the audit trail.

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use duckjump_proto::{Control, ErrorCode, Frame, FsEntry, Ready, Relay, SshParams};
use russh::Disconnect;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

use crate::session::{reject, Conn};

const CHUNK: usize = 64 << 10;
/// More entries than this in one directory are cut (the UI is no `find`).
const MAX_ENTRIES: usize = 10_000;

pub async fn run(session_id: &str, p: SshParams, relay: Option<Relay>, conn: &mut Conn) -> anyhow::Result<()> {
    let (ssh, fingerprint) = crate::ssh::connect(&p, relay.as_ref(), conn).await?;
    let chan = ssh.channel_open_session().await?;
    if let Err(e) = chan.request_subsystem(true, "sftp").await {
        reject(conn, ErrorCode::ConnectFailed, "the server does not offer SFTP").await;
        return Err(e.into());
    }
    let sftp = match SftpSession::new(chan.into_stream()).await {
        Ok(s) => s,
        Err(e) => {
            reject(conn, ErrorCode::ConnectFailed, &format!("SFTP: {e}")).await;
            return Err(e.into());
        }
    };
    conn.send(Frame::Control(Control::Ready(Ready { session_id: session_id.into(), host_key_fingerprint: fingerprint }))).await?;
    info!(host = %p.host, user = %p.username, "sftp open");

    loop {
        let op = match conn.next().await {
            Some(Ok(Frame::Control(c))) => c,
            Some(Ok(other)) => {
                warn!(?other, "unexpected frame between file operations");
                continue;
            }
            Some(Err(e)) => return Err(e.into()),
            None => break,
        };
        let res = match op {
            Control::FsList { path } => list(&sftp, &path, conn).await,
            Control::FsRead { path } => read(&sftp, &path, conn).await,
            Control::FsWrite { path, size, overwrite } => write(&sftp, &path, size, overwrite, conn).await,
            Control::Close { .. } => break,
            other => {
                warn!(?other, "unexpected control in a file session");
                continue;
            }
        };
        if let Err(e) = res {
            if e.downcast_ref::<Gone>().is_some() {
                break;
            }
            warn!("file operation failed: {e:#}");
            reject(conn, ErrorCode::FsFailed, &format!("{e:#}")).await;
        }
    }
    let _ = sftp.close().await;
    let _ = conn.send(Frame::Control(Control::Exit { status: None, reason: None })).await;
    let _ = ssh.disconnect(Disconnect::ByApplication, "done", "").await;
    Ok(())
}

/// The gateway went away mid-operation.
#[derive(Debug)]
struct Gone;
impl std::fmt::Display for Gone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("gateway closed the session")
    }
}
impl std::error::Error for Gone {}

fn dir_of(path: &str) -> &str {
    if path.is_empty() { "." } else { path }
}

async fn list(sftp: &SftpSession, path: &str, conn: &mut Conn) -> anyhow::Result<()> {
    let dir = sftp.canonicalize(dir_of(path)).await?;
    let mut entries = Vec::new();
    for e in sftp.read_dir(dir.as_str()).await? {
        let name = e.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let m = e.metadata();
        let ft = e.file_type();
        entries.push(FsEntry { name, dir: ft.is_dir(), link: ft.is_symlink(), size: m.size.unwrap_or(0), mtime: m.mtime, mode: m.permissions });
        if entries.len() >= MAX_ENTRIES {
            break;
        }
    }
    entries.sort_by(|a, b| b.dir.cmp(&a.dir).then_with(|| a.name.cmp(&b.name)));
    conn.send(Frame::Control(Control::FsEntries { path: dir, entries })).await?;
    Ok(())
}

async fn read(sftp: &SftpSession, path: &str, conn: &mut Conn) -> anyhow::Result<()> {
    let meta = sftp.metadata(path).await?;
    anyhow::ensure!(!meta.is_dir(), "{path} is a directory");
    let mut f = sftp.open(path).await?;
    conn.send(Frame::Control(Control::FsMeta { size: meta.size.unwrap_or(0) })).await?;
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        total += n as u64;
        conn.send(Frame::Output(Bytes::copy_from_slice(&buf[..n]))).await.map_err(|_| Gone)?;
    }
    conn.send(Frame::Control(Control::FsDone { bytes: total })).await?;
    info!(path, bytes = total, "file read");
    Ok(())
}

async fn write(sftp: &SftpSession, path: &str, size: u64, overwrite: bool, conn: &mut Conn) -> anyhow::Result<()> {
    if !overwrite && sftp.try_exists(path).await? {
        // Drain what the gateway already sent for it.
        drain(conn).await?;
        anyhow::bail!("{path} already exists");
    }
    let mut f = match sftp.open_with_flags(path, OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE).await {
        Ok(f) => f,
        Err(e) => {
            drain(conn).await?;
            return Err(e.into());
        }
    };
    let mut total = 0u64;
    loop {
        match conn.next().await {
            Some(Ok(Frame::Input(b))) => {
                total += b.len() as u64;
                anyhow::ensure!(total <= size, "more data than announced");
                f.write_all(&b).await?;
            }
            Some(Ok(Frame::Control(Control::FsEnd))) => break,
            Some(Ok(other)) => anyhow::bail!("unexpected {other:?} while writing"),
            Some(Err(e)) => return Err(e.into()),
            None => return Err(Gone.into()),
        }
    }
    f.shutdown().await?;
    anyhow::ensure!(total == size, "got {total} of {size} bytes");
    conn.send(Frame::Control(Control::FsDone { bytes: total })).await?;
    info!(path, bytes = total, "file written");
    Ok(())
}

/// Skips an upload's data up to its FsEnd.
async fn drain(conn: &mut Conn) -> anyhow::Result<()> {
    loop {
        match conn.next().await {
            Some(Ok(Frame::Control(Control::FsEnd))) => return Ok(()),
            Some(Ok(_)) => {}
            Some(Err(e)) => return Err(e.into()),
            None => return Err(Gone.into()),
        }
    }
}
