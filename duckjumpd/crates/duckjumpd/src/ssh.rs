//! SSH sessions. Unlike guacd, which renders the terminal server-side into
//! PNG updates, the raw PTY stream is forwarded and the browser renders it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use duckjump_proto::{Control, ErrorCode, Frame, Ready, Relay, SshAuth, SshParams};
use russh::client::{self, AuthResult};
use russh::keys::{decode_secret_key, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use tracing::{info, warn};

use crate::recording::Recorder;
use crate::session::{reject, Conn};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub struct HostKeyCheck {
    expected: Option<String>,
    trust_unknown: bool,
    seen: Arc<Mutex<Option<String>>>,
}

impl client::Handler for HostKeyCheck {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let fp = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let ok = match self.expected.as_deref() {
            Some(e) => e == fp,
            // Unknown key: go on only with trust on first use. Refusing here
            // ends the handshake before any credential is sent.
            None => self.trust_unknown,
        };
        *self.seen.lock().unwrap() = Some(fp);
        Ok(ok)
    }
}

/// An authenticated SSH connection, and the server key it showed.
pub type Client = client::Handle<HostKeyCheck>;

/// Connects and authenticates, telling the gateway why when it fails
/// (unknown or changed host key, bad credentials…).
pub async fn connect(p: &SshParams, relay: Option<&Relay>, conn: &mut Conn) -> anyhow::Result<(Client, Option<String>)> {
    let seen = Arc::new(Mutex::new(None));
    let handler = HostKeyCheck { expected: p.host_key.clone(), trust_unknown: p.trust_unknown, seen: seen.clone() };
    let config = Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    });

    let connect = async {
        let (stream, _) = duckjump_net::dial(&p.host, p.port, relay).await?;
        client::connect_stream(config, stream, handler)
            .await
            .map_err(anyhow::Error::from)
    };
    let mut ssh = match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let fp = seen.lock().unwrap().clone();
            if let (None, Some(fp), false) = (&p.host_key, &fp, p.trust_unknown) {
                reject(conn, ErrorCode::HostKeyUnknown, fp).await;
                anyhow::bail!("host key {fp} not approved yet");
            }
            if p.host_key.is_some() && fp.is_some() && fp != p.host_key {
                let msg = format!("host key mismatch: got {}", fp.unwrap());
                reject(conn, ErrorCode::HostKeyMismatch, &msg).await;
                anyhow::bail!(msg);
            }
            reject(conn, ErrorCode::ConnectFailed, &format!("{e:#}")).await;
            return Err(e).context("ssh connect");
        }
        Err(_) => {
            reject(conn, ErrorCode::ConnectFailed, "timed out").await;
            anyhow::bail!("ssh connect timed out");
        }
    };

    let auth = match &p.auth {
        SshAuth::Password { password } => ssh.authenticate_password(&p.username, password).await,
        SshAuth::PrivateKey { key, passphrase } => {
            let key = match decode_secret_key(key, passphrase.as_deref()) {
                Ok(k) => k,
                Err(e) => {
                    reject(conn, ErrorCode::AuthFailed, "invalid private key").await;
                    return Err(e).context("decoding private key");
                }
            };
            let hash = ssh.best_supported_rsa_hash().await?.flatten();
            ssh.authenticate_publickey(&p.username, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                .await
        }
    }?;
    if !matches!(auth, AuthResult::Success) {
        reject(conn, ErrorCode::AuthFailed, "authentication rejected by server").await;
        anyhow::bail!("ssh auth failed for {}", p.username);
    }
    let fingerprint = seen.lock().unwrap().clone();
    Ok((ssh, fingerprint))
}

pub async fn run(
    session_id: &str,
    p: SshParams,
    relay: Option<Relay>,
    conn: &mut Conn,
    mut rec: Option<Recorder>,
) -> anyhow::Result<()> {
    let (ssh, fingerprint) = connect(&p, relay.as_ref(), conn).await?;

    let mut chan = ssh.channel_open_session().await?;
    chan.request_pty(false, &p.term, p.cols.into(), p.rows.into(), 0, 0, &[])
        .await?;
    chan.request_shell(false).await?;

    if let Some(r) = rec.as_mut() {
        r.header(p.cols, p.rows, &p.term)?;
    }
    conn.send(Frame::Control(Control::Ready(Ready {
        session_id: session_id.into(),
        host_key_fingerprint: fingerprint,
    })))
    .await?;
    info!(host = %p.host, user = %p.username, "ssh shell open");

    let (mut tx, mut rx) = conn.split();
    let mut exit_status = None;
    let mut flush_tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = flush_tick.tick() => {
                if let Some(r) = rec.as_mut() { r.flush_if_due()?; }
            }
            frame = rx.next() => match frame {
                Some(Ok(Frame::Input(data))) => {
                    if let Some(r) = rec.as_mut() { r.input(&data)?; }
                    chan.data(&data[..]).await?;
                }
                Some(Ok(Frame::Control(Control::Resize { cols, rows }))) => {
                    if let Some(r) = rec.as_mut() { r.resize(cols, rows)?; }
                    chan.window_change(cols.into(), rows.into(), 0, 0).await?;
                }
                Some(Ok(Frame::Control(Control::Close { .. }))) | None => break,
                Some(Ok(other)) => warn!(?other, "unexpected frame from gateway"),
                Some(Err(e)) => return Err(e.into()),
            },
            msg = chan.wait() => match msg {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    if let Some(r) = rec.as_mut() { r.output(&data)?; }
                    tx.send(Frame::Output(Bytes::copy_from_slice(&data))).await?;
                }
                Some(ChannelMsg::ExitStatus { exit_status: s }) => exit_status = Some(s),
                // Servers usually send EOF before the exit status; wait for Close.
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            },
        }
    }

    let _ = tx.send(Frame::Control(Control::Exit { status: exit_status, reason: None })).await;
    let _ = ssh.disconnect(Disconnect::ByApplication, "session closed", "").await;
    if let Some(r) = rec {
        match tokio::task::spawn_blocking(move || r.finish()).await? {
            Ok(path) => info!(recording = %path.display(), "recording saved"),
            Err(e) => warn!("finishing recording: {e}"),
        }
    }
    Ok(())
}
