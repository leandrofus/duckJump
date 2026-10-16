//! Reaching session targets: directly, or through the gateway's edge relay.

use anyhow::Context;
use palta_proto::Relay;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Opens the TCP connection to the target: directly, or through the gateway's
/// edge relay (`<ticket>\n` answered by `ok\n` or `err <reason>\n`).
pub async fn dial(host: &str, port: u16, relay: Option<&Relay>) -> anyhow::Result<TcpStream> {
    let Some(relay) = relay else {
        return Ok(TcpStream::connect((host, port)).await?);
    };
    let mut s = TcpStream::connect(&relay.addr)
        .await
        .with_context(|| format!("edge relay {}", relay.addr))?;
    s.write_all(format!("{}\n", relay.ticket).as_bytes()).await?;
    // Byte by byte: what follows the status line belongs to the target
    // protocol (an SSH banner, an RFB version string).
    let mut line = Vec::new();
    loop {
        let b = s.read_u8().await.context("edge relay closed")?;
        if b == b'\n' {
            break;
        }
        anyhow::ensure!(line.len() < 4096, "edge relay: status line too long");
        line.push(b);
    }
    match String::from_utf8_lossy(&line).as_ref() {
        "ok" => Ok(s),
        other => anyhow::bail!("edge relay: {}", other.trim_start_matches("err ")),
    }
}

