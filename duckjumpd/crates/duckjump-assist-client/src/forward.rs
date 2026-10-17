//! TCP port forwarding client for duckJump.
//!
//! Listens on a local TCP port and bridges connections across a WebSocket
//! tunnel to the duckJump gateway `/api/v1/connections/{id}/forward`.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

use crate::api::normalize_server;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardConfig {
    pub server_url: String,
    pub token: String,
    pub connection_id_or_name: String,
    pub local_bind: String,
    pub local_port: u16,
    pub remote_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardStats {
    pub connection: String,
    pub local_port: u16,
    pub remote_port: Option<u16>,
    pub active_clients: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub running: bool,
    pub error: Option<String>,
}

pub struct ForwardHandle {
    stop_tx: watch::Sender<bool>,
    stats_fn: Arc<dyn Fn() -> ForwardStats + Send + Sync>,
}

impl ForwardHandle {
    pub fn stop(&self) {
        let _ = self.stop_tx.send(true);
    }

    pub fn stats(&self) -> ForwardStats {
        (self.stats_fn)()
    }
}

/// Spawns a local TCP listener forwarding traffic to the gateway over WebSocket.
pub async fn start_forward(cfg: ForwardConfig) -> Result<ForwardHandle, String> {
    let base_url = normalize_server(&cfg.server_url)?;
    let ws_scheme = if base_url.scheme() == "https" { "wss" } else { "ws" };
    let host = base_url.host_str().ok_or_else(|| "URL de servidor sin host".to_string())?;
    let port_part = if let Some(p) = base_url.port() {
        format!(":{p}")
    } else {
        String::new()
    };

    let mut ws_url = format!(
        "{}://{}{}/api/v1/connections/{}/forward?token={}",
        ws_scheme,
        host,
        port_part,
        url::form_urlencoded::byte_serialize(cfg.connection_id_or_name.as_bytes()).collect::<String>(),
        url::form_urlencoded::byte_serialize(cfg.token.as_bytes()).collect::<String>()
    );

    if let Some(rp) = cfg.remote_port {
        ws_url.push_str(&format!("&port={rp}"));
    }

    let bind_addr = format!("{}:{}", cfg.local_bind, cfg.local_port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| format!("no se pudo escuchar en {bind_addr}: {e}"))?;

    let bound_port = listener
        .local_addr()
        .map(|a| a.port())
        .unwrap_or(cfg.local_port);

    let (stop_tx, mut stop_rx) = watch::channel(false);
    let bytes_sent = Arc::new(AtomicU64::new(0));
    let bytes_received = Arc::new(AtomicU64::new(0));
    let active_clients = Arc::new(AtomicU32::new(0));
    let running = Arc::new(AtomicBool::new(true));

    let stats_sent = bytes_sent.clone();
    let stats_recvd = bytes_received.clone();
    let stats_active = active_clients.clone();
    let stats_running = running.clone();
    let conn_name = cfg.connection_id_or_name.clone();
    let remote_port = cfg.remote_port;

    let stats_fn = Arc::new(move || ForwardStats {
        connection: conn_name.clone(),
        local_port: bound_port,
        remote_port,
        active_clients: stats_active.load(Ordering::Relaxed),
        bytes_sent: stats_sent.load(Ordering::Relaxed),
        bytes_received: stats_recvd.load(Ordering::Relaxed),
        running: stats_running.load(Ordering::Relaxed),
        error: None,
    });

    let loop_running = running.clone();
    let loop_token = cfg.token.clone();
    let loop_ws_url = ws_url.clone();

    tokio::spawn(async move {
        info!(addr = %bind_addr, "TCP forwarder listener started");
        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    if *stop_rx.borrow() {
                        break;
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, peer)) => {
                            debug!(%peer, "Accepted client TCP connection");
                            let client_ws_url = loop_ws_url.clone();
                            let client_token = loop_token.clone();
                            let client_sent = bytes_sent.clone();
                            let client_recvd = bytes_received.clone();
                            let client_active = active_clients.clone();
                            let mut client_stop = stop_rx.clone();

                            tokio::spawn(async move {
                                client_active.fetch_add(1, Ordering::Relaxed);
                                if let Err(e) = proxy_connection(stream, &client_ws_url, &client_token, client_sent, client_recvd, &mut client_stop).await {
                                    warn!("proxy connection error: {e}");
                                }
                                client_active.fetch_sub(1, Ordering::Relaxed);
                            });
                        }
                        Err(e) => {
                            error!("listener accept error: {e}");
                            break;
                        }
                    }
                }
            }
        }
        loop_running.store(false, Ordering::Relaxed);
        info!("TCP forwarder listener stopped");
    });

    Ok(ForwardHandle { stop_tx, stats_fn })
}

async fn proxy_connection(
    stream: TcpStream,
    ws_url: &str,
    token: &str,
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    stop_rx: &mut watch::Receiver<bool>,
) -> Result<(), String> {
    let mut req = ws_url
        .into_client_request()
        .map_err(|e| format!("invalid ws request: {e}"))?;

    // Provide auth via Authorization and Cookie headers in addition to query param
    if !token.is_empty() {
        if let Ok(val) = format!("Bearer {token}").parse() {
            req.headers_mut().insert("Authorization", val);
        }
        if let Ok(val) = format!("duckjump_session={token}").parse() {
            req.headers_mut().insert("Cookie", val);
        }
    }

    let (ws_stream, _) = tokio_tungstenite::connect_async(req)
        .await
        .map_err(|e| format!("websocket connect failed to {ws_url}: {e}"))?;

    let (mut ws_write, mut ws_read) = ws_stream.split();
    let (mut tcp_read, mut tcp_write) = stream.into_split();

    let mut client_stop_tcp = stop_rx.clone();
    let mut client_stop_ws = stop_rx.clone();

    let sent = bytes_sent.clone();
    let tcp_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; 32768];
        loop {
            tokio::select! {
                _ = client_stop_tcp.changed() => {
                    if *client_stop_tcp.borrow() {
                        break;
                    }
                }
                res = tcp_read.read(&mut buf) => {
                    match res {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            sent.fetch_add(n as u64, Ordering::Relaxed);
                            if let Err(e) = ws_write.send(Message::Binary(buf[..n].to_vec().into())).await {
                                debug!("ws send failed: {e}");
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("tcp read error: {e}");
                            break;
                        }
                    }
                }
            }
        }
        let _ = ws_write.close().await;
    });

    let recvd = bytes_received.clone();
    let ws_to_tcp = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = client_stop_ws.changed() => {
                    if *client_stop_ws.borrow() {
                        break;
                    }
                }
                msg = ws_read.next() => {
                    match msg {
                        Some(Ok(Message::Binary(data))) => {
                            recvd.fetch_add(data.len() as u64, Ordering::Relaxed);
                            if let Err(e) = tcp_write.write_all(&data).await {
                                debug!("tcp write error: {e}");
                                break;
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => break,
                        Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                        Some(Err(e)) => {
                            debug!("ws read error: {e}");
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
        let _ = tcp_write.shutdown().await;
    });

    let _ = tokio::join!(tcp_to_ws, ws_to_tcp);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn start_and_stop_forward() {
        let cfg = ForwardConfig {
            server_url: "http://127.0.0.1:8088".into(),
            token: "test-token".into(),
            connection_id_or_name: "test-conn".into(),
            local_bind: "127.0.0.1".into(),
            local_port: 0, // OS assigns port
            remote_port: Some(5432),
        };
        let handle = start_forward(cfg).await.expect("start forward");
        let stats = handle.stats();
        assert!(stats.running);
        assert!(stats.local_port > 0);
        assert_eq!(stats.remote_port, Some(5432));
        assert_eq!(stats.connection, "test-conn");

        handle.stop();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let final_stats = handle.stats();
        assert!(!final_stats.running);
    }
}
