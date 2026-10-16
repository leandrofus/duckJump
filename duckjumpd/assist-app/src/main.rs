//! duckJump Assist desktop app. The window (ui/) asks for support or joins
//! a technician's invitation; this process signs in to the gateway and runs
//! the support session in-process (duckjump-assist), forwarding its events
//! to the window as `assist` events. The join page opens it with a
//! `duckjump-assist://join?server=…&token=…` link (`invite` events); the
//! window asks the user to confirm the server before connecting.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::time::Duration;

use serde::Serialize;
use serde_json::json;
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tauri_plugin_deep_link::DeepLinkExt;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use duckjump_assist::{run_session, CancellationToken, EndReason, SessionConfig};
use duckjump_assist_client::{identity, invite, sso, AccountType, AuthProviders, Gateway, Identity, Invite, LoginOutcome, SupportRequest, SupportSession, User};

/// How often the gateway is asked whether the session still stands.
const STATUS_EVERY: Duration = Duration::from_secs(3);
/// How long closing the window waits to tell the gateway.
const END_ON_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

type CmdResult<T> = Result<T, String>;

fn msg(e: impl std::fmt::Display) -> String {
    e.to_string()
}

struct Active {
    server: String,
    token: String,
    cancel: CancellationToken,
}

#[derive(Default)]
struct AppState {
    gw: Mutex<Option<Gateway>>,
    active: Mutex<Option<Active>>,
    /// The last app link, until the window takes it (it may arrive before
    /// the window listens).
    pending_invite: std::sync::Mutex<Option<Invite>>,
}

impl AppState {
    async fn gateway(&self) -> CmdResult<Gateway> {
        self.gw.lock().await.clone().ok_or_else(|| "conéctese primero a un servidor".to_string())
    }
}

#[tauri::command]
fn detect_identity() -> Identity {
    identity::detect()
}

#[tauri::command]
fn parse_invite(input: String) -> CmdResult<Invite> {
    invite::parse(&input)
}

/// The app link the app was opened with, if the window has not seen it.
#[tauri::command]
fn take_pending_invite(state: State<'_, AppState>) -> Option<Invite> {
    state.pending_invite.lock().unwrap().take()
}

/// Links from the OS (at start, or forwarded by a second instance).
fn open_links(app: &AppHandle, links: Vec<String>) {
    let Some(link) = links.into_iter().find(|l| l.starts_with(invite::SCHEME)) else { return };
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
    match invite::parse_app_link(&link) {
        Ok(inv) => {
            *app.state::<AppState>().pending_invite.lock().unwrap() = Some(inv.clone());
            let _ = app.emit("invite", inv);
        }
        Err(e) => {
            let _ = app.emit("invite-error", e);
        }
    }
}

#[derive(Serialize)]
struct Connected {
    server: String,
    providers: AuthProviders,
}

/// Points the app at a gateway (forgetting any session with another one).
#[tauri::command]
async fn connect(state: State<'_, AppState>, server: String) -> CmdResult<Connected> {
    let gw = Gateway::new(&server)?;
    let providers = gw.providers().await.map_err(msg)?;
    let out = Connected { server: gw.server(), providers };
    *state.gw.lock().await = Some(gw);
    Ok(out)
}

#[tauri::command]
async fn login_password(state: State<'_, AppState>, username: String, password: String) -> CmdResult<LoginOutcome> {
    state.gateway().await?.login(username.trim(), &password).await.map_err(msg)
}

#[tauri::command]
async fn login_totp(state: State<'_, AppState>, code: String) -> CmdResult<User> {
    state.gateway().await?.login_totp(code.trim()).await.map_err(msg)
}

#[tauri::command]
async fn login_sso(state: State<'_, AppState>) -> CmdResult<User> {
    let gw = state.gateway().await?;
    let providers = gw.providers().await.map_err(msg)?;
    let oidc = providers.oidc.ok_or_else(|| "el servidor no tiene inicio de sesión único (SSO) configurado".to_string())?;
    sso::login(&gw, &oidc.login_url).await.map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn logout(state: State<'_, AppState>) -> CmdResult<()> {
    if let Some(gw) = state.gw.lock().await.as_ref() {
        let _ = gw.logout().await;
    }
    Ok(())
}

#[tauri::command]
async fn request_support(state: State<'_, AppState>, reason: String, ticket: String, account_type: String) -> CmdResult<SupportSession> {
    let gw = state.gateway().await?;
    let id = identity::detect();
    // The domain only means something for an AD account; the gateway then
    // records the requester as DOMAIN\user.
    let domain = if account_type == "ad" && id.account_type == AccountType::Ad { id.domain.clone() } else { String::new() };
    let req = SupportRequest {
        target_name: String::new(),
        reason: reason.trim().to_string(),
        ticket: ticket.trim().to_string(),
        account_type,
        domain,
        hostname: id.hostname,
        client_os: id.os,
    };
    gw.request_support(&req).await.map_err(msg)
}

/// Starts sharing this screen under the session `token` of `server`.
#[tauri::command]
async fn start_session(app: AppHandle, state: State<'_, AppState>, server: String, token: String, code: Option<String>) -> CmdResult<()> {
    let gw = Gateway::new(&server)?;
    let server = gw.server();
    let cancel = CancellationToken::new();
    {
        let mut active = state.active.lock().await;
        if active.is_some() {
            return Err("ya hay una asistencia en curso".into());
        }
        *active = Some(Active { server: server.clone(), token: token.clone(), cancel: cancel.clone() });
    }

    // Session events → window.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let events_app = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let _ = events_app.emit("assist", ev);
        }
    });

    // The gateway's view: the technician connected, or ended it.
    let poll_app = app.clone();
    let poll_cancel = cancel.clone();
    let poll_token = token.clone();
    tauri::async_runtime::spawn(async move {
        let mut last = String::new();
        loop {
            tokio::select! {
                _ = poll_cancel.cancelled() => return,
                _ = tokio::time::sleep(STATUS_EVERY) => {}
            }
            let Ok(st) = gw.support_status(&poll_token).await else { continue };
            if st.status != last {
                last = st.status.clone();
                let _ = poll_app.emit("assist", json!({"type": "status", "status": st.status}));
            }
            if st.is_over() {
                poll_cancel.cancel();
                return;
            }
        }
    });

    let run_app = app.clone();
    tauri::async_runtime::spawn(async move {
        let cfg = SessionConfig { server: server.clone(), token: token.clone(), code, width: 1280, height: 800 };
        let result = run_session(cfg, tx, cancel.clone()).await;
        cancel.cancel(); // stops the status poll
        let state = run_app.state::<AppState>();
        {
            let mut active = state.active.lock().await;
            if active.as_ref().is_some_and(|a| a.token == token) {
                *active = None;
            }
        }
        let payload = match result {
            Ok(reason) => {
                if reason == EndReason::Local {
                    if let Ok(gw) = Gateway::new(&server) {
                        let _ = gw.end_support(&token).await;
                    }
                }
                json!({"type": "ended", "reason": reason})
            }
            Err(e) => {
                if let Ok(gw) = Gateway::new(&server) {
                    let _ = gw.end_support(&token).await;
                }
                json!({"type": "ended", "reason": "error", "error": format!("{e:#}")})
            }
        };
        let _ = run_app.emit("assist", payload);
    });
    Ok(())
}

/// The user's stop button: ends the session here and at the gateway.
#[tauri::command]
async fn stop_session(state: State<'_, AppState>) -> CmdResult<()> {
    if let Some(a) = state.active.lock().await.as_ref() {
        a.cancel.cancel();
    }
    Ok(())
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    tauri::Builder::default()
        // First: a second launch (opening a link) hands its link over to the
        // running app and exits.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_deep_link::init())
        .manage(AppState::default())
        .setup(|app| {
            // Installers register the scheme; this covers the AppImage, a
            // portable .exe and development builds.
            #[cfg(any(target_os = "linux", windows))]
            if let Err(e) = app.deep_link().register_all() {
                tracing::warn!("could not register the duckjump-assist:// scheme: {e}");
            }
            let handle = app.handle().clone();
            if let Ok(Some(urls)) = app.deep_link().get_current() {
                open_links(&handle, urls.iter().map(|u| u.to_string()).collect());
            }
            app.deep_link().on_open_url(move |ev| open_links(&handle, ev.urls().iter().map(|u| u.to_string()).collect()));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            detect_identity,
            parse_invite,
            take_pending_invite,
            connect,
            login_password,
            login_totp,
            login_sso,
            logout,
            request_support,
            start_session,
            stop_session,
        ])
        .on_window_event(|window, event| {
            // Closing the window is a stop too, and the gateway must know.
            if let WindowEvent::CloseRequested { .. } = event {
                let state = window.state::<AppState>();
                let active = tauri::async_runtime::block_on(state.active.lock()).take();
                if let Some(a) = active {
                    a.cancel.cancel();
                    if let Ok(gw) = Gateway::new(&a.server) {
                        let _ = tauri::async_runtime::block_on(tokio::time::timeout(END_ON_CLOSE_TIMEOUT, gw.end_support(&a.token)));
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running duckJump Assist");
}
