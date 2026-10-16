//! Single sign-on for a native app (RFC 8252): listen on a loopback port,
//! send the browser to the gateway's login with our redirect_uri, state and
//! PKCE challenge, wait for the redirect back, and redeem the one-time code
//! with the verifier. The session token never travels in a URL.

use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use crate::api::{Gateway, User};

/// How long the user has to finish signing in in the browser.
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

fn random_b64(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("system random source");
    URL_SAFE_NO_PAD.encode(b)
}

/// The S256 challenge of a verifier.
pub fn challenge_of(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// What the loopback redirect brought back.
#[derive(Debug, PartialEq)]
pub enum Callback {
    Code(String),
    Error(String),
    /// Not the callback (a favicon request, a wrong state…): keep waiting.
    Ignore,
}

/// Reads the target of an HTTP request line ("GET /callback?code=… HTTP/1.1").
pub fn parse_callback(request_head: &str, path: &str, state: &str) -> Callback {
    let Some(target) = request_head.lines().next().and_then(|l| l.split_whitespace().nth(1)) else {
        return Callback::Ignore;
    };
    let Ok(u) = Url::parse(&format!("http://loopback{target}")) else {
        return Callback::Ignore;
    };
    if u.path() != path {
        return Callback::Ignore;
    }
    let get = |k: &str| u.query_pairs().find(|(n, _)| n == k).map(|(_, v)| v.into_owned());
    if get("state").as_deref() != Some(state) {
        return Callback::Ignore;
    }
    if let Some(e) = get("error") {
        return Callback::Error(e);
    }
    match get("code") {
        Some(c) if !c.is_empty() => Callback::Code(c),
        _ => Callback::Ignore,
    }
}

const PAGE_OK: &str = "Autenticación completada. Ya puede cerrar esta pestaña y volver a duckJump Assist.";
const PAGE_ERR: &str = "No se pudo iniciar sesión. Vuelva a duckJump Assist para ver el detalle.";

fn page(msg: &str) -> String {
    let body = format!(
        "<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\"><title>duckJump Assist</title>\
         <style>body{{font-family:system-ui,sans-serif;background:#0f1b2d;color:#e8eef7;display:grid;place-items:center;height:100vh;margin:0}}\
         p{{max-width:28rem;text-align:center;font-size:1.05rem;line-height:1.5}}</style></head><body><p>{msg}</p></body></html>"
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

async fn read_head(conn: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
        let n = conn.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// The URL that starts the login in the browser.
pub fn login_url(gw: &Gateway, login_path: &str, redirect: &str, state: &str, challenge: &str) -> Url {
    let mut u = gw.url(login_path);
    u.query_pairs_mut()
        .append_pair("redirect_uri", redirect)
        .append_pair("state", state)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256");
    u
}

/// Runs the whole flow; `open_browser` shows the login page to the user.
pub async fn login_with(
    gw: &Gateway,
    login_path: &str,
    open_browser: impl FnOnce(&str) -> std::io::Result<()>,
) -> anyhow::Result<User> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let path = "/callback";
    let redirect = format!("http://127.0.0.1:{port}{path}");
    let state = random_b64(16);
    let verifier = random_b64(32); // 43 characters
    let to = login_url(gw, login_path, &redirect, &state, &challenge_of(&verifier));
    open_browser(to.as_str()).map_err(|e| anyhow::anyhow!("no se pudo abrir el navegador: {e}"))?;

    let wait = async {
        loop {
            let (mut conn, _) = listener.accept().await?;
            let head = read_head(&mut conn).await.unwrap_or_default();
            let cb = parse_callback(&head, path, &state);
            let resp = match &cb {
                Callback::Code(_) => page(PAGE_OK),
                Callback::Error(_) => page(PAGE_ERR),
                Callback::Ignore => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
            };
            let _ = conn.write_all(resp.as_bytes()).await;
            let _ = conn.shutdown().await;
            match cb {
                Callback::Code(c) => return anyhow::Ok(c),
                Callback::Error(e) => anyhow::bail!("el proveedor de identidad rechazó el inicio de sesión: {e}"),
                Callback::Ignore => continue,
            }
        }
    };
    let code = tokio::time::timeout(LOGIN_TIMEOUT, wait)
        .await
        .map_err(|_| anyhow::anyhow!("se agotó el tiempo para iniciar sesión en el navegador"))??;
    Ok(gw.redeem_sso_code(&code, &verifier).await?)
}

/// [`login_with`] the system browser.
pub async fn login(gw: &Gateway, login_path: &str) -> anyhow::Result<User> {
    login_with(gw, login_path, |u| open::that_detached(u)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge() {
        // RFC 7636, appendix B.
        assert_eq!(challenge_of("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assert_eq!(random_b64(32).len(), 43);
    }

    #[test]
    fn callbacks() {
        let h = |t: &str| format!("GET {t} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert_eq!(parse_callback(&h("/callback?code=abc&state=s1"), "/callback", "s1"), Callback::Code("abc".into()));
        assert_eq!(parse_callback(&h("/callback?error=denied&state=s1"), "/callback", "s1"), Callback::Error("denied".into()));
        assert_eq!(parse_callback(&h("/callback?code=abc&state=other"), "/callback", "s1"), Callback::Ignore);
        assert_eq!(parse_callback(&h("/favicon.ico"), "/callback", "s1"), Callback::Ignore);
        assert_eq!(parse_callback("garbage", "/callback", "s1"), Callback::Ignore);
    }

    /// The browser side: follows the login URL to the loopback redirect,
    /// as the gateway would after the identity provider.
    #[tokio::test]
    async fn loopback_flow_against_a_fake_gateway() {
        let gw_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = gw_listener.local_addr().unwrap();
        // Fake gateway: answers POST /api/v1/auth/oidc/token.
        tokio::spawn(async move {
            loop {
                let (mut c, _) = gw_listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = c.read(&mut buf).await.unwrap();
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let ok = req.starts_with("POST /api/v1/auth/oidc/token") && req.contains("\"code\":\"one-time\"")
                        && req.to_ascii_lowercase().contains("x-duckjump-request: 1");
                    let body = if ok {
                        r#"{"token":"sess-tok","user":{"id":"u1","username":"bob"}}"#
                    } else {
                        r#"{"error":"invalid_code","message":"invalid or expired code"}"#
                    };
                    let status = if ok { "200 OK" } else { "401 Unauthorized" };
                    let resp = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    c.write_all(resp.as_bytes()).await.unwrap();
                });
            }
        });
        let gw = Gateway::new(&format!("http://{gw_addr}")).unwrap();
        let user = login_with(&gw, "/api/v1/auth/oidc/login", |u| {
            let u = Url::parse(u).unwrap();
            let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
            assert_eq!(q["code_challenge_method"], "S256");
            assert_eq!(q["code_challenge"].len(), 43);
            let back = format!("{}?state={}&code=one-time", q["redirect_uri"], q["state"]);
            tokio::spawn(async move {
                // A stray request first: it must not end the wait.
                let _ = reqwest::get(Url::parse(&back).unwrap().join("/favicon.ico").unwrap()).await;
                reqwest::get(back).await.unwrap();
            });
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(user.username, "bob");
    }
}
