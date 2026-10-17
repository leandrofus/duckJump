//! The gateway endpoints the app uses. Sessions are the gateway's
//! `duckjump_session` cookie, kept in the client's cookie jar whether it
//! came from a password login or from single sign-on.

use std::sync::Arc;
use std::time::Duration;

use reqwest::cookie::Jar;
use serde::{Deserialize, Serialize};
use url::Url;

const CSRF_HEADER: &str = "X-DuckJump-Request";
const SESSION_COOKIE: &str = "duckjump_session";

/// An error the gateway answered with, or a transport failure.
#[derive(Debug)]
pub struct ApiError {
    /// HTTP status (0: no answer).
    pub status: u16,
    /// The gateway's error code ("invalid_credentials", "mfa_required"…).
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.status == 0 {
            write!(f, "{}", self.message)
        } else {
            write!(f, "{} (HTTP {})", self.message, self.status)
        }
    }
}

impl std::error::Error for ApiError {}

impl From<reqwest::Error> for ApiError {
    fn from(e: reqwest::Error) -> Self {
        let message = if e.is_connect() || e.is_timeout() {
            "no se pudo conectar con el servidor".to_string()
        } else if e.is_decode() {
            format!("respuesta inesperada del servidor: {e}")
        } else {
            e.to_string()
        };
        ApiError { status: 0, code: "transport".into(), message }
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OidcProvider {
    pub name: String,
    pub login_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthProviders {
    pub local: bool,
    pub oidc: Option<OidcProvider>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub role: String,
}

/// A connection available to the user in the portal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PortalConnection {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub environment: String,
    pub description: String,
    #[serde(default)]
    pub folder_path: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub record: bool,
    #[serde(default)]
    pub credentials: String,
    #[serde(default)]
    pub can_upload: bool,
    #[serde(default)]
    pub can_download: bool,
    #[serde(default)]
    pub can_forward: bool,
    #[serde(default)]
    pub virtual_host: String,
}

/// The answer to a password login: a user, or a TOTP step to go.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoginOutcome {
    pub user: Option<User>,
    pub mfa_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SupportRequest {
    /// Empty: the gateway uses the logged-in user.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub target_name: String,
    pub reason: String,
    pub ticket: String,
    pub account_type: String,
    pub domain: String,
    pub hostname: String,
    pub client_os: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SupportSession {
    pub id: String,
    pub token: String,
    #[serde(default)]
    pub join_url: String,
    pub target_name: String,
    #[serde(default)]
    pub verification_code: String,
    pub status: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SupportStatus {
    pub id: String,
    pub status: String,
    pub target_name: String,
    pub connected_at: Option<String>,
    pub activated_at: Option<String>,
    pub ended_at: Option<String>,
    pub expires_at: String,
}

impl SupportStatus {
    /// The session can no longer be used.
    pub fn is_over(&self) -> bool {
        matches!(self.status.as_str(), "ended" | "expired" | "canceled" | "rejected")
    }
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
    message: String,
}

#[derive(Deserialize)]
struct AppToken {
    token: String,
    user: User,
}

#[derive(Deserialize)]
struct Me {
    user: User,
    mfa_pending: bool,
}

/// A gateway and the session held with it.
#[derive(Clone)]
pub struct Gateway {
    base: Url,
    http: reqwest::Client,
    jar: Arc<Jar>,
    session_token: Arc<std::sync::RwLock<Option<String>>>,
}

/// Accepts "gw:8088", "http://gw:8088/" or "https://gw"; the path is dropped.
pub fn normalize_server(raw: &str) -> std::result::Result<Url, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("ingrese la URL del servidor".into());
    }
    let with_scheme = if raw.contains("://") { raw.to_string() } else { format!("http://{raw}") };
    let mut u = Url::parse(&with_scheme).map_err(|e| format!("URL de servidor inválida: {e}"))?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return Err("el servidor debe ser http:// o https://".into());
    }
    if u.host_str().is_none() {
        return Err("la URL del servidor no tiene host".into());
    }
    u.set_path("/");
    u.set_query(None);
    u.set_fragment(None);
    Ok(u)
}

impl Gateway {
    pub fn new(server: &str) -> std::result::Result<Self, String> {
        let base = normalize_server(server)?;
        let jar = Arc::new(Jar::default());
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .cookie_provider(jar.clone())
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("duckjump-assist-app/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Gateway { base, http, jar, session_token: Arc::new(std::sync::RwLock::new(None)) })
    }

    /// The server URL without the trailing slash, as the agent wants it.
    pub fn server(&self) -> String {
        self.base.as_str().trim_end_matches('/').to_string()
    }

    pub fn url(&self, path: &str) -> Url {
        self.base.join(path.trim_start_matches('/')).expect("relative path")
    }

    /// Current session token if authenticated.
    pub fn session_token(&self) -> Option<String> {
        self.session_token.read().unwrap().clone()
    }

    /// Uses a session token obtained elsewhere (single sign-on).
    pub fn set_session(&self, token: &str) {
        *self.session_token.write().unwrap() = Some(token.to_string());
        self.jar.add_cookie_str(&format!("{SESSION_COOKIE}={token}; Path=/"), &self.base);
    }

    async fn check(resp: reqwest::Response) -> Result<reqwest::Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let body = resp.text().await.unwrap_or_default();
        let (code, message) = match serde_json::from_str::<ErrorBody>(&body) {
            Ok(e) => (e.error, e.message),
            Err(_) => ("http".to_string(), if body.trim().is_empty() { status.to_string() } else { body.trim().to_string() }),
        };
        Err(ApiError { status: status.as_u16(), code, message })
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let resp = self.http.get(self.url(path)).send().await?;
        Ok(Self::check(resp).await?.json().await?)
    }

    async fn post<B: Serialize + ?Sized, T: for<'de> Deserialize<'de>>(&self, path: &str, body: &B) -> Result<T> {
        let req = self.http.post(self.url(path)).header(CSRF_HEADER, "1").json(body);
        let resp = Self::check(req.send().await?).await?;
        Ok(resp.json().await?)
    }

    /// A POST whose answer body does not matter.
    async fn post_empty(&self, path: &str) -> Result<()> {
        let req = self.http.post(self.url(path)).header(CSRF_HEADER, "1");
        Self::check(req.send().await?).await?;
        Ok(())
    }

    pub async fn providers(&self) -> Result<AuthProviders> {
        self.get("/api/v1/auth/providers").await
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<LoginOutcome> {
        let req = self.http.post(self.url("/api/v1/auth/login")).header(CSRF_HEADER, "1").json(&serde_json::json!({"username": username, "password": password}));
        let resp = Self::check(req.send().await?).await?;
        for c in resp.cookies() {
            if c.name() == SESSION_COOKIE {
                *self.session_token.write().unwrap() = Some(c.value().to_string());
            }
        }
        Ok(resp.json().await?)
    }

    pub async fn login_totp(&self, code: &str) -> Result<User> {
        let req = self.http.post(self.url("/api/v1/auth/totp")).header(CSRF_HEADER, "1").json(&serde_json::json!({"code": code}));
        let resp = Self::check(req.send().await?).await?;
        for c in resp.cookies() {
            if c.name() == SESSION_COOKIE {
                *self.session_token.write().unwrap() = Some(c.value().to_string());
            }
        }
        let out: LoginOutcome = resp.json().await?;
        out.user.ok_or_else(|| ApiError { status: 0, code: "mfa".into(), message: "el servidor no completó el inicio de sesión".into() })
    }

    /// The logged-in user, if the session is fully open.
    pub async fn me(&self) -> Result<Option<User>> {
        match self.get::<Me>("/api/v1/auth/me").await {
            Ok(me) if !me.mfa_pending => Ok(Some(me.user)),
            Ok(_) => Ok(None),
            Err(e) if e.status == 401 => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn logout(&self) -> Result<()> {
        *self.session_token.write().unwrap() = None;
        self.post_empty("/api/v1/auth/logout").await
    }

    /// Trades a single sign-on loopback code for a session, and keeps it.
    pub async fn redeem_sso_code(&self, code: &str, verifier: &str) -> Result<User> {
        let t: AppToken = self.post("/api/v1/auth/oidc/token", &serde_json::json!({"code": code, "code_verifier": verifier})).await?;
        self.set_session(&t.token);
        Ok(t.user)
    }

    /// Fetches all connections available to the current user in the portal.
    pub async fn portal_connections(&self) -> Result<Vec<PortalConnection>> {
        self.get("/api/v1/portal/connections").await
    }

    pub async fn request_support(&self, req: &SupportRequest) -> Result<SupportSession> {
        self.post("/api/v1/support/request", req).await
    }

    pub async fn support_status(&self, token: &str) -> Result<SupportStatus> {
        self.get(&format!("/api/v1/support/status/{token}")).await
    }

    pub async fn end_support(&self, token: &str) -> Result<()> {
        self.post_empty(&format!("/api/v1/support/end/{token}")).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_urls() {
        assert_eq!(normalize_server("gw:8088").unwrap().as_str(), "http://gw:8088/");
        assert_eq!(normalize_server(" https://gw.example.com/ui/#x ").unwrap().as_str(), "https://gw.example.com/");
        assert!(normalize_server("").is_err());
        assert!(normalize_server("ftp://gw").is_err());
        let g = Gateway::new("http://gw:8088/").unwrap();
        assert_eq!(g.server(), "http://gw:8088");
        assert_eq!(g.url("/api/v1/auth/me").as_str(), "http://gw:8088/api/v1/auth/me");
    }

    #[test]
    fn statuses_that_end_the_session() {
        let mut s = SupportStatus {
            id: "i".into(),
            status: "active".into(),
            target_name: "t".into(),
            connected_at: None,
            activated_at: None,
            ended_at: None,
            expires_at: "2026-10-16T00:00:00Z".into(),
        };
        assert!(!s.is_over());
        s.status = "expired".into();
        assert!(s.is_over());
    }

    #[test]
    fn support_request_omits_empty_target() {
        let v = serde_json::to_value(SupportRequest { reason: "VPN".into(), ..Default::default() }).unwrap();
        assert!(v.get("target_name").is_none());
    }
}
