//! DJTP control messages (JSON, internally tagged by `type`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    /// First frame from the gateway. Carries already-resolved credentials:
    /// the end user never sees them (credential injection).
    Hello(Hello),
    /// Daemon accepted the session and the remote side is connected.
    Ready(Ready),
    Resize { cols: u16, rows: u16 },
    /// Either side ends the session.
    Close { reason: Option<String> },
    /// The session ended on the remote side: process exit status (SSH), and
    /// why, when the server said (e.g. another login took over an RDP session).
    Exit {
        status: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Clipboard text, either direction (graphical sessions).
    Clipboard { text: String },
    /// Request a full screen update (e.g. when a new participant joins).
    Refresh,
    Error { code: ErrorCode, message: String },

    // File transfer sessions (Target::Sftp): one operation at a time.
    /// List a directory ("" = the login directory).
    FsList {
        #[serde(default)]
        path: String,
    },
    /// Answer to FsList; `path` is the directory, canonicalized.
    FsEntries { path: String, entries: Vec<FsEntry> },
    /// Read a file: answered by FsMeta, its bytes in Output frames, FsDone.
    FsRead { path: String },
    FsMeta {
        #[serde(default)]
        size: u64,
    },
    /// Write a file: its bytes follow in Input frames, then FsEnd; answered
    /// by FsDone. Refused when the file exists, unless overwrite.
    FsWrite {
        path: String,
        #[serde(default)]
        size: u64,
        #[serde(default)]
        overwrite: bool,
    },
    FsEnd,
    FsDone {
        #[serde(default)]
        bytes: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FsEntry {
    pub name: String,
    pub dir: bool,
    #[serde(default)]
    pub link: bool,
    pub size: u64,
    /// Unix seconds.
    #[serde(default)]
    pub mtime: Option<u32>,
    #[serde(default)]
    pub mode: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Unauthorized,
    UnsupportedVersion,
    UnsupportedProtocol,
    HostKeyMismatch,
    /// No key pinned and trust on first use not allowed: the daemon stopped
    /// before authenticating. The message is the fingerprint the server
    /// showed, for an admin to verify and approve.
    HostKeyUnknown,
    AuthFailed,
    /// The server needs credentials and the connection has none: the client
    /// should ask the user and retry with them.
    CredentialsRequired,
    ConnectFailed,
    /// A file operation failed (not found, permission denied…); the
    /// session stays usable for the next one.
    FsFailed,
    Internal,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub version: u16,
    /// Shared secret between gateway and daemon.
    pub token: String,
    /// Gateway-assigned session id, used for logs and recording names.
    pub session_id: String,
    #[serde(flatten)]
    pub target: Target,
    #[serde(default)]
    pub recording: Option<Recording>,
    /// Reach the target through the gateway's edge relay instead of dialing
    /// it directly (hosts behind an edge agent).
    #[serde(default)]
    pub relay: Option<Relay>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Relay {
    pub addr: String,
    pub ticket: String,
    /// The relay speaks TLS with the certificate of this fingerprint
    /// ("SHA256:<hex>" of its DER), checked before the ticket is sent.
    #[serde(default)]
    pub tls_fingerprint: Option<String>,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay").field("addr", &self.addr).finish_non_exhaustive()
    }
}

// Hand-written so credentials never end up in logs.
impl std::fmt::Debug for Hello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hello")
            .field("version", &self.version)
            .field("session_id", &self.session_id)
            .field("target", &self.target)
            .field("recording", &self.recording)
            .field("relay", &self.relay)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "protocol", content = "params", rename_all = "snake_case")]
pub enum Target {
    Ssh(SshParams),
    /// File transfer over SFTP, with the same connection and credential
    /// settings as SSH (cols/rows unused).
    Sftp(SshParams),
    Vnc(VncParams),
    Rdp(RdpParams),
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct RdpParams {
    pub host: String,
    #[serde(default = "default_rdp_port")]
    pub port: u16,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub domain: Option<String>,
    /// "nla" (CredSSP), "tls", or "any" (let the server pick; default).
    #[serde(default = "default_rdp_security")]
    pub security: String,
    /// Expected SHA-256 fingerprint of the server's TLS public key
    /// ("SHA256:<hex>"). None: see `trust_unknown`.
    #[serde(default)]
    pub cert_fingerprint: Option<String>,
    /// With no fingerprint, accept the server's key and report it in Ready
    /// (trust on first use). Otherwise stop with HostKeyUnknown before
    /// sending credentials.
    #[serde(default)]
    pub trust_unknown: bool,
    pub width: u16,
    pub height: u16,
}

fn default_rdp_port() -> u16 {
    3389
}

fn default_rdp_security() -> String {
    "any".into()
}

impl std::fmt::Debug for RdpParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RdpParams")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("security", &self.security)
            .field("size", &(self.width, self.height))
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct VncParams {
    pub host: String,
    #[serde(default = "default_vnc_port")]
    pub port: u16,
    /// Username, for VeNCrypt Plain authentication.
    #[serde(default)]
    pub username: Option<String>,
    /// VNC password (classic VNC authentication, or VeNCrypt Plain).
    #[serde(default)]
    pub password: Option<String>,
    /// Ask the server for exclusive access instead of sharing the desktop.
    #[serde(default)]
    pub exclusive: bool,
    /// "any": TLS (VeNCrypt X.509) when the server offers it, else what it
    /// offers. "tls": refuse servers that do not offer TLS.
    #[serde(default = "default_vnc_security")]
    pub security: String,
    /// Expected fingerprint of the server's TLS certificate (DER).
    #[serde(default)]
    pub cert_fingerprint: Option<String>,
    /// Like RdpParams::trust_unknown.
    #[serde(default)]
    pub trust_unknown: bool,
}

fn default_vnc_security() -> String {
    "any".into()
}

fn default_vnc_port() -> u16 {
    5900
}

impl std::fmt::Debug for VncParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VncParams")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("security", &self.security)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshParams {
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    /// Expected host key fingerprint (`SHA256:...`). None: see
    /// `trust_unknown`.
    #[serde(default)]
    pub host_key: Option<String>,
    /// With no host key, accept the server's and report it in `Ready` so the
    /// gateway pins it (trust on first use). Otherwise the daemon stops with
    /// HostKeyUnknown before authenticating: no credential reaches a server
    /// nobody verified.
    #[serde(default)]
    pub trust_unknown: bool,
    #[serde(default = "default_term")]
    pub term: String,
    pub cols: u16,
    pub rows: u16,
}

fn default_ssh_port() -> u16 {
    22
}

fn default_term() -> String {
    "xterm-256color".into()
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum SshAuth {
    Password { password: String },
    PrivateKey { key: String, passphrase: Option<String> },
}

impl std::fmt::Debug for SshAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshAuth::Password { .. } => f.write_str("Password(<redacted>)"),
            SshAuth::PrivateKey { .. } => f.write_str("PrivateKey(<redacted>)"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recording {
    /// File name (no directories) inside the daemon's recording directory.
    pub name: String,
    /// Also record keystrokes. Off by default because it captures whatever
    /// the user types, including passwords for sudo and the like.
    #[serde(default)]
    pub include_input: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ready {
    pub session_id: String,
    pub host_key_fingerprint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_json_shape() {
        let json = r#"{
            "type": "hello", "version": 1, "token": "t", "session_id": "s1",
            "protocol": "ssh",
            "params": {
                "host": "10.0.0.5", "username": "root", "cols": 80, "rows": 24,
                "auth": {"method": "password", "password": "hunter2"}
            }
        }"#;
        let Control::Hello(h) = serde_json::from_str(json).unwrap() else {
            panic!("not hello")
        };
        let Target::Ssh(p) = &h.target else { panic!("not ssh") };
        assert_eq!(p.port, 22);
        assert_eq!(p.term, "xterm-256color");
        assert!(!format!("{h:?}").contains("hunter2"));
        assert!(!format!("{h:?}").contains("token"));
    }
}
