//! What users paste into "join with a code": a bare token, or the
//! technician's invitation link (which also names the gateway); and the
//! `duckjump-assist://join?server=…&token=…` links the join page opens the
//! app with.

use serde::Serialize;
use url::Url;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Invite {
    /// The gateway the link points at; None for a bare token.
    pub server: Option<String>,
    pub token: String,
}

fn valid_token(t: &str) -> bool {
    !t.is_empty() && t.len() <= 128 && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// The URL scheme the app registers.
pub const SCHEME: &str = "duckjump-assist";

/// Reads a `duckjump-assist://join?server=…&token=…` link. Any web page can
/// open one, so the caller must have the user confirm the server.
pub fn parse_app_link(link: &str) -> Result<Invite, String> {
    let u = Url::parse(link.trim()).map_err(|_| "enlace de la aplicación inválido".to_string())?;
    // duckjump-assist://join?… (host "join") or duckjump-assist:join?…
    let action = u.host_str().unwrap_or_else(|| u.path()).trim_matches('/');
    if u.scheme() != SCHEME || action != "join" {
        return Err("enlace de la aplicación inválido".into());
    }
    let get = |k: &str| u.query_pairs().find(|(n, _)| n == k).map(|(_, v)| v.into_owned());
    let token = get("token").filter(|t| valid_token(t)).ok_or("el enlace no trae un token de soporte válido")?;
    let server = get("server").ok_or("el enlace no indica el servidor")?;
    let su = Url::parse(&server).map_err(|_| "el servidor del enlace es inválido".to_string())?;
    if (su.scheme() != "http" && su.scheme() != "https") || su.host_str().is_none() || !su.username().is_empty() {
        return Err("el servidor del enlace debe ser http:// o https://".into());
    }
    let origin = su.origin().ascii_serialization();
    Ok(Invite { server: Some(origin), token })
}

pub fn parse(input: &str) -> Result<Invite, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("ingrese el código o el enlace de invitación".into());
    }
    if s.starts_with(&format!("{SCHEME}:")) {
        return parse_app_link(s);
    }
    if valid_token(s) {
        return Ok(Invite { server: None, token: s.to_string() });
    }
    let u = Url::parse(s).map_err(|_| "no es un código ni un enlace de invitación válido".to_string())?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return Err("el enlace debe ser http:// o https://".into());
    }
    let segs: Vec<&str> = u.path_segments().map(|p| p.filter(|s| !s.is_empty()).collect()).unwrap_or_default();
    let token = segs
        .windows(2)
        .find(|w| w[0] == "join")
        .map(|w| w[1])
        .filter(|t| valid_token(t))
        .ok_or_else(|| "el enlace no contiene un token de soporte (…/support/join/<token>)".to_string())?;
    let mut server = u.clone();
    server.set_path("");
    server.set_query(None);
    server.set_fragment(None);
    Ok(Invite { server: Some(server.as_str().trim_end_matches('/').to_string()), token: token.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_and_links() {
        assert_eq!(parse("  a1b2c3  ").unwrap(), Invite { server: None, token: "a1b2c3".into() });
        assert_eq!(
            parse("https://gw.acme.com:8443/support/join/0123abcd?x=1").unwrap(),
            Invite { server: Some("https://gw.acme.com:8443".into()), token: "0123abcd".into() }
        );
        assert_eq!(parse("http://10.0.0.5:8088/join/tok_1").unwrap().token, "tok_1");
        assert!(parse("").is_err());
        assert!(parse("https://gw/support/").is_err());
        assert!(parse("https://gw/support/join/../../x").is_err());
        assert!(parse("file:///support/join/abc").is_err());
        assert!(parse("tok en").is_err());
    }

    #[test]
    fn app_links() {
        let inv = parse_app_link("duckjump-assist://join?server=https%3A%2F%2Fgw.acme.com%3A8443%2Fui&token=abc123").unwrap();
        assert_eq!(inv, Invite { server: Some("https://gw.acme.com:8443".into()), token: "abc123".into() });
        // Pasted into the join box too.
        assert_eq!(parse("duckjump-assist://join?server=http://10.0.0.5:8088&token=t1").unwrap().server.as_deref(), Some("http://10.0.0.5:8088"));
        for bad in [
            "duckjump-assist://join?token=t1",                                    // no server
            "duckjump-assist://join?server=http://gw",                            // no token
            "duckjump-assist://join?server=file:///etc&token=t1",                 // not http
            "duckjump-assist://join?server=http://u:p@gw&token=t1",               // credentials
            "duckjump-assist://join?server=http://gw&token=..%2Fx",               // bad token
            "duckjump-assist://other?server=http://gw&token=t1",                  // other action
            "https://gw/join?server=http://gw&token=t1",                          // other scheme
        ] {
            assert!(parse_app_link(bad).is_err(), "{bad}");
        }
    }
}
