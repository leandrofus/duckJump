//! Who is logged in on this workstation, to prefill the support request.
//! This is a hint for the form, not authentication: the gateway decides who
//! the user is (password or single sign-on).

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountType {
    Local,
    /// Active Directory (or another Kerberos realm).
    Ad,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Identity {
    pub username: String,
    /// The AD domain (NetBIOS or DNS name) when the account is a domain one.
    pub domain: String,
    pub hostname: String,
    pub os: String,
    pub account_type: AccountType,
}

impl Identity {
    /// DOMAIN\user for domain accounts, user otherwise.
    pub fn full_name(&self) -> String {
        if self.account_type == AccountType::Ad && !self.domain.is_empty() {
            format!("{}\\{}", self.domain, self.username)
        } else {
            self.username.clone()
        }
    }
}

/// What detection reads from the system, so tests can supply it.
pub struct Probe<'a> {
    pub os: &'a str,
    pub env: &'a dyn Fn(&str) -> Option<String>,
    pub exists: &'a dyn Fn(&str) -> bool,
}

pub fn detect_with(p: &Probe) -> Identity {
    let env = |k: &str| (p.env)(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let mut username = env("USERNAME").or_else(|| env("USER")).or_else(|| env("LOGNAME")).unwrap_or_default();
    let hostname = env("COMPUTERNAME").or_else(|| env("HOSTNAME")).unwrap_or_else(|| {
        if (p.exists)("/etc/hostname") {
            std::fs::read_to_string("/etc/hostname").map(|h| h.trim().to_string()).unwrap_or_default()
        } else {
            String::new()
        }
    });
    let mut id = Identity { username: String::new(), domain: String::new(), hostname, os: p.os.to_string(), account_type: AccountType::Local };

    if p.os == "windows" {
        // USERDOMAIN is the machine name for local accounts.
        let user_domain = env("USERDOMAIN").unwrap_or_default();
        let computer = env("COMPUTERNAME").unwrap_or_default();
        if !user_domain.is_empty() && !user_domain.eq_ignore_ascii_case(&computer) {
            id.account_type = AccountType::Ad;
            id.domain = env("USERDNSDOMAIN").unwrap_or(user_domain);
        }
    } else if let Some((d, u)) = username.split_once('\\') {
        // winbind style: DOMAIN\user
        id.account_type = AccountType::Ad;
        id.domain = d.to_string();
        username = u.to_string();
    } else if let Some((u, d)) = username.split_once('@') {
        // SSSD style: user@domain
        id.account_type = AccountType::Ad;
        id.domain = d.to_string();
        username = u.to_string();
    } else if env("KRB5CCNAME").is_some() && ((p.exists)("/etc/sssd/sssd.conf") || (p.exists)("/etc/krb5.conf")) {
        // A Kerberos ticket on a realm-joined machine.
        id.account_type = AccountType::Ad;
    }
    id.username = username;
    id
}

/// Detects the identity of the current process.
pub fn detect() -> Identity {
    detect_with(&Probe {
        os: std::env::consts::OS,
        env: &|k| std::env::var(k).ok(),
        exists: &|p| std::path::Path::new(p).exists(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn run(os: &str, vars: &[(&str, &str)], files: &[&str]) -> Identity {
        let vars: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let files: Vec<String> = files.iter().map(|s| s.to_string()).collect();
        detect_with(&Probe { os, env: &|k| vars.get(k).cloned(), exists: &|p| files.iter().any(|f| f == p) })
    }

    #[test]
    fn windows_domain_and_local() {
        let id = run("windows", &[("USERNAME", "micaela"), ("USERDOMAIN", "CORP"), ("USERDNSDOMAIN", "CORP.ACME.COM"), ("COMPUTERNAME", "PC-01")], &[]);
        assert_eq!((id.account_type, id.domain.as_str(), id.hostname.as_str()), (AccountType::Ad, "CORP.ACME.COM", "PC-01"));
        assert_eq!(id.full_name(), "CORP.ACME.COM\\micaela");

        let id = run("windows", &[("USERNAME", "ana"), ("USERDOMAIN", "PC-01"), ("COMPUTERNAME", "pc-01")], &[]);
        assert_eq!((id.account_type, id.full_name().as_str()), (AccountType::Local, "ana"));
    }

    #[test]
    fn linux_variants() {
        let id = run("linux", &[("USER", "micaela@corp.acme.com")], &[]);
        assert_eq!((id.account_type, id.username.as_str(), id.domain.as_str()), (AccountType::Ad, "micaela", "corp.acme.com"));

        let id = run("linux", &[("USER", "CORP\\micaela")], &[]);
        assert_eq!(id.full_name(), "CORP\\micaela");

        let id = run("linux", &[("USER", "rodrigo"), ("KRB5CCNAME", "FILE:/tmp/krb5cc_1000")], &["/etc/sssd/sssd.conf"]);
        assert_eq!(id.account_type, AccountType::Ad);
        // A ticket alone, on a machine with no realm configured, is not enough.
        let id = run("linux", &[("USER", "rodrigo"), ("KRB5CCNAME", "FILE:/tmp/x")], &[]);
        assert_eq!(id.account_type, AccountType::Local);
    }
}
