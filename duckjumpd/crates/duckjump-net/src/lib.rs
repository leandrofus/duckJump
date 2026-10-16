//! Reaching session targets: directly, or through the gateway's edge relay
//! (optionally over TLS); and certificate pinning, the way duckjumpd trusts
//! servers and the gateway (by fingerprint, like SSH host keys, not by CA).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use duckjump_proto::Relay;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub use tokio_rustls;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// A byte stream to a target: plain TCP or TLS, chosen at run time.
pub type Stream = Box<dyn AsyncReadWrite + Unpin + Send + Sync>;

/// "SHA256:<hex>" of a certificate's DER, as the gateway computes it.
pub fn fingerprint(der: &[u8]) -> String {
    let sum = Sha256::digest(der);
    let mut s = String::with_capacity(7 + 64);
    s.push_str("SHA256:");
    for b in sum {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Accepts the server certificate whose fingerprint is `expected`, or with
/// none expected any certificate, recording what it saw so the caller can
/// decide (and report it) before sending anything secret. The handshake
/// signatures are still checked: the server proves it holds the key.
#[derive(Debug)]
pub struct PinnedCert {
    pub expected: Option<String>,
    pub seen: Mutex<Option<String>>,
    provider: Arc<CryptoProvider>,
}

impl PinnedCert {
    pub fn new(expected: Option<String>) -> Arc<Self> {
        Arc::new(PinnedCert { expected: expected.map(|e| e.trim().to_ascii_lowercase()).map(|e| e.replacen("sha256:", "SHA256:", 1)), seen: Mutex::new(None), provider: provider() })
    }

    pub fn seen(&self) -> Option<String> {
        self.seen.lock().unwrap().clone()
    }

    /// The certificate was there but not the expected one.
    pub fn mismatch(&self) -> bool {
        matches!((&self.expected, self.seen()), (Some(e), Some(s)) if *e != s)
    }

    pub fn client_config(self: &Arc<Self>) -> rustls::ClientConfig {
        rustls::ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(self.clone())
            .with_no_client_auth()
    }
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = fingerprint(end_entity);
        *self.seen.lock().unwrap() = Some(fp.clone());
        match &self.expected {
            Some(want) if *want != fp => Err(rustls::Error::General(format!("certificate changed: got {fp}"))),
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Wraps `s` in TLS to a server that must present the pinned certificate.
pub async fn tls_connect<S>(s: S, server_name: &str, pin: &Arc<PinnedCert>) -> anyhow::Result<tokio_rustls::client::TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let name = ServerName::try_from(server_name.to_string()).unwrap_or_else(|_| ServerName::try_from("duckjump.invalid").unwrap());
    let connector = tokio_rustls::TlsConnector::from(Arc::new(pin.client_config()));
    Ok(connector.connect(name, s).await?)
}

/// Opens the connection to the target: directly, or through the gateway's
/// edge relay (`<ticket>\n` answered by `ok\n` or `err <reason>\n`), over
/// TLS when the relay has a pinned certificate. Also returns the local
/// address of the TCP connection (RDP puts it in its client info).
pub async fn dial(host: &str, port: u16, relay: Option<&Relay>) -> anyhow::Result<(Stream, SocketAddr)> {
    let Some(relay) = relay else {
        let s = TcpStream::connect((host, port)).await?;
        let _ = s.set_nodelay(true);
        let local = s.local_addr()?;
        return Ok((Box::new(s), local));
    };
    let tcp = TcpStream::connect(&relay.addr)
        .await
        .with_context(|| format!("edge relay {}", relay.addr))?;
    let _ = tcp.set_nodelay(true);
    let local = tcp.local_addr()?;
    let mut s: Stream = match &relay.tls_fingerprint {
        Some(fp) => {
            let pin = PinnedCert::new(Some(fp.clone()));
            let relay_host = relay.addr.rsplit_once(':').map(|(h, _)| h.trim_matches(['[', ']'])).unwrap_or(&relay.addr);
            Box::new(tls_connect(tcp, relay_host, &pin).await.context("edge relay TLS")?)
        }
        None => Box::new(tcp),
    };
    s.write_all(format!("{}\n", relay.ticket).as_bytes()).await?;
    s.flush().await?;
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
        "ok" => Ok((s, local)),
        other => anyhow::bail!("edge relay: {}", other.trim_start_matches("err ")),
    }
}

/// Server side TLS (duckjumpd's listener) from PEM files.
pub fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> anyhow::Result<(rustls::ServerConfig, String)> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::PrivateKeyDer;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<_, _>>()
        .context("reading the certificate")?;
    anyhow::ensure!(!certs.is_empty(), "no certificate in the file");
    let fp = fingerprint(&certs[0]);
    let key = PrivateKeyDer::from_pem_slice(key_pem).context("reading the private key")?;
    let conf = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok((conf, fp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_format() {
        let fp = fingerprint(b"abc");
        assert_eq!(fp, "SHA256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn pin_normalizes_case() {
        let p = PinnedCert::new(Some("sha256:BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD".into()));
        assert_eq!(p.expected.as_deref(), Some(fingerprint(b"abc").as_str()));
    }

    #[tokio::test]
    async fn relay_status_line() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            for answer in ["ok\nSSH-2.0-x", "err no agent\n"] {
                let (mut c, _) = l.accept().await.unwrap();
                let mut buf = [0u8; 7];
                c.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ticket\n");
                c.write_all(answer.as_bytes()).await.unwrap();
            }
        });
        let relay = Relay { addr: addr.clone(), ticket: "ticket".into(), tls_fingerprint: None };
        let (mut s, _) = dial("ignored", 0, Some(&relay)).await.unwrap();
        let mut rest = [0u8; 9];
        s.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"SSH-2.0-x"); // bytes after the status line are the target's
        let err = dial("ignored", 0, Some(&relay)).await.err().unwrap();
        assert!(err.to_string().contains("no agent"), "{err}");
    }
}
