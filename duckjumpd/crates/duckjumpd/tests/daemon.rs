//! End to end through the real binary: the gateway link (plain and TLS), the
//! token check, and a VNC session run in its own worker process and
//! recorded by the parent.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use duckjump_proto::{Control, ErrorCode, Frame, FrameCodec, Hello, Recording, Target, VncParams, PROTOCOL_VERSION};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

const TOKEN: &str = "integration-token-0123456789";
const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/vnc-cert.pem");
const KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/vnc-key.pem");

struct Daemon {
    child: Child,
    addr: String,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn start(recordings: &Path, extra: &[&str]) -> Daemon {
    let addr = format!("127.0.0.1:{}", free_port());
    let child = Command::new(env!("CARGO_BIN_EXE_duckjumpd"))
        .args(["--listen", &addr, "--recordings"])
        .arg(recordings)
        .args(extra)
        .env("DUCKJUMPD_TOKEN", TOKEN)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if TcpStream::connect(&addr).await.is_ok() {
            return Daemon { child, addr };
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("duckjumpd did not start");
}

/// A VNC server with no authentication that accepts one client and then
/// ignores whatever it sends.
async fn fake_vnc() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        s.write_all(b"RFB 003.008\n").await.unwrap();
        let mut v = [0u8; 12];
        s.read_exact(&mut v).await.unwrap();
        s.write_all(&[1, 1]).await.unwrap(); // one type: None
        s.read_u8().await.unwrap();
        s.write_u32(0).await.unwrap(); // SecurityResult ok
        s.read_u8().await.unwrap(); // ClientInit
        s.write_all(&[0, 64, 0, 32]).await.unwrap();
        s.write_all(&[0u8; 16]).await.unwrap();
        s.write_u32(1).await.unwrap();
        s.write_all(b"x").await.unwrap();
        let mut sink = [0u8; 4096];
        while s.read(&mut sink).await.unwrap_or(0) > 0 {}
    });
    port
}

fn hello(token: &str, port: u16, recording: Option<&str>) -> Frame {
    Frame::Control(Control::Hello(Hello {
        version: PROTOCOL_VERSION,
        token: token.into(),
        session_id: "it-session".into(),
        target: Target::Vnc(VncParams {
            host: "127.0.0.1".into(),
            port,
            username: None,
            password: None,
            exclusive: false,
            security: "any".into(),
            cert_fingerprint: None,
            trust_unknown: false,
        }),
        recording: recording.map(|n| Recording { name: n.into(), include_input: false }),
        relay: None,
    }))
}

async fn next<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(c: &mut Framed<S, FrameCodec>) -> Frame {
    tokio::time::timeout(Duration::from_secs(10), c.next()).await.expect("timed out").expect("closed").unwrap()
}

async fn run_vnc_session<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut c: Framed<S, FrameCodec>, rec: &Path) {
    let port = fake_vnc().await;
    c.send(hello(TOKEN, port, Some("it-rec"))).await.unwrap();
    match next(&mut c).await {
        Frame::Control(Control::Ready(r)) => assert_eq!(r.session_id, "it-session"),
        other => panic!("expected ready, got {other:?}"),
    }
    assert!(matches!(next(&mut c).await, Frame::Display(_)), "the desktop size");
    c.send(Frame::Control(Control::Close { reason: None })).await.unwrap();
    while let Some(Ok(f)) = c.next().await {
        if matches!(f, Frame::Control(Control::Exit { .. })) {
            break;
        }
    }
    drop(c);
    // The parent finishes and compresses the recording after the worker exits.
    let gz = rec.join("it-rec.gfx.gz");
    for _ in 0..100 {
        if gz.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no recording at {}", gz.display());
}

/// A scratch directory, removed when dropped.
struct TempDir(std::path::PathBuf);

impl std::ops::Deref for TempDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn vnc_session_in_a_worker_process() {
    let rec = tempdir();
    let d = start(&rec, &[]).await;
    let c = Framed::new(TcpStream::connect(&d.addr).await.unwrap(), FrameCodec);
    run_vnc_session(c, &rec).await;
}

#[tokio::test]
async fn vnc_session_in_process() {
    let rec = tempdir();
    let d = start(&rec, &["--in-process"]).await;
    let c = Framed::new(TcpStream::connect(&d.addr).await.unwrap(), FrameCodec);
    run_vnc_session(c, &rec).await;
}

/// With DUCKJUMP_TEST_S3 and DUCKJUMP_S3_* (make test-s3): the finished recording
/// leaves the local directory for the bucket.
#[tokio::test]
async fn recording_moves_to_s3() {
    if std::env::var("DUCKJUMP_TEST_S3").is_err() {
        return;
    }
    let rec = tempdir();
    let prefix = format!("duckjumpd-it-{}/", free_port());
    let d = start(&rec, &["--s3-prefix", &prefix]).await;
    let mut c = Framed::new(TcpStream::connect(&d.addr).await.unwrap(), FrameCodec);
    let port = fake_vnc().await;
    c.send(hello(TOKEN, port, Some("s3-rec"))).await.unwrap();
    assert!(matches!(next(&mut c).await, Frame::Control(Control::Ready(_))));
    c.send(Frame::Control(Control::Close { reason: None })).await.unwrap();
    while let Some(Ok(f)) = c.next().await {
        if matches!(f, Frame::Control(Control::Exit { .. })) {
            break;
        }
    }
    drop(c);
    // Compressed locally, then uploaded and removed.
    for _ in 0..200 {
        let left: Vec<_> = std::fs::read_dir(&*rec).unwrap().filter_map(|e| e.ok()).collect();
        if left.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("recording still on disk: {:?}", std::fs::read_dir(&*rec).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>());
}

#[tokio::test]
async fn bad_token_is_rejected() {
    let rec = tempdir();
    let d = start(&rec, &[]).await;
    let mut c = Framed::new(TcpStream::connect(&d.addr).await.unwrap(), FrameCodec);
    c.send(hello("wrong-token-0123456789", 1, None)).await.unwrap();
    match next(&mut c).await {
        Frame::Control(Control::Error { code, .. }) => assert_eq!(code, ErrorCode::Unauthorized),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn tls_gateway_link() {
    let rec = tempdir();
    let out = Command::new(env!("CARGO_BIN_EXE_duckjumpd"))
        .args(["--tls-cert", CERT, "--tls-key", KEY, "--print-fingerprint"])
        .env("DUCKJUMPD_TOKEN", TOKEN)
        .output()
        .unwrap();
    let fp = String::from_utf8(out.stdout).unwrap().trim().to_string();
    assert!(fp.starts_with("SHA256:"), "{fp:?}");

    let d = start(&rec, &["--tls-cert", CERT, "--tls-key", KEY]).await;
    // Pinned to another certificate: refused.
    let wrong = duckjump_net::PinnedCert::new(Some(format!("SHA256:{}", "00".repeat(32))));
    let tcp = TcpStream::connect(&d.addr).await.unwrap();
    assert!(duckjump_net::tls_connect(tcp, "duckjumpd", &wrong).await.is_err());

    let pin = duckjump_net::PinnedCert::new(Some(fp));
    let tcp = TcpStream::connect(&d.addr).await.unwrap();
    let tls = duckjump_net::tls_connect(tcp, "duckjumpd", &pin).await.unwrap();
    run_vnc_session(Framed::new(tls, FrameCodec), &rec).await;
}

fn tempdir() -> TempDir {
    let d = std::env::temp_dir().join(format!("duckjumpd-it-{}-{}", std::process::id(), free_port()));
    std::fs::create_dir_all(&d).unwrap();
    TempDir(d)
}

/// File transfer against a real OpenSSH server (deploy/sshd.sh), in a worker
/// process: DUCKJUMP_TEST_SSH=host:port (user duckjump / duckjump123).
#[tokio::test]
async fn sftp_session() {
    let Ok(target) = std::env::var("DUCKJUMP_TEST_SSH") else { return };
    let (host, port) = target.rsplit_once(':').unwrap();
    let rec = tempdir();
    let d = start(&rec, &[]).await;
    let mut c = Framed::new(TcpStream::connect(&d.addr).await.unwrap(), FrameCodec);
    c.send(Frame::Control(Control::Hello(Hello {
        version: PROTOCOL_VERSION,
        token: TOKEN.into(),
        session_id: "sftp-it".into(),
        target: Target::Sftp(duckjump_proto::SshParams {
            host: host.into(),
            port: port.parse().unwrap(),
            username: "duckjump".into(),
            auth: duckjump_proto::SshAuth::Password { password: "duckjump123".into() },
            host_key: None,
            trust_unknown: true,
            term: String::new(),
            cols: 0,
            rows: 0,
        }),
        recording: None,
        relay: None,
    })))
    .await
    .unwrap();
    match next(&mut c).await {
        Frame::Control(Control::Ready(r)) => assert!(r.host_key_fingerprint.is_some()),
        other => panic!("{other:?}"),
    }
    let name = format!("dj-{}.bin", free_port());
    let body: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 256) as u8).collect();

    // Upload in chunks.
    c.send(Frame::Control(Control::FsWrite { path: name.clone(), size: body.len() as u64, overwrite: false })).await.unwrap();
    for chunk in body.chunks(50_000) {
        c.send(Frame::Input(bytes::Bytes::copy_from_slice(chunk))).await.unwrap();
    }
    c.send(Frame::Control(Control::FsEnd)).await.unwrap();
    assert!(matches!(next(&mut c).await, Frame::Control(Control::FsDone { bytes }) if bytes == body.len() as u64));

    // It is listed.
    c.send(Frame::Control(Control::FsList { path: String::new() })).await.unwrap();
    match next(&mut c).await {
        Frame::Control(Control::FsEntries { entries, .. }) => {
            let e = entries.iter().find(|e| e.name == name).expect("uploaded file listed");
            assert_eq!(e.size, body.len() as u64);
            assert!(!e.dir);
        }
        other => panic!("{other:?}"),
    }

    // Download it back.
    c.send(Frame::Control(Control::FsRead { path: name.clone() })).await.unwrap();
    assert!(matches!(next(&mut c).await, Frame::Control(Control::FsMeta { size }) if size == body.len() as u64));
    let mut got = Vec::new();
    loop {
        match next(&mut c).await {
            Frame::Output(b) => got.extend_from_slice(&b),
            Frame::Control(Control::FsDone { bytes }) => {
                assert_eq!(bytes, body.len() as u64);
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(got, body);

    // No silent overwrite; a failure leaves the session usable.
    c.send(Frame::Control(Control::FsWrite { path: name.clone(), size: 1, overwrite: false })).await.unwrap();
    c.send(Frame::Input(bytes::Bytes::from_static(b"x"))).await.unwrap();
    c.send(Frame::Control(Control::FsEnd)).await.unwrap();
    assert!(matches!(next(&mut c).await, Frame::Control(Control::Error { code: ErrorCode::FsFailed, .. })));
    c.send(Frame::Control(Control::FsRead { path: "/nonexistent/x".into() })).await.unwrap();
    assert!(matches!(next(&mut c).await, Frame::Control(Control::Error { code: ErrorCode::FsFailed, .. })));
    c.send(Frame::Control(Control::FsWrite { path: name.clone(), size: 2, overwrite: true })).await.unwrap();
    c.send(Frame::Input(bytes::Bytes::from_static(b"ok"))).await.unwrap();
    c.send(Frame::Control(Control::FsEnd)).await.unwrap();
    assert!(matches!(next(&mut c).await, Frame::Control(Control::FsDone { bytes: 2 })));
    c.send(Frame::Control(Control::Close { reason: None })).await.unwrap();
}
