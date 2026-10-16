//! Recordings in S3-compatible object storage (AWS S3, MinIO, Ceph…).
//!
//! duckjumpd writes recordings to its local directory while sessions run, as
//! always. Once a recording is finished (compressed to `<name>.cast.gz` or
//! `<name>.gfx.gz`) the uploader moves it to the bucket and removes the local
//! copy; the gateway reads it from there. A failed upload stays on disk and
//! is retried, so an outage of the store loses nothing.
//!
//! Requests are signed with AWS Signature Version 4 (single PUT, up to 5 GiB).

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;
use tracing::{info, warn};

#[derive(Clone)]
pub struct S3 {
    /// e.g. https://s3.eu-west-1.amazonaws.com or http://minio:9000
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    /// Key prefix, e.g. "recordings/".
    pub prefix: String,
    /// https://endpoint/bucket/key (MinIO) instead of https://bucket.endpoint/key.
    pub path_style: bool,
    agent: ureq::Agent,
}

impl std::fmt::Debug for S3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3").field("endpoint", &self.endpoint).field("bucket", &self.bucket).field("prefix", &self.prefix).finish_non_exhaustive()
    }
}

const MAX_PUT: u64 = 5 << 30;

impl S3 {
    pub fn new(endpoint: &str, bucket: &str, region: &str, access_key: &str, secret_key: &str, prefix: &str, path_style: bool) -> anyhow::Result<Self> {
        anyhow::ensure!(endpoint.starts_with("http://") || endpoint.starts_with("https://"), "S3 endpoint must be an http(s) URL");
        anyhow::ensure!(!bucket.is_empty() && !access_key.is_empty() && !secret_key.is_empty(), "S3 needs a bucket, an access key and a secret key");
        let agent = ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(10)).timeout_read(Duration::from_secs(60)).build();
        Ok(S3 {
            endpoint: endpoint.trim_end_matches('/').into(),
            bucket: bucket.into(),
            region: if region.is_empty() { "us-east-1".into() } else { region.into() },
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            prefix: prefix.into(),
            path_style,
            agent,
        })
    }

    /// URL and Host header of an object.
    fn locate(&self, key: &str) -> (String, String, String) {
        let (scheme, host) = self.endpoint.split_once("://").unwrap();
        let path = if self.path_style { format!("/{}/{}", self.bucket, uri_encode(key)) } else { format!("/{}", uri_encode(key)) };
        let host = if self.path_style { host.to_string() } else { format!("{}.{host}", self.bucket) };
        (format!("{scheme}://{host}{path}"), host, path)
    }

    /// The Authorization and x-amz-* headers for a request.
    fn sign(&self, method: &str, host: &str, path: &str, payload_hash: &str, now: SystemTime) -> Vec<(String, String)> {
        let (date, amz_date) = amz_dates(now);
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
        let canonical = format!("{method}\n{path}\n\nhost:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n\n{signed_headers}\n{payload_hash}");
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
        let mut key = hmac(format!("AWS4{}", self.secret_key).as_bytes(), date.as_bytes());
        for part in [self.region.as_str(), "s3", "aws4_request"] {
            key = hmac(&key, part.as_bytes());
        }
        let signature = hex(&hmac(&key, to_sign.as_bytes()));
        vec![
            ("x-amz-date".into(), amz_date),
            ("x-amz-content-sha256".into(), payload_hash.into()),
            ("Authorization".into(), format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}", self.access_key)),
        ]
    }

    fn request(&self, method: &str, key: &str, payload_hash: &str) -> ureq::Request {
        let (url, host, path) = self.locate(key);
        let mut req = self.agent.request(method, &url);
        for (k, v) in self.sign(method, &host, &path, payload_hash, SystemTime::now()) {
            req = req.set(&k, &v);
        }
        req
    }

    /// Uploads a file (blocking). The payload hash is computed first, so the
    /// store rejects a body that changed on the way.
    pub fn put_file(&self, key: &str, path: &Path) -> anyhow::Result<u64> {
        let size = std::fs::metadata(path)?.len();
        if size > MAX_PUT {
            bail!("{} is larger than a single S3 PUT allows (5 GiB)", path.display());
        }
        let mut hasher = Sha256::new();
        std::io::copy(&mut BufReader::new(File::open(path)?), &mut HashWriter(&mut hasher))?;
        let hash = hex(&hasher.finalize());
        let body = BufReader::new(File::open(path)?);
        self.request("PUT", key, &hash)
            .set("Content-Length", &size.to_string())
            .send(body)
            .map_err(describe)
            .with_context(|| format!("uploading {key}"))?;
        Ok(size)
    }

    /// Downloads an object (tests).
    #[cfg(test)]
    pub fn get(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        let resp = self.request("GET", key, &hex(&Sha256::digest(b""))).call().map_err(describe)?;
        use std::io::Read;
        let mut out = Vec::new();
        resp.into_reader().take(MAX_PUT).read_to_end(&mut out)?;
        Ok(out)
    }

    pub fn key_for(&self, file_name: &str) -> String {
        format!("{}{file_name}", self.prefix)
    }
}

fn describe(e: ureq::Error) -> anyhow::Error {
    match e {
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();
            let msg = body.split("<Message>").nth(1).and_then(|m| m.split("</Message>").next()).unwrap_or(&body);
            anyhow::anyhow!("S3 answered {code}: {}", msg.chars().take(300).collect::<String>())
        }
        other => anyhow::anyhow!("S3 unreachable: {other}"),
    }
}

struct HashWriter<'a>(&'a mut Sha256);

impl std::io::Write for HashWriter<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// RFC 3986 encoding of an object key, keeping "/".
fn uri_encode(key: &str) -> String {
    let mut out = String::new();
    for b in key.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// ("YYYYMMDD", "YYYYMMDDTHHMMSSZ") in UTC.
fn amz_dates(t: SystemTime) -> (String, String) {
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let date = format!("{y:04}{m:02}{d:02}");
    let amz = format!("{date}T{:02}{:02}{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60);
    (date, amz)
}

/// Finished recordings waiting in the local directory: `*.cast.gz`, `*.gfx.gz`.
fn pending(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
    let mut out: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with(".cast.gz") || n.ends_with(".gfx.gz")))
        .collect();
    out.sort();
    out
}

/// Moves finished recordings to the bucket: on `kick` (a recording just
/// finished) and every minute (retries).
pub async fn uploader(s3: Arc<S3>, dir: PathBuf, kick: Arc<Notify>) {
    loop {
        let (s3c, dirc) = (s3.clone(), dir.clone());
        let _ = tokio::task::spawn_blocking(move || upload_pending(&s3c, &dirc)).await;
        tokio::select! {
            _ = kick.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
        }
    }
}

/// One pass: uploads every finished recording, deleting each once stored.
pub fn upload_pending(s3: &S3, dir: &Path) -> usize {
    let mut n = 0;
    for path in pending(dir) {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        match s3.put_file(&s3.key_for(&name), &path) {
            Ok(size) => {
                if let Err(e) = std::fs::remove_file(&path) {
                    warn!(recording = %name, "uploaded, but the local copy could not be removed: {e}");
                }
                info!(recording = %name, bytes = size, bucket = %s3.bucket, "recording stored in S3");
                n += 1;
            }
            Err(e) => {
                warn!(recording = %name, "S3 upload failed (kept on disk, retried later): {e:#}");
                break; // the store is likely down: wait for the next pass
            }
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates() {
        let t = UNIX_EPOCH + Duration::from_secs(1_440_938_160); // 2015-08-30T12:36:00Z
        assert_eq!(amz_dates(t), ("20150830".into(), "20150830T123600Z".into()));
        let t = UNIX_EPOCH + Duration::from_secs(951_782_400); // 2000-02-29T00:00:00Z
        assert_eq!(amz_dates(t).1, "20000229T000000Z");
    }

    /// The example in AWS's SigV4 documentation for S3 (GET /test.txt).
    #[test]
    fn signature_matches_aws_example() {
        let s3 = S3::new("https://s3.amazonaws.com", "examplebucket", "us-east-1", "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", false).unwrap();
        let t = UNIX_EPOCH + Duration::from_secs(1_369_353_600); // 20130524T000000Z
        // That example also signs a Range header; without it the signature
        // differs, so check the parts that do not depend on it.
        let h = s3.sign("GET", "examplebucket.s3.amazonaws.com", "/test.txt", &hex(&Sha256::digest(b"")), t);
        assert_eq!(h[0].1, "20130524T000000Z");
        assert!(h[2].1.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="));
        // Signing key derivation, from the same document.
        let mut key = hmac(b"AWS4wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", b"20130524");
        for part in ["us-east-1", "s3", "aws4_request"] {
            key = hmac(&key, part.as_bytes());
        }
        assert_eq!(hex(&key), "dbb893acc010964918f1fd433add87c70e8b0db6be30c1fbeafefa5ec6ba8378");
        assert_eq!(s3.locate("rec/a b.cast.gz").0, "https://examplebucket.s3.amazonaws.com/rec/a%20b.cast.gz");
    }

    /// Against a real store: DUCKJUMP_TEST_S3=1 with DUCKJUMP_S3_* (deploy/minio.sh env).
    #[test]
    fn upload_to_real_store() {
        if std::env::var("DUCKJUMP_TEST_S3").is_err() {
            return;
        }
        let env = |k: &str| std::env::var(k).unwrap_or_default();
        let s3 = S3::new(&env("DUCKJUMP_S3_ENDPOINT"), &env("DUCKJUMP_S3_BUCKET"), &env("DUCKJUMP_S3_REGION"), &env("DUCKJUMP_S3_ACCESS_KEY"),
            &env("DUCKJUMP_S3_SECRET_KEY"), "duckjumpd-test/", env("DUCKJUMP_S3_PATH_STYLE") == "1").unwrap();
        let dir = std::env::temp_dir().join(format!("duckjumpd-s3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let body: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(dir.join("t1.cast.gz"), &body).unwrap();
        std::fs::write(dir.join("t2.cast"), b"still recording").unwrap();
        assert_eq!(upload_pending(&s3, &dir), 1);
        assert!(!dir.join("t1.cast.gz").exists(), "local copy kept");
        assert!(dir.join("t2.cast").exists(), "a live recording was uploaded");
        assert_eq!(s3.get("duckjumpd-test/t1.cast.gz").unwrap(), body);
        let bad = S3 { secret_key: "wrong".into(), ..s3.clone() };
        std::fs::write(dir.join("t3.gfx.gz"), b"x").unwrap();
        assert_eq!(upload_pending(&bad, &dir), 0);
        assert!(dir.join("t3.gfx.gz").exists(), "a failed upload must stay on disk");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
