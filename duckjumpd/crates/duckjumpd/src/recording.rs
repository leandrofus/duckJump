//! Session recording in asciicast v2 format (playable with asciinema or
//! asciinema-player in the web UI).
//!
//! Graphical sessions (VNC, RDP) are recorded by [`GfxRecorder`] as the
//! stream of DJTP display operations; see its docs for the format.
//!
//! While the session runs the file is `<name>.cast`, flushed at least once a
//! second so it can be watched live and survives a crash up to the last
//! flush. When the session ends it is compressed to `<name>.cast.gz`
//! (terminal output compresses ~10-30x) and the plain file is removed.

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use flate2::write::GzEncoder;
use flate2::Compression;

use anyhow::{bail, Context};
use duckjump_proto::Recording;
use serde_json::json;

const FLUSH_EVERY: Duration = Duration::from_secs(1);

pub struct Recorder {
    out: BufWriter<File>,
    path: PathBuf,
    start: Instant,
    last_flush: Instant,
    include_input: bool,
    // Bytes of a UTF-8 sequence split across two reads.
    pending_out: Vec<u8>,
    pending_in: Vec<u8>,
}

impl Recorder {
    pub fn create(dir: &Path, spec: &Recording) -> anyhow::Result<Self> {
        let name = &spec.name;
        if name.is_empty()
            || name.starts_with('.')
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        {
            bail!("invalid recording name {name:?}");
        }
        let path = dir.join(format!("{name}.cast"));
        let file = File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        Ok(Self {
            out: BufWriter::new(file),
            path,
            start: Instant::now(),
            last_flush: Instant::now(),
            include_input: spec.include_input,
            pending_out: Vec::new(),
            pending_in: Vec::new(),
        })
    }

    pub fn header(&mut self, cols: u16, rows: u16, term: &str) -> std::io::Result<()> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let h = json!({
            "version": 2, "width": cols, "height": rows, "timestamp": ts,
            "env": {"TERM": term},
        });
        writeln!(self.out, "{h}")
    }

    pub fn output(&mut self, data: &[u8]) -> std::io::Result<()> {
        let text = take_utf8(&mut self.pending_out, data);
        self.event("o", &text)
    }

    pub fn input(&mut self, data: &[u8]) -> std::io::Result<()> {
        if !self.include_input {
            return Ok(());
        }
        let text = take_utf8(&mut self.pending_in, data);
        self.event("i", &text)
    }

    pub fn resize(&mut self, cols: u16, rows: u16) -> std::io::Result<()> {
        self.event("r", &format!("{cols}x{rows}"))
    }

    fn event(&mut self, kind: &str, data: &str) -> std::io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let t = self.start.elapsed().as_secs_f64();
        writeln!(self.out, "{}", json!([t, kind, data]))?;
        if self.last_flush.elapsed() >= FLUSH_EVERY {
            self.out.flush()?;
            self.last_flush = Instant::now();
        }
        Ok(())
    }

    /// Writes buffered events to disk if the last flush is older than
    /// FLUSH_EVERY. The session loop calls it on a timer, so a quiet terminal
    /// still gets its last output on disk.
    pub fn flush_if_due(&mut self) -> std::io::Result<()> {
        if self.last_flush.elapsed() >= FLUSH_EVERY && !self.out.buffer().is_empty() {
            self.out.flush()?;
            self.last_flush = Instant::now();
        }
        Ok(())
    }

    /// Removes the file of a session that never started.
    pub fn discard(self) {
        let path = self.path.clone();
        drop(self.out);
        let _ = std::fs::remove_file(path);
    }

    /// Flushes and compresses the recording. Blocking: run it off the async
    /// executor.
    pub fn finish(mut self) -> std::io::Result<PathBuf> {
        self.out.flush()?;
        drop(self.out);
        compress(&self.path)
    }
}

/// Writes `<path>.gz` (via a temporary file and rename, so a reader never
/// sees half of it) and removes the plain file.
fn compress(path: &Path) -> std::io::Result<PathBuf> {
    let gz = PathBuf::from(format!("{}.gz", path.display()));
    let tmp = PathBuf::from(format!("{}.gz.tmp", path.display()));
    {
        let mut src = BufReader::new(File::open(path)?);
        let mut enc = GzEncoder::new(BufWriter::new(File::create(&tmp)?), Compression::default());
        std::io::copy(&mut src, &mut enc)?;
        enc.finish()?.flush()?;
    }
    std::fs::rename(&tmp, &gz)?;
    std::fs::remove_file(path)?;
    Ok(gz)
}

fn create_file(dir: &Path, spec: &Recording, ext: &str) -> anyhow::Result<(File, PathBuf)> {
    let name = &spec.name;
    if name.is_empty() || name.starts_with('.') || !name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
        bail!("invalid recording name {name:?}");
    }
    let path = dir.join(format!("{name}.{ext}"));
    let file = File::options().write(true).create_new(true).open(&path).with_context(|| format!("creating {}", path.display()))?;
    Ok((file, path))
}

/// Records a graphical session.
///
/// File `<name>.gfx` (gzipped to `.gfx.gz` at the end):
///
/// ```text
/// DJGFX1\n
/// {"version":1,"width":W,"height":H,"timestamp":T}\n
/// then records: f64 BE seconds, u8 kind, u32 BE length, payload
/// ```
///
/// kind 1 is a display payload (duckjump_proto::gfx::Display, encoded); kind 2
/// an input payload: pointer events always (the player draws the pointer),
/// key events only with include_input.
pub struct GfxRecorder {
    out: BufWriter<File>,
    path: PathBuf,
    start: Instant,
    last_flush: Instant,
    include_input: bool,
}

pub const GFX_DISPLAY: u8 = 1;
pub const GFX_INPUT: u8 = 2;

impl GfxRecorder {
    pub fn create(dir: &Path, spec: &Recording, width: u16, height: u16) -> anyhow::Result<Self> {
        let (file, path) = create_file(dir, spec, "gfx")?;
        let mut out = BufWriter::new(file);
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        out.write_all(b"DJGFX1\n")?;
        writeln!(out, "{}", json!({"version": 1, "width": width, "height": height, "timestamp": ts}))?;
        Ok(Self { out, path, start: Instant::now(), last_flush: Instant::now(), include_input: spec.include_input })
    }

    fn record(&mut self, kind: u8, payload: &[u8]) -> std::io::Result<()> {
        self.out.write_all(&self.start.elapsed().as_secs_f64().to_be_bytes())?;
        self.out.write_all(&[kind])?;
        self.out.write_all(&(payload.len() as u32).to_be_bytes())?;
        self.out.write_all(payload)
    }

    pub fn display(&mut self, payload: &[u8]) -> std::io::Result<()> {
        self.record(GFX_DISPLAY, payload)
    }

    /// Records an input event if the policy allows it (pointer always, keys
    /// only with include_input). Acks are never recorded.
    pub fn input(&mut self, payload: &[u8]) -> std::io::Result<()> {
        match payload.first() {
            Some(&duckjump_proto::gfx::IN_POINTER) => self.record(GFX_INPUT, payload),
            Some(&duckjump_proto::gfx::IN_KEY) if self.include_input => self.record(GFX_INPUT, payload),
            _ => Ok(()),
        }
    }

    pub fn flush_if_due(&mut self) -> std::io::Result<()> {
        if self.last_flush.elapsed() >= FLUSH_EVERY && !self.out.buffer().is_empty() {
            self.out.flush()?;
            self.last_flush = Instant::now();
        }
        Ok(())
    }

    pub fn finish(mut self) -> std::io::Result<PathBuf> {
        self.out.flush()?;
        drop(self.out);
        compress(&self.path)
    }
}

/// Appends `data` to `pending` and returns the longest valid UTF-8 prefix,
/// keeping an incomplete trailing sequence for the next call. Invalid bytes
/// are replaced with U+FFFD.
fn take_utf8(pending: &mut Vec<u8>, data: &[u8]) -> String {
    pending.extend_from_slice(data);
    let keep = match std::str::from_utf8(pending) {
        Ok(_) => 0,
        Err(e) if e.error_len().is_none() => pending.len() - e.valid_up_to(),
        Err(_) => 0,
    };
    let tail = pending.split_off(pending.len() - keep);
    let text = String::from_utf8_lossy(pending).into_owned();
    *pending = tail;
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finish_compresses() {
        use std::io::Read;
        let dir = std::env::temp_dir().join(format!("duckjumpd-rec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spec = Recording { name: "t1".into(), include_input: false };
        let mut r = Recorder::create(&dir, &spec).unwrap();
        r.header(80, 24, "xterm").unwrap();
        r.output("hola ñ\r\n".as_bytes()).unwrap();
        let gz = r.finish().unwrap();
        assert!(gz.ends_with("t1.cast.gz"));
        assert!(!dir.join("t1.cast").exists());
        let mut s = String::new();
        flate2::read::GzDecoder::new(File::open(&gz).unwrap()).read_to_string(&mut s).unwrap();
        assert_eq!(s.lines().count(), 2);
        assert!(s.contains("hola ñ"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn utf8_split_across_reads() {
        let mut p = Vec::new();
        let bytes = "ñ🥑".as_bytes();
        assert_eq!(take_utf8(&mut p, &bytes[..1]), "");
        assert_eq!(take_utf8(&mut p, &bytes[1..4]), "ñ");
        assert_eq!(take_utf8(&mut p, &bytes[4..]), "🥑");
        assert!(p.is_empty());
    }
}
