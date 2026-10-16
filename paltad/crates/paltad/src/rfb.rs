//! RFB (VNC) client, written from the protocol spec (RFC 6143 plus the
//! common extensions). It keeps the remote framebuffer in memory and reports
//! what changed, so the display encoder can turn it into tiles.
//!
//! Pixel format: we ask the server for 32 bpp true colour, little-endian,
//! red/green/blue at shifts 16/8/0, so a raw pixel arrives as B, G, R, X.

use anyhow::{bail, ensure, Context};
use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockEncrypt, KeyInit};
use flate2::{Decompress, FlushDecompress, Status};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const ENC_RAW: i32 = 0;
pub const ENC_COPYRECT: i32 = 1;
pub const ENC_ZRLE: i32 = 16;
pub const ENC_DESKTOP_SIZE: i32 = -223;
pub const ENC_LAST_RECT: i32 = -224;
pub const ENC_CURSOR: i32 = -239;
pub const ENC_EXT_DESKTOP_SIZE: i32 = -308;

/// Encodings we offer, most preferred first.
pub const ENCODINGS: &[i32] = &[ENC_ZRLE, ENC_COPYRECT, ENC_RAW, ENC_CURSOR, ENC_DESKTOP_SIZE, ENC_EXT_DESKTOP_SIZE, ENC_LAST_RECT];

const SEC_NONE: u8 = 1;
const SEC_VNC_AUTH: u8 = 2;

#[derive(Debug)]
pub enum AuthError {
    NoCommonSecurity(Vec<u8>),
    PasswordRequired,
    Rejected(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::NoCommonSecurity(t) => write!(f, "no supported security type (server offers {t:?})"),
            AuthError::PasswordRequired => f.write_str("the server requires a VNC password"),
            AuthError::Rejected(r) => write!(f, "authentication rejected: {r}"),
        }
    }
}

impl std::error::Error for AuthError {}

#[derive(Debug, Clone)]
pub struct ServerInit {
    pub width: u16,
    pub height: u16,
    pub name: String,
}

/// VNC authentication: DES-encrypt the 16-byte challenge with the password
/// (first 8 bytes, zero padded) as key, each key byte bit-reversed.
pub fn vnc_auth_response(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    let mut key = [0u8; 8];
    for (k, b) in key.iter_mut().zip(password.bytes()) {
        *k = b.reverse_bits();
    }
    let cipher = des::Des::new_from_slice(&key).expect("8-byte key");
    let mut out = *challenge;
    for chunk in out.chunks_mut(8) {
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
    }
    out
}

/// Runs the RFB handshake up to ServerInit.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, password: Option<&str>, shared: bool) -> anyhow::Result<ServerInit> {
    let mut ver = [0u8; 12];
    s.read_exact(&mut ver).await.context("reading server version")?;
    ensure!(&ver[..4] == b"RFB " && ver[11] == b'\n', "not an RFB server");
    let major: u32 = std::str::from_utf8(&ver[4..7])?.parse()?;
    let minor: u32 = std::str::from_utf8(&ver[8..11])?.parse()?;
    ensure!(major == 3, "unsupported RFB version {major}.{minor}");
    // Some servers announce odd minors (3.889 for Apple); treat >= 8 as 3.8.
    let minor = match minor {
        m if m >= 8 => 8,
        7 => 7,
        _ => 3,
    };
    s.write_all(format!("RFB 003.{minor:03}\n").as_bytes()).await?;

    let chosen = if minor >= 7 {
        let n = s.read_u8().await?;
        if n == 0 {
            bail!(AuthError::Rejected(read_reason(s).await?));
        }
        let mut types = vec![0u8; n as usize];
        s.read_exact(&mut types).await?;
        let pick = if types.contains(&SEC_VNC_AUTH) && password.is_some() {
            SEC_VNC_AUTH
        } else if types.contains(&SEC_NONE) {
            SEC_NONE
        } else if types.contains(&SEC_VNC_AUTH) {
            bail!(AuthError::PasswordRequired);
        } else {
            bail!(AuthError::NoCommonSecurity(types));
        };
        s.write_u8(pick).await?;
        pick
    } else {
        match s.read_u32().await? {
            0 => bail!(AuthError::Rejected(read_reason(s).await?)),
            t => t as u8,
        }
    };

    if chosen == SEC_VNC_AUTH {
        let password = password.ok_or(AuthError::PasswordRequired)?;
        let mut challenge = [0u8; 16];
        s.read_exact(&mut challenge).await?;
        s.write_all(&vnc_auth_response(password, &challenge)).await?;
    }
    // RFB 3.3 sends no result for security type None.
    if chosen == SEC_VNC_AUTH || minor >= 8 {
        if s.read_u32().await? != 0 {
            let reason = if minor >= 8 { read_reason(s).await? } else { "wrong password".into() };
            bail!(AuthError::Rejected(reason));
        }
    }

    s.write_u8(shared as u8).await?; // ClientInit
    let width = s.read_u16().await?;
    let height = s.read_u16().await?;
    let mut pf = [0u8; 16];
    s.read_exact(&mut pf).await?;
    let name_len = s.read_u32().await? as usize;
    ensure!(name_len < 4096, "desktop name too long");
    let mut name = vec![0u8; name_len];
    s.read_exact(&mut name).await?;
    Ok(ServerInit { width, height, name: String::from_utf8_lossy(&name).into_owned() })
}

async fn read_reason<S: AsyncRead + Unpin>(s: &mut S) -> anyhow::Result<String> {
    let n = s.read_u32().await? as usize;
    ensure!(n < 4096, "reason too long");
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).await?;
    Ok(String::from_utf8_lossy(&b).into_owned())
}

// ---- client messages ----

pub async fn set_pixel_format<W: AsyncWrite + Unpin>(w: &mut W) -> std::io::Result<()> {
    // bpp 32, depth 24, little-endian, true colour, max 255/255/255, shifts 16/8/0.
    let msg = [0u8, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0];
    w.write_all(&msg).await
}

pub async fn set_encodings<W: AsyncWrite + Unpin>(w: &mut W, encs: &[i32]) -> std::io::Result<()> {
    let mut msg = vec![2u8, 0];
    msg.extend_from_slice(&(encs.len() as u16).to_be_bytes());
    for e in encs {
        msg.extend_from_slice(&e.to_be_bytes());
    }
    w.write_all(&msg).await
}

pub async fn update_request<W: AsyncWrite + Unpin>(w: &mut W, incremental: bool, width: u16, height: u16) -> std::io::Result<()> {
    let mut msg = vec![3u8, incremental as u8, 0, 0, 0, 0];
    msg.extend_from_slice(&width.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    w.write_all(&msg).await
}

pub async fn key_event<W: AsyncWrite + Unpin>(w: &mut W, keysym: u32, down: bool) -> std::io::Result<()> {
    let mut msg = vec![4u8, down as u8, 0, 0];
    msg.extend_from_slice(&keysym.to_be_bytes());
    w.write_all(&msg).await
}

pub async fn pointer_event<W: AsyncWrite + Unpin>(w: &mut W, buttons: u8, x: u16, y: u16) -> std::io::Result<()> {
    let mut msg = vec![5u8, buttons];
    msg.extend_from_slice(&x.to_be_bytes());
    msg.extend_from_slice(&y.to_be_bytes());
    w.write_all(&msg).await
}

/// ClientCutText. RFB text is Latin-1; characters outside it are dropped.
pub async fn cut_text<W: AsyncWrite + Unpin>(w: &mut W, text: &str) -> std::io::Result<()> {
    let latin1: Vec<u8> = text.chars().filter_map(|c| u8::try_from(u32::from(c)).ok()).collect();
    let mut msg = vec![6u8, 0, 0, 0];
    msg.extend_from_slice(&(latin1.len() as u32).to_be_bytes());
    msg.extend_from_slice(&latin1);
    w.write_all(&msg).await
}

// ---- framebuffer and server messages ----

pub use palta_gfx::{Damage, Framebuffer};

#[derive(Debug)]
pub enum ServerMsg {
    Update(Vec<Damage>),
    Bell,
    CutText(String),
}

/// Reads server messages and keeps the framebuffer current. ZRLE uses one
/// zlib stream for the whole connection, so the inflater lives here.
pub struct Decoder {
    zrle: Decompress,
    zbuf: Vec<u8>,
}

impl Default for Decoder {
    fn default() -> Self {
        Self { zrle: Decompress::new(true), zbuf: Vec::new() }
    }
}

impl Decoder {
    pub async fn read<R: AsyncRead + Unpin>(&mut self, r: &mut R, fb: &mut Framebuffer) -> anyhow::Result<ServerMsg> {
        match r.read_u8().await? {
            0 => self.read_update(r, fb).await.map(ServerMsg::Update),
            1 => {
                // SetColourMapEntries: we use true colour; skip it.
                let mut hdr = [0u8; 5];
                r.read_exact(&mut hdr).await?;
                let n = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                let mut skip = vec![0u8; n * 6];
                r.read_exact(&mut skip).await?;
                Ok(ServerMsg::Update(vec![]))
            }
            2 => Ok(ServerMsg::Bell),
            3 => {
                let mut pad = [0u8; 3];
                r.read_exact(&mut pad).await?;
                let n = r.read_u32().await? as usize;
                ensure!(n <= 1 << 20, "cut text too long");
                let mut b = vec![0u8; n];
                r.read_exact(&mut b).await?;
                Ok(ServerMsg::CutText(b.iter().map(|&c| c as char).collect()))
            }
            t => bail!("unknown server message type {t}"),
        }
    }

    async fn read_update<R: AsyncRead + Unpin>(&mut self, r: &mut R, fb: &mut Framebuffer) -> anyhow::Result<Vec<Damage>> {
        r.read_u8().await?; // padding
        let n = r.read_u16().await?;
        let mut out = Vec::new();
        for _ in 0..n {
            let x = r.read_u16().await?;
            let y = r.read_u16().await?;
            let w = r.read_u16().await?;
            let h = r.read_u16().await?;
            let enc = r.read_i32().await?;
            match enc {
                ENC_LAST_RECT => break,
                ENC_DESKTOP_SIZE | ENC_EXT_DESKTOP_SIZE => {
                    if enc == ENC_EXT_DESKTOP_SIZE {
                        let screens = r.read_u8().await?;
                        let mut skip = vec![0u8; 3 + screens as usize * 16];
                        r.read_exact(&mut skip).await?;
                    }
                    // ExtendedDesktopSize also comes back on every full
                    // update request with the current size: only a real
                    // change counts (treating it as one loops forever).
                    if (w, h) != (fb.width, fb.height) {
                        fb.resize(w, h);
                        out.push(Damage::Resize { width: w, height: h });
                    }
                    continue;
                }
                ENC_CURSOR => {
                    let mut px = vec![0u8; w as usize * h as usize * 4];
                    r.read_exact(&mut px).await?;
                    let row_mask = (w as usize).div_ceil(8);
                    let mut mask = vec![0u8; row_mask * h as usize];
                    r.read_exact(&mut mask).await?;
                    let mut rgba = Vec::with_capacity(px.len());
                    for yy in 0..h as usize {
                        for xx in 0..w as usize {
                            let p = &px[(yy * w as usize + xx) * 4..];
                            let visible = mask[yy * row_mask + xx / 8] & (0x80 >> (xx % 8)) != 0;
                            rgba.extend_from_slice(&[p[2], p[1], p[0], if visible { 255 } else { 0 }]);
                        }
                    }
                    out.push(Damage::Cursor { hx: x, hy: y, w, h, rgba });
                    continue;
                }
                _ => {}
            }
            ensure!(fb.in_bounds(x, y, w, h), "rectangle {x},{y} {w}x{h} outside the {}x{} screen", fb.width, fb.height);
            match enc {
                ENC_RAW => {
                    let mut px = vec![0u8; w as usize * h as usize * 4];
                    r.read_exact(&mut px).await?;
                    for yy in 0..h as usize {
                        for xx in 0..w as usize {
                            let i = (yy * w as usize + xx) * 4;
                            fb.set(x as usize + xx, y as usize + yy, &px[i..i + 3]);
                        }
                    }
                    out.push(Damage::Pixels { x, y, w, h });
                }
                ENC_COPYRECT => {
                    let sx = r.read_u16().await?;
                    let sy = r.read_u16().await?;
                    ensure!(fb.in_bounds(sx, sy, w, h), "copyrect source outside the screen");
                    fb.copy_rect(sx, sy, x, y, w, h);
                    out.push(Damage::Copy { sx, sy, x, y, w, h });
                }
                ENC_ZRLE => {
                    let len = r.read_u32().await? as usize;
                    ensure!(len <= 64 << 20, "ZRLE rectangle too large");
                    let mut z = vec![0u8; len];
                    r.read_exact(&mut z).await?;
                    self.inflate(&z)?;
                    decode_zrle(&self.zbuf, fb, x, y, w, h)?;
                    out.push(Damage::Pixels { x, y, w, h });
                }
                e => bail!("server used encoding {e}, which we did not offer"),
            }
        }
        Ok(out)
    }

    fn inflate(&mut self, input: &[u8]) -> anyhow::Result<()> {
        self.zbuf.clear();
        let mut chunk = vec![0u8; 64 * 1024];
        let mut pos = 0;
        loop {
            let before_in = self.zrle.total_in();
            let before_out = self.zrle.total_out();
            let st = self.zrle.decompress(&input[pos..], &mut chunk, FlushDecompress::Sync)?;
            let consumed = (self.zrle.total_in() - before_in) as usize;
            let produced = (self.zrle.total_out() - before_out) as usize;
            pos += consumed;
            self.zbuf.extend_from_slice(&chunk[..produced]);
            if st == Status::StreamEnd || (pos >= input.len() && produced < chunk.len()) {
                return Ok(());
            }
            ensure!(consumed > 0 || produced > 0, "ZRLE inflate made no progress");
        }
    }
}

/// Decodes the inflated ZRLE data of one rectangle into the framebuffer.
fn decode_zrle(data: &[u8], fb: &mut Framebuffer, rx: u16, ry: u16, rw: u16, rh: u16) -> anyhow::Result<()> {
    let mut c = Cursor { data, pos: 0 };
    let mut ty = 0u16;
    while ty < rh {
        let th = 64.min(rh - ty);
        let mut tx = 0u16;
        while tx < rw {
            let tw = 64.min(rw - tx);
            let (ox, oy) = ((rx + tx) as usize, (ry + ty) as usize);
            let (tw_, th_) = (tw as usize, th as usize);
            let sub = c.u8()?;
            match sub {
                0 => {
                    for yy in 0..th_ {
                        for xx in 0..tw_ {
                            let p = c.take(3)?;
                            fb.set(ox + xx, oy + yy, p);
                        }
                    }
                }
                1 => {
                    let p: [u8; 3] = c.take(3)?.try_into().unwrap();
                    for yy in 0..th_ {
                        for xx in 0..tw_ {
                            fb.set(ox + xx, oy + yy, &p);
                        }
                    }
                }
                2..=16 => {
                    let n = sub as usize;
                    let palette = c.take(n * 3)?.to_vec();
                    let bits = match n {
                        2 => 1,
                        3..=4 => 2,
                        _ => 4,
                    };
                    let per_row = (tw_ * bits).div_ceil(8);
                    for yy in 0..th_ {
                        let row = c.take(per_row)?;
                        for xx in 0..tw_ {
                            let bit = xx * bits;
                            let idx = (row[bit / 8] >> (8 - bits - bit % 8)) & ((1 << bits) - 1) as u8;
                            let idx = idx as usize;
                            ensure!(idx < n, "ZRLE palette index out of range");
                            fb.set(ox + xx, oy + yy, &palette[idx * 3..idx * 3 + 3]);
                        }
                    }
                }
                128 => {
                    let mut i = 0;
                    let total = tw_ * th_;
                    while i < total {
                        let p: [u8; 3] = c.take(3)?.try_into().unwrap();
                        let run = c.run_length()?;
                        ensure!(i + run <= total, "ZRLE run past the tile");
                        for k in i..i + run {
                            fb.set(ox + k % tw_, oy + k / tw_, &p);
                        }
                        i += run;
                    }
                }
                130..=255 => {
                    let n = (sub - 128) as usize;
                    let palette = c.take(n * 3)?.to_vec();
                    let mut i = 0;
                    let total = tw_ * th_;
                    while i < total {
                        let b = c.u8()?;
                        let idx = (b & 0x7f) as usize;
                        ensure!(idx < n, "ZRLE palette index out of range");
                        let run = if b & 0x80 != 0 { c.run_length()? } else { 1 };
                        ensure!(i + run <= total, "ZRLE run past the tile");
                        for k in i..i + run {
                            fb.set(ox + k % tw_, oy + k / tw_, &palette[idx * 3..idx * 3 + 3]);
                        }
                        i += run;
                    }
                }
                s => bail!("invalid ZRLE subencoding {s}"),
            }
            tx += tw;
        }
        ty += th;
    }
    Ok(())
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> anyhow::Result<&'a [u8]> {
        ensure!(self.pos + n <= self.data.len(), "ZRLE data truncated");
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> anyhow::Result<u8> {
        Ok(self.take(1)?[0])
    }
    /// ZRLE run length: 255-valued bytes add up, the last byte ends it; +1.
    fn run_length(&mut self) -> anyhow::Result<usize> {
        let mut n = 1usize;
        loop {
            let b = self.u8()?;
            n += b as usize;
            if b != 255 {
                return Ok(n);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    #[test]
    fn vnc_auth_known_vector() {
        // Reference computed independently with OpenSSL:
        //   key = "password" with each byte bit-reversed = 0e86ceceeef64e26
        //   openssl enc -des-ecb -K 0e86ceceeef64e26 -nopad <<< bytes 00..0f
        let challenge: [u8; 16] = core::array::from_fn(|i| i as u8);
        let want = [0xb8, 0x66, 0x92, 0x41, 0x25, 0xc8, 0xee, 0xbb, 0x9d, 0xeb, 0xc1, 0xdb, 0x61, 0xc5, 0x38, 0xe2];
        assert_eq!(vnc_auth_response("password", &challenge), want);
        // Only the first 8 password bytes count.
        assert_eq!(vnc_auth_response("password-and-more", &challenge), want);
    }

    fn px(r: u8, g: u8, b: u8) -> [u8; 3] {
        [b, g, r] // CPIXEL byte order: B, G, R
    }

    #[test]
    fn zrle_subencodings() {
        // One 4x2 rectangle per test, built by hand.
        let cases: Vec<(Vec<u8>, Vec<[u8; 3]>)> = {
            let red = px(255, 0, 0);
            let blue = px(0, 0, 255);
            let mut v = Vec::new();
            // solid
            v.push(([&[1u8][..], &red].concat(), vec![[255, 0, 0]; 8]));
            // packed palette, 2 colours, 1 bit/px: row bits 1010 / 0101
            v.push(([&[2u8][..], &red, &blue, &[0b1010_0000, 0b0101_0000]].concat(),
                vec![[0, 0, 255], [255, 0, 0], [0, 0, 255], [255, 0, 0], [255, 0, 0], [0, 0, 255], [255, 0, 0], [0, 0, 255]]));
            // plain RLE: 3 red, 5 blue
            v.push(([&[128u8][..], &red, &[2], &blue, &[4]].concat(),
                vec![[255, 0, 0], [255, 0, 0], [255, 0, 0], [0, 0, 255], [0, 0, 255], [0, 0, 255], [0, 0, 255], [0, 0, 255]]));
            // palette RLE: idx0 run 2 (0x80|0, len-1=1), idx1 single x6
            v.push(([&[130u8][..], &red, &blue, &[0x80, 1, 1, 1, 1, 1, 1, 1]].concat(),
                vec![[255, 0, 0], [255, 0, 0], [0, 0, 255], [0, 0, 255], [0, 0, 255], [0, 0, 255], [0, 0, 255], [0, 0, 255]]));
            v
        };
        for (i, (data, want)) in cases.into_iter().enumerate() {
            let mut fb = Framebuffer::new(4, 2);
            decode_zrle(&data, &mut fb, 0, 0, 4, 2).unwrap();
            let got: Vec<[u8; 3]> = fb.rgb.chunks(3).map(|c| [c[0], c[1], c[2]]).collect();
            assert_eq!(got, want, "case {i}");
        }
    }

    #[test]
    fn zrle_stream_across_rects() {
        // Two rects compressed in one zlib stream, as servers do.
        let mut enc = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&[1, 0, 0, 255]).unwrap(); // solid red (B,G,R = 0,0,255)
        enc.flush().unwrap();
        let first = enc.get_ref().clone();
        enc.write_all(&[1, 255, 0, 0]).unwrap(); // solid blue
        enc.flush().unwrap();
        let second = enc.get_ref()[first.len()..].to_vec();

        let mut d = Decoder::default();
        let mut fb = Framebuffer::new(2, 1);
        d.inflate(&first).unwrap();
        decode_zrle(&d.zbuf, &mut fb, 0, 0, 1, 1).unwrap();
        d.inflate(&second).unwrap();
        decode_zrle(&d.zbuf.clone(), &mut fb, 1, 0, 1, 1).unwrap();
        assert_eq!(fb.rgb, vec![255, 0, 0, 0, 0, 255]);
    }

    #[test]
    fn rejects_truncated_and_bad_data() {
        let mut fb = Framebuffer::new(4, 2);
        assert!(decode_zrle(&[0, 1, 2], &mut fb, 0, 0, 4, 2).is_err()); // raw, too short
        assert!(decode_zrle(&[17], &mut fb, 0, 0, 4, 2).is_err()); // invalid subencoding
        assert!(decode_zrle(&[128, 0, 0, 0, 20], &mut fb, 0, 0, 4, 2).is_err()); // run past tile
    }

    /// Against a real server: PALTA_TEST_VNC=host:port[,password].
    #[tokio::test(flavor = "multi_thread")]
    async fn live_server_first_frame() {
        let Ok(spec) = std::env::var("PALTA_TEST_VNC") else { return };
        let (addr, pw) = spec.split_once(',').map(|(a, p)| (a.to_string(), Some(p.to_string()))).unwrap_or((spec.clone(), None));
        let mut s = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let init = handshake(&mut s, pw.as_deref(), true).await.unwrap();
        assert!(init.width > 0 && init.height > 0);
        set_pixel_format(&mut s).await.unwrap();
        set_encodings(&mut s, ENCODINGS).await.unwrap();
        update_request(&mut s, false, init.width, init.height).await.unwrap();
        let mut fb = Framebuffer::new(init.width, init.height);
        let mut dec = Decoder::default();
        // The first answer may be just a resize; then ask for the whole screen again.
        let damage = loop {
            if let ServerMsg::Update(d) = dec.read(&mut s, &mut fb).await.unwrap() {
                if d.iter().any(|x| matches!(x, Damage::Pixels { .. })) { break d; }
                update_request(&mut s, false, fb.width, fb.height).await.unwrap();
            }
        };
        let px: usize = damage.iter().map(|d| match d { Damage::Pixels { w, h, .. } => *w as usize * *h as usize, _ => 0 }).sum();
        assert!(px > 0, "no pixels in the first update: {damage:?}");
        assert!(fb.rgb.iter().any(|&b| b != 0), "framebuffer still black");
        let ops = palta_gfx::encode(&damage, &fb).unwrap();
        let bytes: usize = ops.iter().map(|o| o.encode().len()).sum();
        eprintln!("{}x{} {:?}: {} rects, {} ops, {} KB encoded", init.width, init.height, init.name, damage.len(), ops.len(), bytes / 1024);

        // Wrong password is rejected as an auth error.
        if pw.is_some() {
            let mut s = tokio::net::TcpStream::connect(&addr).await.unwrap();
            let err = handshake(&mut s, Some("wrong-pw"), true).await.unwrap_err();
            assert!(err.downcast_ref::<AuthError>().is_some(), "{err:#}");
        }
    }

    /// A FramebufferUpdate with one ExtendedDesktopSize rect.
    fn ext_size_update(w: u16, h: u16) -> Vec<u8> {
        let mut m = vec![0u8, 0, 0, 1, 0, 0, 0, 0];
        m.extend_from_slice(&w.to_be_bytes());
        m.extend_from_slice(&h.to_be_bytes());
        m.extend_from_slice(&ENC_EXT_DESKTOP_SIZE.to_be_bytes());
        m.extend_from_slice(&[1, 0, 0, 0]); // 1 screen + padding
        m.extend_from_slice(&[0u8; 16]);
        m
    }

    #[tokio::test]
    async fn same_size_is_not_a_resize() {
        let mut fb = Framebuffer::new(800, 600);
        fb.rgb[0] = 9;
        let mut dec = Decoder::default();
        let data = [ext_size_update(800, 600), ext_size_update(1024, 768)].concat();
        let mut r = &data[..];
        let ServerMsg::Update(d) = dec.read(&mut r, &mut fb).await.unwrap() else { panic!() };
        assert!(d.is_empty(), "unchanged size reported: {d:?}");
        assert_eq!(fb.rgb[0], 9, "framebuffer cleared");
        let ServerMsg::Update(d) = dec.read(&mut r, &mut fb).await.unwrap() else { panic!() };
        assert_eq!(d, vec![Damage::Resize { width: 1024, height: 768 }]);
    }

    #[test]
    fn copy_rect_overlapping() {
        let mut fb = Framebuffer::new(3, 1);
        fb.rgb = vec![1, 1, 1, 2, 2, 2, 3, 3, 3];
        fb.copy_rect(0, 0, 1, 0, 2, 1);
        assert_eq!(fb.rgb, vec![1, 1, 1, 1, 1, 1, 2, 2, 2]);
    }
}
