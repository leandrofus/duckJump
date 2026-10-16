//! Apache Guacamole instruction format.
//!
//! An instruction is a comma separated list of elements terminated by `;`.
//! Each element is `LENGTH.VALUE`, where LENGTH is the number of Unicode
//! code points (not bytes) in VALUE. The first element is the opcode:
//!
//! ```text
//! 4.size,1.0,4.1024,3.768;
//! ```

use bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// guacd refuses instructions longer than this; we match it.
pub const MAX_INSTRUCTION_LEN: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub opcode: String,
    pub args: Vec<String>,
}

impl Instruction {
    pub fn new<O: Into<String>, I: IntoIterator<Item = A>, A: Into<String>>(opcode: O, args: I) -> Self {
        Self {
            opcode: opcode.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub fn encode_to(&self, out: &mut String) {
        push_element(out, &self.opcode);
        for a in &self.args {
            out.push(',');
            push_element(out, a);
        }
        out.push(';');
    }
}

impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        self.encode_to(&mut s);
        f.write_str(&s)
    }
}

fn push_element(out: &mut String, v: &str) {
    out.push_str(&v.chars().count().to_string());
    out.push('.');
    out.push_str(v);
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GuacError {
    #[error("io: {0}")]
    Io(String),
    #[error("malformed instruction")]
    Malformed,
    #[error("instruction exceeds {MAX_INSTRUCTION_LEN} bytes")]
    TooLong,
}

impl From<std::io::Error> for GuacError {
    fn from(e: std::io::Error) -> Self {
        GuacError::Io(e.to_string())
    }
}

/// Parses one complete instruction from the start of `buf`.
/// Returns the instruction and the number of bytes consumed, or `None` if
/// more data is needed.
pub fn parse(buf: &[u8]) -> Result<Option<(Instruction, usize)>, GuacError> {
    let mut pos = 0;
    let mut elements = Vec::new();
    loop {
        // LENGTH
        let digits_start = pos;
        while pos < buf.len() && buf[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == buf.len() {
            return incomplete(buf);
        }
        if pos == digits_start || buf[pos] != b'.' {
            return Err(GuacError::Malformed);
        }
        let n: usize = std::str::from_utf8(&buf[digits_start..pos])
            .unwrap()
            .parse()
            .map_err(|_| GuacError::Malformed)?;
        if n > MAX_INSTRUCTION_LEN {
            return Err(GuacError::TooLong);
        }
        pos += 1;

        // VALUE: n code points. Walk UTF-8 lead bytes.
        let value_start = pos;
        let mut chars = 0;
        while chars < n {
            let Some(&b) = buf.get(pos) else {
                return incomplete(buf);
            };
            pos += match b {
                0x00..=0x7f => 1,
                0xc0..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf7 => 4,
                _ => return Err(GuacError::Malformed),
            };
            chars += 1;
        }
        if pos >= buf.len() {
            return incomplete(buf);
        }
        let value = std::str::from_utf8(&buf[value_start..pos]).map_err(|_| GuacError::Malformed)?;
        elements.push(value.to_owned());

        match buf[pos] {
            b',' => pos += 1,
            b';' => {
                pos += 1;
                let mut it = elements.into_iter();
                let opcode = it.next().ok_or(GuacError::Malformed)?;
                return Ok(Some((Instruction { opcode, args: it.collect() }, pos)));
            }
            _ => return Err(GuacError::Malformed),
        }
    }
}

fn incomplete(buf: &[u8]) -> Result<Option<(Instruction, usize)>, GuacError> {
    if buf.len() > MAX_INSTRUCTION_LEN {
        Err(GuacError::TooLong)
    } else {
        Ok(None)
    }
}

#[derive(Debug, Default)]
pub struct GuacCodec;

impl Decoder for GuacCodec {
    type Item = Instruction;
    type Error = GuacError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Instruction>, GuacError> {
        match parse(src)? {
            Some((ins, used)) => {
                src.advance(used);
                Ok(Some(ins))
            }
            None => Ok(None),
        }
    }
}

impl Encoder<Instruction> for GuacCodec {
    type Error = GuacError;

    fn encode(&mut self, ins: Instruction, dst: &mut BytesMut) -> Result<(), GuacError> {
        let mut s = String::new();
        ins.encode_to(&mut s);
        dst.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_codepoint_lengths() {
        let ins = Instruction::new("args", ["VERSION_1_5_0", "año", "🥑"]);
        assert_eq!(ins.to_string(), "4.args,13.VERSION_1_5_0,3.año,1.🥑;");
    }

    #[test]
    fn parses_stream_with_partial_input() {
        let wire = "6.select,3.ssh;4.size,4.1024,3.768,2.96;".as_bytes();
        assert_eq!(parse(&wire[..10]).unwrap(), None);
        let (a, used) = parse(wire).unwrap().unwrap();
        assert_eq!(a, Instruction::new("select", ["ssh"]));
        let (b, _) = parse(&wire[used..]).unwrap().unwrap();
        assert_eq!(b, Instruction::new("size", ["1024", "768", "96"]));
    }

    #[test]
    fn roundtrips_unicode_and_separators() {
        let ins = Instruction::new("clipboard", ["a,b;c.d", "duckjump 🥑 ñ", ""]);
        let s = ins.to_string();
        let (back, used) = parse(s.as_bytes()).unwrap().unwrap();
        assert_eq!(back, ins);
        assert_eq!(used, s.len());
        // A multi-byte char cut in half is just "need more data".
        assert_eq!(parse(&s.as_bytes()[..s.len() - 3]).unwrap(), None);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse(b"x.foo;"), Err(GuacError::Malformed));
        assert_eq!(parse(b"3.foo|"), Err(GuacError::Malformed));
    }
}
