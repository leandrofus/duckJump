//! PTP framing.
//!
//! ```text
//! +----------------+---------+-----------------+
//! | len: u32 (BE)  | kind:u8 | payload (len-1) |
//! +----------------+---------+-----------------+
//! ```
//!
//! `len` counts the kind byte plus the payload. Control frames carry a JSON
//! encoded [`crate::Control`]; data frames carry opaque bytes.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

pub const MAX_FRAME_LEN: usize = 1 << 20;

pub const KIND_CONTROL: u8 = 0x01;
/// Session output, daemon -> gateway.
pub const KIND_OUTPUT: u8 = 0x02;
/// User input, gateway -> daemon.
pub const KIND_INPUT: u8 = 0x03;
/// Display updates of graphical sessions, daemon -> gateway (see [`crate::gfx`]).
pub const KIND_DISPLAY: u8 = 0x04;
/// Keyboard/pointer events and frame acks of graphical sessions, gateway -> daemon.
pub const KIND_INPUT_EVENT: u8 = 0x05;

#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    Control(crate::Control),
    Output(Bytes),
    Input(Bytes),
    Display(Bytes),
    InputEvent(Bytes),
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame too large: {0} bytes")]
    TooLarge(usize),
    #[error("empty frame")]
    Empty,
    #[error("unknown frame kind 0x{0:02x}")]
    UnknownKind(u8),
    #[error("bad control message: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Default)]
pub struct FrameCodec;

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = FrameError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, FrameError> {
        if src.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;
        if len == 0 {
            return Err(FrameError::Empty);
        }
        if len > MAX_FRAME_LEN {
            return Err(FrameError::TooLarge(len));
        }
        if src.len() < 4 + len {
            src.reserve(4 + len - src.len());
            return Ok(None);
        }
        src.advance(4);
        let kind = src.get_u8();
        let payload = src.split_to(len - 1).freeze();
        let frame = match kind {
            KIND_CONTROL => Frame::Control(serde_json::from_slice(&payload)?),
            KIND_OUTPUT => Frame::Output(payload),
            KIND_INPUT => Frame::Input(payload),
            KIND_DISPLAY => Frame::Display(payload),
            KIND_INPUT_EVENT => Frame::InputEvent(payload),
            k => return Err(FrameError::UnknownKind(k)),
        };
        Ok(Some(frame))
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = FrameError;

    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), FrameError> {
        let (kind, payload) = match frame {
            Frame::Control(c) => (KIND_CONTROL, Bytes::from(serde_json::to_vec(&c)?)),
            Frame::Output(b) => (KIND_OUTPUT, b),
            Frame::Input(b) => (KIND_INPUT, b),
            Frame::Display(b) => (KIND_DISPLAY, b),
            Frame::InputEvent(b) => (KIND_INPUT_EVENT, b),
        };
        let len = payload.len() + 1;
        if len > MAX_FRAME_LEN {
            return Err(FrameError::TooLarge(len));
        }
        dst.reserve(4 + len);
        dst.put_u32(len as u32);
        dst.put_u8(kind);
        dst.extend_from_slice(&payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Control;

    #[test]
    fn roundtrip_and_partial_reads() {
        let mut codec = FrameCodec;
        let mut buf = BytesMut::new();
        codec
            .encode(Frame::Control(Control::Resize { cols: 80, rows: 24 }), &mut buf)
            .unwrap();
        codec
            .encode(Frame::Output(Bytes::from_static(b"hola")), &mut buf)
            .unwrap();

        let mut partial = buf.split_to(3);
        assert!(codec.decode(&mut partial).unwrap().is_none());
        partial.unsplit(buf);

        assert_eq!(
            codec.decode(&mut partial).unwrap(),
            Some(Frame::Control(Control::Resize { cols: 80, rows: 24 }))
        );
        assert_eq!(
            codec.decode(&mut partial).unwrap(),
            Some(Frame::Output(Bytes::from_static(b"hola")))
        );
        assert!(partial.is_empty());
    }

    #[test]
    fn rejects_oversized() {
        let mut buf = BytesMut::from(&((MAX_FRAME_LEN + 1) as u32).to_be_bytes()[..]);
        assert!(matches!(
            FrameCodec.decode(&mut buf),
            Err(FrameError::TooLarge(_))
        ));
    }
}
