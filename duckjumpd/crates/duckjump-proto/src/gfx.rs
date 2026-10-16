//! Binary payloads of the graphical frames (DJTP kinds 0x04 and 0x05).
//!
//! All integers are big-endian. The first byte is the operation.
//!
//! Display (`KIND_DISPLAY`, daemon -> client):
//!
//! | op   | name   | body                                                     |
//! |------|--------|----------------------------------------------------------|
//! | 0x01 | SIZE   | u16 width, u16 height (desktop resized; clear it)        |
//! | 0x02 | IMAGE  | u16 x, y, w, h, u8 codec (1 PNG, 2 JPEG), image bytes    |
//! | 0x03 | COPY   | u16 src_x, src_y, w, h, dst_x, dst_y                     |
//! | 0x04 | FILL   | u16 x, y, w, h, u8 r, g, b                               |
//! | 0x05 | CURSOR | u16 hot_x, hot_y, w, h, PNG (RGBA) bytes; w=0: default   |
//! | 0x06 | SYNC   | u32 frame id: everything before it forms one frame       |
//!
//! Input (`KIND_INPUT_EVENT`, client -> daemon):
//!
//! | op   | name    | body                                                   |
//! |------|---------|--------------------------------------------------------|
//! | 0x01 | KEY     | u32 X11 keysym, u8 down (1) / up (0), and optionally   |
//! |      |         | u16 scancode (PC set 1; 0xE0xx = extended; 0 = none)  |
//! | 0x02 | POINTER | u16 x, y, u8 buttons (bit 0 left, 1 middle, 2 right,   |
//! |      |         | 3 wheel up, 4 wheel down, 5 wheel left, 6 wheel right) |
//! | 0x03 | ACK     | u32 frame id: the client finished drawing that frame   |
//!
//! The daemon asks the remote desktop for the next update only after the
//! previous frame is acknowledged, so a slow client or link slows updates
//! down instead of piling them up.

use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const OP_SIZE: u8 = 0x01;
pub const OP_IMAGE: u8 = 0x02;
pub const OP_COPY: u8 = 0x03;
pub const OP_FILL: u8 = 0x04;
pub const OP_CURSOR: u8 = 0x05;
pub const OP_SYNC: u8 = 0x06;

pub const CODEC_PNG: u8 = 1;
pub const CODEC_JPEG: u8 = 2;

pub const IN_KEY: u8 = 0x01;
pub const IN_POINTER: u8 = 0x02;
pub const IN_ACK: u8 = 0x03;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl Rect {
    fn put(&self, b: &mut BytesMut) {
        b.put_u16(self.x);
        b.put_u16(self.y);
        b.put_u16(self.w);
        b.put_u16(self.h);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Display {
    Size { width: u16, height: u16 },
    Image { rect: Rect, codec: u8, data: Bytes },
    Copy { src_x: u16, src_y: u16, rect: Rect },
    Fill { rect: Rect, rgb: [u8; 3] },
    Cursor { hot_x: u16, hot_y: u16, w: u16, h: u16, png: Bytes },
    Sync { frame: u32 },
}

impl Display {
    pub fn encode(&self) -> Bytes {
        let mut b = BytesMut::new();
        match self {
            Display::Size { width, height } => {
                b.put_u8(OP_SIZE);
                b.put_u16(*width);
                b.put_u16(*height);
            }
            Display::Image { rect, codec, data } => {
                b.reserve(10 + data.len());
                b.put_u8(OP_IMAGE);
                rect.put(&mut b);
                b.put_u8(*codec);
                b.extend_from_slice(data);
            }
            Display::Copy { src_x, src_y, rect } => {
                b.put_u8(OP_COPY);
                b.put_u16(*src_x);
                b.put_u16(*src_y);
                b.put_u16(rect.w);
                b.put_u16(rect.h);
                b.put_u16(rect.x);
                b.put_u16(rect.y);
            }
            Display::Fill { rect, rgb } => {
                b.put_u8(OP_FILL);
                rect.put(&mut b);
                b.extend_from_slice(rgb);
            }
            Display::Cursor { hot_x, hot_y, w, h, png } => {
                b.put_u8(OP_CURSOR);
                b.put_u16(*hot_x);
                b.put_u16(*hot_y);
                b.put_u16(*w);
                b.put_u16(*h);
                b.extend_from_slice(png);
            }
            Display::Sync { frame } => {
                b.put_u8(OP_SYNC);
                b.put_u32(*frame);
            }
        }
        b.freeze()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// `scancode` is the physical key (PC set 1, 0xE0xx extended), used by
    /// RDP so the server applies its own layout; 0 when unknown.
    Key { keysym: u32, down: bool, scancode: u16 },
    Pointer { x: u16, y: u16, buttons: u8 },
    Ack { frame: u32 },
}

impl Input {
    pub fn decode(mut b: &[u8]) -> Option<Input> {
        if b.is_empty() {
            return None;
        }
        let op = b.get_u8();
        match op {
            IN_KEY if b.len() >= 5 => {
                let keysym = b.get_u32();
                let down = b.get_u8() != 0;
                let scancode = if b.len() >= 2 { b.get_u16() } else { 0 };
                Some(Input::Key { keysym, down, scancode })
            }
            IN_POINTER if b.len() >= 5 => Some(Input::Pointer { x: b.get_u16(), y: b.get_u16(), buttons: b.get_u8() }),
            IN_ACK if b.len() >= 4 => Some(Input::Ack { frame: b.get_u32() }),
            _ => None,
        }
    }

    pub fn encode(&self) -> Bytes {
        let mut b = BytesMut::new();
        match *self {
            Input::Key { keysym, down, scancode } => {
                b.put_u8(IN_KEY);
                b.put_u32(keysym);
                b.put_u8(down as u8);
                b.put_u16(scancode);
            }
            Input::Pointer { x, y, buttons } => {
                b.put_u8(IN_POINTER);
                b.put_u16(x);
                b.put_u16(y);
                b.put_u8(buttons);
            }
            Input::Ack { frame } => {
                b.put_u8(IN_ACK);
                b.put_u32(frame);
            }
        }
        b.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_roundtrip_and_layout() {
        // The short KEY form (no scancode) still decodes.
        assert_eq!(Input::decode(&[IN_KEY, 0, 0, 0, 0x61, 1]), Some(Input::Key { keysym: 0x61, down: true, scancode: 0 }));
        for i in [Input::Key { keysym: 0xff0d, down: true, scancode: 0x1c }, Input::Pointer { x: 640, y: 400, buttons: 0b101 }, Input::Ack { frame: 7 }] {
            assert_eq!(Input::decode(&i.encode()), Some(i));
        }
        assert_eq!(&Input::Pointer { x: 1, y: 2, buttons: 3 }.encode()[..], &[2, 0, 1, 0, 2, 3]);
        assert_eq!(Input::decode(&[IN_KEY, 0, 0]), None);
    }

    #[test]
    fn display_layout() {
        let d = Display::Fill { rect: Rect { x: 1, y: 2, w: 3, h: 4 }, rgb: [9, 8, 7] };
        assert_eq!(&d.encode()[..], &[4, 0, 1, 0, 2, 0, 3, 0, 4, 9, 8, 7]);
        let c = Display::Copy { src_x: 10, src_y: 20, rect: Rect { x: 30, y: 40, w: 5, h: 6 } };
        assert_eq!(&c.encode()[..], &[3, 0, 10, 0, 20, 0, 5, 0, 6, 0, 30, 0, 40]);
    }
}
