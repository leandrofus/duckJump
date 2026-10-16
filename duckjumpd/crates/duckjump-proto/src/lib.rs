//! Wire protocols spoken by duckjumpd.
//!
//! * [`frame`] / [`msg`]: the DuckJump Transport Protocol (DJTP), the native
//!   protocol between the Go gateway and duckjumpd. Terminal sessions carry the
//!   raw byte stream so the browser renders it (xterm.js) instead of the
//!   daemon rasterizing glyphs into images the way guacd does.
//! * [`guac`]: the Apache Guacamole instruction format, kept for the
//!   compatibility layer with legacy guacd and guacamole-common-js clients.

pub mod frame;
pub mod gfx;
pub mod guac;
pub mod msg;

pub use frame::{Frame, FrameCodec, FrameError};
pub use msg::*;

/// DJTP version negotiated in `Hello`. Bump on incompatible changes.
pub const PROTOCOL_VERSION: u16 = 1;
