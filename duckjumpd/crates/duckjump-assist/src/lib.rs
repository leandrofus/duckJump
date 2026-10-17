//! duckJump Assist: on-demand, attended remote support. The library runs a
//! session ([`session::run_session`]); the `duckjump-assist` binary and the
//! desktop app are front ends to it.

pub mod capture;
pub mod input;
pub mod session;
pub mod sysenv;
pub mod totp;
#[cfg(unix)]
pub mod wayland;

pub use session::{format_verification_code, run_session, EndReason, Event, SessionConfig};
pub use tokio_util::sync::CancellationToken;

/// Log filter when RUST_LOG is not set. zbus warns about every short-lived
/// portal object it cannot cache, which users read as errors.
pub const DEFAULT_LOG_FILTER: &str = "info,zbus=error";
