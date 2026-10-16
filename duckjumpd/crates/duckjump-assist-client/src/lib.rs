//! The core of the duckJump Assist desktop app, without any UI: talking to
//! the gateway, signing in (password, TOTP, single sign-on through a
//! loopback redirect), and reading who is logged in on this workstation.

pub mod api;
pub mod identity;
pub mod invite;
pub mod sso;

pub use api::{ApiError, AuthProviders, Gateway, LoginOutcome, SupportRequest, SupportSession, SupportStatus, User};
pub use identity::{AccountType, Identity};
pub use invite::Invite;
