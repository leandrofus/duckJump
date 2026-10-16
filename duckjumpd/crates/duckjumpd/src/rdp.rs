//! RDP sessions run in a separate worker process, `duckjumpd-rdp` (crate::worker
//! relays and records them).
//!
//! Why its own binary: the RDP stack (TLS, CredSSP/NTLM, bitmap codecs) is
//! the most exposed parsing surface, and IronRDP pins dependency versions
//! that conflict with russh.

use std::path::Path;

use duckjump_proto::{Hello, Recording};

use crate::session::Conn;

pub async fn run(hello: Hello, conn: &mut Conn, worker: &Path, recording: Option<(&Path, Recording)>) -> anyhow::Result<()> {
    crate::worker::relay(hello, conn, worker, &[], recording).await
}
