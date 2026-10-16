<p align="center">
  <img src="assets/brand/duckjump-logo.svg" alt="DuckJump" width="320">
</p>

# duckJump

**duckJump is a reimagining of [Apache Guacamole](https://guacamole.apache.org/):** a clientless, web-based
access bastion for SSH, RDP and VNC hosts, designed from the start as a PAM (*Privileged Access Management*)
tool: a credential vault, expiring access grants, session recording and a tamper-evident audit trail.

It is not a fork. Both the gateway and the session daemon were written from scratch:

| | Apache Guacamole | duckJump |
|---|---|---|
| Web gateway | Java (Tomcat) | Go, a single binary with the UI embedded |
| Session daemon | `guacd`, in C | `paltad`, in Rust; RDP on [IronRDP](https://github.com/Devolutions/IronRDP), one process per session |
| Protocol | Guacamole (text) | PTP, a native binary protocol; a `guacd` compatibility layer is planned |
| SSH terminal | rasterized on the server, sent as images | raw PTY stream, rendered in the browser by xterm.js |
| Credentials | stored in the connection settings | encrypted vault (AES-256-GCM), injected gateway → daemon only, never sent to the browser |
| Getting started | Tomcat + external database + guacd | embedded SQLite, rpm/deb packages with the services ready to run |

> Status: under active development (0.1). Some internal names (`palta-gw`, `paltad`) come from the project's
> code name.

## Features

- **SSH, RDP and VNC** in the browser. RDP with NLA/TLS and certificate pinning; VNC with its own RFB client.
  When a connection has no stored credential, the user is asked when connecting (like mstsc), and nothing is stored.
- **Credential vault**: passwords and private keys are encrypted; users never see them.
- **Access grants** for users or groups, on a connection, a folder or a tag, with optional expiry
  (just-in-time access). Nobody bypasses grants, superadmins included.
- **Session recording**: SSH as asciicast (`.cast`), RDP/VNC in a native graphical format, with an in-browser
  player and configurable retention.
- **Audit log** with a verifiable hash chain: altered or deleted events are detected.
- **Edge sites**: an agent inside a closed network opens an outbound tunnel to the bastion and only reaches
  what its local allow list permits.
- **Local users** with password + TOTP; superadmin, admin, auditor and user roles. OIDC is planned.
- **REST API** described in OpenAPI 3.1, generated from the code.

## Architecture

```
browser ──HTTPS/WebSocket──▶ palta-gw (Go) ──PTP/TCP──▶ paltad (Rust) ──SSH/VNC──▶ host
 React + xterm.js / canvas      │                          └─ paltad-rdp (IronRDP) ──RDP──▶ Windows host
                                ├─ local auth + TOTP, roles, CSRF protection
                                ├─ credential vault (AES-256-GCM)
                                ├─ grants, folders, tags, groups
                                ├─ chained audit log, recordings (SQLite)
                                └─ edge agent hub ◀── WSS + yamux ── palta-agent (closed network)
```

**PTP** (frames `u32 len BE | u8 kind | payload`) carries JSON control messages, the terminal stream and, for
graphical sessions, display operations (size, PNG/JPEG image, copy, fill, cursor, end of frame). `paltad` keeps
the remote framebuffer and sends only what changed; the browser acknowledges every frame, which is the flow
control. Format: [`paltad/crates/palta-proto/src/gfx.rs`](paltad/crates/palta-proto/src/gfx.rs).

| Path | What it is |
|---|---|
| `gateway/` | `palta-gw` (API, WebSocket, auth, vault, SQLite via sqlc, CLI) and `palta-agent` |
| `paltad/crates/paltad` | Session daemon: SSH (russh), VNC, RDP worker proxy, recording |
| `paltad/crates/palta-proto` | PTP and the Guacamole protocol codec |
| `paltad/crates/palta-gfx` | Framebuffer and PNG/JPEG tile encoding |
| `paltad/rdp` | `paltad-rdp`: RDP worker on IronRDP (separate workspace) |
| `web/` | React 19 + Vite UI (bun), English and Spanish |
| `packaging/` | rpm/deb packages and systemd services |
| `docs/SCOPE.md` | Scope and roadmap |

## Install

```sh
make packages      # dist/packages: duckjump and duckjump-agent, as rpm and deb (needs podman or docker)
sudo dnf install ./duckjump-0.1.0-1.x86_64.rpm     # or: sudo apt install ./duckjump_0.1.0-1_amd64.deb
```

The package creates the service user, generates the vault master key and the internal token (in
`/etc/duckjump`, root only), creates an `admin` superadmin with a random password (printed during the install
and saved to `/etc/duckjump/initial-admin-password`), and starts `duckjump.service` and
`duckjump-paltad.service` on **https://&lt;host&gt;:8443** with a self-signed certificate.

- Configuration: `/etc/duckjump/duckjump.env` (port, certificate, agent endpoint).
- CLI: `sudo duckjump user|secret|conn|grant|site …`
- Backups: `/var/lib/duckjump` **together with** `/etc/duckjump/master.key`; without the key the vault cannot
  be opened.
- Supported: RHEL/Rocky/Alma 9+, Debian 11+, Ubuntu 22.04+ (amd64).

**Edge agent** (`duckjump-agent`): in the UI, Sites → New site; put the token in `/etc/duckjump-agent/token`,
and the server address and allowed networks in `/etc/duckjump-agent/agent.env`.

## Development

Requirements: Go 1.26, Rust 1.91, bun, podman (test servers).

```sh
make run           # test sshd, VNC and xrdp + paltad + palta-gw → http://127.0.0.1:8088 (admin / palta-admin-123)
make edge          # adds a simulated edge site: a closed network with an sshd and an agent
make dev-web       # UI with hot reload (proxies /api to the running stack)
make test          # Go, Rust, UI typecheck, and checks the OpenAPI spec is up to date
make generate      # sqlc, OpenAPI and the UI's API types
make stop
make help          # every target
```

### API

REST under `/api/v1`. Sign in with `POST /api/v1/auth/login` (session cookie), then `POST /api/v1/auth/totp`
if the user has TOTP enabled. State-changing requests must carry the `X-Palta-Request` header (CSRF defense).

The contract, [`gateway/openapi/openapi.yaml`](gateway/openapi/openapi.yaml), is generated by `make generate`
from inline comments on the handlers:

```go
// openapi:operation
// summary: Create a folder
// tags: [folders]
// requestBody: { schema: FolderRequest }
// responses:
//   '201': { description: Created, schema: Folder }
//   '409': Error

func (s *Server) createFolder(w http.ResponseWriter, r *http.Request, p principal) error {
```

Method, path, roles, parameters and common errors come from the router. `go test ./...` fails if the spec is
out of date.

## License

duckJump is free software under the [GNU Affero General Public License v3.0 or later](LICENSE)
(AGPL-3.0-or-later). If you modify it and offer it as a network service, you must make the source code of your
version available to its users.

Apache Guacamole is a trademark of The Apache Software Foundation. duckJump is an independent project, not
affiliated with or endorsed by the ASF, and contains no Guacamole code.
