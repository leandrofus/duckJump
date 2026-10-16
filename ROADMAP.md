# Roadmap

duckJump is at 0.1. This is where it stands against similar tools and what comes next, in rough order of
priority. Nothing here is a promise of dates.

## Where we stand

What duckJump aims to be: a modern, lightweight Guacamole with serious PAM, under a stable open license (AGPL).

| | Kind | License | Strong at |
|---|---|---|---|
| Apache Guacamole | web gateway for SSH/RDP/VNC | Apache 2.0 | maturity, more protocols (telnet, Kubernetes), auth extensions (LDAP, SAML, CAS, RADIUS, Duo) |
| JumpServer | open-source web PAM | GPL | SSH/RDP/VNC/databases/Kubernetes in the browser, approval tickets, command filtering, account rotation |
| Teleport | identity-based access | Community Edition with usage limits | short-lived certificates, SSH/Kubernetes/DB/app/desktop access, access requests, `tsh` with port forwarding |
| Warpgate | transparent bastion (Rust) | Apache 2.0 | native clients (`ssh`, `psql`, `mysql`), HTTP, recording; no browser RDP |
| HashiCorp Boundary | identity-based proxy | BSL | port forwarding through its client, credential injection from Vault |
| CyberArk, BeyondTrust, Delinea | commercial PAM | commercial | credential rotation, account discovery, workflows, ITSM integration, session analytics |

(Competitor details are a snapshot; check them before relying on them.)

**Already ahead or on par**

- Access requests with reason (motivo) and start/end time window; approval creates expiring grants.
- Tamper-evident audit: hash chain plus an HMAC chain keyed outside the database, export to syslog or WORM.
- Server keys (SSH, RDP, VNC) pinned and approved by an admin before any credential is sent.
- Grants enforced on live sessions: expiry, revocation or a disabled user ends the session.
- Light to run: one Go binary and one Rust daemon, SQLite by default, rpm/deb packages, one process per session.
- SSH as a raw PTY stream rendered by xterm.js (copyable, searchable), not server-rendered images.
- Edge agents for closed networks.
- Per-grant upload/download over SFTP, with hashes and audit.

**Gaps**

- No credential rotation or checkout; the vault only stores.
- Admins can terminate a session but not watch it live or join it.
- No SSH command filtering or blocking.
- No LDAP / Active Directory or SAML (OpenID Connect only).
- No database or Kubernetes protocols, no port forwarding, no access with native clients.
- No production track record yet: docs, community, HA experience.

## Next

### 1. Access requests

A user asks for access to a connection, folder or tag, for a reason and a duration; an approver (role or group)
approves or denies it; approval creates an expiring grant. Notifications (email, webhook), everything audited,
optional ticket reference for ITSM.

### 2. Live session monitoring

Admins and auditors watch an open session in real time (SSH, RDP, VNC), read-only; optionally join with input,
with the user told they are being watched. Audited.

### 3. LDAP / Active Directory

Bind authentication and group sync, alongside local users and OIDC. Then SAML 2.0.

### 4. Credential rotation

Rotate vaulted passwords and keys on the target (SSH: `passwd` / `authorized_keys`; Windows: local and domain
accounts) on a schedule and after each use. Later: check-out of a credential to a user, with check-in and rotation.

### 5. Port forwarding (TCP access)

Reach a TCP service (a database, an internal API) through duckJump with a native client.

- **New connection type "TCP"**: the daemon dials the target directly or through an edge agent
  (`duckjump_net::dial`), bytes relayed as they come.
- **Through SSH** (`direct-tcpip` via russh), as a second step, to jump through a host with a vaulted credential.
- **`duckjump` CLI**: local listener (`duckjump forward db-prod 5432:localhost:5432`), one WebSocket to the
  gateway per TCP connection; signs in with an API token or OIDC device flow.
- **Policy**: a separate `forward` permission per grant (like upload/download) and an allow list of
  `host:port` per connection, never arbitrary destinations. Live-session enforcement and termination as today.
- **Audit**: destination, duration, bytes each way, user. The content is opaque (usually TLS), so it is not
  recorded; this must be documented. Forwards to SSH/RDP ports would bypass recording, so the allow list is
  required.
- **Not planned**: reverse forwarding (`-R`), which opens the internal network outwards.

### 6. On-demand remote support (duckJump Assist)

Attended-only quick assistance on remote workstations behind NAT/firewalls.

- **On-demand & attended-only**: Portable single binary (`duckjump-assist`), no background services or unattended access. Prominent overlay banner with instant disconnect.
- **Dynamic TOTP verification**: Operator generates a support session link; client opens it and displays a rotating 6-digit TOTP code that must be verified by the operator before session activation.
- **Native DJTP streaming**: Screen capture and diffs encoded directly to DJTP tiles (`duckjump-gfx`) without VNC server overhead, streamed through an outbound WebSocket + yamux tunnel to `duckjump-gw`.
- **Local user priority**: Hardware input by the local user temporarily suspends remote operator inputs.
- **File transfer & audit**: Integrated with user File Tray over SFTP, recorded and verifiable in the HMAC audit chain.

## Later

- SSH command filtering (deny lists, confirm-before-run) on the recorded stream.
- Database protocols with query-level audit (PostgreSQL, MySQL), Kubernetes access.
- Native SSH access through the bastion (`ssh -J`-style), recorded like browser sessions.
- Session sharing between users.
- Browser access to internal web apps (HTTP proxy); a separate project because of cookie and host rewriting.
- `guacd` compatibility backend (already stubbed: `backend` on connections).
- More protocols: telnet.
- Documentation site, HA deployment guide.
